'use strict';

/**
 * ============================================================================
 *  ubuntu-core-manager — main.js
 *  Main-process module for the Ubuntu Core Manager kiosk.
 *
 *  Security model:
 *   - All privileged I/O happens HERE, in the main process (Node).
 *   - snapd is reached exclusively over its Unix Domain Socket
 *     (/run/snapd.socket, exposed to this strict-confinement snap by the
 *     connected `snapd-control` interface). Network state is read with
 *     the standard tools the `network-control` interface is built around
 *     (ip, iw, resolvectl — read-only); network config is written through
 *     snapd's netplan external config. No direct /etc writes, no
 *     renderer-side network.
 *   - TWO independent auth layers (see section 4):
 *       (a) LOCAL admin gate  — the UI lock screen. A local password set on
 *           first boot (offline) and stored hashed in $SNAP_COMMON. This is
 *           what lets a physical operator get in and configure the network
 *           BEFORE any store connectivity exists.
 *       (b) STORE auth        — optional, volatile. snapd /v2/login macaroons,
 *           held in memory only, attached to socket requests when present.
 *           NOT required to enter the UI.
 *   - Every renderer payload is re-validated by rigid regex allow-lists
 *     before it can reach the socket — command/format injection from a
 *     compromised renderer is rejected at the IPC boundary.
 *
 *  Deliberately Electron-free in its core so the socket + auth logic is
 *  unit-testable headlessly (test/run-integration.js against a stub snapd).
 *  The kiosk window lifecycle initialises only when Electron is present.
 * ============================================================================
 */

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

/* ------------------------------------------------------------------ *
 * 1. Constants & input-validation allow-lists (injection prevention)
 * ------------------------------------------------------------------ */

const SNAPD_SOCKET = process.env.SNAPD_SOCKET || '/run/snapd.socket';
const SOCKET_TIMEOUT_MS = 15000;

// Local admin session: 15 minutes of inactivity locks the console.
const SESSION_TIMEOUT_MS = 15 * 60 * 1000;
const SESSION_WARN_MS = 60 * 1000;

// Snap names: lowercase alphanumerics + hyphens, optional `snap_instance`
// revision suffix (matches snapd's naming.InstanceName rules).
const RE_SNAP_NAME = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const RE_INSTANCE_SUFFIX = /^\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

// Channel = a store-issued channel: track[/risk[/branch]], e.g. "stable",
// "latest/stable", "21/stable" (versioned track), or "26/edge/fix-1234" (a short-
// lived BRANCH for testing a fix). THE STORE IS AUTHORITATIVE: channels come from
// the /v2/find `channels` map (or the UI pulldown fed by it), so we do NOT
// re-impose any vocabulary — snapd itself is the ultimate arbiter of what a real
// channel is (it 400s anything the store never had). We validate STRUCTURE ONLY
// (a shape allow-list, not a content block-list): 1-3 URL-safe store-token
// segments, <= 4095 chars (snapd's own channel length limit). That still defeats
// shell/URL injection (no ;, space, newline, empty segment, >3 segments).
// Verified against the live store: 20/20 real node channels + branch names.
const RE_CHANNEL = /^[A-Za-z0-9._+-]+(\/[A-Za-z0-9._+-]+){0,2}$/;

// IPv4 CIDR, e.g. 192.168.1.50/24
const RE_IPV4_CIDR = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\/(3[0-2]|2\d|1\d|[1-9])$/;
// IPv6 CIDR, e.g. fd00::1/64
const RE_IPV4 = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;


// Config keys: dotted lowercase identifiers.
const RE_CONF_KEY = /^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?)*$/;

// snapd store login identity (Ubuntu One email).
const RE_EMAIL = /^[^\s@<>"']{1,64}@[\w-]+(?:\.[\w-]+)+$/;

function validSnapName(name) {
    if (typeof name !== 'string' || name.length > 70) return false;
    const idx = name.lastIndexOf('.');
    const base = idx === -1 ? name : name.slice(0, idx);
    const suffix = idx === -1 ? '' : name.slice(idx);
    return RE_SNAP_NAME.test(base) && (suffix === '' || RE_INSTANCE_SUFFIX.test(suffix));
}

// Bare 'stable' stays valid: real snapd normalises it to latest/stable, and it is
// the pre-search default for manual installs.
// Pure predicate (no input mutation): a channel is a store-issued token. Anything
// outside the store-token alphabet — whitespace, newlines, semicolons, path
// separators, >3 segments — is rejected rather than normalised.
function validChannel(channel) {
    return typeof channel === 'string' && channel.length > 0 && channel.length <= 4095
        && RE_CHANNEL.test(channel);
}

/* ------------------------------------------------------------------ *
 * 2. Minimal YAML (de)serialiser — netplan document round-trip.
 * ------------------------------------------------------------------ */

function yamlNeedsQuote(s) {
    if (s === '') return true;
    if (/^[-#&*!|>%@`"'?,{}\[\] ]/.test(s)) return true;
    if (/(^|\s)(true|false|yes|no|on|off|null|~)$/i.test(s)) return true;
    if (/^[-+]?[.0-9]/.test(s) && !RE_IPV4.test(s)) return true;
    if (s !== s.trim()) return true;
    if (/[:#]|\s/.test(s)) return true;
    return false;
}

function yamlScalar(v) {
    if (v === null || v === undefined) return 'null';
    if (typeof v === 'boolean') return v ? 'true' : 'false';
    if (typeof v === 'number') return String(v);
    const s = String(v);
    if (!yamlNeedsQuote(s)) return s;
    return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

function yamlIsMap(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/** Serialise a JS value into a netplan-compatible YAML document. */
function toYaml(value, indent = 0) {
    const pad = '  '.repeat(indent);
    if (value === null || value === undefined) return pad + 'null\n';
    if (!yamlIsMap(value) && !Array.isArray(value)) return pad + yamlScalar(value) + '\n';

    if (Array.isArray(value)) {
        if (value.length === 0) return pad + '[]\n';
        let out = '';
        for (const item of value) {
            if (yamlIsMap(item)) {
                const body = toYaml(item, indent + 1).replace(/^  /, '');
                out += pad + '- ' + body;
            } else if (Array.isArray(item)) {
                out += pad + '-\n' + toYaml(item, indent + 1);
            } else {
                out += pad + '- ' + yamlScalar(item) + '\n';
            }
        }
        return out;
    }

    const keys = Object.keys(value);
    if (keys.length === 0) return pad + '{}\n';
    let out = '';
    for (const k of keys) {
        const v = value[k];
        const key = yamlNeedsQuote(k) ? yamlScalar(k) : k;
        if (v === null || v === undefined) out += `${pad}${key}: null\n`;
        else if (yamlIsMap(v)) out += `${pad}${key}:\n${toYaml(v, indent + 1)}`;
        else if (Array.isArray(v)) out += `${pad}${key}:\n${toYaml(v, indent + 1)}`;
        else out += `${pad}${key}: ${yamlScalar(v)}\n`;
    }
    return out;
}

function parseYamlScalar(tok) {
    const t = tok.trim();
    if (t === '' || t === 'null' || t === '~') return null;
    if (t === 'true') return true;
    if (t === 'false') return false;
    if (t.startsWith('"') && t.endsWith('"') && t.length > 1) {
        try { return JSON.parse(t); } catch { return t.slice(1, -1); }
    }
    if (t.startsWith("'") && t.endsWith("'") && t.length > 1) return t.slice(1, -1);
    if (/^-?\d+$/.test(t)) return parseInt(t, 10);
    if (/^-?\d+\.\d+$/.test(t)) return parseFloat(t);
    return t;
}

function parseFlowList(s) {
    const inner = s.trim().replace(/^\[/, '').replace(/\]$/, '').trim();
    if (inner === '') return [];
    return inner.split(',').map((x) => parseYamlScalar(x));
}

/** Parse the strict YAML subset that netplan documents use (fail closed). */
function fromYaml(doc) {
    const lines = String(doc)
        .split(/\r?\n/)
        .filter((l) => l.trim() !== '' && !/^\s*#/.test(l));

    let pos = 0;
    const ind = (l) => l.length - l.trimStart().length;

    function parseBlock(level) {
        if (pos >= lines.length) return null;
        const first = lines[pos];
        if (ind(first) < level) return null;
        const t = first.trim();
        if (t === '-' || t.startsWith('- ')) return parseSeq(ind(first));
        if (t.includes(':')) return parseMap(ind(first));
        return parseYamlScalar(t);
    }

    function parseSeq(level) {
        const arr = [];
        while (pos < lines.length) {
            const l = lines[pos];
            if (ind(l) !== level || !l.trim().startsWith('-')) break;
            const rest = l.trim().slice(1).trim();
            pos += 1;
            if (rest === '') {
                arr.push(parseBlock(level + 1));
            } else if (rest.includes(':')) {
                const obj = {};
                const ci = rest.indexOf(':');
                const k = rest.slice(0, ci).trim();
                const v = rest.slice(ci + 1).trim();
                obj[k] = v === '' ? null : (v.startsWith('[') ? parseFlowList(v) : parseYamlScalar(v));
                while (pos < lines.length && ind(lines[pos]) === level + 2
                    && !lines[pos].trim().startsWith('-')) {
                    Object.assign(obj, parseMap(level + 2));
                }
                arr.push(obj);
            } else {
                arr.push(parseYamlScalar(rest));
            }
        }
        return arr;
    }

    function parseMap(level) {
        const obj = {};
        while (pos < lines.length) {
            const l = lines[pos];
            if (ind(l) !== level || l.trim().startsWith('-')) break;
            const m = l.trim().match(/^([^:]+):\s*(.*)$/);
            if (!m) throw new Error('unparsable YAML line: ' + l);
            const key = m[1].trim().replace(/^["']|["']$/g, '');
            const val = m[2].trim();
            pos += 1;
            if (val === '') {
                if (pos < lines.length && ind(lines[pos]) > level) obj[key] = parseBlock(ind(lines[pos]));
                else obj[key] = null;
            } else if (val.startsWith('[')) {
                obj[key] = parseFlowList(val);
            } else {
                obj[key] = parseYamlScalar(val);
            }
        }
        return obj;
    }

    const result = parseBlock(0);
    if (pos < lines.length) throw new Error('trailing unparsed YAML content');
    return result === undefined ? null : result;
}

/* ------------------------------------------------------------------ *
 * 3. Snapd REST client over the Unix Domain Socket
 * ------------------------------------------------------------------ */

function snapdError(status, kind, message, value) {
    const e = new Error(message || `snapd error ${status}`);
    e.name = 'SnapdError';
    e.status = status;
    e.kind = kind || 'unknown';
    e.value = value;
    return e;
}

/**
 * Issue a request to snapd over the UDS; resolves with the decoded
 * `result` field. `auth` = { macaroon, discharges } | null (store-only).
 */
function snapdRequest(method, apiPath, { body = null, auth = null, timeout = SOCKET_TIMEOUT_MS } = {}) {
    return new Promise((resolve, reject) => {
        if (!['GET', 'POST', 'PUT', 'DELETE'].includes(method)) {
            return reject(new Error('method not allowed by snapd client: ' + method));
        }

        const headers = {
            Accept: 'application/json',
            'User-Agent': 'ubuntu-core-manager/1.0 (electron-kiosk)',
        };
        if (body !== null) {
            const raw = typeof body === 'string' ? body : JSON.stringify(body);
            headers['Content-Type'] = typeof body === 'string' ? 'text/plain' : 'application/json';
            headers['Content-Length'] = Buffer.byteLength(raw);
        }
        if (auth && auth.macaroon) {
            // Exact format snapd's server parser accepts (daemon/api.go
            // userFromRequest, strutil.CommaSeparatedList):
            //   Authorization: Macaroon root="<mac>", discharge="<d1>", ...
            let mac = `Macaroon root="${auth.macaroon}"`;
            for (const d of auth.discharges || []) mac += `, discharge="${d}"`;
            headers.Authorization = mac;
        }

        const req = http.request({
            socketPath: SNAPD_SOCKET,
            method,
            path: apiPath,
            headers,
            agent: false,
        }, (res) => {
            const chunks = [];
            res.on('data', (c) => chunks.push(c));
            res.on('end', () => {
                const text = Buffer.concat(chunks).toString('utf8');
                let data = null;
                if (text) {
                    try { data = JSON.parse(text); } catch { data = { raw: text }; }
                }
                const st = res.statusCode || 0;
                if (st >= 200 && st < 300) {
                    // snapd's ASYNC ops (install/remove/etc.) respond
                    //   { type:"async", result: null, change: "<id>" }
                    // — the change id lives at the ENVELOPE top level, not in
                    // result. Surface it as { id } so waitChangeSettled() can
                    // poll /v2/changes/{id}. (Verified against live snapd 2.77.)
                    if (data && data.type === 'async') {
                        resolve(data.change ? { id: String(data.change) } : {});
                    } else if (data && data.result !== undefined) {
                        resolve(data.result);
                    } else {
                        resolve(data === null ? {} : data);
                    }
                } else {
                    const r = data && data.result ? data.result : {};
                    reject(snapdError(st, r.kind, r.message || `HTTP ${st}`, r.value));
                }
            });
        });

        req.setTimeout(timeout, () => req.destroy(new Error('snapd socket timeout after ' + timeout + 'ms')));
        req.on('error', (err) => {
            if (err.code === 'ENOENT' || err.code === 'ECONNREFUSED') {
                const e = new Error(`snapd socket ${SNAPD_SOCKET} unreachable — is the snapd-control interface connected?`);
                e.code = err.code;
                return reject(e);
            }
            reject(err);
        });
        if (body !== null) req.write(typeof body === 'string' ? body : JSON.stringify(body));
        req.end();
    });
}

/* ------------------------------------------------------------------ *
 * 4. Session state — TWO independent auth layers (see file header).
 * ------------------------------------------------------------------ */

const session = {
    // (a) LOCAL admin gate (the UI lock screen)
    localAuthenticated: false,
    localInitialized: false,   // a local password has been set at least once
    localExpiresAt: 0,
    localWarned: false,
    // (b) STORE auth (optional, volatile — never persisted)
    storeAuthenticated: false,
    storeUsername: null,
    storeMacaroon: null,       // volatile, main-process only
    storeDischarges: [],       // volatile, main-process only
};

/* ---- local admin credential (offline; the UI gate) -------------------- *
 * Stored hashed (scrypt) with a per-install random salt in
 * $SNAP_COMMON/admin.cred (mode 0600). Verification never touches the
 * network. Only status booleans cross IPC — never the password or hash. */

function stateDir() {
    return process.env.SNAP_COMMON || process.env.UCM_STATE_DIR
        || path.join(os.tmpdir(), 'ubuntu-core-manager');
}
function adminFile() {
    return path.join(stateDir(), 'admin.cred');
}
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };
function hashPassword(password, salt) {
    return crypto.scryptSync(String(password), salt, SCRYPT.keylen, SCRYPT).toString('base64');
}

function readCred() {
    try {
        const cred = JSON.parse(fs.readFileSync(adminFile(), 'utf8'));
        return (cred && cred.algo === 'scrypt' && cred.salt && cred.hash) ? cred : null;
    } catch { return null; }
}

/** Detect whether a local password has been set (idempotent). */
function detectInitialized() {
    session.localInitialized = readCred() !== null;
    return session.localInitialized;
}

function statusPayload() {
    return {
        // local gate
        initialized: session.localInitialized,
        authenticated: session.localAuthenticated,
        expiresAt: session.localAuthenticated ? session.localExpiresAt : null,
        timeoutMs: SESSION_TIMEOUT_MS,
        // store (optional)
        storeAuthenticated: session.storeAuthenticated,
        storeUsername: session.storeAuthenticated ? session.storeUsername : null,
    };
}

function beginLocalSession() {
    session.localAuthenticated = true;
    session.localInitialized = readCred() !== null;
    session.localExpiresAt = Date.now() + SESSION_TIMEOUT_MS;
    session.localWarned = false;
    return statusPayload();
}

/**
 * First boot only: create the local administrator password.
 * Rejects if a password already exists (use login, or wipe $SNAP_COMMON
 * admin.cred to reset — there is no offline "forgot password" by design).
 */
function createLocalPassword(password) {
    if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
        throw new Error('password must be 8–128 characters');
    }
    if (detectInitialized()) {
        throw new Error('a local administrator password already exists — sign in instead');
    }
    const salt = crypto.randomBytes(16).toString('base64');
    const cred = {
        algo: 'scrypt', N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p,
        salt, hash: hashPassword(password, Buffer.from(salt, 'base64')),
        created: new Date().toISOString(),
    };
    fs.mkdirSync(stateDir(), { recursive: true });
    const tmp = adminFile() + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(cred, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, adminFile());
    fs.chmodSync(adminFile(), 0o600);
    return beginLocalSession();
}

/** Local sign-in: verify the password against the stored scrypt hash. */
function loginLocal(password) {
    if (typeof password !== 'string' || password.length === 0 || password.length > 128) {
        throw new Error('invalid password');
    }
    const cred = readCred();
    if (!cred) throw new Error('no local administrator password is set — create one first');
    const expect = Buffer.from(cred.hash, 'base64');
    const got = Buffer.from(hashPassword(password, Buffer.from(cred.salt, 'base64')), 'base64');
    let ok = false;
    try { ok = expect.length === got.length && crypto.timingSafeEqual(expect, got); }
    catch { ok = false; }
    if (!ok) throw new Error('incorrect password');
    return beginLocalSession();
}

/**
 * Physically-privileged local admin reset: the current administrator signs
 * in, re-confirms the password, and wipes $SNAP_COMMON/admin.cred. The next
 * launch re-enters first-boot setup, where a NEW password is created.
 * There is no "keep the old password" path and no remote/offline trigger —
 * the only way to call this is with an active local session (IPC handler
 * enforces requireAuth), which is what makes it console-privileged.
 */
function resetLocalPassword(password) {
    if (typeof password !== 'string' || password.length === 0 || password.length > 128) {
        throw new Error('invalid password');
    }
    if (!session.localAuthenticated) {
        throw new Error('authentication required — sign in as the current administrator first');
    }
    loginLocal(password); // throws 'incorrect password' on mismatch (timing-safe compare)
    fs.rmSync(adminFile(), { force: true });
    session.localInitialized = false;
    session.localAuthenticated = false;
    session.localExpiresAt = 0;
    session.localWarned = false;
    clearStoreSession('local-reset');
    return statusPayload();
}

/** Lock the console (local logout). Also clears volatile store auth. */
function logoutLocal() {
    session.localAuthenticated = false;
    session.localExpiresAt = 0;
    session.localWarned = false;
    clearStoreSession('local-logout');
    return statusPayload();
}

function authStatus() {
    detectInitialized();
    return statusPayload();
}

/* ---- store auth (optional, volatile) ---------------------------------- *
 * snapd /v2/login contacts the store backend; needs network + a store
 * account. Macaroons live in memory only and are attached to socket
 * requests when present. Independent of the local UI gate. */

function clearStoreSession(reason) {
    session.storeAuthenticated = false;
    session.storeUsername = null;
    session.storeMacaroon = null;
    session.storeDischarges = [];
    return { ok: true, reason: reason || 'cleared' };
}

async function storeLogin(email, password) {
    if (typeof email !== 'string' || !RE_EMAIL.test(email.trim())) throw new Error('invalid email format');
    if (typeof password !== 'string' || password.length < 1 || password.length > 512) throw new Error('invalid password');
    const res = await snapdRequest('POST', '/v2/login', { body: { username: email.trim(), password }, auth: null });
    if (!res || typeof res.macaroon !== 'string') throw new Error('snapd did not return a store macaroon');
    session.storeAuthenticated = true;
    session.storeUsername = res.username || email.trim();
    session.storeMacaroon = res.macaroon;
    session.storeDischarges = Array.isArray(res.discharges) ? res.discharges : [];
    return statusPayload();
}

async function storeLogout() {
    const wasAuth = session.storeAuthenticated;
    const username = session.storeUsername;
    const mac = session.storeMacaroon;
    const dis = session.storeDischarges;
    if (wasAuth) {
        // Invalidate remotely first (bounded), then drop the volatile cache
        // locally — the UI is never blocked longer than the timeout.
        await snapdRequest('POST', '/v2/logout', {
            body: { username },
            auth: { macaroon: mac, discharges: dis },
            timeout: 5000,
        }).catch(() => { /* best-effort remote invalidation */ });
    }
    clearStoreSession('store-logout');
    return statusPayload();
}

/* ------------------------------------------------------------------ *
 * 5. Read APIs (system monitoring & management)
 * ------------------------------------------------------------------ */

// Attach store macaroons to socket requests only when a store login is
// active; otherwise null (reads are openAccess; root/polkit covers writes
// for a root-launched kiosk). Never requires the local gate.
const A = () => (session.storeAuthenticated && session.storeMacaroon
    ? { macaroon: session.storeMacaroon, discharges: session.storeDischarges }
    : null);

async function getSystemInfo() {
    return snapdRequest('GET', '/v2/system-info', { auth: A() });
}

async function listChanges(select = 'all') {
    const s = ['in-progress', 'ready', 'all'].includes(select) ? select : 'all';
    return snapdRequest('GET', '/v2/changes?select=' + s, { auth: A() });
}

/** GET /v2/assertions/model — the device's model ASSERTION.
    Unlike the JSON REST endpoints this returns the RAW assertion text
    (content-type application/x.ubuntu.assertion, verified against live
    snapd 2.77: no JSON envelope at all), so snapdRequest lands in its
    JSON-parse-fallback branch and hands us { raw: text }. Parse the header
    section (lines up to the first blank line; everything after is the
    signature block) into { key: value } with classic/true->bool, PLUS the
    `snaps:` list — a minimal YAML-subset parse (an entry starts at a
    "  -" line; its fields indent deeper: name/type/presence/
    default-channel/id). Validated against a real core24 model assertion
    (round 46b). */
function parseModelAssertion(raw) {
    const out = {};
    if (typeof raw !== 'string' || !raw) return out;
    let entry = null;
    for (const line of raw.split('\n')) {
        if (line.trim() === '') break;              // signature block follows
        if (/^ {2,}-/.test(line)) {                 // a snaps: list entry ("  -")
            entry = {};
            (out.snaps = out.snaps || []).push(entry);
            continue;
        }
        if (/^\s/.test(line)) {                    // indented field of an entry
            if (!entry) continue;
            const i = line.indexOf(':');
            if (i <= 0) continue;
            entry[line.slice(0, i).trim()] = line.slice(i + 1).trim();
            continue;
        }
        const i = line.indexOf(':');                // top-level header (col 0)
        if (i <= 0) continue;
        const k = line.slice(0, i).trim();
        const v = line.slice(i + 1).trim();
        if (!k) continue;
        out[k] = (v === 'true') ? true : (v === 'false') ? false : v;
    }
    return out;
}

/** The device's SYSTEM snap names — authoritative source is the model
    ASSERTION, not the /v2/snaps type field (round 46b, user-corrected):
    the top-level `base:` (the OS snap) + every `snaps:` entry of type
    gadget / kernel / snapd / os. Model-declared APP snaps (e.g. required
    mesa/ubuntu-frame) are NOT system snaps — they keep their full action
    set. A base-type snap that the model does not declare (a second base
    apps depend on) is likewise not a "system snap" (it loses Config
    separately, by type). */
function modelSystemSnaps(model) {
    const set = new Set();
    if (!model || typeof model !== 'object') return set;
    if (model.base) set.add(model.base);
    for (const e of (model.snaps || [])) {
        if (e && e.name && ['gadget', 'kernel', 'snapd', 'os'].includes(e.type)) {
            set.add(e.name);
        }
    }
    return set;
}

async function getModelAssertion() {
    const data = await snapdRequest('GET', '/v2/assertions/model', { auth: A() });
    return parseModelAssertion(data && (typeof data === 'string' ? data : data.raw));
}

/** GET /v2/changes/{id} — one change. The id is a numeric change ID from a
    snapd 2xx write response (validated here; snapd itself 400s anything else). */
async function getChange(id) {
    if (!/^[0-9]{1,10}$/.test(String(id))) throw new Error('invalid change id');
    return snapdRequest('GET', '/v2/changes/' + String(id), { auth: A() });
}

async function getWarnings() {
    return snapdRequest('GET', '/v2/warnings', { auth: A() });
}

/** GET /v2/snaps — installed snaps (name, revision, channel, status). */
async function listSnaps() {
    const res = await snapdRequest('GET', '/v2/snaps', { auth: A() });
    return Array.isArray(res) ? res : (res && Array.isArray(res.snaps) ? res.snaps : []);
}

async function getSnapInfo(name) {
    if (!validSnapName(name)) throw new Error('invalid snap name');
    return snapdRequest('GET', '/v2/snaps/' + encodeURIComponent(name), { auth: A() });
}

/** GET /v2/find — search the store. Unauthenticated by design: global-store search
    works without a /v2/login macaroon (store login is reserved for a later
    private-brand store). Results carry each snap's full `channels` map; the UI
    populates the deploy pulldown from it. */
async function searchSnaps(query, limit = 10) {
    if (typeof query !== 'string' || query.length > 120) throw new Error('invalid search query');
    const clean = query.replace(/[^\p{L}\p{N}._\-+ ]/gu, '').trim();
    const n = Math.min(Math.max(parseInt(limit, 10) || 10, 1), 50);
    const res = await snapdRequest('GET', '/v2/find?name=' + encodeURIComponent(clean) + '&n=' + n, { auth: A() });
    return Array.isArray(res) ? res : (res && res.snaps) || [];
}

/* ------------------------------------------------------------------ *
 * 6. Write APIs — snaps (install / remove / action)
 * ------------------------------------------------------------------ */

/**
 * POST /v2/snaps/{name} with {"action":"install","channel":"stable"}.
 * The channel is regex-whitelisted (official risk levels only) before it
 * can touch the socket — the primary write-side injection vector, closed
 * at the IPC boundary.
 */
async function installSnap(name, channel = 'stable') {
    if (!validSnapName(name)) throw new Error('invalid snap name: ' + JSON.stringify(name));
    if (!validChannel(channel)) {
        throw new Error('invalid channel (expected a store channel like latest/stable, 21/stable or a branch): ' + JSON.stringify(channel));
    }
    // No `--classic` is ever sent: this app runs ONLY on Ubuntu Core, where
    // snapd itself rejects classic-confined snaps (there is no classic base).
    return snapdRequest('POST', '/v2/snaps/' + encodeURIComponent(name), {
        body: { action: 'install', channel },
        auth: A(),
    });
}

/** POST /v2/snaps/{name} with {"action": <whitelisted action>}. */
async function snapAction(name, action, extra = {}) {
    const ALLOWED = new Set(['refresh', 'remove', 'enable', 'disable', 'hold', 'unhold', 'revert', 'switch']);
    if (!validSnapName(name)) throw new Error('invalid snap name');
    if (!ALLOWED.has(action)) throw new Error('snap action not permitted: ' + JSON.stringify(action));
    const body = { action };
    if ((action === 'switch' || action === 'refresh') && extra.channel) {
        if (!validChannel(extra.channel)) throw new Error('invalid channel');
        body.channel = extra.channel;
    }
    if (action === 'refresh' && extra.revision !== undefined) {
        if (!/^\d{1,10}$/.test(String(extra.revision))) throw new Error('invalid revision');
        body.revision = Number(extra.revision);
    }
    return snapdRequest('POST', '/v2/snaps/' + encodeURIComponent(name), { body, auth: A() });
}

/** POST /v2/snaps/{name} with {"action":"install"|"remove","components":[c]}
    — installs or removes ONE snap COMPONENT (round 47m). Live-verified
    against snapd 2.77.1: the parent snap is untouched by a component op.
    (client/snap_op.go: Install/Remove(name, components) -> doSnapAction.) */
async function snapComponent(name, action, component) {
    const ALLOWED = new Set(['install', 'remove']);
    if (!validSnapName(name)) throw new Error('invalid snap name');
    if (!ALLOWED.has(action)) throw new Error('component action not permitted: ' + JSON.stringify(action));
    if (typeof component !== 'string' || !/^[\w.-]+$/.test(component) || component.length > 70)
        throw new Error('invalid component name: ' + JSON.stringify(component));
    return snapdRequest('POST', '/v2/snaps/' + encodeURIComponent(name),
        { body: { action, components: [component] }, auth: A() });
}

/* ------------------------------------------------------------------ *
 * 7. Write APIs — configuration (snap conf + netplan network setup)
 *
 * Modern snapd exposes system configuration as per-snap documents:
 * PUT /v2/snaps/{name}/conf (there is no generic /v2/config route in
 * current snapd). On Ubuntu Core the netplan document is the external
 * config key `core.system.network.netplan` — snapd pushes it to the
 * netplan D-Bus service and applies it atomically.
 * ------------------------------------------------------------------ */

/* ---- snap services (chunk 48a) ------------------------------------------
 * LIVE-VERIFIED (snapd 2.77, source @8d4d073 daemon/api_apps.go +
 * overlord/servicestate): the per-snap services and their state come from
 *   GET /v2/apps?select=service&names=<snap> -> [{name, daemon, daemon-scope,
 *     active?, enabled?}] — `active` (running NOW) and `enabled` (start on
 *     boot) are omitempty booleans, present only when true, and only
 *     decorated while the SNAP itself is active (a disabled snap's services
 *     read as neither active nor enabled). A snap without services answers
 *     HTTP 404 {kind:'app-not-found', message:'snap "X" has no services'}
 *     (verified live: the 404 envelope, NOT a 200 + []), which the client
 *     maps to an empty list — not an error.
 * Control is one ASYNC route:
 *   POST /v2/apps {action: start|stop|restart, names:[snap | snap.app],
 *                  enable?: bool, disable?: bool}
 * The daemon accepts ONLY those three actions (route Actions list) — there is
 * NO boot-only enable/disable. Source (servicestate.Control) + live probes:
 *   start  -> starts, keeps boot state
 *   start+enable -> starts AND starts on boot
 *   stop   -> stops, keeps boot state
 *   stop+disable -> stops AND no longer starts on boot
 *   restart (optionally reload) -> restarts, keeps both
 * So "disable for boot" also stops the service and "enable for boot" also
 * starts it — the UI makes that coupling explicit in its confirmations. */
/** GET /v2/apps?select=service&names=<snap> — the snap's services + state. */
async function getSnapServices(name) {
    if (!validSnapName(name)) throw new Error('invalid snap name');
    const p = '/v2/apps?select=service&names=' + encodeURIComponent(name);
    let res;
    try {
        res = await snapdRequest('GET', p, { auth: A() });
    } catch (e) {
        // LIVE: a snap WITHOUT services is a 404 {kind:'app-not-found',
        // message:'snap "X" has no services'} — not an error, just "none".
        // (An unknown snap 404s as kind:'snap-not-found' — still "none".)
        if (e.name === 'SnapdError' && e.status === 404 && (e.kind === 'app-not-found' || e.kind === 'snap-not-found')) return [];
        throw e;
    }
    if (!res || Array.isArray(res)) return res || [];
    if (res.kind === 'app-not-found') return []; // defensive: a 200 + app-not-found shape
    throw new Error('unexpected services response for ' + name);
}

/** POST /v2/apps — service control. action: start|stop|restart; the
    optional enable/disable flags ride on start/stop per the live contract
    (start+enable sets boot, stop+disable clears it). Returns {id}. */
async function controlSnapService(name, app, action, opts = {}) {
    if (!validSnapName(name)) throw new Error('invalid snap name');
    const re = /^[a-z][a-z0-9-]*$/;
    if (app !== null && (typeof app !== 'string' || !re.test(app) || app.length > 70)) {
        throw new Error('invalid service name');
    }
    if (!['start', 'stop', 'restart'].includes(action)) throw new Error('invalid service action: ' + action);
    for (const f of ['enable', 'disable']) {
        if (opts[f] !== undefined && typeof opts[f] !== 'boolean') throw new Error('invalid service flags');
    }
    const body = { action, names: [app === null ? name : name + '.' + app] };
    if (opts.enable) body.enable = true;
    if (opts.disable) body.disable = true;
    return snapdRequest('POST', '/v2/apps', { body, auth: A() });
}

/** GET /v2/snaps/{name}/conf[?keys=...] */
async function getSnapConfig(name, key = null) {
    if (!validSnapName(name)) throw new Error('invalid snap name');
    let p = '/v2/snaps/' + encodeURIComponent(name) + '/conf';
    if (key !== null) {
        if (!RE_CONF_KEY.test(key)) throw new Error('invalid config key');
        p += '?keys=' + encodeURIComponent(key);
    }
    return snapdRequest('GET', p, { auth: A() });
}

/** Round 48f: a config value the UI types in is a plain string, but snapd
 *   (and the snap's configure hook) expect REAL types — `snap set foo=1234`
 *   stores the NUMBER 1234, `snap set on=true` stores the BOOLEAN true. That
 *   inference lives in the `snap` CLI (clientutil.ParseConfigValues: try to
 *   parse the value as JSON, store it as a string if that fails), NOT in the
 *   snapd daemon (which stores whatever JSON the PUT carries). confInferType
 *   mirrors the CLI's DEFAULT mode: JSON numbers and booleans become native;
 *   everything else — plain text, the literal null, and composites like
 *   {…}/[…] (one key=value must stay ONE scalar, so no -t-style JSON objects)
 *   — stays the plain string. */
function confInferType(v) {
    if (typeof v !== 'string') return v;
    let parsed;
    try { parsed = JSON.parse(v); } catch { return v; }
    if (typeof parsed === 'number' || typeof parsed === 'boolean') return parsed;
    return v;
}

/** PUT /v2/snaps/{name}/conf — body must be a flat {key: scalar} map. */
async function setSnapConfig(name, conf) {
    if (!validSnapName(name)) throw new Error('invalid snap name');
    if (!conf || typeof conf !== 'object' || Array.isArray(conf)) throw new Error('config must be an object');
    const body = {};
    for (const [k, v] of Object.entries(conf)) {
        if (!RE_CONF_KEY.test(k)) throw new Error('invalid config key: ' + JSON.stringify(k));
        if (v !== null && typeof v !== 'string' && typeof v !== 'number' && typeof v !== 'boolean') {
            throw new Error('config value for ' + k + ' must be scalar');
        }
        // Infer the type the way `snap set` does (number/bool when the value is
        // valid JSON of that kind; else the plain string). Deletions (v === null)
        // pass through — the CLI sends null for `key!` too.
        body[k] = confInferType(v);
    }
    if (Object.keys(body).length === 0) throw new Error('empty config payload');
    return snapdRequest('PUT', '/v2/snaps/' + encodeURIComponent(name) + '/conf', { body, auth: A() });
}

/** Read the active netplan document as a parsed JS object.
 * snapd's conf GET with ?keys=X returns { "X": <value> } — unwrap it. */
async function getNetplan() {
    const res = await getSnapConfig('core', 'system.network.netplan');
    const cur = (res && typeof res === 'object' && 'system.network.netplan' in res)
        ? res['system.network.netplan'] : res;
    if (typeof cur === 'string') return fromYaml(cur);
    return cur;
}

/* ------------------------------------------------------------------ *
 * 7a. Network SEED boilerplate (the network-setup-control snap interface)
 *
 * Ubuntu Core ships a netplan seed so an unconfigured box has connectivity at
 * first boot: /etc/netplan/00-snapd-config.yaml (snapd writes it with the
 * "00" origin hint), a set of catch-all (match:) rules, e.g.:
 *   ethernets:
 *     all-en:  { dhcp4: true, match: { name: "en*" } }
 *     all-eth: { dhcp4: true, match: { name: "eth*" } }
 *
 * The app writes network config through snapd's netplan external config, which
 * lands in a SEPARATE origin file (90-snapd-config.yaml on a seeded system —
 * snapd configcore/netplan.go: originHint = "90-snapd-config" if seeded else
 * "00-snapd-config"). But snapd's netplan D-Bus Config() snapshot copies ALL
 * of /etc/netplan at apply time, so the 00 seed is re-merged on top of the
 * app's 90 config on every Apply — the catch-alls survive and keep DHCPing
 * every NIC they cover, including ones the user never touched.
 *
 * The fix: after a device edit APPLIES successfully, DELETE the 00 seed file
 * (it is only there for first-boot connectivity; any other interface the user
 * wants DHCP on can then be set up explicitly). network-setup-control grants
 * /etc/netplan rw. The delete is guarded to catch-all (match:) content so a
 * hand-authored 00 file with real named config is never destroyed, and it
 * happens only on a successful apply (a failed/rolled-back Config.Try must
 * leave the box in its original state). The path is injectable so the
 * integration test runs against a temp file (the dev container must not touch
 * the real /etc/netplan).
 * ------------------------------------------------------------------ */
let __netSeedPath = null;
function __setNetSeedPath(p) { __netSeedPath = p; }
function netSeedBoilerplatePath() {
    return __netSeedPath || process.env.UCM_NETPLAN_SEED || '/etc/netplan/00-snapd-config.yaml';
}
/* Remove the seed boilerplate file if (and only if) it is present AND carries
   catch-all (match:) definitions. Synchronous + total (never throws): a
   missing file is a no-op (already cleared, or a box with no netplan dir).
   Returns 'removed' | 'kept' | 'absent'. */
function clearNetSeedBoilerplate() {
    const p = netSeedBoilerplatePath();
    let txt = '';
    try { txt = fs.readFileSync(p, 'utf8'); }
    catch (e) { return 'absent'; }
    // the catch-all signature — a user's own named entry never carries match:
    if (!/match:/.test(txt)) return 'kept';
    try { fs.unlinkSync(p); } catch (e) { return 'kept'; }
    return 'removed';
}
/* ------------------------------------------------------------------ *
 * 7b. Network DEVICES (the network-control snap interface)
 *
 * The Network page's Interfaces section shows every network device with
 * its LIVE state (the kernel truth — what SSH would actually connect
 * with) and edits its netplan definition (the configured truth, applied
 * through snapd's netplan external config, which does Config.Try + a
 * 30s rollback + a store-reachability check before it commits — see
 * snapd configcore/netplan.go).
 *
 * Live state comes from the standard network tools the network-control
 * interface is BUILT around (ip, iw, resolvectl — all in its AppArmor
 * grant, like the ip/sysctl tools):
 *   ip -j link show        -> per device: kind (bridge/bond/...), link_type
 *                             (ether/wireless/...), operstate/flags
 *   ip -j addr show        -> per device: addresses (family+local+prefixlen)
 *   ip -j route show default -> per device: the default-route gateway
 *   iw dev                 -> which devices are Wi-Fi (absent = none)
 *   resolvectl status      -> per device: the DNS servers actually in use
 * (resolvectl has no -o json on older systemd, so a text parser is the
 * canonical path; ip -j is stable JSON.)
 *
 * DNS SOURCE CAVEAT (round 57, the network-control interface bug): the
 * plug grants the resolved D-Bus API only to peers labelled unconfined,
 * and systemd-resolved runs confined on Core — so `resolvectl status`
 * CANNOT reach per-link data under the interface (the snapd team is
 * fixing it; flagged). The nameservice abstraction, however, grants
 * /run/systemd/resolve/resolv.conf rk — the GLOBAL nameserver list.
 * Per device the app therefore reads: (1) the per-link list from
 * resolvectl when it works, else (2) the global resolv.conf list
 * (readResolvConfNameservers) — and a netplan `dns.nameservers` entry
 * for the device ALWAYS wins (netplan binds DNS to the device; the
 * resolv.conf list is system-wide) — mergeNetplanDevices pass 3.
 *
 * Device model (merged per name):
 *   { name, type: 'ethernet'|'wired'|'wifi'|'bridge'|'bond'|'vlan'|'tunnel'|
 *             'vrf'|'dummy'|'veth'|'other',
 *     connected,             // operstate/flags
 *     addresses: [{ family, cidr }],  // live (all families, scope!=link)
 *     members,               // live bridge members (the master field; [] otherwise)
 *     gateway,               // live default-route via (string|null)
 *     dns,                   // live DNS servers (string[] — resolvectl
 *                            // per-link, else the global resolv.conf;
 *                            // merge pass 3: netplan dns wins)
 *     dnsGlobal,             // the global resolv.conf nameservers (string[])
 *     configured,            // has a netplan definition (bool)
 *     netplan, }             // the netplan definition object (or null)
 *
 * The CARD LIST IS THE KERNEL TRUTH + the user's pending adds — never the
 * netplan document. Netplan entries that name no live device (catch-all
 * directives like "all:", stale or failed entries) must not face the user;
 * netplan stays a backend document. An enslaved link (ip link's `master`
 * field, e.g. a NIC bridged into br0) is a MEMBER — it shows on the bridge
 * card's Members row, not as its own card.
 *
 * Applying: netApplyDevice(cfg) builds the device's netplan entry
 * (ethernets|wifis|bridges, v2 canonical fields: dhcp4/addresses/
 * gateway4/dns.nameservers; wifis + access-points; bridges + interfaces)
 * and PUTs the FULL document through the existing core conf bridge.
 * ------------------------------------------------------------------ */
const RE_NET_NAME = /^[A-Za-z][A-Za-z0-9._:-]{0,15}$/;

/* Injectable live readers — the integration test uses canned outputs (the
   tools' absence / the confined path are dev-container realities). */
let __netLive = null;
function __setNetLive(fns) { __netLive = fns; }
async function netRunLive(fn) {
    if (__netLive && __netLive[fn]) return __netLive[fn]();
    const { execFile } = require('child_process');
    return new Promise((resolve) => {
        const args = LIVE_TOOLS[fn];
        execFile(args[0], args.slice(1), { encoding: 'utf8', timeout: 8000 }, (err, stdout) => {
            resolve({ ok: !err, stdout: stdout || '' });
        });
    });
}
const LIVE_TOOLS = {
    link: ['ip', '-j', 'link', 'show'],
    addr: ['ip', '-j', 'addr', 'show'],
    route: ['ip', '-j', 'route', 'show', 'default'],
    iw: ['iw', 'dev'],
    dns: ['resolvectl', 'status'],
};

/* Round 57: the GLOBAL nameserver list from the resolved-managed
   resolv.conf — the workaround for the network-control interface bug
   (resolvectl status cannot reach systemd-resolved under the plug: the
   resolved D-Bus grants target peers labelled unconfined, resolved runs
   confined on Core; the interface bug is flagged with the snapd team).
   The nameservice abstraction grants /run/systemd/resolve/resolv.conf
   rk, and the file lists every uplink nameserver. It is SYSTEM-WIDE
   (no per-link data), so it is a fallback: the per-link resolvectl list
   wins when it works, and a netplan dns.nameservers entry for the
   device wins over both (netplan binds DNS to the device).
   Pure + total: missing/unreadable file -> [] (never throws). */
let __resolvConfPath = null;
function __setResolvConfPath(p) { __resolvConfPath = p; }
function readResolvConfNameservers() {
    const p = __resolvConfPath || process.env.UCM_RESOLV_CONF || '/run/systemd/resolve/resolv.conf';
    let txt;
    try { txt = fs.readFileSync(p, 'utf8'); } catch { return []; }
    const out = [];
    for (const line of txt.split('\n')) {
        const m = line.match(/^nameserver\s+(\S+)/);
        if (!m) continue;
        const a = m[1].trim();
        if (!a) continue;
        if (!out.includes(a)) out.push(a);
    }
    return out;
}

function netLinkType(kind, linkType) {
    if (kind === 'bridge') return 'bridge';
    if (kind === 'bond') return 'bond';
    if (kind === 'veth') return 'veth';
    if (kind === 'dummy') return 'dummy';
    if (kind === 'vrf') return 'vrf';
    if (kind === 'tun' || kind === 'tap' || kind === 'gre' || kind === 'ip6tnl' || kind === 'sit' || kind === 'erspan' || kind === 'vti' || kind === 'vti6' || kind === 'ipip') return 'tunnel';
    if (linkType === 'vlan' || kind === 'vlan') return 'vlan';
    if (linkType === 'wireless') return 'wifi';
    if (linkType === 'ether') return 'ethernet';
    return kind ? 'other' : 'ethernet'; // a bare physical NIC
}

/* Parse the five live sources into the merged per-device model. Pure over
   its inputs (the readers are injectable), so unit-testable with canned
   tool output. */
async function listNetDevices() {
    const [linkR, addrR, routeR, iwR, dnsR] = await Promise.all([
        netRunLive('link'), netRunLive('addr'), netRunLive('route'), netRunLive('iw'), netRunLive('dns')]);
    const links = (linkR.ok && linkR.stdout) ? (JSON.parse(linkR.stdout) || []) : [];
    const addrs = (addrR.ok && addrR.stdout) ? (JSON.parse(addrR.stdout) || []) : [];
    const routes = (routeR.ok && routeR.stdout) ? (JSON.parse(routeR.stdout) || []) : [];
    const wifi = new Set();
    if (iwR.ok && iwR.stdout) {
        // "Device wlan0 [stacked]"
        for (const m of iwR.stdout.matchAll(/^Device\s+(\S+)/gm)) wifi.add(m[1]);
    }
    // resolvectl status (text):  "Link 28 (eth0)" ... "       DNS Servers: a b c"
    const dnsBy = {};
    if (dnsR.ok && dnsR.stdout) {
        let cur = null;
        for (const line of dnsR.stdout.split('\n')) {
            const h = line.match(/^Link\s+\d+\s+\(([^)]+)\)/);
            if (h) { cur = h[1]; dnsBy[cur] = []; continue; }
            const d = line.match(/^\s+DNS Servers:\s+(.*)$/);
            if (d && cur) {
                // resolved prints "n/a" for a link with no DNS — that is
                // the ABSENCE of servers, not a server.
                const servers = d[1].trim().split(/\s+/).filter((x) => x && x !== 'n/a');
                if (servers.length) dnsBy[cur] = servers;
            }
        }
    }
    // live bridge membership: ip -j link show carries a `master` field on
    // every enslaved link (verified: a dummy set into a bridge reports
    // "master":"br0"). Enslaved links are members of that device, not cards.
    const membersByMaster = {};
    for (const l of links) {
        if (l.ifname && l.ifname !== 'lo' && l.master) (membersByMaster[l.master] = membersByMaster[l.master] || []).push(l.ifname);
    }
    // round 57: the global nameserver list (fallback source for the
    // per-device dns when resolvectl has no per-link data — see
    // readResolvConfNameservers).
    const dnsGlobal = readResolvConfNameservers();
    const devices = [];
    for (const l of links) {
        if (!l.ifname || l.ifname === 'lo') continue; // loopback is not a card
        if (l.master) continue; // enslaved (bridge/bond/vrf member) — a member, not a card
        const kind = l.kind || null;
        const type = wifi.has(l.ifname) ? 'wifi' : netLinkType(kind, l.linkType);
        const up = (l.flags || []).includes('UP') || (l.flags || []).includes('LOWER_UP');
        const addresses = [];
        const a = (addrs.find((x) => x.ifname === l.ifname) || {});
        for (const ai of (a.addr_info || [])) {
            if (ai.family === 'inet' || ai.family === 'inet6') {
                if (ai.scope === 'link' && ai.family === 'inet6') continue; // not displayable
                addresses.push({ family: ai.family, cidr: ai.local + '/' + ai.prefixlen });
            }
        }
        const gw = routes.find((r) => r.dev === l.ifname);
        const liveDns = dnsBy[l.ifname];
        devices.push({
            name: l.ifname, type, connected: !!up, addresses,
            members: type === 'bridge' ? (membersByMaster[l.ifname] || []) : [],
            mac: (typeof l.address === 'string' && l.address) ? l.address.toLowerCase() : null,
            gateway: (gw && gw.gateway) || null,
            // round 57: per-link DNS wins when the parse produced a
            // list for this link (the parser pre-seeds every link header
            // with [], so an empty list means "no data"). Under the
            // network-control interface bug, resolvectl CANNOT read per-link
            // data on Core (resolved runs confined; the plug D-Bus
            // grants target unconfined peers), so fall back to the
            // GLOBAL nameserver list from the resolved-managed
            // resolv.conf (the nameservice grant). A netplan
            // dns.nameservers entry for the device wins over both
            // (mergeNetplanDevices pass 3).
            dns: (liveDns && liveDns.length) ? liveDns : dnsGlobal,
            dnsGlobal,
            configured: false, netplan: null,
        });
    }
    return devices;
}

/* netplan `match:` (catch-all directive) semantics — source-verified in
   libnetplan (netplan_netdef_match_interface): a definition with NO match:
   matches ONLY its own id; one WITH a match: matches when every specified
   property fits (name = fnmatch GLOB, macaddress, driver). These helpers
   replicate that for the physical properties this app can see live
   (name + mac — the driver needs /sys, which no snap plug grants). */
function netGlobMatch(pattern, name) {
    if (typeof pattern !== 'string' || !pattern) return false;
    if (!/[*?[]/.test(pattern)) return pattern === name; // no glob chars: exact
    let re = '';
    for (let i = 0; i < pattern.length; i++) {
        const c = pattern[i];
        if (c === '*') re += '.*';
        else if (c === '?') re += '.';
        else if (c === '[') {
            const end = pattern.indexOf(']', i + 1);
            if (end > i) {
                let inner = pattern.slice(i + 1, end);
                if (inner[0] === '!') inner = '^' + inner.slice(1);
                re += '[' + inner + ']';
                i = end;
            } else re += '\\[';
        }
        else if (c === '\\' || '.+^()|{}$'.includes(c)) re += '\\' + c;
        else re += c;
    }
    return new RegExp('^' + re + '$').test(name);
}
function netDefMatches(def, name, mac) {
    const m = (def && typeof def.match === 'object' && def.match) ? def.match : null;
    if (!m) return false; // a named definition matches only its own id (name-keyed)
    if (m.name != null) {
        const pats = Array.isArray(m.name) ? m.name : [m.name];
        if (!pats.some((p) => netGlobMatch(String(p), name))) return false;
    }
    if (m.macaddress != null) {
        if (!mac) return false;
        const pats = Array.isArray(m.macaddress) ? m.macaddress : [m.macaddress];
        if (!pats.some((p) => String(p).toLowerCase() === mac)) return false;
    }
    // driver: not live-visible (needs /sys) — a match carrying a driver
    // constraint can never be evaluated here, so it does not match.
    if (m.driver != null) return false;
    return true;
}

/* Merge the netplan document's definitions over the live device list:
   pass 1 — configured=true + the netplan entry for names the doc defines.
   A netplan entry with NO live device creates NO card (catch-all
   directives like "all:", stale entries — netplan is a backend document,
   the card list is the kernel truth + the user's pending adds). A bridge
   the user created via "Add bridge" becomes a card when the kernel has it
   (after snapd applies the netplan), not before.
   pass 2 — catch-all (match:) overlay: a live device with NO named entry
   that a match: definition covers is still netplan-CONFIGURED (the default
   Core seed configures en* NICs via "all-en": {match: {name: en*}}) — the
   card shows the catch-all's values and the device's first edit starts
   from them. A named entry always wins (pass 1). */
function mergeNetplanDevices(devices, doc) {
    const net = (doc && doc.network) || {};
    const sections = ['ethernets', 'wifis', 'bridges', 'bonds', 'vlans'];
    const by = new Map(devices.map((d) => [d.name, d]));
    for (const sec of sections) {
        const m = net[sec];
        if (!m || typeof m !== 'object') continue;
        for (const [name, def] of Object.entries(m)) {
            if (!RE_NET_NAME.test(name)) continue;
            const d = by.get(name);
            if (d) { d.configured = true; d.netplan = def; }
            // no live device -> no card (see the docstring)
        }
    }
    // pass 2 — the catch-all (match:) overlay.
    for (const d of devices) {
        if (Object.prototype.hasOwnProperty.call(d, 'netplan') && d.netplan) continue;
        for (const sec of sections) {
            const m = net[sec];
            if (!m || typeof m !== 'object') continue;
            for (const [name, def] of Object.entries(m)) {
                if (name === d.name) continue; // same-id defs are pass 1's job (named win)
                if (!netDefMatches(def, d.name, d.mac)) continue;
                d.configured = true;
                d.netplan = def;
                if (sec === 'wifis') d.type = 'wifi';
                else if (sec === 'bridges' && d.type !== 'wifi') d.type = 'bridge';
                else if (sec === 'bonds' && d.type !== 'wifi') d.type = 'bond';
                else if (sec === 'vlans') d.type = 'vlan';
                break;
            }
            if (d.configured) break;
        }
    }
    // pass 3 (round 57) — the netplan DNS overlay: netplan binds DNS to
    // the DEVICE (there are no system-wide DNS settings), so a named or
    // catch-all definition carrying dns.nameservers IS this device's
    // configured resolver and wins over the live fallback (the
    // resolv.conf global list; when resolvectl works, the per-link list
    // already mirrors it — resolved applies per-link from netplan).
    for (const d of devices) {
        if (!d.netplan) continue;
        const ns = d.netplan.dns && d.netplan.dns.nameservers && d.netplan.dns.nameservers.addresses;
        if (Array.isArray(ns) && ns.length) d.dns = ns.map((x) => String(x)).filter(Boolean);
    }
    // type refinement: a netplan wifis entry wins over the kernel guess, and
    // a bridges/bonds/vlans entry sets the type even for a live link.
    for (const sec of sections) {
        const m = net[sec];
        if (!m || typeof m !== 'object') continue;
        for (const name of Object.keys(m)) {
            const d = by.get(name);
            if (!d) continue;
            if (sec === 'wifis') d.type = 'wifi';
            else if (sec === 'bridges' && d.type !== 'wifi') d.type = 'bridge';
            else if (sec === 'bonds' && d.type !== 'wifi') d.type = 'bond';
            else if (sec === 'vlans') d.type = 'vlan';
        }
    }
    return devices;
}

/* ---- the netplan doc builder (pure) ------------------------------------
   cfg = { name, type: 'ethernet'|'wifi'|'bridge',
           mode: 'dhcp'|'static', address?, gateway?, dns?,
           ssid?, password?, hidden?,
           interfaces? }
   Returns { section, def } (section = the doc's device-type key). v1 scope:
   IPv4 addressing only (DHCP or a static address+gateway+DNS); Wi-Fi is
   WPA-PSK (access-points); bridges carry a member list. The def uses the
   CANONICAL netplan v2 fields (netplan-yaml.md) — addresses/gateway4/dns.
   nameservers — NOT the old round-1 ipv4.gateway4 shape. */
function buildNetDeviceDef(cfg) {
    if (!cfg || typeof cfg !== 'object') throw new Error('network config payload required');
    if (typeof cfg.name !== 'string' || !RE_NET_NAME.test(cfg.name)) {
        throw new Error('invalid device name: ' + JSON.stringify(cfg.name));
    }
    const def = {};
    const staticPart = () => {
        if (typeof cfg.address !== 'string' || !RE_IPV4_CIDR.test(cfg.address)) {
            throw new Error('IPv4 address must carry a /prefix (e.g. 192.168.1.50/24)');
        }
        def.addresses = [cfg.address];
        if (cfg.gateway) {
            if (!RE_IPV4.test(cfg.gateway)) throw new Error('gateway must be a bare IPv4 address');
            def.gateway4 = cfg.gateway;
        }
    };
    const dnsPart = () => {
        if (cfg.dns) {
            const d = (Array.isArray(cfg.dns) ? cfg.dns : [cfg.dns]).map((x) => String(x).trim()).filter(Boolean);
            if (!d.length) throw new Error('DNS servers list is empty');
            for (const x of d) if (!(RE_IPV4.test(x) || /^[0-9a-f:.]+$/i.test(x))) throw new Error('invalid DNS address: ' + x);
            if (d.length) def.dns = { nameservers: { addresses: d } };
        }
    };
    if (cfg.type === 'bridge') {
        const members = Array.isArray(cfg.interfaces) ? cfg.interfaces.map((x) => String(x).trim()).filter(Boolean) : [];
        for (const x of members) if (!RE_NET_NAME.test(x)) throw new Error('invalid bridge member: ' + x);
        def.interfaces = members;
        if (cfg.mode === 'static') staticPart(); else def.dhcp4 = true;
        dnsPart();
        return { section: 'bridges', def };
    }
    if (cfg.type === 'wifi') {
        if (typeof cfg.ssid !== 'string' || !cfg.ssid.trim() || cfg.ssid.length > 32) {
            throw new Error('a Wi-Fi network name (SSID) is required');
        }
        const ap = {};
        const pw = (cfg.password == null) ? '' : String(cfg.password);
        if (pw) {
            if (pw.length < 8 || pw.length > 64) throw new Error('the Wi-Fi password must be 8-64 characters');
            ap.password = pw;
        }
        if (cfg.hidden === true) ap.hidden = true;
        def['access-points'] = { [cfg.ssid.trim()]: ap };
        if (cfg.mode === 'static') staticPart(); else def.dhcp4 = true;
        dnsPart();
        return { section: 'wifis', def };
    }
    if (cfg.type !== 'ethernet') throw new Error('unknown device type: ' + cfg.type);
    if (cfg.mode === 'static') staticPart(); else def.dhcp4 = true;
    dnsPart();
    return { section: 'ethernets', def };
}

/* Apply ONE device's netplan definition: read the current full doc, REPLACE
   just this device's entry in its section (delete it from the others), write
   the whole document back through the core conf bridge. snapd hands it to
   netplan with Config.Try + 30s rollback + store-reachability guard. */
async function netApplyDevice(cfg) {
    const { section, def } = buildNetDeviceDef(cfg);
    // The netplan option is a JSON OBJECT, not a string (source-verified
    // snapd configcore/netplan.go: the SET path tr.Get()s the option into a
    // map[string]any and json.Marshals it to netplan — a YAML string would
    // fail the option decode; the GET path returns the option as the parsed
    // object, e.g. {"network":{...}} — exactly `snap get -d core
    // system.network.netplan.network`). getNetplan() unwraps the conf
    // response and keeps legacy YAML strings parsed.
    const cur = await getNetplan();
    const SECS = ['ethernets', 'wifis', 'bridges', 'bonds', 'vlans'];
    const curNet = (cur && yamlIsMap(cur.network)) ? cur.network : {};
    // BOILERPLATE RULE (user directive, round 55): a catch-all (match:)
    // definition is snapd/console-conf SEED boilerplate ("any en*/eth* NIC ->
    // DHCP"), NOT user configuration — and it silently configures EVERY NIC
    // it covers. So no catch-all ever survives an edit: strip all match:
    // definitions, keep only the NAMED (user's own) entries, then apply this
    // device. Consequences: a pure seed doc is thereby replaced COMPLETELY
    // by the first edit (snapd's own writer "always starts with a clean
    // config" — the new doc is {version: 2} + this device), and a doc that
    // already names devices keeps those entries while the seed catch-alls
    // go. The rule does not depend on how the doc was read (object vs legacy
    // string) — it is shape-agnostic.
    const doc = { network: JSON.parse(JSON.stringify(curNet)) };
    for (const sec of SECS) {
        const m = doc.network[sec];
        if (!yamlIsMap(m)) continue;
        for (const [id, d] of Object.entries(m)) {
            if (d && typeof d === 'object' && typeof d.match === 'object') delete m[id];
        }
        if (Object.keys(m).length === 0) delete doc.network[sec];
    }
    if (!doc.network.version) doc.network.version = 2;
    // this device leaves its other sections (it may have moved type)
    for (const sec of SECS) if (yamlIsMap(doc.network[sec])) delete doc.network[sec][cfg.name];
    if (!yamlIsMap(doc.network[section])) doc.network[section] = {};
    doc.network[section][cfg.name] = def;
    // drop sections that ended up empty (keeps the doc tidy, netplan-valid)
    for (const sec of SECS) {
        if (yamlIsMap(doc.network[sec]) && Object.keys(doc.network[sec]).length === 0) delete doc.network[sec];
    }
    // A plain object body — NOT setSnapConfig (that bridge scalar-encodes
    // values and cannot carry a nested document) and NOT a YAML string.
    return snapdRequest('PUT', '/v2/snaps/core/conf', { body: { 'system.network.netplan': doc }, auth: A() });
}

/* Read the live device list merged with the netplan definitions. */
async function getNetDevices() {
    const devices = await listNetDevices();
    let doc = null;
    try { doc = await getNetplan(); } catch { doc = null; }
    return mergeNetplanDevices(devices, doc);
}

/* ------------------------------------------------------------------ *
 * 8. Timesync / NTP (the timeserver-control snap interface)
 *
 * The Network "Sync time from internet" row wires to snapd's timeserver-control
 * interface (core slot). That interface grants, via AppArmor:
 *   - org.freedesktop.timedate1.SetNTP(bool)        -> enable/disable NTP (LIVE)
 *   - org.freedesktop.DBus.Properties.Get/GetAll     -> read NTP state
 *   - rw /etc/systemd/timesyncd.conf                 -> set the NTP server
 *     (note: timesyncd only picks up a server change after it restarts/reboots)
 *
 * D-Bus is the canonical mechanism (timedatectl set-ntp is just a wrapper over
 * SetNTP, per the interface's own profile). The D-Bus call uses dbus-next; it is
 * a LAZY require (only on the real path) so the plain-node integration test and
 * the puppeteer harness never touch it — they inject a transport / use the mock.
 * ------------------------------------------------------------------ */
const TIMESYNC_CONF_DEFAULT = '/etc/systemd/timesyncd.conf';
function timesyncConfPath() { return process.env.UCM_TIMESYNC_CONF || TIMESYNC_CONF_DEFAULT; }

/* The transport is injectable so the integration test can run without a live
   system bus: __setTimesyncTransport(fn) where fn(spec) -> Promise<body array>. */
let __timesyncTransport = null;
function __setTimesyncTransport(fn) { __timesyncTransport = fn; }
function timesyncTransport(spec) {
    if (__timesyncTransport) return __timesyncTransport(spec);
    const { systemBus, Message, MessageType } = require('dbus-next');
    const bus = systemBus();
    const msg = new Message(Object.assign({}, spec, { type: MessageType.METHOD_CALL }));
    return bus.call(msg).then((r) => (r && r.body) || []);
}
/* dbus-next returns structured values as Variant {signature, value}; unwrap. */
function unwrapVariant(v) {
    return (v && typeof v === 'object' && 'value' in v && 'signature' in v) ? v.value : v;
}
const TIME_DATE_DEST = 'org.freedesktop.timedate1';
const TIME_DATE_PATH = '/org/freedesktop/timedate1';
const TIME_DATE_IFACE = 'org.freedesktop.timedate1';

/* Read the live NTP on/off. The property name varies by systemd version:
   NTPEnabled (systemd >= ~240) with NTP as an alias (older). Read whichever
   is present so it is correct on both the dev box and the Core 24 VM. */
async function timesyncNtpEnabled() {
    const body = await timesyncTransport({ destination: TIME_DATE_DEST, path: TIME_DATE_PATH,
        interface: 'org.freedesktop.DBus.Properties', member: 'GetAll', signature: 's', body: [TIME_DATE_IFACE] });
    const props = (body && body[0]) || {};
    if ('NTPEnabled' in props) return unwrapVariant(props.NTPEnabled);
    if ('NTP' in props) return unwrapVariant(props.NTP);
    return null;
}
/* Enable/disable NTP synchronously (SetNTP has no return / no async change).
   Signature is (use_ntp: b, interactive: b) — "bb" (verified by live bus
   introspection of org.freedesktop.timedate1). The 2nd arg is the polkit
   "interactive" flag; a privileged snap calls it non-interactively (false),
   and the timeserver-control interface grants SetNTP directly (no polkit). */
async function timesyncSetNtp(enabled) {
    await timesyncTransport({ destination: TIME_DATE_DEST, path: TIME_DATE_PATH,
        interface: TIME_DATE_IFACE, member: 'SetNTP', signature: 'bb', body: [ !!enabled, false ] });
}

/* ---- the timesyncd.conf NTP= line (pure helpers, unit-testable) -----------
   timesyncd reads [Time] NTP=<server>. We rewrite that ONE line (keeping the
   rest of the file, including comments, verbatim). */
function parseTimesyncNtp(text) {
    if (!text) return null;
    const m = String(text).split(/\r?\n/).find((l) => /^NTP=/.test(l));
    if (!m) return null;
    const v = m.replace(/^NTP=/, '').trim();
    return v || null;
}
function formatTimesyncNtp(text, server) {
    // Replace the NTP= line, keeping exactly one. The shipped timesyncd.conf
    // carries a commented "#NTP=" as its designated slot, so: rewrite an
    // uncommented NTP= if present, else the commented #NTP=, else append.
    // A single trailing newline (as in a real file) is preserved.
    let raw = String(text == null ? '' : text);
    const hadTrailingNL = raw.endsWith('\n');
    let lines = raw.split(/\r?\n/);
    if (lines.length && lines[lines.length - 1] === '') lines.pop(); // drop the trailing empty
    let activeIdx = -1, commentIdx = -1;
    lines.forEach((l, i) => {
        if (activeIdx === -1 && /^NTP=/.test(l)) activeIdx = i;
        else if (commentIdx === -1 && /^#\s*NTP=/.test(l)) commentIdx = i;
    });
    const at = activeIdx !== -1 ? activeIdx : commentIdx;
    const line = server ? ('NTP=' + String(server)) : '#NTP='; // clear -> commented (distro default)
    if (at !== -1) lines[at] = line; else lines.push(line);
    let out = lines.join('\n');
    if (hadTrailingNL) out += '\n';
    return out;
}

/* High-level API used by the IPC handlers (and exported for the unit test). */
async function timesyncStatus() {
    let server = null;
    try { server = parseTimesyncNtp(fs.readFileSync(timesyncConfPath(), 'utf8')); } catch { server = null; }
    let ntp = null;
    try { ntp = await timesyncNtpEnabled(); } catch { ntp = null; }
    return { ntp: ntp === null ? null : !!ntp, server: server || null };
}
async function timesyncSetEnabled(enabled) {
    if (typeof enabled !== 'boolean') throw new Error('timesync enabled must be a boolean');
    await timesyncSetNtp(enabled);
}
async function timesyncSetServer(server) {
    server = (server == null ? '' : String(server)).trim();
    if (server.length > 255) throw new Error('timeserver address too long');
    if (/\n/.test(server)) throw new Error('timeserver address is invalid');
    const cur = fs.readFileSync(timesyncConfPath(), 'utf8');
    fs.writeFileSync(timesyncConfPath(), formatTimesyncNtp(cur, server), { mode: 0o644 });
}

/* ------------------------------------------------------------------ *
 * 8b. IP forwarding (the network-control snap interface)
 *
 * The Network "IP forwarding" row flips the kernel's IPv4 + IPv6 forwarding
 * switches. There is NO core.* snapd option for it (checked the full list,
 * round 49b) and no D-Bus surface — the sanctioned mechanism is the sysctl
 * nodes, which the network-control interface grants to a strict snap:
 *   @{PROC}/sys/net/ipv{4,6}/** rw   (source @8d4d073 interfaces/builtin/
 *                                      network_control.go)
 * The nodes are root-writable files, so a plain fs.write flips them — no
 * shell-out, no /etc (the app's standing rule). The /proc state does NOT
 * survive a reboot (kernel default, usually 0), so the user's choice is
 * persisted in $SNAP_COMMON/ipforward.pref and RE-APPLIED on app startup
 * (whenReady -> ipfwdApplyPref): the console is the kiosk's primary UI and
 * is up from boot.
 * ------------------------------------------------------------------ */
const IPFWD_NODES = {
    v4: '/proc/sys/net/ipv4/ip_forward',
    v6: '/proc/sys/net/ipv6/conf/all/forwarding',
    v6default: '/proc/sys/net/ipv6/conf/default/forwarding', // new interfaces inherit
};
function ipfwdPrefPath() {
    return process.env.UCM_IPFWD_PREF || (stateDir() ? path.join(stateDir(), 'ipforward.pref') : null);
}
/* Injectable node paths — the integration test uses temp files (the dev
   container cannot exercise the real /proc nodes under confinement). */
let __ipfwdNodes = null;
function __setIpfwdNodes(n) { __ipfwdNodes = n; }
function ipfwdNodePaths() { return __ipfwdNodes || IPFWD_NODES; }
function ipfwdReadNode(p) {
    try { return fs.readFileSync(p, 'utf8').trim() === '1'; } catch { return null; }
}
function ipfwdPrefRead() {
    const p = ipfwdPrefPath();
    if (!p) return false;
    try { return fs.readFileSync(p, 'utf8').trim() === 'on'; } catch { return false; }
}
function ipfwdPrefWrite(on) {
    const p = ipfwdPrefPath();
    if (!p) return; // dev mode (no $SNAP_COMMON / state dir) — nothing durable
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, on ? 'on' : 'off', { mode: 0o600 });
}
async function ipfwdStatus() {
    const n = ipfwdNodePaths();
    const v4 = ipfwdReadNode(n.v4);
    const v6 = ipfwdReadNode(n.v6);
    return { v4, v6, on: (v4 === null || v6 === null) ? null : (v4 && v6), pref: ipfwdPrefRead() };
}
async function ipfwdSet(on) {
    if (typeof on !== 'boolean') throw new Error('ip forwarding must be a boolean');
    const n = ipfwdNodePaths();
    for (const p of Object.values(n)) {
        try { fs.writeFileSync(p, on ? '1' : '0'); }
        catch (e) { throw new Error('cannot write ' + p + ' (is the network-control interface connected?) — ' + e.message); }
    }
    ipfwdPrefWrite(on);
}
/* Re-apply the stored preference at boot. Only ever turns forwarding ON —
   turning it OFF is an explicit user action, so a stale pref can never
   surprise the user with a disabled path. Failures are non-fatal (the plug
   may not be connected, or the nodes unreadable in dev). */
async function ipfwdApplyPref() {
    try {
        if (ipfwdPrefRead()) await ipfwdSet(true);
    } catch (e) { console.error('ip forwarding boot-apply failed:', e.message); }
}

/* ------------------------------------------------------------------ *
 * 9. Interfaces (plug/slot control)
 * ------------------------------------------------------------------ */

const RE_PLUG_SLOT = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)?$/;

// snapd plug/slot references serialize as {snap, plug} / {snap, slot}.
function validPlugRef(ref) {
    return ref && typeof ref === 'object'
        && typeof ref.snap === 'string' && validSnapName(ref.snap)
        && typeof ref.plug === 'string' && RE_PLUG_SLOT.test(ref.plug);
}

function validSlotRef(ref) {
    return ref && typeof ref === 'object'
        && typeof ref.snap === 'string' && validSnapName(ref.snap)
        && typeof ref.slot === 'string' && RE_PLUG_SLOT.test(ref.slot);
}

/**
 * GET /v2/interfaces — the FULL plug/slot topology.
 * LIVE-VERIFIED against snapd 2.77 (this container's daemon):
 *   result = { plugs:[p], slots:[s] }
 *   p = { snap, plug, interface, apps:[...], connections: [{snap,slot},...] | null }
 *   s = { snap, slot, interface, connections: [{snap,plug},...] | null }
 * Connections are NULL (not [] — the Go struct is omitempty) when an endpoint
 * has none, and the endpoint carries NO established/undesired/manual/gadget
 * keys at all (that is the legacy /v2/connections shape, which — worse — only
 * lists plugs/slots that HAVE connections, so it cannot answer "what is
 * unconnected"). The UI derives connected/unconnected purely from `connections`
 * and never branches on the legacy fields.
 */
async function listInterfaces() {
    return snapdRequest('GET', '/v2/interfaces', { auth: A() });
}

/**
 * POST /v2/interfaces — LIVE-VERIFIED (snapd 2.77): the daemon decodes
 * {action, plugs:[{snap,plug}], slots:[{snap,slot}]} (client/
 * interfaces.go InterfaceAction). The SINGULAR {plug, slot} form is
 * REJECTED with 400 "at least one plug and slot is required" — the old
 * code sent that, so every Connect/Disconnect button was a silent no-op
 * that surfaced a raw 400. The write is ASYNC: 202 with the change id at
 * the envelope top level (result null); the topology only settles when
 * the change completes, so the renderer must waitChangeSettled().
 */
async function connectInterface(plug, slot) {
    if (!validPlugRef(plug)) throw new Error('invalid plug reference');
    if (!validSlotRef(slot)) throw new Error('invalid slot reference');
    return snapdRequest('POST', '/v2/interfaces', {
        body: { action: 'connect', plugs: [plug], slots: [slot] },
        auth: A(),
    });
}

/** POST /v2/interfaces {action:"disconnect", plugs:[...], slots:[...]}. */
async function disconnectInterface(plug, slot) {
    if (!validPlugRef(plug)) throw new Error('invalid plug reference');
    if (!validSlotRef(slot)) throw new Error('invalid slot reference');
    return snapdRequest('POST', '/v2/interfaces', {
        body: { action: 'disconnect', plugs: [plug], slots: [slot] },
        auth: A(),
    });
}

/* ------------------------------------------------------------------ *
 * 9. Host diagnostics (read-only /proc + Node os module, no shell-outs)
 * ------------------------------------------------------------------ */

function readHostStats() {
    const out = { hostname: os.hostname(), platform: os.platform(), arch: os.arch() };
    try {
        const load = os.loadavg();
        const total = os.totalmem();
        const free = os.freemem();
        out.mem = {
            total,
            available: free,
            used: total - free,
            usedPercent: total ? Math.round(((total - free) / total) * 1000) / 10 : 0,
        };
        out.load = [load[0], load[1], load[2]];
        out.uptimeSec = Math.floor(os.uptime());
        out.cpus = os.cpus().length;
        try {
            out.swap = (() => {
                const m = String(fs.readFileSync('/proc/meminfo', 'utf8'))
                    .match(/SwapTotal:\s+(\d+) kB[\s\S]*?SwapFree:\s+(\d+) kB/);
                return m ? { total: Number(m[1]) * 1024, free: Number(m[2]) * 1024 } : null;
            })();
        } catch { out.swap = null; }
    } catch { out.mem = null; }
    return out;
}

/* /proc/stat cumulative jiffies for the aggregate cpu line + previous
 * sample. Module-level state: the main process is the only sampler, and
 * the deltas are computed here (renderer never sees raw counters). */
const CPU_SAMPLES = 100;      // history window the sparkline draws (2 s cadence => 3 min)
let cpuPrev = null;           // { idle, total } jiffies at last sample

function cpuTimes() {
    const line = String(fs.readFileSync('/proc/stat', 'utf8')).split('\n')[0]; // 'cpu  u n s i idle iowait irq softirq steal ...'
    const f = line.trim().split(/\s+/).slice(1).map(Number);
    const idle = (f[3] || 0) + (f[4] || 0);           // idle + iowait
    const total = f.reduce((a, b) => a + (b || 0), 0);
    return { idle, total };
}

function readCpuUtilization() {
    const cur = cpuTimes();
    let now = null; // null = boot baseline, no delta computable yet
    if (cpuPrev) {
        const di = cur.idle - cpuPrev.idle;
        const dt = cur.total - cpuPrev.total;
        // 0..100, two decimals; dt===0 only in a fully frozen system.
        now = dt > 0 ? Math.min(100, Math.max(0, (1 - di / dt) * 100)) : 0;
        now = Math.round(now * 100) / 100;
    }
    cpuPrev = cur;
    // ring buffer (module state): oldest -> newest, capped at CPU_SAMPLES.
    // A copy is returned so the IPC layer serializes plain data only.
    readCpuUtilization.buf = (readCpuUtilization.buf || []).concat(now).slice(-CPU_SAMPLES);
    return readCpuUtilization.buf.slice();
}

/**
 * Data partition: on Ubuntu Core the user-writable storage is the
 * /run/mnt/data overlay mount — the space that actually matters to the
 * operator (the read-only / rootfs is not usable capacity).
 *
 * Source of truth: statfs(2) on the mount point (via Node's
 * fs.promises.statfs — the same syscall df(1) uses), with the mount's
 * device + fs type read from /proc/mounts. /proc/diskstats is NOT a
 * source here (I/O counters only, no capacity), and mount-observe
 * grants /proc/mounts reads (verified against snapd's builtin
 * mount-observe interface: @{PROC}/mounts r + statmount/listmount;
 * it does not list /proc/diskstats).
 *
 * Returns:
 *   { mount: '/run/mnt/data', device, fsType, totalBytes, freeBytes
 *     (user-usable = bavail), usedBytes, reservedBytes (root-only
 *     headroom = bfree - bavail), usedPercent (1 dp),
 *     source: 'data'|'root' }
 * Falls back to '/' when /run/mnt/data is not mounted (classic dev
 * container); null when statfs itself fails.
 */
const DATA_MOUNT = '/run/mnt/data';

function mountsTable() {
    try {
        return String(fs.readFileSync('/proc/mounts', 'utf8'))
            .split('\n').map((l) => l.trim().split(/\s+/))
            .filter((f) => f.length >= 3);
    } catch { return []; }
}

async function getDataPartition() {
    const row = (want) =>
        mountsTable().find((f) => f[1] === want) ||
        mountsTable().find((f) => f[1] === want + '/');
    const want = row(DATA_MOUNT) ? DATA_MOUNT : '/';
    let st;
    try { st = await fs.promises.statfs(want); } catch { return null; }
    const r = row(want) || [];
    const total = st.bsize * st.blocks;
    const free = st.bsize * st.bavail;         // usable by the user (df "Avail")
    const used = total - free;                 // used BY df's arithmetic (incl. root reserve)
    const reserved = Math.max(0, st.bsize * st.bfree - free);
    return {
        mount: want,
        device: r[0] || null,
        fsType: r[2] || null,
        totalBytes: total,
        freeBytes: free,
        usedBytes: used,
        reservedBytes: reserved,
        usedPercent: total ? Math.round((used / total) * 1000) / 10 : 0,
        source: want === DATA_MOUNT ? 'data' : 'root',
    };
}

function readProcNetDev() {
    try {
        const text = fs.readFileSync('/proc/net/dev', 'utf8');
        return text.split('\n').slice(2).map((l) => {
            const [label, rest] = l.split(':', 2);
            if (!rest) return null;
            const f = rest.trim().split(/\s+/);
            return { name: label.trim(), rxBytes: Number(f[0]), txBytes: Number(f[8]) };
        }).filter(Boolean);
    } catch { return null; }
}

/** The interface that carries the default route (Destination
 * 00000000 in /proc/net/route). The network graphs show THIS device's
 * traffic only — on a multi-NIC machine aggregating every card would be
 * misleading. null when no default route exists (e.g. booted with no
 * connectivity yet). */
function defaultRouteIface() {
    try {
        const rows = String(fs.readFileSync('/proc/net/route', 'utf8'))
            .split('\n').slice(1).map((l) => l.trim().split(/\s+/))
            .filter((f) => f.length >= 9);
        for (const f of rows) if (f[1] === '00000000') return f[0];
    } catch { /* route table unreadable */ }
    return null;
}

/* /proc/net/dev cumulative byte counters -> per-interval RATES (KiB/s)
 * for the dashboard sparklines. Same sampler pattern as
 * readCpuUtilization(): the main process is the only sampler, deltas are
 * computed here (the renderer never sees raw counters or timestamps),
 * and the ring buffer holds NET_SAMPLES pairs oldest->newest.
 * Counted device: the DEFAULT-ROUTE interface only (loopback is never
 * counted). When no default route exists yet, all non-lo interfaces are
 * summed as a fallback so the graphs still show something.
 * Returns { iface, series }: iface names the device the series is for (the
 * renderer displays it — so the label always matches the data, even on a
 * multi-NIC host where /proc/net/dev order != default route).
 * First sample after boot/baseline has no interval yet -> r/x null.
 */
const NET_SAMPLES = 100;    // 2 s cadence => 3 min window (matches the CPU graph)
let netPrev = null;         // { rx, tx, t }

function readNetTraffic() {
    const ifaces = readProcNetDev() || [];
    const def = defaultRouteIface();
    const counted = def
        ? ifaces.filter((d) => d.name === def)
        : ifaces.filter((d) => d.name !== 'lo');
    let rx = 0, tx = 0;
    for (const d of counted) { rx += d.rxBytes; tx += d.txBytes; }
    const t = Date.now();
    let r = null, x = null;
    if (netPrev) {
        const dt = (t - netPrev.t) / 1000;
        if (dt > 0) {
            // negative deltas can only mean a counter reset (new iface) — clamp
            r = Math.max(0, (rx - netPrev.rx) / dt / 1024);
            x = Math.max(0, (tx - netPrev.tx) / dt / 1024);
            r = Math.round(r * 10) / 10;
            x = Math.round(x * 10) / 10;
        }
    }
    netPrev = { rx, tx, t };
    readNetTraffic.buf = (readNetTraffic.buf || []).concat({ r, x }).slice(-NET_SAMPLES);
    return { iface: counted.length ? counted[0].name : null, series: readNetTraffic.buf.slice() };
}


/* ------------------------------------------------------------------ *
 * 10. Public API (Electron entry AND headless test harness use this)
 * ------------------------------------------------------------------ */

const api = {
    SNAPD_SOCKET,
    SESSION_TIMEOUT_MS,
    validSnapName, validChannel,
    toYaml, fromYaml,
    readHostStats, readProcNetDev, readCpuUtilization, readNetTraffic,

    // local admin gate (the UI lock screen; offline)
    createLocalPassword, loginLocal, logoutLocal, resetLocalPassword, authStatus, detectInitialized,
    // store auth (optional, volatile)
    storeLogin, storeLogout,

    getSystemInfo, getModelAssertion, parseModelAssertion, modelSystemSnaps,
    getDataPartition, mountsTable, defaultRouteIface,
    listChanges, getWarnings,
    listSnaps, getSnapInfo, searchSnaps, getChange,
    getSnapServices, controlSnapService,
    getSnapConfig, getNetplan, listInterfaces, confInferType,
    timesyncStatus, timesyncSetEnabled, timesyncSetServer,
    parseTimesyncNtp, formatTimesyncNtp, __setTimesyncTransport,
    ipfwdStatus, ipfwdSet, ipfwdApplyPref, __setIpfwdNodes,
    getNetDevices, netApplyDevice, buildNetDeviceDef, mergeNetplanDevices,
    listNetDevices, netLinkType, netGlobMatch, netDefMatches, __setNetLive,
    readResolvConfNameservers, __setResolvConfPath,
    clearNetSeedBoilerplate, __setNetSeedPath, netSeedBoilerplatePath,

    installSnap, snapAction, snapComponent,
    setSnapConfig,
    connectInterface, disconnectInterface,
};

module.exports = api;

/* ------------------------------------------------------------------ *
 * 11. Electron integration (only active when running inside Electron):
 *     kiosk window hardening, IPC wiring, 15-min inactivity watchdog.
 * ------------------------------------------------------------------ */

function initElectron() {
    let electron;
    try {
        // eslint-disable-next-line global-require
        electron = process.env.UCM_FAKE_ELECTRON ? global.UCM_FAKE_ELECTRON : require('electron');
    } catch {
        return null; // headless/test mode — module API above is the surface
    }
    // Under plain Node, the npm `electron` package resolves to the binary
    // PATH STRING (or nothing useful); only the real Electron runtime
    // provides `app`. Guard keeps this module headless-testable.
    if (typeof electron === 'string' || !electron || !electron.app) return null;
    const { app, BrowserWindow, ipcMain, session: eSession } = electron;

    // Test harness (UCM_FAKE_ELECTRON): wrap the wiring so a wiring-time
    // TypeError (e.g. .then() on a sync handler) is observable from node tests.
    try {

    // ---- single instance guard --------------------------------------
    if (!app.requestSingleInstanceLock()) {
        app.quit();
        return;
    }
    app.on('second-instance', () => {
        if (mainWin && !mainWin.isDestroyed()) {
            mainWin.show();
            mainWin.focus();
        }
    });

    let mainWin = null;
    let inactivityTimer = null;
    let warnTimer = null;

    const pushAuthStatus = () => {
        if (mainWin && !mainWin.isDestroyed()) {
            mainWin.webContents.send('auth-status-changed', statusPayload());
        }
    };

    // ---- inactivity watchdog: 15 min, armed by any UI activity ------
    // Locks the LOCAL console (and clears volatile store auth) on expiry.
    function armInactivity() {
        if (inactivityTimer) clearTimeout(inactivityTimer);
        if (warnTimer) clearTimeout(warnTimer);
        if (!session.localAuthenticated) return;
        session.localExpiresAt = Date.now() + SESSION_TIMEOUT_MS;
        session.localWarned = false;
        inactivityTimer = setTimeout(() => {
            session.localAuthenticated = false;
            session.localExpiresAt = 0;
            clearStoreSession('inactivity-lock');
            pushAuthStatus();
        }, SESSION_TIMEOUT_MS);
        warnTimer = setTimeout(() => {
            if (session.localAuthenticated) {
                session.localWarned = true;
                pushAuthStatus(); // payload.expiresAt drives the UI countdown chip
            }
        }, SESSION_TIMEOUT_MS - SESSION_WARN_MS);
    }

    // ---- kiosk window -------------------------------------------------
    function createKioskWindow() {
        const win = new BrowserWindow({
            width: 1280,
            height: 800,
            useContentSize: true,
            kiosk: true,
            fullscreen: true,
            frame: false,
            alwaysOnTop: true,
            resizable: false,
            movable: false,
            minimizable: false,
            maximizable: false,
            autoHideMenuBar: true,
            backgroundColor: '#f7f7f7',
            show: false,
            webPreferences: {
                preload: path.join(__dirname, 'preload.js'),
                contextIsolation: true,
                nodeIntegration: false,
                sandbox: true,
                webSecurity: true,
                allowRunningInsecureContent: false,
                experimentalFeatures: false,
                spellcheck: false,
                devTools: false,
                backgroundThrottling: false,
            },
        });

        // Strict CSP injection — fully self-contained, works offline
        // (Vanilla CSS + Ubuntu fonts are bundled in build/).
        const csp = [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline'",
            "font-src 'self' data:",
            "img-src 'self' data:",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
        ].join('; ');
        eSession.defaultSession.webRequest.onHeadersReceived((details, callback) => {
            callback({
                responseHeaders: {
                    ...details.responseHeaders,
                    'Content-Security-Policy': [csp],
                },
            });
        });

        // No popups, no webviews, no navigation away from the app.
        win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
        win.webContents.on('will-navigate', (e) => e.preventDefault());
        win.webContents.on('devtools-opened', () => {
            if (!win.isDestroyed()) win.webContents.closeDevTools();
        });
        app.on('web-contents-created', (_e, contents) => {
            contents.on('will-attach-webview', (e) => e.preventDefault());
        });

        // ---- kiosk input trap: desktop-escape combos ------------------
        const KILL_COMBOS = [
            { key: 'F4', alt: true },        // Alt+F4
            { key: 'F5' },                   // F5
            { key: 'r', ctrl: true },        // Ctrl+R / Ctrl+Shift+R
            { key: 'F11' },                  // fullscreen toggle
            { key: 'w', ctrl: true },        // Ctrl+W close
            { key: 'Tab', alt: true },       // window switcher
        ];
        win.webContents.on('before-input-event', (event, input) => {
            if (input.type !== 'keyDown' || !input.key) return;
            const hit = KILL_COMBOS.some((c) =>
                input.key === c.key
                && (!!c.alt === !!input.alt)
                && (!!c.ctrl === !!input.control)
                && (c.shift === undefined || !!c.shift === !!input.shift));
            if (hit) event.preventDefault();
        });

        // ---- anti workspace-switch: force focus back ------------------
        win.on('blur', () => {
            if (!win.isDestroyed() && win.isVisible()) {
                setImmediate(() => {
                    if (!win.isDestroyed()) {
                        win.setAlwaysOnTop(true, 'screen-saver');
                        win.focus();
                    }
                });
            }
        });
        win.on('maximize', () => { if (!win.isDestroyed()) win.unmaximize(); });
        win.on('minimize', () => { if (!win.isDestroyed()) win.restore(); });

        win.once('ready-to-show', () => win.show());
        win.loadFile(path.join(__dirname, 'ui', 'index.html'));
        win.on('closed', () => { mainWin = null; });
        mainWin = win;

        // ---- test-only hook (UCM_E2E=1): report renderer bootstrap state, then quit.
        if (process.env.UCM_E2E === '1') {
            win.webContents.on('did-finish-load', () => {
                setTimeout(async () => {
                    let probe;
                    try {
                        probe = await win.webContents.executeJavaScript(
                            "({ bridge: typeof window.ucmCore, boot: !!(document.querySelector('#setupView') || document.querySelector('#loginView')) })",
                            false);
                    } catch (err) {
                        probe = { error: String((err && err.message) || err) };
                    }
                    console.log('UCM_E2E_RESULT ' + JSON.stringify(probe));
                    app.quit();
                }, 800);
            });
        }
    }

    // ---- IPC wiring: every handler re-validates its payload ---------
    const guard = (fn) => async (event, ...args) => {
        try {
            const result = await fn(...args);
            return { ok: true, result };
        } catch (err) {
            return { ok: false, error: String((err && err.message) || err) };
        }
    };
    // The UI gate is the LOCAL admin session, not store auth.
    const requireAuth = () => {
        if (!session.localAuthenticated) throw new Error('authentication required');
    };

    // ---- local admin gate (the UI lock screen; offline) --------------
    ipcMain.handle('auth:status', guard(() => authStatus()));
    // createLocalPassword/loginLocal/logoutLocal are SYNCHRONOUS (plain statusPayload
    // objects) — never .then() on them (TypeError: .then is not a function in the
    // real runtime; plain-node tests skip this wiring, so guard it in [10] below).
    ipcMain.handle('auth:create', guard((password) => { const p = createLocalPassword(password); armInactivity(); pushAuthStatus(); return p; }));
    ipcMain.handle('auth:login', guard((password) => { const p = loginLocal(password); armInactivity(); pushAuthStatus(); return p; }));
    ipcMain.handle('auth:logout', guard(() => { const p = logoutLocal(); pushAuthStatus(); return p; }));
    // Console-privileged reset: re-confirms the CURRENT password (so a
    // compromised renderer cannot wipe the gate without it), then deletes
    // admin.cred -> next launch is first-boot setup again.
    ipcMain.handle('auth:reset', guard((password) => { const p = resetLocalPassword(password); pushAuthStatus(); return p; }));
    // Activity beacon (mouse/keyboard/wheel from the UI): re-arm resets the real
    // lock clock to a full 15 minutes. Crucially we ALSO push the fresh expiresAt
    // to the renderer — the header pill is a local countdown from the last received
    // expiresAt, so without this push the pill would keep ticking to 0:00 (display
    // only) while main's real timer was correctly still ~15 min out (the "0:00 but
    // no lock" symptom). Ignored on the login screen so the gate itself never locks.
    ipcMain.on('session:activity', () => {
        if (session.localAuthenticated) { armInactivity(); pushAuthStatus(); }
    });

    // ---- optional store login (macaroons; needs network) ------------
    ipcMain.handle('store:login', guard(async (email, password) => { const p = await storeLogin(email, password); pushAuthStatus(); return p; }));
    ipcMain.handle('store:logout', guard(async () => { const p = await storeLogout(); pushAuthStatus(); return p; }));

    // ---- reads / writes (writes require the local gate) -------------
    ipcMain.handle('sys:info', guard(async () => ({
        snapd: await getSystemInfo().catch(() => null),
        host: readHostStats(),
        model: await getModelAssertion().catch(() => null),
        netdev: readProcNetDev(),
        warnings: await getWarnings().catch(() => []),
    })));
    // CPU utilization history (sparkline). Read-only /proc sampling, so it
    // is open to the local gate like the other diagnostics — no write path.
    ipcMain.handle('sys:cpu', guard(() => readCpuUtilization()));
    // Net traffic rates (sparklines). Same read-only /proc class as sys:cpu.
    ipcMain.handle('sys:net', guard(() => readNetTraffic()));
    ipcMain.handle('sys:model', guard(() => getModelAssertion()));
    // Data partition usage (/run/mnt/data on core, / elsewhere). Read-only.
    ipcMain.handle('sys:data-disk', guard(getDataPartition));
    ipcMain.handle('sys:changes', guard((select) => listChanges(select)));
    ipcMain.handle('sys:change', guard((id) => getChange(id)));
    ipcMain.handle('sys:netplan', guard(() => getNetplan()));

    ipcMain.handle('snaps:list', guard(() => listSnaps()));
    ipcMain.handle('snaps:info', guard((name) => getSnapInfo(name)));
    ipcMain.handle('snaps:search', guard((q, n) => searchSnaps(q, n)));
    ipcMain.handle('snaps:install', guard((name, channel) => { requireAuth(); return installSnap(name, channel); }));
    ipcMain.handle('snaps:action', guard((name, action, extra) => { requireAuth(); return snapAction(name, action, extra || {}); }));
    ipcMain.handle('snaps:component', guard((name, action, component) => { requireAuth(); return snapComponent(name, action, component); }));
    ipcMain.handle('snaps:services', guard((name) => getSnapServices(name)));
    ipcMain.handle('snaps:service', guard((name, app, action, opts) => { requireAuth(); return controlSnapService(name, app || null, action, opts || {}); }));
    ipcMain.handle('snaps:conf-get', guard((name, key) => getSnapConfig(name, key || null)));
    ipcMain.handle('snaps:conf-set', guard((name, conf) => { requireAuth(); return setSnapConfig(name, conf); }));

    // timesync / NTP (timeserver-control interface; reads are open, writes
    // are console-privileged like the other system changes)
    ipcMain.handle('timesync:status', guard(() => timesyncStatus()));
    ipcMain.handle('timesync:set-enabled', guard((b) => { requireAuth(); return timesyncSetEnabled(b); }));
    ipcMain.handle('timesync:set-server', guard((s) => { requireAuth(); return timesyncSetServer(s); }));
    // ip forwarding (network-control interface; reads open, writes are
    // console-privileged like the other system changes)
    // network devices (round 53): the live list (open) + the per-device
    // netplan apply (console-privileged, like the other network changes)
    ipcMain.handle('net:devices', guard(() => getNetDevices()));
    ipcMain.handle('net:apply-device', guard((cfg) => { requireAuth(); return netApplyDevice(cfg); }));
    ipcMain.handle('net:clear-seed', guard(() => { requireAuth(); return clearNetSeedBoilerplate(); }));
    ipcMain.handle('net:forwarding-status', guard(() => ipfwdStatus()));
    ipcMain.handle('net:forwarding-set', guard((b) => { requireAuth(); return ipfwdSet(b); }));
    ipcMain.handle('ifaces:list', guard(() => listInterfaces()));
    ipcMain.handle('ifaces:connect', guard((plug, slot) => { requireAuth(); return connectInterface(plug, slot); }));
    ipcMain.handle('ifaces:disconnect', guard((plug, slot) => { requireAuth(); return disconnectInterface(plug, slot); }));

    // ---- app lifecycle ------------------------------------------------
    app.whenReady().then(() => {
        createKioskWindow();
        ipfwdApplyPref(); // round 51: re-apply the stored ip-forwarding pref at startup
        app.on('activate', () => {
            if (BrowserWindow.getAllWindows().length === 0) createKioskWindow();
        });
    });
    app.on('window-all-closed', () => app.quit());
    app.on('will-quit', () => {
        session.localAuthenticated = false;
        clearStoreSession('quit');
    });

    return { app, BrowserWindow };
    } catch (wireErr) { app.__wireErr = wireErr; throw wireErr; }
}

try { initElectron(); } catch (e) { process.__ucmWireErr = e; }
