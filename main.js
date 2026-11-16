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
        // round 66: the CONFIGURABLE lock timeout (null = "off" — no auto-lock,
        // the UI chip then shows "active" instead of a countdown).
        timeoutMs: lockTimeoutMs(lockTimeoutPref),
        // round A: the appearance pref ('light' | 'dark') — the renderer maps
        // 'dark' to the vanilla <html>.is-dark class (live theme switch).
        appearance: appearancePref,
        // round T: the topbar-clock pref ('on' | 'off') — the renderer
        // shows/hides the topbar clock from it (the appearance idiom).
        showClock: showClockValue(),
        // round I: the local pages list (embedded localhost web UIs) — the
        // renderer renders the sidebar entries + the <webview> views.
        localPages: localPages.map((e) => ({ name: e.name, url: e.url })),
        // store (optional)
        storeAuthenticated: session.storeAuthenticated,
        storeUsername: session.storeAuthenticated ? session.storeUsername : null,
    };
}

function beginLocalSession() {
    session.localAuthenticated = true;
    session.localInitialized = readCred() !== null;
    // round 66: 'off' -> no auto-lock (no expiry); else the pref's minutes.
    const ms = lockTimeoutMs(lockTimeoutPref);
    session.localExpiresAt = ms ? Date.now() + ms : 0;
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
 * 8c. Session inactivity lock timeout (configurable, round 66)
 * ------------------------------------------------------------------
 * The console locks after N minutes of inactivity. N is a user PREFERENCE
 * persisted in the state dir (the round-51 ipfwd pref idiom): one of
 * 5/10/15/30/60 minutes or 'off' (no auto-lock). 15 is the shipped default
 * (the round-1 constant) — a box with no pref file behaves EXACTLY as
 * before. getLockTimeout/setLockTimeout run in the plain-node path (the
 * integration unit-tests them); setLockTimeout ALSO re-arms the active
 * session's REAL watchdog (armLockWatchdog is bound to initElectron's
 * armInactivity), so a change is live, not just at next login.
 */
const LOCK_TIMEOUTS = ['5', '10', '15', '30', '60', 'off'];
const DEFAULT_LOCK_TIMEOUT = '15';
let armLockWatchdog = null; // bound in initElectron (armInactivity)

function lockTimeoutPrefPath() {
    return process.env.UCM_LOCK_TIMEOUT_PREF || (stateDir() ? path.join(stateDir(), 'lock-timeout.pref') : null);
}
function lockTimeoutPrefRead() {
    const p = lockTimeoutPrefPath();
    if (!p) return DEFAULT_LOCK_TIMEOUT;
    try {
        const v = fs.readFileSync(p, 'utf8').trim();
        return LOCK_TIMEOUTS.includes(v) ? v : DEFAULT_LOCK_TIMEOUT;
    } catch { return DEFAULT_LOCK_TIMEOUT; }
}
function lockTimeoutPrefWrite(v) {
    const p = lockTimeoutPrefPath();
    if (!p) return; // dev mode (no state dir) — nothing durable
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, v, { mode: 0o600 });
}
// ms for a timeout value ('off' -> null = no auto-lock).
function lockTimeoutMs(v) {
    return v === 'off' ? null : Number(v) * 60 * 1000;
}
// the CURRENT pref — read once at module load (before any session).
let lockTimeoutPref = lockTimeoutPrefRead();
function getLockTimeout() {
    return { value: lockTimeoutPref, ms: lockTimeoutMs(lockTimeoutPref), allowed: LOCK_TIMEOUTS.slice(), default: DEFAULT_LOCK_TIMEOUT };
}
/**
 * Set the inactivity lock timeout ('off' | '5' | '10' | '15' | '30' | '60').
 * Throws on an unknown value (nothing is written). Persists the pref and —
 * when a session is active — re-arms the REAL watchdog immediately, so the
 * new timeout (or "off") applies to the current session, not just the next.
 */
function setLockTimeout(v) {
    if (typeof v !== 'string' || !LOCK_TIMEOUTS.includes(v)) {
        throw new Error('invalid lock timeout: ' + JSON.stringify(v) + ' (allowed: ' + LOCK_TIMEOUTS.join(', ') + ')');
    }
    lockTimeoutPref = v;
    lockTimeoutPrefWrite(v);
    if (session.localAuthenticated && armLockWatchdog) armLockWatchdog();
    return getLockTimeout();
}

/* ------------------------------------------------------------------ *
 * 8d. Appearance (light/dark theme, round A)
 * ------------------------------------------------------------------ *
 * The app's offline preference for a dark theme. Like the lock timeout
 * (8c) it lives in $SNAP_COMMON (console-privileged, no new snap plug)
 * and is LIVE: setAppearance persists and the new value flows to the
 * renderer through statusPayload (pushed on set). The renderer maps
 * 'dark' -> <html>.is-dark (the vanilla-framework 4.x theme class; the
 * vendored bundle already carries the compiled dark token set). No UI in
 * this round — round B adds the Appearance card + toggle.
 */
const APPEARANCES = ['light', 'dark'];
const DEFAULT_APPEARANCE = 'light';

function appearancePrefPath() {
    return process.env.UCM_APPEARANCE_PREF || (stateDir() ? path.join(stateDir(), 'appearance.pref') : null);
}
function appearancePrefRead() {
    const p = appearancePrefPath();
    if (!p) return DEFAULT_APPEARANCE;
    try {
        const v = fs.readFileSync(p, 'utf8').trim();
        return APPEARANCES.includes(v) ? v : DEFAULT_APPEARANCE;
    } catch { return DEFAULT_APPEARANCE; }
}
function appearancePrefWrite(v) {
    const p = appearancePrefPath();
    if (!p) return; // dev mode (no state dir) — nothing durable
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, v, { mode: 0o600 });
}
// the CURRENT pref — read once at module load (before any session).
let appearancePref = appearancePrefRead();
function getAppearance() {
    return { value: appearancePref, allowed: APPEARANCES.slice(), default: DEFAULT_APPEARANCE };
}
/**
 * Set the appearance ('light' | 'dark'). Throws on an unknown value
 * (nothing is written). Persists the pref; the new value becomes visible
 * to the renderer via the status payload (the caller pushes it).
 */
function setAppearance(v) {
    if (typeof v !== 'string' || !APPEARANCES.includes(v)) {
        throw new Error('invalid appearance: ' + JSON.stringify(v) + ' (allowed: ' + APPEARANCES.join(', ') + ')');
    }
    appearancePref = v;
    appearancePrefWrite(v);
    return getAppearance();
}

/* ------------------------------------------------------------------ *
 * 8e. Local pages (embedded localhost web UIs; round I)
 * ------------------------------------------------------------------ *
 * The user can bookmark a snap's own web UI (a localhost service) as an
 * embedded page: a Settings card manages the list (name + URL), each entry
 * becomes a SIDEBAR entry (below a separator, only when the list is
 * non-empty) whose view is a <webview> inside the app shell (the sidebar
 * stays permanently visible — the guest never replaces the chrome).
 *
 * Security boundary: only LOOPBACK URLs are allowed (http/https on
 * localhost / 127.0.0.1 / ::1, any port/path). This is a privileged,
 * always-on-top admin kiosk; embedding must not reach LAN/external hosts.
 * The guest runs sandboxed (webview guest: no preload, no node; its own
 * partition for cookies).
 *
 * Like appearance (8d) / lock timeout (8c): console-privileged, persisted
 * in $SNAP_COMMON (no new snap plug), LIVE — setLocalPages persists and the
 * new list flows to the renderer through statusPayload (pushed on set).
 * The renderer is the authority for LIST EDITS (it computes add/edit/remove
 * and sends the whole list); main.js VALIDATES every entry + uniqueness and
 * owns persistence.
 */
const LOCAL_PAGES_MAX = 10;                 // keep the sidebar sane
const LOCAL_PAGE_HOSTS = ['localhost', '127.0.0.1', '::1'];

function localPagesPrefPath() {
    return process.env.UCM_LOCAL_PAGES_PREF
        || (stateDir() ? path.join(stateDir(), 'local-pages.pref') : null);
}
function validLocalPageUrl(url) {
    let u;
    try { u = new URL(String(url)); } catch { return false; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    // the URL parser keeps the BRACKETS on an IPv6 hostname ("[::1]") — strip
    // them so "::1" matches the host list.
    const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    return LOCAL_PAGE_HOSTS.includes(host);
}
function validLocalPageName(name) {
    const n = String(name).trim();
    return n.length >= 1 && n.length <= 40;
}
// validate ONE entry; returns null when valid, else the human error string.
function localPageEntryError(e) {
    if (!e || typeof e !== 'object') return 'invalid entry';
    if (!validLocalPageName(e.name)) return 'invalid name';
    if (typeof e.url !== 'string' || !validLocalPageUrl(e.url)) return 'invalid url';
    return null;
}
// validate a WHOLE list; returns null when valid, else the human error string.
function localPagesError(list) {
    if (!Array.isArray(list)) return 'not a list';
    if (list.length > LOCAL_PAGES_MAX) return 'too many local pages (max ' + LOCAL_PAGES_MAX + ')';
    const names = new Set();
    for (const e of list) {
        const err = localPageEntryError(e);
        if (err) return err;
        const key = String(e.name).trim().toLowerCase();
        if (names.has(key)) return 'duplicate name: ' + key;
        names.add(key);
    }
    return null;
}
function localPagesPrefRead() {
    const p = localPagesPrefPath();
    if (!p) return [];
    try {
        const v = JSON.parse(fs.readFileSync(p, 'utf8'));
        return (Array.isArray(v) && !localPagesError(v)) ? v.map((e) => ({ name: String(e.name).trim(), url: e.url })) : [];
    } catch { return []; }
}
function localPagesPrefWrite(list) {
    const p = localPagesPrefPath();
    if (!p) return; // dev mode (no state dir) — nothing durable
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, JSON.stringify(list), { mode: 0o600 });
}
// the CURRENT list — read once at module load (before any session).
let localPages = localPagesPrefRead();
function getLocalPages() {
    return { list: localPages.map((e) => ({ name: e.name, url: e.url })), max: LOCAL_PAGES_MAX };
}
/**
 * Set the WHOLE local-pages list. Throws on any invalid entry (nothing is
 * written). Persists; the new list becomes visible to the renderer via the
 * status payload (the caller pushes it).
 */
function setLocalPages(list) {
    const err = localPagesError(list);
    if (err) throw new Error('invalid local pages: ' + err);
    localPages = list.map((e) => ({ name: String(e.name).trim(), url: e.url }));
    localPagesPrefWrite(localPages);
    return getLocalPages();
}
/**
 * Certificate-error policy for the local-page <webview> guests. Some snap web
 * UIs serve SELF-SIGNED TLS on loopback (LXD: https://127.0.0.1:8443). A
 * self-signed cert on a localhost address is a local trust decision — there is
 * no man-in-the-middle channel between the console and the loopback interface,
 * so verification adds nothing there — but the rest of the kiosk stays fully
 * verified. The SCOPE has two halves: (a) the handler is attached ONLY to the
 * guest partition session (session.fromPartition('ucm-local-pages') — the
 * <webview> guest runs in its OWN session, NOT the default one, so the kiosk's
 * own contents never see this handler); (b) within that session, only these
 * errors on a LOOPBACK request host are allowed. `details` = the session
 * 'certificate-error' payload ({url, error, certificate, mainFrame, ...});
 * returns true to proceed.
 */
const LOCAL_PAGE_CERT_ERRORS = [
    'CERT_SELF_SIGNED',
    'CERT_AUTHORITY_INVALID',   // Chromium's usual error for self-signed certs
    'CERT_COMMON_NAME_INVALID', // CN/SAN not covering the loopback address
];
function localPagesAllowSelfSignedCert(details) {
    if (!details || typeof details !== 'object') return false;
    // Chromium reports the code as 'net::ERR_CERT_...' — strip the prefix so the
    // policy matches the stable CERT_... code (VERIFIED live: a refused
    // self-signed loopback guest delivers error='net::ERR_CERT_AUTHORITY_INVALID').
    const code = String(details.error || '').replace(/^net::ERR_/, '');
    if (!LOCAL_PAGE_CERT_ERRORS.includes(code)) return false;
    try {
        const host = new URL(details.url).hostname.toLowerCase().replace(/^\[|\]$/g, '');
        return LOCAL_PAGE_HOSTS.includes(host);
    } catch { return false; }
}

/* ------------------------------------------------------------------ *
 * 8f. System page (round L): journal + refresh schedule + power
 *
 * Three backends, all console-privileged (the page sits behind the
 * local-admin gate like every other page):
 *   1. SYSTEM JOURNAL  - reads /var/log via the log-observe interface,
 *     which grants journalctl execution + /run/log/journal/** (source-
 *     verified: snapd interfaces/builtin/log_observe.go, 8d4d073). Same
 *     house idiom as ip/resolvctl (sanctioned tool, no new grant).
 *   2. REFRESH SCHEDULE - the core 'refresh.timer' option (round S+4: the
 *     ACTUAL snapd structured scheduling, timeutil.ParseSchedule). Lets the
 *     user pick weekdays (mon-fri, even nth-weekday mon5) AND a time window
 *     (range / spread ~ / split /N); event sets join with ',,'. snapd reads
 *     refresh.timer FIRST (legacy refresh.schedule is a fallback only, and is
 *     dropped here - the app is unreleased). Empty = unset = the built-in
 *     default. Written via the existing core config bridge (async change).
 *   3. POWER / SCHEDULED SHUTDOWN - org.freedesktop.login1.Manager over
 *     the system bus via dbus-next (the shutdown interface is D-BUS
 *     ONLY - source-verified, no systemctl/poweroff allowed). Signatures
 *     verified by live introspection on systemd 255 (== Ubuntu Core 24):
 *       Reboot(b) / PowerOff(b)            b = polkit "interactive" flag
 *       ScheduleShutdown(s, t)             s = mode "reboot"|"poweroff"|
 *                                           "halt"; t = ABSOLUTE
 *                                           CLOCK_REALTIME in USEC
 *       CancelScheduledShutdown() -> b
 *       property ScheduledShutdown (st)    "" + UINT64_MAX when none
 *     Logind persists the schedule to /run/systemd/shutdown/scheduled
 *     (survives app restarts) and creates /run/nologin 5 minutes before
 *     the action.
 * ------------------------------------------------------------------ */

/* ---- 1. system journal (journalctl) -------------------------------- */

const JOURNAL_PRIORITIES = ['debug', 'info', 'notice', 'warning', 'err'];

function journalPriorIndex(p) {
    if (p == null) return 0;
    const i = JOURNAL_PRIORITIES.indexOf(String(p));
    return i < 0 ? 0 : i;
}

/** Build the journalctl argv for the requested view. Pure (unit-tested).
 *   opts: { unit?, match?, pri?, lines?, follow? }
 *   lines: a POSITIVE integer = the N newest entries (-n N); null/absent
 *   = the FULL journal (no -n). unit/grep/priority ALWAYS apply to the
 *   whole journal, not just the tail - a search or a unit filter must
 *   reach entries from long ago (the "why did the unit fail on first
 *   start after boot" case), so -n only ever LIMITS the unfiltered view. */
function journalArgs(opts) {
    const o = opts || {};
    const args = ['--no-pager', '--output=short-iso'];
    // -n N = the N newest entries; OMITTED (lines null/absent) = the FULL journal.
    // A unit / grep / priority filter ALWAYS searches the full journal (round O) -
    // -n only ever limits the UNFILTERED tail, so a search never misses an older
    // entry. v255 prints -n N (with or without -g) oldest-first = the terminal
    // order; the renderer keeps it as-is. (No --no-legend: not available on every
    // systemd - journalTail drops the legend line itself.)
    if (o.lines != null) {
        // 0 / junk -> the shipped 200 default (a fresh read must return data);
        // 100000 cap: the bounded view is a TAIL - an absurd -n is a typo.
        // null is NOT clamped: null = unlimited (the full journal, round O).
        const n = Math.max(1, Math.min(100000, parseInt(o.lines, 10) || 200));
        args.push('-n', String(n));
    }
    if (o.follow) args.push('-f');
    const pri = journalPriorIndex(o.pri);
    if (pri > 0) args.push('-p', JOURNAL_PRIORITIES[pri]);
    if (o.unit) args.push('-u', String(o.unit));
    if (o.match) {
        // The match text is a journalctl GREP PATTERN (-g/--grep, v255): it is
        // matched against the MESSAGE field (PCRE2, case-insensitive by
        // default) — the manpage's "grep features" option. It is NOT a
        // positional MATCH: bare words are invalid there (a positional match
        // needs the FIELD=value form — 'journalctl systemd' -> "Failed to add
        // match: Invalid argument"), which is exactly the error a free-typed
        // pattern produced. With -g, -n N: v255 seeks internally reversed but
        // PRINTS oldest-first (verified live) — the terminal order is kept.
        args.push('-g', String(o.match));
    }
    return args;
}

/* Injectable binary path (the integration test swaps in a stub script). */
let __journalBinary = null;
function __setJournalBinary(p) { __journalBinary = p || null; }

/* Injectable read timeouts (the integration test shrinks them to force the
   kill paths). Fast = a bounded tail; slow = an unbounded full-journal read
   (round O: the whole journal can stream for a while on a big box). */
let __journalTimeoutFast = 8000;
let __journalTimeoutSlow = 60000;
function __setJournalTimeouts(fast, slow) {
    if (fast) __journalTimeoutFast = fast;
    if (slow) __journalTimeoutSlow = slow;
}
function journalBinary() { return __journalBinary || 'journalctl'; }

/* A running follow (journalctl -f) child. One at a time; killed on a new
   follow, on stop, and when the main window closes. */
let __journalFollow = null;
function journalFollowKill() {
    if (__journalFollow) {
        try { __journalFollow.kill('SIGTERM'); } catch { /* already gone */ }
        __journalFollow = null;
    }
}

async function journalTail(opts) {
    const { execFile } = require('child_process');
    return new Promise((resolve) => {
        let settled = false;
        const done = (r) => { if (!settled) { settled = true; resolve(r); } };
        // Timeout: a BOUNDED tail (-n N) is fast (the journal is indexed); an
        // UNBOUNDED full-journal read streams the WHOLE journal and can take
        // tens of seconds on a big box, so it gets a longer budget (round O).
        const bounded = opts && opts.lines != null;
        const tmo = bounded ? __journalTimeoutFast : __journalTimeoutSlow;
        try {
            execFile(journalBinary(), journalArgs(opts), { encoding: 'utf8', timeout: tmo },
                (err, stdout, stderr) => {
                    // err = a non-zero exit (unknown unit, unreadable journal)
                    // or the 8s timeout kill; err=null with empty stdout = an
                    // empty match (fine).
                    const error = err ? String(err.message || err) : (stderr ? String(stderr) : '');
                    // Drop the journal LEGEND line ('-- Journal begins at ... --') -
                    // it models the --no-legend flag, which is not portable across
                    // systemd versions. A real entry never starts with '--'.
                    const lines = String(stdout || '').split('\n').filter((l) => l.length && !l.startsWith('--'));
                    done({ ok: !err, lines: lines, error: error });
                });
        } catch (e) {
            done({ ok: false, lines: [], error: String((e && e.message) || e) });
        }
    });
}

function journalFollow(opts, onLine, onDone) {
    journalFollowKill();
    const { spawn } = require('child_process');
    let child;
    try {
        child = spawn(journalBinary(), journalArgs(Object.assign({}, opts, { follow: true })), { encoding: 'utf8' });
    } catch (e) {
        if (onDone) onDone(String((e && e.message) || e));
        return;
    }
    let buf = '';
    child.stdout.on('data', (d) => {
        buf += d;
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
            const line = buf.slice(0, i);
            buf = buf.slice(i + 1);
            if (line.length && onLine) onLine(line);
        }
    });
    child.on('error', (e) => { if (onDone) onDone(String((e && e.message) || e)); });
    child.on('close', (code) => { buf = ''; if (onDone) onDone(null, code); });
    __journalFollow = child;
    return child;
}

/* ---- 2. snapd refresh SCHEDULE — the STRUCTURED refresh.timer option -------
   (round S+4: the user asked to switch from the LEGACY refresh.schedule
   (time-windows-per-day only) to the ACTUAL snapd scheduling mechanism.
   Source-verified against snapd timeutil/schedule.go ParseSchedule +
   overlord/configstate/configcore/refresh.go + overlord/snapstate/autorefresh.go
   getRefreshScheduleConf.)

   snapd reads core.refresh.timer FIRST; only if it is EMPTY does it fall back to
   the legacy core.refresh.schedule (windows-only). This app is UNRELEASED, so per
   the user the legacy path is DROPPED: refresh.timer is the single source of
   truth. Writing a timer value makes snapd ignore any legacy refresh.schedule.

   GRAMMAR (ParseSchedule) — a comma-separated list of EVENT SETS, where the
   separator between event sets is TWO commas (",,"). Each event set is
   [weekdays][,][time window]:
     weekdays : day | day[-day]  where day = mon|tue|wed|thu|fri|sat|sun,
                optionally with a week-position digit 1-5 (mon5 = the 5th
                Monday; mon2-tue = 2nd Monday through the following Tuesday).
                Ranges may wrap (fri-mon). A weekday with ONLY a position
                (mon1) means that single day.
     time     : HH:MM | HH:MM-HH:MM (range) | HH:MM~HH:MM (spread randomly
                inside) | whole-day "-" or "~" | any of these with /N (split the
                window into N sub-windows). Hours 0-23 (24:00 is a valid END
                only), minutes 0-59, an optional leading zero on the hour.
     weekday and time fragments may BOTH appear in one set, in that order
     (mon-fri,09:00-17:00). Multiple sets join with ",,".
   Special values: "" = unset (the built-in default) and "managed" = an external
   snap drives the refreshes (both are ACCEPTED states; user INPUT is always the
   grammar, never "managed"). */

const RE_CLOCK = /^([0-9]|0[0-9]|1[0-9]|2[0-3]):([0-5][0-9])$|^24:00$/;
const WEEKDAYS = { sun: 0, mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6 };

function parseClock(s) {
    if (!RE_CLOCK.test(s)) return null; // null = not a valid clock
    return true; // we only need VALIDITY (the port never computes a time)
}
function parseTimerWeekday(s) {
    const l = s.length;
    if (l !== 3 && l !== 4) return null;
    const day = s.slice(0, 3);
    let pos = 0;
    if (l === 4) {
        const v = parseInt(s.slice(3), 10);
        if (isNaN(v) || v < 1 || v > 5) return null;
        pos = v;
    }
    if (!(day in WEEKDAYS)) return null;
    return { day, pos };
}
function parseTimerWeekSpan(s) {
    const split = s.split('-');
    if (split.length > 2) return null;
    const start = parseTimerWeekday(split[0]);
    if (!start) return null;
    let end = start;
    if (split.length === 2) {
        end = parseTimerWeekday(split[1]);
        if (!end) return null;
    }
    // snapd: both positions set -> the end position must be >= the start position,
    // and a NON-single span with two positions degrades the end to EveryWeek.
    if (start.pos !== 0 && end.pos !== 0) {
        if (end.pos < start.pos) return null;
    }
    return { start, end };
}
function parseTimerClockSpan(s) {
    // timespan = time ("-" / "~") time [ "/" N ]; or the whole-day tokens "-" / "~"
    // (each optionally followed by "/N").
    let rest = s;
    let splitCount = 0;
    const ci = rest.indexOf('/');
    if (ci >= 0) {
        if (rest.indexOf('/', ci + 1) >= 0) return null; // at most one '/'
        const countStr = rest.slice(ci + 1);
        const c = parseInt(countStr, 10);
        if (isNaN(c) || String(c) !== countStr || c === 0) return null; // positive integer
        splitCount = c;
        rest = rest.slice(0, ci);
    }
    const norm = rest.includes('~') ? rest.replace('~', '-') : rest;
    if (norm === '-') return true; // whole day (optionally split)
    if (norm.includes('-')) {
        const parts = norm.split('-');
        if (parts.length !== 2) return null;
        if (!parseClock(parts[0]) || !parseClock(parts[1])) return null;
        return true;
    }
    return parseClock(norm);
}
function parseTimerEventSet(s) {
    const fragments = s.split(',');
    if (fragments.length === 1) {
        // a lone fragment is EITHER a week span or a clock span
        if (s.includes(':')) {
            if (!parseTimerClockSpan(s)) return false;
            return true;
        }
        if (!parseTimerWeekSpan(s)) return false;
        return true;
    }
    let expectTime = false;
    for (const frag of fragments) {
        if (frag.length === 0) return false;
        if (frag.includes(':')) {
            if (!parseTimerClockSpan(frag)) return false;
            expectTime = true;
        } else if (!expectTime) {
            if (!parseTimerWeekSpan(frag)) return false;
        } else {
            return false; // a weekday fragment after a time fragment
        }
    }
    return true;
}
// PURE (unit-tested): mirrors snapd timeutil.ParseSchedule EXACTLY. "managed" is
// NOT a grammar value (it is the external-management reserved token) so it is
// rejected here; the ACCEPTED-state check ("" or "managed") lives in
// isRefreshTimerAccepted.
function validRefreshTimer(s) {
    if (typeof s !== 'string') return false;
    s = s.trim();
    if (s === '' || s === 'managed') return false;
    const sets = s.split(',,');
    for (const set of sets) {
        if (!parseTimerEventSet(set)) return false;
    }
    return true;
}
// The ACCEPTED states for the option: empty (the built-in default) OR a valid
// structured timer OR "managed". (This is what the read-back / UI-valid flag uses.)
function isRefreshTimerAccepted(s) {
    if (s == null) return true; // null = option absent = the default
    const t = String(s).trim();
    if (t === '') return true;
    if (t === 'managed') return true;
    return validRefreshTimer(t);
}
/* Read the CURRENT refresh.timer (shape-robust: the full-doc and the
   { 'refresh.timer': v } single-key shapes both work; the netplan-merged doc
   nests under network). */
function refreshTimerFromDoc(doc) {
    if (!doc || typeof doc !== 'object') return null;
    if (typeof doc['refresh.timer'] === 'string') return doc['refresh.timer'];
    if (doc.refresh && typeof doc.refresh === 'object' && typeof doc.refresh.timer === 'string') return doc.refresh.timer;
    if (doc.network && typeof doc.network === 'object' && typeof doc.network['refresh.timer'] === 'string') return doc.network['refresh.timer'];
    return null;
}
async function refreshTimerRead() {
    const doc = await getSnapConfig('core');
    return refreshTimerFromDoc(doc);
}
async function refreshTimerWrite(value) {
    // '' = clear the option (snapd's Set drops empty-string scalars -> the
    // built-in default applies again). Writing a non-empty timer is enough:
    // snapd reads refresh.timer first and IGNORES the legacy refresh.schedule,
    // so we do not need to (and must not) touch the legacy option.
    return setSnapConfig('core', { 'refresh.timer': value });
}

/* ---- 2b. global refresh HOLD (round S: the 'Pause auto-refresh' toggle) ----
   This is the REST equivalent of `snap refresh --hold` / `--unhold` (no snap
   names = hold ALL snaps' auto-refresh). Source-verified against snapd
   (cmd/snapd/cli/cmd_snap_op.go holdRefreshes() + client/snap_op.go
   doMultiSnapActionFull + daemon/api_snaps.go):
     hold   = POST /v2/snaps  { action:'hold',   snaps:[], time:'forever',
                                 hold-level:'auto-refresh' }
     unhold = POST /v2/snaps  { action:'unhold', snaps:[] }
   ('forever' is the CLI's own indefinite token; a DURATION would be an RFC3339
   timestamp, but the toggle is ON/OFF, so 'forever' is exactly right. The
   per-snap 'general' level is the NAMED-snaps form - NOT what a global
   --hold does.) Both return an async snapd CHANGE id (the renderer settles it
   like every other change, with the negative-toast-on-failed idiom).
   The LIVE state is read back from sysinfo: GET /v2/system-info carries
   result.refresh.hold = '' (no hold) or an RFC3339 hold-until timestamp
   (client/client.go RefreshInfo; 'forever' arrives as a distant ~100-year
   timestamp, so ANY non-empty value = held). The card's toggle must reflect
   a hold set OUTSIDE the app (the CLI, a snap) too - hence the sysinfo read,
   not our own state. */

// Test seam (integration): inject a fake sysinfo read so refreshHoldRead's
// path can be unit-tested without the socket (models the getSystemInfo shape,
// including the UNWRAPPED result at info.refresh, not info.result.refresh).
let __systemInfoFn = null;
function __setSystemInfoFn(fn) { __systemInfoFn = fn; }

// PURE (unit-tested): is a sysinfo refresh.hold value an ACTIVE hold?
function refreshHoldActive(hold) {
    return hold != null && String(hold).trim() !== '';
}

async function refreshHoldRead() {
    // snapdRequest returns the UNWRAPPED result (like getSnapConfig does) -
    // the refresh info is at result.refresh, i.e. info.refresh here.
    const info = await (__systemInfoFn || getSystemInfo)();
    const hold = info && info.refresh ? info.refresh.hold : undefined;
    return { active: refreshHoldActive(hold), hold: hold == null ? '' : String(hold) };
}

async function setGlobalRefreshHold(hold) {
    // The GLOBAL (all-snaps) auto-refresh hold - the multi-snap REST path
    // POST /v2/snaps (NOT the single-snap /v2/snaps/<name> that snapAction
    // uses). hold=true -> 'forever' auto-refresh hold (== `snap refresh
    // --hold`); hold=false -> remove it (== `snap refresh --unhold`).
    if (hold) {
        return snapdRequest('POST', '/v2/snaps',
            { body: { action: 'hold', snaps: [], time: 'forever', 'hold-level': 'auto-refresh' }, auth: A() });
    }
    return snapdRequest('POST', '/v2/snaps',
            { body: { action: 'unhold', snaps: [] }, auth: A() });
}

// Round S+2: the 'Refresh now' button. The REST equivalent of `snap refresh`
// with NO snap names = refresh ALL installed snaps' auto-refresh. Source-
// verified against snapd (cmd/snapd/cli/cmd_snap_op.go refreshMany([]) ->
// client.RefreshMany -> doMultiSnapAction('refresh', [], {}, {}); every
// multiActionData field is omitempty, so the on-the-wire body is EXACTLY
// { action:'refresh' } - the empty snaps list is dropped). The daemon routes
// action 'refresh' with no names to snapUpdateMany, which refreshes every
// installed snap (and is a clean no-op change when nothing is pending). It
// returns an ASYNC change id - the renderer settles it like every other
// write. Same multi-action POST /v2/snaps path as the hold (no new plug).
async function setGlobalRefreshNow() {
    return snapdRequest('POST', '/v2/snaps',
        { body: { action: 'refresh' }, auth: A() });
}

/* ------------------------------------------------------------------ *
 * 8g. Time card (round T): manual time + timezone + topbar clock
 *
 * The user asked for a "Time" card on the System page (between the
 * refresh schedule and power) with: a manual SET-TIME control, a
 * timezone picker, and a toggle for the topbar clock.
 *
 * MECHANISMS (all source-verified against local snapd @8d4d073 in
 * container snapd-sign-patch /root/snapd — the standing rule):
 *
 * (a) SET-TIME = timedated D-Bus SetTime. There is NO snapd option for
 *     the wall clock (the refresh/schedule/timer/hold options cover
 *     auto-refresh only), so this is the one mechanism that needs a
 *     NEW plug: time-control (interfaces/builtin/time_control.go —
 *     grants Set{Time,LocalRTC} + capability sys_time + RTC access;
 *     deny-auto-connection: true, like the other plugs). Signature
 *     verified against the live bus (busctl introspect + a
 *     dbus-next marshal probe of THIS app's dependency):
 *       SetTime(xbb) = (usec: uint64-UTC, monotonic-serial: uint64,
 *                        interactive: bool)  -> body [usec, 0, false]
 *     The uint64 is sent as a JS NUMBER (the read side arrives as a
 *     BigInt — see timeNowUsec — but the WRITE marshals fine as a
 *     number; the value is a 1.79e15-era usec, far inside the
 *     2^53-safe range).
 *
 * (b) GATE = the live NTP state (timedate1 Properties.Get NTPEnabled,
 *     the same read the Network "Sync time from internet" toggle
 *     uses). If NTP is ON, manual time-setting is refused — with
 *     time sync active, a manual set is meaningless (it gets
 *     overwritten on the next sync). Checked in the renderer (the
 *     rows grey out) AND re-checked here at write time (robust
 *     against a CLI flip between page load and click).
 *
 * (c) TIMEZONE WRITE = the snapd option core.system.timezone (an
 *     EXTERNAL config, configcore/timezone.go: the daemon itself runs
 *     "timedatectl set-timezone <zone>" as the configure handler —
 *     so the app does a PLAIN core conf PUT over the existing snapd
 *     UDS and does NOT need the timezone-control plug for writing,
 *     and does not shell out itself). Validation mirrors snapd's
 *     validTimezone regexp.
 *
 * (d) TIMEZONE LIST = the bundled IANA list (build/data/timezones.json,
 *     captured from "timedatectl list-timezones" on Core 24 = the
 *     VM's tzdata; every entry matches snapd's validTimezone regexp —
 *     snapd would reject a zone name at configure time anyway).
 *     Bundling needs NO plug and NO D-Bus dependency (the
 *     timezone-control ListTimezones grant exists but would be a
 *     second plug for zero benefit).
 *
 * (e) TIMEZONE READ (the CURRENT zone) = timedate1 Properties.Get
 *     Timezone — already granted by the EXISTING timeserver-control
 *     plug (Get{,All} on timedate1), so no new plug.
 *
 * (f) TOPBAR CLOCK = a pure UI pref (show-clock.pref, the
 *     appearance.ipfwd idiom — $SNAP_COMMON, 0600, console-
 *     privileged, rides the status payload like appearance). The
 *     clock itself renders from new Date() in the renderer (the
 *     local time of the OS = exactly what a kiosk topbar should
 *     show); the pref only switches it on/off.
 * ------------------------------------------------------------------ */
/* The IANA zone list (bundled — see 8g(d)). */
function timeZonesPath() {
    return process.env.UCM_TIMEZONES || path.join(__dirname, 'build', 'data', 'timezones.json');
}
let TIMEZONES_CACHE = null;
function listTimezones() {
    if (TIMEZONES_CACHE) return TIMEZONES_CACHE;
    let raw;
    try { raw = JSON.parse(fs.readFileSync(timeZonesPath(), 'utf8')); }
    catch (e) {
        // the bundled list is missing/corrupt — degrade to an EMPTY list (the
        // picker stays usable). A missing data file must NOT throw: that would
        // blank the whole time read. (round-T-fix bug 2)
        console.error('listTimezones: no usable bundled zone list (' + timeZonesPath() + '): ' + String((e && e.message) || e));
        TIMEZONES_CACHE = [];
        return TIMEZONES_CACHE;
    }
    if (!Array.isArray(raw) || raw.some((z) => typeof z !== 'string' || z.trim() === '')) raw = [];
    TIMEZONES_CACHE = raw.slice().sort();
    return TIMEZONES_CACHE;
}
/* test seam: point the zone list at a different file (integration tests). */
function __setTimeZonesFile(p) { process.env.UCM_TIMEZONES = p || null; TIMEZONES_CACHE = null; }
/* snapd's validTimezone (configcore/timezone.go) — the daemon re-validates
   at configure time, but the app rejects junk BEFORE the IPC round-trip. */
const RE_TIMEZONE = /^[a-zA-Z0-9+_-]+(\/[a-zA-Z0-9+_-]+)?(\/[a-zA-Z0-9+_-]+)?$/;
function timezoneValid(zone) {
    return typeof zone === 'string' && RE_TIMEZONE.test(zone) && zone.split('/').length <= 3;
}

/* (e) the CURRENT timezone — timedate1 Properties.Get (granted by the
   existing timeserver-control plug: Get{,All} on timedate1). */
/* The live timedate1 properties in ONE call — Properties.Get**All** (signature
   "s", body [iface]) returning { Prop: Variant, ... }. Properties.Get (signature
   "ss", body [iface, prop]) is REJECTED by systemd on this bus ("Unknown
   interface org.freedesktop.timedate1 or property …") — the round-T bug.
   GetAll is the idiom the already-working Network "Sync time from internet"
   toggle (timesyncNtpEnabled) uses, and it is granted by BOTH timeserver-
   control AND time-control, so it is safe under either plug. (round-T-fix bug 1) */
async function timedateAllProps() {
    const body = await timesyncTransport({ destination: TIME_DATE_DEST, path: TIME_DATE_PATH,
        interface: 'org.freedesktop.DBus.Properties', member: 'GetAll', signature: 's',
        body: [TIME_DATE_IFACE] });
    return (body && body[0]) || {};
}
async function timeNowZone() {
    const p = await timedateAllProps();
    return (p.Timezone != null) ? String(unwrapVariant(p.Timezone)) : null;
}
async function timeNowUsec() {
    const p = await timedateAllProps();
    if (p.TimeUSec == null) return null;
    // the read-side uint64 arrives as a BigInt (JSON.stringify throws) —
    // String() first, then Number (safe: ~1.79e15 usec is inside 2^53).
    return Number(String(unwrapVariant(p.TimeUSec)));
}
async function timeNtpEnabled() {
    const p = await timedateAllProps();
    if (p.NTPEnabled != null) return !!unwrapVariant(p.NTPEnabled);
    if (p.NTP != null) return !!unwrapVariant(p.NTP); // older-systemd alias
    return null;
}
/* (a)+(b) manual set: re-check the gate HERE (a CLI could have enabled
   NTP after the page loaded) + the exact xbb SetTime body. */
async function timeSet(value) {
    if (!Number.isFinite(value)) throw new Error('invalid time: ' + JSON.stringify(value));
    if (await timeNtpEnabled()) {
        throw new Error('time sync is ON — turn it off on the Network page to set the time manually');
    }
    await timesyncTransport({ destination: TIME_DATE_DEST, path: TIME_DATE_PATH,
        interface: TIME_DATE_IFACE, member: 'SetTime', signature: 'xbb',
        body: [Math.round(value), 0, false] });
    return { ok: true };
}
/* (c) timezone: plain core conf — snapd runs timedatectl itself. */
async function timezoneRead() {
    const res = await getSnapConfig('core', 'system.timezone');
    return (res && typeof res === 'object' && 'system.timezone' in res) ? res['system.timezone'] : null;
}
async function timezoneWrite(zone) {
    zone = (zone == null ? '' : String(zone)).trim();
    if (!timezoneValid(zone)) throw new Error('invalid timezone: ' + JSON.stringify(zone));
    await setSnapConfig('core', { 'system.timezone': zone });
    return zone;
}

/* (f) the topbar-clock pref (the appearance idiom: a small 0600 file in
   $SNAP_COMMON, value on the status payload, console-privileged set). */
let SHOW_CLOCKS = ['on', 'off'];
let DEFAULT_SHOW_CLOCK = 'off';
let showClockPref = 'off';
function showClockPrefPath() {
    return process.env.UCM_SHOW_CLOCK_PREF || (stateDir() ? path.join(stateDir(), 'show-clock.pref') : null);
}
function showClockPrefRead() {
    const p = showClockPrefPath();
    if (!p) return DEFAULT_SHOW_CLOCK;
    try {
        const v = fs.readFileSync(p, 'utf8').trim();
        return SHOW_CLOCKS.includes(v) ? v : DEFAULT_SHOW_CLOCK;
    } catch { return DEFAULT_SHOW_CLOCK; }
}
function showClockPrefWrite(v) {
    const p = showClockPrefPath();
    if (!p) return; // dev mode (no state dir) — nothing durable
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, v, { mode: 0o600 });
}
function showClockValue() {
    // Read at CALL time (the ipfwd idiom, NOT the appearance module-load
    // cache): the pref is a one-word 0600 file, and call-time reads keep the
    // UCM_SHOW_CLOCK_PREF seam (integration tests) working on the same
    // required instance.
    return showClockPrefRead();
}
function getShowClock() {
    return { value: showClockValue(), allowed: SHOW_CLOCKS.slice(), default: DEFAULT_SHOW_CLOCK };
}
function setShowClock(v) {
    if (typeof v !== 'string' || !SHOW_CLOCKS.includes(v)) {
        throw new Error('invalid show-clock: ' + JSON.stringify(v) + ' (allowed: ' + SHOW_CLOCKS.join(', ') + ')');
    }
    showClockPrefWrite(v);
    return getShowClock();
}

/* ---- 3. power / scheduled shutdown (login1 over D-Bus) --------------- */

let __login1Transport = null;
function __setLogin1Transport(fn) { __login1Transport = fn; }
function login1Transport(spec) {
    if (__login1Transport) return __login1Transport(spec);
    const { systemBus, Message, MessageType } = require('dbus-next');
    const bus = systemBus();
    const msg = new Message(Object.assign({}, spec, { type: MessageType.METHOD_CALL }));
    return bus.call(msg).then((r) => (r && r.body) || []);
}

const LOGIN1_DEST = 'org.freedesktop.login1';
const LOGIN1_PATH = '/org/freedesktop/login1';
const LOGIN1_IFACE = 'org.freedesktop.login1.Manager';
const POWER_ACTIONS = ['reboot', 'poweroff'];

// Reboot/PowerOff take ONE boolean: the polkit "interactive" flag. A
// privileged snap calls it NON-interactively (false) - no auth prompt.
async function powerAction(action) {
    const a = String(action || '').toLowerCase();
    if (!POWER_ACTIONS.includes(a)) throw new Error('invalid power action: ' + action);
    const member = a === 'reboot' ? 'Reboot' : 'PowerOff';
    await login1Transport({ destination: LOGIN1_DEST, path: LOGIN1_PATH,
        interface: LOGIN1_IFACE, member: member, signature: 'b', body: [false] });
}

/** The ScheduleShutdown 'when' value: an ABSOLUTE CLOCK_REALTIME timestamp
 *   in MICROSECONDS (systemd 255, verified: the timer is armed on
 *   CLOCK_REALTIME). from = Date.now() (ms) -> usec. */
function shutdownWhenUsec(fromMs) {
    const ms = Math.round(Number(fromMs));
    if (!Number.isFinite(ms)) throw new Error('invalid shutdown time');
    return Math.round(ms * 1000);
}

async function powerSchedule(action, whenMs) {
    const a = String(action || '').toLowerCase();
    if (!POWER_ACTIONS.includes(a)) throw new Error('invalid power action: ' + action);
    const usec = shutdownWhenUsec(whenMs);
    await login1Transport({ destination: LOGIN1_DEST, path: LOGIN1_PATH,
        interface: LOGIN1_IFACE, member: 'ScheduleShutdown', signature: 'st', body: [a, usec] });
    return powerScheduledRead();
}

async function powerCancelScheduled() {
    const body = await login1Transport({ destination: LOGIN1_DEST, path: LOGIN1_PATH,
        interface: LOGIN1_IFACE, member: 'CancelScheduledShutdown', signature: '', body: [] });
    return { cancelled: !!unwrapVariant(body && body[0]) };
}

// The ScheduledShutdown property is a STRUCT (st) [mode, usec]; dbus-next
// surfaces it as a 2-element array. logind's "none" sentinel is UINT64_MAX
// (1.844e19, busctl shows 18446744073709551615) — it arrives PRECISION-LOST
// through dbus-next's uint64->number decode, so "near the top of the number
// range" means none. A real schedule timestamp is ~1e15 usec (year ~58k AD
// is 1.8e18, so 1.5e19 leaves 100x headroom above any real time).
function powerScheduledParse(val) {
    let arr = val;
    if (arr && typeof arr === 'object' && !Array.isArray(arr) && 'value' in arr && 'signature' in arr) arr = arr.value;
    if (arr && arr.mode != null) arr = [arr.mode, arr.usec != null ? arr.usec : arr.timeout];
    if (!Array.isArray(arr) || arr.length < 2) return { active: false, action: null, usec: null };
    const mode = String(arr[0] || '');
    const usecRaw = Number(arr[1]);
    const active = mode.length > 0 && Number.isFinite(usecRaw) && usecRaw > 0 && usecRaw < 1.5e19;
    return { active: active, action: active ? mode : null, usec: active ? usecRaw : null };
}

async function powerScheduledRead() {
    const body = await login1Transport({ destination: LOGIN1_DEST, path: LOGIN1_PATH,
        interface: 'org.freedesktop.DBus.Properties', member: 'Get', signature: 'ss',
        body: [LOGIN1_IFACE, 'ScheduledShutdown'] });
    return powerScheduledParse(body && body[0]);
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
    // round 66: the configurable inactivity lock timeout
    getLockTimeout, setLockTimeout, LOCK_TIMEOUTS, DEFAULT_LOCK_TIMEOUT,
    // round A: appearance (light/dark)
    getAppearance, setAppearance, APPEARANCES, DEFAULT_APPEARANCE,
    // round I: local pages (embedded localhost web UIs)
    getLocalPages, setLocalPages, validLocalPageUrl, validLocalPageName, localPagesError, LOCAL_PAGES_MAX,
    localPagesAllowSelfSignedCert,
    // store auth (optional, volatile)
    storeLogin, storeLogout,

    getSystemInfo, getModelAssertion, parseModelAssertion, modelSystemSnaps,
    getDataPartition, mountsTable, defaultRouteIface,
    listChanges, getWarnings,
    listSnaps, getSnapInfo, searchSnaps, getChange,
    getSnapServices, controlSnapService,
    getSnapConfig, getNetplan, listInterfaces, confInferType,
    timesyncStatus, timesyncSetEnabled, timesyncSetServer,
    // round T: the System-page Time card (set-time + timezone + topbar clock)
    listTimezones, timezoneValid, timeNowUsec, timeNowZone, timeNtpEnabled,
    timeSet, timezoneRead, timezoneWrite,
    getShowClock, setShowClock, __setTimeZonesFile, statusPayload,
    parseTimesyncNtp, formatTimesyncNtp, __setTimesyncTransport,
    // round L: System page (journal / refresh schedule / power)
    journalTail, journalArgs, journalFollow, journalFollowKill, JOURNAL_PRIORITIES,
    __setJournalBinary, __setJournalTimeouts,
    refreshTimerRead, refreshTimerWrite, validRefreshTimer, isRefreshTimerAccepted, refreshTimerFromDoc,
    refreshHoldRead, setGlobalRefreshHold, refreshHoldActive, setGlobalRefreshNow, __setSystemInfoFn,
    powerAction, powerSchedule, powerCancelScheduled, powerScheduledRead,
    powerScheduledParse, shutdownWhenUsec, POWER_ACTIONS, __setLogin1Transport,
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
        const ms = lockTimeoutMs(lockTimeoutPref);
        if (!ms) {
            // round 66: "off" — no auto-lock. No watchdog, no expiry; the
            // status payload's timeoutMs is null so the UI chip shows
            // "active" (not a countdown) and the console never locks itself.
            session.localExpiresAt = 0;
            session.localWarned = false;
            return;
        }
        session.localExpiresAt = Date.now() + ms;
        session.localWarned = false;
        inactivityTimer = setTimeout(() => {
            session.localAuthenticated = false;
            session.localExpiresAt = 0;
            clearStoreSession('inactivity-lock');
            pushAuthStatus();
        }, ms);
        warnTimer = setTimeout(() => {
            if (session.localAuthenticated) {
                session.localWarned = true;
                pushAuthStatus(); // payload.expiresAt drives the UI countdown chip
            }
        }, ms - SESSION_WARN_MS);
    }
    // round 66: setLockTimeout re-arms the live session through this.
    armLockWatchdog = armInactivity;

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
                webviewTag: true,       // round I: <webview> for embedded localhost pages
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
        // round J: self-signed TLS for the LOCAL-PAGE <webview> guests (LXD's
        // https://127.0.0.1:8443 UI). Verified against electron.d.ts: the
        // 'certificate-error' event fires on `app` (and per WebContents) — NOT
        // on Session — so the handler is app-level and scoped to the GUEST:
        // a <webview> with partition="ucm-local-pages" loads in
        // session.fromPartition('ucm-local-pages') (its OWN session, not the
        // default one), so we allow only when the offending webContents BELONGS
        // to that session AND the loopback/error policy passes. The kiosk's own
        // contents (default session) never match -> full verification untouched.
        const lpGuestSession = (typeof eSession.fromPartition === 'function')
            ? eSession.fromPartition('ucm-local-pages')
            : null;
        app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
            const isGuest = !!(lpGuestSession && webContents && webContents.session && webContents.session === lpGuestSession);
            const allow = isGuest && localPagesAllowSelfSignedCert({ url, error });
            event.preventDefault();
            callback(allow);
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

        // ---- kiosk content-size re-assert (round-T-fix bug 3) --------------
        // The window is useContentSize + fullscreen. On some Wayland/compositor
        // setups an external re-layout can leave the WEB-CONTENTS view stuck at
        // its initial 1280x800 while the window is taller — the bottom then shows
        // the window background (the user's "empty white space taking the bottom
        // half; the app can't be moved/resized because it is a fixed kiosk). The
        // app never resizes the window itself, so this only CLAMPS drift: if the
        // content size has stopped matching the full primary display, re-assert it.
        // Healthy state (content == work area) -> the 4px tolerance makes this a
        // NO-OP (no thrash). Uses the real display size (NOT a hardcoded 1280x800)
        // so it is correct at any VM resolution.
        let kioskReasserting = false;
        function kioskReassert() {
            if (!win || win.isDestroyed() || kioskReasserting) return;
            try {
                const disp = (electron.screen && electron.screen.getPrimaryDisplay)
                    ? electron.screen.getPrimaryDisplay() : null;
                if (!disp || !disp.workArea) return;
                const cs = win.getContentSize();
                const w = disp.workArea.width, h = disp.workArea.height;
                if (Math.abs(cs[0] - w) > 4 || Math.abs(cs[1] - h) > 4) {
                    kioskReasserting = true;
                    console.error('kiosk content-size drift ' + JSON.stringify(cs) + ' -> display ' + JSON.stringify([w, h]) + '; re-asserting');
                    try { win.setContentSize(w, h, false); } catch (e) {}
                    try { win.setFullScreen(true); } catch (e) {}
                    setTimeout(() => { kioskReasserting = false; }, 500);
                }
            } catch (e) { /* headless / no display — nothing to clamp */ }
        }
        win.on('resize', kioskReassert);
        win.on('blur', kioskReassert);
        win.on('focus', kioskReassert);
        // the most direct trigger: the web-contents VIEW resized (stuck at
        // 800px while the window is taller).
        win.webContents.on('resize', kioskReassert);

        win.once('ready-to-show', () => {
            win.show();
            // the initial kiosk/fullscreen layout can already be desynced
            // (contents pinned at 800px) — correct it once after show.
            setTimeout(kioskReassert, 300);
        });
        win.loadFile(path.join(__dirname, 'ui', 'index.html'));
        win.on('closed', () => { mainWin = null; });
        // round L: a running journal follow (-f child) dies with the window.
        win.on('closed', journalFollowKill);
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
                    // ---- round I: the <webview> E2E (only when UCM_E2E_LOCALPAGE_URL is
                    //      set — the real sandbox/webviewTag check). Create a local
                    //      password + one GOOD (served) and one DEAD (unreachable) local
                    //      page through the REAL bridge, then navigate to each and report
                    //      what actually happened (good -> webview loaded the guest;
                    //      dead -> the app's load-failed fallback card).
                    if (process.env.UCM_E2E_LOCALPAGE_URL) {
                        const lpUrl = process.env.UCM_E2E_LOCALPAGE_URL;
                        const lpPort = parseInt(lpUrl.split(':')[2] || '9000', 10);
                        const deadUrl = 'http://127.0.0.1:' + (lpPort + 1);
                        // round J: a self-signed TLS localhost UI (the LXD case) —
                        // the app's scoped certificate allowance must let the
                        // <webview> proceed to the guest (page index 2).
                        const sslUrl = process.env.UCM_E2E_LOCALPAGE_SSL || null;
                        const LP_PROBE = `
                            (async () => {
                                const wait = (ms) => new Promise((r) => setTimeout(r, ms));
                                try {
                                    await window.ucmCore.auth.create('e2e-probe-password');
                                    await wait(1200);
                                    const pages = [
                                        { name: 'Up', url: ${JSON.stringify(lpUrl)} },
                                        { name: 'Down', url: ${JSON.stringify(deadUrl)} },
                                    ];
                                    ${sslUrl ? 'pages.push({ name: "TLS", url: ' + JSON.stringify(sslUrl) + ' });' : ''}
                                    await window.ucmCore.settings.setLocalPages(pages);
                                    await wait(700);
                                    const navUp = document.querySelector('.ucm-side a[data-view="lp-0"]');
                                    if (navUp) navUp.click();
                                    await wait(2500);
                                    const wv0 = document.querySelector('#view-lp-0 webview');
                                    const r0 = {
                                        active: !document.querySelector('#view-lp-0').classList.contains('ucm-hidden'),
                                        wv: !!wv0,
                                        url: wv0 ? wv0.getURL() : null,
                                        title: wv0 ? wv0.getTitle() : null,
                                    };
                                    const navDown = document.querySelector('.ucm-side a[data-view="lp-1"]');
                                    if (navDown) navDown.click();
                                    await wait(2500);
                                    const fb = document.querySelector('#view-lp-1 .ucm-webview__fallback');
                                    const r1 = {
                                        active: !document.querySelector('#view-lp-1').classList.contains('ucm-hidden'),
                                        fallback: fb ? !fb.classList.contains('ucm-hidden') : null,
                                        fbText: fb ? fb.textContent.trim().slice(0, 80) : null,
                                    };
                                    ${sslUrl ? `
                                    const navTls = document.querySelector('.ucm-side a[data-view="lp-2"]');
                                    if (navTls) navTls.click();
                                    await wait(2500);
                                    const wv2 = document.querySelector('#view-lp-2 webview');
                                    const r2 = {
                                        active: !document.querySelector('#view-lp-2').classList.contains('ucm-hidden'),
                                        wv: !!wv2,
                                        url: wv2 ? wv2.getURL() : null,
                                        title: wv2 ? wv2.getTitle() : null,
                                    };
                                    return { ok: true, r0, r1, r2 };` : 'return { ok: true, r0, r1 };'}
                                } catch (e) {
                                    return { ok: false, error: String((e && e.message) || e) };
                                }
                            })()`;
                        try {
                            probe.lp = await win.webContents.executeJavaScript(LP_PROBE, false);
                        } catch (err) {
                            probe.lp = { ok: false, error: String((err && err.message) || err) };
                        }

                        // ---- round L: the SYSTEM page E2E. READ-ONLY by
                        //      design: the probe reads the REAL journal (the
                        //      log-observe grant) + the REAL login1
                        //      ScheduledShutdown property (the shutdown
                        //      grant's D-Bus surface) — it NEVER calls
                        //      power()/powerSchedule() (a real PowerOff would
                        //      kill the suite).
                        const SYS_PROBE = `
                            (async () => {
                                const wait = (ms) => new Promise((r) => setTimeout(r, ms));
                                try {
                                    const core = window.ucmCore;
                                    const sy = {};
                                    try {
                                        const jt = await core.machine.journalTail({ lines: 20 });
                                        sy.journal = jt ? { ok: jt.ok, n: (jt.lines || []).length, first: (jt.lines && jt.lines.length) ? jt.lines[0].slice(0, 60) : null, error: jt.error || null } : null;
                                    } catch (e) { sy.journal = { ok: false, error: String(e.message || e) }; }
                                    try {
                                        const ps = await core.machine.powerScheduled();
                                        sy.scheduled = ps ? { active: ps.active, action: ps.action, usec: ps.usec } : null;
                                    } catch (e) { sy.scheduled = { error: String(e.message || e) }; }
                                    document.querySelector('.ucm-side a[data-view="system"]').click();
                                    await wait(1500);
                                    sy.viewActive = !document.querySelector('#view-system').classList.contains('ucm-hidden');
                                    sy.cards = Array.from(document.querySelectorAll('#view-system .p-card .p-heading--5')).map((h) => h.textContent.trim());
                                    // round T: the REAL time READ (timedate1
                                    // Properties.Get — granted by the EXISTING
                                    // timeserver-control plug; READ-ONLY, the
                                    // probe never sets time/zone).
                                    try {
                                        const tr = await core.machine.timeRead();
                                        sy.time = tr ? { usecOk: tr.usec != null, zone: tr.zone, ntp: tr.ntp, zones: (tr.zones || []).length } : null;
                                    } catch (e) { sy.time = { error: String(e.message || e) }; }
                                    return { ok: true, sy };
                                } catch (e) {
                                    return { ok: false, error: String((e && e.message) || e) };
                                }
                            })()`;
                        try {
                            probe.sys = await win.webContents.executeJavaScript(SYS_PROBE, false);
                        } catch (err) {
                            probe.sys = { ok: false, error: String((err && err.message) || err) };
                        }
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
    // round 66: the inactivity lock timeout. Console-privileged (requireAuth)
    // like the reset — it is a security setting. The change is live:
    // setLockTimeout re-arms the active session's watchdog, and the new
    // payload (timeoutMs) flows through pushAuthStatus to the UI chip.
    ipcMain.handle('auth:set-lock-timeout', guard((value) => { requireAuth(); const p = setLockTimeout(value); pushAuthStatus(); return p; }));
    // round A: the appearance (light/dark). A console-privileged setting like
    // timesync — it does not touch the gate. Live: setAppearance persists and
    // the new payload (appearance) flows through pushAuthStatus to the
    // renderer, which flips <html>.is-dark.
    ipcMain.handle('settings:set-appearance', guard((value) => { requireAuth(); const p = setAppearance(value); pushAuthStatus(); return p; }));
    // round I: local pages (embedded localhost web UIs). Console-privileged
    // like appearance — set persists and the new list rides the auth status push.
    ipcMain.handle('settings:set-local-pages', guard((list) => { requireAuth(); const p = setLocalPages(list); pushAuthStatus(); return p; }));
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
    // round T: the Time card (the System page). Reads are auth-gated like
    // the other system reads; writes are console-privileged.
    ipcMain.handle('system:time-read', guard(async () => {
        requireAuth();
        const out = { usec: null, zone: null, ntp: null, zones: null };
        try { out.usec = await timeNowUsec(); } catch { /* timedate1 unreachable */ }
        try { out.zone = await timeNowZone(); } catch { /* ditto */ }
        try { out.ntp = await timeNtpEnabled(); } catch { /* ditto */ }
        try { out.zones = listTimezones(); } catch (e) { out.zones = null; out.zonesError = String((e && e.message) || e); }
        return out;
    }));
    ipcMain.handle('system:time-set', guard(async (value) => { requireAuth(); return timeSet(value); }));
    ipcMain.handle('system:timezone-write', guard(async (zone) => { requireAuth(); return timezoneWrite(zone); }));
    ipcMain.handle('settings:set-show-clock', guard((value) => { requireAuth(); const p = setShowClock(value); pushAuthStatus(); return p; }));
    // ip forwarding (network-control interface; reads open, writes are
    // console-privileged like the other system changes)
    // network devices (round 53): the live list (open) + the per-device
    // netplan apply (console-privileged, like the other network changes)
    ipcMain.handle('net:devices', guard(() => getNetDevices()));
    ipcMain.handle('net:apply-device', guard((cfg) => { requireAuth(); return netApplyDevice(cfg); }));
    ipcMain.handle('net:clear-seed', guard(() => { requireAuth(); return clearNetSeedBoilerplate(); }));
    ipcMain.handle('net:forwarding-status', guard(() => ipfwdStatus()));
    ipcMain.handle('net:forwarding-set', guard((b) => { requireAuth(); return ipfwdSet(b); }));

    // ---- round L: System page (console-privileged like every other page) ----
    // Journal (log-observe): the tail is read on demand; a follow streams
    // journalctl -f lines to the renderer over 'system:journal-line'.
    ipcMain.handle('system:journal-tail', guard(async (opts) => {
        requireAuth();
        const r = await journalTail(opts);
        return r;
    }));
    ipcMain.handle('system:journal-follow', guard(async (opts) => {
        requireAuth();
        if (mainWin && !mainWin.isDestroyed()) {
            journalFollow(opts,
                (line) => { if (mainWin && !mainWin.isDestroyed()) mainWin.webContents.send('system:journal-line', line); },
                (err) => { journalFollowKill(); });
        }
        return { started: true };
    }));
    ipcMain.handle('system:journal-stop', guard(async () => {
        requireAuth();
        journalFollowKill();
        return { stopped: true };
    }));
    // Refresh schedule (core config; async snapd change).
    ipcMain.handle('system:refresh-read', guard(async () => {
        requireAuth();
        const value = await refreshTimerRead();
        // 'valid' = the ACCEPTED-state flag ("" default / a valid structured
        // timer / "managed" are all accepted); the user-INPUT grammar check is
        // validRefreshTimer (the renderer uses that, main uses this).
        return { value: value, valid: isRefreshTimerAccepted(value == null ? '' : value) };
    }));
    ipcMain.handle('system:refresh-write', guard(async (value) => {
        requireAuth();
        return refreshTimerWrite(value);
    }));
    // Global refresh hold (round S): the sysinfo LIVE read (open-ish, authed
    // like every other machine read) + the hold/unhold change (console-
    // privileged, like the schedule write).
    ipcMain.handle('system:refresh-hold-read', guard(async () => {
        requireAuth();
        return refreshHoldRead();
    }));
    ipcMain.handle('system:refresh-hold', guard(async (hold) => {
        requireAuth();
        return setGlobalRefreshHold(hold === true);
    }));
    // Round S+2: the 'Refresh now' button (console-privileged, like the hold
    // write - it triggers a store refresh of all installed snaps).
    ipcMain.handle('system:refresh-now', guard(async () => {
        requireAuth();
        return setGlobalRefreshNow();
    }));
    // Power / scheduled shutdown (login1 over D-Bus; the shutdown interface
    // is D-BUS ONLY - no shell-out to poweroff/systemctl).
    ipcMain.handle('system:power', guard(async (action) => {
        requireAuth();
        await powerAction(action);
        return { started: true };
    }));
    ipcMain.handle('system:power-schedule', guard(async (action, whenMs) => {
        requireAuth();
        return powerSchedule(action, whenMs);
    }));
    ipcMain.handle('system:power-cancel-scheduled', guard(async () => {
        requireAuth();
        return powerCancelScheduled();
    }));
    ipcMain.handle('system:power-scheduled', guard(async () => {
        requireAuth();
        return powerScheduledRead();
    }));
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
