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
 *     connected `snapd-control` interface) — no shell-outs, no direct
 *     /etc writes, no renderer-side network.
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

// Store channels we will ever dial: official risk levels only.
const RE_CHANNEL = /^(latest|candidate|beta|edge|stable|devel)(\/[a-z0-9.-]+)?(\/[a-z0-9.-]+)?$/;
const CHANNEL_WHITELIST = new Set(['latest', 'candidate', 'beta', 'edge', 'stable', 'devel']);

// IPv4 CIDR, e.g. 192.168.1.50/24
const RE_IPV4_CIDR = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\/(3[0-2]|2\d|1\d|[1-9])$/;
// IPv6 CIDR, e.g. fd00::1/64
const RE_IPV6_CIDR = /^[0-9a-f:]+\/(12[0-8]|1[01]\d|[1-9]\d)$/i;
const RE_IPV4 = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const RE_IPV6 = /^[0-9a-f:]+$/i;

// Netplan interface names: eth0, enp3s0, ens18, wlan0, ...
const RE_IFACE_NAME = /^[A-Za-z][A-Za-z0-9._:-]{0,15}$/;

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

function validChannel(channel) {
    return typeof channel === 'string' && RE_CHANNEL.test(channel)
        && CHANNEL_WHITELIST.has(channel.split('/')[0]);
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
                    resolve(data && data.result !== undefined ? data.result : (data === null ? {} : data));
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

async function getDisk() {
    return snapdRequest('GET', '/v2/system-info/storage', { auth: A() });
}

async function listChanges(select = 'all') {
    const s = ['in-progress', 'ready', 'all'].includes(select) ? select : 'all';
    return snapdRequest('GET', '/v2/changes?select=' + s, { auth: A() });
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

/** GET /v2/find — search the store. */
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
        throw new Error('invalid channel (allowed: latest/candidate/beta/edge/stable/devel): ' + JSON.stringify(channel));
    }
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

/* ------------------------------------------------------------------ *
 * 7. Write APIs — configuration (snap conf + netplan network setup)
 *
 * Modern snapd exposes system configuration as per-snap documents:
 * PUT /v2/snaps/{name}/conf (there is no generic /v2/config route in
 * current snapd). On Ubuntu Core the netplan document is the external
 * config key `core.system.network.netplan` — snapd pushes it to the
 * netplan D-Bus service and applies it atomically.
 * ------------------------------------------------------------------ */

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
        body[k] = v;
    }
    if (Object.keys(body).length === 0) throw new Error('empty config payload');
    return snapdRequest('PUT', '/v2/snaps/' + encodeURIComponent(name) + '/conf', { body, auth: A() });
}

/** Build the netplan section for one static-IP (or DHCP) interface. */
function buildNetplanIface({ interface: ifname, mode, ipv4, ipv6, gateway4, gateway6, dns }) {
    const net = {};
    if (mode === 'dhcp4') {
        net.dhcp4 = true;
    } else if (mode === 'static') {
        if (!RE_IPV4_CIDR.test(ipv4)) throw new Error('ipv4 must be IPv4 with /prefix (e.g. 192.168.1.50/24)');
        if (gateway4 && !RE_IPV4.test(gateway4)) throw new Error('gateway4 must be a bare IPv4 address');
        const v4 = { addresses: [ipv4] };
        if (gateway4) v4.gateway4 = gateway4;
        net.ipv4 = v4;
        if (ipv6) {
            if (!RE_IPV6_CIDR.test(ipv6)) throw new Error('ipv6 must be IPv6 with /prefix (e.g. fd00::1/64)');
            if (gateway6 && !RE_IPV6.test(gateway6)) throw new Error('gateway6 must be a bare IPv6 address');
            const v6 = { addresses: [ipv6] };
            if (gateway6) v6.gateway6 = gateway6;
            net.ipv6 = v6;
        }
    } else {
        throw new Error('mode must be "dhcp4" or "static"');
    }
    if (dns === true || Array.isArray(dns)) {
        const d = dns === true ? [] : dns.map((x) => {
            if (typeof x !== 'string' || !(RE_IPV4.test(x) || RE_IPV6.test(x))) {
                throw new Error('invalid dns entry: ' + JSON.stringify(x));
            }
            return x;
        });
        if (d.length) net.dns = { nameservers: { addresses: d } };
    }
    return net;
}

/**
 * Apply a network change through snapd's netplan external config
 * (PUT /v2/snaps/core/conf, key system.network.netplan). Read-modify-write
 * on the full document; snapd/netplan apply it atomically.
 */
async function applyNetplanConfig(netcfg) {
    if (!netcfg || typeof netcfg !== 'object') throw new Error('network config payload required');
    const iface = netcfg.interface;
    if (typeof iface !== 'string' || !RE_IFACE_NAME.test(iface)) {
        throw new Error('invalid interface name: ' + JSON.stringify(iface));
    }

    const cur = await getSnapConfig('core', 'system.network.netplan');
    const doc = (cur && typeof cur === 'string') ? fromYaml(cur)
        : (cur && yamlIsMap(cur)) ? cur : {};
    if (!yamlIsMap(doc.network)) doc.network = {};
    if (!yamlIsMap(doc.network.ethernets)) doc.network.ethernets = {};

    doc.network.ethernets[iface] = buildNetplanIface(netcfg);

    const yaml = toYaml(doc);
    return setSnapConfig('core', { 'system.network.netplan': yaml });
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
 * 8. Interfaces (plug/slot control)
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

/** GET /v2/connections — full plug/slot topology. */
async function listInterfaces() {
    return snapdRequest('GET', '/v2/connections', { auth: A() });
}

/** POST /v2/interfaces {action:"connect", plug, slot}. */
async function connectInterface(plug, slot) {
    if (!validPlugRef(plug)) throw new Error('invalid plug reference');
    if (!validSlotRef(slot)) throw new Error('invalid slot reference');
    return snapdRequest('POST', '/v2/interfaces', {
        body: { action: 'connect', plug, slot },
        auth: A(),
    });
}

/** POST /v2/interfaces {action:"disconnect", plug, slot}. */
async function disconnectInterface(plug, slot) {
    if (!validPlugRef(plug)) throw new Error('invalid plug reference');
    if (!validSlotRef(slot)) throw new Error('invalid slot reference');
    return snapdRequest('POST', '/v2/interfaces', {
        body: { action: 'disconnect', plug, slot },
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

/* ------------------------------------------------------------------ *
 * 10. Public API (Electron entry AND headless test harness use this)
 * ------------------------------------------------------------------ */

const api = {
    SNAPD_SOCKET,
    SESSION_TIMEOUT_MS,
    validSnapName, validChannel,
    toYaml, fromYaml, buildNetplanIface,
    readHostStats, readProcNetDev,

    // local admin gate (the UI lock screen; offline)
    createLocalPassword, loginLocal, logoutLocal, authStatus, detectInitialized,
    // store auth (optional, volatile)
    storeLogin, storeLogout,

    getSystemInfo, getDisk, listChanges, getWarnings,
    listSnaps, getSnapInfo, searchSnaps,
    getSnapConfig, getNetplan, listInterfaces,

    installSnap, snapAction,
    setSnapConfig, applyNetplanConfig,
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
    ipcMain.on('session:activity', () => { if (session.localAuthenticated) armInactivity(); });

    // ---- optional store login (macaroons; needs network) ------------
    ipcMain.handle('store:login', guard(async (email, password) => { const p = await storeLogin(email, password); pushAuthStatus(); return p; }));
    ipcMain.handle('store:logout', guard(async () => { const p = await storeLogout(); pushAuthStatus(); return p; }));

    // ---- reads / writes (writes require the local gate) -------------
    ipcMain.handle('sys:info', guard(async () => ({
        snapd: await getSystemInfo().catch(() => null),
        host: readHostStats(),
        netdev: readProcNetDev(),
        warnings: await getWarnings().catch(() => []),
    })));
    ipcMain.handle('sys:disk', guard(() => getDisk()));
    ipcMain.handle('sys:changes', guard((select) => listChanges(select)));
    ipcMain.handle('sys:netplan', guard(() => getNetplan()));

    ipcMain.handle('snaps:list', guard(() => listSnaps()));
    ipcMain.handle('snaps:info', guard((name) => getSnapInfo(name)));
    ipcMain.handle('snaps:search', guard((q, n) => searchSnaps(q, n)));
    ipcMain.handle('snaps:install', guard((name, channel) => { requireAuth(); return installSnap(name, channel); }));
    ipcMain.handle('snaps:action', guard((name, action, extra) => { requireAuth(); return snapAction(name, action, extra || {}); }));
    ipcMain.handle('snaps:conf-get', guard((name, key) => getSnapConfig(name, key || null)));
    ipcMain.handle('snaps:conf-set', guard((name, conf) => { requireAuth(); return setSnapConfig(name, conf); }));

    ipcMain.handle('net:apply', guard((netcfg) => { requireAuth(); return applyNetplanConfig(netcfg); }));
    ipcMain.handle('ifaces:list', guard(() => listInterfaces()));
    ipcMain.handle('ifaces:connect', guard((plug, slot) => { requireAuth(); return connectInterface(plug, slot); }));
    ipcMain.handle('ifaces:disconnect', guard((plug, slot) => { requireAuth(); return disconnectInterface(plug, slot); }));

    // ---- app lifecycle ------------------------------------------------
    app.whenReady().then(() => {
        createKioskWindow();
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
