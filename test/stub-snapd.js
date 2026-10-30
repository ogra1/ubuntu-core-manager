'use strict';

/**
 * test/stub-snapd.js — a minimal snapd emulator over a Unix Domain Socket.
 * Used to integration-test main.js's snapd client without a real Ubuntu Core
 * device. It enforces the same auth contract as the real daemon:
 *   - POST /v2/login issues a root macaroon + a discharge (fake but shaped
 *     like the real thing); the Authorization header must carry
 *     `Macaroon root="..." discharge="..."` for authenticated routes.
 *   - Writes require valid auth; reads are open (like snapd openAccess).
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const SNAPS = [
    {
        name: 'core24', version: '24.04', revision: 4110, channel: '24.04',
        status: 'active', type: 'core', confinement: 'strict', 'tracking-channel': '24.04/stable',
        private: false, installDate: '2026-01-01T00:00:00Z',
    },
    {
        name: 'snapd', version: '2.68', revision: 23448, channel: 'stable', 'tracking-channel': 'latest/stable',
        status: 'active', type: 'snapd', confinement: 'strict',
        private: false, installDate: '2026-01-01T00:00:00Z',
    },
    {
        name: 'htop', version: '3.3.0', revision: 5533, channel: 'latest/stable',
        status: 'active', type: 'app', confinement: 'strict',
        private: false, installDate: '2026-02-01T00:00:00Z',
    },
];

const CONNECTIONS = {
    established: [
        {
            interface: 'network',
            plug: { snap: 'firefox', plug: 'network' },
            slot: { snap: 'core24', slot: 'network' },
            manual: true, gadget: false,
        },
    ],
    undesired: [
        {
            interface: 'home',
            plug: { snap: 'snap-store', plug: 'home' },
            slot: { snap: 'core24', slot: 'home' },
            manual: true, gadget: false,
        },
    ],
    plugs: [
        { snap: 'firefox', name: 'network', interface: 'network', connections: [{ snap: 'core24', slot: 'network' }] },
        { snap: 'snap-store', name: 'home', interface: 'home', connections: [] },
        { snap: 'firefox', name: 'browser', interface: 'browser', connections: [] },
    ],
    slots: [
        { snap: 'core24', name: 'network', interface: 'network', connections: [{ snap: 'firefox', plug: 'network' }] },
        { snap: 'core24', name: 'home', interface: 'home', connections: [] },
        { snap: 'core24', name: 'browser', interface: 'browser', connections: [] },
    ],
};

const NETPLAN_YAML = `network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true
`;

function json(res, status, body) {
    const payload = status >= 400
        ? { type: 'error', statuscode: status, result: body }
        : { type: 'sync', statuscode: status, result: body };
    const raw = JSON.stringify(payload);
    res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(raw) });
    res.end(raw);
}

function authFrom(req) {
    const h = req.headers['authorization'] || '';
    const root = h.match(/root="([^"]+)"/);
    const dis = [...h.matchAll(/discharge="([^"]+)"/g)].map((m) => m[1]);
    return {
        ok: h.startsWith('Macaroon') && !!root && root[1] === 'stub-root-macaroon'
            && dis.includes('stub-discharge-1'),
        root, dis,
    };
}

function makeServer(socketPath, state) {
    // Per-snap configuration documents (snapd /v2/snaps/{name}/conf).
    // htop ships defaults so the conf UI has something to edit; core keeps
    // the netplan external-config key. `null` values model removed keys.
    state.conf = state.conf || {
        htop: { port: '8080', 'logging.level': 'info' },
    };

    fs.existsSync(socketPath) && fs.unlinkSync(socketPath);
    const server = http.createServer((req, res) => {
        const url = new URL(req.url, 'http://stub');
        const p = url.pathname;
        const auth = authFrom(req);
        const body = () => new Promise((resolve) => {
            const chunks = [];
            req.on('data', (c) => chunks.push(c));
            req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        });

        (async () => {
            state.requests.push({ method: req.method, path: p, authed: auth.ok, rawAuth: req.headers['authorization'] || '' });

            // ---- login ---------------------------------------------------
            if (p === '/v2/login' && req.method === 'POST') {
                const data = JSON.parse(await body());
                if (data.username === 'admin@example.com' && data.password === 'correct-horse') {
                    return json(res, 200, {
                        username: data.username,
                        macaroon: 'stub-root-macaroon',
                        discharges: ['stub-discharge-1'],
                    });
                }
                return json(res, 400, { kind: 'snapd-login-invalid', message: 'cannot authenticate the user: invalid credentials' });
            }

            // ---- logout ----------------------------------------------------
            if (p === '/v2/logout' && req.method === 'POST') {
                if (!auth.ok) return json(res, 401, { kind: 'unauthenticated', message: 'unauthenticated access' });
                state.logoutCount += 1;
                return json(res, 200, {});
            }

            // ---- system info / storage ------------------------------------
            if (p === '/v2/system-info' && req.method === 'GET') {
                return json(res, 200, {
                    version: '2.68', series: '16', brand: 'canonical', model: 'core-24-kvm',
                    kernel_version: '6.8.0-40-generic', on_architecture: 'amd64',
                    system_id: 'deadbeef', serial: '0001',
                    storage: { total: 4194304000, used: 1288490188, used_percent: 31, model: 'virtio', type: 'ssd' },
                    cloud_init: { status: 'done' },
                });
            }
            if (p === '/v2/system-info/storage' && req.method === 'GET') {
                return json(res, 200, { total: 4194304000, used: 1288490188, used_percent: 31 });
            }

            // ---- warnings / changes ----------------------------------------
            if (p === '/v2/warnings' && req.method === 'GET') {
                return json(res, 200, [{ warn: 'some warning', last: '2026-10-28T00:00:00Z' }]);
            }
            if (p === '/v2/changes' && req.method === 'GET') {
                const sel = url.searchParams.get('select') || 'all';
                const list = sel === 'in-progress' ? state.changes.filter((c) => c.status === 'Doing')
                    : sel === 'ready' ? state.changes.filter((c) => c.status !== 'Doing')
                    : state.changes;
                return json(res, 200, list);
            }
            // single change (status polling after a write returns { id })
            const chRe = p.match(/^\/v2\/changes\/(\d+)$/);
            if (chRe && req.method === 'GET') {
                const c = state.changes.find((x) => x.id === chRe[1]);
                if (!c) return json(res, 404, { kind: 'not-found', message: `cannot find change ${chRe[1]}` });
                // real snapd: result = { id, kind, summary: "<string>", status, tasks, ... }
                return json(res, 200, { id: c.id, kind: c.kind, summary: (c.summary && c.summary.message) || c.summary, status: c.status });
            }

            // ---- snaps --------------------------------------------------------
            if (p === '/v2/snaps' && req.method === 'GET') {
                return json(res, 200, SNAPS);
            }
            const snapRe = p.match(/^\/v2\/snaps\/([^/]+)$/);
            if (snapRe) {
                const name = decodeURIComponent(snapRe[1]);
                if (req.method === 'GET') {
                    const s = SNAPS.find((x) => x.name === name) || { name, version: '1.0', revision: 1, status: 'active', channel: 'stable', type: 'app' };
                    s.publisher = { username: 'canonical' };
                    s.description = 'stub description';
                    s.channels = { 'latest/stable': { version: s.version, revision: s.revision, size: 1024, released_at: '2026-10-01T00:00:00Z' } };
                    return json(res, 200, s);
                }
                if (req.method === 'POST') {
                    if (!auth.ok) return json(res, 401, { kind: 'unauthenticated', message: 'unauthenticated access' });
                    const data = JSON.parse(await body());
                    state.snapActions.push({ name, data });
                    const allowed = ['install', 'refresh', 'remove', 'enable', 'disable', 'hold', 'unhold', 'revert', 'switch'];
                    if (!allowed.includes(data.action)) {
                        return json(res, 400, { kind: 'not-found', message: `cannot run action "${data.action}" on snap "${name}"` });
                    }
                    if (data.action === 'install' && SNAPS.find((s) => s.name === name)) {
                        return json(res, 400, { kind: 'snap-already-installed', message: `snap "${name}" is already installed` });
                    }
                    // Real snapd semantics: the write returns a change id; the snap
                    // list only reflects the result once the change settles. The
                    // UI must poll /v2/changes/{id} and reload AFTER that.
                    const id = String(state.changeSeq += 1);
                    const change = {
                        id,
                        kind: data.action + '-snap',
                        summary: { message: `${data.action[0].toUpperCase() + data.action.slice(1)} snap "${name}"` },
                        status: 'Doing',
                        spawn_time: new Date().toISOString(),
                    };
                    state.changes.push(change);
                    // The list mutation and the terminal state land TOGETHER (snapd
                    // applies a snap's list change atomically when the change
                    // completes) — otherwise a poll that sees "Done" could still
                    // read the pre-mutation list.
                    if (data.action === 'remove') {
                        // LIVE-VERIFIED (snapd 2.77): the in-flight status oscillates
                        // "Doing" <-> transient "Do" before the terminal state. The
                        // client must keep polling through "Do".
                        setTimeout(() => { if (change.status === 'Doing') change.status = 'Do'; }, 60);
                        setTimeout(() => {
                            const i = SNAPS.findIndex((x) => x.name === name);
                            if (i >= 0) SNAPS.splice(i, 1);
                            change.status = 'Done';
                        }, 320);
                    } else {
                        setTimeout(() => {
                            SNAPS.push({ name, version: '9.9.9', revision: 1, channel: 'stable',
                                'tracking-channel': (data.channel && data.channel.includes('/')) ? data.channel : 'latest/stable',
                                status: 'active', type: 'app', confinement: 'strict' });
                            change.status = 'Done';
                        }, 300);
                    }
                    // REAL snapd 2.77 async envelope (verified on a live daemon):
                    //   { "type":"async", "status-code":202, "result": null, "change": "<id>" }
                    // The change id is at the ENVELOPE top level — the UI client must
                    // read `change`, not `result.id`. (A stub that returns {id} in
                    // result masked this exact bug for three rounds.)
                    const payload = JSON.stringify({ type: 'async', 'status-code': 202, status: 'Accepted', result: null, change: id });
                    return new Promise((resolve) => {
                        res.writeHead(202, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) });
                        res.end(payload);
                        resolve();
                    });
                }
            }

            // ---- snap conf (system config incl. netplan) ----------------------
            // Per-snap config documents: GET /v2/snaps/{name}/conf[?keys=k]
            // -> { k: value } | { k: null }; PUT /v2/snaps/{name}/conf with a
            // {key: scalar|null} map. `core` additionally carries the netplan
            // external-config key. null values remove the key (snapd semantics).
            const confRe = p.match(/^\/v2\/snaps\/([^/]+)\/conf$/);
            if (confRe) {
                const name = decodeURIComponent(confRe[1]);
                if (req.method === 'GET') {
                    const keys = url.searchParams.get('keys');
                    if (name === 'core' && (keys === null || keys.startsWith('system.network.netplan'))) {
                        return json(res, 200, { 'system.network.netplan': state.netplanYaml });
                    }
                    const doc = state.conf[name] || {};
                    if (keys === null) return json(res, 200, doc);
                    const k = decodeURIComponent(keys);
                    return json(res, 200, { [k]: Object.prototype.hasOwnProperty.call(doc, k) ? doc[k] : null });
                }
                if (req.method === 'PUT') {
                    if (!auth.ok) return json(res, 401, { kind: 'unauthenticated', message: 'unauthenticated access' });
                    const data = JSON.parse(await body());
                    state.confSets.push({ name, data });
                    if (name === 'core' && data['system.network.netplan']) {
                        state.netplanYaml = data['system.network.netplan'];
                    } else {
                        if (!state.conf[name]) state.conf[name] = {};
                        for (const [k, v] of Object.entries(data)) {
                            if (v === null) delete state.conf[name][k];
                            else state.conf[name][k] = v;
                        }
                    }
                    return json(res, 200, {});
                }
            }

            // ---- find (store search) -------------------------------------------
            if (p === '/v2/find' && req.method === 'GET') {
                const q = (url.searchParams.get('name') || '').toLowerCase();
                return json(res, 200, [
                    { name: 'mosquitto', summary: 'MQTT broker', publisher: { username: 'mosquitto-dev' }, channels: { 'latest/stable': {} } },
                    { name: 'firefox', summary: 'Web browser', publisher: { username: 'mozilla-canonical' }, channels: { 'latest/stable': {} } },
                ].filter((s) => s.name.includes(q)));
            }

            // ---- interfaces ------------------------------------------------------
            if (p === '/v2/connections' && req.method === 'GET') {
                return json(res, 200, url.searchParams.get('select') === 'all' ? CONNECTIONS : { ...CONNECTIONS, undesired: [] });
            }
            if (p === '/v2/interfaces' && req.method === 'POST') {
                if (!auth.ok) return json(res, 401, { kind: 'unauthenticated', message: 'unauthenticated access' });
                const data = JSON.parse(await body());
                state.ifaceOps.push(data);
                if (data.action !== 'connect' && data.action !== 'disconnect') {
                    return json(res, 400, { kind: 'not-found', message: `unsupported action "${data.action}"` });
                }
                return json(res, 200, { interface: 'stub', plug: data.plug, slot: data.slot, status: 'Done' });
            }

            return json(res, 404, { kind: 'not-found', message: `cannot find ${req.method} ${p}` });
        })().catch((e) => json(res, 500, { kind: 'internal', message: String(e) }));
    });

    return new Promise((resolve) => {
        server.listen(socketPath, () => resolve(server));
    });
}

module.exports = { makeServer };

if (require.main === module) {
    const sock = process.argv[2] || '/tmp/stub-snapd.socket';
    const state = { requests: [], snapActions: [], confSets: [], ifaceOps: [], changeSeq: 100, logoutCount: 0, netplanYaml: NETPLAN_YAML, changes: [
        { id: '1', kind: 'install-snap', summary: { message: 'Install snap "htop"' }, status: 'Done', spawn_time: '2026-10-28T09:00:00Z' },
        { id: '2', kind: 'configure-snap', summary: { message: 'Configure snap "core24"' }, status: 'Ready', spawn_time: '2026-10-28T10:00:00Z' },
    ] };
    makeServer(sock, state).then(() => {
        console.log('stub snapd listening on ' + sock);
        setInterval(() => {
            fs.writeFileSync('/tmp/stub-snapd-state.json', JSON.stringify(state, null, 1));
        }, 500);
    });
}
