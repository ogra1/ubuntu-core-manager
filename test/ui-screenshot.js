'use strict';

/**
 * test/ui-screenshot.js — headless-loads ui/index.html with a mocked
 * `window.ucmCore` bridge (same shape as preload.js) and captures one
 * screenshot per view/state for visual QA.
 *
 * Mocked auth model:
 *   - local gate: initialized=false initially; create(password) requires
 *     'correct-horse'; login(password) requires 'correct-horse';
 *     reset(password) requires the ACTIVE session + 'correct-horse' and
 *     wipes the credential (next state = first-boot setup).
 *   - store login is NOT used by the UI anymore (model-attachment design);
 *     search/install mocks succeed unauthenticated, like a VM with network.
 *
 * Usage: node test/ui-screenshot.js   (writes /root/shots/*.png)
 */

const path = require('path');
const fs = require('fs');
const puppeteer = require('puppeteer');

const ROOT = path.join(__dirname, '..');
const SHOTS = '/root/shots';
fs.mkdirSync(SHOTS, { recursive: true });

const SNAPS = [
    // a core24 BASE is type 'base' on a real system (the 'core' type only
    // exists on pre-core20 classic installs) - the user's "oddly core" row.
    { name: 'core24', version: '24.04.3', revision: 4110, channel: 'stable', 'tracking-channel': '24.04/stable', status: 'active', type: 'base', confinement: 'strict' },
    { name: 'snapd', version: '2.68.4', revision: 23448, channel: 'stable', 'tracking-channel': 'latest/stable', status: 'active', type: 'snapd', confinement: 'strict' },
    { name: 'kernel-noble', version: '6.8.0-40', revision: 1189, channel: 'stable', 'tracking-channel': 'noble/stable', status: 'active', type: 'kernel', confinement: 'strict' },
    // a LOCAL gadget build (x-prefixed revision, no channel — the user's
    // real VM's 'pc' gadget): round 47h must NOT offer it a store switch.
    { name: 'gadget', version: '1.2', revision: 'x1', status: 'active', type: 'gadget', confinement: 'jailmode' },
    { name: 'htop', version: '3.3.0', revision: 5533, channel: 'stable', 'tracking-channel': 'latest/stable', status: 'active', type: 'app', confinement: 'strict' },
    { name: 'mosquitto', version: '2.0.19', revision: 14077, channel: 'stable', 'tracking-channel': 'latest/stable', status: 'active', type: 'app', confinement: 'strict' },
    { name: 'firefox', version: '141.0.2', revision: 543210, channel: 'stable', 'tracking-channel': 'latest/stable', status: 'active', type: 'app', confinement: 'strict' },
    { name: 'old-tool', version: '0.9', revision: 12, channel: 'candidate', 'tracking-channel': 'latest/candidate', status: 'installed', type: 'app', confinement: 'devmode' },
    // a LOCAL sideloaded APP (x-prefixed revision, no channel — round 47j): a
    // store refresh can never apply to it ('no updates available'), so its row
    // must omit the Refresh icon. NOT in the mock STORE (find -> []).
    { name: 'nextcloud', version: '30.0.1', revision: 'x42', status: 'active', type: 'app', confinement: 'strict' },
    // model-`presence: required` app (declared in the mock model) — round 47k
    // must DROP its Remove icon; keeps settings/refresh/revert/power.
    { name: 'snap-store', version: '1.0', revision: 9999, channel: 'stable', 'tracking-channel': 'latest/stable', status: 'active', type: 'app', confinement: 'strict' },
    // a base-type snap the MODEL does NOT declare (apps can depend on a
    // second base): NOT a system snap — it keeps Refresh/Revert/Disable/
    // Remove, only loses Config (round 46b tier 2).
    { name: 'core22', version: '22.04.5', revision: 3120, channel: 'stable', 'tracking-channel': '22.04/stable', status: 'active', type: 'base', confinement: 'strict' },
];

// Rich single-snap details (the harness stand-in for the live
// GET /v2/snaps/{name} object, which carries more than the list fields:
// title / summary / description / publisher / installed-size /
// install-date / links / id). Merged over the SNAPS entry by info().
const SNAP_INFO = {
    htop: {
        title: "Host resources monitor",
        summary: "Interactive ps",
        description: "htop is an **interactive** process viewer for Unix-like systems.\n\nIt shows a task list and a real-time view of CPU/memory usage, including a live view of each process\u2019s threads, open files and environment.\n\nFeatures:\n- Full-screen, keyboard-driven interface\n- Sortable by CPU, memory or any column\n- Per-process I/O and network monitoring\n- Kill, renice and signal any process\n\n0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\nThe task list updates continuously while you watch. See <https://htop.dev> for screenshots and <https://github.com/vt100/htop> for the source and the issue tracker. htop is free software under the GNU General Public License.",
        publisher: { id: "htop-dev", username: "htop-dev", "display-name": "htop-dev", validation: "starred" },
        "installed-size": 8948736,
        "install-date": "2026-10-20T09:15:00Z",
        id: "SNAPINFO-htop-0001",
        links: { website: ["https://htop.dev"], source: ["https://github.com/vt100/htop"], contact: ["https://github.com/vt100/htop/issues"] },
    },
    core24: {
        // canonical-verified, NO title/summary/description/links — exercises
        // the verified check + the 'no display-title' path + the divider.
        publisher: { id: "canonical", username: "canonical", "display-name": "Canonical", validation: "verified" },
    },
};

// Store channel maps per snap (the round-47g mock stand-in for
// /v2/find?name=..., which the info modal uses to offer a channel
// switcher). Snap absent here = a LOCAL snap (no store channels -> no
// switcher, the 'local' marker instead).
const STORE = {
    // a same-named store snap exists for the (local) gadget — the round-47h
    // foot-gun. The switcher must be suppressed by the x revision, NOT by
    // this being empty (it is not empty).
    gadget: { 'latest/stable': {}, 'pc/stable': {} },
    htop: { 'latest/stable': {}, 'latest/candidate': {}, 'latest/beta': {}, 'latest/edge': {},
        '3.3/stable': {}, '3.3/candidate': {}, '3.2/stable': {} },
    firefox: { 'latest/stable': {}, 'latest/candidate': {}, 'latest/edge': {},
        '141/stable': {}, '140/stable': {} },
    mosquitto: { 'latest/stable': {}, 'latest/edge': {}, '2.0/stable': {} },
};

// Per-snap configuration documents (snapd /v2/snaps/{name}/conf).
const SNAP_CONF = {
    htop: { port: '8080', 'logging.level': 'info' },
};

const IFACES = {
    plugs: [
        { snap: 'firefox', plug: 'network', interface: 'network', apps: ['firefox'], connections: [{ snap: 'core', slot: 'network' }] },
        { snap: 'firefox', plug: 'browser', interface: 'browser', apps: ['firefox'], connections: null },
        { snap: 'mosquitto', plug: 'network-bind', interface: 'network-bind', apps: ['mosquitto'], connections: [{ snap: 'core', slot: 'network-bind' }] },
        { snap: 'snap-store', plug: 'home', interface: 'home', apps: ['snap-store'], connections: null },
        { snap: 'htop', plug: 'home', interface: 'home', apps: ['htop'], connections: null },
        { snap: 'radio', plug: 'pps', interface: 'pps', apps: ['radio'], connections: null },
        { snap: 'ucm', plug: 'icon-themes', interface: 'icon-themes', apps: ['ucm'], connections: null },
        // lxd (the user's real example): plug named ceph-conf on the 'content'
        // interface (plug name != interface name) — connected; its Disconnect
        // tooltip must say "ceph-conf", not "content".
        { snap: 'lxd', plug: 'ceph-conf', interface: 'content', apps: ['lxd'], connections: [{ snap: 'data-provider', slot: 'ceph-conf' }] },
    ],
    slots: [
        { snap: 'core', slot: 'network', interface: 'network', connections: [{ snap: 'firefox', plug: 'network' }] },
        { snap: 'core', slot: 'network-bind', interface: 'network-bind', connections: [{ snap: 'mosquitto', plug: 'network-bind' }] },
        { snap: 'core', slot: 'home', interface: 'home', connections: null },
        // the browser interface: one differently-NAMED slot (browser-proxy,
        // NOT 'browser' — so no same-name match for the firefox:browser plug)
        // -> the lxd case: snapd would accept it but it is the wrong namespace,
        // so the UI must NOT offer a pulldown and must treat the plug as having
        // no usable target.
        { snap: 'snap-store', slot: 'browser-proxy', interface: 'browser', connections: null },
        // content interfaces: gtk-common-themes and ubuntu-frame both expose
        // icon-themes — but only the same-NAMED slot qualifies for the ucm
        // icon-themes plug (namespacing), so no pulldown is needed. The
        // gtk-2-themes / ubuntu-frame-diagnostic slots are decoys with other names.
        { snap: 'gtk-common-themes', slot: 'gtk-2-themes', interface: 'icon-themes', connections: null },
        { snap: 'gtk-common-themes', slot: 'icon-themes', interface: 'icon-themes', connections: null },
        { snap: 'ubuntu-frame', slot: 'ubuntu-frame-diagnostic', interface: 'icon-themes', connections: null },
        { snap: 'data-provider', slot: 'ceph-conf', interface: 'content', connections: [{ snap: 'lxd', plug: 'ceph-conf' }] },
    ],
};

const NETPLAN = {
    network: {
        version: 2,
        ethernets: {
            eth0: { dhcp4: true },
            enp3s0: {
                dhcp4: false,
                addresses: ['10.0.0.5/24'],
                gateway4: '10.0.0.1',
                dns: { nameservers: { addresses: ['1.1.1.1', '8.8.8.8'] } },
            },
        },
    },
};

// The mock is (re)created inside the page so functions survive
// evaluateOnNewDocument (argument serialization would strip them).
function mockFactoryJs() {
    return `
    window.__mockCore = (function () {
        let SNAPS = ${JSON.stringify(SNAPS)};
        const CONF = ${JSON.stringify(SNAP_CONF)};
        const INFO = ${JSON.stringify(SNAP_INFO)};
        const STORE = ${JSON.stringify(STORE)};
        const CHANGES = {};
        let IFC = ${JSON.stringify(IFACES)};
        const NETPLAN = ${JSON.stringify(NETPLAN)};
        const LOCAL_PW = 'correct-horse';
        let localSet = false;
        let localAuthed = false;
        let cpuCalls = 0;
        let netCalls = 0;
        const status = () => ({
            initialized: localSet,
            authenticated: localAuthed,
            expiresAt: localAuthed ? Date.now() + 900000 : null,
            timeoutMs: 900000,
            storeAuthenticated: false,
            storeUsername: null,
        });
        return {
            auth: {
                async create(pw) {
                    if (localSet) throw new Error('a local administrator password already exists — sign in instead');
                    if (pw !== LOCAL_PW) throw new Error('simulated: weak password');
                    localSet = true; localAuthed = true;
                    return status();
                },
                async login(pw) {
                    if (!localSet) throw new Error('no local administrator password is set — create one first');
                    if (pw !== LOCAL_PW) throw new Error('incorrect password');
                    localAuthed = true;
                    return status();
                },
                async logout() { localAuthed = false; return status(); },
                // Guarded local-admin reset: active session + correct current
                // password; wipes the credential (initialized=false).
                async reset(pw) {
                    if (!localAuthed) throw new Error('authentication required — sign in as the current administrator first');
                    if (pw !== LOCAL_PW) throw new Error('incorrect password');
                    localSet = false; localAuthed = false;
                    return status();
                },
                async status() { return status(); },
                onStatusChanged() { return () => {}; },
            },
            store: {
                // Backend-only (not used by the UI anymore); kept so the
                // bridge contract stays complete.
                async login() { throw new Error('store login is no longer exposed in the UI'); },
                async logout() { return status(); },
            },
            system: {
                async info() {
                    return {
                        snapd: {
                            version: '2.68.4', series: '16', architecture: 'amd64',
                            'kernel-version': '6.8.0-40-generic',
                            'os-release': { id: 'ubuntu', 'version-id': '24.04' },
                            refresh: { timer: '00:00~24:00/4', last: '2026-10-30T18:45:00Z', next: '2026-10-31T03:55:00Z' },
                        },
                        model: {
                            'authority-id': 'canonical', series: '16', 'brand-id': 'canonical',
                            model: 'core-24-kvm', base: 'core24', grade: 'signed',
                            architecture: 'amd64', 'sign-key-sha3-384': 'stub-key-id',
                            // the model assertion's snaps: list (parsed in
                            // main.js) — DEFINES the system snaps (top-level
                            // base + gadget/kernel/snapd/os entries). Note the
                            // required APP snaps: they are in the model but are
                            // NOT system snaps (round 46b). core22 (a base in
                            // SNAPS) is deliberately NOT listed here.
                            snaps: [
                                { name: 'snapd', type: 'snapd', 'default-channel': 'latest/stable' },
                                { name: 'core24', type: 'base', 'default-channel': 'latest/stable' },
                                { name: 'kernel-noble', type: 'kernel', 'default-channel': 'noble/stable' },
                                { name: 'gadget', type: 'gadget', 'default-channel': 'local' },
                                { name: 'snap-store', type: 'app', presence: 'required', 'default-channel': 'latest/stable' },
                            ],
                        },
                        host: {
                            hostname: 'core-kvm-01', platform: 'linux', arch: 'x64',
                            mem: { total: 8589934592, available: 4294967296, used: 4294967296, usedPercent: 50 },
                            load: [0.42, 0.31, 0.22], uptimeSec: 3723000, cpus: 4,
                            swap: { total: 1073741824, free: 1073741824 },
                        },
                        netdev: [
                            { name: 'lo', rxBytes: 1048576, txBytes: 1048576 },
                            { name: 'eth0', rxBytes: 9961472000, txBytes: 1509949440 },
                            { name: 'enp3s0', rxBytes: 524288000, txBytes: 209715200 },
                        ],
                        // LIVE-verified warning shape { message, first-seen,
                        // last-seen } (user demo data). The newest (by
                        // last-seen) is the long 'apiVersion' message and it
                        // is deliberately LAST in the array.
                        warnings: [
                            { message: 'Another system-level warning message here', 'first-seen': '2026-10-20T12:00:00Z', 'last-seen': '2026-10-21T14:30:00Z', 'delete-after': '1h30m' },
                            { message: "Option value has invalid field name 'apiVersion'. For core26+ snaps, fields must be dash separated lowercase alphanumerics.", 'first-seen': '2026-10-05T16:00:44Z', 'last-seen': '2026-10-22T16:05:12Z' },
                        ],
                    };
                },
                async model() {
                    // the dedicated sys:model route (main.js getModelAssertion)
                    // — loadSnaps uses it when the dashboard's sys:info hasn't
                    // populated the model yet.
                    return {
                        'authority-id': 'canonical', series: '16', 'brand-id': 'canonical',
                        model: 'core-24-kvm', base: 'core24', grade: 'signed',
                        architecture: 'amd64', 'sign-key-sha3-384': 'stub-key-id',
                        snaps: [
                            { name: 'snapd', type: 'snapd', 'default-channel': 'latest/stable' },
                            { name: 'core24', type: 'base', 'default-channel': 'latest/stable' },
                            { name: 'kernel-noble', type: 'kernel', 'default-channel': 'noble/stable' },
                            { name: 'gadget', type: 'gadget', 'default-channel': 'local' },
                            { name: 'snap-store', type: 'app', presence: 'required', 'default-channel': 'latest/stable' },
                        ],
                    };
                },
                // (system.disk bridge removed — the old /v2/system-info/storage
                //  endpoint does not exist on live snapd; storage comes from
                //  statfs via system.dataDisk now)
                // net traffic mock: { iface, series } — one {r,x} pair per call
                // (main samples on its own 2 s clock); idle 0 until call 4, then
                // a sine wave so both sparklines draw a recognizable shape.
                // iface = the default-route device (eth0 in the mock world).
                async net() {
                    netCalls++;
                    const n = Math.min(100, netCalls);
                    const series = Array.from({ length: n }, (_, i) => i < 4
                        ? (i === 0 ? { r: null, x: null } : { r: 0, x: 0 })
                        : { r: Math.round((60 + 40 * Math.sin((i - 3) / 2)) * 10) / 10,
                           x: Math.round((12 + 8 * Math.cos((i - 3) / 2)) * 10) / 10 });
                    return { iface: 'eth0', series };
                },

                async change(id) {
                    const c = CHANGES[id];
                    if (!c) throw new Error('unknown change ' + id);
                    // live snapd shows the in-flight change as "Do" between "Doing"
                    // and the terminal state — the UI must keep polling through it.
                    if (c.status === 'Doing' && c.kind === 'remove-snap' && Date.now() - c.t0 > 150) c.status = 'Do';
                    return c;
                },
                async changes() {
                    // live snapd shape: string summary, hyphenated spawn-time,
                    // and NO guaranteed order (the UI must sort newest-first).
                    return [
                        { id: '14', kind: 'install-snap', summary: 'Install snap "mosquitto"', status: 'Done', 'spawn-time': '2026-10-28T08:12:00Z' },
                        { id: '16', kind: 'connect-plug', summary: 'Connect firefox:network to core24:network', status: 'Done', 'spawn-time': '2026-10-28T09:30:00Z' },
                        { id: '15', kind: 'configure-snap', summary: 'Configure snap "core24"', status: 'Ready', 'spawn-time': '2026-10-28T09:00:00Z' },
                    ];
                },
                async netplan() { return NETPLAN; },
                // data partition mock: /run/mnt/data present (the core case),
                // 33.3% of 8 GiB used, 409.6 MiB root reserve.
                async dataDisk() {
                    return {
                        mount: '/run/mnt/data', device: '/dev/loop4', fsType: 'ext4',
                        totalBytes: 8589934592, freeBytes: 5726623062,
                        usedBytes: 2863311530, reservedBytes: 429496729,
                        usedPercent: 33.3, source: 'data',
                    };
                },
                // CPU sparkline mock: one delta per call (main samples on its own clock),
                // deterministic wave so the drawn shape is stable in screenshots.
                async cpu() {
                    cpuCalls++;
                    const n = Math.min(100, cpuCalls);
                    return Array.from({ length: n }, (_, i) =>
                        Math.round((40 + 30 * Math.sin(i / 3)) * 10) / 10);
                },
            },
            snaps: {
                async list() { return SNAPS; },
                async info(n) {
                    const s = SNAPS.find((x) => x.name === n);
                    if (!s) return null;
                    return Object.assign({}, s, INFO[n] || {});
                },
                // Store search/install: unauthenticated by design (model
                // attachment at image build time) — no store login needed.
                async search(q) {
                    // the info modal queries the STORE for one installed
                    // snap's channels (round 47g) — resolve it first; a
                    // missing entry (e.g. 'core24') = a local snap -> [].
                    if (STORE[q]) return [{ name: q, channels: STORE[q] }];
                    return [
                        { name: 'mosquitto', summary: 'MQTT broker for IoT messaging', publisher: { username: 'mosquitto-dev' }, channels: { 'latest/stable': {} } },
                        { name: 'mqtt-spy', summary: 'Simple MQTT traffic inspector', publisher: { username: 'iot-labs' }, channels: { 'latest/stable': {} } },
                    ].filter((s) => s.name.includes((q || '').toLowerCase()));
                },
                async install(n, ch) {
                    const id = '17';
                    CHANGES[id] = { id, status: 'Doing', kind: 'install-snap', t0: Date.now() };
                    setTimeout(() => {
                        if (!SNAPS.some((x) => x.name === n)) {
                            SNAPS = SNAPS.concat([{ name: n, version: '9.9.9', revision: 1, channel: 'stable', 'tracking-channel': 'latest/stable', status: 'active', type: 'app', confinement: 'strict' }]);
                        }
                        CHANGES[id] = { id, status: 'Done' };
                    }, 250);
                    // real snapd async envelope: id at top level, result null
                    return { id, change: id };
                },
                async action(n, a, extra) {
                    if (a === 'remove' && n === 'core24') throw new Error('cannot remove snap "core24": system snap');
                    const cur = SNAPS.find((x) => x.name === n);
                    if (a === 'revert' && (!cur || !cur.prevRev || cur.prevRev === cur.revision))
                        throw new Error('cannot revert "' + n + '": no revision to revert to');
                    const id = '18';
                    CHANGES[id] = { id, status: 'Doing', kind: a + '-snap', t0: Date.now() };
                    setTimeout(() => {
                        if (a === 'remove') SNAPS = SNAPS.filter((x) => x.name !== n);
                        else if (a === 'disable' && cur) cur.status = 'installed'; // live snapd: not-active == "installed"
                        else if (a === 'enable' && cur) cur.status = 'active';
                        else if (a === 'revert' && cur) { cur.status = 'active'; cur.revision = cur.prevRev; }
                        // a channel-switching REFRESH (round 47g): the daemon
                        // updates the tracking channel + fetches the new
                        // revision for it
                        else if (a === 'refresh' && extra && extra.channel && cur) {
                            cur.channel = extra.channel;
                            cur['tracking-channel'] = extra.channel;
                            if (!/^x/.test(String(cur.revision))) { cur.prevRev = cur.revision; cur.revision = String(Number(cur.revision) + 1); }
                        }
                        else if (cur) { if (!/^x/.test(String(cur.revision))) { cur.prevRev = cur.revision; cur.revision = String(Number(cur.revision) + 1); } cur.status = 'active'; }
                        CHANGES[id] = { id, status: 'Done' };
                    }, a === 'refresh' ? 400 : 1200); // refresh (channel switch) settles fast;
                    // remove/disable/etc. keep the 1.2s window so the inline
                    // confirm cards stay visible for their shots (rounds 45/47c)
                    return { id, change: id };
                },
                async confGet(n, key) {
                    const doc = CONF[n] || {};
                    if (key) return { [key]: Object.prototype.hasOwnProperty.call(doc, key) ? doc[key] : null };
                    return doc;
                },
                async confSet(n, obj) {
                    if (!CONF[n]) CONF[n] = {};
                    for (const [k, v] of Object.entries(obj)) {
                        if (v === null) delete CONF[n][k]; else CONF[n][k] = v;
                    }
                    return {};
                },
            },
            network: { async apply() { return {}; } },
            interfaces: {
                // LIVE-VERIFIED (snapd 2.77): GET /v2/interfaces -> {plugs, slots}
                // (unconnected endpoints carry connections: null); POST is an
                // ASYNC 202 write whose body is the PLURAL plugs[]/slots[] form.
                async list() { return JSON.parse(JSON.stringify(IFC)); },
                async connect(plugRef, slotRef) {
                    const id = String(200 + ((CHANGES['ifaceSeq'] = (CHANGES['ifaceSeq'] || 0) + 1)));
                    CHANGES[id] = { id, status: 'Doing', kind: 'connect-snap', t0: Date.now() };
                    setTimeout(() => {
                        const pg = IFC.plugs.find((x) => x.snap === plugRef.snap && x.plug === plugRef.plug);
                        const sl = IFC.slots.find((x) => x.snap === slotRef.snap && x.slot === slotRef.slot);
                        if (pg) pg.connections = [{ snap: sl.snap, slot: sl.slot }];
                        if (sl) sl.connections = [{ snap: pg.snap, plug: pg.plug }];
                        CHANGES[id] = { id, status: 'Done' };
                    }, 400);
                    return { id, change: id };
                },
                async disconnect(plugRef, slotRef) {
                    const id = String(200 + ((CHANGES['ifaceSeq'] = (CHANGES['ifaceSeq'] || 0) + 1)));
                    CHANGES[id] = { id, status: 'Doing', kind: 'disconnect-snap', t0: Date.now() };
                    setTimeout(() => {
                        const pg = IFC.plugs.find((x) => x.snap === plugRef.snap && x.plug === plugRef.plug);
                        const sl = IFC.slots.find((x) => x.snap === slotRef.snap && x.slot === slotRef.slot);
                        if (pg) pg.connections = null;
                        if (sl) sl.connections = null;
                        CHANGES[id] = { id, status: 'Done' };
                    }, 400);
                    return { id, change: id };
                },
            },
            ping: async () => 'pong',
        };
    })();
    `;
}

(async () => {
    const browser = await puppeteer.launch({
        headless: 'shell',
        args: ['--no-sandbox', '--disable-dev-shm-usage', '--force-color-profile=srgb', '--font-render-hinting=none'],
    });
    const page = await browser.newPage();
    await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 1 });

    const errors = [];
    page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
    page.on('console', (m) => { if (m.type() === 'error' && !/frame-ancestors/.test(m.text())) errors.push('console: ' + m.text()); });
    page.on('requestfailed', (r) => {
        const u = r.url();
        if (!u.startsWith('file://') && !u.startsWith('data:')) errors.push('requestfailed: ' + u + ' ' + (r.failure() && r.failure().errorText));
    });

    // Validate the GENERATED mock (a syntax error in the template literal —
    // e.g. an apostrophe inside a string, or an invalid assignment — is SILENT
    // to node --check of this file; it would kill the mock, leave __mockCore
    // unset, and break the very first setup click). Compile it here.
    new Function(mockFactoryJs());
    // Inject the mock bridge BEFORE the page's own scripts run.
    await page.evaluateOnNewDocument(mockFactoryJs());
    await page.goto('file://' + path.join(ROOT, 'ui', 'index.html'), { waitUntil: 'networkidle2', timeout: 60000 });
    const wait = (ms) => new Promise((r) => setTimeout(r, ms));

    // ---- 1. FIRST BOOT: setup view (create local password) ----
    await wait(600);
    await page.screenshot({ path: path.join(SHOTS, '1-setup.png') });

    // mismatch validation
    await page.type('#setupPassword', 'correct-horse');
    await page.type('#setupConfirm', 'different');
    await page.click('#setupBtn');
    await wait(400);
    await page.screenshot({ path: path.join(SHOTS, '2-setup-mismatch.png') });

    // fix + create -> console (no store chip in the top bar anymore)
    await page.click('#setupConfirm', { clickCount: 3 });
    await page.type('#setupConfirm', 'correct-horse');
    await page.click('#setupBtn');
    await wait(900);
    await page.screenshot({ path: path.join(SHOTS, '3-dashboard-clean.png'), fullPage: true });
    const chipGone = await page.evaluate(() => !document.querySelector('#storeChip') && !document.querySelector('#storeModal'));
    if (!chipGone) console.log('PAGE ERROR: store chip/modal still present in the DOM');
    // CSS-integrity guard (round-17 regression): a mangled rule in app.css
    // (e.g. a rule body swallowing the next rules) is SILENT — no page error,
    // the styles just stop applying. Pin the two computed styles that broke
    // when .p-icon--clock's body was clobbered (it took .ucm-session-chip
    // down with it: pill frame AND clock icon vanished).
    const topbar = await page.evaluate(() => {
        const chip = document.querySelector('#sessionChip');
        const ic = document.querySelector('#sessionChip i');
        const btn = document.querySelector('#lockBtn');
        const lockic = document.querySelector('#lockBtn i');
        if (!chip || !ic || !btn || !lockic) return { error: 'topbar elements missing' };
        const csChip = getComputedStyle(chip);
        const csIc = getComputedStyle(ic);
        const csLock = getComputedStyle(lockic);
        const csBtn = getComputedStyle(btn);
        return {
            chipDisplay: csChip.display,
            chipBg: csChip.backgroundColor,
            chipRadius: csChip.borderRadius,
            clockBg: csIc.backgroundImage.includes('suru-clock.svg'),
            clockH: csIc.height,
            lockBg: csLock.backgroundImage.includes('suru-lock.svg'),
            lockBtnMarginBottom: csBtn.marginBottom,
        };
    });
    if (topbar.error) console.log('PAGE ERROR: ' + topbar.error);
    else {
        // Chromium normalizes computed values (inline-flex -> flex,
        // rgba(247,247,247,1) -> rgb(247,247,247)); the broken-CSS state was
        // display:block + transparent + 0px radius (verified by mutation test).
        if (topbar.chipDisplay !== 'flex' && topbar.chipDisplay !== 'inline-flex')
            console.log('PAGE ERROR: session chip lost its display style (' + JSON.stringify(topbar) + ')');
        if (topbar.chipBg !== 'rgb(247, 247, 247)' && topbar.chipBg !== 'rgba(247, 247, 247, 1)')
            console.log('PAGE ERROR: session chip lost its background (' + JSON.stringify(topbar) + ')');
        if (topbar.chipRadius !== '16px')
            console.log('PAGE ERROR: session chip lost its border-radius (' + JSON.stringify(topbar) + ')');
        if (!topbar.clockBg) console.log('PAGE ERROR: clock icon background not applied');
        if (topbar.lockBtnMarginBottom !== '0px')
            console.log('PAGE ERROR: lock button margin-bottom not zeroed (' + topbar.lockBtnMarginBottom + ')');
        if (!topbar.lockBg) console.log('PAGE ERROR: lock icon background not applied');
    }

    // CPU sparkline guard (dashboard): SVG paths drawn, current-% text set,
    // load stats rendered small. Catches missing mock/renderer wiring the
    // same way the topbar guard catches mangled CSS.
    await wait(4500); // 2+ cpu ticks at the 2 s cadence
    const cpu = await page.evaluate(() => {
        const line = document.querySelector('#cpuLine');
        const area = document.querySelector('#cpuArea');
        const now = document.querySelector('#statCpuNow');
        const load = document.querySelector('#statLoad');
        if (!line || !area || !now || !load) return { error: 'cpu elements missing' };
        const csLoad = getComputedStyle(load);
        const csStat = getComputedStyle(line.closest('.ucm-stat'));
        const ld = line.getAttribute('d') || '';
        const ad = area.getAttribute('d') || '';
        return {
            lineShape: ld.startsWith('M') && /L/.test(ld) ? 'multi' : 'bad:' + ld.slice(0, 20),
            areaClosed: ad.endsWith('Z') && ad.length > ld.length ? true : 'bad',
            nowText: now.textContent,
            loadText: load.textContent,
            loadHint: (document.querySelector('#statLoadHint') || {}).textContent || '',
            loadFontSize: csLoad.fontSize,
            statDisplay: csStat.display,
            lineStroke: getComputedStyle(line).stroke,
        };
    });
    if (cpu.error) console.log('PAGE ERROR: ' + cpu.error);
    else {
        if (cpu.lineShape !== 'multi') console.log('PAGE ERROR: cpu line path not drawn (' + cpu.lineShape + ')');
        if (cpu.areaClosed !== true) console.log('PAGE ERROR: cpu area path not closed (' + cpu.areaClosed + ')');
        if (!/^\d+%$/.test(cpu.nowText)) console.log('PAGE ERROR: cpu current % missing (' + cpu.nowText + ')');
        if (!/cores$/.test(cpu.loadHint)) console.log('PAGE ERROR: load hint missing (' + cpu.loadHint + ')');
        if (!/^\d{1,2}\.\d{2} · \d{1,2}\.\d{2} · \d{1,2}\.\d{2}$/.test(cpu.loadText)) console.log('PAGE ERROR: load stats not small-formatted (' + cpu.loadText + ')');
        // 1.6rem value would be the unstyled .ucm-stat__value; the small
        // override computes to 15.2px.
        if (cpu.loadFontSize !== '15.2px') console.log('PAGE ERROR: load value not shrunk (' + cpu.loadFontSize + ')');
        if (cpu.statDisplay !== 'flex') console.log('PAGE ERROR: cpu stat card lost flex layout (' + cpu.statDisplay + ')');
        if (cpu.lineStroke !== 'rgb(233, 84, 32)') console.log('PAGE ERROR: cpu line not orange (' + cpu.lineStroke + ')');
    }
    await page.screenshot({ path: path.join(SHOTS, '3b-cpu-graph.png') });

    // Recent changes guard (round 27): all four columns populated from the
    // LIVE snapd field names, rows sorted newest-first (mock is fed in a
    // non-sorted order).
    const changes = await page.evaluate(() => {
        const trs = Array.from(document.querySelectorAll('#dashChangesBody tr'));
        if (!trs.length) return { error: 'no change rows' };
        const ths = Array.from(document.querySelectorAll('#dashChangesTable th'));
        return {
            rows: trs.map((tr) => Array.from(tr.querySelectorAll('td')).map((td) => td.textContent.trim())),
            refreshBtn: !!document.querySelector('#dashChangesRefresh'),
            colWidths: ths.map((th) => Math.round(th.getBoundingClientRect().width)),
        };
    });
    if (changes.error) console.log('PAGE ERROR: ' + changes.error);
    else {
        const rows = changes.rows;
        if (rows.length !== 3) console.log('PAGE ERROR: changes row count (' + rows.length + ')');
        if (!rows.every((r) => r.length === 4 && r.every((c) => c.length > 0)))
            console.log('PAGE ERROR: change table has empty cells (' + JSON.stringify(rows) + ')');
        // sorted newest-first: 09:30, 09:00, 08:12 (the mock is 08:12, 09:30, 09:00)
        if (rows.length === 3 && rows[0][0] !== 'connect-plug')
            console.log('PAGE ERROR: changes not sorted newest-first (' + JSON.stringify(rows.map((r) => r[0])) + ')');
        // spawned column: full 'dd.mm.yyyy hh:mm' stamp (same format as the
        // Uptime refresh lines). Assert the SHAPE + the date piece; the
        // time-of-day is TZ-dependent (mock is UTC, harness renders local).
        const spawned = rows[0] ? rows[0][2] : '';
        if (!/^\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}$/.test(spawned))
            console.log('PAGE ERROR: spawned stamp not dd.mm.yyyy hh:mm (' + spawned + ')');
        if (!/28\.10\.2026/.test(spawned))
            console.log('PAGE ERROR: newest spawn date wrong (' + spawned + ')');
        if (rows[0] && rows[0][3] !== 'Connect firefox:network to core24:network')
            console.log('PAGE ERROR: summary column wrong (' + (rows[0] && rows[0][3]) + ')');
        // manual Refresh button removed — the 20 s auto-refresh supersedes it
        if (changes.refreshBtn !== false) console.log('PAGE ERROR: changes Refresh button still present');
        // column widths: Change/Status/Spawned hug content, Summary owns the
        // remainder (>= 2x the widest of the three narrow columns).
        const cw = changes.colWidths || [];
        if (cw.length !== 4) console.log('PAGE ERROR: changes table column count (' + JSON.stringify(cw) + ')');
        else if (Math.max(cw[0], cw[1], cw[2]) >= cw[3] / 2)
            console.log('PAGE ERROR: changes columns not content-hugging (widths ' + JSON.stringify(cw) + ')');
    }

    // System + Model cards (round 20): device identity moved from the System
    // card into the 'Model' stat card (snapd version left the strip; it
    // stays in the rail). System card is compact again -> default 50/50
    // .ucm-kv columns, no mangling.
    const cards = await page.evaluate(() => {
        const sys = document.querySelector('#dashSystem');
        const mstat = document.querySelector('#modelStat');
        if (!sys) return { error: 'dashSystem missing' };
        const rows = Array.from(sys.querySelectorAll(':scope > div'))
            .map((d) => ({ dt: d.querySelector('dt')?.textContent || '', dd: d.querySelector('dd')?.textContent || '' }));
        const get = (k) => rows.find((r) => r.dt === k)?.dd || null;
        const m = (sel) => { const e = document.querySelector(sel); return e ? e.textContent : null; };
        const mcs = mstat ? getComputedStyle(mstat) : null;
        // ALL stat cards in the row must share the same height (grid
        // stretch): the two-line Uptime card and the Model card added a
        // third content line — guard the rhythm across the whole strip.
        const statHeights = Array.from(document.querySelectorAll('#dashStats .ucm-stat'))
            .map((c) => Math.round(c.getBoundingClientRect().height));
        return {
            sysRows: rows.map((r) => r.dt + '=' + r.dd),
            hostname: get('Hostname'), kernel: get('Kernel'),
            arch: get('Architecture'), os: get('OS release'),
            // model rows must be GONE from the System card
            sysHasModelRows: rows.some((r) => ['Model', 'Base', 'Grade', 'Brand'].includes(r.dt)),
            // model stat card
            modelCardDisplay: mcs ? (mcs.display === 'none' ? 'none' : 'visible') : null,
            statHeights,
            statModel: m('#statModel'), statModelHint: m('#statModelHint'),
            brandGone: !document.querySelector('#modelBrand'),
            uptimeLast: m('#statUptimeLast'),
            uptimeNext: m('#statUptimeNext'),
            stampsLineDelta: (() => {
                const a = document.querySelector('#statUptimeLast');
                const b = document.querySelector('#statUptimeNext');
                return a && b ? Math.round(b.getBoundingClientRect().top - a.getBoundingClientRect().top) : null;
            })(),
            snapdGone: !document.querySelector('#statSnapd'),
        };
    });
    if (cards.error) console.log('PAGE ERROR: ' + cards.error);
    else {
        if (cards.hostname !== 'core-kvm-01') console.log('PAGE ERROR: System card Hostname row (' + cards.hostname + ')');
        if (cards.kernel !== '6.8.0-40-generic') console.log('PAGE ERROR: System card Kernel row (' + cards.kernel + ')');
        if (cards.arch !== 'amd64') console.log('PAGE ERROR: System card Architecture row (' + cards.arch + ')');
        if (cards.os !== 'ubuntu 24.04') console.log('PAGE ERROR: System card OS release row (' + cards.os + ')');
        if (cards.sysHasModelRows !== false)
            console.log('PAGE ERROR: model rows still in System card (' + cards.sysRows.join(' ') + ')');
        if (cards.modelCardDisplay !== 'visible') console.log('PAGE ERROR: model stat card not visible (' + cards.modelCardDisplay + ')');
        const hs = cards.statHeights || [];
        if (hs.length < 4 || Math.max(...hs) - Math.min(...hs) > 6)
            console.log('PAGE ERROR: stat card heights off-rhythm (' + JSON.stringify(hs) + ')');
        if (cards.statModel !== 'core-24-kvm') console.log('PAGE ERROR: Model card name (' + cards.statModel + ')');
        if (cards.statModelHint !== 'core24 · signed') console.log('PAGE ERROR: Model card base/grade (' + cards.statModelHint + ')');
        if (cards.brandGone !== true) console.log('PAGE ERROR: brand-id line still in Model card');
        // Uptime: two labeled lines, forced wrap between the stamps, local
        // 'dd.mm.yyyy hh:mm' (the mock uses fixed UTC stamps; the harness
        // runs in the container's local TZ, so assert shape + date pieces,
        // not the offset).
        if (!/^Last refresh \d{2}\.\d{2}\.\d{4} \d{2}:\d{2}$/.test(cards.uptimeLast || ''))
            console.log('PAGE ERROR: uptime last-refresh line wrong (' + cards.uptimeLast + ')');
        if (!/^Next refresh \d{2}\.\d{2}\.\d{4} \d{2}:\d{2}$/.test(cards.uptimeNext || ''))
            console.log('PAGE ERROR: uptime next-refresh line wrong (' + cards.uptimeNext + ')');
        if (!cards.uptimeLast || !cards.uptimeLast.includes('30.10.2026'))
            console.log('PAGE ERROR: refresh last-date not normalized (' + cards.uptimeLast + ')');
        if (!cards.uptimeNext || !cards.uptimeNext.includes('31.10.2026'))
            console.log('PAGE ERROR: refresh next-date not normalized (' + cards.uptimeNext + ')');
        if (cards.stampsLineDelta == null || cards.stampsLineDelta < 5)
            console.log('PAGE ERROR: refresh stamps not on separate lines (delta=' + cards.stampsLineDelta + ')');
        if (cards.snapdGone !== true) console.log('PAGE ERROR: old Snapd stat card still present');
    }
    await page.screenshot({ path: path.join(SHOTS, '3c-system-card.png') });

    // Data partition guard (round 23): donut renders the used wedge as a
    // conic-gradient at the mocked 33.3%, rows show df-consistent numbers.
    const dd = await page.evaluate(() => {
        const donut = document.querySelector('#dataDiskDonut');
        if (!donut) return { error: 'donut missing' };
        const cs = getComputedStyle(donut);
        const txt = (id) => { const e = document.querySelector('#' + id); return e ? e.textContent : ''; };
        return {
            bg: cs.backgroundImage || cs.background,
            radius: cs.borderRadius,
            hole: getComputedStyle(donut, '::before').backgroundColor,
            pct: txt('dataDiskPct'), total: txt('dataDiskTotal'),
            used: txt('dataDiskUsed'), free: txt('dataDiskFree'), res: txt('dataDiskRes'),
            src: txt('dataDiskSrc'),
            legend: !!document.querySelector('.ucm-datadisk__legend'),
            swatch: getComputedStyle(document.querySelector('.ucm-datadisk__sw--used')).backgroundColor,
            reservedGone: !document.querySelector('#dataDiskRes'),
            // header alignment: heading and fs-type caption must share the
            // same vertical centre (Vanilla heading padding-top is zeroed in
            // .ucm-card-datadisk — without it the glyphs are ~4px off).
            headerAlign: (() => {
                const card = document.querySelector('.ucm-card-datadisk');
                if (!card) return null;
                const p = card.querySelector('.p-heading--5').getBoundingClientRect();
                const sp = document.querySelector('#dataDiskSrc').getBoundingClientRect();
                return Math.round((p.top + p.height / 2 - (sp.top + sp.height / 2)) * 10) / 10;
            })(),
            ddKeys: [...document.querySelectorAll('.ucm-card-datadisk .ucm-datadisk__k')].map((k) => k.textContent),
            bodyGap: (() => {
                const card = document.querySelector('.ucm-datadisk').closest('.p-card');
                const sep = card.querySelector('.p-card__header').getBoundingClientRect().bottom;
                const top = Math.min(
                    card.querySelector('#dataDiskDonut').getBoundingClientRect().top,
                    card.querySelector('.ucm-datadisk__row').getBoundingClientRect().top);
                return Math.round(top - sep);
            })(),
        };
    });
    if (dd.error) console.log('PAGE ERROR: ' + dd.error);
    else {
        if (!/conic-gradient/.test(dd.bg)) console.log('PAGE ERROR: donut has no conic-gradient (' + dd.bg.slice(0, 80) + ')');
        if (!dd.bg.includes('33.3%')) console.log('PAGE ERROR: donut wedge not at 33.3% (' + dd.bg.slice(0, 120) + ')');
        if (dd.pct !== '33%') console.log('PAGE ERROR: donut center pct (' + dd.pct + ')');
        if (dd.total !== '8.0 GiB') console.log('PAGE ERROR: data disk total (' + dd.total + ')');
        if (dd.used !== '2.7 GiB') console.log('PAGE ERROR: data disk used (' + dd.used + ')');
        if (dd.free !== '5.3 GiB') console.log('PAGE ERROR: data disk free (' + dd.free + ')');
        if (dd.reservedGone !== true) console.log('PAGE ERROR: Reserved row still present');
        if (dd.bodyGap < 8) console.log('PAGE ERROR: data disk body touches the header separator (gap ' + dd.bodyGap + 'px)');
        if (dd.src !== 'ext4') console.log('PAGE ERROR: data disk source label (' + dd.src + ')');
        if (dd.headerAlign == null) console.log('PAGE ERROR: data disk header alignment not measurable');
        else if (Math.abs(dd.headerAlign) > 2)
            console.log('PAGE ERROR: data disk header not vertically centred (delta ' + dd.headerAlign + 'px)');
        if (!dd.ddKeys || !dd.ddKeys.includes('Free') || dd.ddKeys.includes('Free (user)'))
            console.log('PAGE ERROR: Free row label wrong (' + JSON.stringify(dd.ddKeys) + ')');
        if (!dd.legend) console.log('PAGE ERROR: donut legend missing');
        if (dd.swatch !== 'rgb(233, 84, 32)') console.log('PAGE ERROR: used swatch not orange (' + dd.swatch + ')');
        if (dd.hole !== 'rgb(255, 255, 255)') console.log('PAGE ERROR: donut hole not white (' + dd.hole + ')');
    }
    await page.screenshot({ path: path.join(SHOTS, '3d-data-disk.png') });

    // Net graphs guard (round 25): both sparklines drawn (multi-point paths,
    // closed areas), current rates rendered, active-iface label set.
    const ng = await page.evaluate(() => {
        const ld = document.querySelector('#netDownLine');
        const la = document.querySelector('#netDownArea');
        const lu = document.querySelector('#netUpLine');
        const ua = document.querySelector('#netUpArea');
        const t = (id) => { const e = document.querySelector('#' + id); return e ? e.textContent : ''; };
        const shape = (p) => { const d = p && p.getAttribute ? p.getAttribute('d') : ''; return d.startsWith('M') && /L/.test(d) ? 'multi' : 'bad:' + (d || 'empty').slice(0, 20); };
        return {
            downLine: shape(ld), downArea: la ? (la.getAttribute('d') || '').endsWith('Z') : false,
            upLine: shape(lu), upArea: ua ? (ua.getAttribute('d') || '').endsWith('Z') : false,
            downNow: t('netDownNow'), upNow: t('netUpNow'), src: t('netIfaceSrc'),
            downStroke: ld ? getComputedStyle(ld).stroke : '',
            upStroke: lu ? getComputedStyle(lu).stroke : '',
        };
    });
    if (ng.downLine !== 'multi') console.log('PAGE ERROR: net down line not drawn (' + ng.downLine + ')');
    if (ng.downArea !== true) console.log('PAGE ERROR: net down area not closed');
    if (ng.upLine !== 'multi') console.log('PAGE ERROR: net up line not drawn (' + ng.upLine + ')');
    if (ng.upArea !== true) console.log('PAGE ERROR: net up area not closed');
    if (!/KiB\/s|MiB\/s$/.test(ng.downNow)) console.log('PAGE ERROR: net down rate missing (' + ng.downNow + ')');
    if (!/KiB\/s|MiB\/s$/.test(ng.upNow)) console.log('PAGE ERROR: net up rate missing (' + ng.upNow + ')');
    // label = the default-route device only (the mock reports eth0)
    if (ng.src !== 'eth0') console.log('PAGE ERROR: net iface label wrong (' + ng.src + ')');
    if (ng.downStroke !== 'rgb(233, 84, 32)') console.log('PAGE ERROR: net down line not orange (' + ng.downStroke + ')');
    if (ng.upStroke !== 'rgb(119, 119, 119)') console.log('PAGE ERROR: net up line not grey (' + ng.upStroke + ')');
    await page.screenshot({ path: path.join(SHOTS, '3e-net-graphs.png') });

    // Warnings guard (round 30): the card shows only the LATEST warning
    // (by last-seen, not array order), ellipsized to 60 chars + …, with the
    // full message in the title attribute.
    const LONG = "Option value has invalid field name 'apiVersion'. For core26+ snaps, fields must be dash separated lowercase alphanumerics.";
    const warn = await page.evaluate((long) => {
        const box = document.querySelector('#dashWarnings');
        if (!box) return { error: 'warnings box missing' };
        const p = box.querySelector('p');
        return { text: p ? p.textContent : null, title: p ? p.title : null, longLen: long.length };
    }, LONG);
    if (warn.error) console.log('PAGE ERROR: ' + warn.error);
    else {
        const expected = LONG.slice(0, 60).trimEnd() + '…';
        if (warn.text !== expected)
            console.log('PAGE ERROR: warnings card text wrong (latest+ellipsis) (' + warn.text + ')');
        if (warn.title !== LONG)
            console.log('PAGE ERROR: warnings card missing full title (' + warn.title + ')');
    }

    // ---- 2. SETTINGS VIEW: guarded local-admin reset ----------------
    await page.click('.ucm-side a[data-view="settings"]');
    await wait(500);
    await page.screenshot({ path: path.join(SHOTS, '4-settings-reset.png'), fullPage: true });

    // wrong current password -> validation error (session kept)
    await page.type('#resetCurrent', 'wrong-pass');
    await page.type('#resetConfirm', 'wrong-pass');
    await page.click('#resetBtn');
    await wait(400);
    await page.screenshot({ path: path.join(SHOTS, '5-settings-reset-wrong.png') });

    // correct password (match) -> credential wiped -> first-boot setup again
    await page.click('#resetCurrent', { clickCount: 3 });
    await page.click('#resetConfirm', { clickCount: 3 });
    await page.type('#resetCurrent', 'correct-horse');
    await page.type('#resetConfirm', 'correct-horse');
    await page.click('#resetBtn');
    await wait(700);
    const backToSetup = await page.evaluate(() => !document.querySelector('#setupView').classList.contains('ucm-hidden'));
    if (!backToSetup) console.log('PAGE ERROR: reset did not return to the setup view');
    // round 13: the reset form must be CLEARED after the wipe (old password
    // must not linger in the fields) and the hash must be dropped so the
    // re-created session lands on the dashboard, not #settings.
    const resetClean = await page.evaluate(() => ({
        cur: document.querySelector('#resetCurrent').value,
        confirm: document.querySelector('#resetConfirm').value,
        hash: location.hash,
    }));
    if (resetClean.cur !== '' || resetClean.confirm !== '')
        console.log('PAGE ERROR: reset form kept the old password (' + JSON.stringify(resetClean) + ')');
    if (resetClean.hash !== '')
        console.log('PAGE ERROR: view hash not cleared after reset (hash=' + resetClean.hash + ')');
    await page.screenshot({ path: path.join(SHOTS, '6-reset-to-setup.png') });

    // recreate the password so the remaining steps have a console
    await page.click('#setupPassword', { clickCount: 3 });
    await page.click('#setupConfirm', { clickCount: 3 });
    await page.type('#setupPassword', 'correct-horse');
    await page.type('#setupConfirm', 'correct-horse');
    await page.click('#setupBtn');
    await wait(800);
    // round 13: after reset + new password, the default view is the DASHBOARD
    const onDash = await page.evaluate(() =>
        !document.querySelector('#view-dashboard').classList.contains('ucm-hidden'));
    if (!onDash) console.log('PAGE ERROR: post-reset session did not land on the dashboard');
    // the store-notice info card is gone from the Snaps view
    const noticeGone = await page.evaluate(() => !document.querySelector('#snapsStoreNotice'));
    if (!noticeGone) console.log('PAGE ERROR: snaps store notice card still present');

    // ---- 3. network view (static + validation + apply) ----
    await page.click('.ucm-side a[data-view="network"]');
    await wait(700);
    await page.screenshot({ path: path.join(SHOTS, '7-network-dhcp.png') });
    await page.$eval('#netModeStatic', (el) => { el.checked = true; el.dispatchEvent(new Event('change', { bubbles: true })); });
    await page.select('#netIface', 'eth0');
    await page.type('#netIpv4', '192.168.1.50/24');
    await page.type('#netGw4', 'not-an-ip');
    await wait(300);
    await page.click('#netApply');
    await wait(500);
    await page.screenshot({ path: path.join(SHOTS, '8-network-validation.png') });
    await page.click('#netGw4', { clickCount: 3 });
    await page.type('#netGw4', '192.168.1.1');
    await page.type('#netDns', '1.1.1.1, 8.8.8.8');
    await page.click('#netApply');
    await wait(700);
    await page.screenshot({ path: path.join(SHOTS, '9-network-applied.png') });

    // ---- 4. snaps view (search works WITHOUT a store login) ----
    await page.click('.ucm-side a[data-view="snaps"]');
    await wait(700);
    await page.type('#snapSearchName', 'mosquitto');
    await page.keyboard.press('Enter'); // search field is search-only (Enter must NOT install)
    await wait(700);
    await page.screenshot({ path: path.join(SHOTS, '10-snaps-search.png'), fullPage: true });

    // ---- 4a. Round 47i: the Store results card auto-hides after a
    // successful install, and its close button is icon-only. ----
    const clearBtn = await page.evaluate(() => {
        const b = document.querySelector('#snapSearchClear');
        return { text: b ? b.textContent.trim() : null, aria: b ? (b.getAttribute('aria-label') || '') : null };
    });
    if (clearBtn.text !== '') console.log('PAGE ERROR: the Store results close button is not icon-only (text ' + JSON.stringify(clearBtn.text) + ', round 47i)');
    if (!/clear/i.test(clearBtn.aria)) console.log('PAGE ERROR: the Store results close button has no aria-label (' + JSON.stringify(clearBtn.aria) + ', round 47i)');
    // install mosquitto from its store row -> the card must hide on success
    await page.evaluate(() => {
        const row = Array.from(document.querySelectorAll('#snapSearchBody tr'))
            .find((r) => r.cells && r.cells[0] && r.cells[0].textContent.trim() === 'mosquitto');
        if (!row) throw new Error('mosquitto store row missing');
        const btn = row.querySelector('button.p-button--brand');
        if (!btn) throw new Error('store row Install button missing');
        btn.click();
    });
    await wait(900); // 250ms mock install settle + margin
    const autoHide = await page.evaluate(() => ({
        hidden: !!document.querySelector('#snapSearchResults.ucm-hidden'),
        rows: document.querySelectorAll('#snapSearchBody tr').length,
    }));
    if (!autoHide.hidden) console.log('PAGE ERROR: the Store results card did not auto-hide after a successful install (round 47i)');
    if (autoHide.rows !== 0) console.log('PAGE ERROR: the Store results card still has rows after the install (' + autoHide.rows + ', round 47i)');

    // ---- 4b. per-snap config modal (htop) ----
    await page.evaluate(() => {
        const rows = Array.from(document.querySelectorAll('#snapsCards tbody tr'));
        const htop = rows.find((r) => r.textContent.includes('htop'));
        if (!htop) throw new Error('htop row missing');
        const btn = htop.querySelector('.ucm-iconbtn[aria-label^="Configure"]'); // icon-only: no text to match
        if (!btn) throw new Error('Config button missing');
        btn.click();
    });
    await wait(600);
    const cfgState = await page.evaluate(() => ({
        key: document.querySelector('#cfgKey') ? document.querySelector('#cfgKey').value : null,
        value: document.querySelector('#cfgValue') ? document.querySelector('#cfgValue').value : null,
    }));
    if (cfgState.key !== 'port' || cfgState.value !== '8080')
        console.log(`PAGE ERROR: config modal prefill wrong (${JSON.stringify(cfgState)})`);
    await page.screenshot({ path: path.join(SHOTS, '11-config-modal.png') });
    // change port to a number and save
    await page.click('#cfgValue', { clickCount: 3 });
    await page.type('#cfgValue', '9090');
    await page.select('#cfgType', 'number');
    await page.click('#cfgValue', { clickCount: 3 });
    await page.type('#cfgValue', '9090');
    await page.evaluate(() => document.querySelector('.ucm-config button.p-button--brand').click());
    await wait(700);
    const cfgSaved = await page.evaluate(() => ({
        modalGone: !document.querySelector('.ucm-config'),
        port: window.__mockCore && 'ok',
    }));
    if (cfgSaved.modalGone !== true) console.log('PAGE ERROR: config modal did not close after save');
    await page.screenshot({ path: path.join(SHOTS, '12-config-saved.png') });

    // ---- 4c. Round 47: two interface-card-style cards replace the
    // scrollable table. Card 1 "OS" = the model-assertion system snaps
    // (round-46b definition — the harness mock's model lists
    // core24/snapd/kernel-noble/gadget), Card 2 "Installed Snaps" =
    // everything else. Both alphabetical (live /v2/snaps order is not
    // stable). Columns: Snap | Version / Rev | Track/Channel | Actions —
    // the old Status/Type columns are gone, and no cell keeps a title
    // tooltip (the Track/Channel one was redundant).
    const snCards = await page.evaluate(() => {
        const cards = Array.from(document.querySelectorAll('#snapsCards > .p-card'));
        const titles = cards.map((c) => (c.querySelector('.p-card__header .p-heading--5') || {}).textContent || null);
        const rowsOf = (i) => (cards[i] || {}).querySelectorAll ? Array.from(cards[i].querySelectorAll('tbody tr')) : [];
        const namesOf = (trs) => trs.map((r) => (r.cells && r.cells[0] ? r.cells[0].textContent.trim() : null));
        const sys = rowsOf(0);
        const inst = rowsOf(1);
        const osHeads = cards[0] ? Array.from(cards[0].querySelectorAll('thead th')).map((th) => th.textContent.trim()) : null;
        const instHeads = cards[1] ? Array.from(cards[1].querySelectorAll('thead th')).map((th) => th.textContent.trim()) : null;
        const counts = cards.map((c) => (c.querySelector('.p-card__header .ucm-ifaces-card__counts') || {}).textContent || null);
        const osTitle = (cards[0] || {}).querySelector ? cards[0].querySelector('.ucm-snaps-card__title') : null;
        const osTitleCs = osTitle ? getComputedStyle(osTitle) : null;
        const firstTd = sys.length ? sys[0].cells[0] : null;
        const firstTdCs = firstTd ? getComputedStyle(firstTd) : null;
        // round 47c: the only title tooltips left in the table are the
        // name cells (the 'Show snap info' click affordance). Everything
        // else (esp. the old Track/Channel one) must be tooltip-free.
        let badTitle = 0, nameTitle = 0;
        cards.forEach((c) => c.querySelectorAll('tbody td').forEach((td) => {
            const t = td.getAttribute('title') || '';
            if (!t) return;
            if (t === 'Show snap info') nameTitle++;
            else badTitle++;
        }));
        return {
            count: cards.length, titles, counts,
            osNames: namesOf(sys), instNames: namesOf(inst),
            osRowLen: sys.map((r) => r.cells ? r.cells.length : -1),
            instRowLen: inst.map((r) => r.cells ? r.cells.length : -1),
            osHeads, instHeads,
            badTitle, nameTitle,
            titleSize: osTitleCs ? osTitleCs.fontSize : null,
            titlePadTop: osTitleCs ? osTitleCs.paddingTop : null,
            nameFam: firstTdCs ? firstTdCs.fontFamily : null,
            nameWt: firstTdCs ? firstTdCs.fontWeight : null,
            nameColor: firstTdCs ? firstTdCs.color : null,
            legacyWrap: !!document.querySelector('.ucm-table-wrap.ucm-snaps-table'),
            oldBody: !!document.querySelector('#snapsBody'),
            // round 47j: the store-search placeholder leads with snaps that
            // suit Ubuntu Core (no htop / firefox examples).
            searchPh: (document.querySelector('#snapSearchName') || {}).placeholder || null,
        };
    });
    if (snCards.count !== 2) console.log('PAGE ERROR: snaps page must have exactly two cards (' + snCards.count + ')');
    else {
        if (snCards.titles[0] !== 'OS' || snCards.titles[1] !== 'Installed Snaps')
            console.log('PAGE ERROR: card captions wrong (' + JSON.stringify(snCards.titles) + ', want ["OS","Installed Snaps"])');
        if (JSON.stringify(snCards.osNames) !== JSON.stringify(['core24', 'gadget', 'kernel-noble', 'snapd']))
            console.log('PAGE ERROR: OS card rows wrong (' + JSON.stringify(snCards.osNames) + ', want the four model system snaps, alphabetical)');
        if (JSON.stringify(snCards.instNames) !== JSON.stringify(['core22', 'firefox', 'htop', 'mosquitto', 'nextcloud', 'old-tool', 'snap-store']))
            console.log('PAGE ERROR: Installed Snaps rows not alphabetical (' + JSON.stringify(snCards.instNames) + ')');
        if (JSON.stringify(snCards.osHeads) !== JSON.stringify(['Snap', 'Version / Rev', 'Track/Channel', 'Actions']))
            console.log('PAGE ERROR: card table columns wrong (' + JSON.stringify(snCards.osHeads) + ')');
        if (JSON.stringify(snCards.instHeads) !== JSON.stringify(['Snap', 'Version / Rev', 'Track/Channel', 'Actions']))
            console.log('PAGE ERROR: Installed card columns wrong (' + JSON.stringify(snCards.instHeads) + ')');
        if (snCards.osRowLen.some((n) => n !== 4) || snCards.instRowLen.some((n) => n !== 4))
            console.log('PAGE ERROR: rows must have 4 cells (Status/Type dropped) os=' + JSON.stringify(snCards.osRowLen) + ' inst=' + JSON.stringify(snCards.instRowLen));
        if (snCards.badTitle !== 0) console.log('PAGE ERROR: a non-name cell still carries a title tooltip (' + snCards.badTitle + ' — the Track/Channel tooltip was dropped)');
        if (snCards.nameTitle !== 11) console.log('PAGE ERROR: snap-name info affordance missing (title on ' + snCards.nameTitle + ' of 11 name cells, want 11 — round 47c)');
        if (snCards.titleSize !== '16.8px') console.log('PAGE ERROR: card title is not the ifaces-card 1.05rem size (' + snCards.titleSize + ')');
        if (snCards.titlePadTop !== '0px') console.log('PAGE ERROR: card heading keeps the bundle padding-top (' + snCards.titlePadTop + ')');
        if (snCards.nameWt !== '600') console.log('PAGE ERROR: snap name is not semibold like the interface identity column (weight ' + snCards.nameWt + ', round 47b)');
        if (snCards.nameFam && /mono/i.test(snCards.nameFam)) console.log('PAGE ERROR: snap name still uses a monospace font (' + snCards.nameFam + ', round 47b)');
        if (snCards.nameColor !== 'rgb(59, 59, 59)') console.log('PAGE ERROR: snap name color is not the softened #3b3b3b (' + (snCards.nameColor || 'n/a') + ', round 47c)');
        if (snCards.counts[0] !== '4 snaps' || snCards.counts[1] !== '7 snaps')
            console.log('PAGE ERROR: card meta counts wrong (' + JSON.stringify(snCards.counts) + ', want ["4 snaps","7 snaps"])');
        if (snCards.legacyWrap) console.log('PAGE ERROR: the old scrollable table wrap (.ucm-table-wrap.ucm-snaps-table) is still in the DOM');
        const wantPh = 'e.g. rocketchat-server, nextcloud, mosquitto — Enter runs the search';
        if (snCards.searchPh !== wantPh) console.log('PAGE ERROR: store-search placeholder is not the Ubuntu-Core examples (' + JSON.stringify(snCards.searchPh) + ', round 47j)');
        if (snCards.oldBody) console.log('PAGE ERROR: the old #snapsBody table is still in the DOM');
    }
    await page.screenshot({ path: path.join(SHOTS, '13a-snaps-cards.png'), fullPage: true });
    // ---- 4c. installed-snaps table + remove-confirm card (alignment) ----
    // htop is a non-system snap -> shows Config/Refresh/Remove row actions.
    await page.evaluate(() => {
        const rows = Array.from(document.querySelectorAll('#snapsCards tbody tr'));
        const htop = rows.find((r) => r.textContent.includes('htop'));
        if (!htop) throw new Error('htop row missing');
        const btn = htop.querySelector('.ucm-iconbtn[aria-label^="Remove"]'); // icon-only: no text to match
        if (!btn) throw new Error('Remove button missing');
        btn.click();
    });
    await wait(800); // still inside the 1.2s settle window -> card is up
    // round 47: the confirm card anchors after the cards (below the fold in
    // the .ucm-main scroller) — scroll it into view for the shot.
    await page.evaluate(() => document.querySelector('.ucm-main').scrollTo({ top: 99999 }));
    await wait(200);
    await page.screenshot({ path: path.join(SHOTS, '13-remove-confirm.png'), fullPage: true });
    // Regression guard: every item in the remove-confirm row must share the same
    // vertical centre (bundle's .p-button margin-bottom used to shift the buttons
    // above centre, making the text look bottom-aligned).
    const align = await page.evaluate(() => {
        const box = document.querySelector('.ucm-confirm');
        const msg = document.querySelector('.ucm-confirm__msg');
        const btn = document.querySelector('.ucm-confirm button');
        if (!box || !msg || !btn) return { error: 'confirm row not found' };
        const c = (n) => { const r = n.getBoundingClientRect(); return (r.top + r.bottom) / 2; };
        return { msg: c(msg), btn: c(btn), delta: Math.abs(c(msg) - c(btn)) };
    });
    if (!align.error) {
        if (align.delta > 3) console.log(`PAGE ERROR: confirm row misaligned (delta=${align.delta.toFixed(1)}px)`);
    } else {
        console.log('PAGE ERROR: ' + align.error);
    }
    // dismiss the confirm card so it does not affect later shots
    await page.evaluate(() => {
        const box = document.querySelector('.ucm-confirm');
        if (box) box.remove();
    });

    // ---- 4d. Round 34: icon-only actions column (suru glyphs + Vanilla
    // tooltips), round 46b tiers (system = Refresh+Revert, non-model base
    // loses Config), round 47 cards. Every action is a textless icon button
    // (label lives in data-tooltip / aria-label; the CSS-only
    // .p-tooltip__message child is display:none until hover/focus).
    // Active snap htop -> 5 icons in order gear/refresh/revert/power-black/
    // trash; disabled snap old-tool (live status "installed") -> red power +
    // "Enable" (round 47 dropped the Status column — the red icon + label
    // carry the disabled state).

    const col = await page.evaluate(() => {
        const rowOf = (n) => Array.from(document.querySelectorAll('#snapsCards tbody tr'))
            .find((r) => r.cells && r.cells[0] && r.cells[0].textContent.trim() === n);
        const h = rowOf('htop'); const o = rowOf('old-tool');
        if (!h || !o) return { error: 'htop/old-tool row missing' };
        const k = rowOf('core24'); const g = rowOf('gadget'); const kn = rowOf('kernel-noble'); const c22 = rowOf('core22'); const nc = rowOf('nextcloud'); const ss = rowOf('snap-store');
        const iconList = (r) => r ? Array.from(r.querySelectorAll('.ucm-iconbtn')).map((b) => { const i = b.querySelector('i'); return i ? i.className : ''; }) : null;
        const hbtns = Array.from(h.querySelectorAll('.ucm-iconbtn'));
        const obtns = Array.from(o.querySelectorAll('.ucm-iconbtn'));
        const strip = (b) => { const c = b.cloneNode(true); const m = c.querySelector('.p-tooltip__message'); if (m) m.remove(); return c.textContent.trim(); };
        const bg = (b, cls) => { const i = b && b.querySelector('i.' + cls); return i ? getComputedStyle(i).backgroundImage : null; };
        const hPow = hbtns.find((b) => b.querySelector('i.p-icon--power'));
        const oPow = obtns.find((b) => b.querySelector('i.p-icon--power'));
        const oEn = obtns.find((b) => (b.getAttribute('aria-label') || '').startsWith('Enable'));
        return {
            hCount: hbtns.length, oCount: obtns.length,
            sysCore: iconList(k), sysGadget: iconList(g), sysKernel: iconList(kn), baseC22: iconList(c22), localNc: iconList(nc), requiredSs: iconList(ss),
            hTextless: hbtns.length > 0 && hbtns.every((b) => strip(b) === ''),
            hTooltips: hbtns.map((b) => (b.getAttribute('data-tooltip') || '').length > 0),
            hAria: hbtns.map((b) => (b.getAttribute('aria-label') || '').length > 0),
            hIcons: hbtns.map((b) => { const i = b.querySelector('i'); return i ? i.className : ''; }),
            hPowerImg: bg(hPow, 'p-icon--power'),
            hRefreshImg: bg(hbtns[1], 'p-icon--refresh'),
            hRevertImg: bg(hbtns[2], 'p-icon--revert'),
            hDeleteImg: bg(hbtns[4], 'p-icon--delete'),
            oPowerImg: bg(oPow, 'p-icon--power'),
            oEnableLabel: oEn ? oEn.getAttribute('aria-label') : null,
            msgDisplay: hbtns[0] ? getComputedStyle(hbtns[0].querySelector('.p-tooltip__message')).display : null,
            btnPadL: hbtns[0] ? getComputedStyle(hbtns[0]).paddingLeft : null,
            // round 47b: disabled state is the amber NAME now (Status column
            // gone) — old-tool is disabled in the mock, htop is not.
            oNameColor: getComputedStyle(o.cells[0]).color,
            hNameColor: getComputedStyle(h.cells[0]).color,
            // icon top offset inside its button + the button height, px: round-44c
            // regression - the four suru icons had no bundle vertical-align, so they
            // fell to the text baseline ~2px ABOVE the hover-square centre (the
            // bundle's own p-icons, incl. p-icon--delete, are centred by a
            // vertical-align nudge). All five must be uniform AND centred.
            // (Round 47: the old red disabled badge is gone with the Status
            // column — the red power icon + Enable label are the status now,
            // both still asserted below.)
            iTop: hbtns.map((b) => +((b.querySelector('i').getBoundingClientRect().top) - (b.getBoundingClientRect().top)).toFixed(2)),
            btnH: hbtns[0] ? +getComputedStyle(hbtns[0]).height : null,
        };
    });
    if (col.error) console.log('PAGE ERROR: ' + col.error);
    else {
        if (col.hCount !== 5 || col.oCount !== 5) console.log('PAGE ERROR: actions count (htop=' + col.hCount + ' old-tool=' + col.oCount + ', want 5/5)');
        if (!col.hTextless) console.log('PAGE ERROR: action button still carries text (icon-only violated)');
        if (!col.hTooltips.every(Boolean) || !col.hAria.every(Boolean)) console.log('PAGE ERROR: an action is missing its tooltip/aria label');
        const wantIcons = ['p-icon--settings', 'p-icon--refresh', 'p-icon--revert', 'p-icon--power', 'p-icon--delete'];
        if (JSON.stringify(col.hIcons) !== JSON.stringify(wantIcons)) console.log('PAGE ERROR: action icons wrong or out of order (' + col.hIcons + ')');
        if (!(col.hPowerImg || '').includes('suru-power.svg')) console.log('PAGE ERROR: enabled power icon is not the black suru-power.svg (' + col.hPowerImg + ')');
        if (!(col.hRefreshImg || '').includes('suru-sync.svg')) console.log('PAGE ERROR: refresh icon is not the suru sync glyph (' + col.hRefreshImg + ')');
        if (!(col.hRevertImg || '').includes('suru-undo.svg')) console.log('PAGE ERROR: revert icon is not the suru undo glyph (' + col.hRevertImg + ')');
        if (!(col.hDeleteImg || '').includes('suru-delete.svg')) console.log('PAGE ERROR: remove icon is not the suru trash glyph (' + col.hDeleteImg + ')');
        if (!(col.oPowerImg || '').includes('suru-power-red.svg')) console.log('PAGE ERROR: disabled power icon is not the red suru-power-red.svg (' + col.oPowerImg + ')');
        if (!(col.oEnableLabel || '').startsWith('Enable')) console.log('PAGE ERROR: disabled snap action is not Enable (' + col.oEnableLabel + ')');
        if (col.oNameColor !== 'rgb(179, 107, 0)') console.log('PAGE ERROR: disabled snap name is not the caution amber (' + col.oNameColor + ', want rgb(179, 107, 0) — the round-47b state cue)');
        if (col.hNameColor === 'rgb(179, 107, 0)') console.log('PAGE ERROR: enabled snap name is tinted (' + col.hNameColor + ' — amber must mark DISABLED only, round 47b)');
        if (col.msgDisplay !== 'none') console.log('PAGE ERROR: tooltip message visible before hover (display=' + col.msgDisplay + ')');
        if (col.btnPadL !== '0px') console.log('PAGE ERROR: icon button horizontal padding not zeroed (' + col.btnPadL + ')');
        // round 46: system snaps (base/core/kernel/gadget/snapd) get ONLY
        // Refresh + Revert — snapd refuses config (500 'type base'),
        // disable and remove (400) on them, so no gear/power/trash icons.
        // round 46b: SYSTEM snaps (model-assertion declared: top-level base +
        // gadget/kernel/snapd entries) -> exactly Refresh + Revert.
        if (!col.sysCore || JSON.stringify(col.sysCore) !== JSON.stringify(['p-icon--refresh', 'p-icon--revert']))
            console.log('PAGE ERROR: system snap core24 actions wrong (' + JSON.stringify(col.sysCore) + ', want exactly [refresh, revert], round 46b)');
        // round 47j: LOCAL (x-revision) builds are never refreshed from the
        // store (the daemon would 400 'no updates available') — the row must
        // omit the Refresh icon. gadget = the local SYSTEM case (Revert only);
        // nextcloud = the local tier-3 app case (settings/revert/power/delete).
        if (!col.sysGadget || JSON.stringify(col.sysGadget) !== JSON.stringify(['p-icon--revert']))
            console.log('PAGE ERROR: local system snap gadget still offers a store refresh (' + JSON.stringify(col.sysGadget) + ', want exactly [revert] — round 47j)');
        if (!col.localNc || JSON.stringify(col.localNc) !== JSON.stringify(['p-icon--settings', 'p-icon--revert', 'p-icon--power', 'p-icon--delete']))
            console.log('PAGE ERROR: local app nextcloud still offers a store refresh (' + JSON.stringify(col.localNc) + ', want [settings, revert, power, delete] — round 47j)');
        // round 47k: model-`presence: required` snaps are used by the model —
        // snapd refuses their removal, so the row must omit the trash icon
        // (snap-store is required in the mock model; htop is not and keeps
        // the full five, pinning the drop's scope).
        if (!col.requiredSs || JSON.stringify(col.requiredSs) !== JSON.stringify(['p-icon--settings', 'p-icon--refresh', 'p-icon--revert', 'p-icon--power']))
            console.log('PAGE ERROR: model-required snap-store still offers Remove (' + JSON.stringify(col.requiredSs) + ', want [settings, refresh, revert, power] — round 47k)');
        if (!col.sysKernel || JSON.stringify(col.sysKernel) !== JSON.stringify(['p-icon--refresh', 'p-icon--revert']))
            console.log('PAGE ERROR: system snap kernel actions wrong (' + JSON.stringify(col.sysKernel) + ', want exactly [refresh, revert], round 46b)');
        // tier 2: a base-type snap the model does NOT declare keeps
        // Refresh/Revert/Disable/Remove, only loses Config.
        if (!col.baseC22 || JSON.stringify(col.baseC22) !== JSON.stringify(['p-icon--refresh', 'p-icon--revert', 'p-icon--power', 'p-icon--delete']))
            console.log('PAGE ERROR: non-model base core22 actions wrong (' + JSON.stringify(col.baseC22) + ', want [refresh, revert, power, delete] — no config, round 46b)');
                if (!col.iTop || col.iTop.some((v) => v !== col.iTop[0])) console.log('PAGE ERROR: row icon boxes not vertically uniform in their buttons (offsets ' + JSON.stringify(col.iTop) + ' px, round 44c)');
        else if (col.btnH) { var c44 = (col.btnH - 16) / 2; if (col.iTop.some((v) => Math.abs(v - c44) > 1)) console.log('PAGE ERROR: row icons not centred in their buttons (offsets ' + JSON.stringify(col.iTop) + ' px, want ' + c44.toFixed(2) + ' +-1 - the suru icons lost the bundle vertical-align nudge, round 44c)'); }
    }
    await page.screenshot({ path: path.join(SHOTS, '13b-snaps-actions.png'), fullPage: true });

    // ---- 4f. Round 47c: clicking a snap NAME opens the snap-info modal.
    // The data is the single-snap GET /v2/snaps/{name} (the harness mock's
    // core.snaps.info already returns it). Assert the card's contents, then
    // close it (backdrop) so later steps see a clean table.
    await page.evaluate(() => {
        const name = Array.from(document.querySelectorAll('#snapsCards .ucm-snaps-name'))
            .find((n) => n.textContent.trim() === 'htop');
        if (!name) throw new Error('htop name cell missing');
        name.click();
    });
    await wait(600); // async info fetch + render
    const info = await page.evaluate(() => {
        const modal = document.querySelector('.ucm-modal');
        const body = modal ? modal.querySelector('.ucm-info') : null;
        const card = modal ? modal.querySelector('.ucm-modal__card') : null;
        const t = (sel) => body && (body.querySelector(sel) || {}).textContent || null;
        const descEl = body ? body.querySelector('.ucm-info__desc') : null;
        // section order (round 47d): the description must come BEFORE the
        // first fact table. Compare real DOM order (a flat .ucm-info__sec /
        // .ucm-kv sequence) — the Description sec precedes the first .ucm-kv.
        const seq = body ? Array.from(body.querySelectorAll('.ucm-info__sec, .ucm-kv')) : [];
        const descIdx = seq.findIndex((e) => e.classList.contains('ucm-info__sec') && e.textContent.trim() === 'Description');
        const firstKvIdx = seq.findIndex((e) => e.classList.contains('ucm-kv'));
        // the 80-char token must sit on ONE line (its Range width <= the
        // description container width — the 52rem card guarantee)
        let tok = null;
        if (descEl) {
            const tokStr = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
            const node = descEl.firstChild;
            const idx = node ? node.data.indexOf(tokStr) : -1;
            if (node && idx >= 0) {
                const rng = document.createRange();
                rng.setStart(node, idx);
                rng.setEnd(node, idx + tokStr.length);
                tok = { boxW: Math.round(rng.getBoundingClientRect().width), descW: Math.round(descEl.clientWidth), lineH: Math.round(getComputedStyle(descEl).lineHeight) };
            }
        }
        const closeIc = modal ? modal.querySelector('.ucm-info__close') : null;
        const pb = body ? body.querySelector('.ucm-pub-badge') : null;
        const dd = (label) => {
            if (!body) return null;
            for (const div of body.querySelectorAll('.ucm-kv > div')) {
                if ((div.querySelector('dt') || {}).textContent === label)
                    return (div.querySelector('dd') || {}).textContent;
            }
            return null;
        };
        const ddEl = (label) => {
            if (!body) return null;
            for (const div of body.querySelectorAll('.ucm-kv > div')) {
                if ((div.querySelector('dt') || {}).textContent === label)
                    return div.querySelector('dd');
            }
            return null;
        };
        return {
            shown: !!body,
            title: t('.ucm-info__name'), id: t('.ucm-info__id'),
            summary: t('.ucm-info__summary'),
            chip0: (body && body.querySelector('.ucm-info__chips .p-status-label') || {}).textContent || null,
            version: dd('Version'), channel: (ddEl('Track/Channel') && (ddEl('Track/Channel').querySelector('.ucm-mono') || {}).textContent || '').trim(), publisher: dd('Publisher'),
            website: dd('Website'), source: dd('Source'),
            hasDesc: !!t('.ucm-info__desc'),
            descPlain: (t('.ucm-info__desc') || '').includes('**') ? 'STILL-MARKDOWN' : 'plain',
            // the kiosk is a fixed 900px-tall display — the card must fit
            // fully (head pinned, body scrolls) instead of clipping
            inViewport: card ? (card.getBoundingClientRect().top >= 0 && card.getBoundingClientRect().bottom <= window.innerHeight) : false,
            cardW: card ? Math.round(card.getBoundingClientRect().width) : null,
            closeFilter: closeIc ? getComputedStyle(closeIc).filter : null,
            descIdx, firstKvIdx, tok,
            pubBadgeChar: pb ? pb.textContent : null,
            pubBadgeColor: pb ? getComputedStyle(pb).color : null,
            pubBadgeSize: pb ? getComputedStyle(pb).fontSize : null,
            divPresent: body ? !!body.querySelector('.ucm-info__div') : false,
        };
    });
    if (!info.shown) console.log('PAGE ERROR: clicking a snap name did not open the snap-info modal');
    else {
        if (info.title !== 'Host resources monitor') console.log('PAGE ERROR: info modal title wrong (' + info.title + ')');
        if (info.id !== 'htop') console.log('PAGE ERROR: info modal real name wrong (' + info.id + ')');
        if (info.summary !== 'Interactive ps') console.log('PAGE ERROR: info modal summary wrong (' + info.summary + ')');
        if (info.chip0 !== 'active') console.log('PAGE ERROR: info modal status chip wrong (' + info.chip0 + ')');
        if (info.version !== '3.3.0 (5533)') console.log('PAGE ERROR: info modal version wrong (' + info.version + ')');
        if (info.channel !== 'latest/stable') console.log('PAGE ERROR: info modal track/channel wrong (' + info.channel + ')');
        if (info.publisher !== 'htop-dev\u272A') console.log('PAGE ERROR: info modal publisher wrong (want the name + a star, got ' + JSON.stringify(info.publisher) + ')');
        if (info.pubBadgeChar !== '\u272A') console.log('PAGE ERROR: starred publisher is not the yellow star glyph (got ' + JSON.stringify(info.pubBadgeChar) + ', round 47e)');
        if (info.pubBadgeColor !== 'rgb(217, 164, 0)') console.log('PAGE ERROR: star badge is not the yellow (--ucm-yellow) (got ' + info.pubBadgeColor + ', round 47e)');
        if (info.pubBadgeSize !== '20.8px') console.log('PAGE ERROR: publisher badge is not the enlarged 1.3rem size (got ' + info.pubBadgeSize + ', round 47f)');
        if (info.divPresent !== true) console.log('PAGE ERROR: no divider between the description and the technical info (round 47e)');
        if (info.website !== 'https://htop.dev') console.log('PAGE ERROR: info modal website link wrong (' + info.website + ')');
        if (info.source !== 'https://github.com/vt100/htop') console.log('PAGE ERROR: info modal source link wrong (' + info.source + ')');
        if (!info.hasDesc) console.log('PAGE ERROR: info modal has no description section');
        else if (info.descPlain !== 'plain') console.log('PAGE ERROR: info modal description still carries markdown');
        if (info.inViewport !== true) console.log('PAGE ERROR: info modal card does not fit the 900px kiosk viewport (head pinned + body must scroll)');
        if (!(info.cardW >= 750)) console.log('PAGE ERROR: info modal card is not the wide 52rem size (width ' + info.cardW + 'px, want >=750 — 80 chars/line, round 47d)');
        if (!/brightness\(0\)\s+invert\(1\)/.test(info.closeFilter || '')) console.log('PAGE ERROR: info modal close icon is not whitened (filter ' + info.closeFilter + ', round 47d)');
        if (!(info.descIdx >= 0 && info.firstKvIdx > info.descIdx)) console.log('PAGE ERROR: description is not above the technical info (descIdx ' + info.descIdx + ' firstKvIdx ' + info.firstKvIdx + ', round 47d)');
        if (!info.tok) console.log('PAGE ERROR: the 80-char token line is not found in the description');
        else if (info.tok.boxW > info.tok.descW) console.log('PAGE ERROR: the 80-char line wraps (' + info.tok.boxW + 'px > ' + info.tok.descW + 'px container — card too narrow, round 47d)');
    }
    await page.screenshot({ path: path.join(SHOTS, '13c-snap-info.png') });
    // round 47e: Esc closes the modal (focus is on the close button, so the
    // keydown bubbles to the modal box)
    await page.keyboard.down('Escape');
    await page.keyboard.up('Escape');
    await wait(200);
    const escGone = await page.evaluate(() => !document.querySelector('.ucm-modal'));
    if (!escGone) console.log('PAGE ERROR: Esc did not close the snap-info modal (round 47e)');

    // 4f2. a VERIFIED publisher (core24) -> the green CHECK, and core24 has no
    //      display title so the mono id line is absent — then Esc again.
    await page.evaluate(() => {
        const name = Array.from(document.querySelectorAll('#snapsCards .ucm-snaps-name'))
            .find((n) => n.textContent.trim() === 'core24');
        if (!name) throw new Error('core24 name cell missing');
        name.click();
    });
    await wait(600);
    const c24 = await page.evaluate(() => {
        const body = document.querySelector('.ucm-modal .ucm-info');
        const t = (sel) => body && (body.querySelector(sel) || {}).textContent || null;
        const dd = (label) => {
            if (!body) return null;
            for (const div of body.querySelectorAll('.ucm-kv > div'))
                if ((div.querySelector('dt') || {}).textContent === label) return (div.querySelector('dd') || {}).textContent;
            return null;
        };
        const pb = body ? body.querySelector('.ucm-pub-badge') : null;
        return { shown: !!body, title: t('.ucm-info__name'), hasId: !!t('.ucm-info__id') && t('.ucm-info__id') !== '',
                 publisher: dd('Publisher'), badgeChar: pb ? pb.textContent : null,
                 badgeColor: pb ? getComputedStyle(pb).color : null,
                 divPresent: body ? !!body.querySelector('.ucm-info__div') : false };
    });
    if (!c24.shown) console.log('PAGE ERROR: clicking core24 did not open the snap-info modal');
    else {
        if (c24.title !== 'core24') console.log('PAGE ERROR: no-title snap shows the wrong modal title (' + c24.title + ')');
        if (c24.hasId) console.log('PAGE ERROR: a snap without a display title still shows a mono id line (round 47e)');
        if (c24.publisher !== 'Canonical\u2713') console.log('PAGE ERROR: verified publisher is not the name + a check (want ' + JSON.stringify('Canonical\u2713') + ', got ' + JSON.stringify(c24.publisher) + ')');
        if (c24.badgeChar !== '\u2713') console.log('PAGE ERROR: verified publisher is not the check glyph (got ' + JSON.stringify(c24.badgeChar) + ', round 47e)');
        if (c24.badgeColor !== 'rgb(14, 132, 32)') console.log('PAGE ERROR: check badge is not the positive green (got ' + c24.badgeColor + ', round 47e)');
        if (c24.divPresent !== true) console.log('PAGE ERROR: no divider before the technical info on a no-description snap (round 47e)');
    }
    await page.keyboard.down('Escape');
    await page.keyboard.up('Escape');
    await wait(200);
    const c24Gone = await page.evaluate(() => !document.querySelector('.ucm-modal'));
    if (!c24Gone) console.log('PAGE ERROR: Esc did not close the second snap-info modal (round 47e)');

    // ---- 4g. Round 47g: the channel switcher. A snap with store channels
    // (htop in the mock) shows a 'Switch channel' ghost button on the
    // Track/Channel row; a local snap (core24 — no store channels) shows a
    // quiet 'local' marker instead. The picker is a filterable,
    // track-grouped list; confirming issues a REFRESH with the channel
    // (`switch` is metadata-only and is never used).
    await page.evaluate(() => {
        const n = Array.from(document.querySelectorAll('#snapsCards .ucm-snaps-name'))
            .find((n) => n.textContent.trim() === 'htop');
        if (!n) throw new Error('htop name cell missing (4g)');
        n.click();
    });
    await wait(700); // info + store channel search (async)
    const sw = await page.evaluate(() => {
        const body = document.querySelector('.ucm-modal .ucm-info');
        const dd = (label) => { for (const d of body.querySelectorAll('.ucm-kv > div')) if ((d.querySelector('dt')||{}).textContent === label) return d.querySelector('dd'); return null; };
        const chDd = dd('Track/Channel');
        const btn = chDd ? chDd.querySelector('.ucm-info__switcher') : null;
        return { hasSwitcher: !!btn, btnText: btn ? btn.textContent.trim() : null,
                 cur: chDd ? (chDd.querySelector('.ucm-mono')||{}).textContent.trim() : null };
    });
    if (!sw.hasSwitcher) console.log('PAGE ERROR: htop (has store channels) shows no Switch channel button');
    else {
        if (sw.btnText !== 'Switch channel') console.log('PAGE ERROR: switcher label wrong (' + sw.btnText + ')');
        if (sw.cur !== 'latest/stable') console.log('PAGE ERROR: channel value wrong before switch (' + sw.cur + ')');
        await page.evaluate(() => document.querySelector('.ucm-info__switcher').click());
        await wait(250);
        const pk = await page.evaluate(() => {
            const wrap = document.querySelector('.ucm-info__picker');
            if (!wrap) return { err: true };
            const items = Array.from(wrap.querySelectorAll('.ucm-info__chan'));
            const tracks = Array.from(wrap.querySelectorAll('.ucm-info__track')).map((t) => t.textContent.trim());
            const cur = items.find((i) => i.classList.contains('is-current'));
            const go = wrap.querySelector('.p-button--brand');
            return { items: items.length, tracks,
                     curText: cur ? cur.querySelector('.ucm-mono').textContent.trim() : null,
                     curDisabled: cur ? cur.disabled : null,
                     hasFilter: !!wrap.querySelector('.ucm-info__picker-filter'),
                     goDisabled: go ? go.disabled : true, goText: go ? go.textContent.trim() : null };
        });
        if (pk.err) console.log('PAGE ERROR: the channel picker panel did not open');
        else {
            if (pk.items !== 7) console.log('PAGE ERROR: picker item count wrong (' + pk.items + ', want 7 for htop)');
            if (JSON.stringify(pk.tracks) !== JSON.stringify(['3.2', '3.3', 'latest'])) console.log('PAGE ERROR: picker track grouping wrong (' + JSON.stringify(pk.tracks) + ')');
            if (pk.curText !== 'latest/stable' || pk.curDisabled !== true) console.log('PAGE ERROR: current channel not marked current+disabled (' + JSON.stringify({ t: pk.curText, d: pk.curDisabled }) + ')');
            if (!pk.hasFilter) console.log('PAGE ERROR: picker has no filter input');
            if (pk.goDisabled !== true) console.log('PAGE ERROR: the Switch CTA is enabled before a channel is selected');
            // filter narrows to the candidate channels only
            await page.type('.ucm-info__picker-filter', 'candidate');
            await wait(150);
            const flt = await page.evaluate(() => Array.from(document.querySelectorAll('.ucm-info__chan')).map((b) => b.querySelector('.ucm-mono').textContent.trim()));
            if (JSON.stringify(flt) !== JSON.stringify(['3.3/candidate', 'latest/candidate'])) console.log('PAGE ERROR: channel filter wrong (got ' + JSON.stringify(flt) + ')');
            await page.evaluate(() => { const fi = document.querySelector('.ucm-info__picker-filter'); fi.value = ''; fi.dispatchEvent(new Event('input', { bubbles: true })); });
            await wait(150);
            // select 3.3/candidate -> the CTA arms with the target
            await page.evaluate(() => {
                const it = Array.from(document.querySelectorAll('.ucm-info__chan'))
                    .find((b) => b.querySelector('.ucm-mono').textContent.trim() === '3.3/candidate');
                if (!it) throw new Error('3.3/candidate not in picker');
                it.click();
            });
            await wait(150);
            const selS = await page.evaluate(() => { const go = document.querySelector('.ucm-info__picker .p-button--brand'); return { goText: go.textContent.trim(), goDisabled: go.disabled }; });
            if (selS.goDisabled !== false || selS.goText !== 'Switch to 3.3/candidate') console.log('PAGE ERROR: CTA did not arm on selection (' + JSON.stringify(selS) + ')');
            await page.screenshot({ path: path.join(SHOTS, '13d-snap-info-picker.png') });
            // confirm -> REFRESH with channel settles -> the channel row shows
            // the new current channel and the panel collapses
            await page.evaluate(() => document.querySelector('.ucm-info__picker .p-button--brand').click());
            await wait(1500); // 400ms mock settle + info re-render
            const after = await page.evaluate(() => {
                const body = document.querySelector('.ucm-modal .ucm-info');
                const dd = (label) => { for (const d of body.querySelectorAll('.ucm-kv > div')) if ((d.querySelector('dt')||{}).textContent === label) return d.querySelector('dd'); return null; };
                const chDd = dd('Track/Channel');
                return { cur: chDd ? (chDd.querySelector('.ucm-mono')||{}).textContent.trim() : null,
                         pickerGone: !document.querySelector('.ucm-info__picker') };
            });
            if (after.cur !== '3.3/candidate') console.log('PAGE ERROR: channel row did not update to the new channel after the switch (' + after.cur + ')');
            if (!after.pickerGone) console.log('PAGE ERROR: the picker panel is still open after the switch completed');
        }
    }
    await page.keyboard.down('Escape');
    await page.keyboard.up('Escape');
    await wait(200);
    const swGone = await page.evaluate(() => !document.querySelector('.ucm-modal'));
    if (!swGone) console.log('PAGE ERROR: Esc did not close the modal after the channel switch');
    // round 47h: a LOCAL build (x-prefixed revision) -> NO switcher, even
    // though the mock STORE has channels for the same-named store snap.
    // This is the foot-gun: a locally modified gadget must not be offerable
    // a store refresh that would replace it.
    await page.evaluate(() => {
        const n = Array.from(document.querySelectorAll('#snapsCards .ucm-snaps-name'))
            .find((n) => n.textContent.trim() === 'gadget');
        if (!n) throw new Error('gadget name cell missing (4g)');
        n.click();
    });
    await wait(700);
    const swLocal = await page.evaluate(() => {
        const body = document.querySelector('.ucm-modal .ucm-info');
        const dd = (label) => { for (const d of body.querySelectorAll('.ucm-kv > div')) if ((d.querySelector('dt')||{}).textContent === label) return d.querySelector('dd'); return null; };
        const chDd = dd('Track/Channel');
        const verDd = dd('Version');
        return { hasSwitcher: !!(chDd && chDd.querySelector('.ucm-info__switcher')),
                 local: (chDd ? chDd.textContent : '').includes('local'),
                 version: verDd ? verDd.textContent.trim() : null };
    });
    if (swLocal.hasSwitcher) console.log('PAGE ERROR: a locally-built snap (x revision) offers a Switch channel button (round 47h)');
    if (!swLocal.local) console.log('PAGE ERROR: a locally-built snap is not marked local in the channel row (round 47h)');
    if (swLocal.version !== '1.2 (x1)') console.log('PAGE ERROR: the local gadget revision is not x-prefixed in the mock (' + swLocal.version + ', want 1.2 (x1))');
    await page.keyboard.down('Escape');
    await page.keyboard.up('Escape');
    await wait(200);

    // ---- 4e. Round 45: Disable is a FATAL-class action -> confirmation card ----
    // Disabling a snap (e.g. the app's own) stops it for good until re-enabled,
    // so the power icon must NOT toggle it in one click. Clicking Disable on an
    // ENABLED snap must spawn the inline confirm card (same idiom as Remove);
    // Cancel must leave the snap enabled; Confirm must disable it and flip the
    // row to the red power + Enable. Enable stays one-click (it is the safe,
    // corrective direction).
    await page.evaluate(() => {
        const rows = Array.from(document.querySelectorAll('#snapsCards tbody tr'));
        const htop = rows.find((r) => r.cells && r.cells[0] && r.cells[0].textContent.trim() === 'htop');
        if (!htop) throw new Error('htop row missing');
        const btn = htop.querySelector('.ucm-iconbtn[aria-label="Disable htop"]'); // htop is active -> Disable
        if (!btn) throw new Error('Disable button missing');
        btn.click();
    });
    await wait(400);
    const dis1 = await page.evaluate(() => {
        const rows = Array.from(document.querySelectorAll('#snapsCards tbody tr'));
        const htop = rows.find((r) => r.cells && r.cells[0] && r.cells[0].textContent.trim() === 'htop');
        const box = document.querySelector('.ucm-confirm');
        const msg = box && (box.querySelector('.ucm-confirm__msg') || {}).textContent || null;
        const btns = box ? Array.from(box.querySelectorAll('button')).map((b) => b.textContent.trim()) : [];
        return {
            boxShown: !!box,
            negative: !!(box && box.classList.contains('ucm-confirm--negative')),
            msg, btns,
            disableStillThere: !!htop.querySelector('.ucm-iconbtn[aria-label="Disable htop"]'),
        };
    });
    if (!dis1.boxShown) console.log('PAGE ERROR: clicking Disable did not spawn a confirmation card (it must not be a one-click action)');
    else {
        if (!dis1.negative) console.log('PAGE ERROR: disable confirm card is not the negative style');
        if (!dis1.msg || !/Disable snap “htop”\?/.test(dis1.msg)) console.log('PAGE ERROR: disable confirm message wrong (' + dis1.msg + ')');
        if (JSON.stringify(dis1.btns) !== JSON.stringify(['Disable htop?', 'Cancel'])) console.log('PAGE ERROR: disable confirm buttons wrong (' + JSON.stringify(dis1.btns) + ')');
        if (!dis1.disableStillThere) console.log('PAGE ERROR: row already flipped before confirmation');
    }
    // Cancel -> the snap must stay enabled and the card must vanish
    await page.evaluate(() => {
        const box = document.querySelector('.ucm-confirm');
        const cancel = box && Array.from(box.querySelectorAll('button')).find((b) => b.textContent.trim() === 'Cancel');
        if (!cancel) throw new Error('Cancel button missing');
        cancel.click();
    });
    await wait(300);
    const dis2 = await page.evaluate(() => {
        const rows = Array.from(document.querySelectorAll('#snapsCards tbody tr'));
        const htop = rows.find((r) => r.cells && r.cells[0] && r.cells[0].textContent.trim() === 'htop');
        return {
            cardGone: !document.querySelector('.ucm-confirm'),
            stillDisable: !!htop.querySelector('.ucm-iconbtn[aria-label="Disable htop"]'),
        };
    });
    if (!dis2.cardGone) console.log('PAGE ERROR: confirm card still shown after Cancel');
    if (!dis2.stillDisable) console.log('PAGE ERROR: Cancel did not leave the snap enabled (' + JSON.stringify(dis2) + ')');
    // Confirm -> htop becomes disabled (red badge + red power + Enable), card removed
    await page.evaluate(() => {
        const rows = Array.from(document.querySelectorAll('#snapsCards tbody tr'));
        const htop = rows.find((r) => r.cells && r.cells[0] && r.cells[0].textContent.trim() === 'htop');
        const btn = htop.querySelector('.ucm-iconbtn[aria-label="Disable htop"]');
        if (!btn) throw new Error('Disable button missing (again)');
        btn.click();
    });
    await wait(400);
    await page.evaluate(() => {
        const box = document.querySelector('.ucm-confirm');
        const ok = box && Array.from(box.querySelectorAll('button')).find((b) => b.textContent.trim() === 'Disable htop?');
        if (!ok) throw new Error('Disable confirm button missing');
        ok.click();
    });
    await wait(1900); // 1.2s mock settle + margin
    const dis3 = await page.evaluate(() => {
        const rows = Array.from(document.querySelectorAll('#snapsCards tbody tr'));
        const htop = rows.find((r) => r.cells && r.cells[0] && r.cells[0].textContent.trim() === 'htop');
        const btns = Array.from(htop.querySelectorAll('.ucm-iconbtn'));
        const pow = btns.find((b) => b.querySelector('i.p-icon--power'));
        return {
            cardGone: !document.querySelector('.ucm-confirm'),
            hasEnable: !!htop.querySelector('.ucm-iconbtn[aria-label="Enable htop"]'),
            powRed: !!(pow && pow.querySelector('i.p-icon--power-red')),
        };
    });
    if (!dis3.cardGone) console.log('PAGE ERROR: confirm card still shown after the disable settled');
    if (!dis3.hasEnable || !dis3.powRed) console.log('PAGE ERROR: disabled row is not the red-power + Enable state (' + JSON.stringify(dis3) + ')');
    // restore htop (Enable is one-click) so later steps see a consistent state
    await page.evaluate(() => {
        const rows = Array.from(document.querySelectorAll('#snapsCards tbody tr'));
        const htop = rows.find((r) => r.cells && r.cells[0] && r.cells[0].textContent.trim() === 'htop');
        const en = htop && htop.querySelector('.ucm-iconbtn[aria-label="Enable htop"]');
        if (en) en.click();
    });
    await wait(1900);

    // Round 43/47: the bundle's `td,th { overflow: hidden }` clips the
    // p-tooltip--top-right message of the row actions (it renders above the
    // icon) 100% unless the Actions cell AND header are un-clipped
    // (.ucm-actions-cell / .ucm-ifaces-action { overflow: visible }). Round 47
    // moved the table into a .p-card, so the card is the clip boundary now
    // (the old sticky-thead overflow override no longer applies). Hover the
    // first htop action and assert the message displays with a real box,
    // nothing between it and the card clips it, and the cell + header stay
    // overflow:visible (same idiom as the round-40 guard).
    const snTip = await page.evaluate(() => {
        const rows = Array.from(document.querySelectorAll('#snapsCards tbody tr'));
        const htop = rows.find((r) => r.cells && r.cells[0] && r.cells[0].textContent.trim() === 'htop');
        const btn = htop && htop.querySelector('.ucm-iconbtn');
        if (!btn) return null;
        btn.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
        btn.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
        btn.focus();
        const msg = btn.querySelector('.p-tooltip__message');
        const cs = getComputedStyle(msg);
        const m = msg.getBoundingClientRect();
        const wrap = btn.closest('.p-card'); // round 47: the table lives inside a card
        const wr = wrap.getBoundingClientRect();
        // ancestors between the tooltip and the wrapper: none may clip (the
        // wrapper itself is a legitimate scroll container, overflow:auto).
        let n = msg.parentElement, clipper = null;
        while (n && n !== wrap) {
            const o = getComputedStyle(n).overflow;
            if (o === 'hidden') { clipper = n.tagName.toLowerCase() + '.' + (n.className && String(n.className).slice(0, 40)); break; }
            n = n.parentElement;
        }
        const th = btn.closest('table') ? btn.closest('table').querySelector('thead th.ucm-ifaces-action') : null;
        return { display: cs.display, w: Math.round(m.width), h: Math.round(m.height),
            inWrap: m.top >= wr.top - 1 && m.bottom <= wr.bottom + 1,
            tdOverflow: getComputedStyle(btn.closest('td')).overflow, thOverflow: th ? getComputedStyle(th).overflow : null, clipper };
    });
    if (!snTip)
        console.log('PAGE ERROR: no htop row action to test the snaps tooltip');
    else if (snTip.display === 'none' || snTip.w <= 0 || snTip.h <= 0)
        console.log('PAGE ERROR: snaps row-action tooltip not displayed on hover: ' + JSON.stringify(snTip));
    else if (snTip.clipper)
        console.log('PAGE ERROR: an ancestor still clips the snaps tooltip (overflow:hidden on ' + snTip.clipper + '): ' + JSON.stringify(snTip));
    else if (snTip.tdOverflow !== 'visible')
        console.log('PAGE ERROR: the snaps Actions cell is not overflow:visible (' + snTip.tdOverflow + ')');
    else if (snTip.thOverflow !== 'visible')
        console.log('PAGE ERROR: the snaps Actions header is not overflow:visible (' + snTip.thOverflow + ')');
    else if (!snTip.inWrap)
        console.log('PAGE ERROR: snaps row-action tooltip escapes its card (would be clipped by the card border): ' + JSON.stringify(snTip));
    // defensive: no modal may still be covering the UI (a stuck modal would
    // mask later clicks and mask real layout in the shots)
    const stray = await page.evaluate(() => document.querySelectorAll('.ucm-modal').length);
    if (stray) console.log('PAGE ERROR: stray modal left open before interfaces view');

    // ---- 5. interfaces view (round 37: per-snap cards, snap-connections tables) ----
    // The page shows ALL interfaces (connected + unconnected). One card per
    // consuming snap (sorted by name), each a table (Interface | Plug | Slot |
    // Actions) mirroring `snap connections <snap>`: connected rows on top,
    // unconnected below. System slots (core/snapd/system) render ":name" and
    // their unconnected rows get a BARE Connect (target pre-filled); app slots
    // render "snap:name". Round 39: icon-only Connect/Disconnect (suru
    // add/close, the snaps-table rowBtn idiom). Round 41: the target-slot
    // pulldown is GONE — for content interfaces snapd accepts any same-interface
    // slot, so a picker could only offer broken connections. The only usable
    // target is the same-named slot: one -> shown as plain text + enabled +;
    // none/ambiguous (the lxd case) -> "—" + disabled +. System-slot plugs
    // keep a bare pre-filled connect.
    await page.click('.ucm-side a[data-view="interfaces"]');
    await wait(700);
    await page.screenshot({ path: path.join(SHOTS, '14-interfaces.png'), fullPage: true });

    const ifRead = () => page.evaluate(() => {
        const readCard = (card) => {
            const rows = Array.from(card.querySelectorAll('tr.ucm-iface')).map((tr) => {
                const tds = Array.from(tr.querySelectorAll('td'));
                const sel = tds[2].querySelector('.ucm-iface-select');
                const btn = tr.querySelector('.ucm-ifaces-action .ucm-iconbtn');
                const slotText = sel
                    ? (sel.selectedIndex >= 0 ? sel.options[sel.selectedIndex].text : '')
                    : tds[2].textContent.trim();
                const ic = btn ? btn.querySelector('i') : null;
                const tip = btn ? btn.querySelector('.p-tooltip__message') : null;
                return {
                    iface: tds[0].textContent.trim(),
                    plug: tds[1].textContent.trim(),
                    slot: slotText,
                    tone: tr.className,
                    hasSelect: !!sel,
                    selOpts: sel ? Array.from(sel.options).map((o) => o.value) : null,
                    hasBtn: !!btn,
                    btnAria: btn ? btn.getAttribute('aria-label') : null,
                    btnIconClass: ic ? ic.className : null,
                    btnIconBg: ic ? getComputedStyle(ic).backgroundImage : null,
                    btnDisabled: btn ? (btn.disabled || btn.getAttribute('aria-disabled') === 'true') : null,
                    tipMsg: tip ? tip.textContent.trim() : null,
                };
            });
            const secs = Array.from(card.querySelectorAll('thead th')).map((t) => t.textContent.trim());
            return { rows, head: secs, counts: card.querySelector('.ucm-ifaces-card__counts').textContent.trim() };
        };
        const findCard = (t) => Array.from(document.querySelectorAll('#ifacesCards .p-card'))
            .find((c) => c.querySelector('.ucm-ifaces-card__title').textContent.trim() === t);
        const glyphMid = (el) => {
            const r = document.createRange();
            r.selectNodeContents(el);
            const rects = Array.from(r.getClientRects()).filter((x) => x.width > 0);
            if (!rects.length) return null;
            const top = Math.min(...rects.map((x) => x.top));
            const bot = Math.max(...rects.map((x) => x.bottom));
            return (top + bot) / 2;
        };
        const ffCard = findCard('firefox');
        const headerGlyph = ffCard
            ? { title: glyphMid(ffCard.querySelector('.ucm-ifaces-card__title')),
                counts: glyphMid(ffCard.querySelector('.ucm-ifaces-card__counts')) } : null;
        return {
            refreshBtn: !!document.querySelector('#ifacesRefresh'),
            headerGlyph,
            titles: Array.from(document.querySelectorAll('#ifacesCards .p-card .ucm-ifaces-card__title')).map((t) => t.textContent.trim()),
            summary: document.querySelector('#ifacesSummary').textContent.trim(),
            anySelect: document.querySelectorAll('#ifacesCards .ucm-iface-select').length,
            ff: findCard('firefox') ? readCard(findCard('firefox')) : null,
            mo: findCard('mosquitto') ? readCard(findCard('mosquitto')) : null,
            ss: findCard('snap-store') ? readCard(findCard('snap-store')) : null,
            ht: findCard('htop') ? readCard(findCard('htop')) : null,
            rd: findCard('radio') ? readCard(findCard('radio')) : null,
            uc: findCard('ucm') ? readCard(findCard('ucm')) : null,
            lx: findCard('lxd') ? readCard(findCard('lxd')) : null,
            ffDiv: (function () {
                const card = findCard('firefox');
                if (!card) return null;
                const rows = Array.from(card.querySelectorAll('tr'));
                const pos = rows.filter((r) => /ucm-iface--positive/.test(r.className));
                const cau = rows.filter((r) => /ucm-iface--caution/.test(r.className));
                const div = rows.find((r) => r.className === 'ucm-ifaces-div');
                if (!pos.length || !cau.length || !div) return null;
                return { divH: Math.round(div.getBoundingClientRect().height) };
            })(),
        };
    });
    const ifCardBtn = (title, iface) => page.evaluate(([title, iface]) => {
        const card = Array.from(document.querySelectorAll('#ifacesCards .p-card'))
            .find((c) => c.querySelector('.ucm-ifaces-card__title').textContent.trim() === title);
        const row = Array.from(card.querySelectorAll('tr.ucm-iface')).find((tr) => tr.querySelector('td').textContent.trim() === iface);
        row.querySelector('.ucm-ifaces-action .ucm-iconbtn').click();
    }, [title, iface]);
    let v = await ifRead();

    // The page-top Refresh button is gone (round 39) — the dashboard's 20 s
    // poll pattern is the idiom; the interfaces view reloads on entry.
    if (v.refreshBtn !== false) console.log('PAGE ERROR: interfaces page still has its top Refresh button');
    if (JSON.stringify(v.titles) !== JSON.stringify(['firefox', 'htop', 'lxd', 'mosquitto', 'radio', 'snap-store', 'ucm']))
        console.log('PAGE ERROR: ifaces cards not sorted per consuming snap: ' + JSON.stringify(v.titles));
    if (v.summary !== '7 snaps · 3 connected · 5 unconnected')
        console.log('PAGE ERROR: ifaces summary wrong: ' + v.summary);
    // Round 41: the target-slot pulldown no longer exists anywhere on the page.
    if (v.anySelect > 0)
        console.log('PAGE ERROR: a target-slot pulldown still exists (round 41 removed them all): ' + v.anySelect);
    // Round 40: header title (snap name) and the connected/unconnected
    // counters must sit on the same visual centre — the bundle's stacked
    // .p-heading--5 padding-top used to push the title glyphs ~2px low.
    if (!v.headerGlyph || v.headerGlyph.title == null || v.headerGlyph.counts == null)
        console.log('PAGE ERROR: ifaces header glyph boxes not measurable: ' + JSON.stringify(v.headerGlyph));
    else if (Math.abs(v.headerGlyph.title - v.headerGlyph.counts) > 1)
        console.log('PAGE ERROR: ifaces header title/counters not vertically aligned (glyph midpoints ' + v.headerGlyph.title + ' vs ' + v.headerGlyph.counts + ', delta ' + Math.abs(v.headerGlyph.title - v.headerGlyph.counts).toFixed(1) + 'px, want <=1)');
    // Round-39b: the connected/unconnected sections must be clearly
    // separated — the divider row is padded open, not a collapsed ~6px
    // sliver (which read as two bunched separators). firefox has both
    // sections in the mock; assert its divider height is comfortably > 6px.
    if (!v.ffDiv)
        console.log('PAGE ERROR: firefox divider not measurable (card must have both sections)');
    else if (v.ffDiv.divH < 16)
        console.log('PAGE ERROR: ifaces connected/unconnected sections not visually separated (divider height ' + v.ffDiv.divH + 'px, want >=16; the old sliver was 6px)');
    // Round 40: the row-action tooltip must actually be VISIBLE on hover.
    // Regression: the bundle's `td,th { overflow:hidden }` clipped the
    // p-tooltip--top-right message (positioned above the icon) 100%, so
    // tooltips never showed. Hover a connect/disconnect icon and assert the
    // message is displayed and its box is NOT fully clipped by the cell.
    const tip = await page.evaluate(() => {
        const btn = document.querySelector('#ifacesCards .ucm-ifaces-action .ucm-iconbtn');
        if (!btn) return null;
        btn.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
        btn.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
        btn.focus();
        const msg = btn.querySelector('.p-tooltip__message');
        const cs = getComputedStyle(msg);
        const m = msg.getBoundingClientRect();
        const td = btn.closest('td');
        const card = btn.closest('.p-card');
        const cr = card.getBoundingClientRect();
        // ancestors between the tooltip and the card: none may clip (the
        // card itself is a legitimate scroll container, overflow:auto).
        let n = msg.parentElement, clipper = null;
        while (n && n !== card) {
            const o = getComputedStyle(n).overflow;
            if (o === 'hidden') { clipper = n.tagName.toLowerCase() + '.' + (n.className && String(n.className).slice(0, 30)); break; }
            n = n.parentElement;
        }
        return { display: cs.display, w: Math.round(m.width), h: Math.round(m.height),
            inCard: m.top >= cr.top - 1 && m.bottom <= cr.bottom + 1,
            tdOverflow: getComputedStyle(td).overflow, clipper };
    });
    if (!tip)
        console.log('PAGE ERROR: no row-action icon button to test the tooltip');
    else if (tip.display === 'none' || tip.w <= 0 || tip.h <= 0)
        console.log('PAGE ERROR: row-action tooltip not displayed on hover: ' + JSON.stringify(tip));
    else if (tip.clipper)
        console.log('PAGE ERROR: an ancestor still clips the tooltip (overflow:hidden on ' + tip.clipper + '): ' + JSON.stringify(tip));
    else if (!tip.inCard)
        console.log('PAGE ERROR: row-action tooltip escapes the card (would be clipped by the card scroll container): ' + JSON.stringify(tip));
    // firefox: connected(network, system ":network", green, X icon) on top,
    // unconnected(browser, app pulldown in the Slot column, amber, + icon) below
    if (!v.ff || v.ff.rows.length !== 2) console.log('PAGE ERROR: firefox should have 2 rows: ' + JSON.stringify(v.ff && v.ff.rows));
    else {
        if (!v.ff.head || v.ff.head[0] !== 'Interface' || v.ff.head[1] !== 'Plug' || v.ff.head[2] !== 'Slot' || v.ff.head[3] !== 'Actions')
            console.log('PAGE ERROR: firefox table headers wrong: ' + JSON.stringify(v.ff.head));
        const a = v.ff.rows[0], b = v.ff.rows[1];
        if (a.iface !== 'network' || a.plug !== 'firefox:network' || a.slot !== ':network' || !/positive/.test(a.tone))
            console.log('PAGE ERROR: firefox network row wrong (system slot must be ":network", green): ' + JSON.stringify(a));
        else if (a.hasBtn !== true || a.btnIconClass !== 'p-icon--window-close' || a.hasSelect !== false)
            console.log('PAGE ERROR: firefox network connected row must be an icon-only Disconnect (X, no pulldown): ' + JSON.stringify(a));
        // firefox:browser — the lxd case: the browser interface has a slot
        // (snap-store:browser) but it is NOT the same name, so it is not a
        // usable target: no pulldown, Slot shows "—", Connect is DISABLED.
        if (b.iface !== 'browser' || b.plug !== 'firefox:browser' || b.slot !== '—' || !/caution/.test(b.tone))
            console.log('PAGE ERROR: firefox browser row wrong (no same-named target -> "—", amber, no pulldown): ' + JSON.stringify(b));
        else if (b.hasSelect !== false)
            console.log('PAGE ERROR: firefox browser row must NOT show a pulldown (no usable target): ' + JSON.stringify(b));
        else if (b.hasBtn !== true || b.btnIconClass !== 'p-icon--add' || b.btnDisabled !== true)
            console.log('PAGE ERROR: firefox browser row Connect must be present but DISABLED (no usable target): ' + JSON.stringify(b));
        else if (b.tipMsg !== b.btnAria)
            console.log('PAGE ERROR: firefox browser tooltip must mirror the aria-label: ' + JSON.stringify({ tip: b.tipMsg, aria: b.btnAria }));
        // suru-file pattern: the glyph must be the shipped SVG, not a data-URI
        if (b.btnIconBg.indexOf('suru-add.svg') === -1)
            console.log('PAGE ERROR: firefox Connect glyph is not the suru-add file (got ' + b.btnIconBg + ')');
        if ((a.btnIconBg || '').indexOf('suru-close.svg') === -1)
            console.log('PAGE ERROR: firefox Disconnect glyph is not the suru-close file (got ' + a.btnIconBg + ')');
    }
    // mosquitto: single connected system row ":network-bind" + X icon
    if (!v.mo || v.mo.rows.length !== 1 || v.mo.rows[0].iface !== 'network-bind' || v.mo.rows[0].slot !== ':network-bind' || !/positive/.test(v.mo.rows[0].tone))
        console.log('PAGE ERROR: mosquitto row wrong: ' + JSON.stringify(v.mo && v.mo.rows));
    else if (v.mo.rows[0].hasBtn !== true || v.mo.rows[0].btnIconClass !== 'p-icon--window-close')
        console.log('PAGE ERROR: mosquitto connected row must be an icon-only Disconnect (X): ' + JSON.stringify(v.mo.rows[0]));
    // htop: single unconnected SYSTEM-slot row: Slot stays "—" (pre-fill is
    // inside the bare Connect, like the CLI), enabled + icon
    if (!v.ht || v.ht.rows.length !== 1 || v.ht.rows[0].iface !== 'home' || v.ht.rows[0].slot !== '—' || !/caution/.test(v.ht.rows[0].tone))
        console.log('PAGE ERROR: htop row wrong (unconnected "—", amber): ' + JSON.stringify(v.ht && v.ht.rows));
    else if (v.ht.rows[0].hasSelect !== false || v.ht.rows[0].hasBtn !== true || v.ht.rows[0].btnIconClass !== 'p-icon--add' || v.ht.rows[0].btnDisabled !== false)
        console.log('PAGE ERROR: htop unconnected system row must be a BARE enabled + connect (no dropdown, slot stays "—"): ' + JSON.stringify(v.ht.rows[0]));
    // ucm: the user's real case — icon-themes plug, 3 same-interface content
    // slots but only ONE same-named -> Slot column shows that target as plain
    // text, NO pulldown, enabled + icon.
    if (!v.uc || v.uc.rows.length !== 1) console.log('PAGE ERROR: ucm card should have 1 row: ' + JSON.stringify(v.uc && v.uc.rows));
    else {
        const ur = v.uc.rows[0];
        if (ur.iface !== 'icon-themes' || ur.plug !== 'ucm:icon-themes' || !/caution/.test(ur.tone))
            console.log('PAGE ERROR: ucm icon-themes row wrong: ' + JSON.stringify(ur));
        else if (ur.slot !== 'gtk-common-themes:icon-themes')
            console.log('PAGE ERROR: ucm same-named target must be shown in the Slot column (got "' + ur.slot + '")');
        else if (ur.hasSelect !== false)
            console.log('PAGE ERROR: ucm same-named target must NOT show a pulldown: ' + JSON.stringify(ur));
        else if (ur.hasBtn !== true || ur.btnIconClass !== 'p-icon--add' || ur.btnDisabled !== false)
            console.log('PAGE ERROR: ucm same-named row must be an enabled icon-only Connect (+): ' + JSON.stringify(ur));
    }
    // lxd: connected content row; the tooltip/aria-label must generalize on the
    // PLUG name (ceph-conf), not the interface name (content) — the user's ask.
    if (!v.lx || v.lx.rows.length !== 1 || v.lx.rows[0].iface !== 'content' || v.lx.rows[0].plug !== 'lxd:ceph-conf'
        || v.lx.rows[0].slot !== 'data-provider:ceph-conf' || !/positive/.test(v.lx.rows[0].tone))
        console.log('PAGE ERROR: lxd ceph-conf row wrong: ' + JSON.stringify(v.lx && v.lx.rows));
    else if (v.lx.rows[0].hasBtn !== true || v.lx.rows[0].btnIconClass !== 'p-icon--window-close')
        console.log('PAGE ERROR: lxd connected row must be an icon-only Disconnect (X): ' + JSON.stringify(v.lx.rows[0]));
    else if (v.lx.rows[0].btnAria !== 'Disconnect ceph-conf on lxd')
        console.log('PAGE ERROR: lxd Disconnect tooltip must use the PLUG name (got "' + v.lx.rows[0].btnAria + '", want "Disconnect ceph-conf on lxd" — not the interface name "content")');
    // NO-TARGET case: radio:pps has no connectable slot -> Slot "—", NO empty
    // pulldown, and a visually + functionally disabled + icon.
    if (!v.rd || v.rd.rows.length !== 1) console.log('PAGE ERROR: radio card should have 1 row: ' + JSON.stringify(v.rd && v.rd.rows));
    else {
        const rr = v.rd.rows[0];
        if (rr.iface !== 'pps' || rr.slot !== '—' || !/caution/.test(rr.tone))
            console.log('PAGE ERROR: radio pps row wrong (unconnected "—", amber): ' + JSON.stringify(rr));
        if (rr.hasSelect !== false) console.log('PAGE ERROR: radio pps must NOT show an empty pulldown (no targets): ' + JSON.stringify(rr));
        if (rr.hasBtn !== true || rr.btnDisabled !== true || rr.btnIconClass !== 'p-icon--add')
            console.log('PAGE ERROR: radio pps Connect must be present but disabled (+ icon): ' + JSON.stringify(rr));
        else if (rr.btnAria !== 'Connect pps on radio — no target slots available')
            console.log('PAGE ERROR: radio disabled Connect tooltip wording wrong (got "' + rr.btnAria + '"): ' + JSON.stringify(rr));
    }
    // element shot of the firefox card (VLM layout check)
    const ffCardEl = await page.$('#ifacesCards .p-card');
    if (ffCardEl) await ffCardEl.screenshot({ path: '/root/shots/14b-iface-card-firefox.png', scale: 2 });

    // (a) BARE connect on a system slot (snap-store:home -> :home), no dropdown
    await ifCardBtn('snap-store', 'home');
    await wait(1200);
    v = await ifRead();
    if (!v.ss || v.ss.rows.length !== 1 || v.ss.rows[0].iface !== 'home' || v.ss.rows[0].slot !== ':home' || !/positive/.test(v.ss.rows[0].tone))
        console.log('PAGE ERROR: bare system connect did not move snap-store:home to connected (":home"): ' + JSON.stringify(v.ss && v.ss.rows));
    else if (v.ss.counts !== '1 connected · 0 unconnected') console.log('PAGE ERROR: snap-store counts after bare connect wrong: ' + v.ss.counts);
    // restore state for the next drive: disconnect it again
    await ifCardBtn('snap-store', 'home');
    await wait(1200);
    v = await ifRead();
    if (!v.ss || v.ss.rows.length !== 1 || v.ss.rows[0].slot !== '—' || !/caution/.test(v.ss.rows[0].tone))
        console.log('PAGE ERROR: disconnect did not restore snap-store:home to unconnected ("—"): ' + JSON.stringify(v.ss && v.ss.rows));

    // (b) SINGLE-TARGET connect via the same-named slot (ucm:icon-themes ->
    // gtk-common-themes:icon-themes), no dropdown involved
    await ifCardBtn('ucm', 'icon-themes');
    await wait(1200);
    v = await ifRead();
    if (!v.uc || v.uc.rows.length !== 1 || v.uc.rows[0].slot !== 'gtk-common-themes:icon-themes' || !/positive/.test(v.uc.rows[0].tone))
        console.log('PAGE ERROR: same-named connect did not move ucm:icon-themes to connected: ' + JSON.stringify(v.uc && v.uc.rows));
    else if (v.uc.rows[0].hasBtn !== true || v.uc.rows[0].btnIconClass !== 'p-icon--window-close')
        console.log('PAGE ERROR: ucm connected row must now be an icon-only Disconnect (X): ' + JSON.stringify(v.uc.rows[0]));
    // restore: disconnect it again -> back to the same-named plain-text target
    await ifCardBtn('ucm', 'icon-themes');
    await wait(1200);
    v = await ifRead();
    if (!v.uc || v.uc.rows.length !== 1 || v.uc.rows[0].slot !== 'gtk-common-themes:icon-themes' || !/caution/.test(v.uc.rows[0].tone) || v.uc.rows[0].hasSelect !== false)
        console.log('PAGE ERROR: disconnect did not restore ucm:icon-themes to its same-named plain-text target: ' + JSON.stringify(v.uc && v.uc.rows));

    // Round 41: there is no dropdown connect to drive anymore — a plug with no
    // unique same-named target is simply not connectable from the UI.
    await page.screenshot({ path: path.join(SHOTS, '15-interfaces-after-connect.png'), fullPage: true });

    // ---- 6. lock -> local sign-in view ----
    await page.click('#lockBtn');
    await wait(700);
    await page.screenshot({ path: path.join(SHOTS, '16-login-local.png') });

    // wrong password -> validation error
    await page.type('#loginPassword', 'wrong');
    await page.click('#loginBtn');
    await wait(400);
    await page.screenshot({ path: path.join(SHOTS, '17-login-error.png') });

    console.log('screenshots written to ' + SHOTS);
    if (errors.length) {
        console.log('PAGE ERRORS:');
        errors.slice(0, 20).forEach((e) => console.log('  ' + e));
    } else {
        console.log('no page errors');
    }
    await browser.close();
    process.exit(errors.length ? 1 : 0);
})().catch((e) => { console.error('FATAL', e); process.exit(2); });
