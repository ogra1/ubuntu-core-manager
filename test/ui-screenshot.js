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
    { name: 'core24', version: '24.04.3', revision: 4110, channel: 'stable', 'tracking-channel': '24.04/stable', status: 'active', type: 'core', confinement: 'strict' },
    { name: 'snapd', version: '2.68.4', revision: 23448, channel: 'stable', 'tracking-channel': 'latest/stable', status: 'active', type: 'snapd', confinement: 'strict' },
    { name: 'kernel-noble', version: '6.8.0-40', revision: 1189, channel: 'stable', 'tracking-channel': 'noble/stable', status: 'active', type: 'kernel', confinement: 'strict' },
    { name: 'gadget', version: '1.2', revision: 77, channel: 'local', status: 'active', type: 'gadget', confinement: 'jailmode' },
    { name: 'htop', version: '3.3.0', revision: 5533, channel: 'stable', 'tracking-channel': 'latest/stable', status: 'active', type: 'app', confinement: 'strict' },
    { name: 'mosquitto', version: '2.0.19', revision: 14077, channel: 'stable', 'tracking-channel': 'latest/stable', status: 'active', type: 'app', confinement: 'strict' },
    { name: 'firefox', version: '141.0.2', revision: 543210, channel: 'stable', 'tracking-channel': 'latest/stable', status: 'active', type: 'app', confinement: 'strict' },
    { name: 'old-tool', version: '0.9', revision: 12, channel: 'candidate', 'tracking-channel': 'latest/candidate', status: 'installed', type: 'app', confinement: 'devmode' },
];

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
    ],
    slots: [
        { snap: 'core', slot: 'network', interface: 'network', connections: [{ snap: 'firefox', plug: 'network' }] },
        { snap: 'core', slot: 'network-bind', interface: 'network-bind', connections: [{ snap: 'mosquitto', plug: 'network-bind' }] },
        { snap: 'core', slot: 'home', interface: 'home', connections: null },
        { snap: 'snap-store', slot: 'browser-remote', interface: 'browser', connections: null },
        { snap: 'snap-store', slot: 'browser-view', interface: 'browser', connections: null },
        // content interfaces: gtk-common-themes and ubuntu-frame both expose
        // icon-themes — but only the same-NAMED slot qualifies for the ucm
        // icon-themes plug (namespacing), so no pulldown is needed. The
        // gtk-2-themes / ubuntu-frame-diagnostic slots are decoys with other names.
        { snap: 'gtk-common-themes', slot: 'gtk-2-themes', interface: 'icon-themes', connections: null },
        { snap: 'gtk-common-themes', slot: 'icon-themes', interface: 'icon-themes', connections: null },
        { snap: 'ubuntu-frame', slot: 'ubuntu-frame-diagnostic', interface: 'icon-themes', connections: null },
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
                async info(n) { return SNAPS.find((s) => s.name === n); },
                // Store search/install: unauthenticated by design (model
                // attachment at image build time) — no store login needed.
                async search(q) {
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
                async action(n, a) {
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
                        else if (cur) { cur.prevRev = cur.revision; cur.revision = String(Number(cur.revision) + 1); cur.status = 'active'; }
                        CHANGES[id] = { id, status: 'Done' };
                    }, 1200); // slow settle: keeps the confirm card visible for the shot
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

    // ---- 4b. per-snap config modal (htop) ----
    await page.evaluate(() => {
        const rows = Array.from(document.querySelectorAll('#snapsBody tr'));
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

    // ---- 4c. installed-snaps table + remove-confirm card (alignment) ----
    // htop is a non-system snap -> shows Config/Refresh/Remove row actions.
    await page.evaluate(() => {
        const rows = Array.from(document.querySelectorAll('#snapsBody tr'));
        const htop = rows.find((r) => r.textContent.includes('htop'));
        if (!htop) throw new Error('htop row missing');
        const btn = htop.querySelector('.ucm-iconbtn[aria-label^="Remove"]'); // icon-only: no text to match
        if (!btn) throw new Error('Remove button missing');
        btn.click();
    });
    await wait(800); // still inside the 1.2s settle window -> card is up
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

    // Regression guard: Status/Type columns must hug their content (the 100%-wide
    // table used to stretch every nowrap column, making them "way too wide"), AND
    // the table must fill its scroll parent (round-35: the old max-content table
    // left a big right-side gap between the Actions column and the scrollbar).
    const cw = await page.evaluate(() => {
        const tbl = document.querySelector('.ucm-snaps-table table');
        const wrap = document.querySelector('.ucm-snaps-table');
        if (!tbl) return { error: 'no snaps table' };
        const heads = Array.from(tbl.querySelectorAll('thead th')).map((th) => th.textContent.trim());
        const wi = (label) => heads.indexOf(label);
        const w = (i) => (i >= 0 ? Math.round(tbl.querySelectorAll('thead th')[i].getBoundingClientRect().width) : -1);
        const tr = tbl.getBoundingClientRect();
        const wr = wrap.getBoundingClientRect();
        return { status: w(wi('Status')), type: w(wi('Type')), gap: Math.round(wr.right - tr.right) };
    });
    if (cw.error) console.log('PAGE ERROR: ' + cw.error);
    else if (cw.status > 140 || cw.type > 140)
        console.log(`PAGE ERROR: snaps table Status/Type too wide (status=${cw.status}px type=${cw.type}px, want <=140px)`);
    else if (cw.gap > 4)
        console.log(`PAGE ERROR: snaps table does not fill its scroll parent (right gap=${cw.gap}px, want <=4px)`);

    // ---- 4d. Round 34: icon-only actions column (suru glyphs + Vanilla
    // tooltips) ---- every action is a textless icon button (label lives in
    // data-tooltip / aria-label; the CSS-only .p-tooltip__message child is
    // display:none until hover/focus). Active snap htop -> 5 icons in order
    // gear/refresh/revert/power-black/trash; disabled snap old-tool (live
    // status "installed") -> red power + "Enable" + red disabled badge.
    const col = await page.evaluate(() => {
        const rows = Array.from(document.querySelectorAll('#snapsBody tr'));
        const getRow = (n) => rows.find((r) => r.cells && r.cells[0] && r.cells[0].textContent.trim() === n);
        const h = getRow('htop'); const o = getRow('old-tool');
        if (!h || !o) return { error: 'htop/old-tool row missing' };
        const hbtns = Array.from(h.querySelectorAll('.ucm-iconbtn'));
        const obtns = Array.from(o.querySelectorAll('.ucm-iconbtn'));
        const strip = (b) => { const c = b.cloneNode(true); const m = c.querySelector('.p-tooltip__message'); if (m) m.remove(); return c.textContent.trim(); };
        const bg = (b, cls) => { const i = b && b.querySelector('i.' + cls); return i ? getComputedStyle(i).backgroundImage : null; };
        const hPow = hbtns.find((b) => b.querySelector('i.p-icon--power'));
        const oPow = obtns.find((b) => b.querySelector('i.p-icon--power'));
        const oEn = obtns.find((b) => (b.getAttribute('aria-label') || '').startsWith('Enable'));
        return {
            hCount: hbtns.length, oCount: obtns.length,
            hTextless: hbtns.length > 0 && hbtns.every((b) => strip(b) === ''),
            hTooltips: hbtns.map((b) => (b.getAttribute('data-tooltip') || '').length > 0),
            hAria: hbtns.map((b) => (b.getAttribute('aria-label') || '').length > 0),
            hIcons: hbtns.map((b) => { const i = b.querySelector('i'); return i ? i.className : ''; }),
            hPowerImg: bg(hPow, 'p-icon--power'),
            oPowerImg: bg(oPow, 'p-icon--power'),
            oEnableLabel: oEn ? oEn.getAttribute('aria-label') : null,
            oBadge: (o.querySelector('td:nth-child(2) .p-status-label') || {}).textContent || null,
            msgDisplay: hbtns[0] ? getComputedStyle(hbtns[0].querySelector('.p-tooltip__message')).display : null,
            btnPadL: hbtns[0] ? getComputedStyle(hbtns[0]).paddingLeft : null,
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
        if (!(col.oPowerImg || '').includes('suru-power-red.svg')) console.log('PAGE ERROR: disabled power icon is not the red suru-power-red.svg (' + col.oPowerImg + ')');
        if (!(col.oEnableLabel || '').startsWith('Enable')) console.log('PAGE ERROR: disabled snap action is not Enable (' + col.oEnableLabel + ')');
        if (col.oBadge !== 'disabled') console.log('PAGE ERROR: disabled snap badge is not red disabled (' + col.oBadge + ')');
        if (col.msgDisplay !== 'none') console.log('PAGE ERROR: tooltip message visible before hover (display=' + col.msgDisplay + ')');
        if (col.btnPadL !== '0px') console.log('PAGE ERROR: icon button horizontal padding not zeroed (' + col.btnPadL + ')');
    }
    await page.screenshot({ path: path.join(SHOTS, '13b-snaps-actions.png'), fullPage: true });
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
    // render "snap:name" and keep a target-slot dropdown.
    // Round 39: icon-only Connect/Disconnect (suru add/close, the snaps-table
    // rowBtn idiom) + the target-slot pulldown lives in the SLOT column
    // ("—" when no target; a single same-named target renders as plain text).
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
        return {
            refreshBtn: !!document.querySelector('#ifacesRefresh'),
            titles: Array.from(document.querySelectorAll('#ifacesCards .p-card .ucm-ifaces-card__title')).map((t) => t.textContent.trim()),
            summary: document.querySelector('#ifacesSummary').textContent.trim(),
            ff: findCard('firefox') ? readCard(findCard('firefox')) : null,
            mo: findCard('mosquitto') ? readCard(findCard('mosquitto')) : null,
            ss: findCard('snap-store') ? readCard(findCard('snap-store')) : null,
            ht: findCard('htop') ? readCard(findCard('htop')) : null,
            rd: findCard('radio') ? readCard(findCard('radio')) : null,
            uc: findCard('ucm') ? readCard(findCard('ucm')) : null,
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
    const ifSelectThenConnect = (title, iface, value) => page.evaluate(([title, iface, value]) => {
        const card = Array.from(document.querySelectorAll('#ifacesCards .p-card'))
            .find((c) => c.querySelector('.ucm-ifaces-card__title').textContent.trim() === title);
        const row = Array.from(card.querySelectorAll('tr.ucm-iface')).find((tr) => tr.querySelector('td').textContent.trim() === iface);
        const sel = row.querySelector('.ucm-iface-select');
        sel.value = value;
        row.querySelector('.ucm-ifaces-action .ucm-iconbtn').click();
    }, [title, iface, value]);

    let v = await ifRead();
    // The page-top Refresh button is gone (round 39) — the dashboard's 20 s
    // poll pattern is the idiom; the interfaces view reloads on entry.
    if (v.refreshBtn !== false) console.log('PAGE ERROR: interfaces page still has its top Refresh button');
    if (JSON.stringify(v.titles) !== JSON.stringify(['firefox', 'htop', 'mosquitto', 'radio', 'snap-store', 'ucm']))
        console.log('PAGE ERROR: ifaces cards not sorted per consuming snap: ' + JSON.stringify(v.titles));
    if (v.summary !== '6 snaps · 2 connected · 5 unconnected')
        console.log('PAGE ERROR: ifaces summary wrong: ' + v.summary);
    // Round-39b: the connected/unconnected sections must be clearly
    // separated — the divider row is padded open, not a collapsed ~6px
    // sliver (which read as two bunched separators). firefox has both
    // sections in the mock; assert its divider height is comfortably > 6px.
    if (!v.ffDiv)
        console.log('PAGE ERROR: firefox divider not measurable (card must have both sections)');
    else if (v.ffDiv.divH < 16)
        console.log('PAGE ERROR: ifaces connected/unconnected sections not visually separated (divider height ' + v.ffDiv.divH + 'px, want >=16; the old sliver was 6px)');
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
        if (b.iface !== 'browser' || b.plug !== 'firefox:browser' || b.slot !== 'target slot…' || !/caution/.test(b.tone))
            console.log('PAGE ERROR: firefox browser row wrong (unconnected -> pulldown in Slot column, amber): ' + JSON.stringify(b));
        else if (b.hasSelect !== true || JSON.stringify(b.selOpts) !== JSON.stringify(['', 'snap-store|browser-remote', 'snap-store|browser-view']))
            console.log('PAGE ERROR: firefox browser row dropdown options wrong: ' + JSON.stringify(b.selOpts));
        else if (b.hasBtn !== true || b.btnIconClass !== 'p-icon--add' || b.btnDisabled !== false)
            console.log('PAGE ERROR: firefox browser row must be an enabled icon-only Connect (+): ' + JSON.stringify(b));
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

    // (c) DROPDOWN connect on an app slot (firefox:browser -> snap-store:browser-view)
    await ifSelectThenConnect('firefox', 'browser', 'snap-store|browser-view');
    await wait(1200);
    v = await ifRead();
    if (!v.ff || v.ff.rows.length !== 2 || v.ff.rows[0].slot !== ':network' || v.ff.rows[1].slot !== 'snap-store:browser-view' || !/positive/.test(v.ff.rows[1].tone))
        console.log('PAGE ERROR: dropdown connect did not move firefox:browser to connected: ' + JSON.stringify(v.ff && v.ff.rows));
    else if (v.ff.counts !== '2 connected · 0 unconnected') console.log('PAGE ERROR: firefox counts after dropdown connect wrong: ' + v.ff.counts);
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
