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
    { name: 'old-tool', version: '0.9', revision: 12, channel: 'candidate', 'tracking-channel': 'latest/candidate', status: 'disabled', type: 'app', confinement: 'devmode' },
];

// Per-snap configuration documents (snapd /v2/snaps/{name}/conf).
const SNAP_CONF = {
    htop: { port: '8080', 'logging.level': 'info' },
};

const CONNECTIONS = {
    established: [
        { interface: 'network', plug: { snap: 'firefox', plug: 'network' }, slot: { snap: 'core24', slot: 'network' }, manual: true, gadget: false },
        { interface: 'network-bind', plug: { snap: 'mosquitto', plug: 'network-bind' }, slot: { snap: 'core24', slot: 'network-bind' }, manual: false, gadget: false },
        { interface: 'browser', plug: { snap: 'firefox', plug: 'browser' }, slot: { snap: 'snap-store', slot: 'browser' }, manual: false, gadget: false },
    ],
    undesired: [
        { interface: 'home', plug: { snap: 'snap-store', plug: 'home' }, slot: { snap: 'core24', slot: 'home' }, manual: true, gadget: false },
    ],
    plugs: [
        { snap: 'firefox', name: 'network', interface: 'network', connections: [{ snap: 'core24', slot: 'network' }] },
        { snap: 'mosquitto', name: 'network-bind', interface: 'network-bind', connections: [{ snap: 'core24', slot: 'network-bind' }] },
        { snap: 'snap-store', name: 'home', interface: 'home', connections: [] },
        { snap: 'firefox', name: 'browser', interface: 'browser', connections: [{ snap: 'snap-store', slot: 'browser' }] },
        { snap: 'htop', name: 'home', interface: 'home', connections: [] },
    ],
    slots: [
        { snap: 'core24', name: 'network', interface: 'network', connections: [{ snap: 'firefox', plug: 'network' }] },
        { snap: 'core24', name: 'network-bind', interface: 'network-bind', connections: [{ snap: 'mosquitto', plug: 'network-bind' }] },
        { snap: 'snap-store', name: 'browser', interface: 'browser', connections: [{ snap: 'firefox', plug: 'browser' }] },
        { snap: 'core24', name: 'home', interface: 'home', connections: [] },
        { snap: 'core24', name: 'removable-media', interface: 'removable-media', connections: [] },
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
        const CONNECTIONS = ${JSON.stringify(CONNECTIONS)};
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
                        warnings: [{ warn: 'refresh candidates available for 2 snaps', last: '2026-10-28T00:00:00Z' }],
                    };
                },
                // (system.disk bridge removed — the old /v2/system-info/storage
                //  endpoint does not exist on live snapd; storage comes from
                //  statfs via system.dataDisk now)
                // net traffic mock: one {r,x} pair per call (main samples on
                // its own 2 s clock); idle 0 until call 4, then a sine wave
                // so both sparklines draw a recognizable shape in the shot.
                async net() {
                    netCalls++;
                    const n = Math.min(100, netCalls);
                    return Array.from({ length: n }, (_, i) => i < 4
                        ? (i === 0 ? { r: null, x: null } : { r: 0, x: 0 })
                        : { r: Math.round((60 + 40 * Math.sin((i - 3) / 2)) * 10) / 10,
                           x: Math.round((12 + 8 * Math.cos((i - 3) / 2)) * 10) / 10 });
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
                    const id = '18';
                    CHANGES[id] = { id, status: 'Doing', kind: a + '-snap', t0: Date.now() };
                    setTimeout(() => {
                        if (a === 'remove') SNAPS = SNAPS.filter((x) => x.name !== n);
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
                async list() { return CONNECTIONS; },
                async connect() { return { status: 'Done' }; },
                async disconnect() { return { status: 'Done' }; },
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
        return {
            rows: trs.map((tr) => Array.from(tr.querySelectorAll('td')).map((td) => td.textContent.trim())),
            refreshBtn: !!document.querySelector('#dashChangesRefresh'),
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
        // spawned column: 24h clock (no AM/PM, zero-padded hh:mm) — fmtDate is
        // locale-dependent, so assert the 24h MARKERS, not the exact string.
        const spawned = rows[0] ? rows[0][2] : '';
        if (!spawned || spawned === '—') console.log('PAGE ERROR: spawned column empty (' + spawned + ')');
        if (/\bAM\b|\bPM\b/i.test(spawned)) console.log('PAGE ERROR: spawned date uses 12h clock (' + spawned + ')');
        if (!/\d{2}:\d{2}/.test(spawned)) console.log('PAGE ERROR: spawned date not 24h-formatted (' + spawned + ')');
        if (rows[0] && rows[0][3] !== 'Connect firefox:network to core24:network')
            console.log('PAGE ERROR: summary column wrong (' + (rows[0] && rows[0][3]) + ')');
        // manual Refresh button removed — the 20 s auto-refresh supersedes it
        if (changes.refreshBtn !== false) console.log('PAGE ERROR: changes Refresh button still present');
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
        if (!/^last refresh \d{2}\.\d{2}\.\d{4} \d{2}:\d{2}$/.test(cards.uptimeLast || ''))
            console.log('PAGE ERROR: uptime last-refresh line wrong (' + cards.uptimeLast + ')');
        if (!/^next refresh \d{2}\.\d{2}\.\d{4} \d{2}:\d{2}$/.test(cards.uptimeNext || ''))
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
        if (dd.res !== '410 MiB') console.log('PAGE ERROR: data disk reserved (' + dd.res + ')');
        if (!dd.src.includes('/run/mnt/data')) console.log('PAGE ERROR: data disk source label (' + dd.src + ')');
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
    if (ng.src !== 'eth0 + enp3s0') console.log('PAGE ERROR: net iface label wrong (' + ng.src + ')');
    if (ng.downStroke !== 'rgb(233, 84, 32)') console.log('PAGE ERROR: net down line not orange (' + ng.downStroke + ')');
    if (ng.upStroke !== 'rgb(119, 119, 119)') console.log('PAGE ERROR: net up line not grey (' + ng.upStroke + ')');
    await page.screenshot({ path: path.join(SHOTS, '3e-net-graphs.png') });

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
        const btn = Array.from(htop.querySelectorAll('button')).find((b) => b.textContent.trim().startsWith('Config'));
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
        const btn = Array.from(htop.querySelectorAll('button')).find((b) => b.textContent.trim().startsWith('Remove'));
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
    // table used to stretch every nowrap column, making them "way too wide").
    const cw = await page.evaluate(() => {
        const tbl = document.querySelector('.ucm-snaps-table table');
        if (!tbl) return { error: 'no snaps table' };
        const heads = Array.from(tbl.querySelectorAll('thead th')).map((th) => th.textContent.trim());
        const wi = (label) => heads.indexOf(label);
        const w = (i) => (i >= 0 ? Math.round(tbl.querySelectorAll('thead th')[i].getBoundingClientRect().width) : -1);
        return { status: w(wi('Status')), type: w(wi('Type')) };
    });
    if (cw.error) console.log('PAGE ERROR: ' + cw.error);
    else if (cw.status > 140 || cw.type > 140)
        console.log(`PAGE ERROR: snaps table Status/Type too wide (status=${cw.status}px type=${cw.type}px, want <=140px)`);

    // defensive: no modal may still be covering the UI (a stuck modal would
    // mask later clicks and mask real layout in the shots)
    const stray = await page.evaluate(() => document.querySelectorAll('.ucm-modal').length);
    if (stray) console.log('PAGE ERROR: stray modal left open before interfaces view');

    // ---- 5. interfaces view ----
    await page.click('.ucm-side a[data-view="interfaces"]');
    await wait(700);
    await page.screenshot({ path: path.join(SHOTS, '14-interfaces.png'), fullPage: true });
    await page.click('#ifacesFilterBtn');
    await wait(300);
    await page.screenshot({ path: path.join(SHOTS, '15-interfaces-all.png'), fullPage: true });

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
