'use strict';

/**
 * test/ui-screenshot.js — headless-loads ui/index.html with a mocked
 * `window.ucmCore` bridge (same shape as preload.js) and captures one
 * screenshot per view/state for visual QA.
 *
 * Mocked auth model:
 *   - local gate: initialized=false initially; create(password) requires
 *     'correct-horse'; login(password) requires 'correct-horse'.
 *   - store:      store.login succeeds only when window.__storeOnline is
 *     true (simulates store-backend reachability) — used to show the
 *     graceful offline error.
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
    { name: 'core24', version: '24.04.3', revision: 4110, channel: '24.04', status: 'active', type: 'core', confinement: 'strict' },
    { name: 'snapd', version: '2.68.4', revision: 23448, channel: 'stable', status: 'active', type: 'snapd', confinement: 'strict' },
    { name: 'kernel-noble', version: '6.8.0-40', revision: 1189, channel: 'noble', status: 'active', type: 'kernel', confinement: 'strict' },
    { name: 'gadget', version: '1.2', revision: 77, channel: 'local', status: 'active', type: 'gadget', confinement: 'jailmode' },
    { name: 'htop', version: '3.3.0', revision: 5533, channel: 'latest/stable', status: 'active', type: 'app', confinement: 'strict' },
    { name: 'mosquitto', version: '2.0.19', revision: 14077, channel: 'latest/stable', status: 'active', type: 'app', confinement: 'strict' },
    { name: 'firefox', version: '141.0.2', revision: 543210, channel: 'latest/stable', status: 'active', type: 'app', confinement: 'strict' },
    { name: 'old-tool', version: '0.9', revision: 12, channel: 'candidate', status: 'disabled', type: 'app', confinement: 'devmode' },
];

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
        const SNAPS = ${JSON.stringify(SNAPS)};
        const CONNECTIONS = ${JSON.stringify(CONNECTIONS)};
        const NETPLAN = ${JSON.stringify(NETPLAN)};
        window.__storeOnline = false; // flip per-scenario from the test
        let localSet = false;
        let localAuthed = false;
        let storeAuthed = false;
        const status = () => ({
            initialized: localSet,
            authenticated: localAuthed,
            expiresAt: localAuthed ? Date.now() + 900000 : null,
            timeoutMs: 900000,
            storeAuthenticated: storeAuthed,
            storeUsername: storeAuthed ? 'admin@example.com' : null,
        });
        return {
            auth: {
                async create(pw) {
                    if (localSet) throw new Error('a local administrator password already exists — sign in instead');
                    if (pw !== 'correct-horse') throw new Error('simulated: weak password');
                    localSet = true; localAuthed = true;
                    return status();
                },
                async login(pw) {
                    if (!localSet) throw new Error('no local administrator password is set — create one first');
                    if (pw !== 'correct-horse') throw new Error('incorrect password');
                    localAuthed = true;
                    return status();
                },
                async logout() { localAuthed = false; return status(); },
                async status() { return status(); },
                onStatusChanged() { return () => {}; },
            },
            store: {
                async login(email, pw) {
                    if (!window.__storeOnline)
                        throw new Error('cannot reach the store backend: network unreachable');
                    if (!/admin@example\\.com$/.test(email) || pw !== 'store-pass')
                        throw new Error('cannot authenticate the user: invalid credentials');
                    storeAuthed = true;
                    return status();
                },
                async logout() { storeAuthed = false; return status(); },
            },
            system: {
                async info() {
                    return {
                        snapd: {
                            version: '2.68.4', series: '16', brand: 'canonical', model: 'core-24-kvm',
                            kernel_version: '6.8.0-40-generic', on_architecture: 'amd64', serial: '0001',
                            storage: { total: 4194304000000, used: 1288490188000, used_percent: 31, model: 'VIRTIO BLK', type: 'ssd' },
                            cloud_init: { status: 'done' },
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
                async disk() { return { total: 4194304000000, used: 1288490188000, used_percent: 31 }; },
                async changes() {
                    return [
                        { id: '14', kind: 'install-snap', summary: { message: 'Install snap "mosquitto"' }, status: 'Done', spawn_time: '2026-10-28T08:12:00Z' },
                        { id: '15', kind: 'configure-snap', summary: { message: 'Configure snap "core24"' }, status: 'Ready', spawn_time: '2026-10-28T09:00:00Z' },
                        { id: '16', kind: 'connect-plug', summary: { message: 'Connect firefox:network to core24:network' }, status: 'Done', spawn_time: '2026-10-28T09:30:00Z' },
                    ];
                },
                async netplan() { return NETPLAN; },
            },
            snaps: {
                async list() { return SNAPS; },
                async info(n) { return SNAPS.find((s) => s.name === n); },
                async search(q) {
                    if (!window.__storeOnline) throw new Error('cannot reach the store backend: network unreachable');
                    return [
                        { name: 'mosquitto', summary: 'MQTT broker for IoT messaging', publisher: { username: 'mosquitto-dev' }, channels: { 'latest/stable': {} } },
                        { name: 'mqtt-spy', summary: 'Simple MQTT traffic inspector', publisher: { username: 'iot-labs' }, channels: { 'latest/stable': {} } },
                    ].filter((s) => s.name.includes((q || '').toLowerCase()));
                },
                async install(n, ch) {
                    if (!window.__storeOnline) throw new Error('cannot reach the store backend: network unreachable');
                    return { id: '17' };
                },
                async action(n, a) {
                    if (a === 'remove' && n === 'core24') throw new Error('cannot remove snap "core24": system snap');
                    return { id: '18' };
                },
                async confGet() { return {}; },
                async confSet() { return { id: '19' }; },
            },
            network: { async apply() { return { id: '20' }; } },
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

    // fix + create -> console
    await page.click('#setupConfirm', { clickCount: 3 });
    await page.type('#setupConfirm', 'correct-horse');
    await page.click('#setupBtn');
    await wait(900);
    await page.screenshot({ path: path.join(SHOTS, '3-dashboard-store-offline.png'), fullPage: true });

    // ---- 2. STORE OFFLINE: modal + graceful failure ----
    await page.click('#storeBtn');
    await wait(400);
    await page.type('#storeEmail', 'admin@example.com');
    await page.type('#storePassword', 'store-pass');
    await page.click('#storeConnectBtn');
    await wait(500);
    await page.screenshot({ path: path.join(SHOTS, '4-store-offline-error.png') });
    await page.click('#storeModalClose');
    await wait(200);

    // ---- 3. STORE ONLINE: connect succeeds ----
    await page.evaluate(() => { window.__storeOnline = true; });
    await page.click('#storeBtn');
    await wait(300);
    await page.click('#storePassword', { clickCount: 3 });
    await page.type('#storePassword', 'store-pass');
    await page.click('#storeConnectBtn');
    await wait(700);
    await page.screenshot({ path: path.join(SHOTS, '5-dashboard-store-online.png'), fullPage: true });

    // ---- 4. network view (static + validation + apply) ----
    await page.click('.ucm-side a[data-view="network"]');
    await wait(700);
    await page.screenshot({ path: path.join(SHOTS, '6-network-dhcp.png') });
    await page.$eval('#netModeStatic', (el) => { el.checked = true; el.dispatchEvent(new Event('change', { bubbles: true })); });
    await page.select('#netIface', 'eth0');
    await page.type('#netIpv4', '192.168.1.50/24');
    await page.type('#netGw4', 'not-an-ip');
    await wait(300);
    await page.click('#netApply');
    await wait(500);
    await page.screenshot({ path: path.join(SHOTS, '7-network-validation.png') });
    await page.click('#netGw4', { clickCount: 3 });
    await page.type('#netGw4', '192.168.1.1');
    await page.type('#netDns', '1.1.1.1, 8.8.8.8');
    await page.click('#netApply');
    await wait(700);
    await page.screenshot({ path: path.join(SHOTS, '8-network-applied.png') });

    // ---- 5. snaps view (store online now: search works) ----
    await page.click('.ucm-side a[data-view="snaps"]');
    await wait(700);
    await page.type('#snapSearchName', 'mosquitto');
    await page.click('#snapSearchName');
    await page.keyboard.press('Enter'); // search field is search-only (Enter must NOT install)
    await wait(700);
    await page.screenshot({ path: path.join(SHOTS, '9-snaps-search.png'), fullPage: true });

    // ---- 6. interfaces view ----
    await page.click('.ucm-side a[data-view="interfaces"]');
    await wait(700);
    await page.screenshot({ path: path.join(SHOTS, '10-interfaces.png'), fullPage: true });
    await page.click('#ifacesFilterBtn');
    await wait(300);
    await page.screenshot({ path: path.join(SHOTS, '11-interfaces-all.png'), fullPage: true });

    // ---- 7. lock -> local sign-in view ----
    await page.click('#lockBtn');
    await wait(700);
    await page.screenshot({ path: path.join(SHOTS, '12-login-local.png') });

    // wrong password -> validation error
    await page.type('#loginPassword', 'wrong');
    await page.click('#loginBtn');
    await wait(400);
    await page.screenshot({ path: path.join(SHOTS, '13-login-error.png') });

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
