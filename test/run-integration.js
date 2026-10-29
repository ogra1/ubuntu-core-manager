'use strict';

/**
 * test/run-integration.js — end-to-end test of the main.js snapd client +
 * auth model against the stub snapd server over a real Unix Domain Socket.
 *
 * Covers BOTH auth layers:
 *   (a) local admin gate (offline; scrypt in $SNAP_COMMON-equivalent dir)
 *   (b) store auth (volatile macaroons via /v2/login)
 * plus socket reads/writes, injection rejection, and netplan YAML handling.
 *
 * Run:  node test/run-integration.js   (from the project root)
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const { makeServer } = require('./stub-snapd.js');

const SOCK = '/tmp/test-snapd-' + process.pid + '.socket';
const STATE = fs.mkdtempSync(path.join(os.tmpdir(), 'ucm-state-'));

// Point the client at the stub BEFORE it is required (env is read at load).
process.env.SNAPD_SOCKET = SOCK;
process.env.UCM_STATE_DIR = STATE; // local admin cred storage for tests

let passed = 0;
let failed = 0;
function ok(name, cond, extra = '') {
    if (cond) { passed += 1; console.log('  PASS  ' + name); }
    else { failed += 1; console.log('  FAIL  ' + name + (extra ? '  -> ' + extra : '')); }
}

(async () => {
    const state = { requests: [], snapActions: [], confSets: [], ifaceOps: [], changeSeq: 100, logoutCount: 0,
        netplanYaml: 'network:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: true\n' };
    await makeServer(SOCK, state);
    console.log('stub snapd up on ' + SOCK);

    // Fresh require after env is set.
    const m = require(path.join(__dirname, '..', 'main.js'));

    console.log('\n[1] input-validation allow-lists (injection prevention)');
    ok('valid snap name "firefox"', m.validSnapName('firefox') === true);
    ok('reject snap name "fire;rm -rf/"', m.validSnapName('fire;rm -rf/') === false);
    ok('reject snap name "../etc"', m.validSnapName('../etc') === false);
    ok('reject snap name "UPPER"', m.validSnapName('UPPER') === false);
    ok('accept instance "firefox.42"', m.validSnapName('firefox.42') === true);
    ok('valid channel "stable"', m.validChannel('stable') === true);
    ok('valid channel "latest/edge"', m.validChannel('latest/edge') === true);
    ok('reject channel "stable;curl evil"', m.validChannel('stable;curl evil') === false);
    ok('reject channel "/etc/passwd"', m.validChannel('/etc/passwd') === false);

    console.log('\n[2] YAML round-trip (netplan document)');
    const doc = m.fromYaml(state.netplanYaml);
    ok('parse eth0.dhcp4', doc && doc.network && doc.network.ethernets && doc.network.ethernets.eth0 && doc.network.ethernets.eth0.dhcp4 === true,
        JSON.stringify(doc));
    const rebuilt = m.toYaml(doc);
    const reparsed = m.fromYaml(rebuilt);
    ok('re-parse after toYaml equals original', JSON.stringify(reparsed) === JSON.stringify(doc));

    console.log('\n[3a] LOCAL admin gate (offline; the UI lock screen)');
    const s0 = m.authStatus();
    ok('first boot: not initialized', s0.initialized === false && s0.authenticated === false, JSON.stringify(s0));
    let shortErr = null;
    try { await m.createLocalPassword('short'); } catch (e) { shortErr = e; }
    ok('reject short password on create', !!shortErr && /8–128/.test(shortErr.message), shortErr && shortErr.message);
    const sc = await m.createLocalPassword('correct-horse-battery');
    ok('create -> initialized + authenticated', sc.initialized === true && sc.authenticated === true, JSON.stringify(sc));
    ok('cred file is 0600 and hashed (no plaintext)', (() => {
        const f = path.join(STATE, 'admin.cred');
        if (!fs.existsSync(f)) return false;
        const mode = (fs.statSync(f).mode & 0o777);
        const cred = JSON.parse(fs.readFileSync(f, 'utf8'));
        return mode === 0o600 && cred.algo === 'scrypt' && cred.salt && cred.hash
            && !JSON.stringify(cred).includes('correct-horse-battery');
    })());
    let dupErr = null;
    try { await m.createLocalPassword('another-pass'); } catch (e) { dupErr = e; }
    ok('second create rejected (password exists)', !!dupErr && /already exists/.test(dupErr.message), dupErr && dupErr.message);
    // simulate a lock + re-login
    await m.logoutLocal();
    ok('local logout locks (authenticated=false, still initialized)', (() => {
        const s = m.authStatus();
        return s.authenticated === false && s.initialized === true;
    })());
    let badPw = null;
    try { await m.loginLocal('wrong-password'); } catch (e) { badPw = e; }
    ok('reject wrong password on login', !!badPw && /incorrect password/.test(badPw.message), badPw && badPw.message);
    const re = await m.loginLocal('correct-horse-battery');
    ok('correct password re-enters (offline; no socket hit)', re.authenticated === true);
    const localHits = state.requests.filter((r) => r.path === '/v2/login').length;
    ok('local login never touched the snapd store endpoint', localHits === 0, String(localHits));

    console.log('\n[3b] STORE auth (optional; volatile macaroons; needs network)');
    let storeErr = null;
    try { await m.storeLogin('admin@example.com', 'wrong'); } catch (e) { storeErr = e; }
    ok('store: reject bad credentials (400 from snapd)', !!storeErr && /cannot authenticate/.test(storeErr.message), storeErr && storeErr.message);
    const st0 = await m.storeLogin('admin@example.com', 'correct-horse');
    ok('store: login returns storeAuthenticated', st0.storeAuthenticated === true && st0.storeUsername === 'admin@example.com', JSON.stringify(st0));
    ok('store: response carries NO macaroon to caller', !JSON.stringify(st0).includes('stub-root-macaroon'), JSON.stringify(st0));

    console.log('\n[4] reads over the socket');
    const info = await m.getSystemInfo();
    ok('system-info version', info.version === '2.68', JSON.stringify(info).slice(0, 80));
    const snaps = await m.listSnaps();
    ok('listSnaps returns array of 3', Array.isArray(snaps) && snaps.length === 3, JSON.stringify(snaps).slice(0, 60));
    const find = await m.searchSnaps('fire');
    ok('store search filters', Array.isArray(find) && find.length === 1 && find[0].name === 'firefox', JSON.stringify(find).slice(0, 80));
    const conns = await m.listInterfaces();
    ok('connections has established+plugs+slots', Array.isArray(conns.established) && Array.isArray(conns.plugs) && Array.isArray(conns.slots));

    console.log('\n[5] writes over the socket (store auth enforced)');
    let installErr = null;
    try { await m.installSnap('htop', 'stable'); } catch (e) { installErr = e; } // already installed in stub
    ok('install already-installed rejected by stub', !!installErr && /already installed/.test(installErr.message), installErr && installErr.message);
    const change = await m.installSnap('mosquitto', 'stable');
    ok('install returns change id', typeof change.id === 'string', JSON.stringify(change));
    const recorded = state.snapActions.find((a) => a.name === 'mosquitto');
    ok('socket received exact install payload', recorded && JSON.stringify(recorded.data) === JSON.stringify({ action: 'install', channel: 'stable' }),
        JSON.stringify(recorded && recorded.data));
    ok('socket Authorization carried root+discharge', state.requests.some((r) => r.authed && /root="stub-root-macaroon"/.test(r.rawAuth) && /discharge="stub-discharge-1"/.test(r.rawAuth)));

    let injErr = null;
    try { await m.installSnap('mosquitto; curl evil', 'stable'); } catch (e) { injErr = e; }
    ok('reject injected snap name before socket', !!injErr && /invalid snap name/.test(injErr.message), injErr && injErr.message);
    let chErr = null;
    try { await m.installSnap('mosquitto', 'stable | reboot'); } catch (e) { chErr = e; }
    ok('reject injected channel before socket', !!chErr && /invalid channel/.test(chErr.message), chErr && chErr.message);

    const ifop = await m.connectInterface(
        { snap: 'snap-store', plug: 'home' },
        { snap: 'core24', slot: 'home' });
    ok('connect plug->slot ok', ifop.status === 'Done', JSON.stringify(ifop));
    ok('socket received connect payload', state.ifaceOps.some((o) => o.action === 'connect' && o.plug && o.plug.plug === 'home'));

    console.log('\n[6] netplan via snapd external config (core.system.network.netplan)');
    const before = await m.getNetplan();
    ok('read current netplan doc', before.network.ethernets.eth0.dhcp4 === true, JSON.stringify(before).slice(0, 100));
    await m.applyNetplanConfig({
        interface: 'eth0', mode: 'static',
        ipv4: '192.168.1.50/24', gateway4: '192.168.1.1', dns: ['1.1.1.1'],
    });
    const written = state.confSets[state.confSets.length - 1];
    ok('conf PUT went to core snap', written && written.name === 'core', JSON.stringify(written && written.name));
    const yamlSent = written && written.data['system.network.netplan'];
    ok('netplan yaml contains static address', yamlSent && yamlSent.includes('192.168.1.50/24') && yamlSent.includes('gateway4: 192.168.1.1'),
        String(yamlSent).slice(0, 120));
    ok('original other keys preserved', yamlSent && yamlSent.includes('network:') && yamlSent.includes('version: 2'));
    let netErr = null;
    try { await m.applyNetplanConfig({ interface: 'eth0; rm -rf /', mode: 'static', ipv4: '10.0.0.5/24' }); } catch (e) { netErr = e; }
    ok('reject injected interface name', !!netErr && /invalid interface name/.test(netErr.message), netErr && netErr.message);
    let cidrErr = null;
    try { await m.applyNetplanConfig({ interface: 'eth0', mode: 'static', ipv4: '999.1.1.1/24' }); } catch (e) { cidrErr = e; }
    ok('reject malformed CIDR (999.x)', !!cidrErr && /ipv4 must be/.test(cidrErr.message), cidrErr && cidrErr.message);

    console.log('\n[7] host diagnostics (read-only)');
    const hs = m.readHostStats();
    ok('host stats have hostname+mem', typeof hs.hostname === 'string' && hs.mem && hs.mem.total > 0, JSON.stringify(hs).slice(0, 80));
    const nd = m.readProcNetDev();
    ok('proc netdev parsed', Array.isArray(nd) && nd.some((d) => d.name === 'lo'), JSON.stringify(nd && nd[0]));

    console.log('\n[8] logout purges volatile state');
    const s1 = await m.storeLogout();
    ok('store logout -> storeAuthenticated=false', s1.storeAuthenticated === false);
    ok('remote store logout was called on the socket', state.logoutCount === 1, String(state.logoutCount));
    ok('store macaroon purged from cache', !JSON.stringify(m.authStatus()).includes('stub-root-macaroon'));
    const s2 = await m.logoutLocal();
    ok('local logout still initialized, unauthenticated', s2.initialized === true && s2.authenticated === false);

    console.log('\n[9] renderer bootstrap contract (preload bridge name vs renderer lexicals)');
    // Regression: exposeInMainWorld('core') + top-level `const core` in app.js throws
    // SyntaxError "already declared" in a real Electron renderer (window property vs
    // global lexical), blanking the whole UI. vm.runInContext reproduces the same
    // binding rules against the REAL names read from the shipped sources.
    const vm = require('vm');
    const ctx = vm.createContext({ console });
    ctx.window = ctx;
    ctx.document = { addEventListener: () => {}, querySelector: () => null,
        querySelectorAll: () => [], createElement: () => ({ setAttribute() {}, append() {}, classList: { add() {}, remove() {}, toggle() {} } }) };
    const preloadSrc = fs.readFileSync(path.join(__dirname, '..', 'preload.js'), 'utf8');
    const exposed = (preloadSrc.match(/exposeInMainWorld\(\s*'([^']+)'/) || [])[1];
    ok('preload exposes a bridge name', !!exposed, 'could not read exposeInMainWorld name');
    if (exposed) {
        try { ctx[exposed] = { ping: () => 'pong' }; } catch { ok('bridge name settable on global', false); }
        try {
            vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'ui', 'app.js'), 'utf8'), ctx, { filename: 'app.js' });
            ok('app.js binds cleanly against real bridge name (' + exposed + ')', true);
        } catch (e) {
            ok('app.js binds cleanly against real bridge name (' + exposed + ')', false, e.message);
        }
    }

    console.log('\n[10] ipcMain wiring executes without wiring-time errors (fake-electron)');
    // Regression: auth:create/auth:login/auth:logout were wired as `guard(fn().then(...))`
    // where fn() is SYNCHRONOUS -> ".then is not a function" in the real runtime.
    // The plain-node path above never runs the wiring (initElectron bails before
    // ipcMain.handle), so this section force-runs it with a fake electron module
    // and asserts no handler wiring throws.
    {
        const handlers = {};
        const events = {};
        const sends = [];
        process.env.UCM_FAKE_ELECTRON = '1';
        const WIRE_STATE = fs.mkdtempSync(path.join(os.tmpdir(), 'ucm-wire-'));
        process.env.UCM_STATE_DIR = WIRE_STATE;
        global.UCM_FAKE_ELECTRON = {
            app: {
                requestSingleInstanceLock: () => true,
                on: () => {}, whenReady: () => Promise.resolve(),
                quit: () => {},
            },
            BrowserWindow: class {
                constructor() {
                    this.webContents = { on: () => {}, send: (ch, p) => { sends.push({ ch, p }); }, setWindowOpenHandler: () => {}, executeJavaScript: () => Promise.resolve(null) };
                    this.on = () => {};
                    this.once = () => {};
                    this.loadFile = () => {};
                    this.isDestroyed = () => false;
                    this.isVisible = () => true;
                    this.setAlwaysOnTop = () => {}; this.focus = () => {};
                    this.unmaximize = () => {}; this.restore = () => {};
                    this.show = () => {};
                }
            },
            ipcMain: {
                handle: (ch, fn) => { handlers[ch] = fn; },
                on: (ch, fn) => { events[ch] = fn; },
            },
            session: { defaultSession: { webRequest: { onHeadersReceived: () => {} }, localAuthenticated: false } },
        };
        try {
            delete require.cache[require.resolve(path.join(__dirname, '..', 'main.js'))];
            const mw = require(path.join(__dirname, '..', 'main.js'));
            const wireErr = process.__ucmWireErr || null;
            ok('ipc wiring threw no TypeError', !wireErr, wireErr && wireErr.message);
            ok('auth:create/login/logout handlers registered',
                !!handlers['auth:create'] && !!handlers['auth:login'] && !!handlers['auth:logout']);
            if (handlers['auth:create']) {
                const r = await new Promise((res) => handlers['auth:create'](null, 'testpass-123').then(res));
                ok('auth:create returns guard result (no .then-on-sync crash)',
                    r && r.ok === true && r.result && r.result.authenticated === true, JSON.stringify(r));
                const r2 = await new Promise((res) => handlers['auth:login'](null, 'testpass-123').then(res));
                ok('auth:login returns guard result', r2 && r2.ok === true && r2.result.authenticated === true, JSON.stringify(r2));
                const r3 = await new Promise((res) => handlers['auth:logout'](null).then(res));
                ok('auth:logout returns guard result', r3 && r3.ok === true && r3.result.authenticated === false, JSON.stringify(r3));

                // Inactivity-timer contract: login arms a 15-min countdown; an
                // activity beacon (mouse/keyboard) resets it to the FULL 15 min.
                if (handlers['auth:login'] && events['session:activity']) {
                    const r4 = await new Promise((res) => handlers['auth:login'](null, 'testpass-123').then(res));
                    await new Promise((res) => setTimeout(res, 150)); // let the countdown advance
                    const before = mw.authStatus().expiresAt;
                    events['session:activity'](); // simulate the UI beacon
                    const after = mw.authStatus().expiresAt;
                    const expect = Date.now() + mw.SESSION_TIMEOUT_MS;
                    ok('login arms a 15-min countdown',
                        r4 && r4.ok === true && before > Date.now() && before <= Date.now() + mw.SESSION_TIMEOUT_MS + 100,
                        `before=${before}`);
                    ok('activity beacon resets countdown to ~15min',
                        after > before && Math.abs(after - expect) < 600,
                        `before=${before} after=${after} expect~${expect}`);
                    const lastPush = sends.slice().reverse().find((x) => x.ch === 'auth-status-changed');
                    ok('activity beacon PUSHES fresh expiresAt to renderer (pill reset; fixes "0:00 no lock")',
                        !!lastPush && lastPush.p && lastPush.p.authenticated === true
                        && Math.abs((lastPush.p.expiresAt || 0) - after) < 50,
                        JSON.stringify(lastPush && lastPush.p));
                }
            }
            delete global.UCM_FAKE_ELECTRON;
        } finally {
            delete global.UCM_FAKE_ELECTRON;
            delete process.env.UCM_FAKE_ELECTRON;
            try { fs.rmSync(WIRE_STATE, { recursive: true, force: true }); } catch {}
        }
    }

    console.log(`\n================= ${passed} passed, ${failed} failed =================`);
    fs.rmSync(STATE, { recursive: true, force: true });
    fs.unlinkSync(SOCK);
    process.exit(failed ? 1 : 0);
})().catch((e) => { console.error('FATAL', e); try { fs.rmSync(STATE, { recursive: true, force: true }); fs.unlinkSync(SOCK); } catch {} process.exit(2); });
