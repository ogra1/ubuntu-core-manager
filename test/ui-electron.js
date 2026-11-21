'use strict';

/**
 * test/ui-electron.js — real-Electron bootstrap regression guard.
 *
 * ui-screenshot.js runs the UI under Puppeteer Chromium over file://, where the
 * REAL preload.js never executes (the bridge is mock-injected). This test closes
 * that gap: it boots the actual app (main.js + preload.js + app.js) under the
 * real Electron binary in a minimal window-less way and asserts the renderer
 * bootstrap contract — i.e. app.js binds against the REAL exposed bridge name
 * without a global lexical clash. Regression it pins: exposeInMainWorld('core')
 * + `const core` in app.js => SyntaxError "already declared" => white screen.
 *
 * Requires a display (wayland/x11) for the kiosk window to map. Run:
 *   node test/ui-electron.js
 * (in containers: WAYLAND_DISPLAY / DISPLAY from weston or xvfb-run)
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');
const http = require('http');
const https = require('https');
const tls = require('tls');
const net = require('net');

const ROOT = path.join(__dirname, '..');
const SOCK = '/tmp/e2e-snapd-' + process.pid + '.socket';
const STATE = fs.mkdtempSync(path.join(os.tmpdir(), 'ucm-e2e-'));


(async () => {
    const { makeServer } = require('./stub-snapd.js');
    // round I: a REAL localhost web UI (what a snap might ship). The UCM_E2E
    // probe seeds it as a local page; the <webview> must load it.
    function freePort() {
        return new Promise((resolve) => {
            const srv = net.createServer();
            srv.listen(0, '127.0.0.1', () => { const p = srv.address().port; srv.close(() => resolve(p)); });
        });
    }
    const LP_PORT = await freePort();
    const LP_SERVER = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!doctype html><html><head><meta charset="utf-8"><title>UCM E2E Guest</title></head><body><h1>guest ok</h1></body></html>');
    });
    await new Promise((r) => LP_SERVER.listen(LP_PORT, '127.0.0.1', r));
    const LP_URL = 'http://127.0.0.1:' + LP_PORT;
    // round J: a SELF-SIGNED TLS localhost UI (the LXD case:
    // https://127.0.0.1:8443). The <webview> must load it via the app's
    // scoped certificate-error allowance (guest partition + loopback only).
    const TLS_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'ucm-e2e-tls-'));
    const CERT = path.join(TLS_DIR, 'cert.pem'), KEY = path.join(TLS_DIR, 'key.pem');
    await new Promise((resolve, reject) => {
        require('child_process').execFile('openssl',
            ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
             '-keyout', KEY, '-out', CERT, '-subj', '/CN=localhost',
             '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'],
            (err) => (err ? reject(err) : resolve()));
    });
    const LPS_PORT = await freePort();
    const LP_SSL = https.createServer({ cert: fs.readFileSync(CERT), key: fs.readFileSync(KEY) }, (req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!doctype html><html><head><meta charset="utf-8"><title>UCM E2E TLS Guest</title></head><body><h1>tls guest ok</h1></body></html>');
    });
    await new Promise((r) => LP_SSL.listen(LPS_PORT, '127.0.0.1', r));
    const LP_SSL_URL = 'https://127.0.0.1:' + LPS_PORT;
    await makeServer(SOCK, {
        requests: [], snapActions: [], confSets: [], ifaceOps: [], changeSeq: 1, logoutCount: 0,
        // round KM: the FRESH first-boot device — the root kiosk's socket is
        // authorized via root/polkit without a store macaroon (the setup
        // screen's keymap read + apply run before any store login).
        rootOk: true,
        netplanYaml: 'network:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: true\n',
    });

    const electron = path.join(ROOT, 'node_modules', 'electron', 'dist', 'electron');
    // Mirror the snap launcher's runtime flags exactly (wayland ozone, no-sandbox,
    // no-gpu) — this test is the production-path check, not a convenience run.
    const proc = spawn(electron,
        ['--enable-features=UseOzonePlatform', '--ozone-platform=wayland',
         '--disable-dev-shm-usage', '--no-sandbox', '--disable-gpu',
         `--user-data-dir=${STATE}/electron`, path.join(ROOT, 'main.js')],
        {
            env: {
                ...process.env,
                SNAPD_SOCKET: SOCK,
                UCM_STATE_DIR: STATE,
                UCM_E2E: '1',
                UCM_E2E_LOCALPAGE_URL: LP_URL,
                UCM_E2E_LOCALPAGE_SSL: LP_SSL_URL,
                UCM_LOCAL_PAGES_PREF: path.join(STATE, 'local-pages.pref'),
                DISPLAY: process.env.DISPLAY || '',
                WAYLAND_DISPLAY: process.env.WAYLAND_DISPLAY || '',
            },
            stdio: ['ignore', 'pipe', 'pipe'],
        });

    let out = '';
    proc.stdout.on('data', (d) => { out += d.toString(); });
    proc.stderr.on('data', (d) => { out += d.toString(); });

    const result = await new Promise((resolve) => {
        const timer = setTimeout(() => resolve({ timeout: true }), 45000);
        proc.on('close', (code) => {
            clearTimeout(timer);
            const m = out.match(/UCM_E2E_RESULT (\{.*\})/);
            resolve({ code, probe: m ? JSON.parse(m[1]) : null, tail: out.split('\n').slice(-12).join(' | ') });
        });
    });

    let passed = 0, failed = 0;
    const ok = (name, cond, extra = '') => {
        if (cond) { passed++; console.log('  PASS  ' + name); }
        else { failed++; console.log('  FAIL  ' + name + (extra ? '  -> ' + extra : '')); }
    };

    console.log('\n[ui-electron] real-Electron bootstrap (real preload + real app.js)');
    ok('renderer did not crash before probe', !result.timeout, result.tail);
    const p = result.probe || {};
    ok('bridge object present (window.ucmCore)', p.bridge === 'object', JSON.stringify(p));
    ok('a gate view is visible (setup or login)', p.boot === true, JSON.stringify(p));
    // round T-fix13: the app boots DARK by default (the kiosk is dark-themed).
    // The electron STATE dir is fresh (no appearance.pref), so this proves the
    // REAL main.js default + preload + app.js flip <html>.is-dark end-to-end —
    // the mock harness can't observe this (it drives the theme itself).
    ok('the real app boots DARK (the shipped default; fresh state = no pref)', p.dark === true, JSON.stringify(p));
    // round KM: the first-boot KEYMAP read over the REAL bridge (real preload
    // channel + real main.js + the root-socket stub, no store login): the
    // picker settles on the fresh-device default (English (US)) with no
    // error, and the restart overlay element ships in the markup (hidden).
    ok('first boot: the keymap picker loaded via the real bridge (value=us, no error)',
        p.km && p.km.value === 'us' && p.km.err === false, JSON.stringify(p.km));
    ok('first boot: the keymap restart overlay ships in the markup (hidden)',
        p.km && p.km.overlayEl === true, JSON.stringify(p.km));
    // the REAL preload apply channel, end-to-end: a no-op apply (US on a
    // fresh device) resolves to {} through real main + real stub.
    ok('first boot: the keymaps apply channel round-trips the no-op ({} — no write)',
        p.km && p.km.applyNoop === '{}', JSON.stringify(p.km && p.km.applyNoop));
    // round KM part 2: the two-STEP structure — first boot lands on step 1
    // (the keyboard form + its Continue button), with the password step
    // (step 2) present in the DOM but hidden.
    ok('first boot: the two-step layout is up (step 1 shown, step 2 hidden, step-1 button present)',
        p.km && p.km.step1Hidden === false && p.km.step2Hidden === true && p.km.step1Btn === true,
        JSON.stringify(p.km));
    // round KM part 3: the "asked once" flag is false on a fresh device
    // (the keyboard step is still owed — the real preload channel reads it).
    ok('first boot: the asked-once flag is false (fresh state dir)',
        p.km && p.km.flag === false, JSON.stringify(p.km && p.km.flag));

    // ---- round I: the <webview> E2E (real sandbox/webviewTag). The probe
    // created a local password, seeded a GOOD (served) + a DEAD (unreachable)
    // local page, and navigated to each. Good -> the webview loaded the guest;
    // dead -> the app's load-failed fallback card.
    const lp = p.lp || {};
    ok('the good local page loaded in a real <webview> (webviewTag + sandbox OK)',
        lp.ok === true && lp.r0 && lp.r0.wv === true && (lp.r0.url === LP_URL || lp.r0.url === LP_URL + '/') && lp.r0.title === 'UCM E2E Guest' && lp.r0.active === true,
        JSON.stringify(lp.r0));
    ok('the unreachable local page surfaced the load-failed fallback card',
        lp.ok === true && lp.r1 && lp.r1.fallback === true && /Can.t reach/.test(lp.r1.fbText || '') && lp.r1.active === true,
        JSON.stringify(lp.r1));
    // round J: the SELF-SIGNED TLS local page loaded — the app's scoped
    // certificate allowance (guest partition + loopback) let the webview
    // proceed past the cert error to the real guest.
    ok('the self-signed TLS local page loaded (scoped cert allowance; LXD case)',
        lp.ok === true && lp.r2 && lp.r2.wv === true && (lp.r2.url === LP_SSL_URL || lp.r2.url === LP_SSL_URL + '/') && lp.r2.title === 'UCM E2E TLS Guest' && lp.r2.active === true,
        JSON.stringify(lp.r2));

    // ---- round L: the SYSTEM page (the REAL journal + the REAL login1
    // read). READ-ONLY: the probe never triggers a power action.
    const sy = p.sys || {};
    ok('the system page shows its 5 cards in the real app (nav + loaders wired)',
        sy.ok === true && sy.sy && sy.sy.viewActive === true
        && JSON.stringify(sy.sy.cards) === JSON.stringify(['Journal', 'Snap refresh schedule', 'Time', 'Keyboard layout', 'Power']),
        JSON.stringify(sy.ok ? (sy.sy && sy.sy.cards) : sy.error));
    // round T-KM4: the Keyboard card is present, fed by the real 98-entry list,
    // and the Apply button ships (enabled once the picker settles).
    ok('the system page shows the KEYBOARD card (picker fed, Apply button present)',
        sy.ok === true && sy.sy && sy.sy.kmCard && sy.sy.kmCard.present === true
        && sy.sy.kmCard.opts > 90 && typeof sy.sy.kmCard.value === 'string' && sy.sy.kmCard.value.length > 0 && sy.sy.kmCard.btnPresent === true,
        JSON.stringify(sy.ok ? (sy.sy && sy.sy.kmCard) : sy.error));
    // round T: the REAL time read (timedate1 over the existing
    // timeserver-control plug — READ-ONLY; the wall clock + the live zone
    // must come back, and the bundled zone list must be non-trivial).
    ok('the REAL timedate1 read works (wall clock + live zone + bundled zones; read-only)',
        sy.ok === true && sy.sy && sy.sy.time && sy.sy.time.usecOk === true
        && typeof sy.sy.time.zone === 'string' && sy.sy.time.zone.length > 0
        && sy.sy.time.zones > 400,
        JSON.stringify(sy.ok ? (sy.sy && sy.sy.time) : sy.error));
    ok('the REAL journal (journalctl via log-observe) returns real lines',
        sy.ok === true && sy.sy && sy.sy.journal && sy.sy.journal.ok === true && sy.sy.journal.n > 0,
        JSON.stringify(sy.ok ? (sy.sy && sy.sy.journal) : sy.error));
    // round P: the REAL process read (readProcs over /proc via the preload
    // bridge) returns a non-empty, well-formed table. READ-ONLY - the Stop
    // path (SIGKILL) is exercised in the integration suite, never here.
    ok('the REAL process list (readProcs over /proc via the bridge) is non-empty + well-formed',
        sy.ok === true && sy.sy && sy.sy.procs && sy.sy.procs.ok === true && sy.sy.procs.n > 0,
        JSON.stringify(sy.ok ? (sy.sy && sy.sy.procs) : sy.error));
    // round M: the REAL model-assertion READ (core.system.model -> GET
    // /v2/assertions/model) returns an object through the bridge, never an
    // error. Shape, not content (this env may carry no model -> {}).
    ok('the REAL model assertion (GET /v2/assertions/model via the bridge) resolves without error',
        sy.ok === true && sy.sy && sy.sy.model && sy.sy.model.ok === true && sy.sy.model.keys >= 0,
        JSON.stringify(sy.ok ? (sy.sy && sy.sy.model) : sy.error));
    // round SER: the serial read RESOLVES to an object even on an unregistered
    // box (daemon swallows not-found into an empty 200 body -> {}). hasSerial
    // is asserted ONLY when keys>0, so a box that HAS registered passes too.
    ok('the REAL serial assertion (GET /v2/assertions/serial via the bridge) resolves without error ({} when unregistered)',
        sy.ok === true && sy.sy && sy.sy.serial && sy.sy.serial.ok === true && sy.sy.serial.keys >= 0
        && (sy.sy.serial.keys === 0 || sy.sy.serial.hasSerial === true),
        JSON.stringify(sy.ok ? (sy.sy && sy.sy.serial) : sy.error));
    ok('the REAL login1 ScheduledShutdown read works (D-Bus; nothing scheduled here)',
        sy.ok === true && sy.sy && sy.sy.scheduled && !sy.sy.scheduled.error && sy.sy.scheduled.active === false,
        JSON.stringify(sy.ok ? (sy.sy && sy.sy.scheduled) : sy.error));

    console.log(`\n================= ${passed} passed, ${failed} failed =================`);
    try { LP_SERVER.close(); LP_SSL.close(); fs.rmSync(STATE, { recursive: true, force: true }); fs.rmSync(TLS_DIR, { recursive: true, force: true }); fs.unlinkSync(SOCK); } catch {}
    process.exit(failed ? 1 : 0);
})().catch((e) => { console.error('FATAL', e); process.exit(2); });
