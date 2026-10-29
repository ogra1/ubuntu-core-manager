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

const ROOT = path.join(__dirname, '..');
const SOCK = '/tmp/e2e-snapd-' + process.pid + '.socket';
const STATE = fs.mkdtempSync(path.join(os.tmpdir(), 'ucm-e2e-'));

(async () => {
    const { makeServer } = require('./stub-snapd.js');
    await makeServer(SOCK, {
        requests: [], snapActions: [], confSets: [], ifaceOps: [], changeSeq: 1, logoutCount: 0,
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

    console.log(`\n================= ${passed} passed, ${failed} failed =================`);
    try { fs.rmSync(STATE, { recursive: true, force: true }); fs.unlinkSync(SOCK); } catch {}
    process.exit(failed ? 1 : 0);
})().catch((e) => { console.error('FATAL', e); process.exit(2); });
