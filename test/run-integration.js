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
    const state = { requests: [], snapActions: [], confSets: [], ifaceOps: [], changeSeq: 100, logoutCount: 0, prevRev: {},
        serviceOps: [], serviceChg: 0, services: { 'llama-cpp': [ { snap: 'llama-cpp', name: 'server', daemon: 'simple', 'daemon-scope': 'system', active: true, enabled: true } ] },
        // seed changes in the LIVE shape (string summary, hyphenated spawn-time)
        // and NOT in newest-first order — [4] asserts the field names and the
        // renderer sorts; keep the stub honest.
        // seed changes in the LIVE shape (string summary, hyphenated
        // spawn-time) + FULL detail (tasks with log/progress/ready-time) -
        // the round T-fix19 change-detail asserts read /v2/changes/{id}. NOT
        // in newest-first order (the renderer sorts); seed '2' is not ready.
        changes: [
            { id: '1', kind: 'install-snap', summary: 'Install snap "htop"', status: 'Done',
              'spawn-time': '2026-10-28T09:00:00Z', 'ready-time': '2026-10-28T09:00:42Z',
              tasks: [ { id: '11', kind: 'download-snap', summary: 'Download snap "htop"', status: 'Done',
                         'spawn-time': '2026-10-28T09:00:01Z', 'ready-time': '2026-10-28T09:00:10Z',
                         log: ['Downloading htop 3.3.0 (amd64)', 'Verifying hash'] },
                        { id: '12', kind: 'setup-snap', summary: 'Unpack and setup snap "htop"', status: 'Done',
                         'spawn-time': '2026-10-28T09:00:11Z', 'ready-time': '2026-10-28T09:00:41Z' } ] },
            { id: '2', kind: 'configure-snap', summary: 'Configure snap "core24"', status: 'Doing',
              'spawn-time': '2026-10-28T10:00:00Z',
              tasks: [ { id: '21', kind: 'configure-snap', summary: 'Configure snap "core24"', status: 'Doing',
                         progress: { done: 2, total: 8 }, 'spawn-time': '2026-10-28T10:00:05Z' } ] },
        ],
        netplan: { network: { version: 2, ethernets: { eth0: { dhcp4: true } } } } };
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
    ok('valid channel "21/stable" (versioned track, live-store node channel)', m.validChannel('21/stable') === true);
    ok('valid channel "6/stable" (single-digit track)', m.validChannel('6/stable') === true);
    ok('valid channel "18.04/candidate" (dotted track)', m.validChannel('18.04/candidate') === true);
    ok('valid channel "25-foo/edge/my-hotfix-1234" (store branch: track/risk/branch)', m.validChannel('25-foo/edge/my-hotfix-1234') === true);
    ok('reject channel "stable;curl evil"', m.validChannel('stable;curl evil') === false);
    ok('reject channel "/etc/passwd"', m.validChannel('/etc/passwd') === false);
    ok('reject channel "a/b/c/d" (>3 segments)', m.validChannel('a/b/c/d') === false);
    ok('reject channel with newline', m.validChannel('latest/stable\n') === false);

    console.log('\n[2] YAML helpers round-trip (the legacy string-compat path)');
    // round 54: the netplan option is a JSON OBJECT — the YAML helpers only
    // survive for a LEGACY string value (a pre-object snapd), so [2] uses a
    // self-contained literal, not the stub state.
    const legacyYaml = 'network:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: true\n';
    const doc = m.fromYaml(legacyYaml);
    ok('parse eth0.dhcp4 (legacy YAML string)', doc && doc.network && doc.network.ethernets && doc.network.ethernets.eth0 && doc.network.ethernets.eth0.dhcp4 === true,
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

    // /v2/system-info refresh{last,next} — live snapd shape (UTC ISO);
    // the stub mirrors it and the UI normalizes to local dd.mm.yyyy hh:mm
    ok('system-info carries refresh last/next (UTC ISO)',
        typeof info.refresh?.last === 'string' && typeof info.refresh?.next === 'string'
        && /Z$/.test(info.refresh.last) && /Z$/.test(info.refresh.next),
        JSON.stringify(info.refresh));

    // model assertion: RAW assertion text over the socket, parsed to headers
    const mod = await m.getModelAssertion();
    ok('model assertion parsed: model/base/grade/brand-id',
        mod.model === 'core-24-kvm' && mod.base === 'core24' && mod.grade === 'signed' && mod['brand-id'] === 'canonical',
        JSON.stringify(mod).slice(0, 120));
    ok('model assertion: signature block NOT parsed as headers',
        !Object.keys(mod).some((k) => k.includes('STUBSIGNATUREBLOCK')) && mod.type === 'model',
        Object.keys(mod).join(','));

    // serial assertion (round SER): RAW text over the socket, parsed by the SAME
    // generic header parser (getSerialAssertion -> GET /v2/assertions/serial,
    // the REST equivalent of 'snap known serial'). The col-0 identity headers
    // parse; the indented device-key lines and the signature block do NOT.
    const ser = await m.getSerialAssertion();
    ok('serial assertion parsed: brand-id/model/serial (identity headers)',
        ser.type === 'serial' && ser['brand-id'] === 'QfOqF7d2M1Pk2O0SbEKqTdB9Ry2aI0BP'
        && ser.model === 'frame-uc24' && ser.serial === 'f6d4b37a-3659-48f4-9617-6a93c831c0b0',
        JSON.stringify(ser).slice(0, 160));
    ok('serial assertion: the indented device-key lines do NOT parse as headers',
        ser['device-key'] === '' && !Object.keys(ser).some((k) => k.includes('AcbBTQRWhcGA')),
        JSON.stringify(Object.keys(ser)));
    ok('serial assertion: signature block NOT parsed as headers',
        !Object.keys(ser).some((k) => k.includes('AcLBUgQAAQo')) && ser['sign-key-sha3-384'] === 'wrfougkz3Huq2T_KklfnufCC0HzG7bJ9wP99GV0FF-D3QH3eJtuSRlQc2JhrAoh1',
        Object.keys(ser).join(','));
    // direct parser unit checks (edge cases without the socket)
    ok('parser: classic:true -> boolean true',
        m.parseModelAssertion('type: model\nclassic: true\nmodel: x\n\nSIG').classic === true);
    ok('parser: missing headers -> empty object',
        Object.keys(m.parseModelAssertion(null)).length === 0);
    // the model snaps: list (round 46b: it DEFINES the system snaps)
    ok('model assertion parsed: snaps: list',
        Array.isArray(mod.snaps) && mod.snaps.length === 4 && mod.snaps[0].name === 'snapd'
        && mod.snaps[0].type === 'snapd' && mod.snaps[2].name === 'gadget' && mod.snaps[2].type === 'gadget'
        && mod.snaps[3].type === 'app' && mod.snaps[3].presence === 'required',
        JSON.stringify(mod.snaps));
    ok('modelSystemSnaps: top-level base + gadget/kernel/snapd/os (NOT app entries, NOT unlisted bases)',
        JSON.stringify(Array.from(m.modelSystemSnaps(mod)).sort()) === JSON.stringify(['core24', 'gadget', 'snapd'])
        && m.modelSystemSnaps(null).size === 0
        && m.modelSystemSnaps({ base: 'core24' }).size === 1,
        JSON.stringify(Array.from(m.modelSystemSnaps(mod))));
    const snaps = await m.listSnaps();
    ok('listSnaps returns array of 5 (round KM: the frame is seeded too)', Array.isArray(snaps) && snaps.length === 5, JSON.stringify(snaps).slice(0, 60));
    // round FS: the store SEARCH is full-text (mode 'q' = the snapd
    // /v2/find?q=... `snap find` sends) — it matches summaries, not just
    // names. 'broker' hits mosquitto (summary "MQTT broker") even though no
    // snap is named 'broker'; 'mosquitto-tools' appears too (name match). The
    // DEFAULT (no mode) stays EXACT-NAME resolution for the channel pickers:
    // searchSnaps('fire') with no mode returns only the firefox name.
    const ft = await m.searchSnaps('broker', 10, 'q');
    ok('store FULL-TEXT search (mode q, snap find) matches summaries',
        Array.isArray(ft) && ft.length === 2
        && ft.some((s) => s.name === 'mosquitto') && ft.some((s) => s.name === 'mosquitto-tools'),
        JSON.stringify(ft.map((s) => s.name)));
    // the exact path is EXACT (no prefix/substring): 'firefox' resolves, a
    // prefix ('fire') or a summary term ('broker') does NOT - that separation
    // is what keeps the channel pickers pointing at one specific snap.
    // round LASTCH-FIX: a REAL /v2/find?q= row carries NO channel map
    // (store.Find -> storeSnap: "TODO: not yet defined: channel map") —
    // searchSnaps must merge the exact-name (findOne) map per row, or the
    // UI's per-row channel picker + 'Last changed' degrade to stable-only /
    // '—' (the reported regression; the stub now models this honestly).
    ok('store FULL-TEXT results carry the MERGED channel map (findOne per row; store.Find returns none)',
        ft.length === 2 && ft.every((s) => s.channels && Object.keys(s.channels).length > 0)
        && ft.find((s) => s.name === 'mosquitto').channels['latest/edge']['released-at'] === '2026-10-21T12:00:00Z'
        && ft.find((s) => s.name === 'mosquitto-tools').channels['latest/stable']['released-at'] === '2026-08-02T12:00:00Z',
        JSON.stringify(ft.map((s) => [s.name, s.channels ? Object.keys(s.channels).length : null])));
    const exact = await m.searchSnaps('firefox');
    ok('store search default stays EXACT-NAME (name=, the channel pickers\' path)',
        Array.isArray(exact) && exact.length === 1 && exact[0].name === 'firefox',
        JSON.stringify(exact.map((s) => s.name)));
    const prefix = await m.searchSnaps('fire');
    ok('the exact path does NOT do prefix/substring matching (a find regression)',
        Array.isArray(prefix) && prefix.length === 0,
        JSON.stringify(prefix.map((s) => s.name)));
    const conns = await m.listInterfaces();
    ok('interfaces list has plugs+slots (live /v2/interfaces shape)',
        Array.isArray(conns.plugs) && Array.isArray(conns.slots),
        Object.keys(conns).join(','));
    ok('interfaces list has NO legacy established/undesired keys',
        !('established' in conns) && !('undesired' in conns),
        Object.keys(conns).join(','));
    ok('unconnected plug carries null connections and a `plug` key (not `name`)',
        conns.plugs.some((p) => p.connections === null)
        && conns.plugs.every((p) => typeof p.plug === 'string' && !('name' in p)),
        JSON.stringify(conns.plugs[0]).slice(0, 100));
    // /v2/changes list shape: LIVE snapd returns a plain STRING summary and
    // HYPHENATED 'spawn-time' (the renderer was built against the old stub
    // shape — round-19 class bug). Keep the stub honest.
    const clist = await m.listChanges('all');
    ok('changes list: live field names (string summary, hyphenated spawn-time)',
        clist.length >= 1 && clist.every((c) => typeof c.summary === 'string'
            && typeof c['spawn-time'] === 'string' && !('spawn_time' in c)),
        JSON.stringify(clist[0]).slice(0, 120));
    // round T-fix19: the change-DETAIL shape (the change-detail modal reads
    // getChange(id) -> GET /v2/changes/{id}). LIVE snapd (client/change.go)
    // returns the FULL Change: tasks[] with per-task log + progress +
    // hyphenated times, ready, err. The stub must be honest (the old reduced
    // shape had no tasks).
    const det1 = await m.getChange('1');
    ok('change detail: full Change shape (ready, times, err, tasks[])',
        det1.id === '1' && det1.ready === true && det1.err === null
        && typeof det1['spawn-time'] === 'string' && typeof det1['ready-time'] === 'string'
        && Array.isArray(det1.tasks) && det1.tasks.length === 2,
        JSON.stringify(det1).slice(0, 160));
    ok('change detail: task shape (kind/summary/status/log[]/progress/times)',
        det1.tasks.every((t) => typeof t.kind === 'string' && typeof t.summary === 'string'
            && typeof t.status === 'string' && Array.isArray(t.log)
            && t.progress && typeof t.progress.done === 'number' && typeof t.progress.total === 'number'
            && typeof t['spawn-time'] === 'string'),
        JSON.stringify(det1.tasks[0]).slice(0, 160));
    ok('change detail: a logged task carries its log lines',
        det1.tasks[0].log.length === 2 && (det1.tasks[1].log || []).length === 0,
        JSON.stringify([det1.tasks[0].log, det1.tasks[1].log || []]));
    // a not-ready change: ready false, no ready-time, a Doing task with progress
    const det2 = await m.getChange('2');
    ok('change detail: an in-progress change is not ready (no ready-time, Doing task + progress)',
        det2.ready === false && det2['ready-time'] == null
        && det2.tasks[0].status === 'Doing' && det2.tasks[0].progress.done < det2.tasks[0].progress.total,
        JSON.stringify(det2).slice(0, 160));
    let badIdErr = null;
    try { await m.getChange('12abc'); } catch (e) { badIdErr = e; }
    ok('change detail: a non-numeric id is rejected before the socket',
        !!badIdErr && /invalid change id/.test(badIdErr.message), badIdErr && badIdErr.message);

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




    console.log('\n[6] netplan write path (core.system.network.netplan) — the round-1 single-interface writer is gone (round 53)');
    const deadGone = (() => { const src = require('fs').readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8'); return !src.includes('applyNetplanConfig') && !src.includes('buildNetplanIface'); })();
    ok('the dead round-1 netplan writer (buildNetplanIface/applyNetplanConfig) is removed', deadGone);
    // the live write path is netApplyDevice (one device -> the netplan doc);
    // its full coverage is [13.5]. Here: prove a static ethernet reaches the
    // socket as canonical YAML. The payload is read from the RECORDED PUT
    // (state.confSets) — no settle wait, so this section stays as fast as the
    // round-1 one it replaced (the [7] mosquitto install races the [5]
    // install's 300ms settle; added delay here would 400 it).
    // round 54/55: the option is a JSON OBJECT (a YAML string would fail
    // snapd's option decode) — the RECORDED PUT body must carry the doc as
    // an object. Seed the default Core boilerplate (catch-alls only): an
    // edit onto a pure seed REPLACES it completely (the round-54 case).
    state.netplan = { network: { version: 2, ethernets: { 'all-en': { dhcp4: true, match: { name: 'en*' } }, 'all-eth': { dhcp4: true, match: { name: 'eth*' } } } } };
    await m.netApplyDevice({ name: 'eth0', type: 'ethernet', mode: 'static', address: '192.168.1.50/24', gateway: '192.168.1.1', dns: ['1.1.1.1'] });
    const written6 = state.confSets[state.confSets.length - 1];
    ok('conf PUT went to core snap', written6 && written6.name === 'core', JSON.stringify(written6 && written6.name));
    const sent6 = written6 && written6.data['system.network.netplan'];
    ok('the netplan option value is a JSON OBJECT, not a string', sent6 && typeof sent6 === 'object' && !Array.isArray(sent6), String(typeof sent6));
    ok('an edit onto a pure seed REPLACES it completely (all-en + all-eth gone, doc = version + this device)',
        sent6 && typeof sent6 === 'object' && sent6.network
        && JSON.stringify(sent6.network.ethernets) === JSON.stringify({ eth0: { addresses: ['192.168.1.50/24'], gateway4: '192.168.1.1', dns: { nameservers: { addresses: ['1.1.1.1'] } } } })
        && !('all-en' in (sent6.network.ethernets || {})),
        JSON.stringify(sent6 && sent6.network));
    ok('the replaced doc keeps version: 2', sent6 && sent6.network && sent6.network.version === 2, JSON.stringify(sent6 && sent6.network));
    // round 55 — the seed catch-alls must ALSO be stripped when the doc
    // already carries a NAMED entry (they would silently DHCP-configure NICs
    // the user never touched). The named entry survives, the boilerplate goes.
    state.netplan = { network: { version: 2, ethernets: {
        'all-en': { dhcp4: true, match: { name: 'en*' } },
        'all-eth': { dhcp4: true, match: { name: 'eth*' } },
        enp0s2: { addresses: ['10.0.2.15/24'], gateway4: '10.0.2.2' },
    } } };
    await m.netApplyDevice({ name: 'enp0s2', type: 'ethernet', mode: 'static', address: '192.168.9.10/24', gateway: '192.168.9.1' });
    const sentMix = state.confSets[state.confSets.length - 1].data['system.network.netplan'];
    ok('a named + catch-all doc: the edit keeps the named entry and STRIPS the catch-all boilerplate',
        sentMix && typeof sentMix === 'object' && sentMix.network
        && JSON.stringify(sentMix.network.ethernets) === JSON.stringify({ enp0s2: { addresses: ['192.168.9.10/24'], gateway4: '192.168.9.1' } }),
        JSON.stringify(sentMix && sentMix.network));
    ok('the named + catch-all edit keeps version: 2', sentMix && sentMix.network && sentMix.network.version === 2, JSON.stringify(sentMix && sentMix.network));
    let cidrErr = null;
    try { await m.netApplyDevice({ name: 'eth0', type: 'ethernet', mode: 'static', address: '999.1.1.1/24' }); } catch (e) { cidrErr = e; }
    ok('reject malformed CIDR (999.x) before the socket', !!cidrErr && /prefix/.test(cidrErr.message), cidrErr && cidrErr.message);

    console.log('\n[7] host diagnostics (read-only)');
    // install a brand-new snap: the write returns a change id; the stub settles
    // it ~300ms later and THEN the snap appears in the list (the UI must poll the
    // change and reload after settle — the "list did not refresh" regression).
    const ch = await m.installSnap('mosquitto', 'latest/stable');
    // Regression: snapd's async envelope is {type:"async", result:null, change:"<id>"}
    // — the id lives at the envelope top level. The client MUST surface it as
    // {id}; a stub that puts it in result masks exactly this class of bug.
    ok('async envelope: install surfaces change id as {id} (result is null)',
        ch && /^[0-9]+$/.test(String(ch.id)) && ch.result === undefined, JSON.stringify(ch));
    let pollCh = null;
    for (let i = 0; i < 40 && (!pollCh || pollCh.status === 'Doing'); i++) {
        pollCh = await m.getChange(ch.id);
        if (pollCh && pollCh.status === 'Doing') await new Promise((r) => setTimeout(r, 50));
    }
    ok('change reached terminal state (Done)', pollCh && pollCh.status === 'Done', JSON.stringify(pollCh));
    const afterList = await m.listSnaps();
    ok('snap list refreshed after settle includes new snap', afterList.some((x) => x.name === 'mosquitto'),
        afterList.map((x) => x.name).join(','));
    let againErr = null;
    try { await m.installSnap('mosquitto', 'stable'); } catch (e) { againErr = e; }
    ok('second install rejected (already installed — stub list mutated)', !!againErr, againErr && againErr.message);

    // LIVE snapd 2.77 reports the in-flight change status as "Doing" AND the
    // transient "Do" (observed on a real remove). The settle logic must classify
    // terminal states explicitly and keep polling through "Do" — the old
    // status!=='Doing' rule surfaced 'Removal finished with an error: <name>: Do'.
    const rm = await m.snapAction('htop', 'remove');
    ok('remove returns a snapd change id', rm && /^[0-9]+$/.test(String(rm.id)), JSON.stringify(rm));
    const rmPoll = new Set();
    let rmFinal = null;
    for (let i = 0; i < 80 && !rmFinal; i++) {
        const c = await m.getChange(String(rm.id));
        if (c) { rmPoll.add(c.status); if (/^(done|error|undo|undoing)$/i.test(c.status)) rmFinal = c; }
        // 30ms cadence: slow enough to reliably land inside the stub's 60ms
        // "Doing"->"Do" window, fast enough that the whole wait is <~400ms.
        if (!rmFinal) await new Promise((r) => setTimeout(r, 30));
    }
    ok('remove change passed through the "Do" transient', rmPoll.has('Do'), `[${Array.from(rmPoll).join(', ')}]`);
    ok('remove settled to Done despite the transient', rmFinal && rmFinal.status === 'Done', JSON.stringify(rmFinal));
    ok('htop gone from the list after settle', !(await m.listSnaps()).some((x) => x.name === 'htop'));

    // Round 34: disable / enable / revert / refresh write contracts, LIVE snapd 2.77
    // (probe34b over the real /run/snapd.socket): disable+enable are async 202
    // changes that flip status installed<->active (a DISABLED snap reports status
    // "installed" - there is no "disabled" string and no `active` field;
    // daemon/snap.go mapLocal). revert with no previous revision is a SYNCHRONOUS
    // 400 {message:"cannot revert ... no revision to revert to"}; after a refresh
    // (new revision) revert restores the prior one.
    // normalize revision history: sections [5]+[7] installed mosquitto twice,
    // so it already carries a prevRev target - drop it so the 400 path below
    // is deterministic (a truly pristine install would have no target either).
    delete state.prevRev.mosquitto;
    const mosq = (await m.listSnaps()).find((x) => x.name === 'mosquitto');
    const mosqRev = mosq && mosq.revision;
    const dis = await m.snapAction('mosquitto', 'disable');
    ok('disable returns a snapd change id', dis && /^[0-9]+$/.test(String(dis.id)), JSON.stringify(dis));
    await (async () => { for (let i = 0; i < 40; i++) { const c = await m.getChange(String(dis.id)); if (c && /^(done|error|undo|undoing)$/i.test(c.status)) return c; await new Promise((r) => setTimeout(r, 30)); } })();
    ok('disable -> status flips to "installed" (live snapd: no "disabled" word)', (await m.listSnaps()).find((x) => x.name === 'mosquitto').status === 'installed');
    const en = await m.snapAction('mosquitto', 'enable');
    ok('enable returns a snapd change id', en && /^[0-9]+$/.test(String(en.id)), JSON.stringify(en));
    await (async () => { for (let i = 0; i < 40; i++) { const c = await m.getChange(String(en.id)); if (c && /^(done|error|undo|undoing)$/i.test(c.status)) return c; await new Promise((r) => setTimeout(r, 30)); } })();
    ok('enable -> status back to "active"', (await m.listSnaps()).find((x) => x.name === 'mosquitto').status === 'active');
    let revErr = null;
    try { await m.snapAction('mosquitto', 'revert'); } catch (e) { revErr = e; }
    ok('revert with no revision target -> synchronous 400 (not an async change)', !!revErr && /no revision to revert to/.test(revErr.message), revErr && revErr.message);
    const refr = await m.snapAction('mosquitto', 'refresh');
    ok('refresh returns a snapd change id', refr && /^[0-9]+$/.test(String(refr.id)), JSON.stringify(refr));
    await (async () => { for (let i = 0; i < 40; i++) { const c = await m.getChange(String(refr.id)); if (c && /^(done|error|undo|undoing)$/i.test(c.status)) return c; await new Promise((r) => setTimeout(r, 30)); } })();
    const mosq2 = (await m.listSnaps()).find((x) => x.name === 'mosquitto');
    ok('refresh advanced the revision', mosq2 && String(mosq2.revision) !== String(mosqRev), mosqRev + '->' + (mosq2 && mosq2.revision));
    let rev2 = null;
    try { rev2 = await m.snapAction('mosquitto', 'revert'); } catch (e) { revErr = e; }
    ok('revert allowed once a previous revision exists (after a refresh)', rev2 && /^[0-9]+$/.test(String(rev2.id)), JSON.stringify(rev2));
    if (rev2) { await (async () => { for (let i = 0; i < 40; i++) { const c = await m.getChange(String(rev2.id)); if (c && /^(done|error|undo|undoing)$/i.test(c.status)) return c; await new Promise((r) => setTimeout(r, 30)); } })(); }

    // round 47m: snap COMPONENTS (source client/snap_op.go + LIVE snapd 2.77.1
    // verified over /run/snapd.socket with llama-cpp): a component install/remove
    // is POST /v2/snaps/{name} with {"action":"install"|"remove","components":[c]}
    // — an async change, and it never touches the parent snap. The single-snap
    // GET carries components[] where revision "unset" = not installed and a
    // numeric revision = installed.
    const ci = await m.snapComponent('comp-demo', 'install', 'extra');
    ok('component install returns a change id', ci && /^[0-9]+$/.test(String(ci.id)), JSON.stringify(ci));
    await (async () => { for (let i = 0; i < 40; i++) { const c = await m.getChange(String(ci.id)); if (c && /^(done|error|undo|undoing)$/i.test(c.status)) return c; await new Promise((r) => setTimeout(r, 30)); } })();
    const ci2 = await m.getSnapInfo('comp-demo');
    ok('component install flipped revision unset -> numeric', (ci2.components || []).some((c) => c.name === 'extra' && c.revision !== 'unset'), JSON.stringify((ci2.components || []).find((c) => c.name === 'extra')));
    const crm = await m.snapComponent('comp-demo', 'remove', 'plugin');
    ok('component remove returns a change id', crm && /^[0-9]+$/.test(String(crm.id)), JSON.stringify(crm));
    await (async () => { for (let i = 0; i < 40; i++) { const c = await m.getChange(String(crm.id)); if (c && /^(done|error|undo|undoing)$/i.test(c.status)) return c; await new Promise((r) => setTimeout(r, 30)); } })();
    const cj = await m.getSnapInfo('comp-demo');
    ok('component remove flipped revision -> unset', (cj.components || []).some((c) => c.name === 'plugin' && c.revision === 'unset'), JSON.stringify((cj.components || []).find((c) => c.name === 'plugin')));
    const csnaps = await m.listSnaps();
    ok('parent snap untouched by component ops (comp-demo present, revision intact)', csnaps.some((x) => x.name === 'comp-demo' && x.revision === 500), JSON.stringify(csnaps.find((x) => x.name === 'comp-demo')));
    let compBad = null;
    try { await m.snapComponent('comp-demo', 'enable', 'extra'); } catch (e) { compBad = e; }
    ok('snapComponent rejects a non install/remove action', !!compBad && /component action not permitted/.test(compBad.message), compBad && compBad.message);
    let compBadName = null;
    try { await m.snapComponent('comp-demo', 'install', '../etc'); } catch (e) { compBadName = e; }
    ok('snapComponent rejects an invalid component token', !!compBadName && /invalid component name/.test(compBadName.message), compBadName && compBadName.message);
    ok('revert restored the previous revision', (await m.listSnaps()).find((x) => x.name === 'mosquitto').revision == mosqRev, JSON.stringify(mosq2 && mosq2.revision));


    // LIVE-VERIFIED (snapd 2.77): POST /v2/interfaces is an ASYNC write — 202
    // with the change id at the envelope TOP (result null) — and its body is
    // the PLURAL plugs[]/slots[] form; the singular {plug, slot} body the old
    // code sent is a 400 "at least one plug and slot is required".
    const ifop = await m.connectInterface(
        { snap: 'firefox', plug: 'browser' },
        { snap: 'snap-store', slot: 'browser' });
    ok('connect returns a change id (async envelope)', typeof ifop.id === 'string', JSON.stringify(ifop));
    ok('socket received the PLURAL connect payload', state.ifaceOps.some((o) =>
        o.action === 'connect'
        && Array.isArray(o.plugs) && o.plugs.length === 1 && o.plugs[0].snap === 'firefox' && o.plugs[0].plug === 'browser'
        && Array.isArray(o.slots) && o.slots.length === 1 && o.slots[0].snap === 'snap-store' && o.slots[0].slot === 'browser'),
        JSON.stringify(state.ifaceOps[state.ifaceOps.length - 1]));
    await new Promise((r) => setTimeout(r, 400)); // the stub settles its change at 250ms
    const conns2 = await m.listInterfaces();
    const browserPlug = conns2.plugs.find((p) => p.snap === 'firefox' && p.plug === 'browser');
    ok('topology reflects the connect after settle',
        browserPlug && JSON.stringify(browserPlug.connections) === JSON.stringify([{ snap: 'snap-store', slot: 'browser' }]),
        JSON.stringify(browserPlug && browserPlug.connections));
    const dfop = await m.disconnectInterface(
        { snap: 'firefox', plug: 'network' },
        { snap: 'core24', slot: 'network' });
    ok('disconnect returns a change id (async envelope)', typeof dfop.id === 'string', JSON.stringify(dfop));
    await new Promise((r) => setTimeout(r, 400));
    const conns3 = await m.listInterfaces();
    const netPlug = conns3.plugs.find((p) => p.snap === 'firefox' && p.plug === 'network');
    ok('topology reflects the disconnect after settle (connections null)',
        netPlug && netPlug.connections === null,
        JSON.stringify(netPlug && netPlug.connections));

    const hs = m.readHostStats();
    ok('host stats have hostname+mem', typeof hs.hostname === 'string' && hs.mem && hs.mem.total > 0, JSON.stringify(hs).slice(0, 80));
    // data partition reader: statfs(/run/mnt/data) with root fallback.
    // In this dev container /run/mnt/data is absent -> source 'root'.
    const dp = await m.getDataPartition();
    ok('data disk: consistent statfs shape',
        dp && dp.totalBytes > 0 && dp.usedBytes + dp.freeBytes === dp.totalBytes
        && dp.reservedBytes >= 0 && dp.reservedBytes <= dp.freeBytes
        && dp.usedPercent >= 0 && dp.usedPercent <= 100,
        JSON.stringify(dp).slice(0, 120));
    ok('data disk: mount/source pair is valid',
        (dp.source === 'data' && dp.mount === '/run/mnt/data')
        || (dp.source === 'root' && dp.mount === '/'),
        dp.mount + '/' + dp.source);
    const mt = m.mountsTable();
    ok('mounts table parsed (has a / row)',
        Array.isArray(mt) && mt.every((r) => r.length >= 3) && mt.some((r) => r[1] === '/'),
        JSON.stringify(mt[0]));
    // net traffic sampler: /proc/net/dev cumulative -> rate ring buffer
    // default-route parser: picks the Dest-00000000 interface (this box has
    // one, so it must resolve to a real non-lo device)
    const def = m.defaultRouteIface();
    ok('default route iface resolved from /proc/net/route',
        typeof def === 'string' && def.length > 0 && def !== 'lo', String(def));

    // net sampler returns { iface, series }; iface must be the default-route
    // device (or a non-lo fallback when there is no route).
    const n1 = m.readNetTraffic();
    ok('net sample: shape {iface, series} + null baseline first pair',
        n1 && Array.isArray(n1.series) && n1.series.length === 1
        && n1.series[0].r == null && n1.series[0].x == null
        && (n1.iface == null || (typeof n1.iface === 'string' && n1.iface !== 'lo')),
        JSON.stringify(n1).slice(0, 120));
    if (def) ok('net sample: counted iface IS the default-route device', n1.iface === def, n1.iface + ' vs ' + def);
    await new Promise((r) => setTimeout(r, 60));
    const n2 = m.readNetTraffic();
    ok('net series: second sample has numeric rates >= 0',
        n2.series.length === 2 && typeof n2.series[1].r === 'number' && typeof n2.series[1].x === 'number'
        && n2.series[1].r >= 0 && n2.series[1].x >= 0,
        JSON.stringify(n2).slice(0, 120));

    const nd = m.readProcNetDev();
    ok('proc netdev parsed', Array.isArray(nd) && nd.some((d) => d.name === 'lo'), JSON.stringify(nd && nd[0]));

    // CPU utilization sampler (main-process /proc/stat ring buffer)
    const c1 = m.readCpuUtilization();
    const c2 = m.readCpuUtilization();
    ok('cpu series is an array with a null boot baseline',
        Array.isArray(c1) && Array.isArray(c2) && c1.length === 1 && c1[0] == null && c2.length === 2 && c2[1] != null,
        JSON.stringify(c2));
    ok('cpu deltas are 0..100 numbers',
        c2.every((v) => v == null || (typeof v === 'number' && v >= 0 && v <= 100)),
        JSON.stringify(c2));
    await new Promise((r) => setTimeout(r, 50));
    const c3 = m.readCpuUtilization();
    ok('cpu series grows per call', c3.length === 3, String(c3.length));


    // round P: process control (the process-control plug). readProcs reads
    // /proc per poll (cpu is INSTANTANEOUS - null on the very first sample,
    // a 0..100 number once the aggregate has a delta); sendProcSignal delivers
    // a signal (the snap grants signal(send)+capability kill). The REAL signal
    // test spawns a child and SIGKILLs it through sendProcSignal (no plug is
    // needed in this dev container - the snap's process-control plug is what
    // grants it on a real device; the capability check is the guard's job).
    m.__resetProcState();
    const pr1 = m.readProcs();
    ok('readProcs: returns an array of well-formed rows',
        Array.isArray(pr1) && pr1.length > 0 && pr1.every((r) =>
            Number.isInteger(r.pid) && r.pid > 0 && typeof r.name === 'string' && r.name.length > 0
            && typeof r.state === 'string' && Number.isInteger(r.ppid) && r.ppid >= 0
            && Number.isInteger(r.rss) && r.rss >= 0 && (r.cpu == null || (typeof r.cpu === 'number' && r.cpu >= 0 && r.cpu <= 100))),
        JSON.stringify(pr1 && pr1[0]));
    ok('readProcs: lists the current process (own pid present)',
        pr1.some((r) => r.pid === process.pid),
        'pid ' + process.pid + ' of ' + pr1.length + ' rows');
    const sleep = require('child_process').spawn('/bin/sleep', ['30']);
    await new Promise((r) => setTimeout(r, 80));
    const pr2 = m.readProcs();
    ok('readProcs: a freshly spawned child appears (name=comm "sleep")',
        pr2.some((r) => r.pid === sleep.pid && r.name === 'sleep'),
        'pid ' + sleep.pid);
    // THE CPU FIX (round P-fix2): a genuinely BUSY process must report cpu > 0 on
    // the 2nd sample. The pre-fix version always returned null (it divided by an
    // aggregate recomputed from the SAME snapshot, so the delta was 0) - every row
    // read '-'. A spin loop burns ~one full core -> ~100% (100 ticks/s USER_HZ).
    const spin = require('child_process').spawn('/bin/bash', ['-c', 'while :; do :; done']);
    await new Promise((r) => setTimeout(r, 80));
    m.readProcs(); // baseline for the spin
    await new Promise((r) => setTimeout(r, 1200)); // let it burn jiffies
    const spinRow = m.readProcs().find((r) => r.pid === spin.pid);
    ok('readProcs: a busy process reports cpu > 0 on the 2nd sample (the CPU fix)',
        !!spinRow && typeof spinRow.cpu === 'number' && spinRow.cpu > 0,
        JSON.stringify(spinRow));
    ok('readProcs: state is a clean single letter (the field-index fix; no paren/garbage)',
        pr2.every((r) => typeof r.state === 'string' && r.state.length === 1 && /[RSDZTtWIX]/.test(r.state)),
        JSON.stringify([...new Set(pr2.map((r) => r.state))]));
    try { spin.kill('SIGKILL'); } catch { /* already gone */ }
    // invalid pids/signals are rejected BEFORE any signal is sent
    let badPid = null, badSig = null;
    try { m.sendProcSignal(0, 9); } catch (e) { badPid = e; }
    try { m.sendProcSignal(process.pid, 0); } catch (e) { badSig = e; }
    ok('sendProcSignal: pid 0 (the process group) is rejected', badPid && /invalid pid/.test(badPid.message), badPid && badPid.message);
    ok('sendProcSignal: signal 0 is rejected', badSig && /invalid signal/.test(badSig.message), badSig && badSig.message);
    // the spy: a recorded call, no real signal
    m.__setProcKill((pid, sig) => { global.__spied = { pid, sig }; return true; });
    let spyErr = null; const spyRet = m.sendProcSignal(process.pid, 15);
    ok('sendProcSignal: routes through the (injectable) kill and returns {pid,sig}',
        global.__spied && global.__spied.pid === process.pid && global.__spied.sig === 15
        && spyRet && spyRet.pid === process.pid && spyRet.sig === 15,
        JSON.stringify({ spied: global.__spied, spyRet }));
    m.__setProcKill(null); // restore the real process.kill
    // the REAL signal: SIGKILL the spawned child and confirm it is gone
    m.sendProcSignal(sleep.pid, 9);
    let exitCode = null, signalCode = null;
    await new Promise((r) => { sleep.on('exit', (c, sig) => { exitCode = c; signalCode = sig; r(); }); });
    // a signal death: exitCode is null and signalCode is SIGKILL (NOT exitCode=9 -
    // that only happens for a numeric exit()). sendProcSignal sent SIGKILL (9).
    ok('sendProcSignal (REAL): SIGKILL took the spawned child down (signal death)',
        signalCode === 'SIGKILL' && exitCode === null,
        'exitCode=' + exitCode + ' signalCode=' + signalCode);
    ok('readProcs: the killed pid is no longer listed', !m.readProcs().some((r) => r.pid === sleep.pid), 'pid ' + sleep.pid + ' still present');

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
        const sessionHandlers = {};
        const appHandlers = {};
        process.env.UCM_FAKE_ELECTRON = '1';
        const WIRE_STATE = fs.mkdtempSync(path.join(os.tmpdir(), 'ucm-wire-'));
        process.env.UCM_STATE_DIR = WIRE_STATE;
        // memoized partition sessions: the SAME partition name must return the
        // SAME object — main.js scopes the cert allowance by object identity
        // (webContents.session === session.fromPartition('ucm-local-pages')).
        const FAKE_PARTITIONS = {};
        global.UCM_FAKE_ELECTRON = {
            app: {
                requestSingleInstanceLock: () => true,
                on: (ch, fn) => { appHandlers[ch] = fn; }, whenReady: () => Promise.resolve(),
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
            session: {
            fromPartition: (name) => {
                if (!FAKE_PARTITIONS[name]) FAKE_PARTITIONS[name] = { name, webRequest: { onHeadersReceived: () => {} }, on: (ch, fn) => { sessionHandlers[name + ':' + ch] = fn; } };
                return FAKE_PARTITIONS[name];
            },
            defaultSession: { webRequest: { onHeadersReceived: () => {} }, localAuthenticated: false },
        },
        };
        try {
            delete require.cache[require.resolve(path.join(__dirname, '..', 'main.js'))];
            const mw = require(path.join(__dirname, '..', 'main.js'));
            const wireErr = process.__ucmWireErr || null;
            ok('ipc wiring threw no TypeError', !wireErr, wireErr && wireErr.message);
            ok('auth:create/login/logout handlers registered',
                !!handlers['auth:create'] && !!handlers['auth:login'] && !!handlers['auth:logout']
                && !!handlers['sys:cpu']);
            ok('timesync handlers registered (status open, writes auth-gated)',
                !!handlers['timesync:status'] && !!handlers['timesync:set-enabled'] && !!handlers['timesync:set-server']);
            ok('ip-forwarding handlers registered (status open, writes auth-gated)',
                !!handlers['net:forwarding-status'] && !!handlers['net:forwarding-set']);
            ok('net devices handlers registered (list open, apply auth-gated) + the dead net:apply is gone',
                !!handlers['net:devices'] && !!handlers['net:apply-device'] && !handlers['net:apply']);
            ok('lock-timeout handler registered (round 66, auth-gated)',
                !!handlers['auth:set-lock-timeout']);
            ok('local-pages handler registered (round I, auth-gated)',
                !!handlers['settings:set-local-pages']);
            ok('system-page handlers registered (round L, auth-gated)',
                !!handlers['system:journal-tail'] && !!handlers['system:journal-follow'] && !!handlers['system:journal-stop']
                && !!handlers['system:refresh-read'] && !!handlers['system:refresh-write']
                && !!handlers['system:power'] && !!handlers['system:power-schedule']
                && !!handlers['system:power-cancel-scheduled'] && !!handlers['system:power-scheduled']);
            ok('system-page hold handlers registered (round S: refresh-hold read + write, auth-gated)',
                !!handlers['system:refresh-hold-read'] && !!handlers['system:refresh-hold']);
            ok('system-page refresh-now handler registered (round S+2: the Refresh now button, auth-gated)',
                !!handlers['system:refresh-now']);
            ok('memory-card handlers registered (round MEM: read + write, auth-gated)',
                !!handlers['system:memory-read'] && !!handlers['system:memory-write']);
            ok('journal-persistence handlers registered (round JRN: read + write, auth-gated)',
                !!handlers['system:journal-persistent-read'] && !!handlers['system:journal-persistent-write']);
            ok('recovery handler registered (round RCV: system:recovery, auth-gated)',
                !!handlers['system:recovery']);
            ok('time-card handlers registered (round T: time read/set + timezone write, auth-gated)',
                !!handlers['system:time-read'] && !!handlers['system:time-set'] && !!handlers['system:timezone-write']);
            ok('process-modal handlers registered (round P: procs read open, proc-kill auth-gated, process-control plug)',
                !!handlers['system:procs'] && !!handlers['system:proc-kill']);
            ok('serial-assertion handler registered (round SER: sys:serial read-only, like sys:model)',
                !!handlers['sys:serial']);
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
                // round 66: the configurable inactivity lock timeout (console-
                // privileged like the reset). A change is LIVE: it re-arms the
                // active session's watchdog, so authStatus().timeoutMs and the
                // pushed payload reflect the new value immediately.
                if (handlers['auth:set-lock-timeout']) {
                    const rT = await new Promise((res) => handlers['auth:set-lock-timeout'](null, '30').then(res));
                    ok('auth:set-lock-timeout("30") returns the timeout payload',
                        rT.ok === true && rT.result.value === '30' && rT.result.ms === 30 * 60000, JSON.stringify(rT));
                    const stT = mw.authStatus();
                    ok('the change is LIVE: authStatus().timeoutMs is now 30 min',
                        stT.timeoutMs === 30 * 60000, JSON.stringify(stT));
                    const rBadT = await new Promise((res) => handlers['auth:set-lock-timeout'](null, '7').then(res));
                    ok('auth:set-lock-timeout rejects an unknown value (7 min is not offered)',
                        rBadT.ok === false && /invalid lock timeout/.test(rBadT.error), JSON.stringify(rBadT));
                    const stT2 = mw.authStatus();
                    ok('a rejected set does NOT change the timeout (still 30 min)',
                        stT2.timeoutMs === 30 * 60000, JSON.stringify(stT2));
                    const rOff = await new Promise((res) => handlers['auth:set-lock-timeout'](null, 'off').then(res));
                    ok('auth:set-lock-timeout("off") returns ms:null (no auto-lock)',
                        rOff.ok === true && rOff.result.value === 'off' && rOff.result.ms === null, JSON.stringify(rOff));
                    ok('with "off" the status carries no auto-lock (timeoutMs null, expiresAt 0)',
                        mw.authStatus().timeoutMs === null && mw.authStatus().expiresAt === 0, JSON.stringify(mw.authStatus()));
                    // revert to the shipped default so later sections see 15 min
                    await new Promise((res) => handlers['auth:set-lock-timeout'](null, '15').then(res));
                    ok('the timeout reverts to the 15-min default',
                        mw.authStatus().timeoutMs === 15 * 60000, JSON.stringify(mw.authStatus()));
                } else {
                    ok('auth:set-lock-timeout handler registered', false);
                }
                // round A: the appearance (light/dark) — a console-privileged
                // setting. Live: setAppearance persists and the new payload
                // (appearance) is pushed to the renderer via pushAuthStatus.
                if (handlers['settings:set-appearance']) {
                    const rA = await new Promise((res) => handlers['settings:set-appearance'](null, 'dark').then(res));
                    ok('settings:set-appearance("dark") returns the appearance payload',
                        rA.ok === true && rA.result.value === 'dark' && rA.result.default === 'dark', JSON.stringify(rA));
                    ok('the appearance is LIVE in the status payload (dark)',
                        mw.authStatus().appearance === 'dark', JSON.stringify(mw.authStatus()));
                    const lastA = sends.slice().reverse().find((x) => x.ch === 'auth-status-changed');
                    ok('setting the appearance PUSHES the new payload to the renderer',
                        !!lastA && lastA.p && lastA.p.appearance === 'dark', JSON.stringify(lastA && lastA.p));
                    const rBadA = await new Promise((res) => handlers['settings:set-appearance'](null, 'blue').then(res));
                    ok('settings:set-appearance rejects an unknown value (blue is not offered)',
                        rBadA.ok === false && /invalid appearance/.test(rBadA.error), JSON.stringify(rBadA));
                    const rBadA2 = await new Promise((res) => handlers['settings:set-appearance'](null, 'DARK').then(res));
                    ok('settings:set-appearance rejects wrong-case (DARK)',
                        rBadA2.ok === false && /invalid appearance/.test(rBadA2.error), JSON.stringify(rBadA2));
                    ok('a rejected set does NOT change the appearance (still dark)',
                        mw.authStatus().appearance === 'dark', JSON.stringify(mw.authStatus()));
                    // round T-fix13: the shipped default is dark — set it back
                    // (this section had driven it to dark already) so later
                    // sections see the default.
                    await new Promise((res) => handlers['settings:set-appearance'](null, 'dark').then(res));
                    ok('the appearance reverts to the shipped default (dark)',
                        mw.authStatus().appearance === 'dark', JSON.stringify(mw.authStatus()));
                } else {
                    ok('settings:set-appearance handler registered', false);
                }
                // round I: local pages (embedded localhost web UIs) — a
                // console-privileged setting. Live: setLocalPages persists and the
                // new list is pushed to the renderer via pushAuthStatus.
                if (handlers['settings:set-local-pages']) {
                    const LP = [{ name: 'HA', url: 'http://localhost:8123' }, { name: 'G', url: 'http://127.0.0.1:3000' }];
                    const rLP = await new Promise((res) => handlers['settings:set-local-pages'](null, JSON.parse(JSON.stringify(LP))).then(res));
                    ok('settings:set-local-pages(list) returns the {list,max} payload',
                        rLP.ok === true && rLP.result.max === 10
                        && JSON.stringify(rLP.result.list.map((e) => e.name)) === JSON.stringify(['HA', 'G']), JSON.stringify(rLP));
                    ok('the local pages are LIVE in the status payload',
                        JSON.stringify((mw.authStatus().localPages || []).map((e) => e.name)) === JSON.stringify(['HA', 'G']),
                        JSON.stringify(mw.authStatus().localPages));
                    const lastLP = sends.slice().reverse().find((x) => x.ch === 'auth-status-changed');
                    ok('setting the local pages PUSHES the new payload to the renderer',
                        !!lastLP && lastLP.p && JSON.stringify((lastLP.p.localPages || []).map((e) => e.name)) === JSON.stringify(['HA', 'G']),
                        JSON.stringify(lastLP && lastLP.p && lastLP.p.localPages));
                    const rBadLP = await new Promise((res) => handlers['settings:set-local-pages'](null, [{ name: 'X', url: 'http://10.0.0.5:8080' }]).then(res));
                    ok('set-local-pages rejects a NON-loopback url (the security boundary)',
                        rBadLP.ok === false && /invalid local pages/.test(rBadLP.error), JSON.stringify(rBadLP));
                    const rDupLP = await new Promise((res) => handlers['settings:set-local-pages'](null, [{ name: 'A', url: 'http://localhost:1' }, { name: 'a', url: 'http://localhost:2' }]).then(res));
                    ok('set-local-pages rejects duplicate names (case-insensitive)',
                        rDupLP.ok === false && /duplicate name/.test(rDupLP.error), JSON.stringify(rDupLP));
                    ok('a rejected set does NOT change the local pages (still HA,G)',
                        JSON.stringify((mw.authStatus().localPages || []).map((e) => e.name)) === JSON.stringify(['HA', 'G']),
                        JSON.stringify(mw.authStatus().localPages));
                    await new Promise((res) => handlers['settings:set-local-pages'](null, []).then(res));
                    ok('the local pages revert to empty (the shipped default)',
                        JSON.stringify(mw.authStatus().localPages || []) === JSON.stringify([]), JSON.stringify(mw.authStatus().localPages));
                } else {
                    ok('settings:set-local-pages handler registered', false);
                }
                // round J: the certificate-error handler is APP-level (verified
                // against electron.d.ts: the event fires on app / WebContents,
                // NOT on Session) and scoped to the GUEST partition via
                // webContents.session === session.fromPartition('ucm-local-pages').
                // The fake fromPartition shares one guest-session object, so
                // driving with/without it models guest vs kiosk contents.
                const GUEST_WC = { session: global.UCM_FAKE_ELECTRON.session.fromPartition('ucm-local-pages') };
                const HOST_WC = { session: { name: 'default' } };
                const driveCert = (wc, url, error) => {
                    let cb = null, prevented = false;
                    appHandlers['certificate-error'](
                        { preventDefault: () => { prevented = true; } }, wc, url, error, {},
                        (v) => { cb = v; });
                    return { cb, prevented };
                };
                if (typeof appHandlers['certificate-error'] === 'function') {
                    const okCase = driveCert(GUEST_WC, 'https://127.0.0.1:8443', 'net::ERR_CERT_AUTHORITY_INVALID');
                    ok('certificate-error: self-signed on loopback in the GUEST partition is ALLOWED (real chromium format)',
                        okCase.prevented === true && okCase.cb === true, JSON.stringify({ cb: okCase.cb, prevented: okCase.prevented }));
                    const denyHost = driveCert(GUEST_WC, 'https://10.0.0.5:8443', 'net::ERR_CERT_AUTHORITY_INVALID');
                    ok('certificate-error: a NON-loopback host is DENIED even in the guest partition',
                        denyHost.cb === false, JSON.stringify(denyHost.cb));
                    const denyErr = driveCert(GUEST_WC, 'https://127.0.0.1:8443', 'net::ERR_CERT_DATE_INVALID');
                    ok('certificate-error: an expired cert is DENIED even in the guest partition',
                        denyErr.cb === false, JSON.stringify(denyErr.cb));
                    const denyKiosk = driveCert(HOST_WC, 'https://127.0.0.1:8443', 'net::ERR_CERT_AUTHORITY_INVALID');
                    ok('certificate-error: the KIOSK contents (default session) are DENIED (stays fully verified)',
                        denyKiosk.cb === false, JSON.stringify(denyKiosk.cb));
                } else {
                    ok('the app-level certificate-error handler is registered (round J)', false);
                }
                // Guarded local-admin reset: console-privileged (active session),
                // re-confirms the CURRENT password, wipes $SNAP_COMMON/admin.cred
                // -> next launch is first-boot setup again.
                if (handlers['auth:reset']) {
                    const rBad = await new Promise((res) => handlers['auth:reset'](null, 'wrong-password').then(res));
                    ok('auth:reset rejects an incorrect password (session kept)',
                        rBad.ok === false && /incorrect password/.test(rBad.error), JSON.stringify(rBad));
                    const rReset = await new Promise((res) => handlers['auth:reset'](null, 'testpass-123').then(res));
                    ok('auth:reset wipes the credential (guarded by the current password)',
                        rReset.ok === true && rReset.result.initialized === false && rReset.result.authenticated === false,
                        JSON.stringify(rReset));
                    ok('auth:reset removed admin.cred from disk', !fs.existsSync(path.join(WIRE_STATE, 'admin.cred')));
                    const reInit = mw.authStatus();
                    ok('post-reset status is first-boot (initialized=false)', reInit.initialized === false, JSON.stringify(reInit));
                } else {
                    ok('auth:reset handler registered', false);
                }
                // round KM: the keymaps:apply GATE (console-privileged, with
                // the one first-boot door — the layout must be settable
                // BEFORE the administrator password exists). Drive the three
                // gate states through the auth handlers; the payload is the
                // 'us' no-op (no socket write — [11.5] below reads the
                // fresh-device state, so nothing may have been applied).
                if (handlers['keymaps:apply']) {
                    const rKmA = await new Promise((res) => handlers['keymaps:apply'](null, 'us').then(res));
                    ok('keymaps:apply gate: FIRST BOOT (no local password) is allowed — the layout precedes the password',
                        rKmA.ok === true && rKmA.result && !rKmA.result.id, JSON.stringify(rKmA));
                    await new Promise((res) => handlers['auth:create'](null, 'testpass-123').then(res));
                    const rKmB = await new Promise((res) => handlers['keymaps:apply'](null, 'us').then(res));
                    ok('keymaps:apply gate: an authenticated console is allowed (requireAuth)',
                        rKmB.ok === true && rKmB.result && !rKmB.result.id, JSON.stringify(rKmB));
                    await new Promise((res) => handlers['auth:logout'](null).then(res));
                    const rKmC = await new Promise((res) => handlers['keymaps:apply'](null, 'us').then(res));
                    ok('keymaps:apply gate: a locked-out console (initialized, not authenticated) is refused',
                        rKmC.ok === false && /authentication required/.test(rKmC.error), JSON.stringify(rKmC));
                } else {
                    ok('keymaps:apply handler registered (round KM)', false);
                }
                // round KM part 3: the "asked once" flag (keymap.conf in the
                // state dir). The READ is open (the setup screen runs it
                // pre-gate); the WRITE carries the SAME first-boot door as
                // the apply (open when no local password exists, else
                // requireAuth). The block is SELF-CONTAINED — it sets each
                // state explicitly (the prior apply-gate block left the
                // session in the first-boot door state).
                if (handlers['keymaps:flag']) {
                    const rF0 = await new Promise((res) => handlers['keymaps:flag'](null).then(res));
                    ok('keymaps:flag read is open (no gate) and starts false (fresh state dir)',
                        rF0.ok === true && rF0.result === false, JSON.stringify(rF0));
                    // locked-out console: initialized (a password exists) but
                    // not authenticated -> the door is closed, requireAuth.
                    await new Promise((res) => handlers['auth:create'](null, 'testpass-123').then(res));
                    await new Promise((res) => handlers['auth:logout'](null).then(res));
                    const rF1 = await new Promise((res) => handlers['keymaps:set-flag'](null).then(res));
                    ok('keymaps:set-flag is refused for a locked-out console (initialized, not authenticated — the door is closed)',
                        rF1.ok === false && /authentication required/.test(rF1.error), JSON.stringify(rF1));
                    const rF2 = await new Promise((res) => handlers['keymaps:flag'](null).then(res));
                    ok('a refused set-flag does not flip the flag',
                        rF2.ok === true && rF2.result === false, JSON.stringify(rF2));
                    // a password reset returns the device to FIRST BOOT (no
                    // local password) — the door is OPEN again: the setup
                    // screen must be able to set the flag while creating the
                    // password (the layout step precedes the password).
                    await new Promise((res) => handlers['auth:login'](null, 'testpass-123').then(res));
                    const rF3 = await new Promise((res) => handlers['auth:reset'](null, 'testpass-123').then(res));
                    ok('auth:reset restores first boot (the door re-opens)',
                        rF3.ok === true && rF3.result.initialized === false, JSON.stringify(rF3));
                    const rF4 = await new Promise((res) => handlers['keymaps:set-flag'](null).then(res));
                    ok('keymaps:set-flag is allowed at FIRST BOOT (the door — the layout step precedes the password)',
                        rF4.ok === true && rF4.result === true, JSON.stringify(rF4));
                    const rF5 = await new Promise((res) => handlers['keymaps:flag'](null).then(res));
                    ok('the flag is persisted (the read reflects the first-boot write)',
                        rF5.ok === true && rF5.result === true, JSON.stringify(rF5));
                    // and a password reset NEVER clears the flag (keymap.conf
                    // is not admin.cred — a reset must not un-ask the
                    // layout): create the credential, reset it again, the
                    // flag stays.
                    await new Promise((res) => handlers['auth:create'](null, 'testpass-123').then(res));
                    const rF6 = await new Promise((res) => handlers['auth:reset'](null, 'testpass-123').then(res));
                    ok('a second reset (the user-visible one) wipes the password and the flag SURVIVES it',
                        rF6.ok === true && rF6.result.initialized === false && mw.readKmFlag() === true, JSON.stringify(rF6));
                    // restore a logged-in console for the downstream [11]/
                    // [11.5] sections (they log out in too, but the door
                    // state here must be first-boot, not a stale session).
                    await new Promise((res) => handlers['auth:create'](null, 'testpass-123').then(res));
                } else {
                    ok('keymaps:flag handler registered (round KM part 3)', false);
                }
            delete global.UCM_FAKE_ELECTRON;
        } finally {
            delete global.UCM_FAKE_ELECTRON;
            delete process.env.UCM_FAKE_ELECTRON;
            try { fs.rmSync(WIRE_STATE, { recursive: true, force: true }); } catch {}
        }
    }

    console.log('\n[11] per-snap configuration (snapd /v2/snaps/{name}/conf)');
    // conf UI backend: GET /v2/snaps/{name}/conf (optional ?keys=k),
    // PUT with a flat {key: scalar|null} map; null removes the key.
    // (The guarded reset above wiped the volatile store session — expected:
    // a reset returns the device to first-boot state, so re-login first.)
    await m.storeLogin('admin@example.com', 'correct-horse');
    const confPutId = await m.setSnapConfig('htop', { 'probe.key': 1 });
    ok('conf PUT returns an async change id (live: 202, not a sync 200)', confPutId && confPutId.id, JSON.stringify(confPutId));
    await new Promise((r) => setTimeout(r, 320)); // the stub settles at 250ms (atomic doc flip)
    const confAll = await m.getSnapConfig('htop');
    // round 48f: the doc is NESTED (LIVE shape) — the dotted key is a path.
    ok('conf-get returns the snap doc (nested)', confAll && confAll.port === '8080' && confAll.logging && confAll.logging.level === 'info', JSON.stringify(confAll));
    const confOne = await m.getSnapConfig('htop', 'port');
    ok('conf-get ?keys=port unwraps to {port: value}', confOne && confOne.port === '8080', JSON.stringify(confOne));
    // LIVE (round 48f probe): a single-key GET for a missing key is a 400
    // option-not-found, NOT {key: null}. (The old flat stub lied with null; the
    // app never issues a single-key conf GET, so this is stub honesty only.)
    let confMissErr = null;
    try { await m.getSnapConfig('htop', 'no.such.key'); } catch (e) { confMissErr = e; }
    ok('conf-get unknown single key -> 400 option-not-found (live, not {key:null})',
        !!confMissErr && confMissErr.kind === 'option-not-found' && confMissErr.status === 400,
        confMissErr && (confMissErr.kind + ' ' + confMissErr.status));
    await m.setSnapConfig('htop', { port: 9090 });
    await new Promise((r) => setTimeout(r, 320)); // async conf PUT: the doc flips when the change settles
    const confAfter = await m.getSnapConfig('htop');
    ok('conf-set persists the value (number kept native)', confAfter.port === 9090, JSON.stringify(confAfter));
    const confPut = state.confSets[state.confSets.length - 1];
    ok('conf PUT carried {port: 9090} to htop',
        confPut && confPut.name === 'htop' && JSON.stringify(confPut.data) === JSON.stringify({ port: 9090 }),
        JSON.stringify(confPut && confPut.data));
    let confKeyErr = null;
    try { await m.setSnapConfig('htop', { 'port;rm -rf /': 1 }); } catch (e) { confKeyErr = e; }
    ok('reject injected config key before socket', !!confKeyErr && /invalid config key/.test(confKeyErr.message), confKeyErr && confKeyErr.message);
    let confValErr = null;
    try { await m.setSnapConfig('htop', { port: { nested: true } }); } catch (e) { confValErr = e; }
    ok('reject non-scalar config value', !!confValErr && /scalar/.test(confValErr.message), confValErr && confValErr.message);
    // round 48f GHOST TREE (LIVE snapd behavior, purgeNulls): unsetting the LAST
    // leaf of a branch leaves the emptied parent object behind — the doc becomes
    // {port:9090, logging:{}} — which is exactly why the app must unset the whole
    // TOP-LEVEL key (confWipeTop) instead of just the leaf.
    await m.setSnapConfig('htop', { 'logging.level': null });
    await new Promise((r) => setTimeout(r, 320));
    const confDel = await m.getSnapConfig('htop');
    ok('a plain leaf unset removes the value but snapd leaves the emptied parent hollow (the ghost)',
        confDel && confDel.logging && Object.keys(confDel.logging).length === 0 && confDel.port === 9090, JSON.stringify(confDel));
    // the fix: unsetting the EMPTIED NODE itself (any depth — the REST `key!`
    // equivalent) removes it while the rest of the tree is intact.
    await m.setSnapConfig('htop', { logging: null });
    await new Promise((r) => setTimeout(r, 320));
    const confWipe = await m.getSnapConfig('htop');
    ok('unsetting the emptied node removes it with no ghost tree',
        confWipe && !('logging' in confWipe) && confWipe.port === 9090, JSON.stringify(confWipe));
    // confUnsetKey unit (the renderer helper that picks the key to unset):
    // extracting it from app.js and running it against nested docs.
    {
        const fs = require('fs');
        const appSrc = fs.readFileSync(path.join(__dirname, '..', 'ui', 'app.js'), 'utf8');
        const mfn = appSrc.match(/function confUnsetKey\(doc, full\) \{[\s\S]*?\n\}/);
        ok('confUnsetKey helper is present in app.js', !!mfn);
        if (mfn) {
            const body = mfn[0].slice(mfn[0].indexOf('{') + 1, mfn[0].lastIndexOf('}'));
            const fn = new Function('doc', 'full', body);
            ok('confUnsetKey unsets a top-level scalar leaf',
                fn({ a: 1, b: { c: 2 } }, 'a') === 'a', JSON.stringify(fn({ a: 1, b: { c: 2 } }, 'a')));
            ok('confUnsetKey unsets only the leaf when its parent keeps siblings',
                fn({ a: { b: { c: 1, d: 2 } } }, 'a.b.c') === 'a.b.c', JSON.stringify(fn({ a: { b: { c: 1, d: 2 } } }, 'a.b.c')));
            ok('confUnsetKey unsets the emptied INTERMEDIATE node (not just the leaf, not the top)',
                fn({ a: { b: { c: 1 }, d: 2 } }, 'a.b.c') === 'a.b', JSON.stringify(fn({ a: { b: { c: 1 }, d: 2 } }, 'a.b.c')));
            ok('confUnsetKey unsets the TOP key when the whole branch empties',
                fn({ a: { b: { c: 1 } } }, 'a.b.c') === 'a', JSON.stringify(fn({ a: { b: { c: 1 } } }, 'a.b.c')));
        }
        ok('config trash removal computes the unset key via confUnsetKey',
            /confUnsetKey\(cur, full\)/.test(appSrc), 'renderer does not call confUnsetKey');
    }
    // Round 48f chunk E: confInferType — a config value the UI types is a plain
    // string, but `snap set` (the CLI, clientutil.ParseConfigValues) infers a
    // NUMBER for "1234" and a BOOLEAN for "true" (valid JSON of that kind) and
    // keeps everything else a string. confInferType mirrors that DEFAULT mode
    // (the snapd daemon itself does NO typing — it stores the PUT body as-is).
    {
        const infer = m.confInferType;
        ok('confInferType is exported', typeof infer === 'function');
        ok('confInferType infers an integer', infer('1234') === 1234, JSON.stringify(infer('1234')));
        ok('confInferType infers a negative number', infer('-5') === -5, JSON.stringify(infer('-5')));
        ok('confInferType infers a float', infer('0.5') === 0.5, JSON.stringify(infer('0.5')));
        ok('confInferType infers true', infer('true') === true, JSON.stringify(infer('true')));
        ok('confInferType infers false', infer('false') === false, JSON.stringify(infer('false')));
        ok('confInferType keeps a plain string', infer('hello') === 'hello', JSON.stringify(infer('hello')));
        ok('confInferType keeps a string with spaces', infer('a b') === 'a b', JSON.stringify(infer('a b')));
        ok('confInferType does NOT parse a JSON object (stays one scalar string)',
            infer('{\"a\":1}') === '{\"a\":1}', JSON.stringify(infer('{\"a\":1}')));
        ok('confInferType does NOT parse a JSON array (stays one scalar string)',
            infer('[1,2]') === '[1,2]', JSON.stringify(infer('[1,2]')));
        ok('confInferType passes null through (deletion)', infer(null) === null, JSON.stringify(infer(null)));
        // END-TO-END through the real main.js -> stub socket: a value typed as
        // a string must reach snapd as its inferred native type (this is the
        // user-facing behavior — the doc the snap's hook sees is typed).
        await m.setSnapConfig('htop', { typednum: '1234', typedbool: 'true', typedstr: 'hello' });
        await new Promise((r) => setTimeout(r, 320));
        const typedDoc = await m.getSnapConfig('htop');
        ok('string "1234" reached snapd as the NUMBER 1234', typedDoc.typednum === 1234, JSON.stringify(typedDoc.typednum));
        ok('string "true" reached snapd as the BOOLEAN true', typedDoc.typedbool === true, JSON.stringify(typedDoc.typedbool));
        ok('string "hello" reached snapd as the STRING "hello"', typedDoc.typedstr === 'hello', JSON.stringify(typedDoc.typedstr));
        const typedPut = state.confSets[state.confSets.length - 1];
        ok('the socket payload carried the inferred types (not verbatim strings)',
            typedPut && typedPut.name === 'htop' && typedPut.data.typednum === 1234 && typedPut.data.typedbool === true && typedPut.data.typedstr === 'hello',
            typedPut && JSON.stringify(typedPut.data));
        // setSnapConfig must actually infer (the socket payload is typed)
        const ms = require('fs').readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');
        ok('setSnapConfig applies confInferType to the outgoing value',
            /body\[k\] = confInferType\(v\)/.test(ms), 'setSnapConfig does not call confInferType');
    }

    console.log('\n[11.5] keyboard layout (round KM: the ubuntu-frame external config)');
    // FIRST BOOT: the local password does not exist yet (the [10] reset left
    // the session uninitialized) and there is NO store login — the root
    // kiosk's /run/snapd.socket is authorized via root/polkit (state.rootOk
    // models it). The keymap MUST be settable in exactly this state, because
    // the layout has to be correct before the administrator password is
    // typed. The read (keymaps:list / keymaps:current) is open, like every
    // other socket read; the apply is console-privileged (later sections of
    // this file run authenticated — see the [12] re-login below).
    state.rootOk = true;
    await m.storeLogout();
    const kmList = m.listKeymaps();
    ok('the bundled keymap list has 98 entries (xkb-data 2.46 base.lst, ! layout section)',
        kmList.length === 98, String(kmList.length));
    ok('the keymap list is shaped {id,label} and starts Albanian / ends Wolof (base.lst order)',
        kmList[0] && kmList[0].id === 'al' && kmList[0].label === 'Albanian'
        && kmList[kmList.length - 1].id === 'sn' && kmList[kmList.length - 1].label === 'Wolof',
        JSON.stringify([kmList[0], kmList[kmList.length - 1]]));
    const kmUs = kmList.find((x) => x.id === 'us');
    ok('English (US) is offered (the fresh-device default)',
        !!kmUs && kmUs.label === 'English (US)', JSON.stringify(kmUs));
    // fresh Core: nothing applied -> null (NOT the 400 option-not-found the
    // live daemon sends for a single-key GET of an unset option — the full
    // doc read returns 200 {} and the app scans the `config` value).
    let kmCur = 'unset';
    try { kmCur = await m.readKeymap(); } catch (e) { kmCur = 'ERR:' + e.message; }
    ok('first boot: no keymap applied (readKeymap -> null, not an error)',
        kmCur === null, String(kmCur));
    let kmErr1 = null;
    try { await m.applyKeymap('not-a-keymap-xyz'); } catch (e) { kmErr1 = e; }
    ok('applyKeymap rejects an id that is not in the bundled list (client-side, before any socket write)',
        !!kmErr1 && /unknown keymap/.test(kmErr1.message), kmErr1 && kmErr1.message);
    let kmErr2 = null;
    try { await m.applyKeymap('de;dropbear-keys=x'); } catch (e) { kmErr2 = e; }
    ok('applyKeymap rejects a malformed id (the id allow-list, before list membership)',
        !!kmErr2 && /invalid keymap id/.test(kmErr2.message), kmErr2 && kmErr2.message);
    let kmNoop = 'unset';
    try { kmNoop = await m.applyKeymap('us'); } catch (e) { kmNoop = 'ERR:' + e.message; }
    ok('a fresh device picking English (US) is a NO-OP (no write, no console restart)',
        kmNoop && typeof kmNoop === 'object' && !kmNoop.id, JSON.stringify(kmNoop));
    const kmPutN0 = state.confSets.length;
    const kmPut = await m.applyKeymap('de');
    ok('first-boot apply of German works WITHOUT a store login (root socket; the restart is the frame\'s, not snapd\'s)',
        kmPut && kmPut.id, JSON.stringify(kmPut));
    await new Promise((r) => setTimeout(r, 320)); // the stub conf change settles at 250ms
    let kmCur2 = 'unset';
    try { kmCur2 = await m.readKeymap(); } catch (e) { kmCur2 = 'ERR:' + e.message; }
    ok('after the apply the current layout reads back as de', kmCur2 === 'de', String(kmCur2));
    const kmLastPut = state.confSets[state.confSets.length - 1];
    ok('the socket payload went to ubuntu-frame as {config: \"keymap=de\"} (the documented snap set form)',
        kmLastPut && kmLastPut.name === 'ubuntu-frame'
        && JSON.stringify(kmLastPut.data) === JSON.stringify({ config: 'keymap=de' }),
        JSON.stringify(kmLastPut));
    ok('exactly ONE conf write for the whole first-boot sequence (the US no-op wrote nothing)',
        state.confSets.length === kmPutN0 + 1, String(state.confSets.length - kmPutN0));
    let kmSame = 'unset';
    try { kmSame = await m.applyKeymap('de'); } catch (e) { kmSame = 'ERR:' + e.message; }
    ok('re-applying the current layout is a no-op (idempotent: no second write)',
        kmSame && typeof kmSame === 'object' && !kmSame.id, JSON.stringify(kmSame));
    const kmDoc = await m.getSnapConfig('ubuntu-frame');
    ok('the frame conf doc now carries the config value (nested-doc read)',
        kmDoc && kmDoc.config === 'keymap=de', JSON.stringify(kmDoc));
    // restore the authenticated console (later sections write as the logged-in
    // store session) and stop modelling the root-socket grant.
    await m.storeLogin('admin@example.com', 'correct-horse');
    state.rootOk = false;

    console.log('\n[12] snap services (snapd /v2/apps — chunk 48a)');
    // The UI services backend: GET /v2/apps?select=service&names=<snap> ->
    // [{name, daemon, daemon-scope, active?, enabled?}] (active/enabled are
    // omitempty, present only when true — the client must not invent them).
    const svcs = await m.getSnapServices('llama-cpp');
    ok('services-get returns the service list', Array.isArray(svcs) && svcs.length === 1 && svcs[0].name === 'server', JSON.stringify(svcs));
    ok('service state fields are honest (active+enabled only when true)', svcs[0].active === true && svcs[0].enabled === true, JSON.stringify(svcs[0]));
    const noSvc = await m.getSnapServices('core24');
    ok('a snap without services -> [] (the 404 app-not-found maps to none)', Array.isArray(noSvc) && noSvc.length === 0, JSON.stringify(noSvc));
    let svErr = null;
    try { await m.getSnapServices('bad name!'); } catch (e) { svErr = e; }
    ok('reject invalid snap name for services before socket', !!svErr && /invalid snap name/.test(svErr.message), svErr && svErr.message);
    // Control: POST /v2/apps {action, names, enable?, disable?}. The stub
    // settles the service-control change and flips the service state per the
    // LIVE-verified coupling (start+enable sets both, stop+disable clears both,
    // plain start/stop only touch "running").
    await m.storeLogin('admin@example.com', 'correct-horse');
    const ch1 = await m.controlSnapService('llama-cpp', 'server', 'stop', {});
    ok('service stop returns a change id', ch1 && ch1.id, JSON.stringify(ch1));
    await new Promise((r) => setTimeout(r, 320));
    const st1 = await m.getSnapServices('llama-cpp');
    ok('stop keeps boot state (active off, enabled still true)', !st1[0].active && st1[0].enabled === true, JSON.stringify(st1[0]));
    const op1 = state.serviceOps[state.serviceOps.length - 1];
    ok('stop sent the live shape (no enable/disable flags)', op1 && op1.action === 'stop' && op1.enable === false && op1.disable === false && JSON.stringify(op1.names) === JSON.stringify(['llama-cpp.server']), JSON.stringify(op1));
    const ch2 = await m.controlSnapService('llama-cpp', 'server', 'stop', { disable: true });
    await new Promise((r) => setTimeout(r, 320));
    const st2 = await m.getSnapServices('llama-cpp');
    ok('stop+disable clears BOTH (the API coupling — no boot-only op exists)', !st2[0].active && !st2[0].enabled, JSON.stringify(st2[0]));
    const ch3 = await m.controlSnapService('llama-cpp', null, 'start', { enable: true });
    await new Promise((r) => setTimeout(r, 320));
    const st3 = await m.getSnapServices('llama-cpp');
    ok('start+enable (whole snap, bare name) sets BOTH', st3[0].active === true && st3[0].enabled === true, JSON.stringify(st3[0]));
    let badAct = null;
    try { await m.controlSnapService('llama-cpp', 'server', 'enable', {}); } catch (e) { badAct = e; }
    ok('reject an action the daemon has no op for (enable)', !!badAct && /invalid service action/.test(badAct.message), badAct && badAct.message);
    let badSvc = null;
    try { await m.controlSnapService('llama-cpp', '../etc', 'stop', {}); } catch (e) { badSvc = e; }
    ok('reject an invalid service name before socket', !!badSvc && /invalid service name/.test(badSvc.message), badSvc && badSvc.message);

    console.log('\n[13] timesync / NTP (timeserver-control interface, D-Bus timedate1)');
    {
        // pure helpers — the timesyncd.conf NTP= line parse/format
        const parse = m.parseTimesyncNtp;
        const format = m.formatTimesyncNtp;
        ok('parseTimesyncNtp reads NTP=', parse('[Time]\n#NTP=\nNTP=0.1.2.3\n') === '0.1.2.3');
        ok('parseTimesyncNtp null when no NTP= line', parse('[Time]\n#NTP=ntp.ubuntu.com\n') === null);
        ok('parseTimesyncNtp null for empty NTP=', parse('[Time]\nNTP=\n') === null);
        ok('formatTimesyncNtp rewrites an existing NTP= line', format('[Time]\nNTP=a.b\n#keep\n', 'x.y.z') === '[Time]\nNTP=x.y.z\n#keep\n');
        ok('formatTimesyncNtp replaces a commented-out NTP=', format('[Time]\n#NTP=old\n', 'new.host') === '[Time]\nNTP=new.host\n');
        ok('formatTimesyncNtp appends when no NTP= line', format('[Time]\n', 'h') === '[Time]\nNTP=h\n');
        ok('formatTimesyncNtp clearing re-comments the slot (timesyncd default)', format('[Time]\nNTP=old\n', '') === '[Time]\n#NTP=\n');
        ok('formatTimesyncNtp set then clear round-trips to commented', format(format('[Time]\n#NTP=\n', 'a.b'), '') === '[Time]\n#NTP=\n');

        // timesyncStatus via an INJECTED fake D-Bus transport (no live bus needed)
        m.__setTimesyncTransport(async (spec) => {
            if (spec.member === 'GetAll') return [{ NTPEnabled: { signature: 'b', value: true } }]; // Variant, as dbus-next returns
            if (spec.member === 'SetNTP') { global.__tsNtpSet = spec.body.slice(); global.__tsNtpSig = spec.signature; return []; }
            throw new Error('unexpected transport call: ' + spec.member);
        });
        const TS_CONF = fs.mkdtempSync(path.join(os.tmpdir(), 'ucm-ts-')) + '/timesyncd.conf';
        fs.writeFileSync(TS_CONF, '[Time]\nNTP=9.9.9.9\n');
        process.env.UCM_TIMESYNC_CONF = TS_CONF;
        const st = await m.timesyncStatus();
        ok('timesyncStatus reads NTP from the (Variant) property', st && st.ntp === true, JSON.stringify(st));
        ok('timesyncStatus reads the configured server from the conf', st && st.server === '9.9.9.9', JSON.stringify(st));
        await m.timesyncSetEnabled(false);
        ok('timesyncSetEnabled uses the "bb" SetNTP signature (use_ntp, interactive)',
            global.__tsNtpSig === 'bb', JSON.stringify(global.__tsNtpSig));
        ok('timesyncSetEnabled sends SetNTP(false, false)',
            Array.isArray(global.__tsNtpSet) && global.__tsNtpSet.length === 2
                && global.__tsNtpSet[0] === false && global.__tsNtpSet[1] === false,
            JSON.stringify(global.__tsNtpSet));
        await m.timesyncSetServer('1.1.1.1');
        ok('timesyncSetServer writes the conf NTP= line', fs.readFileSync(TS_CONF, 'utf8') === '[Time]\nNTP=1.1.1.1\n');
        let badTs = null;
        try { await m.timesyncSetEnabled('yes'); } catch (e) { badTs = e; }
        ok('timesyncSetEnabled rejects a non-boolean', !!badTs && /boolean/.test(badTs.message));
        m.__setTimesyncTransport(null);
        delete process.env.UCM_TIMESYNC_CONF;
        delete global.__tsNtpSet;
        delete global.__tsNtpSig;
        try { fs.rmSync(path.dirname(TS_CONF), { recursive: true, force: true }); } catch {}
    }

    console.log('\n[13.5] network devices (the network-control interface: ip / iw / resolvectl + netplan)');
    {
        // canned live tool output (the tools' absence is a dev-container reality —
        // the readers are injectable, so unit-test with canned bytes).
        const LINK = JSON.stringify([
            { ifname: 'lo', index: 1, flags: ['UP', 'LOOPBACK'], linkType: 'ether' },
            { ifname: 'eth0', index: 2, flags: ['UP', 'LOWER_UP'], linkType: 'ether' },
            { ifname: 'enp3s0', index: 3, flags: ['UP', 'LOWER_UP'], linkType: 'ether' },
            { ifname: 'br0', index: 4, kind: 'bridge', flags: [], linkType: 'ether' },
            { ifname: 'enp5s0', index: 5, flags: ['UP', 'LOWER_UP'], linkType: 'ether', master: 'br0' },
        ]);
        const ADDR = JSON.stringify([
            { ifname: 'eth0', addr_info: [
                { family: 'inet', local: '192.168.1.50', prefixlen: 24, scope: 'global' },
                { family: 'inet6', local: '2001:db8::50', prefixlen: 64, scope: 'global' },
                { family: 'inet6', local: 'fe80::1', prefixlen: 64, scope: 'link' },
            ] },
            { ifname: 'enp3s0', addr_info: [ { family: 'inet6', local: 'fe80::2', prefixlen: 64, scope: 'link' } ] },
        ]);
        // NOTE: the default-route JSON field is `gateway` (the probe that read
        // `gvia` came up empty).
        const ROUTE = JSON.stringify([ { dev: 'eth0', gateway: '192.168.1.1', protocol: 'dhcp' } ]);
        const RES = 'Global:\n\tLVS: no\n\nLink 2 (eth0)\n\tCurrent Scopes: none\n\tDNS Servers: 192.168.1.1\n\nLink 3 (enp3s0)\n\tDNS Servers: n/a\n';
        m.__setNetLive({
            link: async () => ({ ok: true, stdout: LINK }),
            addr: async () => ({ ok: true, stdout: ADDR }),
            route: async () => ({ ok: true, stdout: ROUTE }),
            iw: async () => ({ ok: false, stdout: '' }),
            dns: async () => ({ ok: true, stdout: RES }),
        });
        // round 57: hermetic global DNS — the fallback reads the
        // resolved-managed resolv.conf; pin it to a controlled temp file so
        // the suite does not depend on the dev machine's actual file
        // (restored to the default path at the end of this block).
        const GC = '/tmp/ucm-r57-gc.conf';
        fs.writeFileSync(GC, 'nameserver 10.0.2.3\nnameserver fd00::1\n');
        m.__setResolvConfPath(GC);

        // listNetDevices(): the merged LIVE per-device shape
        const dev0 = await m.listNetDevices();
        const d0 = (n) => dev0.find((d) => d.name === n);
        ok('loopback is not a card', !d0('lo'), dev0.map((d) => d.name).join(','));
        ok('eth0 type is ethernet + connected', d0('eth0') && d0('eth0').type === 'ethernet' && d0('eth0').connected === true);
        ok('eth0 addresses keep the v4 + the GLOBAL v6, drop the scope-link v6',
            d0('eth0') && JSON.stringify(d0('eth0').addresses) === JSON.stringify([
                { family: 'inet', cidr: '192.168.1.50/24' }, { family: 'inet6', cidr: '2001:db8::50/64' }]),
            d0('eth0') && JSON.stringify(d0('eth0').addresses));
        ok('enp3s0 (only a link-local v6) has NO displayable addresses',
            d0('enp3s0') && Array.isArray(d0('enp3s0').addresses) && d0('enp3s0').addresses.length === 0);
        ok('eth0 gateway comes from the `gateway` route key', d0('eth0') && d0('eth0').gateway === '192.168.1.1');
        ok('enp3s0 has no default route -> gateway null', d0('enp3s0') && d0('enp3s0').gateway === null);
        ok('the resolvectl text parse gives eth0 its DNS', d0('eth0') && JSON.stringify(d0('eth0').dns) === JSON.stringify(['192.168.1.1']));
        ok('a "n/a" DNS line is NOT a server (enp3s0: no per-link data -> the global fallback, never a literal n/a)',
            d0('enp3s0') && JSON.stringify(d0('enp3s0').dns) === JSON.stringify(['10.0.2.3', 'fd00::1'])
            && !d0('enp3s0').dns.includes('n/a'),
            d0('enp3s0') && JSON.stringify(d0('enp3s0').dns));
        ok('the kind=bridge link is typed bridge + not connected (no UP flag)',
            d0('br0') && d0('br0').type === 'bridge' && d0('br0').connected === false);
        ok('an enslaved device (master: br0) is NOT a card (it is a bridge member)',
            !d0('enp5s0'), dev0.map((d) => d.name).join(','));
        ok('the bridge card carries its LIVE members from the master field',
            d0('br0') && JSON.stringify(d0('br0').members) === JSON.stringify(['enp5s0']),
            d0('br0') && JSON.stringify(d0('br0').members));
        ok('an absent iw does not crash and yields no wifi', dev0.every((d) => d.type !== 'wifi'));

        // round 57: the resolv.conf fallback (the network-control
        // interface bug: resolvctl cannot read per-link DNS under the
        // plug) — the global list applies only where there is no
        // per-link data, and netplan dns wins over both (pass 3 below).
        fs.writeFileSync(GC, '# managed by resolved\n# Do not edit.\nnameserver 10.0.2.3\nsearch home.lan\nnameserver 10.0.2.3\nnameserver fd00::1\n\n');
        const devA = await m.listNetDevices();
        const a0 = (n) => devA.find((d) => d.name === n);
        ok('a device WITH per-link resolvctl DNS keeps it (the global list is not mixed in)',
            a0('eth0') && JSON.stringify(a0('eth0').dns) === JSON.stringify(['192.168.1.1']),
            a0('eth0') && JSON.stringify(a0('eth0').dns));
        ok('a device WITHOUT per-link DNS falls back to the global resolv.conf list (deduped, file order)',
            a0('enp3s0') && JSON.stringify(a0('enp3s0').dns) === JSON.stringify(['10.0.2.3', 'fd00::1'])
            && a0('br0') && JSON.stringify(a0('br0').dns) === JSON.stringify(['10.0.2.3', 'fd00::1']),
            a0('enp3s0') && JSON.stringify(a0('enp3s0').dns));
        ok('the dnsGlobal field carries the same list (the source is distinguishable from per-link)',
            a0('eth0') && JSON.stringify(a0('eth0').dnsGlobal) === JSON.stringify(['10.0.2.3', 'fd00::1']));
        fs.writeFileSync(GC, '');
        const devB = await m.listNetDevices();
        const b0 = (n) => devB.find((d) => d.name === n);
        ok('an EMPTY resolv.conf yields no DNS for the per-link-less devices (the card shows the dash, not garbage)',
            b0('enp3s0') && JSON.stringify(b0('enp3s0').dns) === JSON.stringify([])
            && b0('br0') && JSON.stringify(b0('br0').dns) === JSON.stringify([]));
        fs.writeFileSync(GC, 'nameserver 10.0.2.3\nnameserver fd00::1\n');
        m.__setNetLive({
            link: async () => ({ ok: true, stdout: LINK }),
            addr: async () => ({ ok: true, stdout: ADDR }),
            route: async () => ({ ok: true, stdout: ROUTE }),
            iw: async () => ({ ok: false, stdout: '' }),
            dns: async () => ({ ok: true, stdout: 'Global:\n\tLVS: no\n' }),
        });
        const devC = await m.listNetDevices();
        const c0 = (n) => devC.find((d) => d.name === n);
        ok('when resolvctl has NO per-link data (the interface bug) EVERY device shows the global list',
            ['eth0', 'enp3s0', 'br0'].every((n) => c0(n) && JSON.stringify(c0(n).dns) === JSON.stringify(['10.0.2.3', 'fd00::1'])),
            devC.map((d) => d.name + ':' + JSON.stringify(d.dns)).join(' '));
        const devAll = await m.getNetDevices();
        const z0 = (n) => devAll.find((d) => d.name === n);
        ok('end to end: getNetDevices (the renderer read) carries the fallback list through the netplan merge',
            z0('eth0') && JSON.stringify(z0('eth0').dns) === JSON.stringify(['10.0.2.3', 'fd00::1']));
        m.__setNetLive({
            link: async () => ({ ok: true, stdout: LINK }),
            addr: async () => ({ ok: true, stdout: ADDR }),
            route: async () => ({ ok: true, stdout: ROUTE }),
            iw: async () => ({ ok: false, stdout: '' }),
            dns: async () => ({ ok: true, stdout: RES }),
        });
        fs.unlinkSync(GC);
        m.__setResolvConfPath(null);

        // mergeNetplanDevices(): the configured overlay only — a netplan
        // entry with no live device (incl. a catch-all) creates NO card
        const merged = m.mergeNetplanDevices(dev0, { network: { version: 2,
            ethernets: { eth0: { dhcp4: true }, all: { dhcp4: true }, 'en*': { dhcp4: true, match: { name: 'en*' } } },
            bridges: { br0: { dhcp4: true, interfaces: ['enp3s0'] } },
            wifis: { wlp3s0: { dhcp4: true } } } });
        const mm = (n) => merged.find((d) => d.name === n);
        ok('a netplan-defined device is flagged configured + carries its def', mm('eth0') && mm('eth0').configured === true && mm('eth0').netplan.dhcp4 === true);
        ok('a netplan-only device (wlp3s0) does NOT create a card', !mm('wlp3s0'), mm('wlp3s0') && mm('wlp3s0').name);
        ok('a netplan-only catch-all (all) does NOT create a card', !mm('all'), mm('all') && mm('all').name);
        // a catch-all that COVERS a live device configures it (no card for
        // the catch-all itself; the live device inherits configured + def)
        ok('a catch-all (en*) covering enp3s0 flags it configured + carries the catch-all def',
            mm('enp3s0') && mm('enp3s0').configured === true && mm('enp3s0').netplan.dhcp4 === true,
            mm('enp3s0') && JSON.stringify(mm('enp3s0').netplan));
        ok('the catch-all id itself (en*) still creates no card', !mm('en*'), mm('en*') && mm('en*').name);
        // round 57: the netplan DNS overlay — netplan binds DNS to the
        // DEVICE (there are no system-wide DNS settings), so a
        // configured dns.nameservers wins over the live fallback.
        // NOTE: the `merged` call above mutates dev0 in place (merge sets
        // configured/netplan on the passed objects) - re-read the live list
        // so these asserts see the unmutated devices.
        const dev0f = await m.listNetDevices();
        ok('a named netplan dns.nameservers entry replaces the live dns (device-bound DNS wins)',
            (function () {
                const o = m.mergeNetplanDevices(
                    JSON.parse(JSON.stringify(dev0f)),
                    { network: { version: 2, ethernets: { eth0: { dhcp4: true, dns: { nameservers: { addresses: ['9.9.9.9'] } } } } } });
                const e = o.find((d) => d.name === 'eth0');
                return e && JSON.stringify(e.dns) === JSON.stringify(['9.9.9.9']);
            })());
        ok('a catch-all dns overlay wins over the live fallback for the covered device',
            (function () {
                const o = m.mergeNetplanDevices(
                    JSON.parse(JSON.stringify(dev0f)),
                    { network: { version: 2, ethernets: { 'en*': { dhcp4: true, match: { name: 'en*' }, dns: { nameservers: { addresses: ['1.1.1.1', '8.8.8.8'] } } } } } });
                const e = o.find((d) => d.name === 'enp3s0');
                return e && e.configured === true && JSON.stringify(e.dns) === JSON.stringify(['1.1.1.1', '8.8.8.8']);
            })());
        ok('a netplan entry WITHOUT dns never clobbers the live list (no nameservers -> live dns kept)',
            (function () {
                const o = m.mergeNetplanDevices(
                    JSON.parse(JSON.stringify(dev0f)),
                    { network: { version: 2, ethernets: { eth0: { dhcp4: true } } } });
                const e = o.find((d) => d.name === 'eth0');
                return e && JSON.stringify(e.dns) === JSON.stringify(['192.168.1.1']);
            })());
        // the global-list parser (unit): dedupe, order, comments, junk lines
        fs.writeFileSync('/tmp/ucm-r57-parse.conf', '# comment\n; another\nsearch foo\nnameserver  1.2.3.4\nnameserver 1.2.3.4\nnameserver 5.6.7.8\nnameserver\n');
        m.__setResolvConfPath('/tmp/ucm-r57-parse.conf');
        ok('readResolvConfNameservers parses nameserver lines (deduped, order kept, junk skipped)',
            JSON.stringify(m.readResolvConfNameservers()) === JSON.stringify(['1.2.3.4', '5.6.7.8']),
            JSON.stringify(m.readResolvConfNameservers()));
        m.__setResolvConfPath('/tmp/ucm-r57-missing.conf');
        ok('readResolvConfNameservers is total: a missing file gives [] (never throws)',
            JSON.stringify(m.readResolvConfNameservers()) === JSON.stringify([]));
        fs.unlinkSync('/tmp/ucm-r57-parse.conf');
        m.__setResolvConfPath(null);
        // glob + match semantics (fnmatch parity for the live-visible props)
        ok('netGlobMatch: * is a glob, ? one char, [!..] negation, bare text exact',
            m.netGlobMatch('en*', 'enp0s2') && m.netGlobMatch('en*', 'enp9') && m.netGlobMatch('eth?', 'eth0')
            && !m.netGlobMatch('eth?', 'eth00') && !m.netGlobMatch('en*', 'eth0')
            && m.netGlobMatch('[!e]*', 'wlp0s0') && !m.netGlobMatch('[!e]*', 'eth0')
            && m.netGlobMatch('eth0', 'eth0') && !m.netGlobMatch('eth0', 'eth1'),
            '');
        ok('netDefMatches: no match: never matches; name glob + mac; driver-only unmatchable',
            !m.netDefMatches({ dhcp4: true }, 'enp0s2', 'aa:bb')
            && m.netDefMatches({ match: { name: 'en*' } }, 'enp0s2', 'aa:bb')
            && m.netDefMatches({ match: { name: 'en*', macaddress: 'AA:BB' } }, 'enp0s2', 'aa:bb')
            && !m.netDefMatches({ match: { name: 'en*', macaddress: 'aa:cc' } }, 'enp0s2', 'aa:bb')
            && !m.netDefMatches({ match: { driver: 'e1000' } }, 'enp0s2', 'aa:bb'),
            '');

        // buildNetDeviceDef(): the canonical v2 builders + the rejections
        const bd = m.buildNetDeviceDef;
        ok('eth dhcp builds {dhcp4:true} in ethernets', (() => { const r = bd({ name: 'eth0', type: 'ethernet', mode: 'dhcp' }); return r.section === 'ethernets' && r.def.dhcp4 === true; })());
        const st = bd({ name: 'eth0', type: 'ethernet', mode: 'static', address: '192.168.1.99/24', gateway: '192.168.1.1', dns: ['1.1.1.1', '8.8.8.8'] });
        ok('eth static builds addresses + gateway4 + dns.nameservers',
            JSON.stringify(st.def.addresses) === JSON.stringify(['192.168.1.99/24']) && st.def.gateway4 === '192.168.1.1'
            && JSON.stringify(st.def.dns.nameservers.addresses) === JSON.stringify(['1.1.1.1', '8.8.8.8']));
        const wf = bd({ name: 'wlp3s0', type: 'wifi', mode: 'dhcp', ssid: 'HomeNet', password: 'secret123', hidden: true });
        ok('wifi builds access-points.<ssid>.password + hidden in wifis',
            wf.section === 'wifis' && wf.def['access-points'].HomeNet.password === 'secret123' && wf.def['access-points'].HomeNet.hidden === true);
        const br = bd({ name: 'br1', type: 'bridge', mode: 'static', address: '10.0.0.1/24', interfaces: ['eth0', 'enp3s0'] });
        ok('bridge builds interfaces[] + static in bridges',
            br.section === 'bridges' && JSON.stringify(br.def.interfaces) === JSON.stringify(['eth0', 'enp3s0']) && JSON.stringify(br.def.addresses) === JSON.stringify(['10.0.0.1/24']));
        const rej = (cfg, re) => { let e = null; try { bd(cfg); } catch (x) { e = x; } return e && re.test(e.message); };
        ok('REJECT bad device name', rej({ name: 'bad;rm', type: 'ethernet', mode: 'dhcp' }, /invalid device name/));
        ok('REJECT bad CIDR (999.x) in static mode', rej({ name: 'eth0', type: 'ethernet', mode: 'static', address: '999.1.1.1/24' }, /prefix/));
        ok('REJECT a bare (no-prefix) static address', rej({ name: 'eth0', type: 'ethernet', mode: 'static', address: '10.0.0.1' }, /prefix/));
        ok('REJECT a bad gateway', rej({ name: 'eth0', type: 'ethernet', mode: 'static', address: '10.0.0.1/24', gateway: 'not-an-ip' }, /gateway/));
        ok('REJECT a bad bridge member name', rej({ name: 'br1', type: 'bridge', mode: 'dhcp', interfaces: ['bad;rm'] }, /invalid bridge member/));
        ok('REJECT a wifi with no SSID', rej({ name: 'wlp3s0', type: 'wifi', mode: 'dhcp', ssid: '' }, /SSID/));
        ok('REJECT a wifi password shorter than 8', rej({ name: 'wlp3s0', type: 'wifi', mode: 'dhcp', ssid: 'HomeNet', password: 'short' }, /8-64/));
        ok('REJECT an unknown device type', rej({ name: 'x', type: 'banana', mode: 'dhcp' }, /unknown device type/));

        // netApplyDevice(): the FULL-doc read-modify-write through the stub.
        // Seed the default Core boilerplate (catch-alls only) so the first
        // edit is the boilerplate-replace case; wlp3s0 is NOT covered by
        // en*/eth* — its first edit still wipes the boilerplate (the first
        // device edit replaces what's there, whatever the device).
        state.netplan = { network: { version: 2, ethernets: { 'all-en': { dhcp4: true, match: { name: 'en*' } }, 'all-eth': { dhcp4: true, match: { name: 'eth*' } } } } };
        await m.netApplyDevice({ name: 'wlp3s0', type: 'wifi', mode: 'dhcp', ssid: 'HomeNet', password: 'secret123' });
        await new Promise((r) => setTimeout(r, 350));
        const netOf = () => ((state.netplan || {}).network) || {};
        let nw = netOf();
        ok('netApplyDevice(wifi) wrote the canonical access-points.password',
            nw.wifis && nw.wifis.wlp3s0 && nw.wifis.wlp3s0['access-points'] && nw.wifis.wlp3s0['access-points'].HomeNet
            && nw.wifis.wlp3s0['access-points'].HomeNet.password === 'secret123',
            JSON.stringify(nw.wifis));
        ok('the first edit wiped the ALL catch-all boilerplate (all-en + all-eth gone)',
            !nw.ethernets, JSON.stringify(nw.ethernets));
        // a SUBSEQUENT edit is additive (the first edit's entry is kept)
        await m.netApplyDevice({ name: 'enp3s0', type: 'ethernet', mode: 'dhcp' });
        await new Promise((r) => setTimeout(r, 350));
        nw = netOf();
        ok('a subsequent edit is additive (the first edit\u2019s wifis.wlp3s0 entry survives)',
            nw.wifis && nw.wifis.wlp3s0 && nw.wifis.wlp3s0['access-points'] && nw.wifis.wlp3s0['access-points'].HomeNet
            && nw.wifis.wlp3s0['access-points'].HomeNet.password === 'secret123'
            && nw.ethernets && JSON.stringify(nw.ethernets.enp3s0) === JSON.stringify({ dhcp4: true }),
            JSON.stringify(nw));
        // round 55 e2e: the MIXED doc (named + catch-all) — the named entry
        // is kept/updated, the boilerplate is stripped
        state.netplan = { network: { version: 2, ethernets: {
            'all-en': { dhcp4: true, match: { name: 'en*' } },
            enp9: { dhcp4: true },
        } } };
        await m.netApplyDevice({ name: 'enp9', type: 'ethernet', mode: 'static', address: '10.9.9.9/24' });
        await new Promise((r) => setTimeout(r, 350));
        nw = netOf();
        ok('mixed doc (e2e): the named entry is updated, the catch-all boilerplate is stripped',
            JSON.stringify(nw.ethernets) === JSON.stringify({ enp9: { addresses: ['10.9.9.9/24'] } }),
            JSON.stringify(nw.ethernets));
        // a device RE-TYPED leaves its old section (ethernet->wifi)
        await m.netApplyDevice({ name: 'enp9', type: 'wifi', mode: 'dhcp', ssid: 'Net', password: 'password123' });
        await new Promise((r) => setTimeout(r, 350));
        nw = netOf();
        ok('a re-typed device leaves its OLD section (ethernets.enp9 gone)', !nw.ethernets, JSON.stringify(nw.ethernets));
        ok('a re-typed device lands in its NEW section (wifis.enp9)', nw.wifis && nw.wifis.enp9 && nw.wifis.enp9['access-points'] && nw.wifis.enp9['access-points'].Net, JSON.stringify(nw.wifis));
        ok('version: 2 is preserved across the re-write', nw.version === 2, String(nw.version));
        // an emptied section is DROPPED (the doc must not carry "ethernets: {}")
        const ethKeys = nw.ethernets && Object.keys(nw.ethernets).length;
        if (ethKeys) {
            const last = Object.keys(nw.ethernets)[0];
            await m.netApplyDevice({ name: last, type: 'bridge', mode: 'dhcp', interfaces: ['enp3s0'] });
            await new Promise((r) => setTimeout(r, 350));
            nw = netOf();
            ok('an emptied section is dropped from the doc', !nw.ethernets, JSON.stringify(nw.ethernets));
        } else {
            ok('an emptied section is dropped from the doc (already none)', !nw.ethernets);
        }

        m.__setNetLive(null);
    }

    console.log('\n[14] ip forwarding (network-control interface, /proc sysctl nodes)');
    {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ucm-ipfwd-'));
        const node = (n) => path.join(dir, n);
        ['ip_forward', 'v6all', 'v6default'].forEach((n) => fs.writeFileSync(node(n), '0\n'));
        const PREF = path.join(dir, 'ipforward.pref');
        process.env.UCM_IPFWD_PREF = PREF;
        m.__setIpfwdNodes({ v4: node('ip_forward'), v6: node('v6all'), v6default: node('v6default') });

        let st = await m.ipfwdStatus();
        ok('ipfwdStatus reads the live nodes (off by default)',
            st && st.v4 === false && st.v6 === false && st.on === false && st.pref === false, JSON.stringify(st));
        await m.ipfwdSet(true);
        ok('ipfwdSet(true) writes ALL THREE forwarding nodes (v4 + v6 all/default)',
            fs.readFileSync(node('ip_forward'), 'utf8').trim() === '1'
            && fs.readFileSync(node('v6all'), 'utf8').trim() === '1'
            && fs.readFileSync(node('v6default'), 'utf8').trim() === '1');
        st = await m.ipfwdStatus();
        ok('ipfwdSet(true) persists the preference (on)', st.pref === true, JSON.stringify(st));
        st = await m.ipfwdStatus();
        ok('ipfwdStatus reflects the live state after set', st.on === true && st.pref === true, JSON.stringify(st));
        await m.ipfwdSet(false);
        ok('ipfwdSet(false) clears the nodes (v4 + v6 all/default)',
            fs.readFileSync(node('ip_forward'), 'utf8').trim() === '0'
            && fs.readFileSync(node('v6all'), 'utf8').trim() === '0'
            && fs.readFileSync(node('v6default'), 'utf8').trim() === '0');
        st = await m.ipfwdStatus();
        ok('ipfwdSet(false) clears the preference (off)', st.pref === false, JSON.stringify(st));
        // boot re-apply: a stored "on" wins over the kernel-default (off) state
        fs.writeFileSync(PREF, 'on');
        ['ip_forward', 'v6all', 'v6default'].forEach((n) => fs.writeFileSync(node(n), '0\n'));
        await m.ipfwdApplyPref();
        ok('ipfwdApplyPref re-applies a stored "on" at startup',
            fs.readFileSync(node('ip_forward'), 'utf8').trim() === '1'
            && fs.readFileSync(node('v6default'), 'utf8').trim() === '1');
        // ...and an "off" pref never forces the nodes off (non-destructive)
        fs.writeFileSync(PREF, 'off');
        ['ip_forward', 'v6all', 'v6default'].forEach((n) => fs.writeFileSync(node(n), '1\n'));
        await m.ipfwdApplyPref();
        ok('ipfwdApplyPref never forces nodes OFF (a stale pref is not destructive)',
            fs.readFileSync(node('ip_forward'), 'utf8').trim() === '1'
            && fs.readFileSync(node('v6all'), 'utf8').trim() === '1');
        // a missing/unreadable node degrades to null, not a throw
        fs.rmSync(node('v6all'));
        st = await m.ipfwdStatus();
        ok('ipfwdStatus degrades to null when a node is unreadable', st.v6 === null && st.on === null, JSON.stringify(st));
        let badFw = null;
        try { await m.ipfwdSet('yes'); } catch (e) { badFw = e; }
        ok('ipfwdSet rejects a non-boolean', !!badFw && /boolean/.test(badFw.message));
        // the boot re-apply must be WIRED into app startup as an UNCOMMENTED
        // call (a commented-out or removed call must FAIL this, not just a
        // substring match)
        const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');
        const bootCall = mainSrc.split(/\r?\n/).some((l) =>
            /ipfwdApplyPref\(\)/.test(l) && !/^\s*\/\//.test(l) && !/function ipfwdApplyPref/.test(l));
        ok('app startup re-applies the ip-forwarding pref (uncommented ipfwdApplyPref() call)',
            bootCall, 'no uncommented ipfwdApplyPref() call found in main.js');

        m.__setIpfwdNodes(null);
        delete process.env.UCM_IPFWD_PREF;
        try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
    }

    // 48c2: every shipped icon asset must be WELL-FORMED XML. Chromium (the
    // renderer + the harness) parses SVG-in-<img> leniently and will happily
    // render a file with an undefined namespace prefix, but strict parsers
    // (librsvg / eog / the kiosk image stack) FATAL on it — the round-48c
    // suru-document.svg bug (kept inkscape: attrs on an svg-only root) drew
    // blank. Guard the class, not just the one file.
    const svgs = fs.readdirSync(path.join(__dirname, '..', 'build', 'images')).filter((f) => f.endsWith('.svg'));
    ok('shipped SVG assets exist', svgs.length >= 10, svgs.join(', '));

    console.log('\n[15] netplan seed boilerplate clearing (network-setup-control, the 00-snapd-config.yaml delete)');
    {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ucm-netseed-'));
        const seed = (n) => path.join(dir, n);
        // a catch-all seed (the default Core 00 file) IS removed
        fs.writeFileSync(seed('00-snapd-config.yaml'),
            'network:\n  version: 2\n  ethernets:\n    all-en:\n      dhcp4: true\n      match:\n        name: en*\n    all-eth:\n      dhcp4: true\n      match:\n        name: eth*\n');
        m.__setNetSeedPath(seed('00-snapd-config.yaml'));
        ok('clearNetSeedBoilerplate removes a catch-all (match:) seed file',
            m.clearNetSeedBoilerplate() === 'removed' && !fs.existsSync(seed('00-snapd-config.yaml')),
            '');
        // an absent file is a no-op (never throws)
        m.__setNetSeedPath(seed('does-not-exist.yaml'));
        ok('clearNetSeedBoilerplate is a no-op on a missing file', m.clearNetSeedBoilerplate() === 'absent', '');
        // a hand-authored 00 file with only NAMED entries (no match:) is KEPT
        fs.writeFileSync(seed('00-custom.yaml'),
            'network:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: true\n      addresses:\n        - 10.0.0.5/24\n');
        m.__setNetSeedPath(seed('00-custom.yaml'));
        ok('clearNetSeedBoilerplate KEEPS a 00 file with no catch-all (named-only) config',
            m.clearNetSeedBoilerplate() === 'kept' && fs.existsSync(seed('00-custom.yaml')),
            '');
        // the snap declares the network-setup-control plug (the /etc/netplan
        // rw that the delete needs)
        const sc = fs.readFileSync(path.join(__dirname, '..', 'snap', 'snapcraft.yaml'), 'utf8');
        ok('the snap declares the network-setup-control plug as a plug-list entry (the /etc/netplan rw)',
            /\s+-\s+network-setup-control\s*($|\n)/m.test(sc), '');
        // the delete is exposed on the authed bridge AND called by the UI only
        // after the apply change has reached Done (the 48a idiom) — a failed /
        // rolled-back apply must leave the first-boot seed in place.
        const appSrc = fs.readFileSync(path.join(__dirname, '..', 'ui', 'app.js'), 'utf8');
        const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');
        ok('the net:clear-seed bridge handler is registered (authed)',
            mainSrc.includes("ipcMain.handle('net:clear-seed'") && mainSrc.includes('requireAuth(); return clearNetSeedBoilerplate()'),
            '');
        // the clear must sit in the SUCCESS branch (the else after the status
        // gate), not the failure branch — extract the else-block text and look
        // there, so a clear-on-failure mutation is caught.
        const elseIdx = appSrc.indexOf("if (!ok) toast('negative'");
        const elseBranch = elseIdx !== -1 ? appSrc.slice(elseIdx, elseIdx + 1200) : '';
        const elseBlock = elseBranch.slice(elseBranch.indexOf('else {'));
        ok('the UI clears the seed ONLY in the success (else) branch, gated on the change status',
            elseIdx !== -1 && elseBlock.includes("core.network.clearSeed")
            && elseBranch.slice(0, elseBranch.indexOf('else {')).indexOf('clearSeed') === -1,
            '');
        // e2e: a device edit PUTs the doc; the (renderer-gated) clear then
        // removes the seed — together they leave the box with the user's
        // config and no catch-alls.
        fs.writeFileSync(seed('00-snapd-config.yaml'),
            'network:\n  version: 2\n  ethernets:\n    all-en:\n      dhcp4: true\n      match:\n        name: en*\n');
        m.__setNetSeedPath(seed('00-snapd-config.yaml'));
        state.netplan = { network: { version: 2, ethernets: { 'all-en': { dhcp4: true, match: { name: 'en*' } } } } };
        await m.netApplyDevice({ name: 'enp7', type: 'ethernet', mode: 'dhcp' });
        // the stub settles the async 202 ~350ms later (same wait as [6]/[13.5])
        await new Promise((r) => setTimeout(r, 350));
        // round 55 keeps the app-side strip, so the SENT doc already has no
        // catch-all; the file delete (round 56) is what removes it from the
        // on-disk 00 file that snapd would otherwise re-merge.
        ok('the device edit itself is intact (the 90-side doc carries the device, no catch-alls)',
            state.netplan && state.netplan.network && state.netplan.network.ethernets
            && JSON.stringify(state.netplan.network.ethernets) === JSON.stringify({ enp7: { dhcp4: true } }),
            JSON.stringify(state.netplan));
        // the renderer now observes the change as Done and clears the seed
        const chg = state.changes[state.changes.length - 1];
        ok('the apply change reached Done in the stub (the UI would proceed to clear)',
            chg && chg.status === 'Done', JSON.stringify(chg));
        ok('the successful clear removes the 00 seed file (e2e)',
            m.clearNetSeedBoilerplate() === 'removed' && !fs.existsSync(seed('00-snapd-config.yaml')),
            '');
        m.__setNetSeedPath(null);
        fs.rmSync(dir, { recursive: true, force: true });
    }

    console.log('\n[16] inactivity lock timeout (configurable, round 66)');
    {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ucm-locktimeout-'));
        const PREF = path.join(dir, 'lock-timeout.pref');
        process.env.UCM_LOCK_TIMEOUT_PREF = PREF;
        // read the pref defensively — a no-write regression must FAIL cleanly,
        // not crash on a missing file (the round-51 null-safe-read rule).
        const readPref = () => { try { return fs.readFileSync(PREF, 'utf8'); } catch { return null; } };
        // getLockTimeout reflects the pref file (missing -> the shipped default).
        let gt = m.getLockTimeout();
        ok('no pref file -> the shipped default (15 min)',
            gt.value === '15' && gt.ms === 15 * 60000, JSON.stringify(gt));
        ok('the allowed set is 5/10/15/30/60/off (the user\'s exact options)',
            JSON.stringify(m.LOCK_TIMEOUTS) === JSON.stringify(['5', '10', '15', '30', '60', 'off'])
            && m.DEFAULT_LOCK_TIMEOUT === '15', JSON.stringify(m.LOCK_TIMEOUTS));
        // each offered value -> the right ms
        for (const [v, min] of [['5', 5], ['10', 10], ['15', 15], ['30', 30], ['60', 60]]) {
            const r = m.setLockTimeout(v);
            ok('setLockTimeout(' + JSON.stringify(v) + ') -> ' + min + ' min',
                r.value === v && r.ms === min * 60000 && readPref() === v, JSON.stringify(r));
        }
        // 'off' -> ms null (no auto-lock)
        const rOff = m.setLockTimeout('off');
        ok('setLockTimeout("off") -> ms null + the pref persists',
            rOff.ms === null && readPref() === 'off', JSON.stringify(rOff));
        // get reflects the stored pref
        ok('getLockTimeout reads the stored pref (off)', m.getLockTimeout().value === 'off', '');
        // invalid values throw and leave the pref untouched
        for (const bad of ['7', '', 'off ', 'OFF', 30, '30.5']) {
            let threw = false;
            try { m.setLockTimeout(bad); } catch (e) { threw = /invalid lock timeout/.test(e.message); }
            ok('setLockTimeout rejects ' + JSON.stringify(bad), threw && m.getLockTimeout().value === 'off');
        }
        delete process.env.UCM_LOCK_TIMEOUT_PREF;
        fs.rmSync(dir, { recursive: true, force: true });
    }

    console.log('\n[17] appearance (light/dark theme, round A)');
    {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ucm-appearance-'));
        const PREF = path.join(dir, 'appearance.pref');
        process.env.UCM_APPEARANCE_PREF = PREF;
        const readPref = () => { try { return fs.readFileSync(PREF, 'utf8'); } catch { return null; } };
        // no pref -> the shipped default (dark — round T-fix13)
        let ga = m.getAppearance();
        ok('no pref file -> the shipped default (dark)',
            ga.value === 'dark' && ga.default === 'dark', JSON.stringify(ga));
        ok('the allowed set is light/dark',
            JSON.stringify(m.APPEARANCES) === JSON.stringify(['light', 'dark'])
            && m.DEFAULT_APPEARANCE === 'dark', JSON.stringify(m.APPEARANCES));
        // set to light -> persisted + reflected (the user can still choose light)
        const rLight = m.setAppearance('light');
        ok('setAppearance("light") persists + reflects',
            rLight.value === 'light' && readPref() === 'light', JSON.stringify(rLight));
        ok('getAppearance reads the stored pref (light)', m.getAppearance().value === 'light', '');
        // set back to the default
        const rDark = m.setAppearance('dark');
        ok('setAppearance("dark") persists + reflects',
            rDark.value === 'dark' && readPref() === 'dark', JSON.stringify(rDark));
        // invalid values throw and leave the pref untouched
        for (const bad of ['blue', '', 'DARK', 'dark ', 1, null]) {
            let threw = false;
            try { m.setAppearance(bad); } catch (e) { threw = /invalid appearance/.test(e.message); }
            ok('setAppearance rejects ' + JSON.stringify(bad), threw && m.getAppearance().value === 'dark');
        }
        delete process.env.UCM_APPEARANCE_PREF;
        fs.rmSync(dir, { recursive: true, force: true });
    }

    console.log('\n[18] local pages (embedded localhost web UIs, round I)');
    {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ucm-localpages-'));
        const PREF = path.join(dir, 'local-pages.pref');
        process.env.UCM_LOCAL_PAGES_PREF = PREF;
        const readPref = () => { try { return JSON.parse(fs.readFileSync(PREF, 'utf8')); } catch { return null; } };
        // no pref -> empty (a fresh console has no local pages)
        ok('no pref file -> an empty local-pages list',
            JSON.stringify(m.getLocalPages().list) === JSON.stringify([]), JSON.stringify(m.getLocalPages()));
        // the url boundary (loopback only)
        ok('validLocalPageUrl accepts localhost / 127.0.0.1 / ::1 (any port/path)',
            m.validLocalPageUrl('http://localhost:8123') === true
            && m.validLocalPageUrl('http://127.0.0.1:3000/x') === true
            && m.validLocalPageUrl('https://[::1]:8080') === true, '');
        ok('validLocalPageUrl REJECTS non-loopback hosts (the security boundary)',
            m.validLocalPageUrl('http://10.0.0.5:8080') === false
            && m.validLocalPageUrl('http://192.168.1.1') === false
            && m.validLocalPageUrl('http://8.8.8.8') === false
            && m.validLocalPageUrl('http://example.com') === false, '');
        ok('validLocalPageUrl REJECTS non-http schemes',
            m.validLocalPageUrl('ftp://localhost:21') === false
            && m.validLocalPageUrl('file:///etc/passwd') === false
            && m.validLocalPageUrl('javascript:alert(1)') === false, '');
        ok('validLocalPageName: 1..40 chars, trims whitespace',
            m.validLocalPageName('  HA  ') === true && m.validLocalPageName('') === false
            && m.validLocalPageName('x'.repeat(41)) === false, '');
        // set a valid list -> persists + reflects
        const rSet = m.setLocalPages([{ name: 'HA', url: 'http://localhost:8123' }, { name: 'Grafana', url: 'http://127.0.0.1:3000' }]);
        ok('setLocalPages persists + reflects',
            rSet.list.length === 2 && rSet.list[0].name === 'HA'
            && readPref() && readPref().length === 2, JSON.stringify(rSet));
        ok('getLocalPages reads the stored pref',
            JSON.stringify(m.getLocalPages().list.map((e) => e.name)) === JSON.stringify(['HA', 'Grafana']), '');
        // invalid values throw and leave the pref untouched
        const cases = [
            ['a non-loopback url', [{ name: 'X', url: 'http://10.0.0.5:8080' }], /invalid local pages: invalid url/],
            ['a non-http scheme', [{ name: 'X', url: 'ftp://localhost' }], /invalid local pages: invalid url/],
            ['an empty name', [{ name: '   ', url: 'http://localhost:1' }], /invalid local pages: invalid name/],
            ['a duplicate name (case-insensitive)', [{ name: 'A', url: 'http://localhost:1' }, { name: 'a', url: 'http://localhost:2' }], /duplicate name/],
            ['a non-array', 'nope', /not a list/],
            ['too many entries (>10)', Array.from({ length: 11 }, (_, k) => ({ name: 'p' + k, url: 'http://localhost:' + k })), /too many local pages/],
        ];
        for (const [label, bad, re] of cases) {
            let threw = false;
            try { m.setLocalPages(bad); } catch (e) { threw = re.test(e.message); }
            ok('setLocalPages rejects ' + label,
                threw && JSON.stringify(m.getLocalPages().list.map((e) => e.name)) === JSON.stringify(['HA', 'Grafana']));
        }
        // round J: the local-page self-signed TLS policy (LXD's
        // https://127.0.0.1:8443). The handler is attached ONLY to the guest
        // partition session (see the [10] handler check below), so the unit
        // policy is: the error class AND a loopback request host.
        const cert = (url, error) => m.localPagesAllowSelfSignedCert({ url, error });
        ok('allow: the REAL chromium error format (net::ERR_ prefix) on loopback (the LXD case)',
            cert('https://127.0.0.1:8443', 'net::ERR_CERT_AUTHORITY_INVALID') === true
            && cert('https://127.0.0.1:8443', 'net::ERR_CERT_COMMON_NAME_INVALID') === true, '');
        ok('allow: self-signed / invalid-authority / invalid-CN on loopback (the LXD case)',
            cert('https://127.0.0.1:8443', 'CERT_SELF_SIGNED') === true
            && cert('https://127.0.0.1:8443', 'CERT_AUTHORITY_INVALID') === true
            && cert('https://127.0.0.1:8443', 'CERT_COMMON_NAME_INVALID') === true
            && cert('https://localhost:8443', 'CERT_SELF_SIGNED') === true
            && cert('https://[::1]:8443', 'CERT_SELF_SIGNED') === true, '');
        ok('deny: the same errors on a NON-loopback host (no blanket allowance)',
            cert('https://10.0.0.5:8443', 'CERT_SELF_SIGNED') === false
            && cert('https://192.168.1.10:8443', 'CERT_AUTHORITY_INVALID') === false
            && cert('https://example.com', 'CERT_SELF_SIGNED') === false, '');
        ok('deny: other cert errors (expired/revoked) — a self-signed UI is not an expired-corpse excuse',
            cert('https://127.0.0.1:8443', 'CERT_DATE_INVALID') === false
            && cert('https://127.0.0.1:8443', 'CERT_REVOKED') === false, '');
        ok('deny: a malformed details payload (never proceed)',
            m.localPagesAllowSelfSignedCert(null) === false
            && m.localPagesAllowSelfSignedCert({ url: 'not a url', error: 'CERT_SELF_SIGNED' }) === false
            && m.localPagesAllowSelfSignedCert({ url: 'https://127.0.0.1:8443' }) === false, '');

        // an empty list is valid (clearing everything)
        const rClear = m.setLocalPages([]);
        ok('setLocalPages([]) clears the list', rClear.list.length === 0 && readPref() !== null, JSON.stringify(rClear));
        delete process.env.UCM_LOCAL_PAGES_PREF;
        fs.rmSync(dir, { recursive: true, force: true });
    }

    console.log('\n[19] system page (round L: journal / refresh schedule / power)');
    {
        // ---- journal argv builder (pure) ----
        const jArgs = (o) => m.journalArgs(o);
        ok('journalArgs: the default read is UNBOUNDED (the full journal - no -n; round O: a search/filter must span the WHOLE journal, the bounded 200-line tail is a view choice)',
            !jArgs({}).includes('-n') && JSON.stringify(jArgs({})) === JSON.stringify(['--no-pager', '--output=short-iso']));
        ok('journalArgs: unit + match + priority + lines are all threaded (match = a GREP pattern via -g, round N)',
            JSON.stringify(jArgs({ unit: 'snapd', match: 'foo bar', pri: 'err', lines: 50 }))
                === JSON.stringify(['--no-pager', '--output=short-iso', '-n', '50', '-p', 'err', '-u', 'snapd', '-g', 'foo bar']));
        ok('journalArgs: the match is ALWAYS passed via -g (never as a positional MATCH - a bare positional word is an INVALID match: "Failed to add match" - the round-N bug) AND spans the full journal (no -n)',
            JSON.stringify(jArgs({ match: 'systemd' })) === JSON.stringify(['--no-pager', '--output=short-iso', '-g', 'systemd'])
            && (() => { const a2 = jArgs({ unit: 'u', match: 'm' }); const i = a2.lastIndexOf('m'); return a2[i - 1] === '-g'; })());
        ok('journalArgs: follow adds -f', jArgs({ follow: true }).includes('-f') && jArgs({}).includes('-f') === false);
        const nOf = (args) => args.includes('-n') ? args[args.indexOf('-n') + 1] : null;
        ok('journalArgs: the line count is clamped (0/junk -> the 200 default, >100000 capped; null/absent = UNBOUNDED - no -n)',
            nOf(jArgs({ lines: 0 })) === '200' && nOf(jArgs({ lines: 9999999 })) === '100000'
            && nOf(jArgs({ lines: 'junk' })) === '200' && nOf(jArgs({ lines: 55 })) === '55'
            && nOf(jArgs({ lines: null })) === null && nOf(jArgs({})) === null);

        // ---- journalTail e2e (an INJECTED fake journalctl binary — the house
        //      ip/resolvctl-injection idiom; the real binary is the log-observe
        //      grant, exercised on the VM, never here) ----
        const JDIR = fs.mkdtempSync(path.join(os.tmpdir(), 'ucm-j-'));
        const goodStub = path.join(JDIR, 'journalctl-good');
        fs.writeFileSync(goodStub, '#!/bin/sh\necho "2026-11-14T08:00:01Z host unit[1]: line one"\necho "2026-11-14T08:00:02Z host unit[1]: line two"\n', { mode: 0o755 });
        m.__setJournalBinary(goodStub);
        const jt = await m.journalTail({});
        ok('journalTail: runs the injected binary and returns the lines', jt.ok === true && jt.lines.length === 2 && jt.lines[1] === '2026-11-14T08:00:02Z host unit[1]: line two', JSON.stringify(jt));
        const badStub = path.join(JDIR, 'journalctl-bad');
        fs.writeFileSync(badStub, '#!/bin/sh\necho "No such unit" >&2\nexit 1\n', { mode: 0o755 });
        m.__setJournalBinary(badStub);
        const jt2 = await m.journalTail({ unit: 'nope' });
        ok('journalTail: a failing binary is a clean { ok:false, error } (never throws)', jt2.ok === false && jt2.lines.length === 0 && /No such unit/.test(jt2.error), JSON.stringify(jt2));
        m.__setJournalBinary(null);
        // round O: a HUNG read is a clean { ok:false } on its timeout budget - the
        // BOUNDED tail gets the fast one, the UNBOUNDED full-journal read the slow
        // one (an unbounded read streams the whole journal and legitimately takes
        // longer on a busy box). Shrunk via the injectable timeouts.
        const hangStub = path.join(JDIR, 'journalctl-hang');
        fs.writeFileSync(hangStub, '#!/bin/sh\nsleep 5\n', { mode: 0o755 });
        m.__setJournalBinary(hangStub);
        m.__setJournalTimeouts(150, 300);
        const jtHang = await m.journalTail({ lines: 10 }); // bounded -> the fast budget
        ok('journalTail: a hung BOUNDED read is a clean { ok:false } on the fast timeout (round O)', jtHang.ok === false && jtHang.lines.length === 0, JSON.stringify(jtHang));
        const jtHang2 = await m.journalTail({});           // unbounded -> the slow budget
        ok('journalTail: a hung UNBOUNDED read is a clean { ok:false } on the slow timeout (round O)', jtHang2.ok === false && jtHang2.lines.length === 0, JSON.stringify(jtHang2));
        // the UNBOUNDED read must actually get the SLOW budget (a read that takes
        // 3s SUCCEEDS under the slow one and would be killed under the fast).
        const slowStub = path.join(JDIR, 'journalctl-slow');
        fs.writeFileSync(slowStub, '#!/bin/sh\nsleep 3\necho "2026-11-14T08:00:01Z host unit[1]: slow read done"\n', { mode: 0o755 });
        m.__setJournalBinary(slowStub);
        m.__setJournalTimeouts(1500, 4000);
        const jtSlow = await m.journalTail({});           // unbounded -> survives the 4s budget
        ok('journalTail: an UNBOUNDED read completes on the slow budget (a bounded read of the same duration would be killed; round O)', jtSlow.ok === true && jtSlow.lines.length === 1, JSON.stringify(jtSlow));
        m.__setJournalTimeouts(8000, 60000);
        fs.rmSync(JDIR, { recursive: true, force: true });

        // ---- the refresh.timer validator (round S+4: the STRUCTURED schedule,
        //      mirrors snapd timeutil.ParseSchedule EXACTLY - the cases below are
        //      drawn from snapd's own TestParseSchedule table) ----
        const vt = (v) => m.validRefreshTimer(v);
        ok('refresh timer: a lone time / range / split / spread are all valid',
            vt('9:00') === true && vt('9:00-11:00') === true && vt('9:00-11:00/2') === true && vt('9:00~11:00') === true);
        ok('refresh timer: weekdays (single / range / nth / wrap) are valid',
            vt('mon') === true && vt('mon-wed') === true && vt('mon5') === true && vt('fri-mon') === true && vt('mon-mon2,9:00') === true);
        ok('refresh timer: weekday + time combine (days then window)',
            vt('mon,9:00-11:00') === true && vt('mon-wed,fri,9:00-11:00/2') === true && vt('mon-fri,09:00-17:00') === true);
        ok('refresh timer: multiple event sets join with ,, (and a lone ,, set)',
            vt('9:00-11:00,,20:00-22:00') === true && vt('mon,9:00-11:00,,wed,22:00-23:00') === true && vt('mon,,wed') === true);
        ok('refresh timer: the built-in default (spread + split) parses', vt('00:00~24:00/4') === true);
        ok('refresh timer: malformed values are REJECTED (from snapd ParseSchedule table)',
            vt('09:00-25:00') === false && vt('09:00-24:30') === false && vt('02:60-06:00') === false && vt('25:00-06:00') === false
            && vt('9:00-11:00/0') === false && vt('9:00-11:00/3/3/3') === false && vt('9:00-11:00/invalid') === false
            && vt('mon-01:00') === false && vt('9:00,mon') === false && vt('mon~wed') === false && vt('mon--wed') === false
            && vt('mon9,9:00') === false && vt('mon0,9:00') === false && vt('mon5-mon1,9:00') === false && vt('foo2,9:00') === false
            && vt('-') === false && vt('~/4') === false && vt(',,') === false && vt('') === false && vt('abc') === false
            && vt(null) === false && vt(5) === false);
        ok('refresh timer: "managed" is NOT a timer grammar value (rejected as input)', vt('managed') === false);
        // the ACCEPTED-state flag (the read-back / UI 'valid'): '' default, 'managed',
        // and any valid structured timer are accepted; absent (null) is the default.
        ok('refresh timer accepted-state: the empty string, managed, a valid timer, and absent are all accepted',
            m.isRefreshTimerAccepted('') === true && m.isRefreshTimerAccepted('managed') === true
            && m.isRefreshTimerAccepted('mon-fri,09:00-17:00') === true && m.isRefreshTimerAccepted(null) === true
            && m.isRefreshTimerAccepted('09:00-25:00') === false);

        // ---- the doc-shape-robust refresh.timer read (round 48f nested JSON) ----
        const rd = (d) => m.refreshTimerFromDoc(d);
        ok('timer read: flat dotted key', rd({ 'refresh.timer': 'mon-fri,09:00-17:00' }) === 'mon-fri,09:00-17:00');
        ok('timer read: the NESTED path (snapd stores dotted keys nested)', rd({ refresh: { timer: 'mon-fri,09:00-17:00' } }) === 'mon-fri,09:00-17:00');
        ok('timer read: absent = null (the default state)', rd({ system: { hostname: 'x' } }) === null && rd(null) === null && rd({}) === null);

        // ---- the (st) ScheduledShutdown parse ("" + max = none) ----
        const ps = (v) => m.powerScheduledParse(v);
        const none = ps(['', Number.MAX_SAFE_INTEGER]);
        ok('scheduled: the empty + max-usec value is "none"', none.active === false && none.action === null);
        const on = ps(['reboot', 1794625200000000]);
        ok('scheduled: a real (mode, usec) pair is active', on.active === true && on.action === 'reboot' && on.usec === 1794625200000000);
        const wrapped = ps({ signature: '(st)', value: ['poweroff', 123456789000000] });
        ok('scheduled: the Variant-wrapped struct (as dbus-next returns it) unwraps', wrapped.active === true && wrapped.action === 'poweroff');
        ok('scheduled: garbage never crashes (degrades to none)', ps(null).active === false && ps(['x']).active === false && ps({}).active === false);

        // ---- the ScheduleShutdown 'when' value (CLOCK_REALTIME usec) ----
        const when = m.shutdownWhenUsec(1794625200123);
        ok('shutdown when: ms -> absolute CLOCK_REALTIME usec', when === 1794625200123000);
        let badWhen = null;
        try { m.shutdownWhenUsec('soon'); } catch (e) { badWhen = e; }
        ok('shutdown when: a non-numeric time is rejected', !!badWhen && /invalid/i.test(badWhen.message));

        // ---- the login1 D-Bus calls (INJECTED transport — the 49h
        //      signature-verification idiom; the real calls run on the VM) ----
        const calls = [];
        let fakeSched = null; // the transport's live scheduled state (models logind)
        m.__setLogin1Transport(async (spec) => {
            calls.push(spec);
            if (spec.member === 'ScheduleShutdown') { fakeSched = spec.body.slice(); return []; }
            if (spec.member === 'CancelScheduledShutdown') {
                const had = !!fakeSched;
                fakeSched = null;
                return [{ signature: 'b', value: had }];
            }
            if (spec.member === 'Get' && spec.body && spec.body[1] === 'ScheduledShutdown') {
                return fakeSched ? [fakeSched] : ['', 18446744073709551616]; // the uint64-max sentinel, precision-lost
            }
            return [];
        });
        await m.powerAction('reboot');
        ok('power: Reboot sends the "b" signature with interactive=false (the privileged-snap call)',
            calls.length === 1 && calls[0].destination === 'org.freedesktop.login1'
            && calls[0].interface === 'org.freedesktop.login1.Manager' && calls[0].member === 'Reboot'
            && calls[0].signature === 'b' && JSON.stringify(calls[0].body) === JSON.stringify([false]), JSON.stringify(calls));
        await m.powerAction('poweroff');
        ok('power: PowerOff targets the PowerOff member', calls[1].member === 'PowerOff' && JSON.stringify(calls[1].body) === JSON.stringify([false]));
        let badPower = null;
        try { await m.powerAction('suspend'); } catch (e) { badPower = e; }
        ok('power: an unoffered action is rejected BEFORE the bus', !!badPower && /invalid power action/.test(badPower.message), calls.length === 2 ? '' : 'sent a call');
        const t0 = 1794625200123;
        const sched = await m.powerSchedule('reboot', t0);
        ok('schedule: ScheduleShutdown sends (mode, CLOCK_REALTIME usec)',
            calls[2].member === 'ScheduleShutdown' && calls[2].signature === 'st'
            && calls[2].body[0] === 'reboot' && calls[2].body[1] === t0 * 1000, JSON.stringify(calls[2]));
        ok('schedule: the returned state reflects the new schedule', sched.active === true && sched.action === 'reboot' && sched.usec === t0 * 1000);
        const cancelled = await m.powerCancelScheduled();
        const cancelCall = calls.find((c) => c.member === 'CancelScheduledShutdown');
        ok('cancel: CancelScheduledShutdown is a no-arg call returning {cancelled}',
            cancelCall && cancelCall.signature === '' && cancelled.cancelled === true);
        const none2 = await m.powerScheduledRead();
        ok('scheduled read: the (st) property parses to none after the cancel', none2.active === false);
        // ---- the 'Refresh now' button (round S+2: == `snap refresh` all installed
        //      snaps). Source-verified: the multi-action body is EXACTLY
        //      { action:'refresh' } (every multiActionData field is omitempty, so the
        //      empty snaps list is dropped). The daemon routes it to snapUpdateMany
        //      (refresh-all; a clean no-op change when nothing is pending) - it must
        //      NOT mutate the snap revisions and returns an async change id.
        { const beforeOps = state.multiOps.length;
          const beforeChanges = state.changes.length;
          const chg = await m.setGlobalRefreshNow();
          ok('refresh-now e2e: returns an async CHANGE id', typeof chg.id === 'string' && state.multiOps.length === beforeOps + 1, JSON.stringify(chg));
          const rec = state.multiOps[beforeOps];
          ok('refresh-now e2e: the body is EXACTLY { action: refresh } (no snaps - the omitempty drop)',
             JSON.stringify(rec.data) === JSON.stringify({ action: 'refresh' }), JSON.stringify(rec.data));
          await new Promise((res) => setTimeout(res, 250)); // let the stub change settle
          const afterChanges = state.changes.find((c) => c.id === chg.id);
          ok('refresh-now e2e: the change settles to Done', afterChanges && afterChanges.status === 'Done', JSON.stringify(afterChanges));
          ok('refresh-now e2e: the change is the REFRESH kind (the daemon refresh-all path, not a conf write)', afterChanges && afterChanges.kind === 'refresh-snap', JSON.stringify(afterChanges));
        }
        m.__setLogin1Transport(null);

        // ---- the refresh.timer WRITE target (round S+4 regression guard): a write must
        //      land in the STRUCTURED refresh.timer and round-trip through the real
        //      refreshTimerRead (getSnapConfig core -> refreshTimerFromDoc). If the writer
        //      targeted the legacy refresh.schedule, this round-trip reads null.
        { const chgT = await m.refreshTimerWrite('mon-fri,09:00-17:00');
          ok('refresh timer e2e: a write returns an async CHANGE id', typeof chgT.id === 'string', JSON.stringify(chgT));
          await new Promise((res) => setTimeout(res, 400)); // the stub conf PUT settles (250ms)
          const rb = await m.refreshTimerRead();
          ok('refresh timer e2e: writing refresh.timer ROUND-TRIPS (the target is refresh.timer, not the legacy refresh.schedule)', rb === 'mon-fri,09:00-17:00', JSON.stringify(rb));
          // clear it again so the rest of the section (hold/refresh-now) sees a clean doc
          await m.refreshTimerWrite('');
        }

        // ---- round MEM: the MEMORY card (core tmp.size + swap.size) ----
        // PURE unit tests of the size grammar (mirrors snapd gadget/quantity
        // SplitUnit @8d4d073: INTEGER + B|M|G, no decimals/%%/K/T) + the
        // per-option rules (tmp.go validTmpfsSize: 0 or >= 16MiB; swap.go
        // parseAndValidateSwapSize: integer number of MiB).
        { const g = (v) => m.memSizeToMiB(v);
          ok('memory grammar: M/G/bytes parse (512M=512MiB, 1G=1024MiB, 512 bytes = fractional MiB, 0 = 0)',
              g('512M') === 512 && g('1G') === 1024 && g('512') === 512 / 1048576 && g('0') === 0 && g('16M') === 16);
          ok('memory grammar: decimals, K, %, spaces, signs, and empty are NOT parseable',
              g('1.5G') === -1 && g('512K') === -1 && g('50%') === -1 && g(' 512M') === -1 && g('-5M') === -1 && g('') === -1);
          ok('memory rules: tmp = unset OK, 0 (unlimited) OK, 15M rejected, 16M OK, 1G OK, 1.5G rejected',
              m.memTmpValid('') === true && m.memTmpValid('0') === true && m.memTmpValid('15M') === false
              && m.memTmpValid('16M') === true && m.memTmpValid('1G') === true && m.memTmpValid('1.5G') === false);
          ok('memory rules: swap = unset OK, 0 OK, 512M OK, 1G OK, non-integer-MB bytes rejected, exact-MB bytes OK',
              m.memSwapValid('') === true && m.memSwapValid('0') === true && m.memSwapValid('512M') === true
              && m.memSwapValid('1G') === true && m.memSwapValid('1000000') === false && m.memSwapValid('1048576') === true);
          const md = (d) => m.memFieldFromDoc(d, 'tmp');
          ok('memory read: the NESTED live shape (snapd stores dotted keys nested)', md({ tmp: { size: '1G' } }) === '1G' && md({ swap: { size: 0 } }) === null);
          ok('memory read: the flat scalar + literal-dotted shapes are tolerated', md({ tmp: '1G' }) === '1G' && md({ 'tmp.size': '1G' }) === '1G');
          ok('memory read: absent/null/garbage = unset (null)', md({ system: { hostname: 'x' } }) === null && md(null) === null && md({}) === null && md({ tmp: {} }) === null);
        }
        // e2e round-trip through the REAL client bridge (getSnapConfig core +
        // setSnapConfig -> stub conf PUT 202 + settle): writes land in the
        // nested core doc, the read resolves them, '' clears, and INVALID
        // values are rejected BEFORE the bridge (no change, no conf PUT).
        { const putsBefore = state.confSets.length;
          let badWrite = null;
          try { await m.memoryWrite('tmp', '8M'); } catch (e) { badWrite = e; }
          ok('memory e2e: a sub-16MiB tmp value is rejected BEFORE the bridge (the tmp >= 16M rule)', !!badWrite && /not accepted by snapd/.test(badWrite.message), badWrite && badWrite.message);
          let badSwap = null;
          try { await m.memoryWrite('swap', '1.5G'); } catch (e) { badSwap = e; }
          ok('memory e2e: a decimal swap value is rejected BEFORE the bridge (the integer-MB rule)', !!badSwap && /not accepted by snapd/.test(badSwap.message), badSwap && badSwap.message);
          let badField = null;
          try { await m.memoryWrite('bogus', '1G'); } catch (e) { badField = e; }
          ok('memory e2e: an unknown field is rejected', !!badField && /invalid memory field/.test(badField.message), badField && badField.message);
          ok('memory e2e: the rejected writes produced NO conf PUT', state.confSets.length === putsBefore, JSON.stringify(state.confSets.length) + ' vs ' + putsBefore);
          const chgM1 = await m.memoryWrite('tmp', '1G');
          ok('memory e2e: a valid write returns an async CHANGE id', typeof chgM1.id === 'string', JSON.stringify(chgM1));
          await new Promise((res) => setTimeout(res, 400)); // the stub conf PUT settles (250ms)
          const mr1 = await m.memoryRead();
          ok('memory e2e: tmp.size ROUND-TRIPS (the nested core doc; swap still unset)', mr1.tmp === '1G' && mr1.swap === null, JSON.stringify(mr1));
          await m.memoryWrite('swap', '2G');
          await new Promise((res) => setTimeout(res, 400));
          const mr2 = await m.memoryRead();
          ok('memory e2e: swap.size round-trips too', mr2.tmp === '1G' && mr2.swap === '2G', JSON.stringify(mr2));
          await m.memoryWrite('tmp', '');
          await new Promise((res) => setTimeout(res, 400));
          const mr3 = await m.memoryRead();
          ok('memory e2e: the empty string CLEARS the option (read = unset; swap untouched)', mr3.tmp === '' && mr3.swap === '2G', JSON.stringify(mr3));
          // leave the core doc pristine for the rest of the section
          await m.memoryWrite('swap', '');
          await new Promise((res) => setTimeout(res, 400));
          const mr4 = await m.memoryRead();
          ok('memory e2e: clearing both returns the pristine unset state', mr4.tmp === '' && mr4.swap === '', JSON.stringify(mr4));
        }

        // ---- round JRN: the JOURNAL card (core journal.persistent) ----
        // PURE unit tests of the shape-robust read (the LIVE core doc stores
        // the dotted key NESTED {journal:{persistent}}; a flat scalar or a
        // literal dotted-key shape is tolerated; the value may be a boolean
        // (what `snap set` stores), the string 'true'/'false', or a number) +
        // the e2e round-trip through the REAL client bridge.
        { const jd = (d) => m.journalFieldFromDoc(d);
          ok('journal read: the NESTED live shape (boolean, string, number all resolve)',
              jd({ journal: { persistent: true } }) === true
              && jd({ journal: { persistent: 'false' } }) === 'false'
              && jd({ journal: { persistent: 1 } }) === 1);
          ok('journal read: the flat scalar + literal-dotted shapes are tolerated',
              jd({ journal: 'true' }) === 'true' && jd({ 'journal.persistent': true }) === true);
          ok('journal read: absent/null/garbage = unset (null)',
              jd({ system: { hostname: 'x' } }) === null && jd(null) === null && jd({}) === null && jd({ journal: {} }) === null);
        }
        { const putsBefore = state.confSets.length;
          let badJrn = null;
          try { await m.journalWrite('maybe'); } catch (e) { badJrn = e; }
          ok('journal e2e: a non-boolean value is rejected BEFORE the bridge', !!badJrn && /must be "true" or "false"/.test(badJrn.message), badJrn && badJrn.message);
          ok('journal e2e: the rejected write produced NO conf PUT', state.confSets.length === putsBefore, JSON.stringify(state.confSets.length) + ' vs ' + putsBefore);
          const chgJ = await m.journalWrite('true');
          ok('journal e2e: a valid write returns an async CHANGE id', typeof chgJ.id === 'string', JSON.stringify(chgJ));
          await new Promise((res) => setTimeout(res, 400)); // the stub conf PUT settles (250ms)
          const jr1 = await m.journalRead();
          ok('journal e2e: journal.persistent=true ROUND-TRIPS (the nested core doc)', jr1.persistent === true, JSON.stringify(jr1));
          // the wire format: the PUT body must carry the BOOLEAN (confInferType
          // mirrors `snap set` - `snap set core journal.persistent=true` sends
          // the boolean true, not the string).
          const jput = state.confSets[state.confSets.length - 1];
          ok('journal e2e: the PUT body is EXACTLY { "journal.persistent": true } (the boolean, like the CLI)',
              jput.name === 'core' && JSON.stringify(jput.data) === JSON.stringify({ 'journal.persistent': true }), JSON.stringify(jput.data));
          await m.journalWrite('false');
          await new Promise((res) => setTimeout(res, 400));
          const jr2 = await m.journalRead();
          ok('journal e2e: false round-trips (the OFF->teardown value; never the no-op "")', jr2.persistent === false, JSON.stringify(jr2));
        }

        // ---- round RCV: the RECOVERY card (the `snap reboot` frontend) ----
        // PURE unit: the offered modes are EXACTLY the two the CLI exposes
        // (--recover / --factory-reset; 'run' is current-system-only and
        // 'install' is the install-mode path — neither is offered).
        { ok('recovery modes: the CLI offers recover + factory-reset (exactly)',
              JSON.stringify(m.RECOVERY_MODES) === JSON.stringify(['recover', 'factory-reset']), JSON.stringify(m.RECOVERY_MODES));
          let badMode = null;
          try { await m.recoveryBoot('run'); } catch (e) { badMode = e; }
          ok('recovery: an unoffered mode is rejected BEFORE the request', !!badMode && /invalid recovery mode/.test(badMode.message), badMode && badMode.message);
        }
        // e2e through the REAL client (snapdRequest POST /v2/systems, NO trailing
        // slash -- the daemon 404s the slashed form; the CLI's raw() path.Join
        // cleans its own) + the
        // stub: the EXACT wire format the snap CLI sends ({action:'reboot',
        // mode}) for each mode, the { started } result, and the pristine end.
        { const before = (state.systemsPosts || []).length;
          const rc1 = await m.recoveryBoot('recover');
          ok('recovery e2e: recover resolves { started: true } (a sync 200)', rc1 === true, JSON.stringify(rc1));
          const rpost = (state.systemsPosts || [])[before];
          ok('recovery e2e: the wire body is EXACTLY { action: reboot, mode: recover } (the snap CLI format)',
              rpost && rpost.action === 'reboot' && rpost.mode === 'recover', JSON.stringify(rpost));
          await m.recoveryBoot('factory-reset');
          const fpost = (state.systemsPosts || [])[before + 1];
          ok('recovery e2e: the factory-reset wire body is { action: reboot, mode: factory-reset }',
              fpost && fpost.action === 'reboot' && fpost.mode === 'factory-reset', JSON.stringify(fpost));
          ok('recovery e2e: exactly the two requested reboots were sent (no extras)',
              (state.systemsPosts || []).length === before + 2, JSON.stringify((state.systemsPosts || []).length));
          // round RCVfix: the trailing-slash path form is REJECTED by the stub the
          // way the real daemon rejects it (generic 404 'not found' -> SnapdError
          // -> rethrown, never swallowed as 'started'). Guards the live-bug fix.
          let slash404 = null;
          try {
              await m.snapdRequest('POST', '/v2/systems/', { body: { action: 'reboot', mode: 'bogus' }, auth: m.A(), timeout: 3000 });
          } catch (e) { slash404 = e; }
          ok('recovery e2e guard: POST /v2/systems/ (trailing slash) 404s as a SnapdError (the device behavior)',
              !!slash404 && slash404.name === 'SnapdError' && /not found/.test(slash404.message), slash404 && (slash404.name + ': ' + slash404.message));
          ok('recovery e2e guard: the rejected slashed request was NOT recorded as a reboot',
              (state.systemsPosts || []).length === before + 2);
        }
        // ---- the kiosk content-size clamp (round-T-fix bug 3) ----
        // The VM symptom: an external re-layout left the web-contents view stuck
        // at 1280x800 while the window was taller (bottom half = window
        // background). The app never resizes the window itself — it CLAMPS drift
        // (re-assert the content size to the full display). Unit-test it
        // deterministically: a richer fake electron with a 1920x1080 display,
        // fire the captured 'resize' handler, and assert the clamp re-asserts
        // on drift (800 != 1080) and is a NO-OP when healthy.
        {
          const WIRE2 = fs.mkdtempSync(path.join(os.tmpdir(), 'ucm-wire2-'));
          process.env.UCM_STATE_DIR = WIRE2;
          let lastWin = null;
          global.UCM_FAKE_ELECTRON = {
            app: { requestSingleInstanceLock: () => true, on: () => {}, whenReady: () => Promise.resolve(), quit: () => {} },
            BrowserWindow: class {
              constructor(opts) {
                lastWin = this;
                this._opts = opts || {};
                this._h = {}; this._wc = {};
                this.webContents = { on: (c, fn) => { this._wc[c] = fn; }, send: () => {}, setWindowOpenHandler: () => {}, executeJavaScript: () => Promise.resolve(null) };
                this.on = (c, fn) => { (this._h[c] = this._h[c] || []).push(fn); };
                this.once = (c, fn) => { (this._h[c] = this._h[c] || []).push(fn); };
                this.loadFile = () => {};
                this.isDestroyed = () => false; this.isVisible = () => true;
                this.setAlwaysOnTop = () => {}; this.focus = () => {}; this.unmaximize = () => {}; this.restore = () => {}; this.show = () => {};
                this._cs = [1280, 800]; this._contentSet = 0; this._fsSet = 0;
                this.getContentSize = () => this._cs;
                this.setContentSize = (w, h) => { this._cs = [w, h]; this._contentSet += 1; };
                this.setFullScreen = () => { this._fsSet += 1; };
              }
            },
            ipcMain: { handle: () => {}, on: () => {} },
            session: { fromPartition: (n) => ({ name: n, webRequest: { onHeadersReceived: () => {} }, on: () => {} }), defaultSession: { webRequest: { onHeadersReceived: () => {} }, localAuthenticated: false } },
            screen: { getPrimaryDisplay: () => ({ workArea: { x: 0, y: 0, width: 1920, height: 1080 } }) },
          };
          process.env.UCM_FAKE_ELECTRON = '1';
          try {
            delete require.cache[require.resolve(path.join(__dirname, '..', 'main.js'))];
            require(path.join(__dirname, '..', 'main.js'));
            await new Promise((r) => setImmediate(r));
            await new Promise((r) => setImmediate(r));
            ok('kiosk clamp: the window wired its resize handler (round-T-fix bug 3)',
               lastWin && Array.isArray(lastWin._h['resize']) && lastWin._h['resize'].length >= 1);
            // round T-fix12: the pre-map startup flash is the kiosk backgroundColor.
            // It used to be near-white (#f7f7f7) — a white blast before the app
            // maps. It is now the aubergine (#262626) so the flash matches the
            // dark theme and reads as "loading". Pin the shipped value.
            ok('kiosk window: the backgroundColor is the aubergine dark (no white startup flash)',
               lastWin && lastWin._opts && lastWin._opts.backgroundColor === '#262626',
               JSON.stringify(lastWin && lastWin._opts && lastWin._opts.backgroundColor));
            // drift: content 1280x800 vs display 1920x1080 -> the clamp re-asserts.
            // (defensive: if the handler is absent the ok() above already fired;
            //  the forEach must not CRASH the suite on that mutation.)
            if (Array.isArray(lastWin._h['resize'])) lastWin._h['resize'].forEach((fn) => fn());
            ok('kiosk clamp: a DRIFTED content size (stuck 800px on a 1080 display) is re-asserted to the full display',
               JSON.stringify(lastWin._cs) === JSON.stringify([1920, 1080]) && lastWin._contentSet === 1 && lastWin._fsSet === 1,
               JSON.stringify({ cs: lastWin._cs, contentSet: lastWin._contentSet, fsSet: lastWin._fsSet }));
            // healthy: content now matches the display -> a further resize is a NO-OP.
            await new Promise((r) => setTimeout(r, 600)); // let the re-assert debounce clear
            if (Array.isArray(lastWin._h['resize'])) lastWin._h['resize'].forEach((fn) => fn());
            lastWin._wc['resize'] && lastWin._wc['resize']();
            ok('kiosk clamp: when the content size ALREADY matches the display it is a NO-OP (no thrash)',
               lastWin._contentSet === 1 && lastWin._fsSet === 1 && JSON.stringify(lastWin._cs) === JSON.stringify([1920, 1080]),
               JSON.stringify({ contentSet: lastWin._contentSet, fsSet: lastWin._fsSet }));
          } finally {
            delete process.env.UCM_FAKE_ELECTRON;
            delete global.UCM_FAKE_ELECTRON;
            delete require.cache[require.resolve(path.join(__dirname, '..', 'main.js'))];
            process.env.UCM_STATE_DIR = STATE;
            try { fs.rmSync(WIRE2, { recursive: true, force: true }); } catch {}
          }
        }

        // ---- the TIME card (round T: set-time + timezone + topbar clock) ----
        // (a) the bundled IANA zone list (main.js listTimezones — the file the
        //      renderer's <select> is built from; every entry must pass
        //      snapd's own validTimezone regex or snapd would reject it at
        //      configure time).
        {
          const zones = m.listTimezones();
          ok('timezones: the bundled list is non-trivial and sorted',
             zones.length > 400 && JSON.stringify(zones) === JSON.stringify(zones.slice().sort()), 'n=' + zones.length);
          ok('timezones: every bundled entry passes snapd validTimezone',
             zones.every((z) => m.timezoneValid(z)));
          ok('timezones: the common zones are present (Etc/UTC + a few)',
             zones.includes('Etc/UTC') && zones.includes('Europe/Berlin') && zones.includes('America/New_York') && zones.includes('Asia/Tokyo'));
          // round-T-fix bug 2 (structural): the zone <select> must NOT carry a
          // permanent `disabled` attribute in the markup — the round-T bug. The
          // enable logic lives in loadSystem (the harness locks the runtime
          // state); this locks the markup so the attribute can't regress.
          const idxHtml = fs.readFileSync(path.join(__dirname, '..', 'ui', 'index.html'), 'utf8');
          const zoneSelTag = (idxHtml.match(/<select[^>]*id="timeZoneSelect"[^>]*>/) || [''])[0];
          ok('zone select: the markup carries NO permanent disabled attribute (round-T-fix bug 2)',
             !!zoneSelTag && /disabled/.test(zoneSelTag) === false, zoneSelTag);
          ok('timezoneValid: junk is rejected (not a zone grammar)',
             m.timezoneValid('') === false && m.timezoneValid('a/b/c/d') === false && m.timezoneValid('has space') === false
             && m.timezoneValid('Europe/Berlin') === true && m.timezoneValid('Etc/GMT+5') === true && m.timezoneValid(5) === false);
          // round-T-fix bug 2: a MISSING/CORRUPT bundled list degrades to an
          // EMPTY array (the picker stays usable) — it must NOT throw (that
          // would blank the whole time read, the VM symptom). Point the seam at
          // a bad path, exercise the degrade, then restore the real bundled list.
          const badZoneFile = path.join(STATE, 'ucm-badzones-' + process.pid + '.json');
          m.__setTimeZonesFile('/nonexistent/ucm-zones.json');
          let deg = null, degErr = null;
          try { deg = m.listTimezones(); } catch (e) { degErr = e; }
          ok('listTimezones: a MISSING bundled file degrades to an EMPTY list (no throw)',
             degErr === null && Array.isArray(deg) && deg.length === 0, degErr && degErr.message);
          fs.writeFileSync(badZoneFile, 'not-a-json', 'utf8');
          m.__setTimeZonesFile(badZoneFile);
          let deg2 = null, deg2Err = null;
          try { deg2 = m.listTimezones(); } catch (e) { deg2Err = e; }
          ok('listTimezones: a CORRUPT bundled file degrades to an EMPTY list (no throw)',
             deg2Err === null && Array.isArray(deg2) && deg2.length === 0, deg2Err && deg2Err.message);
          m.__setTimeZonesFile(null); // restore the real bundled list
          try { fs.unlinkSync(badZoneFile); } catch (e) {}
        }
        // (b) set-time: the NTP gate (checked in main at write time) + the
        //      EXACT SetTime(xbb) D-Bus body (injected transport, the 49h
        //      signature-verification idiom).
        {
          const tCalls = [];
          // the read is Properties.Get**All** (the round-T-fix bug 1: the
          // per-property Get(ss) is REJECTED by systemd). The fake returns the
          // full props map (Variant-wrapped, as dbus-next does).
          m.__setTimesyncTransport(async (spec) => {
            tCalls.push(spec);
            if (spec.member === 'GetAll') {
              return [{ NTPEnabled: { signature: 'b', value: false }, Timezone: { signature: 's', value: 'Europe/Berlin' }, TimeUSec: { signature: 't', value: 1794771882397771n } }];
            }
            return [];
          });
          const usec = 1794770000000000;
          const r1 = await m.timeSet(usec);
          // BUG-1 REGRESSION LOCK: the NTP gate read MUST use Properties.GetAll
          // (the working idiom), NOT the per-property Get(ss) that systemd
          // rejects ("Unknown interface ... or property NTPEnabled").
          const propCall = tCalls.find((c) => c.member === 'Get' || c.member === 'GetAll');
          ok('timeSet gate: the NTP read uses Properties.GetAll (the per-property Get(ss) is rejected by systemd — round-T bug 1)',
             !!propCall && propCall.member === 'GetAll' && propCall.signature === 's' && JSON.stringify(propCall.body) === JSON.stringify(['org.freedesktop.timedate1']),
             propCall ? JSON.stringify([propCall.member, propCall.signature, propCall.body.map(String)]) : 'no prop call');
          const setCall = tCalls.find((c) => c.member === 'SetTime');
          ok('timeSet: returns ok and calls SetTime', r1.ok === true && !!setCall);
          ok('timeSet: the body is EXACTLY [usec, 0, false] with the xbb signature (the container introspection truth)',
             setCall && setCall.signature === 'xbb' && setCall.body[0] === usec && setCall.body[1] === 0 && setCall.body[2] === false,
             setCall ? JSON.stringify([setCall.signature, setCall.body.map(String)]) : 'no call');
          // the GATE: with NTP on, a manual set is refused BEFORE any SetTime.
          m.__setTimesyncTransport(async (spec) => {
            if (spec.member === 'GetAll') return [{ NTPEnabled: { signature: 'b', value: true } }];
            throw new Error('SetTime must never be reached while NTP is on');
          });
          let gateErr = null;
          try { await m.timeSet(usec); } catch (e) { gateErr = e; }
          ok('timeSet: refused while NTP is on (the gate — the user: with time sync we do not manually set the time)',
             !!gateErr && /time sync is ON/i.test(gateErr.message), gateErr && gateErr.message);
          let nonFinite = null;
          try { await m.timeSet('junk'); } catch (e) { nonFinite = e; }
          ok('timeSet: a non-finite value is rejected before the D-Bus',
             !!nonFinite && /invalid time/i.test(nonFinite.message), nonFinite && nonFinite.message);
          m.__setTimesyncTransport(null);
        }
        // (c) the timezone WRITE (core conf — snapd runs timedatectl itself;
        //      the app must NOT need the timezone-control plug for this) +
        //      the EXTERNAL-CONFIG round-trip through the stub.
        {
          const before = state.confSets.length;
          await m.timezoneWrite('Europe/Vienna');
          ok('timezoneWrite: returns a zone and sends a conf PUT (async change)',
             state.confSets.length === before + 1);
          const put = state.confSets[state.confSets.length - 1];
          ok('timezoneWrite: the PUT body is EXACTLY { "system.timezone": zone } on the CORE snap',
             put.name === 'core' && JSON.stringify(put.data) === JSON.stringify({ 'system.timezone': 'Europe/Vienna' }), JSON.stringify(put.data));
          await new Promise((res) => setTimeout(res, 400)); // the stub conf PUT settles (250ms)
          const rb = await m.timezoneRead();
          ok('timezoneWrite: the write ROUND-TRIPS (the external-config GET resolves the applied zone)',
             rb === 'Europe/Vienna', JSON.stringify(rb));
          let badZone = null;
          try { await m.timezoneWrite('Not A Zone'); } catch (e) { badZone = e; }
          ok('timezoneWrite: a junk zone is rejected BEFORE the socket (nothing sent)',
             !!badZone && /invalid timezone/i.test(badZone.message) && state.confSets.length === before + 1, badZone && badZone.message);
          // the GET when NOTHING is stored: the live system value (the stub
          // models the real external-config resolution, not "option missing"):
          // wipe the stored doc + move the LIVE zone (the CLI set it) -> the
          // read must return the LIVE zone, proving external-config semantics.
          state.conf.core = {};
          state.timezone = 'Pacific/Honolulu';
          const live = await m.timezoneRead();
          ok('timezoneRead: an absent stored zone RESOLVES TO THE LIVE SYSTEM ZONE (external config, never 404)',
             live === 'Pacific/Honolulu', JSON.stringify(live));
          state.timezone = 'Etc/UTC';
        }

        // ---- the global auto-refresh HOLD (round S: the 'Pause auto-refresh'
        //      toggle; the REST equivalent of `snap refresh --hold`/`--unhold`) ----
        // (i) the PURE active-decision (unit-tested against the sysinfo value).
        //     '' / null / undefined / whitespace = NOT active; any non-empty
        //     string (the 'forever' token or an RFC3339 hold-until timestamp) =
        //     active. A bare `snap refresh --hold` arrives as a distant ~100-year
        //     timestamp, so the truthiness is 'non-empty', NOT '== forever'.
        ok('refresh hold: the active decision is non-empty (not a forever-equality)',
            m.refreshHoldActive('') === false && m.refreshHoldActive(null) === false
            && m.refreshHoldActive(undefined) === false && m.refreshHoldActive('   ') === false
            && m.refreshHoldActive('forever') === true && m.refreshHoldActive('  ') === false
            && m.refreshHoldActive('2099-01-01T00:00:00Z') === true);
        ok('refresh hold: a whitespace-only value is NOT active (the trim, not !!hold)',
            m.refreshHoldActive('\t\n ') === false);

        // (ii) refreshHoldRead with an INJECTED sysinfo shape (the __setSystemInfoFn
        //      seam). The read walks info.refresh.hold (the UNWRAPPED result), NOT
        //      info.result.refresh.hold. Absent/empty = inactive + ''; a timestamp
        //      = active + the string preserved.
        m.__setSystemInfoFn(async () => ({ version: 'x', refresh: { timer: 't', last: 'l', next: 'n' } }));
        { const r = await m.refreshHoldRead();
          ok('refresh hold read: an empty refresh (no hold) is INACTIVE with a blank string',
             r.active === false && r.hold === '', JSON.stringify(r)); }
        m.__setSystemInfoFn(async () => ({ version: 'x' })); // refresh key ABSENT
        { const r = await m.refreshHoldRead();
          ok('refresh hold read: an ABSENT refresh key degrades to inactive (no crash)',
             r.active === false && r.hold === '', JSON.stringify(r)); }
        m.__setSystemInfoFn(async () => ({ version: 'x', refresh: { timer: 't', last: 'l', next: 'n', hold: '2099-01-01T00:00:00Z' } }));
        { const r = await m.refreshHoldRead();
          ok('refresh hold read: a hold timestamp is ACTIVE and PRESERVED verbatim',
             r.active === true && r.hold === '2099-01-01T00:00:00Z', JSON.stringify(r)); }
        m.__setSystemInfoFn(null);

        // (iii) the E2E write path against the STUB: setGlobalRefreshHold(true/false)
        //       must POST the EXACT multi-action body (the CLI's `snap refresh --hold`
        //       form) to /v2/snaps - NOT the single-snap /v2/snaps/<name> path and
        //       NOT a setSnapConfig PUT. Assert the recorded socket body verbatim.
        { const before = state.multiOps.length;
          const chg = await m.setGlobalRefreshHold(true);
          ok('refresh hold e2e: the hold returns an async CHANGE id (settle it)', typeof chg.id === 'string' && state.multiOps.length === before + 1, JSON.stringify(chg));
          const rec = state.multiOps[before];
          ok('refresh hold e2e: the HOLD body is EXACT (action hold, empty snaps, time forever, hold-level auto-refresh)',
             JSON.stringify(rec.data) === JSON.stringify({ action: 'hold', snaps: [], time: 'forever', 'hold-level': 'auto-refresh' }), JSON.stringify(rec.data));
          // let the stub settle (150ms) so the LIVE read-back reflects the hold
          await new Promise((res) => setTimeout(res, 250));
          const heldInfo = await m.getSystemInfo();
          ok('refresh hold e2e: after a hold the LIVE sysinfo read-back is active (result.refresh.hold set)',
             typeof heldInfo.refresh.hold === 'string' && heldInfo.refresh.hold !== '' && m.refreshHoldActive(heldInfo.refresh.hold) === true, JSON.stringify(heldInfo.refresh));
        }
        { const before = state.multiOps.length;
          const chg = await m.setGlobalRefreshHold(false);
          ok('refresh hold e2e: the unhold returns an async CHANGE id', typeof chg.id === 'string' && state.multiOps.length === before + 1, JSON.stringify(chg));
          const rec = state.multiOps[before];
          ok('refresh hold e2e: the UNHOLD body is EXACT (action unhold, empty snaps - no time/hold-level)',
             JSON.stringify(rec.data) === JSON.stringify({ action: 'unhold', snaps: [] }), JSON.stringify(rec.data));
          await new Promise((res) => setTimeout(res, 250));
          const unheldInfo = await m.getSystemInfo();
          ok('refresh hold e2e: after an unhold the LIVE sysinfo read-back is INACTIVE (result.refresh.hold absent)',
             (!unheldInfo.refresh.hold || unheldInfo.refresh.hold === '') && m.refreshHoldActive(unheldInfo.refresh.hold) === false, JSON.stringify(unheldInfo.refresh));
        }
    }

    const svgErr = (txt) => {
        const declared = (txt.match(/xmlns:(\w+)=/g) || []).map((x) => x.slice(6, -1));
        for (const pref of ['inkscape', 'sodipodi']) {
            if (new RegExp('\\s' + pref + ':[\\w-]+="').test(txt) && !declared.includes(pref)) {
                return pref + ': attribute used but its namespace is never declared';
            }
        }
        return null;
    };
    const badSvgs = svgs.map((f) => { const e = svgErr(fs.readFileSync(path.join(__dirname, '..', 'build', 'images', f), 'utf8')); return e ? f + ': ' + e : null; }).filter(Boolean);
    ok('every shipped SVG is well-formed XML (no unbound namespace prefixes)', badSvgs.length === 0, badSvgs.join(' | '));

    console.log(`\n================= ${passed} passed, ${failed} failed =================`);
    fs.rmSync(STATE, { recursive: true, force: true });
    fs.unlinkSync(SOCK);
    process.exit(failed ? 1 : 0);
})().catch((e) => { console.error('FATAL', e); try { fs.rmSync(STATE, { recursive: true, force: true }); fs.unlinkSync(SOCK); } catch {} process.exit(2); });
