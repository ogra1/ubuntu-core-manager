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
        changes: [
            { id: '1', kind: 'install-snap', summary: 'Install snap "htop"', status: 'Done', 'spawn-time': '2026-10-28T09:00:00Z' },
            { id: '2', kind: 'configure-snap', summary: 'Configure snap "core24"', status: 'Ready', 'spawn-time': '2026-10-28T10:00:00Z' },
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
    ok('listSnaps returns array of 4', Array.isArray(snaps) && snaps.length === 4, JSON.stringify(snaps).slice(0, 60));
    const find = await m.searchSnaps('fire');
    ok('store search filters', Array.isArray(find) && find.length === 1 && find[0].name === 'firefox', JSON.stringify(find).slice(0, 80));
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
    // round 54: the option is a JSON OBJECT (a YAML string would fail
    // snapd's option decode) — the RECORDED PUT body must carry the doc as
    // an object. Seed the default Core boilerplate (catch-alls only): the
    // FIRST edit replaces it COMPLETELY.
    state.netplan = { network: { version: 2, ethernets: { 'all-en': { dhcp4: true, match: { name: 'en*' } }, 'all-eth': { dhcp4: true, match: { name: 'eth*' } } } } };
    await m.netApplyDevice({ name: 'eth0', type: 'ethernet', mode: 'static', address: '192.168.1.50/24', gateway: '192.168.1.1', dns: ['1.1.1.1'] });
    const written6 = state.confSets[state.confSets.length - 1];
    ok('conf PUT went to core snap', written6 && written6.name === 'core', JSON.stringify(written6 && written6.name));
    const sent6 = written6 && written6.data['system.network.netplan'];
    ok('the netplan option value is a JSON OBJECT, not a string', sent6 && typeof sent6 === 'object' && !Array.isArray(sent6), String(typeof sent6));
    ok('the first edit REPLACES the complete boilerplate (all-en + all-eth gone, doc = version + this device)',
        sent6 && typeof sent6 === 'object' && sent6.network
        && JSON.stringify(sent6.network.ethernets) === JSON.stringify({ eth0: { addresses: ['192.168.1.50/24'], gateway4: '192.168.1.1', dns: { nameservers: { addresses: ['1.1.1.1'] } } } })
        && !('all-en' in (sent6.network.ethernets || {})),
        JSON.stringify(sent6 && sent6.network));
    ok('the replaced doc keeps version: 2', sent6 && sent6.network && sent6.network.version === 2, JSON.stringify(sent6 && sent6.network));
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
                !!handlers['auth:create'] && !!handlers['auth:login'] && !!handlers['auth:logout']
                && !!handlers['sys:cpu']);
            ok('timesync handlers registered (status open, writes auth-gated)',
                !!handlers['timesync:status'] && !!handlers['timesync:set-enabled'] && !!handlers['timesync:set-server']);
            ok('ip-forwarding handlers registered (status open, writes auth-gated)',
                !!handlers['net:forwarding-status'] && !!handlers['net:forwarding-set']);
            ok('net devices handlers registered (list open, apply auth-gated) + the dead net:apply is gone',
                !!handlers['net:devices'] && !!handlers['net:apply-device'] && !handlers['net:apply']);
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
        ok('a "n/a" DNS line is NOT a server (enp3s0 dns empty)', d0('enp3s0') && JSON.stringify(d0('enp3s0').dns) === JSON.stringify([]));
        ok('the kind=bridge link is typed bridge + not connected (no UP flag)',
            d0('br0') && d0('br0').type === 'bridge' && d0('br0').connected === false);
        ok('an enslaved device (master: br0) is NOT a card (it is a bridge member)',
            !d0('enp5s0'), dev0.map((d) => d.name).join(','));
        ok('the bridge card carries its LIVE members from the master field',
            d0('br0') && JSON.stringify(d0('br0').members) === JSON.stringify(['enp5s0']),
            d0('br0') && JSON.stringify(d0('br0').members));
        ok('an absent iw does not crash and yields no wifi', dev0.every((d) => d.type !== 'wifi'));

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
        // a device RE-TYPED leaves its old section (ethernet->wifi)
        await m.netApplyDevice({ name: 'eth0', type: 'wifi', mode: 'dhcp', ssid: 'Net', password: 'password123' });
        await new Promise((r) => setTimeout(r, 350));
        nw = netOf();
        ok('a re-typed device leaves its OLD section (ethernets.eth0 gone)', !nw.ethernets || !nw.ethernets.eth0, JSON.stringify(nw.ethernets));
        ok('the re-type is additive too (ethernets.enp3s0 from the previous edit survives)',
            nw.ethernets && nw.ethernets.enp3s0 && nw.ethernets.enp3s0.dhcp4 === true,
            JSON.stringify(nw.ethernets));
        ok('a re-typed device lands in its NEW section (wifis.eth0)', nw.wifis && nw.wifis.eth0 && nw.wifis.eth0['access-points'] && nw.wifis.eth0['access-points'].Net, JSON.stringify(nw.wifis));
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
