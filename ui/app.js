'use strict';

/* ============================================================================
 *  ubuntu-core-manager — ui/app.js
 *  Renderer-side single-page controller. Runs fully sandboxed
 *  (contextIsolation + sandbox); the ONLY system surface it has is the
 *  frozen `window.ucmCore` bridge exposed by preload.js. No Node, no fetch,
 *  no storage, no inline scripts.
 *
 *  Auth model (two independent layers, see main.js):
 *   - LOCAL admin gate (offline): first boot => setup (create password);
 *     thereafter => login (password). This is what unlocks the console, so
 *     the operator can configure the network before any connectivity exists.
 *   - STORE auth (optional, volatile): snapd /v2/login macaroons. Shown in
 *     the top bar as "store online/offline"; required only for install and
 *     store search.
 * ==========================================================================*/

const core = window.__mockCore || window.ucmCore; // frozen context bridge (mock for headless QA)
// NOTE: bridge property is 'ucmCore', never 'core' — see preload.js. A global property named
// 'core' collides with THIS top-level lexical and SyntaxErrors the whole file.

/* ----------------------------- tiny DOM utils ---------------------------- */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
        if (k === 'class') node.className = v;
        else if (k === 'text') node.textContent = v;
        else if (k === 'dataset') Object.assign(node.dataset, v);
        else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
        else if (v !== false && v != null) node.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children) {
        if (c == null) continue;
        node.append(c.nodeType ? c : document.createTextNode(c));
    }
    return node;
}

const fmtBytes = (n) => {
    if (n == null || isNaN(n)) return '—';
    const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i += 1; }
    return `${n >= 100 ? Math.round(n) : n.toFixed(1)} ${u[i]}`;
};
const fmtUptime = (s) => {
    if (s == null) return '—';
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    return (d ? `${d}d ` : '') + `${h}h ${m}m`;
};
const fmtDate = (iso) => {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleString(); } catch { return iso; }
};

/* ------------------------------- toasts ---------------------------------- */

function toast(kind, title, message, ttl = 6000) {
    const box = $('#toasts');
    const t = el('div', { class: `p-notification p-notification--${kind}` });
    t.append(
        el('h5', { class: 'p-notification__title', text: title }),
        el('p', { class: 'p-notification__message', text: message })
    );
    box.append(t);
    setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 400); }, ttl);
}
const toastErr = (e) => toast('negative', 'Operation failed', (e && e.message) || String(e));

/* --------------------------- form validation ----------------------------- */
/* Vanilla p-form-validation contract:
 *   group.is-caution  -> caution icon + yellow input
 *   group.is-error    -> error icon + red input
 *   group.is-valid    -> success icon + green input
 * Message text lives in .p-form-validation__message inside the group.    */

function setFieldState(groupId, state, message = '') {
    const group = $('#' + groupId);
    if (!group) return;
    group.classList.remove('is-caution', 'is-error', 'is-valid');
    const msg = $('.p-form-validation__message', group);
    if (msg) msg.textContent = message;
    if (state) group.classList.add('is-' + state);
}

const RE_EMAIL = /^[^\s@<>"']{1,64}@[\w-]+(?:\.[\w-]+)+$/;
const RE_CIDR4 = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\/(3[0-2]|2\d|1\d|[1-9])$/;
const RE_IP4 = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const RE_CIDR6 = /^[0-9a-f:]+\/(12[0-8]|1[01]\d|[1-9]\d)$/i;
const RE_IP6 = /^[0-9a-f:]+$/i;
const RE_SNAP_NAME = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

/* ------------------------------ app state -------------------------------- */

const state = {
    view: 'dashboard',
    // local admin gate (the UI lock screen; offline)
    initialized: false,
    authenticated: false,
    expiresAt: null,
    timeoutMs: 900000,
    // optional store auth
    storeAuthenticated: false,
    storeUsername: null,
    snapd: null,
    host: null,
    netplan: null,
    changes: [],
    warnings: [],
    netdev: null,
    snaps: [],
    connections: [],
    ifacesPendingOnly: true,
    manualLock: false,
    sessionTick: null,
    dashPoll: null,
};

const VIEWS = ['dashboard', 'network', 'snaps', 'interfaces'];
const VIEW_TITLES = { dashboard: 'Dashboard', network: 'Network configuration', snaps: 'Snap packages', interfaces: 'Snap interfaces' };

/* --------------------------- three-gate routing -------------------------- */
/*   !initialized  -> #setupView  (create the local password; offline)
 *   !authenticated-> #loginView  (local password; offline)
 *   authenticated -> #appShell   (console)                                  */

function showGate() {
    const toSetup = !state.initialized;
    const toLogin = state.initialized && !state.authenticated;
    $('#setupView').classList.toggle('ucm-hidden', !toSetup);
    $('#loginView').classList.toggle('ucm-hidden', !toLogin && !toSetup);
    $('#appShell').classList.toggle('ucm-hidden', toSetup || toLogin);
    if (toSetup) $('#setupPassword').focus();
    if (toLogin) $('#loginPassword').focus();
}

function switchView(name) {
    if (!VIEWS.includes(name)) name = 'dashboard';
    state.view = name;
    $$('#appShell .ucm-view').forEach((v) => v.classList.toggle('ucm-hidden', v.dataset.view !== name));
    $$('.ucm-side .p-side-navigation__link').forEach((a) =>
        a.classList.toggle('is-active', a.dataset.view === name));
    $('#topbarTitle').textContent = VIEW_TITLES[name];
    history.replaceState(null, '', '#' + name);

    ({
        dashboard: loadDashboard,
        network: loadNetwork,
        snaps: loadSnaps,
        interfaces: loadInterfaces,
    })[name]();
}

function enterApp() {
    showGate();
    startSessionTick();
    startDashPoll();
    renderStoreStatus();
    const fromHash = (location.hash || '').replace('#', '');
    switchView(VIEWS.includes(fromHash) ? fromHash : 'dashboard');
}

function exitApp() {
    stopSessionTick();
    stopDashPoll();
    $('#setupPassword').value = '';
    $('#setupConfirm').value = '';
    $('#loginPassword').value = '';
    setFieldState('setupPasswordGroup', '');
    setFieldState('setupConfirmGroup', '');
    setFieldState('loginPasswordGroup', '');
    showGate();
}

/* --------------------------- session countdown --------------------------- */

function startSessionTick() {
    stopSessionTick();
    const chip = $('#sessionChip');
    const text = $('#sessionChipText');
    const render = () => {
        if (!state.authenticated) { text.textContent = 'active'; return; }
        const remain = state.expiresAt - Date.now();
        if (remain <= 0) return; // main will push auth-status-changed -> lock
        const m = Math.floor(remain / 60000);
        const s = Math.floor((remain % 60000) / 1000);
        text.textContent = `locks in ${m}:${String(s).padStart(2, '0')}`;
        chip.classList.toggle('is-warning', remain < state.timeoutMs - 60000);
    };
    render();
    state.sessionTick = setInterval(render, 1000);
}
function stopSessionTick() {
    if (state.sessionTick) { clearInterval(state.sessionTick); state.sessionTick = null; }
}

/* ----------------------------- auth (local) ------------------------------ */

async function doCreatePassword() {
    const pw = $('#setupPassword').value;
    const confirm = $('#setupConfirm').value;
    let ok = true;
    if (pw.length < 8 || pw.length > 128) {
        setFieldState('setupPasswordGroup', 'error', 'Password must be 8–128 characters.');
        ok = false;
    } else setFieldState('setupPasswordGroup', 'valid');
    if (confirm !== pw) {
        setFieldState('setupConfirmGroup', 'error', 'Passwords do not match.');
        ok = false;
    } else setFieldState('setupConfirmGroup', 'valid');
    if (!ok) return;

    const btn = $('#setupBtn');
    btn.classList.add('is-disabled');
    try {
        applyAuthPayload(await core.auth.create(pw));
        toast('positive', 'Administrator created', 'Local console password set. The store remains optional.');
    } catch (e) {
        setFieldState('setupPasswordGroup', 'error', e.message);
        setFieldState('setupConfirmGroup', '');
    } finally {
        btn.classList.remove('is-disabled');
    }
}

async function doLogin(password) {
    if (!password) {
        setFieldState('loginPasswordGroup', 'error', 'Password is required.');
        return;
    }
    const btn = $('#loginBtn');
    btn.classList.add('is-disabled');
    try {
        applyAuthPayload(await core.auth.login(password));
    } catch (e) {
        const msg = /incorrect password/i.test(e.message) ? 'Incorrect password.' : e.message;
        setFieldState('loginPasswordGroup', 'error', msg);
    } finally {
        btn.classList.remove('is-disabled');
    }
}

async function doLock() {
    state.manualLock = true;
    try {
        applyAuthPayload(await core.auth.logout());
    } catch {
        applyAuthPayload({ initialized: state.initialized, authenticated: false, expiresAt: null,
            timeoutMs: state.timeoutMs, storeAuthenticated: false, storeUsername: null });
    }
}

function applyAuthPayload(p) {
    if (!p) return;
    const wasAuth = state.authenticated;
    state.initialized = !!p.initialized;
    state.authenticated = !!p.authenticated;
    state.expiresAt = p.expiresAt || null;
    state.timeoutMs = p.timeoutMs || 900000;
    state.storeAuthenticated = !!p.storeAuthenticated;
    state.storeUsername = p.storeUsername || null;

    if (state.authenticated) {
        if (!wasAuth) enterApp();
        startSessionTick();
    } else if (wasAuth) {
        const manual = state.manualLock;
        state.manualLock = false;
        exitApp();
        toast('info', manual ? 'Console locked' : 'Session locked',
            manual ? 'Re-enter the administrator password to continue.'
                   : 'The console was locked after inactivity. Sign in to continue.');
    }
    showGate();
    renderStoreStatus();
}

/* ------------------------- store (optional) ------------------------------ */

function renderStoreStatus() {
    const label = $('#storeStatus');
    const btn = $('#storeBtn');
    const chip = $('#storeChip');
    const notice = $('#snapsStoreNotice');
    if (state.storeAuthenticated) {
        label.className = 'p-status-label p-status-label--positive';
        label.textContent = 'store online';
        btn.textContent = 'Disconnect';
        $('#railRole').textContent = state.storeUsername || 'store connected';
        if (notice) notice.classList.add('ucm-hidden');
    } else {
        label.className = 'p-status-label p-status-label--caution';
        label.textContent = 'store offline';
        btn.textContent = 'Connect to store';
        $('#railRole').textContent = 'local session';
        if (notice) notice.classList.remove('ucm-hidden');
    }
    chip.title = state.storeAuthenticated
        ? `Store session active as ${state.storeUsername}. Click to disconnect.`
        : 'Store access is optional and requires network connectivity.';
}

function openStoreModal() {
    if (state.storeAuthenticated) {
        core.store.logout()
            .then((p) => applyAuthPayload(p))
            .then(() => toast('positive', 'Store disconnected', 'Store authentication cleared (volatile).'));
        return;
    }
    $('#storeModal').classList.remove('ucm-hidden');
    $('#storeFormStatus').textContent = '';
    $('#storeEmail').focus();
}
function closeStoreModal() {
    $('#storeModal').classList.add('ucm-hidden');
    setFieldState('storeEmailGroup', '');
    setFieldState('storePasswordGroup', '');
}

async function doStoreConnect(email, password) {
    let ok = true;
    if (!RE_EMAIL.test(email)) { setFieldState('storeEmailGroup', 'error', 'Enter a valid email address.'); ok = false; }
    else setFieldState('storeEmailGroup', 'valid');
    if (!password) { setFieldState('storePasswordGroup', 'error', 'Password is required.'); ok = false; }
    else setFieldState('storePasswordGroup', 'valid');
    if (!ok) return;

    const btn = $('#storeConnectBtn');
    btn.classList.add('is-disabled');
    $('#storeFormStatus').textContent = 'Connecting… (store backend must be reachable)';
    try {
        const p = await core.store.login(email, password);
        applyAuthPayload(p);
        toast('positive', 'Store connected', `snapd is now authenticated to the store as ${state.storeUsername || email}.`);
        closeStoreModal();
        loadSnaps(); // refresh: store-gated fields may now resolve
    } catch (e) {
        const offline = /unreachable|timeout|ECONNREFUSED|fetch failed|network|store backend/i.test(e.message);
        if (offline) {
            // Connectivity problem, not a credential problem: keep both
            // fields neutral and surface the cause on the status line.
            setFieldState('storePasswordGroup', '');
            setFieldState('storeEmailGroup', '');
            $('#storeFormStatus').textContent =
                'Store backend not reachable — set up the network (Network view), then retry.';
        } else {
            setFieldState('storePasswordGroup', 'error', 'Store sign-in failed: ' + e.message);
            $('#storeFormStatus').textContent = '';
        }
    } finally {
        btn.classList.remove('is-disabled');
    }
}

/* requireStore is reserved for the future private brand store (a later
   iteration) where /v2/login IS required. Global-store search and install
   must work WITHOUT it — snapd's /v2/find and /v2/snaps are open to the
   global store unauthenticated. Do not re-gate them on store login. */
function requireStore() {
    if (!state.storeAuthenticated) {
        toast('caution', 'Store not connected', 'The private brand store needs a store login — use “Connect to store” in the top bar.');
        return false;
    }
    return true;
}

/* ----------------------------- dashboard --------------------------------- */

async function loadDashboard() {
    try {
        const info = await core.system.info();
        state.snapd = info.snapd || null;
        state.host = info.host || null;
        state.netdev = info.netdev || null;
        state.warnings = info.warnings || [];
        renderDashboard();
        loadChanges();
    } catch (e) {
        toastErr(e);
    }
}

async function loadChanges() {
    try {
        state.changes = await core.system.changes('all');
        renderChanges();
    } catch { /* non-fatal */ }
}

function renderDashboard() {
    const h = state.host || {};
    const s = state.snapd || {};

    $('#brandHost').textContent = s.version ? `snapd ${s.version} · ${h.hostname || ''}` : (h.hostname || '—');
    $('#statSnapd').textContent = s.version || '—';
    $('#statSnapdHint').textContent = `on ${s.series || '—'} · ${s.on_architecture || h.arch || ''}`;

    const mem = h.mem;
    if (mem) {
        $('#statMem').textContent = mem.usedPercent + '%';
        const bar = $('#barMem');
        bar.className = 'ucm-bar' + (mem.usedPercent > 90 ? ' is-negative' : mem.usedPercent > 75 ? ' is-caution' : '');
        $('.ucm-bar__fill', bar).style.width = mem.usedPercent + '%';
        $('#statMemHint').textContent = `${fmtBytes(mem.used)} / ${fmtBytes(mem.total)}`;
    }

    if (h.load) {
        $('#statLoad').textContent = h.load.map((x) => x.toFixed(2)).join('  ');
        $('#statLoadHint').textContent = `${h.cpus} cores`;
    }
    $('#statUptime').textContent = fmtUptime(h.uptimeSec);
    $('#statUptimeHint').textContent = `${h.platform || ''} / ${h.arch || ''}`;

    const sys = [
        ['Hostname', h.hostname],
        ['Model / brand', [s.brand, s.model].filter(Boolean).join(' · ')],
        ['Device serial', s.serial],
        ['Kernel', s.kernel_version],
        ['Base release', s.version || null],
        ['Storage', s.storage ? `used ${Math.round((s.storage.used / 1000).toFixed(0))} MB of ${Math.round((s.storage.total / 1000).toFixed(0))} MB` : null],
        ['Cloud-init', s.cloud_init ? s.cloud_init.status : null],
    ];
    renderKV('#dashSystem', sys);

    const st = s.storage || {};
    renderKV('#dashStorage', [
        ['Used', fmtBytes(st.used)],
        ['Total', fmtBytes(st.total)],
        ['Used percent', st.used_percent != null ? st.used_percent + '%' : '—'],
        ['Model', st.model],
        ['Type', st.type],
    ]);

    renderKV('#dashNetdev', (state.netdev || []).filter((d) => d.name !== 'lo').map((d) => [
        d.name, `${fmtBytes(d.rxBytes)} ↓ · ${fmtBytes(d.txBytes)} ↑`,
    ]));

    const w = $('#dashWarnings');
    w.innerHTML = '';
    if (!state.warnings.length) w.append(el('p', { class: 'ucm-muted', text: 'No active warnings.' }));
    else state.warnings.forEach((x) => {
        w.append(el('p', { class: 'p-status-label p-status-label--caution', text: x.message || x.warn || JSON.stringify(x) }));
    });
}

function renderChanges() {
    const body = $('#dashChangesBody');
    body.innerHTML = '';
    const rows = (state.changes || []).slice(0, 8);
    if (!rows.length) {
        body.append(el('tr', {}, el('td', { colspan: '4', class: 'ucm-muted', text: 'No changes recorded.' })));
        return;
    }
    const label = (s) => {
        const k = String(s || '').toLowerCase();
        if (['ready', 'done', 'undone'].includes(k)) return ['positive', s];
        if (['do-error', 'errno', 'error', 'aborted', 'cancelled'].includes(k)) return ['negative', s];
        return ['caution', s];
    };
    rows.forEach((c) => {
        const [tone, word] = label(c.status);
        body.append(el('tr', {},
            el('td', { text: c.kind || '—' }),
            el('td', {}, el('span', { class: `p-status-label p-status-label--${tone}`, text: word })),
            el('td', { class: 'ucm-muted', text: fmtDate(c.spawn_time) }),
            el('td', { class: 'ucm-wrap ucm-muted', text: (c.summary && c.summary.message) || (c.err && c.err.message) || '' }),
        ));
    });
}

function renderKV(sel, pairs) {
    const box = $(sel);
    box.innerHTML = '';
    (pairs || []).forEach(([k, v]) => {
        if (v == null || v === '') return;
        box.append(el('div', {}, el('dt', { text: k }), el('dd', { text: String(v) })));
    });
    if (!box.children.length) box.append(el('p', { class: 'ucm-muted', text: 'No data.' }));
}

function startDashPoll() {
    stopDashPoll();
    state.dashPoll = setInterval(() => {
        if (state.view === 'dashboard' && state.authenticated) loadDashboard();
    }, 20000);
}
function stopDashPoll() {
    if (state.dashPoll) { clearInterval(state.dashPoll); state.dashPoll = null; }
}

/* ------------------------------- network --------------------------------- */

async function loadNetwork() {
    // interface choices from active netplan + /proc/net/dev
    try {
        const [np, info] = await Promise.all([
            core.system.netplan().catch(() => null),
            core.system.info().catch(() => null),
        ]);
        state.netplan = np;
        const names = new Set();
        const eth = np && np.network && np.network.ethernets ? Object.keys(np.network.ethernets) : [];
        eth.forEach((n) => names.add(n));
        (info && info.netdev || []).forEach((d) => names.add(d.name));
        const sel = $('#netIface');
        const cur = sel.value;
        sel.innerHTML = '';
        sel.append(el('option', { value: '', text: '— select —' }));
        Array.from(names).sort().forEach((n) => sel.append(el('option', { value: n, text: n })));
        if (Array.from(names).includes(cur)) sel.value = cur;
    } catch (e) { toastErr(e); }
    try { renderNetplan(); } catch { /* noop */ }
}

function renderNetplan() {
    const pre = $('#netplanPre');
    const doc = state.netplan;
    pre.textContent = doc ? JSON.stringify(doc, null, 2) : 'No netplan document available.';
}

function netMode() {
    return $('#netModeStatic').checked ? 'static' : 'dhcp4';
}

function applyNetModeVisibility() {
    $('#netStaticFields').classList.toggle('ucm-hidden', netMode() !== 'static');
}

async function applyNetwork() {
    const iface = $('#netIface').value;
    const status = $('#netStatus');
    if (!iface) { status.textContent = 'Select an interface.'; return; }

    const payload = { interface: iface, mode: netMode() };
    if (payload.mode === 'static') {
        let ok = true;
        const v4 = $('#netIpv4').value.trim();
        if (!RE_CIDR4.test(v4)) { setFieldState('netIpv4Group', 'error', 'Expected IPv4 with /prefix, e.g. 192.168.1.50/24.'); ok = false; }
        else setFieldState('netIpv4Group', 'valid');
        payload.ipv4 = v4;

        const g4 = $('#netGw4').value.trim();
        if (g4 && !RE_IP4.test(g4)) { setFieldState('netGw4Group', 'error', 'Expected a bare IPv4 address.'); ok = false; }
        else setFieldState('netGw4Group', g4 ? 'valid' : '');
        if (g4) payload.gateway4 = g4;

        const v6 = $('#netIpv6').value.trim();
        if (v6 && !RE_CIDR6.test(v6)) { setFieldState('netIpv6Group', 'error', 'Expected IPv6 with /prefix, e.g. fd00::1/64.'); ok = false; }
        else setFieldState('netIpv6Group', v6 ? 'valid' : '');
        if (v6) payload.ipv6 = v6;

        const g6 = $('#netGw6').value.trim();
        if (g6 && !RE_IP6.test(g6)) { setFieldState('netGw6Group', 'error', 'Expected a bare IPv6 address.'); ok = false; }
        else setFieldState('netGw6Group', g6 ? 'valid' : '');
        if (g6) payload.gateway6 = g6;

        const dns = $('#netDns').value.split(',').map((x) => x.trim()).filter(Boolean);
        if (dns.some((x) => !RE_IP4.test(x) && !RE_IP6.test(x))) {
            setFieldState('netDnsGroup', 'error', 'DNS entries must be IPv4/IPv6 addresses.'); ok = false;
        } else if (dns.length) setFieldState('netDnsGroup', 'valid');
        if (dns.length) payload.dns = dns;

        if (!ok) { status.textContent = 'Fix the highlighted fields.'; return; }
    }

    const btn = $('#netApply');
    btn.classList.add('is-disabled');
    status.textContent = 'Applying…';
    try {
        await core.network.apply(payload);
        toast('positive', 'Network applied', `snapd has applied the new netplan configuration for ${iface}.`);
        status.textContent = 'Applied ✓';
        await loadNetwork();
    } catch (e) {
        toastErr(e);
        status.textContent = 'Failed: ' + e.message;
    } finally {
        btn.classList.remove('is-disabled');
    }
}

/* -------------------------------- snaps ---------------------------------- */

/* Poll a snapd change (returned id from an install/remove/etc. write) until it
   reaches a terminal state, so the snap list can be reloaded AFTER the change
   actually settled — the old fire-and-forget reload raced the change and showed
   a stale list until the view was switched away and back. */
async function waitChangeSettled(change, timeoutMs = 10 * 60 * 1000) {
    const id = change && change.id;
    if (id == null) return null;
    const t0 = Date.now();
    while (Date.now() - t0 < timeoutMs) {
        let c;
        try { c = await core.system.change(id); }
        catch { return null; } // tracking failed — do NOT block the refresh
        if (c && c.status && c.status !== 'Doing') return c;
        await new Promise((r) => setTimeout(r, 250));
    }
    return null;
}

/* snapd's channel is track/risk; a bare "stable" means the latest track. The
   table column shows "Track / Channel" with both halves always present. */
function fmtTrackChannel(ch) {
    const c = String(ch || '');
    const [track, risk] = c.split('/');
    if (track && risk) return `${track} / ${risk}`;
    if (track && !risk) return `${track} / stable`;
    return c || '—';
}

async function loadSnaps() {
    const body = $('#snapsBody');
    try {
        state.snaps = await core.snaps.list();
        renderSnaps();
    } catch (e) {
        toastErr(e);
        body.innerHTML = '';
        body.append(el('tr', {}, el('td', { colspan: '6', class: 'ucm-muted', text: 'Could not load snaps: ' + e.message })));
    }
}

function renderSnaps() {
    const body = $('#snapsBody');
    body.innerHTML = '';
    if (!state.snaps.length) {
        body.append(el('tr', {}, el('td', { colspan: '6', class: 'ucm-muted', text: 'No snaps installed.' })));
        return;
    }
    state.snaps.forEach((s) => {
        const sk = String(s.status || '').toLowerCase();
        const statusTone =
            s.installed === null ? ['negative', 'Removed'] :
            ['disabled', 'failed', 'jailview', 'held', 'frozen'].includes(sk) ? ['negative', s.status] :
            ['activating', 'installing', 'refreshing', 'removing', 'reverting', 'switching'].includes(sk) ? ['caution', s.status] :
            ['positive', s.status || 'installed'];
        const [tone, word] = statusTone;

        const isSystem = s.type === 'core' || s.type === 'gadget' || s.type === 'kernel' || s.type === 'os' || s.name === 'snapd';
        const actions = el('div', { class: 'p-table__cell-action', style: 'text-align:right;' });

        if (!isSystem && s.installed !== null) {
            actions.append(
                rowBtn('Refresh', 'p-icon--success', () => snapOp(s.name, 'refresh')),
                rowBtn('Remove', 'p-icon--delete', () => confirmRemove(s.name)),
            );
        }
        body.append(el('tr', {},
            el('td', { text: s.name, class: 'ucm-mono' }),
            el('td', {}, el('span', { class: `p-status-label p-status-label--${tone}`, text: word })),
            el('td', { class: 'ucm-mono', text: `${s.version || '—'} · r${s.revision || '—'}` }),
            el('td', { class: 'ucm-mono', text: fmtTrackChannel(s.channel), title: s.channel || '' }),
            el('td', { text: s.type || 'app' }),
            actions,
        ));
    });
}

function rowBtn(label, icon, onClick) {
    return el('button', { class: 'p-button--base p-button ucm-rowbtn', type: 'button', onclick: onClick },
        el('i', { class: 'p-icon ' + icon }), label);
}

function confirmRemove(name) {
    // Box is built before its buttons reference it (avoids the TDZ throw the
    // old cancel handler had). One baseline-centred flex row: question icon,
    // message, action buttons — align-items:center, no stray margins.
    const box = el('div', {
        class: 'ucm-confirm ucm-confirm--negative',
        style: 'margin-top:1rem; display:flex; align-items:center; gap:.7rem;',
    });
    const icon = el('i', { class: 'p-icon--question ucm-confirm__ic' });
    const msg = el('p', { class: 'p-notification__message ucm-confirm__msg', text: `Permanently remove snap “${name}”?` });
    const b = el('button', { class: 'p-button--negative p-button', type: 'button', text: `Remove ${name}?` });
    b.onclick = async () => {
        b.classList.add('is-disabled');
        try {
            const change = await core.snaps.action(name, 'remove');
            toast('positive', 'Removal started', `${name} is being removed by snapd.`);
            const done = await waitChangeSettled(change);
            loadSnaps();
            if (done && done.status && done.status.toLowerCase() !== 'done') {
                toast('negative', 'Removal finished with an error', `${name}: ${done.err || done.status}`);
            }
        } catch (e) { toastErr(e); }
        finally { box.remove(); }
    };
    const cancel = el('button', { class: 'p-button--base p-button', type: 'button', text: 'Cancel' });
    cancel.onclick = () => box.remove();
    box.append(icon, msg, b, cancel);
    $('#snapsBody').closest('.ucm-table-wrap').after(box);
    b.focus();
}

async function snapOp(name, action) {
    try {
        const change = await core.snaps.action(name, action);
        toast('positive', 'Change started', `${action} on ${name} is running in snapd.`);
        await waitChangeSettled(change);
        loadSnaps();
    } catch (e) { toastErr(e); }
}

/* Install a specific store result row. The channel pulldown and its options
   live on the row (channels are store-defined, possibly versioned e.g.
   stable/22.04) — never hardcoded. */
async function installFromRow(name, channel, btn) {
    if (!btn) return;
    btn.classList.add('is-disabled');
    btn.textContent = 'Installing…';
    try {
        const change = await core.snaps.install(name, channel);
        toast('positive', 'Install started', `${name} is being installed from channel ${channel}.`);
        const done = await waitChangeSettled(change);
        loadSnaps();
        if (done && done.status && done.status.toLowerCase() !== 'done') {
            toast('negative', 'Install finished with an error', `${name}: ${done.err || done.status}`);
        }
    } catch (e) {
        toastErr(e);
    } finally {
        btn.classList.remove('is-disabled');
        btn.textContent = 'Install';
    }
}

/* Build the per-row channel <select> from a result's `channels` map. Picks the
   best default (latest/stable > stable > first) so the Install button is ready. */
function channelSelect(r) {
    const chs = Object.keys(r.channels || {});
    const sel = el('select', { style: 'max-width:12rem;' });
    if (!chs.length) {
        sel.append(el('option', { value: 'stable', text: 'stable' }));
        return sel;
    }
    const best = chs.find((c) => c === 'latest/stable') || chs.find((c) => c === 'stable') || chs[0];
    chs.sort((x, y) => x.localeCompare(y)).forEach((c) => sel.append(el('option', { value: c, text: c })));
    sel.value = best;
    return sel;
}

function clearStoreResults() {
    $('#snapSearchBody').innerHTML = '';
    $('#snapSearchResults').classList.add('ucm-hidden');
}

async function searchStore() {
    const nameEl = $('#snapSearchName');
    const q = nameEl.value.trim();
    if (!q) { toast('caution', 'Search', 'Enter a snap name to search the store.'); return; }
    const box = $('#snapSearchResults');
    box.classList.remove('ucm-hidden');
    $('#snapSearchBody').innerHTML = '';
    $('#snapSearchBody').append(el('tr', {}, el('td', { colspan: '5', class: 'ucm-muted', text: 'Searching…' })));
    try {
        const results = await core.snaps.search(q, 8);
        $('#snapSearchBody').innerHTML = '';
        if (!results.length) {
            $('#snapSearchBody').append(el('tr', {}, el('td', { colspan: '5', class: 'ucm-muted', text: 'No store results.' })));
            return;
        }
        results.forEach((r) => {
            const publisher = r.publisher && r.publisher.username;
            const chSel = channelSelect(r);
            const installBtn = el('button', {
                class: 'p-button--brand p-button ucm-rowbtn',
                type: 'button',
                onclick: () => installFromRow(r.name, chSel.value, installBtn),
            }, 'Install');
            $('#snapSearchBody').append(el('tr', {},
                el('td', { text: r.name, class: 'ucm-mono' }),
                el('td', { class: 'ucm-wrap', text: r.summary || '' }),
                el('td', { text: publisher || '—' }),
                el('td', {}, chSel),
                el('td', { style: 'text-align:right;', onclick: (e) => { e.stopPropagation(); } }, installBtn),
            ));
        });
    } catch (e) {
        $('#snapSearchBody').innerHTML = '';
        $('#snapSearchBody').append(el('tr', {}, el('td', { colspan: '5', class: 'ucm-muted', text: 'Search failed: ' + e.message })));
    }
}

/* ----------------------------- interfaces -------------------------------- */
/* Verified snapd /v2/connections contract:
 *   GET /v2/connections            -> { established:[c], undesired:[c],
 *                                       plugs:[p], slots:[s] }
 *   c = { interface, plug:{snap,plug}, slot:{snap,slot}, manual, gadget }
 *   p = { snap, name, interface, connections:[{snap,slot}], label, apps }
 *   s = { snap, name, interface, connections:[{snap,plug}], label, apps }
 *   POST /v2/interfaces {action:"connect"|"disconnect",
 *                        plug:{snap,plug}, slot:{snap,slot}}
 */

async function loadInterfaces() {
    const body = $('#ifacesBody');
    try {
        state.connections = await core.interfaces.list();
        renderInterfaces();
    } catch (e) {
        toastErr(e);
        body.innerHTML = '';
        body.append(el('tr', {}, el('td', { colspan: '5', class: 'ucm-muted', text: 'Could not load connections: ' + e.message })));
    }
}

const plugTxt = (p) => p ? `${p.snap}:${p.plug}` : '—';
const slotTxt = (s) => s ? `${s.snap}:${s.slot}` : '—';

function renderInterfaces() {
    const body = $('#ifacesBody');
    body.innerHTML = '';
    const c = state.connections || {};
    const established = c.established || [];
    const undesired = c.undesired || [];
    const plugs = c.plugs || [];
    const slots = c.slots || [];

    const rows = [];
    established.forEach((x) => rows.push({ type: 'connected', iface: x.interface, plug: x.plug, slot: x.slot, manual: x.manual, gadget: x.gadget }));
    undesired.forEach((x) => rows.push({ type: 'disconnected', iface: x.interface, plug: x.plug, slot: x.slot }));
    plugs.forEach((p) => {
        if (!p.connections || !p.connections.length) {
            rows.push({ type: 'available', iface: p.interface, plug: { snap: p.snap, plug: p.name }, slot: null });
        }
    });
    if (state.ifacesPendingOnly) {
        rows.length = 0;
        undesired.forEach((x) => rows.push({ type: 'disconnected', iface: x.interface, plug: x.plug, slot: x.slot }));
        plugs.forEach((p) => {
            if (!p.connections || !p.connections.length) {
                rows.push({ type: 'available', iface: p.interface, plug: { snap: p.snap, plug: p.name }, slot: null });
            }
        });
    }

    $('#ifacesSummary').textContent = `${established.length} connected · ${undesired.length} pending · ${plugs.filter((p) => !p.connections || !p.connections.length).length} available plugs`;

    if (!rows.length) {
        body.append(el('tr', {}, el('td', { colspan: '5', class: 'ucm-muted', text: 'No interface connections to show.' })));
        return;
    }

    rows.forEach((r) => {
        const actions = el('div', { style: 'text-align:right;' });
        if (r.type === 'connected') {
            actions.append(rowBtn('Disconnect', 'p-icon--delete', () => ifaceOp('disconnect', r)));
        } else {
            const slotSel = el('select', { style: 'max-width:13rem; margin-right:.4rem;' }, el('option', { value: '', text: 'target slot…' }));
            slots
                .filter((s) => s.interface === r.iface)
                .forEach((s) => slotSel.append(el('option', {
                    value: s.snap + '|' + s.name,
                    text: `${s.snap}:${s.name}`,
                })));
            if (r.slot) {
                const pre = r.slot.snap + '|' + r.slot.slot;
                if (Array.from(slotSel.options).some((o) => o.value === pre)) slotSel.value = pre;
            }
            const go = el('button', { class: 'p-button--positive p-button', type: 'button' }, 'Connect');
            go.onclick = () => {
                const [snap, name] = (slotSel.value || '').split('|');
                if (!snap) { toast('caution', 'Connect', 'Pick a target slot.'); return; }
                ifaceOp('connect', { plug: r.plug, slot: { snap, slot: name } });
            };
            actions.append(slotSel, go);
        }

        const tone = r.type === 'connected' ? 'positive' : 'caution';
        const word = r.type === 'connected'
            ? (r.gadget ? 'Gadget' : r.manual ? 'Manual' : 'Auto')
            : (r.type === 'disconnected' ? 'Disconnected' : 'Available');

        body.append(el('tr', {},
            el('td', { text: r.iface || '—' }),
            el('td', { class: 'ucm-mono', text: slotTxt(r.slot) }),
            el('td', { class: 'ucm-mono', text: plugTxt(r.plug) }),
            el('td', {}, el('span', { class: `p-status-label p-status-label--${tone}`, text: word })),
            actions,
        ));
    });
}

async function ifaceOp(op, item) {
    try {
        if (op === 'connect') await core.interfaces.connect(item.plug, item.slot);
        else await core.interfaces.disconnect(item.plug, item.slot);
        toast('positive', op === 'connect' ? 'Connected' : 'Disconnected',
            `${plugTxt(item.plug)} ↔ ${slotTxt(item.slot)} (${item.iface || 'interface'})`);
        loadInterfaces();
    } catch (e) { toastErr(e); }
}

/* ------------------------------- wiring ---------------------------------- */

function wire() {
    // local gate: first boot + login + lock
    $('#setupForm').addEventListener('submit', (e) => {
        e.preventDefault();
        doCreatePassword();
    });
    $('#loginForm').addEventListener('submit', (e) => {
        e.preventDefault();
        doLogin($('#loginPassword').value);
    });
    $('#lockBtn').addEventListener('click', doLock);

    // nav
    $$('.ucm-side .p-side-navigation__link').forEach((a) => {
        a.addEventListener('click', (e) => { e.preventDefault(); switchView(a.dataset.view); });
    });

    // main push events (local lock + store changes)
    core.auth.onStatusChanged((p) => applyAuthPayload(p));

    // optional store connect
    $('#storeBtn').addEventListener('click', openStoreModal);
    $('#storeModalClose').addEventListener('click', closeStoreModal);
    $$('#storeModal [data-close="store"]').forEach((n) => n.addEventListener('click', closeStoreModal));
    $('#storeForm').addEventListener('submit', (e) => {
        e.preventDefault();
        doStoreConnect($('#storeEmail').value.trim(), $('#storePassword').value);
    });
    $('#storeDisconnectBtn').addEventListener('click', () => {
        core.store.logout().then((p) => applyAuthPayload(p)).then(closeStoreModal);
    });

    // dashboard
    $('#dashChangesRefresh').addEventListener('click', loadChanges);

    // network
    $('#netModeDhcp').addEventListener('change', applyNetModeVisibility);
    $('#netModeStatic').addEventListener('change', applyNetModeVisibility);
    $('#netApply').addEventListener('click', applyNetwork);
    $('#netplanRefresh').addEventListener('click', () => loadNetwork());
    $('#netReset').addEventListener('click', () => {
        ['netIpv4', 'netGw4', 'netIpv6', 'netGw6', 'netDns'].forEach((id) => { $('#' + id).value = ''; });
        ['netIpv4Group', 'netGw4Group', 'netIpv6Group', 'netGw6Group', 'netDnsGroup'].forEach((id) => setFieldState(id, ''));
        $('#netStatus').textContent = '';
        $('#netModeDhcp').checked = true;
        applyNetModeVisibility();
    });

    // snaps — the search field is a search ONLY: Enter runs the search, never
    // installs. Per-row Install buttons (in the results card) do the install.
    $('#snapSearchBtn').addEventListener('click', searchStore);
    $('#snapSearchName').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); searchStore(); } });
    $('#snapSearchClear').addEventListener('click', clearStoreResults);

    // interfaces
    $('#ifacesRefresh').addEventListener('click', loadInterfaces);
    $('#ifacesFilterBtn').addEventListener('click', () => {
        state.ifacesPendingOnly = !state.ifacesPendingOnly;
        $('#ifacesFilterBtn').textContent = state.ifacesPendingOnly ? 'Show: actionable (not connected)' : 'Show: all';
        renderInterfaces();
    });
}

/* -------------------------------- boot ----------------------------------- */

document.addEventListener('DOMContentLoaded', async () => {
    if (!core || typeof core.auth?.status !== 'function') {
        // No context bridge (e.g. opened in a plain browser during development).
        document.body.insertAdjacentHTML('afterbegin',
            '<div class="p-notification p-notification--negative" style="position:fixed;top:0;left:0;right:0;z-index:99;">' +
            '<p class="p-notification__message">Ubuntu Core Manager must be launched through the Electron kiosk (main.js). ' +
            'The secure IPC bridge (window.ucmCore) is not available in this context.</p></div>');
        return;
    }
    wire();
    applyNetModeVisibility();
    try {
        applyAuthPayload(await core.auth.status());
        if (state.authenticated) enterApp();
        else showGate();
    } catch {
        showGate();
    }
});
