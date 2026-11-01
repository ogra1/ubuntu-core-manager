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
 *   - STORE auth (optional, volatile): snapd /v2/login macaroons. The UI no
 *     longer exposes a store login — on Ubuntu Core the device's store
 *     attachment comes from the model assertion baked into the image, and
 *     global-store search/install work unauthenticated. The backend path
 *     stays for a possible private brand store (later iteration).
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
// snapd timestamps (UTC ISO, e.g. refresh.last/next) -> local
// 'dd.mm.yyyy hh:mm' (user preference). '—' on missing/invalid.
const fmtDm = (iso) => {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return '—';
    const p = (n) => String(n).padStart(2, '0');
    return `${p(d.getDate())}.${p(d.getMonth() + 1)}.${d.getFullYear()} ${p(d.getHours())}:${p(d.getMinutes())}`;
};;

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
    model: null,       // model assertion headers (parsed in main.js)
    host: null,
    cpuSeries: null,      // last sys:cpu sample: (number|null)[] oldest->newest
    cpuPoll: null,
    netplan: null,
    changes: [],
    warnings: [],
    netdev: null,
    dataDisk: null,    // /run/mnt/data usage (statfs) — main.js
    netSeries: null,   // {r,x}[] rates in KiB/s (main.js sampler)
    netIface: null,    // device the net series is counted on (default-route iface)
    netPoll: null,
    snaps: [],
    connections: [],
    ifacesPendingOnly: true,
    manualLock: false,
    sessionTick: null,
    dashPoll: null,
};

const VIEWS = ['dashboard', 'network', 'snaps', 'interfaces', 'settings'];
const VIEW_TITLES = { dashboard: 'Dashboard', network: 'Network configuration', snaps: 'Snap packages', interfaces: 'Snap interfaces', settings: 'Settings' };

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
        dashboard: () => { loadDashboard(); sampleCpu(); sampleNet(); },
        network: loadNetwork,
        snaps: loadSnaps,
        interfaces: loadInterfaces,
        settings: () => {},
    })[name]();
}

function enterApp() {
    showGate();
    startSessionTick();
    startDashPoll();
    startCpuPoll();
    startNetPoll();
    const fromHash = (location.hash || '').replace('#', '');
    switchView(VIEWS.includes(fromHash) ? fromHash : 'dashboard');
}

function exitApp() {
    stopSessionTick();
    stopDashPoll();
    stopCpuPoll();
    stopNetPoll();
    $('#setupPassword').value = '';
    $('#setupConfirm').value = '';
    $('#loginPassword').value = '';
    $('#resetCurrent').value = '';
    $('#resetConfirm').value = '';
    setFieldState('setupPasswordGroup', '');
    setFieldState('setupConfirmGroup', '');
    setFieldState('loginPasswordGroup', '');
    setFieldState('resetCurrentGroup', '');
    setFieldState('resetConfirmGroup', '');
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
    const wasInit = state.initialized;
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
        if (wasInit && !state.initialized) {
            // The credential was just wiped (guarded reset) — not a lock.
            // Next launch is first-boot setup again.
            toast('positive', 'Password wiped',
                'The local administrator credential was erased. Set a new password to continue.');
        } else {
            toast('info', manual ? 'Console locked' : 'Session locked',
                manual ? 'Re-enter the administrator password to continue.'
                       : 'The console was locked after inactivity. Sign in to continue.');
        }
    }
    showGate();
}

/* ------------------------- store (backend only) -------------------------- *
 * The snap store login (snapd /v2/login macaroons) is deliberately NOT
 * surfaced in the UI: on Ubuntu Core the device's store attachment is
 * handled by the model assertion baked into the image, and global-store
 * search/install work unauthenticated. The main-process backend
 * (storeLogin/storeLogout) is kept for a possible private brand store in a
 * later iteration — do not re-add UI around it without that decision.
 */

/* ----------------------------- dashboard --------------------------------- */

async function loadDashboard() {
    try {
        const info = await core.system.info();
        state.snapd = info.snapd || null;
        state.model = info.model || null;   // model assertion headers (main.js)
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
        // /v2/changes returns NO stable order (snapd's internal map
        // iteration) — sort newest-first by spawn-time ourselves, so the
        // card doesn't reshuffle between 20 s refreshes.
        state.changes = [...state.changes].sort((x, y) => {
            const a = new Date(x['spawn-time'] || x.spawn_time || 0).getTime();
            const b = new Date(y['spawn-time'] || y.spawn_time || 0).getTime();
            return b - a;
        });
        renderChanges();
    loadDataDisk();
    } catch { /* non-fatal */ }
}

function renderDashboard() {
    const h = state.host || {};
    const s = state.snapd || {};

    // The snapd version no longer has a stat card — it stays visible in the
    // rail under the logo (brandHost). Never reference the removed
    // #statSnapd/#statSnapdHint here: renderDashboard would throw and the
    // whole dashboard would render empty.
    $('#brandHost').textContent = s.version ? `snapd ${s.version} · ${h.hostname || ''}` : (h.hostname || '—');
    // Device model — model-assertion identity lives in the stat strip
    // (the snapd version was here; it stays visible in the rail under the
    // logo, and per user decision it is not dashboard-tier info). The
    // brand-id line was DROPPED: real VM font metrics wrapped the long
    // account id in the narrow card (user decision: not worth fighting).
    const mod = state.model || {};
    const mstat = $('#modelStat');
    mstat.hidden = false; // always shown: keeps the 4-up stat grid even pre-model
    if (mod.model) {
        $('#modelLabel').textContent = 'Model';
        $('#statModel').textContent = mod.model || '—';
        $('#statModelHint').textContent = [mod.base, mod.grade].filter(Boolean).join(' · ');
    } else {
        // defensive fallback (shouldn't happen on Ubuntu Core): snapd version
        $('#modelLabel').textContent = 'Snapd';
        $('#statModel').textContent = s.version || '—';
        $('#statModelHint').textContent = `on ${s.series || '—'}`;
    }

    const mem = h.mem;
    if (mem) {
        $('#statMem').textContent = mem.usedPercent + '%';
        const bar = $('#barMem');
        bar.className = 'ucm-bar' + (mem.usedPercent > 90 ? ' is-negative' : mem.usedPercent > 75 ? ' is-caution' : '');
        $('.ucm-bar__fill', bar).style.width = mem.usedPercent + '%';
        $('#statMemHint').textContent = `${fmtBytes(mem.used)} / ${fmtBytes(mem.total)}`;
    }

    if (h.load) {
        // the 1/5/15-min averages stay small here — the utilization
        // sparkline + current % (statCpuNow) carry the primary metric.
        $('#statLoad').textContent = h.load.map((x) => x.toFixed(2)).join(' · ');
        $('#statLoadHint').textContent = '1m · 5m · 15m — ' + h.cpus + ' cores';
    }
    if (state.cpuSeries) renderCpuChart();
    $('#statUptime').textContent = fmtUptime(h.uptimeSec);
    // last/next automatic refresh (snapd /v2/system-info refresh{last,next},
    // UTC ISO — rendered in LOCAL time, dd.mm.yyyy hh:mm). One labeled line
    // per stamp: two hint divs = forced line wrap between them.
    const rf = s.refresh || {};
    $('#statUptimeLast').textContent = `Last refresh ${fmtDm(rf.last)}`;
    $('#statUptimeNext').textContent = `Next refresh ${fmtDm(rf.next)}`;

    // System card: platform facts from /v2/system-info (real snapd field
    // names: hyphenated kernel-version, architecture, os-release{ id,
    // version-id }). Device identity (model/base/grade/brand) lives in the
    // 'Model' stat card — keeping the list compact so the default 50/50
    // .ucm-kv columns never need mangling.
    const osr = s['os-release'] || {};
    const sys = [
        ['Hostname', h.hostname],
        ['Kernel', s['kernel-version']],
        ['Architecture', s.architecture],
        ['OS release', [osr.id, osr['version-id']].filter(Boolean).join(' ') || null],
    ];
    renderKV('#dashSystem', sys);

    renderDataDisk();

    // Network activity card: the graphs count the DEFAULT-ROUTE interface
    // (main.js readNetTraffic); the label is set by renderNetIface() from the
    // sampler's own iface so it always matches the graphed device.
    if (state.netSeries) { renderNetGraph(); renderNetIface(); }

    // Warnings: the card is small — show only the LATEST warning
    // (max 'last-seen' when present) and ellipsize long messages so the
    // card keeps its shape; full text in the title attr.
    const w = $('#dashWarnings');
    w.innerHTML = '';
    const warns = state.warnings || [];
    if (!warns.length) {
        w.append(el('p', { class: 'ucm-muted', text: 'No active warnings.' }));
    } else {
        const latest = [...warns].sort((x, y) =>
            String(y['last-seen'] || '').localeCompare(String(x['last-seen'] || '')))[0];
        const msg = latest.message || latest.warn || JSON.stringify(latest);
        const shown = msg.length > 60 ? msg.slice(0, 60).trimEnd() + '…' : msg;
        w.append(el('p', { class: 'p-status-label p-status-label--caution', text: shown, title: msg }));
    }
}

/** Data partition: /run/mnt/data on Ubuntu Core (the writable
 * space that actually belongs to the user), '/' elsewhere. The donut is
 * used-vs-free of the whole partition (df arithmetic, incl. the small
 * root-reserved wedge); the rows spell that out. */
function renderDataDisk() {
    const d = state.dataDisk;
    const set = (id, v) => { const e = $('#' + id); if (e) e.textContent = v; };
    if (!d) {
        set('dataDiskPct', '—'); set('dataDiskTotal', '—');
        set('dataDiskUsed', '—'); set('dataDiskFree', '—');
        const src = $('#dataDiskSrc');
        if (src) src.textContent = '';
        const donut = $('#dataDiskDonut');
        if (donut) donut.style.background = 'conic-gradient(#e9e9e9 0 360deg)';
        return;
    }
    set('dataDiskPct', Math.round(d.usedPercent) + '%');
    set('dataDiskTotal', fmtBytes(d.totalBytes));
    set('dataDiskUsed', fmtBytes(d.usedBytes));
    set('dataDiskFree', fmtBytes(d.freeBytes));
    const src = $('#dataDiskSrc');
    if (src) src.textContent = d.fsType || '—';
    const donut = $('#dataDiskDonut');
    if (donut) {
        const p = Math.min(100, Math.max(0, d.usedPercent));
        donut.style.background =
            `conic-gradient(var(--ucm-orange) 0 ${p}%, #e9e9e9 ${p}% 100%)`;
    }
}

async function loadDataDisk() {
    try {
        state.dataDisk = await core.system.dataDisk();
        renderDataDisk();
    } catch { /* non-fatal; card shows em-dashes */ }
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
        // LIVE snapd shape (verified 2.77): 'spawn-time' is HYPHENATED and
        // 'summary' is a plain STRING — the stub used to feed 'spawn_time'
        // + {summary:{message}} (round-19 class bug: two of the four columns
        // rendered blank on real devices). Read the real fields, with the
        // legacy forms as fallbacks.
        const when = c['spawn-time'] != null ? c['spawn-time'] : c.spawn_time;
        const text = (typeof c.summary === 'string' && c.summary)
            || (c.summary && c.summary.message)
            || (c.err && c.err.message)
            || '';
        body.append(el('tr', {},
            el('td', { text: c.kind || '—' }),
            el('td', {}, el('span', { class: `p-status-label p-status-label--${tone}`, text: word })),
            el('td', { class: 'ucm-muted', text: fmtDm(when) }),
            el('td', { class: 'ucm-wrap ucm-muted', text }),
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

/* CPU utilization sparkline — 2 s cadence (matches the main-process
 * /proc/stat sampler), 100 samples = 3 min window. The renderer only
 * draws; all sampling math happens in main.js. */
function startCpuPoll() {
    stopCpuPoll();
    state.cpuPoll = setInterval(() => {
        if (state.view === 'dashboard' && state.authenticated) sampleCpu();
    }, 2000);
}
function stopCpuPoll() {
    if (state.cpuPoll) { clearInterval(state.cpuPoll); state.cpuPoll = null; }
}
async function sampleCpu() {
    try {
        state.cpuSeries = await core.system.cpu();
        renderCpuChart();
    } catch { /* non-fatal: next tick retries */ }
}

function startNetPoll() {
    stopNetPoll();
    state.netPoll = setInterval(() => {
        if (state.view === 'dashboard' && state.authenticated) sampleNet();
    }, 2000);
}
function stopNetPoll() {
    if (state.netPoll) { clearInterval(state.netPoll); state.netPoll = null; }
}
async function sampleNet() {
    try {
        const res = await core.system.net();
        state.netSeries = res.series;
        state.netIface = res.iface;
        renderNetGraph();
        renderNetIface();
    } catch { /* non-fatal: next tick retries */ }
}
function renderNetIface() {
    // the sampler names the device it counted (default-route iface) — show
    // exactly that, so the label always matches the graphed data.
    $('#netIfaceSrc').textContent = state.netIface || 'no default route';
}


/* Net in/out sparklines (KiB/s rates from the main-process sampler).
 * Auto-scaled per graph to the window peak (floor 1 KiB/s so an idle
 * line stays flat at the baseline instead of jittering at 0.01%). */
function renderNetSpark(lineSel, areaSel, nowSel, key) {
    const series = state.netSeries;
    const line = $(lineSel), area = $(areaSel);
    if (!line || !area || !Array.isArray(series) || !series.length) return;
    const n = series.length, W = 100, H = 30;
    const vals = series.map((p) => (p && p[key] != null ? p[key] : null));
    const known = vals.filter((v) => v != null);
    const mx = Math.max(1, ...known);
    let d = '';
    for (let i = 0; i < n; i++) {
        const v = vals[i];
        if (v == null) continue;
        const x = (i / (n - 1 || 1)) * W;
        const y = H - (v / mx) * H;
        d += (d ? 'L' : 'M') + x.toFixed(2) + ' ' + y.toFixed(2);
    }
    if (!d) return;
    line.setAttribute('d', d);
    area.setAttribute('d', d + 'L' + W + ' ' + H + 'L0 ' + H + 'Z');
    const last = [...vals].reverse().find((v) => v != null);
    $(nowSel).textContent = last != null ? fmtRate(last) : '—';
}
const fmtRate = (kib) =>
    kib >= 1024 ? (kib / 1024).toFixed(1) + ' MiB/s' : kib.toFixed(1) + ' KiB/s';
function renderNetGraph() {
    renderNetSpark('#netDownLine', '#netDownArea', '#netDownNow', 'r');
    renderNetSpark('#netUpLine', '#netUpArea', '#netUpNow', 'x');
}

function renderCpuChart() {
    const series = state.cpuSeries;
    const line = $('#cpuLine'), area = $('#cpuArea');
    if (!line || !area || !Array.isArray(series) || !series.length) return;
    const n = series.length, W = 100, H = 30;
    let d = '';
    for (let i = 0; i < n; i++) {
        const v = series[i];
        if (v == null) continue;
        const x = (i / (n - 1 || 1)) * W;
        const y = H - (Math.min(100, Math.max(0, v)) / 100) * H;
        d += (d ? 'L' : 'M') + x.toFixed(2) + ' ' + y.toFixed(2);
    }
    if (!d) return; // no deltas yet (fresh boot)
    line.setAttribute('d', d);
    area.setAttribute('d', d + 'L' + W + ' ' + H + 'L0 ' + H + 'Z');
    const last = [...series].reverse().find((v) => v != null);
    $('#statCpuNow').textContent = last != null ? Math.round(last) + '%' : '—';
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
/* snapd change status vocabulary (live-verified against snapd 2.77): the
   in-flight state is "Doing", but snapd ALSO emits transient non-terminal
   values (observed: "Do") while a change runs, and the terminal states are
   Done / Error / Undo / Undoing. We must therefore classify TERMINAL states
   explicitly and keep polling on anything else — the old "return when
   status !== 'Doing'" rule treated the transient "Do" as a finished error,
   surfacing toasts like 'Removal finished with an error: htop: Do'. */
const CHANGE_TERMINAL = new Set(['done', 'error', 'undo', 'undoing']);
function isChangeTerminal(status) {
    return CHANGE_TERMINAL.has(String(status || '').toLowerCase());
}

async function waitChangeSettled(change, timeoutMs = 10 * 60 * 1000) {
    const id = change && (change.id != null ? change.id : change.change != null ? change.change : null);
    if (id == null) return null; // no change id in the response — nothing to wait on
    const t0 = Date.now();
    while (Date.now() - t0 < timeoutMs) {
        let c;
        try { c = await core.system.change(String(id)); }
        catch { return null; } // tracking failed — do NOT block the refresh
        if (c && isChangeTerminal(c.status)) return c;
        await new Promise((r) => setTimeout(r, 250));
    }
    return null;
}

/* Installed-snap channel display. VERIFIED against live snapd 2.77 (/v2/snaps):
   an installed snap reports `channel` = RISK ONLY (e.g. "stable") and the real
   track in `tracking-channel` (e.g. "latest/stable"). So: prefer
   tracking-channel, split into "Track / Channel"; fall back to channel.
   Formatting the risk-only `channel` produced the "stable/stable" bug. */
function fmtTrackChannel(snap) {
    const tc = String((snap && (snap.tracking_channel || snap.trackingChannel || snap['tracking-channel'])) || '');
    const ch = String((snap && snap.channel) || '');
    const full = tc || ch;
    if (!full) return '—';
    const [track, risk] = full.split('/');
    if (track && risk) return `${track}/${risk}`;
    if (track && !risk) return `${track}/stable`;
    return full; // bare risk (e.g. "stable") — no track info available
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

/* Round 34: per-row snap actions — ICON-ONLY with Vanilla tooltips.
   The old column showed "Config / Refresh / Remove" as icon+text each (crowded);
   the bundle has no refresh/gear/power icons and p-icon--success is a green
   checkmark (wrong semantic for Refresh), so the actions now use the suru
   glyphs shipped in build/images (see .p-icon--settings/refresh/revert/power
   in app.css):
     Config   = gear (suru settings)
     Refresh  = circular reload arrow (suru view-refresh)
     Revert   = backward-curving undo arrow (suru revert)
     Disable  = power switch, BLACK when the snap is enabled
     Enable   = power switch, RED when the snap is disabled (toggles to Enable)
     Remove   = trash can (bundle p-icon--delete, unchanged)
   Each button IS its own Vanilla .p-tooltip--top-right trigger: the
   .p-tooltip__message child (CSS-only, shown on :hover/:focus) carries the
   label, so the tooltip also appears for keyboard focus (a wrapper span would
   only match :focus on the span itself, which is not focusable). top-right is
   used because the Actions column is right-aligned — the tooltip extends left
   over the table instead of being clipped at the table-wrap's right edge.
   Disabled detection — LIVE snapd 2.77 contract (probe34b over the real
   /run/snapd.socket; daemon/snap.go mapLocal): a DISABLED snap reports
   status "installed" (there is no "disabled" status string) and the REST
   response carries NO `active` field; an ENABLED snap reports status "active".
   So "not active" = disabled. The legacy "disabled" status (pre-2.7x fixtures)
   is still treated as disabled. Consequence for the Status badge column: a
   live-disabled snap shows "installed", which is indistinguishable from an
   active one — the badge is re-derived through the same detector so it reads
   "disabled" (red) instead of a misleading green "installed". */
function snapDisabled(s) {
    const st = String(s.status || '').toLowerCase();
    return !s.active && (st === 'installed' || st === 'disabled');
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
            ['failed', 'jailview', 'held', 'frozen'].includes(sk) ? ['negative', s.status] :
            ['activating', 'installing', 'refreshing', 'removing', 'reverting', 'switching'].includes(sk) ? ['caution', s.status] :
            ['positive', s.status || 'installed'];
        const [tone, word] = statusTone;
        // A snap that reports "installed" (live snapd: not-active == disabled)
        // or the legacy "disabled" status gets the red badge, never a green
        // "installed" — otherwise it would contradict the red Enable power icon.
        const disabled = snapDisabled(s);
        const dispTone = disabled ? 'negative' : tone;
        const dispWord = disabled ? 'disabled' : word;

        const isSystem = s.type === 'core' || s.type === 'gadget' || s.type === 'kernel' || s.type === 'os' || s.name === 'snapd';
        const actions = el('div', { class: 'p-table__cell-action ucm-actions', style: 'text-align:right;' });

        if (!isSystem && s.installed !== null) {
            actions.append(
                rowBtn('Configure ' + s.name, 'p-icon--settings', () => openConfigModal(s.name)),
                rowBtn('Refresh ' + s.name, 'p-icon--refresh', () => snapOp(s.name, 'refresh')),
                rowBtn('Revert ' + s.name, 'p-icon--revert', () => snapOp(s.name, 'revert')),
                rowBtn(disabled ? ('Enable ' + s.name) : ('Disable ' + s.name),
                    disabled ? 'p-icon--power p-icon--power-red' : 'p-icon--power',
                    () => snapOp(s.name, disabled ? 'enable' : 'disable')),
                rowBtn('Remove ' + s.name, 'p-icon--delete', () => confirmRemove(s.name)),
            );
        }
        body.append(el('tr', {},
            el('td', { text: s.name, class: 'ucm-mono' }),
            el('td', {}, el('span', { class: `p-status-label p-status-label--${dispTone}`, text: dispWord })),
            el('td', { class: 'ucm-mono', text: `${s.version || '—'} (${s.revision != null ? s.revision : '—'})` }),
            el('td', { class: 'ucm-mono', text: fmtTrackChannel(s), title: `${s.tracking_channel || s.channel || '—'}` }),
            el('td', { text: s.type || 'app' }),
            el('td', { style: 'text-align:right;' }, actions),
        ));
    });
}

/* Icon-only row action button: the button itself is the Vanilla tooltip
   trigger (p-tooltip--top-right) so the label shows on hover AND keyboard
   focus; the label is also the aria-label. Compact padding keeps a five-icon
   row tight in the Actions cell. NOTE: the tooltip message element keeps the
   raw label as its TEXT so it is visible in CSS-less contexts (the
   screenshot harness) — in-app the bundle hides it until :hover/:focus. */
function rowBtn(label, icon, onClick) {
    return el('button', {
        class: 'p-button--base p-button ucm-rowbtn ucm-iconbtn p-tooltip--top-right',
        type: 'button',
        'aria-label': label,
        'data-tooltip': label,
        onclick: onClick,
    },
        el('i', { class: icon }),
        el('span', { class: 'p-tooltip__message', text: label }));
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
            if (done && done.status && isChangeTerminal(done.status) && done.status.toLowerCase() !== 'done') {
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
        if (done && done.status && isChangeTerminal(done.status) && done.status.toLowerCase() !== 'done') {
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

/* ------------------------- snap configuration ---------------------------- */
/* Per-snap config (snapd /v2/snaps/{name}/conf). Keys follow snapd's dotted
   identifier grammar (validated again in main.js before the socket). Values
   are scalars: string / number / boolean, or null (removes the key). The
   modal edits ONE key at a time — snapd's conf API is a key map, and that
   matches how snap configs actually look (rare, small, scalar). */
const RE_CONF_KEY_UI = /^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?)*$/;

function openConfigModal(name) {
    const card = $('#snapsBody').closest('.ucm-table-wrap');
    const box = el('div', { class: 'ucm-modal' });
    const backdrop = el('div', { class: 'ucm-modal__backdrop', onclick: () => box.remove() });
    const inner = el('div', { class: 'ucm-modal__card' });

    const head = el('div', { class: 'ucm-modal__head' });
    head.append(
        el('p', { class: 'p-heading--5', text: `Configure ${name}`, style: 'margin:0;' }),
        el('button', { class: 'p-button--base p-button', type: 'button', 'aria-label': 'Close', onclick: () => box.remove() },
            el('i', { class: 'p-icon--close' })),
    );

    const bodyBox = el('div', { class: 'ucm-modal__body ucm-config' });
    bodyBox.append(el('p', { class: 'ucm-muted', text: 'Loading configuration…', id: 'cfgStatus' }));
    inner.append(head, bodyBox);
    box.append(backdrop, inner);
    document.body.append(box);

    let current = null; // { key, label, has, type }
    const close = () => box.remove();

    function typeSelect() {
        const sel = el('select', { id: 'cfgType' });
        ['string', 'number', 'boolean', 'delete'].forEach((t) => sel.append(el('option', { value: t, text: t })));
        sel.value = (current && current.type) || 'string';
        return sel;
    }

    function render() {
        bodyBox.innerHTML = '';
        const st = $('#cfgStatus');
        if (st) st.remove();

        const form = el('form', { novalidate: '' });
        form.addEventListener('submit', (e) => e.preventDefault());

        const keyGroup = el('div', { class: 'p-form__group', id: 'cfgKeyGroup' });
        keyGroup.append(
            el('label', { class: 'p-form__label', for: 'cfgKey', text: 'Config key' }),
            el('input', {
                class: 'p-form-validation__input ucm-mono', id: 'cfgKey', type: 'text',
                placeholder: 'e.g. port or logging.level', spellcheck: 'false',
            }),
            el('p', { class: 'p-form-help-text', text: 'Dotted identifier (a-z, 0-9, “-”, “_”, “.”).' }),
            el('p', { class: 'p-form-validation__message', id: 'cfgKeyMsg' }),
        );

        const valGroup = el('div', { class: 'p-form__group', id: 'cfgValueGroup' });
        const typeSel = typeSelect();
        const valInput = el('input', {
            class: 'p-form-validation__input ucm-mono', id: 'cfgValue', type: 'text',
            spellcheck: 'false',
        });
        valGroup.append(
            el('label', { class: 'p-form__label', for: 'cfgValue', text: 'Value' }),
            el('div', { style: 'display:flex; gap:.6rem; align-items:center;' }, valInput, typeSel),
            el('p', { class: 'p-form-help-text', text: 'Type “delete” to remove the key. Numbers and booleans are sent as their native type.' }),
            el('p', { class: 'p-form-validation__message', id: 'cfgValueMsg' }),
        );

        const statusP = el('p', { class: 'ucm-muted', id: 'cfgStatus2', style: 'font-size:.85rem; margin:0 0 1rem;' });

        const btns = el('div', { style: 'display:flex; gap:.8rem; align-items:center;' });
        const saveBtn = el('button', { class: 'p-button--brand p-button', type: 'button', text: 'Save' });
        const cancelBtn = el('button', { class: 'p-button--base p-button', type: 'button', text: 'Cancel', onclick: close });
        btns.append(saveBtn, cancelBtn, statusP);

        form.append(keyGroup, valGroup, btns);
        bodyBox.append(form);

        typeSel.addEventListener('change', () => {
            valInput.value = '';
            valInput.placeholder = typeSel.value === 'number' ? 'e.g. 8080'
                : typeSel.value === 'boolean' ? 'true or false'
                : typeSel.value === 'delete' ? '(no value needed)' : 'e.g. info';
            setFieldState('cfgValueGroup', '');
        });
        valInput.placeholder = 'e.g. info';

        // prefill the existing key, if any
        if (current) {
            $('#cfgKey').value = current.key;
            typeSel.value = current.type;
            if (current.has && current.type !== 'delete') valInput.value = String(current.value == null ? '' : current.value);
        }
        $('#cfgKey').focus();

        saveBtn.onclick = async () => {
            const key = $('#cfgKey').value.trim();
            const type = typeSel.value;
            const raw = valInput.value.trim();
            let ok = true;

            if (!RE_CONF_KEY_UI.test(key)) {
                setFieldState('cfgKeyGroup', 'error', 'Invalid config key (use a dotted identifier: a-z, 0-9, “-”, “_”, “.”).');
                ok = false;
            } else setFieldState('cfgKeyGroup', 'valid');

            let value = null;
            if (type === 'delete') {
                value = null;
                setFieldState('cfgValueGroup', '');
            } else if (type === 'string') {
                if (raw === '') { setFieldState('cfgValueGroup', 'error', 'Enter a value.'); ok = false; }
                else { value = raw; setFieldState('cfgValueGroup', 'valid'); }
            } else if (type === 'number') {
                if (raw === '' || !/^-?\d+(\.\d+)?$/.test(raw)) { setFieldState('cfgValueGroup', 'error', 'Enter a number, e.g. 8080.'); ok = false; }
                else { value = Number(raw); setFieldState('cfgValueGroup', 'valid'); }
            } else if (type === 'boolean') {
                const lr = raw.toLowerCase();
                if (lr !== 'true' && lr !== 'false') { setFieldState('cfgValueGroup', 'error', 'Enter “true” or “false”.'); ok = false; }
                else { value = lr === 'true'; setFieldState('cfgValueGroup', 'valid'); }
            }
            if (!ok) return;

            saveBtn.classList.add('is-disabled');
            statusP.textContent = 'Saving…';
            try {
                await core.snaps.confSet(name, { [key]: value });
                toast('positive', 'Configuration saved', `${name}: ${key} ${value === null ? 'removed' : 'updated'}.`);
                close();
            } catch (e) {
                statusP.textContent = 'Failed: ' + e.message;
            } finally {
                saveBtn.classList.remove('is-disabled');
            }
        };
    }

    // Load the snap's current config, then show the form.
    (async () => {
        let conf = {};
        try { conf = (await core.snaps.confGet(name)) || {}; }
        catch (e) { $('#cfgStatus').textContent = 'Could not load configuration: ' + e.message; return; }
        // Pre-fill the FIRST existing key (snapd conf GET returns {key: value}
        // per key; a snap usually has one or a handful — the operator edits
        // keys one at a time). No keys -> empty form, operator adds one.
        const entries = Object.entries(conf || {}).filter(([, v]) => v !== null);
        if (entries.length) {
            const [k, v] = entries[0];
            const type = typeof v === 'number' ? 'number' : typeof v === 'boolean' ? 'boolean' : 'string';
            current = { key: k, has: true, value: v, type };
        }
        render();
    })();
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

/* --------------------------- settings: reset ----------------------------- */
/* Guarded local-admin reset: an ACTIVE session re-confirms the current
   password, then the credential file is wiped. The IPC handler in main.js
   is the real gate (requireAuth + timing-safe verify); this is just the
   form UX around it. */
async function doResetPassword() {
    const cur = $('#resetCurrent').value;
    const confirm = $('#resetConfirm').value;
    let ok = true;
    if (!cur) { setFieldState('resetCurrentGroup', 'error', 'Enter the current password.'); ok = false; }
    else setFieldState('resetCurrentGroup', 'valid');
    if (confirm !== cur) { setFieldState('resetConfirmGroup', 'error', 'Passwords do not match.'); ok = false; }
    else setFieldState('resetConfirmGroup', 'valid');
    if (!ok) return;

    const btn = $('#resetBtn');
    btn.classList.add('is-disabled');
    try {
        const p = await core.auth.reset(cur);
        applyAuthPayload(p); // wipes the session -> gate falls back to #setupView
        // Drop the view hash: the console re-enters on the DASHBOARD after a
        // reset (the previous #settings fragment would otherwise route the
        // fresh login straight back to the reset form).
        history.replaceState(null, '', location.pathname);
    } catch (e) {
        const mismatch = /incorrect password/i.test(e.message);
        setFieldState('resetCurrentGroup', 'error', mismatch ? 'Incorrect current password.' : e.message);
        setFieldState('resetConfirmGroup', '');
    } finally {
        btn.classList.remove('is-disabled');
    }
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

    // main push events (local lock)
    core.auth.onStatusChanged((p) => applyAuthPayload(p));

    // settings: guarded local-admin reset (re-confirms the current password)
    $('#resetForm').addEventListener('submit', (e) => {
        e.preventDefault();
        doResetPassword();
    });

    // dashboard

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
