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
    systemNames: new Set(), // SYSTEM snap names from the model assertion (round 46b)
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
    ifaces: null,
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
    // SYSTEM snaps = model-assertion-declared (top-level `base` +
    // gadget/kernel/snapd/os entries), NOT the /v2/snaps type field
    // (round 46b, user-corrected). Dashboard's sys:info already fetched
    // the model; derive the set here, loadSnaps has a fetch fallback.
    state.systemNames = modelSystemNames(state.model);
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

/* System snap names from the model assertion — mirrors main.js
   modelSystemSnaps(): top-level `base` + snaps: entries of type gadget /
   kernel / snapd / os. Model-declared app snaps (required mesa/ubuntu-
   frame) are NOT system snaps. */
function modelSystemNames(mod) {
    const set = new Set();
    if (!mod || typeof mod !== 'object') return set;
    if (mod.base) set.add(mod.base);
    for (const e of (mod.snaps || [])) {
        if (e && e.name && ['gadget', 'kernel', 'snapd', 'os'].includes(e.type)) set.add(e.name);
    }
    return set;
}

async function loadSnaps() {
    if (!state.systemNames.size) {
        // model not loaded yet (dashboard sys:info pending) — fetch it
        // directly so the action set is right on first paint.
        try {
            const mod = await core.system.model();
            state.model = state.model || mod;
            state.systemNames = modelSystemNames(mod);
        } catch (e) { /* classic pre-model: stays empty */ }
    }
    const wrap = $('#snapsCards');
    try {
        state.snaps = await core.snaps.list();
        renderSnaps();
    } catch (e) {
        toastErr(e);
        wrap.innerHTML = '';
        wrap.append(el('div', { class: 'p-card' },
            el('div', { class: 'ucm-muted', style: 'padding:.4rem 0;', text: 'Could not load snaps: ' + e.message })));
    }
}

/* Round 34: per-row snap actions — ICON-ONLY with Vanilla tooltips.
   The old column showed "Config / Refresh / Remove" as icon+text each (crowded);
   the bundle has no refresh/gear/power icons and p-icon--success is a green
   checkmark (wrong semantic for Refresh), so the actions now use the suru
   glyphs shipped in build/images (see .p-icon--settings/refresh/revert/power
   in app.css):
     Config   = gear (suru settings)
     Refresh  = two curved arrows (suru sync)
     Revert   = curved back arrow (suru undo)
     Disable  = power switch, BLACK when the snap is enabled
     Enable   = power switch, RED when the snap is disabled (toggles to Enable)
     Remove   = trash can (suru delete - round 44 swapped the bundle's
                p-icon--delete data-URI glyph, which read out of place
                next to the suru set)
     System snaps (model-assertion: top-level `base` + gadget/kernel/
     snapd entries — NOT the type field) show ONLY Refresh + Revert;
     base-type snaps the model does not declare show everything
     except Config (live-verified refusals, round 46b).
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
   is still treated as disabled. Consequence (round 47: the Status column is
   gone, so no badge renders): a live-disabled snap reports "installed", which
   is indistinguishable from an active one — the red power icon + the Enable
   label are re-derived through the same detector instead of a misleading
   green state. */
function snapDisabled(s) {
    const st = String(s.status || '').toLowerCase();
    return !s.active && (st === 'installed' || st === 'disabled');
}

function renderSnaps() {
    // Round 47: the scrollable single table is two INTERFACE-CARD-STYLE
    // cards (the interfaces page idiom — same p-card + p-table look):
    //   "OS"             -> the system snaps (the model assertion's set —
    //                       the round-46b definition, NOT the type field)
    //   "Installed Snaps" -> everything else
    // Both cards are alphabetical: /v2/snaps has NO stable order (snapd
    // map iteration — the round-27 changes lesson), so relying on list
    // order would shuffle the rows on every 20 s reload.
    // Columns: Snap | Version/Rev | Track/Channel | Actions. The old Status
    // and Type columns are dropped; a DISABLED snap still reads through the
    // same detector via the red power icon + the Enable label (the icon set
    // IS the status now).
    const wrap = $('#snapsCards');
    wrap.innerHTML = '';
    if (!state.snaps.length) {
        wrap.append(el('div', { class: 'p-card' },
            el('div', { class: 'ucm-muted', style: 'padding:.4rem 0;', text: 'No snaps installed.' })));
        return;
    }
    const byName = (a, b) => a.name.localeCompare(b.name);
    const sys = state.snaps.filter((s) => state.systemNames.has(s.name)).sort(byName);
    const other = state.snaps.filter((s) => !state.systemNames.has(s.name)).sort(byName);
    wrap.append(snapsCard('OS', sys));
    wrap.append(snapsCard('Installed Snaps', other));
}

function snapsCard(title, snaps) {
    const card = el('div', { class: 'p-card ucm-snaps-card' });
    // The header mirrors the interface cards (title + muted meta count on
    // one flex row). The count reuses the ifaces __counts class so both
    // pages' headers style identically.
    card.append(el('div', { class: 'p-card__header' },
        el('div', { style: 'display:flex; align-items:center; gap:.6rem; flex-wrap:wrap;' },
            el('p', { class: 'p-heading--5 ucm-snaps-card__title', style: 'margin:0;', text: title }),
            el('span', { class: 'ucm-muted ucm-ifaces-card__counts', text: `${snaps.length} snaps` }))));
    const body = el('tbody');
    if (!snaps.length) {
        body.append(el('tr', {}, el('td', { colspan: '4', class: 'ucm-muted', text: 'None' })));
    } else {
        snaps.forEach((s) => body.append(snapsRow(s)));
    }
    // The table reuses .ucm-ifaces-table (the interfaces page's table idiom —
    // the same design the cards copy): small-caps nowrap headers, middle
    // cells, .85rem mono. .ucm-ifaces-action on the Actions header gives it
    // the overflow:visible the tooltip needs (the bundle clips td,th).
    card.append(el('table', { class: 'p-table ucm-ifaces-table' },
        el('thead', {}, el('tr', {},
            el('th', { text: 'Snap' }),
            el('th', { text: 'Version / Rev' }),
            el('th', { text: 'Track/Channel' }),
            el('th', { class: 'ucm-ifaces-action', style: 'text-align:right;', text: 'Actions' }))),
        body));
    return card;
}

function snapsRow(s) {
    const disabled = snapDisabled(s);
    // Action set per snap — round 46b (unchanged):
    //  1. SYSTEM snap (declared in the model assertion: top-level `base`
    //     + gadget/kernel/snapd/os entries — NOT the /v2/snaps type field)
    //     -> Refresh + Revert only.
    //  2. BASE-type snap the model does NOT declare -> everything except
    //     Config (snapd 500s conf on type 'base').
    //  3. everything else -> the full set.
    const isSystem = state.systemNames.has(s.name);
    const isBase = s.type === 'base' || s.type === 'core' || s.type === 'os';
    const actions = el('div', { class: 'p-table__cell-action ucm-actions', style: 'text-align:right;' });

    if (isSystem && s.installed !== null) {
        actions.append(
            rowBtn('Refresh ' + s.name, 'p-icon--refresh', () => snapOp(s.name, 'refresh')),
            rowBtn('Revert ' + s.name, 'p-icon--revert', () => snapOp(s.name, 'revert')),
        );
    } else if (s.installed !== null) {
        if (!isBase) actions.append(rowBtn('Configure ' + s.name, 'p-icon--settings', () => openConfigModal(s.name)));
        actions.append(
            rowBtn('Refresh ' + s.name, 'p-icon--refresh', () => snapOp(s.name, 'refresh')),
            rowBtn('Revert ' + s.name, 'p-icon--revert', () => snapOp(s.name, 'revert')),
            rowBtn(disabled ? ('Enable ' + s.name) : ('Disable ' + s.name),
                disabled ? 'p-icon--power p-icon--power-red' : 'p-icon--power',
                () => (disabled ? snapOp(s.name, 'enable') : confirmDisable(s.name))),
            rowBtn('Remove ' + s.name, 'p-icon--delete', () => confirmRemove(s.name)),
        );
    }
    // Round 47: no Status/Type columns; the Track/Channel cell keeps its
    // fmtTrackChannel() content but LOSES its redundant title tooltip
    // (the user already sees the value). The NAME column is the identity
    // cell — plain semibold like the interface cards' .ucm-iface__iface
    // (Version/Rev + Track/Channel stay mono). Round 47b: with the Status
    // column gone, a DISABLED snap tints its name the caution amber the
    // interface cards use for their not-active rows — the clearest cue
    // without touching the icon row (or its locked centering).
    return el('tr', {},
        // The name is the row's click target -> the snap-info modal (round
        // 47c); pointer cursor + dotted hover underline + the title are the
        // affordance (the one title tooltip left in the table, by design).
        el('td', { text: s.name, title: 'Show snap info',
            class: 'ucm-snaps-name' + (disabled ? ' ucm-snaps-name--disabled' : ''),
            onclick: () => openSnapInfo(s.name) }),

        el('td', { class: 'ucm-mono', text: `${s.version || '—'} (${s.revision != null ? s.revision : '—'})` }),
        el('td', { class: 'ucm-mono', text: fmtTrackChannel(s) }),
        el('td', { class: 'ucm-actions-cell', style: 'text-align:right;' }, actions));
}

/* Icon-only row action button: the button itself is the Vanilla tooltip
   trigger (p-tooltip--top-right) so the label shows on hover AND keyboard
   focus; the label is also the aria-label. Compact padding keeps a five-icon
   row tight in the Actions cell. NOTE: the tooltip message element keeps the
   raw label as its TEXT so it is visible in CSS-less contexts (the
   screenshot harness) — in-app the bundle hides it until :hover/:focus.
   Round 39: the interfaces page Connect/Disconnect actions use this SAME
   idiom (the round-38 labeled buttons read inconsistent with the snaps
   table); their glyphs are the suru add/close SVGs shipped in build/images,
   the same proven suru-file pattern as the snap-row actions above. */
function rowBtn(label, icon, onClick, opts = {}) {
    const btn = el('button', {
        class: 'p-button--base p-button ucm-rowbtn ucm-iconbtn p-tooltip--top-right' + (opts.disabled ? ' is-disabled' : ''),
        type: 'button',
        'aria-label': opts.ariaLabel || label,
        'data-tooltip': opts.tooltip || label,
        disabled: opts.disabled || false,
        'aria-disabled': opts.disabled ? 'true' : 'false',
        onclick: opts.disabled ? null : ((e) => onClick(e.currentTarget)),
    },
        el('i', { class: icon }),
        el('span', { class: 'p-tooltip__message', text: opts.tooltip || label }));
    return btn;
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
    $('#snapsCards').after(box);
    b.focus();
}

function confirmDisable(name) {
    // Disabling a snap is potentially FATAL (disabling the app's own snap stops
    // the running process; disabling a service snap interrupts it), so — like
    // Remove — it must NOT be a one-click power toggle. Same inline confirm idiom
    // as confirmRemove: the box is built before its buttons reference it (avoids
    // the TDZ throw the old cancel handler had), one baseline-centred flex row
    // (question icon, message, action, Cancel), and it removes itself when the
    // change settles (or on Cancel).
    const box = el('div', {
        class: 'ucm-confirm ucm-confirm--negative',
        style: 'margin-top:1rem; display:flex; align-items:center; gap:.7rem;',
    });
    const icon = el('i', { class: 'p-icon--question ucm-confirm__ic' });
    const msg = el('p', { class: 'p-notification__message ucm-confirm__msg', text: `Disable snap “${name}”? It will stop and stay stopped until enabled again.` });
    const b = el('button', { class: 'p-button--negative p-button', type: 'button', text: `Disable ${name}?` });
    b.onclick = async () => {
        b.classList.add('is-disabled');
        try {
            const change = await core.snaps.action(name, 'disable');
            toast('positive', 'Disable started', `${name} is being disabled by snapd.`);
            const done = await waitChangeSettled(change);
            loadSnaps();
            if (done && done.status && isChangeTerminal(done.status) && done.status.toLowerCase() !== 'done') {
                toast('negative', 'Disable finished with an error', `${name}: ${done.err || done.status}`);
            }
        } catch (e) { toastErr(e); }
        finally { box.remove(); }
    };
    const cancel = el('button', { class: 'p-button--base p-button', type: 'button', text: 'Cancel' });
    cancel.onclick = () => box.remove();
    box.append(icon, msg, b, cancel);
    $('#snapsCards').after(box);
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

/* ------------------------- snap info modal (round 47c) ------------------- */
/* Clicking a snap's NAME opens a beautified info card for that snap. The
   data is the single-snap GET /v2/snaps/{name} object (main.js
   getSnapInfo — live-verified to carry title/summary/description/
   publisher{display-name,validation}/installed-size/install-date/links/
   id on installed snaps, beyond the list fields). The card reuses the
   .ucm-modal + .ucm-kv idioms of the config modal; links are display-only
   (the kiosk has no external browser). */
function infoPlain(t) {
    // light markdown plainify — snap descriptions carry **bold**, `code`,
    // headings and <autolinks>; strip the markup, keep the words
    return String(t || '')
        .replace(/^#{1,6}\s+/gm, '')
        .replace(/\*\*([^*]+)\*\*/g, '$1')
        .replace(/`([^`]+)`/g, '$1')
        .replace(/<([a-z]+:\/\/[^\s>]+)>/gi, '$1');
}

/* A locally built / sideloaded snap carries a negative revision, which
   snapd serializes with an 'x' prefix (snap/revision.go: Revision.N < 0 ->
   "x%d"). Store snaps have a numeric revision. So an x-prefixed revision is
   the reliable "this is a local build" marker — and such a snap must NOT be
   offered a store channel switch: refreshing it to a store channel would
   REPLACE the local build (a locally modified gadget could break the OS). */
function isLocalSnap(snap) {
    return /^x/.test(String(snap && snap.revision));
}

function openSnapInfo(name) {
    // Esc closes the modal (round 47e, robustified in 47g): the listener
    // lives on `document` for the modal's whole life — focus can fall to
    // <body> after an async re-render (e.g. a channel switch), and a
    // box-scoped listener would never see that key. Removed on every close
    // path so no stale handler outlives the modal.
    const box = el('div', { class: 'ucm-modal' });
    const onKey = (e) => { if (e.key === 'Escape') closeModal(); };
    const closeModal = () => { document.removeEventListener('keydown', onKey); box.remove(); };
    const backdrop = el('div', { class: 'ucm-modal__backdrop', onclick: () => closeModal() });
    document.addEventListener('keydown', onKey);

    const inner = el('div', { class: 'ucm-modal__card' });
    const close = el('button', { class: 'p-button--base p-button', type: 'button', 'aria-label': 'Close', onclick: () => closeModal() },
        el('i', { class: 'p-icon--close ucm-info__close' }));
    inner.append(el('div', { class: 'ucm-modal__head' },
        el('p', { class: 'p-heading--5', text: 'Snap info', style: 'margin:0;' }),
        close));
    const bodyBox = el('div', { class: 'ucm-modal__body ucm-info' });
    bodyBox.append(el('p', { class: 'ucm-muted', style: 'padding:1rem 0;', text: 'Loading snap info…' }));
    inner.append(bodyBox);
    box.append(backdrop, inner);
    document.body.append(box);
    close.focus();

    let info = null; // the loaded snap info (shared by the loader, renderSnapInfo and the picker)
    const loading = el('span', { class: 'ucm-muted ucm-info__loading', style: 'margin-left:.5rem; font-size:.8rem;', text: 'Loading channels…' });

    (async () => {
        let loaded;
        try {
            loaded = await core.snaps.info(name);
        } catch (e) {
            bodyBox.innerHTML = '';
            bodyBox.append(el('p', { class: 'p-status-label p-status-label--negative', text: 'Could not load snap info: ' + e.message }));
            return;
        }
        if (!loaded || !loaded.name) {
            bodyBox.innerHTML = '';
            bodyBox.append(el('p', { class: 'p-status-label p-status-label--negative', text: 'No info returned by snapd.' }));
            return;
        }
        info = loaded;
        renderSnapInfo();
        // store channels load async (round 47g) — the Track/Channel row shows
        // "Loading channels…" until they arrive (a local snap has none).
        let chans = null;
        try { chans = await core.snaps.search(info.name); } catch (e) { /* store unavailable: no picker */ }
        renderChannelRow(info.name, chans || []);
    })();

    function renderSnapInfo() {
        bodyBox.innerHTML = '';
        const disabled = snapDisabled(info);
        // header: display title (falls back to the snap name) + the mono
        // real name + summary + state chips
        bodyBox.append(el('p', { class: 'ucm-info__name', text: info.title || info.name }));
        if (info.title && info.title !== info.name)
            bodyBox.append(el('p', { class: 'ucm-info__id ucm-mono', text: info.name }));
        if (info.summary)
            bodyBox.append(el('p', { class: 'ucm-info__summary', text: info.summary }));
        const chips = el('div', { class: 'ucm-info__chips' });
        chips.append(el('span', {
            class: `p-status-label p-status-label--${disabled ? 'negative' : 'positive'}`,
            text: disabled ? 'disabled' : (String(info.status || 'active') || 'active'),
        }));
        if (info.type) chips.append(el('span', { class: 'p-status-label p-status-label--information', text: info.type }));
        bodyBox.append(chips);

        // description first (round 47d) — it often carries the how-to
        // (connect/interface) text the user actually comes for
        if (info.description) {
            bodyBox.append(el('p', { class: 'ucm-info__sec', text: 'Description' }));
            bodyBox.append(el('p', { class: 'ucm-info__desc', text: infoPlain(info.description) }));
        }

        // a rule separates the flow text from the technical data (round 47e)
        bodyBox.append(el('div', { class: 'ucm-info__div' }));

        // the fact rows (empty values vanish, like the dashboard KV lists)
        const kv = el('dl', { class: 'ucm-kv' });
        const row = (k, v, mono) => {
            if (v == null || v === '') return;
            kv.append(el('div', {}, el('dt', { text: k }), el('dd', { text: String(v), class: mono ? 'mono' : undefined })));
        };
        row('Version', `${info.version || '—'} (${info.revision != null ? info.revision : '—'})`);
        // Track/Channel — the value is followed by a transient "loading"
        // marker until the store channels resolve (round 47g); the switcher
        // or 'local' marker replaces it.
        const chanDd = el('dd');
        chanDd.append(el('span', { class: 'ucm-mono', text: fmtTrackChannel(info) }), loading.cloneNode(true));
        kv.append(el('div', {}, el('dt', { text: 'Track/Channel' }), chanDd));
        // Publisher (round 47e): the terminal's green check / yellow star
        const pub = info.publisher || {};
        const pubName = pub['display-name'] || pub.username || pub.id || info.developer || null;
        if (pubName) {
            const pubVal = el('span', { class: 'ucm-mono', text: pubName });
            const v = pub.validation;
            if (v === 'verified' || v === 'starred')
                pubVal.append(el('span', { class: 'ucm-pub-badge ' + (v === 'verified' ? 'ucm-pub-badge--verified' : 'ucm-pub-badge--starred'), text: v === 'verified' ? '\u2713' : '\u272A' }));
            kv.append(el('div', {}, el('dt', { text: 'Publisher' }), el('dd', {}, pubVal)));
        }
        row('Size', info['installed-size'] != null ? fmtBytes(info['installed-size']) : null);
        row('Installed', info['install-date'] ? fmtDm(info['install-date']) : null);
        row('Confinement', info.confinement || null);
        row('Grade', info.grade || null);
        row('Snap ID', info.id || null, true);
        if (kv.children.length) bodyBox.append(kv);

        // links (the daemon sends them as single-element arrays)
        const links = {};
        ['website', 'source', 'contact'].forEach((k) => {
            const v = (info.links && info.links[k]) ? info.links[k][0] : info[k];
            if (v) links[k] = v;
        });
        if (Object.keys(links).length) {
            bodyBox.append(el('p', { class: 'ucm-info__sec', text: 'Links' }));
            const lk = el('dl', { class: 'ucm-kv' });
            Object.keys(links).forEach((k) => lk.append(el('div', {},
                el('dt', { text: k[0].toUpperCase() + k.slice(1) }),
                el('dd', { text: links[k], class: 'mono' }))));
            bodyBox.append(lk);
        }
        // the channel switcher panel (round 47g) — empty until opened
        bodyBox.append(el('div', { id: 'snapsInfoPicker' }));
    }

    function renderChannelRow(nm, store) {
        const chRow = Array.from(bodyBox.querySelectorAll('.ucm-kv > div'))
            .find((d) => (d.querySelector('dt') || {}).textContent === 'Track/Channel');
        if (!chRow) return; // modal closed / re-rendered in the meantime
        const dd = chRow.querySelector('dd');
        const cur = fmtTrackChannel(info);
        const val = el('span', { class: 'ucm-mono', text: cur });
        const chanMap = (store[0] && store[0].channels) || {};
        dd.innerHTML = '';
        dd.append(val);
        // round 47h: a local build (x revision) is NEVER offered a store
        // switch, even if a same-named store snap has channels — refreshing
        // to one would replace the local build. The 'local' marker covers
        // both local builds and snaps with no store channels.
        const local = isLocalSnap(info);
        if (!local && Object.keys(chanMap).length > 0) {
            // store channels available AND not a local build -> the quiet
            // ghost switcher
            dd.append(el('button', {
                class: 'p-button--base p-button ucm-info__switcher', type: 'button',
                'aria-label': 'Switch channel for ' + nm, text: 'Switch channel',
                onclick: () => renderPicker(nm, cur, chanMap),
            }));
        } else {
            dd.append(el('span', { class: 'ucm-muted ucm-info__local', style: 'margin-left:.5rem; font-size:.8rem;', text: 'local' }));
        }
    }

    function renderPicker(nm, cur, chanMap) {
        const panel = bodyBox.querySelector('#snapsInfoPicker');
        if (!panel) return;
        panel.innerHTML = '';
        // grouped by track (the part before '/'), risks in the snapd store
        // order (stable -> candidate -> beta -> edge)
        const RISK = ['stable', 'candidate', 'beta', 'edge'];
        const byTrack = new Map();
        Object.keys(chanMap).forEach((c) => {
            const [t] = c.split('/');
            const r = c.split('/')[1] || 'stable';
            if (!byTrack.has(t)) byTrack.set(t, []);
            byTrack.get(t).push({ channel: c, risk: r });
        });
        const tracks = Array.from(byTrack.keys()).sort((a, b) => a.localeCompare(b));
        let sel = null;

        const list = el('div', { class: 'ucm-info__picker-list' });
        const sec = el('p', { class: 'ucm-info__sec', text: 'Available channels' });
        const wrap = el('div', { class: 'ucm-info__picker' });
        const filter = el('input', {
            class: 'ucm-mono ucm-info__picker-filter', type: 'text',
            placeholder: 'Filter channels…', spellcheck: 'false',
        });
        const foot = el('div', { class: 'ucm-info__picker-foot' });
        const selLabel = el('span', { class: 'ucm-muted', text: 'Choose a channel' });
        const cancel = el('button', { class: 'p-button--base p-button', type: 'button', text: 'Cancel' });
        const go = el('button', { class: 'p-button--brand p-button', type: 'button', disabled: true, 'aria-disabled': 'true', text: 'Switch' });
        foot.append(selLabel, cancel, go);
        wrap.append(sec, filter, list, foot);
        panel.append(wrap);

        function paintRows(filt) {
            list.innerHTML = '';
            const f = (filt || '').trim().toLowerCase();
            let shown = 0;
            tracks.forEach((t) => {
                const rows = byTrack.get(t)
                    .filter((e) => !f || e.channel.toLowerCase().includes(f))
                    .sort((a, b) => RISK.indexOf(a.risk) - RISK.indexOf(b.risk));
                if (!rows.length) return;
                if (shown) list.append(el('div', { class: 'ucm-info__track-sep' }));
                list.append(el('p', { class: 'ucm-info__track', text: t }));
                rows.forEach((e) => {
                    shown++;
                    const isCur = e.channel === cur;
                    const item = el('button', {
                        class: 'ucm-info__chan' + (isCur ? ' is-current' : '') + (sel === e.channel ? ' is-sel' : ''),
                        type: 'button',
                        'aria-label': e.channel + (isCur ? ' (current)' : ''),
                        disabled: isCur,
                    },
                        el('span', { class: 'ucm-mono', text: e.channel }),
                        isCur ? el('span', { class: 'ucm-muted', text: 'current' }) : null);
                    if (!isCur) item.onclick = () => {
                        sel = e.channel;
                        Array.from(list.querySelectorAll('.ucm-info__chan')).forEach((b) => b.classList.remove('is-sel'));
                        item.classList.add('is-sel');
                        selLabel.textContent = sel;
                        go.disabled = false;
                        go.setAttribute('aria-disabled', 'false');
                        go.textContent = 'Switch to ' + sel;
                    };
                    list.append(item);
                });
            });
            if (!shown) list.append(el('p', { class: 'ucm-muted', style: 'padding:.5rem 0;', text: 'No channels match.' }));
        }
        filter.oninput = () => paintRows(filter.value);
        paintRows('');

        cancel.onclick = () => { panel.innerHTML = ''; };
        go.onclick = async () => {
            const target = sel;
            if (!target) return;
            go.disabled = true;
            cancel.disabled = true;
            try {
                // a channel switch is a REFRESH with the new channel (round
                // 47g — `switch` only rewrites the tracking metadata, it does
                // not fetch/apply the payload). Async: 202 + change id.
                const change = await core.snaps.action(nm, 'refresh', { channel: target });
                toast('positive', 'Channel switch started', `Refreshing ${nm} to ${target}…`);
                const done = await waitChangeSettled(change);
                panel.innerHTML = ''; // collapse the picker (the re-render
                // below would otherwise leave it detached behind the new row)
                await loadSnaps(); // the table's channel cell updates
                info = await core.snaps.info(nm); // reload the card data
                renderSnapInfo();
                let store2 = null;
                try { store2 = await core.snaps.search(nm); } catch (e2) { /* keep the row as-is */ }
                renderChannelRow(nm, (store2 && store2[0]) ? store2 : []);
                if (done && done.status && isChangeTerminal(done.status) && done.status.toLowerCase() !== 'done')
                    toast('negative', 'Channel switch finished with an error', `${nm}: ${done.err || done.status}`);
            } catch (e) {
                toastErr(e);
            }
        };
        filter.focus();
    }
}
function openConfigModal(name) {
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
/* LIVE-VERIFIED snapd /v2/interfaces contract (snapd 2.77):
 *   GET /v2/interfaces -> { plugs:[p], slots:[s] }  (the FULL topology —
 *   unconnected endpoints are listed too, with `connections: null`)
 *   p = { snap, plug, interface, apps, connections: [{snap,slot},...] | null }
 *   s = { snap, slot, interface, connections: [{snap,plug},...] | null }
 * The legacy GET /v2/connections ({established, undesired, plugs, slots})
 * ONLY lists plugs/slots that have connections, so it cannot answer "what is
 * unconnected" — it is NOT used. POST /v2/interfaces is ASYNC (202 + change id
 * at the envelope top) and its body is the PLURAL form
 * {action, plugs:[{snap,plug}], slots:[{snap,slot}]} (verified live: the
 * singular {plug, slot} form is 400 "at least one plug and slot is required").
 *
 * UI shape (per user, mirrors `snap connections <snap>`): one card per
 * CONSUMING snap (a snap with plugs), sorted by snap name; a single table
 * Interface | Plug | Slot | Actions; that snap's CONNECTED interfaces on top,
 * a divider row, then its UNCONNECTED ones. The Slot column shows the current
 * connection target — ":name" for a system slot (core/snapd/system, per
 * snapd's own cmd_connections.go isSystemSnap), "snap:name" for an app slot,
 * and "—" when the plug is unconnected (exactly like the CLI's "-").
 * Unconnected SYSTEM-slot rows get a BARE Connect (target pre-filled, like
 * `snap connect http:home` which sends an empty slot ref); unconnected
 * APP-slot rows keep a target-slot dropdown. Pure providers (no plugs) are
 * not cards. */

const UCM_SYSTEM_SNAPS = ['core', 'snapd', 'system'];
const isSystemSnap = (n) => UCM_SYSTEM_SNAPS.indexOf(n) !== -1;
// snapd's cmd_connections.go endpoint(): system snaps render as ":name",
// everything else as "snap:name".
const slotDisplay = (slotRef) => (isSystemSnap(slotRef.snap) ? `:${slotRef.slot}` : `${slotRef.snap}:${slotRef.slot}`);

async function loadInterfaces() {
    try {
        state.ifaces = await core.interfaces.list();
    } catch (e) {
        toastErr(e);
        state.ifaces = null;
    }
    renderInterfaces();
}

function ifacesRow(r) {
    const tone = r.connected ? 'positive' : 'caution';
    // Slot column = the current connection target (like the CLI's Slot
    // column: "-", shown as "—", for a loose plug). An unconnected plug has
    // at most ONE safe target: a system slot (pre-filled inside the Connect,
    // so the cell stays "—" like the CLI) or a single same-named slot
    // (namespacing — the only correct content-interface match — shown as
    // plain text). There is no target-slot pulldown (dropped in round 41):
    // snapd would accept any same-interface slot, so the other candidates
    // would all be broken connections.
    let slotCell;
    if (r.slotRef) {
        slotCell = el('td', { class: 'ucm-mono', text: slotDisplay(r.slotRef) });
    } else if (r.singleTarget) {
        slotCell = el('td', { class: 'ucm-mono ucm-muted', text: slotDisplay(r.singleTarget) });
    } else {
        slotCell = el('td', { class: 'ucm-muted', text: '—' });
    }
    // Icon-only row actions, the same idiom as the snaps table (round 34/39):
    // Disconnect = suru close (X), Connect = suru add (+); the button is the
    // Vanilla tooltip trigger so the label is also on keyboard focus.
    const actionCell = el('td', { class: 'ucm-ifaces-action' },
        r.connected
            ? rowBtn(`Disconnect ${r.plug} on ${r.snap}`, 'p-icon--window-close',
                () => disconnectPlug(r.snap, r.plug, r.slotRef))
            : rowBtn(`Connect ${r.plug} on ${r.snap}` + (r.sysSlot || r.singleTarget ? '' : ' — no target slots available'),
                'p-icon--add',
                (btn) => connectPlug(r, btn),
                { disabled: !r.connected && !r.sysSlot && !r.singleTarget }));
    return el('tr', { class: `ucm-iface ucm-iface--${tone}` },
        el('td', { class: 'ucm-iface__iface', text: r.iface || '—' }),
        el('td', { class: 'ucm-mono', text: r.snap + ':' + r.plug }),
        slotCell,
        actionCell);
}

function ifacesCard(snap, conns, uncons) {
    const card = el('div', { class: 'p-card ucm-ifaces-card' });
    card.append(el('div', { class: 'p-card__header' },
        el('div', { style: 'display:flex; align-items:center; gap:.6rem; flex-wrap:wrap;' },
            el('p', { class: 'p-heading--5 ucm-ifaces-card__title', style: 'margin:0;', text: snap }),
            el('span', { class: 'ucm-muted ucm-ifaces-card__counts',
                text: `${conns.length} connected · ${uncons.length} unconnected` }))));

    const body = el('tbody');
    conns.forEach((r) => body.append(ifacesRow(r)));
    if (conns.length && uncons.length) body.append(el('tr', { class: 'ucm-ifaces-div' }, el('td', { colspan: '4' })));
    uncons.forEach((r) => body.append(ifacesRow(r)));

    card.append(el('table', { class: 'p-table ucm-ifaces-table' },
        el('thead', {}, el('tr', {},
            el('th', { text: 'Interface' }),
            el('th', { text: 'Plug' }),
            el('th', { text: 'Slot' }),
            el('th', { class: 'ucm-ifaces-action', style: 'text-align:right;', text: 'Actions' }))),
        body));
    return card;
}

function renderInterfaces() {
    const wrap = $('#ifacesCards');
    wrap.innerHTML = '';
    const c = state.ifaces || {};
    const plugs = c.plugs || [];
    const slots = c.slots || [];

    if (!plugs.length) {
        $('#ifacesSummary').textContent = '';
        wrap.append(el('div', { class: 'p-card' },
            el('div', { class: 'ucm-muted', style: 'padding:.4rem 0;', text: 'No snap consumes any interface on this device.' })));
        return;
    }

    const bySnap = new Map();
    const entry = (snap) => {
        if (!bySnap.has(snap)) bySnap.set(snap, { snap, conns: [], uncons: [] });
        return bySnap.get(snap);
    };

    // A plug is connected iff its `connections` list is non-empty (live snapd
    // uses `null` for none — never rely on a missing/empty distinction).
    plugs.forEach((p) => {
        const cs = Array.isArray(p.connections) ? p.connections : [];
        const e = entry(p.snap);
        if (cs.length) {
            cs.forEach((slotRef) => {
                e.conns.push({ snap: p.snap, plug: p.plug, iface: p.interface, connected: true,
                    slotRef: { snap: slotRef.snap, slot: slotRef.slot } });
            });
        } else {
            // system slot for this interface (the pre-filled `snap connect
            // http:home` target — invisible in the Slot cell, used by Connect)
            const sysSlot = slots.find((s) => s.interface === p.interface && isSystemSnap(s.snap));
            // app-owned free slots (same interface, no connections, not self)
            const free = slots
                .filter((s) => s.interface === p.interface
                    && (!Array.isArray(s.connections) || !s.connections.length)
                    && !isSystemSnap(s.snap)
                    && !(s.snap === p.snap && s.slot === p.plug));
            // Namespacing (round 39/41): for content interfaces snapd accepts
            // ANY same-interface slot as the connect target — but only the
            // same-NAMED slot is actually usable, so offering a pulldown of the
            // "other" slots would only ever offer broken connections (e.g.
            // lxd:ceph-conf -> ubuntu-frame:ubuntu-frame-diagnostic). The
            // pulldown is dropped entirely (round 41): exactly one same-named
            // free slot -> it is the target (Slot column, pre-filled); zero or
            // several same-named -> treated as "no target", like any other
            // plug without a slot.
            const sameName = free.filter((s) => s.slot === p.plug);
            e.uncons.push({ snap: p.snap, plug: p.plug, iface: p.interface, connected: false,
                slotRef: null,
                sysSlot: sysSlot ? { snap: sysSlot.snap, slot: sysSlot.slot } : null,
                singleTarget: (!sysSlot && sameName.length === 1) ? { snap: sameName[0].snap, slot: sameName[0].slot } : null });
        }
    });

    // sorted by consuming snap (card order = snap name)
    const cards = Array.from(bySnap.values()).sort((a, b) => a.snap.localeCompare(b.snap));
    cards.forEach((d) => wrap.append(ifacesCard(d.snap, d.conns, d.uncons)));

    const totalConns = plugs.reduce((n, p) => n + (Array.isArray(p.connections) ? p.connections.length : 0), 0);
    const totalUncons = plugs.length - plugs.filter((p) => Array.isArray(p.connections) && p.connections.length).length;
    $('#ifacesSummary').textContent = `${cards.length} snaps · ${totalConns} connected · ${totalUncons} unconnected`;
}

async function connectPlug(r, btn) {
    // target = the pre-filled system slot, else the single same-named slot.
    // There is no pulldown (round 41): for content interfaces any other
    // same-interface slot would be a broken connection, so a plug with no
    // unique safe target simply cannot be connected from here.
    const target = r.sysSlot
        ? { snap: r.sysSlot.snap, slot: r.sysSlot.slot }
        : (r.singleTarget ? { snap: r.singleTarget.snap, slot: r.singleTarget.slot } : null);
    if (!target || !target.snap || !target.slot) { toast('caution', 'Connect', 'No connectable target slot for this plug.'); return; }
    if (btn) btn.classList.add('is-disabled');
    try {
        const change = await core.interfaces.connect({ snap: r.snap, plug: r.plug }, target);
        toast('positive', 'Connect started', `${r.snap}:${r.plug} → ${slotDisplay(target)}`);
        const done = await waitChangeSettled(change);
        await loadInterfaces();
        if (done && isChangeTerminal(done.status) && done.status.toLowerCase() !== 'done')
            toastErr(new Error(`Connect finished with an error: ${done.status}`));
        else
            toast('positive', 'Connected', `${r.snap}:${r.plug} → ${slotDisplay(target)}`);
    } catch (e) {
        toastErr(e);
    } finally {
        if (btn) btn.classList.remove('is-disabled');
    }
}

async function disconnectPlug(snap, plugRef, slotRef) {
    try {
        const change = await core.interfaces.disconnect({ snap, plug: plugRef }, slotRef);
        toast('positive', 'Disconnect started', `${snap}:${plugRef} ↔ ${slotDisplay(slotRef)}`);
        const done = await waitChangeSettled(change);
        await loadInterfaces();
        if (done && isChangeTerminal(done.status) && done.status.toLowerCase() !== 'done')
            toastErr(new Error(`Disconnect finished with an error: ${done.status}`));
        else
            toast('positive', 'Disconnected', `${snap}:${plugRef} ↔ ${slotDisplay(slotRef)}`);
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

    // interfaces: no page-level Refresh (round 39) — the view
    // reloads on entry, like the dashboard cards reload on their 20 s poll.
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
