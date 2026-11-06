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
    requiredNames: new Set(), // model `presence: required` snap names (round 47k)
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

/* Body-appended popups (the .ucm-modal boxes: snap info + per-snap config)
 * outlive the view state — a lock or credential wipe must NOT leave them
 * sitting in front of the login card, still interactive (round 48f).
 * closeOpenModals() closes every open modal through its OWN close button,
 * which also detaches each modal's document-scoped Esc listener. */
function closeOpenModals() {
    document.querySelectorAll('.ucm-modal').forEach((m) => {
        const i = m.querySelector('.ucm-modal__head .p-icon--close');
        const b = i ? (i.closest('button') || i) : null;
        if (b) b.click();       // its closeModal() also detaches the Esc listener
        else m.remove();
    });
}

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
    closeOpenModals();
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
    state.requiredNames = modelRequiredNames(state.model);
    const fromHash = (location.hash || '').replace('#', '');
    switchView(VIEWS.includes(fromHash) ? fromHash : 'dashboard');
}

function exitApp() {
    closeOpenModals();
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

/* `presence: required` snap names from the model assertion (round 47k) —
   snapd already refuses to remove them ('used by the model'); the row now
   also omits the Remove icon so the action set stays honest. Mirrors
   modelSystemNames: same parse output (main.js parseModelAssertion keeps
   each entry's presence field). */
function modelRequiredNames(mod) {
    const set = new Set();
    if (!mod || typeof mod !== 'object') return set;
    for (const e of (mod.snaps || [])) {
        if (e && e.name && e.presence === 'required') set.add(e.name);
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
            state.requiredNames = modelRequiredNames(mod);
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
     snapd entries — NOT the type field) show ONLY Refresh + Revert (a
     local x-revision build of them drops Refresh, round 47j — Revert only);
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
    //  3. everything else -> the full set, MINUS Remove for model-
    //     `presence: required` snaps (round 47k — snapd refuses it too).
    const isSystem = state.systemNames.has(s.name);
    const isBase = s.type === 'base' || s.type === 'core' || s.type === 'os';
    const actions = el('div', { class: 'p-table__cell-action ucm-actions', style: 'text-align:right;' });

    if (isSystem && s.installed !== null) {
        // Round 47j: a LOCAL build (x-prefixed revision — see
        // isLocalSnap, round 47h) is never fetched from the store, so Refresh
        // would only ever 400 'no updates available'. Omit the icon — the row
        // is honest about what is actionable. A local SYSTEM snap (the
        // user's VM gadget) therefore shows Revert only.
        if (!isLocalSnap(s))
            actions.append(rowBtn('Refresh ' + s.name, 'p-icon--refresh', () => snapOp(s.name, 'refresh')));
        actions.append(rowBtn('Revert ' + s.name, 'p-icon--revert', () => snapOp(s.name, 'revert')));
    } else if (s.installed !== null) {
        if (!isBase) actions.append(rowBtn('Configure ' + s.name, 'p-icon--settings', () => openConfigModal(s.name)));
        // Round 47j: local (x-revision) builds never fetch from the store —
        // the daemon would answer 'no updates available' — so the row omits
        // the Refresh icon (settings / revert / power / delete only).
        if (!isLocalSnap(s))
            actions.append(rowBtn('Refresh ' + s.name, 'p-icon--refresh', () => snapOp(s.name, 'refresh')));
        actions.append(
            rowBtn('Revert ' + s.name, 'p-icon--revert', () => snapOp(s.name, 'revert')),
            rowBtn(disabled ? ('Enable ' + s.name) : ('Disable ' + s.name),
                disabled ? 'p-icon--power p-icon--power-red' : 'p-icon--power',
                () => (disabled ? snapOp(s.name, 'enable') : confirmDisable(s.name))),
        );
        // Round 47k: model-`presence: required` snaps are used by the model —
        // snapd already refuses their removal ('used by the model'), so the row
        // omits the Remove icon like it omits the icons snapd refuses.
        if (!state.requiredNames.has(s.name))
            actions.append(rowBtn('Remove ' + s.name, 'p-icon--delete', () => confirmRemove(s.name)));
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
    // Main-page confirm: a single integrated flex row (question icon + message
    // + confirm + Cancel) — the well-integrated wide-page layout (round 48h2:
    // the two-row layout is popup-only, scoped to .ucm-modal in the CSS).
    const box = el('div', {
        class: 'ucm-confirm ucm-confirm--negative',
        style: 'margin-top:1rem; display:flex; align-items:center; gap:.7rem;',
    });
    const icon = el('i', { class: 'p-icon--question ucm-confirm__ic' });
    const msg = el('p', { class: 'p-notification__message ucm-confirm__msg', text: `Permanently remove snap “${name}”?` });
    // Round 48i: "Remove?" (no snap name) — the message already names the
    // snap, and a static label can't wrap (long names like ubuntu-core-manager
    // used to line-wrap inside the button).
    const b = el('button', { class: 'p-button--negative p-button', type: 'button', text: 'Remove?' });
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
    // Main-page confirm: a single integrated flex row (question icon + message
    // + confirm + Cancel) — the well-integrated wide-page layout (round 48h2:
    // the two-row layout is popup-only, scoped to .ucm-modal in the CSS).
    const box = el('div', {
        class: 'ucm-confirm ucm-confirm--negative',
        style: 'margin-top:1rem; display:flex; align-items:center; gap:.7rem;',
    });
    const icon = el('i', { class: 'p-icon--question ucm-confirm__ic' });
    const msg = el('p', { class: 'p-notification__message ucm-confirm__msg', text: `Disable snap “${name}”? It will stop and stay stopped until enabled again.` });
    // Round 48i: "Disable?" (no snap name) — the message already names the
    // snap, and a static label can't wrap.
    const b = el('button', { class: 'p-button--negative p-button', type: 'button', text: 'Disable?' });
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
        } else if (done && done.status && isChangeTerminal(done.status)) {
            // round 47i: a successful install makes the results card
            // redundant — hide it (the error / settle-timeout paths keep it)
            clearStoreResults();
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
                // round 47n: the store size (download-size, LIVE-verified on
                // /v2/find); em-dash when the store omits it.
                el('td', { class: 'ucm-mono', text: r['download-size'] != null ? fmtBytes(r['download-size']) : '—' }),
                el('td', { style: 'text-align:right;', onclick: (e) => { e.stopPropagation(); } }, installBtn),
            ));
        });
    } catch (e) {
        $('#snapSearchBody').innerHTML = '';
        $('#snapSearchBody').append(el('tr', {}, el('td', { colspan: '5', class: 'ucm-muted', text: 'Search failed: ' + e.message })));
    }
}

/* ------------------------- snap configuration (round 48) ------------------ */
/* The gear on a snap row opens the snap's CONFIGURATION popup. It reuses the
   snap-info modal chrome (round 47c/47g/47d) so it behaves IDENTICALLY to
   that popup: full-screen backdrop, pinned dark head, whitened close icon
   (.ucm-info__close), a body capped to the 900px kiosk, Esc closes via a
   document-scoped listener (focus can fall to <body> after an async
   re-render), and toasts float top-centre ABOVE the card (round 47n: z 80 >
   60) so in-popup notifications are always visible.
   Built in chunks (user request):
     48a  Services card at the top — one row per daemon the snap ships, a
          "Running" switch (stopping is confirm-gated) and a "Start on boot"
          switch (disabling at boot is confirm-gated). snapd couples boot
          state to running state (live-verified: there is no boot-only
          enable/disable — stop+disable stops AND clears boot, start+enable
          starts AND sets boot), and the confirm copy states that.
     48b  the snap's existing config as one card per top-level key, a
          YAML-ish indented tree, trash-per-value removal.
     48c  an add-config form (dotted key + value; a suru document icon
          expands the value field to multiline). */
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
        // components (round 47m) — offered by the snap, each install/removeable;
        // renders nothing when the snap has none (most snaps don't)
        renderComponents();
        // the channel switcher panel (round 47g) — empty until opened
        bodyBox.append(el('div', { id: 'snapsInfoPicker' }));
    }

    // ---------------- components (round 47m) -------------------------
    // The single-snap object carries `components[]`. A component's installed
    // state is its revision: "unset" = offered but NOT installed; a numeric
    // revision (plus installed-size / install-date) = installed (LIVE-verified
    // against llama-cpp on snapd 2.77.1). Install/remove POST the SAME route
    // as a snap action but with a `components` array — a component op never
    // touches the parent snap.
    function renderComponents() {
        const comps = (info && Array.isArray(info.components)) ? info.components : [];
        if (!comps.length) return;
        bodyBox.append(el('p', { class: 'ucm-info__sec', text: 'Components' }));
        const clist = el('div', { class: 'ucm-info__comps' });
        comps.forEach((c) => {
            const installed = c.revision != null && String(c.revision) !== 'unset';
            const ver = c.version ? ' ' + c.version : '';
            // snapd sends installed-size HYPHENATED (Go json tag), not
            // installedSize (round 47n; the 47m camelCase read never matched).
            const meta = (installed && c['installed-size'] != null) ? ' · ' + fmtBytes(c['installed-size']) : '';
            clist.append(el('div', { class: 'ucm-info__comp' + (installed ? ' is-installed' : '') },
                el('div', { class: 'ucm-info__comp-main' },
                    el('span', { class: 'ucm-info__comp-name', text: c.name + ver }),
                    c.summary ? el('span', { class: 'ucm-info__comp-summary', text: c.summary }) : null,
                    el('span', { class: 'ucm-info__comp-meta', text: (installed ? 'Installed' : 'Not installed') + meta })),
                el('button', {
                    class: 'p-button--base p-button ucm-info__comp-btn', type: 'button',
                    'aria-label': (installed ? 'Remove component ' : 'Install component ') + c.name + ' of ' + info.name,
                    text: installed ? 'Remove' : 'Install',
                    onclick: (e) => compOp(c, installed, e.currentTarget),
                })));
        });
        bodyBox.append(clist);
    }

    async function compOp(c, installed, btn) {
        const nm = info.name;
        const act = installed ? 'remove' : 'install';
        if (btn) { btn.classList.add('is-disabled'); btn.disabled = true; }
        try {
            const change = await core.snaps.component(nm, act, c.name);
            toast('positive', (installed ? 'Component removal started' : 'Component install started'),
                nm + '+' + c.name + ' is ' + (installed ? 'being removed' : 'being installed') + '…');
            const done = await waitChangeSettled(change);
            info = await core.snaps.info(nm); // reload (component revision + size)
            renderSnapInfo();
            let store2 = null;
            try { store2 = await core.snaps.search(nm); } catch (e2) { /* keep the row as-is */ }
            renderChannelRow(nm, (store2 && store2[0]) ? store2 : []);
            if (done && done.status && isChangeTerminal(done.status) && done.status.toLowerCase() !== 'done')
                toast('negative', 'Component change finished with an error', nm + '+' + c.name + ': ' + (done.err || done.status));
        } catch (e) { toastErr(e); }
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
/* ---- configuration cards (round 48b) -------------------------------------
   The snap's existing config (GET /v2/snaps/{name}/conf — a flat
   {dotted.key: scalar} map) is shown the way YAML shows it: one card per
   TOP-LEVEL key (a `foo:` card), its dotted sub-keys as an indented tree
   (foo.bar.baz -> 4-space indents, one per level), and a leaf value with a
   trash icon (the snaps-page removal icon, .p-icon--delete). Trash sends
   {key: null} to PUT /v2/snaps/{name}/conf (async 202, the round-1 contract)
   and re-renders the cards — when a top-level key's last leaf is removed its
   whole card disappears. Values are JSON-ish scalars; multiline strings are
   shown block-style (like a YAML block scalar). */
function confTree(root) {
    const tree = {};
    for (const [k, v] of Object.entries(root || {})) {
        if (v === null) continue;
        const parts = k.split('.');
        let node = tree;
        for (let i = 0; i < parts.length - 1; i++) {
            const k = parts[i];
            // Create/enter the subtree for the intermediate segments. A config
            // doc is a flat {dotted: scalar} map; the intermediate levels are
            // implicit. A key that is BOTH a scalar leaf and the prefix of a
            // deeper key is not expressible in YAML (a key can't be a scalar
            // and a map) — if it somehow occurs, the nesting wins (the scalar
            // is dropped) rather than throwing.
            if (node[k] === undefined) node[k] = {};
            else if (typeof node[k] !== 'object' || node[k] === null || Array.isArray(node[k])) node[k] = {};
            node = node[k];
        }
        node[parts[parts.length - 1]] = v;
    }
    return tree;
}
function confPath(prefix, seg) {
    return prefix ? prefix + '.' + seg : seg;
}
/* Round 48f: a config document is NESTED (snapd stores it as nested JSON —
   GET /v2/snaps/{n}/conf returns {top:{sub:{leaf:val}}}, not a flat dotted
   map). The REST equivalent of `snap set <snap> a.b.c!` is PUT {a.b.c: null}.
   snapd's purgeNulls removes the key+value but NEVER prunes an emptied parent
   (live-verified: unsetting the last leaf of foo.bar leaves a hollow
   {foo:{bar:{}}}), so a plain leaf unset leaves a "ghost tree" node behind.
   confUnsetKey deletes `full` from a deep copy of the nested doc and returns
   the HIGHEST ancestor that becomes empty — at ANY depth, not just the top:
   unsetting THAT node with a single REST unset removes it and everything under
   it while every other branch is left intact (live-verified: {a:{b:{c},d}}
   unset a.b -> {a:{d}}). So deleting the last leaf of foo.bar unsets foo.bar
   (hollow node gone, foo keeps its siblings); deleting foo's last leaf unsets
   foo; deleting a leaf whose parent keeps other values unsets just the leaf. */
function confUnsetKey(doc, full) {
    const parts = full.split('.');
    const clone = JSON.parse(JSON.stringify(doc || {}));
    const nodes = [clone];
    let node = clone;
    for (let i = 0; i < parts.length - 1; i++) {
        if (node[parts[i]] === undefined || typeof node[parts[i]] !== 'object' || node[parts[i]] === null)
            return full; // the doc doesn't actually nest this path — unset just the leaf
        node = node[parts[i]];
        nodes.push(node);
    }
    delete node[parts[parts.length - 1]];
    let unsetSegs = parts.length; // default: unset the leaf itself (parts.slice(0, parts.length))
    for (let i = parts.length - 1; i >= 1; i--) {
        // nodes[i] is the ancestor at path parts.slice(0, i); if it is empty it
        // can be unset (key parts.slice(0, i)) and we keep climbing toward the top.
        if (Object.keys(nodes[i]).length > 0) break;
        delete nodes[i - 1][parts[i - 1]]; // prune the emptied ancestor from its parent
        unsetSegs = i;
    }
    return parts.slice(0, unsetSegs).join('.');
}
const confValText = (v) => (typeof v === 'string' ? v : JSON.stringify(v));

function openConfigModal(name) {
    // Same close behaviour as the snap-info modal: the Esc listener lives on
    // `document` for the popup's whole life and every close path removes it.
    const box = el('div', { class: 'ucm-modal' });
    const onKey = (e) => { if (e.key === 'Escape') closeModal(); };
    const closeModal = () => { document.removeEventListener('keydown', onKey); box.remove(); };
    const backdrop = el('div', { class: 'ucm-modal__backdrop', onclick: () => closeModal() });
    document.addEventListener('keydown', onKey);

    const inner = el('div', { class: 'ucm-modal__card' });
    // Dark head -> whiten the close exactly like the info modal (round 47d):
    // the bundle p-icon is a fixed #000 data-URI, only a filter can whiten it.
    const close = el('button', { class: 'p-button--base p-button', type: 'button', 'aria-label': 'Close', onclick: () => closeModal() },
        el('i', { class: 'p-icon--close ucm-info__close' }));
    inner.append(el('div', { class: 'ucm-modal__head' },
        el('p', { class: 'p-heading--5', text: 'Configure ' + name, style: 'margin:0;' }),
        close));
    const bodyBox = el('div', { class: 'ucm-modal__body ucm-config' });
    bodyBox.append(el('p', { class: 'ucm-muted ucm-config__loading', style: 'padding:.5rem 0;', text: 'Loading configuration…' }));
    inner.append(bodyBox);
    box.append(backdrop, inner);
    document.body.append(box);
    close.focus();

    // Confirm-gated actions: an inline .ucm-confirm row (the round-45 idiom)
    // appended at the bottom of the popup body; it removes itself on Cancel
    // or after the change settles. One confirm at a time. (Shared by the
    // service switches, 48a, and the config trash removal, 48b.)
    const askConfirm = (msg, confirmLabel, doIt) => {
        if (box.querySelector('.ucm-confirm')) return;
        // Popup confirm: two-row layout (icon+message on top, buttons
        // left-aligned below) — the .ucm-modal .ucm-confirm CSS owns it, so the
        // in-popup confirms render identically regardless of message length.
        // (Main-page confirms keep the single integrated row — round 48h2.)
        const cbox = el('div', { class: 'ucm-confirm ucm-confirm--negative' });
        const b = el('button', { class: 'p-button--negative p-button', type: 'button', text: confirmLabel });
        const cancel = el('button', { class: 'p-button--base p-button', type: 'button', text: 'Cancel' });
        b.onclick = async () => { b.classList.add('is-disabled'); try { await doIt(); } finally { cbox.remove(); } };
        cancel.onclick = () => cbox.remove();
        cbox.append(
            el('div', { class: 'ucm-confirm__row' },
                el('i', { class: 'p-icon--question ucm-confirm__ic' }),
                el('p', { class: 'p-notification__message ucm-confirm__msg', text: msg })),
            el('div', { class: 'ucm-confirm__actions' }, b, cancel));
        bodyBox.append(cbox);
        b.focus();
    };

    /* ---- services (round 48a) ---------------------------------------------
       snapd's service control (POST /v2/apps, live-verified) couples boot
       state to running state — the only valid ops are start / start+enable /
       stop / stop+disable / restart. So:
         "Running"     — ON->OFF is confirm-gated (stopping can interrupt the
                         snap's function); OFF->ON is one click (the safe,
                         corrective direction — the round-45 idiom).
         "Start on boot" — ON->OFF is confirm-gated, and its copy states that
                         the service is STOPPED at the same time; OFF->ON is
                         one click and starts the service (the only way to
                         set boot in the API). */
    const servicesSec = el('div', {});
    let servicesBusy = false;

    function svcSwitch(labelText, cls) {
        // The offline bundle ships Vanilla's p-switch: the hidden input must
        // sit IMMEDIATELY before the slider (:checked+ rule), visible text
        // before both. The wrapping <label> forwards clicks to the input.
        const lab = el('label', { class: 'p-switch ucm-svc__sw ' + cls });
        lab.append(
            el('span', { class: 'ucm-svc__swlabel', text: labelText }),
            el('input', { class: 'p-switch__input', type: 'checkbox' }),
            el('span', { class: 'p-switch__slider' }),
        );
        return lab;
    }

    async function svcOp(s, action, flags) {
        servicesBusy = true;
        servicesSec.querySelectorAll('input').forEach((i) => { i.disabled = true; });
        try {
            const change = await core.snaps.service(name, s.name, action, flags);
            const verb = action === 'stop'
                ? (flags.disable ? 'Service disabled at boot (stopped)' : 'Service stopped')
                : (flags.enable ? 'Service enabled at boot (started)' : 'Service started');
            toast('positive', verb, name + ': ' + s.name);
            const done = await waitChangeSettled(change);
            let fresh;
            try { fresh = await core.snaps.services(name); } catch { fresh = null; }
            if (fresh) renderServices(fresh);
            if (done && done.status && isChangeTerminal(done.status) && done.status.toLowerCase() !== 'done') {
                toast('negative', 'Service change finished with an error', name + ': ' + s.name + ' — ' + (done.err || done.status));
            }
        } catch (e) {
            toastErr(e);
            let fresh;
            try { fresh = await core.snaps.services(name); } catch { fresh = null; }
            if (fresh) renderServices(fresh);
        } finally {
            servicesBusy = false;
        }
    }

    function renderServices(list) {
        servicesSec.innerHTML = '';
        if (!list.length) {
            servicesSec.append(
                el('p', { class: 'ucm-info__sec', text: 'Services' }),
                el('p', { class: 'ucm-muted', style: 'margin:.2rem 0 0; font-size:.85rem;', text: 'This snap ships no services.' }),
            );
            return;
        }
        const card = el('div', { class: 'p-card ucm-config__card' });
        card.append(el('div', { class: 'p-card__header' },
            el('div', { style: 'display:flex; align-items:center; gap:.6rem;' },
                el('p', { class: 'p-heading--5 ucm-snaps-card__title', style: 'margin:0;', text: 'Services' }),
                el('span', { class: 'ucm-muted ucm-ifaces-card__counts', text: list.length + (list.length === 1 ? ' service' : ' services') }))));
        const rows = el('div', { class: 'ucm-config__cardbody' });
        list.forEach((s) => {
            const active = !!s.active;
            const enabled = !!s.enabled;
            const states = el('div', { class: 'ucm-svc__states' });
            states.append(el('span', {
                class: 'p-status-label ' + (active ? 'p-status-label--positive' : 'p-status-label--information'),
                text: active ? 'running' : 'stopped',
            }));
            states.append(el('span', { class: 'ucm-svc__boot', text: enabled ? 'starts on boot' : 'not on boot' }));
            const swRun = svcSwitch('Running', 'ucm-svc__sw-running');
            swRun.querySelector('input').checked = active;
            const swBoot = svcSwitch('Start on boot', 'ucm-svc__sw-boot');
            swBoot.querySelector('input').checked = enabled;
            const row = el('div', { class: 'ucm-svc' });
            row.append(
                el('div', { class: 'ucm-svc__main' }, el('span', { class: 'ucm-svc__name', text: s.name }), states),
                el('div', { class: 'ucm-svc__switches' }, swRun, swBoot),
            );
            swRun.addEventListener('change', () => {
                if (servicesBusy) { swRun.querySelector('input').checked = active; return; }
                if (active) {
                    swRun.querySelector('input').checked = true; // hold on for the confirm window
                    // 48j: static "Stop?" — the message names the service,
                    // and a static label can't wrap.
                    askConfirm(`Stop service "${s.name}"? It will stop now and keep its start-on-boot setting.`, 'Stop?', () => svcOp(s, 'stop', {}));
                } else {
                    svcOp(s, 'start', {});
                }
            });
            swBoot.addEventListener('change', () => {
                if (servicesBusy) { swBoot.querySelector('input').checked = enabled; return; }
                if (enabled) {
                    swBoot.querySelector('input').checked = true; // hold on for the confirm window
                    askConfirm(`Disable "${s.name}" at boot? This stops the service now AND removes it from the boot sequence.`, `Disable at boot?`, () => svcOp(s, 'stop', { disable: true }));
                } else {
                    svcOp(s, 'start', { enable: true });
                }
            });
            rows.append(row);
        });
        card.append(rows);
        servicesSec.append(el('p', { class: 'ucm-info__sec', text: 'Services' }), card);
    }

    /* ---- configuration (round 48b) ---------------------------------------- */
    const configSec = el('div', { class: 'ucm-svc-sec ucm-conf-sec' });
    let confBusy = false;

    function confRow(node, prefix) {
        // Indent in MONO-CHAR units (round 48d): one level = 2 monospace
        // characters (~17.92px at the .ucm-mono 13.6px size). A nested
        // dotted key therefore sits 2 chars in from its parent — the way a
        // YAML file indents — instead of the earlier single-char 4px step.
        const frag = document.createDocumentFragment();
        Object.keys(node).sort().forEach((seg) => {
            const full = confPath(prefix, seg);
            const child = node[seg];
            if (child && typeof child === 'object' && !Array.isArray(child)) {
                frag.append(el('div', { class: 'ucm-conf__node', style: 'padding-left:' + (prefix ? prefix.split('.').length * 17.92 + 17.92 : 17.92) + 'px;' },
                    el('span', { class: 'ucm-mono ucm-conf__key', text: seg + ':' })));
                frag.append(confRow(child, full));
            } else {
                frag.append(confLeafRow(child, full, prefix ? prefix.split('.').length * 17.92 + 17.92 : 17.92));
            }
        });
        return frag;
    }

    function confLeafRow(value, full, indent) {
        const isMulti = typeof value === 'string' && value.indexOf('\n') !== -1;
        const row = el('div', { class: 'ucm-conf__leaf ' + (isMulti ? 'ucm-conf__leaf--multi' : ''), style: 'padding-left:' + indent + 'px; display:flex; align-items:' + (isMulti ? 'flex-start' : 'center') + '; gap:.6rem;' });
        const kv = el('div', { class: 'ucm-conf__kv', style: 'min-width:0;' });
        kv.append(el('span', { class: 'ucm-mono ucm-conf__key', text: full.split('.').pop() + ':' }));
        kv.append(buildValueEl());
        // Round 48g: IN-PLACE editing of the value — the value text itself is
        // the affordance (like the snap-name cells, 47c): click it and the row
        // swaps the value for a prefilled editor (input for single-line
        // values, textarea for multiline blocks). ENTER saves, ESC cancels —
        // the editor STOPS the Escape propagation, because the config modal
        // keeps a document-level Esc listener that would otherwise close the
        // whole popup. The multiline editor carries an explicit Save button
        // because Enter there is a newline (the 48c textarea idiom). Saving
        // goes through the SAME core.snaps.confSet the add form uses — chunk-E
        // type inference, the configure hook, the settle + re-fetch +
        // re-render idiom — and an UNCHANGED value sends nothing (no pointless
        // hook run). If focus leaves the editor (a click elsewhere), the edit
        // is abandoned and the value row rebuilds. No key renaming here: a
        // rename is two destructive ops — the safe path is the confirm-gated
        // trash + the add form.
        function ucmConfEditGroup() {
            const grp = el('div', { class: 'p-form__group ucm-conf__edit', id: 'ucmConfEditGroup' });
            const inp = el('input', { class: 'p-form-validation__input ucm-mono ucm-conf__editinp', type: 'text', spellcheck: 'false' });
            const ta = el('textarea', { class: 'p-form-validation__input ucm-mono ucm-conf__editinp', spellcheck: 'false' });
            const saveBtn = el('button', { class: 'p-button--brand p-button ucm-conf__editsave', type: 'button', text: 'Save' });
            const hint = el('p', { class: 'ucm-conf__edithint', text: 'Save saves — Esc cancels' });
            grp.append(inp, ta, saveBtn, hint, el('p', { class: 'p-form-validation__message' }));
            const useTa = isMulti;
            inp.hidden = useTa;
            ta.hidden = !useTa;
            saveBtn.hidden = !useTa;
            // Round 48g2: the hint is shown for BOTH editors, worded to each
            // one's real save mechanism — single-line saves on Enter (no
            // button), multiline on the Save button (Enter there is a newline).
            hint.hidden = false;
            hint.textContent = useTa ? 'Save saves — Esc cancels' : 'Enter saves — Esc cancels';
            // Round 48g3: the multiline editor opens at TWICE the content
            // height (the 48g2 content-sized box was confirmed too small for
            // editing headroom). 2x the line count, capped at 16 rows
            // (~300px — inside the 900px kiosk; the modal body scrolls if
            // ever needed) so a 60-line value (ubuntu-frame's display) gets
            // 16 rows, not an 8-row scrolling sliver or a viewport-killer.
            ta.rows = Math.min(16, 2 * String(value).split('\n').length);
            ta.value = useTa ? value : '';
            inp.value = useTa ? '' : confValText(value);
            const doSave = async () => {
                if (grp.classList.contains('is-disabled')) return;
                const raw = useTa ? ta.value : inp.value;
                if (raw === '') { setFieldState('ucmConfEditGroup', 'error', 'Enter a value'); return; }
                const oldText = useTa ? value : confValText(value);
                if (raw === oldText) { closeConfEdit(); return; } // unchanged -> no PUT, no hook run
                grp.classList.add('is-disabled');
                try {
                    const change = await core.snaps.confSet(name, { [full]: raw });
                    const done = await waitChangeSettled(change);
                    if (done && done.status && isChangeTerminal(done.status) && done.status.toLowerCase() !== 'done')
                        toast('negative', 'Saving the value failed', name + ': ' + full + ' — ' + (done.err || done.status));
                    else
                        toast('positive', 'Value updated', name + ': ' + full);
                    let freshRoot = null;
                    try { freshRoot = await core.snaps.confGet(name); } catch { freshRoot = null; }
                    if (freshRoot) renderConfig(freshRoot); // the doc changed — the tree re-renders
                    else closeConfEdit(); // no doc to re-render; drop the editor anyway
                } catch (e) { toastErr(e); closeConfEdit(); }
                finally { grp.classList.remove('is-disabled'); }
            };
            inp.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') { e.preventDefault(); doSave(); }
                else if (e.key === 'Escape') { e.stopPropagation(); closeConfEdit(); }
            });
            ta.addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.stopPropagation(); closeConfEdit(); } });
            saveBtn.addEventListener('click', () => doSave());
            return grp;
        }
        let editGrp = null;
        function showEdit() {
            if (confBusy || editGrp) return;
            editGrp = ucmConfEditGroup();
            trash.hidden = true;
            kv.replaceChildren();
            kv.append(el('span', { class: 'ucm-mono ucm-conf__key', text: full.split('.').pop() + ':' }), editGrp);
            editGrp.querySelectorAll('input,textarea').forEach((f) => {
                f.addEventListener('blur', (e) => {
                    // Round 48g2: clicking the Save button blurs the field
                    // first (mousedown focuses the button) — that blur is NOT
                    // "focus left the editor" (the abandon case), so let blurs
                    // whose relatedTarget is a control inside the group
                    // through; only a blur to the OUTSIDE (a click elsewhere,
                    // the close X, Esc-removal) abandons the edit.
                    if (e.relatedTarget && editGrp.contains(e.relatedTarget)) return;
                    if (f.closest('.ucm-modal')) closeConfEdit();
                });
            });
            const act = editGrp.querySelector('input:not([hidden]),textarea:not([hidden])');
            act.focus();
            if (act.select) act.select();
        }
        function closeConfEdit() {
            if (!editGrp) return;
            editGrp = null;
            trash.hidden = false;
            kv.replaceChildren();
            kv.append(el('span', { class: 'ucm-mono ucm-conf__key', text: full.split('.').pop() + ':' }), buildValueEl());
        }
        function buildValueEl() {
            const vEl = isMulti
                ? el('pre', { class: 'ucm-conf__multi ucm-conf__editable', text: value })
                : el('span', { class: 'ucm-mono ucm-conf__val ucm-conf__editable', text: confValText(value) });
            vEl.title = 'Edit ' + full;
            vEl.addEventListener('click', showEdit);
            return vEl;
        }
        const trash = rowBtn('Remove ' + full, 'p-icon--delete', () => {
            // Removing a config value is destructive (it runs the snap's
            // configure hook and the doc flips when it settles), so — like the
            // service-stops, snap disable/remove and interface disconnect — it
            // is confirm-gated (round 48f). Inline .ucm-confirm row (the
            // round-45 idiom, already shared by the service switches above).
            if (confBusy) return;
            askConfirm(
                // 48j: static "Remove?" — the message names the value + snap.
                `Remove "${full}" from ${name}? The snap's configuration hook will run and the value will be deleted.`,
                'Remove?',
                async () => {
                    confBusy = true;
                    try {
                        // Decide WHICH key to unset BEFORE sending: a plain
                        // leaf unset leaves the emptied parent hollow (the ghost
                        // tree), so unset the HIGHEST ancestor that becomes empty
                        // (at any depth) with one REST unset — that whole node
                        // goes, every other branch stays.
                        let cur = null;
                        try { cur = await core.snaps.confGet(name); } catch { cur = null; }
                        const wipeKey = (cur && typeof cur === 'object') ? confUnsetKey(cur, full) : full;
                        const change = await core.snaps.confSet(name, { [wipeKey]: null });
                        const done = await waitChangeSettled(change);
                        if (done && done.status && isChangeTerminal(done.status) && done.status.toLowerCase() !== 'done') {
                            toast('negative', 'Removing the value failed', name + ': ' + full + ' — ' + (done.err || done.status));
                        } else {
                            toast('positive', 'Value removed', name + ': ' + full);
                        }
                        let freshRoot = null;
                        try { freshRoot = await core.snaps.confGet(name); } catch { freshRoot = null; }
                        if (freshRoot) renderConfig(freshRoot); // re-fetch: the async PUT settled, the doc changed
                    } catch (e) { toastErr(e); }
                    finally { confBusy = false; }
                }
            );
        });
        row.append(kv, trash);
        return row;
    }

    function renderConfig(root) {
        configSec.innerHTML = '';
        const tree = confTree(root);
        const tops = Object.keys(tree);
        configSec.append(el('p', { class: 'ucm-info__sec', text: 'Configuration' }));
        if (!tops.length) {
            configSec.append(el('p', { class: 'ucm-muted', style: 'margin:.2rem 0 0; font-size:.85rem;', text: 'No configuration set for this snap.' }));
            return;
        }
        tops.sort().forEach((top) => {
            // 48b2: NO card header — the top-level key is the FIRST LINE of the
            // YAML tree itself (the 48b header repeated it directly above,
            // which read as "daemon: / daemon: true"). A scalar top-level key
            // renders as the leaf "top: value"; a subtree as the node line
            // "top:" with its children indented beneath it.
            const node = tree[top];
            const card = el('div', { class: 'p-card ucm-config__card' });
            const rows = el('div', { class: 'ucm-config__cardbody' });
            if (node && typeof node === 'object') {
                rows.append(el('div', { class: 'ucm-conf__node', style: 'padding-left:17.92px;' },
                    el('span', { class: 'ucm-mono ucm-conf__key', text: top + ':' })));
                rows.append(confRow(node, top));
            } else {
                rows.append(confLeafRow(node, top, 17.92));
            }
            card.append(rows);
            configSec.append(card);
        });
    }

    (async () => {
        let list = [];
        let loadErr = null;
        try { list = await core.snaps.services(name); }
        catch (e) { loadErr = e; }
        const loading = bodyBox.querySelector('.ucm-config__loading');
        if (loading) loading.remove();
        bodyBox.append(servicesSec);
        // A genuine load failure renders the red chip; a service-less snap
        // (main.js maps its 404 to []) gets the quiet note — never "fatal".
        if (loadErr) {
            servicesSec.append(
                el('p', { class: 'ucm-info__sec', text: 'Services' }),
                el('p', { class: 'p-status-label p-status-label--negative', text: 'Could not load services: ' + loadErr.message }),
            );
        } else {
            renderServices(list);
        }
        // 48b: the snap's existing config as per-top-level-key cards.
        let root = {};
        let confErr = null;
        try { root = await core.snaps.confGet(name); }
        catch (e) { confErr = e; }
        bodyBox.append(configSec);
        if (confErr) {
            configSec.append(
                el('p', { class: 'ucm-info__sec', text: 'Configuration' }),
                el('p', { class: 'p-status-label p-status-label--negative', text: 'Could not load configuration: ' + confErr.message }),
            );
        } else {
            renderConfig(root);
        }
        // 48c: the add-config form (dotted key + value; the suru document
        // icon expands the value into multiline for big pastes, e.g. lxd's
        // daemon.preseed). Saving appends the key to the SAME document the
        // cards above show, so it re-renders into the tree on success.
        const formSec = el('div', { class: 'ucm-svc-sec ucm-conf-sec ucm-conf-formsec' });
        bodyBox.append(formSec);
        let multi = false;

        function formRenderValue() {
            const holder = formSec.querySelector('.ucm-conf-form__valholder');
            const icon = formSec.querySelector('.ucm-conf-form__iconbtn');
            const label = formSec.querySelector('.ucm-conf-form__vlabel');
            // round 48d: the value field is re-created on every single<->multi
            // toggle, so its dismiss listeners are attached here each time. (The
            // group is reached by id — formRenderValue runs in the outer config
            // scope, not the addConfigForm IIFE where valGroup is declared.)
            const attachValueDismiss = (v) => {
                const vg = document.getElementById('cfgvGroup');
                v.addEventListener('input', () => {
                    if (vg && vg.classList.contains('is-error') && v.value !== '')
                        setFieldState('cfgvGroup', '');
                });
                v.addEventListener('blur', () => {
                    if (vg && vg.classList.contains('is-error')) setFieldState('cfgvGroup', '');
                });
            };
            if (!multi) {
                const input = el('input', { class: 'p-form-validation__input ucm-mono', id: 'cfgv', type: 'text', spellcheck: 'false', placeholder: 'e.g. 8080 or true' });
                holder.replaceChildren(input);
                attachValueDismiss(input);
                icon.querySelector('i').className = 'p-icon--document';
                icon.setAttribute('aria-label', 'Use a multiline value (expand)');
                icon.setAttribute('data-tooltip', 'Use a multiline value');
                label.textContent = 'Value';
            } else {
                const ta = el('textarea', { class: 'p-form-validation__input ucm-mono ucm-conf-form__ta', id: 'cfgv', spellcheck: 'false', rows: '6', placeholder: 'Paste a multiline value here (JSON, YAML, …)' });
                holder.replaceChildren(ta);
                attachValueDismiss(ta);
                icon.querySelector('i').className = 'p-icon--collapse';
                icon.setAttribute('aria-label', 'Use a single-line value (collapse)');
                icon.setAttribute('data-tooltip', 'Use a single-line value');
                const countLines = () => { label.textContent = 'Value (multiline — ' + (ta.value ? ta.value.split('\n').length : 1) + ' lines)'; };
                ta.addEventListener('input', countLines); // keep the live line count honest as the user pastes/types
                countLines();
            }
        }

        (function addConfigForm() {
            const form = el('form', { class: 'ucm-conf-form', novalidate: '' });
            const keyGroup = el('div', { class: 'p-form__group ucm-conf-form__keygroup', id: 'cfgkGroup' });
            const keyInput = el('input', { class: 'p-form-validation__input ucm-mono', id: 'cfgk', type: 'text', spellcheck: 'false', placeholder: 'e.g. foo.bar.baz' });
            // round 48d: an error is not a dead end — the user may have typed
            // into the field by accident and never intended to save. The key's
            // error clears as soon as the value is typed valid, and always when
            // focus leaves the field (so a stray error can be dismissed without
            // a successful save — the established live-clear + blur idiom).
            keyInput.addEventListener('input', () => {
                if (keyGroup.classList.contains('is-error') && RE_CONF_KEY_UI.test(keyInput.value.trim()))
                    setFieldState('cfgkGroup', '');
            });
            keyInput.addEventListener('blur', () => {
                if (keyGroup.classList.contains('is-error')) setFieldState('cfgkGroup', '');
            });
            keyGroup.append(
                el('label', { class: 'p-form__label', for: 'cfgk', text: 'Key' }),
                keyInput,
                el('p', { class: 'p-form-validation__message' }),
            );
            const valGroup = el('div', { class: 'p-form__group ucm-conf-form__valgroup', id: 'cfgvGroup' });
            const vlabel = el('label', { class: 'p-form__label ucm-conf-form__vlabel', for: 'cfgv', text: 'Value' });
            const valholder = el('div', { class: 'ucm-conf-form__valholder' });
            valholder.append(el('input', { class: 'p-form-validation__input ucm-mono', id: 'cfgv', type: 'text', spellcheck: 'false', placeholder: 'e.g. 8080 or true' }));
            const iconbtn = el('button', { class: 'p-button--base p-button ucm-iconbtn ucm-conf-form__iconbtn p-tooltip--top-right', type: 'button', 'aria-label': 'Use a multiline value (expand)', 'data-tooltip': 'Use a multiline value' },
                el('i', { class: 'p-icon--document' }),
                el('span', { class: 'p-tooltip__message', text: 'Use a multiline value' }));
            iconbtn.addEventListener('click', () => {
                // The p-tooltip clears on blur/mouseleave — a click (especially
                // via keyboard/touch) fires neither, so the message would linger
                // over the just-expanded field. Force-hide it on the toggle.
                const tip = iconbtn.querySelector('.p-tooltip__message');
                if (tip) tip.style.display = 'none';
                multi = !multi;
                formRenderValue();
            });
            const valrow = el('div', { class: 'ucm-conf-form__valrow' }, valholder, iconbtn);
            valGroup.append(vlabel, valrow,
                el('p', { class: 'p-form-help-text', text: 'A single line, or click the document icon to paste a multiline value (JSON, YAML, …).' }),
                el('p', { class: 'p-form-validation__message' }));
            const saveBtn = el('button', { class: 'p-button--brand p-button ucm-conf-form__save', type: 'submit', text: 'Add value' });
            // round 48d: key + value share ONE line (the fields shorten to
            // fit the card), the "Add value" button stays below the line.
            const formRow = el('div', { class: 'ucm-conf-form__row' }, keyGroup, valGroup);
            form.append(formRow, saveBtn);
            // 48c2: the form lives in a card, like the Services and
            // configuration cards (no header — its own "Key" label leads it).
            const formCard = el('div', { class: 'p-card ucm-config__card' },
                el('div', { class: 'ucm-config__cardbody' }, form));
            formSec.append(el('p', { class: 'ucm-info__sec', text: 'Add configuration' }), formCard);
            formRenderValue();

            // 48e: the form SUBMITS — Enter in either field (a single-line
            // input submits on Enter) and the "Add value" button (a submit
            // button) both run saveValue(). The multiline textarea does NOT
            // submit on Enter (native: Enter inserts a newline), which is the
            // right behavior while pasting a block.
            const saveValue = async () => {
                if (saveBtn.classList.contains('is-disabled')) return; // already saving
                const key = document.getElementById('cfgk').value.trim();
                const valEl = document.getElementById('cfgv');
                const raw = (valEl && valEl.value) ? valEl.value : '';
                let ok = true;
                if (!RE_CONF_KEY_UI.test(key)) {
                    setFieldState('cfgkGroup', 'error', 'Invalid key (use a dotted identifier: a–z, 0–9, “-”, “_”, “.”).');
                    ok = false;
                } else {
                    setFieldState('cfgkGroup', '');
                }
                if (raw === '') {
                    setFieldState('cfgvGroup', 'error', 'Enter a value');
                    ok = false;
                } else {
                    setFieldState('cfgvGroup', '');
                }
                if (!ok) return;
                saveBtn.classList.add('is-disabled');
                try {
                    const change = await core.snaps.confSet(name, { [key]: raw });
                    const done = await waitChangeSettled(change);
                    if (done && done.status && isChangeTerminal(done.status) && done.status.toLowerCase() !== 'done') {
                        toast('negative', 'Saving the value failed', name + ': ' + key + ' — ' + (done.err || done.status));
                    } else {
                        toast('positive', 'Value added', name + ': ' + key);
                    }
                    let freshRoot = null;
                    try { freshRoot = await core.snaps.confGet(name); } catch { freshRoot = null; }
                    if (freshRoot) renderConfig(freshRoot); // the doc changed — the new key joins the tree
                    document.getElementById('cfgk').value = '';
                    if (document.getElementById('cfgv')) document.getElementById('cfgv').value = '';
                } catch (e) { toastErr(e); }
                finally { saveBtn.classList.remove('is-disabled'); }
            };
            form.addEventListener('submit', (e) => { e.preventDefault(); saveValue(); });
        })();
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
                () => confirmDisconnect(r.snap, r.plug, r.slotRef))
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

function confirmDisconnect(snap, plug, slotRef) {
    // Disconnecting an interface can be FATAL — severing e.g. the kiosk's own
    // wayland/x11 connection bricks the session — so, like the snap Remove and
    // Disable actions, it must not be a one-click X (round 48f). Same page
    // confirm idiom as confirmRemove/confirmDisable: the box is built before
    // its buttons reference it (no TDZ throw), one centred flex row (question
    // icon, message, action, Cancel), appended after the interfaces cards and
    // removing itself once the change settles. The actual disconnect + toasts
    // + reload stay in disconnectPlug (the card is a sibling of #ifacesCards,
    // so the reload's innerHTML wipe cannot destroy it).
    // Main-page confirm: a single integrated flex row (question icon + message
    // + confirm + Cancel) — the well-integrated wide-page layout (round 48h2:
    // the two-row layout is popup-only, scoped to .ucm-modal in the CSS).
    const box = el('div', {
        class: 'ucm-confirm ucm-confirm--negative',
        style: 'margin-top:1rem; display:flex; align-items:center; gap:.7rem;',
    });
    const icon = el('i', { class: 'p-icon--question ucm-confirm__ic' });
    const msg = el('p', { class: 'p-notification__message ucm-confirm__msg', text: `Disconnect "${plug}" on ${snap}? It will stop working until it is connected again.` });
    // 48j: static "Disconnect?" — the message names the plug + snap.
    const b = el('button', { class: 'p-button--negative p-button', type: 'button', text: 'Disconnect?' });
    b.onclick = () => {
        b.classList.add('is-disabled');
        disconnectPlug(snap, plug, slotRef).finally(() => box.remove());
    };
    const cancel = el('button', { class: 'p-button--base p-button', type: 'button', text: 'Cancel' });
    cancel.onclick = () => box.remove();
    box.append(icon, msg, b, cancel);
    $('#ifacesCards').after(box);
    b.focus();
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
    // Round 48k: Escape cancels the topmost confirmation dialog — the same as
    // its Cancel button (every confirm's Cancel handler is just box.remove()).
    // Registered here, before any modal can open, so this listener runs before
    // a modal's own document-level Esc handler in the bubble phase;
    // stopImmediatePropagation() then cancels the confirm WITHOUT closing a
    // popup (with no confirm left, a later Esc closes the modal — layered).
    // The config editor's Esc is element-level + stopPropagation, so it never
    // reaches here (and the editor is not a .ucm-confirm).
    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape') return;
        const confirm = document.querySelector('.ucm-confirm');
        if (confirm) {
            e.stopImmediatePropagation();
            confirm.remove();
        }
    });
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
