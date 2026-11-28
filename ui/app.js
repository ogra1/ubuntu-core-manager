/*
 * Copyright 2026 Ubuntu Core Manager contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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

// round LASTCH: date-only sibling of fmtDm — the house DD.MM.YYYY idiom with
// the HH:MM dropped (the info card's 'Last changed' stamp).
const fmtDay = (iso) => {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return '—';
    const p = (n) => String(n).padStart(2, '0');
    return `${p(d.getDate())}.${p(d.getMonth() + 1)}.${d.getFullYear()}`;
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
    // network devices (round 53): live kernel state merged with the netplan
    // definitions; netEditing = the one device card currently in edit form
    // (a pending added bridge carries d.pending until its first Apply).
    devices: null,
    netEditing: null,
    // local admin gate (the UI lock screen; offline)
    initialized: false,
    authenticated: false,
    expiresAt: null,
    // round 66: the CONFIGURABLE inactivity lock timeout (ms; null = "off" —
    // no auto-lock). The default 15 min only seeds the FIRST paint before
    // core.auth.status() lands the real pref.
    timeoutMs: 900000,
    // round A: the appearance (light/dark). The default 'dark' seeds the
    // FIRST paint before core.auth.status() lands the real pref (round
    // T-fix13: dark is the shipped default — the kiosk is dark-themed).
    appearance: 'dark',
    // round I: local pages (embedded localhost web UIs). [] seeds the FIRST
    // paint before core.auth.status() lands the real list.
    localPages: [],
    // round L: the System page's power card (the live scheduled shutdown,
    // read from logind on view entry; {active, action, usec}).
    scheduled: null,
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
    // round KM part 2: the two-STEP first-boot flow. setupStep is 'keymap'
    // (step 1 — the layout is applied BEFORE the password is typed; a real
    // change restarts the console) or 'password' (step 2 — created once, on
    // the settled layout). keymapLoaded resolves once (true, even on error —
    // the error path is a SKIP, never a block: the password stays settable).
    setupStep: 'keymap',
    // round KM part 3: the "asked once" flag (main.js keymap.conf). True
    // once the user has gotten through the keyboard step; every later
    // first-boot entry then skips it (boot reads it; the layout step sets it).
    keymapFlag: false,
    keymapLoaded: false,
    keymapError: false,
    keymapList: [],
    // round T-KM4: the System-page Keyboard card (the post-setup picker).
    keymapCurrent: null,
    sessionTick: null,
    dashPoll: null,
};

const VIEWS = ['dashboard', 'network', 'snaps', 'interfaces', 'settings', 'system'];
const VIEW_TITLES = { dashboard: 'Dashboard', network: 'Network configuration', snaps: 'Snap packages', interfaces: 'Snap interfaces', settings: 'Settings', system: 'System' };

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
    if (toSetup) {
        // round KM part 2: step 1 = the keyboard picker (focused once the list
        // is loaded; the password step is not even in the DOM yet), step 2 =
        // the password. The step the app RE-OPENS into after a layout restart
        // is step 1 — the layout now reads back as applied, so Continue is a
        // no-op into step 2.
        if (state.setupStep === 'password') $('#setupPassword').focus();
        else {
            const kmSel = $('#setupKeymap');
            if (state.keymapLoaded && kmSel) kmSel.focus();
        }
    }
    if (toLogin) $('#loginPassword').focus();
}

function isView(name) {
    return VIEWS.includes(name) || /^lp-\d+$/.test(name); // round I: dynamic local-page views
}
function switchView(name) {
    if (!isView(name)) name = 'dashboard';
    state.view = name;
    $$('#appShell .ucm-view').forEach((v) => v.classList.toggle('ucm-hidden', v.dataset.view !== name));
    $$('.ucm-side .p-side-navigation__link').forEach((a) =>
        a.classList.toggle('is-active', a.dataset.view === name));
    // round I: a local page's title is its entry name (the VIEWS-only map has no
    // lp-* key; fall back to the name, else Dashboard).
    $('#topbarTitle').textContent = VIEW_TITLES[name]
        || (state.localPages.some((e) => e && e.id === name) ? state.localPages.find((e) => e.id === name).name : 'Dashboard');
    history.replaceState(null, '', '#' + name);

    const loaders = {
        dashboard: () => { loadDashboard(); sampleCpu(); sampleNet(); },
        network: loadNetwork,
        snaps: loadSnaps,
        interfaces: loadInterfaces,
        settings: loadSettings,
        system: loadSystem,
    };
    if (loaders[name]) loaders[name]();
    // round I: a local-page view has NO loader — the <webview> is already in
    // the DOM (hidden views still render), so switching just reveals it.
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
    renderLocalPages(); // round I: first paint of the sidebar entries + <webview> views
    const fromHash = (location.hash || '').replace('#', '');
    switchView(isView(fromHash) ? fromHash : 'dashboard');
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
    setFieldState('setupKeymapGroup', '');
    const kmOv = $('#keymapRestart');
    if (kmOv) kmOv.classList.add('ucm-hidden');
    // round KM part 3: a wipe/lock re-enters first boot — at step 1 when the
    // layout step was never done on this device, straight to step 2 when the
    // "asked once" flag is set (the layout is applied; do not ask again).
    updateSetupStep(state.keymapFlag ? 'password' : 'keymap');
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
        if (!state.timeoutMs) {
            // round 66: "off" — no auto-lock, so no countdown. The chip reads
            // "active" (the same word the locked-out state uses; the tooltip
            // from updateLockChrome makes "no auto-lock" explicit).
            text.textContent = 'active';
            chip.classList.remove('is-warning');
            return;
        }
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

/* round 66: the chrome that depends on the lock timeout — the header chip's
   tooltip and the login/setup gate's footnote both reflect the CURRENT
   timeout (or "off"), so they stay honest when the user changes it. */
function lockTimeoutLabel() {
    if (!state.timeoutMs) return 'off';
    const min = state.timeoutMs / 60000;
    return min === 60 ? '1 hour' : min + ' minutes';
}
function updateLockChrome() {
    const chip = $('#sessionChip');
    if (chip) chip.title = state.timeoutMs
        ? 'Console locks after ' + lockTimeoutLabel() + ' without activity'
        : 'Auto-lock is off — the console stays unlocked until you lock it';
    const note = $('#lockNote');
    if (note) note.textContent = state.timeoutMs
        ? 'Sessions lock after ' + lockTimeoutLabel() + ' of inactivity.'
        : 'Auto-lock is off — the console stays unlocked until you lock it manually.';
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
        toast('positive', 'Administrator created', 'Local console password set.');
    } catch (e) {
        setFieldState('setupPasswordGroup', 'error', e.message);
        setFieldState('setupConfirmGroup', '');
    } finally {
        btn.classList.remove('is-disabled');
    }
}

/* round KM part 2: the two-STEP first-boot flow (the ubuntu-frame external
   config). The layout must be in place BEFORE the administrator password is
   typed — the password is stored verbatim from the keys pressed, and a
   layout change after typing would make the stored characters not match the
   keyboard. So step 1 is the layout (its own button: a real change restarts
   the console via the non-interactive #keymapRestart overlay; on the real
   device the app dies with the session and reopens — at step 1 again, now
   reading the settled layout, where Continue is a no-op into step 2). A pick
   that needs no write (the applied layout, or English (US) on a fresh device
   that ships none) advances straight to step 2: no overlay, no restart.
   Step 2 is the password — created ONCE, never restarted into. */
function keymapNoOp(id, cur) {
    return id === cur || (cur === null && id === 'us');
}
function updateSetupStep(step) {
    state.setupStep = step;
    const km = $('#setupKeymapForm');
    const pw = $('#setupPasswordForm');
    if (km) km.classList.toggle('ucm-hidden', step !== 'keymap');
    if (pw) pw.classList.toggle('ucm-hidden', step !== 'password');
    showGate(); // refocus per step (picker vs password)
}
function toggleKeymapHelp() {
    const sel = $('#setupKeymap');
    const help = $('#setupKeymapHelp');
    if (!sel || !help) return;
    help.classList.toggle('ucm-hidden', keymapNoOp(sel.value, state.keymapCurrent));
}
async function loadSetupKeymap() {
    const sel = $('#setupKeymap');
    if (!sel) { state.keymapLoaded = true; return; }
    try {
        // round KM part 3: the flag is read WITH the list. If it is set the
        // user already chose a layout on this device — skip the keyboard
        // step entirely and go straight to the password (the layout is still
        // changeable later via the System page).
        const [list, cur, flag] = await Promise.all([core.keymaps.list(), core.keymaps.current(), core.keymaps.flag()]);
        state.keymapFlag = !!flag;
        if (state.keymapFlag) {
            state.keymapLoaded = true;
            updateSetupStep('password'); // the layout step is done on this device
            return;
        }
        state.keymapList = Array.isArray(list) ? list : [];
        state.keymapCurrent = cur || null;
        sel.innerHTML = '';
        for (const e of state.keymapList) sel.appendChild(new Option(e.label, e.id));
        // Default: the applied layout if it is offered, else English (US)
        // (a fresh device behaves US — picking that then applies nothing).
        let def = (state.keymapCurrent && state.keymapList.some((x) => x.id === state.keymapCurrent)) ? state.keymapCurrent : 'us';
        if (!state.keymapList.some((x) => x.id === def)) def = state.keymapList[0] ? state.keymapList[0].id : '';
        sel.value = def;
        state.keymapLoaded = true;
        toggleKeymapHelp();
        updateSetupStep('keymap'); // step 1, refocused now that the picker is live
    } catch (e) {
        // The frame read failed (frame down / socket gone) — SKIP the layout
        // step, never block the password (the layout stays changeable later
        // once the console is up).
        state.keymapLoaded = true;
        state.keymapError = true;
        setFieldState('setupKeymapGroup', 'error', e.message);
        updateSetupStep('keymap');
    }
}
/* Step 1's Continue. A no-op pick (the applied layout, or US on a fresh
   device) needs no write: straight to step 2. A real change applies the
   layout — the frame (and the console with it) restarts; the overlay is
   NON-interactive on purpose, and the app reopens at step 1 with the layout
   settled, where the SAME Continue is a no-op into step 2. A rejected apply
   (e.g. the frame's hook does not know the id) stays on step 1 with an
   inline error. The password step is only ever reached with the layout in
   place — no password typed in the wrong layout, ever. */
async function doSetupKeymapSubmit() {
    const ov = $('#keymapRestart');
    if (ov && !ov.classList.contains('ucm-hidden')) return; // the restart owns the screen
    if (!state.keymapLoaded) {
        toast('caution', 'Keyboard layout', 'Loading the layouts — one moment.');
        return;
    }
    if (state.keymapError) { updateSetupStep('password'); return; } // step skipped (read failed)
    const sel = $('#setupKeymap');
    const id = sel ? sel.value : '';
    const btn = $('#setupKeymapBtn');
    const help = $('#setupKeymapHelp');
    setFieldState('setupKeymapGroup', '');
    if (keymapNoOp(id, state.keymapCurrent)) {
        // round KM part 3: the layout is in place (nothing to apply) — mark
        // the step done so no later first-boot entry asks again, then on to
        // the password.
        try { await core.keymaps.setFlag(); } catch { /* non-fatal: asked again */ }
        state.keymapFlag = true;
        updateSetupStep('password');
        return;
    }
    if (help) help.classList.add('ucm-hidden'); // the overlay carries the warning
    if (btn) {
        btn.classList.add('is-disabled', 'is-processing');
        btn.insertAdjacentHTML('beforeend', ' <i class="p-icon--spinner u-animation--spin" aria-hidden="true"></i>');
    }
    try {
        const r = await core.keymaps.apply(id);
        if (r && r.id) {
            // A real write: the console is restarting. The overlay stays up;
            // on the real device the app dies with the session and reopens.
            // round KM part 3: the flag is set NOW (before the restart) —
            // the re-opened boot reads it and goes straight to the password,
            // so the user is not asked for the layout a second time. If the
            // write never lands (a lost race with the restart), the worst
            // case is one more question, not a locked-out layout.
            try { await core.keymaps.setFlag(); } catch { /* non-fatal: asked again */ }
            state.keymapFlag = true;
            if (ov) ov.classList.remove('ucm-hidden');
        } else {
            try { await core.keymaps.setFlag(); } catch { /* non-fatal: asked again */ }
            state.keymapFlag = true;
            updateSetupStep('password');
        }
    } catch (e) {
        setFieldState('setupKeymapGroup', 'error', e.message);
        toggleKeymapHelp();
    } finally {
        if (btn) {
            btn.classList.remove('is-disabled', 'is-processing');
            const sp = btn.querySelector('.p-icon--spinner');
            if (sp) sp.remove();
        }
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

// round D (I4): the Appearance card's Theme row shows a Light/Dark value
// next to the toggle. It is a pure DISPLAY of state.appearance (the switch's
// checked state is the control); keep it in sync wherever the appearance is
// applied — applyAuthPayload (the live flip), loadSettings (view-entry) and
// setAppearance (after a change).
function syncThemeLabel() {
    const lbl = $('#themeLabel');
    if (lbl) lbl.textContent = state.appearance === 'dark' ? 'Dark' : 'Light';
}
function applyAuthPayload(p) {
    if (!p) return;
    const wasAuth = state.authenticated;
    const wasInit = state.initialized;
    state.initialized = !!p.initialized;
    state.authenticated = !!p.authenticated;
    state.expiresAt = p.expiresAt || null;
    // round 66: timeoutMs is null when the lock is "off". An explicit null
    // MUST stick (off) — only a payload with NO timeoutMs field at all
    // (undefined) falls back to the current value. (`!= null` was wrong: it
    // kept the stale default and hid a persisted "off" on load.)
    state.timeoutMs = p.timeoutMs !== undefined ? p.timeoutMs : state.timeoutMs;
    // round A: the appearance rides the status payload. An explicit value
    // (including 'light') must stick; only an ABSENT field (undefined) falls
    // back — the same !==undefined contract as timeoutMs. Flipping
    // <html>.is-dark is the ONLY theme action (vanilla 4.x themes the bundle;
    // the app's own chrome dark pass is a separate feature).
    state.appearance = p.appearance !== undefined ? p.appearance : state.appearance;
    document.documentElement.classList.toggle('is-dark', state.appearance === 'dark');
    syncThemeLabel(); // round D (I4): the Light/Dark value next to the switch
    // round I: the local-pages list rides the status payload. An ABSENT field
    // (undefined) falls back; an explicit [] sticks (cleared list). Re-render
    // ONLY when the list actually changed — a lock/appearance push carries the
    // SAME list, and re-rendering on every push (the whole run) churns the DOM
    // + CDP and degrades the timing of other sections' clicks.
    if (p.localPages !== undefined) {
        const lp = p.localPages.map((e, i) => ({ ...e, id: 'lp-' + i }));
        if (JSON.stringify(lp) !== JSON.stringify(state.localPages)) {
            state.localPages = lp;
            renderLocalPages();
        }
    }
    state.storeAuthenticated = !!p.storeAuthenticated;
    state.storeUsername = p.storeUsername || null;
    updateLockChrome();

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
            // round T-fix19: the Change cell is the row's click target -> the
            // change-detail modal (the in-app `snap change <id>`), exactly like
            // the snap-name cell opens snap-info. It shows the ID (mono, bold -
            // the active part, matching `snap changes` whose first column is the
            // ID) WITH the kind alongside (kept at a glance). Pointer + dotted
            // hover underline + the title are the affordance.
            el('td', { title: 'Show change details',
                class: 'ucm-change-kind', onclick: () => openChangeDetail(c.id) },
                el('span', { class: 'ucm-mono', text: String(c.id) }),
                ' ' + (c.kind || '\u2014')),
            el('td', {}, el('span', { class: `p-status-label p-status-label--${tone}`, text: word })),
            el('td', { class: 'ucm-muted', text: fmtDm(when) }),
            el('td', { class: 'ucm-wrap ucm-muted', text }),
        ));
    });
}

/* round T-fix19: the change-detail modal. Clicking a Recent-changes row
   (the kind cell) opens this - the in-app equivalent of `snap change <id>`
   (alias `snap tasks <id>`). The body is ONE scrollable, terminal-styled
   pane (.ucm-change__lines, the journal idiom) holding the change's full
   text: a TASK table (Status / Spawn / Ready / Summary, with a percent
   for an in-progress Doing task) + one LOG block per task that carries a
   log (a dotted rule, the task summary, then its log lines). No filtering
   for now (the journal viewer's filter row is deliberately NOT reused).
   The detail comes from core.system.change(id) -> GET /v2/changes/{id}
   (the same chain waitChangeSettled already uses). */
function openChangeDetail(id) {
    if (document.querySelector('.ucm-modal')) return; // one modal at a time
    const box = el('div', { class: 'ucm-modal ucm-modal--changes' });
    const onKey = (e) => { if (e.key === 'Escape') closeModal(); };
    const closeModal = () => { document.removeEventListener('keydown', onKey); box.remove(); };
    const backdrop = el('div', { class: 'ucm-modal__backdrop', onclick: () => closeModal() });
    document.addEventListener('keydown', onKey);

    const inner = el('div', { class: 'ucm-modal__card' });
    const close = el('button', { class: 'p-button--base p-button', type: 'button', 'aria-label': 'Close', onclick: () => closeModal() },
        el('i', { class: 'p-icon--close ucm-info__close' }));
    inner.append(el('div', { class: 'ucm-modal__head' },
        el('p', { class: 'p-heading--5', text: 'Change details', style: 'margin:0;' }),
        close));
    const bodyBox = el('div', { class: 'ucm-modal__body' });
    const pre = el('pre', { class: 'ucm-change__lines' });
    bodyBox.append(pre);
    inner.append(bodyBox);
    box.append(backdrop, inner);
    document.body.append(box);
    close.focus();

    pre.textContent = 'Loading change\u2026';
    (async () => {
        try {
            const chg = await core.system.change(String(id));
            pre.textContent = changeDetailText(chg);
        } catch (e) {
            pre.textContent = 'Could not load the change details: ' + e.message;
        }
    })();
}

/* round T-fix19: render one change as text, mirroring `snap change <id>`
   (snapd cmd/snapd/cli/cmd_changes.go cmdTasks.showChange): a short
   context header (ID / kind / status / summary / spawned / ready - the
   ID is the row the user clicked), then a tab-separated
   TASK table (Status / Spawn / Ready / Summary - an in-progress Doing
   task with a multi-step progress gets " (NN.NN%)") and, for each task
   that carries a log, a block of a 60-dot rule, the task summary, and the
   log lines. The pane is white-space:pre so the fixed rule + the
   tab-separated rows read like the terminal. */
function changeDetailText(chg) {
    const d = (iso) => fmtDm(iso); // DD.MM.YYYY HH:MM, or — (== the CLI's '-') when null
    const lines = [];
    lines.push('Change ' + chg.id + '    ' + (chg.kind || '') + '    ' + (chg.status || ''));
    if (chg.summary) lines.push(chg.summary);
    lines.push('Spawned ' + d(chg['spawn-time']) + (chg['ready-time'] ? '    Ready ' + d(chg['ready-time']) : ''));
    if (chg.err) lines.push('Error ' + chg.err);
    const tasks = Array.isArray(chg.tasks) ? chg.tasks : [];
    if (!tasks.length) {
        lines.push('');
        lines.push('No tasks recorded for this change.');
        return lines.join('\n');
    }
    lines.push('');
    lines.push('Status\tSpawn\tReady\tSummary');
    for (const t of tasks) {
        let summary = t.summary || '';
        if (t.status === 'Doing' && t.progress && t.progress.total > 1)
            summary += ' (' + (100 * t.progress.done / t.progress.total).toFixed(2) + '%)';
        const ready = t['ready-time'] ? d(t['ready-time']) : '\u2014';
        lines.push([t.status || '', d(t['spawn-time']), ready, summary].join('\t'));
    }
    for (const t of tasks) {
        if (!Array.isArray(t.log) || !t.log.length) continue;
        lines.push('');
        lines.push('......................................................................');
        lines.push(t.summary || '');
        for (const l of t.log) lines.push(l);
    }
    return lines.join('\n');
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
    // The network view = the General card (round 49b) + the Interfaces
    // section (round 53): one card per device, LIVE values by default, the
    // netplan definition editable in place.
    await Promise.all([loadGeneral(), loadNetDevices().catch(() => {})]);
}


/* Round 49b: the Network page is rebuilt as ONE full-width General card,
   grouped by USE CASE (hostname / ssh / proxies / time / forwarding) instead
   of a random field grid. The card is driven by the live snapd CORE system
   config — the SAME per-snap conf document netplan already uses
   (PUT /v2/snaps/core/conf, key core.<key>). The bridge (core.snaps.confGet /
   confSet) is round-1, so NO main.js / preload change is needed to wire it.

   snapd system-option contract (source @8d4d073 configcore, LIVE-verified):
     core.system.hostname            string  (external config: GET reads the live
                                            /etc/hostname, PUT sets it)
     core.service.ssh.disable        bool    (true = ssh OFF; the daemon stops
                                            + masks the ssh unit on apply)
     core.service.ssh.listen-address string  (bare "PORT" -> snapd expands to
                                            0.0.0.0:PORT + [::]:PORT; empty =
                                            the distro default)
     core.proxy.http / core.proxy.https  string (URL; snapd applies it to the
                                            store + snap operations)
   There is NO core.* option for timesync, the timeserver, or IP forwarding —
   none of them reaches the daemon via the conf channel. Timesync/timeserver
   are wired through the timeserver-control interface (round 49f); IP
   forwarding through the network-control interface (round 51: the kernel's
   /proc sysctl nodes, live + a persisted pref re-applied at startup).

   Editing uses the SNAP-CONFIG POPUP's in-place idiom (round 48g): the value
   text is the affordance (dotted underline on hover); clicking it swaps in a
   prefilled input, ENTER saves (an UNCHANGED value sends nothing), ESC
   cancels (stopPropagation), and a blur to the outside abandons. */


/* --- the General card's live values (populated by loadGeneral) ------------- */
function genHasState() { return state && state.gen && state.gen.hostname !== undefined; }

const RE_GEN_HOSTNAME = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const RE_GEN_PROXY = /^(http|https|socks5)?:\/\/[A-Za-z0-9.-]+(:\d+)?$/i;
const RE_GEN_NTP = /^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)+$/;

function genPortNum(p) { return /^\d+$/.test(p) ? parseInt(p, 10) : NaN; }

/* core.service.ssh.listen-address -> the port the user set (a bare port is
   stored by snapd as "0.0.0.0:PORT,[::]:PORT"); null when unset. */
function genParseListen(addr) {
    if (!addr || typeof addr !== 'string') return null;
    const n = String(addr).split(',')[0].trim().split(':').pop();
    return /^\d+$/.test(n) ? n : null;
}

async function loadGeneral() {
    let doc = null;
    try { doc = await core.snaps.confGet('core'); }
    catch (e) { if (!(e && /no such snap|not found/i.test(String(e.message)))) toastErr(e); return; }
    let p = { hostname: null, ssh: true, listen: null, http: null, https: null };
    try {
        const raw = (doc && typeof doc === 'object') ? doc : {};
        const sys = (raw.system && typeof raw.system === 'object') ? raw.system : {};
        const svc = (raw.service && typeof raw.service === 'object') ? raw.service : {};
        const sshc = (svc.ssh && typeof svc.ssh === 'object') ? svc.ssh : {};
        const proxy = (raw.proxy && typeof raw.proxy === 'object') ? raw.proxy : {};
        if (sys.hostname != null) p.hostname = String(sys.hostname);
        p.ssh = sshc.disable === true ? false : true; // absent/false = enabled
        if (sshc['listen-address'] != null) p.listen = String(sshc['listen-address']);
        if (proxy.http != null) p.http = String(proxy.http);
        if (proxy.https != null) p.https = String(proxy.https);
    } catch { /* fall back to the parsed defaults on a malformed doc */ }
    // Fallback (round 49d): when snapd has NO hostname setting yet, show the OS
    // hostname the dashboard already uses instead of a bare "Click to add".
    // state.host.hostname is the dashboard's cached copy (loadDashboard runs
    // before the network view is reachable); read it directly if the cache is
    // not populated yet (a cold open / the harness).
    let osHost = (state.host && state.host.hostname) ? state.host.hostname : null;
    if (!p.hostname && !osHost) {
        try {
            const info = await core.system.info().catch(() => null);
            if (info && info.host && info.host.hostname) osHost = info.host.hostname;
        } catch { osHost = null; }
    }
    // Timesync / NTP (round 49f, timeserver-control interface): the LIVE on/off
    // (org.freedesktop.timedate1.SetNTP) + the configured NTP server (the
    // timesyncd.conf). If the interface isn't reachable (not connected / no bus
    // in the dev container) the read fails -> default on, no server.
    let ts = { ntp: true, server: null };
    try { ts = await core.timesync.status().catch(() => ts); } catch { ts = { ntp: true, server: null }; }
    // IP forwarding (round 51, network-control interface): the LIVE kernel
    // state is the truth the switch shows (like the timesync toggle reads
    // live SetNTP state) — if the read fails (plug not connected / dev) it
    // renders OFF, and a set() failure toasts.
    let fw = { on: null, pref: false };
    try { fw = await core.network.forwarding.status().catch(() => fw); } catch { fw = { on: null, pref: false }; }
    state.gen = { hostname: p.hostname, ssh: p.ssh, listen: p.listen, http: p.http, https: p.https, osHost,
        timesyncNtp: (ts && ts.ntp === null) ? true : !!ts.ntp, timesyncServer: (ts && ts.server) || null,
        ipfwd: fw.on === true };
    const card = $('#genCard');
    if (card) renderGeneral();
}

/* The in-place value editor (round-48g idiom, adapted to the General card):
   a single-line input prefilled with the current value; Enter saves, Esc
   cancels (stopPropagation), a blur to the OUTSIDE abandons. Saving goes
   through the same core.snaps.confSet the config popup uses — an UNCHANGED
   value sends nothing. */
function genInlineEditGroup(field, current, display, onValid, onSave, placeholder) {
    const grp = el('div', { class: 'p-form__group ucm-gen__edit', id: 'ucmGenEditGroup' });
    const inp = el('input', { class: 'p-form-validation__input ucm-mono ucm-gen__editinp', type: 'text', spellcheck: 'false' });
    // round 48f: the config-popup in-place editor is SINGLE-LINE here, so there
    // is no Save button (the "Enter saves — Esc cancels" hint is the affordance).
    const hint = el('p', { class: 'ucm-gen__edithint', text: 'Enter saves \u2014 Esc cancels' });
    const msg = el('p', { class: 'p-form-validation__message ucm-gen__editmsg' });
    grp.append(inp, hint, msg);
    inp.placeholder = placeholder || '';
    inp.value = display == null ? '' : String(display);
    const doSave = async () => {
        if (grp.classList.contains('is-disabled')) return;
        const raw = String(inp.value).trim();
        // the timeserver may be left EMPTY (that clears it -> the distro default
        // NTP) — like the proxies, only the hostname / ssh-port need a value.
        if (raw === '' && field !== 'timeserver') { setFieldState('ucmGenEditGroup', 'error', 'Enter a value'); return; }
        if (onValid && !onValid(raw)) return; // the field shows its own error
        const curText = (current == null ? '' : String(current)).trim();
        if (raw === curText) { closeGenEdit(); return; } // unchanged -> no PUT
        grp.classList.add('is-disabled');
        try {
            const change = await onSave(raw);
            if (change && typeof change === 'object' && change.id != null) await waitChangeSettled(change);
            if (field === 'hostname') state.gen.hostname = raw;
            else if (field === 'http') state.gen.http = raw;
            else if (field === 'https') state.gen.https = raw;
            const savedLabel = { hostname: 'Hostname updated', http: 'Proxy updated', https: 'Proxy updated',
                'ssh-port': 'SSH port updated', timeserver: 'Timeserver updated (applies only after reboot)' }[field] || 'Saved';
            toast('positive', 'Saved', savedLabel);
            renderGeneral();
        } catch (e) { toastErr(e); closeGenEdit(); }
        finally { grp.classList.remove('is-disabled'); }
    };
    inp.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); doSave(); }
        else if (e.key === 'Escape') { e.stopPropagation(); closeGenEdit(); }
    });
    // round 48f-D (config popup): a shown error clears LIVE once the value is
    // valid again, so it is never "stuck"; a blur to the outside abandons the
    // edit (the re-render wipes any lingering message).
    inp.addEventListener('input', () => {
        if (!grp.classList.contains('is-error')) return;
        const raw = String(inp.value).trim();
        if (raw === '') { setFieldState('ucmGenEditGroup', 'error', 'Enter a value'); return; }
        if (onValid && !onValid(raw)) return; // onValid set the specific message
        setFieldState('ucmGenEditGroup', '');
    });
    inp.addEventListener('blur', (e) => {
        if (e.relatedTarget && grp.contains(e.relatedTarget)) return;
        closeGenEdit();
    });
    return grp;
}

let genEditGrp = null;
function closeGenEdit() { if (genEditGrp) { genEditGrp = null; renderGeneral(); } }

function genValText(v, emptyText) { return (v == null || v === '') ? (emptyText || '.....') : String(v); }

/* an editable value slot: shows the value (the dotted-underline click
   affordance) or, while editing, the in-place editor. Used standalone (a
   hostname/proxy row) and inline next to a switch (the ssh port, timeserver). */
function genEditableSlot(field, current, display, onValid, onSave, placeholder, disabled, editLabel, emptyText) {
    const slot = el('span', { class: 'ucm-gen__slot' });
    const val = el('span', {
        class: 'ucm-mono ucm-gen__val' + (disabled ? ' ucm-gen__val--muted' : ' ucm-conf__val ucm-conf__editable'),
        text: genValText(display, disabled ? 'Not available yet' : emptyText),
    });
    if (disabled) {
        val.title = 'No snapd system option yet';
    } else {
        val.title = 'Edit ' + (editLabel || field);
        val.addEventListener('click', () => {
            if (slot.querySelector('.ucm-gen__edit')) return;
            const grp = genInlineEditGroup(field, current, display, onValid, onSave, placeholder);
            genEditGrp = grp;
            slot.replaceChildren(grp);
            const f = grp.querySelector('input');
            f.focus(); if (f.select) f.select();
        });
    }
    slot.append(val);
    return slot;
}

/* an inline [label value] unit (the ssh port / timeserver) — a muted caption
   with the editable value to its right, on the SAME line as the switch, so
   toggling it never changes the row height (round 49c). */
function genLabeledField(labelText, slot) {
    const wrap = el('span', { class: 'ucm-gen__field' });
    wrap.append(el('span', { class: 'ucm-gen__fieldlabel', text: labelText }), slot);
    return wrap;
}

/* a [caption | value] row where the value is an editable slot. */
function genRowEditable(caption, field, current, display, onValid, onSave, placeholder, disabled, emptyText) {
    const row = el('div', { class: 'ucm-gen__row ucm-gen__row--edit' });
    row.append(el('span', { class: 'ucm-gen__label', text: caption }));
    const content = el('div', { class: 'ucm-gen__content' });
    content.append(genEditableSlot(field, current, display, onValid, onSave, placeholder, disabled, caption, emptyText));
    row.append(content);
    return row;
}

/* a [caption | switch (+ optional inline field)] row — the ssh and time rows.
   The switch is the 48a orange p-switch; the inline field is the same unit the
   port uses. A disabled switch renders the scaffold state (no core.* option). */
function genSwitchRow(caption, on, onToggle, disabled, extra) {
    const row = el('div', { class: 'ucm-gen__row ucm-gen__row--toggle' });
    row.append(el('span', { class: 'ucm-gen__label', text: caption }));
    const content = el('div', { class: 'ucm-gen__content ucm-gen__switchline' });
    const lab = el('label', { class: 'p-switch ucm-gen__sw' });
    lab.append(el('input', { class: 'p-switch__input', type: 'checkbox' }), el('span', { class: 'p-switch__slider' }));
    const input = lab.querySelector('input');
    input.checked = !!on;
    if (disabled) { lab.classList.add('is-disabled'); input.disabled = true; }
    else input.addEventListener('change', onToggle);
    content.append(lab);
    if (extra) content.append(extra);
    row.append(content);
    return row;
}

function genProxyRow() {
    // round 49e: HTTP + HTTPS are INLINE [label value] units (the same unit the
    // ssh port and the timeserver use) so the row is one line tall like the
    // others — not a stacked 50/50 block. Each field is 50% of the content
    // (.ucm-gen__field { flex: 1 1 0 }), so the split reads evenly.
    const proxyValid = (v) => { if (v === '') { setFieldState('ucmGenEditGroup', ''); return true; } if (!RE_GEN_PROXY.test(v)) { setFieldState('ucmGenEditGroup', 'error', 'A URL, e.g. http://proxy.example:3128.'); return false; } setFieldState('ucmGenEditGroup', ''); return true; };
    const row = el('div', { class: 'ucm-gen__row ucm-gen__row--proxies' });
    row.append(el('span', { class: 'ucm-gen__label', text: 'Proxy' }));
    const content = el('div', { class: 'ucm-gen__content' });
    content.append(
        genLabeledField('HTTP', genEditableSlot('http', state.gen.http, state.gen.http, proxyValid,
            (v) => core.snaps.confSet('core', { 'proxy.http': v }), 'e.g. http://proxy.example:3128')),
        genLabeledField('HTTPS', genEditableSlot('https', state.gen.https, state.gen.https, proxyValid,
            (v) => core.snaps.confSet('core', { 'proxy.https': v }), 'e.g. http://proxy.example:3128')),
    );
    row.append(content);
    return row;
}

let genRendering = false;
function renderGeneral() {
    if (genRendering) return; // re-entrant (blur fired mid-rebuild) — the outer render wins
    genRendering = true;
    try {
    const card = $('#genCard');
    if (!card || !genHasState()) return;
    const body = card.querySelector('.ucm-net-card__body');
    if (!body) return;
    body.replaceChildren(el('p', { class: 'p-form-help-text ucm-gen__help', text: 'System Settings' }));
    const rows = el('div', { class: 'ucm-gen__rows' });
    // 1 — hostname (wired: core.system.hostname). When snapd has no hostname
    //    setting yet, fall back to the OS hostname the dashboard already shows
    //    (state.host.hostname from core.system.info()) instead of a bare
    //    "Click to add" — it is the value an edit would naturally start from.
    rows.append(genRowEditable('Hostname', 'hostname', state.gen.hostname, state.gen.hostname || state.gen.osHost || null,
        (v) => { if (!RE_GEN_HOSTNAME.test(v)) { setFieldState('ucmGenEditGroup', 'error', 'Lowercase letters, digits and hyphens; must start and end with a letter or digit.'); return false; } setFieldState('ucmGenEditGroup', ''); return true; },
        async (v) => core.snaps.confSet('core', { 'system.hostname': v }), 'e.g. core-24'));
    // 2 — ssh (wired: core.service.ssh.disable + core.service.ssh.listen-address).
    //    the port is an INLINE field on the switch line (not a stacked group),
    //    so turning ssh off removes zero vertical space — the row never collapses.
    const sshToggle = async () => {
        const sw = $('#genCard [data-gen-row="ssh"] .p-switch__input');
        if (sw) sw.disabled = true;
        const on = state.gen.ssh = !state.gen.ssh;
        try {
            const change = await core.snaps.confSet('core', { 'service.ssh.disable': on ? false : true });
            if (change && typeof change === 'object' && change.id != null) await waitChangeSettled(change);
            toast('positive', on ? 'SSH enabled' : 'SSH disabled', on ? 'Remote access is now allowed.' : 'Remote access is now blocked.');
        } catch (e) { state.gen.ssh = !on; toastErr(e); }
        finally { renderGeneral(); }
    };
    const sshRow = genSwitchRow('SSH (remote access)', state.gen.ssh, sshToggle, false);
    sshRow.dataset.genRow = 'ssh';
    if (state.gen.ssh) {
        const port = genParseListen(state.gen.listen);
        const portSlot = genEditableSlot('ssh-port', port, port,
            (raw) => { const n = genPortNum(raw); if (isNaN(n) || n < 1 || n > 65535) { setFieldState('ucmGenEditGroup', 'error', 'A port from 1 to 65535.'); return false; } setFieldState('ucmGenEditGroup', ''); return true; },
            async (raw) => { const change = await core.snaps.confSet('core', { 'service.ssh.listen-address': raw }); state.gen.listen = raw; return change; },
            'e.g. 2222', false, 'SSH port', 'default');
        sshRow.querySelector('.ucm-gen__switchline').append(genLabeledField('Port', portSlot));
    }
    rows.append(sshRow);
    // 3 — time (WIRED, round 49f: the timeserver-control snap interface). The
    //    on/off is LIVE (timedate1.SetNTP); the NTP server is written to
    //    /etc/systemd/timesyncd.conf and applies after a timesyncd restart
    //    (systemd LP #1504657). Laid out like the ssh row: switch + the
    //    timeserver as an inline [label value] field + a quiet note.
    const timeserverValid = (v) => { if (v === '') { setFieldState('ucmGenEditGroup', ''); return true; } if (!RE_GEN_NTP.test(v)) { setFieldState('ucmGenEditGroup', 'error', 'An NTP server address, e.g. 0.ubuntu.pool.ntp.org.'); return false; } setFieldState('ucmGenEditGroup', ''); return true; };
    const timeExtra = el('div', { class: 'ucm-gen__time-extra' });
    timeExtra.append(
        genLabeledField('Timeserver', genEditableSlot('timeserver', state.gen.timesyncServer, state.gen.timesyncServer, timeserverValid,
            async (v) => { await core.timesync.setServer(v); state.gen.timesyncServer = v || null; return null; }, 'e.g. 0.ubuntu.pool.ntp.org', false, 'Timeserver', 'default')),
        el('span', { class: 'ucm-gen__note', text: 'Applies only after reboot' }),
    );
    const timeRow = genSwitchRow('Sync time from internet', state.gen.timesyncNtp, async () => {
        const sw = $('#genCard [data-gen-row="time"] .p-switch__input');
        if (sw) sw.disabled = true;
        const on = !(state.gen.timesyncNtp === true);
        try {
            await core.timesync.setEnabled(on);
            state.gen.timesyncNtp = on;
            toast('positive', on ? 'Time sync enabled' : 'Time sync disabled', on ? 'The system will sync its clock from the internet.' : 'Internet time synchronisation is off.');
        } catch (e) { toastErr(e); }
        finally { renderGeneral(); }
    }, false, timeExtra);
    timeRow.dataset.genRow = 'time';
    rows.append(timeRow);
    // 4 — proxies (wired: core.proxy.http / core.proxy.https) — ONE row: "Proxy"
    //    caption, HTTP + HTTPS as two inline fields side by side.
    rows.append(genProxyRow());
    // 5 — ip forwarding (Wired, round 51: the network-control interface —
    //    live /proc sysctl writes + a persisted pref the app re-applies at
    //    startup; there is NO core.* snapd option for it).
    const fwRow = genSwitchRow('IP forwarding', state.gen.ipfwd === true, async () => {
        const sw = $('#genCard [data-gen-row="ipfwd"] .p-switch__input');
        if (sw) sw.disabled = true;
        const on = !(state.gen.ipfwd === true);
        try {
            await core.network.forwarding.set(on);
            state.gen.ipfwd = on;
            const st = await core.network.forwarding.status().catch(() => null);
            if (st && st.on !== null) state.gen.ipfwd = st.on === true; // the kernel is the truth
            toast('positive', on ? 'IP forwarding enabled' : 'IP forwarding disabled',
                on ? 'IPv4 + IPv6 packets are now forwarded between interfaces.'
                   : 'Packet forwarding is off.');
        } catch (e) { state.gen.ipfwd = on ? false : true; toastErr(e); }
        finally { renderGeneral(); }
    }, false);
    fwRow.dataset.genRow = 'ipfwd';
    rows.append(fwRow);
    body.append(rows);
    } finally { genRendering = false; }
}

/* ------------------- network devices (round 53) ------------------------
   One flat card per device in a 2-up grid. The DEFAULT view is the LIVE
   state (what the kernel is doing right now — the user looks up an SSH
   address here), read via the network-control interface's standard tools
   (ip / iw / resolvectl); editing swaps the card's body for a form
   pre-filled from the NETPLAN definition (the configured truth) and
   applies ONE device's entry through snapd's netplan external config
   (which tries the change for 30s and rolls back if it would lose the
   connection). Physical devices are always shown; virtual ones (bridges,
   v1: added via "Add bridge") come from the netplan doc.
   ---------------------------------------------------------------------- */
const NET_TYPE_NAMES = {
    ethernet: 'Ethernet', wifi: 'Wi-Fi', bridge: 'Bridge', bond: 'Bond',
    vlan: 'VLAN', tunnel: 'Tunnel', vrf: 'VRF', dummy: 'Dummy', veth: 'vEthernet',
    other: 'Network', wired: 'Network',
};
const RE_NET_NAME_UI = /^[A-Za-z][A-Za-z0-9._:-]{0,15}$/;
const RE_NET_CIDR_UI = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\/(3[0-2]|2\d|1\d|[1-9])$/;
const RE_NET_IPV4_UI = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
let netRendering = false;
async function loadNetDevices() {
    const d = await core.network.devices();
    state.devices = Array.isArray(d) ? d : [];
    if (state.view === 'network') renderNetDevices();
}
function netEditingName() { return String(state.netEditing || '').replace(/^new:/, ''); }
function netUniqueBridgeName() {
    const have = new Set((state.devices || []).map((d) => d.name));
    let i = 0;
    while (have.has('br' + i)) i += 1;
    return 'br' + i;
}
function renderNetDevices() {
    if (netRendering) return;
    netRendering = true;
    try {
        const grid = $('#netIfaceGrid');
        if (!grid || !state.devices) return;
        const count = $('#netIfaceCount');
        if (count) count.textContent = state.devices.length + ' device' + (state.devices.length === 1 ? '' : 's');
        grid.replaceChildren(...state.devices.map((d) => netCard(d)));
        // round 63: the "+ Add" button is disabled while a pending (Add) card
        // is open — it re-enables on Apply/Cancel (both end in this render).
        const addBtn = $('#netAddDevice');
        if (addBtn) addBtn.disabled = state.devices.some((x) => x.pending);
    } finally { netRendering = false; }
}
/* a device card: header (name + type + live status pill + the round-58
   pencil edit icon, top-right) + body — the LIVE summary, or the in-place
   edit form while editing (round 59: the card KEEPS its own grid column and
   only grows in height — it no longer spans the row; the form's fields are
   capped and fit the half-width column). The edit icon is in the head so it
   is present in BOTH the view and the edit state; while the card IS being
   edited the icon is disabled (inactive) — clicking it then is a no-op, and
   ESC / Cancel reverts the edit (round 60). */
/* round 60: the single in-place netcard edit form's Escape handler, kept at
   module scope (a slot the current form re-points on each render) so switching
   which card is being edited never leaves a stale document listener firing for
   the previously-edited card. Scoped to the network view, so the 48k confirm /
   modal Esc layering is untouched (a netcard edit is inline in the Network
   page, not inside a modal or a confirm). */
let netEditEscHandler = null;
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && netEditEscHandler && state.view === 'network') {
        e.stopPropagation();
        const h = netEditEscHandler;
        netEditEscHandler = null;
        h();
    }
});
function netCard(d) {
    const card = el('div', { class: 'p-card ucm-netcard' + (state.netEditing === d.name ? ' ucm-netcard--editing' : '') });
    card.dataset.netcard = d.name;
    const head = el('div', { class: 'p-card__header ucm-netcard__head' });
    const statusLabel = el('span', { class: 'p-status-label ' + (d.connected ? 'p-status-label--positive' : 'p-status-label--caution'), text: d.connected ? 'Connected' : 'Not connected' });
    head.append(
        el('span', { class: 'ucm-netcard__name ucm-mono', text: d.name }),
        el('span', { class: 'ucm-netcard__type', text: NET_TYPE_NAMES[d.type] || 'Network' }),
        statusLabel,
        /* round 58: the edit affordance is the suru pencil in the head,
           top-right after the status label (the label's margin-left:auto
           pushes both to the right edge). The old big "Change settings"
           foot button is gone. rowBtn = the app's icon-button idiom
           (tooltip + aria). Clicking while editing re-sets the same name
           (a no-op) — no branch needed. */
        rowBtn('Change settings', 'p-icon--edit',
            (btn) => { state.netEditing = d.name; renderNetDevices(); },
            { tooltip: 'Change settings', ariaLabel: 'Change settings on ' + d.name, disabled: state.netEditing === d.name }),
    );
    card.append(head);
    const body = el('div', { class: 'ucm-netcard__body' });
    body.append(state.netEditing === d.name ? netCardEdit(d) : netCardView(d));
    card.append(body);
    return card;
}
/* the default (view) body: the LIVE values — addresses (the kernel truth,
   what SSH connects with), gateway, DNS — plus the configured mode. */
function netCardView(d) {
    const rowsDl = el('dl', { class: 'ucm-kv ucm-netcard__rows' });
    const live = (v) => (v == null || v === '' || (Array.isArray(v) && !v.length)) ? '—' : String(v);
    const rows = [];
    rows.push(['Addresses', live(d.addresses && d.addresses.length ? d.addresses.map((a) => a.cidr).join(', ') : null)]);
    rows.push(['Gateway', live(d.gateway)]);
    rows.push(['DNS', live(d.dns && d.dns.length ? d.dns.join(', ') : null)]);
    if (d.type === 'wifi') {
        const aps = d.netplan && d.netplan['access-points'] ? Object.keys(d.netplan['access-points']) : [];
        rows.push(['Network', aps.length ? aps[0] : null]);
    }
    if (d.type === 'bridge') {
        // LIVE members first (the kernel truth, from the master field); the
        // netplan member list is only a fallback (a "config" value for a
        // bridge whose members are not up yet).
        const mem = (d.members && d.members.length) ? d.members
            : (d.netplan && d.netplan.interfaces && d.netplan.interfaces.length ? d.netplan.interfaces : null);
        rows.push(['Members', mem ? mem.join(', ') : null]);
    }
    const staticish = d.configured && d.netplan && Array.isArray(d.netplan.addresses) && d.netplan.addresses.length;
    rows.push(['Configured', d.configured ? (staticish ? 'Static IP' : 'Automatic (DHCP)') : null]);
    for (const [k, v] of rows) {
        const r = el('div', { class: 'ucm-netcard__row' });
        r.append(el('dt', { text: k }));
        r.append(el('dd', { class: 'ucm-muted' + (v == null ? '' : ' ucm-netcard__v'), text: v == null ? 'Not configured' : String(v) }));
        rowsDl.append(r);
    }
    // round 58: the "Change settings" foot button is gone — the edit
    // affordance is the pencil in the card head (netCard above), so the
    // view body is just the live rows.
    return rowsDl;
}
/* the in-place edit body: pre-filled from the netplan definition (the
   configured truth), applies ONE device entry to the netplan doc. */
function netCardEdit(d) {
    const np = (d.configured && d.netplan && typeof d.netplan === 'object') ? d.netplan : {};
    const ap0 = (np['access-points'] && Object.keys(np['access-points'])[0]) || null;
    const apDef = ap0 ? np['access-points'][ap0] : {};
    const staticOn = Array.isArray(np.addresses) && np.addresses.length > 0;
    const v = {
        name: d.name,
        type: d.type === 'bridge' ? 'bridge' : (d.type === 'wifi' ? 'wifi' : 'ethernet'),
        mode: staticOn ? 'static' : 'dhcp',
        address: (np.addresses && np.addresses[0]) || '',
        gateway: np.gateway4 || '',
        dns: (np.dns && np.dns.nameservers && np.dns.nameservers.addresses) ? np.dns.nameservers.addresses.slice() : [],
        ssid: ap0 || '',
        password: apDef.password || '',
        hidden: apDef.hidden === true,
        members: np.interfaces && Array.isArray(np.interfaces) ? np.interfaces.slice() : [],
    };
    const box = el('div', { class: 'ucm-netcard__edit' });
    const field = (label, input, cls) => {
        const g = el('div', { class: 'p-form__group ucm-netcard__fg' + (cls ? ' ' + cls : '') });
        g.append(el('label', { class: 'p-form__label', text: label }), input);
        return g;
    };
    // round 60: the Name field is only for NEW (pending, "Add") cards, where
    // it names the new device. For an existing device it was a DISABLED,
    // redundant repeat of the name in the card head — removed.
    let nameInp = null;
    if (d.pending) {
        nameInp = el('input', { class: 'p-form-validation__input ucm-mono', type: 'text', spellcheck: 'false', placeholder: 'e.g. br0' });
        nameInp.value = v.name;
        box.append(field('Name', nameInp, 'ucm-netcard__namefg'));
    }

    // Address mode: a switch (no pulldown) — off = Automatic (DHCP), on =
    // static (reveals the address fields, the "hidden until needed" rule).
    const staticGrp = el('div', { class: 'ucm-netcard__row' });
    const staticSw = el('input', { class: 'p-switch__input', type: 'checkbox' });
    staticSw.checked = v.mode === 'static';
    const staticFields = el('div', { class: 'ucm-netcard__static' });
    staticFields.hidden = v.mode !== 'static';
    const addrInp = el('input', { class: 'p-form-validation__input ucm-mono', type: 'text', spellcheck: 'false', placeholder: 'e.g. 192.168.1.50/24' });
    addrInp.value = v.address;
    const gwInp = el('input', { class: 'p-form-validation__input ucm-mono', type: 'text', spellcheck: 'false', placeholder: 'e.g. 192.168.1.1' });
    gwInp.value = v.gateway;
    staticFields.append(field('IPv4 address', addrInp), field('Gateway', gwInp));
    staticSw.addEventListener('change', () => { staticFields.hidden = !staticSw.checked; });
    staticGrp.append(el('label', { class: 'p-switch ucm-netcard__sw' },
        el('span', { text: 'Static IP' }), staticSw, el('span', { class: 'p-switch__slider' })),
        el('span', { class: 'ucm-muted', text: 'Automatic (DHCP) when off' }));
    box.append(staticGrp, staticFields);

    // Wi-Fi: the network + password (WPA-PSK, v1; the password is a masked
    // field and never shown in the summary).
    let ssidInp = null, pwInp = null, hidSw = null;
    if (v.type === 'wifi') {
        ssidInp = el('input', { class: 'p-form-validation__input', type: 'text', spellcheck: 'false', placeholder: 'Wi-Fi network name' });
        ssidInp.value = v.ssid;
        pwInp = el('input', { class: 'p-form-validation__input', type: 'password', spellcheck: 'false', placeholder: 'password' });
        pwInp.value = v.password;
        box.append(field('Network', ssidInp), field('Wi-Fi password', pwInp));
        hidSw = el('input', { class: 'p-switch__input', type: 'checkbox' });
        hidSw.checked = v.hidden;
        box.append(el('div', { class: 'ucm-netcard__row' },
            el('label', { class: 'p-switch ucm-gen__sw' },
                el('span', { text: 'Hidden network' }), hidSw, el('span', { class: 'p-switch__slider' }))));
    }

    // Bridge: which physical devices join it (a checklist of switches —
    // no pulldown). Virtual devices are not valid members in v1.
    let memberEls = null;
    if (v.type === 'bridge') {
        const list = (state.devices || []).filter((x) => (x.type === 'ethernet' || x.type === 'wifi' || x.type === 'wired') && x.name !== v.name && !x.pending);
        memberEls = new Map();
        const mwrap = el('div', { class: 'ucm-netcard__members' });
        mwrap.append(el('span', { class: 'ucm-muted ucm-netcard__memberscap', text: 'Members' }));
        if (!list.length) mwrap.append(el('span', { class: 'ucm-muted', text: 'no physical devices found' }));
        for (const x of list) {
            const sw = el('input', { class: 'p-switch__input', type: 'checkbox' });
            sw.checked = v.members.includes(x.name);
            memberEls.set(x.name, sw);
            mwrap.append(el('label', { class: 'p-switch ucm-gen__sw ucm-netcard__member' },
                el('span', { class: 'ucm-mono', text: x.name }), sw, el('span', { class: 'p-switch__slider' })));
        }
        box.append(mwrap);
    }

    // DNS: a free-text line that chips itself (Enter/blur commits the
    // tokens) — no pulldown, no extra field.
    const dnsState = { vals: v.dns.slice() };
    const dnsInp = el('input', { class: 'p-form-validation__input ucm-mono', type: 'text', spellcheck: 'false', placeholder: 'e.g. 1.1.1.1, 8.8.8.8' });
    const dnsRow = el('div', { class: 'ucm-netcard__dnsrow' });
    const dnsLive = (raw) => String(raw).split(/[, ]+/).map((x) => x.trim()).filter(Boolean);
    const renderDns = () => {
        dnsRow.replaceChildren(...dnsState.vals.map((x) =>
            el('span', { class: 'p-chip ucm-netcard__dnschip ucm-mono' },
                el('span', { text: x }),
                el('button', {
                    type: 'button', class: 'p-chip__dismiss', 'aria-label': 'Remove ' + x,
                    onclick: () => { dnsState.vals = dnsState.vals.filter((y) => y !== x); renderDns(); },
                }))),
            dnsInp);
    };
    dnsInp.addEventListener('blur', () => {
        if (!dnsRow.contains(dnsInp)) return;
        dnsState.vals = dnsState.vals.concat(dnsLive(dnsInp.value));
        dnsInp.value = '';
        renderDns();
    });
    dnsInp.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter') return;
        e.preventDefault();
        dnsState.vals = dnsState.vals.concat(dnsLive(dnsInp.value));
        dnsInp.value = '';
        renderDns();
    });
    renderDns();
    box.append(el('div', { class: 'p-form__group ucm-netcard__fg' }, el('label', { class: 'p-form__label', text: 'DNS servers' }), dnsRow));

    // footer: Cancel (revert) + Apply (commit through snapd). A rejected
    // apply (snapd's Config.Try lost the connection and rolled back) leaves
    // the doc unchanged — the card goes straight back to its LIVE values.
    const foot = el('div', { class: 'ucm-netcard__foot ucm-netcard__foot--edit' });
    foot.append(
        el('button', { type: 'button', class: 'p-button--base', text: 'Cancel', onclick: () => { if (d.pending) state.devices = state.devices.filter((x) => x !== d); state.netEditing = null; renderNetDevices(); } }),
        (() => { const b = el('button', { type: 'button', class: 'p-button--brand', text: 'Apply' }); return b; })(),
    );
    box.append(foot);
    const applyBtn = foot.querySelector('.p-button--brand');

    // round 60: ESC reverts this edit (the app-wide form idiom). The handler
    // is re-pointed on every render, so it always matches the card that is
    // currently being edited.
    netEditEscHandler = () => { if (d.pending) state.devices = state.devices.filter((x) => x !== d); state.netEditing = null; renderNetDevices(); };

    applyBtn.addEventListener('click', async () => {
        if (applyBtn.disabled) return;
        try {
            const name = nameInp ? nameInp.value.trim() : d.name;
            if (!RE_NET_NAME_UI.test(name)) { toastErr(new Error('device name: letters, digits and - _ . : (max 16)')); return; }
            const cfg = { name, type: v.type, mode: staticSw.checked ? 'static' : 'dhcp', mac: d.mac || null };
            if (staticSw.checked) {
                const a = addrInp.value.trim();
                if (!RE_NET_CIDR_UI.test(a)) { toastErr(new Error('IPv4 address must carry a /prefix, e.g. 192.168.1.50/24')); return; }
                const g = gwInp.value.trim();
                if (g && !RE_NET_IPV4_UI.test(g)) { toastErr(new Error('gateway must be an IPv4 address')); return; }
                cfg.address = a; cfg.gateway = g;
            }
            cfg.dns = dnsState.vals.length ? dnsState.vals.slice() : null;
            if (v.type === 'wifi') {
                const s = (ssidInp.value || '').trim();
                if (!s) { toastErr(new Error('a Wi-Fi network name (SSID) is required')); return; }
                cfg.ssid = s; cfg.password = pwInp.value || ''; cfg.hidden = hidSw.checked;
            }
            if (v.type === 'bridge') {
                cfg.interfaces = [];
                for (const [nm, sw] of memberEls) if (sw.checked) cfg.interfaces.push(nm);
            }
            applyBtn.disabled = true;
            const change = await core.network.applyDevice(cfg);
            const done = (change && typeof change === 'object' && change.id != null) ? await waitChangeSettled(change) : null;
            const ok = !done || !isChangeTerminal(done.status) || done.status.toLowerCase() === 'done';
            if (!ok) toast('negative', 'Configuration not applied', name + ': ' + (done.err || done.status) + ' — the previous settings are still in effect.');
            else {
                toast('positive', 'Configuration applied', name + ' is now using the new settings.');
                // The 00-snapd-config.yaml first-boot seed (catch-all
                // boilerplate) is re-merged by snapd on every netplan apply,
                // so the app's config would not be the whole truth. Delete it
                // only once this edit has APPLIED (a failed/rolled-back change
                // must leave the box in its original state).
                if (core.network.clearSeed) await core.network.clearSeed().catch(() => {});
            }
            state.netEditing = null;
            await loadNetDevices();
        } catch (e) {
            toastErr(e);
            state.netEditing = null;
            await loadNetDevices().catch(() => {});
        } finally {
            if (applyBtn.isConnected) applyBtn.disabled = false;
        }
    });
    return box;
}
/* "Add": a pending card in the edit form (bridge-only per v1 scope — the
   button label is deliberately type-agnostic so later device types can
   reuse it); it only joins the netplan doc when the user clicks Apply (a
   Cancel drops it). */
function netAddBridge() {
    if (!state.devices) return;
    // round 63: ONE pending (Add) card at a time — a click while another add
    // form is open (not yet Applied or Cancelled) is a no-op, so ten clicks
    // don't pile up ten empty device entries. renderNetDevices keeps the
    // button itself disabled in that state (the house greyed control).
    if (state.devices.some((x) => x.pending)) return;
    const nm = netUniqueBridgeName();
    state.devices.push({ name: nm, type: 'bridge', connected: false, addresses: [], gateway: null, dns: [], configured: false, netplan: null, pending: true });
    state.netEditing = nm;
    renderNetDevices();
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
        b.textContent = 'Removing…';
        b.classList.add('is-processing');
        b.insertAdjacentHTML('beforeend', ' <i class="p-icon--spinner u-animation--spin" aria-hidden="true"></i>');
        try {
            const change = await core.snaps.action(name, 'remove');
            toast('positive', 'Removal started', `${name} is being removed by snapd.`);
            const done = await waitChangeSettled(change);
            loadSnaps();
            if (done && done.status && isChangeTerminal(done.status) && done.status.toLowerCase() !== 'done') {
                toast('negative', 'Removal finished with an error', `${name}: ${done.err || done.status}`);
            }
        } catch (e) { toastErr(e); }
        finally {
            b.textContent = 'Remove?';
            b.classList.remove('is-processing');
            const sp = b.querySelector('.p-icon--spinner');
            if (sp) sp.remove();
            box.remove();
        }
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
    btn.classList.add('is-processing');
    btn.insertAdjacentHTML('beforeend', ' <i class="p-icon--spinner u-animation--spin" aria-hidden="true"></i>');
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
        btn.classList.remove('is-processing');
        const sp = btn.querySelector('.p-icon--spinner');
        if (sp) sp.remove();
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
    // round SEARCH-FIN: a closed card is a FINISHED search - the input must
    // not linger with its stale query (the user reported it stayed forever).
    // All close paths funnel here: the card's icon X, the document-level ESC
    // handler, and the post-install success path.
    const inp = $('#snapSearchName');
    if (inp) inp.value = '';
    // round STORECOUNT: the caption must not show a stale count on a closed
    // card (the next search re-sets it before the card reopens).
    $('#snapSearchCount').textContent = '';
}

async function searchStore() {
    const nameEl = $('#snapSearchName');
    const q = nameEl.value.trim();
    if (!q) { toast('caution', 'Search', 'Enter something to search the store (names and descriptions).'); return; }
    const box = $('#snapSearchResults');
    box.classList.remove('ucm-hidden');
    $('#snapSearchBody').innerHTML = '';
    $('#snapSearchBody').append(el('tr', {}, el('td', { colspan: '5', class: 'ucm-muted', text: 'Searching…' })));
    try {
        // FULL-TEXT store search (mode 'q' = the snapd /v2/find?q=... the
        // `snap find` CLI sends) — matches names AND summaries, not just
        // known snap names.
        const results = await core.snaps.search(q, 8, 'q');
        // round STORECOUNT: the card caption counts the results found (the
        // house interface/snaps-card idiom — the store q response has no
        // separate total, so this is the number actually in the table).
        $('#snapSearchCount').textContent = results.length + (results.length === 1 ? ' snap' : ' snaps');
        $('#snapSearchBody').innerHTML = '';
        if (!results.length) {
            $('#snapSearchBody').append(el('tr', {}, el('td', { colspan: '5', class: 'ucm-muted', text: 'No store results.' })));
            return;
        }
        results.forEach((r) => {
            const chSel = channelSelect(r);
            const installBtn = el('button', {
                class: 'p-button--brand p-button ucm-rowbtn',
                type: 'button',
                onclick: () => installFromRow(r.name, chSel.value, installBtn),
            }, 'Install');
            $('#snapSearchBody').append(el('tr', {},
                // round SEARCH-FIN: the name is the row's click target ->
                // the snap-info modal (the installed-snaps .ucm-snaps-name
                // idiom). Store-only snaps render a READ-ONLY store-info
                // modal (renderStoreInfo); the row's Install button stays
                // the only install drive (user choice).
                el('td', { class: 'ucm-mono ucm-storename', title: 'Show snap info',
                    onclick: () => openSnapInfo(r.name, r) }, r.name),
                el('td', { class: 'ucm-wrap', text: r.summary || '' }),
                el('td', {}, publisherSpan(r.publisher || {}, publisherName(r.publisher || {}, r) || '\u2014')),
                el('td', {}, chSel),
                // round 47n: the store size (download-size, LIVE-verified on
                // /v2/find); em-dash when the store omits it.
                el('td', { class: 'ucm-mono', text: r['download-size'] != null ? fmtBytes(r['download-size']) : '—' }),
                el('td', { style: 'text-align:right;', onclick: (e) => { e.stopPropagation(); } }, installBtn),
            ));
        });
    } catch (e) {
        $('#snapSearchCount').textContent = '0 snaps';
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

// round SEARCH-FIN: the publisher identity for a snap/store object —
// the display name first (snapd's longPublisher idiom), falling back to
// username / id / the historic developer field.
// round LASTCH: the date (iso) the snap's CURRENT channel was released, from
// a /v2/find store row's channels map — snapd fills ChannelSnapInfo's
// released-at per channel (the store's 'Last revised' in `snap info`). The
// snap's own
// channel is the key (installed snaps: info.channel; store rows: r.channel).
// Unknown channel or empty map -> null (the row renders '—').
function lastChangedFromMap(snap, chanMap) {
    if (!snap || !chanMap) return null;
    // Installed info: `channel` is the RISK ('stable'), but the store map is
    // keyed by the full TRACK/RISK — the `tracking-channel` is the exact key
    // (the fmtTrackChannel idiom). Store rows: the row's own `channel` is
    // already the full key (no tracking-channel present).
    const tc = String(snap.tracking_channel || snap.trackingChannel || snap['tracking-channel'] || '');
    const ch = String(snap.channel || '');
    const c = (tc && chanMap[tc]) || (ch && chanMap[ch]);
    return c && c['released-at'] ? c['released-at'] : null;
}

// round LASTCH-FIX: the LATEST released-at across the WHOLE channel map
// (any channel) — for the search-results info card: "is this snap still
// maintained?" must not hinge on which single channel the row references
// (a store search row's `channel` is 'stable' by default — an old one when
// the snap moved on). null when no entry carries a released-at.
function latestFromMap(chanMap) {
    let best = null;
    Object.values(chanMap || {}).forEach((c) => {
        const t = c && c['released-at'];
        if (t && (!best || t > best)) best = t;
    });
    return best;
}

function publisherName(pub, info) {
    const p = pub || {};
    return p['display-name'] || p.username || p.id || (info && info.developer) || null;
}

// The publisher NAME + validation badge as DOM: the terminal's green check /
// yellow star (round 47e) — the ONE badge idiom in the app, now shared by
// the info modal's Publisher row and the store-results Publisher column.
function publisherSpan(pub, name) {
    const p = pub || {};
    const span = el('span', { class: 'ucm-mono', text: name == null ? '' : String(name) });
    const v = p.validation;
    if (v === 'verified' || v === 'starred')
        span.append(el('span', { class: 'ucm-pub-badge ' + (v === 'verified' ? 'ucm-pub-badge--verified' : 'ucm-pub-badge--starred'), text: v === 'verified' ? '\u2713' : '\u272A' }));
    return span;
}

function openSnapInfo(name, storeRow) {
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
            // round SEARCH-FIN: a search result that is NOT installed -> the
            // SAME info modal, read-only, fed by the /v2/find?q= row (it
            // carries title/summary/description/publisher+validation/
            // version/confinement/grade/links/channels). Install stays on
            // the results ROW (user choice).
            if (storeRow) { renderStoreInfo(storeRow); return; }
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

    // round SEARCH-FIN: the READ-ONLY store-info body for a NOT-INSTALLED
    // snap (openSnapInfo's storeRow drive from a store-results row). Same
    // header structure as renderSnapInfo: display title, mono real name,
    // summary, a 'Not installed' chip (a store row's 'available' status is
    // not an on-disk state, so the status chip is replaced by this marker),
    // the plainified description, and the Publisher / Version / Size rows
    // (Size = download-size, the store's number). No Track/Channel row
    // (nothing installed to switch); no Links row (the search row's links
    // map is sparse; keep the read-only card lean). Nested like
    // renderSnapInfo so it captures the modal's box/bodyBox.
    function renderStoreInfo(r) {
        if (!box.isConnected) return; // closed (Esc) while the 404 was in flight
        bodyBox.innerHTML = '';
        bodyBox.append(el('p', { class: 'ucm-info__name', text: r.title || r.name }));
        if (r.title && r.title !== r.name)
            bodyBox.append(el('p', { class: 'ucm-info__id ucm-mono', text: r.name }));
        if (r.summary)
            bodyBox.append(el('p', { class: 'ucm-info__summary', text: r.summary }));
        const chips = el('div', { class: 'ucm-info__chips' });
        chips.append(el('span', { class: 'p-status-label p-status-label--information', text: 'Not installed' }));
        bodyBox.append(chips);
        if (r.description) {
            bodyBox.append(el('p', { class: 'ucm-info__sec', text: 'Description' }));
            bodyBox.append(el('p', { class: 'ucm-info__desc', text: infoPlain(r.description) }));
        }
        const kv = el('dl', { class: 'ucm-kv' });
        const row = (k, v, mono) => {
            if (v == null || v === '') return;
            kv.append(el('div', {}, el('dt', { text: k }), el('dd', { text: String(v), class: mono ? 'mono' : undefined })));
        };
        const pubName = publisherName(r.publisher || {}, r);
        if (pubName)
            kv.append(el('div', {}, el('dt', { text: 'Publisher' }), el('dd', {}, publisherSpan(r.publisher || {}, pubName))));
        row('Version', r.version || null);
        row('Last changed', fmtDay(latestFromMap(r.channels || {})));
        row('Size', r['download-size'] != null ? fmtBytes(r['download-size']) : null);
        row('Confinement', r.confinement || null);
        row('Grade', r.grade || null);
        if (kv.children.length) bodyBox.append(kv);
    }

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
        // round LASTCH: 'Last changed' — the CURRENT channel's released-at
        // from the store's channel map. Built with '—' (the channels load
        // async, like the Track/Channel loading marker); renderChannelRow
        // fills it when they land (local builds / unknown channels keep '—').
        row('Last changed', fmtDay(null));
        // Track/Channel — the value is followed by a transient "loading"
        // marker until the store channels resolve (round 47g); the switcher
        // or 'local' marker replaces it.
        const chanDd = el('dd');
        chanDd.append(el('span', { class: 'ucm-mono', text: fmtTrackChannel(info) }), loading.cloneNode(true));
        kv.append(el('div', {}, el('dt', { text: 'Track/Channel' }), chanDd));
        // Publisher (round 47e): the terminal's green check / yellow star —
        // publisherName()/publisherSpan() are SHARED with the store-results
        // Publisher column (round SEARCH-FIN), one badge idiom app-wide.
        const pub = info.publisher || {};
        const pubName = publisherName(pub, info);
        if (pubName)
            kv.append(el('div', {}, el('dt', { text: 'Publisher' }), el('dd', {}, publisherSpan(pub, pubName))));
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
        // round T-fix18: busy feedback for component install/remove - same
        // idiom as the snap Install / Remove / channel-Switch buttons
        // (rounds T-fix14/T-fix17). The label + spinner are dropped again in
        // the finally BEFORE the card re-render (which replaces the whole
        // row with a fresh button), so no spinner can survive on success or
        // error. NOTE the spinner uses the BUNDLE default theming here (the
        // button is a p-button--base, not colored): black on the light
        // theme, white on .is-dark - via the app.css rule that scopes the
        // T-fix14 white override to the brand/negative buttons only.
        if (btn) {
            btn.textContent = installed ? 'Removing\u2026' : 'Installing\u2026';
            btn.classList.add('is-processing');
            btn.insertAdjacentHTML('beforeend', ' <i class="p-icon--spinner u-animation--spin" aria-hidden="true"></i>');
        }
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
        finally {
            // round T-fix18: restore the button (the re-render below replaces
            // the row on success; on the error path the row stays, so the
            // Install/Remove label must come back for a retry).
            if (btn) {
                btn.textContent = installed ? 'Remove' : 'Install';
                btn.classList.remove('is-processing');
                const sp = btn.querySelector('.p-icon--spinner');
                if (sp) sp.remove();
            }
        }
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
        // round LASTCH: the store channels just landed — fill the 'Last
        // changed' row with the CURRENT channel's released-at (unknown
        // channel / local builds keep the '—' the row was built with).
        const lcRow = Array.from(bodyBox.querySelectorAll('.ucm-kv > div'))
            .find((d) => (d.querySelector('dt') || {}).textContent === 'Last changed');
        if (lcRow) lcRow.querySelector('dd').textContent = fmtDay(lastChangedFromMap(info, chanMap));
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
            // round T-fix17: busy feedback for the channel switch - a
            // switch is a REFRESH with the new channel, a potentially
            // long-running download. Same busy idiom as the snap Install /
            // Remove buttons (round T-fix14): the Vanilla .is-processing
            // class (opacity 1, overriding the .is-disabled dim), the label
            // swap, and the appended white spinning .p-icon--spinner
            // (.p-button--base + .p-button--brand both flip to a WHITE
            // glyph via the T-fix14 app.css rule - the bundle would draw
            // black on the orange button in light). Restored in finally
            // (the error path keeps the picker open, so the CTA comes
            // back armed for a retry).
            go.textContent = 'Switching\u2026';
            go.classList.add('is-processing');
            go.insertAdjacentHTML('beforeend', ' <i class="p-icon--spinner u-animation--spin" aria-hidden="true"></i>');
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
            } finally {
                // round T-fix17: restore the CTA even on the error path
                // (the picker stays open there - a retry must be possible).
                go.textContent = 'Switch to ' + target;
                go.classList.remove('is-processing');
                const sp = go.querySelector('.p-icon--spinner');
                if (sp) sp.remove();
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
        // BUGFIX (reset lockout): a System-page keymap change restarts the
        // console and the app RE-OPENS AUTHENTICATED - enterApp runs, NOT
        // loadSetupKeymap, so the in-memory "asked once" flag was never read
        // and sits at its fresh default (false) even though the persisted
        // keymap.conf is true. The reset wipe must therefore RE-READ the
        // persisted flag before applyAuthPayload -> exitApp decides the setup
        // step, or the device re-enters at STEP 1 (the keymap) with an empty
        // picker -> the "Loading the layouts" toast lockout. The flag read is
        // open pre-gate (safe here). A lock never goes stale (the flag was
        // read at boot), so only the reset (wipe) path re-reads it.
        try { state.keymapFlag = await core.keymaps.flag(); }
        catch (e) { /* the in-memory value stands (the reset continues) */ }
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

/* --------------------------- settings (local) ---------------------------- *
 * round 66: the Session card's "Inactivity lock" is a select. It is NOT
 * form-gated — changing it sends the preference immediately and it applies
 * LIVE (main re-arms the active session's watchdog and pushes the new
 * timeoutMs to the chip). */
async function loadSettings() {
    const sel = $('#lockTimeout');
    const themeSel = $('#theme');
    if (!sel && !themeSel) return;
    // round I: the Local pages card — render the entry list + reset the add form
    // to a clean "add" state on every view entry (a stale edit from a prior visit
    // must not persist across view switches).
    lpState.editing = null; lpResetForm(); lpSyncFormButtons(null); renderLocalPagesCard();
    try {
        const p = await core.auth.status();
        if (sel) {
            // an explicit null (off) must stick; only a missing field falls back.
            const t = (p && p.timeoutMs !== undefined) ? p.timeoutMs : state.timeoutMs;
            state.timeoutMs = t;
            sel.value = state.timeoutMs ? String(state.timeoutMs / 60000) : 'off';
            updateLockChrome();
            startSessionTick(); // sync the header chip to the pref (a persisted
                                // "off" must show "active", not a stale countdown)
        }
        // round B: the Theme select must reflect the APPLIED appearance when the
        // view is entered. On a fresh load the <select> shows its HTML default
        // ('light') even though the theme is already dark (applyAuthPayload
        // flipped <html>.is-dark at boot) — so read the pref from status and
        // correct the select. (The <html> class itself is synced on every push;
        // the SELECT is a control, so it needs the view-entry sync.)
        if (themeSel && p && p.appearance !== undefined) {
            state.appearance = p.appearance;
            // round C: the control is a switch — sync its CHECKED state (the
            // <html>.is-dark class itself is synced on every push via
            // applyAuthPayload; the switch is a control, so it needs the
            // view-entry sync to show the persisted value).
            themeSel.checked = (p.appearance === 'dark');
            syncThemeLabel(); // round D (I4): the value follows the applied appearance
        }
    } catch { /* keep the current value on read failure */ }
}
async function setLockTimeout(value) {
    const sel = $('#lockTimeout');
    if (!sel) return;
    // (a change event only fires for a REAL change — the select's value is
    // already `value` here — so no same-value guard is needed)
    sel.disabled = true;
    try {
        const p = await core.auth.setLockTimeout(value);
        // the returned payload (ms) is the truth; sync the select too.
        state.timeoutMs = p && p.ms != null ? p.ms : (value === 'off' ? null : Number(value) * 60000);
        sel.value = value;
        updateLockChrome();
        startSessionTick(); // the countdown (or "active") reflects the new timeout
    } catch (e) {
        toastErr(e);
    } finally {
        sel.disabled = false;
    }
}
/* round B: the Appearance card's Theme select. Like the lock timeout it is
 * NOT form-gated — a change sends immediately and applies LIVE: main
 * persists the pref and pushes the status, and applyAuthPayload flips
 * <html>.is-dark (the vanilla 4.x theme class). */
// round C: the Theme control is a p-switch toggle (off = light, on = dark),
// not a pulldown. The switch's checked state mirrors the appearance.
function themeSwitchChecked() {
    const sw = $('#theme');
    return sw ? !!sw.checked : false;
}
async function setAppearance(value) {
    const sw = $('#theme');
    if (!sw) return;
    // (a change event only fires for a REAL change — the switch's checked
    // state is already the new value here — so no same-value guard is needed)
    sw.disabled = true;
    try {
        const p = await core.settings.setAppearance(value);
        // the pushed status payload (real IPC or the QA mock) updates
        // state.appearance and flips <html>.is-dark via applyAuthPayload.
        // The switch's checked state is re-synced from state.appearance on
        // every load (loadSettings) — here we trust the change we just made.
        sw.checked = (p && p.value ? p.value : value) === 'dark';
        syncThemeLabel(); // round D (I4): the value follows the applied appearance
    } catch (e) {
        toastErr(e);
    } finally {
        sw.disabled = false;
    }
}

/* ------------------------------- wiring ---------------------------------- */


/* ============================= round I: local pages =============================
   Embed a snap's own localhost web UI as a page inside the console. The Settings
   "Local pages" card manages the list (name + URL); each entry becomes a
   sidebar entry (below a separator, only when the list is non-empty) whose view
   is a <webview> (the permanent sidebar stays visible — the guest never replaces
   the chrome). Only LOOPBACK URLs are allowed (http/https on localhost/127.0.0.1/
   ::1) — this is a privileged admin kiosk. The renderer computes the new list on
   add/edit/remove and sends the WHOLE thing to main.js (settings.setLocalPages);
   main.js validates every entry + uniqueness and persists; the result rides the
   auth status payload back through applyAuthPayload -> renderLocalPages().
   The <webview> element is created with the lowercase tag name (the HTML parser
   promotes it to the namespace-qualified webview); it is added to the DOM via a
   string-fragment insert (NOT document.createElement, which would not promote).
=============================================================================== */
const LP_HOSTS = ['localhost', '127.0.0.1', '::1'];
function lpValidUrl(url) {
    let u; try { u = new URL(url); } catch { return false; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    return LP_HOSTS.includes(host);
}
function lpValidName(name) { const n = String(name).trim(); return n.length >= 1 && n.length <= 40; }
// render the sidebar local-page entries (the separator + the links) AND the
// <webview> views (one per entry). Re-runs on every list change (the auth
// payload push) and once at enterApp (the first paint).
function renderLocalPages() {
    const nav = document.querySelector('.ucm-side .p-side-navigation__list');
    const main = $('#appShell .ucm-main');
    const settingsView = document.querySelector('#view-settings');
    if (!nav || !main || !settingsView) return;
    const pages = state.localPages || [];
    // --- sidebar: the separator shows ONLY when there is at least one entry.
    // The entries are appended at the END of the nav <ul> (below Settings); the
    // whole group is re-rendered on every list change (clear + append) so the
    // markup is always exactly the current list.
    nav.querySelectorAll(':scope > .ucm-lp-sepitem, :scope > .ucm-lp-entry').forEach((n) => n.remove());
    if (pages.length) {
        nav.append(
            el('li', { class: 'p-side-navigation__item ucm-lp-sepitem' },
                el('hr', { class: 'ucm-side__sep' })),
        );
        for (const e of pages) {
            nav.append(el('li', { class: 'p-side-navigation__item ucm-lp-entry' },
                el('a', {
                    class: 'p-side-navigation__link', href: '#' + e.id, 'data-view': e.id,
                    onclick: (ev) => { ev.preventDefault(); switchView(e.id); },
                }, el('span', { class: 'ucm-nav-label', text: e.name }))));
        }
    }
    // --- webview views: build one per entry, insert each before the settings
    //     view (so the sidebar + all static views keep their order). Reuse an
    //     existing #view-lp-N if its url matches (avoid a churn on re-render);
    //     otherwise replace it. A <webview> is a custom element that the browser
    //     upgrades; we create it via a fragment string so the parser promotes
    //     it to the right namespace (document.createElement('webview') on a
    //     non-customized tag would give an unknown element).
    const byId = {};
    main.querySelectorAll(':scope > .ucm-view[data-view^="lp-"]').forEach((v) => { byId[v.dataset.view] = v; v.remove(); });
    for (const e of pages) {
        const wv = document.createElement('webview');
        wv.setAttribute('src', e.url);
        wv.setAttribute('class', 'ucm-webview');
        // sandbox the guest (round I): no node, no host preload; the named
        // partition keeps its cookies separate from the host page AND is the
        // SCOPE the main-process self-signed-cert allowance applies to
        // (round J, localPagesAllowSelfSignedCert) — the guest's TLS policy
        // never leaks onto the kiosk's own contents.
        wv.setAttribute('partition', 'ucm-local-pages');
        const view = el('section', { class: 'ucm-view ucm-view--webview ucm-hidden', id: 'view-' + e.id, 'data-view': e.id });
        const wrap = el('div', { class: 'ucm-webview__wrap' });
        const fb = el('div', { class: 'ucm-webview__fallback ucm-hidden' },
            el('p', { class: 'ucm-webview__fb-title', text: 'Can\'t reach ' + e.name }),
            el('p', { class: 'ucm-webview__fb-url mono', text: e.url }),
            el('p', { class: 'ucm-webview__fb-hint', text: 'The page could not be loaded (the snap\'s web UI may be offline, the address changed, or its certificate was rejected).' }),
            el('button', { class: 'p-button ucm-webview__retry', type: 'button', text: 'Retry' }));
        wrap.append(fb, wv);
        view.append(wrap);
        // The webview's load lifecycle -> the unreachable fallback. A refused
        // connection fires did-fail-load (the real error) and, in Electron/Chromium,
        // a did-finish-load for the internal error page right after — so a plain
        // did-finish-load would hide the fallback immediately. Track whether the
        // current load attempt FAILED: reset on each start, set on a genuine
        // failure, and hide the fallback ONLY on a finish whose attempt didn't fail
        // (i.e. a real page loaded, e.g. after a successful Retry).
        let lpFailed = false;
        wv.addEventListener('did-start-loading', () => { lpFailed = false; });
        wv.addEventListener('did-fail-load', (ev) => {
            // ev.errorCode -3 = ERR_ABORTED (a navigation was replaced) — not a real
            // failure; only surface the fallback for a genuine load error.
            if (ev.errorCode === -3) return;
            lpFailed = true;
            fb.classList.remove('ucm-hidden');
            wv.classList.add('ucm-webview--down');
        });
        wv.addEventListener('did-finish-load', () => {
            if (lpFailed) return; // the "finished" load was a failed attempt's error page
            fb.classList.add('ucm-hidden');
            wv.classList.remove('ucm-webview--down');
        });
        fb.querySelector('.ucm-webview__retry').addEventListener('click', () => {
            fb.classList.add('ucm-hidden');
            try { wv.reload(); } catch (_) { try { wv.loadURL(e.url); } catch (__) {} }
        });
        main.insertBefore(view, settingsView);
    }
    // keep the Settings card's entry list in sync with the sidebar + views.
    renderLocalPagesCard();
}
// clear the local-pages form errors + fields (used by add/cancel/save).
function lpResetForm() {
    setFieldState('lpNameGroup', ''); setFieldState('lpUrlGroup', '');
    const n = $('#lpName'), u = $('#lpUrl');
    if (n) n.value = ''; if (u) u.value = '';
}
function lpSyncFormButtons(editing) {
    $('#lpAddBtn').classList.toggle('ucm-hidden', !!editing);
    $('#lpSaveBtn').classList.toggle('ucm-hidden', !editing);
    $('#lpCancelBtn').classList.toggle('ucm-hidden', !editing);
}
// submit the ADD or EDIT. `editing` = the entry id being edited, or null for add.
async function lpSubmit(editing) {
    const name = ($('#lpName') && $('#lpName').value || '').trim();
    const url = ($('#lpUrl') && $('#lpUrl').value || '').trim();
    let bad = false;
    if (!lpValidName(name)) { setFieldState('lpNameGroup', 'error', editing ? 'Enter a name (1–40 characters).' : 'Enter a name for this page.'); bad = true; }
    else setFieldState('lpNameGroup', '');
    if (!lpValidUrl(url)) { setFieldState('lpUrlGroup', 'error', 'Only a localhost address (http:// or https:// on localhost, 127.0.0.1 or ::1).'); bad = true; }
    else setFieldState('lpUrlGroup', '');
    if (bad) return;
    const pages = (state.localPages || []).slice();
    if (editing) {
        const i = pages.findIndex((e) => e.id === editing);
        if (i >= 0) pages[i] = { ...pages[i], name, url };
    } else {
        pages.push({ name, url });
    }
    // duplicate name?
    const lower = {};
    for (const e of pages) { const k = e.name.toLowerCase(); if (lower[k]) { setFieldState('lpNameGroup', 'error', 'That name is already used.'); return; } lower[k] = 1; }
    const btn = editing ? $('#lpSaveBtn') : $('#lpAddBtn');
    if (btn) btn.classList.add('is-disabled');
    try {
        const p = await core.settings.setLocalPages(pages.map((e) => ({ name: e.name, url: e.url })));
        lpResetForm(); lpSyncFormButtons(null);
        // the pushed status re-renders the sidebar + views.
    } catch (e) {
        toastErr(e);
    } finally {
        if (btn) btn.classList.remove('is-disabled');
    }
}
// start editing an existing entry (prefill + swap buttons).
function lpStartEdit(e) {
    $('#lpName').value = e.name;
    $('#lpUrl').value = e.url;
    lpState.editing = e.id;
    lpSyncFormButtons(e.id);
    renderLocalPagesCard(); // highlight the row being edited
    const n = $('#lpName'); if (n) { n.focus(); n.select && n.select(); }
}
function lpCancel() { lpState.editing = null; lpResetForm(); lpSyncFormButtons(null); }
// round T (UI): removing a local page is destructive, so - like every other
// removal in the app (snap Remove/Disable, the config trash) - it is
// CONFIRM-GATED. The trash click opens the house inline .ucm-confirm row
// (the main-page idiom: question icon + message + Remove? + Cancel); the
// actual removal only happens on Remove?.
function lpAskRemove(e) {
    if (document.querySelector('#lpList .ucm-confirm')) return;
    const box = el('div', {
        class: 'ucm-confirm ucm-confirm--negative',
        style: 'margin-top:1rem; display:flex; align-items:center; gap:.7rem;',
    });
    const icon = el('i', { class: 'p-icon--question ucm-confirm__ic' });
    const msg = el('p', { class: 'p-notification__message ucm-confirm__msg', text: 'Remove page “' + e.name + '”? It disappears from the menu and is no longer embedded.' });
    const b = el('button', { class: 'p-button--negative p-button', type: 'button', text: 'Remove?' });
    b.onclick = () => { box.remove(); lpRemove(e); };
    const cancel = el('button', { class: 'p-button--base p-button', type: 'button', text: 'Cancel' });
    cancel.onclick = () => box.remove();
    box.append(icon, msg, b, cancel);
    const list = $('#lpList');
    list.append(box);
    b.focus();
}
function lpRemove(e) {
    const pages = (state.localPages || []).slice();
    const i = pages.findIndex((x) => x.id === e.id);
    if (i < 0) return;
    pages.splice(i, 1);
    if (lpState.editing === e.id) lpCancel();
    core.settings.setLocalPages(pages.map((x) => ({ name: x.name, url: x.url })))
        .then(() => { if (state.view === e.id) switchView('settings'); })
        .catch(toastErr);
}
const lpState = { editing: null };
// render the card's entry LIST (rows with edit/remove).
function renderLocalPagesCard() {
    const list = $('#lpList');
    if (!list) return;
    list.textContent = '';
    const pages = state.localPages || [];
    if (!pages.length) {
        list.append(el('p', { class: 'ucm-lp__empty', text: 'No local pages yet — add one below.' }));
        return;
    }
    for (const e of pages) {
        const row = el('div', { class: 'ucm-lp__row' + (lpState.editing === e.id ? ' is-editing' : ''), 'data-id': e.id });
        const name = el('div', { class: 'ucm-lp__name', text: e.name });
        const url = el('div', { class: 'ucm-lp__url mono', text: e.url });
        const edit = el('button', {
            class: 'p-button--base p-button ucm-iconbtn p-tooltip--top-right', type: 'button',
            'aria-label': 'Edit ' + e.name, 'data-tooltip': 'Edit', title: 'Edit',
        }, el('i', { class: 'p-icon--edit' }));
        edit.addEventListener('click', () => lpStartEdit(e));
        const del = el('button', {
            class: 'p-button--base p-button ucm-iconbtn p-tooltip--top-right', type: 'button',
            'aria-label': 'Remove ' + e.name, 'data-tooltip': 'Remove', title: 'Remove',
        }, el('i', { class: 'p-icon--delete' }));
        del.addEventListener('click', () => lpAskRemove(e));
        const meta = el('div', { class: 'ucm-lp__meta' }, name, url);
        const acts = el('div', { class: 'ucm-lp__acts' }, edit, del);
        row.append(meta, acts);
        list.append(row);
    }
}
// (re)render the card list — called from loadSettings + after each edit.
function renderLocalPagesAll() { renderLocalPagesCard(); }

/* ==========================================================================
 * round L: the SYSTEM page — journal + refresh schedule + power
 * ========================================================================== */

const SYS_JOURNAL_PRIOS = [
    ['all', 'All'], ['info', 'Info +'], ['notice', 'Notice +'], ['warning', 'Warning +'], ['err', 'Errors only'],
];

function sysSetFieldErr(inp, msgEl, text) {
    const group = inp && inp.closest('.p-form__group');
    // The refresh/schedule rows are NOT p-form__groups (the card uses plain
    // divs) — toggle an is-error class on the input itself + set the message.
    if (inp) inp.classList.toggle('is-error', !!text);
    if (msgEl) msgEl.textContent = text || '';
}

function clockMin(d) {
    // 'HH:MM' 24-hour local time — the permanent topbar idiom (mono, compact;
    // no seconds — the topbar is orientation; round T-fix11 removed the
    // Time card's "Current time" line, so the topbar is the only displayed
    // wall clock). round T-fix9.
    const p = (x) => String(x).padStart(2, '0');
    return p(d.getHours()) + ':' + p(d.getMinutes());
}
let __clockTimer = null;
// round-T-fix8: the topbar clock is PERMANENT (the show-clock toggle + pref +
// IPC + status-payload field are removed — bug 3). It always shows and updates
// every second (the same one-second textContent writer the session chip already
// runs in this topbar, which has never caused the desync). No show/hide
// transition, no payload push, no toggle.
function updateTopbarClock() {
    const el = $('#topbarClock');
    if (!el) return;
    el.textContent = clockMin(new Date());
}
function startTopbarClock() {
    if (__clockTimer) return;
    updateTopbarClock();
    __clockTimer = setInterval(updateTopbarClock, 1000);
}
async function loadSystem() {
    // Refresh schedule (core config; the shape-robust read lives in main.js).
    const inp = $('#refreshInput'); const now = $('#refreshNow'); const msg = $('#refreshMsg');
    if (inp) inp.disabled = true;
    let rs = null;
    try { rs = await core.machine.refreshRead(); }
    catch (e) { toastErr(e); if (now) now.textContent = 'Not available yet'; }
    if (rs) {
        const v = rs.value == null ? '' : String(rs.value);
        if (now) now.textContent = v === '' ? 'Default (24/7, every 4 hours)' : v;
        if (inp) { inp.value = v; sysSetFieldErr(inp, msg, ''); }
        // A stored value snapd would REJECT (e.g. set by an older path) must
        // not silently show as current — flag it.
        if (now && v !== '' && rs.valid === false) now.textContent = v + '  (invalid — not applied by snapd)';
    }
    if (inp) inp.disabled = false;
    // Round S: the global auto-refresh HOLD. The switch + state line are synced
    // from the LIVE sysinfo read (main.js refreshHoldRead -> /v2/system-info
    // result.refresh.hold), NOT from a local var - so a hold set OUTSIDE the
    // app (the CLI, a snap) is reflected on re-entry. Non-empty = held.
    let rh = null;
    try { rh = await core.machine.refreshHoldRead(); }
    catch (e) { /* snapd unreachable - leave the row at its HTML default */ }
    syncRefreshHold(rh && rh.active ? true : false, rh && rh.hold);
    // Round JRN: the JOURNAL card's persistence toggle. One conf-doc read
    // (journalPersistentRead) for the stored core journal.persistent
    // (absent = false = the volatile default). The switch + state line are
    // synced from that read - NOT a local var - so a change made outside the
    // app (snap set core journal.persistent=...) is reflected on re-entry.
    let jp = null;
    try { jp = await core.machine.journalPersistentRead(); }
    catch (e) { /* snapd unreachable - leave the row at its HTML default */ }
    syncJournalPersistent(jp ? (jp.persistent === true || jp.persistent === 'true' || jp.persistent === 1) : false);
    // Power: the live scheduled shutdown from logind ("" + max usec = none).
    let psched = null;
    try { psched = await core.machine.powerScheduled(); }
    catch (e) { /* logind unreachable (plug not connected) — the card shows
                   nothing scheduled; the actions will toast the D-Bus error */ }
    state.scheduled = psched && psched.active ? { action: psched.action, usec: psched.usec } : null;
    renderScheduled();
    const when = $('#schedWhen');
    if (when && !when.value) {
        const t = new Date(Date.now() + 15 * 60000);
        t.setSeconds(0, 0);
        const pad = (x) => String(x).padStart(2, '0');
        when.value = t.getFullYear() + '-' + pad(t.getMonth() + 1) + '-' + pad(t.getDate())
            + 'T' + pad(t.getHours()) + ':' + pad(t.getMinutes());
    }
    // Round MEM: the MEMORY card (the System page's tmp + swap sizes). One
    // conf-doc read (memoryRead) for the stored core tmp.size + swap.size
    // (unset -> the default-state text). The picker reflects the stored value
    // (an exact preset, or Custom carrying the raw value). The RAM total for
    // the "50% of RAM" hint comes from state.host (the dashboard host stats —
    // no extra IPC).
    let md = null;
    try { md = await core.machine.memoryRead(); }
    catch (e) { /* snapd unreachable - leave the card at its HTML defaults */ }
    state.mem = md ? { tmp: md.tmp == null ? '' : String(md.tmp), swap: md.swap == null ? '' : String(md.swap) } : { tmp: '', swap: '' };
    syncMemCard(md || {});
    // Round T: the TIME card. One IPC reads the LIVE wall clock + timezone +
    // the NTP flag + the bundled zone list (main.js timeRead). The manual
    // set-time rows are gated by the NTP flag (the Network page's "Sync time
    // from internet" toggle drives the same property): sync ON = greyed out,
    // because a manual set would just be overwritten by the next sync.
    // (round T-fix11: the "Current time" display line was removed — the
    // topbar clock is the live time, the NTP note was redundant with the
    // card subtitle.)
    const timeInp = $('#timeSetInput'); const timeBtn = $('#timeSetBtn');
    const zoneSel = $('#timeZoneSelect'); const zoneBtn = $('#timeZoneApplyBtn');
    // round T-fix11: the "Current time" kvrow (with its redundant
    // "(time sync is on …)" note) was removed from the card — the topbar
    // clock carries the live time, and the NTP state is shown by the greyed
    // set-time row. tr.usec is still read (timeRead returns it) but no longer
    // displayed on this card.
    let tr = null;
    try { tr = await core.machine.timeRead(); }
    catch (e) { /* timedate1/bundled list unavailable — leave the rows at their HTML defaults */ }
    if (tr) {
        const ntpOn = tr.ntp === true;
        if (timeInp) {
            timeInp.disabled = ntpOn;
            if (!ntpOn) {
                const t = new Date(); t.setSeconds(0, 0);
                const pad = (x) => String(x).padStart(2, '0');
                timeInp.value = t.getFullYear() + '-' + pad(t.getMonth() + 1) + '-' + pad(t.getDate())
                    + 'T' + pad(t.getHours()) + ':' + pad(t.getMinutes());
            }
        }
        if (timeBtn) timeBtn.disabled = ntpOn;
        // the zone list: the real IANA list (bundled in build/data/timezones.json).
        // The timezone picker is NOT NTP-gated (a timezone is meaningful whether
        // or not time is synced) — it must be ENABLED whenever it has options.
        // (round-T-fix bug 2: the markup carried a permanent `disabled` and this
        // line never cleared it, so the pulldown was hard-locked to Etc/UTC.)
        if (zoneSel) {
            zoneSel.innerHTML = '';
            const zones = tr.zones || [];
            for (const z of zones) zoneSel.appendChild(new Option(z, z));
            zoneSel.value = (tr.zone && zones.includes(tr.zone)) ? tr.zone : (zones[0] || '');
            zoneSel.disabled = zones.length === 0; // only disabled if the list is empty
        }
        if (zoneBtn) zoneBtn.disabled = !zoneSel || !zoneSel.value;
    }
    // round T-KM4: the KEYBOARD card (post-setup layout change). One read
    // (list + current) populates the picker + the default (the applied
    // layout, or English (US) on a fresh device). The "asked once" flag is
    // NOT consulted - this is the post-setup path, open to any layout.
    await loadSystemKeymap();
}

/* ----------------------------- round MEM: memory card ------------------------
   The core tmp.size + swap.size options (snapd configcore, source-verified at
   @8d4d073). Client-side validation MIRRORS snapd's rules so the user is
   told BEFORE the IPC (the house rule; the daemon would 400 with a harder-to-
   read message otherwise):
     grammar (gadget/quantity/size.go SplitUnit): an INTEGER + optional B|M|G
       (bytes | MiB | GiB). NO decimals (digit-only prefix), NO % (the tmp
       validator has a TODO for it - not accepted), NO K/T.
     tmp:  '' (unset -> 50% of RAM, the tmpfs default) or size >= 16 MiB
       (0 parses = unlimited; the UI allows it in custom, does not preset it).
     swap: '' (unset -> no swap file, the fresh-Core state) or an INTEGER
       number of MEGABYTES (sz % 1MiB == 0; 0 = no swap).
   Writes ride the conf bridge (async change + waitChangeSettled, exactly
   like the refresh schedule); a field is written ONLY when it changed (the
   keymap no-op idiom), so a one-size change is one snapd change. '' clears
   the option (snapd drops empty-string scalars -> the default applies). */
const MEM_SIZE_RE = /^([0-9]+)([BMG])?$/;   // mirrors quantity.SplitUnit (integer + B|M|G)
function memToMiB(v) {
    const m = String(v).match(MEM_SIZE_RE);
    if (!m) return -1;
    const n = Number(m[1]);
    if (!Number.isSafeInteger(n)) return -1;
    const u = m[2] || 'B';
    if (u === 'M') return n;
    if (u === 'G') return n * 1024;
    return n / 1048576;                    // bytes -> (possibly fractional) MiB
}
function memTmpRuleOk(v) {
    if (v === '') return true;             // default (50% of RAM)
    const mb = memToMiB(v);
    return mb >= 0 && (mb === 0 || mb >= 16);  // snapd: 0 ok, <16MiB rejected
}
function memSwapRuleOk(v) {
    if (v === '') return true;             // default (no swap file)
    const mb = memToMiB(v);
    return mb >= 0 && Number.isInteger(mb); // snapd: integer MB (0 = no swap)
}
function memFmtBytes(v) {
    const mb = memToMiB(v);
    if (mb < 0) return String(v);
    if (mb >= 1024) { const g = mb / 1024; return (g % 1 === 0 ? g : g.toFixed(1)) + ' GB'; }
    return mb + ' MB';
}
function memSetRowErr(field, text) {
    const tmp = field === 'tmp';
    const c = $(tmp ? '#memTmpCustom' : '#memSwapCustom');
    const msg = $(tmp ? '#memTmpMsg' : '#memSwapMsg');
    sysSetFieldErr(c, msg, text);
}
function syncMemCard(rd) {
    // round MEM2: the "current value" display rows are gone (the pickers show
    // the chosen value), so this only syncs the two pickers + custom inputs
    // from the read (preset hit -> that option; else Custom carrying the value).
    const tmpSel = $('#memTmpSelect'); const swapSel = $('#memSwapSelect');
    if (!tmpSel || !swapSel) return;
    const tmpVal = rd.tmp == null ? '' : String(rd.tmp);
    const swapVal = rd.swap == null ? '' : String(rd.swap);
    const pick = (sel, c, val) => {
        const hit = Array.from(sel.options).some((o) => o.value === val);
        if (hit) { sel.value = val; if (c) { c.value = ''; c.hidden = true; } }
        else { sel.value = 'custom'; if (c) { c.value = val; c.hidden = false; } }
        if (c) c.classList.remove('is-error');
    };
    pick(tmpSel, $('#memTmpCustom'), tmpVal);
    pick(swapSel, $('#memSwapCustom'), swapVal);
    memSetRowErr('tmp', '');
    memSetRowErr('swap', '');
}
async function applyMemory() {
    const tmpSel = $('#memTmpSelect'); const swapSel = $('#memSwapSelect');
    if (!tmpSel || !swapSel) return;
    const sizeOf = (sel, c) => {
        if (sel.value !== 'custom') return { value: sel.value, error: null };
        const v = (c && c.value ? c.value : '').trim();
        if (!v) return { value: '', error: 'Enter a size, e.g. 512M or 2G' };
        if (!MEM_SIZE_RE.test(v)) return { value: '', error: 'Invalid size — an integer with an optional B, M or G unit (e.g. 512M, 3G)' };
        return { value: v, error: null };
    };
    const t = sizeOf(tmpSel, $('#memTmpCustom'));
    const sw = sizeOf(swapSel, $('#memSwapCustom'));
    let bad = false;
    if (t.error) { memSetRowErr('tmp', t.error); bad = true; }
    else if (!memTmpRuleOk(t.value)) { memSetRowErr('tmp', 'Must be at least 16 MB (0 means unlimited)'); bad = true; }
    else memSetRowErr('tmp', '');
    if (sw.error) { memSetRowErr('swap', sw.error); bad = true; }
    else if (!memSwapRuleOk(sw.value)) { memSetRowErr('swap', 'Must be a whole number of MB (integer with M or G, or 0)'); bad = true; }
    else memSetRowErr('swap', '');
    if (bad) return;
    const cur = state.mem || { tmp: '', swap: '' };
    const tmpChanged = String(cur.tmp) !== t.value;
    const swapChanged = String(cur.swap) !== sw.value;
    if (!tmpChanged && !swapChanged) {
        toast('info', 'No memory changes to apply', 'The current sizes match the selection.');
        return;
    }
    const btn = $('#memApplyBtn');
    if (btn) btn.disabled = true;
    let failed = null;
    try {
        if (tmpChanged) {
            const change = (await core.machine.memoryWrite('tmp', t.value)) || null;
            if (change && change.id != null) {
                const done = await waitChangeSettled(change);
                if (done && isChangeTerminal(done.status) && String(done.status).toLowerCase() !== 'done') failed = 'tmp';
            }
        }
        if (!failed && swapChanged) {
            const change = (await core.machine.memoryWrite('swap', sw.value)) || null;
            if (change && change.id != null) {
                const done = await waitChangeSettled(change);
                if (done && isChangeTerminal(done.status) && String(done.status).toLowerCase() !== 'done') failed = 'swap';
            }
        }
        if (failed) {
            toast('negative', 'Memory size not applied', (failed === 'tmp' ? 'The /tmp size' : 'The swap file size') + ' is unchanged — the previous value is still in effect.');
            const rd = await core.machine.memoryRead().catch(() => null);
            if (rd) syncMemCard(rd);
        } else {
            if (tmpChanged) toast('positive', 'tmp size updated', t.value === '' ? '/tmp is back to the default (half of RAM).' : (t.value === '0' ? '/tmp is now unlimited.' : '/tmp is now limited to ' + memFmtBytes(t.value) + '.'));
            if (swapChanged) toast('positive', 'swap size updated', (sw.value === '' || sw.value === '0') ? 'No swap file (the option is unset).' : 'A ' + memFmtBytes(sw.value) + ' swap file is now active.');
            state.mem = {
                tmp: tmpChanged ? t.value : String(cur.tmp),
                swap: swapChanged ? sw.value : String(cur.swap),
            };
            // reflect the LIVE persisted state on the card (the "current" lines
            // + the pickers): a success re-reads so the display is the truth
            // snapd actually stored (a write that settled Done == persisted).
            const rd2 = await core.machine.memoryRead().catch(() => null);
            syncMemCard(rd2 || state.mem);
        }
    } catch (e) { toastErr(e); }
    finally {
        if (btn) btn.disabled = false;
    }
}

async function doSetTime() {
    const inp = $('#timeSetInput'); const btn = $('#timeSetBtn');
    if (!inp || !inp.value) return;
    const local = new Date(inp.value).getTime();
    if (!Number.isFinite(local)) { toastErr(new Error('could not read the time from the field')); return; }
    btn.disabled = true;
    try {
        await core.machine.timeSet(Math.round((local - new Date().getTimezoneOffset() * 60000) * 1000)); // local -> UTC usec
        // round T-fix11: no more "Current time" line to update — the topbar
        // clock (1s interval) reflects the new wall time on its own.
        toast('positive', 'Time set', 'The system clock was set manually.');
    } catch (e) { toastErr(e); }
    finally { btn.disabled = false; }
}

async function doSetZone() {
    const sel = $('#timeZoneSelect'); const btn = $('#timeZoneApplyBtn'); const msg = $('#timeZoneMsg');
    if (!sel || !sel.value) return;
    const zone = sel.value;
    btn.disabled = true;
    let change = null;
    try {
        change = (await core.machine.timeZoneWrite(zone)) || null;
        toast('positive', 'Time zone updated', 'The device is now in ' + zone + '.');
    } catch (e) { toastErr(e); }
    finally {
        btn.disabled = false;
        if (change) {
            const done = await waitChangeSettled(change);
            if (done && isChangeTerminal(done.status) && String(done.status).toLowerCase() !== 'done') {
                toast('negative', 'Time zone not applied', 'The previous time zone is still in effect.');
            }
        }
    }
}

/* round T-KM4: the System-page KEYBOARD card (the post-setup layout change).
   Reuses the first-boot IPC + the top-level #keymapRestart overlay. NOT
   gated by the "asked once" flag (that gates first-boot only). A real change
   returns {id} and shows the overlay (the app reopens; do NOT await settle);
   a no-op (the applied layout, or US on a fresh device) returns {} and just
   toasts. A rejected id (unknown to the frame hook) surfaces inline. */
function toggleKeymapCardWarn() {
    const sel = $('#keymapSelect'); const warn = $('#keymapWarn');
    if (!sel || !warn) return;
    warn.classList.toggle('ucm-hidden', keymapNoOp(sel.value, state.keymapCurrent));
}

async function loadSystemKeymap() {
    const sel = $('#keymapSelect'); const btn = $('#keymapApplyBtn');
    const msg = $('#keymapMsg');
    if (!sel) return;
    if (btn) btn.disabled = true;
    sel.innerHTML = '';
    try {
        const [list, cur] = await Promise.all([core.keymaps.list(), core.keymaps.current()]);
        const entries = Array.isArray(list) ? list : [];
        state.keymapList = entries;
        state.keymapCurrent = cur || null;
        for (const e of entries) sel.appendChild(new Option(e.label, e.id));
        // Show the applied layout; a fresh device (null) defaults to English
        // (US) - the same fresh-device behavior as the first-boot picker.
        let def = (state.keymapCurrent && entries.some((x) => x.id === state.keymapCurrent)) ? state.keymapCurrent : 'us';
        if (!entries.some((x) => x.id === def)) def = entries[0] ? entries[0].id : '';
        sel.value = def;
        sel.disabled = entries.length === 0;
        if (btn) btn.disabled = !sel.value;
        toggleKeymapCardWarn();
    } catch (e) {
        sysSetFieldErr(sel, msg, e.message);
        if (btn) btn.disabled = true;
    }
}

async function doApplySystemKeymap() {
    const sel = $('#keymapSelect'); const btn = $('#keymapApplyBtn'); const msg = $('#keymapMsg');
    const ov = $('#keymapRestart');
    if (!sel || !sel.value) return;
    if (ov && !ov.classList.contains('ucm-hidden')) return; // the restart owns the screen
    const id = sel.value;
    if (btn) {
        btn.classList.add('is-disabled', 'is-processing');
        btn.insertAdjacentHTML('beforeend', ' <i class="p-icon--spinner u-animation--spin" aria-hidden="true"></i>');
    }
    try {
        const r = await core.keymaps.apply(id);
        if (r && r.id) {
            // A real write: the console is restarting. The overlay stays up;
            // on the real device the app dies with the session and reopens
            // (the card repopulates with the settled layout). Do NOT await
            // the change settling.
            if (ov) ov.classList.remove('ucm-hidden');
        } else {
            // No-op pick (the applied layout, or US on a fresh device): no
            // write, no restart - confirm it is already in place.
            toast('positive', 'Keyboard layout', 'The layout is already in place.');
        }
        sysSetFieldErr(null, msg, '');
        toggleKeymapCardWarn();
    } catch (e) {
        // A rejected id (the frame hook does not know it) - surface inline.
        sysSetFieldErr(sel, msg, e.message);
    } finally {
        if (btn) {
            btn.classList.remove('is-disabled', 'is-processing');
            const sp = btn.querySelector('.p-icon--spinner');
            if (sp) sp.remove();
        }
    }
}


function renderScheduled() {
    const row = $('#scheduledRow'); const msg = $('#scheduledMsg'); const btn = $('#scheduledCancelBtn');
    if (!row) return;
    const sc = state.scheduled;
    row.classList.toggle('ucm-hidden', !sc);
    if (sc) {
        const when = new Date(sc.usec / 1000);
        const verb = sc.action === 'reboot' ? 'Reboot' : 'Shut down';
        const dt = when.toLocaleString([], { dateStyle: 'medium', timeStyle: 'medium' });
        if (msg) msg.textContent = verb + ' is scheduled for ' + dt + '.';
        if (btn) btn.disabled = false;
    } else if (btn) { btn.disabled = true; }
}

async function doPower(action) {
    const label = action === 'reboot' ? 'Reboot' : 'Shut down';
    await core.machine.power(action);
    toast('positive', label + ' started', 'The system is now ' + (action === 'reboot' ? 'rebooting' : 'shutting down') + '.');
}

// The power confirm (a PAGE-level confirm — the single integrated row idiom,
// like confirmRemove/confirmDisable; the popup two-row layout is scoped to
// .ucm-modal in the CSS). STATIC verb button (round 48i): the message names
// the action, the button never repeats it. Esc cancels (the 48k document
// listener removes the topmost .ucm-confirm).
/* round RCV: the RECOVERY card (the `snap reboot` frontend, the last System
   card). 'Boot into recovery' (snap reboot --recover) uses the house
   PAGE-LEVEL confirm idiom (like confirmPower: the single integrated row;
   Esc cancels via the 48k document listener). 'Factory reset' (snap reboot
   --factory-reset) is DESTRUCTIVE, so it gets a real popup with a Yes/No
   RADIO selection (the user's explicit requirement): "No" is checked by
   default and the Confirm button stays DISABLED until "Yes" is selected —
   a stray Enter/click can never trigger the reset.
   The call is synchronous and the device reboots almost immediately after
   snapd accepts it, so on success (or a socket failure AFTER the request was
   sent — main.js recoveryBoot reports both as started) the full-screen
   NON-interactive overlay appears (the keymap-restart idiom): the user is
   told what is happening, and the app dies a moment later. A real snapd
   error (unsupported mode, degraded mode, dead socket) re-opens to a
   negative toast + no overlay. */
function showRecoveryOverlay(mode) {
    const o = $('#recoveryRestart');
    if (!o) return;
    const t = $('#recoveryRestartTitle');
    const n = $('#recoveryRestartNote');
    if (mode === 'factory-reset') {
        if (t) t.textContent = 'Factory reset in progress…';
        if (n) n.textContent = 'The system is wiping the data partition and will reboot as a fresh device in a moment.';
    } else {
        if (t) t.textContent = 'Rebooting into recovery mode…';
        if (n) n.textContent = 'The system is restarting — it will come back into recovery mode in a moment.';
    }
    o.classList.remove('ucm-hidden');
}
function confirmRecoveryBoot() {
    const host = document.querySelector('#view-system .col-12');
    if (!host) return;
    if (host.querySelector('.ucm-confirm')) return;
    const box = el('div', {
        class: 'ucm-confirm ucm-confirm--negative',
        style: 'margin-top:1rem; display:flex; align-items:center; gap:.7rem;',
    });
    const icon = el('i', { class: 'p-icon--question ucm-confirm__ic' });
    const msg = el('p', { class: 'p-notification__message ucm-confirm__msg', text: 'Reboot the system into recovery mode now?' });
    const b = el('button', { class: 'p-button--negative p-button', type: 'button', text: 'Reboot to recovery?' });
    b.onclick = async () => {
        b.classList.add('is-disabled');
        try {
            const r = (await core.machine.recovery('recover')) || {};
            if (r.started) {
                showRecoveryOverlay('recover');
                toast('positive', 'Reboot to recovery started', 'The system is restarting into recovery mode.');
            }
        } catch (e) {
            toastErr(e);
        } finally {
            box.remove();
        }
    };
    const cancel = el('button', { class: 'p-button--base p-button', type: 'button', text: 'Cancel' });
    cancel.onclick = () => box.remove();
    box.append(icon, msg, b, cancel);
    host.appendChild(box);
    b.focus();
}
function openFactoryResetModal() {
    if (document.querySelector('.ucm-modal')) return; // one modal at a time
    const box = el('div', { class: 'ucm-modal ucm-modal--factoryreset' });
    const onKey = (e) => { if (e.key === 'Escape') closeModal(); };
    const closeModal = () => {
        document.removeEventListener('keydown', onKey);
        box.remove();
    };
    const backdrop = el('div', { class: 'ucm-modal__backdrop', onclick: () => closeModal() });
    document.addEventListener('keydown', onKey);
    const inner = el('div', { class: 'ucm-modal__card' });
    const close = el('button', { class: 'p-button--base p-button', type: 'button', 'aria-label': 'Close', onclick: () => closeModal() },
        el('i', { class: 'p-icon--close ucm-info__close' }));
    inner.append(el('div', { class: 'ucm-modal__head' },
        el('p', { class: 'p-heading--5', text: 'Factory reset', style: 'margin:0;' }),
        close));
    const body = el('div', { class: 'ucm-modal__body' });
    body.append(
        el('p', { class: 'p-form-validation__message is-error', style: 'margin-bottom:1rem;', text: 'This erases ALL data, snaps, and settings on the device and reboots it as a fresh, pristine system. This cannot be undone.' }),
        el('p', { text: 'Proceed with the factory reset?', style: 'font-weight:600;' }),
    );
    const radioRow = el('div', { class: 'ucm-factoryreset__radios' });
    const mkRadio = (val, label, checked) => el('label', { class: 'p-radio' },
        el('input', { class: 'p-radio__input', type: 'radio', name: 'factoryResetChoice', value: val, id: val === 'yes' ? 'factoryResetYes' : 'factoryResetNo', checked: checked === true ? true : false }),
        el('span', { class: 'p-radio__label', text: label }));
    radioRow.append(mkRadio('no', 'No — keep the system as it is', true), mkRadio('yes', 'Yes — factory reset the device'));
    body.append(radioRow);
    // the action row is styled in app.css (.ucm-factoryreset__actions, round
    // RCV-UI: 34rem card + radios in a row + left-aligned confirm/cancel).
    const actions = el('div', { class: 'ucm-factoryreset__actions' });
    const cancelBtn = el('button', { class: 'p-button--base p-button', type: 'button', text: 'Cancel' });
    cancelBtn.onclick = () => closeModal();
    const confirmBtn = el('button', { class: 'p-button--negative p-button', type: 'button', text: 'Factory reset', disabled: true });
    confirmBtn.onclick = async () => {
        const yes = document.querySelector('input[name="factoryResetChoice"][value="yes"]');
        if (!yes || !yes.checked) return; // the radios are the gate
        confirmBtn.disabled = true;
        try {
            const r = (await core.machine.recovery('factory-reset')) || {};
            if (r.started) {
                box.remove();
                document.removeEventListener('keydown', onKey);
                showRecoveryOverlay('factory-reset');
                toast('positive', 'Factory reset started', 'The device is wiping and rebooting as a fresh system.');
            }
        } catch (e) {
            confirmBtn.disabled = false;
            toastErr(e);
        }
    };
    // the radios ENABLE the confirm only on an explicit "Yes" (the user's
    // explicit-confirmation requirement: No is the default and inert).
    radioRow.querySelectorAll('input[type=radio]').forEach((r) => {
        r.addEventListener('change', () => {
            confirmBtn.disabled = r.value !== 'yes' || !r.checked;
        });
    });
    actions.append(confirmBtn, cancelBtn);
    body.append(actions);
    inner.append(body);
    box.append(backdrop, inner);
    document.body.appendChild(box);
    close.focus();
}

function confirmPower(action) {
    const host = document.querySelector('#view-system .col-12');
    if (!host) return;
    if (host.querySelector('.ucm-confirm')) return;
    const verb = action === 'reboot' ? 'Reboot' : 'Shut down';
    const box = el('div', {
        class: 'ucm-confirm ucm-confirm--negative',
        style: 'margin-top:1rem; display:flex; align-items:center; gap:.7rem;',
    });
    const icon = el('i', { class: 'p-icon--question ucm-confirm__ic' });
    const msg = el('p', { class: 'p-notification__message ucm-confirm__msg', text: verb + ' the system now?' });
    const b = el('button', { class: 'p-button--negative p-button', type: 'button', text: verb + '?' });
    b.onclick = async () => {
        b.classList.add('is-disabled');
        try { await doPower(action); } catch (e) { toastErr(e); }
        finally { box.remove(); }
    };
    const cancel = el('button', { class: 'p-button--base p-button', type: 'button', text: 'Cancel' });
    cancel.onclick = () => box.remove();
    box.append(icon, msg, b, cancel);
    host.appendChild(box);
    b.focus();
}

function openJournalModal() {
    if (document.querySelector('.ucm-modal')) return; // one modal at a time
    let unsub = null;
    let following = false;
    let busy = false;
    const lines = [];            // chronological (the terminal order: oldest first, newest appended at the bottom)
    const box = el('div', { class: 'ucm-modal ucm-modal--journal' });
    const onKey = (e) => { if (e.key === 'Escape') stopFollow().then(closeModal); };
    const closeModal = () => {
        stopFollow();
        if (unsub) { try { unsub(); } catch { /* already gone */ } unsub = null; }
        document.removeEventListener('keydown', onKey);
        box.remove();
    };
    const backdrop = el('div', { class: 'ucm-modal__backdrop', onclick: () => closeModal() });
    document.addEventListener('keydown', onKey);

    const inner = el('div', { class: 'ucm-modal__card' });
    const close = el('button', { class: 'p-button--base p-button', type: 'button', 'aria-label': 'Close', onclick: () => closeModal() },
        el('i', { class: 'p-icon--close ucm-info__close' }));
    inner.append(el('div', { class: 'ucm-modal__head' },
        el('p', { class: 'p-heading--5', text: 'Journal', style: 'margin:0;' }),
        close));

    // --- the filter row (unit + match + priority + LINES + follow + refresh) --
    const filters = el('div', { class: 'ucm-journal__filters' });
    const unitInp = el('input', { class: 'p-form-validation__input', type: 'text', placeholder: 'unit (e.g. snapd)', 'aria-label': 'Filter by unit', spellcheck: 'false' });
    const matchInp = el('input', { class: 'p-form-validation__input', type: 'text', placeholder: 'match text (grep style)', 'aria-label': 'Match text', spellcheck: 'false' });
    const prioSel = el('select', { class: 'ucm-kv--select', 'aria-label': 'Minimum priority' });
    for (const [v, label] of SYS_JOURNAL_PRIOS) prioSel.append(el('option', { value: v, text: label }));
    // The number of entries to show (round O): DEFAULT 200 (a bounded, fast tail);
    // the user types a count for a bigger/smaller tail or CLEARS the field for
    // UNLIMITED = the FULL journal. A search / unit filter ALWAYS spans the whole
    // journal regardless of the count (reaching entries from long ago). main.js
    // clamps (0/junk -> 200, absurd > 100000 capped); null = unlimited.
    const linesInp = el('input', { class: 'p-form-validation__input ucm-journal__lines-input', type: 'number', min: '1', max: '100000', step: '1', value: '200', placeholder: 'all', 'aria-label': 'Number of lines (empty = all)', spellcheck: 'false' });
    const followBtn = el('button', { class: 'p-button--base p-button', type: 'button', text: 'Follow' });
    const refreshBtn = el('button', { class: 'p-button--base p-button', type: 'button', text: 'Refresh' });
    const statusLine = el('span', { class: 'ucm-journal__status ucm-muted', text: 'Loading…' });
    filters.append(unitInp, matchInp, prioSel, linesInp, refreshBtn, followBtn, statusLine);

    const pre = el('pre', { class: 'ucm-journal__lines' });
    // FOLLOW MODE: the pane stays pinned to the bottom while lines arrive (like a
    // terminal). The user SCROLLING UP un-sticks it AND STOPS the follow (round O
    // ask: 'if the user manually scrolls up the follow mode should be stopped').
    let autoStuck = true;
    pre.addEventListener('scroll', () => {
        const nearBottom = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 24;
        if (!nearBottom && autoStuck) autoStuck = false;
        else if (nearBottom) autoStuck = true;
        if (!nearBottom && following) stopFollow().then(() => setStatus('Stopped following'));
        // (round P: the same short message as the button-stop - the long
        // '(scrolled away from the tail)' suffix overflowed the nowrap status span's
        // line and the flex row wrapped to a second line = a jitter on every stop.)
    });
    const bodyBox = el('div', { class: 'ucm-modal__body' });
    bodyBox.append(filters, pre);
    inner.append(bodyBox);
    box.append(backdrop, inner);
    document.body.append(box);
    close.focus();

    const opts = () => ({
        unit: unitInp.value.trim(),
        match: matchInp.value.trim(),
        pri: prioSel.value === 'all' ? null : prioSel.value,
        // A unit / match / priority filter ALWAYS spans the WHOLE journal (round O:
        // the user must be able to find an entry from long ago, e.g. a first-boot
        // failure) - the count is ignored while a filter is active. With no filter,
        // the field's number = the N newest (a TAIL, default 200); an EMPTY field
        // = UNLIMITED = the full journal.
        lines: (unitInp.value.trim() || matchInp.value.trim() || prioSel.value !== 'all')
            ? null
            : (linesInp.value === '' ? null : parseInt(linesInp.value, 10) || 200),
    });
    const render = () => {
        pre.textContent = lines.length ? lines.join('\n') : '(no matching entries)';
        if (autoStuck) pre.scrollTop = pre.scrollHeight; // stay on the newest line
    };
    const setStatus = (t) => { if (statusLine) statusLine.textContent = t; };

    // Note (round O): a filter / 'all' read is an UNBOUNDED full-journal query -
    // journalctl streams the whole journal, so on a busy box the status shows
    // 'Loading…' longer than the 200-line tail does (main.js gives the unbounded
    // read a 60s budget, vs 8s for the bounded tail).
    const loadTail = async () => {
        if (busy) return;
        busy = true; setStatus('Loading…');
        try {
            const r = await core.machine.journalTail(opts());
            if (!r || r.ok === false) { setStatus('Could not read the journal: ' + (r ? r.error : '')); return; }
            lines.length = 0;
            for (const l of (r.lines || [])) lines.push(l); // terminal order (newest at the bottom)
            render();
            setStatus(lines.length + ' entries');
        } catch (e) { toastErr(e); setStatus('Could not read the journal'); }
        finally {
            // The error path above RETURNS early — without this, a failed
            // query (bad match expression, unknown unit) left the buttons
            // permanently inert until the modal was re-opened.
            busy = false;
        }
    };

    const stopFollow = async () => {
        if (!following) return;
        following = false;
        followBtn.textContent = 'Follow';
        // NO re-pin here: a BUTTON stop happens while autoStuck is still true (the pane
        // is already at the bottom), and a SCROLL-UP stop has un-sticked it - yanking the
        // user back to the bottom would undo the very gesture they made (round O).
        try { await core.machine.journalStop(); } catch { /* best effort */ }
    };

    // ONE journal-line subscription per modal (round Q): registered here ONCE and released
    // in closeModal. The old code registered a NEW onJournalLine on every follow start and
    // never released the previous one - main broadcasts each line to EVERY registered
    // listener, so after N stop/start cycles each line was rendered N+1 times (the
    // 'duplicated / triplicated follow' bug). The handler body is stable for the modal's
    // lifetime (append + re-render) and lines only arrive while a follow child is active,
    // so exactly one listener is all we need.
    unsub = core.machine.onJournalLine((line) => {
        lines.push(line); // the terminal appends at the bottom
        if (lines.length > 2000) lines.shift();
        if (autoStuck) pre.scrollTop = pre.scrollHeight; // follow the tail
        render();
    });
    followBtn.onclick = async () => {
        if (busy) return;
        if (following) { await stopFollow(); setStatus('Stopped following'); return; }
        following = true; followBtn.textContent = 'Stop';
        autoStuck = true; lines.length = 0; render(); pre.scrollTop = pre.scrollHeight;
        setStatus('Following…');
        try {
            await core.machine.journalFollow(opts());
        } catch {
            following = false; followBtn.textContent = 'Follow';
            setStatus('Could not start following');
            autoStuck = true;
            if (pre) pre.scrollTop = pre.scrollHeight;
        }
    };
    const reload = () => loadTail();
    refreshBtn.onclick = reload;
    linesInp.addEventListener('change', reload); // a new count (or 'all') re-reads
    // Enter in the filter inputs = reload (the affordance a text field gives).
    for (const f of [unitInp, matchInp]) {
        f.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); loadTail(); } });
    }
    prioSel.addEventListener('change', () => loadTail());

    loadTail(); // first fill (async; its own busy flag guards against re-entry)
}

/* Round S+2: the 'Refresh now' button - an IMMEDIATE store refresh of every
   installed snap (== `snap refresh` with no names; the REST equivalent is the
   multi-action POST /v2/snaps { action:'refresh' }). It triggers a real
   change that can take a while, so the button is disabled while the change is
   in flight and a hint line shows progress. Positive toast on start, negative
   on a rejected request or a FAILED change (the round-52 rule: state what
   happened, not the expected behaviour). */
async function doRefreshNow() {
    const btn = $('#refreshNowBtn'); const hint = $('#refreshNowHint');
    if (btn) btn.disabled = true;
    if (hint) hint.textContent = 'Refreshing…';
    let change = null;
    try {
        change = (await core.machine.refreshNow()) || null;
        toast('positive', 'Refresh started', 'snapd is now refreshing all installed snaps.');
    } catch (e) {
        if (btn) btn.disabled = false;
        if (hint) hint.textContent = '';
        toastErr(e);
        return;
    }
    const done = (change && change.id != null) ? await waitChangeSettled(change) : null;
    if (btn) btn.disabled = false;
    if (hint) hint.textContent = '';
    if (done && isChangeTerminal(done.status) && String(done.status).toLowerCase() !== 'done') {
        toast('negative', 'Refresh did not complete', 'The refresh change failed; try again.');
    }
}

// Round S: render the 'Pause auto-refresh' switch + state line from a LIVE read
// ({ active, hold }). POLARITY: ON (checked) = held (paused), OFF = running. The
// hold is a sysinfo refresh.hold string ('' = absent = no hold); any non-empty
// value is a held-until timestamp (a bare --hold arrives as a distant
// ~100-year time, e.g. a date in 2319) - so the state line is just Held/Not
// held; the held-until DATE is intentionally NOT shown (round S+2).
// ---- round P: the process control modal (top/htop-style) ---------------
// Opened from the little info icon in the DASHBOARD "System load" card
// (the user's ask: a top/htop-like process list, sortable by name / RAM /
// CPU, with the ability to stop a process). The data comes from
// core.machine.procs() (main.js reads /proc once per poll and returns an
// INSTANTANEOUS per-process CPU% by deltaing the aggregate jiffies between
// polls); stopping sends a signal through core.machine.kill (the
// process-control plug grants signal(send)+kill) and is CONFIRM-GATED,
// exactly like the power actions (destructive).
//
// The modal is a live VIEW: it auto-refreshes every 2 s while open
// (re-rendering in place: the table keeps its scroll position, the active
// sort persists, and the running poll is the ONLY thing that re-fills the
// rows). Sorting is a pure client-side comparator on the cached row set
// (name asc, CPU desc, RSS desc) - the house top/htop ordering.
// ---- round M: the Model assertion modal (the REST equivalent of `snap known
// model`) - opened from the little info icon on the dashboard "Model" card.
// Read-only: it re-reads the FULL model assertion through core.system.model()
// (main.js getModelAssertion -> GET /v2/assertions/model, parsed by
// parseModelAssertion) and lays out every top-level header as a house .ucm-kv
// row + the snaps: list as a house table. The Model card itself only surfaces a
// few fields (model/base/grade); the modal is the whole assertion (minus the
// opaque signature block, which snap known shows but is not useful in a UI).
function openModelModal() {
    if (document.querySelector('.ucm-modal')) return; // one modal at a time
    const box = el('div', { class: 'ucm-modal' });
    const onKey = (e) => { if (e.key === 'Escape') closeModal(); };
    const closeModal = () => { document.removeEventListener('keydown', onKey); box.remove(); };
    const backdrop = el('div', { class: 'ucm-modal__backdrop', onclick: () => closeModal() });
    document.addEventListener('keydown', onKey);

    const inner = el('div', { class: 'ucm-modal__card' });
    const close = el('button', { class: 'p-button--base p-button', type: 'button', 'aria-label': 'Close', onclick: () => closeModal() },
        el('i', { class: 'p-icon--close ucm-info__close' }));
    inner.append(el('div', { class: 'ucm-modal__head' },
        el('p', { class: 'p-heading--5', text: 'Model', style: 'margin:0;' }),
        close));
    const bodyBox = el('div', { class: 'ucm-modal__body ucm-info' });
    bodyBox.append(el('p', { class: 'ucm-muted', style: 'padding:1rem 0;', text: 'Loading model assertion\u2026' }));
    inner.append(bodyBox);
    box.append(backdrop, inner);
    document.body.append(box);
    close.focus();

    // The model's snaps: list -> a house table (Name / Type / Presence / Default
    // channel). mono on the identifier-like cells, a muted dash for an absent
    // field (presence is optional; type/channel are present on every entry).
    const snapsTable = (snaps) => {
        const table = el('table', { class: 'p-table ucm-ifaces-table ucm-model__snaps' });
        const theadRow = el('tr', {},
            el('th', { text: 'Name' }), el('th', { text: 'Type' }),
            el('th', { text: 'Presence' }), el('th', { text: 'Default channel' }));
        table.append(el('thead', {}, theadRow));
        const tbody = el('tbody');
        (snaps || []).forEach((e) => {
            tbody.append(el('tr', {},
                el('td', { class: 'ucm-mono', text: e.name || '\u2014' }),
                el('td', { class: 'ucm-mono', text: e.type || '\u2014' }),
                el('td', { text: e.presence || '\u2014' }),
                el('td', { class: 'ucm-mono', text: e['default-channel'] || '\u2014' })));
        });
        table.append(tbody);
        return table;
    };

    (async () => {
        let mod;
        try {
            mod = await core.system.model();
        } catch (e) {
            bodyBox.innerHTML = '';
            bodyBox.append(el('p', { class: 'p-status-label p-status-label--negative', text: 'Could not read the model assertion: ' + e.message }));
            return;
        }
        bodyBox.innerHTML = '';
        if (!mod || typeof mod !== 'object' || Object.keys(mod).length === 0) {
            bodyBox.append(el('p', { class: 'p-status-label p-status-label--negative', text: 'No model assertion returned by snapd.' }));
            return;
        }
        // Every top-level header EXCEPT the snaps: list -> a .ucm-kv row, in
        // assertion order (the raw field names, faithful to `snap known model`).
        const kv = el('dl', { class: 'ucm-kv ucm-model__kv' });
        Object.keys(mod).forEach((k) => {
            if (k === 'snaps') return;
            const v = mod[k];
            if (v == null || v === '') return;
            kv.append(el('div', {},
                el('dt', { text: k }),
                el('dd', { class: 'ucm-mono', text: String(v) })));
        });
        if (kv.children.length) bodyBox.append(kv);
        // The snaps: list (the model's declared snaps).
        if (Array.isArray(mod.snaps) && mod.snaps.length) {
            bodyBox.append(el('p', { class: 'ucm-model__snaps-cap', text: 'Snaps (' + mod.snaps.length + ')' }));
            bodyBox.append(snapsTable(mod.snaps));
        }
        // the model identity, for context at the top of the modal
        if (mod.model) {
            bodyBox.prepend(el('p', { class: 'ucm-model__summary', text: 'Model ' + mod.model + (mod.base ? ' \u00b7 base ' + mod.base : '') + (mod.grade ? ' \u00b7 ' + mod.grade : '') }));
        }
        // The DEVICE SERIAL section (appended at the BOTTOM - user: "attach the
        // data, keep the popup as-is otherwise"). Read through core.system.serial()
        // (main.js getSerialAssertion -> GET /v2/assertions/serial, the REST
        // equivalent of `snap known serial`). A core device that has registered
        // with the store carries it; a classic box / a device that has not
        // registered resolves to {} (the daemon swallows the not-found into an
        // empty body) and the section is OMITTED (an empty caption would be
        // noise). Shown: the identity headers in raw field names (faithful to
        // `snap known serial`) - NOT the multi-line device-key and NOT the
        // signature block (the user does not need them in a UI; they stay in the
        // CLI). The empty-value guard also drops the parser's empty device-key.
        let ser;
        try { ser = await core.system.serial(); } catch { ser = null; }
        if (ser && typeof ser === 'object' && Object.keys(ser).length > 0) {
            const skv = el('dl', { class: 'ucm-kv ucm-model__serial-kv' });
            Object.keys(ser).forEach((k) => {
                if (k === 'snaps') return;
                const v = ser[k];
                if (v == null || v === '') return;
                skv.append(el('div', {},
                    el('dt', { text: k }),
                    el('dd', { class: 'ucm-mono', text: String(v) })));
            });
            if (skv.children.length) {
                bodyBox.append(el('p', { class: 'ucm-model__snaps-cap ucm-model__serial', text: 'Serial' }));
                bodyBox.append(skv);
            }
        }
    })();
}

function openProcessModal() {
    if (document.querySelector('.ucm-modal')) return; // one modal at a time
    let rows = [];
    let sortKey = 'cpu';
    let sortDir = -1;  // 1 asc, -1 desc - default CPU % DESC (most active on top)
    let poll = null;
    let busy = false;
    let closing = false;

    const box = el('div', { class: 'ucm-modal ucm-modal--procs' });
    const onKey = (e) => { if (e.key !== 'Escape') return; if (confirmSlot.querySelector('.ucm-confirm')) return; closeModal(); };
    const backdrop = el('div', { class: 'ucm-modal__backdrop', onclick: () => closeModal() });
    const inner = el('div', { class: 'ucm-modal__card' });
    const close = el('button', { class: 'p-button--base p-button', type: 'button', 'aria-label': 'Close', onclick: () => closeModal() },
        el('i', { class: 'p-icon--close ucm-info__close' }));
    inner.append(el('div', { class: 'ucm-modal__head' },
        el('p', { class: 'p-heading--5', text: 'Processes', style: 'margin:0;' }),
        close));

    // The toolbar: a short status line + the refresh cadence note. (No filter
    // field: a full /proc list is small on a Core box and the 3 sorts cover the
    // ask.)
    const status = el('span', { class: 'ucm-procs__status ucm-muted', text: 'Loading\u2026' });
    const toolbar = el('div', { class: 'ucm-procs__toolbar' },
        status,
        el('span', { class: 'ucm-procs__cadence ucm-muted', text: 'auto-refresh 2 s' }));

    const table = el('table', { class: 'p-table ucm-ifaces-table ucm-procs__table' });
    // the <colgroup> carries the column widths the FIXED table layout reads
    // (the rows re-render every 2 s poll; only the static thead + cols may
    // define geometry - see the .ucm-procs__table rule in app.css). The Name
    // col has NO width (CSS): it is the flexible filler, so the table's
    // minimum width is only the five fixed cols and a narrow window can never
    // overflow horizontally (round P3c).
    table.append(el('colgroup', {},
        el('col', { class: 'c-procs-pid' }),
        el('col', { class: 'c-procs-name' }),
        el('col', { class: 'c-procs-state' }),
        el('col', { class: 'c-procs-cpu' }),
        el('col', { class: 'c-procs-ram' }),
        el('col', { class: 'c-procs-act' })));
    const thead = el('thead');
    const headCols = [
        ['pid', 'PID', false],
        ['name', 'Name', true],
        ['state', 'State', false],
        ['cpu', 'CPU %', true],
        ['rss', 'RAM', true],
    ];
    const headRow = el('tr');
    for (const [key, label, sortable] of headCols) {
        const th = el('th', sortable ? {} : { class: 'ucm-procs__th--nosort' });
        if (sortable) {
            th.classList.add('ucm-procs__th');
            th.tabIndex = '0';
            th.setAttribute('role', 'button');
            th.title = 'Sort by ' + label;
            th.addEventListener('click', () => toggleSort(key));
            th.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleSort(key); } });
        }
        th.append(el('span', { class: 'ucm-procs__thlabel', text: label }));
        headRow.append(th);
    }
    // the Stop column header (right-aligned, not sortable)
    headRow.append(el('th', { class: 'ucm-procs__th--stop', text: 'Stop' }));
    thead.replaceChildren(headRow);

    const tbody = el('tbody');
    table.append(thead, tbody);
    const tableWrap = el('div', { class: 'ucm-procs__scroll' }, table);

    const confirmSlot = el('div', { class: 'ucm-procs__confirm' });
    const bodyBox = el('div', { class: 'ucm-modal__body ucm-modal__body--proc' });
    bodyBox.append(toolbar, tableWrap, confirmSlot);
    inner.append(bodyBox);
    box.append(backdrop, inner);

    const fmtCpu = (v) => (v == null ? '\u2014' : (Number.isInteger(v) ? String(v) : v.toFixed(1)));
    // State: /proc/<pid>/stat gives a single CODE LETTER (R/S/D/Z/T/...). A bare
    // letter is not self-explanatory to an operator, so the CELL shows a short
    // readable WORD (Running, Sleeping, ...) and the FULL meaning rides in a
    // legend - each cell's title (hover) + the column header's title (round
    // P: the user asked for readable states, or at least a legend - we do both).
    const PROC_STATE = {
        R: 'Running', S: 'Sleeping', D: 'Disk I/O', Z: 'Zombie', T: 'Stopped',
        t: 'Tracing', W: 'Out of swap', X: 'Dead', I: 'Idle',
    };
    const PROC_STATE_DESC = {
        R: 'Running or runnable (on a CPU)',
        S: 'Sleeping (waiting for an event or I/O)',
        D: 'Uninterruptible sleep (usually disk I/O)',
        Z: 'Zombie (exited; the parent has not reaped it)',
        T: 'Stopped (a SIGSTOP, or being debugged)',
        t: 'Tracing stop',
        W: 'Out of swap (legacy; now D or S)',
        X: 'Dead (should never be visible)',
        I: 'Idle (a kernel thread, or unused)',
    };
    const stateWord = (st) => PROC_STATE[st] || (st ? ('State ' + st) : 'Unknown');
    const stateDesc = (st) => (st && PROC_STATE_DESC[st]) ? (st + ' = ' + PROC_STATE_DESC[st]) : stateWord(st);
    const STATE_LEGEND = 'State: ' + Object.entries(PROC_STATE_DESC).map(([k, v]) => k + ' = ' + v).join('; ');

    const sortedRows = () => {
        const copy = rows.slice();
        copy.sort((a, b) => {
            let r = 0;
            if (sortKey === 'name') r = a.name.localeCompare(b.name);
            else if (sortKey === 'cpu') r = (a.cpu == null ? -1 : a.cpu) - (b.cpu == null ? -1 : b.cpu);
            else if (sortKey === 'rss') r = a.rss - b.rss;
            return r * sortDir || a.pid - b.pid; // stable: pid as the final tiebreak
        });
        return copy;
    };

    function paintSort() {
        const theadRow = table.querySelector('thead tr');
        if (!theadRow) return;
        theadRow.querySelectorAll('th').forEach((th) => th.classList.remove('is-sorted', 'is-sorted-desc'));
        const idx = headCols.findIndex((c) => c[0] === sortKey);
        if (idx >= 0) {
            const th = theadRow.children[idx];
            th.classList.add('is-sorted');
            if (sortDir < 0) th.classList.add('is-sorted-desc');
        }
    }

    function renderRows() {
        tbody.replaceChildren(...sortedRows().map((p) => {
            const row = el('tr', { dataset: { pid: String(p.pid) } });
            row.append(
                el('td', { class: 'ucm-mono', text: String(p.pid) }),
                el('td', { class: 'ucm-mono ucm-procs__name', text: p.name }),
                el('td', { class: 'ucm-procs__state', text: stateWord(p.state), title: stateDesc(p.state) }),
                el('td', { class: 'ucm-mono ucm-procs__cpu', text: fmtCpu(p.cpu) }),
                el('td', { class: 'ucm-mono', text: fmtBytes(p.rss) }),
            );
            // Icon-only X - the same suru-close button as the interface
            // disconnect (a column of "Stop" words is visually heavy). The
            // aria-label keeps the meaning; the title is the hover; the click
            // still opens the same confirm-gated SIGKILL flow.
            const stopBtn = el('button', {
                class: 'p-button--base p-button ucm-procs__stop ucm-iconbtn', type: 'button',
                'aria-label': 'Stop ' + p.name + ' (' + p.pid + ')',
                title: 'Stop ' + p.name + ' (' + p.pid + ')',
            }, el('i', { class: 'p-icon--window-close' }));
            stopBtn.addEventListener('click', () => stopProcess(p.pid, p.name));
            row.append(el('td', { class: 'ucm-procs__act' }, stopBtn));
            return row;
        }));
    }

    async function refresh() {
        if (closing) return;
        try {
            const data = await core.machine.procs();
            if (closing) return;
            rows = Array.isArray(data) ? data : [];
            status.textContent = rows.length + ' processes';
            renderRows();
        } catch (e) {
            if (closing) return;
            status.textContent = 'Cannot read processes: ' + ((e && e.message) || String(e));
        }
    }

    function toggleSort(key) {
        if (sortKey === key) sortDir *= -1;
        else { sortKey = key; sortDir = (key === 'name') ? 1 : -1; }
        paintSort();
        renderRows();
    }

    // In-modal confirm (the house idiom, round 48h): two-row layout appended to
    // this modal's own bodyBox - the .ucm-modal .ucm-confirm CSS owns it, so it
    // renders identically to the snap-info / config in-modal confirms. (There is
    // no global askConfirm; openConfigModal keeps a local one, so this is a
    // self-contained copy bound to THIS box.)
    function stopProcess(pid, name) {
        if (busy) return;
        if (confirmSlot.querySelector('.ucm-confirm')) return;
        const cbox = el('div', { class: 'ucm-confirm ucm-confirm--negative' });
        const b = el('button', { class: 'p-button--negative p-button', type: 'button', text: 'Stop?' });
        const cancel = el('button', { class: 'p-button--base p-button', type: 'button', text: 'Cancel' });
        b.onclick = async () => {
            b.classList.add('is-disabled');
            busy = true;
            try {
                await core.machine.kill(pid, 9);
                toast('positive', 'Process stopped', name + ' (pid ' + pid + ') sent SIGKILL');
                refresh();
            } catch (e) { toastErr(e); }
            finally { busy = false; cbox.remove(); }
        };
        cancel.onclick = () => cbox.remove();
        cbox.append(
            el('div', { class: 'ucm-confirm__row' },
                el('i', { class: 'p-icon--question ucm-confirm__ic' }),
                el('p', { class: 'p-notification__message ucm-confirm__msg', text: 'Stop ' + name + ' (pid ' + pid + ')? Sending SIGKILL terminates it immediately without cleanup.' })),
            el('div', { class: 'ucm-confirm__actions' }, b, cancel));
        confirmSlot.append(cbox);
        b.focus();
    }

    function closeModal() {
        closing = true;
        if (poll) { clearInterval(poll); poll = null; }
        document.removeEventListener('keydown', onKey);
        box.remove();
    }

    document.body.append(box);
    document.addEventListener('keydown', onKey);
    // the State column header carries the full legend (hover the header) -
    // set here (not at header-build time) so STATE_LEGEND is already initialised
    const stateTh = headRow.children[2];
    if (stateTh) stateTh.title = STATE_LEGEND;
    close.focus();
    paintSort();
    refresh();
    poll = setInterval(refresh, 2000);
}

/* round JRN: the JOURNAL card's persistence toggle (core journal.persistent).
   The switch is a p-switch (the .ucm-sys__holdrow idiom of the refresh card's
   Pause toggle). The state line reads "Volatile" (the fresh-Core default: the
   journal lives in memory and is cleared on reboot) or "Persistent on disk"
   (the journal is written to /var/log/journal and survives reboots). The write
   is 'true'|'false' (NEVER '' - an ON->OFF that sent '' would be a no-op and
   the switch would lie; snapd only removes the dir on an explicit false, and
   only if it created the dir itself - otherwise the change fails and the
   negative toast says so, the switch reverts to the re-read state). */
function syncJournalPersistent(on) {
    const sw = $('#journalPersistentSwitch'); const st = $('#journalPersistentState');
    if (sw) sw.checked = !!on;
    if (st) st.textContent = on ? 'Persistent on disk' : 'Volatile';
}
async function setJournalPersistent(on) {
    const sw = $('#journalPersistentSwitch');
    if (sw) sw.disabled = true;
    let change = null;
    try {
        change = (await core.machine.journalPersistentWrite(on ? 'true' : 'false')) || null;
    } catch (e) {
        if (sw) sw.disabled = false;
        toastErr(e);
        // revert the switch to the stored state (the write failed pre-bridge)
        const rr = await core.machine.journalPersistentRead().catch(() => null);
        syncJournalPersistent(rr ? (rr.persistent === true || rr.persistent === 'true' || rr.persistent === 1) : !on);
        return;
    }
    const done = (change && change.id != null) ? await waitChangeSettled(change) : null;
    if (sw) sw.disabled = false;
    if (done && isChangeTerminal(done.status) && String(done.status).toLowerCase() !== 'done') {
        // the change ran but FAILED - the classic case: OFF was requested but
        // snapd refuses to remove a /var/log/journal it did not create. The
        // switch reverts to the (re-read) state; the negative toast states what
        // happened (the round-52 rule), not the expected behaviour.
        toast('negative', 'Journal persistence not changed', 'snapd could not apply the change; the previous state is still in effect.');
        const rr = await core.machine.journalPersistentRead().catch(() => null);
        syncJournalPersistent(rr ? (rr.persistent === true || rr.persistent === 'true' || rr.persistent === 1) : !on);
        return;
    }
    // re-read so the switch + line reflect snapd - never a stale local value.
    let rr = null;
    try { rr = await core.machine.journalPersistentRead(); }
    catch (e) { /* fall back to the intended state if the read-back is unreachable */ }
    syncJournalPersistent(rr ? (rr.persistent === true || rr.persistent === 'true' || rr.persistent === 1) : on);
    if (on) toast('positive', 'Journal is now persistent', 'The system journal is written to disk and will survive reboots.');
    else toast('positive', 'Journal is now volatile', 'The system journal is kept in memory only and is cleared on reboot.');
}

function syncRefreshHold(active, hold) {
    const sw = $('#refreshHoldSwitch'); const st = $('#refreshHoldState');
    if (sw) sw.checked = !!active;
    if (st) st.textContent = active ? 'Held' : 'Not held';
}

// Round S: the toggle handler. Writes through the machine bridge (an async
// snapd change, settled like every other write), then RE-READS the live state so
// the switch + line reflect snapd - never a stale local value. Positive toast on
// success, negative on a rejected request or a FAILED change (the round-52 rule:
// the negative toast states what happened, not the expected behaviour).
async function setRefreshHold(on) {
    const sw = $('#refreshHoldSwitch');
    if (sw) sw.disabled = true;
    let change = null;
    try {
        change = (await core.machine.refreshHold(on)) || null;
    } catch (e) {
        if (sw) sw.disabled = false;
        toastErr(e);
        return;
    }
    const done = (change && change.id != null) ? await waitChangeSettled(change) : null;
    if (sw) sw.disabled = false;
    if (done && isChangeTerminal(done.status) && String(done.status).toLowerCase() !== 'done') {
        toast('negative', 'Auto-refresh hold not ' + (on ? 'set' : 'cleared'), 'The change did not complete; the previous state is still in effect.');
        return;
    }
    let rr = null;
    try { rr = await core.machine.refreshHoldRead(); }
    catch (e) { /* fall back to the intended state if the read-back is unreachable */ }
    syncRefreshHold(rr ? rr.active : on, rr && rr.hold);
    if (on) toast('positive', 'Auto-refresh paused', 'snapd holds every snap auto-refresh.');
    else toast('positive', 'Auto-refresh resumed', 'Auto-refresh runs on its normal schedule.');
}

async function applyRefreshSchedule() {
    const inp = $('#refreshInput'); const msg = $('#refreshMsg'); const btn = $('#refreshApplyBtn');
    if (!inp) return;
    const value = inp.value.trim();
    if (!validRefreshScheduleUi(value)) {
        sysSetFieldErr(inp, msg, 'Not a valid timer — e.g. 02:00-06:00 or mon-fri,09:00-17:00 (days + time window); separate schedules with ,,');
        return;
    }
    sysSetFieldErr(inp, msg, '');
    btn.disabled = true;
    let change = null;
    try {
        change = (await core.machine.refreshWrite(value)) || null;
        const now = $('#refreshNow');
        if (now) now.textContent = value === '' ? 'Default (24/7, every 4 hours)' : value;
        toast('positive', 'Refresh schedule updated', value === '' ? 'snapd now uses its default schedule.' : 'snapd now refreshes on this schedule.');
    } catch (e) { toastErr(e); }
    finally {
        btn.disabled = false;
        if (change) {
            const done = await waitChangeSettled(change);
            if (done && isChangeTerminal(done.status) && String(done.status).toLowerCase() !== 'done') {
                toast('negative', 'Refresh schedule not applied', 'The previous schedule is still in effect.');
            }
        }
    }
}

// round S+4: the STRUCTURED refresh timer (the actual snapd scheduling
// mechanism). Mirrors main.js validRefreshTimer (which mirrors snapd
// timeutil.ParseSchedule EXACTLY - verified against snapd's own ParseSchedule
// test table). The renderer must reject BEFORE the IPC (the house rule: UI
// validation first, snapd is the final authority). Grammar: a comma-separated
// list of event sets (sets join with ',,'); each set = [weekdays][,][time
// window]. Weekday: mon|tue|wed|thu|fri|sat|sun (+optional 1-5 = nth in
// month), a single day or a range (may wrap, e.g. fri-mon). Time: HH:MM,
// HH:MM-HH:MM (range), HH:MM~HH:MM (spread), any + /N (split). Hours 0-23
// (24:00 allowed), minutes 0-59.
const RE_SYS_CLOCK = /^([0-9]|0[0-9]|1[0-9]|2[0-3]):([0-5][0-9])$|^24:00$/;
const SYS_WEEKDAYS = { sun: 0, mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6 };
function sysClockOk(s) { return RE_SYS_CLOCK.test(s); }
function sysWeekday(s) {
    const l = s.length;
    if (l !== 3 && l !== 4) return null;
    const day = s.slice(0, 3);
    let pos = 0;
    if (l === 4) { const v = parseInt(s.slice(3), 10); if (isNaN(v) || v < 1 || v > 5) return null; pos = v; }
    if (!(day in SYS_WEEKDAYS)) return null;
    return { day, pos };
}
function sysWeekSpan(s) {
    const split = s.split('-');
    if (split.length > 2) return null;
    const start = sysWeekday(split[0]);
    if (!start) return null;
    let end = start;
    if (split.length === 2) { end = sysWeekday(split[1]); if (!end) return null; }
    if (start.pos !== 0 && end.pos !== 0 && end.pos < start.pos) return null; // mon5-mon1
    return true;
}
function sysClockSpan(s) {
    let rest = s;
    const ci = rest.indexOf('/');
    if (ci >= 0) {
        if (rest.indexOf('/', ci + 1) >= 0) return false;
        const countStr = rest.slice(ci + 1);
        const c = parseInt(countStr, 10);
        if (isNaN(c) || String(c) !== countStr || c === 0) return false;
        rest = rest.slice(0, ci);
    }
    const norm = rest.includes('~') ? rest.replace('~', '-') : rest;
    if (norm === '-') return false; // bare '-' / '~' are not a valid time (snapd rejects them)
    if (norm.includes('-')) {
        const parts = norm.split('-');
        if (parts.length !== 2) return false;
        return sysClockOk(parts[0]) && sysClockOk(parts[1]);
    }
    return sysClockOk(norm);
}
function sysEventSet(s) {
    const fragments = s.split(',');
    if (fragments.length === 1) {
        if (s.includes(':')) return sysClockSpan(s);
        return sysWeekSpan(s);
    }
    let expectTime = false;
    for (const frag of fragments) {
        if (frag.length === 0) return false;
        if (frag.includes(':')) { if (!sysClockSpan(frag)) return false; expectTime = true; }
        else if (!expectTime) { if (!sysWeekSpan(frag)) return false; }
        else { return false; }
    }
    return true;
}
function validRefreshScheduleUi(v) {
    if (typeof v !== 'string') return false;
    v = v.trim();
    if (v === '') return true; // empty = unset = the built-in default
    if (v === 'managed') return false; // reserved; not a timer value
    return v.split(',,').every((set) => sysEventSet(set));
}

async function schedulePower() {
    const action = ($('#schedAction') || {}).value || 'reboot';
    const when = $('#schedWhen'); const msg = $('#schedMsg');
    if (!when) return;
    const t = Date.parse(when.value);
    if (!Number.isFinite(t)) { sysSetFieldErr(when, msg, 'Pick a date and time.'); return; }
    const now = Date.now();
    if (t <= now) { sysSetFieldErr(when, msg, 'The time must be in the future.'); return; }
    if (t > now + 7 * 24 * 3600 * 1000) { sysSetFieldErr(when, msg, 'The most you can schedule is 7 days ahead.'); return; }
    sysSetFieldErr(when, msg, '');
    const btn = $('#schedBtn'); btn.disabled = true;
    try {
        const res = await core.machine.powerSchedule(action, t);
        state.scheduled = res && res.active ? { action: res.action, usec: res.usec } : null;
        renderScheduled();
        const verb = action === 'reboot' ? 'Reboot' : 'Shut down';
        toast('positive', verb + ' scheduled', new Date(t).toLocaleString([], { dateStyle: 'medium', timeStyle: 'medium' }) + ' — logins are blocked from 5 minutes before.');
    } catch (e) { toastErr(e); }
    finally { btn.disabled = false; }
}

async function cancelScheduled() {
    const btn = $('#scheduledCancelBtn'); if (btn) btn.disabled = true;
    try {
        await core.machine.powerCancelScheduled();
        state.scheduled = null;
        renderScheduled();
        toast('positive', 'Scheduled power action cancelled', '');
    } catch (e) { toastErr(e); }
    finally { if (btn) btn.disabled = false; }
}

function wire() {
    startTopbarClock();
    const netAdd = $('#netAddDevice');
    if (netAdd) netAdd.addEventListener('click', () => netAddBridge());

    // round T: the Time card (null-guarded — the house wire rule).
    const timeBtn = $('#timeSetBtn');
    if (timeBtn) timeBtn.addEventListener('click', () => doSetTime());
    const zoneBtn = $('#timeZoneApplyBtn');
    if (zoneBtn) zoneBtn.addEventListener('click', () => doSetZone());
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
    // round T: ESC dismisses the Local-pages form error. A rejected add/edit
    // (bad url / name) otherwise lingers until a view switch or a valid
    // re-submit; ESC clears it now. The house pattern (round-39 snaps-search
    // / round-60 netcard): document-level, scoped to the settings view, and it
    // YIELDS to any open .ucm-confirm / .ucm-modal (registered after the 48k
    // confirm handler, so a confirm closes on its own Esc first). A dismiss
    // clears the is-error state + message but KEEPS the typed values (a
    // dismiss is not a reset - the user keeps their draft).
    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape' || state.view !== 'settings') return;
        if (document.querySelector('.ucm-confirm') || document.querySelector('.ucm-modal')) return;
        const ng = $('#lpNameGroup'), ug = $('#lpUrlGroup');
        if (ng && ng.classList.contains('is-error')) setFieldState('lpNameGroup', '');
        if (ug && ug.classList.contains('is-error')) setFieldState('lpUrlGroup', '');
    });
    // local gate: first boot + login + lock
    // round KM part 2: the two-STEP first-boot flow. Step 1 = the keyboard
    // layout (its own form + button; a real change restarts the console via
    // the #keymapRestart overlay, a no-op advances to step 2). Step 2 = the
    // password, created once on the settled layout. The picker's change
    // shows/hides the inline restart warning (a no-op pick — the current
    // layout, or US on a fresh device — never warns).
    const kmSel = $('#setupKeymap');
    if (kmSel) kmSel.addEventListener('change', () => {
        if (!state.keymapError) toggleKeymapHelp();
    });
    $('#setupKeymapForm').addEventListener('submit', (e) => {
        e.preventDefault();
        doSetupKeymapSubmit();
    });
    $('#setupPasswordForm').addEventListener('submit', (e) => {
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

    // round I: the Local pages card form (add / save / cancel / remove).
    const lpAdd = $('#lpAddBtn'); if (lpAdd) lpAdd.addEventListener('click', () => lpSubmit(null));
    const lpSave = $('#lpSaveBtn'); if (lpSave) lpSave.addEventListener('click', () => lpSubmit(lpState.editing));
    const lpCancel = $('#lpCancelBtn'); if (lpCancel) lpCancel.addEventListener('click', () => lpCancel());
    // Enter in the URL field submits (add or save, depending on mode).
    const lpUrlIn = $('#lpUrl'); if (lpUrlIn) lpUrlIn.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); lpSubmit(lpState.editing); }
        if (e.key === 'Escape' && lpState.editing) { e.stopPropagation(); lpCancel(); }
    });
    const lpNameIn = $('#lpName'); if (lpNameIn) lpNameIn.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); lpUrlIn && lpUrlIn.focus(); }
    });

    // settings: the inactivity lock timeout (round 66) — applies live
    $('#lockTimeout').addEventListener('change', (e) => setLockTimeout(e.target.value));
    // settings: the theme (round C) — a p-switch toggle (off=light, on=dark),
    // applies live (the push flips <html>.is-dark).
    // Null-guarded: wire() runs once at boot; if the Appearance card is ever
    // absent the switch is null and the bare .addEventListener would throw and
    // abort the whole wire (a missing control must not take down unrelated
    // listeners).
    const themeSw = $('#theme');
    if (themeSw) themeSw.addEventListener('change', (e) => setAppearance(e.target.checked ? 'dark' : 'light'));

    // dashboard

    // snaps — the search field is a search ONLY: Enter runs the search, never
    // installs. Per-row Install buttons (in the results card) do the install.
    $('#snapSearchBtn').addEventListener('click', searchStore);
    $('#snapSearchName').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); searchStore(); }
    });
    // round T-fix15: ESC closes the store-results card from ANY focus, like
    // the other Esc handlers (the T-fix13 version was element-level on the
    // search field with stopPropagation, so it only fired while the field
    // was focused). Now a document-level, focus-independent handler that
    // yields to a topmost surface, using the same layered Esc idiom as the
    // modals (their document onKey) and the 48k confirm above: if a
    // .ucm-confirm is open the 48k handler owns this Esc (it calls
    // stopImmediatePropagation, and this handler is registered AFTER it);
    // if a .ucm-modal is open the modal's own document handler closes it
    // first and this guard defers; only when no confirm/modal is up AND
    // the card is visible does this Esc clear the store results (the same
    // action as the card's icon X, #snapSearchClear -> clearStoreResults).
    // A later Esc (after the confirm/modal closed) then closes the card -
    // layered, exactly like the rest of the app.
    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape') return;
        if (document.querySelector('.ucm-confirm')) return; // the 48k confirm owns this Esc
        if (document.querySelector('.ucm-modal')) return;  // an open modal owns this Esc
        if (state.view !== 'snaps') return;                 // views hide-don't-remove; the card is not topmost on another view
        const card = $('#snapSearchResults');
        if (card && !card.classList.contains('ucm-hidden')) clearStoreResults();
    });
    $('#snapSearchClear').addEventListener('click', clearStoreResults);

    // interfaces: no page-level Refresh (round 39) — the view
    // reloads on entry, like the dashboard cards reload on their 20 s poll.

    // ---- round L: the System page (journal / refresh / power) ------------
    // ---- round P: the dashboard process modal (the info icon on the
    // System load card) ------------
    const procInfo = $('#procInfoBtn');
    if (procInfo) procInfo.addEventListener('click', () => openProcessModal());
    // ---- round M: the dashboard Model assertion modal (the info icon on the
    // Model card) ------------
    const modelInfo = $('#modelInfoBtn');
    if (modelInfo) modelInfo.addEventListener('click', () => openModelModal());
    const jOpen = $('#journalOpenBtn');
    if (jOpen) jOpen.addEventListener('click', () => openJournalModal());
    // Round JRN: the Journal card's persistence toggle (null-guarded - the
    // house wire rule).
    const jPersist = $('#journalPersistentSwitch');
    if (jPersist) jPersist.addEventListener('change', () => setJournalPersistent(jPersist.checked));
    const rApply = $('#refreshApplyBtn');
    if (rApply) rApply.addEventListener('click', () => applyRefreshSchedule());
    const rHold = $('#refreshHoldSwitch');
    if (rHold) rHold.addEventListener('change', () => setRefreshHold(rHold.checked));
    const rNow = $('#refreshNowBtn');
    if (rNow) rNow.addEventListener('click', () => doRefreshNow());
    const rDefault = $('#refreshDefaultBtn');
    if (rDefault) rDefault.addEventListener('click', () => {
        const inp = $('#refreshInput'); const msg = $('#refreshMsg');
        if (inp) inp.value = '';
        sysSetFieldErr(inp, msg, '');
        applyRefreshSchedule();
    });
    // Round MEM: the Memory card (null-guarded — the house wire rule).
    const memApplyBtn = $('#memApplyBtn');
    if (memApplyBtn) memApplyBtn.addEventListener('click', () => applyMemory());
    for (const pair of [['#memTmpSelect', '#memTmpCustom'], ['#memSwapSelect', '#memSwapCustom']]) {
        const sel = $(pair[0]); const c = $(pair[1]);
        if (sel) sel.addEventListener('change', () => {
            if (c) { c.hidden = sel.value !== 'custom'; if (sel.value !== 'custom') c.value = ''; }
        });
    }
    const rebootBtn = $('#rebootNowBtn');
    if (rebootBtn) rebootBtn.addEventListener('click', () => {
        confirmPower('reboot');
    });
    const shutdownBtn = $('#shutdownNowBtn');
    if (shutdownBtn) shutdownBtn.addEventListener('click', () => {
        confirmPower('poweroff');
    });
    const schedBtn = $('#schedBtn');
    if (schedBtn) schedBtn.addEventListener('click', () => schedulePower());
    const cancelBtn = $('#scheduledCancelBtn');
    if (cancelBtn) cancelBtn.addEventListener('click', () => cancelScheduled());
    // Round RCV: the Recovery card (null-guarded — the house wire rule).
    const rcvBoot = $('#recoveryBootBtn');
    if (rcvBoot) rcvBoot.addEventListener('click', () => confirmRecoveryBoot());
    const factoryBtn = $('#factoryResetBtn');
    if (factoryBtn) factoryBtn.addEventListener('click', () => openFactoryResetModal());
    // round T-KM4: the System-page KEYBOARD card (post-setup layout change).
    const kmBtn = $('#keymapApplyBtn');
    if (kmBtn) kmBtn.addEventListener('click', () => doApplySystemKeymap());
    const kmSelC = $('#keymapSelect');
    if (kmSelC) kmSelC.addEventListener('change', () => toggleKeymapCardWarn()); // round T-KM4: a pick that != the current layout must show the restart warning (a no-op never warns)
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
    try {
        applyAuthPayload(await core.auth.status());
        if (state.authenticated) enterApp();
        else {
            showGate();
            // round KM: first boot (no local password yet) — load the
            // keyboard layouts so the picker is the first control. A real
            // frame restart RE-OPENS the app (this branch again), by which
            // point the applied layout is read back and the step is settled.
            if (!state.initialized) loadSetupKeymap();
        }
    } catch {
        showGate();
    }
});
