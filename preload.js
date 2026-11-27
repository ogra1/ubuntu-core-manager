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

/**
 * ============================================================================
 *  ubuntu-core-manager — preload.js
 *  Context-isolation bridge between the sandboxed renderer and the main
 *  process.
 *
 *  Guarantees:
 *   - Runs with contextIsolation: true and sandbox: true (see main.js).
 *     The renderer NEVER gets require/Node access; it only sees the
 *     frozen `window.core` API below.
 *   - This file exposes ONLY promise-returning call wrappers plus a
 *     one-way activity beacon and a single incoming event subscription.
 *     It never exposes: ipcRenderer itself, Node globals, file paths,
 *     or any credential material. The local password is verified against
 *     a scrypt hash in the main process and never persisted to the
 *     renderer; store macaroons live solely in the main process's
 *     volatile heap and cannot be read from here.
 *   - All channel names are constants; the renderer cannot choose or
 *     forge IPC channel names (no dynamic channel parameter).
 * ============================================================================
 */

const { contextBridge, ipcRenderer } = require('electron');

// One-way activity beacon (no response). Sent on any user input so the
// main process can keep its 15-minute inactivity watchdog armed.
const sendActivity = () => {
    try { ipcRenderer.send('session:activity'); } catch { /* noop */ }
};

// Debounce the beacon: coalescing input storms keeps IPC traffic minimal
// while still resetting the inactivity timer accurately.
let beaconScheduled = false;
const scheduleBeacon = () => {
    if (beaconScheduled) return;
    beaconScheduled = true;
    setTimeout(() => {
        beaconScheduled = false;
        sendActivity();
    }, 1000);
};

// Attach activity listeners to the global (page) object. The renderer is
// sandboxed, but window-level input events are available and trusted here.
window.addEventListener('mousemove', scheduleBeacon, { passive: true });
window.addEventListener('mousedown', scheduleBeacon, { passive: true });
window.addEventListener('keydown', scheduleBeacon, { passive: true });
window.addEventListener('wheel', scheduleBeacon, { passive: true });
window.addEventListener('touchstart', scheduleBeacon, { passive: true });
window.addEventListener('focus', scheduleBeacon, { passive: true });

/**
 * Wrap an invoke so that main-process { ok, result|error } envelopes
 * become native promises: resolve(result) / reject(Error(message)).
 * The renderer therefore can never observe transport-level details.
 */
const invoke = (channel) => (...args) =>
    new Promise((resolve, reject) => {
        ipcRenderer.invoke(channel, ...args).then((env) => {
            if (env && env.ok === true) resolve(env.result);
            else reject(new Error(env && env.error ? env.error : 'IPC call failed'));
        }, (err) => reject(err));
    });

const api = Object.freeze({
    // ---- local admin gate (the UI lock screen; fully offline) -------
    // status payload: { initialized, authenticated, expiresAt, timeoutMs,
    //                   appearance, storeAuthenticated, storeUsername }
    auth: Object.freeze({
        status: invoke('auth:status'),           // () => status
        create: invoke('auth:create'),           // (password) => status  (first boot only)
        login: invoke('auth:login'),             // (password) => status
        logout: invoke('auth:logout'),           // () => status
        // Console-privileged admin reset: re-confirms the current
        // password, then wipes the stored credential. Next launch is
        // first-boot setup again. (UI is currently hidden behind the
        // Settings view; the handler stays available for that path.)
        reset: invoke('auth:reset'),             // (password) => status
        // round 66: set the inactivity lock timeout ('5' | '10' | '15' |
        // '30' | '60' minutes, or 'off' = no auto-lock). Console-privileged.
        // Returns the lock-timeout payload { value, ms, allowed, default }.
        setLockTimeout: invoke('auth:set-lock-timeout'),  // (value) => {value,ms,allowed,default}
        // Subscribe to 'auth-status-changed' pushed by main on create,
        // login, logout, or 15-min inactivity lock. Callback receives the
        // status payload above only — never any credential material.
        onStatusChanged: (cb) => {
            const listener = (_e, payload) => {
                try { cb(payload); } catch { /* never break main push */ }
            };
            ipcRenderer.on('auth-status-changed', listener);
            return () => ipcRenderer.removeListener('auth-status-changed', listener);
        },
    }),

    // ---- appearance (light/dark theme; round A) --------------------
    // Console-privileged (auth-required) setting, persisted in $SNAP_COMMON
    // (no new snap plug). 'dark' -> the renderer adds <html>.is-dark (the
    // vanilla 4.x theme class; the vendored bundle already carries the
    // compiled dark token set). The current value also rides the auth
    // status payload (appearance).
    settings: Object.freeze({
        setAppearance: invoke('settings:set-appearance'),  // (value) => {value,allowed,default}
        // round I: local pages (embedded localhost web UIs). SET takes the whole
        // list (renderer computes add/edit/remove); the CURRENT list rides the
        // auth status payload (core.auth.status().localPages) — read-only here.
        setLocalPages: invoke('settings:set-local-pages'),  // (list) => {list,max}
    }),

    // ---- optional STORE login (snapd /v2/login; needs network) ------
    store: Object.freeze({
        login: invoke('store:login'),            // (email, password) => status
        logout: invoke('store:logout'),          // () => status
    }),

    // ---- system monitoring & management --------------------------------
    system: Object.freeze({
        info: invoke('sys:info'),               // { snapd, host, model, netdev, warnings }
        model: invoke('sys:model'),             // model assertion headers { model, base, grade, 'brand-id', ... }
        serial: invoke('sys:serial'),            // serial assertion headers { 'brand-id', model, serial, 'device-key-sha3-384', ... } or {} (no serial yet)
        dataDisk: invoke('sys:data-disk'),      // /run/mnt/data usage { mount, device, fsType, total/free/used/reservedBytes, usedPercent, source }
        cpu: invoke('sys:cpu'),                 // => number|null[] (oldest->newest, 0..100; null = pre-boot sample)
        net: invoke('sys:net'),                 // => { iface, series:{r,x}|null[] } — rates in KiB/s (in=down r, out=up x), counted iface = default-route
        changes: invoke('sys:changes'),         // (select?) => change list
        change: invoke('sys:change'),           // (id) => one change (status poll for write ops)
        netplan: invoke('sys:netplan'),         // active netplan doc (parsed)
    }),

    // ---- snaps ----------------------------------------------------------
    snaps: Object.freeze({
        list: invoke('snaps:list'),             // installed snaps
        info: invoke('snaps:info'),             // (name)
        search: invoke('snaps:search'),         // (query, limit?, mode?) — store; mode 'q' = FULL-TEXT (snap find), default = exact-name resolve (snap info)
        install: invoke('snaps:install'),       // (name, channel='stable') — store
        action: invoke('snaps:action'),         // (name, action, extra?)
        component: invoke('snaps:component'),   // (name, 'install'|'remove', component) — round 47m
        services: invoke('snaps:services'),     // (name) -> [{name, active?, enabled?, ...}]
        service: invoke('snaps:service'),       // (name, app|null, start|stop|restart, {enable?,disable?})
        confGet: invoke('snaps:conf-get'),      // (name, key?)
        confSet: invoke('snaps:conf-set'),      // (name, {key: scalar})
    }),

    // ---- network configuration (via snapd netplan external config) -----
    network: Object.freeze({
        // ---- network devices (round 53, network-control interface) ----
        // live state (ip/iw/resolvectl) merged with the netplan definitions
        devices: invoke('net:devices'),               // => [ { name, type, connected, addresses[], gateway, dns[], configured, netplan } ]
        applyDevice: invoke('net:apply-device'),      // (cfg) — one device's netplan entry, full-doc PUT
        clearSeed: invoke('net:clear-seed'),          // () -> 'removed'|'kept'|'absent' — delete the 00-snapd-config.yaml boilerplate
        // ---- ip forwarding (network-control interface, round 51) -------
        forwarding: Object.freeze({
            status: invoke('net:forwarding-status'), // => { v4, v6, on, pref } (null = unreadable)
            set: invoke('net:forwarding-set'),       // (boolean) — LIVE + persisted
        }),
    }),

    // ---- plug/slot interface control ------------------------------------
    interfaces: Object.freeze({
        list: invoke('ifaces:list'),            // /v2/connections
        connect: invoke('ifaces:connect'),      // (plugRef, slotRef)
        disconnect: invoke('ifaces:disconnect'),// (plugRef, slotRef)
    }),

    // ---- timesync / NTP (timeserver-control interface, D-Bus timedate1) ---
    timesync: Object.freeze({
        status: invoke('timesync:status'),          // { ntp:boolean|null, server:string|null }
        setEnabled: invoke('timesync:set-enabled'), // (boolean) — LIVE
        setServer: invoke('timesync:set-server'),   // (string) — applies after a timesyncd restart
    }),

    // ---- keyboard layout (round KM: ubuntu-frame external config) --------
    // list is open (the first-boot setup screen runs it pre-gate); apply is
    // console-privileged (see the keymaps:apply handler in main.js).
    keymaps: Object.freeze({
        list: invoke('keymaps:list'),          // => [{id, label}] (bundled, xkb-data 2.46)
        current: invoke('keymaps:current'),    // => id|null (null = fresh Core, none set)
        apply: invoke('keymaps:apply'),        // (id) => {change}|{} (async conf PUT; {} = already applied)
        flag: invoke('keymaps:flag'),          // => boolean (the "asked once" flag; part 3)
        setFlag: invoke('keymaps:set-flag'),   // () => true (persisted; set when the layout step completes)
    }),

    // ---- machine operations (round L: the System page) -------------------
    // Console-privileged. 'system' above is the system-INFO namespace; this
    // one is the system-OPERATIONS namespace (journal / refresh schedule /
    // power) so the two never collide.
    machine: Object.freeze({
        // Journal (the log-observe interface grants journalctl execution).
        journalTail: invoke('system:journal-tail'),      // ({unit?, match?, pri?, lines?}) -> { ok, lines[], error }
        journalFollow: invoke('system:journal-follow'),  // (opts) -> { started } — streams to onJournalLine
        journalStop: invoke('system:journal-stop'),      // -> { stopped }
        onJournalLine: (cb) => {
            const listener = (_e, line) => { try { cb(line); } catch { /* never break main push */ } };
            ipcRenderer.on('system:journal-line', listener);
            return () => ipcRenderer.removeListener('system:journal-line', listener);
        },
        // Snapd refresh schedule (core 'refresh.schedule' option; '' = default).
        refreshRead: invoke('system:refresh-read'),      // -> { value:string|null, valid:boolean }
        refreshWrite: invoke('system:refresh-write'),    // (value) -> async snapd change (wait + settle like other conf writes)
        // Round S: the global auto-refresh HOLD (the 'Pause auto-refresh'
        // toggle; the REST equivalent of `snap refresh --hold`). The read is
        // the LIVE sysinfo state (reflects a hold set OUTSIDE the app, e.g.
        // the CLI), the write is an async snapd change (waitChangeSettled in
        // the renderer, exactly like refreshWrite).
        refreshHoldRead: invoke('system:refresh-hold-read'), // -> { active:boolean, hold:string }
        refreshHold: invoke('system:refresh-hold'),          // (boolean) -> async snapd change (hold/unhold)
        // Round S+2: the 'Refresh now' button (== `snap refresh` all snaps). An
        // async snapd change (settle it like every other write).
        refreshNow: invoke('system:refresh-now'),             // () -> async snapd change (refresh all snaps)
        // Round MEM: the Memory card (core tmp.size + swap.size). The read is
        // the stored conf doc ({ tmp, swap }, each string|number|null — null =
        // unset = the default state: 50% of RAM / no swap file); the write is
        // an async snapd change (field 'tmp'|'swap', value a size string,
        // '' = unset -> the built-in default applies again).
        memoryRead: invoke('system:memory-read'),             // -> { tmp, swap }
        memoryWrite: invoke('system:memory-write'),           // (field, value) -> async snapd change
        // Round T: the Time card. timeRead = the LIVE wall clock +
        // timezone + NTP flag + the bundled zone list; timeSet is the
        // gated manual set (time-control plug, SetTime xbb); timeZoneWrite
        // is the core.system.timezone conf PUT (snapd runs timedatectl).
        timeRead: invoke('system:time-read'),          // () -> { usec, zone, ntp, zones[] }
        timeSet: invoke('system:time-set'),            // (usec-utc) -> { ok } (refused while NTP is ON)
        timeZoneWrite: invoke('system:timezone-write'),// (zone) -> async snapd change (wait + settle)
        // Power (org.freedesktop.login1 over D-Bus — the shutdown interface
        // is D-BUS ONLY; no shell-out).
        power: invoke('system:power'),                   // ('reboot'|'poweroff') — immediate
        powerSchedule: invoke('system:power-schedule'),  // (action, whenMs) — ScheduleShutdown (CLOCK_REALTIME usec)
        powerCancelScheduled: invoke('system:power-cancel-scheduled'), // -> { cancelled:boolean }
        powerScheduled: invoke('system:power-scheduled'), // -> { active, action, usec } ("" + max = none)
        // round P: the process modal (the `process-control` plug). procs is an
        // OPEN read (the table; one poll = one INSTANTANEOUS sample, cpu may be
        // null on the first sample); kill is console-privileged (the renderer
        // confirm-gates it) and takes (pid, sig) with sig a positive signal
        // number (9 = SIGKILL, 15 = SIGTERM, 18 = SIGCONT).
        procs: invoke('system:procs'),                 // -> [ { pid, name, state, ppid, rss, cpu } ]
        kill: invoke('system:proc-kill'),              // (pid, sig) -> { pid, sig }
    }),

    // ---- misc ------------------------------------------------------------
    ping: () => Promise.resolve('pong'),
});

contextBridge.exposeInMainWorld('ucmCore', api);  // NOT 'core': a global property of a name colliding with a
// top-level lexical (const core) in a renderer script throws SyntaxError
// 'already declared' and blanks the whole UI (regression: VM white-screen, 2026-10-29).
