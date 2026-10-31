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
    //                   storeAuthenticated, storeUsername }
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

    // ---- optional STORE login (snapd /v2/login; needs network) ------
    store: Object.freeze({
        login: invoke('store:login'),            // (email, password) => status
        logout: invoke('store:logout'),          // () => status
    }),

    // ---- system monitoring & management --------------------------------
    system: Object.freeze({
        info: invoke('sys:info'),               // { snapd, host, model, netdev, warnings }
        model: invoke('sys:model'),             // model assertion headers { model, base, grade, 'brand-id', ... }
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
        search: invoke('snaps:search'),         // (query, limit?) — store
        install: invoke('snaps:install'),       // (name, channel='stable') — store
        action: invoke('snaps:action'),         // (name, action, extra?)
        confGet: invoke('snaps:conf-get'),      // (name, key?)
        confSet: invoke('snaps:conf-set'),      // (name, {key: scalar})
    }),

    // ---- network configuration (via snapd netplan external config) -----
    network: Object.freeze({
        apply: invoke('net:apply'),
        // netcfg = { interface, mode:'dhcp4'|'static', ipv4?, ipv6?,
        //            gateway4?, gateway6?, dns? }
    }),

    // ---- plug/slot interface control ------------------------------------
    interfaces: Object.freeze({
        list: invoke('ifaces:list'),            // /v2/connections
        connect: invoke('ifaces:connect'),      // (plugRef, slotRef)
        disconnect: invoke('ifaces:disconnect'),// (plugRef, slotRef)
    }),

    // ---- misc ------------------------------------------------------------
    ping: () => Promise.resolve('pong'),
});

contextBridge.exposeInMainWorld('ucmCore', api);  // NOT 'core': a global property of a name colliding with a
// top-level lexical (const core) in a renderer script throws SyntaxError
// 'already declared' and blanks the whole UI (regression: VM white-screen, 2026-10-29).
