# Ubuntu Core Manager

Hardened **Electron kiosk** for managing an **Ubuntu Core** device from a
locked-down terminal. Built for `confinement: strict` snaps on top of an
`ubuntu-frame`-style Wayland compositor.

The UI is Canonical **Vanilla Framework** (compiled locally, CSP `self`), and
all privileged I/O happens in the main process over the **snapd Unix Domain
Socket** — never in the renderer, never via shell-outs or `/etc` writes.

```
ubuntu-core-manager/
├── main.js                     # Main process: kiosk window, snapd UDS client,
│                               #   volatile auth, 15-min inactivity watchdog
├── preload.js                  # Context-isolation bridge (frozen window.ucmCore)
├── ui/
│   ├── index.html              # Vanilla Framework SPA shell + login view
│   ├── app.js                  # Renderer controller (dashboard/network/snaps/interfaces)
│   └── app.css                 # Kiosk layout + aubergine theme over Vanilla
├── build/css/
│   └── vanilla-framework.css   # Compiled Vanilla 4.61 (local, 'self')
├── package.json
├── snap/snapcraft.yaml         # strict-confinement snap (snapd-control plug)
└── test/
    ├── stub-snapd.js           # snapd emulator over a UDS
    ├── run-integration.js      # 38-test socket + validation suite
    └── ui-screenshot.js        # headless QA (mock bridge + Puppeteer)
```

## Security model

| Layer | Control |
|---|---|
| **Window** | `kiosk`, `frame:false`, `fullscreen`, `alwaysOnTop`, no menu; `before-input-event` traps Alt+F4 / Ctrl+R / F5 / F11 / Ctrl+W / Alt+Tab; `blur` → forced refocus (anti workspace-switch) |
| **Renderer** | `contextIsolation:true`, `nodeIntegration:false`, `sandbox:true`, `devTools:false`; no popups/webviews/navigation; strict CSP injected via `onHeadersReceived` |
| **Bridge** | `preload.js` exposes only a frozen `window.ucmCore` of promise wrappers (NOT 'core': a global lexical of that name in app.js would SyntaxError the renderer) + one activity beacon + one status subscription. Channel names are constants; the renderer can never forge a channel or reach `ipcRenderer`/Node |
| **Auth** | **Two independent layers.** (a) *Local admin gate* = the UI lock screen: a device-local password set on first boot, stored **scrypt-hashed** (random salt, 0600) in `$SNAP_COMMON/admin.cred`, verified fully **offline** — this is what lets an operator get in and configure networking before any connectivity exists. (b) *Store auth* = optional `POST /v2/login` **macaroons**, cached in **volatile main-process memory only**, never persisted, never sent to the renderer. The renderer only ever sees status booleans + expiry |
| **Session** | 15-minute inactivity timer armed by mouse/keyboard IPC; on expiry the local session locks (and volatile store auth clears) and `auth-status-changed` drops the UI back to the sign-in screen |
| **Socket** | Node `http` over `socketPath:/run/snapd.socket` (via the `snapd-control` interface). No `child_process`, no fs writes |
| **Injection** | Every renderer value is re-validated in main by regex allow-lists (snap name, store channel, IPv4/IPv6 CIDR, interface name, config key, plug/slot ref) **before** it can reach the socket |

## snapd API surface used (verified against snapd source)

- `POST /v2/login`, `POST /v2/logout` — optional **store** macaroon auth
  (needs store-backend connectivity). Header format
  `Authorization: Macaroon root="…", discharge="…"` (single line, comma-separated).
  Note this is snapd's *store* login (Ubuntu One), deliberately NOT used as the
  UI gate — see the security table for the local admin password that is.
- `GET /v2/system-info`, `GET /v2/system-info/storage`, `GET /v2/changes`,
  `GET /v2/warnings` — monitoring.
- `GET /v2/snaps`, `GET /v2/snaps/{name}`, `POST /v2/snaps/{name}`
  (`install|refresh|remove|enable|disable|hold|unhold|revert|switch`),
  `GET /v2/find` — snap lifecycle.
- `GET|PUT /v2/snaps/{name}/conf` — per-snap configuration. **Netplan** is the
  external config key `core.system.network.netplan` (current snapd has no
  generic `/v2/config` route). The app reads the live document, rewrites one
  interface, and writes the full document back; snapd applies it atomically.
- `GET /v2/connections`, `POST /v2/interfaces` (`connect|disconnect`) —
  plug/slot control. Refs serialize as `{snap, plug}` / `{snap, slot}`.

## Build

```bash
# 1. Compile the local Vanilla asset (SCSS source, npm package ships no CSS)
git clone --depth 1 https://github.com/canonical/vanilla-framework /tmp/vf
cd /tmp/vf && npm i sass
npx sass --load-path=node_modules --style=compressed \
  --silence-deprecation=mixed-decls,import,global-builtin \
  scss/build.scss /path/to/ubuntu-core-manager/build/css/vanilla-framework.css

# 2. Run (dev) / test
npm start                     # needs Electron on PATH or `npx electron .`
npm test                      # socket + validation suite vs stub snapd
npm run test:ui               # headless UI QA (writes /root/shots/*.png)
```

## Deploying as a strict snap

`snap/snapcraft.yaml` uses the `snapd-control` plug (grants `rw` on
`/run/snapd.socket`) and runs Electron with `--no-sandbox` (required under
strict confinement). On the device, the interface must be connected:

```
snap connect ubuntu-core-manager:snapd-control
```

## Notes / tradeoffs

- **Vanilla & fonts are fully offline (no CDN at runtime):** Canonical does
  not publish a prebuilt `vanilla-framework.css` (the npm package is SCSS
  only), so the framework is compiled into the snap (`build/css/`, served
  `self`). Vanilla's `@font-face` rules normally reference
  `assets.ubuntu.com`; for the first-boot/no-network case the three Ubuntu
  font files are downloaded at build time and bundled under `build/fonts/`,
  and the compiled CSS is rewritten to relative local paths. The CSP is
  therefore pure `'self'` (plus `data:` for the inlined SVG icons), and the
  UI renders identically with the network cable unplugged.
- **Electron under strict:** Chromium needs `--no-sandbox` and a working X or
  Wayland surface; the app enforces kiosk focus behaviour itself so it does not
  depend on compositor-specific escape keys.
- **Auth is a local password, not the snapd store login:** the UI gate is a
  device-local admin password (scrypt, `$SNAP_COMMON`, offline) so first boot
  works with no network and no catch-22 ("can't log in to set up the network").
  snapd's `/v2/login` (Ubuntu One → store backend) is exposed separately as an
  optional "Connect to store" action for install/search; it is volatile and
  never required to enter the console. Reset of the local password is by design
  offline-privileged only (wipe `$SNAP_COMMON/admin.cred`); there is no
  network-based recovery path.
