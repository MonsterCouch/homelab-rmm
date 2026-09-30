# Homelab RMM Desktop Application Design Specification

**Date:** 2026-09-22  
**Status:** Approved  
**Author:** Antigravity & User  

---

## 1. Executive Summary & Goals

Transform Homelab RMM from a browser-dependent tab workflow into a first-class, native Windows desktop application while preserving enterprise-grade 24/7 service continuity.

### Core Objectives
1. **First-Class Desktop Experience**: A dedicated application process (`Homelab RMM.exe`) that launches into a sleek, standalone window with its own taskbar identity, custom icon, and no browser URL bar or browser tabs.
2. **Enterprise Service Continuity (ScreenConnect / FortiClient Model)**: Separation between the 24/7 background Windows Service (`HomelabRMMServer`) and the graphical operator client (`Homelab RMM.exe`). Reboots and user logoffs never disrupt monitoring, alerting, or agent connections.
3. **Seamless Tray Integration**:
   - Clicking the window close button ("X") minimizes the application to the Windows System Tray rather than killing the process.
   - Clean tray context menu with only **Open Homelab RMM** and **Exit**.
   - Exiting the desktop GUI leaves the background server service running 24/7.
4. **Zero-CGO & Lightweight Footprint**: Utilizes pure Go Windows WebView2 bindings (`github.com/jchv/go-webview2`) powered by the Evergreen Microsoft Edge Chromium engine built into Windows 10/11. Zero CGO dependencies (`CGO_ENABLED=0`), generating a compact ~15MB native binary.

---

## 2. System Architecture

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │ 1. Windows Background Service ("HomelabRMMServer")                     │
 │    - Runs 24/7 under LocalSystem / Service Control Manager             │
 │    - Starts automatically at boot before user login                    │
 │    - Survives user logoffs, locked screens, and reboots                │
 │    - Binds HTTPS/WSS on port :8443                                     │
 │    - Manages SQLite database, background jobs, alerting, and scripts   │
 └──────────────────────────────────┬─────────────────────────────────────┘
                                    │ Localhost / LAN HTTPS & WSS
                                    ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ 2. Native Desktop Application ("Homelab RMM.exe")                      │
 │    - Binary: cmd/rmm-desktop/ (subsystem: windowsgui)                  │
 │    - Native Win32 Window with embedded Microsoft Edge WebView2         │
 │    - Intercepts WM_CLOSE to hide window to System Tray                 │
 │    - Shell_NotifyIconW tray icon with custom homelab-rmm.ico           │
 │    - Tray Menu: "Open Homelab RMM" | "Exit"                            │
 └────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Detailed Component Design

### 3.1 Desktop Client Entry Point (`cmd/rmm-desktop/main.go`)
- **Compilation**: Compiled with `-ldflags "-H windowsgui -s -w"` to ensure no black command prompt window flashes upon launch.
- **Icon Resource**: Embeds `installer/windows/homelab-rmm.ico` via Go syso / Windows resource.
- **Service Detection & Startup**:
  1. Probes `https://localhost:8443/api/auth/state` (or configured URL).
  2. If the service is running, connects directly.
  3. If not running:
     - Attempts to start the `HomelabRMMServer` service if registered.
     - Fallback: spins up the embedded `server.Server` engine in a background goroutine so the operator can always access the console even in a standalone/portable setup.
  4. Initializes the WebView2 window and navigates to the console.

### 3.2 WebView2 Window Configuration
- **Dimensions**: Default 1280x820, min size 960x600, resizable, centered on monitor.
- **DPI Awareness**: Per-Monitor V2 DPI awareness enabled.
- **Certificate Handling**: Configured with `--allow-insecure-localhost` / `--ignore-certificate-errors` to smoothly accept local self-signed certificates without browser error banners.
- **Local Data Isolation**: WebView2 user data stored in `%LocalAppData%\HomelabRMM\webview` to ensure clean separation from edge profiles.

### 3.3 System Tray & Window Lifecycle (`cmd/rmm-desktop/tray_windows.go`)
- **Window Subclassing**: Subclasses the top-level `HWND` using `SetWindowLongPtrW(hwnd, GWLP_WNDPROC, ...)`.
- **`WM_CLOSE` Interception**:
  - When the user clicks the "X" button, the window catches `WM_CLOSE`.
  - Calls `ShowWindow(hwnd, SW_HIDE)`.
  - Ensures the tray icon is active in the Windows notification area.
- **Tray Interactions**:
  - **Left Click / Double Click**: Calls `ShowWindow(hwnd, SW_SHOW)`, `ShowWindow(hwnd, SW_RESTORE)`, and `SetForegroundWindow(hwnd)`.
  - **Right Click**: Displays a native Win32 popup menu via `TrackPopupMenuEx`:
    - **Open Homelab RMM** (restores window)
    - *[Separator]*
    - **Exit** (terminates the desktop client; server service continues running).

### 3.4 Build System & Packaging
- **`tools/build.ps1`**:
  - Adds target `desktop`:
    ```powershell
    go build -ldflags "-s -w -H windowsgui -X $module/internal/server.Version=$Version" -o dist/Homelab-RMM.exe ./cmd/rmm-desktop
    ```
- **`installer/windows/rmm-server.wxs`**:
  - Installs `Homelab-RMM.exe` alongside `rmm-server.exe` into `C:\Program Files\HomelabRMM Server\`.
  - Updates Desktop and Start Menu shortcuts to point directly to `Homelab-RMM.exe`.

---

## 4. Verification & Testing Strategy
1. **Service Independence Test**: Verify that closing or exiting `Homelab RMM.exe` leaves the Windows Service running and endpoints continue to report metrics.
2. **Minimize to Tray Test**: Verify clicking "X" hides the window to the tray, and clicking the tray icon restores it.
3. **Exit Test**: Verify clicking "Exit" from the tray menu cleanly exits the GUI process without lingering processes.
4. **Local Verification**: Ensure all builds and tests pass with `CGO_ENABLED=0` without pushing to GitHub.
