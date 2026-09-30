# Desktop Application (Homelab RMM Console) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a native Windows desktop application (`Homelab-RMM.exe`) using pure-Go Microsoft Edge WebView2 bindings that hosts the Homelab RMM console in a standalone, dedicated window with minimize-to-tray capability, keeping the background server engine active for service continuity.

**Architecture:** A standalone Windows GUI executable (`cmd/rmm-desktop`) compiled with `-H windowsgui`. It detects or runs the server in the background, renders the console in a hardware-accelerated WebView2 Chromium window, and subclasses the Win32 window procedure to intercept `WM_CLOSE` (minimizing to the System Tray with a clean context menu: "Open Homelab RMM" and "Exit").

**Tech Stack:** Go 1.27, Windows Win32 API (`golang.org/x/sys/windows`, `shell32`, `user32`), `github.com/jchv/go-webview2`, Microsoft Edge WebView2 runtime.

**Spec:** [`docs/superpowers/specs/2026-09-22-desktop-app-design.md`](file:///C:/Users/temp/Desktop/agy/homelab-rmm/docs/superpowers/specs/2026-09-22-desktop-app-design.md)

## Global Constraints
- Keep all work strictly local; do NOT push to remote GitHub.
- Maintain `CGO_ENABLED=0` compatibility across the build.
- Preserve 24/7 background service continuity: closing or exiting the desktop app GUI must never terminate the background Windows service if installed.
- System tray context menu must contain ONLY:
  - "Open Homelab RMM"
  - Separator
  - "Exit"

---

### Task 1: Desktop Host & Server Coordination (`cmd/rmm-desktop/main.go`)

**Files:**
- Create: `cmd/rmm-desktop/main.go`
- Test: Compile and execute verification

- [ ] **Step 1: Write `cmd/rmm-desktop/main.go`**
  - Implement command line parsing (optional flags `--server-url`, `--data`).
  - Implement server coordination:
    - Probe `https://localhost:8443` (or configured URL) to see if an active server is listening.
    - If not responding, initialize the embedded `server.Server` instance in a background goroutine against the default data directory.
    - Wait up to 5 seconds for the server to report ready on the port.
  - Initialize the WebView2 instance using `github.com/jchv/go-webview2`:
    - Window title: "Homelab RMM"
    - Default dimensions: 1280 x 820
    - Navigate to `https://localhost:8443` (or target URL).

- [ ] **Step 2: Verify `cmd/rmm-desktop` builds**
  ```powershell
  go build -o rmm-desktop.exe ./cmd/rmm-desktop
  ```

---

### Task 2: Win32 Subclassing & System Tray Integration (`cmd/rmm-desktop/tray_windows.go`)

**Files:**
- Create: `cmd/rmm-desktop/tray_windows.go`
- Modify: `cmd/rmm-desktop/main.go`

- [ ] **Step 1: Implement Win32 System Tray & Window Interception**
  - Use `golang.org/x/sys/windows` and Win32 APIs:
    - `Shell_NotifyIconW` for tray icon management (`NIM_ADD`, `NIM_MODIFY`, `NIM_DELETE`).
    - `SetWindowLongPtrW` / `CallWindowProcW` for subclassing the WebView2 `HWND`.
    - Intercept `WM_CLOSE`: call `ShowWindow(hwnd, SW_HIDE)` to minimize to tray instead of destroying the window.
    - Intercept tray callback message (`WM_TRAYICON`):
      - `WM_LBUTTONUP` / `WM_LBUTTONDBLCLK`: call `ShowWindow(hwnd, SW_SHOW)`, `ShowWindow(hwnd, SW_RESTORE)`, `SetForegroundWindow(hwnd)`.
      - `WM_RBUTTONUP`: construct native popup menu using `CreatePopupMenu`, `AppendMenuW`:
        - Item 1001: "Open Homelab RMM"
        - Separator
        - Item 1002: "Exit"
      - Show menu with `TrackPopupMenuEx`.
      - On 1001: restore window.
      - On 1002: clean up tray icon, terminate WebView2, and exit process cleanly.

- [ ] **Step 2: Connect Tray to `main.go`**
  - Call tray setup during window initialization.
  - Set window icon using `WM_SETICON` with the application icon.

- [ ] **Step 3: Compile and test GUI interaction**
  ```powershell
  go build -ldflags "-H windowsgui" -o rmm-desktop.exe ./cmd/rmm-desktop
  ```

---

### Task 3: Build Script & Installer Packaging

**Files:**
- Modify: `tools/build.ps1`
- Modify: `installer/windows/rmm-server.wxs`

- [ ] **Step 1: Add `desktop` target to `tools/build.ps1`**
  - Add `desktop` target to build `Homelab-RMM.exe` into `dist/` with `-H windowsgui`.
  - Update `all` / package targets to include `Homelab-RMM.exe`.

- [ ] **Step 2: Update MSI Installer definition (`installer/windows/rmm-server.wxs`)**
  - Add `Homelab-RMM.exe` component into `INSTALLFOLDER`.
  - Update Start Menu and Desktop shortcuts to launch `[INSTALLFOLDER]Homelab-RMM.exe`.

---

### Task 4: Full Local Verification

- [ ] **Step 1: Run all project unit tests**
  ```powershell
  go test ./...
  ```

- [ ] **Step 2: Test desktop application launch and tray lifecycle**
  - Launch `rmm-desktop.exe`.
  - Verify window appears with console loaded.
  - Verify clicking "X" minimizes to tray.
  - Verify clicking tray icon restores window.
  - Verify right-click menu has only "Open Homelab RMM" and "Exit".
  - Verify clicking "Exit" closes the application cleanly.
