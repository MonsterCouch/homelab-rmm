# Handoff

State of Homelab RMM as of 2026-09-16, written for whoever picks the project up on a
workstation. Everything below is true of `main` at `99e44f6`, which is 40 commits ahead of
`origin/main` and **deliberately not pushed** (the owner's free GitHub Actions minutes are
nearly spent; every push to `main` runs the full CI workflow). Released version is still
**v0.2.0**; everything since is in `CHANGELOG.md` under `[Unreleased]`.

## What exists

A self-hosted RMM for a home lab, in the spirit of NinjaOne's scripting, patching and
automation combined with ScreenConnect's remote desktop.

- **Server** (`cmd/rmm-server`, `internal/server`): one Go binary, SQLite (pure Go, no cgo),
  self-signed HTTPS with certificate pinning for agents, embedded React console, WebSocket hub
  for agents, sessions + TOTP, roles (admin / tech / viewer), multi-tenancy (Organizations & Sites),
  technician scoping (`org_scope`), software catalog, IT ticketing, network discovery & SNMP scanner,
  audit log, SMTP alerts, and in-place self-updating (`/api/server/update`).
- **Agent** (`cmd/rmm-agent`, `internal/agent`): one Go binary for Windows and Linux, runs as
  a service, outbound-only connection, inventory, metrics, scripts (PowerShell, cmd, bash, sh,
  python), services, processes, event log / journal, files, power, Wake-on-LAN, patching
  (Windows Update Agent, apt/dnf/pacman/zypper), device network quarantine (`isolate`),
  remote shell (ConPTY / pty), remote desktop helper (`internal/agent/desktop`, spawned into the
  interactive session with privacy banner and multi-monitor switching), portal pipe server
  (`internal/portalpipe`), and the baselines engine (`internal/agent/baseline*.go`).
- **Desktop Companion** (`cmd/rmm-desktop`): lightweight tray client for Windows end users and
  technicians. Connects to `rmm-agent` via Named Pipe `\\.\pipe\homelab-rmm-portal` or directly
  to an RMM server, providing portal pass generation and support launcher.
- **Baselines** (`internal/baselines` shared validator, `internal/server/*baselines*`,
  `web/src/pages/Baseline*.tsx`): desired-state checks with drift alerts and self-healing.
  Contract and kind reference: `docs/BASELINES.md`.
- **Console & Portal** (`web/`): Vite + React + TypeScript, embedded via `web/embed.go` from `web/dist`.
  Features administrative management, multi-tenant scoping, software catalog, ticketing, network discovery,
  and a dedicated end-user client portal (`/portal`).
- **Android** (`android/`, its own Gradle build): the pinned-trust foundation of a WebView
  shell around the console. `:trust` is a pure-JVM module (fingerprint, sealed server list,
  pairing URI, trust store) with 51 passing tests; the app module has the AndroidKeyStore
  server store, `PinnedHttp`, manifest, network security config and signing config, and
  builds an installable APK. The WebView stack and the real screens are NOT written yet -
  the Activities are placeholders whose comments name the task that replaces each one.
  Design and task list: `docs/ANDROID.md`.
- Size: about 50k lines of Go, 18k of TypeScript, 2.8k of Kotlin. History is linear.

Read in this order: `README.md`, `docs/ARCHITECTURE.md`, `docs/API.md`,
`docs/BASELINES.md`, `docs/DESKTOP-PROTOCOL.md`, `docs/SECURITY.md`,
`docs/OPERATIONS.md`, `docs/DEVELOPMENT.md`, `docs/ROADMAP.md`.

## Toolchain

- Go: `go.mod` says 1.26; a Go 1.24+ install auto-downloads the toolchain. No C compiler
  needed anywhere (modernc SQLite, pure-Go screenshot and X11 libraries).
- Node 22 + npm for the console. `cd web && npm ci && npm run build` produces `web/dist`,
  which the server embeds. Commit nothing under `web/dist` (only `.gitkeep`).
- Playwright's Chromium for the end-to-end smoke (`web/e2e/smoke.mjs`): it launches Chromium
  itself; set `PLAYWRIGHT_BROWSERS_PATH` if yours is not in the default location.

## Build, test, run

```bash
make web                      # console
make server agents            # cross-compiles into dist/ (windows/linux, amd64/arm64/arm)
make test                     # go vet + go test ./... + console build
make package                  # zips + tar.gz + SHA256SUMS (rebuilds first)
go test -race -count=1 ./...  # the full suite; internal/server takes ~7 minutes
```

Dev loop (from `docs/DEVELOPMENT.md`):

```bash
go run ./cmd/rmm-server run --insecure --listen 127.0.0.1:8080 --data ./tmp/data
cd web && npm run dev          # proxies /api and /ws to the server
RMM_AGENT_DIR=./tmp/agent go run ./cmd/rmm-agent install --server http://127.0.0.1:8080 --token <token> --no-service
RMM_AGENT_DIR=./tmp/agent go run ./cmd/rmm-agent run
```

First run: navigating to the web console prompts to create the initial administrator account. The check and creation are atomic under an exclusive mutex (`setupMu`) and require no setup code. Subsequent setup requests return 403 Forbidden.

End-to-end smoke with a real Linux agent (83 steps, the strongest check we have):

```bash
go build -o rmm-server ./cmd/rmm-server && go build -o rmm-agent ./cmd/rmm-agent
RMM_DATA_DIR=/tmp/rmm-smoke ./rmm-server run --insecure --listen 127.0.0.1:18080 &
PW_BASE=http://127.0.0.1:18080 RMM_DATA_DIR=/tmp/rmm-smoke AGENT_BIN=$PWD/rmm-agent node web/e2e/smoke.mjs
```

`tools/build.ps1` is the Windows twin of the Makefile / `tools/build.sh`.

## Releasing

CI is `.github/workflows/build.yml`: every push to `main` and every PR runs the console
build, vet, tests and cross-compile. A release is cut by **Actions → Build → Run workflow**
with `release_tag` set (for example `v0.3.0`): the run stamps the version, builds, creates the
tag on the runner and publishes a GitHub Release with the archives and checksums. Pushing a
`v*` tag by hand also works. Update `CHANGELOG.md` first (move the `[Unreleased]` section to
the new version and fix the compare links at the bottom).

## How it was verified

- `go test -race` across all packages, Windows and Linux cross-compiles and vets, console
  type-check, and the Playwright smoke against a real Linux agent (terminal, files,
  processes, scripts with live output, desktop viewer protocol, baselines drift → alert →
  remediate → resolve).
- Remote desktop was tested end to end on Xvfb with real pixels, mouse, keyboard and wheel.
- Independent adversarial reviews attacked the server live (install-script injection, role
  gates, enrollment-token races, forwarded headers, setup takeover, CSRF) and the fixes are
  pinned by `internal/server/security_test.go` and `baselines_verify_test.go`.
- **2026-09-15/16: the first real-Windows run.** An agent was installed as the service
  `HomelabRMMAgent` on a Windows 11 Home 25H2 workstation and thirteen subsystems were
  exercised live against it - service lifecycle and installer, inventory, metrics, scripts,
  services and processes, event log, files, patching (scan only), ConPTY shell, remote
  desktop, baselines, power/WoL, and the agent's Windows security posture - each compared
  field by field against independent ground truth from PowerShell, WMI and the registry.
  That produced 95 findings, every one of them fixed across ten independently reviewed
  batches. `CHANGELOG.md` `[Unreleased]` is the list.
- `go test ./...` passes on Windows for the first time. It never had: the server test
  fixture left its SQLite handle open, and Windows cannot delete an open file, so 91
  passing tests were reported as cleanup failures.
- The console's phone pass was measured with Playwright at 390x844 and 412x915 against a
  real server: zero horizontal overflow on twelve pages, tables replaced by cards, and the
  1280-wide layout unchanged.
- The console phone work was reviewed against an isolated server and a second agent running in
  the interactive session (2026-09-17), because the batches themselves were merged unreviewed -
  a usage limit killed their reviewers. The terminal opens a real PowerShell and returns
  `whoami`, its key bar carries Ctrl/Alt/Tab, the arrows and the control chords, and
  auto-connect is correctly gated on pointer type: a phone-width visit to the Terminal tab
  produced no `shell.open` audit row at all, while a mouse-width visit produced one. Remote
  desktop streams live at phone width (2560x1440 source, ~9 fps) with its own key bar and
  touch handling. No JavaScript errors in any of it, no console batch touched a file it did
  not own, and nothing added a dependency, a service worker or a protocol change.
- `tools\build.ps1` ran on real Windows for the first time (2026-09-16). A full
  `-Target all,package` cross-compiled nine binaries, every one stamped
  `v0.2.0-43-g1e3fc5d` where a Windows build used to stamp `dev`, wrote six archives and
  SHA256SUMS, and the stale-binary guard then refused to package once a source file was
  touched, naming the file and the target to rebuild.
- **Enterprise Security Audit Suite (`internal/server/security_audit_test.go`):** 16 comprehensive
  vulnerability test cases (`VULN-001` through `VULN-016`) verify tenant isolation (`org_scope`),
  IDOR prevention, enrollment hijacking protection, dynamic fleet tag bypass defenses, SSE stream
  tenant isolation, subnet scan bounds, and admin route gating.
- **Device Network Quarantine:** Verified on Linux (`iptables` `RMM_ISOLATE` chain) and Windows
  (`netsh advfirewall` prefix rules), isolating host network traffic while preserving RMM connectivity.
- **Local IPC Security:** Verified Named Pipe DACL hardening (`internal/portalpipe`) on Windows
  denying remote network logons and permitting interactive users.
- **Deployment Packaging & In-Place Updates:** Verified Tagged MSI binary configuration trailers
  (`[HOMELAB_RMM_CONFIG]`), dynamic Debian package generation (`internal/server/install_package_test.go`),
  and server in-place binary swapping (`/api/server/update`).

## What has NOT been verified

- Windows is now exercised (see above), but four paths on it still are not, because each
  needs an action too destructive for the owner's live workstation or a machine it lacks:
  **installing** a patch (only the scan ran), any baseline **remediation**, the
  **power** endpoint (reboot/shutdown/lock/logoff), and killing a **critical process**.
  All four were audited statically and their guards are unit-tested.
- `deploy\uninstall.ps1` has still never been executed: it uninstalls the agent, so running it
  here would take the validation host offline. Run it once on a machine you can spare.
- The Android app has never run on a device or an emulator. In particular **the gating
  unknown of `docs/ANDROID.md` is still open**: whether a `wss://` handshake to a pinned
  self-signed host reaches `WebViewClient.onReceivedSslError`. The Chromium source path
  says it should; only a device settles it, and the app's own Connection test answers it.
  If it turns out false, the terminal and the remote desktop cannot work inside the app
  and the fallback is `tailscale cert` on the server, not a relay in the app.
- Linux paths that need systemd, ufw/firewalld or a package install were unit-tested against
  canned output; the container used for development had no systemd and no network for apt.
- Wayland desktops are captured through the ScreenCast portal and a pure-Go PipeWire client, which has never run against a real compositor or PipeWire daemon; it falls back to the Screenshot portal when it fails (X11 is unchanged). See docs/OPERATIONS.md, "Wayland screen capture".
- Docker image builds were not executed (no daemon available); the Dockerfile was reviewed.

## Known open items

1. ~~No LICENSE file.~~ **Closed 2026-09-18**: MonsterCouch proprietary licence (`LICENSE`)
   committed to repo root and automatically packaged into all release archives.
2. ~~Windows build tooling.~~ **Closed 2026-09-16**: `tools\build.ps1` was executed on real
   Windows, stamps the real version, and its stale-binary guard fires. See "How it was verified".
3. Drift alerts cannot link back to the baseline and check that raised them: the alerts API
   exposes no `dedupe_key` / `baseline_id` (the key `drift:<baseline>:<check>:<agent>`
   already holds both). Needs `internal/server/alerts.go` plus `web/src/api/types.ts`.
4. Baseline maintenance windows are not enforced on the device (no window field in
   `protocol.AgentConfig`); flap counters and log throttles are in memory and reset on
   server restart.
5. ~~Agent self-update & server in-place update~~ **Closed**: Server in-place updates
   (`POST /api/server/update`) and fleet agent updates from staged packages in `agents/` are
   implemented and operational.
6. Console `--text-faint` contrast is below WCAG AA for de-emphasised text app-wide.
6a. **The Android app is one stage of three.** `docs/ANDROID.md` holds the full task list;
   what remains is the WebView stack (the single pin call site, the host bridge, downloads,
   the biometric gate) and the screens (server list, trust review, pin mismatch, QR scan,
   Connection test, settings), then `android/README.md` and a `make apk` target. Build what
   exists with `cd android && ./gradlew :trust:test :app:assembleDebug`.
6c. **Nine findings from the metrics, files and desktop validation are recorded but not**
   **fixed**, each for a stated reason rather than an oversight. Needing a protocol or schema
   change: `swap_used` is collected every 30 s but never stored, charted or alertable; a
   listing carries no Windows file attributes, so hidden/system/reparse are invisible and every
   entry claims `rwxrwxrwx`; `net_rx`/`net_tx` report 0 B/s rather than "unknown" when the
   counter resets, so the graph dips at every agent restart. Inherent to running as SYSTEM in
   session 0: drives that exist only in the interactive user's session (mapped network drives,
   `subst`, a cloud filesystem) are missing from both the metrics and the drive-root listing.
   Needing real work: the remote pointer is invisible in the desktop stream (GDI capture
   excludes the cursor and no helper sends the documented `cursor` message); a read-only viewer
   cannot open a desktop session at all although the viewer implements a view-only mode, which
   wants the input-bearing messages gated rather than the whole socket; an agent config push
   still drops up to one metrics sample and re-phases the series; alternate data streams are
   downloadable by path but never listed.
6b. Three console tasks from the phone pass were not reached: the BaselineStatus compliance
   matrix still renders as a wide table on a phone (C18), the long tail of destructive-action
   adjacency and bulk bars (C19), and the Dashboard/search polish beyond what landed (C16,
   C17 partially). The ranked defect list with evidence is in the design workflow output.
7. Product gaps ranked by an independent review, none started: view-only / observe mode for
   the desktop, in-session file transfer and clipboard sync, more notification channels than
   SMTP (webhook automations exist), fleet-wide patch approval UI, CSV export exists but
   saved views are basic, session recording.

## Conventions that matter

- Never change `internal/protocol/protocol.go` without keeping old agents working; agents
  ignore unknown fields, the server ignores reports with an unknown version.
- Every non-GET API call needs `X-Requested-With: fetch`; browser WebSockets are
  origin-checked; viewers get 403 on every mutation, including shell, desktop, downloads and
  enrollment tokens.
- Roles: a `tech` can run scripts as root/SYSTEM by design; command-kind
  baseline checks and sensitive file paths are admin-only, even for preview.
- Remediation safety lives in `internal/agent/baseline_group.go`
  (`planGroupMembers`) and `internal/baselines` (path rules, limits). Tests assert the
  invariants, not the environment; keep it that way (the GitHub runner's `adm` group differs
  from a container's).
- Scripts, alert rules and baselines seeded on first run are in `internal/server/seed.go`,
  guarded by settings keys so operator deletions are never re-added.
- Telemetry, logs and state: server `server.log` and `rmm.db` in the data dir
  (`%ProgramData%\HomelabRMM` or `/var/lib/homelab-rmm`); agent `agent.json`,
  `agent.log`, `baselines.json` in `%ProgramData%\HomelabRMM` or `/etc/homelab-rmm`.

## Context from the build environment (why some things look the way they do)

- The code was written in a cloud container whose git proxy silently dropped tag pushes and
  branch deletions; that is why releases are cut by the workflow-dispatch input instead of a
  pushed tag. Pushing tags from a normal workstation works too.
- A stray branch `claude/self-hosted-rmm-tool-1o6uvs` in `MonsterCouch/untitled-racing-game`
  holds an early copy of this repository's history; it is redundant and can be deleted.
