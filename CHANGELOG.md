# Changelog

All notable changes to Homelab RMM. The format follows [Keep a Changelog](https://keepachangelog.com/)
and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Remote terminal over WebRTC:** the terminal moves its bytes over a WebRTC data channel (`term`, raw pty bytes, no string
  conversion) and keeps the WebSocket relay as the fallback; the switch is ordered so no byte is lost or reordered, and the
  browser falls back after 4 s or on any failure. The ICE servers from `RMM_ICE_SERVERS`, credentials included, now reach the
  agent in `shell.open` as well as the browser, so TURN works on both ends. The status line shows `WebRTC (direct)` or `Relay`;
  see `docs/TERMINAL-PROTOCOL.md`.
- **Update agent button on the device page:** confirms, then runs the single-device update (signed in organizations that sign
  actions), offers a forced reinstall when the device already runs the build, and shows the outcome as a toast. The update event
  is now broadcast live, so the Activity tab shows it without a reload.
- **`/dev/uinput` access on Linux:** `rmm-agent install` writes `/etc/udev/rules.d/70-homelab-rmm-uinput.rules` and reloads udev so the
  desktop helper (running as the session user) can inject input on Wayland without manual steps; `rmm-agent uninstall` removes it.
- **Wayland screen capture on Linux:** the desktop helper reads frames from the XDG ScreenCast portal through a pure-Go
  PipeWire client (no CGO, no libpipewire), with the Screenshot portal as the fallback and `RMM_WAYLAND_PORTAL=0` as the
  off switch. It is verified on GNOME 50 on Wayland; see `docs/OPERATIONS.md`, "Wayland screen capture".
- **Update source in the console:** the agent reports where an update came from (origin, subnet cache or cache failure);
  the device activity tab and the fleet update summary show it.
- **Multi-Tenancy Hierarchy (Organizations & Sites):** Manage multi-client fleets under distinct
  Organizations with physical Sites, technician assignment (`org_scope`), and tenant isolation.
- **Client Self-Service Portal & Desktop Companion (`rmm-desktop`):**
  - Token-authenticated end-user portal (`/portal`) for requesting help, tracking tickets, and running approved self-service scripts.
  - Windows tray companion (`cmd/rmm-desktop`) with Named Pipe IPC (`\\.\pipe\homelab-rmm-portal`) and DACL hardening (`pipeSDDL`).
- **Integrated IT Ticketing:** Multi-tenant ticketing workflow with status tracking (open, in-progress, resolved, closed),
  public client comments, and internal technician-only notes (`is_internal: true`).
- **Software Catalog:** Global repository of reusable software packages with automated silent install/uninstall
  commands, platform targeting, and tracked deployments.
- **Network Discovery & SNMP Polling:** Subnet discovery scanner and built-in SNMP (v2c) polling engine
  for detecting routers, switches, NAS, and printers, mapping open ports, and managing unmanaged network assets.
- **Device Network Quarantine (Isolation):** One-click device isolation via `POST /api/agents/{id}/isolate`.
  Applies `iptables` rules on Linux or Windows Advanced Firewall policies on Windows, isolating the endpoint from
  all network traffic while preserving bidirectional RMM communication.
- **Remote Desktop Multi-Monitor & Privacy Banner:** Multi-monitor display switching (`monitor` message) and a
  topmost, click-through, non-interactive overlay privacy banner on Windows to notify local users during remote sessions.
- **Zero-Touch Deployment Packaging:**
  - **Tagged MSI Overlay:** Dynamic 8 KB configuration trailer (`[HOMELAB_RMM_CONFIG]`) appended to `rmm-agent.msi` for
    zero-argument double-click installation and seamless GPO/Intune deployment.
  - **Dynamic Debian Generator:** On-the-fly Debian `.deb` package generation (`/install/{token}/deb`) containing pre-compiled
    agent binaries, systemd unit definitions, and embedded enrollment configs.
- **In-Place Server Self-Updating:** `POST /api/server/update` performs atomic binary replacement of `rmm-server`,
  synchronizes updated agent packages in the `agents/` directory, and restarts the service gracefully.

### Fixed
- **Reinstall refreshes the A/B slot:** `rmm-agent install` run from a newer binary now replaces the active slot's `rmm-agent` (atomic temp-file write, fsync, rename, 0755) when its SHA-256 differs, so the service no longer keeps running the previous build; the refresh is refused (with a warning) while an update is pending, since a running supervisor keeps its own copy of `state.json`; re-run the install once the update settles.
- **Desktop helper log spam:** the "fast-start video encode failed; tiles only" debug line is logged once per session instead of every frame on platforms without a hardware video encoder.
- **Linux service unit:** the systemd unit template used `text/template` syntax the service library no longer accepts, so the service did not install.
- **Linux supervisor:** it handed the worker the Windows pipe name and the worker dialled it, so the watchdog killed the worker every 30 seconds.
- **Wayland capture:** the portal method is `OpenPipeWireRemote`, not `OpenPipeRemote`.
- **Wayland capture:** the PipeWire stream never wrote `active_driver_id`, so the driver never scheduled it and no frame arrived.

### Security & Hardening
- **Revoking access now ends what the account has open:** a terminal, a remote desktop or the live event stream used to be
  checked once, when it opened, and then ran until the tab closed. Signing out, a password change or reset, a demotion, a
  narrower organization scope and deleting the account now close them at once (close code 1008), and the shell or desktop helper
  on the device is torn down with them. A sweep every 30 s catches what the server cannot see happen: an expired session, a
  password reset from the CLI, a device moved to another organization.
- **A device's identity is no longer the server's to reassign:** the agent accepts a new agent ID and key only as the answer
  to an enrollment, never on a session it opened with its key. With an enforcing trust bundle pinned, re-enrolling after a
  rejected key must return the identity the device already had; anything else is refused, so a grant or action signed for one
  device cannot be run on another. A device that was deleted on purpose and should enroll as new needs `trust.json` and
  `log_head.json` removed first. Without an enforcing bundle, re-enrollment is unchanged.
- **Two-step sign-in cannot be replaced with a session alone:** `POST /api/me/totp/begin` is refused (409) while a factor is
  enabled. Turn it off with the password first, as before.
- **The login limit is per address again:** a successful sign-in takes back its own attempt and no longer clears the
  address's count, which let anyone with a working account reset the limit and keep guessing someone else's password.
- **Former operators stop counting as signers:** a user whose security key is in a trust bundle cannot be deleted until the
  key is removed from the bundle (409, the rule deleting a single key already followed), and a signature made with a key whose
  owner is no longer a technician or administrator is rejected (403) instead of counting toward the threshold.
- **Security Audit Mitigations (VULN-001 - VULN-016):**
  - Strict tenant IDOR verification across all agent, task, baseline, and ticket endpoints (`VULN-001`, `VULN-006`).
  - Fleet tag bypass prevention: dynamic intersection of tag selectors with user's `org_scope` (`VULN-007`, `VULN-015`, `VULN-016`).
  - Admin role enforcement on server updates, global software catalog entries, discovery scans, and audit logs (`VULN-003`, `VULN-008`, `VULN-011`, `VULN-013`).
  - Real-time Server-Sent Events (SSE) stream tenant isolation to prevent event leakage (`VULN-014`).
  - Rate limiting and bounds checking on subnet scans and UDP SNMP packet decoding (`VULN-004`, `VULN-005`).
- **First-Run Setup Simplification:** Removed the setup code requirement. First-run administrator creation is guarded
  atomically via exclusive mutex (`setupMu`) on `POST /api/auth/setup`, closing immediately upon creation.

**First run on real Windows.** Everything Windows-specific had only ever been cross-compiled and
reviewed. On 2026-09-15 the agent was installed as a service on a Windows 11 workstation, every
subsystem was exercised against it, and 95 findings were confirmed and fixed. Nothing here changes
the protocol; old agents keep working.

### Added
- **Windows installers.** `rmm-server-<version>-x64.msi` and `rmm-agent-<version>-x64.msi`, built
  by `tools\build.ps1 -Target msi` with WiX v7: a real Add/Remove Programs entry with an icon,
  upgrades that replace the binary without touching the data directory, an uninstall that
  deregisters the service rather than leaving it pointing at a file that is gone, and Start-menu
  and desktop shortcuts to the console. Every setting is an MSI property, so
  `msiexec /i rmm-agent.msi /qn SERVER=... TOKEN=...` is a whole unattended deployment. Both are
  now attached to each release by a Windows CI job; it runs only for releases, because a Windows
  runner bills at twice the Linux rate.
- **22 Windows scripts** in the seeded library, across Diagnostics, Maintenance, Security, Users
  and Software — all of them executed against a live Windows 11 agent rather than only reviewed.
  Component-store cleanup reclaimed 10.34 GB on the validation machine.
- **`--tailscale-cert`.** The server gets a real Let's Encrypt certificate for its tailnet name
  from `tailscale cert`, re-asks daily, and swaps a renewed one in **without a restart** because
  the listener reads the certificate through a `GetCertificate` hook. Renewal is why this belongs
  in the server and not the installer: the certificates last 90 days, so minting one at install
  time only moves the outage a quarter into the future. Any failure is a warning, never fatal — a
  server that cannot reach Tailscale still starts on its self-signed certificate.
- **Pinning stops being a time bomb.** When the served certificate verifies against the host trust
  store for the public URL's host, the server hands out **no** fingerprint: enrollment commands
  omit `--fingerprint` and agents use system trust, which survives every renewal. A self-signed
  certificate is still pinned, because nothing else vouches for it. `GET /api/enroll` reports both
  `fingerprint` (what to pin, empty when there is nothing to) and `cert_fingerprint` (what is
  actually served).
- **`rmm-server setup-code` command:** Retained for backward compatibility; prints an informational
  notice stating that first-run setup codes are no longer required, directing operators to configure
  the initial administrator account directly via the web console.
- **`tools\build.ps1 -Platforms`** restricts the cross-compile, e.g. `-Platforms windows/amd64`.
  The MSI target consumes only that pair, so the release job no longer builds nine binaries on
  the expensive runner to package two.

### Licensing
- **`LICENSE`** settles it: proprietary, licensed rather than sold, with access for evaluation
  granting internal evaluation only. Until now the repository carried no licence file at all, so
  no rights were granted to anyone and the release archives shipped a placeholder saying as much.
- **`THIRD-PARTY-NOTICES.md`** carries the attributions the compiled-in components require. The
  binaries link 22 Go modules and the console bundle embeds 40 npm packages; every one is
  permissive (MIT, BSD, ISC, Apache 2.0, zlib), so none is copyleft and none forces this source
  open, but all of them require their copyright notice to travel with a copy of the software. Both
  MSIs install it beside the executable and both packagers stage it into every archive and now
  fail rather than build one without it. It is generated from the components' own licence files,
  including the `NOTICE` that Apache 2.0 section 4(d) requires be reproduced.

### Fixed
- **A fresh clone did not compile.** `go build ./...` failed with `pattern all:dist: no matching
  files found`, because `web/embed.go` embeds `web/dist` and the directory did not exist. The
  README claimed a tracked `.gitkeep` held it open, but the ignore rule excluded `/web/dist/`
  itself and git never descends into an excluded directory — so the `!/web/dist/.gitkeep`
  negation below it had never had any effect. The rule now excludes the contents instead, and the
  `.gitkeep` exists. The build scripts still refuse to build `rmm-server` without
  `web/dist/index.html`, so this cannot silently ship a console-less server.
- **The Windows service wrote no log.** The slog handler was `io.MultiWriter(os.Stderr, file)`;
  a process the Service Control Manager starts has no standard handles, so the first write failed
  and slog swallowed the error: `agent.log` (and `server.log`, including the first-run **setup
  code**) stayed at 0 bytes on every Windows install. A writer that drops unusable sinks replaces
  it; `install`'s start confirmation works again and waits 45 s to outlast the SCM's own timeout.
- **Text outside the ANSI/OEM code page** was corrupted everywhere on Windows: PowerShell script
  bodies (now written with a UTF-8 BOM), script output (decoded from the console code page; python
  runs with `PYTHONIOENCODING=utf-8`), the console terminal (ConPTY now starts in UTF-8 with
  `TERM`/`COLORTERM` set) and the event log (`wevtutil /uni:true`, decoded from UTF-16LE).
- **Scripts**: a line over 1 MiB no longer wedges a run until its timeout; output that hits the
  1 MiB cap is marked `[output truncated]` and the server keeps the longer of the streamed and final
  copies; cancelling records `cancelled` rather than `failed` (no false "Script failed" alert);
  an `os_filter` mismatch answers 409 instead of 200 with a bogus `run_id`; Windows exit codes are
  sign-extended (`exit -1` is -1, not 4294967295); python is found through `py.exe` and the
  registry; orphaned `rmm-script-*` temp directories are swept at start-up; the whole child tree is
  killed on timeout or cancel through a kill-on-close job object.
- **Inventory**: `cpu_cores` is the physical core count (it was the logical count); `antivirus`
  names the active product first and marks each product's state; software `installed` is always an
  ISO date or empty; timezone carries its UTC offset (`EDT (UTC-04:00)`) plus `extra.timezone_id`;
  Entra ID (`S-1-12-1-*`) user hives are enumerated; the logged-in-users fallback no longer calls
  `query.exe` on editions without it and logs the WTS error instead of discarding it.
- **Event log**: events whose provider message cannot be rendered are no longer dropped from a
  page; search scans a fixed window of the newest 5000 records whatever the page size and matches
  beyond the 8000-character display cap; Windows page limits match Linux (default 200, max 5000).
- **Patching**: a `winget:` row in an install batch no longer aborts the whole batch (WUA updates
  install, winget rows are reported individually as not installable from the service account); a
  failed winget half of a scan is reported as `scan_error` instead of marking every winget row
  "installed"; `scan_error` is typed and shown in the console; `POST /api/patches/status` accepts
  the snake_case keys the API emits and rejects unmatched items; severity ordering puts Critical
  first (Linux `security` ranks with Important); `categories` is always an array; `downloaded` and
  `description` reach the API and console; the Installed tab is fed from WUA history.
- **Baselines**: `registry` checks verify the stored value type (a REG_QWORD read as `dword` is an
  error, not a truncated pass); `disk_free` with `/` on Windows is an error instead of silently
  measuring the system drive; `package` names may contain spaces and parentheses on Windows;
  `registry` paths may contain GUID braces and punctuation, and rejections name the offending part;
  an unknown `windows_feature` reports "not found"; a `command` check abandoned at its deadline keeps
  its `expected` label and partial output, guarded by a test over every kind on both platforms.
- **Services and processes**: a service whose description is an unresolvable MUI resource keeps its
  start type; process command-line truncation is rune-safe; process CPU% is normalised by core count.
- **Power / WoL**: `poweroff`, `halt` and `logout` aliases work on Windows; `delay_sec` is honoured
  for logoff; the shutdown message is capped at 512 UTF-16 code units; the Wake-on-LAN magic packet
  leaves on the interface whose subnet contains the target.
- **Terminal**: `opened` is emitted only once the device has actually started the shell; a 0x0 or
  absurd resize is refused instead of collapsing the console; the exit watcher no longer races the
  pseudo-console handle it waits on.
- **Installer script**: `--fingerprint` is rendered only when non-empty (PowerShell 5.1 dropped the
  empty argument and the install failed on every server without a pinned certificate); the script
  refuses before downloading when no SHA-256 exists for the architecture; an unknown `?os=` is a 400
  instead of the Linux script.
- **Windows build**: `tools\build.ps1` stamps the real version (a `| Select-Object -First 1` after
  `git describe` left `$LASTEXITCODE = -1`, so every Windows build said `dev`) and its `package`
  target refuses stale binaries like `build.sh`; `deploy\uninstall.ps1 -Purge` removes
  `baselines.json` and `helper.log` too and deletes the directory when empty.
- `maintenance_until` rejects negative values and is capped at 30 days; `notes`, `display_name` and
  tags are bounded; the Windows software list is bounded like the Linux one.

- **`go test ./...` passes on Windows.** The server test fixture left its SQLite handle open at
  cleanup, so Windows (which cannot delete an open file) reported every passing server test as a
  failure; the fixture now shuts the server down in the same order `Run` does, `Run` closes the
  database when the listener fails to bind, and the syslog ordering test no longer assumes UTC.

### Security
- Baseline `file` paths are canonicalised on both sides: an NTFS 8.3 short name
  (`C:\ProgramData\HOMELA~1\agent.json`) could reach the agent's own configuration directory past
  the server guard and the admin gate. Short-name components are refused by the server and resolved
  by the agent before comparison.
- `%ProgramData%\HomelabRMM` now gets its owner set as well as its DACL, so a standard user who
  pre-created the directory no longer keeps `WRITE_DAC` over the device key; the server hardens its
  Windows data directory (`rmm.db`, `server.key`) the same way instead of inheriting "Users can read".
- `processes/kill` refuses Windows critical processes and the agent itself (the only guard was
  `pid <= 4`); denied and failed service actions and kills are audited with their outcome.
- Every interpreter the agent launches as SYSTEM (`powershell.exe`, `cmd.exe`, `pwsh`, `winget`) is
  resolved by absolute path or an administrator-only root, never a bare PATH lookup; `cmd` script
  parameters are quoted with cmd.exe's rules and values containing `" % !` or newlines are refused.
- Agent self-update requires a 64-hex SHA-256 and an `https` URL (or `http` only to the configured
  server), aborts on a failed executable-path resolution, and survives a lingering `.old`.
- Reading the Security channel or any PowerShell channel of the event log requires the write role
  and is audited as `eventlog.query`.
- `rmm-agent install` warns when the binary it registers lives in a directory (or is a file)
  writable by non-administrators, and when the server URL is plain `http://`.
- Terminal WebSockets have a 1 MiB read limit and ping-based liveness, so an abandoned browser tab
  no longer leaves a SYSTEM shell open.

### Documentation
- Windows enrollment documents the antivirus reality (AMSI blocks the `iex` one-liner; Bitdefender
  on the validation machine) and makes the two-step form the primary path, run with
  `powershell -NoProfile -ExecutionPolicy Bypass -File`. Manual installs go in an
  administrators-only directory. `agent.json`'s Windows protection is described as a DACL, not
  `0600`; the enrollment token it keeps is called out; OPERATIONS.md describes the real Windows
  diagnostic channels; API.md gains an **Event log** section, run statuses, exit-code
  representation, `scan_error`, power aliases; ARCHITECTURE.md describes the script runner, patch
  severity ordering and `agent.update` accurately; README no longer advertises public IP.

## [0.2.0] - 2026-09-15

**Baselines: desired state, drift detection and self-healing.**

A baseline is a named list of checks that says how a device should look, assigned with the same
target model as tasks and alert rules (all / agents / groups / tags / OS). Agents evaluate their
assigned baselines on their own interval — **offline too** — and report every pass. When the
baseline is *enforced* and the check allows remediation, the agent fixes the drift itself and
reports the check as `fixed`. Nothing in this release changes behaviour for an existing
installation until an operator creates or enables a baseline.

### Added
- **Twelve check kinds**: `service`, `package`, `registry`, `file`, `command`, `group_members`,
  `firewall`, `time_sync`, `sysctl`, `windows_feature`, `reboot_pending`, `disk_free`. Each check
  carries its own severity, OS filter, timeout and `remediate` flag, so one baseline can fix the
  two things you trust it to fix and only report the rest. Parameter shapes, limits and validation
  live in the new `internal/baselines` package and are the single definition both sides use: the
  server rejects an invalid check with a 400 naming the field, the agent re-validates before it
  runs anything.
- **Agent engine** (`internal/agent/baseline*.go`). One goroutine per process, so passes never
  overlap; the next pass is scheduled an interval after the previous one *finished*; the start-up
  pass and config-change passes are jittered so a fleet-wide edit is not a thundering herd; every
  check runs under its own deadline enforced by the engine, so a check wedged in a syscall cannot
  stop the device evaluating. `baselines.json` beside `agent.json` (0600, tmp+rename) holds the
  specs, the last report per baseline and the per-check fix hold-offs, and is loaded *before* the
  first connection, so a device that reboots while the server is unreachable still evaluates and
  reports what it saw when it reconnects.
- **Drift alerts** with the dedupe key `drift:<baseline>:<check>:<agent>`, `rule_kind` `drift` and
  a null `rule_id`, opened at the check's severity and resolved automatically when the check passes
  again. Severity `info` reports without ever opening an alert. A check that is re-fixed on five
  consecutive passes opens a second `keeps drifting back` alert instead of raising an event every
  interval.
- **Automation triggers** `drift_detected` and `drift_fixed`, carrying the baseline, the check, its
  kind, severity, state, expected, observed and detail.
- **Compliance** per device, per baseline and fleet-wide, on the dashboard and on a new device
  **Compliance** tab that works for an offline device — reading its last known state is the point.
- **Preview**: dry-run an unsaved draft on up to ten live devices. It never fixes, never writes to
  the device and never stores a result.
- **Console**: a Baselines page, an editor with typed forms per kind (plus raw JSON, validated
  against the same shapes), a device × check status matrix with per-cell detail and history, and a
  dashboard tile. The enforce toggle carries an explicit warning that the agent will change these
  devices without asking.
- **API**: `GET/POST /api/baselines`, `GET/PUT/DELETE /api/baselines/{id}`,
  `/api/baselines/{id}/status`, `/evaluate`, `/remediate`, `/api/baselines/preview`,
  `/api/agents/{id}/baselines`, `/api/agents/{id}/baselines/history` and `/api/compliance`; a new
  `baseline` SSE event. Audit actions `baseline.create/update/delete/enable/disable/evaluate/
  remediate/preview/command_check/reboot_check`.
- **Two seeded baselines**, *Windows workstation hygiene* and *Linux server hygiene*, both shipped
  **disabled and unenforced** with every destructive check report-only. They run from their own
  `seeded_baselines` guard rather than the existing `seeded` key, so they appear on upgrade from
  0.1.0 as well as on a fresh database.
- Database migration 4: `baselines`, `baseline_checks`, `baseline_results`, `baseline_state`,
  `baseline_history`. `baseline_history` is purged on the events retention setting.

### Security
- **An enforced baseline changes devices without asking, and the `command` kind is arbitrary
  root/SYSTEM code.** Enforcement is opt-in and warned about; creating, editing **or previewing** a
  baseline that contains a `command` check, a `file` check writing outside `/etc` or `ProgramData`,
  or a `reboot_pending` check with `allow_reboot` requires the **admin** role and is audited by
  name (a preview is on that list because it runs the draft on the devices it names); a
  fleet-wide (`{"all":true}`) enforced reboot check is refused without an explicit
  `confirm_fleet_reboot`. `command` runs through the existing script-runner path — a temp
  directory, a 0700 file, `exec.Command` with arguments, never a shell string.
- **The dangerous refusals are enforced on the device**, so they hold whatever the server was
  talked into sending: never empty `Administrators`/`sudo`/`wheel`/`adm`/`root` or remove RID 500,
  uid 0, the account the agent runs as, or a domain principal without `allow_domain`; never change
  a `boot`/`system` service start type; never stop or disable the agent's own service; never write
  to `/proc`, `/sys`, `/dev`, `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`,
  `C:\Windows\System32\config` or the agent's own configuration directory; never follow a symlink
  in a managed path's parent chain; never remove a directory; never accept a setuid/setgid/sticky
  mode; at most one baseline-initiated reboot per device per 24 h, and none while a script run or
  shell session is live.
- A member name that would be read as an option by `gpasswd` or `net localgroup` (leading `-` or
  `/`) is reported as drift and never passed to either tool.
- Windows `package` remediation stays refused from the service account unless the check sets
  `allow_winget: true` *and* winget resolves, matching the existing patch-management decision
  rather than quietly working around it.
- Baseline check parameters are readable by every signed-in account, viewers included; the console
  says so in the Add-check dialog. They are not a place for secrets.
- A baseline set can no longer be frozen into the operator-editable `agent_defaults` settings blob
  and pushed to every device regardless of targets: `agentConfig` resolves baselines after the
  settings unmarshal, and the settings writer nulls the field.

### Changed
- `alertEngine` gained `openDrift`, which opens an alert with a null `rule_id`, `rule_kind`
  `drift` and the check's severity while reusing the same dedupe, maintenance-window suppression,
  SSE broadcast and `alert_opened` automation. `drift` is deliberately **not** a creatable alert
  rule kind.
- `PATCH /api/agents/{id}` now pushes a fresh agent config when `group_id`, `clear_group` or
  `tags` change, not only when `monitored_services` does, so a device that gains or loses a
  baseline through group or tag membership learns about it immediately. Deleting a group pushes to
  its former members.
- Drift email is a **digest**: at most one mail per (device, baseline) per report, only when the
  baseline has `notify_email` and a newly-transitioned check is `critical`, and suppressed if one
  went out for that pair in the last hour. A first evaluation of a seven-check baseline over
  twenty devices would otherwise have sent up to 140 mails.
- `internal/protocol` is unchanged on the wire. Its comments on `baseline.evaluate` and
  `baseline.remediate` still say "reply `[]BaselineReport`"; the replies are in fact ACKs
  (`{"accepted":true,…}`) and the results arrive as one unsolicited `baseline` frame, because a
  reply carrying the report as well would double every transition, alert and automation. The
  comments will be corrected when the file is next opened.
- `web/e2e/smoke.mjs` fails fast, naming the binary, when the agent it was given predates the
  baselines API, instead of timing out 200 lines later on a selector.
- `tools/build.sh package` refuses a staged binary older than the Go sources or `web/dist` it was
  built from, naming the offending file, instead of silently archiving whatever `dist/` still held
  from an earlier build. The console is embedded in the server binary, so that mismatch is
  invisible until someone runs the archive: a `package` run on its own produced archives carrying
  `docs/BASELINES.md` and a server with no baselines API in it. `ALLOW_STALE_BUILD=1` packages it
  anyway; `make package` was never affected, since it depends on `server agents`.

## [0.1.0] - 2026-09-15

Initial release.

### Security
- **Install script endpoint hardened.** `GET /install/{token}` now renders a script only for a
  token that matches `^[A-Za-z0-9_-]{16,64}$` *and* could still enroll a device; anything else is
  a 404. `?arch=` must be one of `amd64`, `arm64`, `arm`, `386` or the request is a 400, and the
  public URL, token and fingerprint are escaped for the single-quoted literal they are
  interpolated into. Previously the token path segment went into the script verbatim, so a
  crafted URL could add commands to a script that is piped into `bash` or `iex` as root.
  Responses are `Cache-Control: no-store`.
- **Viewers can no longer open a terminal, a remote desktop session, download a file or read an
  enrollment token.** `GET /ws/shell/{id}`, `GET /ws/desktop/{id}`,
  `GET /api/agents/{id}/fs/download` and `GET /api/enroll` are behind the same write check as
  everything else and return 403 for the `viewer` role. The enrollment listing carries the token
  *values*, which are all anyone needs to add a device of their own to the fleet. Directory
  listings and the rest of the read-only console are unchanged.
- **Enrollment tokens are consumed atomically.** The use count is decremented with a conditional
  `UPDATE` inside the transaction that creates the device record. Concurrent enrollments on a
  one-use token previously produced one device per racing agent and left `uses_left` negative,
  which reads as "unlimited" forever. `-1` is now the only non-positive value that still enrolls:
  `POST /api/enroll` clamps `uses` to `{-1} ∪ [1..]` instead of storing what it is sent, rows an
  older server drove below `-1` are repaired on upgrade (migration 2), and anything else `<= 0`
  reads as exhausted.
- **`X-Forwarded-For` is ignored unless you say where the proxy is.** New `--trusted-proxies`
  flag and `RMM_TRUSTED_PROXIES` environment variable (comma-separated IPs or CIDRs); the header
  is believed only for connections from those networks. Without it a client could forge the
  header to get a fresh login-limiter bucket per attempt and write any address into the audit
  log. Add the flag when running behind a reverse proxy. When the header *is* believed, the hop
  list is read from the **right**, skipping hops that are themselves trusted proxies: nginx's
  `$proxy_add_x_forwarded_for` and Caddy's default both *append* to whatever the client sent, so
  taking the left-most hop (as the first version of this fix did) left the forgery wide open in
  exactly the reverse-proxy deployment the flag exists for. A CIDR with host bits set covers its
  whole network and now says so in the log.
- **Changing your own password now deletes your other sessions**, so reacting to a stolen cookie
  by changing the password actually ends it.
- **First-run setup needs a one-time code — from everywhere, loopback included.** A server that
  starts with no users mints a random setup code and prints it to the console and `server.log`,
  and every `POST /api/auth/setup` must present it (constant-time comparison, rate-limited,
  refusals audited as `setup.refused`). There is no loopback exemption: a peer address of
  `127.0.0.1` is equally a same-host reverse proxy relaying the LAN, another local process, or a
  page in the operator's own browser. Restart the server before creating a user to mint a new
  one; the code is cleared once the administrator exists. `GET /api/auth/state` reports
  `setup_code_required` and the setup form always asks.
- **First-run setup is atomic.** The "are there users yet?" check and the insert run under one
  lock; the ~250 ms bcrypt hash between them was previously wide enough for a handful of
  concurrent requests to each create an administrator.
- **`/api/auth/setup`, `/api/auth/login` and `/api/auth/logout` carry a CSRF guard.** They sit
  outside the session middleware, so `X-Requested-With` was never checked on them and any
  `Content-Type` was accepted — a cross-origin "simple request" reached them. They now require
  the header, an `Origin` host matching `Host`, and an `application/json` body.
- **Content-Security-Policy** on every response: `default-src 'self'`, `script-src 'self'` (no
  inline or `eval`ed script), `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`,
  `form-action 'self'`.
- **A re-enrollment that takes over an existing offline device record is audited as
  `agent.rekeyed`**, logged at WARN with the source address and written to that device's event
  timeline, so a reinstall and a machine claiming another's hostname are no longer both filed as
  `agent.enrolled`. An enrollment that collides with a hostname a device is currently *using* is
  audited as **`agent.duplicate_hostname`** — nothing is re-keyed, but the fleet now has two rows
  with one name, which is the confusing half of the same attempt.
- **The install scripts verify the agent binary and pin the download.** `/install/<token>` now
  carries the SHA-256 of the binary the server would serve (one per architecture on Linux, where
  `uname -m` picks) and the script refuses to install anything that does not match. The download
  connection is pinned to the server certificate — a validation callback comparing the
  certificate's SHA-256 on Windows instead of returning `$true` for everything, and
  `curl --pinnedpubkey sha256//<SPKI>` on Linux where curl supports it — rather than accepting
  any certificate. `/api/agent-download` is still unauthenticated by design; it is no longer
  unverified.

### Fixed
- Desktop and shell relays send a Close frame instead of dropping the socket, so a session no
  longer ends as an abnormal 1006 disconnect in the browser — and the code says which ending it
  was. A peer that closed cleanly has its code forwarded; a peer that died without a close frame
  is reported as 1011 with a reason naming it, so a crashed helper is distinguishable from a
  finished session (they were briefly both 1000). The desktop viewer's pre-bridge failures — no
  graphical session, helper never connected, request cancelled — close properly too, and so does
  the terminal, which had no close path at all.
- The Windows install script wraps `$svc.WaitForStatus('Stopped', ...)` in a `try`/`catch`. It is
  a .NET call that throws `TimeoutException`, and with `$ErrorActionPreference = 'Stop'` a
  service that would not stop aborted the script with a raw stack trace — before the process wait
  and the `Move-Item` retries that exist to handle exactly that case ever ran.
- `rmm-agent install` / `rmm-server install` over a **running** service stop it and wait for it
  to disappear before reinstalling, instead of failing with
  `ERROR_SERVICE_MARKED_FOR_DELETE`. The Windows install script likewise stops the service, waits
  for `rmm-agent.exe` to exit and retries the binary swap, instead of failing with a sharing
  violation.

### Tooling
- **`make package` can no longer archive a server with no console.** `rmm-server` embeds
  `web/dist`, and that directory is gitignored apart from `.gitkeep`, so a build that skipped the
  UI step embedded a single empty file, compiled without a warning and produced an archive whose
  console was a directory listing of `.gitkeep`. `make`, `tools/build.sh` and `tools/build.ps1`
  now refuse to build `rmm-server` (and to package) when `web/dist/index.html` is missing, and
  say to run `make web` first; `ALLOW_EMPTY_WEB=1` builds one deliberately for use with
  `--dev-web`. CI additionally greps every packaged server binary for the embedded `index.html`,
  so the artefact itself is checked and not just the source tree.
- `deploy/uninstall.sh` / `uninstall.ps1` say that the `agent.json` they keep holds the
  enrollment token as well as the device identity.

### Documentation
- **README no longer promises a download that does not exist.** There is no `v*` tag yet, so the
  quick starts now open with how to get the archives today (`make all && make package`, or the
  CI `dist` artefact) and the License section states plainly that no `LICENSE` file has been
  chosen — which is what the archives' placeholder already said. `docs/DEVELOPMENT.md` lists both
  as blockers for the first release.
- **The enrollment token's real lifecycle is documented.** README said the agent "never uses the
  token again"; in fact `agent.json` keeps `enroll_token` and replays it whenever the server
  rejects the key, which is what makes a deleted device reappear within seconds as a new record
  with no history, and what leaves a multi-use token at rest on every device it enrolled until it
  expires. README, `docs/SECURITY.md` and the housekeeping checklist in `docs/OPERATIONS.md` now
  say so and how to remove a device for good.
- **`docs/ARCHITECTURE.md` no longer claims nothing fires `agent_offline`.** The hub has always
  fired it; what it lacks is a grace period. The scheduler section now describes when
  `agent_online`/`agent_offline` fire (the device's current socket, so a replaced socket stays
  quiet), that a reconnect flap fires both, that a dead socket takes up to 90 s to notice, and
  that an `offline` alert rule plus `alert_opened` is the way to get "offline for N minutes". The
  same section documents the 60-fires-a-minute cap per automation.
- The `X-Requested-With` CSRF guard is described as it behaves: **any** non-empty value is
  accepted (`docs/API.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`) — the defence is that a
  cross-site form cannot set a custom header at all, not the literal `fetch` the console sends.
  WebSocket upgrades are exempt and rely on the same-origin check.
- `docs/ARCHITECTURE.md`'s auth section still described the loopback exemption that the setup
  code replaced.
- **Docker deployment notes.** `docker-compose.yml` and `docs/OPERATIONS.md` explain that the
  first-run setup code has to come from `docker logs` (the image is distroless — nothing to
  `docker exec` into), that with a published port the container sees the bridge gateway rather
  than `127.0.0.1` for requests from the Docker host, which is what the audit log and the login
  limiter then key on, and that `RMM_TRUSTED_PROXIES` is for a real proxy in front of the
  container and must not be pointed at the gateway wholesale. The comment claiming
  `RMM_PUBLIC_URL` can be changed later in Settings is replaced by what actually happens: it
  seeds the setting on first start, and the saved setting wins afterwards.

### Server
- Single binary with embedded web console, JSON API, Server-Sent Events, SQLite (pure Go,
  WAL, versioned migrations) and a self-signed certificate generated on first run.
- Windows service / systemd unit management (`install`, `uninstall`, `start`, `stop`,
  `restart`, `status`) and a `user` CLI (`add`, `passwd`, `list`).
- Agent hub: outbound WebSocket per device, enrollment tokens (uses, expiry, group), per-device
  keys stored hashed, keepalive, config push, live event fan-out to browsers.
- Users with admin / tech / viewer roles, bcrypt passwords, TOTP two-factor, session cookies,
  CSRF header check, same-origin WebSocket check, login rate limiting, audit log.
- Monitoring: metrics history with bucketed queries, inventory snapshots, monitored services,
  maintenance mode.
- Alert engine: cpu, memory, disk, offline, service, reboot required, script failed, patch
  failed and event-pattern rules; sustained thresholds, deduplication, auto-resolve,
  acknowledge, email notifications (STARTTLS / TLS / plain SMTP).
- Scripting: library with categories, parameters, timeouts and OS filters; PowerShell, cmd,
  bash, sh, python; streamed output; queued runs for offline devices; targets by device, group,
  tag or OS; cron-scheduled tasks; automations (run script, email, webhook) on device, alert,
  enrollment, reboot and patch events.
- Patch management: scan/approve/ignore/install with live log, policies with scan and install
  schedules, approved / all / security modes, reboot never / if required / always.
- Relays: browser terminal over a pseudo-terminal, remote desktop bridge with single-use helper
  tokens.
- Device tools: processes, services, event log / journal, file browser with upload and
  download, power actions, Wake-on-LAN via a peer agent on the same subnet.
- Enrollment: install scripts for Windows (PowerShell) and Linux (bash) served per token; agent
  binaries served from `<data>/agents/` or beside the executable.
- Seed data on first start: 17 starter scripts (Windows PowerShell and Linux bash) across
  Maintenance, Diagnostics, Updates, Security and Users; seven default alert rules; `Servers`
  and `Workstations` groups; a scan-every-6-hours patch policy.
- Retention purge (metrics, runs, events, audit, resolved alerts, tokens, sessions).

### Agent (Windows, Linux)
- Service install with certificate pinning by SHA-256 fingerprint, reconnect with backoff,
  identity kept across reinstalls, automatic re-enrollment after key revocation.
- Inventory (hardware, OS, disks, network, software, GPUs, users, pending reboot, antivirus)
  and periodic metrics.
- Scripts with positional parameters, streamed output, timeout and cancel (process-tree kill).
- Shell sessions (ConPTY on Windows, pty on Linux), processes, services, event log (wevtutil)
  and journald, files, power actions, Wake-on-LAN, updates (Windows Update Agent; apt, dnf/yum,
  pacman, zypper), self-update primitive (`agent.update`).
- Remote desktop helper: GDI / X11 capture with 64×64 tile diffing, JPEG/PNG tiles, flow
  control, mouse and keyboard injection (SendInput / XTEST), multi-monitor, clipboard paste,
  Ctrl-Alt-Del; launched in the console session (session 0 → user or SYSTEM token) or as the
  X11 session owner.

### Web console
- React + TypeScript SPA: dashboard, devices with overview / terminal / desktop / processes /
  services / event log / files / software / patches / runs / events tabs, scripts editor,
  runs, tasks with cron editor, automations, alerts and rules, patches, users, audit,
  settings, account (password, TOTP).

### Tooling
- Makefile, `tools/build.sh`, `tools/build.ps1` (cross-compile for windows/amd64,
  windows/arm64, linux/amd64, linux/arm64 and linux/arm agents; release archives with
  checksums), GitHub Actions build and release workflow, Dockerfile (distroless, agents baked
  in) and docker-compose, deploy examples (systemd unit, Caddy, nginx, uninstall scripts).

[Unreleased]: https://github.com/MonsterCouch/homelab-rmm/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/MonsterCouch/homelab-rmm/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/MonsterCouch/homelab-rmm/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/MonsterCouch/homelab-rmm/releases/tag/v0.1.0
