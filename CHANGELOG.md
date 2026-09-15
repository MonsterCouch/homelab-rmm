# Changelog

All notable changes to Homelab RMM. The format follows [Keep a Changelog](https://keepachangelog.com/)
and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

Nothing yet.

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
  token that matches `^[A-Za-z0-9_-]{16,64}$` *and* could still enrol a device; anything else is
  a 404. `?arch=` must be one of `amd64`, `arm64`, `arm`, `386` or the request is a 400, and the
  public URL, token and fingerprint are escaped for the single-quoted literal they are
  interpolated into. Previously the token path segment went into the script verbatim, so a
  crafted URL could add commands to a script that is piped into `bash` or `iex` as root.
  Responses are `Cache-Control: no-store`.
- **Viewers can no longer open a terminal, a remote desktop session, download a file or read an
  enrolment token.** `GET /ws/shell/{id}`, `GET /ws/desktop/{id}`,
  `GET /api/agents/{id}/fs/download` and `GET /api/enroll` are behind the same write check as
  everything else and return 403 for the `viewer` role. The enrolment listing carries the token
  *values*, which are all anyone needs to add a device of their own to the fleet. Directory
  listings and the rest of the read-only console are unchanged.
- **Enrolment tokens are consumed atomically.** The use count is decremented with a conditional
  `UPDATE` inside the transaction that creates the device record. Concurrent enrolments on a
  one-use token previously produced one device per racing agent and left `uses_left` negative,
  which reads as "unlimited" forever. `-1` is now the only non-positive value that still enrols:
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
- **A re-enrolment that takes over an existing offline device record is audited as
  `agent.rekeyed`**, logged at WARN with the source address and written to that device's event
  timeline, so a reinstall and a machine claiming another's hostname are no longer both filed as
  `agent.enrolled`. An enrolment that collides with a hostname a device is currently *using* is
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
  enrolment token as well as the device identity.

### Documentation
- **README no longer promises a download that does not exist.** There is no `v*` tag yet, so the
  quick starts now open with how to get the archives today (`make all && make package`, or the
  CI `dist` artefact) and the License section states plainly that no `LICENSE` file has been
  chosen — which is what the archives' placeholder already said. `docs/DEVELOPMENT.md` lists both
  as blockers for the first release.
- **The enrolment token's real lifecycle is documented.** README said the agent "never uses the
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
- Agent hub: outbound WebSocket per device, enrolment tokens (uses, expiry, group), per-device
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
  enrolment, reboot and patch events.
- Patch management: scan/approve/ignore/install with live log, policies with scan and install
  schedules, approved / all / security modes, reboot never / if required / always.
- Relays: browser terminal over a pseudo-terminal, remote desktop bridge with single-use helper
  tokens.
- Device tools: processes, services, event log / journal, file browser with upload and
  download, power actions, Wake-on-LAN via a peer agent on the same subnet.
- Enrolment: install scripts for Windows (PowerShell) and Linux (bash) served per token; agent
  binaries served from `<data>/agents/` or beside the executable.
- Seed data on first start: 17 starter scripts (Windows PowerShell and Linux bash) across
  Maintenance, Diagnostics, Updates, Security and Users; seven default alert rules; `Servers`
  and `Workstations` groups; a scan-every-6-hours patch policy.
- Retention purge (metrics, runs, events, audit, resolved alerts, tokens, sessions).

### Agent (Windows, Linux)
- Service install with certificate pinning by SHA-256 fingerprint, reconnect with backoff,
  identity kept across reinstalls, automatic re-enrolment after key revocation.
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

[Unreleased]: https://github.com/MonsterCouch/homelab-rmm/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/MonsterCouch/homelab-rmm/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/MonsterCouch/homelab-rmm/releases/tag/v0.1.0
