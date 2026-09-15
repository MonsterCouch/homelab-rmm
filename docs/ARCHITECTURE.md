# Architecture

Homelab RMM is two Go binaries and a React single-page application. This document describes how
they fit together; the wire types in `internal/protocol/protocol.go` and the route table in
`internal/server/api.go` are the source of truth when the two disagree.

## 1. Components

```
 browser ──HTTPS/WSS──▶ rmm-server ◀──WSS (outbound from device)── rmm-agent (service, SYSTEM/root)
   SPA + SSE               │ ▲                                        │
                           │ └────── WSS /ws/desktop-agent ────── rmm-agent desktop-helper
                        SQLite                                      (interactive session)
```

| Component | Where | Role |
|---|---|---|
| `rmm-server` (`cmd/rmm-server`, `internal/server`) | one binary, Windows service / systemd / Docker | HTTPS listener (`:8443`), embedded web UI, JSON API, agent WebSocket endpoint, SQLite store, alert engine, scheduler, mailer, relays |
| `rmm-agent` (`cmd/rmm-agent`, `internal/agent`) | every managed device, as SYSTEM or root | keeps one outbound WebSocket, pushes inventory and metrics, answers requests (scripts, shell, files, services, updates, power, desktop) |
| desktop helper (`rmm-agent desktop-helper`, `internal/agent/desktop`) | spawned by the agent inside the interactive session | captures the screen and injects input; connects back to the server on its own socket |
| web UI (`web/`) | built to `web/dist`, embedded with `go:embed` (`web/embed.go`) | React 18 + TypeScript, xterm.js terminal, uPlot charts |
| `internal/protocol` | shared | envelope and every message type |
| `internal/svc` | shared | `kardianos/service` wrapper: install/uninstall/start/stop as a Windows service or systemd unit |

### Repository layout

```
cmd/rmm-server, cmd/rmm-agent   entry points, flag parsing, service specs
internal/protocol               wire types (envelope, requests, replies)
internal/server                 config, TLS, db + migrations, auth, hub, api_*.go, runs, alerts,
                                scheduler, patches, mail, relay (shell + desktop), static, install, seed
internal/agent                  agent core (agent.go, conn.go, config.go), per-feature files with
                                _windows.go / _linux.go implementations; platform_other.go is the contract
internal/agent/desktop          capture, tiling, input injection, session launch, helper TLS
internal/svc                    service manager wrapper
web/                            SPA source; web/dist is embedded
tools/                          build.sh, build.ps1
deploy/                         systemd unit, Caddy/nginx examples, uninstall scripts
docs/                           this folder
```

## 2. Connection model

**Outbound only.** The agent dials `wss://<public-url>/ws/agent`; the server never connects to a
device. The public URL comes from `--public-url` / `RMM_PUBLIC_URL`, else the `public_url`
setting, else `https://<hostname>:<port>` (`Server.PublicURL`).

**Certificate pinning.** On first start the server writes a self-signed ECDSA P-256 certificate
(`server.crt`/`server.key`, 10-year validity, SANs: hostname, LAN IPv4 addresses, `localhost`,
`127.0.0.1`, the public-URL host) and logs its SHA-256 fingerprint. The install script hands that
fingerprint to `rmm-agent install`, which stores it in `agent.json`. `agent.TLSConfig` then
verifies the peer certificate against the pin and nothing else (`InsecureSkipVerify` with a
`VerifyPeerCertificate` callback). An empty fingerprint means "use the system trust store", which
is what you want with a CA-issued certificate or a TLS-terminating proxy.

**Enrolment → per-agent key.** The first connection carries `X-Enroll-Token`. The server checks
the token before upgrading the socket (`checkEnrollToken`), waits for the `hello` frame, then
`enrollAgent` creates the device (or re-keys an offline device with the same hostname + OS),
decrements the token's uses and answers with a `welcome` frame containing `agent_id` and a
32-byte random `agent_key`. The agent persists both and from then on sends
`Authorization: Bearer <key>`; the server stores only `sha256(key)`. A revoked key (device
deleted) makes the agent drop its identity and re-enrol if it still has a token.

**Liveness.** The hub pings every 30 s and drops a socket silent for 90 s; the agent reconnects
with exponential backoff from 2 s to 60 s plus jitter. A new socket for the same agent id replaces
the old one. `agents.online` in the database is a convenience; the hub's in-memory map is
authoritative and the API overlays it.

**After hello** the server pushes `agent.config` (metrics interval, inventory interval, monitored
services) from the `agent_defaults` setting and the device's `monitored_services`. The agent
sends inventory immediately, then metrics every 30 s and inventory hourly by default.

## 3. Wire protocol

Every frame is a JSON `Envelope`:

```json
{"t": "script.run", "id": "a1b2", "d": { ... }, "err": ""}
```

- `t` — message type. Agent → server: `hello`, `inventory`, `metrics`, `event`, `pong`, `reply`,
  `stream`. Server → agent: the request names below.
- `id` — correlation id chosen by the server; the agent echoes it in every `stream` and in the
  final `reply`.
- `d` — type-specific payload; `err` — error text in a reply instead of `d`.

Three interaction shapes, all implemented in the hub (`internal/server/hub.go`):

| Shape | Hub method | Example |
|---|---|---|
| request / reply | `Hub.Request(ctx, agent, type, in, &out)` | `proc.list`, `fs.read`, `updates.scan` |
| request / stream… / reply | `Hub.Stream(agent, type, in, sink)` | `script.run` (stdout/stderr chunks), `shell.open` (terminal output) |
| fire and forget | `Hub.Notify(agent, type, in)` | `shell.input`, `shell.resize`, `script.cancel`, `agent.config` |

Request catalogue (`protocol.Req*`): `ping`, `inventory.refresh`, `shell.open/input/resize/close`,
`script.run`, `script.cancel`, `proc.list`, `proc.kill`, `svc.list`, `svc.action`, `updates.scan`,
`updates.install`, `eventlog.query`, `fs.list/read/write/delete/mkdir/rename`, `power`,
`desktop.start`, `wol`, `agent.update`, `agent.config`. The agent runs every request on its own
goroutine (`Agent.dispatch` → `handle`), so a long update scan never blocks a keystroke, and a
handler panic is turned into an error reply.

Timeouts on the server side: 30 s for quick requests, 2 min for inventory refresh, 15 min for a
patch scan, 3 h for a patch install, 20 min for long file operations. Script timeouts are per
script (default 300 s) and enforced by the agent, which kills the whole process tree.

`protocol.Version` (currently 1) is sent in `hello`; the server accepts older agents. The
agent build version from `hello` is stored on the device and shown in the console.

## 4. Server subsystems

### Hub (`hub.go`)
Owns every live agent socket, routes replies and stream chunks by id, and fans `hubEvent`s
(`agent_online`, `agent_offline`, `metrics`, `inventory`, `event`, `alert`, `run`, `patches`)
out to browser subscribers of `GET /api/events` (Server-Sent Events). Slow SSE consumers drop
events rather than block the agent loop.

### Runs (`runs.go`)
`runTracker.Start` records a `script_runs` row and streams `script.run` to the agent, keeping live
stdout/stderr (up to 2 MB each) in memory so the UI can tail a run before it finishes. A library
script sent to an offline device is stored as `queued` and released by `releaseQueued` when the
device connects; ad hoc bodies are not persisted and therefore cannot be queued. Exit code ≠ 0,
an agent error or a timeout marks the run `failed`/`timeout` and feeds the alert engine.

### Alert engine (`alerts.go`)
Rules (`alert_rules`) are loaded into memory and re-read whenever one is saved. Inputs: every
metrics sample (cpu, memory, disk per mount, monitored services, pending reboot), agent events
(pattern match), run failures, patch failures, and a 30-second sweep for `offline` rules that is
time-based so a device that vanished while the server was down is still caught. `sustained`
implements "condition true for N minutes"; `dedupe_key = rule:agent:extra` keeps one open alert
per condition; `auto_resolve` closes it when the condition clears; a device in maintenance mode
(`maintenance_until` in the future) opens nothing. Opening an alert broadcasts to the UI, emails
(when `notify_email`) and fires `alert_opened` automations.

### Scheduler (`scheduler.go`)
One `robfig/cron` table (5-field expressions plus `@hourly`-style descriptors, local time) rebuilt
from `tasks` and `patch_policies` on every change. Task kinds: `script`, `patch_scan`,
`patch_install`, `reboot`, `inventory`, each resolved against `Targets` (`all`, agent ids, group
ids, tags, OS). Automations are evaluated by trigger (`agent_online`, `agent_offline`,
`alert_opened`, `alert_resolved`, `enrolled`, `reboot_required`, `patch_installed`) with an
optional target/rule/severity filter and run a script, send an email or POST a JSON webhook.
(`agent_offline` is accepted by the API and UI but, as of 0.1.0, nothing calls
`scheduler.automation("agent_offline", …)` when a socket drops: use an `offline` alert rule
plus an `alert_opened` automation for the same effect.) An
hourly `purge` enforces retention (metrics 30 d, runs 90 d, events 30 d, audit and resolved
alerts 365 d by default), expires tokens and sessions, and fails runs stuck in `running` for over
six hours after a restart.

### Patches (`patches.go`)
`patchScan` asks the agent for `updates.scan` and reconciles the `patches` table: new ids become
`available`, known ones are refreshed (keeping `approved`/`ignored`/`installing`), ids no longer
reported become `installed`. `patchInstall` marks the chosen ids `installing`, sends
`updates.install` (progress arrives as `patch` events) and records `installed`/`failed` per id,
raising `patch_failed` alerts and `patch_installed` automations. A policy's install run first
scans, then approves according to `mode` (`approved` = only what you approved, `all`,
`security` = Critical/Important severity, a Security category, or a package from apt, dnf or
pacman), installs, and
reboots per `reboot` (`never`, `if_required`, `always`). A device with no patch rows gets a scan
20 s after its first connection.

### Relays (`relay.go`)
- **Shell**: the browser WebSocket `/ws/shell/{id}` sends `open`/`in`/`resize`/`close`; the
  server streams `shell.open` to the agent and forwards `ShellChunk`s back as `out`. The agent
  runs the shell in a pseudo-terminal (ConPTY on Windows, `creack/pty` on Linux).
- **Desktop**: `/ws/desktop/{id}` creates a single-use random token, asks the agent for
  `desktop.start {token, quality}`, waits up to 45 s for the helper to connect to
  `/ws/desktop-agent?token=…`, then bridges the two sockets frame for frame (binary tiles one
  way, JSON input the other) without decoding video. `docs/DESKTOP-PROTOCOL.md` has the frame
  formats and how the helper is launched in session 0 / X11.

Both relays check that the WebSocket `Origin` host equals the request `Host`.

### Auth (`auth.go`)
bcrypt passwords, TOTP (`pquerna/otp`), 14-day session tokens in `sessions`, cookie `rmm_session`
(`HttpOnly`, `SameSite=Strict`, `Secure` unless `--insecure`), `X-Requested-With: fetch` required
on every non-GET API call, a 10-per-minute login limiter per client IP, roles `admin` / `tech`
(no users or settings) / `viewer` (read-only). `X-Forwarded-For` is honoured for the audit log
and the limiter, so the server should only be reachable through a proxy you control when one is
used.

### Static UI (`static.go`)
Serves `web/dist` from the embedded filesystem (or `--dev-web DIR`), immutable caching for
`/assets/`, and falls back to `index.html` for client-side routes.

### Agent binaries and install scripts (`install.go`)
`GET /api/agent-download/{file}` serves `rmm-agent-<os>-<arch>[.exe]` from `<data>/agents/`, then
`<dir of rmm-server>/agents/`, then `<dir of rmm-server>/`, unauthenticated (the binary is not a
secret; enrolment still needs a token). `GET /install/{token}?os=windows|linux&arch=` renders the
bootstrap script with the public URL, token and fingerprint baked in.

### Seed data (`seed.go`)
On a fresh database `seedDefaults` inserts the starter script library (17 scripts across
Maintenance, Diagnostics, Updates, Security, Users), seven alert rules, the `Servers` and
`Workstations` groups and a scan-only patch policy. It runs once (`settings.seeded = 1`) and only
fills empty tables, so deleted defaults stay deleted.

## 5. Storage

SQLite through `modernc.org/sqlite` (pure Go, so everything cross-compiles with `CGO_ENABLED=0`).
`openDB` sets WAL journaling, `busy_timeout=5000`, foreign keys on, `synchronous=NORMAL`, and one
connection (`SetMaxOpenConns(1)`) because SQLite is single-writer. Migrations are the `migrations`
slice in `db.go`, applied in order and tracked in `PRAGMA user_version`.

| Table | Purpose | Notable columns |
|---|---|---|
| `settings` | key/value config: `public_url`, `smtp`, `agent_defaults`, `retention`, `seeded`, `last_patch_scan:<agent>` | |
| `users`, `sessions` | operators and their cookies | `role`, `totp_secret`, `totp_enabled`, `expires_at` |
| `groups` | device groups | unique `name` |
| `enroll_tokens` | bootstrap tokens | `uses_left` (-1 unlimited), `expires_at`, `group_id` |
| `agents` | one row per device | `key_hash`, `os`, `platform`, `arch`, `tags` (JSON), `custom_fields` (JSON), `inventory` (JSON snapshot), `last_metrics` (JSON), `monitored_services`, `maintenance_until`, `pending_reboot` |
| `metrics` | time series, `(agent_id, ts)` primary key, WITHOUT ROWID | `cpu`, `mem_used`, `disks` (JSON), `net_rx/tx`, `load1`, `procs` |
| `scripts` | library | `language`, `body`, `params` (JSON `[{name, description, default, required}]`), `timeout_sec`, `os_filter` |
| `script_runs` | executions | `status` (`queued`, `running`, `done`, `failed`, `timeout`, `cancelled`), `trigger` (`manual`, `task`, `automation`), `args`, `stdout`, `stderr` |
| `tasks` | scheduled/manual jobs | `kind`, `script_id`, `targets` (JSON), `schedule` (cron), `options` (JSON), `next_run` |
| `automations` | event → action | `trigger`, `filter` (JSON), `action`, `action_params` (JSON) |
| `alert_rules`, `alerts` | rules and open/acked/resolved alerts | `kind`, `params` (JSON), `severity`, `dedupe_key`, `notified` |
| `patches` | per-device update inventory, `(agent_id, patch_id)` | `status` (`available`, `approved`, `installing`, `installed`, `failed`, `ignored`), `severity`, `categories`, `source` |
| `patch_policies` | scan/install schedules | `scan_schedule`, `install_schedule`, `mode`, `reboot` |
| `audit` | who did what | `user`, `ip`, `action`, `target`, `details` |
| `agent_events` | unsolicited agent events (service changes, patch progress, log lines) | `kind`, `message`, `fields` |

Metric queries bucket by time in SQL (`MetricsRange`) so a 30-day chart never ships a million
rows.

## 6. Agent internals

- `agent.go` — connect/reconnect loop, hello/welcome, config push, timers, dispatcher.
- `conn.go` — pinned TLS dialer and a mutex-serialised writer (gorilla/websocket allows one
  writer).
- `inventory.go`, `metrics.go` — gopsutil plus per-platform extras (`inventory_windows.go`:
  WMI/registry for manufacturer, serial, installed software, antivirus, pending-reboot registry
  keys; `inventory_linux.go`: DMI, `/etc/os-release`, dpkg/rpm/pacman package lists,
  `reboot-required` / `needs-restarting`).
- `scripts.go` — writes the body to a temp file with the right extension, launches the
  interpreter (`pwsh` → `powershell.exe`; `cmd.exe /d /c`; `python3`/`python`/`py`; `bash` → `sh`)
  with parameters as positional arguments, sets `RMM_RUN_ID`, streams lines, enforces timeout and
  cancel by killing the process group / job.
- `shell*.go` — pseudo-terminal sessions; `services_*.go`, `proc_*.go`, `eventlog_*.go`,
  `updates_*.go`, `power_*.go`, `files.go`, `wol.go` — the per-feature handlers;
  `platform_other.go` documents the contract each platform file fulfils.
- `update.go` — `agent.update` downloads a binary over the pinned TLS client, verifies SHA-256,
  swaps it next to the running one and exits so the service manager restarts it (no server-side
  trigger exists yet).
- `desktop/` — see `docs/DESKTOP-PROTOCOL.md`.

## 7. Configuration resolution

Server: flags → `RMM_*` environment (`RMM_DATA_DIR`, `RMM_LISTEN`, `RMM_PUBLIC_URL`,
`RMM_CERT_FILE`, `RMM_KEY_FILE`, `RMM_INSECURE`, `RMM_DEV_WEB_DIR`, `RMM_DEBUG`) applied on top
(`Config.FromEnv`). `rmm-server install` bakes the flags it was given into the service definition.
Default data directory: `%ProgramData%\HomelabRMM` on Windows, `/var/lib/homelab-rmm` as root,
`~/.homelab-rmm` otherwise.

Agent: `agent.json` in `RMM_AGENT_DIR`, else `%ProgramData%\HomelabRMM` or `/etc/homelab-rmm`.
Fields: `server_url`, `agent_id`, `key`, `enroll_token`, `fingerprint`.

## 8. Versioning

`internal/server.Version` and `internal/agent.Version` default to `dev` and are stamped at build
time with `-ldflags "-X …=v1.2.3"` (Makefile, `tools/build.sh`, `tools/build.ps1`, CI). The
server reports its version in `/api/auth/state`, `/api/system` and the dashboard; agents report
theirs in `hello`.
