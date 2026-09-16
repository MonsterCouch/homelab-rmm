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
internal/baselines              desired-state param types, validation and limits, shared by both sides
internal/server                 config, TLS, db + migrations, auth, hub, api_*.go, runs, alerts,
                                scheduler, patches, baselines, mail, relay (shell + desktop), static,
                                install, seed
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
`enrollAgent` creates the device (or re-keys an offline device with the same hostname + OS) and
consumes one of the token's uses **in a single transaction**: the decrement is a conditional
`UPDATE ... WHERE uses_left > 0` that must affect exactly one row, so simultaneous enrolments
cannot stretch a one-use token past one device or drive the count negative (`-1` means unlimited
and is left alone; every other value `<= 0` reads as exhausted, migration 2 repairs rows an older
server damaged, and `POST /api/enroll` clamps `uses` on the way in). `enrollAgent` reports back
what it did: a re-key is audited as `agent.rekeyed` rather than `agent.enrolled`, and an
enrolment that collides with a hostname a device is currently *using* — which gets its own record,
since only offline records are adopted — as `agent.duplicate_hostname`. Both add a row to the
device's event timeline. The server then
answers with a `welcome` frame containing `agent_id` and a 32-byte random `agent_key`. The agent persists both and from then on sends
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

- `t` — message type. Agent → server: `hello`, `inventory`, `metrics`, `event`, `baseline`,
  `pong`, `reply`, `stream`. Server → agent: the request names below.
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
`desktop.start`, `wol`, `agent.update`, `agent.config`, `baseline.evaluate`,
`baseline.remediate`, `baseline.preview`. The agent runs every request on its own
goroutine (`Agent.dispatch` → `handle`), so a long update scan never blocks a keystroke, and a
handler panic is turned into an error reply.

Timeouts on the server side: 30 s for quick requests, 2 min for inventory refresh, 15 min for a
patch scan, 3 h for a patch install, 20 min for long file operations. Script timeouts are per
script (default 300 s) and enforced by the agent, which kills the whole process tree.

`baseline.evaluate` and `baseline.remediate` reply with an **ACK only**
(`{"accepted":true,…}`): the pass itself arrives as exactly one unsolicited `baseline` frame, so a
reply carrying the report as well would double every transition, alert and automation.
`baseline.preview` is the one exception — its reply *is* the report, and no frame follows, because
nothing about a preview is stored.

`protocol.Version` (currently 1) is sent in `hello`; the server accepts older agents. The
agent build version from `hello` is stored on the device and shown in the console.

## 4. Server subsystems

### Hub (`hub.go`)
Owns every live agent socket, routes replies and stream chunks by id, and fans `hubEvent`s
(`agent_online`, `agent_offline`, `metrics`, `inventory`, `event`, `alert`, `run`, `patches`,
`baseline`)
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
(pattern match — these are the events an agent *emits*, and the only kind it emits today is
`patch`; **no** platform feeds the Windows Event Log or journald into the engine, so the event
log is pull-only), run failures, patch failures, and a 30-second sweep for `offline` rules that is
time-based so a device that vanished while the server was down is still caught. `sustained`
implements "condition true for N minutes"; `dedupe_key = rule:agent:extra` keeps one open alert
per condition; `auto_resolve` closes it when the condition clears; a device in maintenance mode
(`maintenance_until` in the future) opens nothing. Opening an alert broadcasts to the UI, emails
(when `notify_email`) and fires `alert_opened` automations.

Drift alerts come in through `openDrift`, not `open`: `rule_id` is NULL, `rule_kind` is `drift` and
the severity is the check's, but the dedupe SELECT, the maintenance-window suppression, the SSE
broadcast and the `alert_opened` automation are the same. `drift` is deliberately **not** in
`validRuleKinds` — that map gates operator-created rows in `alert_rules`, and a drift alert has no
rule. `openDrift` is always called with `notify = false` (the baseline engine sends one digest per
(agent, baseline) instead of one mail per check), and nothing but the baseline code resolves a
`drift` key: `purge` auto-closes only `script_failed`, `patch_failed` and `event`.

### Scheduler (`scheduler.go`)
One `robfig/cron` table (5-field expressions plus `@hourly`-style descriptors, local time) rebuilt
from `tasks` and `patch_policies` on every change. Task kinds: `script`, `patch_scan`,
`patch_install`, `reboot`, `inventory`, each resolved against `Targets` (`all`, agent ids, group
ids, tags, OS). Automations are evaluated by trigger (`agent_online`, `agent_offline`,
`alert_opened`, `alert_resolved`, `enrolled`, `reboot_required`, `patch_installed`,
`drift_detected`, `drift_fixed`) with an optional target/rule/severity filter and run a script,
send an email or POST a JSON webhook. The two drift triggers carry no `rule_id`, so a `rule_ids`
filter never matches one.

`agent_online` fires from `scheduler.agentOnline` when a device's socket comes up (the same call
that releases its queued runs); `agent_offline` fires when that device's **current** socket goes
away, at the end of `Hub.handleAgentWS`.
A socket that has already been replaced by a reconnect does not fire it — only the connection
the hub still holds for that id declares the device offline — and `enrolled` fires at enrolment
rather than when the enrolling socket eventually drops. What none of them have is a grace
period: a Wi-Fi drop that reconnects produces `agent_offline` and then `agent_online`, a
half-open socket is only noticed when the 30 s keepalive has missed pongs for 90 s, and a server
restart looks like every device going offline and coming back. For "offline for N minutes"
semantics use an `offline` **alert rule** (`Minutes`, default grace 5) with an `alert_opened`
automation: `sweepOffline` is time-based, runs every 30 s and measures from `last_seen`, so it
also catches a device that vanished while the server was down. Keep `agent_offline` for things
that are safe to do on a flap. Each automation is capped at `maxAutomationFiresPerMinute` (60)
fires a minute by `autoLimit`, and a skipped fire is logged at WARN, so neither a flapping fleet
nor an `alert_opened` → `run_script` loop can run away.

An hourly `purge` enforces retention (metrics 30 d, runs 90 d, events and `baseline_history`
30 d, audit and resolved alerts 365 d by default), expires tokens and sessions, and fails runs stuck in `running` for over
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

"No longer reported ⇒ installed" only runs for a scan that reported **no** error. The agent's
error text is kept in `last_patch_scan_error:<agent>` and served as `scan_error`, and an agent
that could not enumerate one of its sources (an apt index that would not refresh, a winget that
resolved and then failed) sets it: an empty list from a broken source is otherwise
indistinguishable from "everything is up to date", which would mark every row of that source
installed and resolve its alerts.

On Windows a scan reports three things. Applicable Windows updates, with `downloaded`
(IsDownloaded) so the console can tell an already-staged cumulative update from one that still has
to come down the wire. The last 200 `IUpdateSearcher::QueryHistory` entries that installed
successfully, as `installed` rows — the only record of what a freshly enrolled device already has,
since a pending update it never offered can never "disappear" from a later scan (an id that is
still pending wins over its history entry, so an update waiting for a reboot stays pending); the
`installed_at` of such a row is when this server first saw it, not the device's own install date,
because the wire format carries no per-update timestamp. And `winget upgrade` rows,
`source = 'winget'`, which are **informational**: the agent service account cannot install them,
so they are excluded from `all:true` approvals, from a policy's `all` mode and from "install
everything approved". An explicitly requested winget id comes back as a per-id failure and the
rest of the batch still installs — one unsupported id never fails a whole batch. The SYSTEM
account's winget view also differs from the logged-in user's (per-user package registrations), so
the list is not what that user sees in a terminal.

### Baselines (`baselines.go`, `baselines_db.go`, `api_baselines.go`)
Desired state. `agentConfig` resolves the enabled baselines whose targets match a device and sends
the **complete** set in every config push and in `welcome` — never a delta — after the
`agent_defaults` settings blob is unmarshalled, so a baseline set can never be frozen into
settings and pushed to the whole fleet. Every create/update/delete/enable/disable pushes to the
union of the previously and newly matched online devices; so does a group, tag or group-delete
change.

Ingest arrives as `TypeBaseline` through `ac.enqueue` (the inventory/event path — 5 s push-back
then a warning, never the droppable metrics path, because the frame is the only record of an
offline pass). One `withTx` per report: version and monotonic-`TS` guards, membership re-read
inside the transaction, results for unknown, negative or repeated check ids dropped, upsert,
history rows for real transitions. Alert opens/resolves, `drift_detected`/`drift_fixed`
automations, the digest mail and the `baseline` SSE event all run **after** the commit — the alert
engine and `sched.automation` take the same single SQLite connection.

`baselines.version` is bumped only by changes the agent can see and the bump, the check writes and
the `stale = 1` marking of existing results happen in one transaction. A save is a **merge**:
check ids are permanent (`AUTOINCREMENT`, so a deleted id never comes back and inherits the dead
check's results and alerts), and a check dropped from the body takes its results and its open
drift alerts with it. `internal/baselines` is the single definition of every kind's parameters,
used by the server to validate a write (unknown keys are a 400) and by the agent to re-validate at
evaluation time (unknown keys ignored, so an older agent keeps working).

### Relays (`relay.go`)
- **Shell**: the browser WebSocket `/ws/shell/{id}` sends `open`/`in`/`resize`/`close`; the
  server streams `shell.open` to the agent and forwards `ShellChunk`s back as `out`. The agent
  runs the shell in a pseudo-terminal (ConPTY on Windows, `creack/pty` on Linux).
- **Desktop**: `/ws/desktop/{id}` creates a single-use random token, asks the agent for
  `desktop.start {token, quality}`, waits up to 45 s for the helper to connect to
  `/ws/desktop-agent?token=…`, then bridges the two sockets frame for frame (binary tiles one
  way, JSON input the other) without decoding video. `docs/DESKTOP-PROTOCOL.md` has the frame
  formats and how the helper is launched in session 0 / X11.

Both relays check that the WebSocket `Origin` host equals the request `Host`, and both **end
with a Close frame** rather than by dropping the socket, so the browser gets a code instead of
1006: a peer that closed cleanly has its code forwarded, a peer that vanished without one is
reported as 1011 with a reason naming it, and the desktop viewer's pre-bridge failures (no
graphical session, helper never connected, request cancelled) close the same way.

### Auth (`auth.go`)
bcrypt passwords, TOTP (`pquerna/otp`), 14-day session tokens in `sessions`, cookie `rmm_session`
(`HttpOnly`, `SameSite=Strict`, `Secure` unless `--insecure`), a non-empty `X-Requested-With`
header required on every non-GET API call (only its presence is checked — a cross-site form
cannot set any custom header; the console sends `fetch`), a 10-per-minute login limiter per client IP, roles `admin` / `tech`
(no users or settings) / `viewer` (read-only — `requireWrite` also covers `/ws/shell/{id}`,
`/ws/desktop/{id}`, the file download and `GET /api/enroll`, whose body carries token values).
Changing your own password deletes your other sessions. The three `/api/auth/*` endpoints sit on
the outer mux, outside `requireUser`, so `authGuard` gives them the same CSRF check plus an
`Origin`/`Host` match and a JSON `Content-Type` requirement. `clientIP` uses the peer address and
reads `X-Forwarded-For` only when the peer is inside one of `Server.trustedProxies`
(`--trusted-proxies`); it then scans the hop list right-to-left past hops that are themselves
trusted proxies, because the proxies in `deploy/` append to the header rather than replacing it,
which makes the left-most hop attacker-chosen. While the user table is empty, `Server.setupCode`
(a random hex value minted in `New`, printed at startup) is required by `POST /api/auth/setup`
from every source address including loopback, and `Server.setupMu` makes the "no users yet?"
check and the insert one step so a first-run window cannot create two administrators.

### Static UI (`static.go`)
Serves `web/dist` from the embedded filesystem (or `--dev-web DIR`), immutable caching for
`/assets/`, and falls back to `index.html` for client-side routes.

### Agent binaries and install scripts (`install.go`)
`GET /api/agent-download/{file}` serves `rmm-agent-<os>-<arch>[.exe]` from `<data>/agents/`, then
`<dir of rmm-server>/agents/`, then `<dir of rmm-server>/`, unauthenticated (the binary is not a
secret; enrolment still needs a token — and the install script checks what it downloaded).
`GET /install/{token}?os=windows|linux&arch=` renders the bootstrap script with the public URL,
token, certificate fingerprint, public-key pin and `agentBinarySHA256` baked in (one hash per
architecture for Linux, where `uname -m` decides). The script verifies that hash before it runs
the binary and pins the download connection to the server certificate, so the unauthenticated
download endpoint is not an unverified one. The script itself is piped into a root shell, so its
inputs are whitelisted before they reach it: the token must match `^[A-Za-z0-9_-]{16,64}$` and
still pass `checkEnrollToken` (404 otherwise), `arch` must be one of `amd64|arm64|arm|386` (400
otherwise), and every interpolated value goes through `psQuote` / `shQuote` for the single-quoted
literal it lands in (`render` substitutes `@@NAME@@` placeholders in one pass, so a value cannot
introduce another).

### Seed data (`seed.go`)
On a fresh database `seedDefaults` inserts the starter script library (17 scripts across
Maintenance, Diagnostics, Updates, Security, Users), seven alert rules, the `Servers` and
`Workstations` groups and a scan-only patch policy. It runs once (`settings.seeded = 1`) and only
fills empty tables, so deleted defaults stay deleted.

The two starter baselines run from their **own** guard (`settings.seeded_baselines` plus an empty
`baselines` table), because every v0.1.0 database already has `seeded = 1` and reusing that key
would mean the seeds never appeared on upgrade. Both ship disabled *and* unenforced, and every
destructive check in them (`group_members`, the SMB1 registry value, service start-type changes,
`reboot_pending`) ships `remediate = 0`.

## 5. Storage

SQLite through `modernc.org/sqlite` (pure Go, so everything cross-compiles with `CGO_ENABLED=0`).
`openDB` sets WAL journaling, `busy_timeout=5000`, foreign keys on, `synchronous=NORMAL`, and one
connection (`SetMaxOpenConns(1)`) because SQLite is single-writer. Migrations are the `migrations`
slice in `db.go`, applied in order and tracked in `PRAGMA user_version`.

| Table | Purpose | Notable columns |
|---|---|---|
| `settings` | key/value config: `public_url`, `smtp`, `agent_defaults`, `retention`, `seeded`, `seeded_baselines`, `last_patch_scan:<agent>`, `last_patch_scan_error:<agent>` | |
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
| `patches` | per-device update inventory, `(agent_id, patch_id)` | `status` (`available`, `approved`, `installing`, `installed`, `failed`, `ignored`), `severity` (listed worst-first by an explicit rank, not by the TEXT column's own order; Windows reports the MSRC ratings, apt/dnf/zypper report `security`, which ranks with `Important` so a distro's security updates are never the rows a `LIMIT` drops), `categories` (always a JSON array), `source`, `downloaded`, `description` |
| `patch_policies` | scan/install schedules | `scan_schedule`, `install_schedule`, `mode`, `reboot` |
| `audit` | who did what | `user`, `ip`, `action`, `target`, `details` |
| `agent_events` | the device event timeline: `patch` progress lines pushed by the agent, `enrol` and `drift` rows written by the server. Monitored-service state is **not** here — it rides in each metrics sample and reaches operators through the alert engine | `kind`, `message`, `fields` |
| `baselines` | desired-state definitions | `targets` (JSON), `enforce`, `interval_sec`, `enabled`, `version` |
| `baseline_checks` | the checks of a baseline | **`id INTEGER PRIMARY KEY AUTOINCREMENT`** (identity is permanent), `position` (presentation only), `kind`, `params` (JSON), `remediate`, `severity`, `os_filter`, `timeout_sec` |
| `baseline_results` | current state per (device, check) | `state`, `expected`, `observed`, `detail`, `fixed`, `version`, `stale`, `checked_at` (device clock), `received_at` / `since` (server clock) |
| `baseline_state` | per (device, baseline) ingest bookkeeping | `version`, `last_report_ts`, `last_received_at`, `last_trigger` |
| `baseline_history` | every state transition | denormalised `check_name`; `agent_id` and `check_id` carry **no** FK, so history outlives a deleted device or check |

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
- `scripts.go` — writes the body to a private temp directory (0700) with the right extension,
  launches the interpreter with the parameters as positional arguments, sets `RMM_RUN_ID`, streams
  lines as they arrive, and enforces timeout and cancel by killing the process **tree**: on Windows
  `taskkill /T /F /PID` with `os.Process.Kill` as the fallback (`proc_windows.go`), on Linux the
  process group. Kill-on-close job objects exist only for PTY shell sessions (`shell_windows.go`),
  not for script runs. The run directory is removed afterwards — with a retry, because Windows can
  still hold the script file a moment after the interpreter exits — and directories orphaned by a
  killed agent are swept at start-up. Four details are worth knowing:
  - **Interpreters.** On Windows every one is an absolute path, never a bare name resolved from
    PATH (the agent runs as SYSTEM; see `systemExe` in `exec_windows.go`): `pwsh` from its Program
    Files install, else `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`; `cmd.exe`
    through `systemExe`; python from `%SystemRoot%\py.exe`, then the
    `SOFTWARE\Python\PythonCore\*\InstallPath` keys, then the machine PATH. Because the agent runs
    as LocalSystem it inherits the *machine* PATH only, so a per-user Python — the python.org and
    Store default — is invisible to it: install Python, or at least its `py.exe` launcher, for all
    users. `bash` is the exception: it has no fixed location on Windows (Git Bash, WSL) and is
    still taken from PATH. Elsewhere `pwsh`, `python3`/`python` and `bash` → `sh` come from PATH.
  - **Encoding.** A `.ps1` is written with a UTF-8 BOM, because Windows PowerShell 5.1 reads a
    BOM-less script in the ANSI code page and mangles every non-ASCII character in it. Captured
    output that is not already valid UTF-8 is decoded from the OEM code page (`winDecodeOutput`),
    and python runs with `PYTHONIOENCODING=utf-8`. A `.cmd` body gets no BOM — cmd.exe would echo
    it as part of the first line — and cmd reads a batch file in the console code page, so a batch
    body should stay ASCII; use `powershell` for anything else.
  - **Arguments are data.** For `cmd` the command line is built by hand with cmd.exe's own quoting
    rules, and a value containing `"`, `%`, `!` or a newline is refused with an error: cmd re-parses
    those whatever the quoting, and exec's `\"` escape would let a parameter start a second command
    as SYSTEM that appears in no script body.
  - **Limits.** Each stream keeps 1 MiB in the final result and marks the cut with
    `[output truncated]`; everything is streamed either way, and the server stores whichever of the
    streamed and the final copy is longer. Windows exit codes are sign-extended, so `exit -1` reads
    `-1` rather than `4294967295`.
- `baseline*.go` — the desired-state engine. One goroutine per process: passes never overlap, the
  next pass is scheduled an interval after the previous one *finished*, every check runs under its
  own deadline enforced by the engine (so a check wedged in a syscall cannot stop the device), and
  remediation is serialised by a process-wide mutex that `package`/`windows_feature`/
  `reboot_pending` fixes share with `installUpdates`. `baselines.json` beside `agent.json`
  (0600, tmp+rename) holds the specs, the last report per baseline and the per-check fix
  hold-offs, and is loaded *before* the first connection so an offline device still evaluates; on
  reconnect the cached reports are re-sent exactly once with their original timestamps.
  `baseline_kinds.go` is the device-side layer over `internal/baselines`; the per-OS work lives in
  `baseline_linux.go` / `baseline_windows.go`, with the pure parsers and planners split out
  (`baseline_group.go`, `baseline_winparse.go`) so they are unit-tested on any build host.
- `shell*.go` — pseudo-terminal sessions; `services_*.go`, `proc_*.go`, `eventlog_*.go`,
  `updates_*.go`, `power_*.go`, `files.go`, `wol.go` — the per-feature handlers;
  `platform_other.go` documents the contract each platform file fulfils.
  `eventlog_windows.go` reads channels through `wevtutil /uni:true` (UTF-16, so text outside the
  system ANSI code page is not folded to "?") and falls back to a second `/f:XML` pass whenever
  wevtutil warns that it could not render a record, because `/f:RenderedXml` drops such records
  while still exiting 0. Page sizes, the fixed search window and the level vocabulary are the
  cross-platform contract in [API.md](API.md#event-log).
- `update.go` — `agent.update` **requires** a 64-hex SHA-256 and a URL that is `https`, or plain
  `http` only against the configured server's own host, and refuses both before it fetches
  anything: what this installs runs as SYSTEM/root, and the TLS client pins nothing when the
  agent has no fingerprint. It then downloads over that client, verifies the hash, swaps the
  binary next to the running one and exits so the service manager restarts it (no server-side
  trigger exists yet).
- `desktop/` — see `docs/DESKTOP-PROTOCOL.md`.

## 7. Configuration resolution

Server: flags → `RMM_*` environment (`RMM_DATA_DIR`, `RMM_LISTEN`, `RMM_PUBLIC_URL`,
`RMM_CERT_FILE`, `RMM_KEY_FILE`, `RMM_INSECURE`, `RMM_DEV_WEB_DIR`, `RMM_DEBUG`) applied on top
(`Config.FromEnv`). `rmm-server install` bakes the flags it was given into the service definition.
Default data directory: `%ProgramData%\HomelabRMM` on Windows, `/var/lib/homelab-rmm` as root,
`~/.homelab-rmm` otherwise.

Agent: `agent.json` in `RMM_AGENT_DIR`, else `%ProgramData%\HomelabRMM` or `/etc/homelab-rmm`.
Fields: `server_url`, `agent_id`, `key`, `enroll_token`, `fingerprint`. `baselines.json` sits
beside it and is written by the agent only — the desired-state specs, the last report per baseline
and the fix hold-offs — so that a device that reboots while the server is unreachable still
evaluates. A file that will not parse is logged and ignored, never fatal.

## 8. Versioning

`internal/server.Version` and `internal/agent.Version` default to `dev` and are stamped at build
time with `-ldflags "-X …=v1.2.3"` (Makefile, `tools/build.sh`, `tools/build.ps1`, CI). The
server reports its version in `/api/auth/state`, `/api/system` and the dashboard; agents report
theirs in `hello`.
