# Changelog

All notable changes to Homelab RMM. The format follows [Keep a Changelog](https://keepachangelog.com/)
and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

Nothing yet.

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

[Unreleased]: https://github.com/MonsterCouch/homelab-rmm/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/MonsterCouch/homelab-rmm/releases/tag/v0.1.0
