# Homelab RMM

Homelab RMM is a self-hosted remote monitoring and management tool for a home lab: the
scripting, patching and automation of NinjaOne plus the remote desktop of ScreenConnect, in
spirit, without the per-endpoint invoice. The server is **one Go binary** with the web console,
API, SQLite database and agent endpoint inside; it runs as a Windows service or a systemd unit,
or in Docker. Agents for Windows and Linux connect **outbound** over a single WebSocket, so
devices behind NAT or on Wi-Fi need no inbound ports, and pin the server certificate so a
self-signed setup is safe.

## Features

- **Monitoring** — CPU, memory, disk, network, load and process count every 30 s (configurable),
  charted per device with 30 days of history; monitored services with state alerts.
- **Inventory** — OS and kernel, hardware (CPU cores/threads, memory, manufacturer/model/serial,
  BIOS), disks, network interfaces with MACs, installed software, GPUs, logged-in users, pending
  reboot, antivirus, timezone.
- **Alerting with email** — rules for CPU, memory, disk, offline, service state, reboot required,
  script and patch failures and event-log patterns; sustained thresholds, auto-resolve,
  acknowledge, maintenance mode per device, SMTP notifications (STARTTLS, implicit TLS or plain).
- **Scripting** — PowerShell, cmd, bash, sh and python bodies, a script library with categories,
  parameters (defaults, required), timeouts and OS filters; live streamed output; run on one
  device, a group, a tag or everything; queued for offline devices; cron **scheduling**;
  **automations** on events (device online/offline, alert opened/resolved, enrolled, reboot
  required, patch installed, baseline drift detected/fixed) that run a script, send an email or
  call a webhook.
- **Patch management** — Windows Update (WUA) on Windows; apt, dnf/yum, pacman and zypper on
  Linux; scan, approve, ignore, install with live log, reboot policy, scheduled scan and install
  policies with approved / all / security-only modes.
- **Baselines** — desired state with drift detection and self-healing: a named list of checks
  (service, package, registry, file, command, local group members, firewall, time sync, sysctl,
  Windows feature, pending reboot, disk free) assigned by group, tag or OS. Agents evaluate on
  their own interval, **offline too**, report every pass, and — when the baseline is *enforced*
  and the check allows it — fix the drift themselves. Drift opens an alert and fires
  `drift_detected` / `drift_fixed` automations; a dry-run preview shows what a draft would do
  before you save it. Fleet and per-device compliance scores.
- **Remote terminal** — PowerShell, cmd, bash or sh in a real pseudo-terminal (ConPTY on Windows)
  from the browser.
- **Remote desktop** — screen streaming with tile diffing, mouse and keyboard, multi-monitor,
  clipboard paste, Ctrl-Alt-Del; works on the logon screen and UAC prompts on Windows; X11 on
  Linux.
- **Device tools** — processes (kill), services (start/stop/restart/enable/disable), Windows
  event log and journald viewer, file browser with upload/download/rename/delete, reboot,
  shutdown, lock, log off, and **Wake-on-LAN** relayed through another agent on the same subnet.
- **Organisation** — groups, tags, custom fields, notes, display names.
- **Users** — admin / tech / viewer roles (a viewer looks at everything and changes nothing: no
  writes, and no terminal, remote desktop, file download or enrolment token either), TOTP
  two-factor authentication, session management, password reset from the CLI.
- **Audit log** of every action with user and source address.

## Screenshots

_Coming soon: dashboard, device overview, remote desktop, script run with live output._

> **Releases.** [v0.1.0](https://github.com/MonsterCouch/homelab-rmm/releases/tag/v0.1.0) is
> published, so the download links in the two quick starts below resolve: each
> `homelab-rmm-<os>-<arch>.zip`, the linux `.tar.gz` files and `SHA256SUMS` are attached to it,
> and `releases/latest/download/...` always points at the newest tagged version. That is the
> *released* version, not `main` — [CHANGELOG.md](CHANGELOG.md) says what is in each one, and
> baselines (desired state, drift detection, self-healing) arrive in 0.2.0. To run something
> newer than the latest tag, produce the archives yourself — see
> [Building from source](#building-from-source):
> `make all && make package` writes exactly the `dist/homelab-rmm-<os>-<arch>.zip` /
> `.tar.gz` the quick starts unpack (server, `agents/`, docs, `deploy/`, `SHA256SUMS`) — or take
> the `dist` artefact from the newest green run of the
> [Build workflow](https://github.com/MonsterCouch/homelab-rmm/actions/workflows/build.yml).
> Everything after the download step is exactly as written.

## Quick start (Windows server)

1. Download `homelab-rmm-windows-amd64.zip` (or `-arm64`) from the
   [releases](https://github.com/MonsterCouch/homelab-rmm/releases) page (see the note above for
   which version that is, and how to build a newer one).
2. Extract it to `C:\Program Files\HomelabRMM`. You get `rmm-server.exe` and an `agents\` folder
   with the agent binaries for every platform; the server serves those to devices you enrol.
3. From an **elevated** PowerShell:

   ```powershell
   cd 'C:\Program Files\HomelabRMM'
   .\rmm-server.exe install --public-url https://rmm.lan:8443
   New-NetFirewallRule -DisplayName 'Homelab RMM' -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
   ```

   `install` checks the configuration, registers the Windows service **HomelabRMMServer**
   (automatic start, restart on failure) and starts it. Data lives in `%ProgramData%\HomelabRMM`
   (`rmm.db`, `server.crt`, `server.key`, `server.log`). `--public-url` is the address agents will
   use; it goes into every install command and into the certificate's names. Omit it and the
   server uses `https://<hostname>:8443`. Other flags: `--listen :8443`, `--data DIR`,
   `--cert/--key` for your own certificate, `--insecure` for plain HTTP behind a reverse proxy,
   `--trusted-proxies IP,CIDR,...` to name that proxy so its `X-Forwarded-For` is believed (it is
   ignored otherwise, and every request is then audited as coming from the proxy).
4. Open `https://rmm.lan:8443` (or `https://<hostname>:8443`). The certificate is self-signed and
   generated on first run, so the browser warns once. Either accept the exception or trust it:
   the certificate covers the machine's hostname, its LAN IPs at generation time, `localhost` and
   the `--public-url` host, and you can import `%ProgramData%\HomelabRMM\server.crt` into the
   *Trusted Root Certification Authorities* store
   (`certutil -addstore -f Root "$env:ProgramData\HomelabRMM\server.crt"` from an elevated
   prompt; Firefox keeps its own store, use *Accept the risk* or *Settings → Certificates → View
   → Servers → Add Exception*).
5. The first visit shows the setup form: create the admin account (add an email if you want
   alert mail later). Turn on two-factor under *Account*.

   Because nobody is signed in yet, a server with no users mints a **one-time setup code** and
   prints it at startup — to the console and as a `WARN` line in `server.log` in the data
   directory:

   ```
   ==== FIRST-RUN SETUP CODE: 3f9a1c07 ====
   ```

   The form **always** asks for it, including from a browser on the server itself: that account
   is root on every device you go on to enrol, and a connection from `127.0.0.1` could equally be
   a reverse proxy relaying the LAN, another program on the box, or a web page you happen to have
   open. Reading the code is the thing that proves it is you. Lost it? Restart the server before
   anyone creates a user and it prints a new one; once the admin exists the code is neither
   minted nor asked for again.
6. **Devices → Enrol**: create an enrolment token (name, optional group, number of uses, expiry),
   copy the Windows or Linux one-liner and run it on each machine you want to manage:
   - Windows, elevated PowerShell:
     `[Net.ServicePointManager]::ServerCertificateValidationCallback={$true}; iex ((New-Object Net.WebClient).DownloadString('https://rmm.lan:8443/install/<token>?os=windows'))`
     (append `&arch=arm64` for Windows on ARM)
   - Linux, any shell: `curl -fsSk 'https://rmm.lan:8443/install/<token>?os=linux' | sudo bash`

   The device appears in the console within seconds. The one-liners are explained under
   [Enrolling devices](#enrolling-devices).
7. Optional: *Settings → Email* for alert notifications, *Settings → Retention*, *Alerts → Alert rules*
   (seven sensible rules are created for you), *Scripts* (a starter library is there).

Managing the service later: `rmm-server.exe start | stop | restart | status | uninstall`
(elevated). Users from the CLI: `rmm-server.exe user add --username alice --role tech`,
`user passwd --username alice`, `user list` (`--data DIR` if you moved the data directory).

## Quick start (Linux server)

**Binary + systemd** (the `curl` line fetches the newest tagged release; to run something newer
than that, unpack the archive `make package` built, or the CI `dist` artefact, into
`/opt/homelab-rmm` instead)

```bash
curl -LO https://github.com/MonsterCouch/homelab-rmm/releases/latest/download/homelab-rmm-linux-amd64.tar.gz   # or -arm64
sudo mkdir -p /opt/homelab-rmm && sudo tar -xzf homelab-rmm-linux-amd64.tar.gz -C /opt/homelab-rmm
cd /opt/homelab-rmm
sudo ./rmm-server install --public-url https://rmm.lan:8443
```

`install` registers and starts the systemd unit **HomelabRMMServer** (`systemctl status
HomelabRMMServer`). As root the data directory is `/var/lib/homelab-rmm`; as a normal user it
is `~/.homelab-rmm`. The agent binaries are found in `agents/` next to the executable (or in
`<data>/agents/`). Then continue from step 4 above. `deploy/homelab-rmm-server.service` is an
alternative unit with a dedicated user and systemd hardening.

**Docker**

```bash
git clone https://github.com/MonsterCouch/homelab-rmm && cd homelab-rmm
# edit RMM_PUBLIC_URL in docker-compose.yml
docker compose up -d --build
```

The image (`Dockerfile`, distroless, runs as a non-root user) has the server at `/rmm-server`
and every agent binary in `/agents/`, so enrolment works out of the box. Data is the `/data`
volume. Details and a bind-mount variant are in `docker-compose.yml` and
[docs/OPERATIONS.md](docs/OPERATIONS.md).

## Enrolling devices

An enrolment token (Devices → Enrol) is the only secret a new device needs. Tokens expire
(24 h by default), have a use count (1 by default, unlimited possible) and can pre-assign a
group. The console prints two commands per token:

- The **Windows** one-liner downloads the install script from `/install/<token>?os=windows`,
  which downloads `rmm-agent-windows-<arch>.exe` from `/api/agent-download/`, places it at
  `C:\Program Files\HomelabRMM\rmm-agent.exe` and runs `rmm-agent.exe install --server <url>
  --token <token> --fingerprint <sha256>`. That writes `%ProgramData%\HomelabRMM\agent.json` and
  registers the Windows service **HomelabRMMAgent**. Re-running it **over a running agent** is
  supported: the script stops the service and waits for it to report `Stopped`, waits for
  `rmm-agent.exe` to actually exit, then retries the file swap for a few seconds, because Windows
  will not let you overwrite an executable that is still mapped. `install` itself stops the old
  service and waits for it to disappear before registering the new one, rather than tripping over
  `ERROR_SERVICE_MARKED_FOR_DELETE`.
- The **Linux** one-liner does the same with `curl` and `bash`: binary at
  `/opt/homelab-rmm/rmm-agent`, config at `/etc/homelab-rmm/agent.json`, systemd unit
  **HomelabRMMAgent**. The architecture (amd64, arm64, armv7) is detected from `uname -m`.

The script is served only for a **live enrolment token** — anything else is a 404 — and only for
an architecture this project ships, so the URL cannot be used to push arbitrary text into the
root shell it is piped to.

Both commands skip certificate validation for the **one fetch of the install script**, because
the device has never seen the server's self-signed certificate. Everything after that is pinned:
the script downloads the agent over a connection pinned to the server's certificate (its public
key, on Linux), checks the binary's **SHA-256** against the hash the server rendered into the
script and refuses to install on a mismatch, and passes the certificate's SHA-256 **fingerprint**
to the agent, which from then on refuses to talk to anything else. See
[docs/SECURITY.md](docs/SECURITY.md) for why the first fetch is acceptable on a LAN and what to
do if it is not for you.

On first connection the agent presents the token, the server creates the device record and
issues a per-device key; the agent stores the key in `agent.json` (mode 0600) and authenticates
with it from then on. A reinstall on a host with the same name and OS replaces the old record
instead of creating a duplicate.

**The token stays in `agent.json` too** (`enroll_token`), and it is used again whenever the key
stops working: that is what makes the self-healing in
[Troubleshooting](#troubleshooting) — `unknown agent key` — work, and it has two consequences
worth knowing before you choose the token's *Uses* and expiry.

- A token created with more than one use (the console offers "unlimited") sits on the disk of
  **every** device it enrolled, readable by root/SYSTEM there, until it expires (24 h by
  default). Prefer a single-use token per machine; keep the expiry short.
- **Deleting a device in the console does not keep it away.** The agent notices its key was
  rejected and re-enrols with the stored token within seconds — as a *new* record, with a new
  id and no history. To remove a device for good, uninstall or stop the agent first (see
  *Agent install, uninstall, update*), then delete it; or wait for the token to expire, or
  exhaust its uses, before deleting. The re-enrolment is visible in the audit log as
  `agent.enrolled` / `agent.rekeyed`.

**Manual install** (no download step): copy `agents/rmm-agent-<os>-<arch>[.exe]` from the
release archive to the device and run, elevated:

```
rmm-agent install --server https://rmm.lan:8443 --token <token> --fingerprint <sha256 hex>
```

The fingerprint is shown on the Enrol page and printed in `server.log` at startup. Omit
`--fingerprint` only when the server certificate is signed by a CA the device already trusts.
`--no-service` writes the config without registering a service (development).

## Baselines

A **baseline** is a named list of checks that says how a device should look, assigned with the same
target model as tasks and alert rules. Agents evaluate their assigned baselines on their own
interval — **offline too** — and report every pass. When the baseline is **enforced** and the check
allows remediation, the agent fixes the drift itself and reports the check as `fixed`; otherwise it
reports `fail` and leaves the device alone.

Two baselines are seeded on first run, **disabled and unenforced**, with every destructive check
report-only: *Windows workstation hygiene* and *Linux server hygiene*. Read them, adjust them,
enable them; enforce them when you believe them.

Baselines → **New baseline**, then add checks with the typed forms (or raw JSON). Twelve kinds:
`service`, `package`, `registry`, `file`, `command`, `group_members`, `firewall`, `time_sync`,
`sysctl`, `windows_feature`, `reboot_pending`, `disk_free`. Each check carries a severity
(`info` reports but never opens an alert), an OS filter, a timeout and its own **remediate** flag —
so one baseline can fix the two things you trust it to fix and only report the other five.

**Preview on devices** dry-runs the draft on up to ten live devices before you save: it never fixes
anything, never writes to the device and never stores a result. It does *run* the draft's checks,
so previewing a draft that contains a `command` check needs the same **admin** role saving one
does.

A worked example — every SSH server must carry a hardening drop-in, and the agent must put it back:

```jsonc
POST /api/baselines
{
  "name": "SSH hardening",
  "targets": { "tags": ["ssh"], "os": "linux" },
  "enabled": true,
  "enforce": true,            // the agent will change these devices without asking
  "interval_sec": 3600,
  "notify_email": true,
  "checks": [
    { "name": "Hardening drop-in present",
      "kind": "file",
      "params": { "path": "/etc/ssh/sshd_config.d/99-rmm.conf",
                  "state": "present",
                  "content": "PermitRootLogin no\nPasswordAuthentication no\n",
                  "mode": "0644", "owner": "root:root" },
      "remediate": true, "severity": "critical", "os_filter": "linux", "timeout_sec": 30 },

    { "name": "sshd running and enabled",
      "kind": "service",
      "params": { "name": "ssh", "state": "running", "start_type": "auto" },
      "remediate": true, "severity": "critical", "os_filter": "linux", "timeout_sec": 60 },

    { "name": "Review members of sudo",
      "kind": "group_members",
      "params": { "group": "sudo", "allowed": ["ansible", "admin"], "mode": "subset" },
      "remediate": false, "severity": "warning", "os_filter": "linux", "timeout_sec": 30 }
  ]
}
```

Delete the drop-in on a device and, within the interval, the agent writes it back and the check
reports `fixed`. Take `"enforce": false` instead and the same drift reports `fail`, opens a drift
alert with the check's severity, and waits for you — the status view's **Remediate** button runs
the fixes on that one device on demand.

What that gets you:

- **Drift alerts** keyed `drift:<baseline>:<check>:<agent>`, resolved automatically when the check
  passes again. Severity comes from the check; `info` checks never open one.
- **Automations** on `drift_detected` and `drift_fixed` (run a script, send an email, POST a
  webhook). They carry no alert rule, so an automation filtered by alert rules never matches one.
- **Compliance**: per device, per baseline and fleet-wide, on the dashboard and on each device's
  **Compliance** tab — which works for an offline device, because its last known state is the whole
  point.
- A **history** of every transition per device, kept for the events retention period.

Two things to know before you switch `enforce` on. An enforced baseline changes machines with no
further confirmation, so the toggle asks you to confirm; and the `command` kind runs arbitrary code
as root/SYSTEM on every matched device, so a baseline containing one can only be created, edited or
previewed by an **admin** and is audited by name. Check parameters are readable by every signed-in user,
viewers included — put no secrets in them.

[docs/BASELINES.md](docs/BASELINES.md) has every kind's parameters and its exact refusals, the
state machine, the API and the console.

## Agent install, uninstall, update

| | Windows | Linux |
|---|---|---|
| Binary | `C:\Program Files\HomelabRMM\rmm-agent.exe` | `/opt/homelab-rmm/rmm-agent` |
| Config + log | `%ProgramData%\HomelabRMM\agent.json`, `agent.log` | `/etc/homelab-rmm/agent.json`, `agent.log` |
| Service | `HomelabRMMAgent` (runs as SYSTEM) | `HomelabRMMAgent.service` (runs as root) |
| Control | `rmm-agent.exe start\|stop\|restart\|status` | `rmm-agent start\|stop\|restart\|status` or `systemctl` |

- **Uninstall**: `rmm-agent uninstall` stops and removes the service and leaves `agent.json` in
  place (it holds the device identity). Delete the binary and the config yourself, or use
  `deploy/uninstall.ps1` / `deploy/uninstall.sh` (`-Purge` / `--purge` removes the config too).
  Then delete the device in the console so it does not linger as offline.
- **Update**: re-run the enrolment one-liner with a fresh token. It stops the service, swaps the
  binary and re-installs; because `agent.json` already exists for the same server, the device
  keeps its identity and history. Alternatively stop the service, replace the binary and start
  it. A push-from-console self-update is on the roadmap (the protocol already has
  `agent.update`).
- **Re-enrol** (after a server certificate change or a deleted device): run the one-liner
  again. An agent whose key was revoked on the server and that still has its original token
  re-enrols by itself.

## Upgrading the server

1. Stop the service (`rmm-server stop`, `systemctl stop HomelabRMMServer` or `docker compose down`).
2. Replace `rmm-server(.exe)` and the `agents/` folder with the new release (Docker: rebuild or
   pull, then `docker compose up -d`).
3. Start it. Database migrations run automatically at startup (`PRAGMA user_version`); the
   certificate, keys and settings are untouched, so agents reconnect without any action.

Agents keep working with a newer server; each device shows its agent version in the console
so you can see which ones are behind.

## Backup

Everything is in the data directory (`%ProgramData%\HomelabRMM`, `/var/lib/homelab-rmm`, or the
Docker `/data` volume):

- `rmm.db` (+ `rmm.db-wal`, `rmm.db-shm` while running) — all state;
- `server.crt`, `server.key` — the certificate agents pin. **Losing the key means every agent
  must be re-enrolled**;
- `agents/` — optional agent binaries;
- `server.log` — rotated at 20 MB to `server.log.1`.

Stop the service and copy the directory, or take an online copy of the database with
`sqlite3 rmm.db ".backup /path/rmm-backup.db"` and copy the certificate files. Restore by
stopping the service, putting the files back and starting it. More in
[docs/OPERATIONS.md](docs/OPERATIONS.md).

## Troubleshooting

- **Where are the logs?** Agent: `%ProgramData%\HomelabRMM\agent.log` or
  `/etc/homelab-rmm/agent.log` (rotated at 10 MB). Server: `server.log` in the data directory,
  also on stderr / `journalctl -u HomelabRMMServer` / `docker logs`. Set the environment variable
  `RMM_DEBUG=1` on either side for debug output.
- **The device never appears.** Check `agent.log`. `enrolment refused: token expired/exhausted`:
  create a new token. `connection refused` / timeouts: the device cannot reach the public URL on
  port 8443 (firewall on the server?). `rmm-agent status` shows whether the service is running.
- **`server certificate fingerprint mismatch` in agent.log.** The server's certificate changed
  (new install, regenerated or replaced certificate). Re-run the enrolment one-liner on the
  device, or edit `fingerprint` in `agent.json` and restart the agent. Set
  `fingerprint` to `""` to use the system trust store instead (only with a CA-signed certificate).
- **`unknown agent key`.** The device was deleted in the console. It re-enrols on its own if its
  `agent.json` still has a token that is valid; otherwise run the one-liner again.
- **Browser says the certificate is not valid for this name.** The name you typed is not in the
  certificate. Use one that is (hostname, IP), or set `--public-url` and delete
  `server.crt`/`server.key` so a new certificate is generated at the next start (agents enrolled
  before that need re-enrolling: new certificate, new fingerprint). Or bring your own certificate
  with `--cert/--key`.
- **Locked out.** `rmm-server user passwd --username <you>` sets a new password, clears the
  user's sessions **and disables that user's TOTP** (re-enrol the authenticator under *Account*
  afterwards). An admin can also reset another user's 2FA under *Users*, or create a new admin
  with `rmm-server user add`.
- **Remote desktop shows "Wayland sessions are not supported".** The Linux desktop is running
  Wayland; log in with an X11/Xorg session. On Windows the helper needs an interactive console
  session; the logon screen and UAC prompts are captured through the SYSTEM token.
- **Terminal fails to open.** The agent needs `powershell.exe`/`pwsh` (Windows) or `bash`/`sh`
  (Linux) on PATH. PowerShell scripts prefer `pwsh` and fall back to Windows PowerShell 5.1.
- **A Linux device shows no patches.** No supported package manager was found (apt-get, dnf,
  yum, pacman, zypper); the scan result carries the reason.
- **TOTP codes are rejected.** Clock drift: sync time on the server and on your phone.

## Security model (summary)

- Agents only make **outbound** connections and **pin** the server certificate by SHA-256
  fingerprint; enrolment tokens are single-use and expire; each device gets its own key, stored
  hashed on the server.
- Operators sign in with bcrypt-hashed passwords, optional TOTP, `HttpOnly` + `SameSite=Strict`
  session cookies (14 days), an `X-Requested-With` header on every state-changing request
  including sign-in and first-run setup (CSRF), same-origin checks on WebSockets, login rate
  limiting (10/min per IP) and roles. First-run setup always requires the one-time code the
  server prints at startup.
- The **console is root/SYSTEM on every enrolled device**. Keep it on the LAN or behind a VPN,
  turn on 2FA for every account and give day-to-day accounts the *tech* or *viewer* role.
- An **enforced baseline changes devices without asking**, and its `command` kind is arbitrary
  root/SYSTEM code. Enforcement is off by default, both seeded baselines ship disabled and
  report-only, a baseline containing a `command` check, a `file` check outside `/etc` or
  `ProgramData`, or an `allow_reboot` check needs the *admin* role, and the refusals that matter
  (never empty a privileged group, never change a boot-start driver, never stop the agent's own
  service, never write outside the allowed paths) are enforced on the **device**.
- The install one-liners disable certificate validation for the very first fetch only, so that a
  self-signed server can bootstrap; the agent binary is then hash-checked and pulled over a
  pinned connection, and the agent pins the certificate from then on.

The full threat model, what is and is not protected, and recommendations are in
[docs/SECURITY.md](docs/SECURITY.md).

## Roadmap

- Agent self-update pushed from the console (`agent.update` exists in the protocol; the
  server-side release manager does not yet).
- Wayland capture for the Linux remote desktop.
- macOS agent (the platform contract in `internal/agent/platform_other.go` is ready for it).
- Published container images and signed releases.
- More notification channels for alerts (webhooks are available through automations today).
- Script output search and run comparisons; software inventory diffing.

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | components, connection model, wire protocol, database schema, alert engine, scheduler, patch flow, desktop relay |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | paths, service control, logs, backup and restore, reverse proxies, custom certificates, retention, moving the server |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | dev loop, running an agent locally, tests, cross-compiling, adding a request type end to end |
| [docs/BASELINES.md](docs/BASELINES.md) | desired state: check kinds, the state machine, versions, ingest, the API and the console |
| [docs/SECURITY.md](docs/SECURITY.md) | threat model and recommendations |
| [docs/API.md](docs/API.md) | HTTP API and event stream |
| [docs/DESKTOP-PROTOCOL.md](docs/DESKTOP-PROTOCOL.md) | remote desktop wire format |
| [CHANGELOG.md](CHANGELOG.md) | release notes |

## Building from source

Go 1.26, Node 22. `make all` builds the UI and every binary into `dist/`; `make package` then
archives what `all` produced.

`make package` does **not** build the UI itself. The server binary embeds `web/dist`
(`web/embed.go`), and that directory is gitignored apart from a `.gitkeep`, so a server compiled
before the UI exists embeds one empty file, compiles without a warning and serves no console at
all. `make`, `tools/build.sh` and `tools/build.ps1` therefore refuse to build `rmm-server` when
`web/dist/index.html` is missing and tell you to run `make web` first; `ALLOW_EMPTY_WEB=1`
overrides that for a binary you intend to run with `--dev-web`. `tools/build.ps1` is the Windows
twin of the Makefile. See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## License

**Not settled yet.** The repository carries no `LICENSE` file, so no licence is granted — treat
the code as all rights reserved until one is added. The release archives ship a placeholder that
says the same (`tools/build.sh` writes it when `LICENSE` is absent); once the file exists it is
copied into every archive instead. It was still missing when 0.1.0 was tagged, so that release
carries the placeholder too; adding a real one is the outstanding licensing chore.
