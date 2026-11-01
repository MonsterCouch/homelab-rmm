# Operations

Day-two guide for running Homelab RMM. Everything here describes what the binaries actually do;
when in doubt, `rmm-server` and `rmm-agent` print their usage with no arguments.

## 1. Paths

### Server

| | Windows | Linux (root) | Linux (user) | Docker |
|---|---|---|---|---|
| Executable | wherever you extracted it, e.g. `C:\Program Files\HomelabRMM\rmm-server.exe` | e.g. `/opt/homelab-rmm/rmm-server` | same | `/rmm-server` |
| Data directory (`--data`, `RMM_DATA_DIR`) | `%ProgramData%\HomelabRMM` | `/var/lib/homelab-rmm` | `~/.homelab-rmm` | `/data` (volume) |
| Database | `<data>\rmm.db` (+ `-wal`, `-shm`) | | | |
| Certificate | `<data>\server.crt`, `server.key` (0600) | | | |
| Log | `<data>\server.log`, rotated to `server.log.1` at 20 MB; also stderr | | | `docker logs` + `/data/server.log` |
| Agent binaries served to devices | `<data>\agents\` first, then `agents\` beside the executable, then beside the executable | | | `/agents/` (baked in), `/data/agents/` overrides |
| Service | Windows service `HomelabRMMServer` | systemd `HomelabRMMServer.service` in `/etc/systemd/system/` | | container |

### Agent

| | Windows | Linux |
|---|---|---|
| Executable | `C:\Program Files\HomelabRMM\rmm-agent.exe` | `/opt/homelab-rmm/rmm-agent` |
| Config directory (`RMM_AGENT_DIR`) | `%ProgramData%\HomelabRMM` | `/etc/homelab-rmm` |
| Config | `agent.json`: `server_url`, `agent_id`, `key`, `enroll_token`, `fingerprint` | same |
| Config protection | a protected DACL on the config directory: `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators` only (see below) | mode `0700` on the directory, `0600` on `agent.json`, owned by root |
| Log | `agent.log`, rotated to `agent.log.1` at 10 MB | same |
| Service | `HomelabRMMAgent`, runs as LocalSystem, automatic start, restart on failure after 5 s | `HomelabRMMAgent.service`, runs as root, `Restart=always`, `RestartSec=5` |
| Script temp files | `%TEMP%\rmm-script-*` (deleted after the run) | `/tmp/rmm-script-*` |

On a Windows box that runs both the server and an agent they share `%ProgramData%\HomelabRMM`;
the file names do not collide.

**How the agent's files are protected on Windows.** Not by a Unix mode — Go's `0600` is ignored
there. The agent replaces the DACL of `%ProgramData%\HomelabRMM` at every start with a
*protected* one (inheritance from `%ProgramData%`, which grants `BUILTIN\Users` read, is
dropped), granting full control to `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators` and
inheritable by everything inside, so `agent.json` and `agent.log` are covered too. Check it with
`icacls C:\ProgramData\HomelabRMM`, not with a mode: the console's own file browser reports a
meaningless POSIX `-rw-rw-rw-` for Windows paths. A failure to apply it is logged as
`cannot restrict permissions on the agent directory`.

## 2. Service control

```
rmm-server install [--listen :8443] [--data DIR] [--public-url URL] [--cert F --key F] [--insecure]
                   [--trusted-proxies IP,CIDR,...]
rmm-server uninstall | start | stop | restart | status
rmm-agent  install --server URL --token TOKEN [--fingerprint HEX] [--no-service]
rmm-agent  uninstall | start | stop | restart | status
```

`install` re-registers an existing service (it uninstalls first), validates the configuration
by opening the data directory, database and certificate, and starts the service with the flags
you gave it. Change flags by running `install` again with the new set. Native tools work too:
`sc query HomelabRMMServer`, `systemctl status HomelabRMMServer`, `journalctl -u HomelabRMMAgent -f`.

**Where the binary sits is part of the install.** `install` registers the image it was run from
and copies nothing, and the service manager starts that exact file as LocalSystem (Windows) or
root (Linux) at every boot. It therefore has to live where only administrators can write —
`C:\Program Files\HomelabRMM`, `/opt/homelab-rmm` — or whoever can replace it owns the machine.
The install command the console prints already puts it there; a manual install (copy the binary,
run `install` by hand) must do it too. `rmm-agent install` inspects the location it is about to
register — the directory *and* the binary itself, by DACL on Windows and by owner and mode on
Linux — and prints a warning naming what is unprotected, the accounts that can write it and
where the binary belongs instead. It warns rather than refuses:
running the agent out of a build tree is normal while developing. `rmm-server install` does not
check, and the same rule applies to it.

Re-running `rmm-agent install` from a newer binary also refreshes the supervisor's active A/B slot (`bin/current/rmm-agent`) when its SHA-256 differs, so the service restarts on the new build rather than the previous slot copy.

Running in the foreground for a test: `rmm-server run --data ./tmp --listen :8443`. Every flag
has an environment twin (`RMM_LISTEN`, `RMM_DATA_DIR`, `RMM_PUBLIC_URL`, `RMM_CERT_FILE`,
`RMM_KEY_FILE`, `RMM_INSECURE`, `RMM_TRUSTED_PROXIES`, `RMM_DEV_WEB_DIR`), which is what the
Docker image and the example systemd unit use. `RMM_DEBUG=1` switches both binaries to debug logging (every API
request is logged with its duration).

### First run: creating the administrator

On first startup with no users in the database, navigate to the web console in your browser (e.g. `https://localhost:8443` or your configured public URL). The console presents the welcome setup form to create the initial administrator account.

- Concurrent setup requests do not race: the "no users yet?" check and the insert are atomic, so a first-run window produces exactly one administrator.
- Once the first administrator is created, first-run setup is closed and all subsequent visits route to `/login`.
- If you ever need to reset the administrator password or add users from the command line, use:
  ```
  rmm-server user passwd --username <name>
  rmm-server user add --username <name> --role admin
  ```

### Users from the command line

```
rmm-server user add --username alice --role admin|tech|viewer   # prompts for the password
rmm-server user passwd --username alice                          # new password; sessions cleared, TOTP disabled
rmm-server user list
```

Add `--data DIR` when the data directory is not the default. These commands open the database
directly and can run while the service is up (SQLite WAL with a 5 s busy timeout).

## 3. Logs and diagnostics

- **Server**: `server.log` in the data directory and stderr (journal / Event Log / `docker logs`).
  Startup prints `listening addr=… tls=… fingerprint=… data=… version=…`; the fingerprint line is
  what agents pin. Agent connects/disconnects, enrollments, alerts opened and tasks run are logged
  at info. Two `WARN` lines are worth alerting on: `agent record re-keyed by enrollment` (a device
  took over an existing, offline device record — see the audit note below) and `first-run setup refused`.
- **Agent**: `agent.log` in the config directory, on Windows as on Linux. `connected server=…
  agent_id=…` means all is well; `session ended err=… retry_in=…` shows why it is reconnecting.
  Two `WARN` lines matter: `agent key rejected, re-enrolling with stored token` (the server no
  longer knows this device's key — pair it with the server's `agent record re-keyed by
  enrollment`) and `server URL is plaintext` (the connection to the server is not encrypted; see
  `--insecure` below). `RMM_DEBUG=1` in the service's environment adds debug lines.
  On Windows the agent runs under the Service Control Manager, which gives the process **no
  standard handles at all** — stderr goes nowhere, so `agent.log` is the only copy. When the
  service dies before it can write anything, the SCM's own record is the fallback: the service
  is registered with `ERROR_CONTROL = NORMAL`, so a failed start is in the **System** event log
  as a Service Control Manager event 7000/7009 naming `HomelabRMMAgent` (`sc qc HomelabRMMAgent`
  shows the setting). On Linux the same lines also reach the journal
  (`journalctl -u HomelabRMMAgent`), and `/var/log/HomelabRMMAgent.err` on a host without
  systemd.
- **In the console**: *Settings → System* (`/api/system`) shows version, public URL,
  fingerprint, data directory, database size and connected agents; *Audit* lists every action
  with user and IP.
- **Per device**: *Events* tab (agent events: service changes, patch progress), *Runs* tab
  (script output), and the alert history.

## 4. Backup and restore

What to keep (all in the data directory):

| File | Why |
|---|---|
| `rmm.db` | every device, user, script, run, alert, setting |
| `server.crt`, `server.key` | the identity agents and the phone pin; without the key every agent must re-enroll (§6) |
| `agents/` | only if you placed agent binaries there |

**Cold backup** (simplest, always consistent): stop the service, copy the directory, start it.

**Hot backup** of the database while running: `sqlite3 rmm.db ".backup rmm-YYYYMMDD.db"`
(the SQLite CLI; on Windows download `sqlite3.exe`). Do not copy `rmm.db` alone while the server
runs — the `-wal` file holds recent writes.

**Restore**: stop the service, replace `rmm.db` (delete any stale `rmm.db-wal`/`rmm.db-shm`), put
`server.crt`/`server.key` back, start. Agents reconnect on their own because the certificate and
their keys are unchanged.

Docker: back up the `rmm-data` volume (`docker run --rm -v rmm-data:/data -v "$PWD":/backup
alpine tar czf /backup/rmm-data.tgz -C /data .`) with the container stopped, or run the
`sqlite3 .backup` inside a helper container.

## QUIC transport (optional)

By default agents talk to the server over WebSocket on the HTTPS port. QUIC is an opt-in second transport that gives each server request its own stream, so a stalled file transfer no longer delays a shell, and it survives an address change without reconnecting.

- **Enable:** start the server with `--quic` (or `RMM_QUIC=1`). `rmm-server install` passes the flag through. The UDP port is the HTTPS port unless you set `--quic-port N` (`RMM_QUIC_PORT`); the host is the one in `--listen`. Environment variables override flags.
- **Firewall:** allow inbound UDP on that port in addition to TCP. Agents never need an inbound port.
- **Not with `--insecure`, and not behind a reverse proxy:** QUIC always carries TLS 1.3 straight to the server, so the server refuses `--quic --insecure` at start, and Caddy or nginx in front of it cannot carry the UDP traffic. Such deployments stay on WebSocket.
- **Rollout:** an agent learns the port from the WebSocket `welcome`, stores it as `quic_port` in `agent.json`, and uses QUIC from its next session. The device header and `GET /api/agents` show the transport in use.
- **Fallback:** in the default `auto` mode, if the QUIC handshake fails (UDP blocked, no answer in 4 s) the agent falls back to WebSocket at once, records `quic_failed_at`, and does not try UDP again for 10 minutes. A refusal sent by the server (for example an unknown key) is not a transport failure and never triggers a fallback.
- **Agent override:** `RMM_TRANSPORT=websocket|quic|auto` (or `transport` in `agent.json`) wins over the default. `websocket` never dials UDP; `quic` always dials and never falls back, which is useful for testing. An unrecognised value logs a warning and means `auto`.
- **Notes:** devices connecting by QUIC are recorded with their UDP peer address, not an `X-Forwarded-For` value.

## Metrics storage (telemetry engines)

The per-device metrics series is the one table that grows by every device every few seconds, so it can live outside the SQLite file. Everything else (devices, alerts, audit, settings) always stays in `rmm.db`.

| Engine | Flag | Where | Use it when |
|---|---|---|---|
| `sqlite` | default | the `metrics` table in `rmm.db` | a homelab or a few hundred devices; nothing changes |
| `pebble` | `--telemetry pebble` | `<data dir>/telemetry/`, embedded, no second process | thousands of devices on one server; charts over 30 days stay fast |
| `clickhouse` | `--telemetry clickhouse --telemetry-dsn http://host:8123` | an existing ClickHouse server, over its HTTP interface | you already run ClickHouse, or want the series off the server's disk |

Environment variables win over flags, as for `run`: `RMM_TELEMETRY`, `RMM_TELEMETRY_DSN`, `RMM_TELEMETRY_USER`, `RMM_TELEMETRY_PASSWORD`. `rmm-server install` carries the engine, DSN and user into the service command line. The password never goes on the command line: `install` writes it (from `RMM_TELEMETRY_PASSWORD` or the DSN's `user:password@` part) to `<data>/telemetry.pass` in the restricted data directory, and the server reads that file at start unless `RMM_TELEMETRY_PASSWORD` is set. Reinstalling without a password keeps the stored file. An unknown engine, or ClickHouse without a DSN, is refused at start, and so is an unreachable ClickHouse. *Settings -> System* shows the engine and its size (`telemetry_engine`, `telemetry_bytes` on `GET /api/system`).

**Switching engines.** Stop the server first; the server now holds `<data dir>/rmm.lock` and both subcommands refuse with "stop the server first" while it is held.

```
rmm-server telemetry migrate --to pebble [--data DIR]
rmm-server telemetry migrate --to clickhouse --telemetry-dsn http://user:pass@clickhouse:8123 [--data DIR]
```

`migrate` copies every sample in time order in batches of 5000, prints progress every 50,000, and ends with the flags to start the server with. It never deletes the SQLite rows, so switching back is just removing the flag (samples written meanwhile stay in the other engine). Running it twice on Pebble is safe; ClickHouse must start empty and the command refuses a table that already holds rows. After you have run on the new engine for a while:

```
rmm-server telemetry drop-sqlite --telemetry pebble [--data DIR]
```

It refuses unless `--telemetry` or `RMM_TELEMETRY` names a non-SQLite engine, deletes in chunks, and leaves the `VACUUM` to you (`sqlite3 rmm.db VACUUM`, server stopped) because only that returns the space.

**ClickHouse setup.** Create a user that can create and write one table; the server creates `rmm_metrics` (`MergeTree`, ordered by agent and time) on first start. Use `http://` only on a trusted network, or `https://` with a certificate the server's system trust store accepts. Samples are batched (500 rows or one second) and retried, with up to 50,000 held in memory while ClickHouse is unreachable; retention runs as `ALTER TABLE ... DELETE` with `mutations_sync=1`. A plain MergeTree keeps a duplicate if two samples share an agent and timestamp. **This engine was tested against a fake of the HTTP protocol, not a live ClickHouse**, so try it on a copy first.

Backup: with `pebble`, copy `<data dir>/telemetry/` along with `rmm.db` while the server is stopped (section 4); ClickHouse is backed up by ClickHouse. PostgreSQL is not supported as the main database.

## Update cache (subnet mesh)

Devices on one subnet can fetch an agent update once across the WAN and share it over the LAN. Off by default. Enable it in *Settings -> Update cache* (admin): the switch, a port (default 7443, minimum 1024) and a cache size per leader (default 2 GiB, minimum 64 MiB). The setting is global; devices are still only ever grouped within one organization.

- **Who leads.** Devices of one organization sharing an IPv4 subnet (a /24 when the interface prefix is wider than /22) form a group of at least two. The server picks the longest-online device that reports it can serve (a writable cache directory and a bindable port) and re-checks every 60 s and on every online/offline event. Docker, WSL, Hyper-V and tunnel adapters are ignored. No multicast or mDNS is used.
- **What is cached.** Agent binaries, which is what `agent.update` fetches. Windows updates and winget packages are not: they come from Microsoft, where Delivery Optimization already shares on the LAN.
- **Firewall.** The leader listens on TCP and UDP (HTTP/3) on the port, on every interface. Allow that port inbound from the subnet only. The Windows agent adds its own rules (`remoteip=LocalSubnet`, through a hidden `netsh`) when it becomes leader and removes them when it stops; on Linux add the rule yourself.
- **Seeing it work.** A device's Overview shows an *Update cache* line with its role, hits and misses (a leader also shows bytes served and stored). The agent log and the `agent.update` reply say `cache <id> over h3`, `origin`, or `origin (the cache failed: ...)`. The console shows the same as a sentence ("Downloaded from the subnet cache (leader X over HTTP/3)", "Downloaded from the server", or the server with the reason the cache failed) under the update on the device's *Events* tab, and a fleet update summary counts devices by source. An agent too old to send the reply shows "Download source not reported". Devices updated through `update-all` (unsigned) are not counted in the summary.
- **When it fails.** The member falls back to the server on any error, so a dead leader costs a retry, not an update. Switching the feature off clears every assignment. The leader keeps `cache.crt`, `cache.key` and the store in the agent's config directory; deleting the store only costs a refill.

## Windows servicing repair

When Windows Update fails because the servicing stack or update catalog is damaged, an operator or a patch policy can run a repair (Windows only). The steps, in this fixed order: `dism_restore` (`DISM /Online /Cleanup-Image /RestoreHealth`, 60 min), `sfc` (`sfc /scannow`, 30 min, advisory), `reset_components` (stops `wuauserv`, `bits`, `cryptsvc`, `msiserver`, renames `SoftwareDistribution` and `catroot2` to `.bak.<time>`, restarts the services), `add_package` (a `.cab` or `.msu` with a SHA-256, through `DISM /Add-Package`; API only) and `rescan`. A failed step stops the rest, except `sfc`. Exit 3010 means a reboot is needed.

- **By hand:** device page -> *Patches* -> *Repair Windows servicing*. It goes through the signing flow in a signing organization. The last repair, with each step's result, shows below the patch list; `GET /api/agents/{id}/servicing` lists the history.
- **Automatically:** *Patches -> policy -> Repair Windows servicing = Automatic*. When a scan or install on a device under that policy returns a known servicing code (`0x80240020`, `0x80073712`, `0x800F081F`, `0x800F0922`, `0x800F0831`, `0x8024A105`, `0x80240034`, `0x80244022`, `0x8007000E`, `0x80070020`, and `0x80070002`/`0x80070003` from a Windows Update operation), the server runs `dism_restore`, `reset_components` and `rescan` once, waiting for the device's patch job. The limit is one automatic repair per device per 24 hours, and none while one runs. winget errors never start one.
- **Reboot:** a policy reboot of `if_required` or `always` becomes `if_required`; `never` stays `never`.
- **Signing organizations:** each enabled automatic policy adds a standing-approval unit (purpose `repair`) to *Review & sign*. Without a valid approval the agent refuses in enforce mode, the attempt is recorded as failed, and the cooldown is spent, so sign it before turning the policy on.
- **Alerts and audit:** an automatic repair raises `event` alerts (`servicing_started`, `servicing_finished`), writes an `agent_events` row, and audits `servicing.repair.auto` and `servicing.repair` under `policy:<name>`. It restarts the Windows Update services, so keep policy schedules outside the hours users are mid-update.

## Wayland screen capture (Linux)

On a Wayland session the desktop helper captures through the XDG ScreenCast portal and an in-process PipeWire client. The first session prompts the person at the machine to allow screen sharing; the restore token the agent saves makes later sessions silent. X11 sessions are unchanged.

- **`RMM_WAYLAND_PORTAL`.** Set in the agent service's environment. `0` turns the portal path off and the helper uses the Screenshot portal / X capture. Any other value, including `1`, unset or a typo, leaves it on.
- **What to look for.** Set `RMM_DEBUG=1` and read the agent log during a desktop session. `desktop: ScreenCast portal session ready` (with node and monitor counts) means the portal answered. `desktop: Wayland capture uses PipeWire` means the first frame arrived and PipeWire was chosen. `desktop: PipeWire capture disabled by RMM_WAYLAND_PORTAL=0` is the switch. `desktop: PipeWire capture unavailable; falling back to the Screenshot portal` (at start) and `desktop: PipeWire capture failed; falling back to the Screenshot portal` (later) carry an `err` field with the reason. `... failed and there is no X display to fall back to` means the session has no capture at all.
- **Fallback and retry.** A portal or stream error, a `Session.Closed` signal from the portal (share revoked, portal or compositor restarted), or a running stream that has sent no frame for 2 minutes switches to the Screenshot portal. A first frame that has not arrived after 2 seconds does not: an idle screen sends nothing, so capture just continues. While on the fallback the helper probes the portal again, after 30 seconds and then at doubling delays up to 10 minutes, and goes back to PipeWire when a probe works. It retries only when a restore token is saved, so no approval dialog appears unasked. A screen that stays idle for over 2 minutes looks the same as a stalled stream and also causes one switch to the fallback and back. Monitor sizes are corrected from the first frame of each stream (the portal reports logical sizes, the stream delivers pixels), and the monitor layout can differ between the two paths.
- **Input (`/dev/uinput`).** On Wayland, mouse and keyboard input goes through `/dev/uinput`, which is `root:root 0600` on Ubuntu and so not writable by the session user the helper runs as. On Linux, `rmm-agent install` writes `/etc/udev/rules.d/70-homelab-rmm-uinput.rules` containing `KERNEL=="uinput", GROUP="input", MODE="0660", TAG+="uaccess"` (loading the `uinput` module first if `/dev/uinput` is missing), then runs `udevadm control --reload-rules` and `udevadm trigger --name-match=uinput`. The `uaccess` tag makes logind give the active seat user an ACL on the device, so no group membership or re-login is needed. A failure here is a warning and does not fail the install; `rmm-agent uninstall` removes the rule. To do it by hand, create that file with that one line and run the two `udevadm` commands as root. The helper's `input needs /dev/uinput ... not writable` error means the rule is missing or has not been applied.
- **Status.** Verified on GNOME 50 and KDE Plasma 6.6 (Wayland, PipeWire 1.6.2, Ubuntu 26.04.1), at 100% and 200% display scaling. The first session needs the person at the machine to accept the share prompt once (GNOME: tick "remember this selection"; KDE: click the monitor tile in "Share screen with"); later sessions are silent on both. If nobody answers the prompt within 2 minutes the helper falls back to the Screenshot portal for that session. Not verified: compositors that offer only DMA-BUF, and multi-monitor. If it falls back on your machine, the `err` text is what the maintainers need.

## Terminal over WebRTC

`RMM_ICE_SERVERS` (comma-separated `url|user|credential` entries; default `stun:stun.l.google.com:19302`) now also reaches the agent for terminal sessions: the server puts the servers, TURN credentials included, in `shell.open`, so both ends can use a relay. If a direct path cannot be built within about 4 seconds, or breaks later, the terminal stays on or returns to the WebSocket relay without closing the session. The terminal status line reads `Connected · <shell> · WebRTC (direct)` or `Connected · <shell> · Relay`. A switch to WebRTC leaves a `shell.rtc` audit row and a "Terminal session upgraded to WebRTC" device event. Wire format: `docs/TERMINAL-PROTOCOL.md`.

## 5. Reverse proxy (`--insecure` behind Caddy or nginx)

You may prefer your own TLS termination (Let's Encrypt, an internal CA, one wildcard for the
lab). Run the server on plain HTTP bound to localhost and tell it its public name:

```
rmm-server install --insecure --listen 127.0.0.1:8080 --public-url https://rmm.example.lan \
  --trusted-proxies 127.0.0.1
```

Ready-made configurations: `deploy/Caddyfile` and `deploy/nginx.conf`. What matters:

- **WebSockets** on `/ws/agent` (one per device, open for days), `/ws/desktop-agent` (binary
  frames up to 32 MB), `/ws/shell/*` and `/ws/desktop/*`. nginx needs `proxy_http_version 1.1`
  and the `Upgrade`/`Connection` headers; both proxies need long read/send timeouts.
- **Server-Sent Events** on `/api/events` and streamed script output: disable response
  buffering (`proxy_buffering off`, Caddy `flush_interval -1`).
- **Host header** must be forwarded unchanged: browser WebSockets are accepted only when the
  `Origin` host matches `Host`.
- **`X-Forwarded-For`**: ignored unless you say where the proxy is. Pass
  `--trusted-proxies 127.0.0.1` (or `RMM_TRUSTED_PROXIES=127.0.0.1`) — a comma-separated list of
  IPs or CIDRs; a bare address means that host alone. Only when the connection *comes from* one
  of those is the header read at all, and then the server walks the hop list **from the right**,
  skipping addresses that are themselves trusted proxies, and takes the first one that is not.
  That is deliberate: `deploy/nginx.conf` uses `$proxy_add_x_forwarded_for` and Caddy appends by
  default, so what arrives is `<whatever the client sent>, <the address the proxy saw>` — the
  left-most hop is the client's own invention and only the right-most non-proxy hop is evidence.
  A hop that will not parse breaks the chain and the peer address is used instead. Without the
  flag every request behind the proxy is recorded as coming from the proxy and they all share one
  limiter bucket. Keep the list as narrow as the proxy actually is — anything that can reach the
  server from a trusted network can claim to be any client — and note that a CIDR with host bits
  set covers its whole network (`10.0.0.5/8` is all of `10.0.0.0/8`; the server logs a warning
  when you write one). The HTTP port still must not be reachable except through the proxy (bind
  to `127.0.0.1`, or firewall it).
- **Caddy**: `deploy/Caddyfile` shows the proxy side only. Add `--trusted-proxies 127.0.0.1` to
  the `rmm-server install` line there too, or every request is audited as coming from Caddy.
- **Body size**: file uploads to devices are raw request bodies; allow at least 32–64 MB.
- **Cookies**: with `--insecure` the session cookie is set without the `Secure` flag (the server
  cannot see the proxy's TLS). It is still `HttpOnly` and `SameSite=Strict`.
- **Docker, even without a proxy**: a container with a published port (`ports: - "8443:8443"`)
  never sees `127.0.0.1`. Requests from the Docker host itself arrive from the bridge gateway
  (`172.17.0.1`, or the compose network's gateway), so *that* is what the audit log records and
  what the login limiter buckets them under; requests from other machines normally keep their
  own address through the NAT rule. Do **not** trust the gateway with `RMM_TRUSTED_PROXIES`
  unless a reverse proxy really is the only thing that can reach the port — the setting means
  "believe `X-Forwarded-For` from here", and anything on the host would then be able to write any
  address into the audit log. When a proxy container does front the server, trust that
  container's address on the compose network and nothing wider.

**What `--insecure` means for agents.** With no certificate of its own the server has no
fingerprint; install commands carry an empty pin and agents validate the proxy's certificate
with the **device's system trust store**. That works with a public CA (Let's Encrypt) out of the
box, and with a private CA only after its root is installed on every device (Windows:
`certutil -addstore Root ca.crt`; Debian/Ubuntu: copy to `/usr/local/share/ca-certificates/` and
`update-ca-certificates`; RHEL family: `/etc/pki/ca-trust/source/anchors/` and
`update-ca-trust`). Alternatively pass the proxy certificate's fingerprint to `rmm-agent install
--fingerprint` by hand, remembering that it changes at every renewal (Let's Encrypt: every 60–90
days), which would strand the agents. Pinning only makes sense for a long-lived certificate.

**`--insecure` with no proxy in front is plain HTTP, all the way to the agent.** The one-liner a
server started that way prints carries an `http://` URL, and an agent configured with one dials
`ws://`: no TLS, no certificate check, no pin — a `fingerprint` in `agent.json` is not consulted
at all. Everything then travels in clear text, starting with the device key in the
`Authorization` header and including script bodies, shell traffic and file transfers. `rmm-agent
install` prints a warning when `--server` is an `http://` URL and the agent logs
`server URL is plaintext` at every start; neither refuses, because a loopback server
(`http://127.0.0.1:…`, a development rig) is a legitimate use of it. Anything reachable over a
network wants `https://`, whether from the server's own certificate or from a proxy in front
of it.

## 6. Certificates: names, custom files, rotation

### The names on the generated certificate

The self-signed pair is written **once** — on the first start that finds no `server.crt` in the
data directory — is valid for ten years, and is never re-issued. That long life is deliberate: a
certificate nobody has to renew is a pin nobody has to rotate. Its names are frozen at the moment
it is written:

| Source | What it puts in the certificate |
|---|---|
| always | `localhost`, `127.0.0.1` |
| `os.Hostname()` | the machine's **short** name (`RMM-HOST`), never an FQDN, and never a name only DNS knows |
| network interfaces | every non-loopback **IPv4** address the host had at that instant; IPv6 is filtered out entirely, so a tailnet `fd7a:…` address is never covered and a `100.x.y.z` one only if Tailscale was already up |
| `--public-url` / `RMM_PUBLIC_URL` | its host — **but only on the run that generates the certificate** |

That last row is the one that catches people. The flag seeds the `public_url` *setting* on first
run and the certificate is generated from the seeded value in the same start. Setting Public URL
afterwards from *Settings*, or adding the flag to an installation that already has a certificate,
changes what install commands and alert mail say and nothing on disk. The server does say so — in
the log, and only there. `checkCertHost` runs at startup, and again every time *Settings* is
saved, and the one line it writes — before the `listening` line — is the one that carries the
names actually in the certificate:

```
level=WARN msg="certificate does not cover the public URL" host=rmm.example.ts.net dns_sans="[localhost RMM-HOST]" ip_sans="[127.0.0.1 192.168.1.12]"
```

`dns_sans`/`ip_sans` is the whole SAN list, and that line is the only place it is printed. The
warning after `listening` carries the remediation sentence and no names at all:

```
level=WARN msg="certificate name mismatch" detail="the server certificate does not cover \"rmm.example.ts.net\": browsers report a name mismatch and an agent enrolled without a fingerprint pin refuses to connect. Supply your own certificate with --cert/--key, or delete server.crt and server.key from <data-dir> and restart to regenerate one (every agent must then re-pin the new fingerprint)."
```

The console shows neither. That same sentence is what `GET /api/system` returns as `cert_warning`,
but no page reads the field today: *Settings → System* lists version, public URL, fingerprint,
data directory, database size, uptime and agents connected, and says nothing about names. **A
quiet Settings page is not evidence that the certificate covers the name** — the startup log is
the place to look, or `cert_warning` from the API if you would rather script it.

**A name mismatch here is normal, and on its own it is not a fault.** Browsing to
`https://rmm.example.ts.net:8443` when the certificate says `localhost, 127.0.0.1, RMM-HOST,
192.168.1.12` gets you two complaints rather than one: an untrusted issuer *and*
a name that does not match (`ERR_CERT_COMMON_NAME_INVALID` in Chrome). Importing `server.crt`
into a trust store clears the first and never the second. Everything that pins — the agents, the
install scripts, the Android app — decides on the leaf's SHA-256 and on nothing else, so a pinned
client that ignores the hostname is behaving as designed; `docs/SECURITY.md` and `docs/ANDROID.md`
§2.2 rule 1 say why, before someone files it as a bug.

If a name has to be covered, it has to be there when the certificate is made: pass
`--public-url https://<the name you will actually use>` on the very first start, or regenerate
deliberately (below).

### Custom certificates (`--cert`/`--key`)

`--cert FILE --key FILE` (or `RMM_CERT_FILE`/`RMM_KEY_FILE`) replaces the generated certificate;
PEM, any key type Go's `tls` accepts. `install` resolves both to absolute paths, refuses one
without the other, and refuses a pair it cannot load. The server reports **this leaf's** SHA-256
as the fingerprint and puts it in every install command, so everything under "Rotating" below
applies to replacing these files too.

They are read **once**, at start, into a static TLS configuration: there is no `GetCertificate`
callback, no SIGHUP and no file watcher. Renewing a certificate in place therefore does nothing
at all until `rmm-server restart` — put the restart in whatever does the renewing.

### Rotating the certificate — every pin breaks at the same instant

To regenerate the built-in certificate (to cover a new name, or because the key is suspect):

1. Note the current fingerprint (*Settings → System*), so afterwards you can prove it changed.
2. Put the name you want covered into the **Public URL** *before* stopping: the certificate takes
   its extra name from the effective public URL, and the value saved in *Settings* wins over
   `--public-url` (the flag only seeds the setting on first run, and the server warns when the
   two disagree). Only if the setting has never been filled in does the flag decide.
3. `rmm-server stop`.
4. Move `server.crt` and `server.key` out of the data directory — keep them until the fleet is
   back, because putting them back is the only undo.
5. `rmm-server start`. The pair is regenerated on the way up, with the new name in it.
6. Read the new fingerprint from the startup line `listening … fingerprint=…`, or from
   *Settings → System*, and confirm the startup `certificate name mismatch` warning is gone.
7. Re-pin every client, below. Until you do, they are all broken.

The failure shapes differ, which is why a rotation done by accident is expensive:

- **Agents fail quietly.** Each logs `session ended err=… server certificate fingerprint
  mismatch: got <hex>` to `agent.log` and retries with a backoff capped at a minute, indefinitely.
  Nothing reaches the server, so there is no server-side log line and no audit entry — the devices
  just go offline in the console, and an `offline` alert rule is the only thing that will actively
  tell you. Fix per device: re-run the enrollment one-liner from the console (the identity survives
  because `server_url` is unchanged), or edit `fingerprint` in `agent.json` and restart the
  service. **You cannot push that as a script**: running a script needs the agent connected, and
  it is not. Budget for reaching each device some other way.
- **The phone fails loudly.** The Android app refuses the connection and shows its pin-mismatch
  screen with the expected and the presented fingerprint; there is no "proceed anyway". Fix:
  *Server detail → Rotate pin*, then confirm the new fingerprint through Trust review, out of
  band, the same way it was added. The app never learns a pin from the connection it is
  verifying, so this step is deliberately human.
- **Browsers** warn again — new issuer, and possibly a new name mismatch. Re-import `server.crt`
  wherever it was imported.
- **New enrollments are fine.** The console renders install commands from the live fingerprint, so
  anything enrolled after the restart pins the new certificate.

Rotate before enrolling a fleet, or at a time when you can reach the devices. Do **not** rotate to
make a name mismatch go away: the mismatch is normal (above), and the regeneration costs a
re-pinning of everything.

### Not rotating: a certificate the clients already trust

If the reason to regenerate is a name, consider the other direction — give the server a
certificate the clients trust on their own and stop pinning. On a tailnet that is two commands:

```
tailscale cert --cert-file server.crt --key-file server.key <host>.<tailnet>.ts.net
rmm-server install --cert <dir>/server.crt --key <dir>/server.key \
  --public-url https://<host>.<tailnet>.ts.net:8443
```

Put the pair where the service account can read it — the data directory is the obvious place, and
on Windows `tailscale cert` writes to the working directory of the elevated shell you ran it in,
which is usually not where you want it left.

The result is a publicly trusted leaf carrying the MagicDNS name, so browsers, Android and every
system trust store accept it with no warning, no mismatch and no pin to manage — the Android app
holds such a server with an empty fingerprint (system trust). Three costs, all real:

- **Every agent must be re-enrolled with an empty pin** (`rmm-agent install --server … --token …
  --fingerprint ""`). The certificate is renewed about every 90 days and the fingerprint changes
  with it; as §5 puts it, pinning only makes sense for a long-lived certificate.
- **Every renewal needs a restart.** `tailscale cert` rewrites the files and the server reads them
  once (above), so renew and restart together, on a schedule you control. Every agent reconnects.
- **The two models are mutually exclusive.** One listener, one certificate, one fingerprint: you
  cannot serve a pinned self-signed certificate to the agents and a publicly trusted one to the
  phone.

`tailscale serve --bg https / http://127.0.0.1:8080` in front of `rmm-server --insecure --listen
127.0.0.1:8080 --trusted-proxies 127.0.0.1 --public-url https://<host>.<tailnet>.ts.net` gets to
the same place with tailscaled owning the renewal, so there are no restarts — at the price of the
`--insecure` caveats in §5: the fingerprint is empty everywhere (install commands carry no pin)
and the session cookie is issued without `Secure`.

The console itself can use whichever certificate your browser trusts; the pin is what the agents
and the Android app care about.

## 7. Settings that affect operations

*Settings* (admin only) → stored in the `settings` table:

- **Public URL** — overrides the hostname guess; used in install commands and alert emails. The
  value saved here wins over `--public-url`, which only seeds it on first run (the server logs a
  warning when the two disagree), and it is what §6 reads when a certificate is generated.
- **Email** — SMTP host, port, `starttls` (587) / `tls` (465) / `none`, credentials, from,
  recipients; *Send test* verifies it.
- **Agent defaults** — metrics interval (minimum 5 s), inventory interval (minimum 60 s); pushed
  to every connected agent when saved. The patch scan interval field is stored for future use;
  today scans are driven by patch policies and by the first-contact scan.
- **Retention** — days to keep metrics (30), script runs (90), audit entries (365), agent
  events (30). Resolved alerts follow the audit setting, and baseline drift history follows the
  agent-events setting. Purge runs hourly. Shrinking retention
  does not shrink `rmm.db` on disk until you `VACUUM` it (`sqlite3 rmm.db VACUUM` with the server
  stopped). With `--telemetry pebble` or `clickhouse` the metrics retention is applied to that
  engine instead (see Metrics storage).

Per device (*Overview → Edit*): display name, group, tags, custom fields, notes, monitored
services (state pushed with every metrics sample and alertable), **maintenance mode** until a
time (suppresses new alerts and policy-driven patch installs).

## 8. Moving the server to another machine

1. Stop the old service. Copy the data directory (database and certificate files).
2. Install the new server with the copied data directory (`--data`) and, if the address changes,
   the new `--public-url`.
3. Agents still point at the old `server_url` in `agent.json`. Keep the old name/IP (DNS change,
   same IP) and nothing else is needed. Otherwise, before shutting the old one down, push a
   script to every device that edits `server_url` in `agent.json` and restarts the service
   (`Restart-Service HomelabRMMAgent` / `systemctl restart HomelabRMMAgent`), or re-run the
   enrollment one-liner from the new server on each device (the identity survives when the
   `server_url` matches, so pick the DNS approach when you can).
4. The certificate moves with the data directory, so the pin stays valid and the phone keeps
   working. If you generate a new one, re-pin everything — §6.

## 9. Housekeeping checklist

- Watch `rmm.db` size in *Settings → System*; metrics dominate, retention controls it.
- Keep enrollment tokens short-lived; expired ones disappear from the list automatically. They
  are also the reason a deleted device can come back: the agent keeps `enroll_token` in
  `agent.json` and re-enrolls with it the moment its key is rejected, as a **new** record with no
  history. Stop or uninstall the agent (`rmm-agent stop` / `rmm-agent uninstall`, or
  `deploy/uninstall.ps1` / `deploy/uninstall.sh`) *before* deleting the device, or make sure the
  token it holds is expired or exhausted.
- Review *Audit* and *Users* occasionally; remove accounts you no longer use. In *Audit*, an
  **`agent.rekeyed`** entry means an enrollment adopted an existing offline device record instead
  of creating a new one. That is what a reinstall looks like — and also what a machine claiming
  another's hostname looks like, so any you did not cause deserves a look. An
  **`agent.duplicate_hostname`** entry is the same attempt against a device that was *online*:
  nothing was adopted, but you now have two rows with one hostname, so make sure you aim scripts
  at the right one. A plain new device is `agent.enrolled`.
- Give people who only need dashboards the `viewer` role: on top of being refused every write, a
  viewer cannot open a terminal (`/ws/shell`), start a remote desktop session (`/ws/desktop`),
  download a file from a device, or read the enrollment token list (`GET /api/enroll`) — a token
  is all anyone needs to add a device of their own.
- After upgrading the server, replace the `agents/` folder too so newly enrolled devices get the
  matching agent.
- Leave the certificate alone unless you mean it. Regenerating `server.crt`/`server.key`
  invalidates every agent's pin and the phone's at the same moment, and a hostname mismatch — the
  usual reason someone reaches for it — is normal here and not what it is for. §6 has both the
  names the certificate actually carries and the rotation procedure.
- Keep the server itself patched: it is a device like any other and can run the agent.

## Installing on Windows with the MSI packages

`tools\build.ps1 -Target all,msi` produces `dist\rmm-agent-<version>-x64.msi` and
`dist\rmm-server-<version>-x64.msi`. The `msi` target needs the WiX Toolset
(`winget install --id WiXToolset.WiXCLI`, then `wix eula accept wix7`) and is
deliberately not part of `-Target all`, so a machine without WiX still builds
everything else.

MSI rather than a self-extracting `.exe` because the agent is the package that
has to reach a fleet: `msiexec` takes the server URL and enrollment token as
properties, and Group Policy, Intune and SCCM all deploy an MSI natively.

**Agent.** Create an enrollment token in the console under Devices, Enroll
device, then:

```
msiexec /i rmm-agent.msi /qn SERVER="https://rmm.example.ts.net:8443" TOKEN="<token>"
```

Add `FINGERPRINT="<64 hex>"` only when the server serves a self-signed
certificate. Omit it when the certificate is publicly trusted — one from
`tailscale cert` is — and the agent uses system trust, which also means nothing
has to be re-pinned when that certificate renews.

**Tagged MSI (Zero-Touch Enrollment).** In addition to command-line properties, the server can
dynamically append a binary configuration overlay trailer (`[HOMELAB_RMM_CONFIG]...[END_HOMELAB_RMM_CONFIG]`)
directly to `rmm-agent.msi` when downloaded via the web console (`/install/{token}/msi`).
When launched, the installer reads the embedded trailer to extract `SERVER`, `TOKEN`, and optional
`FINGERPRINT`, enabling zero-parameter double-click installation or silent mass deployment via Active
Directory GPO or Microsoft Intune:

```
msiexec /i HomelabRMM-Agent.msi /qn
```

**Debian / Ubuntu Package (`.deb`).** For Debian and Ubuntu endpoints, the web console provides
dynamic `.deb` package generation via `/install/{token}/deb?arch=amd64`.
The server builds an `ar` binary package containing the pre-compiled `rmm-agent` executable, the
systemd unit (`HomelabRMMAgent.service`), and an embedded `agent.json` pre-configured with the
enrollment token and server URL. Install cleanly with:

```bash
sudo dpkg -i homelab-rmm-agent_amd64.deb
```
The service starts and registers automatically upon package installation.

The package installs to `C:\Program Files\HomelabRMM`, an administrators-only
directory, and then runs the agent's own `install` subcommand, so exactly one
tested code path writes `agent.json`, registers the service and confirms it
started. `%ProgramData%\HomelabRMM` is never touched by the installer, so a
device keeps its identity across an upgrade: reinstalling or upgrading over an
existing agent reuses the device key rather than enrolling a second time.

Uninstall (`msiexec /x rmm-agent.msi /qn`, or Add/Remove Programs) deregisters
the service and removes the files, and deliberately leaves `%ProgramData%` in
place. Remove that directory by hand to retire a device for good.

**Server.**

```
msiexec /i rmm-server.msi /qn PUBLICURL="https://rmm.example.ts.net:8443"
```

`LISTEN` defaults to `0.0.0.0:8443` and `DATADIR` to
`C:\ProgramData\HomelabRMM-Server\data`, which is deliberately not the agent's
`%ProgramData%\HomelabRMM`: the two collide on a machine running both, which is
the normal case for a homelab. Pass `CERTFILE` and `KEYFILE` together to serve a
certificate you already have.

Bind to every interface and restrict reachability with the firewall rather than
by binding one address, so the service still starts when that interface is not
up yet at boot. For a Tailscale-only server:

```
New-NetFirewallRule -DisplayName 'Homelab RMM server (Tailscale only)' -Direction Inbound `
    -Action Allow -Protocol TCP -LocalPort 8443 -InterfaceAlias 'Tailscale'
```

Neither package is code-signed, so SmartScreen and reputation-based antivirus
will have an opinion on a fresh machine. That is expected; see the antivirus
notes in the README.

### Tailscale certificates

Pass `--tailscale-cert` (or `TAILSCALE=1` to the MSI) and the server gets a
real Let's Encrypt certificate for its tailnet name, then keeps it renewed:

```
msiexec /i rmm-server.msi /qn TAILSCALE=1 PUBLICURL="https://box.tailnet-name.ts.net:8443"
```

It mints the certificate before the listener starts, re-asks once a day, and
swaps a renewed one in **without a restart**, because the listener reads the
certificate through a hook rather than a copy taken at startup. Requires
HTTPS certificates to be enabled for the tailnet in the Tailscale admin
console; without that, `tailscale cert` returns "your Tailscale account does
not support getting TLS certs".

Any failure is a warning, never fatal: a server that cannot reach Tailscale
still starts on a self-signed certificate rather than refusing to run.

The reason this belongs in the server and not in the installer is renewal.
These certificates last 90 days, so minting one at install time only moves
the outage a quarter into the future, and only the process that serves the
certificate can pick up a new one on its own.

**This is also what stops pinning becoming a time bomb.** A fingerprint pin
is a promise about one specific certificate, and a publicly trusted one is
designed to be replaced. So when the served certificate verifies against the
host trust store for the public URL's host, the server hands out **no**
fingerprint: the enrollment commands omit `--fingerprint` and agents use
system trust, which keeps working across every renewal. A self-signed
certificate is still pinned, because nothing else vouches for it. `GET
/api/enroll` reports both, `fingerprint` being what to pin (empty when there
is nothing to) and `cert_fingerprint` the certificate actually being served.

`deploy\renew-tailscale-cert.ps1` remains for a server that cannot use the
flag, for instance one behind a reverse proxy that terminates TLS itself. It
re-mints, re-locks the key and restarts the service only when the file
changed. Register it as a weekly SYSTEM task:

```
$script = 'C:\ProgramData\HomelabRMM-Server\renew-tailscale-cert.ps1'
$a = New-ScheduledTaskAction -Execute powershell.exe `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`""
$t = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am
$p = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'Homelab RMM cert renewal' -Action $a -Trigger $t -Principal $p
```

## 10. Server in-place updates

Homelab RMM supports in-place server self-updating without manual binary replacement:

1. **Check for Updates**: Navigate to *Settings → System* in the web console or call `GET /api/system`.
   The server checks for staged binaries in `dist/` or updates matching the release tag.
2. **Apply Update**: Click **Update Server** or invoke `POST /api/server/update` with admin credentials.
3. **Execution**:
   - The server inspects the running binary path (`os.Executable()`).
   - It stages the replacement binary and synchronizes updated `rmm-agent*` binaries to the server's
     `agents/` directory so fleet devices can be updated from the console.
   - It performs an atomic binary swap (`rmm-server.exe` / `rmm-server`) and initiates a graceful service restart.
   - Ongoing agent connections reconnect automatically within seconds.

## 11. Desktop tray companion (`rmm-desktop`)

`rmm-desktop` provides a lightweight system tray application for end users and technicians on Windows:

- **Agent Companion Mode**: Launched without flags in an interactive user session:
  ```cmd
  rmm-desktop.exe
  ```
  It discovers the local `rmm-agent` service via Named Pipe (`\\.\pipe\homelab-rmm-portal`), displays
  a system tray icon with connectivity status, and allows the user to open the client self-service
  portal or review open tickets in one click.
- **Server URL & Console Mode**:
  By default, `rmm-desktop` discovers the server URL from local agent configuration (`agent.json`), Windows registry (`HKLM\Software\HomelabRMM\ServerURL`), or `--server-url`:
  ```cmd
  rmm-desktop.exe --server-url https://rmm.example.lan:8443
  ```
  Pass `--mode server` to open the administrative web console in a dedicated WebView2 window rather than the client self-service portal.
- **Deployment**:
  Can be configured to run at user logon via Group Policy, Active Directory login script, or by
  placing a shortcut in `%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup` or adding an
  entry under `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`.
