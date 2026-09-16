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
run `install` by hand) must do it too. `rmm-agent install` inspects the directory it is about to
register — the DACL on Windows, the owner and mode on Linux — and prints a warning naming the
directory, the accounts that can write it and where to move it. It warns rather than refuses:
running the agent out of a build tree is normal while developing. `rmm-server install` does not
check, and the same rule applies to it.

Running in the foreground for a test: `rmm-server run --data ./tmp --listen :8443`. Every flag
has an environment twin (`RMM_LISTEN`, `RMM_DATA_DIR`, `RMM_PUBLIC_URL`, `RMM_CERT_FILE`,
`RMM_KEY_FILE`, `RMM_INSECURE`, `RMM_TRUSTED_PROXIES`, `RMM_DEV_WEB_DIR`), which is what the
Docker image and the example systemd unit use. `RMM_DEBUG=1` switches both binaries to debug logging (every API
request is logged with its duration).

### First run: the one-time setup code

Until an account exists, anyone who can reach the port could complete the setup form and become
the administrator. So a server that starts with an **empty user table mints a random setup code**
and prints it two ways:

```
==== FIRST-RUN SETUP CODE: 3f9a1c07 ====
```

on the console (stderr: `journalctl -u HomelabRMMServer`, `docker logs`) and — the place to look
when it runs as a Windows service, where stderr goes nowhere — as a `WARN` line in `server.log`
in the data directory:

```
level=WARN msg="FIRST RUN: no users yet. ..." setup_code=3f9a1c07
```

- The setup form **always** shows a **Setup code** field and the request is refused with 403
  until it matches — from the LAN, from behind a reverse proxy, and from a browser on the server
  itself. There is no loopback exemption: a peer address of `127.0.0.1` can equally be a same-host
  reverse proxy relaying the whole LAN, any local process on the box, or a hostile page open in
  your own browser, and none of those should be able to claim the account that is root on every
  device you later enrol. Reading the code proves you can see the server's console or log, which
  is the thing worth proving.
- Wrong codes are rate-limited like logins and audited as `setup.refused`.
- Concurrent setup requests do not race: the "no users yet?" check and the insert are one step,
  so a first-run window produces exactly one administrator.
- **Lost the code?** Restart the server *before anyone creates a user*: a new code is minted on
  every start that finds no users, so `rmm-server restart` (or `systemctl restart
  HomelabRMMServer`) prints a fresh one. Once the first account exists the code stops being
  minted and stops being asked for — from then on recovery is `rmm-server user passwd`.
- **Docker**: read it from the container log —
  `docker logs homelab-rmm 2>&1 | grep -i "setup code"` (`docker compose logs rmm` with the
  compose file). The image is distroless, so there is no shell to `docker exec` into; the same
  code is in `/data/server.log` inside the volume if you need it later, as the `setup_code=`
  attribute of the `FIRST RUN` warning
  (`docker run --rm -v rmm-data:/data busybox grep setup_code /data/server.log`). A fresh code
  needs `docker compose restart rmm` while the user table is still empty.

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
  what agents pin, and on a first run the one-time setup code is printed beside it. Agent
  connects/disconnects, enrolments, alerts opened and tasks run are logged at info. Two `WARN`
  lines are worth alerting on: `agent record re-keyed by enrolment` (a device took over an
  existing, offline device record — see the audit note below) and `first-run setup refused`.
- **Agent**: `agent.log` in the config directory, on Windows as on Linux. `connected server=…
  agent_id=…` means all is well; `session ended err=… retry_in=…` shows why it is reconnecting.
  Two `WARN` lines matter: `agent key rejected, re-enrolling with stored token` (the server no
  longer knows this device's key — pair it with the server's `agent record re-keyed by
  enrolment`) and `server URL is plaintext` (the connection to the server is not encrypted; see
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
| `server.crt`, `server.key` | the identity agents pin; without the key every agent must re-enrol |
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

## 6. Custom certificates

`--cert FILE --key FILE` (or `RMM_CERT_FILE`/`RMM_KEY_FILE`) replaces the generated certificate;
PEM, any key type Go's `tls` accepts. The server pins **exactly this leaf certificate's**
SHA-256 in every install command, so:

- Rotating the certificate changes the fingerprint. Every enrolled agent then logs
  `server certificate fingerprint mismatch` and stays offline until its `agent.json`
  `fingerprint` is updated (re-run the enrolment one-liner, or edit the file and restart the
  service). Plan certificate changes before enrolling a fleet, or enrol with an empty fingerprint
  and a certificate the devices trust through their system store.
- The generated self-signed certificate lasts ten years for exactly this reason.
- To add names to the generated certificate, set `--public-url`, stop the server, delete
  `server.crt` and `server.key`, start it (new fingerprint; re-enrol agents).

The console itself can use whichever certificate your browser trusts; only the agents care about
the pin.

## 7. Settings that affect operations

*Settings* (admin only) → stored in the `settings` table:

- **Public URL** — overrides the hostname guess; used in install commands and alert emails.
- **Email** — SMTP host, port, `starttls` (587) / `tls` (465) / `none`, credentials, from,
  recipients; *Send test* verifies it.
- **Agent defaults** — metrics interval (minimum 5 s), inventory interval (minimum 60 s); pushed
  to every connected agent when saved. The patch scan interval field is stored for future use;
  today scans are driven by patch policies and by the first-contact scan.
- **Retention** — days to keep metrics (30), script runs (90), audit entries (365), agent
  events (30). Resolved alerts follow the audit setting, and baseline drift history follows the
  agent-events setting. Purge runs hourly. Shrinking retention
  does not shrink `rmm.db` on disk until you `VACUUM` it (`sqlite3 rmm.db VACUUM` with the server
  stopped).

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
   enrolment one-liner from the new server on each device (the identity survives when the
   `server_url` matches, so pick the DNS approach when you can).
4. The certificate moves with the data directory, so the pin stays valid. If you generate a new
   one, re-enrol.

## 9. Housekeeping checklist

- Watch `rmm.db` size in *Settings → System*; metrics dominate, retention controls it.
- Keep enrolment tokens short-lived; expired ones disappear from the list automatically. They
  are also the reason a deleted device can come back: the agent keeps `enroll_token` in
  `agent.json` and re-enrols with it the moment its key is rejected, as a **new** record with no
  history. Stop or uninstall the agent (`rmm-agent stop` / `rmm-agent uninstall`, or
  `deploy/uninstall.ps1` / `deploy/uninstall.sh`) *before* deleting the device, or make sure the
  token it holds is expired or exhausted.
- Review *Audit* and *Users* occasionally; remove accounts you no longer use. In *Audit*, an
  **`agent.rekeyed`** entry means an enrolment adopted an existing offline device record instead
  of creating a new one. That is what a reinstall looks like — and also what a machine claiming
  another's hostname looks like, so any you did not cause deserves a look. An
  **`agent.duplicate_hostname`** entry is the same attempt against a device that was *online*:
  nothing was adopted, but you now have two rows with one hostname, so make sure you aim scripts
  at the right one. A plain new device is `agent.enrolled`.
- Give people who only need dashboards the `viewer` role: on top of being refused every write, a
  viewer cannot open a terminal (`/ws/shell`), start a remote desktop session (`/ws/desktop`),
  download a file from a device, or read the enrolment token list (`GET /api/enroll`) — a token
  is all anyone needs to add a device of their own.
- After upgrading the server, replace the `agents/` folder too so newly enrolled devices get the
  matching agent.
- Keep the server itself patched: it is a device like any other and can run the agent.
