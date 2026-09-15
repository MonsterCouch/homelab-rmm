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
| Config | `agent.json` (0600): `server_url`, `agent_id`, `key`, `enroll_token`, `fingerprint` | same |
| Log | `agent.log`, rotated to `agent.log.1` at 10 MB | same |
| Service | `HomelabRMMAgent`, runs as LocalSystem, automatic start, restart on failure after 5 s | `HomelabRMMAgent.service`, runs as root, `Restart=always`, `RestartSec=5` |
| Script temp files | `%TEMP%\rmm-script-*` (deleted after the run) | `/tmp/rmm-script-*` |

On a Windows box that runs both the server and an agent they share `%ProgramData%\HomelabRMM`;
the file names do not collide.

## 2. Service control

```
rmm-server install [--listen :8443] [--data DIR] [--public-url URL] [--cert F --key F] [--insecure]
rmm-server uninstall | start | stop | restart | status
rmm-agent  install --server URL --token TOKEN [--fingerprint HEX] [--no-service]
rmm-agent  uninstall | start | stop | restart | status
```

`install` re-registers an existing service (it uninstalls first), validates the configuration
by opening the data directory, database and certificate, and starts the service with the flags
you gave it. Change flags by running `install` again with the new set. Native tools work too:
`sc query HomelabRMMServer`, `systemctl status HomelabRMMServer`, `journalctl -u HomelabRMMAgent -f`.

Running in the foreground for a test: `rmm-server run --data ./tmp --listen :8443`. Every flag
has an environment twin (`RMM_LISTEN`, `RMM_DATA_DIR`, `RMM_PUBLIC_URL`, `RMM_CERT_FILE`,
`RMM_KEY_FILE`, `RMM_INSECURE`, `RMM_DEV_WEB_DIR`), which is what the Docker image and the
example systemd unit use. `RMM_DEBUG=1` switches both binaries to debug logging (every API
request is logged with its duration).

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
  what agents pin. Agent connects/disconnects, enrolments, alerts opened and tasks run are logged
  at info.
- **Agent**: `agent.log`. `connected server=… agent_id=…` means all is well; `session ended
  err=… retry_in=…` shows why it is reconnecting.
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
rmm-server install --insecure --listen 127.0.0.1:8080 --public-url https://rmm.example.lan
```

Ready-made configurations: `deploy/Caddyfile` and `deploy/nginx.conf`. What matters:

- **WebSockets** on `/ws/agent` (one per device, open for days), `/ws/desktop-agent` (binary
  frames up to 32 MB), `/ws/shell/*` and `/ws/desktop/*`. nginx needs `proxy_http_version 1.1`
  and the `Upgrade`/`Connection` headers; both proxies need long read/send timeouts.
- **Server-Sent Events** on `/api/events` and streamed script output: disable response
  buffering (`proxy_buffering off`, Caddy `flush_interval -1`).
- **Host header** must be forwarded unchanged: browser WebSockets are accepted only when the
  `Origin` host matches `Host`.
- **`X-Forwarded-For`**: the first address is recorded in the audit log and used by the login
  rate limiter. Because the server trusts it blindly, the HTTP port must not be reachable except
  through the proxy (bind to `127.0.0.1`, or firewall it).
- **Body size**: file uploads to devices are raw request bodies; allow at least 32–64 MB.
- **Cookies**: with `--insecure` the session cookie is set without the `Secure` flag (the server
  cannot see the proxy's TLS). It is still `HttpOnly` and `SameSite=Strict`.

**What `--insecure` means for agents.** With no certificate of its own the server has no
fingerprint; install commands carry an empty pin and agents validate the proxy's certificate
with the **device's system trust store**. That works with a public CA (Let's Encrypt) out of the
box, and with a private CA only after its root is installed on every device (Windows:
`certutil -addstore Root ca.crt`; Debian/Ubuntu: copy to `/usr/local/share/ca-certificates/` and
`update-ca-certificates`; RHEL family: `/etc/pki/ca-trust/source/anchors/` and
`update-ca-trust`). Alternatively pass the proxy certificate's fingerprint to `rmm-agent install
--fingerprint` by hand, remembering that it changes at every renewal (Let's Encrypt: every 60–90
days), which would strand the agents. Pinning only makes sense for a long-lived certificate.

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
  events (30). Resolved alerts follow the audit setting. Purge runs hourly. Shrinking retention
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
- Keep enrolment tokens short-lived; expired ones disappear from the list automatically.
- Review *Audit* and *Users* occasionally; remove accounts you no longer use.
- After upgrading the server, replace the `agents/` folder too so newly enrolled devices get the
  matching agent.
- Keep the server itself patched: it is a device like any other and can run the agent.
