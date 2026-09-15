# Security

Homelab RMM gives whoever holds a console account **administrative control of every enrolled
device**: arbitrary scripts as SYSTEM/root, a root shell, the file system, the screen. Treat the
server like a domain controller, not like a dashboard. This document says what the software
protects, what it does not, and how to deploy it so the difference does not matter.

## Threat model

Designed for: a home lab or small network whose operator owns every device and the server, with
the console reachable on the LAN or over a VPN. Adversaries considered:

1. **Someone on the network** who can observe or tamper with traffic between agents, browsers
   and the server (a compromised IoT device, a guest on the Wi-Fi).
2. **A compromised or malicious device** that holds an agent key and tries to reach other
   devices or the server's data.
3. **A stolen enrolment token** or a stolen `agent.json`.
4. **Web attacks** against a signed-in operator: CSRF, cross-site WebSocket hijacking, session
   theft.
5. **Password guessing** against the console.

Not designed for: exposing the console to the public internet, multi-tenant hosting, or
adversaries with root on the server host (they have everything: the SQLite file, the TLS key,
the SMTP password).

## What is protected, and how

**Transport.** Agents dial the server over TLS 1.2+ and pin the server certificate's SHA-256
fingerprint (`internal/agent/conn.go`). A network attacker cannot impersonate the server to an
agent, even with a certificate from a public CA, because only the pinned leaf is accepted.
Browsers use ordinary TLS; the generated certificate is self-signed, so the browser warns until
you trust it — an attacker who can present *another* self-signed certificate would produce the
same warning, which is why you should import the real one once rather than click through every
time.

**Device identity.** Enrolment requires a token created by an operator. Tokens are 24 random
bytes, expire (24 h default) and have a use count (1 default); an exhausted or expired token is
refused, hidden from the list and purged a day after its expiry. The
per-device key is 32 random bytes; the server stores `sha256(key)` (`agents.key_hash`), so the
database does not contain usable credentials. Deleting a device revokes its key immediately
(the socket is dropped). Every agent-originated message is attributed to the key's device; an
agent cannot act on, or read data about, another device — the only cross-device action, Wake-
on-LAN, is initiated by the server and consists of a broadcast magic packet.

**The desktop helper** connects with a single-use 24-byte token minted for one viewer session,
consumed on first use and discarded when the viewer disconnects.

**Operators.** Passwords are bcrypt-hashed; TOTP two-factor is available per account; sessions
are 14-day random tokens in a cookie marked `HttpOnly`, `SameSite=Strict` and `Secure` (except
with `--insecure`, where the proxy provides TLS). Every state-changing API request must carry
`X-Requested-With`, which a cross-site form cannot set — together with `SameSite=Strict` that is
the CSRF defence. Browser WebSockets are accepted only when `Origin` matches `Host`. Login is
rate-limited to 10 attempts per minute per client address, and failed logins are audited.

**Roles.** `viewer` cannot change anything (every non-GET is rejected), `tech` cannot manage
users or settings, `admin` can do everything. An admin cannot demote or delete their own
account by accident.

**Audit.** Every login, script run, shell and desktop session, power action, patch operation,
settings change and user change is written to the `audit` table with user and source address.

**Agent hardening.** Helper tools are resolved by absolute path in `System32` on Windows so a
writable directory on PATH cannot shadow `shutdown.exe`; commands never go through a shell;
command output is capped (32 MB / 10 MB) so a runaway process cannot exhaust memory; script
processes are killed as a tree on timeout or cancel. Script bodies are written to a private temp
directory (0700) and removed afterwards.

**Downloads.** `/api/agent-download/` is unauthenticated on purpose (the install script runs
before the device has credentials), restricted to files named `rmm-agent-*` in the agents
directories, and serves nothing else. `/install/<token>` renders a script that contains only the
public URL, the token you already had to know, and the certificate fingerprint.

## The install one-liners and certificate validation

The enrolment commands the console prints contain
`[Net.ServicePointManager]::ServerCertificateValidationCallback={$true}` (Windows) or `curl -k`
(Linux). They disable certificate validation for **one download**: the install script and the
agent binary. That is unavoidable when the server uses a self-signed certificate the device has
never seen. During that window an attacker on the path could serve a different binary. The
mitigation is the pin: the script passes the *real* server's fingerprint to `rmm-agent install`,
and from the first WebSocket onward the agent talks only to the certificate it was told about.

If that window is unacceptable in your environment:

- run the server (or a proxy in front of it) with a certificate the device already trusts, and
  remove the validation override from the command before running it; or
- copy `agents/rmm-agent-<os>-<arch>` to the device by other means and run
  `rmm-agent install --server … --token … --fingerprint …` by hand, comparing the fingerprint
  with the one in the console (`Settings → System`) — this is the manual install described in the
  README and it never disables validation.

Verify a fingerprint out of band before pasting it; it is the trust anchor for that device.

## What is not protected

- **Anyone with a console account is root everywhere.** There is no per-device permission model
  beyond the three roles. Do not share accounts; create a `viewer` for people who only need to
  look.
- **The console is not hardened for the open internet.** No account lockout beyond the
  per-minute limiter, no WebAuthn, no IP allow-lists, no brute-force alerting. Keep it on the
  LAN or behind a VPN (WireGuard, Tailscale).
- **`X-Forwarded-For` is trusted unconditionally.** Behind a proxy that is correct; exposed
  directly, a client can forge the header to evade the login limiter and pollute the audit log.
  Bind the HTTP listener to localhost when a proxy is used, and never combine `--insecure` with
  a listener reachable from the network.
- **Script parameters are stored in clear text** in `script_runs.args`. The "Create local user"
  starter script warns about this: passwords passed as parameters are visible to every console
  user who can read runs. Prefer scripts that generate secrets on the device or read them from
  a vault.
- **Agent configuration is only as safe as the device.** `agent.json` (0600, owned by root /
  LocalSystem) contains the device key; whoever has root on a device has that key. It grants
  nothing beyond that device's own identity.
- **Email is plain text.** Alert mail carries device names and messages; use STARTTLS/TLS to
  your relay and do not put secrets in alert titles.
- **The database is not encrypted at rest.** The data directory should be readable only by the
  service account (the installer sets 0750 on Linux; on Windows `%ProgramData%\HomelabRMM`
  inherits ProgramData ACLs — tighten them if other local users exist).
- **Enrolment re-uses an offline device record** with the same hostname and OS. A rogue machine
  that knows a valid token and a victim's hostname could take over that record while the victim
  is offline (it would receive the victim's group/tags and queued runs). Keep tokens single-use
  and short-lived, and watch the `agent.enrolled` audit entries.
- **Remote desktop shows whatever is on screen**, including the lock screen and UAC prompts on
  Windows (by design, via the SYSTEM token). Sessions are audited; there is no on-screen consent
  prompt for the person at the device.

## Recommendations

1. **Keep the server off the public internet.** LAN only, or a VPN. If you must expose it, do so
   through a reverse proxy with its own authentication layer in front.
2. **Enable TOTP on every account**, starting with the first admin you create.
3. **Use the least role** that gets the job done; create a separate `viewer` account for
   dashboards on a wall.
4. **Trust the server certificate in your browser** once (`server.crt`), so a warning ever seen
   again means something.
5. **Short, single-use enrolment tokens**; delete leftovers.
6. **Back up `server.key` with the database** and protect the backup like a password store; it
   is what every agent pins.
7. **Keep the server and agents updated**, and let the server manage itself as a device so it is
   patched with the rest.
8. **Review the audit log** now and then; `login.failed` bursts and unexpected `shell.open` or
   `desktop.open` entries are the things to look for.
9. **Reverse proxies**: forward `Host` unchanged, bind the backend to `127.0.0.1`, and read the
   `--insecure` section of `docs/OPERATIONS.md` before choosing it.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository rather than a public issue, with the
version (`rmm-server version`), the component, and reproduction steps.
