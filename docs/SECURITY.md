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
3. **A stolen enrollment token** or a stolen `agent.json`.
4. **Web attacks** against a signed-in operator: CSRF, cross-site WebSocket hijacking, session
   theft.
5. **Password guessing** against the console.

Not designed for: exposing the console to the untrusted public internet without a reverse proxy/VPN,
or adversaries with root/administrator access on the server host (they have everything: the SQLite file,
the TLS private key, the SMTP credentials). Multi-tenancy (Organizations and Sites) is supported and
enforces strict cross-tenant isolation and technician scoping.

## What is protected, and how

**Transport.** Agents dial the server over TLS 1.2+ and pin the server certificate's SHA-256
fingerprint (`internal/agent/conn.go`). A network attacker cannot impersonate the server to an
agent, even with a certificate from a public CA, because only the pinned leaf is accepted.
Browsers use ordinary TLS; the generated certificate is self-signed, so the browser warns until
you trust it — an attacker who can present *another* self-signed certificate would produce the
same warning, which is why you should import the real one once rather than click through every
time. Expect that import to leave a *second* warning standing: the names in the generated
certificate are fixed when it is written and often do not include the name you browse to — see
"The name on the certificate is not the trust anchor" below.

That protection is the `https://` case, which is what the console's install command produces for
a server with a certificate. It does **not** hold for a `server_url` of `http://` — what a server
run with `--insecure` and no proxy in front hands out: the agent then dials `ws://`, no TLS code
runs at all, a configured `fingerprint` is never consulted, and the device key and every byte
after it are in clear text. `rmm-agent install` warns about an `http://` URL and the agent logs
`server URL is plaintext` at every start, but neither refuses it, because a loopback development
server is a legitimate use of it. Treat any fleet whose agents carry an `http://` URL as
unprotected against adversary 1 above.

**Device identity.** Enrollment requires a token created by an operator. Tokens are 24 random
bytes, expire (24 h default) and have a use count (1 default); an exhausted or expired token is
refused, hidden from the list and purged a day after its expiry. The use is **consumed in the
same SQLite transaction that creates the device record**, with a conditional
`UPDATE ... WHERE uses_left > 0`, so devices racing on one token cannot stretch it: a one-use
token enrolls exactly one device however many arrive at once. `-1` is the operator's "unlimited"
and is the **only** non-positive value that still enrolls: a count the create endpoint would have
stored verbatim is clamped to `{-1} ∪ [1..]`, a row an older server drove below `-1` is repaired
on upgrade (migration 2), and any other value `<= 0` reads as exhausted rather than as unlimited.
The
per-device key is 32 random bytes; the server stores `sha256(key)` (`agents.key_hash`), so the
database does not contain usable credentials. Deleting a device revokes its key immediately
(the socket is dropped). Every agent-originated message is attributed to the key's device; an
agent cannot act on, or read data about, another device — the only cross-device action, Wake-
on-LAN, is initiated by the server and consists of a broadcast magic packet.

**The token stays on the device.** `agent.json` keeps `enroll_token` alongside the key
(`internal/agent/config.go`), and the agent replays it whenever the server answers 401 — that is
how a device recovers from a revoked key without anyone visiting it, and it is a deliberate
trade. What it costs: a token created with several uses, or the console's "unlimited", is at rest
on every device it enrolled (readable only by root, or by SYSTEM and Administrators on Windows,
so anyone who is already root there can lift it) until it expires — one more reason to prefer
single-use tokens and short expiries. And
**deleting a device does not revoke the token on it**: the agent re-enrolls within seconds as a
brand-new record with no history, so removing a machine for good means stopping or uninstalling
its agent first, or waiting out the token. The rejoin is auditable (`agent.enrolled`, or
`agent.rekeyed` when it adopts an existing record).

**The desktop helper** connects with a single-use 24-byte token minted for one viewer session,
consumed on first use and discarded when the viewer disconnects.

**Operators.** Passwords are bcrypt-hashed; TOTP two-factor is available per account; sessions
are 14-day random tokens in a cookie marked `HttpOnly`, `SameSite=Strict` and `Secure` (except
with `--insecure`, where the proxy provides TLS). Every state-changing API request must carry
`X-Requested-With` — any value, because what matters is that a cross-site form or a CORS
"simple request" cannot set a custom header at all; together with `SameSite=Strict` that is the
CSRF defence. Browser WebSockets are accepted only when `Origin` matches `Host`. Login is
rate-limited to 10 attempts per minute per client address, and failed logins are audited.
Changing your own password **deletes your other sessions**, so reacting to a stolen cookie by
changing the password actually ends it.

**First-run setup.** Until an account exists, `POST /api/auth/setup` creates the initial
administrator account — which has administrative control over every device enrolled in the system.
The check ("are there any users?") and the creation run atomically under an exclusive mutex
(`s.setupMu`), guaranteeing that exactly one administrator can be created during first-run setup
regardless of concurrency or network timing. As soon as the first account is created,
`/api/auth/setup` is permanently closed and all subsequent attempts return HTTP 403 Forbidden.
`GET /api/auth/state` reports `needs_setup: true` and `setup_code_required: false` when uninitialized.

`/api/auth/setup`, `/api/auth/login` and `/api/auth/logout` sit outside the session middleware,
so they carry their own CSRF guard: `X-Requested-With` is required, the `Origin` host must match
`Host`, and a body that is not `application/json` is refused. Without it a cross-origin page
could post a CORS "simple request" to either endpoint — claiming the first administrator, or
signing a victim's browser into an account the attacker controls.

**Client address.** The login limiter and the audit log key on the peer address.
`X-Forwarded-For` is believed **only** when the peer is inside a network named by
`--trusted-proxies` / `RMM_TRUSTED_PROXIES`; otherwise it is ignored. Without that a client
could forge the header to buy a fresh limiter bucket per attempt and write any address it liked
into the audit trail.

When it *is* believed, the list is walked from the **right**, skipping hops that are themselves
trusted proxies, and the first remaining address wins. That matters because every proxy config
this project ships APPENDS rather than replaces (nginx's `$proxy_add_x_forwarded_for`, and Caddy
by default): the header the server sees is `<whatever the client sent>, <the peer the proxy
saw>`, so the **left-most** entry is exactly the value an attacker chose. Taking it would have
restored the forgery in the one deployment the guard exists for. A hop that will not parse breaks
the chain and the peer address is used instead. Note that `net.ParseCIDR` masks host bits off, so
`--trusted-proxies 10.0.0.5/8` trusts all of `10.0.0.0/8`; the server logs a warning when a value
does that.

**Browser hardening.** Responses carry `Content-Security-Policy: default-src 'self'` with
`script-src 'self'` (no inline or `eval`ed script), `object-src 'none'`, `base-uri 'none'`,
`frame-ancestors 'none'` and `form-action 'self'`, plus `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY` and `Referrer-Policy: same-origin`. Injected markup cannot load or run
code from anywhere else, and the console cannot be framed.

**Roles.** `viewer` cannot change anything (every non-GET is rejected), `tech` cannot manage
users or settings, `admin` can do everything. An admin cannot demote or delete their own
account by accident. A viewer is also refused the endpoints that are reads only in HTTP terms:
`GET /ws/shell/{id}`, `GET /ws/desktop/{id}` and `GET /api/agents/{id}/fs/download` all return
403, because a terminal, a desktop session and pulling a file off a device are not "looking".
`GET /api/enroll` is writer-only for the same reason: its body contains the enrollment token
**values**, and a token is all anyone needs to add a device of their own to the fleet (and, via
the hostname adoption below, to take over an offline device's record). Browsing a directory
listing stays available.

**Baseline enforcement and the `command` kind.** An **enforced** baseline changes devices with no
further confirmation, and a `command` check is arbitrary code run as SYSTEM/root on every matched
device on a timer. Four things bound that:

- Enforcement is opt-in and loud. `enforce` defaults to false, the console toggle carries an
  explicit warning, and both seeded baselines ship **disabled and unenforced** with every
  destructive check (`group_members`, the SMB1 registry value, service start-type changes,
  `reboot_pending`) shipping `remediate = 0`. The Linux seed's `sudo`/`wheel` reviews carry an
  empty `allowed` list on purpose: a shipped allow-list there would be a fleet-wide
  privilege-removal button one toggle away.
- Extra privilege for the sharp kinds. Creating, editing **or previewing** a baseline containing a
  `command` check, a `file` check writing outside `/etc` or `ProgramData`, or a `reboot_pending`
  check with `allow_reboot` requires the **admin** role — the routes are `requireWrite`, and the
  handlers check admin themselves. Preview is on that list because it *runs* the draft on the
  devices named in the request: gating only the save path would leave the same script one
  `POST /api/baselines/preview` away for any write account. They are audited as
  `baseline.command_check` (with `"preview": true` and the agent ids when it was a dry run) and
  `baseline.reboot_check` with the check name, alongside
  `baseline.create/update/delete/enable/disable/evaluate/remediate/preview`. A baseline targeting `{"all": true}` that enforces an `allow_reboot` check is
  refused unless the request carries `"confirm_fleet_reboot": true`.
- **The refusals live on the device.** The agent enforces them whatever the server was talked into
  sending: never empty `Administrators`/`sudo`/`wheel`/`adm`/`root` or remove RID 500, uid 0, the
  account the agent runs as, or a domain principal without `allow_domain`; never change a
  `boot`/`system` service start type; never stop or disable the agent's own service; never write
  to `/proc`, `/sys`, `/dev`, `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`,
  `C:\Windows\System32\config` or the agent's own configuration directory; never follow a symlink
  in a managed path's parent chain; never delete a directory; never accept a mode with a
  setuid/setgid/sticky bit; at most one baseline-initiated reboot per device per 24 h, and none
  while a script run or shell session is live. A `command` check runs through the same path as a
  script run — a temp directory, a 0700 file, `exec.Command` with arguments, never a shell string.
- **A path is compared as the filesystem sees it, not as it was spelled.** A directory on a
  Windows volume has two equally valid names: `C:\ProgramData\HomelabRMM` and its NTFS 8.3 short
  name `C:\ProgramData\HOMELA~1` open the same file, and `C:\PROGRA~1` is Program Files. A deny
  list that compares strings matches neither the short form nor a different case, so both sides
  now handle it: the **server refuses an 8.3-shaped component outright** (it cannot see the
  device's filesystem, and such a path can stand for any directory at all, so it never counts as
  "inside ProgramData" for the admin gate either), and the **agent resolves the real path** —
  short names expanded, case folded, symlinks followed — before comparing it with its own
  configuration directory.
- **Windows package installs stay refused.** The `package` kind will not invoke winget from the
  service account unless the check sets `allow_winget: true` *and* winget resolves, matching the
  existing patch-management decision rather than quietly working around it.

**Check parameters are not a place for secrets.** `GET /api/baselines/{id}` is session-only, which
includes **viewers**, and the parameters carry the `command` bodies and any `file` content verbatim.
The console says so in the Add-check dialog. Have the check read a secret on the device instead.

**Audit.** Every login, script run, shell and desktop session, power action, patch operation,
file operation (`file.download`, `file.upload`, `file.delete`, `file.mkdir`, `file.rename`),
settings change and user change is written to the `audit` table with user and source address,
along with `setup.refused` (a wrong setup code), `agent.enrolled`, `agent.rekeyed` and
`agent.duplicate_hostname`. A **service action, process kill or file operation is audited
whether or not it worked**: the attempt is what the log is read for, and a refusal carries
`"outcome":"failed"` with the device's own error, so "nobody tried to stop the antivirus" and
"somebody tried and was refused" are not the same empty log — and a sweep for unreadable paths
(SAM, a password database, an `.ssh` key) leaves the same trail as a successful one.

**Agent hardening.** Helper tools are resolved by absolute path in `System32` on Windows so a
writable directory on PATH cannot shadow `shutdown.exe`. The same rule covers every PowerShell the
agent starts as SYSTEM — the console terminal and the Windows Update scripts alike: `pwsh` is taken
from `%ProgramFiles%\PowerShell\7`, or from PATH only when that entry is itself inside `Program
Files` or `%SystemRoot%`, and otherwise the absolute `System32` `powershell.exe` is used.
Commands never go through a shell; command output is capped (32 MB / 10 MB) so a runaway
process cannot exhaust memory; script
processes are killed as a tree on timeout or cancel. Script bodies are written to a private temp
directory (0700) and removed afterwards.

**Process kills are bounded.** A pid is not an intention: `csrss.exe`, `wininit.exe`,
`winlogon.exe`, `services.exe` and `lsass.exe` are listed with ordinary pids like any other row,
and terminating one bugchecks Windows with `CRITICAL_PROCESS_DIED` — an unplanned reboot with
data loss, one click away in the console's process table. The agent refuses pids 0-4, the
processes the operating system is held up by (by name, on both platforms), anything Windows
itself marks critical (`IsProcessCritical`), and its own image — the service and the desktop
helper both run from it, so a kill there would drop the device off the console or end the remote
desktop session.

**Agent self-update.** `agent.update` will not install a binary without a **64-hex SHA-256** (an
empty hash used to skip verification altogether) and will not fetch one from just anywhere: the
URL must be `https`, or plain `http` against the configured server's own host, which is the
`--insecure`-behind-a-proxy deployment. What it installs runs as SYSTEM/root at the next restart.

**Downloads.** `/api/agent-download/` is unauthenticated on purpose (the install script runs
before the device has credentials), restricted to files named `rmm-agent-*` in the agents
directories, and serves nothing else. `/install/<token>` renders a script that contains the
public URL, the token you already had to know, the certificate fingerprint and public-key pin,
and the **SHA-256 of the agent binary** this server would serve. Because that script is piped
straight into `bash` or `iex` as root, everything interpolated into it is checked first: the
token must match `^[A-Za-z0-9_-]{16,64}$` **and** still be a live enrollment token (anything else
is a 404, so the endpoint is not an injection oracle either), `?arch=` must be one of `amd64`,
`arm64`, `arm`, `386`, and every value is escaped for the single-quoted literal it lands in
(`''` for PowerShell, `'\''` for the shell). The response is `Cache-Control: no-store`.

**What the install script does with the binary.** The download endpoint authenticates nobody and
the bootstrap connection cannot check a CA chain, so the script does not accept what it gets on
trust:

- it **verifies the SHA-256** of the downloaded binary against the hash the server rendered into
  the script, and refuses to install on a mismatch (the Linux script carries one hash per
  architecture, because `uname -m` decides which one it needs; an architecture the server has no
  binary for gets no hash and the script stops rather than installing something unverifiable);
- it **pins the connection** rather than turning validation off outright. On Windows the
  validation callback accepts exactly the certificate whose SHA-256 the script carries — the same
  one the agent pins afterwards — instead of returning `$true` for everything. On Linux `curl`
  gets `--pinnedpubkey sha256//<base64 SPKI>` alongside `-k` (which only skips the chain; the pin
  is still enforced) when the local curl supports it, and falls back to the hash check when it
  does not.

## The install one-liners and certificate validation

The enrollment commands the console prints contain
`[Net.ServicePointManager]::ServerCertificateValidationCallback={$true}` (Windows) or `curl -k`
(Linux). They disable certificate validation for **one fetch**: the install script itself. That
is unavoidable when the server uses a self-signed certificate the device has never seen — it is
trust on first use, and it is the residual risk of this bootstrap.

Everything the script then does is pinned to what that first fetch said: the agent binary is
downloaded over a connection pinned to the server's certificate (public key on Linux) and its
SHA-256 is checked before it is run, and the fingerprint the script passes to `rmm-agent install`
is what the agent pins from the first WebSocket onward. So an attacker who is on the path only
for the binary download achieves nothing; one who is on the path for the **script fetch** can
rewrite the script and the hashes in it together, which is what the alternatives below remove.

If that window is unacceptable in your environment:

- run the server (or a proxy in front of it) with a certificate the device already trusts, and
  remove the validation override from the command before running it; or
- copy `agents/rmm-agent-<os>-<arch>` to the device by other means and run
  `rmm-agent install --server … --token … --fingerprint …` by hand, comparing the fingerprint
  with the one in the console (`Settings → System`) — this is the manual install described in the
  README and it never disables validation. **Put the binary in an administrators-only directory
  first** — `C:\Program Files\HomelabRMM` or `/opt/homelab-rmm`, which is what the rendered
  installer uses — and run `install` from there. `install` registers the image path it was run
  from and copies nothing, so a binary left in `Downloads`, on the Desktop or in a build tree
  makes the file the SCM launches as LocalSystem (or systemd launches as root) writable by an
  unprivileged account: replacing it is SYSTEM at the next start, with no UAC prompt anywhere.
  `install` inspects that directory *and* the binary in it — a binary built or unpacked by an
  unprivileged account keeps an entry for that account wherever it is moved to — and warns,
  naming the accounts that can write them, but it does not refuse.

Verify a fingerprint out of band before pasting it; it is the trust anchor for that device.

**The name on the certificate is not the trust anchor, and it usually will not match.** The
names in the generated certificate are decided once, when the file is written, and never revised:
`localHostnames()` (`internal/server/tls.go`) supplies `localhost`, `127.0.0.1`, the machine's
**short** name from `os.Hostname()` (never an FQDN) and every non-loopback **IPv4** address the
host had at that instant. IPv6 is filtered out entirely (`ipn.IP.To4() != nil`), so a tailnet
`fd7a:…` address is never covered and a `100.x.y.z` one only if Tailscale was already up. The
public URL's host is prepended to that list, but only on the run that actually *generates* the
certificate — `--public-url`/`RMM_PUBLIC_URL` seeds the `public_url` setting immediately before
the certificate block (`internal/server/server.go`), so a MagicDNS name
(`<host>.<tailnet>.ts.net`) is a name on the certificate only when it was the `--public-url` host
on **first run**. Setting Public URL later, from *Settings*, changes what install commands and
alert mail say and nothing on disk. How would you know the name is not covered? From the log and
nowhere else: at startup, and again at every settings save, the server warns `certificate does
not cover the public URL` with the certificate's real names in `dns_sans=`/`ip_sans=`, and
follows it with `certificate name mismatch`, whose `detail=` is the remediation sentence.
`GET /api/system` returns that sentence as `cert_warning`, but no page in the console displays
it today, so a Settings screen that looks clean proves nothing (`docs/OPERATIONS.md` §6 shows
both lines).

So reaching the server by any other name — the MagicDNS name, an FQDN, an address added after the
certificate was written — produces a **hostname mismatch on top of the self-signed warning**, and
that pair is the normal state of a healthy deployment rather than a symptom of one. Every pinned
client here is built on exactly that: the agent sets `InsecureSkipVerify: true` and checks nothing
but the fingerprint (`internal/agent/conn.go`), the install script's Windows callback compares one
SHA-256 instead of returning `$true`, and the Android app accepts the WebView's `SSL_IDMISMATCH`
alongside `SSL_UNTRUSTED` once the pin matches and turns its hostname verifier off
(`docs/ANDROID.md` §2.2 rule 1). **A pinned client that also rejects on the name rejects every
legitimate connection**, so if you are reviewing one of those code paths, the missing hostname
check is the design and not an oversight. The fingerprint carries the whole decision — which is
why it is worth comparing character by character, out of band, once.

**Rotating the certificate rotates every pin at the same instant.** The fingerprint is the
SHA-256 of the leaf, so replacing `server.crt`/`server.key` — regenerating the self-signed pair to
cover a new name, or moving to a certificate from `--cert`/`--key` — invalidates every pin in the
fleet simultaneously, and the failures do not look alike. Agents fail **quietly**: each logs
`session ended err=… server certificate fingerprint mismatch: got <hex>` to `agent.log` and
retries with a backoff capped at a minute, for as long as it takes; nothing reaches the server, so
there is no server-side line either and the devices simply stop being online. The phone fails
**loudly and safely**: the app shows its pin-mismatch dead end with the expected and the presented
fingerprint side by side, and there is no way past it, because it never learns a pin from the
connection it is verifying. Browsers warn again. Plan the change before enrolling a fleet, keep
the old files until the fleet is back, and do not regenerate a certificate while chasing a name
mismatch — the mismatch is normal (above) and the regeneration is not free. The procedure, and
the alternative of a certificate the clients already trust (`tailscale cert`) with what that
costs, are in `docs/OPERATIONS.md` §6.

**Antivirus will have an opinion, and it is not wrong.** The one-line Windows form — a
`Net.WebClient` `DownloadString` piped into `iex`, with certificate validation turned off first —
is the shape of a dropper, and AMSI-aware scanners refuse it on sight (Bitdefender:
`ScriptContainedMaliciousContent`, before a line runs). The documented path is therefore the
two-step one: `Invoke-WebRequest -OutFile` the script, **read it**, then run it with
`powershell -NoProfile -ExecutionPolicy Bypass -File` (the default `Restricted` execution policy
refuses `& script.ps1`, so the bare form fails on a fresh client). That is strictly
better for review as well — the one-liner executes a script nobody looked at.

Expect the agent binary to be questioned too: the releases carry no Authenticode signature, so
SmartScreen and reputation engines have nothing to go on, and an agent that runs scripts as
SYSTEM and reads the event log scores highly with behavioural engines. Exclusions for
`C:\Program Files\HomelabRMM` and `%ProgramData%\HomelabRMM` are the usual answer; decide that
deliberately, because an exclusion is a hole you are choosing to keep. The manual install needs
neither the script nor the download.

## What is not protected

- **Anyone with a console account is root everywhere.** There is no per-device permission model
  beyond the three roles. Do not share accounts; create a `viewer` for people who only need to
  look.
- **The console is not hardened for the open internet.** No account lockout beyond the
  per-minute limiter, no WebAuthn, no IP allow-lists, no brute-force alerting. Keep it on the
  LAN or behind a VPN (WireGuard, Tailscale).
- **Behind a reverse proxy the client address is only as good as the proxy.** With
  `--trusted-proxies` set, anything that reaches the server from that network can claim any
  client address in `X-Forwarded-For`. Bind the HTTP listener to localhost when a proxy is used,
  never list a whole LAN as a trusted proxy, and never combine `--insecure` with a listener
  reachable from the network.
- **Script parameters are stored in clear text** in `script_runs.args`. The "Create local user"
  starter script warns about this: passwords passed as parameters are visible to every console
  user who can read runs. Prefer scripts that generate secrets on the device or read them from
  a vault.
- **Agent configuration is only as safe as the device.** `agent.json` holds the device key, and
  whoever is root or SYSTEM on a device has it. The file is protected by the platform and not by
  the Go file mode: `0600` and root ownership on Linux, and on Windows a *protected DACL* on
  `%ProgramData%\HomelabRMM` granting only `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`,
  re-applied at every agent start and inherited by the files inside (the `0600` Go passes there
  is ignored, and the console's own file browser reports a meaningless `-rw-rw-rw-` for Windows
  paths — check it with `icacls`). What it grants is **more than that device's identity**: it
  also holds `enroll_token`, deliberately kept so a device whose key was revoked can re-enroll
  unattended (see "The token stays on the device" above). Until that token expires or runs out
  of uses, whoever reads one device's `agent.json` can enroll new devices into the fleet and, with
  a victim's hostname, take over an offline device's record. Single-use, short-lived tokens keep
  that window small; a long-lived multi-use token turns every device that used it into a copy of
  the fleet credential.
- **Email is plain text.** Alert mail carries device names and messages; use STARTTLS/TLS to
  your relay and do not put secrets in alert titles.
- **The database is not encrypted at rest.** It is, however, readable only by the service
  account: 0750 on Linux, and on Windows the server replaces the data directory's inherited
  ACL with a protected one granting SYSTEM and Administrators only — the same lockdown the agent
  applies to `%ProgramData%\HomelabRMM`, and for the same reason (`BUILTIN\Users` inherits
  read-and-execute from `%ProgramData%`, which would expose `rmm.db` and `server.key` to every
  local account). The directory's **owner** is set as well: an owner keeps `WRITE_DAC` whatever
  the DACL says, so a standard user who pre-created the directory could otherwise hand the
  permissions straight back. One more entry is written when — and only when — the process doing
  the locking is neither SYSTEM nor an elevated administrator, which is what `rmm-server run
  --data-dir <dir>` from an ordinary shell is: **its own account**. Without that entry the other
  two deny it the database it is about to open, on a directory it has just protected and can no
  longer use. It is the directory's owner, so the entry grants it nothing it could not take
  anyway, and `BUILTIN\Users` stays out either way; the service and an elevated install get the
  SYSTEM + Administrators DACL unchanged. Anyone with administrative rights on the server host
  still has everything, as they always do.
- **Enrollment re-uses an offline device record** with the same hostname and OS. A rogue machine
  that knows a valid token and a victim's hostname could take over that record while the victim
  is offline (it would receive the victim's group/tags and queued runs, and the victim's own key
  stops working). The server cannot tell that apart from the reinstall it is there to support,
  so it does not refuse it — it *reports* it: a re-enrollment that adopts an existing record is
  audited as **`agent.rekeyed`** rather than `agent.enrolled`, logged at WARN with the source
  address, and written to that device's own event timeline. Only an **offline** record is
  adopted; an enrollment that collides with a hostname a device is currently using gets its own
  record instead (hostnames are not unique), which leaves two rows with one name in the console —
  that is audited as **`agent.duplicate_hostname`**, also at WARN and also on the new device's
  timeline. Keep tokens single-use and short-lived, and treat either entry, if you did not cause
  it, as an incident.
- **Remote desktop shows whatever is on screen**, including the lock screen and UAC prompts on
  Windows (by design, via the SYSTEM token). Sessions are audited. On Windows, an overlay privacy
  banner (`HomelabRMM - Remote Support Active`) is displayed across active monitors to inform the
  local user whenever a remote desktop session is active.
- **A `tech` can still make a device run code on a timer.** The admin gate covers the `command`,
  privileged-`file` and `allow_reboot` kinds, but a write account can create a baseline of the
  other kinds, enable it, enforce it and have every matched device act on it every minute. The
  blast radius of `tech` is deliberately close to `admin`; the difference is user management and
  the sharp kinds, not "cannot change devices".
- **Baseline check parameters are stored and served in clear text**, like script parameters, and
  are readable by every signed-in account including `viewer`.
- **A preview runs the draft's `check` scripts on real devices** before anything is saved. It never
  fixes, never writes to the device and never stores a result, but the code does execute — which is
  why the endpoint is audited, needs the write role, and needs **admin** for exactly the drafts
  saving would need admin for (a `command` check, a `file` check outside the managed trees, an
  `allow_reboot` check).

## Multi-Tenancy Scoping, RBAC & Hardening (VULN-001 - VULN-016)

The platform supports multi-tenant MSP/homelab operations through Organizations and Sites,
backed by strict tenant-scoping defenses and role-based access control:

1. **Tenant & Target Scoping (`org_scope`)**:
   - Users with the `tech` role can be assigned an `org_scope` (list of organization IDs). When
     configured, visibility and operational authority are strictly bounded to that scope.
   - **IDOR Protection (`VULN-001`)**: All agent endpoints (`/api/agents/{id}/*` — including script
     execution, file downloads, process killing, service management, device isolation, and deletion)
     enforce tenant boundaries. Requests for agents outside the caller's `org_scope` return
     `404 Not Found` rather than `403 Forbidden` to prevent tenant resource enumeration.
   - **Enrollment Hijacking Defense (`VULN-002`)**: Agents cannot adopt existing records or cross
     tenant boundaries without matching cryptographic keys. Technicians cannot reassign an agent's
     `org_id` or `site_id` via `PATCH /api/agents/{id}` (`VULN-010`).
   - **Ticketing & Comment PII Separation (`VULN-006`)**: Tickets are isolated by organization.
     Internal technician notes (`is_internal: true`) are restricted to technicians and admins, and
     are never exposed to end users via the client portal token interface.
   - **Fleet Tag Bypass Prevention (`VULN-007`, `VULN-015`, `VULN-016`)**: When a scoped technician
     schedules an ad-hoc task, configures a patch automation policy, or sets an alert rule using
     tags or fleet selectors, the target agent set is dynamically intersected with the technician's
     `org_scope` in the database. Technicians cannot reach unassigned tenant devices by targeting
     common tags (e.g. `tag:servers`).
   - **Baseline & Preview Scoping (`VULN-009`)**: Baselines evaluate and enforce exclusively against
     devices inside the user's permitted organizations. Baseline previews (`POST /api/baselines/preview`)
     similarly execute dry runs only on scoped agents.
   - **SSE Stream Tenant Isolation (`VULN-014`)**: The real-time Server-Sent Events stream
     (`GET /api/events`) filters all agent heartbeats, status updates, metrics, and ticket events
     against the subscriber's `org_scope`. Technicians never receive event frames for other tenants.

2. **Role Restrictions & Admin Gates**:
   - **Software Catalog (`VULN-003`)**: Creating, editing, or deleting global software packages
     (`/api/software-catalog`) requires the `admin` role. Technicians can trigger installs on scoped
     devices, but cannot alter package repositories or binaries.
   - **Automations & Fleet Updates (`VULN-008`, `VULN-011`)**: Accessing or modifying event automations
     (`/api/automations`, `VULN-008`), triggering fleet-wide agent updates (`POST /api/agents/update-all`, `VULN-011`),
     in-place server updates (`POST /api/server/update`), and full system audit logs (`/api/audit`) require full `admin` rights.
   - **Network Subnet Scanning (`VULN-013`)**: Initiating server-side network scans without an agent probe
     (`POST /api/network-scans`) requires the `admin` role (`VULN-013`). Technicians can only dispatch scans via online agents in their `org_scope`.

3. **Protocol & Parser Hardening**:
   - **Subnet Scan Bounding (`VULN-004`)**: Subnet discovery sweeps enforce strict CIDR bounds: targets
     must be private or loopback IPv4 ranges between /22 (1024 hosts maximum) and /30 (public and link-local ranges
     are rejected), preventing network flood or worker pool exhaustion.
   - **SNMP Packet Bounds (`VULN-005`)**: The internal SNMP v2c scanner parses UDP responses with strict
     buffer bounds, validated ASN.1 BER TLV lengths, and maximum recursion depth (32 levels), preventing buffer
     over-reads and panic conditions from malformed network responses.
   - **Client Portal Run Isolation (`VULN-012`)**: Device-authenticated portal users (`GET /api/portal/runs/{id}`)
     can only inspect runs triggered by the client portal on their own machine, preventing inspection of administrative runs or other devices.

4. **Device Network Isolation (Quarantine)**:
   - When an endpoint is suspected of compromise, operators can isolate it via
     `POST /api/agents/{id}/isolate` with `{"isolate": true}` (or release with `{"isolate": false}`).
   - **Linux**: Creates an `iptables` chain (`RMM_ISOLATE`) at the top of `INPUT` and `OUTPUT`.
     It permits loopback (`lo`), established connections, DNS (port 53), DHCP (ports 67/68), and
     outbound TCP traffic to the RMM server's host and port. All other traffic is dropped.
   - **Windows**: Configures Windows Advanced Firewall (`netsh advfirewall`) rules prefixed
     `HomelabRMM-Isolate-`, setting default profile policy to block inbound and outbound traffic
     while allowing loopback, DNS, and traffic to the RMM server IP and port.
   - In both cases, the RMM control channel remains alive for triage, script execution, and remote
     de-isolation.

5. **Named Pipe IPC Security (`rmm-desktop`)**:
   - The desktop tray companion communicates with the elevated `rmm-agent` on Windows via Named
     Pipe `\\.\pipe\homelab-rmm-portal`.
   - The pipe DACL is hardened via SDDL: `D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`:
     - `D;;GA;;;NU`: Explicit denial for Network Users to prevent remote access over SMB/file sharing.
     - `PIPE_REJECT_REMOTE_CLIENTS`: Rejects cross-machine pipe connections at the kernel level.
     - `SYSTEM` and `Administrators`: Full Control (`GA`).
     - Interactive Users (`IU`): Generic Read and Write (`GRGW`) to request portal passes.
     - Pipe connections enforce a concurrency limit (`maxClients = 8`) and a 30-second client
     deadline to prevent pipe slot starvation.

6. **Remote Desktop Multi-Monitor & Privacy Banner**:
   - Remote desktop streaming captures display frames across primary and secondary monitors. The
     client can switch active displays via protocol messages (`{"t":"monitor","index":<n>}`).
   - On Windows, a topmost, click-through, non-interactive overlay banner
     (`HomelabRMM - Remote Support Active`) is rendered across active monitors using layered window
     styling (`WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_NOACTIVATE`) to ensure
     users are clearly informed when remote control is taking place.

## Recommendations

1. **Keep the server off the public internet.** LAN only, or a VPN. If you must expose it, do so
   through a reverse proxy with its own authentication layer in front.
2. **Enable TOTP on every account**, starting with the first admin you create.
3. **Use the least role** that gets the job done; create a separate `viewer` account for
   dashboards on a wall.
4. **Trust the server certificate in your browser** once (`server.crt`), so a warning ever seen
   again means something. A name mismatch survives that import and is expected (above); a
   changed issuer is not.
5. **Short, single-use enrollment tokens**; delete leftovers.
6. **Back up `server.key` with the database** and protect the backup like a password store; it
   is what every agent, and the phone, pins. Restoring it is what lets a rebuilt server keep the
   fleet; generating a new pair strands every pinned client at once (`docs/OPERATIONS.md` §6).
7. **Keep the server and agents updated**, and let the server manage itself as a device so it is
   patched with the rest.
8. **Review the audit log** now and then; `login.failed` bursts and unexpected `shell.open` or
   `desktop.open` entries are the things to look for.
9. **Reverse proxies**: forward `Host` unchanged, bind the backend to `127.0.0.1`, pass
   `--trusted-proxies` with the proxy's address (otherwise `X-Forwarded-For` is ignored and
   every request is audited as coming from the proxy), and read the `--insecure` section of
   `docs/OPERATIONS.md` before choosing it.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository rather than a public issue, with the
version (`rmm-server version`), the component, and reproduction steps.
