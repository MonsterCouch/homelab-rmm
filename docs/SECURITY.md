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
refused, hidden from the list and purged a day after its expiry. The use is **consumed in the
same SQLite transaction that creates the device record**, with a conditional
`UPDATE ... WHERE uses_left > 0`, so devices racing on one token cannot stretch it: a one-use
token enrols exactly one device however many arrive at once. `-1` is the operator's "unlimited"
and is the **only** non-positive value that still enrols: a count the create endpoint would have
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
on every device it enrolled (0600, root/SYSTEM-readable, so anyone who is already root there can
lift it) until it expires — one more reason to prefer single-use tokens and short expiries. And
**deleting a device does not revoke the token on it**: the agent re-enrols within seconds as a
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

**First-run setup.** Until an account exists, `POST /api/auth/setup` would hand the first
administrator account — which is root on every device you later enrol — to whoever asked first.
A server that starts with an empty user table therefore mints a random **one-time setup code**
and prints it to the console and to `server.log` in the data directory. Every setup request must
present it (compared in constant time, and rate-limited like a login), **including one from
`127.0.0.1`**: a loopback peer address says nothing about who is at the far end of a same-host
reverse proxy, nothing about which local user on the server is asking, and nothing about whether
a page in the operator's own browser made the request. Requiring the code means whoever completes
setup has demonstrated they can read the server's console or log. The code is spent the moment
the administrator exists; it is minted per start, so if you lose it, restart the server before
anyone creates a user and read the new one.

The check and the insert run under one lock, so a first-run window produces exactly one
administrator however many requests arrive at once — the bcrypt hash between them used to be a
wide enough gap for eight.

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
`GET /api/enroll` is writer-only for the same reason: its body contains the enrolment token
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
settings change and user change is written to the `audit` table with user and source address,
along with `setup.refused` (a wrong setup code), `agent.enrolled`, `agent.rekeyed` and
`agent.duplicate_hostname`. A **service action or process kill is audited whether or not it
worked**: the attempt is what the log is read for, and a refusal carries
`"outcome":"failed"` with the device's own error, so "nobody tried to stop the antivirus" and
"somebody tried and was refused" are not the same empty log.

**Agent hardening.** Helper tools are resolved by absolute path in `System32` on Windows so a
writable directory on PATH cannot shadow `shutdown.exe`; commands never go through a shell;
command output is capped (32 MB / 10 MB) so a runaway process cannot exhaust memory; script
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
token must match `^[A-Za-z0-9_-]{16,64}$` **and** still be a live enrolment token (anything else
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

The enrolment commands the console prints contain
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
  README and it never disables validation.

Verify a fingerprint out of band before pasting it; it is the trust anchor for that device.

**Antivirus will have an opinion, and it is not wrong.** The one-line Windows form — a
`Net.WebClient` `DownloadString` piped into `iex`, with certificate validation turned off first —
is the shape of a dropper, and AMSI-aware scanners refuse it on sight (Bitdefender:
`ScriptContainedMaliciousContent`, before a line runs). The documented path is therefore the
two-step one: `Invoke-WebRequest -OutFile` the script, **read it**, then run it. That is strictly
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
- **Agent configuration is only as safe as the device.** `agent.json` (0600, owned by root /
  LocalSystem) contains the device key; whoever has root on a device has that key. It grants
  nothing beyond that device's own identity.
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
- **Enrolment re-uses an offline device record** with the same hostname and OS. A rogue machine
  that knows a valid token and a victim's hostname could take over that record while the victim
  is offline (it would receive the victim's group/tags and queued runs, and the victim's own key
  stops working). The server cannot tell that apart from the reinstall it is there to support,
  so it does not refuse it — it *reports* it: a re-enrolment that adopts an existing record is
  audited as **`agent.rekeyed`** rather than `agent.enrolled`, logged at WARN with the source
  address, and written to that device's own event timeline. Only an **offline** record is
  adopted; an enrolment that collides with a hostname a device is currently using gets its own
  record instead (hostnames are not unique), which leaves two rows with one name in the console —
  that is audited as **`agent.duplicate_hostname`**, also at WARN and also on the new device's
  timeline. Keep tokens single-use and short-lived, and treat either entry, if you did not cause
  it, as an incident.
- **Remote desktop shows whatever is on screen**, including the lock screen and UAC prompts on
  Windows (by design, via the SYSTEM token). Sessions are audited; there is no on-screen consent
  prompt for the person at the device.
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
9. **Reverse proxies**: forward `Host` unchanged, bind the backend to `127.0.0.1`, pass
   `--trusted-proxies` with the proxy's address (otherwise `X-Forwarded-For` is ignored and
   every request is audited as coming from the proxy), and read the `--insecure` section of
   `docs/OPERATIONS.md` before choosing it.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository rather than a public issue, with the
version (`rmm-server version`), the component, and reproduction steps.
