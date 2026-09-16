# Baselines: desired state with drift detection and self-healing

A **baseline** declares how a device should look. It is a named list of **checks**, each with a
kind, kind-specific parameters, a severity, an OS filter and a flag saying whether the agent may
fix it. Baselines are assigned to devices with the same target model as tasks and alert rules
(all / agents / groups / tags / OS). The agent evaluates its assigned baselines on their interval,
**offline too**, reports every pass, and, when the baseline is **enforced** and the check allows
**remediation**, fixes the drift itself and reports the check as `fixed`.

Wire types live in `internal/protocol/protocol.go` (`BaselineSpec`, `BaselineCheck`,
`BaselineReport`, `BaselineResult`; messages `TypeBaseline`, `baseline.evaluate`,
`baseline.remediate`, `baseline.preview`). Parameter shapes, limits and validation live in
`internal/baselines` and are the **single definition** both sides use: the server rejects an
invalid check with a 400 naming the field, the agent re-validates at evaluation time and reports
`error` rather than passing an unvalidated argument to a command.

> `internal/protocol/protocol.go` still comments `ReqBaselineEvaluate` / `ReqBaselineRemediate`
> as "reply `[]BaselineReport`". That is stale — see [One report, one ingest](#one-report-one-ingest).

## States

Each (device, check) has a state after every pass:

| state | meaning |
|---|---|
| `pass` | compliant |
| `fail` | drift observed and not fixed (remediation not allowed, baseline not enforced, a fix declined to start, or a preview) |
| `fixed` | drift was observed, the remediation ran and the re-check passed in the same pass |
| `error` | the check itself could not run (missing tool, timeout, permission), or the fix ran and the re-check still fails; `detail` says why |
| `skipped` | the check does not apply: OS filter, kind not implemented on this platform, or a kind this agent is too old to know |

A check with no row yet is `unknown`: it is simply absent from the API's `results` array. The
console renders it as an `unknown` chip rather than an empty cell — "this device has not answered
for this check yet" is a state an operator can act on, and the status view filters on it.

An **unknown kind is `skipped`, never `error`.** An agent older than the server will meet kinds it
does not implement; reporting `error` would open a drift alert on every device in the fleet the
moment a new kind ships. `observed` then reads `kind <k> is not supported by agent <version>` and
the console shows it as a hint to upgrade the agent.

### Transitions

The server stores one row per (device, check) and compares every report against it:

- `since` is the server time of the first report carrying the **current** state. It is unchanged
  while the state repeats, and reset on any change — `fail -> error` included. It is *not* reset
  by a version bump, a params edit or the stale flag.
- A **history row** (`baseline_history`), the agent event and the `drift_detected` /
  `drift_fixed` automation fire **only on an actual state change**, never once per pass. A
  device's very first row for a check writes no history when that first state is `pass` or
  `skipped` — that is establishing the baseline, not a transition.
- A **drift alert** is opened for *every* report whose state is `fail` or `error`, not only on the
  transition. `open()` already dedupes on the key, and transition-only opening loses the alert
  forever when the first failing report lands inside a maintenance window.
- The dedupe key is exactly `drift:<baseline_id>:<check_id>:<agent_id>`, built from ids and never
  from names. `rule_kind` is `drift` and `rule_id` is NULL — a drift alert has no `alert_rules`
  row, and `drift` is deliberately **not** in `validRuleKinds` (that map gates operator-created
  rules).
- Severity `info` never opens an alert. It writes history, updates the matrix and broadcasts SSE,
  so informational drift does not fill the Alerts page with rows nothing resolves. `warning` and
  `critical` open alerts.
- `fail -> error` is a state change (new `since`, a history row) but does **not** resolve and
  re-open the alert: the key is the same, so it stays open.
- `fail|error -> pass|fixed` resolves the alert.

### Flap control

A check something else keeps putting back — a GPO, a package hook — would otherwise raise an event
and a `drift_fixed` automation every interval forever. So a run of consecutive `fixed` passes is
**one** event and one automation: they fire only when the previous stored state was not `fixed`.
After **5 consecutive `fixed` passes** the server opens a second alert, `<check> keeps drifting
back`, with key `driftflap:<baseline>:<check>:<agent>` at the check's severity. The agent keeps
fixing; the alert is the signal that an operator should find out what keeps breaking it.

## Evaluation (agent)

- **One evaluation goroutine per agent process.** Passes never overlap, and the next pass is
  scheduled `interval` after the previous one **finished**.
- The start-up pass runs 20 s + a random 0–10 s after the agent starts; a config change schedules
  a pass 5–30 s out (randomised), so a fleet-wide edit does not arrive as a thundering herd.
- `interval_sec` is clamped to [60, 86400] (default 3600) on both sides; `timeout_sec` per check
  to [5, 600] (default 60) for **every** kind. A check that exceeds its timeout is `error` with
  detail `timed out after Ns` and the pass continues with the next check. The deadline is enforced
  by the engine, not by the kind, so a check wedged in a syscall (a hung NFS mount, a stuck SCM
  query) cannot stop the device evaluating. A timed-out check still reports the `expected` label it
  would have compared against (every kind publishes it before it starts work), with `observed`
  `no answer`. A `command` check gets its own deadline a **full second** shorter than the engine's,
  so the script runner's timeout normally wins the race and the partial output the script printed
  reaches `detail`; the `timed out after Ns` it reports is the check's own `timeout_sec`.
- Remediation runs only when `spec.enforce && check.remediate && state == fail`. After a fix the
  check is evaluated again: pass → `fixed`, otherwise `error` with the fix output in `detail`.
- A check whose fix **failed** is not retried for 60 minutes. The hold-off is keyed by check id,
  persisted (so a restart loop cannot re-run a destructive failing fix every start-up) and cleared
  when the check next passes or when the check's params change. A manual `baseline.remediate`
  ignores the hold-off and clears it on success.
- At most **one remediation runs per device at a time**. `package`, `windows_feature` and
  `reboot_pending` fixes additionally take the same process-wide package/servicing mutex
  `installUpdates` holds, so a baseline fix can never run apt/dnf/winget or DISM while a patch
  install is running; if it is held the check is `error` with detail
  `another package operation is in progress` and is retried next pass with no hold-off.
- A remediation is **skipped** (the state stays whatever the probe found, with the reason in
  `detail`, and no hold-off) while a script run is live, while a shell session is open for a
  reboot, or when today's one reboot has already been used. "Nothing was started" is not an error.
- `expected` and `observed` are truncated to 256 bytes, `detail` to 4 KiB, and a whole report to
  1 MiB (details are dropped first, then whole results, with one synthetic `error` result saying
  so). They never carry secrets from params — but see [Security](#security).

### Offline, restart and reconnect

`<config dir>/baselines.json` (mode 0600, written tmp+rename like `agent.json`) holds the specs,
the last report per baseline, the fix hold-offs and the reboot bookkeeping. It is loaded **before
the first connection**, so a device that reboots while the server is unreachable still evaluates.
A file that will not parse is logged and ignored — the agent starts with no baselines, never
fatally. `agent.json` is not extended.

On reconnect the agent re-sends its cached last report per baseline **exactly once**, with the
original `TS`, `Version` and `Trigger` unchanged, and only for baselines still present at the same
version. Cached reports older than 7 days are dropped instead. The start-up pass ~20 s later then
supersedes it.

The pushed set is always **complete**: every `agent.config` and the `welcome` frame carry the full
set of matching enabled baselines, never a delta. The agent replaces its whole set on every config
push; a baseline that disappears (unassigned, disabled, deleted) stops immediately, its cached
report, hold-offs and timer are dropped, and an in-flight pass for it is allowed to finish but its
report is discarded rather than sent.

## Check kinds

Parameters are a JSON object. Unknown keys are **rejected by the server** (400, so a console typo
never becomes a check that silently does nothing) and **ignored by the agent** (so an agent one
release behind keeps evaluating the fields it understands). A check whose kind is not implemented
on the device's OS, or whose `os_filter` does not match, is `skipped`.

| kind | params | platforms | fix |
|---|---|---|---|
| `service` | `name`, `state` (`running`\|`stopped`), `start_type` (`auto`\|`manual`\|`disabled`\|`any`, default `any`) | windows, linux | start/stop and set the start type (SCM / `systemctl enable`\|`disable`) |
| `package` | `name` (a package id, a winget id, **or** a Windows program name as the Uninstall keys spell it), `state` (`present`\|`absent`), `min_version` (optional, present only), `allow_winget` (windows, default false) | linux (dpkg/rpm/pacman/zypper), windows (Uninstall registry keys + `winget list`) | linux: the package manager, non-interactively; windows: refused unless `allow_winget` |
| `registry` | `path` (`HKLM\…` or `HKCU\…`), `name`, `type` (`dword`\|`qword`\|`string`\|`expand_string`\|`multi_string`), `value` | windows | create the key if needed and set the value |
| `file` | `path`, `state` (`present`\|`absent`), and for `present` optionally `content`, `sha256`, `contains`, `mode` (**linux only**), `owner` (**linux only**) | windows, linux | present: write `content` and set mode/owner; absent: delete a regular file. `sha256`/`contains` without `content` are check-only |
| `command` | `language` (`bash`\|`sh`\|`powershell`\|`cmd`\|`python`), `check`, `fix` (optional), `expected` (label) | windows, linux | run `fix`, then re-run `check` |
| `group_members` | `group`, `allowed` (names), `mode` (`exact`\|`subset`, default `subset`), `allow_domain` (default false) | windows (local groups), linux (`/etc/group` + `getent`) | remove members that are not allowed; **never adds** |
| `firewall` | `enabled` (default true) | windows (all three profiles), linux (ufw, else firewalld, else `skipped`) | enable/disable |
| `time_sync` | `enabled` (default true) | windows (`w32time` + a real source), linux (`timedatectl`) | enable |
| `sysctl` | `key`, `value` (always a string) | linux | `sysctl -w` **and** rewrite `/etc/sysctl.d/90-homelab-rmm.conf` |
| `windows_feature` | `name`, `state` (`enabled`\|`disabled`) | windows | `Enable-`/`Disable-WindowsOptionalFeature -NoRestart` |
| `reboot_pending` | `max_hours` (≥1), `allow_reboot` (default false) | windows, linux | reboot with a 60 s notice, only with `allow_reboot` |
| `disk_free` | `mount`, `min_free_pct` in (0,100) | windows, linux | check only |

`expected` and `observed` are short human strings: `running / auto` vs `stopped / disabled`,
`present 8.5.0` vs `absent`, `domain/private/public: on/on/off`.

### Kind notes that matter

Several kinds do **not** behave the way a one-line table suggests. These rules are enforced by the
agent whatever the server sent.

**`service` — start types.** Windows reports `boot|system|auto|auto_delayed|manual|disabled|unknown`;
systemd reports `auto|manual|disabled`. So: `auto` **matches `auto_delayed` too**, and fixing to
`auto` does not clear the delayed-start flag on a service that is already `auto_delayed`. Observed
`boot`, `system` or `unknown` never satisfies any expectation — it is `fail` with the real observed
string — and remediation is **refused** for `boot`/`system` (`refusing to change a boot/system
start type`: that is how a machine is made unbootable). On Linux there is no distinguishable
`manual`, so `start_type: manual` is check-only there (`systemd has no manual start type; use
any`), and `auto` on a `static`/`indirect`/`generated` unit is `error` with the systemctl message
rather than an endless fix/re-check loop. The agent also **refuses to remediate its own
service or unit at all** (`refusing to change the RMM agent's own service`) — stopping or disabling
it would kill the process performing the remediation, and a device that is no longer running the
agent can never be told to put it back. The check still reports the state.

**`package` on Windows is check-only by default.** `installUpdates` already refuses winget from the
service account, and `resolveWinget` documents that winget is usually unavailable to SYSTEM. So a
Windows `package` fix is `error` with detail `winget is not usable from the agent service account`
unless the params set `allow_winget: true` **and** winget resolves; even then the install runs
`--silent --accept-package-agreements --accept-source-agreements --disable-interactivity` under a
15-minute cap with its whole output in `detail`. On Linux the manager is detected in the order
apt/dpkg, dnf/rpm, pacman, zypper and installs run non-interactively through `exec.Command` args.

**`package` names have two legal spellings**, because the two platforms match on different things.
A package-manager id or a winget id (`unattended-upgrades`, `Git.Git`) is one; a Windows program
name exactly as the Uninstall keys hold it — `7-Zip 26.03 (x64)`, `GitHub CLI`,
`Intel® Chipset Device Software` — is the other, and it is what the Windows `package` kind compares
against (case-insensitively, after trimming). Such a name may be any single line of printable text
up to 256 characters, but it may not begin with a space or with anything that is not a letter or a
digit, so it can never be read as an option by the winget command line it is passed to as one
argument. The **device** then re-validates with its own platform rule: a name dpkg could never hold
is `error` on a Linux device (`… is not a valid package name`) rather than a 400 that would stop
the Windows baseline being written at all — give such a check `os_filter: windows`.

**`min_version` comparison is specified.** Strip an epoch (`1:`) and everything from the first `-`,
`~` or `+`, then compare the remaining dot-separated fields numerically left to right, missing
fields as 0, a non-numeric field as a string. If either side yields no numeric field at all the
result is `error` with `cannot compare versions "X" and "Y"` — **never** `fail`. A false drift
alert that self-heals by installing a package is worse than an error.

**`file` path safety.** The path must be absolute and free of `..` after cleaning, and the agent
refuses (state `error`) if any component of the parent chain is a symlink. Denied on both sides:
`/proc`, `/sys`, `/dev`, `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers` (and `/etc/sudoers.d` unless
`state: present` with explicit `content`), the agent's own configuration directory,
`C:\Windows\System32\config`, and the agent's ProgramData directory.
A path is compared as the filesystem sees it, not as it was spelled: the server refuses any
component in NTFS 8.3 short form (`HOMELA~1`, `PROGRA~1`) outright — it cannot see the device's
filesystem, and such a name can stand for any directory at all, so it never counts as "inside
ProgramData" for the admin gate either — and the agent resolves short names, case and symlinks on
both sides before comparing with its own configuration directory.
`C:\Windows\System32\drivers\etc\hosts` is allowed but **audited**. `state: absent` removes a
**regular file** only — never a directory, never recursively. `mode` is a 3- or 4-digit octal
≤ 0777 with no setuid/setgid/sticky bit. Writes are tmp+rename in the same directory, preserving
mode and owner when the file already exists.

**`file`: `mode` and `owner` are Linux-only and are IGNORED on Windows.** NTFS ACLs are not
expressible as `0644`, so on a Windows device neither field is checked and neither is applied: they
are dropped from the `expected` label, the result reads
`present, mode and owner are not checked on Windows` in `observed`, and a check that names them can
still report `pass`. They are accepted rather than refused on write because one baseline is meant to
cover a mixed fleet — the same `file` check carrying `mode: "0644"` is enforced on the Linux devices
it matches and ignored on the Windows ones. If the Windows half matters on its own, give the check
`os_filter: windows` and leave `mode`/`owner` out.

**`group_members` is the most dangerous kind**, so the agent enforces its own rules. It never
removes the built-in Administrator (well-known RID 500) or `root`/uid 0; never removes the account
the agent service runs as; never removes the **last** remaining member of `Administrators`, `sudo`,
`wheel`, `adm` or `root` — if applying the removals would empty such a group it applies **none** of
them and reports `error` with `refusing to empty <group>`; and never removes a domain principal (a
name with `\` or `@`) from a local group unless `allow_domain: true` — it reports that as drift
instead. A member name beginning with `-` or `/` is reported as drift and never passed to `gpasswd`
or `net localgroup`, which would read it as an option. On Linux, accounts whose **primary** group is
the target count as members (they never appear in `/etc/group`) and are always protected: they are
drift you report, not drift you fix. `mode` semantics: `subset` (the default) means observed
members must be a subset of `allowed` and extras are removed; `exact` means membership must equal
`allowed` — extras are removed but **missing members are never added**, so an `exact` check with a
missing member ends `fail`, or `error` if a remediation ran.

**`registry`.** Only `HKLM` and `HKCU` roots. Under the SYSTEM service account **`HKCU` is the
service's own hive, not the signed-in user's** — the console labels it so and the seed never uses
it. Keys are opened `WOW64_64KEY`. `HKLM\SAM`, `HKLM\SECURITY` and the agent's own service key are
denied. The JSON type of `value` is fixed by `type` (number for `dword`/`qword` within range,
string for `string`/`expand_string`, array of strings for `multi_string`); anything else is a 400
server-side and `error` agent-side. `expand_string` compares the **unexpanded** stored value. A
missing key or value with remediation off is `fail`, not `error`.

`type` also fixes the type the value must be **stored** as on the device: `dword` reads a
`REG_DWORD` and nothing else, `qword` a `REG_QWORD`, `string` a `REG_SZ`, `expand_string` a
`REG_EXPAND_SZ`, `multi_string` a `REG_MULTI_SZ`. A value stored as another type is `error`
(`the check declares dword (REG_DWORD) but the value is stored as REG_QWORD`), never `pass`: the
pairs are not interchangeable, a 64-bit value read as a `dword` would compare only its low 32 bits,
and remediating such a check would rewrite the value with a different registry type.

**Registry path characters.** A key name may contain anything Windows allows, which is everything
but a backslash: GUID braces (`HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-…}`,
`HKLM\SOFTWARE\Classes\CLSID\{…}`), parentheses, commas, apostrophes and non-ASCII are all fine —
the path reaches `registry.OpenKey`, never a command line. What is refused, with a 400 that names
the offending part: a root other than `HKLM`/`HKCU`, an empty key name (a doubled or trailing
backslash), a wildcard (`*`, `?`), a control character, a path over 1024 characters or a key name
over 256, and the denied hives above.

**`firewall` / `time_sync` / `sysctl` / `windows_feature` / `disk_free`.** `enabled` defaults to
**true** when absent, so `{}` means "must be on". Windows firewall requires all three profiles to
match (observed `domain/private/public: on/on/off`); Linux uses ufw if present, else firewalld,
else reports `skipped` with `no supported firewall` — never `fail`. Windows time sync wants
`w32time` running and a real source (`Local CMOS Clock` and `Free-running System Clock` do not
count); Linux reads `timedatectl`. `sysctl` reads `/proc/sys/<key with dots as slashes>` and the
fix runs `sysctl -w` **and** rewrites `/etc/sysctl.d/90-homelab-rmm.conf` as a whole file the agent
owns — one sorted `key = value` line per managed key, tmp+rename, so concurrent sysctl checks do
not clobber each other. `windows_feature` fixes run **without** `-All`, so a feature whose parent is
disabled fails loudly rather than enabling a tree nobody asked for. A `windows_feature` name no
optional feature has is `error` with `there is no optional feature named '<name>' on this device`,
the way an unknown service is — `Get-WindowsOptionalFeature` returns nothing for it rather than
failing. `disk_free` normalises `mount` to `C:` form on Windows and a `/`-prefixed path on Linux;
an unknown mount is `error`, not `fail`, and the mount is always named in `expected` and `observed`.
**A bare `/` or `\` is not a Windows mount**: on a Windows device it is `error`
(`/ is not a mount point on this device: a Windows mount is a drive such as C:, or the path of a
mounted folder`), not a silent measurement of whichever drive the agent runs from. A mixed-fleet
`disk_free` check therefore needs one check per platform with `os_filter` set, not a single `/`.

**`reboot_pending`.** With `allow_reboot: true` the check may only be created by an **admin**, is
audited as `baseline.reboot_check`, and the console asks for a typed confirmation. The agent
refuses to reboot while any script run or shell session is live and allows at most **one
baseline-initiated reboot per device per 24 h** (persisted). It always goes through the existing
`powerAction` with a 60 s notice. Because a re-check one second after scheduling would report
`error`, a scheduled reboot is reported as `fail` with `fixed: true` and
`a restart was scheduled with a 60 second notice`. Server side, a baseline whose targets are
`{"all": true}` and which contains an `allow_reboot` check is refused unless `enforce` is false or
the request carries `"confirm_fleet_reboot": true`.

**`command` is arbitrary root/SYSTEM code** — see [Security](#security).

## Limits

Enforced server-side on write and defensively on the agent:

| | |
|---|---|
| `name` | ≤ 120 characters, counted in characters and not bytes (baseline and check) |
| `description` | ≤ 2000 characters |
| params JSON | ≤ 16 KiB per check — except `command` (2 × 64 KiB + 4 KiB) and `file` (256 KiB + 8 KiB), whose payloads could not otherwise fit |
| `command.check` / `command.fix` | ≤ 64 KiB each |
| `file.content` | ≤ 256 KiB |
| checks | ≤ 64 per baseline |
| baselines | ≤ 100 per server, ≤ 16 matching one device (the extras are dropped from the push, by id, with a log) |
| `expected` / `observed` | ≤ 256 bytes each (truncated with an ellipsis) |
| `detail` | ≤ 4096 bytes |
| a whole report | ≤ 1 MiB |
| `evaluate` `agent_ids` | ≤ 500 (empty = every matched device) |
| `preview` `agent_ids` | 1–10 |

## Versions

`baselines.version` starts at 1 and is incremented by exactly 1 on every successful POST/PUT that
changes a field the **agent** receives: `name`, `enforce`, `interval_sec`, or any check field
including its position. It is *not* bumped for `description`, `notify_email`, `targets` or
`enabled` — the agent never sees those, and toggling `enabled` simply moves the baseline in or out
of the pushed set. The bump, the check writes and the stale marking all happen in one transaction;
the server never decrements or reuses a version.

On a bump, existing `baseline_results` are marked `stale = 1` rather than deleted, so the console
shows the last known state greyed as "awaiting re-evaluation" instead of an empty matrix. Stale
results count as `unknown`: out of both the numerator and the denominator of compliance. The next
accepted report for the current version clears the flag.

The agent echoes the version it evaluated. The server **ignores** a report whose version is lower
than the stored one, and ignores (logging once per agent per minute) one that is higher — which can
only mean a rolled-back database.

## Check identity

`baseline_checks.id` is the only identity a result, a history row or an alert key ever uses;
`position` is presentation only, and renumbering it never renumbers ids. The table is
`INTEGER PRIMARY KEY AUTOINCREMENT` on purpose: SQLite otherwise reuses the largest free rowid
after a DELETE, and a recycled id would inherit the dead check's results, history and still-open
drift alert.

**`PUT /api/baselines/{id}` is a merge, never a delete-and-reinsert.** Per element of `checks`: no
`id` (or `id: 0`) inserts; an `id` belonging to this baseline updates in place; an `id` belonging to
another baseline or to nothing is a 400 `unknown check id`; the same id twice is a 400
`duplicate check id` with nothing written. Every existing check whose id is absent from the body is
deleted, and in the same transaction its `baseline_results` go with it and its drift alerts are
resolved through the alert engine's resolve path, so the SSE `alert` event and the `alert_resolved`
automation fire. `baseline_history` rows stay: they store a denormalised `check_name` and the
`check_id` column carries no foreign key, so the audit trail survives a deleted check, a deleted
baseline and a deleted device.

Changing `kind` on an existing id is **not** an update: the server treats it as delete + insert
(new id, the cleanup above), because `expected`/`observed` from the old kind are meaningless under
the new one. Changing only `params`, `name`, `severity`, `remediate`, `os_filter` or `timeout_sec`
keeps the id and the stored results, marking them stale.

## Report ordering

`BaselineReport.TS` is the **device** clock and cannot be trusted across a reboot. The server
stamps `received_at` itself and applies two guards: the version guard above, and a per-baseline
monotonic guard (`baseline_state`) that ignores a report whose `TS` is strictly lower than the last
one seen at the same version. `checked_at` in the results table is the agent's `TS`; `since`,
`received_at`, `last_report` and every retention decision use server time. A `TS` more than 24 h
ahead of the server is clamped to `received_at` and logged once.

`Trigger` is validated against `schedule|startup|config|manual|remediate|preview`; anything else is
stored as `schedule` and logged at debug. It is kept in `baseline_state.last_trigger` and shown in
the device view, because "when did this last actually run, and why" is the first question about a
device that has been offline.

## One report, one ingest

The `baseline.evaluate` and `baseline.remediate` replies are **ACKs only**:
`{"accepted":true,"baseline_ids":[1,2]}` and
`{"accepted":true,"baseline_id":4,"check_ids":[12,13]}`. The results arrive separately, as exactly
one `TypeBaseline` frame per completed pass. A reply carrying the report as well would double every
transition, every alert and every automation.

`baseline.preview` is the one exception: its reply **is** the `BaselineReport` and no
`TypeBaseline` frame accompanies it. An unsaved spec has no check ids, so the server assigns
synthetic negatives before sending — check *i* gets `id = -(i+1)` — and echoes the mapping in
`spec_checks[]`. The agent treats ids as opaque. The server drops, without storing, any
`TypeBaseline` frame whose trigger is `preview`, whose baseline it cannot match to an assigned
enabled baseline, or whose results carry `check_id <= 0`.

A preview **never fixes and never persists**: the agent ignores `spec.enforce` and every
`check.remediate`, never runs a `fix`, never writes its state file and never touches its schedule,
hold-offs or reboot bookkeeping. Drift reports `fail`, never `fixed`. A preview request also
carries an expiry: one that has been queued past the caller's deadline is dropped rather than run,
so the operator's `check` scripts do not execute on a device for a console that gave up minutes ago.

## Server

### Schema (migration 4)

`baselines` (id, name, description, targets, enforce, interval_sec, notify_email, enabled, version,
created_at, updated_at) · `baseline_checks` (id AUTOINCREMENT, baseline_id → baselines ON DELETE
CASCADE, position, name, kind, params, remediate, severity, os_filter, timeout_sec) ·
`baseline_results` (agent_id, check_id, baseline_id, state, expected, observed, detail, fixed,
duration_ms, version, stale, checked_at, received_at, since, PK (agent_id, check_id)) ·
`baseline_state` (agent_id, baseline_id, version, last_report_ts, last_received_at, last_trigger,
PK (agent_id, baseline_id)) · `baseline_history` (id, agent_id, baseline_id, check_id, check_name,
ts, from_state, to_state, detail). `baseline_history.agent_id` and `.check_id` deliberately carry
**no** foreign key so history outlives a deleted device or check; every other FK is enforced
(`foreign_keys(ON)` is in the DSN), which is why ingest re-reads check membership inside its
transaction.

### Ingest

`hub.readLoop` routes `TypeBaseline` through `ac.enqueue` beside inventory and events — 5 s
push-back, then a warning, **never** silently droppable like metrics, because the frame is the only
record of an offline pass — and `ingestLoop.handle` calls the ingest hook.

One `withTx` per report. Inside it: load `{check_id → {baseline_id, name, severity, remediate}}`
for the baseline; drop results whose `check_id` is not in that map or is ≤ 0; keep the **first**
occurrence of a repeated check id and stop once every live check has been seen, so one frame can
never ask for unbounded work on the single SQLite connection; upsert; write history rows for state
changes. Alert opens and resolves, automation fires, the digest mail and the SSE broadcast all run
**after** the commit — the alert engine and `sched.automation` take the same connection and would
serialise badly inside the transaction.

### Config push

`agentConfig` resolves `cfg.Baselines` **after** `SettingJSON("agent_defaults", …)` and clears the
field first; `handlePutSettings` and `loadSettings` null `AgentDefaults.Baselines` before storing,
so a baseline set can never be frozen into the operator-editable settings blob and pushed to every
device regardless of targets.

Every baseline create, update, delete, enable and disable pushes to the **union** of the previously
matched and the newly matched online devices, and `handleUpdateAgent` pushes when `GroupID`,
`ClearGroup` or `Tags` are present. Group delete snapshots its members before the `ON DELETE SET
NULL` fires. When a device stops matching — a targets edit, a disable, a delete, a group or tag
change — the server deletes that device's `baseline_results` and `baseline_state` rows for the
baseline and resolves its open `drift:` alerts. Nothing else resolves a drift alert:
`scheduler.purge()` auto-closes only `script_failed`, `patch_failed` and `event`.

### Email

`openDrift` is always called with `notify = false`: the first evaluation of a 7-check baseline over
20 devices would otherwise send 140 mails. Instead, after a report is fully ingested the server
sends **at most one digest per (agent, baseline) per report**, only when the baseline has
`notify_email` and at least one newly-transitioned check has severity `critical`, subject
`[RMM CRITICAL] <device> - baseline <name>`, body listing each check with expected vs observed —
and suppressed if one was sent for that pair in the last 60 minutes.

### Compliance

Per device per baseline: `applicable = pass + fail + fixed + error` (all results minus `skipped`
minus stale/unknown); `score = 100 × (pass + fixed) / applicable`; when `applicable == 0` the score
is **null**, never 0 and never 100. Per baseline: the unweighted mean of the non-null device
scores — devices matched but never reported are counted in `devices` and `devices_unknown` but
excluded from the mean. Fleet: the unweighted mean of the non-null per-device scores over devices
with at least one assigned baseline, null when there are none. An offline device keeps its last
score (shown with its age) and does not drag the fleet score to zero. Percentages are rounded to
one decimal.

### Retention

`baseline_history` is purged in `scheduler.purge()` on the **events** retention setting (30 days by
default).

### Seed

Two baselines on first run, guarded by a new `seeded_baselines` key and an empty-table check — not
the existing `seeded` key, which every v0.1.0 database already has set, so the seeds do appear on
upgrade. Both ship **disabled and unenforced**, and every destructive check in them ships with
`remediate = 0`:

- **Windows workstation hygiene** — firewall on (all profiles), time sync on, SMB1 server disabled,
  Print Spooler stopped and manual, review the members of Administrators, no reboot pending over
  72 h, `C:` at least 10 % free.
- **Linux server hygiene** — SSH running and enabled shipped as **two** checks, `ssh` for
  Debian/Ubuntu and `sshd` for RHEL/SUSE (a seed naming a unit that does not exist would `error`
  and drift-alert the whole fleet), time sync on, firewall on where one is installed,
  `net.ipv4.ip_forward = 0`, `unattended-upgrades` present, root filesystem at least 10 % free, and
  **report-only** reviews of `sudo` and `wheel` membership with an empty `allowed` list — shipping a
  hard-coded allow-list there would be a fleet-wide privilege-removal button one toggle away.

Only `firewall`, `time_sync` and `sysctl` carry `remediate = 1`, and even those do nothing until an
operator enables *and* enforces the baseline.

## API

All under the session cookie. Timestamps are unix seconds; arrays are never null; errors are
`{"error":"…"}` with 400 (validation), 403 (role), 404 (`not found`), 409 (`agent is offline`).

| method and path | role | purpose |
|---|---|---|
| `GET /api/baselines` | session | list with compliance and device counts |
| `POST /api/baselines` | write | create (201) |
| `GET /api/baselines/{id}` | session | one baseline with its checks, ordered by position |
| `PUT /api/baselines/{id}` | write | merge-save (see [Check identity](#check-identity)) |
| `DELETE /api/baselines/{id}` | write | delete, cleaning up results and alerts fleet-wide |
| `GET /api/baselines/{id}/status?limit=` | session | the device × check matrix (limit default 200, max 500, `truncated`) |
| `POST /api/baselines/{id}/evaluate` | write | fan-out; **always 200** with `queued\|offline\|error` per device |
| `POST /api/baselines/{id}/remediate` | write | one device; 409 when offline, 400 when unmatched |
| `POST /api/baselines/preview` | write (admin for the checks below) | dry run an unsaved spec; **always 200** with `ok\|offline\|timeout\|error` per device |
| `GET /api/agents/{id}/baselines` | session | device view: every assigned baseline, its checks and current results |
| `GET /api/agents/{id}/baselines/history?limit=&baseline_id=` | session | transitions, newest first (default 100, max 1000); `baseline_id` narrows them to one baseline **in SQL**, which is what the status view's per-baseline drawer asks for |
| `GET /api/compliance` | session | fleet summary for the dashboard |

`preview` and `remediate` cause code to run on a device, so they need the write role even though
they read. Creating, editing **or previewing** a baseline that contains a `command` check, a `file`
check writing outside `/etc` or `ProgramData`, or an `allow_reboot` check additionally needs
**admin**. Preview is on that list because it *runs* the draft: a `command` check's `check` script
executes as SYSTEM/root on every device named in the request, so a gate that only covered the save
path would be decoration — a non-admin could preview the check instead of saving it and get exactly
the same code run.

Audit actions, exactly: `baseline.create`, `baseline.update`, `baseline.delete`, `baseline.enable`,
`baseline.disable`, `baseline.evaluate`, `baseline.remediate`, `baseline.preview`,
`baseline.command_check`, `baseline.reboot_check`. The target is the baseline id; details carry the
name, the check ids (inserted and deleted) and the agent ids involved. A previewed `command` check
also writes a `baseline.command_check` entry — with an empty target, because there is no baseline
yet, and `"preview": true` plus the agent ids in the details — so "who made a device run a script"
stays one grep over one action.

**Empty targets match nothing.** `Targets.Matches` returns false for `{}`, and an `os` filter is an
AND, not an OR — so a baseline with no targets silently applies to nobody. `POST` and `PUT` refuse
targets that select nothing with a 400 `these targets match no devices` unless the body sets
`"allow_empty_targets": true`, and the console shows the matched-device count live beside the
picker.

### Shapes

```jsonc
// GET /api/baselines -> [BaselineOut, ...]      (a bare array, like GET /api/alert-rules)
{"id":1,"name":"Windows workstation hygiene","description":"","targets":{"groups":[2],"os":"windows"},
 "enforce":false,"interval_sec":3600,"notify_email":false,"enabled":false,"version":3,
 "checks_count":7,"devices":10,"devices_reported":8,"devices_drifted":2,"devices_unknown":2,
 "compliance":92.5,"last_change":1757890000,"created_at":1757000000,"updated_at":1757880000}

// a check, as returned
{"id":7,"baseline_id":1,"position":0,"name":"Firewall on","kind":"firewall","params":{"enabled":true},
 "remediate":true,"severity":"critical","os_filter":"windows","timeout_sec":60}

// a result, as returned. A check with no row yet is absent, and renders as unknown.
{"check_id":7,"state":"fail","expected":"enabled","observed":"domain/private/public: on/on/off",
 "detail":"","fixed":false,"duration_ms":83,"version":3,"stale":false,
 "checked_at":1757899990,"received_at":1757899991,"since":1757800000}

// POST/PUT body. `position` is the array index; a position field in the body is ignored.
{"name":"…","description":"","targets":{"groups":[2],"os":"windows"},"enforce":false,
 "interval_sec":3600,"notify_email":false,"enabled":false,
 "allow_empty_targets":false,"confirm_fleet_reboot":false,
 "checks":[{"id":7,"name":"Firewall on","kind":"firewall","params":{"enabled":true},
            "remediate":true,"severity":"critical","os_filter":"windows","timeout_sec":60}]}

// POST /api/baselines/{id}/evaluate  {"agent_ids":["a1b2"]}   (absent/empty = every matched device)
{"baseline_id":1,"requested":3,"queued":2,"offline":1,
 "agents":[{"agent_id":"a1b2","status":"queued"},{"agent_id":"e5f6","status":"offline"}]}

// POST /api/baselines/{id}/remediate  {"agent_id":"a1b2","check_ids":[7,9]}
// check_ids absent = every currently failing check that allows remediation (NOT every check).
{"baseline_id":1,"agent_id":"a1b2","accepted":[7],
 "refused":[{"check_id":9,"reason":"remediation is disabled for this check"}],"report":null}

// POST /api/baselines/preview  {"spec":{…},"agent_ids":["a1b2"]}
{"spec_checks":[{"index":0,"id":-1,"name":"Firewall on","kind":"firewall","os_filter":"windows"}],
 "devices":[{"agent_id":"a1b2","agent_name":"ws-7","os":"windows","status":"ok","error":"",
             "results":[{"check_id":-1,"state":"fail","expected":"enabled",
                         "observed":"domain/private/public: on/on/off","detail":"","fixed":false,
                         "duration_ms":83}],"duration_ms":120}]}

// SSE, event name `baseline`. A notification, not data: the console refetches.
// `changed` carries only real transitions, capped at 20 (`changed_truncated`).
event: baseline
data: {"kind":"baseline","agent_id":"a1b2","data":{"baseline_id":1,"version":3,"trigger":"schedule",
       "ts":1757899991,"counts":{"pass":5,"fail":1,"fixed":0,"error":0,"skipped":1},
       "compliance":85.7,"changed":[{"check_id":7,"from":"pass","to":"fail"}]}}
```

Drift alerts emit their own `alert` events as usual, so the console must not double-count.
`'baseline'` is in `EventKind` in `web/src/api/types.ts` **and** in the `KINDS` array in
`web/src/hooks/useEvents.tsx` — an `EventSource` only receives named events it has a listener for.

## Automations

Triggers `drift_detected` and `drift_fixed` are in `validTriggers`. The data map passed to the
action is `{baseline_id, baseline_name, check_id, check_name, kind, severity, state, expected,
observed, detail}`. There is **no** `rule_id`, so an automation filtered by `rule_ids` can never
match a drift trigger — the console says so beside the filter. The existing 60-fires-per-minute cap
applies unchanged.

## Console

- Nav entry **Baselines** after Automations; routes `/baselines`, `/baselines/new`,
  `/baselines/:id` (status) and `/baselines/:id/edit`.
- **List**: name, enabled/enforcing badges, targets summary, check count, compliance, last change.
- **Editor**: name, description, the shared `TargetPicker` (so the targets JSON is identical to
  tasks and alert rules) with a live matched-device count, an enforce toggle carrying the explicit
  warning *"the agent will change these devices without asking"*, interval, notify-by-email, and a
  reorderable check list. The Add-check dialog has a kind picker and a typed form per kind plus a
  raw-JSON mode; both are validated against the same shapes the server enforces before Save
  enables. The dialog states that params are readable by every signed-in user — put no secrets in
  them — and shows a red warning on the `command` kind.
- **Preview on devices** dry-runs the draft before saving.
- **Status view**: the device × check matrix with state chips, a cell drawer showing expected vs
  observed, `since` and detail with a fix button, per-device Evaluate and Remediate, and a history
  drawer.
- **Device tab Compliance** — deliberately without `needsOnline`: reading the last known state of
  an offline device is the point.
- **Dashboard tile**: fleet compliance, drifted devices and open drift alerts.
- Every mutating control is hidden or disabled for a read-only account.

## Security

**`command` is arbitrary root/SYSTEM code on every matched device.** Creating, editing or
previewing a baseline containing one requires the **admin** role (the routes are `requireWrite`;
all three handlers check admin themselves), is audited as `baseline.command_check` with the check
name, and the console shows a red warning in the Add-check dialog. The agent runs it through the existing script-runner path — a
temp directory, a 0700 file, `exec.Command` with args, never a shell string — with
`RMM_BASELINE_ID` and `RMM_CHECK_ID` in the environment. Semantics: `check` exit 0 = `pass`,
non-zero = `fail`, could-not-start or timeout = `error`; `observed` is the first non-empty stdout
line (≤ 256 bytes) or `exit <code>`; `expected` is the `expected` label or `exit 0`; `detail` is the
last 4 KiB of stderr, then stdout. A `fix` with no `check` is a 400.

Enforcement is the other sharp edge: an **enforced** baseline changes devices without asking
anyone. That is why enforce is off by default, why the toggle carries a warning, why both seeds
ship disabled *and* unenforced with every destructive check report-only, why a fleet-wide
`allow_reboot` needs an explicit `confirm_fleet_reboot`, and why the refusals above (empty a
privileged group, change a boot-start driver, stop the agent's own service, write outside the
allowed paths) live in the **agent**, where they hold whatever the server was talked into sending.

Check params are readable by every signed-in user through `GET /api/baselines/{id}`, including
viewers. They are not a place for credentials.

## Where the code is

| | |
|---|---|
| shared param types, validation, limits | `internal/baselines/` |
| the device engine, scheduling, state file | `internal/agent/baseline.go` |
| per-kind evaluation and remediation | `internal/agent/baseline_kinds.go`, `baseline_linux.go`, `baseline_windows.go`, `baseline_group.go`, `baseline_winparse.go`, `baseline_other.go` |
| ingest, alerts, automations, compliance | `internal/server/baselines.go` |
| queries and the merge-save transaction | `internal/server/baselines_db.go` |
| HTTP handlers | `internal/server/api_baselines.go` |
| console | `web/src/pages/Baselines.tsx`, `BaselineEditor.tsx`, `BaselineStatus.tsx`, `web/src/components/baselines/`, `web/src/pages/device/Compliance.tsx` |
