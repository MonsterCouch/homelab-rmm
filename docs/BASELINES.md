# Baselines: desired state with drift detection and self-healing

A **baseline** declares how a device should look. It is a named list of **checks**, each with a
kind, kind-specific parameters, a severity, an OS filter and a flag saying whether the agent may
fix it. Baselines are assigned to devices with the same target model as tasks and alert rules
(all / agents / groups / tags / OS). The agent evaluates its assigned baselines on their interval,
**offline too**, reports every pass, and, when the baseline is **enforced** and the check allows
**remediation**, fixes the drift itself and reports the check as `fixed`.

Wire types live in `internal/protocol/protocol.go` (`BaselineSpec`, `BaselineCheck`,
`BaselineReport`, `BaselineResult`; messages `TypeBaseline`, `baseline.evaluate`,
`baseline.remediate`, `baseline.preview`). This document is the contract for the check kinds,
the state machine, the server behaviour and the API.

## States

Each (device, check) has a state after every pass:

| state | meaning |
|---|---|
| `pass` | compliant |
| `fail` | drift observed and not fixed (remediation not allowed, baseline not enforced, or preview) |
| `fixed` | drift was observed, the remediation ran and the re-check passed in the same pass |
| `error` | the check itself could not run (missing tool, timeout, permission) or the fix failed and the re-check still fails; `detail` says why |
| `skipped` | the check does not apply (OS filter, kind unsupported on this platform) |

Transitions are what matter to the server: `pass -> fail|error` opens a **drift alert**
(rule kind `drift`, severity from the check, dedupe key `drift:<baseline>:<check>:<agent>`);
`fail|error -> pass|fixed` resolves it. `fixed` also raises an agent event and the automation
trigger `drift_fixed`; `fail|error` raise `drift_detected` (once per transition, not per pass).

## Evaluation rules (agent)

- One evaluation goroutine per device; baselines run one after another, checks in order, each
  under its own timeout (default 60 s, `command` kind honours `timeout_sec`).
- Interval minimum 60 s. A new or changed config (new `version`) triggers a pass within 30 s.
  A pass also runs ~20 s after the agent starts.
- Remediation runs only when `spec.enforce && check.remediate && state == fail`. After a fix the
  check is evaluated again: pass → `fixed`, otherwise `error` with the fix output in `detail`.
- A check whose fix failed is not retried automatically for 60 minutes (per check), to avoid
  flapping; a manual `baseline.remediate` ignores that hold-off.
- `baseline.preview` evaluates an unsaved spec and never fixes anything (the dry run used by the
  editor before saving).
- Reports are sent after every pass. The agent keeps the last report per baseline and re-sends
  it after reconnecting so the server catches up on offline drift.
- `detail`, `observed` and `expected` are bounded (4 KB) and never contain secrets from params.

## Check kinds

Parameters are JSON objects. `os` says where the kind is implemented; elsewhere the result is
`skipped`. "Fix" describes the remediation; "check only" kinds ignore `remediate`.

| kind | params | platforms | fix |
|---|---|---|---|
| `service` | `name`, `state` (`running`\|`stopped`), `start_type` (`auto`\|`manual`\|`disabled`\|`any`, default `any`) | windows, linux | start/stop the service and set the start type (SCM / `systemctl enable|disable`) |
| `package` | `name`, `state` (`present`\|`absent`), `min_version` (optional, compared as dotted numbers) | linux (dpkg/rpm/pacman/zypper), windows (registry Uninstall keys + `winget list`) | linux: package manager install/remove; windows: `winget install --id`/`uninstall` when winget resolves, else `error` |
| `registry` | `path` (`HKLM\...` or `HKCU\...`), `name`, `type` (`dword`\|`qword`\|`string`\|`expand_string`\|`multi_string`), `value` | windows | create the key if needed and set the value |
| `file` | `path`, `state` (`present`\|`absent`), and for present optionally `content` (exact), `sha256`, `contains` (substring), `mode` (octal, linux), `owner` (linux) | windows, linux | present: write `content` (only when given) and set mode/owner; absent: delete. `sha256`/`contains` without `content` are check only |
| `command` | `language` (`bash`\|`sh`\|`powershell`\|`cmd`\|`python`), `check` (script; exit 0 = compliant, stdout first line = observed), `fix` (script, optional), `expected` (label) | windows, linux | run `fix`, then re-run `check` |
| `group_members` | `group` (e.g. `Administrators`, `sudo`, `wheel`), `allowed` (list of names), `mode` (`exact`\|`subset`) | windows (local groups), linux (/etc/group + getent) | remove members that are not allowed; never adds |
| `firewall` | `enabled` (bool) | windows (all three profiles), linux (ufw or firewalld) | enable/disable |
| `time_sync` | `enabled` (bool) | windows (`w32time` running + NTP configured), linux (`timedatectl` NTP) | enable |
| `sysctl` | `key`, `value` | linux | write `/etc/sysctl.d/90-homelab-rmm.conf` and apply with `sysctl -w` |
| `windows_feature` | `name`, `state` (`enabled`\|`disabled`) | windows (`Get-WindowsOptionalFeature -Online`) | `Enable-/Disable-WindowsOptionalFeature -NoRestart` |
| `reboot_pending` | `max_hours` (int), `allow_reboot` (bool, default false) | windows, linux | reboots with a 60 s notice only when `allow_reboot` is true; otherwise check only |
| `disk_free` | `mount`, `min_free_pct` | windows, linux | check only |

`expected` and `observed` are short human strings ("running / auto" vs "stopped / disabled",
"present 8.5.0" vs "absent", "sha256 ab12..." vs "sha256 cd34...").

## Server

- Tables: `baselines` (id, name, description, targets, enforce, interval_sec, notify_email,
  enabled, version, created_at, updated_at), `baseline_checks` (id, baseline_id, position, name,
  kind, params, remediate, severity, os_filter, timeout_sec), `baseline_results` (agent_id,
  check_id, baseline_id, state, expected, observed, detail, fixed, checked_at, since (when the
  current state began), PRIMARY KEY (agent_id, check_id)), `baseline_history` (id, agent_id,
  baseline_id, check_id, ts, from_state, to_state, detail).
- The agent config (`agentConfig`) resolves the baselines whose targets match the device and
  sends them as `BaselineSpec`s; every baseline change pushes the config to affected online
  agents; a device whose group/tags change gets a push too.
- Ingest of `TypeBaseline`: results are upserted, transitions recorded, drift alerts opened or
  resolved, `baseline` SSE event broadcast, automations `drift_detected` / `drift_fixed` fired.
  Reports for a version older than the stored one are ignored; results for checks that no
  longer exist are dropped.
- Compliance for a device = pass+fixed / (all - skipped); for a baseline = average over its
  matched devices; fleet = average over devices with at least one baseline.
- Retention: `baseline_history` follows the events retention setting.
- Seed (first run, both **disabled**): "Windows workstation hygiene" (firewall on, time sync on,
  SMB1 off, Print Spooler manual, no local admins beyond Administrator, reboot pending < 72 h,
  C: free > 10 %) and "Linux server hygiene" (sshd running + enabled, time sync on, firewall on
  where present, `net.ipv4.ip_forward = 0`, `unattended-upgrades` present on Debian, root
  filesystem free > 10 %, no extra members of `sudo`/`wheel`).

## API

All under the session cookie; mutations need a write role.

| method and path | purpose |
|---|---|
| `GET /api/baselines` | list with compliance % and device counts |
| `POST /api/baselines` / `PUT /api/baselines/{id}` / `DELETE /api/baselines/{id}` | CRUD; body is the baseline with nested `checks` |
| `GET /api/baselines/{id}` | one baseline with checks |
| `GET /api/baselines/{id}/status` | matrix: devices × checks with state, observed, expected, since; plus per-device compliance |
| `POST /api/baselines/{id}/evaluate` `{agent_ids?}` | ask online targets to evaluate now |
| `POST /api/baselines/{id}/remediate` `{agent_id, check_ids?}` | run fixes now on one device |
| `POST /api/baselines/preview` `{spec, agent_ids}` | dry run an unsaved spec on online devices; returns per-device reports |
| `GET /api/agents/{id}/baselines` | device view: every assigned baseline with its checks and current results |
| `GET /api/agents/{id}/baselines/history?limit=` | transitions for the device |
| `GET /api/compliance` | fleet summary for the dashboard (score, drifted devices, open drift alerts, worst checks) |

## Console

- Nav entry **Baselines** (after Automations). List: name, enabled/enforce badges, targets summary,
  checks count, compliance %, last change. Editor: name, description, targets picker, enforce
  toggle (with a warning about automatic changes), interval, notify by email, checks list with
  reorder; "Add check" dialog with a kind picker and a typed form per kind (plus raw JSON for
  power users), remediate toggle, severity, OS filter, timeout. "Preview on devices" runs the dry
  run and shows results before saving.
- Status view: device × check matrix with state chips, filters (state, device, OS), row actions
  (evaluate now, remediate failing, remediate one check), history drawer.
- Device tab **Compliance**: assigned baselines, each check with expected vs observed, fix buttons,
  since when, history.
- Dashboard tile: fleet compliance % and drifted device count, linking to Baselines. Drift alerts
  show in Alerts with their check name.
- Everything role-aware and covered by the Playwright smoke.
