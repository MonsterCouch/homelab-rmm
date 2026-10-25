# HTTP API

Everything is JSON. All routes are defined in `internal/server/api.go`; response shapes are the
Go structs in the same package (`Agent`, `Script`, `Run`, `Task`, `Automation`, `AlertRule`,
`Alert`, `Patch`, `PatchPolicy`, `Group`, `EnrollToken`, `User`, `Settings`, `MetricRow`) and in
`internal/protocol` (`Inventory`, `Metrics`, `Process`, `Service`, `EventLogEntry`, `FsEntry`,
`Update`). Read those files for field names — they are the source of truth.

## Authentication

- Cookie session (`rmm_session`, HttpOnly, SameSite=Strict).
- Every non-GET request **must** carry an `X-Requested-With` header or it is rejected with 403.
  Only its **presence** is checked, never its value — the point is that a cross-site form or a
  CORS "simple request" cannot set a custom header at all, so `XMLHttpRequest` works as well as
  the `fetch` the console sends. That includes `/api/auth/setup`, `/api/auth/login` and
  `/api/auth/logout`, which sit outside the session middleware and carry their own copy of the
  check (`authGuard`): they also require the `Origin` host (when present) to match `Host`, and
  refuse a body whose `Content-Type` is not `application/json` (415). WebSocket upgrades are
  exempt from the header (a browser cannot set one on a WebSocket) and are guarded by the
  same-origin check instead.
- `GET /api/auth/state` → `{needs_setup, setup_code_required, user, version}`. When
  `needs_setup` is true the UI shows the first-run form and calls
  `POST /api/auth/setup {username,password,email}` → `{ok:true}` plus the session cookie.
  `setup_code_required` reports `false`; no one-time setup code is required on first run.
  403 once a user exists, 429 when rate-limited (the setup endpoint shares the login limiter).
  Concurrent setup requests are serialised (`Server.setupMu`), so exactly one of them creates the
  administrator and subsequent requests are rejected with 403.
- `POST /api/auth/login {username,password,code}` → `{ok,user}` or `{needs_totp:true}` (re-post
  with the 6-digit `code`). 401 on bad credentials, 429 when rate-limited.
- `POST /api/auth/logout`.
- `POST /api/me/password {current,new}` changes your own password and **deletes your other
  sessions**; the calling session survives.
- Roles: `admin` (everything), `tech` (operations, scripts, runs, device management; can be scoped
  by `org_scope`), `viewer` (read-only: every POST/PUT/PATCH/DELETE returns 403, and so do the GETs
  that are not really reads — `/ws/shell/{id}`, `/ws/desktop/{id}`, `/api/agents/{id}/fs/download`,
  the sensitive event-log channels (see [Event log](#event-log)) and `GET /api/enroll`), `poc`
  (Point of Contact for client ticketing portal).
- The client address used by the rate limiter and the audit log is the peer address.
  `X-Forwarded-For` is honoured only when the peer is inside a network given to
  `--trusted-proxies` / `RMM_TRUSTED_PROXIES`, and then the list is read from the **right**,
  skipping hops that are themselves trusted proxies — the proxies this project ships configs for
  append to the header rather than replacing it, so the left-most hop is the client's own text.
- Every response carries `Content-Security-Policy: default-src 'self'` (script-src `'self'`, no
  inline script), `X-Content-Type-Options`, `X-Frame-Options: DENY` and `Referrer-Policy`.
- Errors are `{"error": "message"}` with a 4xx/5xx status.

## Live updates

`GET /api/events` is Server-Sent Events. Event names: `agent_online`, `agent_offline`, `metrics`
(data = latest `protocol.Metrics`), `inventory`, `event`, `alert`, `run` (data =
`{run_id, status?, stream?, data?, exit_code?}` — streamed script output), `patches`, `baseline`
(data = `{baseline_id, version, trigger, ts, counts{pass,fail,fixed,error,skipped}, compliance,
changed[{check_id,from,to}], changed_truncated?}` — a notification, not data: refetch). Each has
`{kind, agent_id, data}` JSON in the data field. An `EventSource` only receives named events it has
a listener for, so a new kind has to be added to `KINDS` in `web/src/hooks/useEvents.tsx` as well.
For users with an assigned `org_scope`, events are tenant-filtered at the hub layer (VULN-014) so
technicians never receive telemetry or state changes for devices outside their scope.

## Endpoints

See `routes()` in `internal/server/api.go`. Highlights:

- Devices: `GET /api/agents`, `GET /api/agents/{id}` (includes `inventory` and `last_metrics`; an online device also carries `transport`, `"websocket"` or `"quic"`, the transport of its live connection),
  `PATCH /api/agents/{id}` (`AgentUpdate`), `DELETE`, `GET /api/agents/{id}/metrics?from=&to=&points=` (the same on every telemetry engine),
  `POST /api/agents/{id}/refresh`, `GET .../processes`, `POST .../processes/kill {pid}`,
  `GET .../services`, `POST .../services/action {name, action}`,
  `GET .../eventlog?log=System&level=error&limit=200&search=&since=` (contract in
  [Event log](#event-log)), `GET .../fs?path=`,
  `GET .../fs/download?path=` (binary), `POST .../fs/upload?path=` (raw body; on a device whose organisation has a
  trust bundle it answers `{staged, commit_required, upload_id, bytes, sha256}` and the file is only
  staged until `POST .../fs/commit {upload_id}`, which goes through the signing flow, signing the
  destination, size and SHA-256 rather than the bytes; see `docs/SECURITY.md`, Signed actions),
  `POST .../fs/delete|mkdir {path}`, `POST .../fs/rename {from,to}`,
  `POST .../isolate {isolate: true|false}` (device network quarantine: host firewall lockdown blocking non-RMM traffic while preserving control channel),
  `POST .../power {action: reboot|shutdown|lock|logoff, delay_sec, message}` — `poweroff` and
  `halt` are accepted as aliases of `shutdown`, `logout` as an alias of `logoff`; `delay_sec` is a
  grace period honoured for reboot, shutdown and logoff, while lock is always immediate,
  `POST .../wol`,
  `POST .../update` (dispatches self-update instruction to agent),
  `POST .../run {script_id | language+body, args, timeout_sec}` → `{run_id}` (409 when the run
  cannot start, including a `script_id` whose `os_filter` does not match the device),
  `GET .../patches` → `{patches, last_scan, scan_error}` (`scan_error` is what the agent said went
  wrong during the last scan, `""` when it was clean: a scan whose update source failed still
  answers 200 and still refreshes `last_scan`, so this is the only signal that the list is stale),
  `POST .../patches/scan`,
  `GET .../servicing?limit=` (default 20) → bare array of repair records, newest first
  `{id, agent_id, policy_id, trigger: manual|auto, code, why, started_at, finished_at, status, result, by}`
  (`why` is the sentence for the error `code`; `result` is `{steps: [{name, status: ok|failed|skipped,
  exit_code, duration_ms, tail}], reboot_required, scan}`),
  `POST .../servicing/repair {steps?, package?: {url, sha256}, reboot?: never|if_required}` (Windows
  only, signed like `script.run`; 202 `{ok, id}`; empty `steps` become `dism_restore`,
  `reset_components`, `rescan` and empty `reboot` `never` before signing; steps are `dism_restore`,
  `sfc`, `reset_components`, `add_package`, `rescan`; a package must be https, `.cab` or `.msu`, carry a
  64-hex `sha256` and goes with `add_package`; 400 on a non-Windows device or a bad value, 409 while a
  patch job holds the device),
  `POST .../patches/install {ids | all:true, reboot_if_required}` (202, follow `patches` events),
  `GET .../events` (agent event log).
- Terminal: WebSocket `/ws/shell/{id}`. Send `{"t":"open","shell":"powershell|cmd|bash|sh|","cols","rows"}`,
  then `{"t":"in","data"}`, `{"t":"resize","cols","rows"}` and `{"t":"close"}`; receive
  `{"t":"opened","session"}`, `{"t":"out","data"}`, `{"t":"closed"}`, `{"t":"error","message"}`.
  `opened` is sent only once the device has answered, so it means a shell really exists and its
  `session` is live; an open the device refused (an unsupported shell name, no ConPTY, no
  `/bin/sh`) arrives as `error` then `closed` with **no** `opened` before it. A `resize` is
  applied only when both dimensions are 1..1000 on Windows (1..65535 on Linux); anything else —
  including the `0x0` a viewer sends while its container is hidden — is refused by the device and
  the session keeps the size it had. The socket is capped at 1 MiB per frame (a bigger one ends
  it with `1009`), and the server pings every 25 s and ends the session with `1001` when the
  viewer has not answered for 90 s, so a browser that vanished without closing the connection
  cannot leave a shell running on the device. Answering the ping is the whole of the contract:
  every browser does so automatically, and a client must **not** send `{"t":"in","data":""}` as
  a keepalive — that types into the shell. On Windows the shell is started on code page 65001
  and with `TERM=xterm-256color` / `COLORTERM=truecolor`, so its output is byte-accurate UTF-8
  exactly as on Linux (where the shell gets `LANG=C.UTF-8`).
- Remote desktop: WebSocket `/ws/desktop/{id}?quality=60` — see `docs/DESKTOP-PROTOCOL.md`. The
  viewer socket is bounded exactly like the terminal's: 1 MiB per frame, a ping every 25 s, and
  the session ends when the viewer has not answered for 90 s. The device's helper is then closed
  with `1001` and the reason `the viewer stopped answering`, so a phone that slept mid-session
  does not leave the operator's screen being captured for nobody.
- Organizations & Sites: `GET /api/organizations`, `POST /api/organizations` (`{name}`, admin only),
  `PUT /api/organizations/{id}` (`{name}`, admin only), `DELETE /api/organizations/{id}` (admin only),
  `GET /api/organizations/{id}/sites`, `GET /api/sites` (all accessible sites),
  `POST /api/organizations/{id}/sites` (`{name}`, admin only),
  `PUT /api/sites/{id}` (`{name}`, admin only), `DELETE /api/sites/{id}` (admin only).
- Groups `/api/groups`, enrollment `/api/enroll` (POST returns `{token, windows, linux}` install
  commands; GET returns `{tokens, public_url, fingerprint}`).
  `GET /install/{token}?os=windows|linux&arch=` renders the install script (unauthenticated, live token only).
  `GET /install/{token}/msi` downloads the Windows MSI installer with embedded configuration tag overlay.
  `GET /install/{token}/deb?arch=amd64|arm64` dynamically builds and streams a configured Debian `.deb` package.
- Scripts `/api/scripts`, `POST /api/scripts/run {script_id|language+body, args, targets|agent_ids}`
  → `{runs: {agentId: runId|"error: ..."|"skipped: ..."}}`, runs `/api/runs?agent=&limit=`,
  `/api/runs/{id}` (includes stdout/stderr, live while running), `POST /api/runs/{id}/cancel`.
  In an organization that signs actions a run is never queued for an offline device, because its
  signature would expire before the device is back: a library script answers `error: device is
  offline: a signed run cannot wait for it, ...` for that device (no signature is asked for it) and
  an ad hoc body `error: agent is offline`. `POST /api/agents/{id}/run` answers 409 with the same
  text. Organizations that do not sign actions still queue library scripts. Unattended runs
  (tasks, automations) queue in every case and keep their standing approval.
- Standing approvals: `GET /api/approvals/unsigned?org=` → one row per unit that needs a signature,
  `{type, id, name, reason, org, purpose}`. `POST /api/approvals/objects/{type}/{id}/sign?org=&purpose=`
  goes through the signing flow (428, then a retry with `X-Action-Auth`). With both `org` and
  `purpose` it signs exactly that unit; otherwise it signs the first unit that needs it. Answers
  `{expires_at, org, purpose, remaining}`, where `remaining` counts the other units of the object
  that still need a signature, or `{already_approved: true, expires_at, remaining}` when the unit
  needs none (no signature is asked for).
- Pending approvals (the signing queue): `GET /api/approvals` lists what the caller may still sign;
  `GET /api/approvals/{manifest_id}` returns one entry in the same shape, or 404 when the caller may
  not sign it (unknown, expired, done, another organization, or already signed by the caller).
  An entry is listed when it is neither done nor expired, the caller may access its organization,
  it has a signature already or the caller issued it, and the caller has not signed it. So the
  caller's own challenge shows up with `have: 0`, which is what `rmm-signer` signs out of band.
  `POST /api/approvals/{manifest_id}/sign {assertion}` is unchanged. Entry:
  `{manifest_id, manifest (base64url of the exact bytes), summary, have, need, created_by, issuer,
  org, created_at, expires_at, kind (action|grant|standing), op, ops[], targets[], target_names{},
  rp_id, origins[], allow_credentials[], user_verification (required|preferred), signers[]}`.
  The arrays are never null. `target_names` maps agent ids to display names, only for agents the
  caller may access. `allow_credentials` is the caller's own credential ids in the organization's
  bundle; `user_verification` is `required` when the bundle sets `require_uv`. `signers` names the
  owners who have signed so far. `summary` and `target_names` are the server's words; `manifest`
  is what a signature covers.
  A run's `status` is `queued|running|done|failed|timeout|cancelled` — a cancel is not a failure
  and raises no `script_failed` alert. `exit_code` is the interpreter's, sign-extended on Windows
  (`exit -1` reads `-1`, not `4294967295`), or `-1` when the run never produced one.
- Tasks `/api/tasks` (`kind`: script|patch_scan|patch_install|reboot|inventory; `schedule` is a
  5-field cron or `@hourly`/`@daily`; `targets` = `{all, agents[], groups[], tags[], os}`),
  `POST /api/tasks/{id}/run`.
- Automations `/api/automations` (`trigger`: agent_online|agent_offline|alert_opened|alert_resolved|
  enrolled|reboot_required|patch_installed|drift_detected|drift_fixed; `action`:
  run_script|email|webhook; `action_params`:
  `{script_id, args}` / `{subject}` / `{url}`; `filter`: `{targets, rule_ids[], severity}`).
  `agent_online`/`agent_offline` follow the socket with no grace period, so a reconnect flap
  fires both — use an `offline` alert rule plus `alert_opened` when you want "offline for N
  minutes". `drift_detected`/`drift_fixed` carry no `rule_id`, so a `rule_ids` filter never matches
  one; their data map is `{baseline_id, baseline_name, check_id, check_name, kind, severity, state,
  expected, observed, detail}`. Each automation is capped at 60 fires a minute.
- Alert rules `/api/alert-rules` (`kind`: cpu|memory|disk|offline|service|reboot_required|
  script_failed|patch_failed|event; `params`: `{threshold, minutes, mount, service, pattern}`),
  alerts `/api/alerts?status=open|acked|resolved|all`. Baseline drift produces alerts with
  `rule_kind: "drift"` and a null `rule_id` — they have no `alert_rules` row, and `drift` is
  deliberately not a creatable rule kind.
  `POST /api/alerts/{id}/ack|resolve`, `POST /api/alerts/resolve-all`.
  `kind: "event"` matches **agent-emitted events only**, and the only kind an agent emits today
  is `patch` — the lines an update install prints. Nothing watches the Windows Event Log or
  journald on any platform, so an `event` rule never fires on a log record: the event log is
  strictly pull-only (`GET /api/agents/{id}/eventlog`). Matches also dedupe on the event kind,
  so such a rule opens one alert per device, not one per line.
- Baselines: `GET /api/baselines`, `POST /api/baselines` (201), `GET|PUT|DELETE
  /api/baselines/{id}`, `GET /api/baselines/{id}/status?limit=` (the device × check matrix),
  `POST /api/baselines/{id}/evaluate {agent_ids?}` (always 200; per-device `queued|offline|error`),
  `POST /api/baselines/{id}/remediate {agent_id, check_ids?}` (409 when the device is offline),
  `POST /api/baselines/preview {spec, agent_ids}` (1–10 devices, always 200; per-device
  `ok|offline|timeout|error`; check ids are synthetic negatives), `GET /api/agents/{id}/baselines`,
  `GET /api/agents/{id}/baselines/history?limit=&baseline_id=` (`baseline_id` narrows the rows to
  one baseline in SQL), `GET /api/compliance`. A `PUT` is a **merge**:
  a check with an `id` is updated in place, one without is inserted, one missing from the body is
  deleted with its results and alerts. Reads are session-only (viewers included); every mutation
  and `evaluate`/`remediate`/`preview` needs the write role, and a `command` check, a `file` check
  outside `/etc`/`ProgramData` or an `allow_reboot` check needs **admin** — on `preview` as well as
  on the save path, because a preview runs the draft on the devices it names. Full shapes and the
  check-kind parameter schemas are in [BASELINES.md](BASELINES.md).
- Patches `/api/patches?agent=&status=`, `POST /api/patches/status {items:[{agent_id,patch_id}], status: approved|ignored|available}`
  (`AgentID`/`PatchID` are accepted too; the reply is `{ok:true, changed:<rows>}`, and a body whose
  items match no patch — wrong ids, or patches that are installing or installed — is **404**, not a
  silent success), policies `/api/patch-policies` (`mode`: approved|all|security; `reboot`:
  never|if_required|always).
  A patch row carries `source` (`wua`, `winget`, `apt`, `dnf`, `pacman`, `zypper`), `downloaded`
  (Windows Update has already staged the payload, so `size` is not a download still to come) and
  `description`. **`source: "winget"` rows are informational**: they are the application upgrades
  `winget upgrade` lists for the agent's service account, the agent refuses to install them, and
  the server leaves them out of `all:true` approvals and of "install everything approved". Sending
  one explicitly comes back as a per-id failure, and the rest of the batch still installs.
- Software Catalog: `GET /api/software-catalog?os=`, `POST /api/software-catalog` (admin only: `{name, description, publisher, version, category, icon, install_cmd, uninstall_cmd, update_cmd, os}`),
  `GET /api/software-catalog/{id}`, `PUT /api/software-catalog/{id}` (admin only), `DELETE /api/software-catalog/{id}` (admin only),
  `POST /api/agents/{id}/software/install` (`{catalog_id?, custom_cmd?}` - `custom_cmd` requires admin),
  `POST /api/agents/{id}/software/uninstall` (`{catalog_id?, custom_cmd?}` - `custom_cmd` requires admin).
- IT Ticketing: `GET /api/tickets?org_id=&site_id=&status=&priority=&agent_id=&assigned_to=&limit=`,
  `POST /api/tickets` (`{subject, description, requester_name, requester_email, requester_phone?, priority, status?, org_id?, site_id?, agent_id?}`),
  `GET /api/tickets/{id}` (returns ticket with `comments` array), `PUT /api/tickets/{id}`, `DELETE /api/tickets/{id}` (admin only),
  `POST /api/tickets/{id}/comments` (`{body, is_internal?}`), `GET /api/agents/{id}/tickets`.
- Network Discovery & SNMP: `GET /api/discovered-devices?org_id=&site_id=&status=&device_type=`,
  `GET /api/discovered-devices/{id}`, `PUT /api/discovered-devices/{id}` (`{status?, device_type?, hostname?, org_id?, site_id?}`),
  `DELETE /api/discovered-devices/{id}`, `POST /api/discovered-devices/{id}/poll` (SNMP v2c poll directly or via agent),
  `GET /api/network-scans`, `POST /api/network-scans` (`{subnet, agent_id?}` - private IPv4 /22 to /30; server-side scans without `agent_id` require admin).
- Client Portal (token pass or session): `POST /api/agent/portal-pass` (agent mints 15-minute portal pass token),
  `GET /portal/start?pass=` (redeems pass token and sets portal cookie),
  `GET /api/portal/config` (device identity, org/site, domain user, is_poc),
  `GET /api/portal/software` (self-service catalog items with installation status),
  `POST /api/portal/software/action` (`{software_id, action: "install"|"uninstall"|"update", agent_id?}`),
  `GET /api/portal/runs/{id}` (poll self-service run status for caller's agent),
  `GET /api/portal/tickets`, `GET /api/portal/tickets/{id}`,
  `POST /api/portal/tickets` (`{subject, description, requester_name, requester_email?, requester_phone?, priority?}`),
  `POST /api/portal/tickets/{id}/comments` (`{body}`).
- Transparency log (`GET`, 503 when the server has no log): `/api/log/head` → `{size, hash, key, note}`
  (`key` is the note verifier key bundles pin as `log_key`, `note` the base64 signed head);
  `/api/log/proof?index=` → `{size, hash, note, index, proof}`, the inclusion proof at the current head
  (400 for a bad index, 404 for a leaf past the end); `/api/log/consistency?from=&to=` → `{from, to, proof}`
  (`from` at least 1, `to` defaults to the current size, 400 outside that range). These three need no
  session, since they hold only hashes and sizes. `/api/log/entries/{index}` → `{index, kind, data, ts}`
  with `data` the base64 leaf (`manifest`, `bundle` or `audit`) is admin only (403 for a technician, 401
  without a session). The `approvals` table keeps each standing approval's leaf in `log_index`; the API
  does not return it, but the approval's dispatch carries the proof. A trust proposal accepts
  `require_log_proof` and `log_key`; the latter must be this server's own key, and `require_log_proof`
  needs one. The head of a device's `executed.log` is the agent's `executed_head` field (and `inventory.executed_head`) in `GET /api/agents` and `GET /api/agents/{id}`.
- In-Place & Fleet Updates: `GET /api/server/version` (version, arch, staged update status),
  `POST /api/server/update` (admin only: in-place server executable swap & service restart),
  `POST /api/agents/update-all` (admin only: updates at once the online devices of organizations that do
  not sign actions, counted in `dispatched_to`. It dispatches nothing to the online devices of the others
  and returns them as `signed_groups`, one entry per organization and agent build (OS and architecture):
  `{org, org_name, os, arch, version, sha256, agent_ids}`, each of which is meant for `update-batch`. A
  build that more than 2000 online devices of one organization run comes back as several entries, in
  device-ID order, because 2000 is what `update-batch` takes. Online devices the server has no agent
  build for (their OS or architecture) are sent nothing and counted in `skipped_no_build`, so an empty
  `signed_groups` with `dispatched_to` 0 does not mean that they were up to date. The build a device
  gets is chosen by the architecture it announced when it connected, never by its inventory, so every
  entry is accepted by `update-batch` as it stands. Online devices whose recorded digest says they
  already run the build are left out of both and counted in `up_to_date`. Audited as `fleet.update_all`
  with the counts),
  `POST /api/agents/update-batch` (admin only: `{agent_ids}`, at most 2000, which must all belong to one
  organization and run one build, otherwise 400. It goes through the signing flow (428, then a retry
  with `X-Action-Auth`) as one high-risk `agent.update` manifest whose payload is
  `{url, sha256, version}`, so it needs `high_threshold` signers and may answer 202 and wait in the
  approvals queue for the others; for an organization that does not sign actions it sends at once.
  Each device checks the binary's SHA-256 after it downloads it; a device that already runs that
  build answers as done and downloads and restarts nothing, though the manifest still needed its
  signature. Devices already on the build by their recorded digest are dropped before the manifest is
  built, so it names only the rest; when none are left it answers 200
  `{ok, dispatched_to: 0, up_to_date, signed: false, message}` with no 428. Answers
  `{ok, dispatched_to, signed, accepted, installing, offline, up_to_date, failed: [{id, name, error}], message}`,
  where `dispatched_to`, `accepted`, `installing` and `offline` count devices: `accepted` have
  downloaded and checked the binary, `installing` did not reply within 20 seconds (a device replies
  only once the binary is staged), `offline` were not connected, and `dispatched_to` is `accepted`
  plus `installing`. `failed` lists, with the device's name, the devices that answered with an error
  or could not be sent the request, and the `message` names them as devices that did not take the
  update, never as unreachable (that word is for `offline`). `signed` says whether the update went
  out under a signature: it is false for an organization that does not sign actions, for an operator
  who chose *Continue without signing* in `audit` mode, and when the organization stopped signing
  between the listing and the request. Audited as `fleet.update` with the name and source address of
  the operator who asked, not of whoever added the last signature, the counts, and for the first 20
  failed devices their `id`, `name` and clipped `error` under `failures`; see `docs/SECURITY.md`,
  Signed actions),
  `POST /api/agents/{id}/update` (dispatch update to specific agent; waits as long as `update-batch`
  does. A device still downloading and checking the binary answers 200
  `{ok: true, installing: true, message}` and restarts on its own when done, an offline device 409,
  any other error 400 with the device's reason. A device that already runs the build, by the digest
  it reported at its last update-check (recorded for 24 hours), answers 200
  `{ok: true, up_to_date: true, message}` before any signature is asked for, unless `?force=1`),
  `GET /api/agent/update-check` (the version probe every agent makes every 5 minutes, sent with the
  agent's key rather than a console session. Where it would advertise a build to a device of an
  organization in `enforce` mode, it answers `update_available: false` and
  `signed_update_required: true` instead, with that build's `version` and `sha256` but no `url`; the
  device refuses an unsigned update by itself in any case. `os` must be `windows` or `linux` and
  `arch` one of `amd64`, `arm64`, `arm` or `386`: the server looks a build up by that name only, so
  any other value gets `update_available: false`).
- Admin: `/api/settings` (GET/PUT `Settings`; `mesh_cache: {enabled, port, max_bytes}` is the subnet update cache, off by default, with a port of at least 1024 and `max_bytes` of at least 64 MiB or 400, and unchanged by a PUT that omits it), `POST /api/settings/test-mail`,
  `/api/users` (manage accounts, roles, and `org_scope`), `GET /api/audit?limit=` (rows carry `log_index`, the entry's leaf in the transparency log, -1 for one that was never logged), `GET /api/system` (also `telemetry_engine` and `telemetry_bytes`, -1 when the engine cannot report a size), `GET /api/dashboard`.

## Event log

`GET /api/agents/{id}/eventlog?log=&level=&limit=&search=&since=` reads the device's log live —
there is no server-side copy, no history and no alerting on it (see the `event` alert kind
above). Parameters, and the one contract both agents keep:

| Parameter | Meaning |
|---|---|
| `log` | Windows: a channel name (`System`, `Application`, `Security`, `Setup`, `Microsoft-Windows-…/Operational`), default `System`. Linux: empty/`system`/`application` = the whole journal, `kernel`, `security`/`auth`, or a unit / syslog identifier. |
| `level` | **Minimum** severity: `critical`, `error` (= critical or error), `warning` (= those plus warning), `info`/`all` = everything. Anything unrecognised is **ignored**, i.e. it reads as `all` — a typo such as `err` silently widens the query rather than failing it. |
| `limit` | Page size. Default 200 when absent or ≤ 0, clamped to **5000** on both platforms; the response does not say it was clamped. |
| `search` | Case-insensitive substring over the message and the source. |
| `since` | Unix time in seconds (milliseconds tolerated); only records at or after it. |

- **Search depth.** The agent, not the log service, does the matching on Windows, so it reads the
  newest **5000** records matching `log`/`level`/`since` and filters those, *whatever* `limit`
  says — a narrower page size no longer narrows the search. The Linux agent hands the pattern to
  `journalctl -g`, which searches the whole journal. Either way a match older than the window is
  not found, so narrow with `since` rather than with `limit`.
- **Message truncation.** A message longer than 8000 characters is cut there and ends in `…`.
  The cut happens after the search, so `search` still matches text past character 8000.
- **Levels on the wire.** Entries carry `critical`, `error`, `warning`, `info` or (Windows only)
  `verbose`. `critical` means Windows Level 1; on Linux `critical` is a synonym for `error`, and
  neither `verbose` nor a `critical` of its own is ever produced there.
- **Roles and audit.** `log` values of `Security`/`auth` and any channel containing `powershell`
  (case-insensitive) are audit trails — logons with account names and SIDs, command lines,
  script blocks — so they need the **write** role like `fs/download` and are written to the audit
  log as `eventlog.query` with the device and the channel. Every other channel is a plain read a
  viewer may do, and is not audited.
