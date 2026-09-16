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
  `POST /api/auth/setup {username,password,email,code}` → `{ok:true}` plus the session cookie.
  `setup_code_required` is true whenever setup still has to happen — there is no exemption for
  any source address, loopback included. The server prints a one-time setup code at startup while
  it has no users (console and `server.log`) and every setup request must send it as `code`. 403
  on a wrong code, 403 once a user exists, 429 when rate-limited (the setup endpoint shares the
  login limiter). Concurrent requests are serialised, so exactly one of them creates the
  administrator.
- `POST /api/auth/login {username,password,code}` → `{ok,user}` or `{needs_totp:true}` (re-post
  with the 6-digit `code`). 401 on bad credentials, 429 when rate-limited.
- `POST /api/auth/logout`.
- `POST /api/me/password {current,new}` changes your own password and **deletes your other
  sessions**; the calling session survives.
- Roles: `admin` (everything), `tech` (everything except users/settings), `viewer` (read-only:
  every POST/PUT/PATCH/DELETE returns 403, and so do the GETs that are not really reads —
  `/ws/shell/{id}`, `/ws/desktop/{id}`, `/api/agents/{id}/fs/download`, the sensitive event-log
  channels (see [Event log](#event-log)) and `GET /api/enroll`, whose body carries the enrolment
  token values).
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

## Endpoints

See `routes()` in `internal/server/api.go`. Highlights:

- Devices: `GET /api/agents`, `GET /api/agents/{id}` (includes `inventory` and `last_metrics`),
  `PATCH /api/agents/{id}` (`AgentUpdate`), `DELETE`, `GET /api/agents/{id}/metrics?from=&to=&points=`,
  `POST /api/agents/{id}/refresh`, `GET .../processes`, `POST .../processes/kill {pid}`,
  `GET .../services`, `POST .../services/action {name, action}`,
  `GET .../eventlog?log=System&level=error&limit=200&search=&since=` (contract in
  [Event log](#event-log)), `GET .../fs?path=`,
  `GET .../fs/download?path=` (binary), `POST .../fs/upload?path=` (raw body),
  `POST .../fs/delete|mkdir {path}`, `POST .../fs/rename {from,to}`,
  `POST .../power {action: reboot|shutdown|lock|logoff, delay_sec, message}`, `POST .../wol`,
  `POST .../run {script_id | language+body, args, timeout_sec}` → `{run_id}`,
  `GET .../patches` → `{patches, last_scan}`, `POST .../patches/scan`,
  `POST .../patches/install {ids | all:true, reboot_if_required}` (202, follow `patches` events),
  `GET .../events` (agent event log).
- Terminal: WebSocket `/ws/shell/{id}`. Send `{"t":"open","shell":"powershell|cmd|bash|sh|","cols","rows"}`,
  then `{"t":"in","data"}` and `{"t":"resize","cols","rows"}`; receive `{"t":"opened"}`,
  `{"t":"out","data"}`, `{"t":"closed"}`, `{"t":"error","message"}`.
- Remote desktop: WebSocket `/ws/desktop/{id}?quality=60` — see `docs/DESKTOP-PROTOCOL.md`.
- Groups `/api/groups`, enrolment `/api/enroll` (POST returns `{token, windows, linux}` install
  commands; GET returns `{tokens, public_url, fingerprint}`). `GET /install/{token}?os=windows|linux&arch=`
  renders the install script and is unauthenticated, but only for a token that could still enrol
  (404 otherwise) and an `arch` of `amd64|arm64|arm|386` (400 otherwise).
- Scripts `/api/scripts`, `POST /api/scripts/run {script_id|language+body, args, targets|agent_ids}`
  → `{runs: {agentId: runId|"error: ..."}}`, runs `/api/runs?agent=&limit=`, `/api/runs/{id}`
  (includes stdout/stderr, live while running), `POST /api/runs/{id}/cancel`.
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
- Patches `/api/patches?agent=&status=`, `POST /api/patches/status {items:[{AgentID,PatchID}], status: approved|ignored|available}`,
  policies `/api/patch-policies` (`mode`: approved|all|security; `reboot`: never|if_required|always).
- Admin: `/api/settings` (GET/PUT `Settings`), `POST /api/settings/test-mail`, `/api/users`,
  `GET /api/audit?limit=`, `GET /api/system`, `GET /api/dashboard`.

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
