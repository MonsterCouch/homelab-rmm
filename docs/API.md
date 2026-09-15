# HTTP API

Everything is JSON. All routes are defined in `internal/server/api.go`; response shapes are the
Go structs in the same package (`Agent`, `Script`, `Run`, `Task`, `Automation`, `AlertRule`,
`Alert`, `Patch`, `PatchPolicy`, `Group`, `EnrollToken`, `User`, `Settings`, `MetricRow`) and in
`internal/protocol` (`Inventory`, `Metrics`, `Process`, `Service`, `EventLogEntry`, `FsEntry`,
`Update`). Read those files for field names — they are the source of truth.

## Authentication

- Cookie session (`rmm_session`, HttpOnly, SameSite=Strict).
- Every non-GET request **must** send the header `X-Requested-With: fetch` (CSRF guard) or it is
  rejected with 403.
- `GET /api/auth/state` → `{needs_setup, user, version}`. When `needs_setup` is true the UI shows
  the first-run form and calls `POST /api/auth/setup {username,password,email}`.
- `POST /api/auth/login {username,password,code}` → `{ok,user}` or `{needs_totp:true}` (re-post
  with the 6-digit `code`). 401 on bad credentials, 429 when rate-limited.
- `POST /api/auth/logout`.
- Roles: `admin` (everything), `tech` (everything except users/settings), `viewer` (read-only:
  every POST/PUT/PATCH/DELETE returns 403).
- Errors are `{"error": "message"}` with a 4xx/5xx status.

## Live updates

`GET /api/events` is Server-Sent Events. Event names: `agent_online`, `agent_offline`, `metrics`
(data = latest `protocol.Metrics`), `inventory`, `event`, `alert`, `run` (data =
`{run_id, status?, stream?, data?, exit_code?}` — streamed script output), `patches`. Each has
`{kind, agent_id, data}` JSON in the data field.

## Endpoints

See `routes()` in `internal/server/api.go`. Highlights:

- Devices: `GET /api/agents`, `GET /api/agents/{id}` (includes `inventory` and `last_metrics`),
  `PATCH /api/agents/{id}` (`AgentUpdate`), `DELETE`, `GET /api/agents/{id}/metrics?from=&to=&points=`,
  `POST /api/agents/{id}/refresh`, `GET .../processes`, `POST .../processes/kill {pid}`,
  `GET .../services`, `POST .../services/action {name, action}`,
  `GET .../eventlog?log=System&level=error&limit=200&search=`, `GET .../fs?path=`,
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
  commands; GET returns `{tokens, public_url, fingerprint}`).
- Scripts `/api/scripts`, `POST /api/scripts/run {script_id|language+body, args, targets|agent_ids}`
  → `{runs: {agentId: runId|"error: ..."}}`, runs `/api/runs?agent=&limit=`, `/api/runs/{id}`
  (includes stdout/stderr, live while running), `POST /api/runs/{id}/cancel`.
- Tasks `/api/tasks` (`kind`: script|patch_scan|patch_install|reboot|inventory; `schedule` is a
  5-field cron or `@hourly`/`@daily`; `targets` = `{all, agents[], groups[], tags[], os}`),
  `POST /api/tasks/{id}/run`.
- Automations `/api/automations` (`trigger`: agent_online|agent_offline|alert_opened|alert_resolved|
  enrolled|reboot_required|patch_installed; `action`: run_script|email|webhook; `action_params`:
  `{script_id, args}` / `{subject}` / `{url}`; `filter`: `{targets, rule_ids[], severity}`).
- Alert rules `/api/alert-rules` (`kind`: cpu|memory|disk|offline|service|reboot_required|
  script_failed|patch_failed|event; `params`: `{threshold, minutes, mount, service, pattern}`),
  alerts `/api/alerts?status=open|acked|resolved|all`, `POST /api/alerts/{id}/ack|resolve`,
  `POST /api/alerts/resolve-all`.
- Patches `/api/patches?agent=&status=`, `POST /api/patches/status {items:[{AgentID,PatchID}], status: approved|ignored|available}`,
  policies `/api/patch-policies` (`mode`: approved|all|security; `reboot`: never|if_required|always).
- Admin: `/api/settings` (GET/PUT `Settings`), `POST /api/settings/test-mail`, `/api/users`,
  `GET /api/audit?limit=`, `GET /api/system`, `GET /api/dashboard`.
