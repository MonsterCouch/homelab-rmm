# Phase 4C: Windows servicing repair (design, 2026-10-24)

Roadmap item "Autonomous Windows servicing repair". When Windows Update fails because the servicing stack or the update catalog is damaged, the agent repairs it the way a technician would, and does so on its own only where a policy allows it.

## The operation

A new protected request `servicing.repair` (Windows only, `ClassAction`: it changes system state, so it is signed like `script.run` or covered by a standing approval), payload:

```json
{"steps": ["dism_restore", "sfc", "reset_components", "add_package", "rescan"], "package": {"url": "...", "sha256": "..."}, "reboot": "never|if_required"}
```

Steps, each with its own timeout and its output tail kept:

1. `dism_restore`: `dism.exe /Online /Cleanup-Image /RestoreHealth` (60 min). `/Source:` is added when the payload names a package directory.
2. `sfc`: `sfc.exe /scannow` (30 min).
3. `reset_components`: stop `wuauserv`, `bits`, `cryptsvc`, `msiserver`; rename `%SystemRoot%\SoftwareDistribution` and `%SystemRoot%\System32\catroot2` to `.bak.<ts>` (an existing `.bak` from an earlier repair is deleted first); start the services again. Never deletes anything else.
4. `add_package`: fetches the `.cab`/`.msu` through `cache.Fetch` (4B) with the named hash, then `dism.exe /Online /Add-Package /PackagePath:<file> /NoRestart` (60 min). Skipped without a package.
5. `rescan`: the ordinary update scan, so the result shows whether the repair worked.

Every executable is started hidden (`runHidden`, the same path winget uses) and by absolute path under `%SystemRoot%\System32`. The result is `{steps: [{name, status: ok|failed|skipped, exit_code, duration_ms, tail}], reboot_required, scan: <UpdatesScanResult>}`; a failed step stops the sequence unless the step is `sfc` (advisory). On other operating systems the request answers "servicing repair is a Windows operation".

## When it runs

- **Manually**: the device page's Patches card gets "Repair Windows servicing" (choice of steps, package optional), which goes through the signing flow.
- **Automatically**: `patch_policies.repair` (`off` default, `auto`). With `auto`, when a scan or install result for a device under the policy carries a servicing error code, the server queues one repair for that device with the default steps (`dism_restore`, `reset_components`, `rescan`) and the policy's reboot setting, at most once per device per 24 hours, and records it. In a signing organization the policy's repair is a standing approval unit (purpose `repair`, constraints `{op: servicing.repair, steps, reboot}`), listed on Review & sign like `install` and `reboot`.
- Servicing error codes that trigger it: `0x80240020`, `0x80073712`, `0x800F081F`, `0x800F0922`, `0x800F0831`, `0x80070002` and `0x80070003` on a WUA operation, `0x8024A105`, `0x80240034`, `0x80244022`, `0x8007000E`, `0x80070020`. The server parses `0x8[0-9A-Fa-f]{7}` out of `UpdatesScanResult.Error` and `UpdatesInstallResult.Failed` values; the list lives in one table in code with a sentence per code.

## Records and alerts

Table `servicing_repairs(id, agent_id, policy_id, trigger (manual|auto), code, started_at, finished_at, status, result JSON, by)`. `GET /api/agents/{id}/servicing` lists them; the device page shows the last one with its steps. An automatic repair raises an `event` alert through the existing alert engine ("servicing repair started on <device> after 0x80240020" and its outcome), and the audit log records who or which policy started it.

## Tests

Agent: the step runner with a fake command executor (each step's command line, timeouts, hidden window attribute, the rename sequence on a temp directory standing in for SystemRoot, stop-on-failure, advisory sfc, package fetch through a fake cache, non-Windows answer). Server: code parsing from both result shapes, the 24-hour cooldown, the policy flag and its standing unit, the audit and alert rows, the manual endpoint through the signing flow (`newSignFixture`).

## Status (implemented 2026-10-24)

Built as designed: the agent step runner (`servicing_windows.go`, with `servicing_other.go` answering on other systems), `internal/server/servicing.go` (code table, records, automatic flow), migration 18, the manual endpoint, the policy field and the standing unit. The device page and the policy editor have the console side. The agent's commands were exercised through a fake executor and a temp directory standing in for `SystemRoot`; they have not been run against a genuinely damaged Windows installation.

Deviations from the design above:
- **`dism_restore` never adds `/Source:`.** The payload names a package file, not a directory, so there is no input for it.
- **Standing approval is narrower than the manual request.** The unit binds the exact steps (`dism_restore`, `reset_components`, `rescan`) and the reboot mode (`if_required` or `never`) and refuses any payload carrying a package, so an unattended repair cannot be pointed at a download. `actionauth.Constraints` gained `steps` and `reboot`, and `Constraints.check` a `servicing.repair` case (`manifest.go` and `verifier.go` changed for this).
- **Package fetch.** The agent fetches the package through the cache client (the leader when one is assigned, else the origin) and refuses a URL that is not https or not on the `server_url` host; the step's tail records where it came from.
- **Code parsing.** `parseServicingCode` skips any part of a joined error that mentions winget, so a winget failure never starts a repair. `0x80070002` and `0x80070003` count only on a Windows Update operation (`WUAOnly`).
- **Rescan is not fed back.** After a repair the server clears `last_patch_scan_error` and updates `pending_reboot`, but leaves the patch table to the next ordinary scan.
- **Cooldown.** One automatic repair per device per 24 hours, and none while a record is `running`, checked and inserted under a mutex (`servicingMu`, a package variable). A repair waits up to 10 minutes for the device's patch job; if the claim times out the record is deleted, an alert says the repair did not start, and the cooldown is not spent. A record left `running` by a crash is marked failed at the next start, and the scheduler's purge pass does the same for any older than 4 hours, so a stale record never blocks the device for good.
- **`WUAOnly`** is enforced: `0x80070002` and `0x80070003` count only in scan errors, never in install failures. `GET /api/agents/{id}/servicing` clamps `limit` to 1..200.
- **No valid approval.** In a signing organization with no valid standing approval the request is still sent with no `auth`; the agent refuses in enforce mode, as with patch installs. That attempt uses up the cooldown and is recorded as failed.
- **Records.** `servicing_repairs.by` is quoted in SQL; the record turns final only after its audit row, event and alert exist; the outcome also writes a `patch` row to `agent_events`.
- **Console.** The manual dialog does not offer `add_package` (a package URL needs its own input), so that step is reachable through the API only.
