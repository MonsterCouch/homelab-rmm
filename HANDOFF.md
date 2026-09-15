# Handoff

State of Homelab RMM as of 2026-09-15, written for whoever picks the project up on a
workstation. Everything below is true of `main` at `9df12df` (release **v0.2.0**).

## What exists

A self-hosted RMM for a home lab, in the spirit of NinjaOne's scripting, patching and
automation combined with ScreenConnect's remote desktop.

- **Server** (`cmd/rmm-server`, `internal/server`): one Go binary, SQLite (pure Go, no cgo),
  self-signed HTTPS with certificate pinning for agents, embedded React console, WebSocket hub
  for agents, sessions + TOTP, roles (admin / tech / viewer), audit log, SMTP alerts.
- **Agent** (`cmd/rmm-agent`, `internal/agent`): one Go binary for Windows and Linux, runs as
  a service, outbound-only connection, inventory, metrics, scripts (PowerShell, cmd, bash, sh,
  python), services, processes, event log / journal, files, power, Wake-on-LAN, patching
  (Windows Update Agent, apt/dnf/pacman/zypper), remote shell (ConPTY / pty), remote desktop
  helper (`internal/agent/desktop`, spawned into the interactive session), and the baselines
  engine (`internal/agent/baseline*.go`).
- **Baselines** (`internal/baselines` shared validator, `internal/server/*baselines*`,
  `web/src/pages/Baseline*.tsx`): desired-state checks with drift alerts and self-healing.
  Contract and kind reference: `docs/BASELINES.md`.
- **Console** (`web/`): Vite + React + TypeScript, embedded via `web/embed.go` from `web/dist`.
- Size: about 40k lines of Go and 15k of TypeScript. Twelve commits; history is linear.

Read in this order: `README.md`, `docs/ARCHITECTURE.md`, `docs/API.md`,
`docs/BASELINES.md`, `docs/DESKTOP-PROTOCOL.md`, `docs/SECURITY.md`,
`docs/OPERATIONS.md`, `docs/DEVELOPMENT.md`.

## Toolchain

- Go: `go.mod` says 1.26; a Go 1.24+ install auto-downloads the toolchain. No C compiler
  needed anywhere (modernc SQLite, pure-Go screenshot and X11 libraries).
- Node 22 + npm for the console. `cd web && npm ci && npm run build` produces `web/dist`,
  which the server embeds. Commit nothing under `web/dist` (only `.gitkeep`).
- Playwright's Chromium for the end-to-end smoke (`web/e2e/smoke.mjs`): it launches Chromium
  itself; set `PLAYWRIGHT_BROWSERS_PATH` if yours is not in the default location.

## Build, test, run

```bash
make web                      # console
make server agents            # cross-compiles into dist/ (windows/linux, amd64/arm64/arm)
make test                     # go vet + go test ./... + console build
make package                  # zips + tar.gz + SHA256SUMS (rebuilds first)
go test -race -count=1 ./...  # the full suite; internal/server takes ~7 minutes
```

Dev loop (from `docs/DEVELOPMENT.md`):

```bash
go run ./cmd/rmm-server run --insecure --listen 127.0.0.1:8080 --data ./tmp/data
cd web && npm run dev          # proxies /api and /ws to the server
RMM_AGENT_DIR=./tmp/agent go run ./cmd/rmm-agent install --server http://127.0.0.1:8080 --token <token> --no-service
RMM_AGENT_DIR=./tmp/agent go run ./cmd/rmm-agent run
```

First run prints a one-time **setup code** in the log; the setup form always asks for it.

End-to-end smoke with a real Linux agent (83 steps, the strongest check we have):

```bash
go build -o rmm-server ./cmd/rmm-server && go build -o rmm-agent ./cmd/rmm-agent
RMM_DATA_DIR=/tmp/rmm-smoke ./rmm-server run --insecure --listen 127.0.0.1:18080 &
PW_BASE=http://127.0.0.1:18080 RMM_DATA_DIR=/tmp/rmm-smoke AGENT_BIN=$PWD/rmm-agent node web/e2e/smoke.mjs
```

`tools/build.ps1` is the Windows twin of the Makefile / `tools/build.sh`.

## Releasing

CI is `.github/workflows/build.yml`: every push to `main` and every PR runs the console
build, vet, tests and cross-compile. A release is cut by **Actions → Build → Run workflow**
with `release_tag` set (for example `v0.3.0`): the run stamps the version, builds, creates the
tag on the runner and publishes a GitHub Release with the archives and checksums. Pushing a
`v*` tag by hand also works. Update `CHANGELOG.md` first (move the `[Unreleased]` section to
the new version and fix the compare links at the bottom).

## How it was verified

- `go test -race` across all packages, Windows and Linux cross-compiles and vets, console
  type-check, and the Playwright smoke against a real Linux agent (terminal, files,
  processes, scripts with live output, desktop viewer protocol, baselines drift → alert →
  remediate → resolve).
- Remote desktop was tested end to end on Xvfb with real pixels, mouse, keyboard and wheel.
- Independent adversarial reviews attacked the server live (install-script injection, role
  gates, enrolment-token races, forwarded headers, setup takeover, CSRF) and the fixes are
  pinned by `internal/server/security_test.go` and `baselines_verify_test.go`.

## What has NOT been verified

- **Nothing has run on a real Windows machine.** Every Windows path (SCM, registry, WMI,
  WTS, ConPTY, wevtutil, the Windows Update Agent PowerShell, the session-0 desktop helper,
  SendInput, the Windows baseline kinds, `tools/build.ps1`, the PowerShell installer) is
  cross-compiled, vet-checked and reviewed line by line only. Install one Windows agent
  first and read `%ProgramData%\HomelabRMM\agent.log`.
- Linux paths that need systemd, ufw/firewalld or a package install were unit-tested against
  canned output; the container used for development had no systemd and no network for apt.
- Wayland desktops are refused by design (X11 works).
- Docker image builds were not executed (no daemon available); the Dockerfile was reviewed.

## Known open items

1. **No LICENSE file.** Archives ship a placeholder. Pick one.
2. `tools/build.ps1 package` lacks the stale-binary guard that `tools/build.sh` has; port
   `fresh`/`first_newer` and run it once on Windows.
3. Drift alerts cannot link back to the baseline and check that raised them: the alerts API
   exposes no `dedupe_key` / `baseline_id` (the key `drift:<baseline>:<check>:<agent>`
   already holds both). Needs `internal/server/alerts.go` plus `web/src/api/types.ts`.
4. Baseline maintenance windows are not enforced on the device (no window field in
   `protocol.AgentConfig`); flap counters and log throttles are in memory and reset on
   server restart.
5. Agent self-update: the agent implements `agent.update` (download, SHA-256 check, swap),
   but nothing on the server triggers it yet.
6. Console `--text-faint` contrast is below WCAG AA for de-emphasised text app-wide.
7. Product gaps ranked by an independent review, none started: view-only / observe mode for
   the desktop, in-session file transfer and clipboard sync, more notification channels than
   SMTP (webhook automations exist), fleet-wide patch approval UI, CSV export exists but
   saved views are basic, session recording.

## Conventions that matter

- Never change `internal/protocol/protocol.go` without keeping old agents working; agents
  ignore unknown fields, the server ignores reports with an unknown version.
- Every non-GET API call needs `X-Requested-With: fetch`; browser WebSockets are
  origin-checked; viewers get 403 on every mutation, including shell, desktop, downloads and
  enrolment tokens.
- Gameplay of the roles: a `tech` can run scripts as root/SYSTEM by design; command-kind
  baseline checks and sensitive file paths are admin-only, even for preview.
- Balance of remediation safety lives in `internal/agent/baseline_group.go`
  (`planGroupMembers`) and `internal/baselines` (path rules, limits). Tests assert the
  invariants, not the environment; keep it that way (the GitHub runner's `adm` group differs
  from a container's).
- Scripts, alert rules and baselines seeded on first run are in `internal/server/seed.go`,
  guarded by settings keys so operator deletions are never re-added.
- Telemetry, logs and state: server `server.log` and `rmm.db` in the data dir
  (`%ProgramData%\HomelabRMM` or `/var/lib/homelab-rmm`); agent `agent.json`,
  `agent.log`, `baselines.json` in `%ProgramData%\HomelabRMM` or `/etc/homelab-rmm`.

## Context from the build environment (why some things look the way they do)

- The code was written in a cloud container whose git proxy silently dropped tag pushes and
  branch deletions; that is why releases are cut by the workflow-dispatch input instead of a
  pushed tag. Pushing tags from a normal workstation works too.
- A stray branch `claude/self-hosted-rmm-tool-1o6uvs` in `MonsterCouch/untitled-racing-game`
  holds an early copy of this repository's history; it is redundant and can be deleted.
