# Development

## Prerequisites

- Go 1.26 (`go.mod` pins `go 1.26.0`; an older toolchain downloads it automatically with
  `GOTOOLCHAIN=auto`).
- Node 22 and npm for the web UI.
- Optional: `make` (Linux/macOS), PowerShell 5.1+ (Windows, `tools/build.ps1`), Docker.

Module: `github.com/MonsterCouch/homelab-rmm`. Everything builds with `CGO_ENABLED=0`, including
SQLite (`modernc.org/sqlite`), so cross-compiling needs no C toolchain.

## Dev loop

**Backend** in the foreground with plain HTTP, a throwaway data directory and the UI served from
disk instead of the embedded copy:

```bash
go run ./cmd/rmm-server run --insecure --listen :8080 --data ./tmp/server --dev-web web/dist
```

`--dev-web` reads `web/dist` on every request, so `npm run build` in `web/` is enough to see UI
changes without restarting Go. Skip `--insecure` to exercise the real TLS path: the certificate
is generated in `./tmp/server` and its fingerprint is printed at startup.

**Frontend** with hot reload:

```bash
cd web && npm install && npm run dev
```

Vite serves `http://localhost:5173` and proxies `/api` and `/ws` to the Go server. The target
defaults to `https://localhost:8443`; point it at the dev server above with
`RMM_DEV_TARGET=http://localhost:8080 npm run dev`. Cookies stay same-origin because the browser
only ever talks to Vite. `npm run typecheck` runs `tsc --noEmit`; `npm run build` type-checks and
builds `web/dist` (it keeps `web/dist/.gitkeep`, which `go:embed` needs to exist even when the
UI has not been built).

**An agent on the same machine** without touching `/etc` or `%ProgramData%` and without a
service:

```bash
# create a token in the console (Devices → Enrol), then:
RMM_AGENT_DIR=./tmp/agent go run ./cmd/rmm-agent install --server http://localhost:8080 --token <token> --no-service
RMM_AGENT_DIR=./tmp/agent go run ./cmd/rmm-agent run
```

`RMM_AGENT_DIR` moves `agent.json` and `agent.log`; `--no-service` writes the config only. The
agent runs as your user, so anything needing root/SYSTEM (service control, updates, power,
session-0 desktop launch) will fail or degrade — that is expected. With a display available the
desktop helper runs in-process instead of being spawned. Omit `--fingerprint` for an `http://`
server; for the TLS dev server pass the fingerprint printed at startup (or leave it empty and
accept that the self-signed certificate is then rejected by the system store).

`Ctrl-C` stops either binary cleanly (`internal/svc` runs the same function the service manager
would).

## Tests

```bash
go vet ./...
go test ./...
go test ./internal/server/ -run EndToEnd -v  # full server path with a fake agent (no OS access needed)
go test ./internal/server/ -run Seed -v    # default library / rules / groups / policy
cd web && npm run build                     # type-check + bundle
```

`make test` (or `tools/build.sh test`, `tools/build.ps1 -Target test`) runs all three. Platform
files are covered by `*_windows_test.go` / `*_linux_test.go`; parsers have fixtures in
`winparse_test.go` and `linuxparse_test.go`. The desktop package's X11 integration test skips
itself unless Xvfb is installed.

## Cross-compiling and packaging

```bash
make all         # web UI, then rmm-server and rmm-agent for every platform into dist/
make server      # rmm-server: windows/amd64, windows/arm64, linux/amd64, linux/arm64
make agents      # rmm-agent: the same four plus linux/arm (GOARM=7)
make package     # dist/homelab-rmm-<os>-<arch>.zip (+ .tar.gz for linux), SHA256SUMS
make VERSION=v1.2.3 package
```

`make server` embeds whatever is in `web/dist` at that moment — run `make web` (or `make all`)
first for a release build, and note that `make package` only archives what `server` and `agents`
produced; it never builds the UI. An unbuilt `web/dist` used to be silent: the directory is
gitignored apart from `.gitkeep`, so `go:embed all:dist` succeeded with one empty file, the
build printed no warning and the archive shipped a server whose console was a directory listing
of `.gitkeep`. Now `make`, `tools/build.sh` and `tools/build.ps1` all refuse to build
`rmm-server` when `web/dist/index.html` is missing; `ALLOW_EMPTY_WEB=1` (environment variable,
or `make ALLOW_EMPTY_WEB=1 server`) builds one deliberately, which is what you want for a binary
that will run with `--dev-web`. CI additionally greps every packaged server binary for the
embedded `index.html`, so a console-less archive cannot reach a release. Binaries are stamped with `git describe --tags --always` unless
`VERSION` is given, via `-ldflags "-s -w -X …/internal/server.Version=… -X …/internal/agent.Version=…"`
and `-trimpath`. The archive layout (server at the root, `agents/rmm-agent-<os>-<arch>[.exe]`
beside it) is what `internal/server/install.go` looks up, so a server run from an extracted
archive can enrol devices without any copying.

Without make: `tools/build.sh <targets>` (bash) or `tools/build.ps1 -Target <targets>`
(PowerShell 5.1 compatible; builds the zips with `System.IO.Compression` so entry names use
forward slashes). CI (`.github/workflows/build.yml`) runs vet, tests, the UI build and
`make server agents package` on every push and pull request, uploads `dist/` as an artifact, and
on a `v*` tag publishes a GitHub Release with the archives and `SHA256SUMS`.

Docker: `docker build -t homelab-rmm .` or `docker compose up -d --build`
(`--platform linux/arm64` works through buildx).

## Repository layout

See `docs/ARCHITECTURE.md` §1. In short: `cmd/` entry points, `internal/protocol` wire types,
`internal/server` the control plane (`api_*.go` handlers by area), `internal/agent` the device
daemon with `_windows.go`/`_linux.go` pairs and `platform_other.go` as the contract,
`internal/agent/desktop` the remote desktop helper, `web/` the SPA.

## Adding a request type end to end

Example: a new `disk.smart` request that returns S.M.A.R.T. health for each disk.

1. **Protocol** (`internal/protocol/protocol.go`): add the request name and the payloads.

   ```go
   ReqDiskSmart = "disk.smart"

   type SmartDisk struct {
       Device string `json:"device"`
       Healthy bool  `json:"healthy"`
       Temp    int   `json:"temp_c,omitempty"`
   }
   ```

   Bump `protocol.Version` only if an existing message changes shape; a new request is
   backwards compatible (old agents answer `unknown request`).

2. **Agent contract** (`internal/agent/platform_other.go`): declare the function every platform
   implements, with a comment saying what it must return.

   ```go
   // smartStatus reports per-disk S.M.A.R.T. health (smartctl / WMI MSStorageDriver_FailurePredictStatus).
   func smartStatus(ctx context.Context) ([]protocol.SmartDisk, error) { return nil, errUnsupported }
   ```

   Implement it in `smart_windows.go` and `smart_linux.go` (build tags, never through a shell —
   use `runHidden` / `runCmd` helpers, cap output, honour `ctx`). Add fixture-based tests for
   any parsing in `winparse_test.go` / `linuxparse_test.go`.

3. **Agent dispatcher** (`internal/agent/agent.go`, `handle`): one case.

   ```go
   case protocol.ReqDiskSmart:
       out, err = smartStatus(ctx)
   ```

4. **Server API** (`internal/server/api_agents.go` + `api.go`): a handler that asks the hub and
   a route.

   ```go
   func (s *Server) handleDiskSmart(w http.ResponseWriter, r *http.Request) {
       ctx, cancel := context.WithTimeout(r.Context(), quickTimeout)
       defer cancel()
       var out []protocol.SmartDisk
       if err := s.hub.Request(ctx, r.PathValue("id"), protocol.ReqDiskSmart, nil, &out); err != nil {
           fail(w, err) // maps ErrAgentOffline to 409, errNotFound to 404
           return
       }
       writeJSON(w, 200, out)
   }
   // in routes():
   api.HandleFunc("GET /api/agents/{id}/smart", s.handleDiskSmart)
   ```

   Use `s.requireWrite(...)` for anything that changes state, `s.audit(r, "smart.query", id,
   nil)` for actions worth recording, and `Hub.Stream` instead of `Request` when the agent will
   send progress chunks. Document the route in `docs/API.md`.

5. **UI** (`web/src`): add the type to `api/types.ts`, a client call in `api/client.ts`, and a
   tab or panel under `pages/device/`. Non-GET calls already carry the `X-Requested-With` header
   through the shared client.

6. **Fake agent in tests**: teach `internal/server/e2e_test.go`'s `fakeAgent.loop` to answer the
   new request so the server path is covered without an OS.

## Conventions

- gofmt, `go vet` clean, errors wrapped with context (`fmt.Errorf("scan updates: %w", err)`),
  no panics on input from the network or the OS.
- Anything a script or command returns is untrusted: cap sizes, parse defensively, time out.
- Platform code goes in `_windows.go`/`_linux.go` files behind the contract in
  `platform_other.go`; never `runtime.GOOS` branches in shared logic when a file split will do.
- Database changes are a new entry in `migrations` in `db.go`; never edit an applied one.
- Balance between the two binaries: the agent stays dumb (execute, report), policy lives in the
  server.

## Releasing

`v0.1.0` is tagged and published, with the six archives and `SHA256SUMS` attached to it by CI, so
the download URLs in `README.md` resolve. The repository still has no `LICENSE`, so
`tools/build.sh` puts a placeholder in every archive — including the ones already released. That
is the one release chore still outstanding.

1. Add a `LICENSE` file (the packagers copy it into every archive as soon as it exists; until
   then they write "No LICENSE file is present in this build").
2. Update `CHANGELOG.md` — move `[Unreleased]` to the new version with a date, and add its
   compare link at the bottom of the file.
3. `git tag v1.2.3 && git push --tags`.
4. CI builds, tests and attaches `homelab-rmm-<os>-<arch>.zip`, the linux `.tar.gz` files and
   `SHA256SUMS` to the GitHub Release.
5. Check that the README's release note still reads true for the new version — in particular the
   line about which features `releases/latest` now carries.

Packaging by hand: `make package` is safe on its own — it depends on `server agents`, so it
rebuilds first. The script targets do **not** build anything; `tools/build.sh package` and
`tools\build.ps1 -Target package` archive whatever `server` and `agents` last left in `dist/`,
and because the console is embedded in the server binary a stale archive looks right until it is
run. Use `tools/build.sh all package`. Both `tools/build.sh` and `tools\build.ps1` refuse a
binary older than the sources or `web/dist` it was built from (`ALLOW_STALE_BUILD=1` packages it
anyway).
