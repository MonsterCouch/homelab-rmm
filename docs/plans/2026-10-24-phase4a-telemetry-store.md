# Phase 4A: telemetry store (design, 2026-10-24)

Roadmap item "Embedded dual-engine storage". Metrics samples leave the SQLite file; everything transactional stays.

## Why

`metrics` is the one table that grows by every device every few seconds. It shares the single SQLite connection with every request, its purge deletes in time slices to keep that connection free, and a 30-day chart groups a million rows on read. A store built for append-and-range-scan takes that load off SQLite without a second server.

## Engine

`github.com/cockroachdb/pebble` (pure Go, the LSM behind CockroachDB). One Pebble database at `<data dir>/telemetry/`. Keys and values:

| key | value |
|---|---|
| `m` + agent id + `\x00` + ts (8 bytes big-endian) | one sample, binary: varint-encoded cpu×1000, mem_used, mem_total, net_rx, net_tx, uptime, load1×1000, procs, then the disks JSON |
| `r` + agent id + `\x00` + bucket start (8 bytes) | a 5-minute rollup kept on ingest: count, sums of the numeric fields, the last sample's ts, disks and uptime |

Reads over spans longer than 6 hours use rollups, shorter spans use samples, both bucketed to `maxPoints` exactly as `MetricHistory` does today (average of the numeric fields, the last sample's disks and uptime). Purge is one `DeleteRange` per prefix and runs where the SQLite purge runs. Agent deletion removes both prefixes.

## Interface

```go
// internal/telemetry
type Store interface {
    WriteMetrics(agentID string, m protocol.Metrics) error
    MetricHistory(agentID string, from, to int64, maxPoints int) ([]MetricRow, error)
    Purge(before int64) error
    DeleteAgent(agentID string) error
    Close() error
}
func OpenSQLite(db *sql.DB) Store        // today's table and queries, moved here unchanged
func OpenPebble(dir string) (Store, error)
func OpenClickHouse(dsn, user, password string) (Store, error)
```

`MetricRow` moves from the server package to `telemetry` (a type alias stays in `server` so handlers and tests do not change). `agents.last_metrics` stays in SQLite: it is a per-device current value, not a series.

## Selection and migration

- `--telemetry sqlite|pebble|clickhouse` (`RMM_TELEMETRY`), default `sqlite`, so nothing changes for an existing installation until the operator switches. `--telemetry-dsn` (`RMM_TELEMETRY_DSN`), `RMM_TELEMETRY_USER`, `RMM_TELEMETRY_PASSWORD` for ClickHouse.
- `rmm-server telemetry migrate --to pebble|clickhouse` copies every `metrics` row in ts order, in batches, prints progress, and ends by printing the flag to start the server with. It refuses to run while the server holds the database (the existing lock the server takes on start; check how `OpenDatabase` is guarded). It does not delete the SQLite rows; `rmm-server telemetry drop-sqlite` does that explicitly after the operator has switched.
- Health: `GET /api/admin/stats` (or wherever server stats live) reports the telemetry engine and its size; the Settings page shows them.

## ClickHouse

The HTTP interface only (`net/http`, no driver): `INSERT INTO rmm_metrics FORMAT JSONEachRow` batched every second or 500 rows, `SELECT ... GROUP BY intDiv(ts, bucket)` for history, `ALTER TABLE ... DELETE WHERE ts < ?` for purge, the table created on open with `ENGINE = MergeTree ORDER BY (agent_id, ts) TTL` left to retention. Verified against a fake of the HTTP protocol in tests, so the docs say so.

## Not done, and why

PostgreSQL for the transactional data. The server has several hundred statements written in SQLite's dialect (`INSERT OR REPLACE`, `PRAGMA`, `?` placeholders, `datetime()` arithmetic, `last_insert_rowid`), so a second OLTP engine is a rewrite of the data layer, not a driver. It stays on the roadmap as its own phase.

## Tests

`internal/telemetry`: the three stores against one shared conformance test (write, history over short and long spans with bucket counts and averages, purge, delete agent, reopen keeps data) with ClickHouse behind an httptest fake that checks the SQL it receives; the server's metrics handlers pass unchanged against `sqlite` and `pebble`; the migrate command on a seeded database.

## Status (implemented 2026-10-24)

Built as designed: `internal/telemetry` holds `Store` and the three engines (`OpenSQLite`, `OpenPebble`, `OpenClickHouse`), the data-directory lock, and the `telemetry migrate` and `telemetry drop-sqlite` subcommands. The same conformance test runs against all three engines. ClickHouse has only been verified against an httptest fake of its HTTP protocol, never against a real server.

Deviations from the design above:
- **Pebble v2.** The module is `github.com/cockroachdb/pebble/v2` (v2.1.7), and its logger is a no-op so "Found 0 WALs" no longer reaches the console. `go mod tidy` made it a direct requirement.
- **Optional interfaces beside `Store`:** `BatchWriter` (`WriteBatch`, used by the migration), `Inspector` (`Engine`, `SizeBytes`) and `Counter` (`Count`, ClickHouse only).
- **The lock.** The server had no lock on `rmm.db`, so `Run` now takes `<data>/rmm.lock` (`flock` on Unix, `LockFileEx` on Windows) and both subcommands refuse with "stop the server first". `closeStorage()` releases it on every exit path, after telemetry and the database.
- **ClickHouse duplicates.** The table is a plain MergeTree, so a second sample at the same agent and timestamp is kept beside the first instead of replacing it. For that reason `migrate --to clickhouse` refuses a table that already holds rows, and the conformance test skips its replace checks for this engine. Inserts are batched at 500 rows or every second with retry, capped at 50,000 rows while the server is unreachable; purge and agent deletion use `mutations_sync=1`.
- **Rollup straddling the cutoff.** Pebble purge keeps a 5-minute rollup that spans the cutoff rather than splitting it.
- **Where stats live.** `/api/system` (in `api.go`) reports `telemetry_engine` and `telemetry_bytes` (-1 when SQLite cannot say), not `/api/admin/stats`.
- **`DB.telemetry`.** `DB` carries the active store, defaulting to the SQLite one in `openDB`, so `saveMetrics`, `MetricsRange` and `DeleteAgent` keep their signatures. `DeleteAgent` deletes telemetry first and returns the error so a retry is possible.
- **ClickHouse credentials.** `install` keeps the user in the service's DSN and writes the password to `<data>/telemetry.pass` (data directory restricted first, file mode 0600), because a service does not inherit the installing shell's environment and a password on the command line is visible to every local account. The server reads the file unless `RMM_TELEMETRY_PASSWORD` is set; the printed flags never include a password.
- **Telemetry is best effort.** A failed `WriteMetrics` is logged at most once a minute and `last_metrics`, `last_seen` and `pending_reboot` are still updated, so alerts and the live view survive a ClickHouse outage or a full disk. The ClickHouse store only buffers on write (50,000 rows while unreachable) and flushes from its own goroutine.
- **Startup.** The data-directory lock is taken before `rmm.db` is opened, so a second server process never runs migrations or marks devices offline; a failed `New` closes the telemetry store and the database. Pebble's `Errorf` reaches the log; `Infof` stays silent.
- **`drop-sqlite`** opens the named engine and refuses unless it already holds samples, so the only copy of the history cannot be dropped.
- **PostgreSQL** stays unbuilt, for the reason in the section above.

A first whole-package `go test ./internal/server` run once failed in `TestQUICClosingTheConnectionFailsPendingRequests`; it passed alone eight times and in the next whole run, so it is treated as a pre-existing flake in the QUIC tests, not a telemetry fault.
