package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/telemetry"
)

// telemetryEngines are the engines the metrics handlers must behave the same
// on. ClickHouse is covered against a protocol fake in internal/telemetry.
var telemetryEngines = []string{"sqlite", "pebble"}

// newTelemetryServer starts a test server on one engine. The fixture's own
// cleanup closes only the SQLite handle, and Windows will not remove a data
// directory that still has Pebble files open, so the store is closed first
// (cleanups run last-in first-out).
func newTelemetryServer(t *testing.T, engine string) (*Server, *browser) {
	t.Helper()
	s, _, b := newTestServerWith(t, Config{Telemetry: engine})
	t.Cleanup(func() { s.db.telemetry.Close() })
	return s, b
}

func addTestAgent(t *testing.T, s *Server, id string) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT INTO agents(id, key_hash, hostname, os, enrolled_at) VALUES(?,'h',?,'linux',?)`, id, id+"-box", now()); err != nil {
		t.Fatal(err)
	}
}

func TestMetricsHandlersOnEveryEngine(t *testing.T) {
	for _, engine := range telemetryEngines {
		t.Run(engine, func(t *testing.T) {
			s, b := newTelemetryServer(t, engine)
			addTestAgent(t, s, "m1")
			addTestAgent(t, s, "m10")
			base := now() - 100
			for i := 0; i < 20; i++ {
				m := &protocol.Metrics{TS: base + int64(i), CPUPct: float64(i), MemUsed: 5, MemTotal: 10,
					Disks: []protocol.DiskUsage{{Mount: "/", UsedPct: float64(i)}}, PendingReboot: i == 19}
				if err := s.db.saveMetrics("m1", m); err != nil {
					t.Fatal(err)
				}
			}
			// A neighbour whose id starts with m1 must not appear in m1's chart.
			if err := s.db.saveMetrics("m10", &protocol.Metrics{TS: base + 5, CPUPct: 99}); err != nil {
				t.Fatal(err)
			}

			var rows []MetricRow
			b.mustJSON("GET", fmt.Sprintf("/api/agents/m1/metrics?from=%d&to=%d&points=1000", base, base+19), nil, &rows)
			if len(rows) != 20 || rows[19].CPU != 19 || len(rows[19].Disks) != 1 || rows[19].Disks[0].UsedPct != 19 {
				t.Fatalf("history over the API wrong on %s: %d rows, last %+v", engine, len(rows), rows[len(rows)-1])
			}
			for _, r := range rows {
				if r.CPU == 99 {
					t.Fatal("another device's sample leaked into the chart")
				}
			}

			// The per-device current value stays in SQLite whatever the engine.
			a, err := s.db.GetAgent("m1")
			if err != nil || a.LastMetrics == nil || a.LastMetrics.CPUPct != 19 {
				t.Fatalf("last_metrics is not kept in SQLite: %+v, %v", a, err)
			}
			var inSQLite int
			s.db.QueryRow(`SELECT COUNT(*) FROM metrics`).Scan(&inSQLite)
			if engine == "pebble" && inSQLite != 0 {
				t.Fatalf("the pebble engine still wrote %d rows to rmm.db", inSQLite)
			}
			if engine == "sqlite" && inSQLite != 21 {
				t.Fatalf("the sqlite engine holds %d rows, want 21", inSQLite)
			}

			// The stats endpoint names the engine.
			var sys struct {
				Engine string `json:"telemetry_engine"`
				Bytes  int64  `json:"telemetry_bytes"`
			}
			b.mustJSON("GET", "/api/system", nil, &sys)
			if sys.Engine != engine {
				t.Fatalf("/api/system reports engine %q, want %q", sys.Engine, engine)
			}
			if engine == "pebble" && sys.Bytes <= 0 {
				t.Fatalf("/api/system reports size %d for a store holding data", sys.Bytes)
			}

			// Deleting a device removes its series and only its series.
			if st, body := b.do("DELETE", "/api/agents/m1", nil); st != 200 {
				t.Fatalf("delete agent: %d %s", st, body)
			}
			if got, err := s.db.MetricsRange("m1", base, base+19, 100); err != nil || len(got) != 0 {
				t.Fatalf("m1's samples survived its deletion: %v, %v", got, err)
			}
			if got, err := s.db.MetricsRange("m10", base, base+19, 100); err != nil || len(got) != 1 {
				t.Fatalf("deleting m1 removed its neighbour's samples: %v, %v", got, err)
			}
		})
	}
}

func TestPurgeAppliesRetentionOnEveryEngine(t *testing.T) {
	for _, engine := range telemetryEngines {
		t.Run(engine, func(t *testing.T) {
			s, _ := newTelemetryServer(t, engine)
			addTestAgent(t, s, "p1")
			old, recent := now()-40*86400, now()-60
			for _, ts := range []int64{old, old + 10, recent} {
				if err := s.db.saveMetrics("p1", &protocol.Metrics{TS: ts, CPUPct: 1}); err != nil {
					t.Fatal(err)
				}
			}
			s.sched.purge() // default retention: 30 days of metrics
			got, err := s.db.MetricsRange("p1", old-10, now(), 2000)
			if err != nil {
				t.Fatal(err)
			}
			// The row's timestamp is its bucket start, so compare loosely.
			if len(got) != 1 || got[0].TS < now()-86400 {
				t.Fatalf("after purge on %s: %+v, want only the recent sample", engine, got)
			}
		})
	}
}

func TestTelemetryConfigIsChecked(t *testing.T) {
	if err := CheckTelemetryConfig(Config{}); err != nil {
		t.Fatalf("the default must be valid: %v", err)
	}
	if err := CheckTelemetryConfig(Config{Telemetry: "Pebble"}); err != nil {
		t.Fatalf("engine names are case-insensitive: %v", err)
	}
	if err := CheckTelemetryConfig(Config{Telemetry: "clickhouse"}); err == nil || !strings.Contains(err.Error(), "--telemetry-dsn") {
		t.Fatalf("clickhouse without a DSN must say what is missing, got %v", err)
	}
	if err := CheckTelemetryConfig(Config{Telemetry: "mysql"}); err == nil || !strings.Contains(err.Error(), "mysql") {
		t.Fatalf("an unknown engine must be named in the error, got %v", err)
	}
	// New refuses before it creates anything.
	dir := t.TempDir() + "/data"
	if _, err := New(Config{DataDir: dir, Insecure: true, SkipSeed: true, Telemetry: "mysql"}); err == nil {
		t.Fatal("New accepted an unknown telemetry engine")
	}
}

func TestTelemetryEnvironment(t *testing.T) {
	t.Setenv("RMM_TELEMETRY", "clickhouse")
	t.Setenv("RMM_TELEMETRY_DSN", "http://ch:8123")
	t.Setenv("RMM_TELEMETRY_USER", "rmm")
	t.Setenv("RMM_TELEMETRY_PASSWORD", "pw")
	c := Config{Telemetry: "pebble"}.FromEnv()
	if c.Telemetry != "clickhouse" || c.TelemetryDSN != "http://ch:8123" || c.TelemetryUser != "rmm" || c.TelemetryPassword != "pw" {
		t.Fatalf("environment not applied: %+v", c)
	}
}

// A server that cannot reach its ClickHouse must fail to start with the
// reason, not start and lose every sample.
func TestUnreachableClickHouseStopsStartup(t *testing.T) {
	_, err := New(Config{DataDir: t.TempDir(), Insecure: true, SkipSeed: true, Telemetry: "clickhouse", TelemetryDSN: "http://127.0.0.1:1"})
	if err == nil || !strings.Contains(err.Error(), "telemetry") {
		t.Fatalf("want a telemetry startup error, got %v", err)
	}
}

func TestRunHoldsAndReleasesTheDataDirectoryLock(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: dir, Listen: "127.0.0.1:0", Insecure: true, SkipSeed: true, Telemetry: "pebble"}

	// A second process on the same directory is refused with a plain reason.
	hold, err := telemetry.LockDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// New refuses before it opens rmm.db, so a second process cannot run
	// migrations or mark the live server's devices offline.
	if _, err := New(cfg); !errors.Is(err, telemetry.ErrDataDirBusy) {
		t.Fatalf("New with the directory locked returned %v, want ErrDataDirBusy", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, "rmm.db")); serr == nil {
		t.Fatal("a refused New created or opened rmm.db")
	}
	hold()

	// While the server runs, the lock is held; after it stops, it is free.
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	waitFor(t, "the data directory lock to be taken", func() bool {
		unlock, err := telemetry.LockDataDir(dir)
		if err != nil {
			return true
		}
		unlock()
		return false
	})
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not stop")
	}
	unlock, err := telemetry.LockDataDir(dir)
	if err != nil {
		t.Fatalf("the lock was not released on shutdown: %v", err)
	}
	unlock()
}

func TestFailedNewReleasesThePebbleDirectory(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: dir, Listen: "127.0.0.1:0", Insecure: true, SkipSeed: true, Telemetry: "pebble"}
	// A directory where the transparency log key belongs makes New fail after
	// the telemetry store is already open.
	if err := os.Mkdir(cfg.path("log.key"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg); err == nil {
		t.Fatal("New succeeded with an unusable log.key")
	}
	if err := os.Remove(cfg.path("log.key")); err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("the retry could not open the telemetry store the failed New left behind: %v", err)
	}
	s.closeStorage()
}

// failingStore is a telemetry engine whose writes fail, as ClickHouse does
// during an outage.
type failingStore struct{ telemetry.Store }

func (failingStore) WriteMetrics(string, protocol.Metrics) error {
	return errors.New("the store is down")
}

func TestTelemetryWriteFailureStillUpdatesTheDevice(t *testing.T) {
	s, _, _ := newTestServer(t)
	s.db.Exec(`INSERT INTO agents(id, key_hash, hostname, os, enrolled_at) VALUES('dev-tf','h','tbox','linux',?)`, now())
	s.db.telemetry = failingStore{s.db.telemetry}
	m := &protocol.Metrics{TS: now(), CPUPct: 7}
	if err := s.db.saveMetrics("dev-tf", m); err != nil {
		t.Fatalf("a telemetry failure aborted the metrics path: %v", err)
	}
	var lm string
	var seen int64
	s.db.QueryRow(`SELECT last_metrics, last_seen FROM agents WHERE id = ?`, "dev-tf").Scan(&lm, &seen)
	if lm == "" || lm == "{}" || seen == 0 {
		t.Fatalf("last_metrics and last_seen were not updated: %q %d", lm, seen)
	}
}
