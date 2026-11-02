package telemetry

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	_ "modernc.org/sqlite"
)

// testSchema is the metrics table as the server's migrations create it, minus
// the foreign key to agents, which the telemetry package does not own.
const testSchema = `CREATE TABLE metrics (
	agent_id TEXT NOT NULL,
	ts INTEGER NOT NULL,
	cpu REAL NOT NULL,
	mem_used INTEGER NOT NULL,
	mem_total INTEGER NOT NULL,
	disks TEXT NOT NULL,
	net_rx INTEGER NOT NULL,
	net_tx INTEGER NOT NULL,
	uptime INTEGER NOT NULL,
	load1 REAL NOT NULL DEFAULT 0,
	procs INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (agent_id, ts)
) WITHOUT ROWID;
CREATE INDEX idx_metrics_ts ON metrics(ts);`

func openTestSQLite(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "t.db")+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(testSchema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// engine builds a store and can open the same data again.
type engine struct {
	name string
	// replaces is false for ClickHouse: the table is a plain MergeTree as the
	// design says, so a second sample at the same agent and timestamp is kept
	// as a duplicate rather than replacing the first. Device clocks make that
	// rare, and the cost is one sample counted twice in an average.
	replaces bool

	open   func(t *testing.T) Store
	reopen func(t *testing.T, s Store) Store
}

func engines(t *testing.T) []engine {
	t.Helper()
	return []engine{
		{
			name: "sqlite", replaces: true,
			open: func(t *testing.T) Store { return OpenSQLite(openTestSQLite(t)) },
			// The handle belongs to the server, so "reopening" is wrapping it again.
			reopen: func(t *testing.T, s Store) Store { return OpenSQLite(s.(*sqliteStore).db) },
		},
		func() engine {
			dir := ""
			return engine{
				name: "pebble", replaces: true,
				open: func(t *testing.T) Store {
					dir = filepath.Join(t.TempDir(), "telemetry")
					s, err := OpenPebble(dir)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { s.Close() })
					return s
				},
				reopen: func(t *testing.T, s Store) Store {
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
					n, err := OpenPebble(dir)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { n.Close() })
					return n
				},
			}
		}(),
		func() engine {
			var fake *fakeClickHouse
			return engine{
				name: "clickhouse",
				open: func(t *testing.T) Store {
					fake = newFakeClickHouse(t)
					s, err := OpenClickHouse(fake.srv.URL, "", "")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { s.Close() })
					return s
				},
				reopen: func(t *testing.T, s Store) Store {
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
					n, err := OpenClickHouse(fake.srv.URL, "", "")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { n.Close() })
					return n
				},
			}
		}(),
	}
}

func metric(ts int64, cpu float64, i int) protocol.Metrics {
	return protocol.Metrics{
		TS: ts, CPUPct: cpu, MemUsed: uint64(1000 + i), MemTotal: 4000,
		Disks:    []protocol.DiskUsage{{Mount: "/", Total: 100, Used: uint64(i), UsedPct: float64(i)}},
		NetRxBps: uint64(10 * i), NetTxBps: uint64(5 * i), Uptime: uint64(100 + i), Load1: 0.5, ProcCount: 50 + i,
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func history(t *testing.T, s Store, id string, from, to int64, points int) []MetricRow {
	t.Helper()
	rows, err := s.MetricHistory(id, from, to, points)
	must(t, err)
	if rows == nil {
		t.Fatal("history returned nil rather than an empty list, which the API would render as JSON null")
	}
	return rows
}

// diskPct is the used_pct of a row's single disk, or -1 when it has none.
func diskPct(r MetricRow) float64 {
	if len(r.Disks) != 1 {
		return -1
	}
	return r.Disks[0].UsedPct
}

func TestConformance(t *testing.T) {
	// 1_800_000_000 is divisible by 9, 300 and 7200, which keeps the bucket
	// arithmetic below exact for every engine.
	const base = int64(1_800_000_000)
	for _, e := range engines(t) {
		t.Run(e.name, func(t *testing.T) {
			s := e.open(t)

			// Short span: twenty one-second samples for device "a".
			for i := 0; i < 20; i++ {
				must(t, s.WriteMetrics("a", metric(base+int64(i), float64(i), i)))
			}
			// "ab" shares a prefix with "a" and must never leak into its range.
			must(t, s.WriteMetrics("ab", metric(base+3, 99, 99)))

			rows := history(t, s, "a", base, base+19, 1_000_000)
			if len(rows) != 20 {
				t.Fatalf("one row per sample expected (points clamped to the maximum), got %d", len(rows))
			}
			if rows[19].TS != base+19 || rows[19].CPU != 19 || diskPct(rows[19]) != 19 || rows[19].Uptime != 119 {
				t.Fatalf("last sample wrong: %+v", rows[19])
			}
			if rows[0].MemUsed != 1000 || rows[0].MemTotal != 4000 || rows[0].Procs != 50 || rows[0].Load1 != 0.5 {
				t.Fatalf("first sample wrong: %+v", rows[0])
			}

			// Bucketed: span 19 over 2 points is 9-second buckets.
			rows = history(t, s, "a", base, base+19, 2)
			if len(rows) != 3 {
				t.Fatalf("want 3 buckets, got %d: %+v", len(rows), rows)
			}
			for i, want := range []struct {
				ts      int64
				cpu     float64
				lastPct float64
				uptime  uint64
				mem     uint64
			}{{base, 4, 8, 108, 1004}, {base + 9, 13, 17, 117, 1013}, {base + 18, 18.5, 19, 119, 1018}} {
				r := rows[i]
				if r.TS != want.ts || r.CPU != want.cpu || diskPct(r) != want.lastPct || r.Uptime != want.uptime || r.MemUsed != want.mem {
					t.Fatalf("bucket %d = %+v, want %+v", i, r, want)
				}
			}

			// A device nobody wrote, and a window with nothing in it, are empty lists.
			if got := history(t, s, "nobody", base, base+19, 10); len(got) != 0 {
				t.Fatalf("unknown device returned rows: %+v", got)
			}
			if got := history(t, s, "a", base+1000, base+2000, 10); len(got) != 0 {
				t.Fatalf("empty window returned rows: %+v", got)
			}

			// Replacing a sample must not double-count it.
			if e.replaces {
				must(t, s.WriteMetrics("a", metric(base, 100, 0)))
				rows = history(t, s, "a", base, base+19, 2)
				if rows[0].CPU != (100+1+2+3+4+5+6+7+8)/9.0 {
					t.Fatalf("replaced sample averaged wrongly: %+v", rows[0])
				}
				must(t, s.WriteMetrics("a", metric(base, 0, 0)))
			}

			// Long span: 480 minute-spaced samples over eight hours, cpu 10
			// for the first half and 20 for the second. Pebble answers this
			// from rollups, the others from the samples; the answer is the same.
			var batch []Sample
			for k := 0; k < 480; k++ {
				cpu := 10.0
				if k >= 240 {
					cpu = 20
				}
				batch = append(batch, Sample{AgentID: "long", Metrics: metric(base+int64(k)*60, cpu, k)})
			}
			if bw, ok := s.(BatchWriter); ok {
				must(t, bw.WriteBatch(batch))
			} else {
				t.Fatal("every store must implement BatchWriter")
			}
			long := history(t, s, "long", base, base+8*3600, 4)
			if len(long) != 4 {
				t.Fatalf("want 4 long-span buckets, got %d: %+v", len(long), long)
			}
			for i, want := range []float64{10, 10, 20, 20} {
				r := long[i]
				if r.TS != base+int64(i)*7200 || r.CPU != want || diskPct(r) != float64(i*120+119) {
					t.Fatalf("long bucket %d = %+v, want cpu %v and last disk %d", i, r, want, i*120+119)
				}
			}
			// Replace the first sample of the long series: the first bucket's
			// average moves by exactly one sample's worth.
			firstLong := 10.0
			if e.replaces {
				must(t, s.WriteMetrics("long", metric(base, 130, 0)))
				firstLong = 11
				long = history(t, s, "long", base, base+8*3600, 4)
				if long[0].CPU != firstLong {
					t.Fatalf("replacing a sample must not double-count it in the rollup: %+v", long[0])
				}
			}

			// Data survives a reopen.
			s = e.reopen(t, s)
			if got := history(t, s, "a", base, base+19, 1_000_000); len(got) != 20 {
				t.Fatalf("after reopen: %d rows, want 20", len(got))
			}
			if got := history(t, s, "long", base, base+8*3600, 4); len(got) != 4 || got[0].CPU != firstLong {
				t.Fatalf("after reopen the long series changed: %+v", got)
			}

			// Purge removes old samples everywhere and keeps newer ones.
			must(t, s.Purge(base+10))
			if got := history(t, s, "a", base, base+19, 1_000_000); len(got) != 10 || got[0].TS != base+10 {
				t.Fatalf("after purge of a: %+v", got)
			}
			must(t, s.Purge(base+4*3600))
			long = history(t, s, "long", base, base+8*3600, 4)
			if len(long) != 2 || long[0].TS != base+4*3600 || long[0].CPU != 20 {
				t.Fatalf("after purge of long: %+v", long)
			}

			// Deleting a device leaves its prefix-sharing neighbour alone.
			must(t, s.DeleteAgent("a"))
			if got := history(t, s, "a", base, base+8*3600, 100); len(got) != 0 {
				t.Fatalf("device a survived deletion: %+v", got)
			}
			if got := history(t, s, "ab", base, base+19, 100); len(got) != 0 {
				// "ab" had one sample at base+3, which the purge at base+10 removed.
				t.Fatalf("ab should have been purged already: %+v", got)
			}
			must(t, s.WriteMetrics("ab", metric(base+3600, 7, 1)))
			must(t, s.DeleteAgent("a"))
			if got := history(t, s, "ab", base, base+7200, 10); len(got) != 1 {
				t.Fatalf("deleting a removed its neighbour ab: %+v", got)
			}
			must(t, s.DeleteAgent("long"))
			if got := history(t, s, "long", base, base+8*3600, 4); len(got) != 0 {
				t.Fatalf("long survived deletion: %+v", got)
			}
			if in, ok := s.(Inspector); !ok || in.Engine() != e.name {
				t.Fatalf("Inspector missing or reports the wrong engine")
			}
		})
	}
}

// TestCopyFromSQLite seeds a database past one page of the copy and checks
// the destination answers the way the source does, then that DropSQLite
// empties the source.
func TestCopyFromSQLite(t *testing.T) {
	src := openTestSQLite(t)
	srcStore := OpenSQLite(src)
	const base = int64(1_800_000_000)
	var seed []Sample
	for i := 0; i < 6000; i++ {
		// Two devices share every timestamp, which the paging key must keep apart.
		seed = append(seed,
			Sample{AgentID: "x", Metrics: metric(base+int64(i), float64(i%50), i%90)},
			Sample{AgentID: "y", Metrics: metric(base+int64(i), float64(i%30), i%90)})
	}
	must(t, srcStore.(BatchWriter).WriteBatch(seed))
	dst, err := OpenPebble(filepath.Join(t.TempDir(), "telemetry"))
	must(t, err)
	defer dst.Close()
	var last int64
	n, err := CopyFromSQLite(src, dst, func(done int64) { last = done })
	must(t, err)
	if n != 12000 || last != 12000 {
		t.Fatalf("copied %d (progress %d), want 12000", n, last)
	}
	for _, id := range []string{"x", "y"} {
		a, b := history(t, srcStore, id, base, base+6000, 200), history(t, dst, id, base, base+6000, 200)
		if fmt.Sprint(a) != fmt.Sprint(b) {
			t.Fatalf("device %s differs after copy:\nsqlite %v\npebble %v", id, a[:2], b[:2])
		}
	}
	// Copying again is harmless on Pebble: samples replace themselves and the
	// rollups are corrected rather than doubled.
	if _, err := CopyFromSQLite(src, dst, nil); err != nil {
		t.Fatal(err)
	}
	if a, b := history(t, srcStore, "x", base, base+6000, 200), history(t, dst, "x", base, base+6000, 200); fmt.Sprint(a) != fmt.Sprint(b) {
		t.Fatal("a second copy changed the destination")
	}
	dropped, err := DropSQLite(src)
	must(t, err)
	if dropped != 12000 {
		t.Fatalf("dropped %d rows, want 12000", dropped)
	}
	if got := history(t, srcStore, "x", base, base+6000, 200); len(got) != 0 {
		t.Fatal("rows remain after drop")
	}
}
