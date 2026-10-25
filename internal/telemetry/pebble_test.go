package telemetry

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cockroachdb/pebble/v2"
)

func openPebbleForTest(t *testing.T) (*pebbleStore, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "telemetry")
	s, err := OpenPebble(dir)
	must(t, err)
	t.Cleanup(func() { s.Close() })
	return s.(*pebbleStore), dir
}

func TestPebbleKeysAndRollupLayout(t *testing.T) {
	p, _ := openPebbleForTest(t)
	const base = int64(1_800_000_000)
	// Three samples in one 5-minute bucket, one in the next.
	for i, ts := range []int64{base + 10, base + 20, base + 290, base + 310} {
		must(t, p.WriteMetrics("dev", metric(ts, float64(10*(i+1)), i)))
	}
	v, closer, err := p.db.Get(prefixedKey('m', "dev", base+20))
	must(t, err)
	s, err := decodeSample(v)
	closer.Close()
	must(t, err)
	if s.cpu != 20000 || s.memUsed != 1001 || s.procs != 51 {
		t.Fatalf("sample value does not hold cpu x1000, mem and procs: %+v", s)
	}
	if !strings.Contains(string(s.disks), `"used_pct":1`) {
		t.Fatalf("the disks JSON trails the varints: %s", s.disks)
	}
	v, closer, err = p.db.Get(prefixedKey('r', "dev", base))
	must(t, err)
	r, err := decodeRollup(v)
	closer.Close()
	must(t, err)
	if r.count != 3 || r.cpu != 60000 || r.lastTS != base+290 || r.uptime != 102 {
		t.Fatalf("first rollup wrong: %+v", r)
	}
	// Key shape: space byte, id, 0x00, 8-byte big-endian timestamp.
	k := prefixedKey('m', "dev", 0x0102030405060708)
	if !bytes.Equal(k, append([]byte("mdev\x00"), 1, 2, 3, 4, 5, 6, 7, 8)) {
		t.Fatalf("key layout changed: %q", k)
	}
}

func TestPebbleListsAgentsAcrossKeySpaces(t *testing.T) {
	p, _ := openPebbleForTest(t)
	for _, id := range []string{"b", "a", "ab", "zz"} {
		must(t, p.WriteMetrics(id, metric(1_800_000_000, 1, 1)))
	}
	ids, err := p.agents('m')
	must(t, err)
	if strings.Join(ids, ",") != "a,ab,b,zz" {
		t.Fatalf("agents = %v", ids)
	}
}

func TestPebbleOpenIsQuiet(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	p, dir := openPebbleForTest(t)
	must(t, p.WriteMetrics("a", metric(1_800_000_000, 1, 1)))
	must(t, p.Close())
	s, err := OpenPebble(dir)
	must(t, err)
	defer s.Close()
	if buf.Len() != 0 {
		t.Fatalf("Pebble wrote to the standard logger: %q", buf.String())
	}
}

func TestPebbleSecondOpenIsRefused(t *testing.T) {
	_, dir := openPebbleForTest(t)
	if s, err := OpenPebble(dir); err == nil {
		s.Close()
		t.Fatal("two processes could open one Pebble directory")
	}
}

func TestPebblePurgeWritesRangeTombstones(t *testing.T) {
	p, _ := openPebbleForTest(t)
	const base = int64(1_800_000_000)
	var batch []Sample
	for i := 0; i < 1000; i++ {
		batch = append(batch, Sample{AgentID: "a", Metrics: metric(base+int64(i), 1, 1)})
	}
	must(t, p.WriteBatch(batch))
	must(t, p.Purge(base+500))
	it, err := p.db.NewIter(&pebble.IterOptions{LowerBound: []byte("ma\x00"), UpperBound: []byte("ma\x01")})
	must(t, err)
	defer it.Close()
	n := 0
	for ok := it.First(); ok; ok = it.Next() {
		n++
	}
	if n != 500 {
		t.Fatalf("%d samples left after purge, want 500", n)
	}
	// Purging nothing, or before the epoch, must not make an invalid range.
	must(t, p.Purge(0))
	must(t, p.Purge(-5))
}

func TestPebbleUseAfterCloseIsAnErrorNotAPanic(t *testing.T) {
	p, _ := openPebbleForTest(t)
	must(t, p.Close())
	must(t, p.Close())
	if err := p.WriteMetrics("a", metric(1_800_000_000, 1, 1)); err == nil {
		t.Fatal("a write after Close succeeded")
	}
	if _, err := p.MetricHistory("a", 0, 10, 10); err == nil {
		t.Fatal("a read after Close succeeded")
	}
	if p.Purge(10) == nil || p.DeleteAgent("a") == nil {
		t.Fatal("purge or delete after Close succeeded")
	}
}

func TestPebbleSizeIsReported(t *testing.T) {
	p, _ := openPebbleForTest(t)
	must(t, p.WriteMetrics("a", metric(1_800_000_000, 1, 1)))
	if n, err := p.SizeBytes(); err != nil || n <= 0 {
		t.Fatalf("size = %d, %v", n, err)
	}
}

// A long span must give the same buckets and averages as the SQLite engine,
// whether it is answered from rollups (bucket a multiple of 5 minutes) or from
// raw samples (any other bucket), and a range that starts and ends inside a
// rollup must not count the samples outside it.
func TestPebbleLongSpanMatchesSQLite(t *testing.T) {
	p, _ := openPebbleForTest(t)
	sq := OpenSQLite(openTestSQLite(t))
	const base = int64(1_800_000_000)
	for ts := base; ts < base+14*3600; ts += 30 {
		m := metric(ts, float64(ts%97), int(ts%13))
		must(t, p.WriteMetrics("dev", m))
		must(t, sq.WriteMetrics("dev", m))
	}
	for _, tc := range []struct {
		from, to int64
		points   int
	}{
		{base + 100, base + 12*3600 + 170, 600}, // 72 s buckets: raw
		{base + 100, base + 12*3600 + 170, 36},  // 1200 s buckets: rollups with raw edges
		{base + 3600, base + 13*3600, 12},       // 3600 s buckets, aligned ends
	} {
		want := history(t, sq, "dev", tc.from, tc.to, tc.points)
		got := history(t, p, "dev", tc.from, tc.to, tc.points)
		if len(got) != len(want) {
			t.Fatalf("%+v: pebble gave %d rows, sqlite %d", tc, len(got), len(want))
		}
		for i := range want {
			if got[i].TS != want[i].TS || diff(got[i].CPU, want[i].CPU) > 0.01 {
				t.Fatalf("%+v row %d: pebble %+v, sqlite %+v", tc, i, got[i], want[i])
			}
		}
	}
}

func diff(a, b float64) float64 {
	if a > b {
		return a - b
	}
	return b - a
}
