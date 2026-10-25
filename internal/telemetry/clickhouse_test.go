package telemetry

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// fakeClickHouse speaks enough of the ClickHouse HTTP protocol for the store:
// it records every statement and the parameters sent with it, checks that the
// SQL has the shape the store promises (typed parameters, no spliced values,
// the documented engine and ordering), and answers from an in-memory table.
type fakeClickHouse struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	rows     []clickhouseRow
	sqls     []string
	inserts  int // INSERT statements received
	failNext int // answer the next n inserts with a 500
	quote64  bool
	user     string
	pass     string
	badAuth  int
}

func newFakeClickHouse(t *testing.T) *fakeClickHouse {
	f := &fakeClickHouse{t: t}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeClickHouse) statements() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sqls...)
}

func (f *fakeClickHouse) rowCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.rows)
}

func (f *fakeClickHouse) fail(w http.ResponseWriter, code int, msg string) {
	http.Error(w, msg, code)
}

func (f *fakeClickHouse) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.user != "" {
		if u, p, ok := r.BasicAuth(); !ok || u != f.user || p != f.pass {
			f.badAuth++
			f.fail(w, 401, "Code: 516. Authentication failed")
			return
		}
	}
	q := r.URL.Query()
	body, _ := io.ReadAll(r.Body)
	sql, data := string(body), []byte(nil)
	if s := q.Get("query"); s != "" {
		sql, data = s, body
	}
	sql = strings.TrimSpace(sql)
	f.sqls = append(f.sqls, sql)
	param := func(name string) string { return q.Get("param_" + name) }
	pint := func(name string) int64 {
		n, err := strconv.ParseInt(param(name), 10, 64)
		if err != nil {
			f.t.Errorf("parameter %s is not an integer: %q", name, param(name))
		}
		return n
	}
	// Whatever was sent, the SQL text itself must never carry a value.
	for _, name := range []string{"agent"} {
		if v := param(name); len(v) > 3 && strings.Contains(sql, v) {
			f.t.Errorf("the SQL carries the %s value %q instead of a typed parameter: %s", name, v, sql)
		}
	}
	switch {
	case strings.HasPrefix(sql, "CREATE TABLE IF NOT EXISTS rmm_metrics"):
		if !strings.Contains(sql, "ENGINE = MergeTree ORDER BY (agent_id, ts)") {
			f.t.Errorf("table definition lacks the documented engine and order: %s", sql)
		}
	case sql == "INSERT INTO rmm_metrics FORMAT JSONEachRow":
		f.inserts++
		if f.failNext > 0 {
			f.failNext--
			f.fail(w, 500, "Code: 999. injected failure")
			return
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var row clickhouseRow
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				f.t.Errorf("insert line is not valid JSONEachRow: %q", line)
				continue
			}
			f.rows = append(f.rows, row)
		}
	case strings.HasPrefix(sql, "SELECT intDiv(ts, {bucket:Int64}) * {bucket:Int64} AS bts"):
		for _, want := range []string{"FROM rmm_metrics", "agent_id = {agent:String}", "ts BETWEEN {from:Int64} AND {to:Int64}", "GROUP BY bts ORDER BY bts", "FORMAT JSONEachRow", "argMax(disks, ts)"} {
			if !strings.Contains(sql, want) {
				f.t.Errorf("history query lacks %q: %s", want, sql)
			}
		}
		f.history(w, param("agent"), pint("from"), pint("to"), pint("bucket"))
	case strings.HasPrefix(sql, "ALTER TABLE rmm_metrics DELETE WHERE ts < {before:Int64}"):
		if q.Get("mutations_sync") != "1" {
			f.t.Errorf("purge must wait for its mutation: %v", q)
		}
		before := pint("before")
		f.keep(func(r clickhouseRow) bool { return r.TS >= before })
	case strings.HasPrefix(sql, "ALTER TABLE rmm_metrics DELETE WHERE agent_id = {agent:String}"):
		if q.Get("mutations_sync") != "1" {
			f.t.Errorf("agent deletion must wait for its mutation: %v", q)
		}
		id := param("agent")
		f.keep(func(r clickhouseRow) bool { return r.AgentID != id })
	case strings.HasPrefix(sql, "SELECT count() FROM rmm_metrics"):
		io.WriteString(w, strconv.Itoa(len(f.rows))+"\n")
	case strings.HasPrefix(sql, "SELECT sum(bytes_on_disk) FROM system.parts"):
		io.WriteString(w, strconv.Itoa(len(f.rows)*40)+"\n")
	default:
		f.t.Errorf("unexpected statement: %s", sql)
		f.fail(w, 400, "unexpected")
	}
}

func (f *fakeClickHouse) keep(pred func(clickhouseRow) bool) {
	kept := f.rows[:0:0]
	for _, r := range f.rows {
		if pred(r) {
			kept = append(kept, r)
		}
	}
	f.rows = kept
}

func (f *fakeClickHouse) history(w http.ResponseWriter, agent string, from, to, bucket int64) {
	groups := map[int64][]clickhouseRow{}
	for _, r := range f.rows {
		if r.AgentID == agent && r.TS >= from && r.TS <= to {
			b := r.TS / bucket * bucket
			groups[b] = append(groups[b], r)
		}
	}
	keys := make([]int64, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	// A real server quotes 64-bit integers unless asked not to; the store asks,
	// and the quote64 switch lets a test check it copes when it is ignored.
	num := func(n int64) any {
		if f.quote64 {
			return strconv.FormatInt(n, 10)
		}
		return n
	}
	enc := json.NewEncoder(w)
	for _, k := range keys {
		g := groups[k]
		var cpu, mem, memTotal, rx, tx, load, procs float64
		last := g[0]
		for _, r := range g {
			cpu += r.CPU
			mem += float64(r.MemUsed)
			memTotal += float64(r.MemTotal)
			rx += float64(r.NetRx)
			tx += float64(r.NetTx)
			load += r.Load1
			procs += float64(r.Procs)
			if r.TS >= last.TS {
				last = r
			}
		}
		n := float64(len(g))
		enc.Encode(map[string]any{
			"bts": num(k), "a_cpu": cpu / n, "a_mem_used": mem / n, "a_mem_total": memTotal / n,
			"a_net_rx": rx / n, "a_net_tx": tx / n, "a_load1": load / n, "a_procs": procs / n,
			"last_disks": last.Disks, "last_uptime": num(int64(last.Uptime)),
		})
	}
}

func TestClickHouseBatchesAndRetries(t *testing.T) {
	f := newFakeClickHouse(t)
	s, err := OpenClickHouse(f.srv.URL, "", "")
	must(t, err)
	base := time64()
	for i := 0; i < clickhouseFlushRows-1; i++ {
		must(t, s.WriteMetrics("a", metric(base+int64(i), 1, 1)))
	}
	if f.inserts != 0 {
		t.Fatalf("an insert was sent after %d rows, before the batch was full", clickhouseFlushRows-1)
	}
	// The 500th row wakes the flusher, which sends one insert of all 500; the
	// write itself returns without waiting for it.
	must(t, s.WriteMetrics("a", metric(base+1000, 1, 1)))
	for end := time.Now().Add(5 * time.Second); f.rowCount() < clickhouseFlushRows && time.Now().Before(end); {
		time.Sleep(5 * time.Millisecond)
	}
	if f.inserts != 1 || f.rowCount() != clickhouseFlushRows {
		t.Fatalf("want one insert of %d rows, got %d inserts and %d rows", clickhouseFlushRows, f.inserts, f.rowCount())
	}

	// A write below the threshold is flushed by the timer within about a second.
	must(t, s.WriteMetrics("b", metric(base, 2, 2)))
	deadline := time.Now().Add(5 * time.Second)
	for f.rowCount() < clickhouseFlushRows+1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if f.rowCount() != clickhouseFlushRows+1 {
		t.Fatal("the timer never flushed a lone sample")
	}

	// A failed insert keeps the rows and the next flush sends them.
	f.mu.Lock()
	f.failNext = 1
	f.mu.Unlock()
	must(t, s.WriteMetrics("c", metric(base, 3, 3)))
	// The flush may fail or the timer may have consumed the injected failure
	// first; either way the row must still arrive.
	_ = s.(*clickhouseStore).flush()
	if rows := history(t, s, "c", base, base, 10); len(rows) != 1 || rows[0].CPU != 3 {
		t.Fatalf("a sample was lost across a failed insert: %+v", rows)
	}

	// Close flushes what is still buffered.
	must(t, s.WriteMetrics("d", metric(base, 4, 4)))
	must(t, s.Close())
	must(t, s.Close()) // a second Close is harmless
	found := false
	for _, r := range f.rows {
		found = found || r.AgentID == "d"
	}
	if !found {
		t.Fatal("Close dropped the buffered sample")
	}
}

func TestClickHouseSendsCredentialsAndRefusesBadDSN(t *testing.T) {
	f := newFakeClickHouse(t)
	f.user, f.pass = "rmm", "s3cret"
	if _, err := OpenClickHouse(f.srv.URL, "rmm", "wrong"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a wrong password must fail on open with the server's answer, got %v", err)
	}
	s, err := OpenClickHouse(f.srv.URL, "rmm", "s3cret")
	must(t, err)
	s.Close()
	// Credentials may also ride in the DSN, which is how `install` carries them.
	withUser := strings.Replace(f.srv.URL, "http://", "http://rmm:s3cret@", 1)
	s, err = OpenClickHouse(withUser, "", "")
	must(t, err)
	s.Close()

	for _, bad := range []string{"", "clickhouse://host", "host:8123", "http://"} {
		if _, err := OpenClickHouse(bad, "", ""); err == nil {
			t.Errorf("DSN %q was accepted", bad)
		}
	}
}

func TestClickHouseReadsQuotedIntegers(t *testing.T) {
	f := newFakeClickHouse(t)
	f.quote64 = true
	s, err := OpenClickHouse(f.srv.URL, "", "")
	must(t, err)
	defer s.Close()
	base := time64()
	must(t, s.WriteMetrics("q", protocol.Metrics{TS: base, CPUPct: 5, Uptime: 77}))
	rows := history(t, s, "q", base, base, 10)
	if len(rows) != 1 || rows[0].TS != base || rows[0].Uptime != 77 {
		t.Fatalf("quoted 64-bit integers were misread: %+v", rows)
	}
}

func TestClickHouseCountAndSize(t *testing.T) {
	f := newFakeClickHouse(t)
	s, err := OpenClickHouse(f.srv.URL, "", "")
	must(t, err)
	defer s.Close()
	must(t, s.(BatchWriter).WriteBatch([]Sample{{AgentID: "a", Metrics: metric(time64(), 1, 1)}}))
	if n, err := s.(Counter).Count(); err != nil || n != 1 {
		t.Fatalf("count = %d, %v", n, err)
	}
	if n, err := s.(Inspector).SizeBytes(); err != nil || n != 40 {
		t.Fatalf("size = %d, %v", n, err)
	}
}

func time64() int64 { return 1_800_000_000 }

func TestClickHouseNeverSplicesAnAgentIDIntoSQL(t *testing.T) {
	f := newFakeClickHouse(t)
	s, err := OpenClickHouse(f.srv.URL, "", "")
	must(t, err)
	defer s.Close()
	id := "x'; DROP TABLE rmm_metrics; --"
	base := time64()
	must(t, s.WriteMetrics(id, metric(base, 9, 1)))
	if rows := history(t, s, id, base, base, 10); len(rows) != 1 || rows[0].CPU != 9 {
		t.Fatalf("a device id with quotes did not round-trip: %+v", rows)
	}
	must(t, s.DeleteAgent(id))
	if f.rowCount() != 0 {
		t.Fatal("DeleteAgent did not remove the device")
	}
	for _, sql := range f.statements() {
		if strings.Contains(sql, "DROP TABLE") {
			t.Fatalf("a device id reached the SQL text: %s", sql)
		}
	}
}

func TestClickHouseFullBufferNeverFailsOrBlocksAWrite(t *testing.T) {
	f := newFakeClickHouse(t)
	s, err := OpenClickHouse(f.srv.URL, "", "")
	must(t, err)
	defer s.Close()
	f.mu.Lock()
	f.failNext = 1000
	f.mu.Unlock()
	base := time64()
	start := time.Now()
	for i := 0; i < clickhouseFlushRows*2; i++ {
		if err := s.WriteMetrics("a", metric(base+int64(i), 1, 1)); err != nil {
			t.Fatalf("a write during an outage must not report the outage to the ingest path: %v", err)
		}
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("writes waited on ClickHouse")
	}
}

func TestOpenClickHouseErrorHidesThePassword(t *testing.T) {
	for _, dsn := range []string{"tcp://rmm:s3cretpw@host:9000", "clickhouse://rmm:s3cretpw@host", "http://rmm:s3cretpw@", "http://rmm:s3cretpw@host:99999x/%zz"} {
		_, err := OpenClickHouse(dsn, "", "")
		if err == nil || strings.Contains(err.Error(), "s3cretpw") {
			t.Fatalf("%s: want an error without the password, got %v", dsn, err)
		}
	}
}
