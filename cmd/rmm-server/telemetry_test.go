package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/server"
	"github.com/MonsterCouch/homelab-rmm/internal/telemetry"
)

const seedBase = int64(1_800_000_000)

// seedDataDir creates a real data directory whose rmm.db holds three devices
// with 100 metrics samples each, then releases it the way a stopped server
// would.
func seedDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	s, err := server.New(server.Config{DataDir: dir, Insecure: true, SkipSeed: true})
	if err != nil {
		t.Fatal(err)
	}
	db := s.DB()
	for _, id := range []string{"a", "b", "c"} {
		if _, err := db.Exec(`INSERT INTO agents(id, key_hash, hostname, os, enrolled_at) VALUES(?,'h',?,'linux',1)`, id, id); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 100; i++ {
			if _, err := db.Exec(`INSERT INTO metrics(agent_id, ts, cpu, mem_used, mem_total, disks, net_rx, net_tx, uptime, load1, procs)
				VALUES(?,?,?,?,?,?,0,0,?,0,1)`, id, seedBase+int64(i), float64(i), 10, 20, `[{"mount":"/","total":100,"used":1,"used_pct":`+string(rune('1'+i%9))+`}]`, 1000+i); err != nil {
				t.Fatal(err)
			}
		}
	}
	db.Close()
	return dir
}

func sqliteMetricRows(t *testing.T, dir string) int {
	t.Helper()
	db, err := server.OpenDatabase(server.Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM metrics`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func runTelemetryCmd(args ...string) (code int, out, errOut string) {
	var o, e bytes.Buffer
	code = telemetryMain(args, &o, &e)
	return code, o.String(), e.String()
}

func TestTelemetryMigrateToPebble(t *testing.T) {
	dir := seedDataDir(t)
	code, out, errOut := runTelemetryCmd("migrate", "--to", "pebble", "--data", dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "Copied 300 samples to pebble") {
		t.Fatalf("progress line missing: %s", out)
	}
	if !strings.Contains(out, "--telemetry pebble") || !strings.Contains(out, "RMM_TELEMETRY=pebble") {
		t.Fatalf("the output must say how to start the server: %s", out)
	}
	if !strings.Contains(out, "drop-sqlite") {
		t.Fatalf("the output must say the SQLite rows are kept and how to drop them: %s", out)
	}
	if n := sqliteMetricRows(t, dir); n != 300 {
		t.Fatalf("migrate deleted SQLite rows: %d left, want 300", n)
	}
	st, err := telemetry.OpenPebble(filepath.Join(dir, "telemetry"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, id := range []string{"a", "b", "c"} {
		rows, err := st.MetricHistory(id, seedBase, seedBase+99, 1000)
		if err != nil || len(rows) != 100 || rows[99].CPU != 99 || rows[99].Uptime != 1099 {
			t.Fatalf("device %s after migration: %d rows, %v", id, len(rows), err)
		}
	}
	// Running it again is harmless on Pebble.
	st.Close()
	if code, _, errOut := runTelemetryCmd("migrate", "--to", "pebble", "--data", dir); code != 0 {
		t.Fatalf("second migrate exit %d: %s", code, errOut)
	}
}

func TestTelemetryRefusesWhileTheServerHoldsTheDirectory(t *testing.T) {
	dir := seedDataDir(t)
	unlock, err := telemetry.LockDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"migrate", "--to", "pebble", "--data", dir},
		{"drop-sqlite", "--telemetry", "pebble", "--data", dir},
	} {
		code, _, errOut := runTelemetryCmd(args...)
		if code != 1 || !strings.Contains(errOut, "stop the server") {
			t.Fatalf("%v: exit %d, %q; want a refusal that says to stop the server", args, code, errOut)
		}
	}
	if n := sqliteMetricRows(t, dir); n != 300 {
		t.Fatalf("a refused command changed the database: %d rows", n)
	}
	unlock()
	if code, _, errOut := runTelemetryCmd("migrate", "--to", "pebble", "--data", dir); code != 0 {
		t.Fatalf("after the lock was released: exit %d: %s", code, errOut)
	}
}

func TestTelemetryDropSQLite(t *testing.T) {
	dir := seedDataDir(t)

	// Without naming the engine the server moved to, it would delete live data.
	code, _, errOut := runTelemetryCmd("drop-sqlite", "--data", dir)
	if code != 1 || !strings.Contains(errOut, "refusing to drop") {
		t.Fatalf("exit %d, %q; want a refusal while the engine is sqlite", code, errOut)
	}
	if n := sqliteMetricRows(t, dir); n != 300 {
		t.Fatalf("the refused drop deleted rows: %d", n)
	}

	// Naming pebble is not enough: nothing has been migrated yet, so the
	// drop would delete the only copy of the history.
	code, _, errOut = runTelemetryCmd("drop-sqlite", "--telemetry", "pebble", "--data", dir)
	if code != 1 || !strings.Contains(errOut, "refusing to drop") || sqliteMetricRows(t, dir) != 300 {
		t.Fatalf("exit %d, %q; want a refusal while the target holds nothing", code, errOut)
	}
	if code, _, errOut := runTelemetryCmd("migrate", "--to", "pebble", "--data", dir); code != 0 {
		t.Fatalf("migrate exit %d: %s", code, errOut)
	}

	code, out, errOut := runTelemetryCmd("drop-sqlite", "--telemetry", "pebble", "--data", dir)
	if code != 0 || !strings.Contains(out, "Deleted 300 samples") {
		t.Fatalf("exit %d, out %q, err %q", code, out, errOut)
	}
	if n := sqliteMetricRows(t, dir); n != 0 {
		t.Fatalf("%d rows remain", n)
	}
}

func TestTelemetryDropSQLiteReadsTheEnvironment(t *testing.T) {
	dir := seedDataDir(t)
	t.Setenv("RMM_TELEMETRY", "pebble")
	if code, _, errOut := runTelemetryCmd("migrate", "--to", "pebble", "--data", dir); code != 0 {
		t.Fatalf("migrate exit %d: %s", code, errOut)
	}
	if code, out, errOut := runTelemetryCmd("drop-sqlite", "--data", dir); code != 0 {
		t.Fatalf("exit %d, out %q, err %q", code, out, errOut)
	}
	if n := sqliteMetricRows(t, dir); n != 0 {
		t.Fatalf("%d rows remain", n)
	}
}

func TestTelemetryCommandErrors(t *testing.T) {
	dir := seedDataDir(t)
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"migrate", "--data", dir}, 2, "--to is required"},
		{[]string{"migrate", "--to", "sqlite", "--data", dir}, 2, "not a target engine"},
		{[]string{"migrate", "--to", "mysql", "--data", dir}, 2, "not a target engine"},
		{[]string{"migrate", "--to", "clickhouse", "--data", dir}, 2, "--telemetry-dsn"},
		{[]string{"migrate", "--to", "pebble", "--data", filepath.Join(dir, "nowhere")}, 1, "no database at"},
		{[]string{"drop-sqlite", "--telemetry", "pebble", "--data", filepath.Join(dir, "nowhere")}, 1, "no database at"},
	} {
		code, _, errOut := runTelemetryCmd(tc.args...)
		if code != tc.code || !strings.Contains(errOut, tc.want) {
			t.Errorf("%v: exit %d %q, want exit %d containing %q", tc.args, code, errOut, tc.code, tc.want)
		}
	}
	if code, _, _ := runTelemetryCmd(); code != 2 {
		t.Errorf("no subcommand: exit %d, want 2", code)
	}
	if code, _, _ := runTelemetryCmd("frobnicate", "--data", dir); code != 2 {
		t.Errorf("unknown subcommand: exit %d, want 2", code)
	}
}

// chCounter is the smallest ClickHouse stand-in the migration needs: it
// accepts the table creation, answers count(), and counts inserted rows.
type chCounter struct {
	mu       sync.Mutex
	existing int
	inserted int
	agents   map[string]int
}

func (c *chCounter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	defer c.mu.Unlock()
	q := r.URL.Query().Get("query")
	switch {
	case strings.HasPrefix(q, "INSERT INTO rmm_metrics"):
		for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
			var row struct {
				AgentID string `json:"agent_id"`
			}
			if json.Unmarshal([]byte(line), &row) == nil {
				c.inserted++
				c.agents[row.AgentID]++
			}
		}
	case strings.HasPrefix(string(body), "SELECT count()"):
		io.WriteString(w, strconv.Itoa(c.existing)+"\n")
	}
}

func TestTelemetryMigrateToClickHouse(t *testing.T) {
	dir := seedDataDir(t)
	ch := &chCounter{agents: map[string]int{}}
	srv := httptest.NewServer(ch)
	defer srv.Close()

	code, out, errOut := runTelemetryCmd("migrate", "--to", "clickhouse", "--telemetry-dsn", srv.URL, "--data", dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if ch.inserted != 300 || ch.agents["a"] != 100 || ch.agents["c"] != 100 {
		t.Fatalf("ClickHouse received %d rows %v, want 100 per device", ch.inserted, ch.agents)
	}
	if !strings.Contains(out, "--telemetry clickhouse --telemetry-dsn "+srv.URL) {
		t.Fatalf("the output must give the server flags: %s", out)
	}

	// A table that already has data is refused, because MergeTree would keep
	// the copied rows twice.
	ch.existing, ch.inserted = 5, 0
	code, _, errOut = runTelemetryCmd("migrate", "--to", "clickhouse", "--telemetry-dsn", srv.URL, "--data", dir)
	if code != 1 || !strings.Contains(errOut, "already holds 5 samples") || ch.inserted != 0 {
		t.Fatalf("exit %d, %q, inserted %d; want a refusal before any insert", code, errOut, ch.inserted)
	}
}

func TestMigrateOutputNeverPrintsADSNPassword(t *testing.T) {
	cfg := server.Config{TelemetryDSN: "http://rmm:hunter2@ch:8123"}
	if got := serverFlagFor("clickhouse", cfg); strings.Contains(got, "hunter2") {
		t.Fatalf("the password was printed: %s", got)
	}
}

func TestTelemetryFlagsAndInstallArgs(t *testing.T) {
	t.Setenv("RMM_TELEMETRY", "")
	t.Setenv("RMM_TELEMETRY_DSN", "")
	cfg := parseFlags([]string{"--telemetry", "clickhouse", "--telemetry-dsn", "http://ch:8123"})
	if cfg.Telemetry != "clickhouse" || cfg.TelemetryDSN != "http://ch:8123" {
		t.Fatalf("flags not parsed: %+v", cfg)
	}
	// The environment wins over the flag, as for the other settings.
	t.Setenv("RMM_TELEMETRY", "pebble")
	if cfg := parseFlags([]string{"--telemetry", "clickhouse"}); cfg.Telemetry != "pebble" {
		t.Fatalf("the environment did not win: %+v", cfg)
	}

	// A service does not inherit the installing shell's environment, so the
	// user travels in the DSN. The password never does: service arguments are
	// readable by other local users, so it goes in a file in the data dir.
	cfg = server.Config{Listen: ":8443", DataDir: "/d", Telemetry: "clickhouse", TelemetryDSN: "http://ch:8123", TelemetryUser: "rmm", TelemetryPassword: "pw"}
	args := strings.Join(installArgs(cfg), " ")
	if !strings.Contains(args, "--telemetry clickhouse") || !strings.Contains(args, "--telemetry-dsn http://rmm@ch:8123") || strings.Contains(args, "pw") {
		t.Fatalf("install args lose the telemetry settings: %s", args)
	}
	cfg.DataDir = t.TempDir()
	cfg.TelemetryDSN = "http://rmm:dsnpw@ch:8123"
	cfg.TelemetryPassword = ""
	if a := strings.Join(installArgs(cfg), " "); strings.Contains(a, "dsnpw") {
		t.Fatalf("a password in the DSN reached the service arguments: %s", a)
	}
	if err := installTelemetryPassword(cfg); err != nil {
		t.Fatal(err)
	}
	if got := server.TelemetryPassword(cfg); got != "dsnpw" {
		t.Fatalf("the server cannot read back the stored password: %q", got)
	}
	if st, err := os.Stat(server.TelemetryPasswordFile(cfg)); err != nil || st.Mode().Perm()&0o077 != 0 && runtime.GOOS != "windows" {
		t.Fatalf("the password file is missing or readable by others: %v %v", st, err)
	}
	if a := strings.Join(installArgs(server.Config{Listen: ":8443", DataDir: "/d"}), " "); strings.Contains(a, "telemetry") {
		t.Fatalf("the default engine must not appear in install args: %s", a)
	}
	if err := validateConfig(server.Config{Listen: ":8443", DataDir: t.TempDir(), Telemetry: "clickhouse"}); err == nil {
		t.Fatal("validateConfig accepted clickhouse without a DSN")
	}
}
