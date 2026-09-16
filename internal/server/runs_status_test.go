package server

import (
	"strings"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// TestRunStatusSeparatesCancelFromFailure: the agent reports a cancelled run
// with exit code -1 and error "cancelled", which used to land in the same
// bucket as a real failure - in /api/runs, in runs_failed_24h and in the
// script_failed alert rule, so an operator's own cancel opened an alert.
func TestRunStatusSeparatesCancelFromFailure(t *testing.T) {
	cases := []struct {
		name string
		res  protocol.ScriptResult
		want string
	}{
		{"clean", protocol.ScriptResult{ExitCode: 0}, "done"},
		{"non-zero exit", protocol.ScriptResult{ExitCode: 3}, "failed"},
		{"agent error", protocol.ScriptResult{ExitCode: -1, Error: "python is not installed on this device"}, "failed"},
		{"cancelled", protocol.ScriptResult{ExitCode: -1, Error: "cancelled"}, "cancelled"},
		{"timeout wins", protocol.ScriptResult{ExitCode: -1, TimedOut: true, Error: "timed out after 25s"}, "timeout"},
	}
	for _, c := range cases {
		if got := runStatus(c.res); got != c.want {
			t.Errorf("%s: runStatus = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestFinishKeepsTheFullerOutput: the agent caps the capture it sends back
// below the cap on what the server buffers while the run streams, so the
// reply used to shrink a large report the console had already displayed.
func TestFinishKeepsTheFullerOutput(t *testing.T) {
	s, _, _ := newTestServer(t)
	if _, err := s.db.Exec(`INSERT INTO agents(id, key_hash, hostname, os, enrolled_at, last_seen) VALUES('chatty','h','chattybox','linux',?,?)`, now(), now()); err != nil {
		t.Fatal(err)
	}
	insert := func(id string) {
		t.Helper()
		if _, err := s.db.Exec(`INSERT INTO script_runs(id, script_name, agent_id, trigger, run_by, args, status, started_at)
			VALUES(?,?,?,?,?,?,?,?)`, id, "big report", "chatty", "manual", "admin", "[]", "running", now()); err != nil {
			t.Fatal(err)
		}
	}

	// The reply carries the first half; the stream carried all of it.
	full := strings.Repeat("LINE\n", 4000)
	insert("r-long")
	lr := &liveRun{agentID: "chatty"}
	lr.write("stdout", full)
	lr.write("stderr", "warn one\nwarn two\n")
	s.runs.finish("r-long", "chatty", "done", protocol.ScriptResult{
		RunID: "r-long", ExitCode: 0, Stdout: full[:len(full)/2] + "\n[output truncated]", Stderr: "warn one\n",
	}, lr)
	run, err := s.db.GetRun("r-long")
	if err != nil {
		t.Fatal(err)
	}
	if run.Stdout != full {
		t.Fatalf("stored %d bytes of stdout, the stream had %d", len(run.Stdout), len(full))
	}
	if !strings.Contains(run.Stderr, "warn two") {
		t.Fatalf("stderr lost the streamed copy: %q", run.Stderr)
	}

	// The reply is the fuller one when the stream was dropped on the floor.
	insert("r-short")
	s.runs.finish("r-short", "chatty", "done", protocol.ScriptResult{RunID: "r-short", ExitCode: 0, Stdout: "from the reply\n"}, &liveRun{agentID: "chatty"})
	run, err = s.db.GetRun("r-short")
	if err != nil || run.Stdout != "from the reply\n" {
		t.Fatalf("the reply's own output was dropped: %+v (%v)", run, err)
	}
}

// TestCancelledRunRaisesNoAlert: runs.go routes "failed" and "timeout" to the
// script_failed rule, and a cancel recorded as "failed" therefore opened an
// alert for the operator's own click.
func TestCancelledRunRaisesNoAlert(t *testing.T) {
	s, _, b := newTestServer(t)
	b.mustJSON("POST", "/api/alert-rules", AlertRule{Name: "script failed", Kind: "script_failed",
		Targets: Targets{All: true}, Severity: "warning", Enabled: true}, nil)
	if _, err := s.db.Exec(`INSERT INTO agents(id, key_hash, hostname, os, enrolled_at, last_seen) VALUES('box','h','box','linux',?,?)`, now(), now()); err != nil {
		t.Fatal(err)
	}
	run := func(id, status string, res protocol.ScriptResult) {
		t.Helper()
		if _, err := s.db.Exec(`INSERT INTO script_runs(id, script_name, agent_id, trigger, run_by, args, status, started_at)
			VALUES(?,?,?,?,?,?,?,?)`, id, "slow", "box", "manual", "admin", "[]", "running", now()); err != nil {
			t.Fatal(err)
		}
		s.runs.finish(id, "box", status, res, &liveRun{agentID: "box"})
	}

	run("r-cancel", "cancelled", protocol.ScriptResult{RunID: "r-cancel", ExitCode: -1, Error: "cancelled"})
	if al, _ := s.db.ListAlerts("open", "box", 10); len(al) != 0 {
		t.Fatalf("cancelling a run must not open an alert: %+v", al)
	}
	stored, err := s.db.GetRun("r-cancel")
	if err != nil || stored.Status != "cancelled" {
		t.Fatalf("a cancelled run must not read as a failure: %+v (%v)", stored, err)
	}

	// The same path still alerts on a genuine failure.
	run("r-fail", "failed", protocol.ScriptResult{RunID: "r-fail", ExitCode: 3})
	if al, _ := s.db.ListAlerts("open", "box", 10); len(al) != 1 {
		t.Fatalf("a failed run must still open an alert, got %+v", al)
	}
}

// TestRunOnAgentRejectsOSMismatch: the endpoint used to answer 200 with
// {"run_id":"skipped: os mismatch"}, a run id that 404s for ever after, so a
// client following the documented contract polled a run that never existed.
func TestRunOnAgentRejectsOSMismatch(t *testing.T) {
	s, _, b := newTestServer(t)
	var sc Script
	b.mustJSON("POST", "/api/scripts", Script{Name: "disk usage", Language: "bash", Body: "df -h", OSFilter: "linux"}, &sc)
	if _, err := s.db.Exec(`INSERT INTO agents(id, key_hash, hostname, os, enrolled_at, last_seen) VALUES('win1','h','winbox','windows',?,?)`, now(), now()); err != nil {
		t.Fatal(err)
	}
	st, body := b.do("POST", "/api/agents/win1/run", map[string]any{"script_id": sc.ID})
	if st != 409 {
		t.Fatalf("an os mismatch must not answer 2xx, got %d: %s", st, body)
	}
	if !strings.Contains(string(body), "os mismatch") {
		t.Fatalf("the error must say why the run was skipped: %s", body)
	}
	if strings.Contains(string(body), `"run_id"`) {
		t.Fatalf("no run was created, so no run id may be handed back: %s", body)
	}
	var runs []Run
	b.mustJSON("GET", "/api/runs?agent=win1", nil, &runs)
	if len(runs) != 0 {
		t.Fatalf("a skipped run must not be recorded: %+v", runs)
	}

	// An offline device with a matching script still queues, and still gets
	// its run id back.
	if _, err := s.db.Exec(`INSERT INTO agents(id, key_hash, hostname, os, enrolled_at, last_seen) VALUES('lin1','h2','linbox','linux',?,?)`, now(), now()); err != nil {
		t.Fatal(err)
	}
	var out struct {
		RunID string `json:"run_id"`
	}
	b.mustJSON("POST", "/api/agents/lin1/run", map[string]any{"script_id": sc.ID}, &out)
	if r, err := s.db.GetRun(out.RunID); err != nil || r.Status != "queued" {
		t.Fatalf("a matching script should still start: %+v (%v)", r, err)
	}
}
