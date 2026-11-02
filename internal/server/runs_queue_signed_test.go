package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// goOffline drops an agent's socket and waits until the hub notices.
func goOffline(t *testing.T, s *Server, ag *sigAgent) {
	t.Helper()
	ag.raw.ws.Close()
	waitFor(t, "agent offline", func() bool { return !s.hub.IsOnline(ag.ID()) })
}

// comeBack reconnects an offline agent with its key, as a real agent does.
// Connecting is what releases the device's queued runs.
func (f *signFixture) comeBack(old *sigAgent, host string) *sigAgent {
	f.t.Helper()
	ra := dialAgentAs(f.t, f.ts, http.Header{"Authorization": []string{"Bearer " + old.raw.key}}, host, "linux")
	a := &sigAgent{t: f.t, s: f.s, raw: ra, nonce: old.nonce}
	go a.loop()
	waitFor(f.t, "agent online", func() bool { return f.s.hub.IsOnline(ra.id) })
	return a
}

func countRuns(t *testing.T, s *Server, where string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM script_runs ` + where).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// An operator is not asked to sign a run for a device that cannot receive it:
// the signature would expire before the device is back, and the manifest
// would name a device the run never reaches.
func TestSignedRunOnOfflineDeviceIsNotOfferedForSigning(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeAudit, 1, 10)
	ag := f.addAgent("offbox")
	var sc Script
	f.admin.mustJSON("POST", "/api/scripts", Script{Name: "lib", Language: "bash", Body: "echo q", TimeoutSec: 30}, &sc)
	goOffline(t, f.s, ag)

	st, data := f.admin.do("POST", "/api/scripts/run", map[string]any{"agent_ids": []string{ag.ID()}, "script_id": sc.ID})
	if st != http.StatusOK {
		t.Fatalf("run = %d %s, want 200 with the outcome and no signing challenge", st, data)
	}
	var res struct {
		Runs map[string]string `json:"runs"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatal(err)
	}
	if want := "error: " + ErrSignedRunOffline.Error(); res.Runs[ag.ID()] != want {
		t.Fatalf("outcome = %q, want %q", res.Runs[ag.ID()], want)
	}
	if n := countRuns(t, f.s, ""); n != 0 {
		t.Fatalf("%d rows in script_runs, want none", n)
	}
}

// An ad hoc body is never queued, so the multi-device path answers the plain
// offline error without a signing challenge, as the single-device path does.
func TestAdHocRunOnOfflineDeviceIsNotOfferedForSigning(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeAudit, 1, 10)
	ag := f.addAgent("offbox")
	goOffline(t, f.s, ag)

	st, data := f.admin.do("POST", "/api/scripts/run", map[string]any{"agent_ids": []string{ag.ID()}, "language": "bash", "body": "echo q"})
	if st != http.StatusOK {
		t.Fatalf("run = %d %s, want 200 with the outcome and no signing challenge", st, data)
	}
	var res struct {
		Runs map[string]string `json:"runs"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatal(err)
	}
	if want := "error: " + ErrAgentOffline.Error(); res.Runs[ag.ID()] != want {
		t.Fatalf("outcome = %q, want %q", res.Runs[ag.ID()], want)
	}
}

// The check in Start is the authoritative one: a device can drop between the
// challenge and the last signature.
func TestStartRefusesASignedRunForAnOfflineDevice(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeAudit, 1, 10)
	ag := f.addAgent("offbox")
	var sc Script
	f.admin.mustJSON("POST", "/api/scripts", Script{Name: "lib", Language: "bash", Body: "echo q", TimeoutSec: 30}, &sc)
	script, err := f.s.db.GetScript(sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	goOffline(t, f.s, ag)

	_, err = f.s.runs.Start(ag.ID(), RunRequest{Script: script, Trigger: "manual", RunBy: "admin", Auth: &protocol.ActionAuth{M: "x"}})
	if !errors.Is(err, ErrSignedRunOffline) {
		t.Fatalf("Start = %v, want ErrSignedRunOffline", err)
	}
	if n := countRuns(t, f.s, ""); n != 0 {
		t.Fatalf("%d rows in script_runs, want none", n)
	}
}

// A run queued for an offline device by an automation keeps the reference to
// the automation's standing approval, so it is released signed.
func TestQueuedAutomationRunIsReleasedWithItsStandingApproval(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeAudit, 1, 10)
	ag := f.addAgent("autobox")
	var sc Script
	f.admin.mustJSON("POST", "/api/scripts", Script{Name: "fix", Language: "bash", Body: "echo fix", TimeoutSec: 30}, &sc)
	// alert_resolved never fires in this test, so only the explicit Start
	// below produces a run.
	var au Automation
	f.admin.mustJSON("POST", "/api/automations", map[string]any{"name": "fixer", "trigger": "alert_resolved", "filter": map[string]any{},
		"action": "run_script", "action_params": map[string]any{"script_id": sc.ID}, "enabled": true}, &au)
	aid := strconv.FormatInt(au.ID, 10)
	if st, body := signedCall(t, f.admin, f.ka, "POST", "/api/approvals/objects/automation/"+aid+"/sign", nil); st != 200 {
		t.Fatalf("sign automation = %d %s", st, body)
	}
	script, _ := f.s.db.GetScript(sc.ID)
	goOffline(t, f.s, ag)

	id, err := f.s.runs.Start(ag.ID(), RunRequest{Script: script, Trigger: "automation", RunBy: "automation:fixer",
		Standing: &standingRef{Type: approvalAutomation, ID: aid}})
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	f.s.db.QueryRow(`SELECT standing FROM script_runs WHERE id = ? AND status = 'queued'`, id).Scan(&stored)
	if stored != "automation:"+aid {
		t.Fatalf("queued row standing = %q, want automation:%s", stored, aid)
	}

	back := f.comeBack(ag, "autobox")
	got := back.wait(protocol.ReqScriptRun, 1)[0]
	if got.Env.A == nil || !got.Dec.Verified || !got.Dec.Allow {
		t.Fatalf("released automation run: A=%v decision=%+v", got.Env.A, got.Dec)
	}
}

// A row written before the standing column existed has only a task id, and
// still finds the task's approval.
func TestQueuedLegacyTaskRowStillFindsItsApproval(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeAudit, 1, 10)
	ag := f.addAgent("taskbox")
	var sc Script
	f.admin.mustJSON("POST", "/api/scripts", Script{Name: "hello", Language: "bash", Body: "echo a", TimeoutSec: 30}, &sc)
	var task Task
	f.admin.mustJSON("POST", "/api/tasks", map[string]any{"name": "nightly", "kind": "script", "script_id": sc.ID,
		"targets": Targets{All: true}, "schedule": "", "enabled": true}, &task)
	tid := strconv.FormatInt(task.ID, 10)
	if st, body := signedCall(t, f.admin, f.ka, "POST", "/api/approvals/objects/task/"+tid+"/sign", nil); st != 200 {
		t.Fatalf("sign task = %d %s", st, body)
	}
	goOffline(t, f.s, ag)
	if _, err := f.s.db.Exec(`INSERT INTO script_runs(id, script_id, script_name, agent_id, task_id, trigger, run_by, args, status, started_at)
		VALUES(?,?,?,?,?,?,?,'[]','queued',?)`, randomHex(8), sc.ID, sc.Name, ag.ID(), task.ID, "task", "scheduler", now()); err != nil {
		t.Fatal(err)
	}

	back := f.comeBack(ag, "taskbox")
	got := back.wait(protocol.ReqScriptRun, 1)[0]
	if got.Env.A == nil || !got.Dec.Verified {
		t.Fatalf("released legacy row: A=%v decision=%+v", got.Env.A, got.Dec)
	}
}

// An org without a bundle is unchanged: offline library runs queue and are
// released when the device connects.
func TestUnsignedOrgStillQueuesAndReleases(t *testing.T) {
	f := newSignFixture(t, "", 1, 10)
	ag := f.addAgent("plainbox")
	var sc Script
	f.admin.mustJSON("POST", "/api/scripts", Script{Name: "lib", Language: "bash", Body: "echo q", TimeoutSec: 30}, &sc)
	goOffline(t, f.s, ag)

	var res struct {
		Runs map[string]string `json:"runs"`
	}
	f.admin.mustJSON("POST", "/api/scripts/run", map[string]any{"agent_ids": []string{ag.ID()}, "script_id": sc.ID}, &res)
	if res.Runs[ag.ID()] == "" || countRuns(t, f.s, "WHERE status = 'queued'") != 1 {
		t.Fatalf("outcome %v; want one queued run", res.Runs)
	}
	back := f.comeBack(ag, "plainbox")
	got := back.wait(protocol.ReqScriptRun, 1)[0]
	if got.Env.A != nil {
		t.Fatalf("an unsigned org's run carried auth: %+v", got.Env.A)
	}
	waitFor(t, "row claimed", func() bool { return countRuns(t, f.s, "WHERE status = 'queued'") == 0 })
}
