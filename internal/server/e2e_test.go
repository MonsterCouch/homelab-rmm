package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// fakeAgent speaks the agent protocol from a test so the whole server path
// (enrollment, hub routing, streaming, alerting) is exercised without an OS.
type fakeAgent struct {
	t     *testing.T
	ws    *websocket.Conn
	mu    sync.Mutex
	id    string
	key   string
	reqs  chan protocol.Envelope
	stop  chan struct{}
	shell map[string]bool
	// baselineAnswer, when set, is the pass the fake agent reports after a
	// baseline.evaluate or baseline.remediate request. A real agent ACKs the
	// request and sends the report as its own TypeBaseline frame, so that is
	// what this does - the reply is never a report (one pass, one ingest).
	baselineAnswer *protocol.BaselineReport
	// baselineRequests records what the server asked for, so a test can
	// assert that an evaluate reached the device.
	baselineRequests []protocol.Envelope
}

// setBaselineAnswer arms the report the fake agent sends after the next
// evaluate or remediate request.
func (f *fakeAgent) setBaselineAnswer(rep *protocol.BaselineReport) {
	f.mu.Lock()
	f.baselineAnswer = rep
	f.mu.Unlock()
}

func (f *fakeAgent) baselineAsks() []protocol.Envelope {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]protocol.Envelope{}, f.baselineRequests...)
}

// sendBaselineReport pushes an unsolicited pass, exactly as a scheduled or
// offline evaluation does.
func (f *fakeAgent) sendBaselineReport(rep protocol.BaselineReport) {
	f.send(protocol.Envelope{T: protocol.TypeBaseline, D: protocol.Must(rep)})
}

func (f *fakeAgent) send(env protocol.Envelope) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ws.WriteJSON(env); err != nil {
		f.t.Logf("fake agent write: %v", err)
	}
}

func dialAgent(t *testing.T, wsURL string, hdr http.Header) *fakeAgent {
	t.Helper()
	ws, resp, err := websocket.DefaultDialer.Dial(wsURL+"/ws/agent", hdr)
	if err != nil {
		if resp != nil {
			t.Fatalf("dial: %v (status %d)", err, resp.StatusCode)
		}
		t.Fatalf("dial: %v", err)
	}
	f := &fakeAgent{t: t, ws: ws, reqs: make(chan protocol.Envelope, 64), stop: make(chan struct{}), shell: map[string]bool{}}
	f.send(protocol.Envelope{T: protocol.TypeHello, D: protocol.Must(protocol.Hello{Hostname: "testbox", OS: "linux", Platform: "Test Linux 1.0", Arch: "amd64", Version: "test", ProtocolVersion: protocol.Version})})
	var env protocol.Envelope
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := ws.ReadJSON(&env); err != nil {
		t.Fatalf("welcome: %v", err)
	}
	if env.T != "welcome" {
		t.Fatalf("expected welcome, got %s %s", env.T, env.Err)
	}
	var w struct {
		AgentID string `json:"agent_id"`
		Key     string `json:"agent_key"`
	}
	json.Unmarshal(env.D, &w)
	f.id, f.key = w.AgentID, w.Key
	ws.SetReadDeadline(time.Time{})
	go f.loop()
	return f
}

// loop answers requests the way a real agent would, for the handful of
// request types the tests use.
func (f *fakeAgent) loop() {
	for {
		var env protocol.Envelope
		if err := f.ws.ReadJSON(&env); err != nil {
			close(f.stop)
			return
		}
		switch env.T {
		case protocol.ReqPing:
			f.send(protocol.Envelope{T: protocol.TypePong, ID: env.ID})
		case protocol.ReqAgentConfig:
		case protocol.ReqProcList:
			f.send(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, D: protocol.Must([]protocol.Process{{PID: 1, Name: "init"}, {PID: 42, Name: "sshd"}})})
		case protocol.ReqScriptRun:
			var sr protocol.ScriptRun
			json.Unmarshal(env.D, &sr)
			f.send(protocol.Envelope{T: protocol.TypeStream, ID: env.ID, D: protocol.Must(protocol.ScriptChunk{RunID: sr.RunID, Stream: "stdout", Data: "hello from " + sr.Language + "\n"})})
			f.send(protocol.Envelope{T: protocol.TypeStream, ID: env.ID, D: protocol.Must(protocol.ScriptChunk{RunID: sr.RunID, Stream: "stderr", Data: "warn\n"})})
			code := 0
			if strings.Contains(sr.Body, "exit 3") {
				code = 3
			}
			f.send(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, D: protocol.Must(protocol.ScriptResult{RunID: sr.RunID, ExitCode: code, Duration: 5})})
		case protocol.ReqShellOpen:
			f.mu.Lock()
			f.shell[env.ID] = true
			f.mu.Unlock()
			f.send(protocol.Envelope{T: protocol.TypeStream, ID: env.ID, D: protocol.Must(protocol.ShellChunk{Session: env.ID, Data: "$ "})})
		case protocol.ReqShellInput:
			var in protocol.ShellInput
			json.Unmarshal(env.D, &in)
			f.send(protocol.Envelope{T: protocol.TypeStream, ID: in.Session, D: protocol.Must(protocol.ShellChunk{Session: in.Session, Data: "echo:" + in.Data})})
		case protocol.ReqShellClose:
			var in protocol.ShellClose
			json.Unmarshal(env.D, &in)
			f.send(protocol.Envelope{T: protocol.TypeReply, ID: in.Session, D: protocol.Must(protocol.ShellChunk{Session: in.Session, EOF: true})})
		case protocol.ReqUpdatesScan:
			f.send(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, D: protocol.Must(protocol.UpdatesScanResult{Updates: []protocol.Update{
				{ID: "kb1", Title: "Security Update KB1", KB: "KB1", Severity: "Critical", Source: "wua"},
				{ID: "pkg-a", Title: "pkg-a 1.0 -> 1.1", Source: "apt", Version: "1.1"},
			}})})
		case protocol.ReqUpdatesInstall:
			var in protocol.UpdatesInstall
			json.Unmarshal(env.D, &in)
			res := protocol.UpdatesInstallResult{Failed: map[string]string{}}
			for _, id := range in.IDs {
				if id == "pkg-a" {
					res.Failed[id] = "download failed"
				} else {
					res.Installed = append(res.Installed, id)
				}
			}
			f.send(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, D: protocol.Must(res)})
		case protocol.ReqBaselineEvaluate, protocol.ReqBaselineRemediate:
			f.mu.Lock()
			f.baselineRequests = append(f.baselineRequests, env)
			answer := f.baselineAnswer
			f.baselineAnswer = nil
			f.mu.Unlock()
			// ACK only. The pass arrives as its own TypeBaseline frame.
			f.send(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, D: protocol.Must(map[string]any{"accepted": true})})
			if answer != nil {
				f.sendBaselineReport(*answer)
			}
		case protocol.ReqBaselinePreview:
			// The one request whose REPLY is the report, and which never
			// sends a TypeBaseline frame.
			var in protocol.BaselinePreview
			json.Unmarshal(env.D, &in)
			rep := protocol.BaselineReport{BaselineID: in.Spec.ID, Version: in.Spec.Version, TS: time.Now().Unix(), Trigger: "preview"}
			for i, c := range in.Spec.Checks {
				state, observed := "pass", "ok"
				if i == 0 {
					state, observed = "fail", "drifted"
				}
				rep.Results = append(rep.Results, protocol.BaselineResult{CheckID: c.ID, State: state, Expected: "ok", Observed: observed, DurationMs: 3})
			}
			f.send(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, D: protocol.Must(rep)})
		case protocol.ReqInventoryRefresh:
			f.send(protocol.Envelope{T: protocol.TypeInventory, D: protocol.Must(protocol.Inventory{Hostname: "testbox", OS: "linux", Network: []protocol.NetIface{{Name: "eth0", MAC: "aa:bb:cc:dd:ee:ff", IPs: []string{"10.0.0.5/24"}}}})})
			f.send(protocol.Envelope{T: protocol.TypeReply, ID: env.ID})
		default:
			f.send(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, Err: "fake agent: unsupported " + env.T})
		}
	}
}

// browser is an authenticated HTTP client.
type browser struct {
	t    *testing.T
	c    *http.Client
	base string
}

func (b *browser) do(method, path string, body any) (int, []byte) {
	b.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		bs, _ := json.Marshal(body)
		rd = bytes.NewReader(bs)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, b.base+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "fetch")
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

func (b *browser) mustJSON(method, path string, body any, out any) {
	b.t.Helper()
	st, data := b.do(method, path, body)
	if st/100 != 2 {
		b.t.Fatalf("%s %s -> %d: %s", method, path, st, data)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			b.t.Fatalf("%s %s: bad json %v: %s", method, path, err, data)
		}
	}
}

// newTestServer is a server with an admin created and a signed-in browser.
// The fixture itself lives in testutil_test.go so tests that need a different
// Config can share it.
func newTestServer(t *testing.T) (*Server, *httptest.Server, *browser) {
	t.Helper()
	return newTestServerWith(t, Config{})
}

func wsURL(ts *httptest.Server) string { return "ws" + strings.TrimPrefix(ts.URL, "http") }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestEndToEnd(t *testing.T) {
	s, ts, b := newTestServer(t)

	// --- auth guard ---
	if st, _ := b.do("POST", "/api/groups", map[string]string{"name": "x"}); st != 201 {
		t.Fatalf("admin should create groups, got %d", st)
	}
	anon := &browser{t: t, c: &http.Client{}, base: ts.URL}
	if st, _ := anon.do("GET", "/api/agents", nil); st != 401 {
		t.Fatalf("anonymous should be 401, got %d", st)
	}
	// missing CSRF header
	req, _ := http.NewRequest("POST", ts.URL+"/api/groups", strings.NewReader(`{"name":"y"}`))
	resp, _ := b.c.Do(req)
	if resp.StatusCode != 403 {
		t.Fatalf("POST without X-Requested-With should be 403, got %d", resp.StatusCode)
	}

	// --- enrollment ---
	var tok struct{ Token, Windows, Linux string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab", "uses": 1}, &tok)
	if !strings.Contains(tok.Windows, tok.Token) || !strings.Contains(tok.Linux, "curl") {
		t.Fatalf("install commands malformed: %+v", tok)
	}
	badHdr := http.Header{"X-Enroll-Token": []string{"nope"}}
	if _, resp, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/agent", badHdr); err == nil || resp == nil || resp.StatusCode != 401 {
		t.Fatalf("bad token must be refused with 401, err=%v", err)
	}
	agent := dialAgent(t, wsURL(ts), http.Header{"X-Enroll-Token": []string{tok.Token}})
	if agent.id == "" || agent.key == "" {
		t.Fatal("enrollment did not return id+key")
	}
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(agent.id) })

	// token was single use
	if _, resp, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/agent", http.Header{"X-Enroll-Token": []string{tok.Token}}); err == nil || resp == nil || resp.StatusCode != 401 {
		t.Fatalf("exhausted token must be refused with 401, err=%v", err)
	}

	var agents []Agent
	b.mustJSON("GET", "/api/agents", nil, &agents)
	if len(agents) != 1 || !agents[0].Online || agents[0].Hostname != "testbox" {
		t.Fatalf("agent list wrong: %+v", agents)
	}

	// --- inventory + metrics ingestion ---
	agent.send(protocol.Envelope{T: protocol.TypeInventory, D: protocol.Must(protocol.Inventory{Hostname: "testbox", OS: "linux", CPUModel: "TestCPU", Disks: []protocol.Disk{{Mount: "/", Total: 100, Used: 50}}})})
	waitFor(t, "inventory saved", func() bool {
		a, err := s.db.GetAgent(agent.id)
		return err == nil && a.Inventory != nil && a.Inventory.CPUModel == "TestCPU"
	})
	// alert rule: disk > 90%
	var rule AlertRule
	b.mustJSON("POST", "/api/alert-rules", AlertRule{Name: "disk full", Kind: "disk", Params: RuleParams{Threshold: 90}, Targets: Targets{All: true}, Severity: "critical", AutoResolve: true, Enabled: true}, &rule)
	agent.send(protocol.Envelope{T: protocol.TypeMetrics, D: protocol.Must(protocol.Metrics{TS: time.Now().Unix(), CPUPct: 12, MemUsed: 1, MemTotal: 2, Disks: []protocol.DiskUsage{{Mount: "/", Total: 100, Used: 95, UsedPct: 95}}})})
	waitFor(t, "disk alert opened", func() bool {
		al, _ := s.db.ListAlerts("open", agent.id, 10)
		return len(al) == 1 && al[0].Severity == "critical"
	})
	agent.send(protocol.Envelope{T: protocol.TypeMetrics, D: protocol.Must(protocol.Metrics{TS: time.Now().Unix() + 1, CPUPct: 12, MemUsed: 1, MemTotal: 2, Disks: []protocol.DiskUsage{{Mount: "/", Total: 100, Used: 10, UsedPct: 10}}})})
	waitFor(t, "disk alert auto-resolved", func() bool {
		al, _ := s.db.ListAlerts("open", agent.id, 10)
		return len(al) == 0
	})
	var rows []MetricRow
	b.mustJSON("GET", fmt.Sprintf("/api/agents/%s/metrics?from=%d&to=%d", agent.id, time.Now().Unix()-60, time.Now().Unix()+60), nil, &rows)
	if len(rows) == 0 {
		t.Fatal("no metric rows returned")
	}

	// --- request/reply ---
	var procs []protocol.Process
	b.mustJSON("GET", "/api/agents/"+agent.id+"/processes", nil, &procs)
	if len(procs) != 2 || procs[1].Name != "sshd" {
		t.Fatalf("processes wrong: %+v", procs)
	}

	// --- scripts: library, run with streaming, failure alert ---
	b.mustJSON("POST", "/api/alert-rules", AlertRule{Name: "script failed", Kind: "script_failed", Targets: Targets{All: true}, Severity: "warning", Enabled: true}, nil)
	var sc Script
	b.mustJSON("POST", "/api/scripts", Script{Name: "hello", Language: "bash", Body: "echo hi"}, &sc)
	var runResp struct{ Runs map[string]string }
	b.mustJSON("POST", "/api/scripts/run", map[string]any{"script_id": sc.ID, "agent_ids": []string{agent.id}}, &runResp)
	runID := runResp.Runs[agent.id]
	waitFor(t, "run done", func() bool {
		r, err := s.db.GetRun(runID)
		return err == nil && r.Status == "done" && strings.Contains(r.Stdout, "hello from bash") && strings.Contains(r.Stderr, "warn")
	})
	// ad hoc failing script raises a script_failed alert
	var adhoc struct {
		RunID string `json:"run_id"`
	}
	b.mustJSON("POST", "/api/agents/"+agent.id+"/run", map[string]any{"language": "bash", "body": "exit 3"}, &adhoc)
	waitFor(t, "failed run + alert", func() bool {
		r, err := s.db.GetRun(adhoc.RunID)
		if err != nil || r.Status != "failed" || r.ExitCode != 3 {
			return false
		}
		al, _ := s.db.ListAlerts("open", agent.id, 10)
		return len(al) == 1 && strings.Contains(al[0].Title, "Script failed")
	})

	// --- tasks: manual run on all targets ---
	var task Task
	b.mustJSON("POST", "/api/tasks", Task{Name: "nightly", Kind: "script", ScriptID: &sc.ID, Targets: Targets{All: true}, Schedule: "0 3 * * *", Enabled: true}, &task)
	if task.NextRun == 0 {
		t.Fatal("scheduled task has no next_run")
	}
	var ran struct{ Devices int }
	b.mustJSON("POST", fmt.Sprintf("/api/tasks/%d/run", task.ID), nil, &ran)
	if ran.Devices != 1 {
		t.Fatalf("task should run on 1 device, got %d", ran.Devices)
	}
	if st, body := b.do("POST", "/api/tasks", Task{Name: "bad", Kind: "script", ScriptID: &sc.ID, Schedule: "not cron"}); st != 400 {
		t.Fatalf("bad cron should be 400: %d %s", st, body)
	}

	// --- shell relay ---
	hdr := http.Header{}
	u, _ := http.NewRequest("GET", ts.URL, nil)
	for _, c := range b.c.Jar.Cookies(u.URL) {
		hdr.Add("Cookie", c.Name+"="+c.Value)
	}
	hdr.Set("Origin", ts.URL)
	shell, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/shell/"+agent.id, hdr)
	if err != nil {
		t.Fatalf("shell ws: %v", err)
	}
	shell.WriteJSON(map[string]any{"t": "open", "shell": "bash", "cols": 80, "rows": 24})
	readMsg := func() map[string]any {
		var m map[string]any
		shell.SetReadDeadline(time.Now().Add(3 * time.Second))
		if err := shell.ReadJSON(&m); err != nil {
			t.Fatalf("shell read: %v", err)
		}
		return m
	}
	if m := readMsg(); m["t"] != "opened" {
		t.Fatalf("expected opened, got %v", m)
	}
	if m := readMsg(); m["t"] != "out" || m["data"] != "$ " {
		t.Fatalf("expected prompt, got %v", m)
	}
	shell.WriteJSON(map[string]any{"t": "in", "data": "ls\r"})
	if m := readMsg(); m["data"] != "echo:ls\r" {
		t.Fatalf("expected echo, got %v", m)
	}
	shell.Close()
	// cross-origin refused
	hdr.Set("Origin", "https://evil.example")
	if _, resp, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/shell/"+agent.id, hdr); err == nil || resp == nil || resp.StatusCode != 403 {
		t.Fatalf("cross-origin shell should be refused: err=%v", err)
	}

	// --- patches ---
	var pr struct{ Patches []Patch }
	b.mustJSON("POST", "/api/agents/"+agent.id+"/patches/scan", nil, &pr)
	if len(pr.Patches) != 2 {
		t.Fatalf("expected 2 patches, got %+v", pr.Patches)
	}
	b.mustJSON("POST", "/api/alert-rules", AlertRule{Name: "patch failed", Kind: "patch_failed", Targets: Targets{All: true}, Severity: "warning", Enabled: true}, nil)
	b.mustJSON("POST", "/api/agents/"+agent.id+"/patches/install", map[string]any{"all": true}, nil)
	waitFor(t, "patch outcomes", func() bool {
		ps, _ := s.db.ListPatches(agent.id, "", 10)
		var inst, failed int
		for _, p := range ps {
			switch p.Status {
			case "installed":
				inst++
			case "failed":
				failed++
			}
		}
		return inst == 1 && failed == 1
	})
	waitFor(t, "patch failed alert", func() bool {
		al, _ := s.db.ListAlerts("open", agent.id, 10)
		for _, a := range al {
			if strings.HasPrefix(a.Title, "Patch failed") {
				return true
			}
		}
		return false
	})

	// --- wake on lan needs inventory MAC; the only agent is the target, so no sender ---
	b.mustJSON("POST", "/api/agents/"+agent.id+"/refresh", nil, nil)
	waitFor(t, "mac known", func() bool {
		a, _ := s.db.GetAgent(agent.id)
		return a != nil && a.Inventory != nil && len(a.Inventory.Network) == 1
	})
	if st, _ := b.do("POST", "/api/agents/"+agent.id+"/wol", nil); st != 409 {
		t.Fatalf("wol without a sender should be 409, got %d", st)
	}

	// --- audit trail exists ---
	var audit []map[string]any
	b.mustJSON("GET", "/api/audit", nil, &audit)
	if len(audit) < 5 {
		t.Fatalf("audit too short: %d", len(audit))
	}

	// --- reconnect with key; offline detection; queued run released ---
	agent.ws.Close()
	waitFor(t, "agent offline", func() bool { return !s.hub.IsOnline(agent.id) })
	b.mustJSON("POST", "/api/scripts/run", map[string]any{"script_id": sc.ID, "agent_ids": []string{agent.id}}, &runResp)
	queued := runResp.Runs[agent.id]
	if r, _ := s.db.GetRun(queued); r == nil || r.Status != "queued" {
		t.Fatalf("run on offline agent should queue: %+v", r)
	}
	agent2 := dialAgent(t, wsURL(ts), http.Header{"Authorization": []string{"Bearer " + agent.key}})
	if agent2.id != agent.id {
		t.Fatalf("key reconnect changed identity: %s vs %s", agent2.id, agent.id)
	}
	waitFor(t, "queued run released and done", func() bool {
		r, _ := s.db.GetRun(queued)
		return r != nil && r.Status == "done"
	})

	// viewer role is read-only
	b.mustJSON("POST", "/api/users", map[string]string{"username": "ro", "password": "password123", "role": "viewer"}, nil)
	ro := newBrowser(t, ts)
	ro.mustJSON("POST", "/api/auth/login", map[string]string{"username": "ro", "password": "password123"}, nil)
	if st, _ := ro.do("POST", "/api/groups", map[string]string{"name": "z"}); st != 403 {
		t.Fatalf("viewer write should be 403, got %d", st)
	}
	if st, _ := ro.do("GET", "/api/settings", nil); st != 403 {
		t.Fatalf("viewer settings should be 403, got %d", st)
	}
	if st, _ := ro.do("GET", "/api/agents", nil); st != 200 {
		t.Fatalf("viewer read should be 200, got %d", st)
	}
}

func TestTargetsAndRateLimit(t *testing.T) {
	gid := int64(3)
	a := &Agent{ID: "a1", OS: "windows", GroupID: &gid, Tags: []string{"Lab", "nas"}}
	cases := []struct {
		t    Targets
		want bool
	}{
		{Targets{All: true}, true},
		{Targets{All: true, OS: "linux"}, false},
		{Targets{Agents: []string{"a1"}}, true},
		{Targets{Groups: []int64{3}}, true},
		{Targets{Groups: []int64{4}}, false},
		{Targets{Tags: []string{"lab"}}, true},
		{Targets{}, false},
	}
	for i, c := range cases {
		if got := c.t.Matches(a); got != c.want {
			t.Errorf("case %d: got %v want %v", i, got, c.want)
		}
	}
	rl := newRateLimiter(2, time.Minute)
	if !rl.allow("x") || !rl.allow("x") || rl.allow("x") {
		t.Fatal("rate limiter miscounted")
	}
	rl.reset("x")
	if !rl.allow("x") {
		t.Fatal("reset failed")
	}
}
