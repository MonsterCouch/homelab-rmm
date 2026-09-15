package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// ---- helpers ----

// syncBuffer is a log sink a test can read while the server writes to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLogs redirects slog for the duration of one test.
func captureLogs(t *testing.T) *syncBuffer {
	t.Helper()
	old := slog.Default()
	buf := &syncBuffer{}
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return buf
}

// enrolToken mints a token straight in the database, for tests that have no
// signed-in browser.
func enrolToken(t *testing.T, s *Server) string {
	t.Helper()
	tok := randomToken(24)
	if _, err := s.db.Exec(`INSERT INTO enroll_tokens(token, name, uses_left, expires_at, created_by, created_at) VALUES(?,?,?,?,?,?)`,
		tok, "test", -1, time.Now().Add(time.Hour).Unix(), "test", now()); err != nil {
		t.Fatal(err)
	}
	return tok
}

// browserHeader is the cookie+origin header set a signed-in browser sends on
// a WebSocket upgrade.
func browserHeader(t *testing.T, ts *httptest.Server, b *browser) http.Header {
	t.Helper()
	hdr := http.Header{}
	u, _ := http.NewRequest("GET", ts.URL, nil)
	for _, c := range b.c.Jar.Cookies(u.URL) {
		hdr.Add("Cookie", c.Name+"="+c.Value)
	}
	hdr.Set("Origin", ts.URL)
	return hdr
}

// ---- SRV-01 / SRV-06: replacing a live socket ----

// TestSocketReplacementWithLiveStream pins SRV-01: a second socket for an
// agent that has a script streaming used to close the old connection while
// holding the hub's write lock, and the run sink then took the same lock for
// reading. sync.RWMutex is not reentrant, so the hub wedged for good.
//
// It also pins SRV-06: the replaced socket's teardown must not record the
// device as offline, because the device is still connected.
func TestSocketReplacementWithLiveStream(t *testing.T) {
	s, ts, b := newTestServer(t)
	tok := enrolToken(t, s)

	first := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tok}}, "flapper", "linux")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(first.id) })

	// a run the agent accepts and never answers, so a stream sink stays registered
	var sc Script
	b.mustJSON("POST", "/api/scripts", Script{Name: "slow", Language: "bash", Body: "sleep 600"}, &sc)
	var started struct {
		RunID string `json:"run_id"`
	}
	b.mustJSON("POST", "/api/agents/"+first.id+"/run", map[string]any{"script_id": sc.ID}, &started)
	waitFor(t, "run live", func() bool {
		_, _, ok := s.runs.Live(started.RunID)
		return ok
	})

	// the device reconnects with its key while the old socket is still open
	second := dialAgentAs(t, ts, http.Header{"Authorization": []string{"Bearer " + first.key}}, "flapper", "linux")
	if second.id != first.id {
		t.Fatalf("reconnect changed identity: %s vs %s", second.id, first.id)
	}

	answered := make(chan bool, 1)
	go func() { answered <- s.hub.IsOnline(first.id) }()
	select {
	case online := <-answered:
		if !online {
			t.Fatal("the device should still be online on its new socket")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hub.IsOnline never returned: the hub mutex is held forever")
	}

	// the abandoned run is failed by the replaced socket's close
	waitFor(t, "run released", func() bool {
		r, err := s.db.GetRun(started.RunID)
		return err == nil && r.Status == "failed"
	})

	// ...and the replaced socket's teardown leaves the device online
	time.Sleep(300 * time.Millisecond)
	var col int
	if err := s.db.QueryRow(`SELECT online FROM agents WHERE id = ?`, first.id).Scan(&col); err != nil {
		t.Fatal(err)
	}
	if col != 1 {
		t.Fatal("a replaced socket marked a still-connected device offline")
	}
	if !s.hub.IsOnline(first.id) {
		t.Fatal("hub lost the replacement socket")
	}
}

// ---- SRV-03: tailing a live run ----

// TestTailLiveRunIsRaceFree pins SRV-03. Under -race the unsynchronised
// strings.Builder in liveRun reports a data race between the agent read loop
// and GET /api/runs/{id}.
func TestTailLiveRunIsRaceFree(t *testing.T) {
	s, ts, b := newTestServer(t)
	tok := enrolToken(t, s)
	ag := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tok}}, "tailbox", "linux")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(ag.id) })

	// stream chunks for whatever script.run arrives, then finish
	chunks := make(chan string, 1)
	go func() {
		for {
			var env protocol.Envelope
			if err := ag.ws.ReadJSON(&env); err != nil {
				return
			}
			switch env.T {
			case protocol.ReqPing:
				ag.ws.WriteJSON(protocol.Envelope{T: protocol.TypePong, ID: env.ID})
			case protocol.ReqScriptRun:
				var sr protocol.ScriptRun
				json.Unmarshal(env.D, &sr)
				for i := 0; i < 300; i++ {
					ag.ws.WriteJSON(protocol.Envelope{T: protocol.TypeStream, ID: env.ID,
						D: protocol.Must(protocol.ScriptChunk{RunID: sr.RunID, Stream: "stdout", Data: strings.Repeat("x", 64) + "\n"})})
				}
				ag.ws.WriteJSON(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, D: protocol.Must(protocol.ScriptResult{RunID: sr.RunID})})
				chunks <- sr.RunID
			}
		}
	}()

	var sc Script
	b.mustJSON("POST", "/api/scripts", Script{Name: "chatty", Language: "bash", Body: "yes"}, &sc)
	var started struct {
		RunID string `json:"run_id"`
	}
	b.mustJSON("POST", "/api/agents/"+ag.id+"/run", map[string]any{"script_id": sc.ID}, &started)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			poll := newBrowser(t, ts)
			poll.mustJSON("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "password123"}, nil)
			for {
				select {
				case <-stop:
					return
				default:
				}
				poll.do("GET", "/api/runs/"+started.RunID, nil)
			}
		}()
	}
	select {
	case <-chunks:
	case <-time.After(10 * time.Second):
		t.Fatal("agent never got the script")
	}
	waitFor(t, "run finished", func() bool {
		r, err := s.db.GetRun(started.RunID)
		return err == nil && r.Status == "done"
	})
	close(stop)
	wg.Wait()
}

// ---- SRV-04: wake on LAN sender selection ----

// TestWakeOnLanPicksSender pins SRV-04: ListAgents never loads inventory, so
// the "same subnet" loop skipped every candidate and /wol always answered 409.
func TestWakeOnLanPicksSender(t *testing.T) {
	s, ts, b := newTestServer(t)
	tok := enrolToken(t, s)

	target := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tok}}, "sleeper", "linux")
	sender := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tok}}, "awake", "linux")
	waitFor(t, "both online", func() bool { return s.hub.IsOnline(target.id) && s.hub.IsOnline(sender.id) })

	// the sender answers the magic-packet request
	wolSent := make(chan string, 4)
	go func() {
		for {
			var env protocol.Envelope
			if err := sender.ws.ReadJSON(&env); err != nil {
				return
			}
			switch env.T {
			case protocol.ReqPing:
				sender.ws.WriteJSON(protocol.Envelope{T: protocol.TypePong, ID: env.ID})
			case protocol.ReqWakeOnLan:
				var w protocol.WakeOnLan
				json.Unmarshal(env.D, &w)
				sender.ws.WriteJSON(protocol.Envelope{T: protocol.TypeReply, ID: env.ID})
				wolSent <- w.MAC
			}
		}
	}()

	inv := func(mac, ip string) string {
		return jsonText(protocol.Inventory{Network: []protocol.NetIface{{Name: "eth0", MAC: mac, IPs: []string{ip}}}})
	}
	s.db.Exec(`UPDATE agents SET inventory = ? WHERE id = ?`, inv("aa:bb:cc:dd:ee:01", "10.0.0.5/24"), target.id)
	s.db.Exec(`UPDATE agents SET inventory = ? WHERE id = ?`, inv("aa:bb:cc:dd:ee:02", "10.0.0.6/24"), sender.id)

	var res struct{ Via string }
	b.mustJSON("POST", "/api/agents/"+target.id+"/wol", nil, &res)
	if res.Via != sender.id {
		t.Fatalf("expected the other online device on the same /24 to be chosen, got via=%q", res.Via)
	}
	select {
	case mac := <-wolSent:
		if mac != "aa:bb:cc:dd:ee:01" {
			t.Fatalf("magic packet carried %q", mac)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the sender never received the wol request")
	}
}

// ---- SRV-05: the "enrolled" automation ----

// TestEnrolledAutomationFiresAtEnrolment pins SRV-05: the trigger was fired
// from a defer, so it ran when the socket eventually dropped - after the
// agent_offline automation, hours or days later.
func TestEnrolledAutomationFiresAtEnrolment(t *testing.T) {
	s, ts, b := newTestServer(t)
	var sc Script
	b.mustJSON("POST", "/api/scripts", Script{Name: "onboard", Language: "bash", Body: "echo welcome"}, &sc)
	b.mustJSON("POST", "/api/automations", map[string]any{
		"name": "onboarding", "trigger": "enrolled", "action": "run_script", "enabled": true,
		"action_params": json.RawMessage(fmt.Sprintf(`{"script_id":%d}`, sc.ID)),
	}, nil)

	tok := enrolToken(t, s)
	ag := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tok}}, "newbox", "linux")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(ag.id) })

	waitFor(t, "onboarding run started while the device is connected", func() bool {
		runs, _ := s.db.ListRuns(ag.id, 10)
		for _, r := range runs {
			// queued would mean it fired after the socket dropped
			if r.Trigger == "automation" && r.Status != "queued" {
				return s.hub.IsOnline(ag.id)
			}
		}
		return false
	})
}

// ---- SRV-02: the desktop helper handler ----

// TestDesktopHandlerReturns pins SRV-02: handleDesktopAgentWS waited on
// r.Context(), which after a hijack is only cancelled once the handler
// returns - so every desktop session leaked a goroutine and a connection.
func TestDesktopHandlerReturns(t *testing.T) {
	s, ts, b := newTestServer(t)
	tok := enrolToken(t, s)

	helperConnected := make(chan *websocket.Conn, 1)
	ag := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tok}}, "deskbox", "windows")
	go func() {
		for {
			var env protocol.Envelope
			if err := ag.ws.ReadJSON(&env); err != nil {
				return
			}
			switch env.T {
			case protocol.ReqPing:
				ag.ws.WriteJSON(protocol.Envelope{T: protocol.TypePong, ID: env.ID})
			case protocol.ReqDesktopStart:
				var ds protocol.DesktopStart
				json.Unmarshal(env.D, &ds)
				h, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/desktop-agent?token="+ds.Token, nil)
				if err != nil {
					return
				}
				helperConnected <- h
				ag.ws.WriteJSON(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, D: protocol.Must(protocol.DesktopStartResult{Started: true})})
			}
		}
	}()
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(ag.id) })

	viewer, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/desktop/"+ag.id, browserHeader(t, ts, b))
	if err != nil {
		t.Fatalf("viewer dial: %v", err)
	}
	var helper *websocket.Conn
	select {
	case helper = <-helperConnected:
	case <-time.After(5 * time.Second):
		t.Fatal("helper never connected")
	}
	viewer.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := viewer.ReadMessage(); err != nil {
		t.Fatalf("viewer first read: %v", err)
	}
	helper.Close()
	viewer.Close()

	deadline := time.Now().Add(5 * time.Second)
	for {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		if !strings.Contains(string(buf[:n]), "handleDesktopAgentWS") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("handleDesktopAgentWS is still parked after the session ended")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestDesktopHelperAfterViewerGaveUpIsClosed pins the second half of SRV-02:
// a helper that arrives once the viewer has gone must not be parked in the
// buffered channel forever, still capturing the screen.
func TestDesktopHelperAfterViewerGaveUpIsClosed(t *testing.T) {
	ds := &desktopSession{helper: make(chan *websocket.Conn, 1)}
	ds.finish()
	if ds.offerHelper(nil) {
		t.Fatal("a session whose viewer has gone must refuse the helper")
	}
}

// ---- SRV-17: queued runs released twice ----

func TestReleaseQueuedClaimsTheRow(t *testing.T) {
	s, ts, b := newTestServer(t)
	tok := enrolToken(t, s)
	ag := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tok}}, "queuebox", "linux")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(ag.id) })

	var sc Script
	b.mustJSON("POST", "/api/scripts", Script{Name: "queued", Language: "bash", Body: "echo q"}, &sc)
	id := randomHex(8)
	if _, err := s.db.Exec(`INSERT INTO script_runs(id, script_id, script_name, agent_id, trigger, run_by, args, status, started_at)
		VALUES(?,?,?,?,?,?,'[]','queued',?)`, id, sc.ID, sc.Name, ag.id, "manual", "test", now()); err != nil {
		t.Fatal(err)
	}

	// two connects for the same device racing to release the same row
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runs.releaseQueued(ag.id)
		}()
	}
	wg.Wait()

	// exactly one script.run reached the device
	deliveries := 0
	ag.ws.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	for {
		var env protocol.Envelope
		if err := ag.ws.ReadJSON(&env); err != nil {
			break
		}
		if env.T == protocol.ReqScriptRun {
			deliveries++
		}
	}
	if deliveries != 1 {
		t.Fatalf("a queued run was launched %d times", deliveries)
	}
}

// ---- SRV-09: overlapping patch work ----

func TestPatchInstallRefusesWhenBusy(t *testing.T) {
	s, ts, b := newTestServer(t)
	tok := enrolToken(t, s)
	ag := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tok}}, "patchbox", "linux")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(ag.id) })
	s.db.Exec(`INSERT INTO patches(agent_id, patch_id, title, status, first_seen, last_seen) VALUES(?,?,?,'approved',?,?)`,
		ag.id, "kb1", "Security Update", now(), now())

	if st, body := b.do("POST", "/api/agents/"+ag.id+"/patches/install", map[string]any{"ids": []string{"kb1"}}); st != 202 {
		t.Fatalf("first install: %d %s", st, body)
	}
	waitFor(t, "install claimed", func() bool {
		s.patchMu.Lock()
		defer s.patchMu.Unlock()
		return s.patchJobs[ag.id]
	})
	if st, _ := b.do("POST", "/api/agents/"+ag.id+"/patches/install", map[string]any{"ids": []string{"kb1"}}); st != 409 {
		t.Fatalf("a second concurrent install should be 409, got %d", st)
	}
	if st, _ := b.do("POST", "/api/agents/"+ag.id+"/patches/scan", nil); st != 409 {
		t.Fatalf("a scan overlapping an install should be 409, got %d", st)
	}
}

// ---- OP-08: the agent's scan error ----

func TestPatchScanErrorIsKept(t *testing.T) {
	s, ts, b := newTestServer(t)
	tok := enrolToken(t, s)
	ag := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tok}}, "aptbox", "linux")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(ag.id) })
	// a patch the scan will not list again: a failed refresh must not decide
	// it was installed elsewhere
	s.db.Exec(`INSERT INTO patches(agent_id, patch_id, title, status, first_seen, last_seen) VALUES(?,?,?,'available',?,?)`,
		ag.id, "old-pkg", "old package", now(), now())

	go func() {
		for {
			var env protocol.Envelope
			if err := ag.ws.ReadJSON(&env); err != nil {
				return
			}
			switch env.T {
			case protocol.ReqPing:
				ag.ws.WriteJSON(protocol.Envelope{T: protocol.TypePong, ID: env.ID})
			case protocol.ReqUpdatesScan:
				ag.ws.WriteJSON(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, D: protocol.Must(protocol.UpdatesScanResult{
					Error:   "refreshing the package index failed: could not resolve deb.example",
					Updates: []protocol.Update{{ID: "cached-1", Title: "cached package", Source: "apt"}},
				})})
			}
		}
	}()

	var out struct {
		ScanError string `json:"scan_error"`
		LastScan  int64  `json:"last_scan"`
	}
	b.mustJSON("POST", "/api/agents/"+ag.id+"/patches/scan", nil, &out)
	if !strings.Contains(out.ScanError, "package index") {
		t.Fatalf("the scan error was dropped: %+v", out)
	}
	ps, _ := s.db.ListPatches(ag.id, "", 10)
	for _, p := range ps {
		if p.PatchID == "old-pkg" && p.Status == "installed" {
			t.Fatal("a scan whose index refresh failed must not decide a patch was installed elsewhere")
		}
	}
}

// ---- OP-09: power auditing ----

func TestPowerIsAuditedAndMapsAgentErrors(t *testing.T) {
	s, ts, b := newTestServer(t)
	tok := enrolToken(t, s)
	ag := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tok}}, "powerbox", "linux")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(ag.id) })
	go func() {
		for {
			var env protocol.Envelope
			if err := ag.ws.ReadJSON(&env); err != nil {
				return
			}
			switch env.T {
			case protocol.ReqPing:
				ag.ws.WriteJSON(protocol.Envelope{T: protocol.TypePong, ID: env.ID})
			case protocol.ReqPower:
				ag.ws.WriteJSON(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, Err: "systemctl reboot: System has not been booted with systemd"})
			}
		}
	}()

	// a bad action is a client error and never reaches the device
	if st, _ := b.do("POST", "/api/agents/"+ag.id+"/power", map[string]any{"action": "restart"}); st != 400 {
		t.Fatalf("unknown action should be 400, got %d", st)
	}
	// a device that refuses is a gateway error, not a client error
	if st, _ := b.do("POST", "/api/agents/"+ag.id+"/power", map[string]any{"action": "reboot"}); st != 502 {
		t.Fatalf("agent-side failure should be 502, got %d", st)
	}
	var audit []struct{ Action, Target string }
	b.mustJSON("GET", "/api/audit?limit=50", nil, &audit)
	var requested, failed bool
	for _, a := range audit {
		if a.Action == "power.requested" && a.Target == ag.id {
			requested = true
		}
		if a.Action == "power.failed" && a.Target == ag.id {
			failed = true
		}
	}
	if !requested || !failed {
		t.Fatalf("a failed reboot must leave a trace: requested=%v failed=%v (%+v)", requested, failed, audit)
	}
}

// ---- OP-02: public URL precedence ----

func TestPublicURLSettingWinsOverTheFlag(t *testing.T) {
	dir := t.TempDir()
	s, _, b := newTestServerWith(t, Config{DataDir: dir, PublicURL: "https://flag.example:8443"})
	if got := s.PublicURL(); got != "https://flag.example:8443" {
		t.Fatalf("the flag should seed public_url on first run, got %q", got)
	}
	var saved Settings
	b.mustJSON("PUT", "/api/settings", map[string]any{"public_url": "https://console.example:9443"}, &saved)
	if got := s.PublicURL(); got != "https://console.example:9443" {
		t.Fatalf("the Settings value must win over the flag, got %q", got)
	}
	var sys map[string]any
	b.mustJSON("GET", "/api/system", nil, &sys)
	if sys["public_url"] != "https://console.example:9443" {
		t.Fatalf("/api/system disagrees with the Settings page: %v", sys["public_url"])
	}
	if !strings.Contains(s.installCommandLinux("tok"), "console.example:9443") {
		t.Fatalf("install commands still embed the flag: %s", s.installCommandLinux("tok"))
	}
}

// ---- SRV-12: dashboard liveness ----

func TestDashboardCountsFromTheHub(t *testing.T) {
	s, ts, b := newTestServer(t)
	tok := enrolToken(t, s)
	ag := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tok}}, "dashbox", "linux")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(ag.id) })
	// the stale column is what a restart (or any CLI command) leaves behind
	s.db.markAllOffline()

	var dash struct {
		Online  int `json:"agents_online"`
		Offline int `json:"agents_offline"`
	}
	b.mustJSON("GET", "/api/dashboard", nil, &dash)
	if dash.Online != 1 || dash.Offline != 0 {
		t.Fatalf("dashboard read the stale online column: %+v", dash)
	}
}

// ---- SRV-18: metrics range ----

func TestMetricsRangeClampsPointsAndTakesTheLastDisks(t *testing.T) {
	s, _, _ := newTestServer(t)
	s.db.Exec(`INSERT INTO agents(id, key_hash, hostname, os, enrolled_at) VALUES('m1','h','mbox','linux',?)`, now())
	base := now() - 100
	for i := 0; i < 20; i++ {
		m := &protocol.Metrics{TS: base + int64(i), CPUPct: float64(i), Disks: []protocol.DiskUsage{{Mount: "/", UsedPct: float64(i)}}}
		if err := s.db.saveMetrics("m1", m); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.db.MetricsRange("m1", base, base+19, 1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) > maxMetricPoints {
		t.Fatalf("points were not clamped: %d rows", len(rows))
	}
	// Wide buckets: each one's disks must come from its LAST sample. The old
	// MAX(disks) was a lexicographic maximum over JSON text, which for
	// used_pct 0..19 picks the "9" row, never the newest.
	wide, err := s.db.MetricsRange("m1", base, base+19, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(wide) == 0 {
		t.Fatal("no buckets returned")
	}
	last := wide[len(wide)-1]
	if len(last.Disks) != 1 || last.Disks[0].UsedPct != 19 {
		t.Fatalf("disks came from an arbitrary row (%+v), want the bucket's last sample (used_pct 19)", last.Disks)
	}
}

// ---- script device context ----

func TestScriptRunCarriesDeviceContext(t *testing.T) {
	s, ts, b := newTestServer(t)
	tok := enrolToken(t, s)
	ag := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tok}}, "envbox", "linux")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(ag.id) })
	b.mustJSON("PATCH", "/api/agents/"+ag.id, map[string]any{
		"tags":          []string{"lab", "nas"},
		"custom_fields": map[string]string{"asset tag": "A-17"},
	}, nil)

	got := make(chan map[string]string, 1)
	go func() {
		for {
			var env protocol.Envelope
			if err := ag.ws.ReadJSON(&env); err != nil {
				return
			}
			switch env.T {
			case protocol.ReqPing:
				ag.ws.WriteJSON(protocol.Envelope{T: protocol.TypePong, ID: env.ID})
			case protocol.ReqScriptRun:
				var sr protocol.ScriptRun
				json.Unmarshal(env.D, &sr)
				got <- sr.Env
				ag.ws.WriteJSON(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, D: protocol.Must(protocol.ScriptResult{RunID: sr.RunID})})
			}
		}
	}()

	var sc Script
	b.mustJSON("POST", "/api/scripts", Script{Name: "ctx", Language: "bash", Body: "env"}, &sc)
	var started struct {
		RunID string `json:"run_id"`
	}
	b.mustJSON("POST", "/api/agents/"+ag.id+"/run", map[string]any{"script_id": sc.ID, "env": map[string]string{"RMM_TRIGGER": "mine"}}, &started)

	select {
	case env := <-got:
		if env["RMM_DEVICE_ID"] != ag.id || env["RMM_HOSTNAME"] != "envbox" || env["RMM_OS"] != "linux" {
			t.Fatalf("device context missing: %+v", env)
		}
		if env["RMM_TAGS"] != "lab,nas" {
			t.Fatalf("tags wrong: %q", env["RMM_TAGS"])
		}
		if env["RMM_CF_ASSET_TAG"] != "A-17" {
			t.Fatalf("custom fields missing: %+v", env)
		}
		if env["RMM_TRIGGER"] != "mine" {
			t.Fatalf("explicit env must win, got %q", env["RMM_TRIGGER"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the script never reached the device")
	}
}

func TestCustomFieldEnvName(t *testing.T) {
	cases := map[string]string{
		"asset tag": "RMM_CF_ASSET_TAG",
		"Site":      "RMM_CF_SITE",
		"a-b.c":     "RMM_CF_A_B_C",
		"---":       "",
		"":          "",
	}
	for in, want := range cases {
		if got := customFieldEnv(in); got != want {
			t.Errorf("customFieldEnv(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- settings audit ----

func TestSettingsAuditSaysWhatChanged(t *testing.T) {
	_, _, b := newTestServer(t)
	b.mustJSON("PUT", "/api/settings", map[string]any{
		"public_url": "https://rmm.example:8443",
		"retention":  map[string]any{"metrics_days": 7, "runs_days": 90, "audit_days": 365, "events_days": 30},
	}, nil)
	// saving the same values again must not write a second, identical row
	b.mustJSON("PUT", "/api/settings", map[string]any{
		"public_url": "https://rmm.example:8443",
		"retention":  map[string]any{"metrics_days": 7, "runs_days": 90, "audit_days": 365, "events_days": 30},
	}, nil)

	var audit []struct{ Action, Target, Details string }
	b.mustJSON("GET", "/api/audit?limit=50", nil, &audit)
	n := 0
	var details string
	for _, a := range audit {
		if a.Action == "settings.update" {
			n++
			details = a.Details
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly one settings.update row, got %d", n)
	}
	if !strings.Contains(details, "public_url") || !strings.Contains(details, "retention.metrics_days 30->7") {
		t.Fatalf("settings audit does not say what changed: %q", details)
	}
}

// ---- OP-07 regression pin: viewers and enrolment tokens ----

func TestViewerCannotReadEnrolTokens(t *testing.T) {
	_, ts, b := newTestServer(t)
	b.mustJSON("POST", "/api/users", map[string]string{"username": "vic", "password": "password123", "role": "viewer"}, nil)
	ro := newBrowser(t, ts)
	ro.mustJSON("POST", "/api/auth/login", map[string]string{"username": "vic", "password": "password123"}, nil)
	if st, body := ro.do("GET", "/api/enroll", nil); st != 403 {
		t.Fatalf("a viewer must not read live enrolment tokens: %d %s", st, body)
	}
}

// ---- SRV-10 / SRV-11: alerts that can never resolve, and automation loops ----

func TestScriptFailedAlertsDedupePerDevice(t *testing.T) {
	s, ts, b := newTestServer(t)
	tok := enrolToken(t, s)
	b.mustJSON("POST", "/api/alert-rules", AlertRule{Name: "script failed", Kind: "script_failed", Targets: Targets{All: true}, Severity: "warning", Enabled: true}, nil)
	ag := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tok}}, "failbox", "linux")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(ag.id) })

	for i := 0; i < 3; i++ {
		runID := randomHex(8)
		s.db.Exec(`INSERT INTO script_runs(id, script_name, agent_id, trigger, run_by, args, status, started_at) VALUES(?,?,?,'manual','t','[]','failed',?)`,
			runID, "nightly", ag.id, now())
		s.alerts.scriptFailed(ag.id, runID, "failed")
	}
	al, _ := s.db.ListAlerts("open", ag.id, 20)
	if len(al) != 1 {
		t.Fatalf("three failures of the same job should share one open alert, got %d", len(al))
	}
}

func TestAutomationTriggeredRunDoesNotOpenAnAlert(t *testing.T) {
	s, ts, b := newTestServer(t)
	tok := enrolToken(t, s)
	b.mustJSON("POST", "/api/alert-rules", AlertRule{Name: "script failed", Kind: "script_failed", Targets: Targets{All: true}, Severity: "warning", Enabled: true}, nil)
	ag := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tok}}, "loopbox", "linux")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(ag.id) })

	runID := randomHex(8)
	s.db.Exec(`INSERT INTO script_runs(id, script_name, agent_id, trigger, run_by, args, status, started_at) VALUES(?,?,?,'automation','automation:fixit','[]','failed',?)`,
		runID, "fixit", ag.id, now())
	s.alerts.scriptFailed(ag.id, runID, "failed")
	al, _ := s.db.ListAlerts("open", ag.id, 20)
	if len(al) != 0 {
		t.Fatalf("an automation's own failed run must not re-open the alert that started it: %+v", al)
	}
}

func TestPurgeResolvesStaleAlerts(t *testing.T) {
	s, _, _ := newTestServer(t)
	s.db.Exec(`INSERT INTO agents(id, key_hash, hostname, os, enrolled_at) VALUES('p1','h','pbox','linux',?)`, now())
	old := now() - int64(staleAlertDays+1)*86400
	s.db.Exec(`INSERT INTO alerts(rule_kind, agent_id, severity, title, dedupe_key, status, opened_at) VALUES('script_failed','p1','warning','old','k1','open',?)`, old)
	s.db.Exec(`INSERT INTO alerts(rule_kind, agent_id, severity, title, dedupe_key, status, opened_at) VALUES('cpu','p1','warning','recent','k2','open',?)`, now())
	s.sched.purge()

	al, _ := s.db.ListAlerts("open", "p1", 20)
	if len(al) != 1 || al[0].Title != "recent" {
		t.Fatalf("purge should resolve only the stale non-self-resolving alert, got %+v", al)
	}
}

// ---- SRV-13: SMTP sockets ----

// TestSendMailClosesTheSocketWhenSTARTTLSIsMissing pins SRV-13: the early
// return skipped the deferred Close, leaking one socket per alert.
func TestSendMailClosesTheSocketWhenSTARTTLSIsMissing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	closed := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		fmt.Fprint(c, "220 fake ESMTP\r\n")
		br := bufio.NewReader(c)
		br.ReadString('\n') // EHLO
		fmt.Fprint(c, "250 fake\r\n")
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := br.ReadString('\n'); err != nil {
			closed <- struct{}{} // the client hung up, which is what we want
			return
		}
		// the client said something instead of closing: leave the channel empty
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	ms := MailSettings{Host: host, Port: atoiOrZero(port), From: "a@b", To: []string{"c@d"}, TLSMode: "starttls", Enabled: true}
	if err := sendMail(ms, "s", "b"); err == nil {
		t.Fatal("a server with no STARTTLS must be an error")
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the SMTP socket was leaked on the STARTTLS failure path")
	}
}

func atoiOrZero(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// ---- OP-04 / OP-14 / SRV-16: bind, log and shut down ----

// TestRunLogsListeningOnlyAfterBinding pins OP-04.
func TestRunLogsListeningOnlyAfterBinding(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	logs := captureLogs(t)
	s, err := New(Config{DataDir: t.TempDir(), Listen: busy.Addr().String(), Insecure: true, SkipSeed: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Run(ctx); err == nil {
		t.Fatal("Run should fail when the port is taken")
	}
	if strings.Contains(logs.String(), "msg=listening") {
		t.Fatalf("a failed bind logged the startup success line:\n%s", logs.String())
	}
}

// TestGracefulShutdown pins OP-14 and SRV-16: the shutdown is announced, and
// agents are told why their socket is going away instead of seeing a reset.
func TestGracefulShutdown(t *testing.T) {
	logs := captureLogs(t)
	s, err := New(Config{DataDir: t.TempDir(), Listen: "127.0.0.1:18742", Insecure: true, SkipSeed: true})
	if err != nil {
		t.Fatal(err)
	}
	tok := enrolToken(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	waitFor(t, "server listening", func() bool {
		c, err := net.DialTimeout("tcp", "127.0.0.1:18742", 200*time.Millisecond)
		if err != nil {
			return false
		}
		c.Close()
		return true
	})

	ws, _, err := websocket.DefaultDialer.Dial("ws://127.0.0.1:18742/ws/agent", http.Header{"X-Enroll-Token": []string{tok}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ws.WriteJSON(protocol.Envelope{T: protocol.TypeHello, D: protocol.Must(protocol.Hello{Hostname: "byebox", OS: "linux"})})
	var welcome protocol.Envelope
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := ws.ReadJSON(&welcome); err != nil || welcome.T != "welcome" {
		t.Fatalf("welcome: %v %s", err, welcome.T)
	}

	cancel()
	ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _, rerr := ws.ReadMessage()
	if !websocket.IsCloseError(rerr, websocket.CloseServiceRestart) {
		t.Fatalf("the agent should be told the server is restarting, got %v", rerr)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Run never returned")
	}
	out := logs.String()
	if !strings.Contains(out, "shutting down") || !strings.Contains(out, "msg=stopped") {
		t.Fatalf("a clean stop must be visible in the log:\n%s", out)
	}
}

// ---- OP-05 / SRV-07: the CLI database path ----

func TestOpenDatabaseRefusesAMissingDatabase(t *testing.T) {
	dir := t.TempDir()
	if _, err := OpenDatabase(Config{DataDir: dir + "/typo"}); err == nil {
		t.Fatal("a wrong --data must be an error, not a fresh empty database")
	}
	if _, err := New(Config{DataDir: dir, Listen: "127.0.0.1:0", Insecure: true, SkipSeed: true}); err != nil {
		t.Fatal(err)
	}
	db, err := OpenDatabase(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("the real directory should open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

// ---- SRV-20 coverage gaps: the SSE stream and the offline sweep ----

// TestEventStreamDelivers opens GET /api/events, which no test had ever
// opened, and checks that a hub event reaches it.
func TestEventStreamDelivers(t *testing.T) {
	s, ts, b := newTestServer(t)
	req, _ := http.NewRequest("GET", ts.URL+"/api/events", nil)
	req.Header.Set("X-Requested-With", "fetch")
	u, _ := http.NewRequest("GET", ts.URL, nil)
	for _, c := range b.c.Jar.Cookies(u.URL) {
		req.AddCookie(c)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("event stream status %d", resp.StatusCode)
	}
	br := bufio.NewReader(resp.Body)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, "hello") {
		t.Fatalf("expected the hello event first, got %q (%v)", line, err)
	}

	go func() {
		for i := 0; i < 20; i++ {
			s.hub.broadcast(hubEvent{Kind: "agent_online", AgentID: "ghost"})
			time.Sleep(50 * time.Millisecond)
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("event stream read: %v", err)
		}
		if strings.Contains(l, "agent_online") {
			return
		}
	}
	t.Fatal("the broadcast never reached the event stream")
}

// TestSweepOfflineOpensAnAlert drives the alert engine's periodic sweep,
// which no test had ever run: the offline rule kind, its grace period and
// maintenance-mode suppression were all uncovered.
func TestSweepOfflineOpensAnAlert(t *testing.T) {
	s, _, b := newTestServer(t)
	var rule AlertRule
	b.mustJSON("POST", "/api/alert-rules", AlertRule{Name: "offline", Kind: "offline",
		Params: RuleParams{Minutes: 5}, Targets: Targets{All: true}, Severity: "critical", AutoResolve: true, Enabled: true}, &rule)

	// a device that has not been seen for an hour, and never has a socket
	s.db.Exec(`INSERT INTO agents(id, key_hash, hostname, os, enrolled_at, last_seen) VALUES('off1','h','offbox','linux',?,?)`, now(), now()-3600)
	s.alerts.sweepOffline()
	al, _ := s.db.ListAlerts("open", "off1", 10)
	if len(al) != 1 || al[0].Title != "Device offline" {
		t.Fatalf("the offline sweep should have opened one alert, got %+v", al)
	}

	// a second device in maintenance stays quiet
	s.db.Exec(`INSERT INTO agents(id, key_hash, hostname, os, enrolled_at, last_seen, maintenance_until) VALUES('off2','h2','maintbox','linux',?,?,?)`,
		now(), now()-3600, now()+3600)
	s.alerts.sweepOffline()
	if al2, _ := s.db.ListAlerts("open", "off2", 10); len(al2) != 0 {
		t.Fatalf("a device in maintenance must not raise an offline alert: %+v", al2)
	}
}

// TestPartialSettingsSaveKeepsRetention: a PUT that leaves retention out (or
// sends zeros) used to store "0 days", which the next hourly purge reads as
// "delete every metric, run, audit row and event".
func TestPartialSettingsSaveKeepsRetention(t *testing.T) {
	s, _, b := newTestServer(t)
	b.mustJSON("PUT", "/api/settings", map[string]any{"public_url": "https://rmm.example:8443"}, nil)
	got := s.loadSettings()
	if got.Retention.MetricsDays != 30 || got.Retention.RunsDays != 90 || got.Retention.AuditDays != 365 || got.Retention.EventsDays != 30 {
		t.Fatalf("a partial save wiped retention: %+v", got.Retention)
	}
}

// TestCancelRun covers both halves of run cancellation, which SRV-20 listed
// as untested: a queued run is claimed and closed in the database, and a live
// one sends script.cancel to the device that is running it.
func TestCancelRun(t *testing.T) {
	s, ts, b := newTestServer(t)
	var sc Script
	b.mustJSON("POST", "/api/scripts", Script{Name: "slow", Language: "bash", Body: "sleep 600"}, &sc)

	// ---- queued: the device is offline, so the run waits in the database
	if _, err := s.db.Exec(`INSERT INTO agents(id, key_hash, hostname, os, enrolled_at, last_seen) VALUES('down','hdown','downbox','linux',?,?)`, now(), now()); err != nil {
		t.Fatal(err)
	}
	var queued struct {
		RunID string `json:"run_id"`
	}
	b.mustJSON("POST", "/api/agents/down/run", map[string]any{"script_id": sc.ID}, &queued)
	if r, err := s.db.GetRun(queued.RunID); err != nil || r.Status != "queued" {
		t.Fatalf("an offline device should queue the run, got %+v (%v)", r, err)
	}
	b.mustJSON("POST", "/api/runs/"+queued.RunID+"/cancel", nil, nil)
	r, err := s.db.GetRun(queued.RunID)
	if err != nil || r.Status != "cancelled" {
		t.Fatalf("cancelling a queued run should mark it cancelled, got %+v (%v)", r, err)
	}
	if r.FinishedAt == 0 {
		t.Fatal("a cancelled run needs a finished_at, or it is swept as stuck later")
	}
	// the row is no longer queued, so a reconnect must not release it and the
	// second cancel has nothing to act on
	s.runs.releaseQueued("down")
	if again, _ := s.db.GetRun(queued.RunID); again.Status != "cancelled" {
		t.Fatalf("releaseQueued resurrected a cancelled run: %+v", again)
	}
	if st, _ := b.do("POST", "/api/runs/"+queued.RunID+"/cancel", nil); st/100 == 2 {
		t.Fatalf("cancelling an already cancelled run should fail, got %d", st)
	}

	// ---- live: the agent accepts the run and never answers it
	tok := enrolToken(t, s)
	ag := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tok}}, "slowbox", "linux")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(ag.id) })
	var live struct {
		RunID string `json:"run_id"`
	}
	b.mustJSON("POST", "/api/agents/"+ag.id+"/run", map[string]any{"script_id": sc.ID}, &live)
	waitFor(t, "run live", func() bool {
		_, _, ok := s.runs.Live(live.RunID)
		return ok
	})
	b.mustJSON("POST", "/api/runs/"+live.RunID+"/cancel", nil, nil)

	ag.ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		var env protocol.Envelope
		if err := ag.ws.ReadJSON(&env); err != nil {
			t.Fatalf("script.cancel never reached the device: %v", err)
		}
		if env.T != protocol.ReqScriptCancel {
			continue // the script.run request itself, or a keepalive ping
		}
		var in map[string]string
		json.Unmarshal(env.D, &in)
		if in["run_id"] != live.RunID {
			t.Fatalf("cancel named the wrong run: %v", in)
		}
		break
	}
}

// TestSustainedWindowMustBeCrossed drives a "CPU above N% for M minutes"
// rule. sustained() is what separates a rule that fires on one spike from one
// that waits out its window, and SRV-20 found nothing exercising it - a
// regression either way is silent: an alert storm, or a threshold that never
// fires at all.
func TestSustainedWindowMustBeCrossed(t *testing.T) {
	s, _, b := newTestServer(t)
	var rule AlertRule
	b.mustJSON("POST", "/api/alert-rules", AlertRule{Name: "cpu", Kind: "cpu",
		Params: RuleParams{Threshold: 80, Minutes: 10}, Targets: Targets{All: true},
		Severity: "warning", AutoResolve: true, Enabled: true}, &rule)
	if _, err := s.db.Exec(`INSERT INTO agents(id, key_hash, hostname, os, enrolled_at, last_seen) VALUES('busy','hbusy','busybox','linux',?,?)`, now(), now()); err != nil {
		t.Fatal(err)
	}
	key := dedupe(rule.ID, "busy", "")
	openNow := func() []Alert {
		t.Helper()
		al, err := s.db.ListAlerts("open", "busy", 10)
		if err != nil {
			t.Fatal(err)
		}
		return al
	}
	backdate := func(by int64) {
		s.alerts.mu.Lock()
		defer s.alerts.mu.Unlock()
		if _, ok := s.alerts.since[key]; !ok {
			t.Fatal("the sustained window was never started")
		}
		s.alerts.since[key] = now() - by
	}

	hot := &protocol.Metrics{CPUPct: 95, MemTotal: 100, MemUsed: 1}
	cool := &protocol.Metrics{CPUPct: 5, MemTotal: 100, MemUsed: 1}

	// the first hot sample only starts the clock
	s.alerts.metrics("busy", hot)
	if al := openNow(); len(al) != 0 {
		t.Fatalf("one hot sample must not open a sustained alert: %+v", al)
	}
	// and so does the next one, while the window is still running
	s.alerts.metrics("busy", hot)
	if al := openNow(); len(al) != 0 {
		t.Fatalf("the window has not elapsed yet: %+v", al)
	}
	// a sample below the threshold clears it, so the clock restarts from zero
	s.alerts.metrics("busy", cool)
	s.alerts.mu.Lock()
	_, running := s.alerts.since[key]
	s.alerts.mu.Unlock()
	if running {
		t.Fatal("a sample below the threshold must clear the sustained window")
	}

	// hot again, with the window backdated past its end
	s.alerts.metrics("busy", hot)
	backdate(11 * 60)
	s.alerts.metrics("busy", hot)
	al := openNow()
	if len(al) != 1 || !strings.Contains(al[0].Title, "CPU above") {
		t.Fatalf("the alert should fire once the window is crossed, got %+v", al)
	}
	// every later sample dedupes onto the same alert
	s.alerts.metrics("busy", hot)
	s.alerts.metrics("busy", hot)
	if al := openNow(); len(al) != 1 {
		t.Fatalf("a sustained alert must not re-open on every sample: %+v", al)
	}
	// and auto_resolve closes it when the device cools down
	s.alerts.metrics("busy", cool)
	if al := openNow(); len(al) != 0 {
		t.Fatalf("auto_resolve should have closed the alert: %+v", al)
	}
}
