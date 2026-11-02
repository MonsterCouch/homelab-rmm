package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// ---- parsing ----

func TestServicingParseCode(t *testing.T) {
	for _, tc := range []struct {
		name, text, want string
	}{
		{"scan error", "Windows Update search failed: 0x80073712", "0x80073712"},
		{"lower case is normalised", "failed with 0x800f081f (CBS_E_SOURCE_MISSING)", "0x800F081F"},
		{"upper case prefix", "error 0X80240020 occurred", "0x80240020"},
		{"install failure reason", "Install failed: 0x800F0922", "0x800F0922"},
		{"the first known code wins", "0x80004005 then 0x80240034 then 0x80073712", "0x80240034"},
		{"WUA file not found", "Search failed: 0x80070002", "0x80070002"},
		{"WUA path not found", "Search failed: 0x80070003", "0x80070003"},
		{"a winget failure is not a Windows Update failure", "winget upgrade failed: 0x80070002", ""},
		{"a winget part is skipped, the WUA part counts", "winget upgrade failed: 0x80070002; Search failed: 0x8024A105", "0x8024A105"},
		{"an unknown code", "failed: 0x80004005", ""},
		{"no code", "the network is unreachable", ""},
		{"a short hex number is not a code", "0x8007 and 0x80", ""},
		{"empty", "", ""},
	} {
		if got := parseServicingCode(tc.text); got != tc.want {
			t.Errorf("%s: parseServicingCode(%q) = %q, want %q", tc.name, tc.text, got, tc.want)
		}
	}
}

func TestServicingCodeTableIsComplete(t *testing.T) {
	want := []string{"0x80240020", "0x80073712", "0x800F081F", "0x800F0922", "0x800F0831", "0x80070002", "0x80070003",
		"0x8024A105", "0x80240034", "0x80244022", "0x8007000E", "0x80070020"}
	if len(servicingCodes) != len(want) {
		t.Errorf("table has %d codes, the design lists %d", len(servicingCodes), len(want))
	}
	for _, code := range want {
		c, ok := servicingCodes[code]
		if !ok {
			t.Errorf("%s is missing from the table", code)
			continue
		}
		if !strings.HasSuffix(c.Why, ".") || len(strings.Fields(c.Why)) < 6 {
			t.Errorf("%s: %q is not a sentence", code, c.Why)
		}
		if got := parseServicingCode("error " + strings.ToLower(code)); got != code {
			t.Errorf("%s does not parse back to itself: %q", code, got)
		}
	}
}

func TestServicingFailedReasonsAreJoinedInKeyOrder(t *testing.T) {
	got := failedReasons(map[string]string{"b": "second 0x80073712", "a": "first"})
	if got != "first; second 0x80073712" {
		t.Errorf("failedReasons = %q", got)
	}
	if parseServicingCode(got) != "0x80073712" {
		t.Error("the joined reasons lose the code")
	}
}

// ---- a fake Windows agent ----

type winAgent struct {
	*sigAgent
	mu2        sync.Mutex
	scanErr    string
	failed     map[string]string
	repairErr  string
	repairBody protocol.ServicingRepairResult
}

func (w *winAgent) set(fn func()) { w.mu2.Lock(); fn(); w.mu2.Unlock() }

func (w *winAgent) run() {
	for {
		var env protocol.Envelope
		if err := w.raw.ws.ReadJSON(&env); err != nil {
			return
		}
		if env.T == protocol.ReqAgentConfig || env.T == protocol.ReqTrustUpdate {
			if env.ID != "" {
				w.reply(env.ID, nil)
			}
			continue
		}
		dec := w.verifier().Check(env.T, env.D, env.A)
		w.mu.Lock()
		w.seen = append(w.seen, sigSeen{env, dec})
		w.mu.Unlock()
		if env.ID == "" {
			continue
		}
		w.mu2.Lock()
		scanErr, failed, repairErr, body := w.scanErr, w.failed, w.repairErr, w.repairBody
		w.mu2.Unlock()
		switch env.T {
		case protocol.ReqUpdatesScan:
			w.reply(env.ID, protocol.UpdatesScanResult{Error: scanErr})
		case protocol.ReqUpdatesInstall:
			w.reply(env.ID, protocol.UpdatesInstallResult{Installed: []string{}, Failed: failed})
		case protocol.ReqServicingRepair:
			if repairErr != "" {
				w.mu.Lock()
				w.raw.ws.WriteJSON(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, Err: repairErr})
				w.mu.Unlock()
				continue
			}
			w.reply(env.ID, body)
		default:
			w.reply(env.ID, map[string]any{})
		}
	}
}

func okRepairBody() protocol.ServicingRepairResult {
	return protocol.ServicingRepairResult{
		Steps: []protocol.ServicingStep{
			{Name: "dism_restore", Status: "ok", DurationMS: 5, Tail: "The restore operation completed successfully."},
			{Name: "reset_components", Status: "ok"},
			{Name: "rescan", Status: "ok"},
		},
		Scan: &protocol.UpdatesScanResult{},
	}
}

// addWinAgent enrolls a fake Windows agent that answers like the real one
// would. enroll is how the test server hands out its token.
func (f *signFixture) addWinAgent(name string) *winAgent {
	f.t.Helper()
	var tok struct{ Token string }
	f.admin.mustJSON("POST", "/api/enroll", map[string]any{"name": name, "uses": 1}, &tok)
	ra := dialAgentAs(f.t, f.ts, http.Header{"X-Enroll-Token": []string{tok.Token}}, name, "windows")
	w := &winAgent{sigAgent: &sigAgent{t: f.t, s: f.s, raw: ra, nonce: actionauth.NewMemoryNonceStore()}, repairBody: okRepairBody()}
	go w.run()
	waitFor(f.t, "agent online", func() bool { return f.s.hub.IsOnline(ra.id) })
	return w
}

func waitServicing(t *testing.T, s *Server, agentID string, n int) []ServicingRecord {
	t.Helper()
	var got []ServicingRecord
	waitFor(t, "a finished servicing record", func() bool {
		got, _ = s.db.listServicing(agentID, 50)
		if len(got) < n {
			return false
		}
		for _, r := range got {
			if r.Status == "running" {
				return false
			}
		}
		return true
	})
	return got
}

func setRepairPolicy(t *testing.T, b *browser, repair, reboot string) PatchPolicy {
	t.Helper()
	var p PatchPolicy
	b.mustJSON("POST", "/api/patch-policies", map[string]any{
		"name": "Repair policy", "targets": map[string]any{"all": true}, "enabled": true,
		"mode": "approved", "reboot": reboot, "repair": repair,
	}, &p)
	return p
}

// ---- the policy field ----

func TestServicingPolicyRepairField(t *testing.T) {
	_, _, admin := newTestServer(t)
	p := setRepairPolicy(t, admin, "auto", "never")
	if p.Repair != "auto" {
		t.Fatalf("created policy = %+v", p)
	}
	var def PatchPolicy
	admin.mustJSON("POST", "/api/patch-policies", map[string]any{"name": "Plain", "targets": map[string]any{"all": true}}, &def)
	if def.Repair != "off" {
		t.Errorf("default repair = %q, want off", def.Repair)
	}
	if st, body := admin.do("POST", "/api/patch-policies", map[string]any{"name": "Bad", "repair": "always"}); st != 400 || !strings.Contains(string(body), "repair") {
		t.Errorf("repair=always = %d %s", st, body)
	}
	// An update that omits the field keeps it.
	var upd PatchPolicy
	admin.mustJSON("PUT", fmt.Sprintf("/api/patch-policies/%d", p.ID), map[string]any{"name": "Renamed", "targets": map[string]any{"all": true}, "enabled": true}, &upd)
	if upd.Repair != "auto" {
		t.Errorf("an update without repair changed it to %q", upd.Repair)
	}
	var list []PatchPolicy
	admin.mustJSON("GET", "/api/patch-policies", nil, &list)
	found := false
	for _, x := range list {
		if x.ID == p.ID {
			found = x.Repair == "auto"
		}
	}
	if !found {
		t.Errorf("the list does not carry repair: %+v", list)
	}
	admin.mustJSON("PUT", fmt.Sprintf("/api/patch-policies/%d", p.ID), map[string]any{"name": "Renamed", "targets": map[string]any{"all": true}, "enabled": true, "repair": "off"}, &upd)
	if upd.Repair != "off" {
		t.Errorf("repair off was not saved: %q", upd.Repair)
	}
}

func TestServicingPolicyUnit(t *testing.T) {
	s, _, admin := newTestServer(t)
	p := setRepairPolicy(t, admin, "auto", "always")
	u := repairUnit(&p)
	if u.Type != approvalPatchPolicy || u.Purpose != "repair" || u.Cons.Op != protocol.ReqServicingRepair ||
		!slices.Equal(u.Cons.Steps, []string{"dism_restore", "reset_components", "rescan"}) || u.Cons.Reboot != "if_required" {
		t.Fatalf("unit = %+v", u)
	}
	never := p
	never.Reboot = "never"
	if repairUnit(&never).Hash == u.Hash || repairUnit(&never).Cons.Reboot != "never" {
		t.Error("the reboot setting is not part of what is signed")
	}
	// no install schedule, yet the unit exists on its own
	units := s.objectUnits(approvalPatchPolicy, fmt.Sprint(p.ID))
	if len(units) != 1 || units[0].Purpose != "repair" {
		t.Fatalf("objectUnits = %+v", units)
	}
	admin.mustJSON("PUT", fmt.Sprintf("/api/patch-policies/%d", p.ID), map[string]any{"name": p.Name, "targets": map[string]any{"all": true}, "enabled": true, "repair": "off"}, nil)
	if units := s.objectUnits(approvalPatchPolicy, fmt.Sprint(p.ID)); len(units) != 0 {
		t.Errorf("a policy with repair off still needs an approval: %+v", units)
	}
}

// ---- automatic repair ----

func TestServicingAutoRepairFromScanWithCooldownAndAlerts(t *testing.T) {
	f := newSignFixture(t, "", 1, 10)
	ag := f.addWinAgent("win1")
	id := ag.ID()
	f.admin.mustJSON("POST", "/api/alert-rules", map[string]any{
		"name": "servicing", "kind": "event", "params": map[string]any{"pattern": "servicing repair"},
		"targets": map[string]any{"all": true}, "severity": "warning", "enabled": true,
	}, nil)
	ag.set(func() { ag.scanErr = "Windows Update search failed: 0x80073712" })

	// no policy: a servicing code alone does nothing
	f.admin.mustJSON("POST", "/api/agents/"+id+"/patches/scan", nil, nil)
	time.Sleep(300 * time.Millisecond)
	if n := len(ag.requests(protocol.ReqServicingRepair)); n != 0 {
		t.Fatalf("a repair started without a policy that allows it (%d)", n)
	}

	// policy with repair off: still nothing
	p := setRepairPolicy(t, f.admin, "off", "never")
	f.admin.mustJSON("POST", "/api/agents/"+id+"/patches/scan", nil, nil)
	time.Sleep(300 * time.Millisecond)
	if n := len(ag.requests(protocol.ReqServicingRepair)); n != 0 {
		t.Fatalf("a repair started under repair=off (%d)", n)
	}

	f.admin.mustJSON("PUT", fmt.Sprintf("/api/patch-policies/%d", p.ID), map[string]any{"name": p.Name, "targets": map[string]any{"all": true}, "enabled": true, "reboot": "if_required", "repair": "auto"}, nil)
	f.admin.mustJSON("POST", "/api/agents/"+id+"/patches/scan", nil, nil)
	got := ag.wait(protocol.ReqServicingRepair, 1)
	var req protocol.ServicingRepair
	json.Unmarshal(got[0].Env.D, &req)
	if !slices.Equal(req.Steps, []string{"dism_restore", "reset_components", "rescan"}) || req.Reboot != "if_required" || req.Package != nil {
		t.Fatalf("auto repair sent %+v", req)
	}
	recs := waitServicing(t, f.s, id, 1)
	r := recs[0]
	if r.Trigger != "auto" || r.Code != "0x80073712" || r.Status != "ok" || r.By != "policy:"+p.Name ||
		r.PolicyID == nil || *r.PolicyID != p.ID || r.FinishedAt == 0 || !strings.Contains(r.Why, "component store") {
		t.Fatalf("record = %+v", r)
	}
	var res protocol.ServicingRepairResult
	if err := json.Unmarshal(r.Result, &res); err != nil || len(res.Steps) != 3 || res.Steps[0].Tail == "" {
		t.Fatalf("stored result = %s (%v)", r.Result, err)
	}

	// audit rows: who (which policy) started it, and its outcome
	var auditStart, auditDone int
	f.s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action = 'servicing.repair.auto' AND target = ? AND user LIKE 'policy:%'`, id).Scan(&auditStart)
	f.s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action = 'servicing.repair' AND target = ?`, id).Scan(&auditDone)
	if auditStart != 1 || auditDone != 1 {
		t.Errorf("audit rows: start=%d done=%d", auditStart, auditDone)
	}
	// event alerts: started and finished, each with its sentence
	waitFor(t, "the two event alerts", func() bool {
		var n int
		f.s.db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE agent_id = ? AND title IN ('Event: servicing_started','Event: servicing_finished')`, id).Scan(&n)
		return n == 2
	})
	var msg string
	f.s.db.QueryRow(`SELECT message FROM alerts WHERE agent_id = ? AND title = 'Event: servicing_started'`, id).Scan(&msg)
	if !strings.Contains(msg, "Servicing repair started on win1 after 0x80073712") {
		t.Errorf("start alert = %q", msg)
	}

	// the cooldown: a second scan with the same error starts nothing today ...
	f.admin.mustJSON("POST", "/api/agents/"+id+"/patches/scan", nil, nil)
	time.Sleep(400 * time.Millisecond)
	if n := len(ag.requests(protocol.ReqServicingRepair)); n != 1 {
		t.Fatalf("a second repair started inside the cooldown (%d requests)", n)
	}
	// ... but does once the last one is older than a day
	f.s.db.Exec(`UPDATE servicing_repairs SET started_at = ? WHERE agent_id = ?`, now()-25*3600, id)
	f.admin.mustJSON("POST", "/api/agents/"+id+"/patches/scan", nil, nil)
	ag.wait(protocol.ReqServicingRepair, 2)
	if recs := waitServicing(t, f.s, id, 2); len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}

	// a manual repair does not count toward the cooldown, a running one does
	f.s.db.Exec(`UPDATE servicing_repairs SET started_at = ? WHERE agent_id = ?`, now()-25*3600, id)
	f.s.db.insertServicing(id, nil, "manual", "", "admin")
	f.admin.mustJSON("POST", "/api/agents/"+id+"/patches/scan", nil, nil)
	time.Sleep(400 * time.Millisecond)
	if n := len(ag.requests(protocol.ReqServicingRepair)); n != 2 {
		t.Fatalf("a repair started while another was running (%d requests)", n)
	}
}

func TestServicingFailedStepFailsTheRecordAndAClearScanDoesNothing(t *testing.T) {
	f := newSignFixture(t, "", 1, 10)
	ag := f.addWinAgent("win2")
	id := ag.ID()
	setRepairPolicy(t, f.admin, "auto", "never")
	ag.set(func() {
		ag.scanErr = ""
		ag.repairBody = protocol.ServicingRepairResult{Steps: []protocol.ServicingStep{
			{Name: "dism_restore", Status: "failed", ExitCode: 1726, Tail: "The remote procedure call failed."},
			{Name: "reset_components", Status: "skipped"},
		}}
	})
	f.admin.mustJSON("POST", "/api/agents/"+id+"/patches/scan", nil, nil)
	time.Sleep(300 * time.Millisecond)
	if n := len(ag.requests(protocol.ReqServicingRepair)); n != 0 {
		t.Fatalf("a clean scan started a repair")
	}
	ag.set(func() { ag.scanErr = "failed 0x800F0831" })
	f.admin.mustJSON("POST", "/api/agents/"+id+"/patches/scan", nil, nil)
	recs := waitServicing(t, f.s, id, 1)
	if recs[0].Status != "failed" || recs[0].Code != "0x800F0831" {
		t.Fatalf("record = %+v", recs[0])
	}
	var ev string
	waitFor(t, "the outcome event", func() bool {
		return f.s.db.QueryRow(`SELECT message FROM agent_events WHERE agent_id = ? AND message LIKE 'Servicing repair finished%'`, id).Scan(&ev) == nil
	})
	if !strings.Contains(ev, "step dism_restore failed") {
		t.Errorf("event = %q", ev)
	}
}

func TestServicingRequestErrorIsRecorded(t *testing.T) {
	f := newSignFixture(t, "", 1, 10)
	ag := f.addWinAgent("win3")
	id := ag.ID()
	setRepairPolicy(t, f.admin, "auto", "never")
	ag.set(func() { ag.scanErr = "0x80240034"; ag.repairErr = "refused: no valid signature" })
	f.admin.mustJSON("POST", "/api/agents/"+id+"/patches/scan", nil, nil)
	recs := waitServicing(t, f.s, id, 1)
	if recs[0].Status != "failed" || !strings.Contains(string(recs[0].Result), "refused: no valid signature") {
		t.Fatalf("record = %+v result=%s", recs[0], recs[0].Result)
	}
}

func TestServicingInstallFailureStartsRepair(t *testing.T) {
	f := newSignFixture(t, "", 1, 10)
	ag := f.addWinAgent("win4")
	id := ag.ID()
	setRepairPolicy(t, f.admin, "auto", "never")
	ag.set(func() { ag.failed = map[string]string{"KB1": "Install failed: 0x800F0922"} })
	if _, err := f.s.patchInstall(id, []string{"KB1"}, false, "admin", nil); err != nil {
		t.Fatal(err)
	}
	ag.wait(protocol.ReqServicingRepair, 1)
	recs := waitServicing(t, f.s, id, 1)
	if recs[0].Code != "0x800F0922" || recs[0].Trigger != "auto" {
		t.Fatalf("record = %+v", recs[0])
	}
}

func TestServicingAutoRepairNeedsAWindowsDevice(t *testing.T) {
	f := newSignFixture(t, "", 1, 10)
	lin := f.addAgent("lin1")
	setRepairPolicy(t, f.admin, "auto", "never")
	f.s.autoRepairAfter(lin.ID(), "failed 0x80073712")
	time.Sleep(200 * time.Millisecond)
	if recs, _ := f.s.db.listServicing(lin.ID(), 10); len(recs) != 0 {
		t.Errorf("a Linux device got a servicing repair: %+v", recs)
	}
}

// ---- signing ----

func TestServicingAutoRepairRunsUnderTheStandingApproval(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeEnforce, 1, 10)
	ag := f.addWinAgent("win5")
	id := ag.ID()
	p := setRepairPolicy(t, f.admin, "auto", "never")

	var unsigned []map[string]any
	f.admin.mustJSON("GET", "/api/approvals/unsigned", nil, &unsigned)
	listed := false
	for _, u := range unsigned {
		if u["type"] == approvalPatchPolicy && u["id"] == fmt.Sprint(p.ID) && u["purpose"] == "repair" {
			listed = true
		}
	}
	if !listed {
		t.Fatalf("the repair is not on the review list: %v", unsigned)
	}

	ag.set(func() { ag.scanErr = "0x80073712" })
	f.admin.mustJSON("POST", "/api/agents/"+id+"/patches/scan", nil, nil)
	first := ag.wait(protocol.ReqServicingRepair, 1)
	if first[0].Env.A != nil || first[0].Dec.Allow {
		t.Fatalf("an unsigned repair was allowed by the agent: %+v", first[0].Dec)
	}
	waitServicing(t, f.s, id, 1)

	signPath := fmt.Sprintf("/api/approvals/objects/patch_policy/%d/sign?org=%s&purpose=repair", p.ID, trustOrg)
	if st, body := signedCall(t, f.admin, f.ka, "POST", signPath, nil); st != 200 {
		t.Fatalf("signing the repair approval = %d %s", st, body)
	}
	f.admin.mustJSON("GET", "/api/approvals/unsigned", nil, &unsigned)
	for _, u := range unsigned {
		if u["type"] == approvalPatchPolicy && u["purpose"] == "repair" {
			t.Fatalf("still listed after signing: %v", u)
		}
	}

	f.s.db.Exec(`UPDATE servicing_repairs SET started_at = ? WHERE agent_id = ?`, now()-25*3600, id)
	f.admin.mustJSON("POST", "/api/agents/"+id+"/patches/scan", nil, nil)
	second := ag.wait(protocol.ReqServicingRepair, 2)
	if second[1].Env.A == nil || !second[1].Dec.Verified || !second[1].Dec.Allow {
		t.Fatalf("the repair was not allowed under its approval: %+v", second[1].Dec)
	}

	// editing the policy's reboot setting voids the approval
	f.s.db.Exec(`UPDATE servicing_repairs SET started_at = ? WHERE agent_id = ?`, now()-25*3600, id)
	waitServicing(t, f.s, id, 2)
	f.admin.mustJSON("PUT", fmt.Sprintf("/api/patch-policies/%d", p.ID), map[string]any{"name": p.Name, "targets": map[string]any{"all": true}, "enabled": true, "reboot": "if_required", "repair": "auto"}, nil)
	f.admin.mustJSON("POST", "/api/agents/"+id+"/patches/scan", nil, nil)
	third := ag.wait(protocol.ReqServicingRepair, 3)
	if third[2].Env.A != nil || third[2].Dec.Allow {
		t.Fatalf("a changed policy still ran under the old approval: %+v", third[2].Dec)
	}
}

func TestServicingManualRepairThroughTheSigningFlow(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeEnforce, 1, 10)
	ag := f.addWinAgent("win6")
	id := ag.ID()
	path := "/api/agents/" + id + "/servicing/repair"

	// validation happens before anything is offered for signing
	for name, body := range map[string]map[string]any{
		"unknown step":          {"steps": []string{"format"}},
		"bad reboot":            {"reboot": "always"},
		"package without step":  {"steps": []string{"sfc"}, "package": map[string]string{"url": "https://x/a.cab", "sha256": strings.Repeat("a", 64)}},
		"step without package":  {"steps": []string{"add_package"}},
		"http package":          {"steps": []string{"add_package"}, "package": map[string]string{"url": "http://x/a.cab", "sha256": strings.Repeat("a", 64)}},
		"exe package":           {"steps": []string{"add_package"}, "package": map[string]string{"url": "https://x/a.exe", "sha256": strings.Repeat("a", 64)}},
		"package without a sum": {"steps": []string{"add_package"}, "package": map[string]string{"url": "https://x/a.cab", "sha256": "abc"}},
	} {
		if st, out := f.admin.do("POST", path, body); st != 400 {
			t.Errorf("%s = %d %s, want 400", name, st, out)
		}
	}

	body := map[string]any{"steps": []string{"dism_restore", "sfc"}, "reboot": "if_required"}
	c := ask(t, f.admin, "POST", path, body)
	m := c.parsed(t)
	var pl protocol.ServicingRepair
	json.Unmarshal(m.Payload, &pl)
	if m.Op != protocol.ReqServicingRepair || m.Kind != actionauth.KindAction || m.Targets[0] != id ||
		!slices.Equal(pl.Steps, []string{"dism_restore", "sfc"}) || pl.Reboot != "if_required" ||
		!strings.Contains(c.Summary, "dism_restore, sfc") {
		t.Fatalf("manifest = %+v payload=%s summary=%q", m, m.Payload, c.Summary)
	}
	if got := ag.requests(protocol.ReqServicingRepair); len(got) != 0 {
		t.Fatal("the agent was sent a repair before anything was signed")
	}
	st, out := f.admin.doHdr("POST", path, body, c.signedBy(t, f.ka))
	if st != http.StatusAccepted {
		t.Fatalf("signed repair = %d %s", st, out)
	}
	got := ag.wait(protocol.ReqServicingRepair, 1)
	if got[0].Env.A == nil || !got[0].Dec.Verified || !got[0].Dec.Allow {
		t.Fatalf("agent decision = %+v", got[0].Dec)
	}
	recs := waitServicing(t, f.s, id, 1)
	if recs[0].Trigger != "manual" || recs[0].By != "admin" || recs[0].PolicyID != nil || recs[0].Status != "ok" {
		t.Fatalf("record = %+v", recs[0])
	}

	// the listing endpoint
	var list []ServicingRecord
	f.admin.mustJSON("GET", "/api/agents/"+id+"/servicing", nil, &list)
	if len(list) != 1 || list[0].ID != recs[0].ID {
		t.Fatalf("listing = %+v", list)
	}
	var audited int
	f.s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action = 'servicing.repair.request' AND target = ?`, id).Scan(&audited)
	if audited != 1 {
		t.Errorf("request audit rows = %d", audited)
	}

	// empty body: the concrete default steps are what gets signed
	c2 := ask(t, f.admin, "POST", path, nil)
	var pl2 protocol.ServicingRepair
	json.Unmarshal(c2.parsed(t).Payload, &pl2)
	if !slices.Equal(pl2.Steps, defaultRepairSteps()) || pl2.Reboot != "never" {
		t.Fatalf("default payload = %+v", pl2)
	}
}

func TestServicingManualRepairUnsignedServerAndGuards(t *testing.T) {
	f := newSignFixture(t, "", 1, 10)
	ag := f.addWinAgent("win7")
	id := ag.ID()
	path := "/api/agents/" + id + "/servicing/repair"

	// busy: a patch job holds the device
	release, ok := f.s.claimPatchJob(id)
	if !ok {
		t.Fatal("could not claim the patch job")
	}
	if st, out := f.admin.do("POST", path, map[string]any{"steps": []string{"sfc"}}); st != http.StatusConflict {
		t.Errorf("busy device = %d %s, want 409", st, out)
	}
	release()
	if recs, _ := f.s.db.listServicing(id, 10); len(recs) != 0 {
		t.Errorf("a refused request left a record: %+v", recs)
	}

	if st, out := f.admin.do("POST", path, map[string]any{"steps": []string{"sfc"}}); st != http.StatusAccepted {
		t.Fatalf("unsigned org = %d %s", st, out)
	}
	waitServicing(t, f.s, id, 1)

	// the lock is released afterwards
	if rel, ok := f.s.claimPatchJob(id); !ok {
		t.Error("the patch job was not released after the repair")
	} else {
		rel()
	}

	// Linux devices answer the plain sentence
	lin := f.addAgent("lin2")
	st, out := f.admin.do("POST", "/api/agents/"+lin.ID()+"/servicing/repair", nil)
	if st != 400 || !strings.Contains(string(out), "servicing repair is a Windows operation") {
		t.Errorf("linux = %d %s", st, out)
	}
	// unknown device
	if st, _ := f.admin.do("GET", "/api/agents/nope/servicing", nil); st != 404 {
		t.Errorf("unknown device = %d", st)
	}
}

// ---- review fixes ----

func TestServicingWUAOnlyCodesIgnoreInstallReasons(t *testing.T) {
	if got := parseServicingCodeIn("Install failed: 0x80070002", false); got != "" {
		t.Errorf("a generic file-not-found in an install reason started a repair: %q", got)
	}
	if got := parseServicingCodeIn("Install failed: 0x800F0922", false); got != "0x800F0922" {
		t.Errorf("a servicing code in an install reason must still count, got %q", got)
	}
	if got := parseServicingCodeIn("Search failed: 0x80070002", true); got != "0x80070002" {
		t.Errorf("a scan error with a WUA-only code must count, got %q", got)
	}
}

func TestServicingStaleRunningRecordDoesNotBlockRepair(t *testing.T) {
	f := newSignFixture(t, "", 1, 10)
	ag := f.addWinAgent("win-stale")
	id := ag.ID()
	setRepairPolicy(t, f.admin, "auto", "never")

	// A running row from a server that died, plus a fresh one that is real.
	oldID, err := f.s.db.insertServicing(id, nil, "manual", "", "admin")
	if err != nil {
		t.Fatal(err)
	}
	f.s.db.Exec(`UPDATE servicing_repairs SET started_at = ? WHERE id = ?`, now()-int64(servicingRequestTimeout/time.Second)-60, oldID)
	f.s.db.failStaleServicing(int64(servicingRequestTimeout / time.Second))
	recs, _ := f.s.db.listServicing(id, 10)
	if len(recs) != 1 || recs[0].Status != "failed" || !strings.Contains(string(recs[0].Result), "restarted") {
		t.Fatalf("the stale record was not failed: %+v", recs)
	}
	liveID, _ := f.s.db.insertServicing(id, nil, "manual", "", "admin")
	f.s.db.failStaleServicing(int64(servicingRequestTimeout / time.Second))
	if recs, _ = f.s.db.listServicing(id, 10); recs[0].ID != liveID || recs[0].Status != "running" {
		t.Fatalf("a repair that is still within its time limit was failed: %+v", recs[0])
	}
	// At startup nothing can be running, whatever its age.
	f.s.db.failStaleServicing(0)
	if recs, _ = f.s.db.listServicing(id, 10); recs[0].Status != "failed" {
		t.Fatalf("the startup sweep left a running record: %+v", recs[0])
	}

	// The cooldown query itself ignores a running row past the time limit.
	f.s.db.Exec(`DELETE FROM servicing_repairs WHERE agent_id = ?`, id)
	staleID, _ := f.s.db.insertServicing(id, nil, "manual", "", "admin")
	f.s.db.Exec(`UPDATE servicing_repairs SET started_at = ? WHERE id = ?`, now()-int64(servicingRequestTimeout/time.Second)-60, staleID)
	ag.set(func() { ag.scanErr = "0x80073712" })
	f.admin.mustJSON("POST", "/api/agents/"+id+"/patches/scan", nil, nil)
	ag.wait(protocol.ReqServicingRepair, 1)
}

func TestServicingBusyDeviceDoesNotSpendTheCooldown(t *testing.T) {
	old := servicingClaimWait
	servicingClaimWait = 300 * time.Millisecond
	defer func() { servicingClaimWait = old }()
	f := newSignFixture(t, "", 1, 10)
	ag := f.addWinAgent("win-busy")
	id := ag.ID()
	setRepairPolicy(t, f.admin, "auto", "never")
	release, ok := f.s.claimPatchJob(id)
	if !ok {
		t.Fatal("could not claim the patch job")
	}
	f.s.autoRepairAfter(id, "failed 0x80073712")
	time.Sleep(time.Second)
	release()
	if recs, _ := f.s.db.listServicing(id, 10); len(recs) != 0 {
		t.Fatalf("a repair that never started left a record that counts against the cooldown: %+v", recs)
	}
	f.s.autoRepairAfter(id, "failed 0x80073712")
	ag.wait(protocol.ReqServicingRepair, 1)
}

func TestServicingListLimitIsClamped(t *testing.T) {
	f := newSignFixture(t, "", 1, 10)
	ag := f.addWinAgent("win-limit")
	id := ag.ID()
	for i := 0; i < 3; i++ {
		f.s.db.insertServicing(id, nil, "manual", "", "admin")
	}
	for q, want := range map[string]int{"-1": 1, "0": 1, "2": 2, "100000": 3} {
		var list []ServicingRecord
		f.admin.mustJSON("GET", "/api/agents/"+id+"/servicing?limit="+q, nil, &list)
		if len(list) != want {
			t.Errorf("limit=%s returned %d records, want %d", q, len(list), want)
		}
	}
}
