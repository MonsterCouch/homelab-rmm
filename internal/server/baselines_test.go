package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// ---- test bodies ----

type tCheck struct {
	ID         int64           `json:"id,omitempty"`
	Name       string          `json:"name"`
	Kind       string          `json:"kind"`
	Params     json.RawMessage `json:"params"`
	Remediate  bool            `json:"remediate"`
	Severity   string          `json:"severity"`
	OSFilter   string          `json:"os_filter,omitempty"`
	TimeoutSec int             `json:"timeout_sec,omitempty"`
}

type tBaseline struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Targets           Targets  `json:"targets"`
	Enforce           bool     `json:"enforce"`
	IntervalSec       int      `json:"interval_sec"`
	NotifyEmail       bool     `json:"notify_email"`
	Enabled           bool     `json:"enabled"`
	AllowEmptyTargets bool     `json:"allow_empty_targets"`
	Checks            []tCheck `json:"checks"`
}

func firewallCheck(name string) tCheck {
	return tCheck{Name: name, Kind: "firewall", Params: json.RawMessage(`{"enabled":true}`), Severity: "warning"}
}

func timeSyncCheck(name string) tCheck {
	return tCheck{Name: name, Kind: "time_sync", Params: json.RawMessage(`{"enabled":true}`), Severity: "critical"}
}

// newBaselineFixture is a signed-in admin, one connected linux device and no
// seeded data.
func newBaselineFixture(t *testing.T) (*Server, *httptest.Server, *browser, *fakeAgent) {
	t.Helper()
	s, ts, b := newTestServer(t)
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab", "uses": 1}, &tok)
	agent := dialAgent(t, wsURL(ts), http.Header{"X-Enroll-Token": []string{tok.Token}})
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(agent.id) })
	return s, ts, b, agent
}

func createBaseline(t *testing.T, b *browser, body tBaseline) baselineDetailOut {
	t.Helper()
	var out baselineDetailOut
	st, data := b.do("POST", "/api/baselines", body)
	if st != 201 {
		t.Fatalf("create baseline -> %d: %s", st, data)
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("create baseline: bad json %v: %s", err, data)
	}
	return out
}

func putBaseline(t *testing.T, b *browser, id int64, body tBaseline) baselineDetailOut {
	t.Helper()
	var out baselineDetailOut
	b.mustJSON("PUT", fmt.Sprintf("/api/baselines/%d", id), body, &out)
	return out
}

func checksToInput(checks []BaselineCheck) []tCheck {
	out := make([]tCheck, 0, len(checks))
	for _, c := range checks {
		out = append(out, tCheck{ID: c.ID, Name: c.Name, Kind: c.Kind, Params: c.Params, Remediate: c.Remediate,
			Severity: c.Severity, OSFilter: c.OSFilter, TimeoutSec: c.TimeoutSec})
	}
	return out
}

// ---- CRUD ----

// A check id is the only identity a result, a history row and an alert key
// ever use, so an edit must keep it, a delete must never hand it to the next
// check (AUTOINCREMENT), and a version bump must happen exactly when the
// AGENT's view changed.
func TestBaselineCRUDStableIDsAndVersion(t *testing.T) {
	_, _, b, _ := newBaselineFixture(t)

	body := tBaseline{Name: "hygiene", Targets: Targets{All: true}, IntervalSec: 900,
		Checks: []tCheck{firewallCheck("Firewall on"), timeSyncCheck("Time sync")}}
	created := createBaseline(t, b, body)
	if created.Version != 1 || len(created.Checks) != 2 {
		t.Fatalf("created: version=%d checks=%d", created.Version, len(created.Checks))
	}
	c1, c2 := created.Checks[0].ID, created.Checks[1].ID
	if c1 == 0 || c2 == 0 || c1 == c2 {
		t.Fatalf("check ids wrong: %d %d", c1, c2)
	}
	if created.Checks[0].Position != 0 || created.Checks[1].Position != 1 {
		t.Fatalf("positions wrong: %+v", created.Checks)
	}

	// A change the agent never sees (description, notify, targets) does not
	// bump the version.
	body.Checks = checksToInput(created.Checks)
	body.Description = "edited"
	body.NotifyEmail = true
	got := putBaseline(t, b, created.ID, body)
	if got.Version != 1 {
		t.Fatalf("description edit bumped the version to %d", got.Version)
	}
	if got.Checks[0].ID != c1 || got.Checks[1].ID != c2 {
		t.Fatalf("check ids changed on a no-op save: %+v", got.Checks)
	}

	// A change the agent DOES see bumps it by exactly one, keeping the ids.
	body.Checks[0].Name = "Firewall enabled"
	got = putBaseline(t, b, created.ID, body)
	if got.Version != 2 || got.Checks[0].ID != c1 || got.Checks[1].ID != c2 {
		t.Fatalf("rename: version=%d ids=%d,%d", got.Version, got.Checks[0].ID, got.Checks[1].ID)
	}

	// Dropping a check deletes it; adding one must NOT reuse its id, or the
	// new check inherits the dead one's results, history and open alert.
	body.Checks = body.Checks[:1]
	got = putBaseline(t, b, created.ID, body)
	if got.Version != 3 || len(got.Checks) != 1 || got.Checks[0].ID != c1 {
		t.Fatalf("delete: version=%d checks=%+v", got.Version, got.Checks)
	}
	body.Checks = append(body.Checks, timeSyncCheck("Time sync again"))
	got = putBaseline(t, b, created.ID, body)
	if got.Version != 4 || len(got.Checks) != 2 {
		t.Fatalf("insert: version=%d checks=%d", got.Version, len(got.Checks))
	}
	if got.Checks[1].ID == c2 {
		t.Fatalf("a deleted check id came back: %d (declare the table AUTOINCREMENT)", c2)
	}
	c3 := got.Checks[1].ID

	// Changing the kind of an existing id is a delete plus an insert: the old
	// expected/observed mean nothing under the new kind.
	body.Checks = checksToInput(got.Checks)
	body.Checks[1].Kind = "firewall"
	body.Checks[1].Params = json.RawMessage(`{"enabled":true}`)
	got = putBaseline(t, b, created.ID, body)
	if got.Checks[1].ID == c3 {
		t.Fatalf("changing kind kept the check id %d", c3)
	}

	// An id that belongs to no check of this baseline is a 400, never a
	// silent insert.
	body.Checks = checksToInput(got.Checks)
	body.Checks[0].ID = 99999
	if st, data := b.do("PUT", fmt.Sprintf("/api/baselines/%d", created.ID), body); st != 400 || !strings.Contains(string(data), "unknown check id") {
		t.Fatalf("unknown check id -> %d: %s", st, data)
	}

	// Empty targets match nothing: that is a 400 unless it is deliberate.
	empty := tBaseline{Name: "nobody", Targets: Targets{}, Checks: []tCheck{firewallCheck("Firewall on")}}
	if st, data := b.do("POST", "/api/baselines", empty); st != 400 || !strings.Contains(string(data), "match no devices") {
		t.Fatalf("empty targets -> %d: %s", st, data)
	}
	empty.AllowEmptyTargets = true
	if st, _ := b.do("POST", "/api/baselines", empty); st != 201 {
		t.Fatalf("allow_empty_targets -> %d", st)
	}

	var list []BaselineOut
	b.mustJSON("GET", "/api/baselines", nil, &list)
	if len(list) != 2 {
		t.Fatalf("list has %d baselines", len(list))
	}
	if st, _ := b.do("DELETE", fmt.Sprintf("/api/baselines/%d", created.ID), nil); st != 200 {
		t.Fatal("delete failed")
	}
	if st, _ := b.do("GET", fmt.Sprintf("/api/baselines/%d", created.ID), nil); st != 404 {
		t.Fatalf("deleted baseline -> %d", st)
	}
}

// ---- config push ----

func TestBaselineConfigCarriesMatchedSpecsOnly(t *testing.T) {
	s, _, b, agent := newBaselineFixture(t)

	// A windows-only baseline never reaches a linux device.
	createBaseline(t, b, tBaseline{Name: "windows only", Targets: Targets{All: true, OS: "windows"}, Enabled: true,
		AllowEmptyTargets: true, Checks: []tCheck{firewallCheck("Firewall on")}})
	if got := s.agentConfig(agent.id).Baselines; len(got) != 0 {
		t.Fatalf("linux device got a windows baseline: %+v", got)
	}

	created := createBaseline(t, b, tBaseline{Name: "all devices", Targets: Targets{All: true}, Enabled: true, Enforce: true,
		IntervalSec: 30, Checks: []tCheck{firewallCheck("Firewall on"), timeSyncCheck("Time sync")}})
	cfg := s.agentConfig(agent.id)
	if len(cfg.Baselines) != 1 || len(cfg.Baselines[0].Checks) != 2 {
		t.Fatalf("config baselines wrong: %+v", cfg.Baselines)
	}
	spec := cfg.Baselines[0]
	if spec.ID != created.ID || !spec.Enforce || spec.Version != created.Version {
		t.Fatalf("spec wrong: %+v", spec)
	}
	if spec.IntervalSec != minBaselineInterval {
		t.Fatalf("interval not clamped: %d", spec.IntervalSec)
	}

	// Disabling it takes it out of the pushed set entirely (and does not bump
	// the version: the baseline simply leaves the set).
	body := tBaseline{Name: "all devices", Targets: Targets{All: true}, Enabled: false, Enforce: true, IntervalSec: 30,
		Checks: checksToInput(created.Checks)}
	got := putBaseline(t, b, created.ID, body)
	if got.Version != created.Version {
		t.Fatalf("toggling enabled bumped the version: %d -> %d", created.Version, got.Version)
	}
	if n := len(s.agentConfig(agent.id).Baselines); n != 0 {
		t.Fatalf("disabled baseline still pushed (%d)", n)
	}
}

// agent_defaults is an operator-editable settings blob that unmarshals into
// the same struct the agent config is built from. A baseline set frozen into
// it would be pushed to every device whatever its targets say.
func TestBaselinesNeverLeakIntoAgentDefaults(t *testing.T) {
	s, _, b, _ := newBaselineFixture(t)
	b.mustJSON("PUT", "/api/settings", map[string]any{
		"agent_defaults": map[string]any{
			"metrics_interval_sec":   30,
			"inventory_interval_sec": 3600,
			"baselines":              []map[string]any{{"id": 1, "name": "smuggled", "version": 9, "checks": []any{}}},
		},
	}, nil)
	if raw := s.db.Setting("agent_defaults", ""); strings.Contains(raw, "smuggled") || strings.Contains(raw, "baselines") {
		t.Fatalf("a baseline set was stored in agent_defaults: %s", raw)
	}
}

// ---- ingest ----

func blReport(baselineID int64, version int, results ...protocol.BaselineResult) protocol.BaselineReport {
	return protocol.BaselineReport{BaselineID: baselineID, Version: version, TS: time.Now().Unix(), Trigger: "schedule", Results: results}
}

func blResult(checkID int64, state string) protocol.BaselineResult {
	return protocol.BaselineResult{CheckID: checkID, State: state, Expected: "enabled", Observed: state, DurationMs: 7}
}

func resultsFor(t *testing.T, s *Server, baselineID int64, agentID string) map[int64]BaselineResult {
	t.Helper()
	byAgent, err := s.db.baselineResultsFor(baselineID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[int64]BaselineResult{}
	for _, r := range byAgent[agentID] {
		out[r.CheckID] = r
	}
	return out
}

func openDriftAlerts(t *testing.T, s *Server, agentID string) []Alert {
	t.Helper()
	all, err := s.db.ListAlerts("open", agentID, 50)
	if err != nil {
		t.Fatal(err)
	}
	out := []Alert{}
	for _, a := range all {
		if a.RuleKind == "drift" {
			out = append(out, a)
		}
	}
	return out
}

func historyCount(t *testing.T, s *Server, agentID string) int {
	t.Helper()
	rows, err := s.db.BaselineHistory(agentID, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func TestBaselineIngestTransitionsAlertsAndHistory(t *testing.T) {
	s, _, b, agent := newBaselineFixture(t)
	created := createBaseline(t, b, tBaseline{Name: "hygiene", Targets: Targets{All: true}, Enabled: true, IntervalSec: 3600,
		Checks: []tCheck{
			firewallCheck("Firewall on"),
			timeSyncCheck("Time sync"),
			{Name: "Notes only", Kind: "disk_free", Params: json.RawMessage(`{"mount":"/","min_free_pct":10}`), Severity: "info"},
		}})
	c1, c2, c3 := created.Checks[0].ID, created.Checks[1].ID, created.Checks[2].ID

	// First pass: one drifted check, one informational failure. A first
	// `pass` is the baseline being established and writes no history.
	agent.sendBaselineReport(blReport(created.ID, created.Version, blResult(c1, "pass"), blResult(c2, "fail"), blResult(c3, "fail")))
	waitFor(t, "drift alert", func() bool { return len(openDriftAlerts(t, s, agent.id)) == 1 })
	al := openDriftAlerts(t, s, agent.id)[0]
	if al.Severity != "critical" || !strings.Contains(al.Title, "Time sync") {
		t.Fatalf("drift alert wrong: %+v", al)
	}
	var key string
	s.db.QueryRow(`SELECT dedupe_key FROM alerts WHERE id = ?`, al.ID).Scan(&key)
	if want := fmt.Sprintf("drift:%d:%d:%s", created.ID, c2, agent.id); key != want {
		t.Fatalf("dedupe key %q, want %q", key, want)
	}
	rs := resultsFor(t, s, created.ID, agent.id)
	if len(rs) != 3 || rs[c1].State != "pass" || rs[c2].State != "fail" {
		t.Fatalf("results wrong: %+v", rs)
	}
	firstSince := rs[c2].Since
	if firstSince == 0 {
		t.Fatal("since not stamped")
	}
	if n := historyCount(t, s, agent.id); n != 2 {
		t.Fatalf("history rows = %d, want 2 (the two failures, not the pass)", n)
	}

	// The same failing pass again: one alert, no new history row, `since`
	// unchanged - but the alert is re-offered every time, not only on the
	// transition (a first failure inside a maintenance window would otherwise
	// never open one).
	agent.sendBaselineReport(blReport(created.ID, created.Version, blResult(c1, "pass"), blResult(c2, "fail"), blResult(c3, "fail")))
	waitFor(t, "second pass stored", func() bool {
		return resultsFor(t, s, created.ID, agent.id)[c2].ReceivedAt >= firstSince
	})
	time.Sleep(50 * time.Millisecond)
	if n := len(openDriftAlerts(t, s, agent.id)); n != 1 {
		t.Fatalf("a repeated failure opened %d alerts", n)
	}
	if n := historyCount(t, s, agent.id); n != 2 {
		t.Fatalf("a repeated failure wrote history: %d rows", n)
	}
	if got := resultsFor(t, s, created.ID, agent.id)[c2].Since; got != firstSince {
		t.Fatalf("since moved on an unchanged state: %d -> %d", firstSince, got)
	}

	// Results for a check that no longer exists are dropped, not stored, and
	// a check id of 0 or less is never persisted (preview ids are negative).
	agent.sendBaselineReport(blReport(created.ID, created.Version, blResult(c1, "pass"), blResult(999999, "fail"), blResult(-1, "fail")))
	time.Sleep(150 * time.Millisecond)
	if rs := resultsFor(t, s, created.ID, agent.id); len(rs) != 3 {
		t.Fatalf("a result for an unknown check was stored: %+v", rs)
	}

	// A report for an older version is ignored outright.
	agent.sendBaselineReport(blReport(created.ID, created.Version-1, blResult(c2, "pass")))
	time.Sleep(150 * time.Millisecond)
	if got := resultsFor(t, s, created.ID, agent.id)[c2].State; got != "fail" {
		t.Fatalf("a stale-version report was applied: state=%s", got)
	}

	// Recovery resolves the alert and records the transition. `since` is
	// backdated first so the reset is visible within one test second.
	if _, err := s.db.Exec(`UPDATE baseline_results SET since = 1000 WHERE agent_id = ? AND check_id = ?`, agent.id, c2); err != nil {
		t.Fatal(err)
	}
	agent.sendBaselineReport(blReport(created.ID, created.Version, blResult(c1, "pass"), blResult(c2, "pass"), blResult(c3, "pass")))
	waitFor(t, "alert resolved", func() bool { return len(openDriftAlerts(t, s, agent.id)) == 0 })
	if n := historyCount(t, s, agent.id); n != 4 {
		t.Fatalf("history rows = %d, want 4", n)
	}
	if got := resultsFor(t, s, created.ID, agent.id)[c2].Since; got <= 1000 {
		t.Fatalf("since was not reset by a state change: %d", got)
	}

	// A version bump marks the stored results stale rather than deleting
	// them, and the next accepted report clears the flag.
	body := tBaseline{Name: "hygiene renamed", Targets: Targets{All: true}, Enabled: true, IntervalSec: 3600, Checks: checksToInput(created.Checks)}
	bumped := putBaseline(t, b, created.ID, body)
	if bumped.Version != created.Version+1 {
		t.Fatalf("version = %d", bumped.Version)
	}
	if rs := resultsFor(t, s, created.ID, agent.id); !rs[c1].Stale {
		t.Fatalf("results not marked stale after a version bump: %+v", rs[c1])
	}
	var status struct {
		Devices []baselineDeviceOut `json:"devices"`
	}
	b.mustJSON("GET", fmt.Sprintf("/api/baselines/%d/status", created.ID), nil, &status)
	if len(status.Devices) != 1 || status.Devices[0].Compliance != nil || !status.Devices[0].Stale {
		t.Fatalf("stale device should have no compliance score: %+v", status.Devices)
	}
	agent.sendBaselineReport(blReport(created.ID, bumped.Version, blResult(c1, "pass"), blResult(c2, "pass"), blResult(c3, "pass")))
	waitFor(t, "stale cleared", func() bool { return !resultsFor(t, s, created.ID, agent.id)[c1].Stale })

	// A device that stops matching loses its rows, and its drift alerts are
	// resolved: nothing else ever resolves one.
	agent.sendBaselineReport(blReport(created.ID, bumped.Version, blResult(c1, "pass"), blResult(c2, "fail"), blResult(c3, "pass")))
	waitFor(t, "drift alert again", func() bool { return len(openDriftAlerts(t, s, agent.id)) == 1 })
	body.Targets = Targets{All: true, OS: "windows"}
	body.AllowEmptyTargets = true
	body.Checks = checksToInput(bumped.Checks)
	putBaseline(t, b, created.ID, body)
	waitFor(t, "alerts resolved after the device stopped matching", func() bool { return len(openDriftAlerts(t, s, agent.id)) == 0 })
	if rs := resultsFor(t, s, created.ID, agent.id); len(rs) != 0 {
		t.Fatalf("results kept for a device that no longer matches: %+v", rs)
	}
}

// The console never polls: it refetches when the `baseline` SSE event says
// something changed, so the event has to carry the ids and the shape the
// console (and web/src/hooks/useEvents.tsx) registers for.
func TestBaselineSSEEventShape(t *testing.T) {
	s, _, b, agent := newBaselineFixture(t)
	created := createBaseline(t, b, tBaseline{Name: "hygiene", Targets: Targets{All: true}, Enabled: true,
		Checks: []tCheck{firewallCheck("Firewall on"), timeSyncCheck("Time sync")}})
	c1, c2 := created.Checks[0].ID, created.Checks[1].ID

	ch, unsub := s.hub.subscribe()
	defer unsub()
	agent.sendBaselineReport(blReport(created.ID, created.Version, blResult(c1, "pass"), blResult(c2, "fail")))

	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("no baseline event was broadcast")
		case ev := <-ch:
			if ev.Kind != "baseline" {
				continue
			}
			if ev.AgentID != agent.id {
				t.Fatalf("event agent = %q", ev.AgentID)
			}
			// Marshalled the way handleEvents writes it, so the test sees
			// exactly what the browser sees.
			raw, err := json.Marshal(ev)
			if err != nil {
				t.Fatal(err)
			}
			var got struct {
				Kind    string `json:"kind"`
				AgentID string `json:"agent_id"`
				Data    struct {
					BaselineID int64          `json:"baseline_id"`
					Version    int            `json:"version"`
					Trigger    string         `json:"trigger"`
					TS         int64          `json:"ts"`
					Counts     map[string]int `json:"counts"`
					Compliance *float64       `json:"compliance"`
					Changed    []struct {
						CheckID int64  `json:"check_id"`
						From    string `json:"from"`
						To      string `json:"to"`
					} `json:"changed"`
				} `json:"data"`
			}
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("baseline event is not the documented shape: %v: %s", err, raw)
			}
			if got.Data.BaselineID != created.ID || got.Data.Version != created.Version || got.Data.Trigger != "schedule" {
				t.Fatalf("event data wrong: %s", raw)
			}
			if got.Data.Counts["pass"] != 1 || got.Data.Counts["fail"] != 1 {
				t.Fatalf("event counts wrong: %s", raw)
			}
			if got.Data.Compliance == nil || *got.Data.Compliance != 50 {
				t.Fatalf("event compliance wrong: %s", raw)
			}
			if len(got.Data.Changed) != 1 || got.Data.Changed[0].CheckID != c2 || got.Data.Changed[0].To != "fail" {
				t.Fatalf("event transitions wrong: %s", raw)
			}
			return
		}
	}
}

// A device that joins or leaves a group joins or leaves every baseline that
// targets it. Leaving must clear the rows and resolve the alerts: nothing
// else ever updates them again, and nothing else resolves a drift alert.
func TestBaselineMembershipFollowsGroupChanges(t *testing.T) {
	s, _, b, agent := newBaselineFixture(t)
	var g Group
	b.mustJSON("POST", "/api/groups", map[string]any{"name": "servers"}, &g)
	created := createBaseline(t, b, tBaseline{Name: "servers only", Targets: Targets{Groups: []int64{g.ID}}, Enabled: true,
		AllowEmptyTargets: true, Checks: []tCheck{timeSyncCheck("Time sync")}})
	c1 := created.Checks[0].ID
	if n := len(s.agentConfig(agent.id).Baselines); n != 0 {
		t.Fatalf("a device outside the group got %d baselines", n)
	}

	b.mustJSON("PATCH", "/api/agents/"+agent.id, map[string]any{"group_id": g.ID}, nil)
	if n := len(s.agentConfig(agent.id).Baselines); n != 1 {
		t.Fatalf("joining the group pushed %d baselines", n)
	}
	agent.sendBaselineReport(blReport(created.ID, created.Version, blResult(c1, "fail")))
	waitFor(t, "drift alert", func() bool { return len(openDriftAlerts(t, s, agent.id)) == 1 })

	b.mustJSON("PATCH", "/api/agents/"+agent.id, map[string]any{"clear_group": true}, nil)
	waitFor(t, "alerts resolved when the device left the group", func() bool { return len(openDriftAlerts(t, s, agent.id)) == 0 })
	if rs := resultsFor(t, s, created.ID, agent.id); len(rs) != 0 {
		t.Fatalf("results kept after the device left the group: %+v", rs)
	}
	if n := len(s.agentConfig(agent.id).Baselines); n != 0 {
		t.Fatalf("leaving the group left %d baselines pushed", n)
	}
}

// A preview is a dry run of a spec that may never be saved, and its check ids
// are synthetic negatives. A frame that claims to be one is dropped whole.
func TestBaselinePreviewFramesAreNeverStored(t *testing.T) {
	s, _, b, agent := newBaselineFixture(t)
	created := createBaseline(t, b, tBaseline{Name: "hygiene", Targets: Targets{All: true}, Enabled: true,
		Checks: []tCheck{timeSyncCheck("Time sync")}})
	c1 := created.Checks[0].ID
	rep := blReport(created.ID, created.Version, blResult(c1, "fail"))
	rep.Trigger = "preview"
	agent.sendBaselineReport(rep)
	// Followed by a real one, so the wait has something to land on.
	agent.sendBaselineReport(blReport(created.ID, created.Version, blResult(c1, "pass")))
	waitFor(t, "the real report", func() bool { return resultsFor(t, s, created.ID, agent.id)[c1].State == "pass" })
	if n := historyCount(t, s, agent.id); n != 0 {
		t.Fatalf("a preview frame was ingested: %d history rows", n)
	}
	if n := len(openDriftAlerts(t, s, agent.id)); n != 0 {
		t.Fatalf("a preview frame opened %d alerts", n)
	}
}

// ---- endpoints ----

func TestBaselineStatusDeviceViewAndCompliance(t *testing.T) {
	s, ts, b, agent := newBaselineFixture(t)
	created := createBaseline(t, b, tBaseline{Name: "hygiene", Targets: Targets{All: true}, Enabled: true,
		Checks: []tCheck{firewallCheck("Firewall on"), timeSyncCheck("Time sync"), timeSyncCheck("Time sync 2")}})
	c1, c2, c3 := created.Checks[0].ID, created.Checks[1].ID, created.Checks[2].ID
	agent.sendBaselineReport(blReport(created.ID, created.Version, blResult(c1, "pass"), blResult(c2, "fail"), blResult(c3, "skipped")))
	waitFor(t, "report stored", func() bool { return len(resultsFor(t, s, created.ID, agent.id)) == 3 })

	var status struct {
		Baseline BaselineOut         `json:"baseline"`
		Checks   []BaselineCheck     `json:"checks"`
		Devices  []baselineDeviceOut `json:"devices"`
		Summary  struct {
			Devices        int      `json:"devices"`
			DevicesDrifted int      `json:"devices_drifted"`
			Compliance     *float64 `json:"compliance"`
		} `json:"summary"`
		Truncated bool `json:"truncated"`
	}
	b.mustJSON("GET", fmt.Sprintf("/api/baselines/%d/status", created.ID), nil, &status)
	if len(status.Devices) != 1 || len(status.Checks) != 3 {
		t.Fatalf("status wrong: %+v", status)
	}
	d := status.Devices[0]
	// pass+fixed over pass+fail+fixed+error: skipped is outside compliance.
	if d.Compliance == nil || *d.Compliance != 50 {
		t.Fatalf("device compliance = %v, want 50", d.Compliance)
	}
	if d.Counts.Skipped != 1 || d.Counts.Fail != 1 || d.LastTrigger != "schedule" {
		t.Fatalf("counts wrong: %+v", d)
	}
	if status.Summary.DevicesDrifted != 1 || status.Summary.Compliance == nil || *status.Summary.Compliance != 50 {
		t.Fatalf("summary wrong: %+v", status.Summary)
	}

	var dev struct {
		AgentID    string   `json:"agent_id"`
		Compliance *float64 `json:"compliance"`
		Baselines  []struct {
			ID     int64 `json:"id"`
			Checks []struct {
				ID     int64           `json:"id"`
				Result *BaselineResult `json:"result"`
			} `json:"checks"`
			Counts baselineCounts `json:"counts"`
		} `json:"baselines"`
	}
	b.mustJSON("GET", "/api/agents/"+agent.id+"/baselines", nil, &dev)
	if len(dev.Baselines) != 1 || len(dev.Baselines[0].Checks) != 3 || dev.Baselines[0].Checks[0].Result == nil {
		t.Fatalf("device view wrong: %+v", dev)
	}
	if dev.Compliance == nil || *dev.Compliance != 50 {
		t.Fatalf("device compliance = %v", dev.Compliance)
	}

	var hist struct {
		History []BaselineHistoryRow `json:"history"`
	}
	b.mustJSON("GET", "/api/agents/"+agent.id+"/baselines/history", nil, &hist)
	if len(hist.History) != 1 || hist.History[0].CheckName != "Time sync" || hist.History[0].ToState != "fail" {
		t.Fatalf("history wrong: %+v", hist.History)
	}

	var comp struct {
		Score              *float64 `json:"score"`
		DevicesWithBases   int      `json:"devices_with_baselines"`
		DevicesDrifted     int      `json:"devices_drifted"`
		ChecksFailing      int      `json:"checks_failing"`
		OpenDriftAlerts    int      `json:"open_drift_alerts"`
		BaselinesEnabled   int      `json:"baselines_enabled"`
		BaselinesEnforcing int      `json:"baselines_enforcing"`
		WorstChecks        []struct {
			CheckID int64 `json:"check_id"`
			Failing int   `json:"failing"`
		} `json:"worst_checks"`
		ByBaseline []byBaselineOut `json:"by_baseline"`
	}
	b.mustJSON("GET", "/api/compliance", nil, &comp)
	if comp.Score == nil || *comp.Score != 50 || comp.DevicesWithBases != 1 || comp.DevicesDrifted != 1 {
		t.Fatalf("fleet compliance wrong: %+v", comp)
	}
	if comp.ChecksFailing != 1 || comp.OpenDriftAlerts != 1 || comp.BaselinesEnabled != 1 || comp.BaselinesEnforcing != 0 {
		t.Fatalf("fleet counters wrong: %+v", comp)
	}
	if len(comp.WorstChecks) != 1 || comp.WorstChecks[0].CheckID != c2 || comp.WorstChecks[0].Failing != 1 {
		t.Fatalf("worst checks wrong: %+v", comp.WorstChecks)
	}
	if len(comp.ByBaseline) != 1 || comp.ByBaseline[0].DevicesDrifted != 1 {
		t.Fatalf("by_baseline wrong: %+v", comp.ByBaseline)
	}
	_ = ts
}

func TestBaselineEvaluateRemediateAndPreview(t *testing.T) {
	s, ts, b, agent := newBaselineFixture(t)
	created := createBaseline(t, b, tBaseline{Name: "hygiene", Targets: Targets{All: true}, Enabled: true, Enforce: true,
		Checks: []tCheck{
			{Name: "Firewall on", Kind: "firewall", Params: json.RawMessage(`{"enabled":true}`), Severity: "warning", Remediate: true},
			timeSyncCheck("Time sync"),
		}})
	c1, c2 := created.Checks[0].ID, created.Checks[1].ID

	// evaluate: the reply is an ACK, the pass arrives as its own frame.
	agent.setBaselineAnswer(&protocol.BaselineReport{BaselineID: created.ID, Version: created.Version, TS: time.Now().Unix(),
		Trigger: "manual", Results: []protocol.BaselineResult{blResult(c1, "fail"), blResult(c2, "pass")}})
	var ev struct {
		Requested int              `json:"requested"`
		Queued    int              `json:"queued"`
		Offline   int              `json:"offline"`
		Agents    []agentActionOut `json:"agents"`
	}
	b.mustJSON("POST", fmt.Sprintf("/api/baselines/%d/evaluate", created.ID), map[string]any{}, &ev)
	if ev.Requested != 1 || ev.Queued != 1 || len(ev.Agents) != 1 || ev.Agents[0].Status != "queued" {
		t.Fatalf("evaluate wrong: %+v", ev)
	}
	waitFor(t, "evaluate report ingested", func() bool { return resultsFor(t, s, created.ID, agent.id)[c1].State == "fail" })

	// remediate: a check with remediation off is refused per check, never
	// silently skipped, and only the accepted ids reach the device.
	var rem struct {
		Accepted []int64           `json:"accepted"`
		Refused  []refusedCheckOut `json:"refused"`
		Report   *json.RawMessage  `json:"report"`
	}
	b.mustJSON("POST", fmt.Sprintf("/api/baselines/%d/remediate", created.ID),
		map[string]any{"agent_id": agent.id, "check_ids": []int64{c1, c2}}, &rem)
	if len(rem.Accepted) != 1 || rem.Accepted[0] != c1 || len(rem.Refused) != 1 || rem.Refused[0].CheckID != c2 {
		t.Fatalf("remediate wrong: %+v", rem)
	}
	if rem.Report != nil {
		t.Fatal("remediate must not carry a report: the pass arrives as a TypeBaseline frame")
	}
	asks := agent.baselineAsks()
	if len(asks) < 2 {
		t.Fatalf("the device was not asked: %+v", asks)
	}

	// An empty check_ids means every FAILING check that allows remediation.
	b.mustJSON("POST", fmt.Sprintf("/api/baselines/%d/remediate", created.ID), map[string]any{"agent_id": agent.id}, &rem)
	if len(rem.Accepted) != 1 || rem.Accepted[0] != c1 {
		t.Fatalf("default remediate set wrong: %+v", rem)
	}

	// preview: synthetic negative ids, never stored, never fixing.
	var pv struct {
		SpecChecks []previewSpecCheck `json:"spec_checks"`
		Devices    []previewDeviceOut `json:"devices"`
	}
	spec := map[string]any{
		"spec":      map[string]any{"name": "draft", "enforce": true, "interval_sec": 3600, "checks": []tCheck{firewallCheck("Firewall on"), timeSyncCheck("Time sync")}},
		"agent_ids": []string{agent.id},
	}
	b.mustJSON("POST", "/api/baselines/preview", spec, &pv)
	if len(pv.SpecChecks) != 2 || pv.SpecChecks[0].ID != -1 || pv.SpecChecks[1].ID != -2 {
		t.Fatalf("preview ids wrong: %+v", pv.SpecChecks)
	}
	if len(pv.Devices) != 1 || pv.Devices[0].Status != "ok" || len(pv.Devices[0].Results) != 2 {
		t.Fatalf("preview devices wrong: %+v", pv.Devices)
	}
	if pv.Devices[0].Results[0].CheckID != -1 || pv.Devices[0].Results[0].Fixed {
		t.Fatalf("preview result wrong: %+v", pv.Devices[0].Results[0])
	}
	var negatives int
	s.db.QueryRow(`SELECT COUNT(*) FROM baseline_results WHERE check_id <= 0`).Scan(&negatives)
	if negatives != 0 {
		t.Fatalf("%d preview results were persisted", negatives)
	}
	if st, _ := b.do("POST", "/api/baselines/preview", map[string]any{"spec": map[string]any{"checks": []tCheck{}}, "agent_ids": []string{}}); st != 400 {
		t.Fatal("preview with no devices should be 400")
	}
	many := make([]string, maxPreviewAgents+1)
	for i := range many {
		many[i] = agent.id
	}
	if st, _ := b.do("POST", "/api/baselines/preview", map[string]any{"spec": map[string]any{"name": "d", "checks": []tCheck{firewallCheck("f")}}, "agent_ids": many}); st != 400 {
		t.Fatal("preview over the device cap should be 400")
	}
	// An invalid spec is the only other 400: unknown params key.
	bad := map[string]any{"spec": map[string]any{"name": "d", "checks": []tCheck{{Name: "x", Kind: "disk_free", Params: json.RawMessage(`{"mount":"/","min_free_percent":10}`), Severity: "warning"}}}, "agent_ids": []string{agent.id}}
	if st, data := b.do("POST", "/api/baselines/preview", bad); st != 400 {
		t.Fatalf("unknown params key -> %d: %s", st, data)
	}

	// Offline devices are an ANSWER, not a failure of the whole request - and
	// a remediation, which cannot be queued, is a 409.
	agent.ws.Close()
	waitFor(t, "agent offline", func() bool { return !s.hub.IsOnline(agent.id) })
	b.mustJSON("POST", "/api/baselines/preview", spec, &pv)
	if len(pv.Devices) != 1 || pv.Devices[0].Status != "offline" || pv.Devices[0].Error == "" {
		t.Fatalf("offline preview wrong: %+v", pv.Devices)
	}
	b.mustJSON("POST", fmt.Sprintf("/api/baselines/%d/evaluate", created.ID), map[string]any{}, &ev)
	if ev.Offline != 1 || ev.Queued != 0 || ev.Agents[0].Status != "offline" {
		t.Fatalf("offline evaluate wrong: %+v", ev)
	}
	if st, data := b.do("POST", fmt.Sprintf("/api/baselines/%d/remediate", created.ID), map[string]any{"agent_id": agent.id}); st != 409 {
		t.Fatalf("remediate on an offline device -> %d: %s", st, data)
	}
	_ = ts
}

// ---- roles, admin gates and audit ----

func TestBaselineRolesGatesAndAudit(t *testing.T) {
	_, ts, b, _ := newBaselineFixture(t)
	created := createBaseline(t, b, tBaseline{Name: "hygiene", Targets: Targets{All: true}, Checks: []tCheck{firewallCheck("Firewall on")}})

	b.mustJSON("POST", "/api/users", map[string]string{"username": "ro", "password": "password123", "role": "viewer"}, nil)
	ro := newBrowser(t, ts)
	ro.mustJSON("POST", "/api/auth/login", map[string]string{"username": "ro", "password": "password123"}, nil)
	writes := []struct {
		method, path string
		body         any
	}{
		{"POST", "/api/baselines", tBaseline{Name: "x", Targets: Targets{All: true}, Checks: []tCheck{firewallCheck("f")}}},
		{"PUT", fmt.Sprintf("/api/baselines/%d", created.ID), tBaseline{Name: "x", Targets: Targets{All: true}, Checks: []tCheck{firewallCheck("f")}}},
		{"DELETE", fmt.Sprintf("/api/baselines/%d", created.ID), nil},
		{"POST", fmt.Sprintf("/api/baselines/%d/evaluate", created.ID), map[string]any{}},
		{"POST", fmt.Sprintf("/api/baselines/%d/remediate", created.ID), map[string]any{"agent_id": "x"}},
		{"POST", "/api/baselines/preview", map[string]any{"spec": map[string]any{"name": "d"}, "agent_ids": []string{"x"}}},
	}
	for _, w := range writes {
		if st, data := ro.do(w.method, w.path, w.body); st != http.StatusForbidden {
			t.Errorf("viewer %s %s -> %d: %s", w.method, w.path, st, data)
		}
	}
	for _, p := range []string{"/api/baselines", fmt.Sprintf("/api/baselines/%d", created.ID), fmt.Sprintf("/api/baselines/%d/status", created.ID), "/api/compliance"} {
		if st, data := ro.do("GET", p, nil); st != http.StatusOK {
			t.Errorf("viewer GET %s -> %d: %s", p, st, data)
		}
	}

	// A `command` check runs as SYSTEM/root on every matched device, and an
	// allow_reboot check can reboot the fleet: both need an administrator,
	// even though the route itself is requireWrite.
	b.mustJSON("POST", "/api/users", map[string]string{"username": "tech", "password": "password123", "role": "tech"}, nil)
	tech := newBrowser(t, ts)
	tech.mustJSON("POST", "/api/auth/login", map[string]string{"username": "tech", "password": "password123"}, nil)
	cmd := tBaseline{Name: "scripted", Targets: Targets{All: true}, Checks: []tCheck{
		{Name: "check uptime", Kind: "command", Params: json.RawMessage(`{"language":"bash","check":"uptime","expected":"up"}`), Severity: "warning"},
	}}
	if st, data := tech.do("POST", "/api/baselines", cmd); st != http.StatusForbidden {
		t.Fatalf("tech creating a command check -> %d: %s", st, data)
	}
	adminMade := createBaseline(t, b, cmd)

	// A fleet-wide reboot needs an explicit confirmation.
	reboot := tBaseline{Name: "reboots", Targets: Targets{All: true}, Enforce: true, Checks: []tCheck{
		{Name: "reboot when overdue", Kind: "reboot_pending", Params: json.RawMessage(`{"max_hours":72,"allow_reboot":true}`), Severity: "warning", Remediate: true},
	}}
	if st, data := b.do("POST", "/api/baselines", reboot); st != 400 || !strings.Contains(string(data), "confirm_fleet_reboot") {
		t.Fatalf("fleet reboot without confirmation -> %d: %s", st, data)
	}

	var audit []struct {
		Action string `json:"action"`
		Target string `json:"target"`
	}
	b.mustJSON("GET", "/api/audit?limit=200", nil, &audit)
	seen := map[string]bool{}
	for _, a := range audit {
		seen[a.Action] = true
	}
	for _, want := range []string{"baseline.create", "baseline.command_check"} {
		if !seen[want] {
			t.Errorf("audit is missing %s: %+v", want, audit)
		}
	}
	b.do("DELETE", fmt.Sprintf("/api/baselines/%d", adminMade.ID), nil)
	b.mustJSON("GET", "/api/audit?limit=200", nil, &audit)
	seen = map[string]bool{}
	for _, a := range audit {
		seen[a.Action] = true
	}
	if !seen["baseline.delete"] {
		t.Error("audit is missing baseline.delete")
	}
}

// ---- compliance arithmetic ----

func TestBaselineComplianceMath(t *testing.T) {
	// No applicable result at all is null: not 0 (which reads as "totally
	// broken") and not 100 (which reads as "perfect").
	if got := countResults(nil, 3).score(); got != nil {
		t.Fatalf("no data scored %v, want null", *got)
	}
	skippedOnly := []BaselineResult{{CheckID: 1, State: "skipped"}}
	if got := countResults(skippedOnly, 1).score(); got != nil {
		t.Fatalf("skipped-only scored %v, want null", *got)
	}
	stale := []BaselineResult{{CheckID: 1, State: "pass", Stale: true}, {CheckID: 2, State: "fail", Stale: true}}
	c := countResults(stale, 2)
	if c.Unknown != 2 || c.score() != nil {
		t.Fatalf("stale results must count as unknown: %+v", c)
	}
	mixed := []BaselineResult{{State: "pass"}, {State: "fixed"}, {State: "fail"}, {State: "error"}, {State: "skipped"}}
	c = countResults(mixed, 6)
	if c.Unknown != 1 {
		t.Fatalf("a check with no row must count as unknown: %+v", c)
	}
	if got := c.score(); got == nil || *got != 50 {
		t.Fatalf("score = %v, want 50", got)
	}
	if !c.drifted() {
		t.Fatal("fail+error is drift")
	}
	fifty, hundred := 50.0, 100.0
	if got := meanScore([]*float64{&fifty, nil, &hundred}); got == nil || *got != 75 {
		t.Fatalf("mean = %v, want 75", got)
	}
	if got := meanScore([]*float64{nil, nil}); got != nil {
		t.Fatalf("mean of nothing = %v, want null", *got)
	}
}

func TestBaselineParamValidation(t *testing.T) {
	cases := []struct {
		kind   string
		params string
		ok     bool
	}{
		{"firewall", `{"enabled":true}`, true},
		{"firewall", `{"enabled":true,"profile":"domain"}`, false}, // unknown key
		{"service", `{"name":"Spooler","state":"stopped","start_type":"manual"}`, true},
		{"service", `{"name":"-rf","state":"stopped"}`, false},
		{"service", `{"name":"Spooler","state":"paused"}`, false},
		{"registry", `{"path":"HKLM\\SOFTWARE\\Acme","name":"X","type":"dword","value":1}`, true},
		{"registry", `{"path":"HKLM\\SAM\\X","name":"X","type":"dword","value":1}`, false},
		{"registry", `{"path":"HKLM\\SOFTWARE\\Acme","name":"X","type":"dword","value":"1"}`, false},
		{"registry", `{"path":"HKCR\\X","name":"X","type":"dword","value":1}`, false},
		{"file", `{"path":"/etc/ssh/sshd_config.d/99-rmm.conf","state":"present","content":"X","mode":"0644"}`, true},
		{"file", `{"path":"/etc/shadow","state":"present","content":"x"}`, false},
		{"file", `{"path":"../etc/passwd","state":"absent"}`, false},
		{"file", `{"path":"/etc/x","state":"present","content":"x","mode":"4755"}`, false},
		{"command", `{"language":"bash","check":"true","fix":"true"}`, true},
		{"command", `{"language":"bash","fix":"true"}`, false},
		{"command", `{"language":"perl","check":"true"}`, false},
		{"sysctl", `{"key":"net.ipv4.ip_forward","value":"0"}`, true},
		{"sysctl", `{"key":"net.ipv4.ip_forward","value":0}`, false},
		{"disk_free", `{"mount":"C:","min_free_pct":10}`, true},
		{"disk_free", `{"mount":"C:","min_free_pct":0}`, false},
		{"reboot_pending", `{"max_hours":0}`, false},
		{"group_members", `{"group":"sudo","allowed":[],"mode":"subset"}`, true},
		{"group_members", `{"group":"sudo","mode":"loose"}`, false},
		{"nonsense", `{}`, false},
	}
	for _, c := range cases {
		err := validateCheckParams(c.kind, json.RawMessage(c.params))
		if (err == nil) != c.ok {
			t.Errorf("%s %s: err=%v want ok=%v", c.kind, c.params, err, c.ok)
		}
	}
	// A kind that is not implemented on the OS the check is filtered to is a
	// save-time error, not a fleet of `skipped` rows.
	in := baselineInput{Name: "x", Checks: []baselineCheckInput{{Name: "c", Kind: "sysctl", OSFilter: "windows", Params: json.RawMessage(`{"key":"a.b","value":"1"}`)}}}
	if err := validateBaselineInput(&in); err == nil {
		t.Fatal("sysctl filtered to windows should be refused")
	}
	// Defaults are filled in and the interval is clamped both ways.
	in = baselineInput{Name: "x", IntervalSec: 5, Checks: []baselineCheckInput{{Name: "c", Kind: "firewall", Params: json.RawMessage(`{"enabled":true}`)}}}
	if err := validateBaselineInput(&in); err != nil {
		t.Fatal(err)
	}
	if in.IntervalSec != minBaselineInterval || in.Checks[0].Severity != "warning" || in.Checks[0].TimeoutSec != defaultCheckTimeout {
		t.Fatalf("defaults not applied: %+v", in)
	}
}

// ---- seed ----

func TestSeededBaselinesAreSafe(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// An upgraded database already records seeded=1; the baselines have their
	// own guard key or they would never appear.
	if err := db.SetSetting(seededKey, "1"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := seedDefaults(db); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	list, err := db.ListBaselinesWithChecks()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != len(defaultBaselines) {
		t.Fatalf("seeded %d baselines, want %d (and seeding twice must not duplicate)", len(list), len(defaultBaselines))
	}
	for _, b := range list {
		if b.Enabled || b.Enforce {
			t.Errorf("%q ships enabled=%v enforce=%v; a seeded baseline must never change a device", b.Name, b.Enabled, b.Enforce)
		}
		for _, c := range b.Checks {
			switch c.Kind {
			case "firewall", "time_sync", "sysctl":
			default:
				if c.Remediate {
					t.Errorf("%q: destructive check %q ships with remediation on", b.Name, c.Name)
				}
			}
			if c.Kind == "group_members" && strings.Contains(strings.ToLower(c.Name), "sudo") {
				var p struct {
					Allowed []string `json:"allowed"`
					Mode    string   `json:"mode"`
				}
				json.Unmarshal(c.Params, &p)
				if len(p.Allowed) != 0 || p.Mode != "subset" || c.Remediate {
					t.Errorf("the sudo membership seed must be report-only: %+v", c)
				}
			}
			if checkAllowsReboot(c) {
				t.Errorf("%q: a seeded check may not allow reboots", c.Name)
			}
		}
	}
}

// ---- adversarial review, 2026-09-15 ----

// A save body that names the same check id twice used to MERGE: the duplicate
// updated the same row a second time and every other check of the baseline -
// crowded out of the body by the duplicate - was treated as "absent" and
// deleted with its results. Two checks in, one check out, 200 OK.
func TestBaselineDuplicateCheckIDIsRefused(t *testing.T) {
	_, _, b, _ := newBaselineFixture(t)
	created := createBaseline(t, b, tBaseline{Name: "dup", Targets: Targets{All: true}, Enabled: true,
		Checks: []tCheck{firewallCheck("Firewall on"), timeSyncCheck("Time sync")}})
	in := checksToInput(created.Checks)

	body := tBaseline{Name: "dup", Targets: Targets{All: true}, Enabled: true, Checks: []tCheck{in[0], in[0]}}
	st, data := b.do("PUT", fmt.Sprintf("/api/baselines/%d", created.ID), body)
	if st != 400 || !strings.Contains(string(data), "duplicate check id") {
		t.Fatalf("a duplicated check id -> %d: %s", st, data)
	}
	// And nothing was lost: the refusal is a whole-request 400.
	var after baselineDetailOut
	b.mustJSON("GET", fmt.Sprintf("/api/baselines/%d", created.ID), nil, &after)
	if len(after.Checks) != 2 || after.Checks[0].ID != in[0].ID || after.Checks[1].ID != in[1].ID {
		t.Fatalf("the refused save changed the baseline: %+v", after.Checks)
	}
	if after.Version != created.Version {
		t.Fatalf("the refused save bumped the version: %d -> %d", created.Version, after.Version)
	}
	// The same id coming back after a kind change is a duplicate too.
	kindChanged := in[0]
	kindChanged.Kind, kindChanged.Params = "time_sync", json.RawMessage(`{"enabled":true}`)
	body.Checks = []tCheck{kindChanged, in[0]}
	if st, data := b.do("PUT", fmt.Sprintf("/api/baselines/%d", created.ID), body); st != 400 {
		t.Fatalf("a duplicated id across a kind change -> %d: %s", st, data)
	}
}

// The admin gate for a `file` check is baselines.RequiresAdmin and nothing
// else. The server's own copy asked whether the path CONTAINED "/programdata/",
// so /opt/evil/programdata/hook.sh read as a managed file and a tech could
// write it on every matched device.
func TestBaselineFileAdminGateUsesTheSharedRule(t *testing.T) {
	_, ts, admin, _ := newBaselineFixture(t)
	admin.mustJSON("POST", "/api/users", map[string]string{"username": "tech", "password": "password123", "role": "tech"}, nil)
	tech := newBrowser(t, ts)
	tech.mustJSON("POST", "/api/auth/login", map[string]string{"username": "tech", "password": "password123"}, nil)

	fileCheck := func(path string) tBaseline {
		return tBaseline{Name: "file " + path, Targets: Targets{All: true}, Checks: []tCheck{{
			Name: "managed file", Kind: "file", Severity: "warning",
			Params: json.RawMessage(fmt.Sprintf(`{"path":%q,"state":"present","content":"x"}`, path)),
		}}}
	}
	for _, path := range []string{
		"/opt/evil/programdata/hook.sh", // outside /etc, merely CONTAINS programdata
		"/usr/lib/systemd/system/x.service",
		`C:\Users\Public\hook.ps1`, // a user profile, not ProgramData
	} {
		if st, data := tech.do("POST", "/api/baselines", fileCheck(path)); st != http.StatusForbidden {
			t.Errorf("tech writing %s -> %d (want 403): %s", path, st, data)
		}
		if st, data := admin.do("POST", "/api/baselines", fileCheck(path)); st != 201 {
			t.Errorf("admin writing %s -> %d: %s", path, st, data)
		}
	}
	// /etc and ProgramData stay a tech's job: that is the whole point of the
	// carve-out (baselines.FileNeedsAdmin, which both sides read).
	for _, path := range []string{"/etc/ssh/sshd_config.d/99-rmm.conf", `C:\ProgramData\app\hook.ps1`} {
		if st, data := tech.do("POST", "/api/baselines", fileCheck(path)); st != 201 {
			t.Errorf("tech writing %s -> %d: %s", path, st, data)
		}
	}
}

// One pass reports a check once. A frame that repeats a check id used to
// upsert and write a history row per repetition, so a single pass produced a
// run of transitions, fired the drift automations several times over, and did
// all of it inside the transaction that holds the one SQLite connection.
func TestBaselineRepeatedResultsInOneReportAreDropped(t *testing.T) {
	s, _, b, agent := newBaselineFixture(t)
	created := createBaseline(t, b, tBaseline{Name: "repeats", Targets: Targets{All: true}, Enabled: true,
		Checks: []tCheck{firewallCheck("Firewall on")}})
	c1 := created.Checks[0].ID

	agent.sendBaselineReport(blReport(created.ID, created.Version,
		blResult(c1, "fail"), blResult(c1, "pass"), blResult(c1, "fail"), blResult(c1, "pass")))
	waitFor(t, "report ingested", func() bool { return len(resultsFor(t, s, created.ID, agent.id)) == 1 })
	time.Sleep(100 * time.Millisecond)

	if got := resultsFor(t, s, created.ID, agent.id)[c1].State; got != "fail" {
		t.Fatalf("first occurrence should win, got %q", got)
	}
	if n := historyCount(t, s, agent.id); n != 1 {
		t.Fatalf("one pass wrote %d history rows, want 1", n)
	}
	if n := len(openDriftAlerts(t, s, agent.id)); n != 1 {
		t.Fatalf("one pass opened %d drift alerts, want 1", n)
	}
}

// A disabled baseline is in no device's config, so asking a device to
// evaluate or remediate it can only produce a pass that never arrives.
func TestBaselineActionsRefuseADisabledBaseline(t *testing.T) {
	_, _, b, agent := newBaselineFixture(t)
	created := createBaseline(t, b, tBaseline{Name: "off", Targets: Targets{All: true}, Enabled: false,
		Checks: []tCheck{{Name: "Firewall on", Kind: "firewall", Params: json.RawMessage(`{"enabled":true}`), Severity: "warning", Remediate: true}}})
	if st, data := b.do("POST", fmt.Sprintf("/api/baselines/%d/evaluate", created.ID), map[string]any{}); st != 400 {
		t.Fatalf("evaluate on a disabled baseline -> %d: %s", st, data)
	}
	if st, data := b.do("POST", fmt.Sprintf("/api/baselines/%d/remediate", created.ID), map[string]any{"agent_id": agent.id}); st != 400 {
		t.Fatalf("remediate on a disabled baseline -> %d: %s", st, data)
	}
}

// Deleting a baseline must resolve its drift alerts on EVERY device that
// carries one, not only the devices its targets still select: a device that
// drifted and then stopped matching would keep the alert open forever, since
// nothing else resolves a drift alert (scheduler.purge auto-closes only
// script_failed, patch_failed and event).
func TestBaselineDeleteResolvesAlertsOfUnmatchedDevices(t *testing.T) {
	s, _, b, agent := newBaselineFixture(t)
	created := createBaseline(t, b, tBaseline{Name: "sweep", Targets: Targets{All: true}, Enabled: true,
		Checks: []tCheck{timeSyncCheck("Time sync")}})
	c1 := created.Checks[0].ID
	agent.sendBaselineReport(blReport(created.ID, created.Version, blResult(c1, "fail")))
	waitFor(t, "drift alert", func() bool { return len(openDriftAlerts(t, s, agent.id)) == 1 })

	// The device stops matching without the cleanup path running: exactly the
	// state a crash between the write and the push leaves behind.
	if _, err := s.db.Exec(`UPDATE baselines SET targets = ? WHERE id = ?`, `{"all":true,"os":"windows"}`, created.ID); err != nil {
		t.Fatal(err)
	}
	if st, data := b.do("DELETE", fmt.Sprintf("/api/baselines/%d", created.ID), nil); st != 200 {
		t.Fatalf("delete -> %d: %s", st, data)
	}
	if n := len(openDriftAlerts(t, s, agent.id)); n != 0 {
		t.Fatalf("%d drift alerts outlived the baseline", n)
	}
}
