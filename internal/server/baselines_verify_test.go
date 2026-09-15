package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// ---- the preview route is part of authoring, so it carries the same gate ----

// A `command` check runs as SYSTEM/root on the devices it is previewed on.
// The save path refuses one from a non-admin; if the preview route does not,
// the gate is decoration - the same script runs, on the devices of the
// caller's choosing, with nothing in the audit log to say a script ran.
func TestBaselinePreviewCommandCheckNeedsAdmin(t *testing.T) {
	_, ts, b, agent := newBaselineFixture(t)
	b.mustJSON("POST", "/api/users", map[string]string{"username": "tech", "password": "password123", "role": "tech"}, nil)
	tech := newBrowser(t, ts)
	tech.mustJSON("POST", "/api/auth/login", map[string]string{"username": "tech", "password": "password123"}, nil)

	draft := map[string]any{
		"spec": map[string]any{"name": "draft", "checks": []tCheck{
			{Name: "rce", Kind: "command", Params: json.RawMessage(`{"language":"bash","check":"id"}`), Severity: "warning"},
		}},
		"agent_ids": []string{agent.id},
	}
	if st, data := tech.do("POST", "/api/baselines/preview", draft); st != http.StatusForbidden {
		t.Fatalf("tech previewing a command check -> %d: %s", st, data)
	}
	// The same draft with a `file` check outside the managed trees, which is
	// the other admin-only reason, and an allow_reboot check.
	outside := map[string]any{
		"spec": map[string]any{"name": "draft", "checks": []tCheck{
			{Name: "hook", Kind: "file", Params: json.RawMessage(`{"path":"/usr/local/bin/hook.sh","state":"present","content":"x"}`), Severity: "warning"},
		}},
		"agent_ids": []string{agent.id},
	}
	if st, data := tech.do("POST", "/api/baselines/preview", outside); st != http.StatusForbidden {
		t.Fatalf("tech previewing a file check outside /etc -> %d: %s", st, data)
	}
	// A check a tech may save, it may also preview.
	ok := map[string]any{
		"spec":      map[string]any{"name": "draft", "checks": []tCheck{firewallCheck("Firewall on")}},
		"agent_ids": []string{agent.id},
	}
	if st, data := tech.do("POST", "/api/baselines/preview", ok); st != 200 {
		t.Fatalf("tech previewing an ordinary check -> %d: %s", st, data)
	}
	// An admin may, and the run is audited as a command check even though no
	// baseline exists to hang it on.
	if st, data := b.do("POST", "/api/baselines/preview", draft); st != 200 {
		t.Fatalf("admin previewing a command check -> %d: %s", st, data)
	}
	var audit []struct {
		User    string `json:"user"`
		Action  string `json:"action"`
		Details string `json:"details"`
	}
	b.mustJSON("GET", "/api/audit?limit=200", nil, &audit)
	found := false
	for _, a := range audit {
		if a.Action == "baseline.command_check" && strings.Contains(a.Details, `"preview":true`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("a previewed command check must be audited as baseline.command_check: %+v", audit)
	}
}

// ---- a hostile or buggy agent cannot steer the store ----

// Everything a report can carry that does not belong to this baseline at this
// version has to be dropped without touching a stored row: the device sending
// it is the one thing on the wire that is not the operator.
func TestBaselineHostileReportIsIgnored(t *testing.T) {
	s, _, b, agent := newBaselineFixture(t)
	mine := createBaseline(t, b, tBaseline{Name: "mine", Targets: Targets{All: true}, Enabled: true, IntervalSec: 3600,
		Checks: []tCheck{firewallCheck("Firewall on"), timeSyncCheck("Time sync")}})
	other := createBaseline(t, b, tBaseline{Name: "other", Targets: Targets{All: true}, Enabled: true, IntervalSec: 3600,
		Checks: []tCheck{firewallCheck("Somebody else's check")}})
	c1, c2 := mine.Checks[0].ID, mine.Checks[1].ID
	foreign := other.Checks[0].ID

	// A good pass first, so there is a row every later frame could damage.
	agent.sendBaselineReport(blReport(mine.ID, mine.Version, blResult(c1, "pass"), blResult(c2, "pass")))
	waitFor(t, "first pass", func() bool { return len(resultsFor(t, s, mine.ID, agent.id)) == 2 })
	history := historyCount(t, s, agent.id)

	// Ids that are not this baseline's live checks: unknown, zero, negative
	// (a preview id), and one belonging to another baseline.
	rep := blReport(mine.ID, mine.Version,
		blResult(999999, "fail"), blResult(0, "fail"), blResult(-1, "fail"), blResult(foreign, "fail"))
	agent.sendBaselineReport(rep)
	// A frame the server accepts stamps baseline_state, so waiting for the
	// state row proves the frame was processed rather than still in flight.
	waitFor(t, "hostile frame processed", func() bool {
		st, ok := s.db.baselineStateFor(agent.id, mine.ID)
		return ok && st.LastTrigger == "schedule"
	})
	time.Sleep(50 * time.Millisecond)
	if rs := resultsFor(t, s, mine.ID, agent.id); len(rs) != 2 || rs[c1].State != "pass" || rs[c2].State != "pass" {
		t.Fatalf("results changed by a report full of ids that are not live checks: %+v", rs)
	}
	if rs := resultsFor(t, s, other.ID, agent.id); len(rs) != 0 {
		t.Fatalf("a report for one baseline wrote a result for another: %+v", rs)
	}
	if n := historyCount(t, s, agent.id); n != history {
		t.Fatalf("history rows %d, want %d: a dropped result must not write history", n, history)
	}
	if n := len(openDriftAlerts(t, s, agent.id)); n != 0 {
		t.Fatalf("a dropped result opened %d alerts", n)
	}

	// An OLD version is ignored whole, even the parts that would be legal.
	agent.sendBaselineReport(blReport(mine.ID, mine.Version-1, blResult(c1, "fail"), blResult(c2, "fail")))
	// A version AHEAD of the stored one is ignored too: it can only mean a
	// rolled-back database, and trusting it would store a state for a spec
	// this server has never had.
	agent.sendBaselineReport(blReport(mine.ID, mine.Version+5, blResult(c1, "error"), blResult(c2, "error")))
	// A baseline this device is not assigned at all.
	agent.sendBaselineReport(blReport(mine.ID+9999, mine.Version, blResult(c1, "fail")))
	time.Sleep(150 * time.Millisecond)
	if rs := resultsFor(t, s, mine.ID, agent.id); rs[c1].State != "pass" || rs[c2].State != "pass" {
		t.Fatalf("an out-of-version report was stored: %+v", rs)
	}

	// An illegal state word is stored as `error`, never as "" - no
	// compliance sum, transition or alert path can classify an empty state.
	agent.sendBaselineReport(blReport(mine.ID, mine.Version, blResult(c1, "PWNED"), blResult(c2, "pass")))
	waitFor(t, "illegal state normalised", func() bool {
		return resultsFor(t, s, mine.ID, agent.id)[c1].State == "error"
	})

	// An out-of-order frame at the same version (an older device clock) is
	// ignored by the monotonic guard.
	old := blReport(mine.ID, mine.Version, blResult(c1, "pass"), blResult(c2, "pass"))
	old.TS = time.Now().Add(-2 * time.Hour).Unix()
	agent.sendBaselineReport(old)
	time.Sleep(150 * time.Millisecond)
	if st := resultsFor(t, s, mine.ID, agent.id)[c1].State; st != "error" {
		t.Fatalf("an out-of-order report overwrote a newer one: state %q", st)
	}
}

// A device that repeats one check id many times in one frame must not be able
// to make the server do unbounded work on its single connection.
func TestBaselineOneFrameCannotAskForUnboundedWork(t *testing.T) {
	s, _, b, agent := newBaselineFixture(t)
	created := createBaseline(t, b, tBaseline{Name: "mine", Targets: Targets{All: true}, Enabled: true, IntervalSec: 3600,
		Checks: []tCheck{firewallCheck("Firewall on")}})
	c1 := created.Checks[0].ID

	rep := blReport(created.ID, created.Version)
	for i := 0; i < 5000; i++ {
		state := "fail"
		if i%2 == 0 {
			state = "pass"
		}
		rep.Results = append(rep.Results, blResult(c1, state))
	}
	start := time.Now()
	agent.sendBaselineReport(rep)
	waitFor(t, "the frame is ingested", func() bool { return len(resultsFor(t, s, created.ID, agent.id)) == 1 })
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("5000 repeats of one check took %s", d)
	}
	if st := resultsFor(t, s, created.ID, agent.id)[c1].State; st != "pass" {
		t.Fatalf("the FIRST occurrence must win, got %q", st)
	}
	if n := historyCount(t, s, agent.id); n != 0 {
		t.Fatalf("history rows = %d: a first `pass` is the baseline being established, and the repeats are dropped", n)
	}
}

// ---- concurrency ----

// Twenty consoles pressing Evaluate at once: every answer is a well-formed
// fan-out result, the device gets the requests, and nothing races.
func TestBaselineConcurrentEvaluateRequests(t *testing.T) {
	s, _, b, agent := newBaselineFixture(t)
	created := createBaseline(t, b, tBaseline{Name: "mine", Targets: Targets{All: true}, Enabled: true, IntervalSec: 3600,
		Checks: []tCheck{firewallCheck("Firewall on")}})

	const n = 20
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		bad  []string
		seen int
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, data := b.do("POST", fmt.Sprintf("/api/baselines/%d/evaluate", created.ID), map[string]any{})
			var out struct {
				Queued int `json:"queued"`
				Agents []struct {
					Status string `json:"status"`
				} `json:"agents"`
			}
			mu.Lock()
			defer mu.Unlock()
			if st != 200 {
				bad = append(bad, fmt.Sprintf("status %d: %s", st, data))
				return
			}
			if err := json.Unmarshal(data, &out); err != nil {
				bad = append(bad, "bad json: "+err.Error())
				return
			}
			if len(out.Agents) != 1 || out.Agents[0].Status != "queued" {
				bad = append(bad, fmt.Sprintf("agents %+v", out.Agents))
				return
			}
			seen += out.Queued
		}()
	}
	wg.Wait()
	if len(bad) > 0 {
		t.Fatalf("concurrent evaluates: %v", bad)
	}
	if seen != n {
		t.Fatalf("queued %d of %d", seen, n)
	}
	waitFor(t, "the device saw every request", func() bool { return len(agent.baselineAsks()) >= n })

	// And the reports they produce - all at once, for the same check - leave
	// exactly one row and one alert.
	for i := 0; i < n; i++ {
		agent.sendBaselineReport(blReport(created.ID, created.Version, blResult(created.Checks[0].ID, "fail")))
	}
	waitFor(t, "a drift alert", func() bool { return len(openDriftAlerts(t, s, agent.id)) == 1 })
	time.Sleep(200 * time.Millisecond)
	if got := len(openDriftAlerts(t, s, agent.id)); got != 1 {
		t.Fatalf("%d drift alerts for one drifted check", got)
	}
	if n := historyCount(t, s, agent.id); n != 1 {
		t.Fatalf("history rows = %d, want 1: only the first transition is a change", n)
	}
}

// ---- history is filtered where the rows are ----

// The status view's history drawer asks for ONE baseline. Filtering the newest
// N rows in the browser shows an empty drawer whenever another baseline owns
// them, which on a device with two baselines is most of the time.
func TestBaselineHistoryFiltersByBaseline(t *testing.T) {
	s, _, b, agent := newBaselineFixture(t)
	quiet := createBaseline(t, b, tBaseline{Name: "quiet", Targets: Targets{All: true}, Enabled: true, IntervalSec: 3600,
		Checks: []tCheck{firewallCheck("Firewall on")}})
	noisy := createBaseline(t, b, tBaseline{Name: "noisy", Targets: Targets{All: true}, Enabled: true, IntervalSec: 3600,
		Checks: []tCheck{timeSyncCheck("Time sync")}})

	// One transition on the quiet baseline, then plenty on the noisy one.
	agent.sendBaselineReport(blReport(quiet.ID, quiet.Version, blResult(quiet.Checks[0].ID, "fail")))
	waitFor(t, "the quiet transition", func() bool { return historyCount(t, s, agent.id) == 1 })
	for i := 0; i < 12; i++ {
		// Starts on `fail`, so every report including the first is a
		// transition: a first `pass` is the baseline being established and
		// deliberately writes no row.
		state := "fail"
		if i%2 == 1 {
			state = "pass"
		}
		agent.sendBaselineReport(blReport(noisy.ID, noisy.Version, blResult(noisy.Checks[0].ID, state)))
		want := i + 2
		waitFor(t, "noisy transition", func() bool { return historyCount(t, s, agent.id) >= want })
	}

	var out struct {
		History []BaselineHistoryRow `json:"history"`
	}
	b.mustJSON("GET", fmt.Sprintf("/api/agents/%s/baselines/history?limit=5&baseline_id=%d", agent.id, quiet.ID), nil, &out)
	if len(out.History) != 1 || out.History[0].BaselineID != quiet.ID {
		t.Fatalf("the quiet baseline's history is not there: %+v", out.History)
	}
	// Unfiltered, the same limit is all noise - which is the bug this
	// parameter exists to fix.
	b.mustJSON("GET", fmt.Sprintf("/api/agents/%s/baselines/history?limit=5", agent.id), nil, &out)
	for _, h := range out.History {
		if h.BaselineID == quiet.ID {
			t.Skip("the newest rows still contain the quiet baseline; the filter is untested here")
		}
	}
}

// ---- names are counted the way the message says ----

func TestBaselineNamesAreCountedInCharacters(t *testing.T) {
	_, _, b, _ := newBaselineFixture(t)
	body := func(name string) tBaseline {
		return tBaseline{Name: name, Targets: Targets{All: true}, Enabled: false, Checks: []tCheck{firewallCheck(name)}}
	}
	// 120 Japanese characters are 360 bytes: a byte count refuses this at a
	// third of the limit the console's maxLength enforces.
	long := strings.Repeat("ベ", maxBaselineNameLen)
	if st, data := b.do("POST", "/api/baselines", body(long)); st != 201 {
		t.Fatalf("a %d-character name -> %d: %s", maxBaselineNameLen, st, data)
	}
	if st, _ := b.do("POST", "/api/baselines", body(long+"ベ")); st != 400 {
		t.Fatalf("a %d-character name -> %d, want 400", maxBaselineNameLen+1, st)
	}
	// A name with an emoji, a combining mark and a right-to-left override
	// survives the round trip byte for byte.
	odd := "Ünïcödé ✅ 🚀 ‮evil‬"
	var out baselineDetailOut
	b.mustJSON("POST", "/api/baselines", body(odd), &out)
	if out.Name != odd || out.Checks[0].Name != odd {
		t.Fatalf("name round trip: %q / %q", out.Name, out.Checks[0].Name)
	}
}

// ---- an agent that reports for a baseline it no longer holds ----

func TestBaselineReportAfterUnassignIsDropped(t *testing.T) {
	s, _, b, agent := newBaselineFixture(t)
	created := createBaseline(t, b, tBaseline{Name: "mine", Targets: Targets{All: true}, Enabled: true, IntervalSec: 3600,
		Checks: []tCheck{firewallCheck("Firewall on")}})
	c1 := created.Checks[0].ID
	agent.sendBaselineReport(blReport(created.ID, created.Version, blResult(c1, "fail")))
	waitFor(t, "the drift alert", func() bool { return len(openDriftAlerts(t, s, agent.id)) == 1 })

	// Disabling it takes the device's results and its alert with it...
	putBaseline(t, b, created.ID, tBaseline{Name: "mine", Targets: Targets{All: true}, Enabled: false, IntervalSec: 3600,
		Checks: checksToInput(created.Checks)})
	waitFor(t, "the alert is resolved", func() bool { return len(openDriftAlerts(t, s, agent.id)) == 0 })
	if rs := resultsFor(t, s, created.ID, agent.id); len(rs) != 0 {
		t.Fatalf("a disabled baseline kept its results: %+v", rs)
	}
	// ...and a late report from a device that had not got the message yet
	// must not put them back.
	agent.sendBaselineReport(blReport(created.ID, created.Version, blResult(c1, "fail")))
	time.Sleep(150 * time.Millisecond)
	if rs := resultsFor(t, s, created.ID, agent.id); len(rs) != 0 {
		t.Fatalf("a report for a disabled baseline was stored: %+v", rs)
	}
	if n := len(openDriftAlerts(t, s, agent.id)); n != 0 {
		t.Fatalf("a report for a disabled baseline opened %d alerts", n)
	}
}

// ---- the evaluate fan-out is bounded and says what it did ----

func TestBaselineEvaluateBoundsTheDeviceList(t *testing.T) {
	_, _, b, agent := newBaselineFixture(t)
	created := createBaseline(t, b, tBaseline{Name: "mine", Targets: Targets{All: true}, Enabled: true, IntervalSec: 3600,
		Checks: []tCheck{firewallCheck("Firewall on")}})
	ids := make([]string, maxEvaluateAgents+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("ghost%04d", i)
	}
	st, data := b.do("POST", fmt.Sprintf("/api/baselines/%d/evaluate", created.ID), map[string]any{"agent_ids": ids})
	if st != 400 || !strings.Contains(string(data), "at most") {
		t.Fatalf("an unbounded device list -> %d: %s", st, data)
	}
	// A named device that does not match is answered, not silently skipped.
	var out struct {
		Agents []agentActionOut `json:"agents"`
	}
	b.mustJSON("POST", fmt.Sprintf("/api/baselines/%d/evaluate", created.ID), map[string]any{"agent_ids": []string{agent.id, "ghost"}}, &out)
	if len(out.Agents) != 2 {
		t.Fatalf("both named devices must be answered: %+v", out.Agents)
	}
	for _, a := range out.Agents {
		if a.AgentID == "ghost" && a.Status != "error" {
			t.Fatalf("an unknown device must be reported, not queued: %+v", a)
		}
	}
}

var _ = protocol.TypeBaseline
