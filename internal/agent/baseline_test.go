package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/baselines"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// fakeKind drives the engine's state machine with no operating system behind
// it: a scripted sequence of check answers and a fix that can succeed, fail
// or flip the next answer.
type fakeKind struct {
	mu       sync.Mutex
	answers  []kindResult // consumed in order; the last one repeats
	checks   int
	fixes    int
	fixErr   error
	fixAfter *kindResult // what the check answers once the fix has run
	delay    time.Duration
	noFix    bool
	veto     string
	// label is what a real kind publishes with setExpected before it starts
	// work, so a check abandoned at its deadline still reports it.
	label string
}

func (f *fakeKind) impl() *kindImpl {
	k := &kindImpl{check: f.doCheck}
	if !f.noFix {
		k.fix = f.doFix
	}
	if f.veto != "" {
		k.fixable = func(*checkCtx) (bool, string) { return false, f.veto }
	}
	return k
}

func (f *fakeKind) doCheck(ctx context.Context, c *checkCtx) kindResult {
	if f.label != "" {
		c.setExpected(f.label)
	}
	f.mu.Lock()
	if f.delay > 0 {
		d := f.delay
		f.mu.Unlock()
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return blError("something", "no answer", "")
		}
		f.mu.Lock()
	}
	f.checks++
	if f.fixes > 0 && f.fixAfter != nil {
		r := *f.fixAfter
		f.mu.Unlock()
		return r
	}
	var r kindResult
	switch {
	case len(f.answers) == 0:
		r = blPass("ok", "ok")
	case f.checks <= len(f.answers):
		r = f.answers[f.checks-1]
	default:
		r = f.answers[len(f.answers)-1]
	}
	f.mu.Unlock()
	return r
}

func (f *fakeKind) doFix(ctx context.Context, c *checkCtx) (string, error) {
	f.mu.Lock()
	f.fixes++
	err := f.fixErr
	f.mu.Unlock()
	return "fix ran", err
}

func (f *fakeKind) counts() (checks, fixes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checks, f.fixes
}

// testEngine builds an engine with a temp config directory, a controllable
// clock and no jitter, so a schedule assertion is exact.
func testEngine(t *testing.T, kinds map[string]*fakeKind) (*baselineEngine, *time.Time) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(EnvConfigDir, dir)
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	e := newBaselineEngine(nil)
	e.now = func() time.Time { return now }
	e.jitter = func(time.Duration) time.Duration { return 0 }
	e.kinds = func(kind string) *kindImpl {
		if f, ok := kinds[kind]; ok {
			return f.impl()
		}
		return nil
	}
	return e, &now
}

func spec(id int64, enforce bool, checks ...protocol.BaselineCheck) protocol.BaselineSpec {
	return protocol.BaselineSpec{ID: id, Name: "b", Version: 1, Enforce: enforce, IntervalSec: 3600, Checks: checks}
}

func check(id int64, kind string) protocol.BaselineCheck {
	return protocol.BaselineCheck{ID: id, Name: "c", Kind: kind, Params: json.RawMessage(`{}`), Remediate: true, Severity: "warning", TimeoutSec: 30}
}

func onlyResult(t *testing.T, rep *protocol.BaselineReport) protocol.BaselineResult {
	t.Helper()
	if rep == nil || len(rep.Results) != 1 {
		t.Fatalf("expected one result, got %+v", rep)
	}
	return rep.Results[0]
}

func TestBaselinePassLeavesTheDeviceAlone(t *testing.T) {
	f := &fakeKind{answers: []kindResult{blPass("running", "running")}}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	rep := e.runPass(context.Background(), spec(1, true, check(7, "fake")), baselines.TriggerSchedule, passOpts{})
	r := onlyResult(t, rep)
	if r.State != baselines.StatePass || r.Fixed {
		t.Fatalf("expected a clean pass, got %+v", r)
	}
	if _, fixes := f.counts(); fixes != 0 {
		t.Fatalf("a passing check must not be remediated (%d fixes)", fixes)
	}
	if rep.Version != 1 || rep.Trigger != baselines.TriggerSchedule || rep.BaselineID != 1 {
		t.Fatalf("report envelope is wrong: %+v", rep)
	}
}

func TestBaselineFailBecomesFixed(t *testing.T) {
	pass := blPass("running", "running")
	f := &fakeKind{answers: []kindResult{blFail("running", "stopped", "")}, fixAfter: &pass}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	rep := e.runPass(context.Background(), spec(1, true, check(7, "fake")), baselines.TriggerSchedule, passOpts{})
	r := onlyResult(t, rep)
	if r.State != baselines.StateFixed || !r.Fixed {
		t.Fatalf("expected fixed, got %+v", r)
	}
	if !strings.Contains(r.Detail, "fix ran") {
		t.Fatalf("the fix output belongs in the detail: %q", r.Detail)
	}
	checks, fixes := f.counts()
	if checks != 2 || fixes != 1 {
		t.Fatalf("expected check, fix, re-check; got %d checks and %d fixes", checks, fixes)
	}
	if e.holdUntil(7) != 0 {
		t.Fatal("a successful fix must not set a hold-off")
	}
}

func TestBaselineFixThatDoesNotStickIsAnError(t *testing.T) {
	f := &fakeKind{answers: []kindResult{blFail("running", "stopped", "")}}
	e, now := testEngine(t, map[string]*fakeKind{"fake": f})
	rep := e.runPass(context.Background(), spec(1, true, check(7, "fake")), baselines.TriggerSchedule, passOpts{})
	r := onlyResult(t, rep)
	if r.State != baselines.StateError || !r.Fixed {
		t.Fatalf("expected error after a fix that did not stick, got %+v", r)
	}
	if want := now.Add(baselineHoldoff).Unix(); e.holdUntil(7) != want {
		t.Fatalf("hold-off is %d, want %d", e.holdUntil(7), want)
	}
}

func TestBaselineHoldOffStopsTheNextFixAndManualIgnoresIt(t *testing.T) {
	f := &fakeKind{answers: []kindResult{blFail("running", "stopped", "")}}
	e, now := testEngine(t, map[string]*fakeKind{"fake": f})
	sp := spec(1, true, check(7, "fake"))
	e.runPass(context.Background(), sp, baselines.TriggerSchedule, passOpts{})
	_, fixesAfterFirst := f.counts()

	*now = now.Add(5 * time.Minute)
	rep := e.runPass(context.Background(), sp, baselines.TriggerSchedule, passOpts{})
	r := onlyResult(t, rep)
	if r.State != baselines.StateFail || r.Fixed {
		t.Fatalf("inside the hold-off the check stays failing and untouched: %+v", r)
	}
	if !strings.Contains(r.Detail, "not retrying") {
		t.Fatalf("the hold-off must be visible to the operator: %q", r.Detail)
	}
	if _, fixes := f.counts(); fixes != fixesAfterFirst {
		t.Fatalf("the fix ran again inside the hold-off (%d -> %d)", fixesAfterFirst, fixes)
	}

	// A manual remediation ignores the hold-off, which is the whole point of
	// the button.
	rep = e.runPass(context.Background(), sp, baselines.TriggerRemediate, passOpts{manual: true, fixOnly: map[int64]bool{7: true}})
	if _, fixes := f.counts(); fixes != fixesAfterFirst+1 {
		t.Fatalf("a manual remediation must ignore the hold-off (%d fixes)", fixes)
	}
	if onlyResult(t, rep).State != baselines.StateError {
		t.Fatalf("the fix still does not stick, so the state is error: %+v", rep.Results[0])
	}

	// Past the window the scheduled pass tries again.
	*now = now.Add(baselineHoldoff + time.Minute)
	before := 0
	_, before = f.counts()
	e.runPass(context.Background(), sp, baselines.TriggerSchedule, passOpts{})
	if _, fixes := f.counts(); fixes != before+1 {
		t.Fatalf("after the hold-off the fix must be retried (%d -> %d)", before, fixes)
	}
}

func TestBaselineFixBusyDoesNotHoldOff(t *testing.T) {
	f := &fakeKind{answers: []kindResult{blFail("x", "y", "")}, fixErr: busyf("another package operation is in progress")}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	r := onlyResult(t, e.runPass(context.Background(), spec(1, true, check(7, "fake")), baselines.TriggerSchedule, passOpts{}))
	if r.State != baselines.StateError || !strings.Contains(r.Detail, "another package operation") {
		t.Fatalf("expected a busy error, got %+v", r)
	}
	if e.holdUntil(7) != 0 {
		t.Fatal("a fix that never ran must not start an hour of silence")
	}
}

func TestBaselineNotEnforcedNeverFixes(t *testing.T) {
	f := &fakeKind{answers: []kindResult{blFail("running", "stopped", "")}}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	r := onlyResult(t, e.runPass(context.Background(), spec(1, false, check(7, "fake")), baselines.TriggerSchedule, passOpts{}))
	if r.State != baselines.StateFail || r.Fixed {
		t.Fatalf("an unenforced baseline reports drift and changes nothing: %+v", r)
	}
	if !strings.Contains(r.Detail, "not enforced") {
		t.Fatalf("the reason belongs in the detail: %q", r.Detail)
	}
	if _, fixes := f.counts(); fixes != 0 {
		t.Fatal("an unenforced baseline must not remediate")
	}
}

func TestBaselineRemediateFalseIsRefusedPerCheck(t *testing.T) {
	f := &fakeKind{answers: []kindResult{blFail("x", "y", "")}}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	ck := check(7, "fake")
	ck.Remediate = false
	r := onlyResult(t, e.runPass(context.Background(), spec(1, true, ck), baselines.TriggerSchedule, passOpts{}))
	if r.State != baselines.StateFail || !strings.Contains(r.Detail, "remediation is disabled") {
		t.Fatalf("expected a refusal naming the check setting, got %+v", r)
	}
	if _, fixes := f.counts(); fixes != 0 {
		t.Fatal("remediate:false must be honoured by the agent too")
	}
}

func TestBaselinePreviewNeverFixes(t *testing.T) {
	f := &fakeKind{answers: []kindResult{blFail("running", "stopped", "")}}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	sp := spec(1, true, check(7, "fake")) // enforced, remediate on: the worst case
	rep := e.runPass(context.Background(), sp, baselines.TriggerPreview, passOpts{preview: true})
	r := onlyResult(t, rep)
	if r.State != baselines.StateFail || r.Fixed {
		t.Fatalf("a preview reports fail and fixes nothing: %+v", r)
	}
	if _, fixes := f.counts(); fixes != 0 {
		t.Fatal("a preview must never run a fix")
	}
	if e.holdUntil(7) != 0 {
		t.Fatal("a preview must not touch the hold-off table")
	}
	if _, err := os.Stat(baselineStatePath()); !os.IsNotExist(err) {
		t.Fatal("a preview must not write the state file")
	}
}

func TestBaselineOSFilterAndUnknownKindAreSkipped(t *testing.T) {
	f := &fakeKind{}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	other := "windows"
	if hostGOOS() == "windows" {
		other = "linux"
	}
	ck := check(7, "fake")
	ck.OSFilter = other
	r := onlyResult(t, e.runPass(context.Background(), spec(1, true, ck), baselines.TriggerSchedule, passOpts{}))
	if r.State != baselines.StateSkipped || !strings.Contains(r.Observed, "os_filter") {
		t.Fatalf("an os_filter miss is skipped: %+v", r)
	}
	if checks, _ := f.counts(); checks != 0 {
		t.Fatal("a skipped check must not run")
	}
	r = onlyResult(t, e.runPass(context.Background(), spec(1, true, check(8, "quantum")), baselines.TriggerSchedule, passOpts{}))
	if r.State != baselines.StateSkipped || !strings.Contains(r.Observed, "not supported by agent") {
		t.Fatalf("an unknown kind is skipped with an upgrade hint, never error: %+v", r)
	}
}

func TestBaselineCheckTimeoutIsAnError(t *testing.T) {
	f := &fakeKind{delay: 2 * time.Second, label: "running / auto"}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	ck := check(7, "fake")
	ck.TimeoutSec = 5 // clamped up from anything smaller
	sp := spec(1, false, ck)
	sp.Checks[0].TimeoutSec = 5
	// Shorten the deadline by giving the kind more work than the clamp.
	f.delay = 6 * time.Second
	start := time.Now()
	r := onlyResult(t, e.runPass(context.Background(), sp, baselines.TriggerSchedule, passOpts{}))
	if r.State != baselines.StateError || !strings.Contains(r.Detail, "timed out after 5s") {
		t.Fatalf("expected a 5 s timeout error, got %+v", r)
	}
	// A timed-out check still says what it was waiting for: an empty
	// `expected` is an empty cell in the status matrix and in the drift alert.
	if r.Expected != "running / auto" {
		t.Fatalf("the timeout must keep the check's expected label, got %q", r.Expected)
	}
	if r.Observed != "no answer" {
		t.Fatalf("a check that never answered observes nothing, got %q", r.Observed)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("the timeout did not bound the check (%s)", d)
	}
}

func TestBaselineKindVetoKeepsTheFailure(t *testing.T) {
	f := &fakeKind{answers: []kindResult{blFail("x", "y", "")}, veto: "sha256 and contains describe a file without saying what it should hold"}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	r := onlyResult(t, e.runPass(context.Background(), spec(1, true, check(7, "fake")), baselines.TriggerSchedule, passOpts{}))
	if r.State != baselines.StateFail || r.Fixed || !strings.Contains(r.Detail, "sha256") {
		t.Fatalf("a kind that cannot fix this check reports fail with the reason: %+v", r)
	}
	if _, fixes := f.counts(); fixes != 0 {
		t.Fatal("the veto must stop the fix")
	}
}

func TestBaselineConfigChangeSchedulesAPassWithinThirtySeconds(t *testing.T) {
	f := &fakeKind{}
	e, now := testEngine(t, map[string]*fakeKind{"fake": f})
	e.jitter = func(d time.Duration) time.Duration { return d } // worst case

	e.setSpecs([]protocol.BaselineSpec{spec(1, false, check(7, "fake"))})
	due := e.due[1]
	if due.Before(now.Add(baselineConfigDelay)) || due.After(now.Add(30*time.Second)) {
		t.Fatalf("a new baseline must be evaluated within 30 s, due at %s (now %s)", due, *now)
	}
	if e.reason[1] != baselines.TriggerConfig {
		t.Fatalf("a pushed baseline runs with the config trigger, got %q", e.reason[1])
	}

	// Claim the pass, so the timer is an interval out, then push the same
	// version again: nothing may move.
	if _, _, ok := e.nextDue(); !ok {
		// The baseline is not due yet at this instant; claim it explicitly.
		e.due[1] = *now
		if _, _, ok := e.nextDue(); !ok {
			t.Fatal("the baseline should have been claimable")
		}
	}
	*now = now.Add(10 * time.Minute)
	e.setSpecs([]protocol.BaselineSpec{spec(1, false, check(7, "fake"))}) // same version
	if e.due[1].Before(now.Add(30 * time.Minute)) {
		t.Fatalf("an unchanged version must not reschedule the baseline (due %s, now %s)", e.due[1], *now)
	}
	bumped := spec(1, false, check(7, "fake"))
	bumped.Version = 2
	e.setSpecs([]protocol.BaselineSpec{bumped})
	if e.due[1].After(now.Add(30 * time.Second)) {
		t.Fatalf("a version bump must schedule a pass within 30 s, due at %s", e.due[1])
	}
	if e.reason[1] != baselines.TriggerConfig {
		t.Fatalf("a version bump runs with the config trigger, got %q", e.reason[1])
	}
}

func TestBaselineVersionBumpClearsHoldOffsAndCache(t *testing.T) {
	f := &fakeKind{answers: []kindResult{blFail("x", "y", "")}}
	e, now := testEngine(t, map[string]*fakeKind{"fake": f})
	e.setSpecs([]protocol.BaselineSpec{spec(1, true, check(7, "fake"))})
	sp := e.specs[1]
	rep := e.runPass(context.Background(), sp, baselines.TriggerStartup, passOpts{})
	e.finishPass(sp, rep)
	if e.holdUntil(7) == 0 || e.last[1] == nil {
		t.Fatal("the failing pass should have left a hold-off and a cached report")
	}
	*now = now.Add(time.Minute)
	bumped := spec(1, true, check(7, "fake"))
	bumped.Version = 3
	e.setSpecs([]protocol.BaselineSpec{bumped})
	if e.holdUntil(7) != 0 {
		t.Fatal("a version bump means the params may have changed: the hold-off is stale")
	}
	if e.last[1] != nil {
		t.Fatal("a cached report for an older version must not be re-sent as if it were current")
	}
}

func TestBaselineUnassignStopsEverything(t *testing.T) {
	f := &fakeKind{}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	e.setSpecs([]protocol.BaselineSpec{spec(1, false, check(7, "fake")), spec(2, false, check(8, "fake"))})
	e.setHold(7, e.now().Add(time.Hour).Unix())
	e.setSpecs([]protocol.BaselineSpec{spec(2, false, check(8, "fake"))})
	if _, ok := e.specs[1]; ok {
		t.Fatal("a baseline that left the pushed set must be dropped")
	}
	if _, ok := e.due[1]; ok {
		t.Fatal("its timer must be dropped")
	}
	if e.holdUntil(7) != 0 {
		t.Fatal("its hold-offs must be dropped")
	}
	// An empty push clears the lot: "no baselines" arrives as an absent field.
	e.setSpecs(nil)
	if len(e.specs) != 0 || len(e.due) != 0 {
		t.Fatalf("an empty config must clear every assignment, left %d", len(e.specs))
	}
}

func TestBaselineFinishPassDiscardsAReportForAnEditedBaseline(t *testing.T) {
	f := &fakeKind{}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	sp := spec(1, false, check(7, "fake"))
	e.setSpecs([]protocol.BaselineSpec{sp})
	rep := e.runPass(context.Background(), sp, baselines.TriggerSchedule, passOpts{})
	bumped := sp
	bumped.Version = 2
	e.setSpecs([]protocol.BaselineSpec{bumped})
	e.finishPass(sp, rep)
	if e.last[1] != nil {
		t.Fatal("a report for a version that is no longer current must be discarded")
	}
}

func TestBaselineStateFileRoundTrip(t *testing.T) {
	f := &fakeKind{answers: []kindResult{blFail("x", "y", "")}}
	e, now := testEngine(t, map[string]*fakeKind{"fake": f})
	sp := spec(1, true, check(7, "fake"))
	e.setSpecs([]protocol.BaselineSpec{sp})
	rep := e.runPass(context.Background(), e.specs[1], baselines.TriggerStartup, passOpts{})
	e.finishPass(e.specs[1], rep)

	b, err := os.ReadFile(baselineStatePath())
	if err != nil {
		t.Fatalf("the state file must exist after a pass: %v", err)
	}
	st, _ := os.Stat(baselineStatePath())
	if hostGOOS() != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("the state file must be owner-only, got %v", st.Mode().Perm())
	}
	var f2 baselineStateFile
	if err := json.Unmarshal(b, &f2); err != nil {
		t.Fatal(err)
	}
	if len(f2.Specs) != 1 || f2.LastReports["1"] == nil || len(f2.Holdoff) != 1 {
		t.Fatalf("the state file is missing something: %s", b)
	}

	e2 := newBaselineEngine(nil)
	e2.now = func() time.Time { return *now }
	e2.jitter = func(time.Duration) time.Duration { return 0 }
	e2.kinds = e.kinds
	e2.load()
	if len(e2.specs) != 1 || e2.last[1] == nil || e2.holdUntil(7) == 0 {
		t.Fatalf("the reloaded engine forgot something: specs=%d last=%v hold=%d", len(e2.specs), e2.last[1], e2.holdUntil(7))
	}
	if e2.due[1] != now.Add(baselineStartDelay) {
		t.Fatalf("a reloaded baseline runs its start-up pass, due at %s", e2.due[1])
	}
	if e2.reason[1] != baselines.TriggerStartup {
		t.Fatalf("a reloaded baseline runs with the startup trigger, got %q", e2.reason[1])
	}
}

func TestBaselineUnreadableStateFileIsIgnoredNotFatal(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvConfigDir, dir)
	if err := os.WriteFile(filepath.Join(dir, "baselines.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := newBaselineEngine(nil)
	e.load()
	if len(e.specs) != 0 {
		t.Fatal("a corrupt state file must leave an empty set")
	}
}

func TestBaselineResendRules(t *testing.T) {
	f := &fakeKind{}
	e, now := testEngine(t, map[string]*fakeKind{"fake": f})
	e.setSpecs([]protocol.BaselineSpec{spec(1, false, check(7, "fake")), spec(2, false, check(8, "fake"))})
	old := &protocol.BaselineReport{BaselineID: 1, Version: 1, TS: now.Add(-8 * 24 * time.Hour).Unix(), Trigger: baselines.TriggerSchedule}
	fresh := &protocol.BaselineReport{BaselineID: 2, Version: 1, TS: now.Add(-time.Hour).Unix(), Trigger: baselines.TriggerSchedule}
	e.last[1], e.last[2] = old, fresh
	e.resend() // no socket: nothing panics, and the stale one is dropped
	if e.last[1] != nil {
		t.Fatal("a report older than a week must be dropped rather than re-sent")
	}
	if e.last[2] == nil || e.last[2].TS != fresh.TS || e.last[2].Trigger != baselines.TriggerSchedule {
		t.Fatal("a re-send must keep the original timestamp and trigger")
	}
}

func TestBaselineEvaluateAndRemediateAck(t *testing.T) {
	f := &fakeKind{answers: []kindResult{blFail("x", "y", "")}}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	c1, c2 := check(7, "fake"), check(8, "fake")
	c2.Remediate = false
	e.setSpecs([]protocol.BaselineSpec{spec(1, true, c1, c2)})

	ack, err := e.requestEvaluate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if ack["accepted"] != true {
		t.Fatalf("evaluate must ACK: %+v", ack)
	}
	if ids, _ := ack["baseline_ids"].([]int64); len(ids) != 1 || ids[0] != 1 {
		t.Fatalf("evaluate must name the baselines it queued: %+v", ack)
	}

	// With no cached report there is nothing failing yet, so an empty
	// check list accepts nothing - it must never mean "every check".
	ack2, err := e.requestRemediate(protocol.BaselineRemediate{BaselineID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if ids, _ := ack2["check_ids"].([]int64); len(ids) != 0 {
		t.Fatalf("an empty check list means every FAILING check, got %+v", ids)
	}

	// After a failing pass the same request picks the failing, fixable check.
	e.last[1] = &protocol.BaselineReport{BaselineID: 1, Version: 1, Results: []protocol.BaselineResult{
		{CheckID: 7, State: baselines.StateFail}, {CheckID: 8, State: baselines.StateFail},
	}}
	ack3, err := e.requestRemediate(protocol.BaselineRemediate{BaselineID: 1})
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := ack3["check_ids"].([]int64)
	if len(ids) != 1 || ids[0] != 7 {
		t.Fatalf("a check with remediate:false must be refused, got %+v", ids)
	}
	if _, err := e.requestRemediate(protocol.BaselineRemediate{BaselineID: 99}); err == nil {
		t.Fatal("a baseline this device does not have must be refused")
	}
}

func TestBaselineManualRemediateFixesOnlyTheNamedChecks(t *testing.T) {
	f := &fakeKind{answers: []kindResult{blFail("x", "y", "")}}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	sp := spec(1, false, check(7, "fake"), check(8, "fake")) // NOT enforced
	rep := e.runPass(context.Background(), sp, baselines.TriggerRemediate, passOpts{manual: true, fixOnly: map[int64]bool{8: true}})
	if len(rep.Results) != 2 {
		t.Fatalf("every check is evaluated, only the named one is fixed: %+v", rep.Results)
	}
	if rep.Results[0].Fixed {
		t.Fatal("check 7 was not named and must not be touched")
	}
	if !rep.Results[1].Fixed {
		t.Fatal("check 8 was named and must be remediated even though the baseline is not enforced")
	}
}

func TestBaselineReportIsBounded(t *testing.T) {
	rep := &protocol.BaselineReport{BaselineID: 1}
	for i := 0; i < 64; i++ {
		rep.Results = append(rep.Results, protocol.BaselineResult{
			CheckID: int64(i + 1), State: baselines.StateFail,
			Detail: strings.Repeat("d", 60<<10), Observed: strings.Repeat("o", 200),
		})
	}
	boundReport(rep)
	if n := reportSize(rep); n > baselines.MaxReportBytes {
		t.Fatalf("the report is still %d bytes", n)
	}
	if len(rep.Results) == 0 {
		t.Fatal("bounding must not empty the report")
	}
	for _, r := range rep.Results {
		if r.CheckID <= 0 {
			t.Fatalf("every result must keep a real check id: %+v", r)
		}
	}

	// Details go first; only then whole results, and the loss is stated.
	huge := &protocol.BaselineReport{BaselineID: 1}
	for i := 0; i < 64; i++ {
		huge.Results = append(huge.Results, protocol.BaselineResult{
			CheckID: int64(i + 1), State: baselines.StateFail, Observed: strings.Repeat("o", 60<<10),
		})
	}
	boundReport(huge)
	if reportSize(huge) > baselines.MaxReportBytes {
		t.Fatalf("still too large: %d", reportSize(huge))
	}
	last := huge.Results[len(huge.Results)-1]
	if last.State != baselines.StateError || !strings.Contains(last.Detail, "dropped") {
		t.Fatalf("a truncated report must say so: %+v", last)
	}
}

func TestBaselineResultStringsAreBounded(t *testing.T) {
	f := &fakeKind{answers: []kindResult{{
		state:    baselines.StateFail,
		expected: strings.Repeat("e", 4000),
		observed: strings.Repeat("o", 4000),
		detail:   strings.Repeat("d", 40000),
	}}}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	ck := check(7, "fake")
	ck.Remediate = false
	r := onlyResult(t, e.runPass(context.Background(), spec(1, true, ck), baselines.TriggerSchedule, passOpts{}))
	if len(r.Expected) > baselines.MaxObservedBytes || len(r.Observed) > baselines.MaxObservedBytes {
		t.Fatalf("expected/observed are bounded at %d bytes, got %d/%d", baselines.MaxObservedBytes, len(r.Expected), len(r.Observed))
	}
	if len(r.Detail) > baselines.MaxDetailBytes {
		t.Fatalf("detail is bounded at %d bytes, got %d", baselines.MaxDetailBytes, len(r.Detail))
	}
}

func TestBaselineInvalidParamsAreAnErrorNotAPanic(t *testing.T) {
	e, _ := testEngine(t, nil)
	e.kinds = defaultKindImpl
	ck := protocol.BaselineCheck{ID: 7, Kind: "sysctl", Params: json.RawMessage(`{"key":"NOT A KEY","value":"1"}`), TimeoutSec: 10}
	if !baselines.KindRunsOn("sysctl", hostGOOS()) {
		t.Skip("sysctl is a linux kind")
	}
	r := onlyResult(t, e.runPass(context.Background(), spec(1, true, ck), baselines.TriggerSchedule, passOpts{}))
	if r.State != baselines.StateError || !strings.Contains(r.Detail, "key") {
		t.Fatalf("invalid params are an error naming the field: %+v", r)
	}
}

func TestBaselineEngineLoopRunsAndStops(t *testing.T) {
	f := &fakeKind{}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	e.now = time.Now
	ctx, cancel := context.WithCancel(context.Background())
	e.start(ctx)
	e.mu.Lock()
	e.specs[1] = spec(1, false, check(7, "fake"))
	e.due[1] = time.Now().Add(-time.Second)
	e.mu.Unlock()
	e.poke()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if checks, _ := f.counts(); checks > 0 {
			cancel()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	t.Fatal("the loop never evaluated a due baseline")
}

func TestBaselinePreviewThroughTheQueue(t *testing.T) {
	f := &fakeKind{answers: []kindResult{blFail("x", "y", "")}}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	e.now = time.Now
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.start(ctx)
	sp := spec(-1, true, check(-1, "fake"))
	rep, err := e.preview(ctx, sp)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Trigger != baselines.TriggerPreview || len(rep.Results) != 1 {
		t.Fatalf("unexpected preview report: %+v", rep)
	}
	if rep.Results[0].CheckID != -1 {
		t.Fatalf("the agent treats check ids as opaque, including the synthetic negatives: %+v", rep.Results[0])
	}
	if _, fixes := f.counts(); fixes != 0 {
		t.Fatal("a preview never fixes")
	}
	if len(e.specs) != 0 {
		t.Fatal("a preview must not join the assigned set")
	}
}

// hostGOOS is runtime.GOOS behind a name the tests can read; it keeps the
// import out of the table above.
func hostGOOS() string { return goosName }
