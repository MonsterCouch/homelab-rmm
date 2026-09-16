package agent

// The guards a baseline must never lose: what the engine does when a
// remediation is declined rather than attempted, what it does with a check
// that ignores its deadline, and the three refusals that stop a
// self-healing agent from healing itself into an unmanaged device.

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/baselines"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// blockingKind ignores its context entirely, which is what a real check does
// when it is inside a blocking system call: Lstat on a hung mount, an SCM
// query on a wedged service.
type blockingKind struct {
	block time.Duration
	done  chan struct{}
}

func (b *blockingKind) impl() *kindImpl {
	return &kindImpl{check: func(context.Context, *checkCtx) kindResult {
		time.Sleep(b.block)
		close(b.done)
		return blPass("never", "reached")
	}}
}

func TestBaselineSkippedFixLeavesTheCheckFailingWithNoHoldOff(t *testing.T) {
	// A32: a remediation the agent declined to START (a live script run, an
	// open shell, one reboot a day) leaves the state alone. Reporting `error`
	// instead would flap fail -> error -> fail on every pass of a device
	// somebody runs scripts on, writing a history row and resetting `since`
	// each time.
	f := &fakeKind{
		answers: []kindResult{blFail("running", "stopped", "the service is stopped")},
		fixErr:  skipf("a script run is in progress on this device; the fix will be retried on the next pass"),
	}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	r := onlyResult(t, e.runPass(context.Background(), spec(1, true, check(7, "fake")), baselines.TriggerSchedule, passOpts{}))
	if r.State != baselines.StateFail {
		t.Fatalf("a declined fix keeps the state the check found, got %q", r.State)
	}
	if r.Fixed {
		t.Fatal("nothing ran, so the result must not claim a remediation did")
	}
	if !strings.Contains(r.Detail, "script run is in progress") {
		t.Fatalf("the reason must reach the operator: %q", r.Detail)
	}
	if !strings.Contains(r.Detail, "the service is stopped") {
		t.Fatalf("the check's own detail must survive the refusal: %q", r.Detail)
	}
	if e.holdUntil(7) != 0 {
		t.Fatal("a fix that never started must not start an hour of silence")
	}
}

func TestBaselineBusyFixIsAnErrorThatClaimsNothing(t *testing.T) {
	// The other half of A32: the package database is held by a patch install,
	// which IS an error, but still nothing ran.
	f := &fakeKind{
		answers: []kindResult{blFail("present", "absent", "")},
		fixErr:  busyf("another package operation is in progress"),
	}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	r := onlyResult(t, e.runPass(context.Background(), spec(1, true, check(7, "fake")), baselines.TriggerSchedule, passOpts{}))
	if r.State != baselines.StateError || r.Fixed {
		t.Fatalf("expected an error that claims no remediation, got %+v", r)
	}
	if e.holdUntil(7) != 0 {
		t.Fatal("a fix that never started must not start an hour of silence")
	}
}

func TestBaselineCheckThatIgnoresItsDeadlineCannotStopTheEngine(t *testing.T) {
	// The pass gives up at the check's timeout even when the kind is stuck in
	// a system call no context can interrupt, and the NEXT check still runs.
	b := &blockingKind{block: 30 * time.Second, done: make(chan struct{})}
	f := &fakeKind{}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	e.kinds = func(kind string) *kindImpl {
		if kind == "stuck" {
			return b.impl()
		}
		return f.impl()
	}
	sp := spec(1, false, check(7, "stuck"), check(8, "fake"))
	sp.Checks[0].TimeoutSec = 5

	start := time.Now()
	rep := e.runPass(context.Background(), sp, baselines.TriggerSchedule, passOpts{})
	elapsed := time.Since(start)
	if elapsed > 20*time.Second {
		t.Fatalf("the stuck check held the engine for %s", elapsed)
	}
	if len(rep.Results) != 2 {
		t.Fatalf("the pass must continue with the next check: %+v", rep.Results)
	}
	if rep.Results[0].State != baselines.StateError || !strings.Contains(rep.Results[0].Detail, "timed out after 5s") {
		t.Fatalf("the stuck check must report the timeout the contract names: %+v", rep.Results[0])
	}
	if rep.Results[1].State != baselines.StatePass {
		t.Fatalf("the second check must still have run: %+v", rep.Results[1])
	}
	select {
	case <-b.done:
	case <-time.After(60 * time.Second):
		t.Fatal("the abandoned check goroutine never finished")
	}
}

func TestBaselineParamsFromANewerServerAreNotDrift(t *testing.T) {
	// A28/A42: an agent older than the server meets params keys it has never
	// heard of. Reporting `error` would open a drift alert on every matched
	// device the moment a new field ships.
	f := &fakeKind{answers: []kindResult{blPass("ok", "ok")}}
	e, _ := testEngine(t, map[string]*fakeKind{"disk_free": f})
	ck := check(7, "disk_free")
	ck.Params = json.RawMessage(`{"mount":"/","min_free_pct":10,"min_free_inodes_pct":5}`)
	r := onlyResult(t, e.runPass(context.Background(), spec(1, false, ck), baselines.TriggerSchedule, passOpts{}))
	if r.State != baselines.StatePass {
		t.Fatalf("a params key this build does not know must be ignored, not reported as drift: %+v", r)
	}
	// The same params through the WRITER's validator is still a 400.
	if err := baselines.ValidateCheck("disk_free", ck.Params); err == nil {
		t.Fatal("the server must still refuse an unknown key so a console typo is caught")
	}
	// And a rule that is not about unknown keys is still enforced on both.
	bad := json.RawMessage(`{"mount":"/","min_free_pct":0}`)
	if err := baselines.ValidateCheckLenient("disk_free", bad); err == nil {
		t.Fatal("the agent must still enforce the real parameter rules")
	}
}

func TestBaselineInvalidParamsStillReportAnError(t *testing.T) {
	f := &fakeKind{answers: []kindResult{blPass("ok", "ok")}}
	e, _ := testEngine(t, map[string]*fakeKind{"disk_free": f})
	ck := check(7, "disk_free")
	ck.Params = json.RawMessage(`{"mount":"","min_free_pct":200}`)
	r := onlyResult(t, e.runPass(context.Background(), spec(1, false, ck), baselines.TriggerSchedule, passOpts{}))
	if r.State != baselines.StateError || !strings.Contains(r.Detail, "mount") {
		t.Fatalf("invalid parameters are an error naming the field, got %+v", r)
	}
	if checks, _ := f.counts(); checks != 0 {
		t.Fatal("a check with invalid parameters must not reach the device")
	}
}

func TestBaselineAgentsOwnServiceIsNeverRemediated(t *testing.T) {
	for _, name := range []string{ServiceName, strings.ToLower(ServiceName), ServiceName + ".service", " " + ServiceName + " "} {
		if !blIsOwnService(name) {
			t.Fatalf("%q must be recognised as the agent's own service", name)
		}
	}
	for _, name := range []string{"Spooler", "sshd", "HomelabRMMAgentHelper", ""} {
		if blIsOwnService(name) {
			t.Fatalf("%q is not the agent's own service", name)
		}
	}
}

func TestBaselinePreviewDoesNotRecordAPendingReboot(t *testing.T) {
	e, now := testEngine(t, nil)
	// A preview answers with "as of now" but writes nothing down (A8).
	if got := e.pendingSince(true, true); got != now.Unix() {
		t.Fatalf("a preview must answer with the current time, got %d", got)
	}
	e.mu.Lock()
	recorded := e.rebootSince
	e.mu.Unlock()
	if recorded != 0 {
		t.Fatalf("a preview must not record the first sighting, got %d", recorded)
	}
	// A real pass does record it, and keeps it across later passes.
	first := e.pendingSince(true, false)
	*now = now.Add(2 * time.Hour)
	if again := e.pendingSince(true, false); again != first {
		t.Fatalf("the first sighting must not move: %d -> %d", first, again)
	}
	if cleared := e.pendingSince(false, false); cleared != 0 {
		t.Fatalf("no pending reboot clears the bookkeeping, got %d", cleared)
	}
}

func TestGroupPlanNeverRemovesANameItCannotPassSafely(t *testing.T) {
	// The member list comes from the DEVICE, not from the check, so it has
	// never been through the server's validator. "gpasswd -d -x sudo" is what
	// a name beginning with a dash would become.
	p := baselines.GroupMembersParams{Group: "sudo", Allowed: []string{"root"}}
	plan := planGroupMembers("sudo", []string{"root", "alice", "-x", "/delete"}, p, groupGuard{Builtin: []string{"root"}})
	if len(plan.Remove) != 1 || plan.Remove[0] != "alice" {
		t.Fatalf("only the safe name may be removed, got %+v", plan.Remove)
	}
	for _, n := range []string{"-x", "/delete"} {
		if !inFold(plan.Kept, n) {
			t.Fatalf("%q must be reported as drift and left alone: %+v", n, plan.Kept)
		}
		if plan.Reasons[n] == "" {
			t.Fatalf("a kept name needs a reason the operator can read: %+v", plan.Reasons)
		}
	}
	if !plan.Drifted(p.EffectiveMode()) {
		t.Fatal("the unsafe names are still drift")
	}
}

func TestWinStartTypeOK(t *testing.T) {
	cases := []struct {
		want, got string
		ok        bool
	}{
		{"", "auto", true},
		{"any", "manual", true},
		{"any", "disabled", true},
		{"auto", "auto", true},
		{"auto", "auto_delayed", true}, // A37(a): never clear a delayed start
		{"auto", "manual", false},
		{"manual", "manual", true},
		{"manual", "auto", false},
		{"disabled", "disabled", true},
		// A37(b): a driver's start type satisfies nothing, not even "any".
		{"any", "boot", false},
		{"", "system", false},
		{"auto", "boot", false},
		{"disabled", "system", false},
		{"any", "unknown", false},
		{"any", "", false},
	}
	for _, c := range cases {
		if got := winStartTypeOK(c.want, c.got); got != c.ok {
			t.Errorf("winStartTypeOK(%q, %q) = %v, want %v", c.want, c.got, got, c.ok)
		}
	}
}

func TestWinValidServiceName(t *testing.T) {
	for _, n := range []string{"Spooler", "w32time", "HomelabRMMAgent"} {
		if !winValidServiceName(n) {
			t.Errorf("%q is a valid service name", n)
		}
	}
	for _, n := range []string{"", "   ", `C:\evil.exe`, "a/b", strings.Repeat("x", 257)} {
		if winValidServiceName(n) {
			t.Errorf("%q must be refused before it reaches the SCM", n)
		}
	}
}

func TestBaselineReportKeepsEveryStateLegal(t *testing.T) {
	// Whatever a kind answers, the server must never store an empty state:
	// a result with "" would be a row no compliance sum can classify.
	f := &fakeKind{answers: []kindResult{{state: "", expected: "x", observed: "y"}}}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	rep := e.runPass(context.Background(), spec(1, true, check(7, "fake")), baselines.TriggerSchedule, passOpts{})
	for _, r := range rep.Results {
		if !baselines.ValidState(r.State) {
			t.Fatalf("illegal state %q reached the wire: %+v", r.State, r)
		}
	}
}

func TestBaselineEveryResultCarriesItsCheckID(t *testing.T) {
	f := &fakeKind{answers: []kindResult{blFail("x", "y", "")}}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	sp := spec(1, false, check(-1, "fake"), check(-2, "fake"))
	rep := e.runPass(context.Background(), sp, baselines.TriggerPreview, passOpts{preview: true})
	var ids []int64
	for _, r := range rep.Results {
		ids = append(ids, r.CheckID)
	}
	if len(ids) != 2 || ids[0] != -1 || ids[1] != -2 {
		t.Fatalf("the synthetic preview ids must come back unchanged and in order: %+v", ids)
	}
	if rep.Version != sp.Version || rep.BaselineID != sp.ID {
		t.Fatalf("a report echoes the baseline and version it evaluated: %+v", rep)
	}
	var _ protocol.BaselineReport = *rep
}

func TestBaselineStalePreviewIsNotRunLate(t *testing.T) {
	// A preview runs the operator's own `command` check scripts. One that
	// reaches the head of the queue minutes after the console gave up is
	// work nobody is waiting for, so it is dropped rather than executed.
	f := &fakeKind{}
	e, now := testEngine(t, map[string]*fakeKind{"fake": f})
	req := &baselineReq{
		kind:    "preview",
		spec:    spec(-1, false, check(-1, "fake")),
		reply:   make(chan *protocol.BaselineReport, 1),
		expires: now.Add(30 * time.Second),
	}
	*now = now.Add(time.Hour)
	e.serve(context.Background(), req)
	select {
	case rep := <-req.reply:
		if rep != nil {
			t.Fatalf("a preview past its deadline must not run: %+v", rep)
		}
	default:
		t.Fatal("the caller must always be answered, even with nothing")
	}
	if checks, _ := f.counts(); checks != 0 {
		t.Fatal("a stale preview must not touch the device")
	}
}

func TestBaselineEvaluateRefusalIsAnErrorNotAnAck(t *testing.T) {
	// The server passes a nil reply target for baseline.evaluate: it reads
	// the envelope's error, never the ACK body. An agent that answered a
	// full queue with {"accepted":false} would have the console report the
	// device as queued when it refused.
	f := &fakeKind{}
	e, _ := testEngine(t, map[string]*fakeKind{"fake": f})
	e.setSpecs([]protocol.BaselineSpec{spec(1, false, check(7, "fake"))})
	for i := 0; i < cap(e.reqs); i++ {
		if err := e.enqueue(&baselineReq{kind: "evaluate"}); err != nil {
			t.Fatalf("filling the queue at %d: %v", i, err)
		}
	}
	if _, err := e.requestEvaluate(nil); err == nil {
		t.Fatal("a refused evaluate must come back as an error")
	}
	if _, err := e.requestRemediate(protocol.BaselineRemediate{BaselineID: 1}); err == nil {
		t.Fatal("a refused remediate must come back as an error")
	}
}

// A34's device-side backstop compared two SPELLINGS of a path, and a
// filesystem has more than one name for the same directory: an NTFS 8.3 short
// name (C:\ProgramData\HOMELA~1 is C:\ProgramData\HomelabRMM), a symlinked
// install path, a different case. The agent is the only side that can resolve
// them, so both sides of the comparison go through the filesystem first.
func TestBaselineFilePathRefusesTheConfigDirUnderAnotherName(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real-config")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link-config")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("this platform will not let the test make a symlink: %v", err)
	}
	// The agent knows its directory by the link; the baseline names the same
	// directory by its real path, whose own parents hold no symlink at all -
	// so nothing but the canonicalised comparison can refuse it.
	t.Setenv(EnvConfigDir, link)
	err := blFilePathSafe(baselines.FileParams{Path: filepath.Join(real, "agent.json"), State: "present", Content: "{}"})
	if err == nil {
		t.Fatal("a baseline reached the agent's own configuration directory by another name")
	}
	if !strings.Contains(err.Error(), "configuration directory") {
		t.Errorf("the refusal must name the reason, got %v", err)
	}
	// A neighbour that merely starts with the same characters is not inside
	// it and stays manageable.
	if err := blFilePathSafe(baselines.FileParams{Path: real + "-notes.txt", State: "present", Content: "x"}); err != nil {
		t.Errorf("a file beside the configuration directory is a legitimate target: %v", err)
	}
}

func TestBlCanonPath(t *testing.T) {
	// The longest existing ancestor is resolved and the rest is appended, so
	// a file a baseline is about to CREATE is still compared by its real
	// parent directory.
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(sub)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := blCanonPath(filepath.Join(sub, "not-yet.txt")), filepath.Join(resolved, "not-yet.txt"); got != want {
		t.Errorf("blCanonPath = %q, want %q", got, want)
	}

	// The resolver's answer is used for the part that exists, whatever the
	// caller spelled (this is what expands an 8.3 short name on Windows).
	fake := func(p string) (string, error) {
		if filepath.Base(p) == "HOMELA~1" {
			return filepath.Join(filepath.Dir(p), "HomelabRMM"), nil
		}
		return "", errors.New("does not exist")
	}
	got := blCanonPathWith(filepath.Join("C:", "ProgramData", "HOMELA~1", "agent.json"), fake)
	if want := filepath.Join("C:", "ProgramData", "HomelabRMM", "agent.json"); got != want {
		t.Errorf("blCanonPathWith = %q, want %q", got, want)
	}
	// A path nothing can resolve is returned untouched rather than mangled
	// into something that would compare equal to the wrong thing.
	never := func(string) (string, error) { return "", errors.New("no") }
	if got := blCanonPathWith("/no/such/place/file.txt", never); got != "/no/such/place/file.txt" {
		t.Errorf("an unresolvable path must come back unchanged, got %q", got)
	}
}

// The kinds live behind build tags - a Windows test binary cannot call
// lnxSysctlCheck and a Linux one cannot call winFeatureCheck - so the only
// way to hold every kind to the same rule from either GOOS is to read the
// source. The rule is the one probe depends on: a check publishes the label
// it would have reported before it starts work, so that a check the engine
// abandons at its deadline still tells the operator what it was waiting for
// instead of leaving an empty cell in the status matrix and in the drift
// alert.
func TestEveryBaselineKindPublishesItsExpectedLabel(t *testing.T) {
	for _, name := range []string{"baseline_kinds.go", "baseline_linux.go", "baseline_windows.go"} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		found := 0
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil || !isKindCheckFunc(fn) {
				continue
			}
			found++
			if !publishesExpected(fn.Body) {
				t.Errorf("%s: %s never calls c.setExpected, so a run abandoned at the engine's deadline reports an empty expected", name, fn.Name.Name)
			}
		}
		if found == 0 {
			t.Errorf("%s: found no kind check functions - has the signature changed?", name)
		}
	}
}

// isKindCheckFunc reports whether fn has kindImpl.check's signature:
// func(context.Context, *checkCtx) kindResult.
func isKindCheckFunc(fn *ast.FuncDecl) bool {
	res := fn.Type.Results
	if res == nil || len(res.List) != 1 || len(res.List[0].Names) != 0 || astTypeName(res.List[0].Type) != "kindResult" {
		return false
	}
	var params []string
	for _, p := range fn.Type.Params.List {
		n := len(p.Names)
		if n == 0 {
			n = 1
		}
		for i := 0; i < n; i++ {
			params = append(params, astTypeName(p.Type))
		}
	}
	return len(params) == 2 && params[0] == "context.Context" && params[1] == "*checkCtx"
}

// publishesExpected reports whether the body calls c.setExpected as a
// statement of its own, not inside a branch: the label has to be published on
// every path that goes on to touch the OS.
func publishesExpected(body *ast.BlockStmt) bool {
	for _, st := range body.List {
		expr, ok := st.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := expr.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "setExpected" {
			continue
		}
		if recv, ok := sel.X.(*ast.Ident); ok && recv.Name == "c" {
			return true
		}
	}
	return false
}

func astTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + astTypeName(t.X)
	case *ast.SelectorExpr:
		return astTypeName(t.X) + "." + t.Sel.Name
	}
	return ""
}
