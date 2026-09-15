package agent

// The desired-state engine. One goroutine per agent process evaluates the
// baselines the server assigned to this device - on a timer, offline too -
// fixes the drift it is allowed to fix, and reports every pass with one
// TypeBaseline frame.
//
// Three rules shape the whole file:
//
//   - Passes never overlap. Everything that evaluates or remediates runs on
//     the loop goroutine, so a slow apt install cannot be racing a scheduled
//     pass of another baseline on the same box.
//   - Offline is the normal case, not an error. Specs, the last report per
//     baseline and the fix hold-offs live in baselines.json beside agent.json,
//     are loaded before the first connection and are re-sent once on
//     reconnect, so a device that drifted while the server was down still
//     reports what it saw.
//   - The socket may not exist. a.socket() is nil before the first connection
//     and points at a dead conn while offline; a send failure means "stay
//     cached", never a lost pass.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/baselines"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

const (
	// The start-up pass waits so it does not compete with the first
	// inventory, and jitters so a fleet rebooting together does not arrive
	// as one wave.
	baselineStartDelay  = 20 * time.Second
	baselineStartJitter = 10 * time.Second
	// A config change schedules a pass 5-30 s out, for the same reason: an
	// operator editing one baseline must not make 200 devices evaluate at
	// the same instant.
	baselineConfigDelay  = 5 * time.Second
	baselineConfigJitter = 25 * time.Second
	// A check whose fix failed is left alone for an hour. The window is per
	// check and survives a restart, so a failing destructive fix cannot be
	// retried every time the service comes up.
	baselineHoldoff = 60 * time.Minute
	// A cached report older than this is dropped rather than re-sent: it
	// describes a machine state a week stale.
	baselineResendMaxAge = 7 * 24 * time.Hour
	// At most one baseline-initiated reboot per device per day.
	baselineRebootEvery = 24 * time.Hour
	// Package and feature remediations get their own ceiling; a check
	// timeout of at most 600 s is about the check, not about apt.
	baselineSlowFixTimeout = 15 * time.Minute
	// How long a queued preview stays worth running when the caller gave no
	// deadline. A preview runs the operator's CHECK scripts on the device; a
	// dry run that reaches the head of the queue long after the console
	// stopped listening is work nobody asked for any more.
	baselinePreviewMaxWait = 2 * time.Minute
)

// kindResult is one kind's answer about one check.
type kindResult struct {
	state    string // pass, fail, error, skipped
	expected string
	observed string
	detail   string
}

func blPass(expected, observed string) kindResult {
	return kindResult{state: baselines.StatePass, expected: expected, observed: observed}
}

func blFail(expected, observed, detail string) kindResult {
	return kindResult{state: baselines.StateFail, expected: expected, observed: observed, detail: detail}
}

func blError(expected, observed, detail string) kindResult {
	return kindResult{state: baselines.StateError, expected: expected, observed: observed, detail: detail}
}

func blSkip(observed string) kindResult {
	return kindResult{state: baselines.StateSkipped, observed: observed}
}

// checkCtx is what a kind implementation is handed: the baseline it belongs
// to, the check itself and the engine (for the script runner and the
// persistent scraps a kind needs, such as the reboot bookkeeping).
type checkCtx struct {
	e     *baselineEngine
	spec  *protocol.BaselineSpec
	check *protocol.BaselineCheck
	// preview is set for a dry run. A kind that keeps bookkeeping of its own
	// (reboot_pending remembers when a pending restart was first seen) reads
	// it and stays read-only, because a preview persists nothing (A8).
	preview bool
}

// params decodes the check's parameters leniently: an unknown key is the
// server's problem (it rejects one with a 400), and ignoring it here is what
// lets an older agent keep evaluating a check a newer console extended.
func (c *checkCtx) params(v any) error {
	return baselines.DecodeLenient(c.check.Params, v)
}

// kindImpl is a check kind. fix is nil for the check-only kinds; a kind whose
// fix is nil reports drift as `fail` however enforcing the baseline is.
// fixable is the per-CHECK veto the kind itself casts: a `file` check that
// only knows a sha256 has nothing to write, and a `command` check with no fix
// script has nothing to run. Both are `fail`, not `error`, and the reason
// reaches the operator in the detail column.
type kindImpl struct {
	check   func(ctx context.Context, c *checkCtx) kindResult
	fix     func(ctx context.Context, c *checkCtx) (detail string, err error)
	fixable func(c *checkCtx) (ok bool, why string)
}

// errFixBusy is a fix that did not run because something else on the device
// owns the OS resource it needs - the package database, the servicing stack.
// A32 names that case `error` with the reason in the detail, and it carries
// NO hold-off: the next pass should try again rather than wait an hour.
var errFixBusy = errors.New("busy")

type fixBusyError struct{ msg string }

func (e *fixBusyError) Error() string { return e.msg }
func (e *fixBusyError) Unwrap() error { return errFixBusy }

func busyf(format string, args ...any) error {
	return &fixBusyError{msg: fmt.Sprintf(format, args...)}
}

// errFixSkipped is a fix the agent deliberately did not START, because doing
// so would collide with something the operator is doing right now (a live
// script run, an open shell) or with a rule of its own (one reboot a day).
// A32 is explicit that this leaves the check as it was - `fail`, with the
// reason in the detail - and NOT `error`: a device an operator runs scripts
// on would otherwise flap fail -> error -> fail every interval, writing a
// history row, resetting `since` and re-notifying on each pass. It carries
// no hold-off either.
var errFixSkipped = errors.New("skipped")

type fixSkippedError struct{ msg string }

func (e *fixSkippedError) Error() string { return e.msg }
func (e *fixSkippedError) Unwrap() error { return errFixSkipped }

func skipf(format string, args ...any) error {
	return &fixSkippedError{msg: fmt.Sprintf(format, args...)}
}

// baselineEngine owns every piece of baseline state on the device.
type baselineEngine struct {
	a *Agent

	mu      sync.Mutex
	specs   map[int64]protocol.BaselineSpec
	due     map[int64]time.Time
	reason  map[int64]string // why the next pass was scheduled: config or startup
	last    map[int64]*protocol.BaselineReport
	holdoff map[int64]int64 // check id -> unix seconds until a fix may run again

	lastReboot  int64 // unix; the last reboot this engine triggered
	rebootSince int64 // unix; when a pending reboot was first observed

	reqs chan *baselineReq
	wake chan struct{}

	// fixMu makes remediation single-file across the whole process.
	fixMu sync.Mutex

	// Test seams. now is the clock; kinds resolves a kind to its
	// implementation, so a test can drive the state machine with kinds that
	// have no operating system behind them.
	now    func() time.Time
	jitter func(d time.Duration) time.Duration
	kinds  func(kind string) *kindImpl
}

// baselineReq is a server request that has to run on the engine goroutine.
type baselineReq struct {
	kind     string // evaluate, remediate, preview
	ids      []int64
	baseline int64
	checkIDs []int64
	spec     protocol.BaselineSpec
	reply    chan *protocol.BaselineReport
	// expires is when a queued request stops being worth running. Only a
	// preview sets it: an evaluate or a remediate is an instruction that
	// stays true however long the queue was.
	expires time.Time
}

func newBaselineEngine(a *Agent) *baselineEngine {
	e := &baselineEngine{
		a:       a,
		specs:   map[int64]protocol.BaselineSpec{},
		due:     map[int64]time.Time{},
		reason:  map[int64]string{},
		last:    map[int64]*protocol.BaselineReport{},
		holdoff: map[int64]int64{},
		reqs:    make(chan *baselineReq, 8),
		wake:    make(chan struct{}, 1),
		now:     time.Now,
		jitter:  func(d time.Duration) time.Duration { return time.Duration(rand.Int63n(int64(d) + 1)) },
		kinds:   defaultKindImpl,
	}
	return e
}

// start loads the on-disk state and runs the evaluation loop until ctx ends.
// It is called before the first connection so an agent that boots with no
// server still evaluates what it was last told to.
func (e *baselineEngine) start(ctx context.Context) {
	e.load()
	go e.loop(ctx)
}

func (e *baselineEngine) loop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case r := <-e.reqs:
			e.serve(ctx, r)
		case <-e.wake:
			e.runDue(ctx)
		case <-t.C:
			e.runDue(ctx)
		}
	}
}

func (e *baselineEngine) poke() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// ---- configuration ----

// setSpecs replaces the whole assigned set (A10). A baseline that is gone
// stops immediately: its schedule, its cached report and its checks'
// hold-offs go with it, and an in-flight pass for it is discarded when it
// finishes rather than sent.
func (e *baselineEngine) setSpecs(in []protocol.BaselineSpec) {
	now := e.now()
	e.mu.Lock()
	keep := map[int64]bool{}
	changed := false
	if len(in) > baselines.MaxBaselinesPerAgent {
		slog.Warn("the server pushed more baselines than the contract allows; the extra ones are ignored",
			"pushed", len(in), "limit", baselines.MaxBaselinesPerAgent)
		in = in[:baselines.MaxBaselinesPerAgent]
	}
	for _, s := range in {
		if s.ID <= 0 {
			continue
		}
		s = normaliseSpec(s)
		keep[s.ID] = true
		old, had := e.specs[s.ID]
		e.specs[s.ID] = s
		if !had || old.Version != s.Version {
			changed = true
			// A changed version means the params may have changed, so the
			// hold-offs of this baseline's checks are stale (A31).
			for _, ck := range old.Checks {
				delete(e.holdoff, ck.ID)
			}
			if had && old.Version != s.Version {
				delete(e.last, s.ID)
			}
			e.due[s.ID] = now.Add(baselineConfigDelay + e.jitter(baselineConfigJitter))
			e.reason[s.ID] = baselines.TriggerConfig
		} else if _, ok := e.due[s.ID]; !ok {
			e.due[s.ID] = now.Add(baselineStartDelay + e.jitter(baselineStartJitter))
			e.reason[s.ID] = baselines.TriggerStartup
		}
	}
	for id, s := range e.specs {
		if keep[id] {
			continue
		}
		changed = true
		delete(e.specs, id)
		delete(e.due, id)
		delete(e.reason, id)
		delete(e.last, id)
		for _, ck := range s.Checks {
			delete(e.holdoff, ck.ID)
		}
	}
	e.mu.Unlock()
	e.save()
	if changed {
		e.poke()
	}
}

// normaliseSpec applies the agent-side clamps. The server clamps too; an
// agent that trusts a pushed interval of 1 s would hammer the device.
func normaliseSpec(s protocol.BaselineSpec) protocol.BaselineSpec {
	s.IntervalSec = baselines.ClampInterval(s.IntervalSec)
	checks := make([]protocol.BaselineCheck, 0, len(s.Checks))
	for _, ck := range s.Checks {
		ck.TimeoutSec = baselines.ClampTimeout(ck.TimeoutSec)
		checks = append(checks, ck)
	}
	s.Checks = checks
	return s
}

// ---- scheduling ----

// runDue evaluates every baseline whose timer has expired, one after another
// in id order. The next pass is scheduled an interval after this one
// FINISHED, so a 60 s interval and a 90 s pass do not queue up.
func (e *baselineEngine) runDue(ctx context.Context) {
	for {
		spec, trigger, ok := e.nextDue()
		if !ok {
			return
		}
		rep := e.runPass(ctx, spec, trigger, passOpts{})
		e.finishPass(spec, rep)
		if ctx.Err() != nil {
			return
		}
	}
}

// nextDue claims the next baseline whose timer has expired and says why it is
// running: `config` after an edit, `startup` for a baseline that has never
// reported, `schedule` otherwise.
func (e *baselineEngine) nextDue() (protocol.BaselineSpec, string, bool) {
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()
	ids := make([]int64, 0, len(e.due))
	for id, at := range e.due {
		if !at.After(now) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		s, ok := e.specs[id]
		if !ok {
			delete(e.due, id)
			delete(e.reason, id)
			continue
		}
		trigger := e.reason[id]
		if trigger == "" {
			if _, reported := e.last[id]; reported {
				trigger = baselines.TriggerSchedule
			} else {
				trigger = baselines.TriggerStartup
			}
		}
		// Claim it now so a second call cannot pick the same baseline.
		e.due[id] = now.Add(time.Duration(s.IntervalSec) * time.Second)
		delete(e.reason, id)
		return s, trigger, true
	}
	return protocol.BaselineSpec{}, "", false
}

// finishPass reschedules, caches and sends one completed pass. A report for a
// baseline that was unassigned or edited while the pass ran is dropped.
func (e *baselineEngine) finishPass(spec protocol.BaselineSpec, rep *protocol.BaselineReport) {
	if rep == nil {
		return
	}
	e.mu.Lock()
	cur, ok := e.specs[spec.ID]
	if !ok || cur.Version != spec.Version {
		e.mu.Unlock()
		slog.Debug("baseline report discarded: the assignment changed while the pass ran", "baseline", spec.ID)
		return
	}
	e.due[spec.ID] = e.now().Add(time.Duration(cur.IntervalSec) * time.Second)
	delete(e.reason, spec.ID)
	e.last[spec.ID] = rep
	e.mu.Unlock()
	e.save()
	e.sendReport(rep)
}

// ---- requests from the server ----

// requestEvaluate queues a pass for the named baselines (empty = all) and
// ACKs at once: the report arrives later as its own frame, so the server
// ingests exactly one report per pass (A6). A queue that is full is returned
// as an ERROR, not as an ACK saying accepted:false - the server reads the
// reply's error, not its body, and would otherwise tell the operator the
// device was queued when it refused.
func (e *baselineEngine) requestEvaluate(ids []int64) (map[string]any, error) {
	e.mu.Lock()
	var want []int64
	for id := range e.specs {
		if len(ids) == 0 || containsID(ids, id) {
			want = append(want, id)
		}
	}
	e.mu.Unlock()
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	if want == nil {
		want = []int64{}
	}
	if err := e.enqueue(&baselineReq{kind: "evaluate", ids: want}); err != nil {
		return nil, err
	}
	return map[string]any{"accepted": true, "baseline_ids": want}, nil
}

// requestRemediate queues a remediation pass for one baseline. An empty
// check list means every check that is currently failing and allows a fix -
// never every check (A45). Checks with remediate=false are refused here too,
// not only by the server.
func (e *baselineEngine) requestRemediate(in protocol.BaselineRemediate) (map[string]any, error) {
	e.mu.Lock()
	spec, ok := e.specs[in.BaselineID]
	lastRep := e.last[in.BaselineID]
	e.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("baseline %d is not assigned to this device", in.BaselineID)
	}
	failing := map[int64]bool{}
	if lastRep != nil {
		for _, r := range lastRep.Results {
			if r.State == baselines.StateFail {
				failing[r.CheckID] = true
			}
		}
	}
	var accepted []int64
	for _, ck := range spec.Checks {
		if !ck.Remediate {
			continue
		}
		if len(in.CheckIDs) > 0 {
			if containsID(in.CheckIDs, ck.ID) {
				accepted = append(accepted, ck.ID)
			}
			continue
		}
		if failing[ck.ID] {
			accepted = append(accepted, ck.ID)
		}
	}
	if accepted == nil {
		accepted = []int64{}
	}
	if err := e.enqueue(&baselineReq{kind: "remediate", baseline: in.BaselineID, checkIDs: accepted}); err != nil {
		return nil, err
	}
	return map[string]any{"accepted": true, "baseline_id": in.BaselineID, "check_ids": accepted}, nil
}

// preview evaluates an unsaved spec and returns the report as the reply. It
// is the one case where the reply IS the report and no TypeBaseline frame is
// sent; it never fixes, never persists and never touches the schedule (A8).
func (e *baselineEngine) preview(ctx context.Context, spec protocol.BaselineSpec) (*protocol.BaselineReport, error) {
	// The caller's deadline, measured on the ENGINE's clock so a test with a
	// fixed clock and a real context cannot make every preview look stale.
	expires := e.now().Add(baselinePreviewMaxWait)
	if d, ok := ctx.Deadline(); ok {
		if wait := time.Until(d); wait > 0 && wait < baselinePreviewMaxWait {
			expires = e.now().Add(wait)
		}
	}
	req := &baselineReq{kind: "preview", spec: spec, reply: make(chan *protocol.BaselineReport, 1), expires: expires}
	if err := e.enqueue(req); err != nil {
		return nil, err
	}
	select {
	case rep := <-req.reply:
		if rep == nil {
			return nil, errors.New("the baseline preview did not run")
		}
		return rep, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(10 * time.Minute):
		return nil, errors.New("the baseline preview did not finish in time")
	}
}

func (e *baselineEngine) enqueue(r *baselineReq) error {
	select {
	case e.reqs <- r:
		return nil
	default:
		return errors.New("the agent is already running baseline work; try again shortly")
	}
}

// serve runs one queued request on the loop goroutine.
func (e *baselineEngine) serve(ctx context.Context, r *baselineReq) {
	switch r.kind {
	case "evaluate":
		for _, id := range r.ids {
			e.mu.Lock()
			spec, ok := e.specs[id]
			e.mu.Unlock()
			if !ok {
				continue
			}
			rep := e.runPass(ctx, spec, baselines.TriggerManual, passOpts{})
			e.finishPass(spec, rep)
		}
	case "remediate":
		e.mu.Lock()
		spec, ok := e.specs[r.baseline]
		e.mu.Unlock()
		if !ok {
			return
		}
		opt := passOpts{manual: true, fixOnly: map[int64]bool{}}
		for _, id := range r.checkIDs {
			opt.fixOnly[id] = true
		}
		rep := e.runPass(ctx, spec, baselines.TriggerRemediate, opt)
		e.finishPass(spec, rep)
	case "preview":
		if !r.expires.IsZero() && e.now().After(r.expires) {
			// The console gave up while a pass held the queue. A preview
			// runs the operator's own check scripts; running them now would
			// be work nobody is waiting for.
			select {
			case r.reply <- nil:
			default:
			}
			return
		}
		spec := normaliseSpec(r.spec)
		rep := e.runPass(ctx, spec, baselines.TriggerPreview, passOpts{preview: true})
		select {
		case r.reply <- rep:
		default:
		}
	}
}

// ---- one pass ----

type passOpts struct {
	preview bool
	manual  bool           // a baseline.remediate request
	fixOnly map[int64]bool // manual: the only checks allowed to be fixed
}

func (e *baselineEngine) runPass(ctx context.Context, spec protocol.BaselineSpec, trigger string, opt passOpts) *protocol.BaselineReport {
	rep := &protocol.BaselineReport{
		BaselineID: spec.ID,
		Version:    spec.Version,
		TS:         e.now().Unix(),
		Trigger:    trigger,
		Results:    []protocol.BaselineResult{},
	}
	for i := range spec.Checks {
		if ctx.Err() != nil {
			break
		}
		rep.Results = append(rep.Results, e.evaluateCheck(ctx, &spec, &spec.Checks[i], opt))
	}
	boundReport(rep)
	return rep
}

// evaluateCheck runs one check, remediates it when it is allowed to, and
// re-checks after a fix. Everything it can go wrong with is a result, never
// a panic and never an unvalidated argument on a command line.
func (e *baselineEngine) evaluateCheck(ctx context.Context, spec *protocol.BaselineSpec, ck *protocol.BaselineCheck, opt passOpts) (result protocol.BaselineResult) {
	start := e.now()
	fixed := false
	out := func(r kindResult) protocol.BaselineResult {
		if !baselines.ValidState(r.state) {
			// The five states are the whole vocabulary the server counts,
			// transitions and alerts on. A kind that answered with anything
			// else - a zero kindResult from a path that forgot to set one -
			// must not reach the wire as a row no compliance sum can
			// classify: it is an error, and it says which kind produced it.
			r = blError(r.expected, orText(r.observed, "no answer"),
				joinDetail(r.detail, fmt.Sprintf("the %s check returned no usable state (%q)", ck.Kind, r.state)))
		}
		return protocol.BaselineResult{
			CheckID:    ck.ID,
			State:      r.state,
			Expected:   baselines.Truncate(r.expected, baselines.MaxObservedBytes),
			Observed:   baselines.Truncate(r.observed, baselines.MaxObservedBytes),
			Detail:     baselines.Truncate(r.detail, baselines.MaxDetailBytes),
			Fixed:      fixed,
			DurationMs: e.now().Sub(start).Milliseconds(),
		}
	}
	defer func() {
		// A kind that panics must cost one result, not the agent - and the
		// result still has to be a legal state, or the server stores "".
		if p := recover(); p != nil {
			slog.Error("baseline check panicked", "baseline", spec.ID, "check", ck.ID, "kind", ck.Kind, "panic", p)
			result = out(blError("a check that runs", "the check crashed",
				fmt.Sprintf("the %s check panicked on this device: %v", ck.Kind, p)))
		}
	}()

	if ck.OSFilter != "" && ck.OSFilter != runtime.GOOS {
		return out(blSkip(fmt.Sprintf("os_filter %s does not match %s", ck.OSFilter, runtime.GOOS)))
	}
	impl := e.kinds(ck.Kind)
	if impl == nil {
		return out(blSkip(fmt.Sprintf("kind %s is not supported by agent %s", ck.Kind, Version)))
	}
	if baselines.KindKnown(ck.Kind) {
		// The LENIENT reader: every rule except "no unknown keys", which the
		// server already enforced when the check was written. An agent older
		// than the server must not report `error` for a params field a newer
		// console added (A28).
		if err := baselines.ValidateCheckLenient(ck.Kind, ck.Params); err != nil {
			return out(blError("valid parameters", "invalid parameters", err.Error()))
		}
	}
	timeout := time.Duration(baselines.ClampTimeout(ck.TimeoutSec)) * time.Second
	c := &checkCtx{e: e, spec: spec, check: ck, preview: opt.preview}
	res := e.probe(ctx, impl.check, c, timeout)
	if res.state == baselines.StatePass {
		if !opt.preview {
			e.clearHold(ck.ID)
		}
		return out(res)
	}
	if res.state != baselines.StateFail {
		return out(res)
	}
	if impl.fix == nil {
		if ck.Remediate {
			res.detail = joinDetail(res.detail, "this check kind reports drift but cannot repair it")
		}
		return out(res)
	}
	// Two different "no": the operator's (not enforced, remediate off, still
	// inside a hold-off) and the kind's own (nothing to write, no fix script).
	// The operator's answer comes first, because it is the one they set.
	allow, why := e.fixAllowed(spec, ck, opt)
	if !allow {
		if why != "" {
			res.detail = joinDetail(res.detail, why)
		}
		return out(res)
	}
	if impl.fixable != nil {
		if ok, why := impl.fixable(c); !ok {
			return out(kindResult{state: res.state, expected: res.expected, observed: res.observed, detail: joinDetail(res.detail, why)})
		}
	}
	fixDetail, err := e.remediate(ctx, impl, c, timeout)
	switch {
	case errors.Is(err, errFixSkipped):
		// Nothing was started, so nothing changed and nothing is claimed:
		// the check keeps the state its own probe found (A32).
		return out(blFail(res.expected, res.observed, joinDetail(res.detail, fixDetail, err.Error())))
	case errors.Is(err, errFixBusy):
		// The OS resource is held by another transaction on this device.
		// A32 names this one `error`, with no hold-off.
		return out(blError(res.expected, res.observed, joinDetail(res.detail, fixDetail, err.Error())))
	}
	// Past here a remediation really ran, whatever it achieved.
	fixed = true
	switch {
	case errors.Is(err, errFixPending):
		// The fix started something the device finishes on its own (a
		// restart with a notice). The check still fails; saying "fixed"
		// would be a lie and saying "error" would hide a working remedy.
		e.setHold(ck.ID, start.Add(baselineHoldoff).Unix())
		return out(blFail(res.expected, res.observed, joinDetail(res.detail, fixDetail, err.Error())))
	case err != nil:
		e.setHold(ck.ID, start.Add(baselineHoldoff).Unix())
		return out(blError(res.expected, res.observed, joinDetail(fixDetail, err.Error())))
	}
	after := e.probe(ctx, impl.check, c, timeout)
	switch after.state {
	case baselines.StatePass:
		// A check that passes again clears its hold-off, including the one a
		// manual remediation was asked to ignore.
		e.clearHold(ck.ID)
		return out(kindResult{
			state: baselines.StateFixed, expected: after.expected, observed: after.observed,
			detail: joinDetail(fixDetail, after.detail),
		})
	case baselines.StateSkipped:
		return out(after)
	default:
		e.setHold(ck.ID, start.Add(baselineHoldoff).Unix())
		return out(blError(after.expected, after.observed,
			joinDetail(fixDetail, orText(after.detail, "the fix ran but the check still does not pass"))))
	}
}

// fixAllowed answers "may this drift be repaired right now", and says why not
// when the answer is no. The reason reaches the operator in the detail
// column: a check that silently does not self-heal is a support call.
func (e *baselineEngine) fixAllowed(spec *protocol.BaselineSpec, ck *protocol.BaselineCheck, opt passOpts) (bool, string) {
	if opt.preview {
		return false, "preview: nothing was changed"
	}
	if !ck.Remediate {
		return false, "remediation is disabled for this check"
	}
	if opt.manual {
		if !opt.fixOnly[ck.ID] {
			return false, ""
		}
		return true, ""
	}
	if !spec.Enforce {
		return false, "the baseline is not enforced, so nothing was changed"
	}
	if until := e.holdUntil(ck.ID); until > e.now().Unix() {
		return false, fmt.Sprintf("a previous fix failed; not retrying before %s", time.Unix(until, 0).UTC().Format(time.RFC3339))
	}
	return true, ""
}

// remediate serialises the fix against every other remediation on the device
// and refuses to run one while an operator's script is live.
func (e *baselineEngine) remediate(ctx context.Context, impl *kindImpl, c *checkCtx, timeout time.Duration) (string, error) {
	if e.a != nil && e.a.runs != nil && e.a.runs.live() {
		return "", skipf("a script run is in progress on this device; the fix will be retried on the next pass")
	}
	e.fixMu.Lock()
	defer e.fixMu.Unlock()
	fctx, cancel := context.WithTimeout(e.fixContext(ctx, c.check.Kind), e.fixTimeout(c.check.Kind, timeout))
	defer cancel()
	detail, err := impl.fix(fctx, c)
	if err == nil && fctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("the fix timed out after %s", e.fixTimeout(c.check.Kind, timeout))
	}
	return detail, err
}

// fixContext detaches the slow package-shaped fixes from the caller's
// cancellation for the same reason pmInstall does: SIGKILL in the middle of a
// dpkg or MSI transaction leaves a package database that needs a human.
func (e *baselineEngine) fixContext(ctx context.Context, kind string) context.Context {
	switch kind {
	case "package", "windows_feature":
		return context.WithoutCancel(ctx)
	}
	return ctx
}

func (e *baselineEngine) fixTimeout(kind string, checkTimeout time.Duration) time.Duration {
	switch kind {
	case "package", "windows_feature":
		if checkTimeout < baselineSlowFixTimeout {
			return baselineSlowFixTimeout
		}
	}
	return checkTimeout
}

// probe runs one kind's check under its own deadline and turns an expired one
// into the error the contract names.
//
// The check runs on its own goroutine and the deadline is enforced HERE, not
// only inside the kind. Most of what a check does is a blocking system call -
// Lstat on a hung NFS mount, an SCM query on a wedged service, disk.Usage on
// a disconnected volume - and a context cannot interrupt one. Waiting for it
// on the engine goroutine would stop every other baseline on the device, and
// every queued evaluate and preview with them, for as long as the kernel
// takes. So the pass gives up at the deadline, reports the timeout the
// contract names and moves on; the abandoned goroutine writes to a buffered
// channel nobody reads and ends when its syscall does.
func (e *baselineEngine) probe(ctx context.Context, fn func(context.Context, *checkCtx) kindResult, c *checkCtx, timeout time.Duration) kindResult {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	done := make(chan kindResult, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				done <- blError("a check that runs", "the check crashed",
					fmt.Sprintf("the %s check panicked on this device: %v", c.check.Kind, p))
			}
		}()
		done <- fn(cctx, c)
	}()
	timedOut := func(r kindResult) kindResult {
		return blError(r.expected, orText(r.observed, "no answer"), fmt.Sprintf("timed out after %ds", int(timeout.Seconds())))
	}
	select {
	case r := <-done:
		if cctx.Err() == context.DeadlineExceeded && r.state != baselines.StateSkipped {
			return timedOut(r)
		}
		return r
	case <-cctx.Done():
		if ctx.Err() != nil {
			// The whole agent is shutting down, not one slow check.
			return blError("a check that runs", "no answer", "the agent stopped before the check finished")
		}
		return timedOut(kindResult{})
	}
}

// ---- hold-offs ----

func (e *baselineEngine) holdUntil(checkID int64) int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.holdoff[checkID]
}

func (e *baselineEngine) setHold(checkID, until int64) {
	e.mu.Lock()
	e.holdoff[checkID] = until
	e.mu.Unlock()
	e.save()
}

func (e *baselineEngine) clearHold(checkID int64) {
	e.mu.Lock()
	_, had := e.holdoff[checkID]
	delete(e.holdoff, checkID)
	e.mu.Unlock()
	if had {
		e.save()
	}
}

// ---- sending ----

// sendReport writes one TypeBaseline frame if there is a socket. There is no
// queue: the last report per baseline is the cache, and reconnect re-sends it.
func (e *baselineEngine) sendReport(rep *protocol.BaselineReport) {
	if e.a == nil {
		return
	}
	c := e.a.socket()
	if c == nil {
		slog.Debug("baseline report cached: no connection", "baseline", rep.BaselineID)
		return
	}
	if err := c.send(protocol.Envelope{T: protocol.TypeBaseline, D: protocol.Must(rep)}); err != nil {
		slog.Debug("baseline report cached: send failed", "baseline", rep.BaselineID, "err", err)
	}
}

// resend replays the cached last report per baseline exactly once after a
// reconnect, with its ORIGINAL timestamp, version and trigger, so the server
// can order it against the start-up pass that follows. Reports for baselines
// that are gone or whose version moved on are not re-sent, and one older than
// a week is dropped.
func (e *baselineEngine) resend() {
	now := e.now()
	e.mu.Lock()
	dropped := false
	var out []*protocol.BaselineReport
	for id, rep := range e.last {
		spec, ok := e.specs[id]
		if !ok || rep == nil || spec.Version != rep.Version {
			continue
		}
		if rep.TS > 0 && now.Sub(time.Unix(rep.TS, 0)) > baselineResendMaxAge {
			delete(e.last, id)
			dropped = true
			continue
		}
		out = append(out, rep)
	}
	e.mu.Unlock()
	if dropped {
		e.save()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BaselineID < out[j].BaselineID })
	for _, rep := range out {
		e.sendReport(rep)
	}
}

// boundReport keeps a report under the wire limit: details go first, then
// whole results, and what was dropped is said out loud in one synthetic
// error result rather than silently missing.
func boundReport(rep *protocol.BaselineReport) {
	if reportSize(rep) <= baselines.MaxReportBytes {
		return
	}
	for i := range rep.Results {
		rep.Results[i].Detail = ""
	}
	if reportSize(rep) <= baselines.MaxReportBytes {
		return
	}
	const headroom = 1024
	dropped := 0
	var markerID int64
	for len(rep.Results) > 0 && reportSize(rep) > baselines.MaxReportBytes-headroom {
		markerID = rep.Results[len(rep.Results)-1].CheckID
		rep.Results = rep.Results[:len(rep.Results)-1]
		dropped++
	}
	if dropped == 0 {
		return
	}
	rep.Results = append(rep.Results, protocol.BaselineResult{
		CheckID:  markerID,
		State:    baselines.StateError,
		Expected: "a report under 1 MiB",
		Observed: "report too large",
		Detail:   fmt.Sprintf("%d result(s) were dropped so the report would fit in %d bytes", dropped, baselines.MaxReportBytes),
	})
}

func reportSize(rep *protocol.BaselineReport) int {
	b, err := json.Marshal(rep)
	if err != nil {
		return 0
	}
	return len(b)
}

// ---- persistence (A9) ----

// baselineStateFile is baselines.json: everything the engine needs to keep
// working with no server, written with the same tmp+rename Config.Save uses.
type baselineStateFile struct {
	SavedAt     int64                               `json:"saved_at"`
	Specs       []protocol.BaselineSpec             `json:"specs"`
	LastReports map[string]*protocol.BaselineReport `json:"last_reports,omitempty"`
	Holdoff     map[string]int64                    `json:"holdoff,omitempty"`
	LastReboot  int64                               `json:"last_reboot,omitempty"`
	RebootSince int64                               `json:"reboot_pending_since,omitempty"`
}

func baselineStatePath() string { return filepath.Join(ConfigDir(), "baselines.json") }

// load reads baselines.json. A file that will not parse is a warning and an
// empty set, never a failure to start: an agent that refuses to run because
// of its own cache is worse than one that has forgotten its baselines and is
// about to be told them again.
func (e *baselineEngine) load() {
	e.mu.Lock()
	defer e.mu.Unlock()
	b, err := os.ReadFile(baselineStatePath())
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("cannot read the baseline state file", "path", baselineStatePath(), "err", err)
		}
		return
	}
	var f baselineStateFile
	if err := json.Unmarshal(b, &f); err != nil {
		slog.Warn("the baseline state file is not readable and was ignored", "path", baselineStatePath(), "err", err)
		return
	}
	now := e.now()
	for _, s := range f.Specs {
		if s.ID <= 0 {
			continue
		}
		s = normaliseSpec(s)
		e.specs[s.ID] = s
		e.due[s.ID] = now.Add(baselineStartDelay + e.jitter(baselineStartJitter))
		e.reason[s.ID] = baselines.TriggerStartup
	}
	for k, rep := range f.LastReports {
		id, err := strconv.ParseInt(k, 10, 64)
		if err != nil || rep == nil {
			continue
		}
		if _, ok := e.specs[id]; ok {
			e.last[id] = rep
		}
	}
	for k, until := range f.Holdoff {
		id, err := strconv.ParseInt(k, 10, 64)
		if err != nil || until <= now.Unix() {
			continue
		}
		e.holdoff[id] = until
	}
	e.lastReboot, e.rebootSince = f.LastReboot, f.RebootSince
}

// save writes the state file. A failure is logged once per call and never
// stops a pass: the device still evaluates, it just forgets across a restart.
func (e *baselineEngine) save() {
	e.mu.Lock()
	f := baselineStateFile{
		SavedAt:     e.now().Unix(),
		Specs:       make([]protocol.BaselineSpec, 0, len(e.specs)),
		LastReports: map[string]*protocol.BaselineReport{},
		Holdoff:     map[string]int64{},
		LastReboot:  e.lastReboot,
		RebootSince: e.rebootSince,
	}
	ids := make([]int64, 0, len(e.specs))
	for id := range e.specs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		f.Specs = append(f.Specs, e.specs[id])
	}
	for id, rep := range e.last {
		f.LastReports[strconv.FormatInt(id, 10)] = rep
	}
	now := e.now().Unix()
	for id, until := range e.holdoff {
		if until > now {
			f.Holdoff[strconv.FormatInt(id, 10)] = until
		}
	}
	e.mu.Unlock()

	b, err := json.Marshal(&f)
	if err != nil {
		slog.Warn("cannot marshal the baseline state", "err", err)
		return
	}
	if err := EnsureConfigDir(); err != nil {
		slog.Warn("cannot create the agent directory for the baseline state", "err", err)
		return
	}
	path := baselineStatePath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		slog.Warn("cannot write the baseline state", "path", tmp, "err", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		slog.Warn("cannot replace the baseline state", "path", path, "err", err)
		os.Remove(tmp)
	}
}

// rebootBookkeeping reads and updates the two dates the reboot_pending kind
// needs: when a pending reboot was first seen, and when this engine last
// caused one.
func (e *baselineEngine) pendingSince(pending, readOnly bool) int64 {
	now := e.now().Unix()
	e.mu.Lock()
	defer e.mu.Unlock()
	if readOnly {
		if pending && e.rebootSince == 0 {
			// Nothing is recorded yet and a preview may not record it, so
			// answer with "as of now" rather than with 1970.
			return now
		}
		return e.rebootSince
	}
	switch {
	case !pending:
		e.rebootSince = 0
	case e.rebootSince == 0:
		e.rebootSince = now
	}
	return e.rebootSince
}

func (e *baselineEngine) rebootedRecently() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastReboot > 0 && e.now().Sub(time.Unix(e.lastReboot, 0)) < baselineRebootEvery
}

func (e *baselineEngine) markRebooted() {
	e.mu.Lock()
	e.lastReboot = e.now().Unix()
	e.mu.Unlock()
	e.save()
}

// ---- small helpers ----

// live reports whether a script run is in flight. A remediation must not
// fight an operator's own script for the same package database or service.
func (r *scriptRunner) live() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.cancels) > 0
}

// anyOpen reports whether an interactive shell session is attached, which is
// the one thing that stops a baseline-initiated reboot dead.
func (m *shellManager) anyOpen() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions) > 0
}

func containsID(ids []int64, id int64) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

func joinDetail(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	switch len(out) {
	case 0:
		return ""
	case 1:
		return out[0]
	}
	s := out[0]
	for _, p := range out[1:] {
		s += "\n" + p
	}
	return s
}

func orText(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
