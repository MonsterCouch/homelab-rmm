package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/MonsterCouch/homelab-rmm/internal/baselines"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// ---- limits (docs/BASELINES.md, amendment A29) ----

const (
	// Sizes and counts are the shared limits, named here so the server code
	// reads in its own vocabulary while there is still exactly one value.
	maxBaselineNameLen       = baselines.MaxNameLen
	maxBaselineDescLen       = baselines.MaxDescriptionLen
	maxChecksPerBaseline     = baselines.MaxChecksPerBaseline
	maxBaselinesTotal        = baselines.MaxBaselines
	maxBaselinesPerDevice    = baselines.MaxBaselinesPerAgent
	maxExpectedObservedBytes = baselines.MaxObservedBytes
	maxDetailBytes           = baselines.MaxDetailBytes

	minBaselineInterval = baselines.MinIntervalSec
	defaultCheckTimeout = baselines.DefaultTimeoutSec

	// maxPreviewAgents bounds a dry run; every device gets its own socket
	// request and they all run in parallel.
	maxPreviewAgents = 10
	// maxEvaluateAgents bounds an EXPLICIT device list on an evaluate. An
	// empty list means "every matched device" and is bounded by the fleet;
	// a named list is bounded here, because every name gets an answer.
	maxEvaluateAgents = 500
	// driftFlapPasses is how many consecutive `fixed` passes mean "something
	// on the device is putting the drift back": the server stops treating it
	// as routine self-healing and raises an alert for a human (A22).
	driftFlapPasses = 5
	// driftDigestQuiet is the minimum gap between two critical drift digests
	// for the same (device, baseline).
	driftDigestQuiet = int64(60 * 60)
	// maxChangedInEvent caps the transition list in the SSE payload; the
	// console refetches anyway.
	maxChangedInEvent = 20
)

// ---- parameter validation ----
//
// internal/baselines is the ONE definition of what a check's params are: the
// typed struct per kind, the validator and the limits. The server refuses a
// bad check with a 400 that names the field; the agent re-validates the same
// params at evaluation time and reports `error` rather than handing an
// unvalidated string to exec. A second hand-written validator on this side is
// exactly how the two would drift apart.

func validateCheckParams(kind string, params json.RawMessage) error {
	return baselines.ValidateCheck(kind, params)
}

// validBaselineSeverity gates a check's drift-alert severity. `info` is a
// real severity that deliberately opens no alert (A20).
func validBaselineSeverity(s string) bool { return baselines.ValidSeverity(s) }

// checkAllowsReboot reports whether a reboot_pending check is allowed to
// reboot the device - the most dangerous remediation in the product. The rule
// itself lives in internal/baselines, so the agent refuses exactly what the
// server audits.
func checkAllowsReboot(c BaselineCheck) bool {
	return baselines.AllowsReboot(c.Kind, c.Params)
}

// checkFilePath is the path a `file` check writes, or "" when it cannot be
// read (a check that fails validation never gets this far).
func checkFilePath(c BaselineCheck) string {
	var p baselines.FileParams
	if baselines.DecodeLenient(c.Params, &p) != nil {
		return ""
	}
	return p.Path
}

// adminOnlyReasons lists why a baseline needs the admin role: `command` runs
// arbitrary code as SYSTEM/root, `file` outside the two configuration trees
// can rewrite anything, and `allow_reboot` can reboot the fleet.
//
// The rule is baselines.RequiresAdmin and nothing else. A second, hand-rolled
// copy on this side is how the gate springs a leak: the previous one asked
// whether the path CONTAINED "/programdata/", so /opt/evil/programdata/hook.sh
// looked like a managed file and a non-admin could write it on every device.
func adminOnlyReasons(checks []BaselineCheck) []string {
	var out []string
	for _, c := range checks {
		if need, why := baselines.RequiresAdmin(c.Kind, c.Params); need {
			out = append(out, fmt.Sprintf("check %q: %s", c.Name, why))
		}
	}
	return out
}

// auditedFilePaths are the `file` check paths that are allowed but worth their
// own line in the audit log (the Windows hosts file, A34).
func auditedFilePaths(checks []BaselineCheck) []string {
	var out []string
	for _, c := range checks {
		if c.Kind != "file" {
			continue
		}
		if p := checkFilePath(c); p != "" && baselines.FileIsAudited(p) {
			out = append(out, p)
		}
	}
	return out
}

func hasRebootCheck(checks []BaselineCheck) bool {
	for _, c := range checks {
		if checkAllowsReboot(c) {
			return true
		}
	}
	return false
}

// validateBaselineInput normalises and checks a create/update body. It
// returns a message meant for an operator: which check, which field.
func validateBaselineInput(in *baselineInput) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return fmt.Errorf("name is required")
	}
	// Counted in CHARACTERS, not bytes: the limit is what the console's
	// maxLength counts, and a name in Japanese or with an emoji in it would
	// otherwise be refused at a third of its apparent length, with an error
	// message saying "120 characters" over a 41-character name.
	if utf8.RuneCountInString(in.Name) > maxBaselineNameLen {
		return fmt.Errorf("name must be at most %d characters", maxBaselineNameLen)
	}
	if utf8.RuneCountInString(in.Description) > maxBaselineDescLen {
		return fmt.Errorf("description must be at most %d characters", maxBaselineDescLen)
	}
	in.IntervalSec = baselines.ClampInterval(in.IntervalSec)
	if len(in.Checks) > maxChecksPerBaseline {
		return fmt.Errorf("a baseline may have at most %d checks", maxChecksPerBaseline)
	}
	for i := range in.Checks {
		c := &in.Checks[i]
		c.Name = strings.TrimSpace(c.Name)
		if c.Name == "" {
			return fmt.Errorf("check %d: name is required", i+1)
		}
		if utf8.RuneCountInString(c.Name) > maxBaselineNameLen {
			return fmt.Errorf("check %q: name must be at most %d characters", c.Name, maxBaselineNameLen)
		}
		if c.Severity == "" {
			c.Severity = "warning"
		}
		if !validBaselineSeverity(c.Severity) {
			return fmt.Errorf("check %q: severity must be info, warning or critical", c.Name)
		}
		if !baselines.ValidOSFilter(c.OSFilter) {
			return fmt.Errorf("check %q: os_filter must be empty, windows or linux", c.Name)
		}
		if !baselines.KindKnown(c.Kind) {
			return fmt.Errorf("check %q: unknown kind %q", c.Name, c.Kind)
		}
		if c.OSFilter != "" && !baselines.KindRunsOn(c.Kind, c.OSFilter) {
			return fmt.Errorf("check %q: kind %s is not implemented on %s", c.Name, c.Kind, c.OSFilter)
		}
		c.TimeoutSec = baselines.ClampTimeout(c.TimeoutSec)
		if len(c.Params) == 0 {
			c.Params = json.RawMessage("{}")
		}
		if err := validateCheckParams(c.Kind, c.Params); err != nil {
			return fmt.Errorf("check %q: %v", c.Name, err)
		}
	}
	return nil
}

// ---- config resolution ----

// baselineSpec is a stored baseline as the agent receives it. A standing
// approval binds the SHA-256 of exactly this value, so the config and the
// Review & sign page must both build it here.
func baselineSpec(b *Baseline) protocol.BaselineSpec {
	spec := protocol.BaselineSpec{
		ID:          b.ID,
		Name:        b.Name,
		Version:     b.Version,
		Enforce:     b.Enforce,
		IntervalSec: baselines.ClampInterval(b.IntervalSec),
		Checks:      make([]protocol.BaselineCheck, 0, len(b.Checks)),
	}
	for _, c := range b.Checks {
		spec.Checks = append(spec.Checks, protocol.BaselineCheck{
			ID: c.ID, Name: c.Name, Kind: c.Kind, Params: c.Params, Remediate: c.Remediate,
			Severity: c.Severity, OSFilter: c.OSFilter, TimeoutSec: baselines.ClampTimeout(c.TimeoutSec),
		})
	}
	return spec
}

// baselineSpecsFor is the COMPLETE set of enabled baselines matching a
// device. Partial or incremental pushes are forbidden: the agent replaces its
// whole set on every config, so anything left out is stopped on the device.
func (s *Server) baselineSpecsFor(a *Agent) []protocol.BaselineSpec {
	list, err := s.db.ListBaselinesWithChecks()
	if err != nil {
		slog.Warn("resolve baselines for agent", "agent", a.ID, "err", err)
		return nil
	}
	out := []protocol.BaselineSpec{}
	for _, b := range list {
		if !b.Enabled || !b.Targets.Matches(a) {
			continue
		}
		out = append(out, baselineSpec(b))
	}
	if len(out) > maxBaselinesPerDevice {
		// Which ones survive has to be stable: the list arrives ordered by
		// NAME, so renaming a baseline would otherwise silently swap which of
		// them a device evaluates. Ids are the identity everything else uses.
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		dropped := make([]int64, 0, len(out)-maxBaselinesPerDevice)
		for _, sp := range out[maxBaselinesPerDevice:] {
			dropped = append(dropped, sp.ID)
		}
		slog.Warn("device matches more baselines than the per-device limit; the extra ones are not pushed",
			"agent", a.ID, "matched", len(out), "limit", maxBaselinesPerDevice, "not_pushed", dropped)
		out = out[:maxBaselinesPerDevice]
	}
	if len(out) == 0 {
		// An empty (non-nil) slice still marshals away under `omitempty`,
		// which is exactly the "no baselines" the agent must act on: it
		// replaces its whole set, so an absent field clears every assignment.
		return nil
	}
	return out
}

// assignedBaselines are the enabled baselines a device currently matches.
func (s *Server) assignedBaselines(a *Agent) ([]*Baseline, error) {
	list, err := s.db.ListBaselines()
	if err != nil {
		return nil, err
	}
	out := []*Baseline{}
	for _, b := range list {
		if b.Enabled && b.Targets.Matches(a) {
			out = append(out, b)
		}
	}
	return out, nil
}

func (s *Server) assignedBaselineIDs(agentID string) map[int64]bool {
	out := map[int64]bool{}
	a, err := s.db.GetAgent(agentID)
	if err != nil {
		return out
	}
	list, err := s.assignedBaselines(a)
	if err != nil {
		return out
	}
	for _, b := range list {
		out[b.ID] = true
	}
	return out
}

// matchedAgentIDs is the set of devices a target expression selects.
func (s *Server) matchedAgentIDs(t Targets) map[string]bool {
	out := map[string]bool{}
	agents, err := s.db.ResolveTargets(t)
	if err != nil {
		slog.Warn("resolve baseline targets", "err", err)
		return out
	}
	for _, a := range agents {
		out[a.ID] = true
	}
	return out
}

// pushConfigTo pushes the full agent config to every ONLINE device in the set.
func (s *Server) pushConfigTo(ids map[string]bool) {
	for id := range ids {
		if s.hub.IsOnline(id) {
			s.pushAgentConfig(id)
		}
	}
}

// applyBaselineMembership is what every baseline create, update, delete,
// enable and disable ends with. Devices that stopped matching lose their
// stored results and have their open drift alerts resolved - nothing else
// ever resolves a drift alert, and a status matrix full of rows nothing will
// update is worse than an empty one. The config is then pushed to the union
// of the two sets, so a device that lost a baseline stops evaluating it.
func (s *Server) applyBaselineMembership(baselineID int64, before, after map[string]bool) {
	for id := range before {
		if after[id] {
			continue
		}
		s.forgetBaselineOn(id, baselineID)
	}
	union := map[string]bool{}
	for id := range before {
		union[id] = true
	}
	for id := range after {
		union[id] = true
	}
	s.pushConfigTo(union)
}

// forgetBaselineOn drops a device's state for a baseline and resolves its
// drift alerts through the alert engine, so the SSE event and the
// alert_resolved automation fire exactly as they would for any other alert.
func (s *Server) forgetBaselineOn(agentID string, baselineID int64) {
	keys, err := s.db.openDriftKeysFor(agentID, baselineID)
	if err != nil {
		slog.Warn("collect drift alerts", "agent", agentID, "baseline", baselineID, "err", err)
	}
	if err := s.db.forgetBaselineOn(agentID, baselineID); err != nil {
		slog.Warn("clear baseline results", "agent", agentID, "baseline", baselineID, "err", err)
	}
	for _, k := range keys {
		s.alerts.resolveKey(k)
	}
	s.baselines.forgetDevice(agentID, baselineID)
}

// forgetCheck resolves the open alerts of a check that has been deleted or
// had its kind changed. Its results went with it inside the save
// transaction; its history rows stay.
func (s *Server) forgetCheck(baselineID, checkID int64) {
	keys, err := s.db.openDriftKeysForCheck(baselineID, checkID)
	if err != nil {
		slog.Warn("collect drift alerts for check", "baseline", baselineID, "check", checkID, "err", err)
		return
	}
	for _, k := range keys {
		s.alerts.resolveKey(k)
	}
	s.baselines.forgetCheck(baselineID, checkID)
}

// agentMembershipChanged is called after a device's group or tags changed (or
// its group was deleted): baselines it no longer matches are cleaned up and
// the new config is pushed.
func (s *Server) agentMembershipChanged(agentID string, before map[int64]bool) {
	after := s.assignedBaselineIDs(agentID)
	for id := range before {
		if !after[id] {
			s.forgetBaselineOn(agentID, id)
		}
	}
	if s.hub.IsOnline(agentID) {
		s.pushAgentConfig(agentID)
	}
}

// ---- drift keys ----

// driftKey is the dedupe key of a drift alert. It is built from ids only:
// names change, and a renamed check must not orphan its open alert.
func driftKey(baselineID, checkID int64, agentID string) string {
	return fmt.Sprintf("drift:%d:%d:%s", baselineID, checkID, agentID)
}

func driftFlapKey(baselineID, checkID int64, agentID string) string {
	return fmt.Sprintf("driftflap:%d:%d:%s", baselineID, checkID, agentID)
}

// ---- ingest ----

// baselineEngine holds the little state that does not belong in SQLite: how
// many consecutive passes a check has been re-fixed on a device (flap
// detection), when the last critical digest went out, and the log throttles.
type baselineEngine struct {
	s          *Server
	mu         sync.Mutex
	fixedRuns  map[string]int
	lastDigest map[string]int64
	lastLog    map[string]int64
}

func newBaselineEngine(s *Server) *baselineEngine {
	return &baselineEngine{s: s, fixedRuns: map[string]int{}, lastDigest: map[string]int64{}, lastLog: map[string]int64{}}
}

// logOnce rate-limits a log line to one per key per minute.
func (e *baselineEngine) logOnce(key string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if last, ok := e.lastLog[key]; ok && now()-last < 60 {
		return false
	}
	e.lastLog[key] = now()
	return true
}

func (e *baselineEngine) forgetDevice(agentID string, baselineID int64) {
	prefix := fmt.Sprintf("%s|%d|", agentID, baselineID)
	e.mu.Lock()
	defer e.mu.Unlock()
	for k := range e.fixedRuns {
		if strings.HasPrefix(k, prefix) {
			delete(e.fixedRuns, k)
		}
	}
	delete(e.lastDigest, fmt.Sprintf("%s|%d", agentID, baselineID))
}

// forgetAgent drops every in-memory counter for a device that no longer
// exists. The maps are keyed by agent id, so without this a fleet that churns
// leaks one entry per (device, check) forever.
func (e *baselineEngine) forgetAgent(agentID string) {
	prefix := agentID + "|"
	e.mu.Lock()
	defer e.mu.Unlock()
	for k := range e.fixedRuns {
		if strings.HasPrefix(k, prefix) {
			delete(e.fixedRuns, k)
		}
	}
	for k := range e.lastDigest {
		if strings.HasPrefix(k, prefix) {
			delete(e.lastDigest, k)
		}
	}
	for k := range e.lastLog {
		if strings.HasSuffix(k, ":"+agentID) {
			delete(e.lastLog, k)
		}
	}
}

func (e *baselineEngine) forgetCheck(baselineID, checkID int64) {
	suffix := fmt.Sprintf("|%d|%d", baselineID, checkID)
	e.mu.Lock()
	defer e.mu.Unlock()
	for k := range e.fixedRuns {
		if strings.HasSuffix(k, suffix) {
			delete(e.fixedRuns, k)
		}
	}
}

// fixedRun counts consecutive `fixed` passes for one (device, check) and
// returns the new count. Any other state resets it.
func (e *baselineEngine) fixedRun(agentID string, baselineID, checkID int64, isFixed bool) int {
	key := fmt.Sprintf("%s|%d|%d", agentID, baselineID, checkID)
	e.mu.Lock()
	defer e.mu.Unlock()
	if !isFixed {
		delete(e.fixedRuns, key)
		return 0
	}
	e.fixedRuns[key]++
	return e.fixedRuns[key]
}

// digestAllowed reports whether a critical digest may go out now for this
// (device, baseline), and records that it did.
func (e *baselineEngine) digestAllowed(agentID string, baselineID int64) bool {
	key := fmt.Sprintf("%s|%d", agentID, baselineID)
	e.mu.Lock()
	defer e.mu.Unlock()
	if last, ok := e.lastDigest[key]; ok && now()-last < driftDigestQuiet {
		return false
	}
	e.lastDigest[key] = now()
	return true
}

// resultOutcome is what one ingested result did, carried out of the
// transaction so the alert engine, the automations and the mailer run after
// the commit (they each take the single SQLite connection).
type resultOutcome struct {
	checkID   int64
	checkName string
	kind      string
	severity  string
	state     string
	from      string
	changed   bool
	expected  string
	observed  string
	detail    string
}

// onBaselineReport is the hub's entry point for a TypeBaseline frame.
func (s *Server) onBaselineReport(agentID string, rep *protocol.BaselineReport) {
	s.baselines.ingest(agentID, rep)
}

func (e *baselineEngine) ingest(agentID string, rep *protocol.BaselineReport) {
	if rep == nil {
		return
	}
	// A preview never reaches the store: its ids are synthetic negatives and
	// its results describe a spec that may never be saved.
	if rep.Trigger == "preview" {
		slog.Debug("dropping preview baseline report", "agent", agentID, "baseline", rep.BaselineID)
		return
	}
	trigger := rep.Trigger
	if !baselines.ValidTrigger(trigger) {
		slog.Debug("unknown baseline trigger, recording as schedule", "agent", agentID, "trigger", rep.Trigger)
		trigger = "schedule"
	}
	b, err := e.s.db.GetBaseline(rep.BaselineID)
	if err != nil {
		slog.Debug("baseline report for an unknown baseline", "agent", agentID, "baseline", rep.BaselineID)
		return
	}
	a, err := e.s.db.GetAgent(agentID)
	if err != nil {
		return
	}
	if !b.Enabled || !b.Targets.Matches(a) {
		slog.Debug("baseline report for a baseline this device is not assigned", "agent", agentID, "baseline", b.ID)
		return
	}
	if rep.Version < b.Version {
		slog.Debug("ignoring baseline report for an old version", "agent", agentID, "baseline", b.ID, "report", rep.Version, "stored", b.Version)
		return
	}
	if rep.Version > b.Version {
		if e.logOnce("ahead:" + agentID) {
			slog.Warn("baseline report is ahead of the stored version, which can only mean a rolled-back database",
				"agent", agentID, "baseline", b.ID, "report", rep.Version, "stored", b.Version)
		}
		return
	}

	received := now()
	ts := rep.TS
	if ts <= 0 {
		ts = received
	}
	if ts > received+86400 {
		if e.logOnce("clock:" + agentID) {
			slog.Warn("baseline report timestamp is more than a day ahead of the server; using server time", "agent", agentID, "report_ts", rep.TS)
		}
		ts = received
	}
	if st, ok := e.s.db.baselineStateFor(agentID, b.ID); ok && st.Version == rep.Version && ts < st.LastReportTS {
		slog.Debug("ignoring out-of-order baseline report", "agent", agentID, "baseline", b.ID, "ts", ts, "last", st.LastReportTS)
		return
	}

	var (
		outcomes []resultOutcome
		dropped  int
	)
	err = e.s.db.withTx(context.Background(), func(tx *sql.Tx) error {
		// Membership is re-read inside the transaction: baseline_results has
		// a foreign key on check_id, so a check deleted while this report was
		// in flight would make the insert fail and lose the whole pass.
		type checkRow struct{ name, kind, severity string }
		checks := map[int64]checkRow{}
		rows, err := tx.Query(`SELECT id, name, kind, severity FROM baseline_checks WHERE baseline_id = ?`, b.ID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id int64
			var c checkRow
			if err := rows.Scan(&id, &c.name, &c.kind, &c.severity); err != nil {
				rows.Close()
				return err
			}
			checks[id] = c
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		outcomes = outcomes[:0]
		// One pass reports each check at most once. A frame that repeats a
		// check id - a buggy agent, or a hostile one - would otherwise upsert
		// and write a history row per repetition: three copies of one check
		// produced three transitions out of a single pass, fired the
		// drift_detected/drift_fixed automations three times, and did all of
		// it inside the transaction that holds the single SQLite connection.
		// First occurrence wins; the rest are dropped like any other result
		// that does not belong to a live check.
		seen := make(map[int64]bool, len(checks))
		for i, r := range rep.Results {
			// A baseline has at most 64 checks, so once every live check has
			// been seen there is nothing left a further result could be for.
			// Stopping here bounds the work a single frame can ask of the
			// one connection, whatever the agent sent.
			if len(checks) == 0 || len(seen) == len(checks) {
				dropped += len(rep.Results) - i
				break
			}
			c, ok := checks[r.CheckID]
			if r.CheckID <= 0 || !ok || seen[r.CheckID] {
				dropped++
				continue
			}
			seen[r.CheckID] = true
			state := r.State
			if !baselines.ValidState(state) {
				state = "error"
			}
			expected := baselines.Truncate(r.Expected, maxExpectedObservedBytes)
			observed := baselines.Truncate(r.Observed, maxExpectedObservedBytes)
			detail := baselines.Truncate(r.Detail, maxDetailBytes)

			var prevState string
			var prevSince int64
			err := tx.QueryRow(`SELECT state, since FROM baseline_results WHERE agent_id = ? AND check_id = ?`, agentID, r.CheckID).Scan(&prevState, &prevSince)
			isNew := err != nil
			since := received
			if !isNew && prevState == state {
				// `since` is the server time of the FIRST report carrying the
				// current state; a version bump, an edit or the stale flag
				// never reset it.
				since = prevSince
			}
			if _, err := tx.Exec(`INSERT INTO baseline_results(agent_id, check_id, baseline_id, state, expected, observed, detail, fixed, duration_ms, version, stale, checked_at, received_at, since)
				VALUES(?,?,?,?,?,?,?,?,?,?,0,?,?,?)
				ON CONFLICT(agent_id, check_id) DO UPDATE SET
					baseline_id=excluded.baseline_id, state=excluded.state, expected=excluded.expected, observed=excluded.observed,
					detail=excluded.detail, fixed=excluded.fixed, duration_ms=excluded.duration_ms, version=excluded.version,
					stale=0, checked_at=excluded.checked_at, received_at=excluded.received_at, since=excluded.since`,
				agentID, r.CheckID, b.ID, state, expected, observed, detail, r.Fixed, r.DurationMs, rep.Version, ts, received, since); err != nil {
				return err
			}

			if isNew {
				prevState = ""
			}
			// A device's very first `pass` (or `skipped`) is not a transition
			// worth an audit row, an automation or an event: it is the
			// baseline being established. Everything else is, including a
			// first report that is already drifted.
			record := prevState != state && !(isNew && (state == "pass" || state == "skipped"))
			if record {
				if _, err := tx.Exec(`INSERT INTO baseline_history(agent_id, baseline_id, check_id, check_name, ts, from_state, to_state, detail) VALUES(?,?,?,?,?,?,?,?)`,
					agentID, b.ID, r.CheckID, c.name, received, prevState, state, detail); err != nil {
					return err
				}
			}
			outcomes = append(outcomes, resultOutcome{checkID: r.CheckID, checkName: c.name, kind: c.kind, severity: c.severity,
				state: state, from: prevState, changed: record, expected: expected, observed: observed, detail: detail})
		}
		_, err = tx.Exec(`INSERT INTO baseline_state(agent_id, baseline_id, version, last_report_ts, last_received_at, last_trigger) VALUES(?,?,?,?,?,?)
			ON CONFLICT(agent_id, baseline_id) DO UPDATE SET version=excluded.version, last_report_ts=excluded.last_report_ts,
				last_received_at=excluded.last_received_at, last_trigger=excluded.last_trigger`,
			agentID, b.ID, rep.Version, ts, received, trigger)
		return err
	})
	if err != nil {
		slog.Warn("store baseline report", "agent", agentID, "baseline", b.ID, "err", err)
		return
	}
	if dropped > 0 {
		slog.Debug("dropped baseline results for checks that no longer exist", "agent", agentID, "baseline", b.ID, "dropped", dropped)
	}
	e.afterIngest(a, b, rep, trigger, ts, outcomes)
}

// afterIngest runs everything that must NOT hold the ingest transaction: the
// alert engine, the automations, the digest mail and the SSE broadcast.
func (e *baselineEngine) afterIngest(a *Agent, b *Baseline, rep *protocol.BaselineReport, trigger string, ts int64, outcomes []resultOutcome) {
	var (
		counts baselineCounts
		// changed is the capped list the SSE payload carries; transitions is
		// how many there really were, so `changed_truncated` says "there were
		// more" rather than "there were exactly the cap and more results".
		changed     []map[string]any
		transitions int
		criticals   []resultOutcome
	)
	// The open drift keys for this (device, baseline) are read ONCE: without
	// it every passing check of every pass costs a SELECT on the single
	// SQLite connection, and a 64-check baseline over a fleet is a lot of
	// queries to learn that there is nothing to resolve.
	openKeys := map[string]bool{}
	if keys, err := e.s.db.openDriftKeysFor(a.ID, b.ID); err == nil {
		for _, k := range keys {
			openKeys[k] = true
		}
	}
	for _, o := range outcomes {
		counts.add(o.state, false)
		key := driftKey(b.ID, o.checkID, a.ID)
		switch o.state {
		case "fail", "error":
			// Opened on EVERY failing report, not only on the transition:
			// open() dedupes on the key anyway, and a first failure that
			// lands inside a maintenance window would otherwise never open an
			// alert at all (there is no second transition to catch it).
			if o.severity != "info" && !openKeys[key] {
				title := fmt.Sprintf("%s: %s", b.Name, o.checkName)
				e.s.alerts.openDrift(a.ID, key, o.severity, title, driftMessage(o), false)
			}
		case "pass", "fixed", "skipped":
			if openKeys[key] {
				e.s.alerts.resolveKey(key)
			}
		}
		flapKey := driftFlapKey(b.ID, o.checkID, a.ID)
		if run := e.fixedRun(a.ID, b.ID, o.checkID, o.state == "fixed"); run >= driftFlapPasses && o.severity != "info" && !openKeys[flapKey] {
			e.s.alerts.openDrift(a.ID, flapKey, o.severity,
				fmt.Sprintf("%s keeps drifting back", o.checkName),
				fmt.Sprintf("%s has been re-fixed on %d consecutive passes of baseline %q. Something on the device is putting the drift back; automatic remediation cannot win this one.", o.checkName, run, b.Name), false)
		}
		if !o.changed {
			continue
		}
		transitions++
		if len(changed) < maxChangedInEvent {
			changed = append(changed, map[string]any{"check_id": o.checkID, "from": o.from, "to": o.state})
		}
		data := map[string]any{
			"baseline_id": b.ID, "baseline_name": b.Name, "check_id": o.checkID, "check_name": o.checkName,
			"kind": o.kind, "severity": o.severity, "state": o.state, "expected": o.expected, "observed": o.observed, "detail": o.detail,
		}
		switch o.state {
		case "fail", "error":
			e.s.sched.automation("drift_detected", a.ID, data)
			e.recordEvent(a.ID, "drift", fmt.Sprintf("%s: %s is %s (expected %s, observed %s)", b.Name, o.checkName, o.state, orDash(o.expected), orDash(o.observed)))
			if o.severity == "critical" {
				criticals = append(criticals, o)
			}
		case "fixed":
			// A run of consecutive `fixed` passes is ONE event: the agent
			// re-fixing the same drift every interval must not raise an event
			// and an automation every interval forever.
			e.s.sched.automation("drift_fixed", a.ID, data)
			e.recordEvent(a.ID, "drift", fmt.Sprintf("%s: %s drifted and was fixed (%s)", b.Name, o.checkName, orDash(o.observed)))
		}
	}

	if b.NotifyEmail && len(criticals) > 0 && e.digestAllowed(a.ID, b.ID) {
		// ONE digest per (device, baseline) per report, never one mail per
		// alert: a seven-check baseline over twenty devices would otherwise
		// send 140 mails on its first evaluation.
		subject := fmt.Sprintf("[RMM CRITICAL] %s - baseline %s", a.DisplayName, b.Name)
		var sb strings.Builder
		fmt.Fprintf(&sb, "Critical drift on %s for baseline %q.\n\n", a.DisplayName, b.Name)
		for _, o := range criticals {
			fmt.Fprintf(&sb, "- %s: %s\n  expected: %s\n  observed: %s\n", o.checkName, o.state, orDash(o.expected), orDash(o.observed))
			if o.detail != "" {
				fmt.Fprintf(&sb, "  detail: %s\n", clipLines(o.detail, 5))
			}
		}
		fmt.Fprintf(&sb, "\nOpen the console: %s/baselines/%d\n", e.s.PublicURL(), b.ID)
		body := sb.String()
		e.s.goJob(func() {
			if err := e.s.mail.Send(subject, body); err != nil {
				slog.Debug("drift digest not sent", "err", err)
			}
		})
	}

	// The device's compliance after this pass, over every check of the
	// baseline (not only the ones in this report).
	deviceCounts, err := e.s.db.countsFor(a.ID, b.ID, len(b.Checks))
	if err != nil {
		slog.Debug("compliance after ingest", "agent", a.ID, "baseline", b.ID, "err", err)
	}
	data := map[string]any{
		"baseline_id": b.ID, "version": rep.Version, "trigger": trigger, "ts": ts,
		"counts":     map[string]int{"pass": counts.Pass, "fail": counts.Fail, "fixed": counts.Fixed, "error": counts.Error, "skipped": counts.Skipped},
		"compliance": deviceCounts.score(),
		"changed":    changed,
	}
	if changed == nil {
		data["changed"] = []map[string]any{}
	}
	if transitions > len(changed) {
		data["changed_truncated"] = true
	}
	e.s.hub.broadcast(hubEvent{Kind: "baseline", AgentID: a.ID, Data: data})
}

// recordEvent writes a device event row for a drift transition. It goes
// straight into agent_events: routing it through onAgentEvent would run the
// operator's `event` alert rules over drift the drift alert already covers.
func (e *baselineEngine) recordEvent(agentID, kind, msg string) {
	if _, err := e.s.db.Exec(`INSERT INTO agent_events(agent_id, ts, kind, message, fields) VALUES(?,?,?,?,'{}')`, agentID, now(), kind, msg); err != nil {
		slog.Debug("record drift event", "agent", agentID, "err", err)
	}
	e.s.hub.broadcast(hubEvent{Kind: "event", AgentID: agentID, Data: map[string]any{"ts": now(), "kind": kind, "message": msg}})
}

func driftMessage(o resultOutcome) string {
	msg := fmt.Sprintf("Expected %s, observed %s.", orDash(o.expected), orDash(o.observed))
	if o.state == "error" {
		msg = "The check could not run. " + msg
	}
	if o.detail != "" {
		msg += "\n\n" + clipLines(o.detail, 20)
	}
	return msg
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// clipLines keeps the first n lines of a bounded string (alerts and mail show
// the head of a fix's output, never the whole thing).
func clipLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[:n], "\n") + "\n..."
}

// ---- compliance ----

// baselineCounts is a device's result mix for one baseline. `skipped` and
// `unknown` (a check with no row, or a stale one) are outside compliance
// entirely: they are neither a numerator nor a denominator.
type baselineCounts struct {
	Pass    int `json:"pass"`
	Fail    int `json:"fail"`
	Fixed   int `json:"fixed"`
	Error   int `json:"error"`
	Skipped int `json:"skipped"`
	Unknown int `json:"unknown"`
}

func (c *baselineCounts) add(state string, stale bool) {
	if stale {
		c.Unknown++
		return
	}
	switch state {
	case "pass":
		c.Pass++
	case "fail":
		c.Fail++
	case "fixed":
		c.Fixed++
	case "error":
		c.Error++
	case "skipped":
		c.Skipped++
	default:
		c.Unknown++
	}
}

func (c *baselineCounts) addAll(o baselineCounts) {
	c.Pass += o.Pass
	c.Fail += o.Fail
	c.Fixed += o.Fixed
	c.Error += o.Error
	c.Skipped += o.Skipped
	c.Unknown += o.Unknown
}

func (c baselineCounts) applicable() int { return c.Pass + c.Fail + c.Fixed + c.Error }

func (c baselineCounts) drifted() bool { return c.Fail+c.Error > 0 }

// score is the compliance percentage, or nil when nothing applicable has been
// measured. It is never 0 and never 100 for a device that reported nothing:
// "no data" is not "perfect" and it is not "broken".
func (c baselineCounts) score() *float64 {
	n := c.applicable()
	if n == 0 {
		return nil
	}
	v := float64(c.Pass+c.Fixed) * 100 / float64(n)
	v = float64(int64(v*10+0.5)) / 10
	return &v
}

// countResults folds a device's stored results, counting the checks that have
// no row at all as unknown.
func countResults(results []BaselineResult, totalChecks int) baselineCounts {
	var c baselineCounts
	for _, r := range results {
		c.add(r.State, r.Stale)
	}
	if missing := totalChecks - len(results); missing > 0 {
		c.Unknown += missing
	}
	return c
}

// meanScore is the unweighted mean of the non-nil scores, or nil when there
// are none. An offline device keeps its last score and does not drag the
// fleet to zero; a device that never reported is simply not in the mean.
func meanScore(scores []*float64) *float64 {
	sum, n := 0.0, 0
	for _, s := range scores {
		if s != nil {
			sum += *s
			n++
		}
	}
	if n == 0 {
		return nil
	}
	v := sum / float64(n)
	v = float64(int64(v*10+0.5)) / 10
	return &v
}

// baselineStats is the per-baseline summary the list and the status view show.
type baselineStats struct {
	Devices         int
	DevicesReported int
	DevicesDrifted  int
	DevicesUnknown  int
	Compliance      *float64
}

func (s *Server) baselineStatsFor(b *Baseline, results map[string][]BaselineResult, matched []*Agent) baselineStats {
	st := baselineStats{Devices: len(matched)}
	scores := make([]*float64, 0, len(matched))
	for _, a := range matched {
		rs, reported := results[a.ID]
		if reported {
			st.DevicesReported++
		}
		c := countResults(rs, len(b.Checks))
		sc := c.score()
		if sc == nil {
			st.DevicesUnknown++
		} else {
			scores = append(scores, sc)
		}
		if c.drifted() {
			st.DevicesDrifted++
		}
	}
	st.Compliance = meanScore(scores)
	return st
}

// mapKeys is the key set of an id-keyed map, for a sorted iteration.
func mapKeys[V any](m map[int64]V) []int64 {
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// sortedInt64s is a stable order for id lists in API payloads and audit rows.
func sortedInt64s(in []int64) []int64 {
	out := append([]int64{}, in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
