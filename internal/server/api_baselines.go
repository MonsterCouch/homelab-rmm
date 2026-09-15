package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/baselines"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// ---- API shapes ----

// BaselineOut is a baseline plus the numbers the console lists it with.
type BaselineOut struct {
	ID              int64    `json:"id"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Targets         Targets  `json:"targets"`
	Enforce         bool     `json:"enforce"`
	IntervalSec     int      `json:"interval_sec"`
	NotifyEmail     bool     `json:"notify_email"`
	Enabled         bool     `json:"enabled"`
	Version         int      `json:"version"`
	ChecksCount     int      `json:"checks_count"`
	Devices         int      `json:"devices"`
	DevicesReported int      `json:"devices_reported"`
	DevicesDrifted  int      `json:"devices_drifted"`
	DevicesUnknown  int      `json:"devices_unknown"`
	Compliance      *float64 `json:"compliance"`
	LastChange      int64    `json:"last_change"`
	CreatedAt       int64    `json:"created_at"`
	UpdatedAt       int64    `json:"updated_at"`
}

// baselineDetailOut is BaselineOut with its checks, in position order.
type baselineDetailOut struct {
	BaselineOut
	Checks []BaselineCheck `json:"checks"`
}

type baselineDeviceOut struct {
	AgentID          string           `json:"agent_id"`
	AgentName        string           `json:"agent_name"`
	OS               string           `json:"os"`
	Online           bool             `json:"online"`
	MaintenanceUntil int64            `json:"maintenance_until"`
	Compliance       *float64         `json:"compliance"`
	Stale            bool             `json:"stale"`
	Version          int              `json:"version"`
	LastReport       int64            `json:"last_report"`
	LastTrigger      string           `json:"last_trigger"`
	Counts           baselineCounts   `json:"counts"`
	Results          []BaselineResult `json:"results"`
}

func (s *Server) baselineOut(b *Baseline, st baselineStats, checksCount int, lastChange int64) BaselineOut {
	return BaselineOut{
		ID: b.ID, Name: b.Name, Description: b.Description, Targets: b.Targets, Enforce: b.Enforce,
		IntervalSec: b.IntervalSec, NotifyEmail: b.NotifyEmail, Enabled: b.Enabled, Version: b.Version,
		ChecksCount: checksCount, Devices: st.Devices, DevicesReported: st.DevicesReported,
		DevicesDrifted: st.DevicesDrifted, DevicesUnknown: st.DevicesUnknown, Compliance: st.Compliance,
		LastChange: lastChange, CreatedAt: b.CreatedAt, UpdatedAt: b.UpdatedAt,
	}
}

// ---- list / get ----

func (s *Server) handleListBaselines(w http.ResponseWriter, r *http.Request) {
	list, err := s.db.ListBaselinesWithChecks()
	if err != nil {
		fail(w, err)
		return
	}
	results, err := s.db.allBaselineResults()
	if err != nil {
		fail(w, err)
		return
	}
	changes, err := s.db.lastBaselineChanges()
	if err != nil {
		fail(w, err)
		return
	}
	agents, err := s.db.ListAgents()
	if err != nil {
		fail(w, err)
		return
	}
	out := []BaselineOut{}
	for _, b := range list {
		matched := matchAgents(agents, b.Targets)
		st := s.baselineStatsFor(b, results[b.ID], matched)
		out = append(out, s.baselineOut(b, st, len(b.Checks), changes[b.ID]))
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleGetBaseline(w http.ResponseWriter, r *http.Request) {
	id, err := pathInt(r, "id")
	if err != nil {
		writeErr(w, 400, "bad baseline id")
		return
	}
	out, err := s.baselineDetail(id)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) baselineDetail(id int64) (*baselineDetailOut, error) {
	b, err := s.db.GetBaseline(id)
	if err != nil {
		return nil, err
	}
	results, err := s.db.baselineResultsFor(id)
	if err != nil {
		return nil, err
	}
	agents, err := s.db.ListAgents()
	if err != nil {
		return nil, err
	}
	changes, err := s.db.lastBaselineChanges()
	if err != nil {
		return nil, err
	}
	st := s.baselineStatsFor(b, results, matchAgents(agents, b.Targets))
	return &baselineDetailOut{BaselineOut: s.baselineOut(b, st, len(b.Checks), changes[id]), Checks: b.Checks}, nil
}

func matchAgents(agents []*Agent, t Targets) []*Agent {
	out := make([]*Agent, 0, len(agents))
	for _, a := range agents {
		if t.Matches(a) {
			out = append(out, a)
		}
	}
	return out
}

// ---- create / update ----

func (s *Server) handleCreateBaseline(w http.ResponseWriter, r *http.Request) {
	s.saveBaselineRequest(w, r, 0)
}

func (s *Server) handleUpdateBaseline(w http.ResponseWriter, r *http.Request) {
	id, err := pathInt(r, "id")
	if err != nil {
		writeErr(w, 400, "bad baseline id")
		return
	}
	s.saveBaselineRequest(w, r, id)
}

// saveBaselineRequest is POST and PUT. A PUT MERGES the checks by id (see
// DB.saveBaseline): stable ids are the whole point, because a result, a
// history row and an open drift alert all address a check by its id.
func (s *Server) saveBaselineRequest(w http.ResponseWriter, r *http.Request, id int64) {
	var in baselineInput
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if err := validateBaselineInput(&in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	var (
		prev   *Baseline
		before = map[string]bool{}
	)
	if id != 0 {
		var err error
		prev, err = s.db.GetBaseline(id)
		if err != nil {
			fail(w, err)
			return
		}
		if prev.Enabled {
			before = s.matchedAgentIDs(prev.Targets)
		}
	} else {
		n, err := s.db.countBaselines()
		if err != nil {
			fail(w, err)
			return
		}
		if n >= maxBaselinesTotal {
			writeErr(w, 400, fmt.Sprintf("at most %d baselines are supported", maxBaselinesTotal))
			return
		}
	}

	checks := checksFromInput(in.Checks)
	// `command` runs code as SYSTEM/root on every matched device, a `file`
	// check outside the configuration trees can rewrite anything, and
	// allow_reboot can reboot the fleet. The route is requireWrite; these
	// need an administrator.
	if reasons := adminOnlyReasons(checks); len(reasons) > 0 && !userFrom(r.Context()).IsAdmin() {
		writeErr(w, http.StatusForbidden, "admin only: "+reasons[0])
		return
	}
	if hasRebootCheck(checks) && in.Targets.All && in.Enforce && !in.ConfirmFleetReboot {
		writeErr(w, 400, `this baseline would let every device reboot itself: set confirm_fleet_reboot, narrow the targets, or turn enforce off`)
		return
	}
	matched, err := s.db.ResolveTargets(in.Targets)
	if err != nil {
		fail(w, err)
		return
	}
	if len(matched) == 0 && !in.AllowEmptyTargets {
		writeErr(w, 400, "these targets match no devices")
		return
	}

	saved, res, err := s.db.saveBaseline(r.Context(), id, in)
	if err != nil {
		if errors.Is(err, errUnknownCheckID) {
			writeErr(w, 400, "unknown check id")
			return
		}
		if errors.Is(err, errDuplicateCheckID) {
			writeErr(w, 400, "duplicate check id: a check may appear once in the body")
			return
		}
		fail(w, err)
		return
	}

	// A check that went away takes its results with it (inside the save
	// transaction); its open alerts are resolved here, through the engine, so
	// the SSE event and the alert_resolved automation fire.
	for _, cid := range res.DeletedChecks {
		s.forgetCheck(saved.ID, cid)
	}
	after := map[string]bool{}
	if saved.Enabled {
		after = s.matchedAgentIDs(saved.Targets)
	}
	s.applyBaselineMembership(saved.ID, before, after)

	target := strconv.FormatInt(saved.ID, 10)
	checkIDs := make([]int64, 0, len(saved.Checks))
	for _, c := range saved.Checks {
		checkIDs = append(checkIDs, c.ID)
	}
	details := map[string]any{"name": saved.Name, "version": saved.Version, "checks": len(saved.Checks),
		"check_ids": checkIDs, "devices": len(after)}
	if len(res.DeletedChecks) > 0 {
		details["deleted_check_ids"] = res.DeletedChecks
	}
	// The hosts file is legitimately managed and legitimately abused: allowed,
	// but it goes in the audit entry by name (A34).
	if audited := auditedFilePaths(saved.Checks); len(audited) > 0 {
		details["audited_files"] = audited
	}
	if id == 0 {
		s.audit(r, "baseline.create", target, details)
	} else {
		s.audit(r, "baseline.update", target, details)
		if res.EnabledChanged {
			if saved.Enabled {
				s.audit(r, "baseline.enable", target, saved.Name)
			} else {
				s.audit(r, "baseline.disable", target, saved.Name)
			}
		}
	}
	for _, c := range saved.Checks {
		if c.Kind == "command" {
			s.audit(r, "baseline.command_check", target, map[string]any{"check": c.Name, "check_id": c.ID})
		}
		if checkAllowsReboot(c) {
			s.audit(r, "baseline.reboot_check", target, map[string]any{"check": c.Name, "check_id": c.ID})
		}
	}

	out, err := s.baselineDetail(saved.ID)
	if err != nil {
		fail(w, err)
		return
	}
	status := 200
	if id == 0 {
		status = 201
	}
	writeJSON(w, status, out)
}

func checksFromInput(in []baselineCheckInput) []BaselineCheck {
	out := make([]BaselineCheck, 0, len(in))
	for i, c := range in {
		out = append(out, BaselineCheck{ID: c.ID, Position: i, Name: c.Name, Kind: c.Kind, Params: c.Params,
			Remediate: c.Remediate, Severity: c.Severity, OSFilter: c.OSFilter, TimeoutSec: c.TimeoutSec})
	}
	return out
}

func (s *Server) handleDeleteBaseline(w http.ResponseWriter, r *http.Request) {
	id, err := pathInt(r, "id")
	if err != nil {
		writeErr(w, 400, "bad baseline id")
		return
	}
	b, err := s.db.GetBaseline(id)
	if err != nil {
		fail(w, err)
		return
	}
	before := s.matchedAgentIDs(b.Targets)
	// Resolve the alerts BEFORE the rows go: after the delete there is
	// nothing left to find them from, and nothing else ever resolves a drift
	// alert. The sweep is by KEY, not by the currently matched devices: a
	// device that drifted and then stopped matching still has this baseline's
	// alert open, and it would stay open forever.
	keys, err := s.db.openDriftKeysForBaseline(id)
	if err != nil {
		slog.Warn("collect drift alerts for baseline", "baseline", id, "err", err)
	}
	for _, k := range keys {
		s.alerts.resolveKey(k)
	}
	for agentID := range before {
		s.baselines.forgetDevice(agentID, id)
	}
	if err := s.db.DeleteBaseline(id); err != nil {
		fail(w, err)
		return
	}
	s.pushConfigTo(before)
	s.audit(r, "baseline.delete", strconv.FormatInt(id, 10), map[string]any{"name": b.Name, "devices": len(before)})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- status matrix ----

func (s *Server) handleBaselineStatus(w http.ResponseWriter, r *http.Request) {
	id, err := pathInt(r, "id")
	if err != nil {
		writeErr(w, 400, "bad baseline id")
		return
	}
	b, err := s.db.GetBaseline(id)
	if err != nil {
		fail(w, err)
		return
	}
	limit := int(queryInt(r, "limit", 200))
	if limit <= 0 {
		limit = 200
	}
	if limit > 500 {
		limit = 500
	}
	results, err := s.db.baselineResultsFor(id)
	if err != nil {
		fail(w, err)
		return
	}
	states, err := s.db.baselineStatesFor(id)
	if err != nil {
		fail(w, err)
		return
	}
	agents, err := s.agentsWithLiveness()
	if err != nil {
		fail(w, err)
		return
	}
	matched := matchAgents(agents, b.Targets)
	stats := s.baselineStatsFor(b, results, matched)
	changes, err := s.db.lastBaselineChanges()
	if err != nil {
		fail(w, err)
		return
	}

	truncated := false
	shown := matched
	if len(shown) > limit {
		shown, truncated = shown[:limit], true
	}
	devices := make([]baselineDeviceOut, 0, len(shown))
	for _, a := range shown {
		rs := results[a.ID]
		sort.Slice(rs, func(i, j int) bool { return rs[i].CheckID < rs[j].CheckID })
		c := countResults(rs, len(b.Checks))
		st := states[a.ID]
		d := baselineDeviceOut{
			AgentID: a.ID, AgentName: a.DisplayName, OS: a.OS, Online: a.Online, MaintenanceUntil: a.MaintenanceUntil,
			Compliance: c.score(), Version: st.Version, LastReport: st.LastReceivedAt, LastTrigger: st.LastTrigger,
			Counts: c, Results: rs,
		}
		if d.Results == nil {
			d.Results = []BaselineResult{}
		}
		for _, x := range rs {
			if x.Stale {
				d.Stale = true
				break
			}
		}
		devices = append(devices, d)
	}
	writeJSON(w, 200, map[string]any{
		"baseline": s.baselineOut(b, stats, len(b.Checks), changes[id]),
		"checks":   b.Checks,
		"devices":  devices,
		"summary": map[string]any{
			"devices": stats.Devices, "devices_reported": stats.DevicesReported,
			"devices_drifted": stats.DevicesDrifted, "devices_unknown": stats.DevicesUnknown,
			"compliance": stats.Compliance,
		},
		"truncated": truncated,
	})
}

// ---- evaluate ----

type agentActionOut struct {
	AgentID string `json:"agent_id"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
}

// handleBaselineEvaluate is a fan-out, so it is never a 409: an offline
// device is reported as offline per device and is simply not asked. It will
// run its own schedule and report when it reconnects.
func (s *Server) handleBaselineEvaluate(w http.ResponseWriter, r *http.Request) {
	id, err := pathInt(r, "id")
	if err != nil {
		writeErr(w, 400, "bad baseline id")
		return
	}
	b, err := s.db.GetBaseline(id)
	if err != nil {
		fail(w, err)
		return
	}
	if !b.Enabled {
		// A disabled baseline is not in any device's config, so the agent
		// would refuse the request. Saying "queued" for a pass that can never
		// arrive is worse than saying no.
		writeErr(w, 400, "this baseline is disabled: enable it before asking devices to evaluate it")
		return
	}
	var in struct {
		AgentIDs []string `json:"agent_ids"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if len(in.AgentIDs) > maxEvaluateAgents {
		// An explicit list is bounded: every id the caller names gets a row in
		// the answer whether it exists or not, so an unbounded list is an
		// unbounded response built out of nothing.
		writeErr(w, 400, fmt.Sprintf("at most %d devices may be named; leave agent_ids empty for every matched device", maxEvaluateAgents))
		return
	}
	matched := s.matchedAgentIDs(b.Targets)
	ids := in.AgentIDs
	if len(ids) == 0 {
		for agentID := range matched {
			ids = append(ids, agentID)
		}
		sort.Strings(ids)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		out = make([]agentActionOut, 0, len(ids))
	)
	add := func(res agentActionOut) {
		mu.Lock()
		out = append(out, res)
		mu.Unlock()
	}
	for _, agentID := range ids {
		agentID := agentID
		switch {
		case !matched[agentID]:
			add(agentActionOut{AgentID: agentID, Status: "error", Error: "device is not matched by this baseline"})
			continue
		case !s.hub.IsOnline(agentID):
			add(agentActionOut{AgentID: agentID, Status: "offline", Error: ErrAgentOffline.Error()})
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := agentActionOut{AgentID: agentID, Status: "queued"}
			// The reply is an ACK, not a report: the pass itself arrives as a
			// TypeBaseline frame, so it is ingested exactly once.
			if err := s.hub.Request(ctx, agentID, protocol.ReqBaselineEvaluate, protocol.BaselineEvaluate{BaselineIDs: []int64{b.ID}}, nil); err != nil {
				res.Status, res.Error = "error", err.Error()
				if errors.Is(err, ErrAgentOffline) {
					res.Status = "offline"
				}
			}
			add(res)
		}()
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].AgentID < out[j].AgentID })
	queued, offline := 0, 0
	for _, o := range out {
		switch o.Status {
		case "queued":
			queued++
		case "offline":
			offline++
		}
	}
	s.audit(r, "baseline.evaluate", strconv.FormatInt(id, 10), map[string]any{"name": b.Name, "requested": len(ids), "queued": queued})
	writeJSON(w, 200, map[string]any{
		"baseline_id": b.ID, "requested": len(ids), "queued": queued, "offline": offline, "agents": out,
	})
}

// ---- remediate ----

type refusedCheckOut struct {
	CheckID int64  `json:"check_id"`
	Reason  string `json:"reason"`
}

// handleBaselineRemediate asks one device to run fixes now. Unlike a script
// run there is no persisted run row to queue, so an offline device is a 409.
func (s *Server) handleBaselineRemediate(w http.ResponseWriter, r *http.Request) {
	id, err := pathInt(r, "id")
	if err != nil {
		writeErr(w, 400, "bad baseline id")
		return
	}
	b, err := s.db.GetBaseline(id)
	if err != nil {
		fail(w, err)
		return
	}
	if !b.Enabled {
		writeErr(w, 400, "this baseline is disabled: the device is not holding it, so there is nothing to remediate")
		return
	}
	var in struct {
		AgentID  string  `json:"agent_id"`
		CheckIDs []int64 `json:"check_ids"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	a, err := s.db.GetAgent(in.AgentID)
	if err != nil {
		fail(w, err)
		return
	}
	if !b.Targets.Matches(a) {
		writeErr(w, 400, "this device is not matched by the baseline")
		return
	}
	if !s.hub.IsOnline(a.ID) {
		fail(w, ErrAgentOffline)
		return
	}

	if len(in.CheckIDs) > maxChecksPerBaseline {
		writeErr(w, 400, fmt.Sprintf("a baseline has at most %d checks", maxChecksPerBaseline))
		return
	}
	byID := map[int64]BaselineCheck{}
	for _, c := range b.Checks {
		byID[c.ID] = c
	}
	want := in.CheckIDs
	if len(want) == 0 {
		// "every currently failing check that allows remediation" - NOT every
		// check: a manual remediate is a fix for the drift on screen.
		failing, err := s.db.failingCheckIDs(a.ID, b.ID)
		if err != nil {
			fail(w, err)
			return
		}
		for _, cid := range failing {
			if c, ok := byID[cid]; ok && c.Remediate {
				want = append(want, cid)
			}
		}
	}
	accepted := []int64{}
	refused := []refusedCheckOut{}
	for _, cid := range sortedInt64s(want) {
		c, ok := byID[cid]
		switch {
		case !ok:
			refused = append(refused, refusedCheckOut{CheckID: cid, Reason: "unknown check id"})
		case !c.Remediate:
			// Refused per check and reported, never silently skipped.
			refused = append(refused, refusedCheckOut{CheckID: cid, Reason: "remediation is disabled for this check"})
		default:
			accepted = append(accepted, cid)
		}
	}
	if len(accepted) > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), quickTimeout)
		defer cancel()
		if err := s.hub.Request(ctx, a.ID, protocol.ReqBaselineRemediate, protocol.BaselineRemediate{BaselineID: b.ID, CheckIDs: accepted}, nil); err != nil {
			fail(w, err)
			return
		}
	}
	s.audit(r, "baseline.remediate", strconv.FormatInt(id, 10), map[string]any{"name": b.Name, "agent_id": a.ID, "checks": accepted})
	writeJSON(w, 200, map[string]any{
		"baseline_id": b.ID, "agent_id": a.ID, "accepted": accepted, "refused": refused,
		// Always null: the agent ACKs and the pass arrives as a TypeBaseline
		// frame, which becomes a `baseline` SSE event the console refetches on.
		"report": nil,
	})
}

// ---- preview ----

type previewSpecCheck struct {
	Index    int    `json:"index"`
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	OSFilter string `json:"os_filter"`
}

type previewResultOut struct {
	CheckID    int64  `json:"check_id"`
	State      string `json:"state"`
	Expected   string `json:"expected"`
	Observed   string `json:"observed"`
	Detail     string `json:"detail"`
	Fixed      bool   `json:"fixed"`
	DurationMs int64  `json:"duration_ms"`
}

type previewDeviceOut struct {
	AgentID    string             `json:"agent_id"`
	AgentName  string             `json:"agent_name"`
	OS         string             `json:"os"`
	Status     string             `json:"status"`
	Error      string             `json:"error"`
	Results    []previewResultOut `json:"results"`
	DurationMs int64              `json:"duration_ms"`
}

// handleBaselinePreview dry-runs an unsaved spec. It never 409s: an offline
// device is an answer ("status":"offline"), not an error for the whole
// request. Check ids are synthetic negatives so the console can map results
// back to the rows it is editing; the server refuses to store them.
func (s *Server) handleBaselinePreview(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Spec struct {
			Name        string               `json:"name"`
			Enforce     bool                 `json:"enforce"`
			IntervalSec int                  `json:"interval_sec"`
			Checks      []baselineCheckInput `json:"checks"`
		} `json:"spec"`
		AgentIDs []string `json:"agent_ids"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if len(in.AgentIDs) == 0 {
		writeErr(w, 400, "agent_ids is required")
		return
	}
	if len(in.AgentIDs) > maxPreviewAgents {
		writeErr(w, 400, fmt.Sprintf("a preview may target at most %d devices", maxPreviewAgents))
		return
	}
	draft := baselineInput{Name: in.Spec.Name, IntervalSec: in.Spec.IntervalSec, Checks: in.Spec.Checks, AllowEmptyTargets: true}
	if draft.Name == "" {
		draft.Name = "preview"
	}
	if err := validateBaselineInput(&draft); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// A preview is part of authoring, and it RUNS the draft on real devices:
	// a `command` check's script executes as SYSTEM/root on every device
	// named here. The admin gate the save path applies has to hold on this
	// route too, or it is decoration - a non-admin could preview the check
	// instead of saving it and get exactly the same code run.
	draftChecks := checksFromInput(draft.Checks)
	if reasons := adminOnlyReasons(draftChecks); len(reasons) > 0 && !userFrom(r.Context()).IsAdmin() {
		writeErr(w, http.StatusForbidden, "admin only: "+reasons[0])
		return
	}

	spec := protocol.BaselineSpec{
		ID:   0,
		Name: draft.Name,
		// A preview never fixes and never persists: enforce is off on the
		// wire as well as ignored by the agent.
		Enforce:     false,
		IntervalSec: draft.IntervalSec,
		Checks:      make([]protocol.BaselineCheck, 0, len(draft.Checks)),
	}
	specChecks := make([]previewSpecCheck, 0, len(draft.Checks))
	for i, c := range draft.Checks {
		synthetic := int64(-(i + 1))
		spec.Checks = append(spec.Checks, protocol.BaselineCheck{
			ID: synthetic, Name: c.Name, Kind: c.Kind, Params: c.Params, Remediate: false,
			Severity: c.Severity, OSFilter: c.OSFilter, TimeoutSec: c.TimeoutSec,
		})
		specChecks = append(specChecks, previewSpecCheck{Index: i, ID: synthetic, Name: c.Name, Kind: c.Kind, OSFilter: c.OSFilter})
	}

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	devices := make([]previewDeviceOut, len(in.AgentIDs))
	var wg sync.WaitGroup
	for i, agentID := range in.AgentIDs {
		i, agentID := i, agentID
		d := previewDeviceOut{AgentID: agentID, Results: []previewResultOut{}}
		a, err := s.db.GetAgent(agentID)
		if err != nil {
			d.Status, d.Error = "error", "unknown device"
			devices[i] = d
			continue
		}
		d.AgentName, d.OS = a.DisplayName, a.OS
		if !s.hub.IsOnline(agentID) {
			d.Status, d.Error = "offline", ErrAgentOffline.Error()
			devices[i] = d
			continue
		}
		devices[i] = d
		wg.Add(1)
		go func() {
			defer wg.Done()
			devCtx, devCancel := context.WithTimeout(ctx, 60*time.Second)
			defer devCancel()
			started := time.Now()
			var rep protocol.BaselineReport
			err := s.hub.Request(devCtx, agentID, protocol.ReqBaselinePreview, protocol.BaselinePreview{Spec: spec}, &rep)
			d := devices[i]
			d.DurationMs = time.Since(started).Milliseconds()
			switch {
			case err == nil:
				d.Status = "ok"
				for _, res := range rep.Results {
					d.Results = append(d.Results, previewResultOut{
						CheckID: res.CheckID, State: res.State, Expected: baselines.Truncate(res.Expected, maxExpectedObservedBytes),
						Observed: baselines.Truncate(res.Observed, maxExpectedObservedBytes), Detail: baselines.Truncate(res.Detail, maxDetailBytes),
						// A preview never fixes anything, whatever the agent says.
						Fixed: false, DurationMs: res.DurationMs,
					})
				}
			case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
				d.Status, d.Error = "timeout", "the device did not answer in time"
			case errors.Is(err, ErrAgentOffline):
				d.Status, d.Error = "offline", ErrAgentOffline.Error()
			default:
				d.Status, d.Error = "error", err.Error()
			}
			devices[i] = d
		}()
	}
	wg.Wait()

	s.audit(r, "baseline.preview", "", map[string]any{"name": draft.Name, "checks": len(draft.Checks), "agents": in.AgentIDs})
	// A previewed `command` check ran code on those devices. It gets the same
	// audit action a saved one does, so "who made a device run a script"
	// stays one grep, with no baseline id because there is no baseline yet.
	for _, c := range draftChecks {
		if c.Kind == "command" {
			s.audit(r, "baseline.command_check", "", map[string]any{"check": c.Name, "preview": true, "agents": in.AgentIDs})
		}
	}
	writeJSON(w, 200, map[string]any{"spec_checks": specChecks, "devices": devices})
}

// ---- device view ----

type deviceBaselineCheckOut struct {
	BaselineCheck
	Result *BaselineResult `json:"result"`
}

func (s *Server) handleAgentBaselines(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	a, err := s.db.GetAgent(agentID)
	if err != nil {
		fail(w, err)
		return
	}
	a.Online = s.hub.IsOnline(a.ID)
	list, err := s.db.ListBaselinesWithChecks()
	if err != nil {
		fail(w, err)
		return
	}
	results, err := s.db.baselineResultsForAgent(agentID)
	if err != nil {
		fail(w, err)
		return
	}
	states, err := s.db.baselineStatesForAgent(agentID)
	if err != nil {
		fail(w, err)
		return
	}
	out := []map[string]any{}
	var total baselineCounts
	for _, b := range list {
		if !b.Enabled || !b.Targets.Matches(a) {
			continue
		}
		byCheck := map[int64]BaselineResult{}
		stale := false
		for _, res := range results[b.ID] {
			byCheck[res.CheckID] = res
			if res.Stale {
				stale = true
			}
		}
		checks := make([]deviceBaselineCheckOut, 0, len(b.Checks))
		for _, c := range b.Checks {
			row := deviceBaselineCheckOut{BaselineCheck: c}
			if res, ok := byCheck[c.ID]; ok {
				r := res
				row.Result = &r
			}
			checks = append(checks, row)
		}
		counts := countResults(results[b.ID], len(b.Checks))
		total.addAll(counts)
		st := states[b.ID]
		out = append(out, map[string]any{
			"id": b.ID, "name": b.Name, "enforce": b.Enforce, "enabled": b.Enabled, "interval_sec": b.IntervalSec,
			"version": b.Version, "last_report": st.LastReceivedAt, "last_trigger": st.LastTrigger, "stale": stale,
			"compliance": counts.score(), "counts": counts, "checks": checks,
		})
	}
	writeJSON(w, 200, map[string]any{
		"agent_id": a.ID, "online": a.Online, "compliance": total.score(), "baselines": out,
	})
}

func (s *Server) handleAgentBaselineHistory(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	limit := queryInt(r, "limit", 100)
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	// Optional: one baseline's transitions only. The status view's history
	// drawer is per baseline, and filtering the newest `limit` rows in the
	// browser shows an empty drawer whenever another baseline has been busier.
	baselineID := queryInt(r, "baseline_id", 0)
	rows, err := s.db.BaselineHistory(agentID, limit, baselineID)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"agent_id": agentID, "history": rows})
}

// ---- fleet compliance ----

type worstCheckOut struct {
	BaselineID   int64  `json:"baseline_id"`
	BaselineName string `json:"baseline_name"`
	CheckID      int64  `json:"check_id"`
	CheckName    string `json:"check_name"`
	Kind         string `json:"kind"`
	Severity     string `json:"severity"`
	Failing      int    `json:"failing"`
	Applicable   int    `json:"applicable"`
}

type byBaselineOut struct {
	ID             int64    `json:"id"`
	Name           string   `json:"name"`
	Enabled        bool     `json:"enabled"`
	Enforce        bool     `json:"enforce"`
	Score          *float64 `json:"score"`
	Devices        int      `json:"devices"`
	DevicesDrifted int      `json:"devices_drifted"`
}

func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request) {
	list, err := s.db.ListBaselinesWithChecks()
	if err != nil {
		fail(w, err)
		return
	}
	results, err := s.db.allBaselineResults()
	if err != nil {
		fail(w, err)
		return
	}
	agents, err := s.db.ListAgents()
	if err != nil {
		fail(w, err)
		return
	}

	perDevice := map[string]*baselineCounts{}
	checksAssigned := map[string]int{}
	type checkStat struct {
		check      BaselineCheck
		baseline   *Baseline
		failing    int
		applicable int
	}
	checkStats := map[int64]*checkStat{}
	byBaseline := []byBaselineOut{}
	enabled, enforcing := 0, 0

	for _, b := range list {
		if b.Enabled {
			enabled++
		}
		if b.Enabled && b.Enforce {
			enforcing++
		}
		matched := matchAgents(agents, b.Targets)
		st := s.baselineStatsFor(b, results[b.ID], matched)
		byBaseline = append(byBaseline, byBaselineOut{ID: b.ID, Name: b.Name, Enabled: b.Enabled, Enforce: b.Enforce,
			Score: st.Compliance, Devices: st.Devices, DevicesDrifted: st.DevicesDrifted})
		if !b.Enabled {
			continue
		}
		for _, c := range b.Checks {
			checkStats[c.ID] = &checkStat{check: c, baseline: b}
		}
		for _, a := range matched {
			if perDevice[a.ID] == nil {
				perDevice[a.ID] = &baselineCounts{}
			}
			checksAssigned[a.ID] += len(b.Checks)
			c := countResults(results[b.ID][a.ID], len(b.Checks))
			perDevice[a.ID].addAll(c)
			for _, res := range results[b.ID][a.ID] {
				cs := checkStats[res.CheckID]
				if cs == nil || res.Stale {
					continue
				}
				if res.State != "skipped" {
					cs.applicable++
				}
				if res.State == "fail" || res.State == "error" {
					cs.failing++
				}
			}
		}
	}

	var (
		scores                                                        []*float64
		devicesCompliant, devicesDrifted, devicesUnknown, checksTotal int
		checksFailing, checksError                                    int
	)
	for id, c := range perDevice {
		checksTotal += checksAssigned[id]
		checksFailing += c.Fail
		checksError += c.Error
		sc := c.score()
		scores = append(scores, sc)
		switch {
		case sc == nil:
			devicesUnknown++
		case c.drifted():
			devicesDrifted++
		default:
			devicesCompliant++
		}
	}

	worst := make([]worstCheckOut, 0, len(checkStats))
	for _, cs := range checkStats {
		if cs.failing == 0 {
			continue
		}
		worst = append(worst, worstCheckOut{BaselineID: cs.baseline.ID, BaselineName: cs.baseline.Name,
			CheckID: cs.check.ID, CheckName: cs.check.Name, Kind: cs.check.Kind, Severity: cs.check.Severity,
			Failing: cs.failing, Applicable: cs.applicable})
	}
	sort.Slice(worst, func(i, j int) bool {
		if worst[i].Failing != worst[j].Failing {
			return worst[i].Failing > worst[j].Failing
		}
		return worst[i].CheckID < worst[j].CheckID
	})
	if len(worst) > 10 {
		worst = worst[:10]
	}
	sort.Slice(byBaseline, func(i, j int) bool { return byBaseline[i].Name < byBaseline[j].Name })

	writeJSON(w, 200, map[string]any{
		"score": meanScore(scores), "devices_total": len(agents), "devices_with_baselines": len(perDevice),
		"devices_compliant": devicesCompliant, "devices_drifted": devicesDrifted, "devices_unknown": devicesUnknown,
		"checks_total": checksTotal, "checks_failing": checksFailing, "checks_error": checksError,
		"open_drift_alerts": s.db.countOpenDriftAlerts(), "baselines_enabled": enabled, "baselines_enforcing": enforcing,
		"worst_checks": worst, "by_baseline": byBaseline, "updated_at": now(),
	})
}
