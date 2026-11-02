package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// Windows servicing repair (docs/plans/2026-10-24-phase4c-servicing-repair.md).
//
// When Windows Update fails because the servicing stack or the update catalog
// is damaged, the agent can repair it (protocol.ReqServicingRepair). An
// operator starts that by hand through the signing flow; a patch policy with
// repair = "auto" starts it by itself, under the policy's standing approval,
// at most once per device per day.

// servicingCooldown is how long an automatic repair holds off the next one on
// the same device. A repair that did not cure the error would otherwise run
// again after every scan, and each one stops the update services and renames
// two directories.
const servicingCooldown = 24 * time.Hour

// servicingCode is one servicing error code the server recognises.
type servicingCode struct {
	// Why is the sentence the console and the alert show: what the code means
	// for the update stack.
	Why string
	// WUAOnly marks codes that are generic Win32 errors (file or path not
	// found). They count only in the error of a Windows Update scan, never in
	// an install's per-update failure reasons: those include driver and other
	// updates whose own file-not-found says nothing about the update stack.
	WUAOnly bool
}

// servicingCodes is the one table of codes that start an automatic repair.
var servicingCodes = map[string]servicingCode{
	"0x80240020": {Why: "Windows Update could not complete because its session state is broken (no interactive user for the operation)."},
	"0x80073712": {Why: "A file the servicing stack needs is missing from the component store, so the store is corrupt."},
	"0x800F081F": {Why: "The source files needed to repair or install a component could not be found in the component store."},
	"0x800F0922": {Why: "The servicing stack could not install the update, which usually points at a damaged component store."},
	"0x800F0831": {Why: "A package manifest the update depends on is missing from the component store."},
	"0x80070002": {Why: "Windows Update could not find a file it needs, which a damaged update catalog or component store causes.", WUAOnly: true},
	"0x80070003": {Why: "Windows Update could not find a path it needs, which a damaged update catalog or component store causes.", WUAOnly: true},
	"0x8024A105": {Why: "Automatic Updates could not service the request, which usually means its state or catalog is damaged."},
	"0x80240034": {Why: "The update download failed, often because the download cache is damaged."},
	"0x80244022": {Why: "The update service kept answering that it is unavailable, which resetting the update catalog sometimes clears."},
	"0x8007000E": {Why: "Windows Update ran out of memory, which a damaged update catalog can cause."},
	"0x80070020": {Why: "A file the update needs is locked by another process, commonly a stuck Windows Update component."},
}

// servicingMu serializes the cooldown check and the insert of an automatic
// repair record.
var servicingMu sync.Mutex

var sha256HexRE = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

var hresultRE = regexp.MustCompile(`0[xX]8[0-9A-Fa-f]{7}`)

// parseServicingCode returns the first servicing error code in text, in the
// table's canonical spelling (upper-case hex after 0x), or "". Text is a scan
// error or an install failure reason. The agent joins a winget failure onto a
// scan's error with "; ", and a winget message must not start a Windows
// repair, so those parts are ignored.
func parseServicingCode(text string) string {
	return parseServicingCodeIn(text, true)
}

// parseServicingCodeIn is parseServicingCode for text from a scan error
// (scan true) or from an install's failure reasons (scan false); only a scan
// error may carry a WUAOnly code.
func parseServicingCodeIn(text string, scan bool) string {
	for _, part := range strings.Split(text, "; ") {
		if strings.Contains(strings.ToLower(part), "winget") {
			continue
		}
		for _, m := range hresultRE.FindAllString(part, -1) {
			code := "0x" + strings.ToUpper(m[2:])
			if c, ok := servicingCodes[code]; ok && (scan || !c.WUAOnly) {
				return code
			}
		}
	}
	return ""
}

// failedReasons joins the reasons of an install's failed updates.
func failedReasons(failed map[string]string) string {
	keys := make([]string, 0, len(failed))
	for k := range failed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, failed[k])
	}
	return strings.Join(parts, "; ")
}

// ---- records ----

// ServicingRecord is one row of servicing_repairs.
type ServicingRecord struct {
	ID         int64           `json:"id"`
	AgentID    string          `json:"agent_id"`
	PolicyID   *int64          `json:"policy_id"`
	Trigger    string          `json:"trigger"` // manual, auto
	Code       string          `json:"code"`
	Why        string          `json:"why,omitempty"` // what Code means
	StartedAt  int64           `json:"started_at"`
	FinishedAt int64           `json:"finished_at"`
	Status     string          `json:"status"` // running, ok, failed
	Result     json.RawMessage `json:"result"`
	By         string          `json:"by"`
}

func (d *DB) insertServicing(agentID string, policyID *int64, trigger, code, by string) (int64, error) {
	res, err := d.Exec(`INSERT INTO servicing_repairs(agent_id, policy_id, trigger, code, started_at, status, result, "by") VALUES(?,?,?,?,?,'running','{}',?)`,
		agentID, policyID, trigger, code, now(), by)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) finishServicing(id int64, status string, result any) {
	d.Exec(`UPDATE servicing_repairs SET status = ?, finished_at = ?, result = ? WHERE id = ?`, status, now(), jsonText(result), id)
}

// failStaleServicing finishes the records a server death left in 'running'.
// A repair lasts at most servicingRequestTimeout, so a running row older than
// that (olderThan seconds before now; 0 at startup, when nothing can still be
// running) will never be finished by anyone, and it would hold off every
// later repair on the device and keep the console's repair button disabled.
func (d *DB) failStaleServicing(olderThan int64) {
	d.Exec(`UPDATE servicing_repairs SET status = 'failed', finished_at = ?, result = ? WHERE status = 'running' AND started_at <= ?`,
		now(), jsonText(map[string]string{"error": "the server restarted while the repair was running, so its outcome is unknown"}), now()-olderThan)
}

func (d *DB) listServicing(agentID string, limit int64) ([]ServicingRecord, error) {
	rows, err := d.Query(`SELECT id, agent_id, policy_id, trigger, code, started_at, finished_at, status, result, "by"
		FROM servicing_repairs WHERE agent_id = ? ORDER BY started_at DESC, id DESC LIMIT ?`, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ServicingRecord{}
	for rows.Next() {
		var r ServicingRecord
		var pid sql.NullInt64
		var res string
		if err := rows.Scan(&r.ID, &r.AgentID, &pid, &r.Trigger, &r.Code, &r.StartedAt, &r.FinishedAt, &r.Status, &res, &r.By); err != nil {
			return nil, err
		}
		if pid.Valid {
			r.PolicyID = &pid.Int64
		}
		if json.Valid([]byte(res)) {
			r.Result = json.RawMessage(res)
		} else {
			r.Result = json.RawMessage(`{}`)
		}
		r.Why = servicingCodes[r.Code].Why
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- running a repair ----

// servicingJob is one repair about to run on one device.
type servicingJob struct {
	id      int64
	agentID string
	trigger string
	by      string
	code    string
	req     protocol.ServicingRepair
	auth    *protocol.ActionAuth
}

// servicingClaimWait is how long an automatic repair waits for a running
// patch job to end before it gives up; it is a variable so tests can shorten
// it. DISM cannot run beside a Windows Update scan or install, and the repair
// is queued from inside one.
var servicingClaimWait = 10 * time.Minute

// servicingRequestTimeout bounds one repair: DISM 60 min, SFC 30 min, a
// package download and add, a rescan.
const servicingRequestTimeout = 4 * time.Hour

// defaultRepairSteps is what an automatic repair sends and a standing approval
// names. They are in the agent's canonical order.
func defaultRepairSteps() []string {
	return []string{protocol.ServicingDismRestore, protocol.ServicingResetComponents, protocol.ServicingRescan}
}

// repairReboot is the reboot setting a repair of policy p carries: repairs
// only ever restart when one is required, so a policy that reboots always
// after installs gets the same if_required here.
func repairReboot(p *PatchPolicy) string {
	if p.Reboot == "if_required" || p.Reboot == "always" {
		return "if_required"
	}
	return "never"
}

func repairRequest(p *PatchPolicy) protocol.ServicingRepair {
	return protocol.ServicingRepair{Steps: defaultRepairSteps(), Reboot: repairReboot(p)}
}

// repairUnit is the standing approval a policy's automatic repairs run under.
func repairUnit(p *PatchPolicy) approvalUnit {
	req := repairRequest(p)
	c := actionauth.Constraints{Op: protocol.ReqServicingRepair, Steps: req.Steps, Reboot: req.Reboot}
	return approvalUnit{Type: approvalPatchPolicy, ID: strconv.FormatInt(p.ID, 10), Purpose: "repair", Name: p.Name + " (servicing repair)", Cons: c, Hash: unitHash(c, "")}
}

// executeRepair sends the request and records the outcome. The caller holds
// the device's patch job.
func (s *Server) executeRepair(j servicingJob) {
	ctx, cancel := context.WithTimeout(s.jobContext(), servicingRequestTimeout)
	defer cancel()
	var res protocol.ServicingRepairResult
	err := s.hub.RequestA(ctx, j.agentID, protocol.ReqServicingRepair, j.req, &res, j.auth)
	label := s.alerts.agentLabel(j.agentID)
	var status, msg string
	var stored any
	switch {
	case err != nil:
		status = "failed"
		msg = fmt.Sprintf("Servicing repair failed on %s: %s", label, err.Error())
		stored = map[string]string{"error": err.Error()}
	default:
		status = "ok"
		var failedStep string
		for _, st := range res.Steps {
			if st.Status == "failed" && st.Name != protocol.ServicingSFC {
				status, failedStep = "failed", st.Name
				break
			}
		}
		msg = fmt.Sprintf("Servicing repair finished on %s: ok", label)
		if status == "failed" {
			msg = fmt.Sprintf("Servicing repair finished on %s: step %s failed", label, failedStep)
		}
		stored = res
		if res.Scan != nil {
			s.db.SetSetting("last_patch_scan_error:"+j.agentID, res.Scan.Error)
		}
		s.db.Exec(`UPDATE agents SET pending_reboot = ? WHERE id = ?`, res.RebootRequired || (res.Scan != nil && res.Scan.RebootPending), j.agentID)
	}
	ts := now()
	s.db.Exec(`INSERT INTO agent_events(agent_id, ts, kind, message, fields) VALUES(?,?,?,?,?)`, j.agentID, ts, "patch", msg, jsonText(map[string]any{"servicing_repair": j.id, "status": status}))
	s.hub.broadcast(hubEvent{Kind: "event", AgentID: j.agentID, Data: map[string]any{"ts": ts, "kind": "patch", "message": msg}})
	s.hub.broadcast(hubEvent{Kind: "patches", AgentID: j.agentID})
	s.db.Audit(j.by, "", "servicing.repair", j.agentID, map[string]any{"id": j.id, "status": status, "trigger": j.trigger, "code": j.code})
	if j.trigger == "auto" {
		s.alerts.event(j.agentID, &protocol.Event{Kind: "servicing_finished", Message: msg})
	}
	// The record turns final last: whoever sees it finished can rely on the
	// audit row, the event and the alert already being there.
	s.db.finishServicing(j.id, status, stored)
}

// ---- automatic repair ----

// repairPolicyFor is the first enabled auto-repair policy whose targets reach
// the device.
func (s *Server) repairPolicyFor(a *Agent) *PatchPolicy {
	pols, err := s.db.ListPatchPolicies()
	if err != nil {
		return nil
	}
	for i := range pols {
		if p := &pols[i]; p.Enabled && p.Repair == "auto" && p.Targets.Matches(a) {
			return p
		}
	}
	return nil
}

// autoRepairAfter is called with the error text of a finished scan or the
// failure reasons of a finished install. When the text carries a servicing
// code and a policy allows it, one repair is queued for the device and
// recorded; nothing here blocks the scan or install that called it.
func (s *Server) autoRepairAfter(agentID, text string) {
	s.autoRepair(agentID, text, true)
}

// autoRepairAfterInstall is autoRepairAfter for an install's failure reasons,
// which may not start a repair on a generic file-not-found code.
func (s *Server) autoRepairAfterInstall(agentID, text string) {
	s.autoRepair(agentID, text, false)
}

func (s *Server) autoRepair(agentID, text string, scan bool) {
	code := parseServicingCodeIn(text, scan)
	if code == "" {
		return
	}
	a, err := s.db.GetAgent(agentID)
	if err != nil || a.OS != "windows" {
		return
	}
	p := s.repairPolicyFor(a)
	if p == nil {
		return
	}
	// The check and the insert are one step: a scan and an install ending
	// together must not both start a repair.
	servicingMu.Lock()
	var recent int
	s.db.QueryRow(`SELECT COUNT(*) FROM servicing_repairs WHERE agent_id = ? AND ((status = 'running' AND started_at > ?) OR (trigger = 'auto' AND started_at > ?))`,
		agentID, now()-int64(servicingRequestTimeout/time.Second), now()-int64(servicingCooldown/time.Second)).Scan(&recent)
	if recent > 0 {
		servicingMu.Unlock()
		slog.Info("automatic servicing repair skipped: one ran in the last day or is running", "agent", agentID, "code", code)
		return
	}
	by := "policy:" + p.Name
	id, err := s.db.insertServicing(agentID, &p.ID, "auto", code, by)
	servicingMu.Unlock()
	if err != nil {
		slog.Warn("cannot record a servicing repair", "agent", agentID, "err", err)
		return
	}
	label := agentLabel(a)
	start := fmt.Sprintf("Servicing repair started on %s after %s: %s", label, code, servicingCodes[code].Why)
	s.db.Audit(by, "", "servicing.repair.auto", agentID, map[string]any{"id": id, "code": code, "policy": p.Name})
	s.alerts.event(agentID, &protocol.Event{Kind: "servicing_started", Message: start})
	j := servicingJob{id: id, agentID: agentID, trigger: "auto", by: by, code: code, req: repairRequest(p),
		auth: s.standingAuthForUnit(agentID, repairUnit(p), true)}
	s.goJob(func() {
		release, ok := s.waitPatchJob(agentID, servicingClaimWait)
		if !ok {
			// Nothing ran, so the record must not spend the day's cooldown
			// either; the device gets its repair at the next failing scan.
			s.db.Exec(`DELETE FROM servicing_repairs WHERE id = ?`, id)
			msg := fmt.Sprintf("Servicing repair did not start on %s: a patch job kept the device busy", label)
			s.alerts.event(agentID, &protocol.Event{Kind: "servicing_finished", Message: msg})
			s.hub.broadcast(hubEvent{Kind: "patches", AgentID: agentID})
			return
		}
		defer release()
		s.executeRepair(j)
	})
}

// waitPatchJob claims the device's patch job, retrying until wait has passed.
func (s *Server) waitPatchJob(agentID string, wait time.Duration) (func(), bool) {
	deadline := time.Now().Add(wait)
	for {
		if release, ok := s.claimPatchJob(agentID); ok {
			return release, true
		}
		if time.Now().After(deadline) || s.jobContext().Err() != nil {
			return nil, false
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ---- handlers ----

func (s *Server) handleListServicing(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.getScopedAgent(w, r, id); !ok {
		return
	}
	limit := queryInt(r, "limit", 20)
	if limit < 1 {
		limit = 1
	} else if limit > 200 {
		limit = 200
	}
	list, err := s.db.listServicing(id, limit)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// validateRepairRequest settles what will be sent: defaults are filled in
// because a signature covers the concrete payload.
func validateRepairRequest(in *protocol.ServicingRepair) error {
	if len(in.Steps) == 0 {
		in.Steps = defaultRepairSteps()
	}
	known := map[string]bool{
		protocol.ServicingDismRestore: true, protocol.ServicingSFC: true, protocol.ServicingResetComponents: true,
		protocol.ServicingAddPackage: true, protocol.ServicingRescan: true,
	}
	seen := map[string]bool{}
	var steps []string
	for _, st := range in.Steps {
		if !known[st] {
			return fmt.Errorf("unknown repair step %q", st)
		}
		if !seen[st] {
			seen[st] = true
			steps = append(steps, st)
		}
	}
	in.Steps = steps
	switch in.Reboot {
	case "":
		in.Reboot = "never"
	case "never", "if_required":
	default:
		return errors.New(`reboot must be "never" or "if_required"`)
	}
	if in.Package != nil {
		u, err := url.Parse(in.Package.URL)
		ext := ""
		if err == nil {
			ext = strings.ToLower(path.Ext(u.Path))
		}
		switch {
		case err != nil || u.Scheme != "https" || u.Host == "":
			return errors.New("the package url must be an https URL")
		case ext != ".cab" && ext != ".msu":
			return errors.New("the package must be a .cab or .msu file")
		case !sha256HexRE.MatchString(in.Package.SHA256):
			return errors.New("the package needs a SHA-256 hash of 64 hex digits")
		}
		if !seen[protocol.ServicingAddPackage] {
			return errors.New("a package was given but the add_package step is not selected")
		}
	} else if seen[protocol.ServicingAddPackage] {
		return errors.New("the add_package step needs a package")
	}
	return nil
}

func (s *Server) handleServicingRepair(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, ok := s.getScopedAgent(w, r, id)
	if !ok {
		return
	}
	if a.OS != "windows" {
		writeErr(w, http.StatusBadRequest, "servicing repair is a Windows operation")
		return
	}
	var in protocol.ServicingRepair
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if err := validateRepairRequest(&in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.hub.IsOnline(id) {
		fail(w, ErrAgentOffline)
		return
	}
	req := in
	s.runSigned(w, r, signedAction{
		Org: a.OrgID, Op: protocol.ReqServicingRepair, Targets: []string{id}, Payload: req,
		Summary: fmt.Sprintf("Repair Windows servicing on %s (%s)%s", agentLabel(a), strings.Join(req.Steps, ", "),
			map[bool]string{true: ", rebooting if required", false: ""}[req.Reboot == "if_required"]),
		Run: func(w http.ResponseWriter, r *http.Request, auth *protocol.ActionAuth) {
			release, ok := s.claimPatchJob(id)
			if !ok {
				writeErr(w, http.StatusConflict, errPatchBusy.Error())
				return
			}
			by := actor(r)
			recID, err := s.db.insertServicing(id, nil, "manual", "", by)
			if err != nil {
				release()
				fail(w, err)
				return
			}
			s.audit(r, "servicing.repair.request", id, req)
			j := servicingJob{id: recID, agentID: id, trigger: "manual", by: by, req: req, auth: auth}
			s.goJob(func() {
				defer release()
				s.executeRepair(j)
			})
			writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "id": recID})
		},
	})
}
