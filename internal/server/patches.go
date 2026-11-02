package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

type Patch struct {
	AgentID        string   `json:"agent_id"`
	AgentName      string   `json:"agent_name,omitempty"`
	PatchID        string   `json:"patch_id"`
	Title          string   `json:"title"`
	KB             string   `json:"kb"`
	Severity       string   `json:"severity"`
	Categories     []string `json:"categories"`
	Size           int64    `json:"size"`
	Source         string   `json:"source"`
	Version        string   `json:"version"`
	Status         string   `json:"status"`
	RebootRequired bool     `json:"reboot_required"`
	// Downloaded is Windows Update's IsDownloaded: the payload is already on
	// the device and the size beside it is not a download that still has to
	// happen. Description is the agent's (truncated) update description.
	Downloaded  bool   `json:"downloaded"`
	Description string `json:"description,omitempty"`
	FirstSeen   int64  `json:"first_seen"`
	LastSeen    int64  `json:"last_seen"`
	InstalledAt int64  `json:"installed_at"`
	Error       string `json:"error"`
}

// patchSeverityRank orders the severity TEXT column worst-first. SQLite sorts
// TEXT lexicographically, so the old `severity DESC` put Critical below
// Unspecified, Moderate and Low, and the LIMIT truncated the worst patches
// first.
//
// Critical/Important/Moderate/Low are Windows Update's MSRC ratings.
// "security" is what apt, dnf and zypper set (internal/agent/linuxparse.go)
// and is the ONLY non-empty severity a Linux device ever reports, so it has
// to rank with the rated updates rather than fall into the unrated bucket -
// otherwise the LIMIT cuts a distro's security updates like any other row.
// It ties with Important on purpose: an advisory covers the update but the
// distro gave no rating. ORDER BY breaks the tie on title.
const patchSeverityRank = `CASE UPPER(p.severity) WHEN 'CRITICAL' THEN 0 WHEN 'IMPORTANT' THEN 1 WHEN 'SECURITY' THEN 1 WHEN 'MODERATE' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END`

// patchSourceInstallable excludes the sources the agent cannot install from a
// bulk approve or an "install everything approved" batch. winget rows are
// reported for visibility only: the agent service account cannot install
// them (see internal/agent/updates_windows.go).
const patchSourceInstallable = ` AND source <> 'winget'`

type PatchPolicy struct {
	ID              int64   `json:"id"`
	Name            string  `json:"name"`
	Targets         Targets `json:"targets"`
	ScanSchedule    string  `json:"scan_schedule"`
	InstallSchedule string  `json:"install_schedule"`
	Mode            string  `json:"mode"`
	Reboot          string  `json:"reboot"`
	// Repair is "off" (the default) or "auto": with auto, a scan or install
	// that reports a servicing error code starts one servicing repair on the
	// device (see servicing.go).
	Repair    string `json:"repair"`
	Enabled   bool   `json:"enabled"`
	CreatedAt int64  `json:"created_at"`
}

func (d *DB) ListPatches(agentID, status string, limit int64) ([]Patch, error) {
	q := `SELECT p.agent_id, COALESCE(NULLIF(a.display_name,''), a.hostname, ''), p.patch_id, p.title, p.kb, p.severity, p.categories, p.size, p.source, p.version, p.status, p.reboot_required, p.downloaded, p.description, p.first_seen, p.last_seen, p.installed_at, p.error
		FROM patches p LEFT JOIN agents a ON a.id = p.agent_id WHERE 1=1`
	args := []any{}
	if agentID != "" {
		q += ` AND p.agent_id = ?`
		args = append(args, agentID)
	}
	if status != "" && status != "all" {
		q += ` AND p.status = ?`
		args = append(args, status)
	}
	q += ` ORDER BY p.status, ` + patchSeverityRank + `, p.title LIMIT ?`
	args = append(args, limit)
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Patch{}
	for rows.Next() {
		var p Patch
		var cats string
		if err := rows.Scan(&p.AgentID, &p.AgentName, &p.PatchID, &p.Title, &p.KB, &p.Severity, &cats, &p.Size, &p.Source, &p.Version, &p.Status, &p.RebootRequired, &p.Downloaded, &p.Description, &p.FirstSeen, &p.LastSeen, &p.InstalledAt, &p.Error); err != nil {
			return nil, err
		}
		// The API promises an array. Rows written before categories were
		// stored as "[]" hold the literal "null", which unmarshals a
		// pre-initialised slice straight back to nil.
		p.Categories = []string{}
		var cl []string
		if json.Unmarshal([]byte(cats), &cl) == nil && cl != nil {
			p.Categories = cl
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// patchCategories marshals an update's categories for storage. A nil slice
// marshals to the literal "null", which the column (NOT NULL DEFAULT '[]')
// and the published Patch type both say it is not.
func patchCategories(c []string) string {
	if c == nil {
		c = []string{}
	}
	return jsonText(c)
}

func (d *DB) ListPatchPolicies() ([]PatchPolicy, error) {
	rows, err := d.Query(`SELECT id, name, targets, scan_schedule, install_schedule, mode, reboot, repair, enabled, created_at FROM patch_policies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PatchPolicy{}
	for rows.Next() {
		var p PatchPolicy
		var t string
		if err := rows.Scan(&p.ID, &p.Name, &t, &p.ScanSchedule, &p.InstallSchedule, &p.Mode, &p.Reboot, &p.Repair, &p.Enabled, &p.CreatedAt); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(t), &p.Targets)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (d *DB) GetPatchPolicy(id int64) (*PatchPolicy, error) {
	policies, err := d.ListPatchPolicies()
	if err != nil {
		return nil, err
	}
	for i := range policies {
		if policies[i].ID == id {
			return &policies[i], nil
		}
	}
	return nil, errNotFound
}

// errPatchBusy is returned when a device already has a patch job running.
// Patch work is serialised per device: two overlapping installs used to mark
// each other's in-flight patches failed, and a scan that overlapped an install
// could flip 'installing' rows to 'installed' before the result arrived.
var errPatchBusy = errors.New("a patch scan or installation is already running on this device")

// claimPatchJob reserves a device for one patch job. The returned release must
// be called when the job ends; ok is false when another job holds it.
func (s *Server) claimPatchJob(agentID string) (release func(), ok bool) {
	s.patchMu.Lock()
	defer s.patchMu.Unlock()
	if s.patchJobs[agentID] {
		return nil, false
	}
	s.patchJobs[agentID] = true
	var once sync.Once
	return func() {
		once.Do(func() {
			s.patchMu.Lock()
			delete(s.patchJobs, agentID)
			s.patchMu.Unlock()
		})
	}, true
}

// patchScan asks the agent for its update list and reconciles the table:
// new ids are inserted as available, known ones refreshed, and ids no longer
// reported (installed out of band) are marked installed.
func (s *Server) patchScan(agentID string) error {
	release, ok := s.claimPatchJob(agentID)
	if !ok {
		return errPatchBusy
	}
	defer release()
	return s.patchScanLocked(agentID)
}

func (s *Server) patchScanLocked(agentID string) error {
	ctx, cancel := context.WithTimeout(s.jobContext(), 15*time.Minute)
	defer cancel()
	var res protocol.UpdatesScanResult
	if err := s.hub.Request(ctx, agentID, protocol.ReqUpdatesScan, nil, &res); err != nil {
		slog.Warn("patch scan failed", "agent", agentID, "err", err)
		return err
	}
	// The agent reports a partial result rather than nothing when its package
	// index could not be refreshed. Dropping res.Error made a failed refresh
	// look like a clean scan: a fresh "scanned just now" timestamp beside a
	// stale package list, with nothing anywhere saying why.
	s.db.SetSetting("last_patch_scan_error:"+agentID, res.Error)
	if res.Error != "" {
		slog.Warn("patch scan reported a problem", "agent", agentID, "err", res.Error)
	}
	seen := map[string]bool{}
	ts := now()
	for _, u := range res.Updates {
		seen[u.ID] = true
		status := "available"
		if u.Installed {
			status = "installed"
		}
		s.db.Exec(`INSERT INTO patches(agent_id, patch_id, title, kb, severity, categories, size, source, version, status, reboot_required, downloaded, description, first_seen, last_seen, installed_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(agent_id, patch_id) DO UPDATE SET title=excluded.title, kb=excluded.kb, severity=excluded.severity, categories=excluded.categories,
				size=excluded.size, version=excluded.version, reboot_required=excluded.reboot_required, downloaded=excluded.downloaded,
				description=excluded.description, last_seen=excluded.last_seen,
				status = CASE WHEN patches.status IN ('approved','ignored','installing') AND excluded.status='available' THEN patches.status ELSE excluded.status END,
				installed_at = CASE WHEN excluded.status='installed' AND patches.installed_at=0 THEN excluded.last_seen
					WHEN excluded.status='available' AND patches.status='installed' THEN 0
					ELSE patches.installed_at END`,
			agentID, u.ID, u.Title, u.KB, u.Severity, patchCategories(u.Categories), u.SizeBytes, u.Source, u.Version, status, u.RebootReq, u.Downloaded, u.Description, ts, ts, map[bool]int64{true: ts, false: 0}[u.Installed])
	}
	// An id the agent offers again after the table called it installed was
	// never installed (or a sweep over a broken scan decided it was), so the
	// stale installed_at goes with the status.
	//
	// Anything previously pending that the agent no longer lists was installed
	// elsewhere - but only believe that when the scan itself was clean:
	// a scan whose index refresh failed lists from a stale cache, and
	// 'installing' rows belong to an install that has not reported yet.
	if res.Error == "" {
		rows, err := s.db.Query(`SELECT patch_id FROM patches WHERE agent_id = ? AND status IN ('available','approved')`, agentID)
		if err == nil {
			var gone []string
			for rows.Next() {
				var id string
				rows.Scan(&id)
				if !seen[id] {
					gone = append(gone, id)
				}
			}
			rows.Close()
			for _, id := range gone {
				s.db.Exec(`UPDATE patches SET status='installed', installed_at=? WHERE agent_id=? AND patch_id=?`, ts, agentID, id)
				s.alerts.patchResolved(agentID, id)
			}
		}
	}
	s.db.Exec(`UPDATE agents SET pending_reboot = ? WHERE id = ?`, res.RebootPending, agentID)
	s.db.SetSetting("last_patch_scan:"+agentID, strconv.FormatInt(ts, 10))
	missingCount := 0
	for _, u := range res.Updates {
		if !u.Installed {
			missingCount++
		}
	}
	scanMsg := fmt.Sprintf("Patch scan completed: %d missing updates detected", missingCount)
	s.db.Exec(`INSERT INTO agent_events(agent_id, ts, kind, message, fields) VALUES(?,?,?,?,?)`, agentID, ts, "patch", scanMsg, jsonText(map[string]any{"updates_found": missingCount}))
	s.hub.broadcast(hubEvent{Kind: "event", AgentID: agentID, Data: map[string]any{"ts": ts, "kind": "patch", "message": scanMsg}})
	s.hub.broadcast(hubEvent{Kind: "patches", AgentID: agentID})
	// A scan that failed on a damaged update stack is what an automatic
	// servicing repair reacts to.
	s.autoRepairAfter(agentID, res.Error)
	return nil
}

// patchInstall installs the given ids (nil = every approved patch) and records the outcome.
func (s *Server) patchInstall(agentID string, ids []string, reboot bool, by string, auth *protocol.ActionAuth) (*protocol.UpdatesInstallResult, error) {
	release, ok := s.claimPatchJob(agentID)
	if !ok {
		return nil, errPatchBusy
	}
	defer release()
	return s.patchInstallLocked(agentID, ids, reboot, by, auth)
}

// installablePatchIDs are the ids an "install everything" request will send:
// what is available or already approved and installable by the agent.
func (s *Server) installablePatchIDs(agentID string) []string {
	rows, err := s.db.Query(`SELECT patch_id FROM patches WHERE agent_id = ? AND status IN ('available','approved')`+patchSourceInstallable+` ORDER BY patch_id`, agentID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

func (s *Server) patchInstallLocked(agentID string, ids []string, reboot bool, by string, auth *protocol.ActionAuth) (*protocol.UpdatesInstallResult, error) {
	if ids == nil {
		// Only what the agent can actually install: a winget row approved by
		// hand would otherwise ride along in the batch and come back failed.
		rows, err := s.db.Query(`SELECT patch_id FROM patches WHERE agent_id = ? AND status = 'approved'`+patchSourceInstallable, agentID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			rows.Scan(&id)
			ids = append(ids, id)
		}
		rows.Close()
	}
	if len(ids) == 0 {
		return &protocol.UpdatesInstallResult{}, nil
	}
	for _, id := range ids {
		s.db.Exec(`UPDATE patches SET status='installing', error='' WHERE agent_id=? AND patch_id=?`, agentID, id)
	}
	s.hub.broadcast(hubEvent{Kind: "patches", AgentID: agentID})
	ctx, cancel := context.WithTimeout(s.jobContext(), 3*time.Hour)
	defer cancel()
	var res protocol.UpdatesInstallResult
	err := s.hub.RequestA(ctx, agentID, protocol.ReqUpdatesInstall, protocol.UpdatesInstall{IDs: ids, Reboot: reboot}, &res, auth)
	ts := now()
	if err != nil {
		for _, id := range ids {
			s.db.Exec(`UPDATE patches SET status='failed', error=? WHERE agent_id=? AND patch_id=? AND status='installing'`, err.Error(), agentID, id)
		}
		s.alerts.patchFailed(agentID, "patch installation", err.Error())
		s.hub.broadcast(hubEvent{Kind: "patches", AgentID: agentID})
		return nil, err
	}
	for _, id := range res.Installed {
		s.db.Exec(`UPDATE patches SET status='installed', installed_at=?, error='' WHERE agent_id=? AND patch_id=?`, ts, agentID, id)
		var title string
		s.db.QueryRow(`SELECT title FROM patches WHERE agent_id=? AND patch_id=?`, agentID, id).Scan(&title)
		s.alerts.patchResolved(agentID, id)
		s.sched.automation("patch_installed", agentID, map[string]any{"patch_id": id, "title": title})
	}
	for id, msg := range res.Failed {
		s.db.Exec(`UPDATE patches SET status='failed', error=? WHERE agent_id=? AND patch_id=?`, msg, agentID, id)
		var title string
		s.db.QueryRow(`SELECT title FROM patches WHERE agent_id=? AND patch_id=?`, agentID, id).Scan(&title)
		s.alerts.patchFailed(agentID, title, msg)
	}
	// Anything still 'installing' got no verdict - scoped to the ids THIS call
	// sent, never to the whole device: an unqualified sweep marked a parallel
	// install's in-flight patches failed and mailed an alert about them.
	sweep := make([]any, 0, len(ids)+1)
	sweep = append(sweep, agentID)
	for _, id := range ids {
		sweep = append(sweep, id)
	}
	s.db.Exec(`UPDATE patches SET status='failed', error='no result reported' WHERE agent_id=? AND status='installing' AND patch_id IN (`+placeholders(len(ids))+`)`, sweep...)
	s.db.Exec(`UPDATE agents SET pending_reboot = ? WHERE id = ?`, res.RebootReq, agentID)
	s.db.Audit(by, "", "patch.install", agentID, map[string]any{"installed": res.Installed, "failed": res.Failed})
	installMsg := fmt.Sprintf("Patch installation completed: %d installed, %d failed", len(res.Installed), len(res.Failed))
	s.db.Exec(`INSERT INTO agent_events(agent_id, ts, kind, message, fields) VALUES(?,?,?,?,?)`, agentID, ts, "patch", installMsg, jsonText(map[string]any{
		"installed_count": len(res.Installed),
		"failed_count":    len(res.Failed),
		"reboot_required": res.RebootReq,
	}))
	s.hub.broadcast(hubEvent{Kind: "event", AgentID: agentID, Data: map[string]any{"ts": ts, "kind": "patch", "message": installMsg}})
	s.hub.broadcast(hubEvent{Kind: "patches", AgentID: agentID})
	s.autoRepairAfterInstall(agentID, failedReasons(res.Failed))
	return &res, nil
}

// patchInstallPolicy applies a policy's mode: approve the matching set, then install it.
func (s *Server) patchInstallPolicy(agentID string, p *PatchPolicy) {
	release, ok := s.claimPatchJob(agentID)
	if !ok {
		slog.Info("patch policy skipped: a patch job is already running", "agent", agentID, "policy", p.Name)
		return
	}
	defer release()
	if err := s.patchScanLocked(agentID); err != nil {
		return
	}
	switch p.Mode {
	case "all":
		s.db.Exec(`UPDATE patches SET status='approved' WHERE agent_id=? AND status='available'`+patchSourceInstallable, agentID)
	case "security":
		s.db.Exec(`UPDATE patches SET status='approved' WHERE agent_id=? AND status='available' AND (severity IN ('Critical','Important') OR categories LIKE '%Security%' OR source IN ('apt','dnf','pacman'))`, agentID)
	}
	// The policy runs with nobody present: its standing approvals (install,
	// and the reboot after it) vouch for these requests, while they still
	// match the policy as it is now.
	instUnit, rebootU := policyUnits(p)
	res, err := s.patchInstallLocked(agentID, nil, p.Reboot == "if_required", "policy:"+p.Name, s.standingAuthForUnit(agentID, instUnit, true))
	if err != nil {
		return
	}
	if p.Reboot == "always" && (len(res.Installed) > 0) {
		ctx, cancel := context.WithTimeout(context.Background(), quickTimeout)
		defer cancel()
		var rebootAuth *protocol.ActionAuth
		if rebootU != nil {
			rebootAuth = s.standingAuthForUnit(agentID, *rebootU, true)
		}
		s.hub.RequestA(ctx, agentID, protocol.ReqPower, protocol.Power{Action: "reboot", Delay: 60, Message: "Rebooting after patch installation (RMM policy " + p.Name + ")"}, nil, rebootAuth)
	}
}

// ---- handlers ----

func (s *Server) handleListPatches(w http.ResponseWriter, r *http.Request) {
	agentQuery := r.URL.Query().Get("agent")
	if agentQuery != "" {
		if _, ok := s.getScopedAgent(w, r, agentQuery); !ok {
			return
		}
	}
	p, err := s.db.ListPatches(agentQuery, r.URL.Query().Get("status"), queryInt(r, "limit", 2000))
	if err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if me != nil && !me.IsAdmin() && len(me.OrgScope) > 0 {
		filtered := make([]Patch, 0, len(p))
		for _, item := range p {
			if a, err := s.db.GetAgent(item.AgentID); err == nil && s.canAccessAgent(me, a.OrgID) {
				filtered = append(filtered, item)
			}
		}
		p = filtered
	}
	writeJSON(w, 200, p)
}

func (s *Server) handleAgentPatches(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.getScopedAgent(w, r, id); !ok {
		return
	}
	p, err := s.db.ListPatches(id, r.URL.Query().Get("status"), 2000)
	if err != nil {
		fail(w, err)
		return
	}
	last, _ := strconv.ParseInt(s.db.Setting("last_patch_scan:"+id, "0"), 10, 64)
	writeJSON(w, 200, map[string]any{
		"patches": p, "last_scan": last,
		// What the agent said went wrong during the scan ("" when it was
		// clean): an unreachable repository leaves a fresh timestamp beside a
		// stale list, and this is the only place that says so.
		"scan_error": s.db.Setting("last_patch_scan_error:"+id, ""),
	})
}

func (s *Server) handlePatchScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.getScopedAgent(w, r, id); !ok {
		return
	}
	if !s.hub.IsOnline(id) {
		fail(w, ErrAgentOffline)
		return
	}
	s.audit(r, "patch.scan", id, nil)
	if err := s.patchScan(id); err != nil {
		if errors.Is(err, errPatchBusy) {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		fail(w, err)
		return
	}
	s.handleAgentPatches(w, r)
}

func (s *Server) handlePatchInstall(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.getScopedAgent(w, r, id); !ok {
		return
	}
	var in struct {
		IDs    []string `json:"ids"`
		All    bool     `json:"all"`
		Reboot bool     `json:"reboot_if_required"`
	}
	readJSON(r, &in)
	if !in.All && len(in.IDs) == 0 {
		writeErr(w, 400, "ids required (or all=true)")
		return
	}
	if !s.hub.IsOnline(id) {
		fail(w, ErrAgentOffline)
		return
	}
	// What will be sent is settled now, because a signature covers it: "all"
	// becomes the concrete list of what is installable at this moment.
	ids := in.IDs
	if in.All {
		ids = s.installablePatchIDs(id)
	}
	run := func(w http.ResponseWriter, r *http.Request, auth *protocol.ActionAuth) {
		if in.All {
			s.db.Exec(`UPDATE patches SET status='approved' WHERE agent_id=? AND status='available'`+patchSourceInstallable, id)
		}
		release, ok := s.claimPatchJob(id)
		if !ok {
			writeErr(w, http.StatusConflict, errPatchBusy.Error())
			return
		}
		s.audit(r, "patch.install.request", id, in)
		// long-running: run in the background and let the UI follow via events
		by, reboot := actor(r), in.Reboot
		s.goJob(func() {
			defer release()
			s.patchInstallLocked(id, ids, reboot, by, auth)
		})
		writeJSON(w, 202, map[string]any{"ok": true})
	}
	if len(ids) == 0 {
		run(w, r, nil) // nothing to install: nothing is sent
		return
	}
	a, _ := s.db.GetAgent(id)
	s.runSigned(w, r, signedAction{
		Org: a.OrgID, Op: protocol.ReqUpdatesInstall, Targets: []string{id}, Payload: protocol.UpdatesInstall{IDs: ids, Reboot: in.Reboot},
		Summary: fmt.Sprintf("Install %d update(s) on %s%s", len(ids), agentLabel(a), map[bool]string{true: ", rebooting if required", false: ""}[in.Reboot]),
		Run:     run,
	})
}

// patchRef is one item of a status change. Both spellings of the two keys are
// accepted: the console sends the Go field names, and a client that round-
// trips a Patch straight from GET /api/patches sends the snake_case names the
// API itself emits. Matching only one of them made the other a silent no-op
// that still answered 200 and still wrote an audit record.
type patchRef struct {
	AgentID    string `json:"AgentID"`
	PatchID    string `json:"PatchID"`
	AgentIDAlt string `json:"agent_id"`
	PatchIDAlt string `json:"patch_id"`
}

func (p patchRef) agent() string {
	if strings.TrimSpace(p.AgentID) != "" {
		return p.AgentID
	}
	return strings.TrimSpace(p.AgentIDAlt)
}

func (p patchRef) patch() string {
	if strings.TrimSpace(p.PatchID) != "" {
		return p.PatchID
	}
	return strings.TrimSpace(p.PatchIDAlt)
}

// handlePatchStatus sets approved/ignored/available for a set of patches.
func (s *Server) handlePatchStatus(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Items  []patchRef `json:"items"`
		Status string     `json:"status"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	switch in.Status {
	case "approved", "ignored", "available":
	default:
		writeErr(w, 400, "status must be approved, ignored or available")
		return
	}
	if len(in.Items) == 0 {
		writeErr(w, 400, "items required")
		return
	}
	me := userFrom(r.Context())
	var changed int64
	for _, it := range in.Items {
		agentID, patchID := it.agent(), it.patch()
		if agentID == "" || patchID == "" {
			continue
		}
		if a, err := s.db.GetAgent(agentID); err != nil || !s.canAccessAgent(me, a.OrgID) {
			continue
		}
		res, err := s.db.Exec(`UPDATE patches SET status=? WHERE agent_id=? AND patch_id=? AND status IN ('available','approved','ignored','failed')`, in.Status, agentID, patchID)
		if err != nil {
			fail(w, err)
			return
		}
		n, _ := res.RowsAffected()
		changed += n
	}
	// Nothing matched: the ids are wrong, or every one of them is installing
	// or already installed. Saying "ok" to that hid a client sending the
	// wrong key names for months.
	if changed == 0 {
		writeErr(w, 404, "no patch matched: check agent_id/patch_id, and that the patches are not installing or installed")
		return
	}
	s.audit(r, "patch."+in.Status, "", changed)
	s.hub.broadcast(hubEvent{Kind: "patches"})
	writeJSON(w, 200, map[string]any{"ok": true, "changed": changed})
}

func (s *Server) handleListPatchPolicies(w http.ResponseWriter, r *http.Request) {
	p, err := s.db.ListPatchPolicies()
	if err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if me != nil && !me.IsAdmin() && len(me.OrgScope) > 0 {
		filtered := make([]PatchPolicy, 0, len(p))
		for _, item := range p {
			if s.canAccessTargets(me, item.Targets) {
				filtered = append(filtered, item)
			}
		}
		p = filtered
	}
	writeJSON(w, 200, p)
}

func (s *Server) savePatchPolicy(w http.ResponseWriter, r *http.Request, id int64) {
	var p PatchPolicy
	if err := readJSON(r, &p); err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if id != 0 {
		existing, err := s.db.GetPatchPolicy(id)
		if err != nil {
			fail(w, err)
			return
		}
		if !s.canAccessTargets(me, existing.Targets) {
			writeErr(w, http.StatusForbidden, "access denied: patch policy outside organization scope")
			return
		}
	}
	if strings.TrimSpace(p.Name) == "" {
		writeErr(w, 400, "name required")
		return
	}
	for _, expr := range []string{p.ScanSchedule, p.InstallSchedule} {
		if expr != "" {
			if err := validateCron(expr); err != nil {
				writeErr(w, 400, "schedule: "+err.Error())
				return
			}
		}
	}
	if err := s.validateTargetsScope(me, p.Targets); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	if p.Mode == "" {
		p.Mode = "approved"
	}
	if p.Reboot == "" {
		p.Reboot = "never"
	}
	switch p.Repair {
	case "off", "auto":
	case "":
		// A client that predates the field must not switch repairs off (or
		// on) by leaving it out: an update keeps what the policy has.
		p.Repair = "off"
		if id != 0 {
			if existing, err := s.db.GetPatchPolicy(id); err == nil && existing.Repair != "" {
				p.Repair = existing.Repair
			}
		}
	default:
		writeErr(w, 400, `repair must be "off" or "auto"`)
		return
	}
	var err error
	if id == 0 {
		var res interface{ LastInsertId() (int64, error) }
		res, err = s.db.Exec(`INSERT INTO patch_policies(name, targets, scan_schedule, install_schedule, mode, reboot, repair, enabled, created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
			p.Name, jsonText(p.Targets), p.ScanSchedule, p.InstallSchedule, p.Mode, p.Reboot, p.Repair, p.Enabled, now())
		if err == nil {
			id, _ = res.LastInsertId()
		}
	} else {
		_, err = s.db.Exec(`UPDATE patch_policies SET name=?, targets=?, scan_schedule=?, install_schedule=?, mode=?, reboot=?, repair=?, enabled=? WHERE id=?`,
			p.Name, jsonText(p.Targets), p.ScanSchedule, p.InstallSchedule, p.Mode, p.Reboot, p.Repair, p.Enabled, id)
	}
	if err != nil {
		fail(w, err)
		return
	}
	p.ID = id
	s.sched.reload()
	s.audit(r, "patch_policy.save", p.Name, nil)
	writeJSON(w, 200, p)
}

func (s *Server) handleCreatePatchPolicy(w http.ResponseWriter, r *http.Request) {
	s.savePatchPolicy(w, r, 0)
}
func (s *Server) handleUpdatePatchPolicy(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	s.savePatchPolicy(w, r, id)
}
func (s *Server) handleDeletePatchPolicy(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	existing, err := s.db.GetPatchPolicy(id)
	if err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if !s.canAccessTargets(me, existing.Targets) {
		writeErr(w, http.StatusForbidden, "access denied: patch policy outside organization scope")
		return
	}
	s.db.Exec(`DELETE FROM patch_policies WHERE id = ?`, id)
	s.sched.reload()
	s.audit(r, "patch_policy.delete", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}
