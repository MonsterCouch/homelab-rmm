package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
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
	FirstSeen      int64    `json:"first_seen"`
	LastSeen       int64    `json:"last_seen"`
	InstalledAt    int64    `json:"installed_at"`
	Error          string   `json:"error"`
}

type PatchPolicy struct {
	ID              int64   `json:"id"`
	Name            string  `json:"name"`
	Targets         Targets `json:"targets"`
	ScanSchedule    string  `json:"scan_schedule"`
	InstallSchedule string  `json:"install_schedule"`
	Mode            string  `json:"mode"`
	Reboot          string  `json:"reboot"`
	Enabled         bool    `json:"enabled"`
	CreatedAt       int64   `json:"created_at"`
}

func (d *DB) ListPatches(agentID, status string, limit int64) ([]Patch, error) {
	q := `SELECT p.agent_id, COALESCE(NULLIF(a.display_name,''), a.hostname, ''), p.patch_id, p.title, p.kb, p.severity, p.categories, p.size, p.source, p.version, p.status, p.reboot_required, p.first_seen, p.last_seen, p.installed_at, p.error
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
	q += ` ORDER BY p.status, p.severity DESC, p.title LIMIT ?`
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
		if err := rows.Scan(&p.AgentID, &p.AgentName, &p.PatchID, &p.Title, &p.KB, &p.Severity, &cats, &p.Size, &p.Source, &p.Version, &p.Status, &p.RebootRequired, &p.FirstSeen, &p.LastSeen, &p.InstalledAt, &p.Error); err != nil {
			return nil, err
		}
		p.Categories = []string{}
		json.Unmarshal([]byte(cats), &p.Categories)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (d *DB) ListPatchPolicies() ([]PatchPolicy, error) {
	rows, err := d.Query(`SELECT id, name, targets, scan_schedule, install_schedule, mode, reboot, enabled, created_at FROM patch_policies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PatchPolicy{}
	for rows.Next() {
		var p PatchPolicy
		var t string
		if err := rows.Scan(&p.ID, &p.Name, &t, &p.ScanSchedule, &p.InstallSchedule, &p.Mode, &p.Reboot, &p.Enabled, &p.CreatedAt); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(t), &p.Targets)
		out = append(out, p)
	}
	return out, rows.Err()
}

// patchScan asks the agent for its update list and reconciles the table:
// new ids are inserted as available, known ones refreshed, and ids no longer
// reported (installed out of band) are marked installed.
func (s *Server) patchScan(agentID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	var res protocol.UpdatesScanResult
	if err := s.hub.Request(ctx, agentID, protocol.ReqUpdatesScan, nil, &res); err != nil {
		slog.Warn("patch scan failed", "agent", agentID, "err", err)
		return err
	}
	seen := map[string]bool{}
	ts := now()
	for _, u := range res.Updates {
		seen[u.ID] = true
		status := "available"
		if u.Installed {
			status = "installed"
		}
		s.db.Exec(`INSERT INTO patches(agent_id, patch_id, title, kb, severity, categories, size, source, version, status, reboot_required, first_seen, last_seen, installed_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(agent_id, patch_id) DO UPDATE SET title=excluded.title, kb=excluded.kb, severity=excluded.severity, categories=excluded.categories,
				size=excluded.size, version=excluded.version, reboot_required=excluded.reboot_required, last_seen=excluded.last_seen,
				status = CASE WHEN patches.status IN ('approved','ignored','installing') AND excluded.status='available' THEN patches.status ELSE excluded.status END,
				installed_at = CASE WHEN excluded.status='installed' AND patches.installed_at=0 THEN excluded.last_seen ELSE patches.installed_at END`,
			agentID, u.ID, u.Title, u.KB, u.Severity, jsonText(u.Categories), u.SizeBytes, u.Source, u.Version, status, u.RebootReq, ts, ts, map[bool]int64{true: ts, false: 0}[u.Installed])
	}
	// anything previously pending that the agent no longer lists was installed elsewhere
	rows, err := s.db.Query(`SELECT patch_id FROM patches WHERE agent_id = ? AND status IN ('available','approved','installing')`, agentID)
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
		}
	}
	s.db.Exec(`UPDATE agents SET pending_reboot = ? WHERE id = ?`, res.RebootPending, agentID)
	s.db.SetSetting("last_patch_scan:"+agentID, strconv.FormatInt(ts, 10))
	s.hub.broadcast(hubEvent{Kind: "patches", AgentID: agentID})
	return nil
}

// patchInstall installs the given ids (nil = every approved patch) and records the outcome.
func (s *Server) patchInstall(agentID string, ids []string, reboot bool, by string) (*protocol.UpdatesInstallResult, error) {
	if ids == nil {
		rows, err := s.db.Query(`SELECT patch_id FROM patches WHERE agent_id = ? AND status = 'approved'`, agentID)
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Hour)
	defer cancel()
	var res protocol.UpdatesInstallResult
	err := s.hub.Request(ctx, agentID, protocol.ReqUpdatesInstall, protocol.UpdatesInstall{IDs: ids, Reboot: reboot}, &res)
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
		s.sched.automation("patch_installed", agentID, map[string]any{"patch_id": id, "title": title})
	}
	for id, msg := range res.Failed {
		s.db.Exec(`UPDATE patches SET status='failed', error=? WHERE agent_id=? AND patch_id=?`, msg, agentID, id)
		var title string
		s.db.QueryRow(`SELECT title FROM patches WHERE agent_id=? AND patch_id=?`, agentID, id).Scan(&title)
		s.alerts.patchFailed(agentID, title, msg)
	}
	// anything still 'installing' got no verdict
	s.db.Exec(`UPDATE patches SET status='failed', error='no result reported' WHERE agent_id=? AND status='installing'`, agentID)
	s.db.Exec(`UPDATE agents SET pending_reboot = ? WHERE id = ?`, res.RebootReq, agentID)
	s.db.Audit(by, "", "patch.install", agentID, map[string]any{"installed": res.Installed, "failed": res.Failed})
	s.hub.broadcast(hubEvent{Kind: "patches", AgentID: agentID})
	return &res, nil
}

// patchInstallPolicy applies a policy's mode: approve the matching set, then install it.
func (s *Server) patchInstallPolicy(agentID string, p *PatchPolicy) {
	if err := s.patchScan(agentID); err != nil {
		return
	}
	switch p.Mode {
	case "all":
		s.db.Exec(`UPDATE patches SET status='approved' WHERE agent_id=? AND status='available'`, agentID)
	case "security":
		s.db.Exec(`UPDATE patches SET status='approved' WHERE agent_id=? AND status='available' AND (severity IN ('Critical','Important') OR categories LIKE '%Security%' OR source IN ('apt','dnf','pacman'))`, agentID)
	}
	res, err := s.patchInstall(agentID, nil, p.Reboot == "if_required", "policy:"+p.Name)
	if err != nil {
		return
	}
	if p.Reboot == "always" && (len(res.Installed) > 0) {
		ctx, cancel := context.WithTimeout(context.Background(), quickTimeout)
		defer cancel()
		s.hub.Request(ctx, agentID, protocol.ReqPower, protocol.Power{Action: "reboot", Delay: 60, Message: "Rebooting after patch installation (RMM policy " + p.Name + ")"}, nil)
	}
}

// ---- handlers ----

func (s *Server) handleListPatches(w http.ResponseWriter, r *http.Request) {
	p, err := s.db.ListPatches(r.URL.Query().Get("agent"), r.URL.Query().Get("status"), queryInt(r, "limit", 2000))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, p)
}

func (s *Server) handleAgentPatches(w http.ResponseWriter, r *http.Request) {
	p, err := s.db.ListPatches(r.PathValue("id"), r.URL.Query().Get("status"), 2000)
	if err != nil {
		fail(w, err)
		return
	}
	last, _ := strconv.ParseInt(s.db.Setting("last_patch_scan:"+r.PathValue("id"), "0"), 10, 64)
	writeJSON(w, 200, map[string]any{"patches": p, "last_scan": last})
}

func (s *Server) handlePatchScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.hub.IsOnline(id) {
		fail(w, ErrAgentOffline)
		return
	}
	s.audit(r, "patch.scan", id, nil)
	if err := s.patchScan(id); err != nil {
		fail(w, err)
		return
	}
	s.handleAgentPatches(w, r)
}

func (s *Server) handlePatchInstall(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		IDs    []string `json:"ids"`
		All    bool     `json:"all"`
		Reboot bool     `json:"reboot_if_required"`
	}
	readJSON(r, &in)
	if in.All {
		s.db.Exec(`UPDATE patches SET status='approved' WHERE agent_id=? AND status='available'`, id)
		in.IDs = nil
	} else if len(in.IDs) == 0 {
		writeErr(w, 400, "ids required (or all=true)")
		return
	}
	if !s.hub.IsOnline(id) {
		fail(w, ErrAgentOffline)
		return
	}
	// long-running: run in the background and let the UI follow via events
	go s.patchInstall(id, in.IDs, in.Reboot, actor(r))
	s.audit(r, "patch.install.request", id, in)
	writeJSON(w, 202, map[string]any{"ok": true})
}

// handlePatchStatus sets approved/ignored/available for a set of patches.
func (s *Server) handlePatchStatus(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Items  []struct{ AgentID, PatchID string } `json:"items"`
		Status string                              `json:"status"`
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
	for _, it := range in.Items {
		s.db.Exec(`UPDATE patches SET status=? WHERE agent_id=? AND patch_id=? AND status IN ('available','approved','ignored','failed')`, in.Status, it.AgentID, it.PatchID)
	}
	s.audit(r, "patch."+in.Status, "", len(in.Items))
	s.hub.broadcast(hubEvent{Kind: "patches"})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleListPatchPolicies(w http.ResponseWriter, r *http.Request) {
	p, err := s.db.ListPatchPolicies()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, p)
}

func (s *Server) savePatchPolicy(w http.ResponseWriter, r *http.Request, id int64) {
	var p PatchPolicy
	if err := readJSON(r, &p); err != nil {
		fail(w, err)
		return
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
	if p.Mode == "" {
		p.Mode = "approved"
	}
	if p.Reboot == "" {
		p.Reboot = "never"
	}
	var err error
	if id == 0 {
		var res interface{ LastInsertId() (int64, error) }
		res, err = s.db.Exec(`INSERT INTO patch_policies(name, targets, scan_schedule, install_schedule, mode, reboot, enabled, created_at) VALUES(?,?,?,?,?,?,?,?)`,
			p.Name, jsonText(p.Targets), p.ScanSchedule, p.InstallSchedule, p.Mode, p.Reboot, p.Enabled, now())
		if err == nil {
			id, _ = res.LastInsertId()
		}
	} else {
		_, err = s.db.Exec(`UPDATE patch_policies SET name=?, targets=?, scan_schedule=?, install_schedule=?, mode=?, reboot=?, enabled=? WHERE id=?`,
			p.Name, jsonText(p.Targets), p.ScanSchedule, p.InstallSchedule, p.Mode, p.Reboot, p.Enabled, id)
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
	s.db.Exec(`DELETE FROM patch_policies WHERE id = ?`, id)
	s.sched.reload()
	s.audit(r, "patch_policy.delete", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}
