package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// AlertRule is a condition evaluated against agent data.
type AlertRule struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	Params      RuleParams `json:"params"`
	Targets     Targets    `json:"targets"`
	Severity    string     `json:"severity"`
	NotifyEmail bool       `json:"notify_email"`
	AutoResolve bool       `json:"auto_resolve"`
	Enabled     bool       `json:"enabled"`
	CreatedAt   int64      `json:"created_at"`
}

type RuleParams struct {
	Threshold float64 `json:"threshold"` // percent for cpu/memory/disk
	Minutes   int     `json:"minutes"`   // sustained duration (cpu/memory) or offline grace
	Mount     string  `json:"mount"`     // disk: "" = any
	Service   string  `json:"service"`   // service: name ("" = every monitored service)
	Pattern   string  `json:"pattern"`   // event: substring in message
}

var validRuleKinds = map[string]bool{"cpu": true, "memory": true, "disk": true, "offline": true, "service": true, "reboot_required": true, "script_failed": true, "patch_failed": true, "event": true}

type Alert struct {
	ID         int64  `json:"id"`
	RuleID     *int64 `json:"rule_id"`
	RuleKind   string `json:"rule_kind"`
	AgentID    string `json:"agent_id"`
	AgentName  string `json:"agent_name"`
	Severity   string `json:"severity"`
	Title      string `json:"title"`
	Message    string `json:"message"`
	Status     string `json:"status"`
	OpenedAt   int64  `json:"opened_at"`
	AckedAt    int64  `json:"acked_at"`
	AckedBy    string `json:"acked_by"`
	ResolvedAt int64  `json:"resolved_at"`
}

func (d *DB) ListAlertRules() ([]AlertRule, error) {
	rows, err := d.Query(`SELECT id, name, kind, params, targets, severity, notify_email, auto_resolve, enabled, created_at FROM alert_rules ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AlertRule{}
	for rows.Next() {
		var r AlertRule
		var p, t string
		if err := rows.Scan(&r.ID, &r.Name, &r.Kind, &p, &t, &r.Severity, &r.NotifyEmail, &r.AutoResolve, &r.Enabled, &r.CreatedAt); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(p), &r.Params)
		json.Unmarshal([]byte(t), &r.Targets)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *DB) ListAlerts(status, agentID string, limit int64) ([]Alert, error) {
	q := `SELECT al.id, al.rule_id, al.rule_kind, COALESCE(al.agent_id,''), COALESCE(NULLIF(a.display_name,''), a.hostname, ''), al.severity, al.title, al.message, al.status, al.opened_at, al.acked_at, al.acked_by, al.resolved_at
		FROM alerts al LEFT JOIN agents a ON a.id = al.agent_id WHERE 1=1`
	args := []any{}
	switch status {
	case "open":
		q += ` AND al.status != 'resolved'`
	case "", "all":
	default:
		q += ` AND al.status = ?`
		args = append(args, status)
	}
	if agentID != "" {
		q += ` AND al.agent_id = ?`
		args = append(args, agentID)
	}
	q += ` ORDER BY al.opened_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.RuleID, &a.RuleKind, &a.AgentID, &a.AgentName, &a.Severity, &a.Title, &a.Message, &a.Status, &a.OpenedAt, &a.AckedAt, &a.AckedBy, &a.ResolvedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// alertEngine evaluates rules. Threshold rules need the condition to hold for
// Params.Minutes before opening, tracked in `since`; when the condition
// clears the open alert auto-resolves if the rule allows it.
type alertEngine struct {
	s     *Server
	mu    sync.Mutex
	rules []AlertRule
	since map[string]int64 // dedupe key -> first time condition seen true
}

func newAlertEngine(s *Server) *alertEngine {
	e := &alertEngine{s: s, since: map[string]int64{}}
	e.reload()
	return e
}

func (e *alertEngine) reload() {
	rules, err := e.s.db.ListAlertRules()
	if err != nil {
		slog.Warn("load alert rules", "err", err)
		return
	}
	e.mu.Lock()
	e.rules = rules
	e.mu.Unlock()
}

func (e *alertEngine) rulesFor(kind string, a *Agent) []AlertRule {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []AlertRule
	for _, r := range e.rules {
		if r.Enabled && r.Kind == kind && (a == nil || r.Targets.Matches(a)) {
			out = append(out, r)
		}
	}
	return out
}

func dedupe(ruleID int64, agentID, extra string) string {
	return fmt.Sprintf("%d:%s:%s", ruleID, agentID, extra)
}

// open creates an alert unless one with the same key is already open.
func (e *alertEngine) open(rule *AlertRule, agentID, key, title, msg string) {
	var existing int64
	if err := e.s.db.QueryRow(`SELECT id FROM alerts WHERE dedupe_key = ? AND status != 'resolved'`, key).Scan(&existing); err == nil {
		return
	}
	if a, err := e.s.db.GetAgent(agentID); err == nil && a.MaintenanceUntil > now() {
		return // in maintenance: stay quiet
	}
	var ruleID *int64
	sev, kind, notify := "warning", "", true
	if rule != nil {
		ruleID, sev, kind, notify = &rule.ID, rule.Severity, rule.Kind, rule.NotifyEmail
	}
	res, err := e.s.db.Exec(`INSERT INTO alerts(rule_id, rule_kind, agent_id, severity, title, message, dedupe_key, status, opened_at) VALUES(?,?,?,?,?,?,?,'open',?)`,
		ruleID, kind, agentID, sev, title, msg, key, now())
	if err != nil {
		slog.Warn("open alert", "err", err)
		return
	}
	id, _ := res.LastInsertId()
	slog.Info("alert opened", "id", id, "agent", agentID, "title", title)
	e.s.hub.broadcast(hubEvent{Kind: "alert", AgentID: agentID, Data: map[string]any{"id": id, "status": "open", "severity": sev, "title": title}})
	if notify {
		go e.notify(id, agentID, sev, title, msg)
	}
	e.s.sched.automation("alert_opened", agentID, map[string]any{"alert_id": id, "rule_id": ruleID, "severity": sev, "title": title, "message": msg})
}

func (e *alertEngine) resolveKey(key string) {
	rows, err := e.s.db.Query(`SELECT id, agent_id, title FROM alerts WHERE dedupe_key = ? AND status != 'resolved'`, key)
	if err != nil {
		return
	}
	type row struct {
		id    int64
		agent string
		title string
	}
	var list []row
	for rows.Next() {
		var r row
		rows.Scan(&r.id, &r.agent, &r.title)
		list = append(list, r)
	}
	rows.Close()
	for _, r := range list {
		e.s.db.Exec(`UPDATE alerts SET status='resolved', resolved_at=? WHERE id=?`, now(), r.id)
		e.s.hub.broadcast(hubEvent{Kind: "alert", AgentID: r.agent, Data: map[string]any{"id": r.id, "status": "resolved", "title": r.title}})
		e.s.sched.automation("alert_resolved", r.agent, map[string]any{"alert_id": r.id, "title": r.title})
	}
}

func (e *alertEngine) notify(id int64, agentID, sev, title, msg string) {
	name := agentID
	if a, err := e.s.db.GetAgent(agentID); err == nil {
		name = a.DisplayName
	}
	body := fmt.Sprintf("%s\n\nDevice: %s\nSeverity: %s\nTime: %s\n\n%s\n\nOpen the console: %s/alerts\n", title, name, sev, time.Now().Format(time.RFC1123), msg, e.s.PublicURL())
	if err := e.s.mail.Send(fmt.Sprintf("[RMM %s] %s - %s", strings.ToUpper(sev), name, title), body); err != nil {
		slog.Debug("alert mail not sent", "err", err)
		return
	}
	e.s.db.Exec(`UPDATE alerts SET notified = 1 WHERE id = ?`, id)
}

// sustained implements "condition true for N minutes" and returns whether to fire.
func (e *alertEngine) sustained(key string, cond bool, minutes int) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !cond {
		delete(e.since, key)
		return false
	}
	first, ok := e.since[key]
	if !ok {
		e.since[key] = now()
		return minutes <= 0
	}
	return now()-first >= int64(minutes)*60
}

// ---- inputs ----

func (e *alertEngine) metrics(agentID string, m *protocol.Metrics) {
	a, err := e.s.db.GetAgent(agentID)
	if err != nil {
		return
	}
	for _, r := range e.rulesFor("cpu", a) {
		key := dedupe(r.ID, agentID, "")
		if e.sustained(key, m.CPUPct >= r.Params.Threshold, r.Params.Minutes) {
			e.open(&r, agentID, key, fmt.Sprintf("CPU above %.0f%%", r.Params.Threshold), fmt.Sprintf("CPU has been at %.0f%% for %d minutes.", m.CPUPct, r.Params.Minutes))
		} else if m.CPUPct < r.Params.Threshold && r.AutoResolve {
			e.resolveKey(key)
		}
	}
	for _, r := range e.rulesFor("memory", a) {
		key := dedupe(r.ID, agentID, "")
		pct := 0.0
		if m.MemTotal > 0 {
			pct = float64(m.MemUsed) / float64(m.MemTotal) * 100
		}
		if e.sustained(key, pct >= r.Params.Threshold, r.Params.Minutes) {
			e.open(&r, agentID, key, fmt.Sprintf("Memory above %.0f%%", r.Params.Threshold), fmt.Sprintf("Memory use is %.0f%%.", pct))
		} else if pct < r.Params.Threshold && r.AutoResolve {
			e.resolveKey(key)
		}
	}
	for _, r := range e.rulesFor("disk", a) {
		for _, d := range m.Disks {
			if r.Params.Mount != "" && !strings.EqualFold(r.Params.Mount, d.Mount) {
				continue
			}
			key := dedupe(r.ID, agentID, d.Mount)
			if d.UsedPct >= r.Params.Threshold {
				e.open(&r, agentID, key, fmt.Sprintf("Disk %s above %.0f%%", d.Mount, r.Params.Threshold), fmt.Sprintf("%s is %.1f%% full (%s free).", d.Mount, d.UsedPct, humanBytes(d.Total-d.Used)))
			} else if r.AutoResolve {
				e.resolveKey(key)
			}
		}
	}
	for _, r := range e.rulesFor("service", a) {
		for name, state := range m.Services {
			if r.Params.Service != "" && !strings.EqualFold(r.Params.Service, name) {
				continue
			}
			key := dedupe(r.ID, agentID, name)
			if state != "running" {
				e.open(&r, agentID, key, "Service "+name+" is "+state, fmt.Sprintf("Monitored service %q is %s.", name, state))
			} else if r.AutoResolve {
				e.resolveKey(key)
			}
		}
	}
	for _, r := range e.rulesFor("reboot_required", a) {
		key := dedupe(r.ID, agentID, "")
		if m.PendingReboot {
			e.open(&r, agentID, key, "Reboot required", "The device reports a pending reboot.")
		} else if r.AutoResolve {
			e.resolveKey(key)
		}
	}
}

func (e *alertEngine) inventory(agentID string, inv *protocol.Inventory) {
	if inv.PendingReboot {
		e.s.sched.automation("reboot_required", agentID, nil)
	}
}

func (e *alertEngine) event(agentID string, ev *protocol.Event) {
	a, err := e.s.db.GetAgent(agentID)
	if err != nil {
		return
	}
	for _, r := range e.rulesFor("event", a) {
		if r.Params.Pattern != "" && !strings.Contains(strings.ToLower(ev.Message), strings.ToLower(r.Params.Pattern)) {
			continue
		}
		// Keyed by rule+device+event KIND, not by the whole message: every
		// distinct log line used to open its own alert that nothing ever
		// resolved, so a chatty log filled the alerts list forever. The line
		// itself is in the body.
		e.open(&r, agentID, dedupe(r.ID, agentID, ev.Kind), "Event: "+ev.Kind, ev.Message)
	}
}

func (e *alertEngine) scriptFailed(agentID, runID, status string) {
	a, err := e.s.db.GetAgent(agentID)
	if err != nil {
		return
	}
	run, _ := e.s.db.GetRun(runID)
	name := runID
	if run != nil {
		name = run.ScriptName
		// A run an automation started must not open an alert: with the
		// shipped "Script failed" rule and an alert_opened -> run_script
		// automation, the failure opens the alert that fires the automation
		// that runs the script that fails - as fast as the device can manage.
		if run.Trigger == "automation" {
			slog.Debug("not alerting on an automation-triggered run", "run", runID, "agent", agentID)
			return
		}
	}
	for _, r := range e.rulesFor("script_failed", a) {
		// Keyed by rule+device, NOT by run id: a nightly job that fails every
		// night used to leave one permanent alert and one email per night,
		// none of which anything could ever resolve. Now the first failure
		// opens it and the rest are deduped until someone resolves it.
		e.open(&r, agentID, dedupe(r.ID, agentID, ""), "Script failed: "+name, fmt.Sprintf("Run %s ended with status %s.", runID, status))
	}
}

func (e *alertEngine) patchFailed(agentID, title, errMsg string) {
	a, err := e.s.db.GetAgent(agentID)
	if err != nil {
		return
	}
	for _, r := range e.rulesFor("patch_failed", a) {
		e.open(&r, agentID, dedupe(r.ID, agentID, title), "Patch failed: "+title, errMsg)
	}
}

// patchResolved closes the patch_failed alerts for a patch that has since
// installed. Without it the alert for a patch that failed once and then went
// in on the next attempt stayed open for good.
func (e *alertEngine) patchResolved(agentID, patchID string) {
	var title string
	if err := e.s.db.QueryRow(`SELECT title FROM patches WHERE agent_id=? AND patch_id=?`, agentID, patchID).Scan(&title); err != nil || title == "" {
		return
	}
	a, err := e.s.db.GetAgent(agentID)
	if err != nil {
		return
	}
	for _, r := range e.rulesFor("patch_failed", a) {
		if r.AutoResolve {
			e.resolveKey(dedupe(r.ID, agentID, title))
		}
	}
}

func (e *alertEngine) agentOnline(agentID string) {
	a, err := e.s.db.GetAgent(agentID)
	if err != nil {
		return
	}
	for _, r := range e.rulesFor("offline", a) {
		if r.AutoResolve {
			e.resolveKey(dedupe(r.ID, agentID, ""))
		}
	}
	e.mu.Lock()
	delete(e.since, "offline:"+agentID)
	e.mu.Unlock()
}

func (e *alertEngine) agentOffline(agentID string) {
	e.mu.Lock()
	e.since["offline:"+agentID] = now()
	e.mu.Unlock()
}

// run is the periodic sweep: offline detection is time-based rather than
// event-based so a device that vanished while the server restarted is still caught.
func (e *alertEngine) run(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.sweepOffline()
		}
	}
}

func (e *alertEngine) sweepOffline() {
	agents, err := e.s.db.ListAgents()
	if err != nil {
		return
	}
	for _, a := range agents {
		if e.s.hub.IsOnline(a.ID) {
			continue
		}
		for _, r := range e.rulesFor("offline", a) {
			grace := r.Params.Minutes
			if grace <= 0 {
				grace = 5
			}
			e.mu.Lock()
			since, ok := e.since["offline:"+a.ID]
			e.mu.Unlock()
			if !ok {
				since = a.LastSeen
			}
			if now()-since >= int64(grace)*60 {
				e.open(&r, a.ID, dedupe(r.ID, a.ID, ""), "Device offline", fmt.Sprintf("%s has not checked in for %d minutes.", a.DisplayName, (now()-since)/60))
			}
		}
	}
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
