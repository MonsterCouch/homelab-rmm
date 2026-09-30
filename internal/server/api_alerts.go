package server

import (
	"net/http"
	"strconv"
	"strings"
)

func (s *Server) handleListAlertRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.db.ListAlertRules()
	if err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if me != nil && !me.IsAdmin() && len(me.OrgScope) > 0 {
		filtered := make([]AlertRule, 0, len(rules))
		for _, item := range rules {
			if s.canAccessTargets(me, item.Targets) {
				filtered = append(filtered, item)
			}
		}
		rules = filtered
	}
	writeJSON(w, 200, rules)
}

func (s *Server) saveAlertRule(w http.ResponseWriter, r *http.Request, id int64) {
	var in AlertRule
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if id != 0 {
		existing, err := s.db.GetAlertRule(id)
		if err != nil {
			fail(w, err)
			return
		}
		if !s.canAccessTargets(me, existing.Targets) {
			writeErr(w, http.StatusForbidden, "access denied: alert rule outside organization scope")
			return
		}
	}
	if strings.TrimSpace(in.Name) == "" || !validRuleKinds[in.Kind] {
		writeErr(w, 400, "name and a valid kind are required")
		return
	}
	switch in.Severity {
	case "info", "warning", "critical":
	default:
		in.Severity = "warning"
	}
	if err := s.validateTargetsScope(me, in.Targets); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	var err error
	if id == 0 {
		var res interface{ LastInsertId() (int64, error) }
		res, err = s.db.Exec(`INSERT INTO alert_rules(name, kind, params, targets, severity, notify_email, auto_resolve, enabled, created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
			in.Name, in.Kind, jsonText(in.Params), jsonText(in.Targets), in.Severity, in.NotifyEmail, in.AutoResolve, in.Enabled, now())
		if err == nil {
			id, _ = res.LastInsertId()
		}
	} else {
		_, err = s.db.Exec(`UPDATE alert_rules SET name=?, kind=?, params=?, targets=?, severity=?, notify_email=?, auto_resolve=?, enabled=? WHERE id=?`,
			in.Name, in.Kind, jsonText(in.Params), jsonText(in.Targets), in.Severity, in.NotifyEmail, in.AutoResolve, in.Enabled, id)
	}
	if err != nil {
		fail(w, err)
		return
	}
	in.ID = id
	s.alerts.reload()
	s.audit(r, "alert_rule.save", in.Name, nil)
	writeJSON(w, 200, in)
}

func (s *Server) handleCreateAlertRule(w http.ResponseWriter, r *http.Request) {
	s.saveAlertRule(w, r, 0)
}
func (s *Server) handleUpdateAlertRule(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	s.saveAlertRule(w, r, id)
}
func (s *Server) handleDeleteAlertRule(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	existing, err := s.db.GetAlertRule(id)
	if err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if !s.canAccessTargets(me, existing.Targets) {
		writeErr(w, http.StatusForbidden, "access denied: alert rule outside organization scope")
		return
	}
	s.db.Exec(`DELETE FROM alert_rules WHERE id = ?`, id)
	s.alerts.reload()
	s.audit(r, "alert_rule.delete", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "open"
	}
	agentQuery := r.URL.Query().Get("agent")
	if agentQuery != "" {
		if _, ok := s.getScopedAgent(w, r, agentQuery); !ok {
			return
		}
	}
	al, err := s.db.ListAlerts(status, agentQuery, queryInt(r, "limit", 200))
	if err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if me != nil && !me.IsAdmin() && len(me.OrgScope) > 0 {
		filtered := make([]Alert, 0, len(al))
		for _, a := range al {
			if ag, err := s.db.GetAgent(a.AgentID); err == nil && s.canAccessAgent(me, ag.OrgID) {
				filtered = append(filtered, a)
			}
		}
		al = filtered
	}
	writeJSON(w, 200, al)
}

func (s *Server) handleAckAlert(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	var agentID string
	if err := s.db.QueryRow(`SELECT agent_id FROM alerts WHERE id = ?`, id).Scan(&agentID); err != nil {
		writeErr(w, 404, "alert not found")
		return
	}
	if _, ok := s.getScopedAgent(w, r, agentID); !ok {
		return
	}
	s.db.Exec(`UPDATE alerts SET status='acked', acked_at=?, acked_by=? WHERE id=? AND status='open'`, now(), actor(r), id)
	s.hub.broadcast(hubEvent{Kind: "alert", AgentID: agentID, Data: map[string]any{"id": id, "status": "acked"}})
	s.audit(r, "alert.ack", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleResolveAlert(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	var agentID string
	if err := s.db.QueryRow(`SELECT agent_id FROM alerts WHERE id = ?`, id).Scan(&agentID); err != nil {
		writeErr(w, 404, "alert not found")
		return
	}
	if _, ok := s.getScopedAgent(w, r, agentID); !ok {
		return
	}
	s.db.Exec(`UPDATE alerts SET status='resolved', resolved_at=? WHERE id=? AND status!='resolved'`, now(), id)
	s.hub.broadcast(hubEvent{Kind: "alert", AgentID: agentID, Data: map[string]any{"id": id, "status": "resolved"}})
	s.audit(r, "alert.resolve", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleResolveAllAlerts(w http.ResponseWriter, r *http.Request) {
	me := userFrom(r.Context())
	// One statement either way. The database has a single connection, so
	// reading alerts and updating them inside the read waited forever for
	// the connection the read was holding, and hung every other request.
	q := `UPDATE alerts SET status='resolved', resolved_at=? WHERE status!='resolved'`
	args := []any{now()}
	if !me.IsAdmin() && len(me.OrgScope) > 0 {
		q += ` AND agent_id IN (SELECT id FROM agents WHERE org_id IN (?` + strings.Repeat(",?", len(me.OrgScope)-1) + `))`
		for _, o := range me.OrgScope {
			args = append(args, o)
		}
	}
	res, err := s.db.Exec(q, args...)
	if err != nil {
		fail(w, err)
		return
	}
	n, _ := res.RowsAffected()
	broadcastEv := hubEvent{Kind: "alert", Data: map[string]any{"status": "resolved_all"}}
	if !me.IsAdmin() && len(me.OrgScope) == 1 {
		broadcastEv.OrgID = me.OrgScope[0]
	}
	s.hub.broadcast(broadcastEv)
	s.audit(r, "alert.resolve_all", "", n)
	writeJSON(w, 200, map[string]any{"ok": true, "resolved": n})
}
