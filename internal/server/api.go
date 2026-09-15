package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// routes builds the HTTP mux. Everything under /api requires a session
// except the auth endpoints; /ws/agent is for agents; the rest is the UI.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// agents
	mux.HandleFunc("GET /ws/agent", s.hub.handleAgentWS)
	mux.HandleFunc("GET /ws/desktop-agent", s.handleDesktopAgentWS)
	mux.HandleFunc("GET /api/agent-download/{file}", s.handleAgentDownload)
	mux.HandleFunc("GET /install/{token}", s.handleInstallScript)

	// auth
	mux.HandleFunc("GET /api/auth/state", s.handleAuthState)
	mux.HandleFunc("POST /api/auth/setup", s.handleSetup)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleLogout)

	api := http.NewServeMux()
	api.HandleFunc("GET /api/me", s.handleMe)
	api.HandleFunc("POST /api/me/password", s.handleChangePassword)
	api.HandleFunc("POST /api/me/totp/begin", s.handleTOTPBegin)
	api.HandleFunc("POST /api/me/totp/confirm", s.handleTOTPConfirm)
	api.HandleFunc("POST /api/me/totp/disable", s.handleTOTPDisable)
	api.HandleFunc("GET /api/events", s.handleEvents)
	api.HandleFunc("GET /api/dashboard", s.handleDashboard)

	api.HandleFunc("GET /api/agents", s.handleListAgents)
	api.HandleFunc("GET /api/agents/{id}", s.handleGetAgent)
	api.HandleFunc("PATCH /api/agents/{id}", s.requireWrite(s.handleUpdateAgent))
	api.HandleFunc("DELETE /api/agents/{id}", s.requireWrite(s.handleDeleteAgent))
	api.HandleFunc("GET /api/agents/{id}/metrics", s.handleAgentMetrics)
	api.HandleFunc("GET /api/agents/{id}/events", s.handleAgentEvents)
	api.HandleFunc("POST /api/agents/{id}/refresh", s.requireWrite(s.handleAgentRefresh))
	api.HandleFunc("GET /api/agents/{id}/processes", s.handleProcesses)
	api.HandleFunc("POST /api/agents/{id}/processes/kill", s.requireWrite(s.handleProcKill))
	api.HandleFunc("GET /api/agents/{id}/services", s.handleServices)
	api.HandleFunc("POST /api/agents/{id}/services/action", s.requireWrite(s.handleServiceAction))
	api.HandleFunc("GET /api/agents/{id}/eventlog", s.handleEventLog)
	api.HandleFunc("GET /api/agents/{id}/fs", s.handleFsList)
	api.HandleFunc("GET /api/agents/{id}/fs/download", s.handleFsDownload)
	api.HandleFunc("POST /api/agents/{id}/fs/upload", s.requireWrite(s.handleFsUpload))
	api.HandleFunc("POST /api/agents/{id}/fs/delete", s.requireWrite(s.handleFsDelete))
	api.HandleFunc("POST /api/agents/{id}/fs/mkdir", s.requireWrite(s.handleFsMkdir))
	api.HandleFunc("POST /api/agents/{id}/fs/rename", s.requireWrite(s.handleFsRename))
	api.HandleFunc("POST /api/agents/{id}/power", s.requireWrite(s.handlePower))
	api.HandleFunc("POST /api/agents/{id}/wol", s.requireWrite(s.handleWakeOnLan))
	api.HandleFunc("POST /api/agents/{id}/run", s.requireWrite(s.handleRunScriptOnAgent))
	api.HandleFunc("GET /api/agents/{id}/patches", s.handleAgentPatches)
	api.HandleFunc("POST /api/agents/{id}/patches/scan", s.requireWrite(s.handlePatchScan))
	api.HandleFunc("POST /api/agents/{id}/patches/install", s.requireWrite(s.handlePatchInstall))
	api.HandleFunc("GET /ws/shell/{id}", s.handleShellWS)
	api.HandleFunc("GET /ws/desktop/{id}", s.handleDesktopViewerWS)

	api.HandleFunc("GET /api/groups", s.handleListGroups)
	api.HandleFunc("POST /api/groups", s.requireWrite(s.handleCreateGroup))
	api.HandleFunc("PUT /api/groups/{id}", s.requireWrite(s.handleUpdateGroup))
	api.HandleFunc("DELETE /api/groups/{id}", s.requireWrite(s.handleDeleteGroup))

	api.HandleFunc("GET /api/enroll", s.handleListEnroll)
	api.HandleFunc("POST /api/enroll", s.requireWrite(s.handleCreateEnroll))
	api.HandleFunc("DELETE /api/enroll/{id}", s.requireWrite(s.handleDeleteEnroll))

	api.HandleFunc("GET /api/scripts", s.handleListScripts)
	api.HandleFunc("POST /api/scripts", s.requireWrite(s.handleCreateScript))
	api.HandleFunc("GET /api/scripts/{id}", s.handleGetScript)
	api.HandleFunc("PUT /api/scripts/{id}", s.requireWrite(s.handleUpdateScript))
	api.HandleFunc("DELETE /api/scripts/{id}", s.requireWrite(s.handleDeleteScript))
	api.HandleFunc("POST /api/scripts/run", s.requireWrite(s.handleRunScript))
	api.HandleFunc("GET /api/runs", s.handleListRuns)
	api.HandleFunc("GET /api/runs/{id}", s.handleGetRun)
	api.HandleFunc("POST /api/runs/{id}/cancel", s.requireWrite(s.handleCancelRun))

	api.HandleFunc("GET /api/tasks", s.handleListTasks)
	api.HandleFunc("POST /api/tasks", s.requireWrite(s.handleCreateTask))
	api.HandleFunc("PUT /api/tasks/{id}", s.requireWrite(s.handleUpdateTask))
	api.HandleFunc("DELETE /api/tasks/{id}", s.requireWrite(s.handleDeleteTask))
	api.HandleFunc("POST /api/tasks/{id}/run", s.requireWrite(s.handleRunTask))

	api.HandleFunc("GET /api/automations", s.handleListAutomations)
	api.HandleFunc("POST /api/automations", s.requireWrite(s.handleCreateAutomation))
	api.HandleFunc("PUT /api/automations/{id}", s.requireWrite(s.handleUpdateAutomation))
	api.HandleFunc("DELETE /api/automations/{id}", s.requireWrite(s.handleDeleteAutomation))

	api.HandleFunc("GET /api/alert-rules", s.handleListAlertRules)
	api.HandleFunc("POST /api/alert-rules", s.requireWrite(s.handleCreateAlertRule))
	api.HandleFunc("PUT /api/alert-rules/{id}", s.requireWrite(s.handleUpdateAlertRule))
	api.HandleFunc("DELETE /api/alert-rules/{id}", s.requireWrite(s.handleDeleteAlertRule))
	api.HandleFunc("GET /api/alerts", s.handleListAlerts)
	api.HandleFunc("POST /api/alerts/{id}/ack", s.requireWrite(s.handleAckAlert))
	api.HandleFunc("POST /api/alerts/{id}/resolve", s.requireWrite(s.handleResolveAlert))
	api.HandleFunc("POST /api/alerts/resolve-all", s.requireWrite(s.handleResolveAllAlerts))

	api.HandleFunc("GET /api/patches", s.handleListPatches)
	api.HandleFunc("POST /api/patches/status", s.requireWrite(s.handlePatchStatus))
	api.HandleFunc("GET /api/patch-policies", s.handleListPatchPolicies)
	api.HandleFunc("POST /api/patch-policies", s.requireWrite(s.handleCreatePatchPolicy))
	api.HandleFunc("PUT /api/patch-policies/{id}", s.requireWrite(s.handleUpdatePatchPolicy))
	api.HandleFunc("DELETE /api/patch-policies/{id}", s.requireWrite(s.handleDeletePatchPolicy))

	api.HandleFunc("GET /api/settings", s.requireAdmin(s.handleGetSettings))
	api.HandleFunc("PUT /api/settings", s.requireAdmin(s.handlePutSettings))
	api.HandleFunc("POST /api/settings/test-mail", s.requireAdmin(s.handleTestMail))
	api.HandleFunc("GET /api/users", s.requireAdmin(s.handleListUsers))
	api.HandleFunc("POST /api/users", s.requireAdmin(s.handleCreateUser))
	api.HandleFunc("PUT /api/users/{id}", s.requireAdmin(s.handleUpdateUser))
	api.HandleFunc("DELETE /api/users/{id}", s.requireAdmin(s.handleDeleteUser))
	api.HandleFunc("GET /api/audit", s.handleAudit)
	api.HandleFunc("GET /api/system", s.handleSystemInfo)

	mux.Handle("/api/", s.requireUser(api))
	mux.Handle("/ws/shell/", s.requireUser(api))
	mux.Handle("/ws/desktop/", s.requireUser(api))
	mux.Handle("/", s.staticHandler())

	return logRequests(secureHeaders(mux))
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ws/") {
			slog.Debug("http", "method", r.Method, "path", r.URL.Path, "ms", time.Since(start).Milliseconds())
		}
	})
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// fail maps common errors to statuses.
func fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errNotFound):
		writeErr(w, http.StatusNotFound, "not found")
	case errors.Is(err, ErrAgentOffline):
		writeErr(w, http.StatusConflict, "agent is offline")
	default:
		writeErr(w, http.StatusBadRequest, err.Error())
	}
}

func readJSON(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, v)
}

func pathInt(r *http.Request, name string) (int64, error) {
	return strconv.ParseInt(r.PathValue(name), 10, 64)
}

func queryInt(r *http.Request, name string, def int64) int64 {
	if v := r.URL.Query().Get(name); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func actor(r *http.Request) string {
	if u := userFrom(r.Context()); u != nil {
		return u.Username
	}
	return "anonymous"
}

func (s *Server) audit(r *http.Request, action, target string, details any) {
	s.db.Audit(actor(r), clientIP(r), action, target, details)
}

// ---- auth handlers ----

func (s *Server) handleAuthState(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(sessionCookie)
	var u *User
	if c != nil {
		u = s.db.userBySession(c.Value)
	}
	writeJSON(w, 200, map[string]any{
		"needs_setup": s.db.UserCount() == 0,
		"user":        u,
		"version":     Version,
	})
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if s.db.UserCount() > 0 {
		writeErr(w, http.StatusForbidden, "already set up")
		return
	}
	var in struct{ Username, Password, Email string }
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if strings.TrimSpace(in.Username) == "" {
		writeErr(w, 400, "username required")
		return
	}
	id, err := s.db.CreateUser(in.Username, in.Password, RoleAdmin, in.Email)
	if err != nil {
		fail(w, err)
		return
	}
	s.db.Audit(in.Username, clientIP(r), "setup", "", nil)
	tok, err := s.db.createSession(id, clientIP(r), r.UserAgent())
	if err != nil {
		fail(w, err)
		return
	}
	s.setSessionCookie(w, r, tok, int(sessionTTL.Seconds()))
	writeJSON(w, 200, map[string]any{"ok": true})
}

var loginLimiter = newRateLimiter(10, time.Minute)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !loginLimiter.allow(ip) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts, try again in a minute")
		return
	}
	var in struct{ Username, Password, Code string }
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	res, err := s.db.authenticate(strings.TrimSpace(in.Username), in.Password, strings.TrimSpace(in.Code))
	if err != nil {
		s.db.Audit(in.Username, ip, "login.failed", "", nil)
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if res.NeedsTOTP {
		writeJSON(w, 200, map[string]any{"needs_totp": true})
		return
	}
	tok, err := s.db.createSession(res.User.ID, ip, r.UserAgent())
	if err != nil {
		fail(w, err)
		return
	}
	loginLimiter.reset(ip)
	s.db.Audit(res.User.Username, ip, "login", "", nil)
	s.setSessionCookie(w, r, tok, int(sessionTTL.Seconds()))
	writeJSON(w, 200, map[string]any{"ok": true, "user": res.User})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, _ := r.Cookie(sessionCookie); c != nil {
		s.db.deleteSession(c.Value)
	}
	s.setSessionCookie(w, r, "", -1)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, userFrom(r.Context()))
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	var in struct{ Current, New string }
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if res, err := s.db.authenticate(u.Username, in.Current, ""); err != nil || (res.User == nil && !res.NeedsTOTP) {
		writeErr(w, 403, "current password is wrong")
		return
	}
	if len(in.New) < 8 {
		writeErr(w, 400, "password must be at least 8 characters")
		return
	}
	h, err := hashPassword(in.New)
	if err != nil {
		fail(w, err)
		return
	}
	s.db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, h, u.ID)
	s.audit(r, "password.changed", u.Username, nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleTOTPBegin(w http.ResponseWriter, r *http.Request) {
	secret, url, err := s.db.beginTOTP(userFrom(r.Context()))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"secret": secret, "url": url})
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code string }
	readJSON(r, &in)
	if err := s.db.confirmTOTP(userFrom(r.Context()), strings.TrimSpace(in.Code)); err != nil {
		fail(w, err)
		return
	}
	s.audit(r, "totp.enabled", actor(r), nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	var in struct{ Password string }
	readJSON(r, &in)
	if res, err := s.db.authenticate(u.Username, in.Password, ""); err != nil || (res.User == nil && !res.NeedsTOTP) {
		writeErr(w, 403, "password is wrong")
		return
	}
	s.db.disableTOTP(u.ID)
	s.audit(r, "totp.disabled", u.Username, nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- live events (SSE) ----

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	ch, unsub := s.hub.subscribe()
	defer unsub()
	fmt.Fprintf(w, "event: hello\ndata: {}\n\n")
	fl.Flush()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case ev := <-ch:
			b, _ := json.Marshal(ev)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Kind, b)
			fl.Flush()
		}
	}
}

// ---- dashboard ----

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	agents, err := s.db.ListAgents()
	if err != nil {
		fail(w, err)
		return
	}
	var online, offline, reboot, windows, linux int
	for _, a := range agents {
		if a.Online {
			online++
		} else {
			offline++
		}
		if a.PendingReboot {
			reboot++
		}
		switch a.OS {
		case "windows":
			windows++
		case "linux":
			linux++
		}
	}
	var openAlerts, critical, patches, runsToday, runsFailed int
	s.db.QueryRow(`SELECT COUNT(*), SUM(severity = 'critical') FROM alerts WHERE status != 'resolved'`).Scan(&openAlerts, &critical)
	s.db.QueryRow(`SELECT COUNT(DISTINCT agent_id) FROM patches WHERE status IN ('available','approved')`).Scan(&patches)
	dayAgo := now() - 86400
	s.db.QueryRow(`SELECT COUNT(*), SUM(status IN ('failed','timeout')) FROM script_runs WHERE started_at > ?`, dayAgo).Scan(&runsToday, &runsFailed)
	alerts, _ := s.db.ListAlerts("open", "", 10)
	runs, _ := s.db.ListRuns("", 10)
	writeJSON(w, 200, map[string]any{
		"agents_online": online, "agents_offline": offline, "pending_reboot": reboot,
		"windows": windows, "linux": linux,
		"open_alerts": openAlerts, "critical_alerts": critical, "devices_need_patches": patches,
		"runs_24h": runsToday, "runs_failed_24h": runsFailed,
		"recent_alerts": alerts, "recent_runs": runs,
		"server_version": Version, "uptime": int64(time.Since(s.startedAt).Seconds()),
	})
}

func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	var dbSize int64
	s.db.QueryRow(`SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()`).Scan(&dbSize)
	writeJSON(w, 200, map[string]any{
		"version": Version, "public_url": s.PublicURL(), "fingerprint": s.fingerprint,
		"data_dir": s.cfg.DataDir, "db_bytes": dbSize, "uptime": int64(time.Since(s.startedAt).Seconds()),
		"agents_connected": len(s.hub.OnlineIDs()),
	})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 200)
	rows, err := s.db.Query(`SELECT id, ts, user, ip, action, target, details FROM audit ORDER BY ts DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()
	type row struct {
		ID      int64  `json:"id"`
		TS      int64  `json:"ts"`
		User    string `json:"user"`
		IP      string `json:"ip"`
		Action  string `json:"action"`
		Target  string `json:"target"`
		Details string `json:"details"`
	}
	out := []row{}
	for rows.Next() {
		var x row
		rows.Scan(&x.ID, &x.TS, &x.User, &x.IP, &x.Action, &x.Target, &x.Details)
		out = append(out, x)
	}
	writeJSON(w, 200, out)
}
