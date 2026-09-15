package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
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

	// auth. These hang off the OUTER mux - there is no session yet - so
	// requireUser's CSRF check never runs on them and authGuard applies it.
	mux.HandleFunc("GET /api/auth/state", s.handleAuthState)
	mux.HandleFunc("POST /api/auth/setup", s.authGuard(s.handleSetup))
	mux.HandleFunc("POST /api/auth/login", s.authGuard(s.handleLogin))
	mux.HandleFunc("POST /api/auth/logout", s.authGuard(s.handleLogout))

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
	api.HandleFunc("GET /api/agents/{id}/fs/download", s.requireWrite(s.handleFsDownload))
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
	api.HandleFunc("GET /ws/shell/{id}", s.requireWrite(s.handleShellWS))
	api.HandleFunc("GET /ws/desktop/{id}", s.requireWrite(s.handleDesktopViewerWS))

	api.HandleFunc("GET /api/groups", s.handleListGroups)
	api.HandleFunc("POST /api/groups", s.requireWrite(s.handleCreateGroup))
	api.HandleFunc("PUT /api/groups/{id}", s.requireWrite(s.handleUpdateGroup))
	api.HandleFunc("DELETE /api/groups/{id}", s.requireWrite(s.handleDeleteGroup))

	// The listing carries the token VALUES, which are bearer credentials for
	// enrolling a device - a write. A viewer must not read them.
	api.HandleFunc("GET /api/enroll", s.requireWrite(s.handleListEnroll))
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

	// Baselines. Reads are session-only (a viewer may look at compliance);
	// every mutation is requireWrite, and preview/evaluate/remediate are
	// writes too because they run code on a device. The admin-only gates for
	// `command`, `file` outside the config trees and allow_reboot live inside
	// the save handler, since the route itself is requireWrite.
	api.HandleFunc("GET /api/baselines", s.handleListBaselines)
	api.HandleFunc("POST /api/baselines", s.requireWrite(s.handleCreateBaseline))
	api.HandleFunc("POST /api/baselines/preview", s.requireWrite(s.handleBaselinePreview))
	api.HandleFunc("GET /api/baselines/{id}", s.handleGetBaseline)
	api.HandleFunc("PUT /api/baselines/{id}", s.requireWrite(s.handleUpdateBaseline))
	api.HandleFunc("DELETE /api/baselines/{id}", s.requireWrite(s.handleDeleteBaseline))
	api.HandleFunc("GET /api/baselines/{id}/status", s.handleBaselineStatus)
	api.HandleFunc("POST /api/baselines/{id}/evaluate", s.requireWrite(s.handleBaselineEvaluate))
	api.HandleFunc("POST /api/baselines/{id}/remediate", s.requireWrite(s.handleBaselineRemediate))
	api.HandleFunc("GET /api/agents/{id}/baselines", s.handleAgentBaselines)
	api.HandleFunc("GET /api/agents/{id}/baselines/history", s.handleAgentBaselineHistory)
	api.HandleFunc("GET /api/compliance", s.handleCompliance)

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
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self' data:; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'")
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
	s.db.Audit(actor(r), s.clientIP(r), action, target, details)
}

// ---- auth handlers ----

func (s *Server) handleAuthState(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(sessionCookie)
	var u *User
	if c != nil {
		u = s.db.userBySession(c.Value)
	}
	needs := s.db.UserCount() == 0
	writeJSON(w, 200, map[string]any{
		"needs_setup": needs,
		// There is no exemption: whoever completes first-run setup proves they
		// can read the server's console or log. See handleSetup.
		"setup_code_required": needs,
		"user":                u,
		"version":             Version,
	})
}

// authGuard is the CSRF defence for the endpoints that cannot use requireUser
// because they run before a session exists. Without it a cross-origin page can
// post a "simple request" (Content-Type: text/plain, no custom header, which
// needs no preflight) to /api/auth/setup and claim the first administrator
// account, or to /api/auth/login and sign a victim's browser into an account
// the attacker controls.
func (s *Server) authGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("X-Requested-With") == "" {
				writeErr(w, http.StatusForbidden, "missing X-Requested-With header")
				return
			}
			// A browser always sends Origin on a cross-site POST; a same-origin
			// fetch from the console sends its own origin, which matches Host.
			if !sameOrigin(r) {
				writeErr(w, http.StatusForbidden, "cross-origin request refused")
				return
			}
			// text/plain and the other CORS-safelisted types are exactly what a
			// no-preflight cross-origin post can carry.
			if ct := r.Header.Get("Content-Type"); ct != "" {
				if mt, _, err := mime.ParseMediaType(ct); err != nil || mt != "application/json" {
					writeErr(w, http.StatusUnsupportedMediaType, "expected application/json")
					return
				}
			}
		}
		next(w, r)
	}
}

// SetupCode is the one-time first-run code, or "" once an administrator
// exists (or if this process started with users and therefore minted none).
func (s *Server) SetupCode() string {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	return s.setupCode
}

// handleSetup creates the first administrator.
//
// Two things make it dangerous. It is unauthenticated by definition, so
// between the server starting and the operator reaching the form, anyone who
// can open a socket to the port - a machine on the LAN, a browser behind a
// reverse proxy, any local process, or a hostile page via CSRF - could claim
// the account that is root on every enrolled device. And the check "is there a
// user yet?" is separated from the insert by a ~250 ms bcrypt hash, so
// concurrent requests all passed it and each created an administrator.
//
// So: the one-time code printed at startup is ALWAYS required (there is no
// loopback exemption - a peer address of 127.0.0.1 proves nothing about who is
// at the other end of a same-host proxy, and says nothing about which local
// user is asking), and the check and the insert happen under setupMu so first
// run really is once.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if s.db.UserCount() > 0 {
		writeErr(w, http.StatusForbidden, "already set up")
		return
	}
	if !loginLimiter.allow(ip) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts, try again in a minute")
		return
	}
	var in struct{ Username, Password, Email, Code string }
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}

	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	// Re-checked under the lock: without this, every request that got past the
	// check above while the first one was hashing created its own admin.
	if s.db.UserCount() > 0 {
		writeErr(w, http.StatusForbidden, "already set up")
		return
	}
	// An empty s.setupCode means this process did not mint one (it started
	// with users that have since gone): refuse rather than accept an empty
	// code, and say how to get a new one.
	if s.setupCode == "" || !constantTimeEqual(strings.ToLower(strings.TrimSpace(in.Code)), s.setupCode) {
		s.db.Audit(in.Username, ip, "setup.refused", "", "wrong setup code")
		slog.Warn("first-run setup refused: wrong setup code", "ip", ip, "username", in.Username)
		writeErr(w, http.StatusForbidden, "wrong setup code: use the one-time code the server printed at startup (console, or server.log in the data directory). Restart the server before anyone creates a user to mint a new one")
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
	s.setupCode = "" // spent
	s.db.Audit(in.Username, ip, "setup", "", nil)
	tok, err := s.db.createSession(id, ip, r.UserAgent())
	if err != nil {
		fail(w, err)
		return
	}
	s.setSessionCookie(w, r, tok, int(sessionTTL.Seconds()))
	writeJSON(w, 200, map[string]any{"ok": true})
}

var loginLimiter = newRateLimiter(10, time.Minute)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
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
	// every other session (a stolen cookie included) stops working now
	if c, _ := r.Cookie(sessionCookie); c != nil {
		s.db.Exec(`DELETE FROM sessions WHERE user_id = ? AND token != ?`, u.ID, c.Value)
	} else {
		s.db.Exec(`DELETE FROM sessions WHERE user_id = ?`, u.ID)
	}
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
	// The hub, not the agents.online column: the column is wiped at every
	// startup, so the dashboard used to report "0 online" beside a device
	// list on the same screen that showed them all up.
	agents, err := s.agentsWithLiveness()
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
	// COALESCE: SUM() over no rows is NULL, which fails the Scan halfway
	// through. The counts happened to survive because database/sql assigns
	// left to right, which is not something to rely on.
	if err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(severity = 'critical'), 0) FROM alerts WHERE status != 'resolved'`).Scan(&openAlerts, &critical); err != nil {
		slog.Warn("dashboard alert counts", "err", err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(DISTINCT agent_id) FROM patches WHERE status IN ('available','approved')`).Scan(&patches); err != nil {
		slog.Warn("dashboard patch count", "err", err)
	}
	dayAgo := now() - 86400
	if err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(status IN ('failed','timeout')), 0) FROM script_runs WHERE started_at > ?`, dayAgo).Scan(&runsToday, &runsFailed); err != nil {
		slog.Warn("dashboard run counts", "err", err)
	}
	alerts, err := s.db.ListAlerts("open", "", 10)
	if err != nil {
		fail(w, err)
		return
	}
	runs, err := s.db.ListRuns("", 10)
	if err != nil {
		fail(w, err)
		return
	}
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
		// "" unless the certificate does not cover public_url, in which case
		// this says so and how to fix it.
		"cert_warning": s.CertWarning(),
		// true when --public-url/RMM_PUBLIC_URL is set on the command line.
		// It seeded public_url on first run; the setting is what takes effect.
		"public_url_flag": s.cfg.PublicURL,
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
