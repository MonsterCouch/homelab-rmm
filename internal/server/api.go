package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/telemetry"
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
	mux.HandleFunc("GET /install/{token}/msi", s.handleInstallMSI)
	mux.HandleFunc("GET /install/{token}/deb", s.handleInstallDeb)

	// auth. These hang off the OUTER mux - there is no session yet - so
	// requireUser's CSRF check never runs on them and authGuard applies it.
	mux.HandleFunc("GET /api/auth/state", s.handleAuthState)
	mux.HandleFunc("POST /api/auth/setup", s.authGuard(s.handleSetup))
	mux.HandleFunc("POST /api/auth/login", s.authGuard(s.handleLogin))
	mux.HandleFunc("POST /api/auth/logout", s.authGuard(s.handleLogout))

	// Client portal. A device user gets in with a pass the device's agent
	// asked for (portal_auth.go); a console user with their session. These
	// hang off the outer mux because a device user has no console session.
	mux.HandleFunc("POST /api/agent/portal-pass", s.handleAgentPortalPass)
	mux.HandleFunc("GET /portal/start", s.handlePortalStart)
	mux.HandleFunc("GET /api/portal/config", s.portalGuard(s.handlePortalConfig))
	mux.HandleFunc("GET /api/portal/software", s.portalGuard(s.handlePortalSoftware))
	mux.HandleFunc("POST /api/portal/software/action", s.portalGuard(s.handlePortalSoftwareAction))
	mux.HandleFunc("GET /api/portal/runs/{id}", s.portalGuard(s.handlePortalGetRun))
	mux.HandleFunc("GET /api/portal/tickets", s.portalGuard(s.handlePortalListTickets))
	mux.HandleFunc("GET /api/portal/tickets/{id}", s.portalGuard(s.handlePortalGetTicket))
	mux.HandleFunc("POST /api/portal/tickets", s.portalGuard(s.handlePortalCreateTicket))
	mux.HandleFunc("POST /api/portal/tickets/{id}/comments", s.portalGuard(s.handlePortalAddComment))

	mux.HandleFunc("GET /api/agent/update-check", s.handleAgentUpdateCheck)

	// Transparency log heads and proofs hold only hashes and sizes, and an
	// outside auditor has no session. The leaves themselves are admin only
	// (below).
	mux.HandleFunc("GET /api/log/head", s.handleLogHead)
	mux.HandleFunc("GET /api/log/proof", s.handleLogProof)
	mux.HandleFunc("GET /api/log/consistency", s.handleLogConsistency)

	api := http.NewServeMux()
	api.HandleFunc("GET /api/server/version", s.handleServerVersionInfo)
	api.HandleFunc("POST /api/server/update", s.requireAdmin(s.handleServerUpdate))
	api.HandleFunc("POST /api/agents/update-all", s.requireAdmin(s.handleDispatchAllAgentsUpdate))
	api.HandleFunc("POST /api/agents/update-batch", s.requireAdmin(s.handleDispatchAgentBatchUpdate))
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
	api.HandleFunc("POST /api/agents/{id}/update", s.requireWrite(s.handleDispatchAgentUpdate))
	api.HandleFunc("GET /api/agents/{id}/metrics", s.handleAgentMetrics)
	api.HandleFunc("GET /api/agents/{id}/events", s.handleAgentEvents)
	api.HandleFunc("POST /api/agents/{id}/refresh", s.requireWrite(s.handleAgentRefresh))
	api.HandleFunc("GET /api/agents/{id}/processes", s.handleProcesses)
	api.HandleFunc("POST /api/agents/{id}/processes/kill", s.requireWrite(s.handleProcKill))
	api.HandleFunc("GET /api/agents/{id}/services", s.handleServices)
	api.HandleFunc("POST /api/agents/{id}/services/action", s.requireWrite(s.handleServiceAction))
	api.HandleFunc("GET /api/agents/{id}/eventlog", s.guardEventLog(s.handleEventLog))
	api.HandleFunc("GET /api/agents/{id}/fs", s.handleFsList)
	api.HandleFunc("GET /api/agents/{id}/fs/download", s.requireWrite(s.handleFsDownload))
	api.HandleFunc("POST /api/agents/{id}/fs/upload", s.requireWrite(s.handleFsUpload))
	api.HandleFunc("POST /api/agents/{id}/fs/commit", s.requireWrite(s.handleFsCommit))
	api.HandleFunc("POST /api/agents/{id}/fs/delete", s.requireWrite(s.handleFsDelete))
	api.HandleFunc("POST /api/agents/{id}/fs/mkdir", s.requireWrite(s.handleFsMkdir))
	api.HandleFunc("POST /api/agents/{id}/fs/rename", s.requireWrite(s.handleFsRename))
	api.HandleFunc("POST /api/agents/{id}/power", s.requireWrite(s.handlePower))
	api.HandleFunc("POST /api/agents/{id}/wol", s.requireWrite(s.handleWakeOnLan))
	api.HandleFunc("POST /api/agents/{id}/isolate", s.requireWrite(s.handleIsolateAgent))
	api.HandleFunc("POST /api/agents/{id}/run", s.requireWrite(s.handleRunScriptOnAgent))
	api.HandleFunc("GET /api/agents/{id}/patches", s.handleAgentPatches)
	api.HandleFunc("POST /api/agents/{id}/patches/scan", s.requireWrite(s.handlePatchScan))
	api.HandleFunc("POST /api/agents/{id}/patches/install", s.requireWrite(s.handlePatchInstall))
	api.HandleFunc("GET /api/agents/{id}/servicing", s.handleListServicing)
	api.HandleFunc("POST /api/agents/{id}/servicing/repair", s.requireWrite(s.handleServicingRepair))
	api.HandleFunc("GET /ws/shell/{id}", s.requireWrite(s.handleShellWS))
	api.HandleFunc("GET /ws/desktop/{id}", s.requireWrite(s.handleDesktopViewerWS))

	api.HandleFunc("GET /api/organizations", s.handleListOrganizations)
	api.HandleFunc("POST /api/organizations", s.requireAdmin(s.handleCreateOrganization))
	api.HandleFunc("PUT /api/organizations/{id}", s.requireAdmin(s.handleUpdateOrganization))
	api.HandleFunc("DELETE /api/organizations/{id}", s.requireAdmin(s.handleDeleteOrganization))
	api.HandleFunc("GET /api/organizations/{id}/sites", s.handleListSites)
	api.HandleFunc("GET /api/sites", s.handleListSites)
	api.HandleFunc("POST /api/organizations/{id}/sites", s.requireAdmin(s.handleCreateSite))
	api.HandleFunc("PUT /api/sites/{id}", s.requireAdmin(s.handleUpdateSite))
	api.HandleFunc("DELETE /api/sites/{id}", s.requireAdmin(s.handleDeleteSite))

	// Phase 3 signed actions. Security keys belong to whoever registers them;
	// the trust bundle is the fleet's root of trust and admin only.
	api.HandleFunc("POST /api/webauthn/register/begin", s.handleWebAuthnBegin)
	api.HandleFunc("POST /api/webauthn/register/finish", s.handleWebAuthnFinish)
	api.HandleFunc("GET /api/webauthn/credentials", s.handleListCredentials)
	api.HandleFunc("DELETE /api/webauthn/credentials/{id}", s.handleDeleteCredential)
	api.HandleFunc("GET /api/organizations/{id}/trust", s.requireAdmin(s.handleGetOrgTrust))
	api.HandleFunc("POST /api/organizations/{id}/trust/proposals", s.requireAdmin(s.handleCreateTrustProposal))
	api.HandleFunc("GET /api/trust/proposals/{pid}", s.requireAdmin(s.handleGetTrustProposal))
	api.HandleFunc("POST /api/trust/proposals/{pid}/sign", s.requireAdmin(s.handleSignTrustProposal))
	api.HandleFunc("POST /api/trust/proposals/{pid}/recovery", s.requireAdmin(s.handleRecoverTrustProposal))
	api.HandleFunc("GET /api/log/entries/{index}", s.requireAdmin(s.handleLogEntry))

	// Signed actions: the approvals queue, standing approvals of unattended
	// objects, and the grants behind the shell, desktop and file browser.
	api.HandleFunc("GET /api/approvals", s.handleListApprovals)
	api.HandleFunc("GET /api/approvals/unsigned", s.handleUnsignedApprovals)
	api.HandleFunc("POST /api/approvals/objects/{type}/{id}/sign", s.requireWrite(s.handleSignObject))
	api.HandleFunc("GET /api/approvals/{manifest_id}", s.handleGetApproval)
	api.HandleFunc("POST /api/approvals/{manifest_id}/sign", s.requireWrite(s.handleSignApproval))
	api.HandleFunc("POST /api/agents/{id}/grant", s.requireWrite(s.handleGrant))

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

	api.HandleFunc("GET /api/automations", s.requireAdmin(s.handleListAutomations))
	api.HandleFunc("POST /api/automations", s.requireAdmin(s.handleCreateAutomation))
	api.HandleFunc("PUT /api/automations/{id}", s.requireAdmin(s.handleUpdateAutomation))
	api.HandleFunc("DELETE /api/automations/{id}", s.requireAdmin(s.handleDeleteAutomation))

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

	// Software Catalog & Privileged Self-Service Execution
	api.HandleFunc("GET /api/software-catalog", s.handleListSoftwareCatalog)
	api.HandleFunc("POST /api/software-catalog", s.requireAdmin(s.handleCreateSoftwareCatalogItem))
	api.HandleFunc("GET /api/software-catalog/{id}", s.handleGetSoftwareCatalogItem)
	api.HandleFunc("PUT /api/software-catalog/{id}", s.requireAdmin(s.handleUpdateSoftwareCatalogItem))
	api.HandleFunc("DELETE /api/software-catalog/{id}", s.requireAdmin(s.handleDeleteSoftwareCatalogItem))
	api.HandleFunc("POST /api/agents/{id}/software/install", s.requireWrite(s.handleAgentSoftwareInstall))
	api.HandleFunc("POST /api/agents/{id}/software/uninstall", s.requireWrite(s.handleAgentSoftwareUninstall))

	// Network Discovery & SNMP Polling
	api.HandleFunc("GET /api/discovered-devices", s.handleListDiscoveredDevices)
	api.HandleFunc("GET /api/discovered-devices/{id}", s.handleGetDiscoveredDevice)
	api.HandleFunc("PUT /api/discovered-devices/{id}", s.requireWrite(s.handleUpdateDiscoveredDevice))
	api.HandleFunc("DELETE /api/discovered-devices/{id}", s.requireWrite(s.handleDeleteDiscoveredDevice))
	api.HandleFunc("POST /api/discovered-devices/{id}/poll", s.requireWrite(s.handlePollDiscoveredDeviceSNMP))
	api.HandleFunc("GET /api/network-scans", s.handleListNetworkScans)
	api.HandleFunc("POST /api/network-scans", s.requireWrite(s.handleStartNetworkScan))

	// Integrated Helpdesk Ticketing System
	api.HandleFunc("GET /api/tickets", s.handleListTickets)
	api.HandleFunc("GET /api/tickets/{id}", s.handleGetTicket)
	api.HandleFunc("POST /api/tickets", s.handleCreateTicket)
	api.HandleFunc("PUT /api/tickets/{id}", s.requireWrite(s.handleUpdateTicket))
	api.HandleFunc("DELETE /api/tickets/{id}", s.requireAdmin(s.handleDeleteTicket))
	api.HandleFunc("POST /api/tickets/{id}/comments", s.requireWrite(s.handleAddTicketComment))
	api.HandleFunc("GET /api/agents/{id}/tickets", s.handleAgentTickets)

	api.HandleFunc("GET /api/settings", s.requireAdmin(s.handleGetSettings))
	api.HandleFunc("PUT /api/settings", s.requireAdmin(s.handlePutSettings))
	api.HandleFunc("POST /api/settings/test-mail", s.requireAdmin(s.handleTestMail))
	api.HandleFunc("GET /api/users", s.requireAdmin(s.handleListUsers))
	api.HandleFunc("POST /api/users", s.requireAdmin(s.handleCreateUser))
	api.HandleFunc("PUT /api/users/{id}", s.requireAdmin(s.handleUpdateUser))
	api.HandleFunc("DELETE /api/users/{id}", s.requireAdmin(s.handleDeleteUser))
	api.HandleFunc("GET /api/audit", s.requireAdmin(s.handleAudit))
	api.HandleFunc("GET /api/system", s.handleSystemInfo)

	mux.Handle("/api/", s.requireUser(api))
	mux.Handle("/ws/shell/", s.requireUser(api))
	mux.Handle("/ws/desktop/", s.requireUser(api))
	mux.Handle("/", s.staticHandler())

	return logRequests(secureHeaders(mux))
}

// sensitiveEventLogChannel reports whether a channel name is an audit trail
// rather than an ordinary log. The Security channel is the device's own
// audit record (logons, and 4798-style enumerations with account names and
// SIDs) and the PowerShell channels carry whole command lines and script
// blocks, i.e. anything ever typed into a script. Reading one of those off a
// device gives up more than downloading a file from it, which has always
// been requireWrite and audited. Everything else - System, Application, a
// unit's journal - stays a plain read a viewer may do.
//
// The comparison is case- and space-insensitive because the channel name is
// resolved case-insensitively on both agents ("security" reaches the same
// log as "Security").
func sensitiveEventLogChannel(log string) bool {
	l := strings.ToLower(strings.TrimSpace(log))
	// "auth" is the Linux agent's name for the same selector.
	return l == "security" || l == "auth" || strings.Contains(l, "powershell")
}

// guardEventLog gates and records the sensitive channels of
// GET /api/agents/{id}/eventlog. The decision is per request, not per route,
// because the channel is a query parameter. The audit row is written before
// the device is asked: the operator asked for the Security log either way,
// and a read that fails because the device is offline is still worth a line.
func (s *Server) guardEventLog(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if !sensitiveEventLogChannel(q.Get("log")) {
			next(w, r)
			return
		}
		if !userFrom(r.Context()).CanWrite() {
			writeErr(w, http.StatusForbidden, "read-only account")
			return
		}
		s.audit(r, "eventlog.query", r.PathValue("id"), map[string]string{
			"log":    q.Get("log"),
			"level":  q.Get("level"),
			"search": q.Get("search"),
		})
		next(w, r)
	}
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
	case errors.Is(err, ErrSignedRunOffline):
		writeErr(w, http.StatusConflict, err.Error())
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

// audit records what a request did in the name of the person it speaks for,
// at their address.
func (s *Server) audit(r *http.Request, action, target string, details any) {
	s.db.Audit(actor(r), s.requesterIP(r), action, target, details)
}

// requesterIP is the address of the person a request speaks for: the client's,
// unless the request runs a signed action for the operator who asked for it,
// whose address the pending entry kept (see withIssuer).
func (s *Server) requesterIP(r *http.Request) string {
	if from, ok := r.Context().Value(issuerAddrKey{}).(string); ok && from != "" {
		return from
	}
	return s.clientIP(r)
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
		"needs_setup":         needs,
		"setup_code_required": false,
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

// SetupCode is deprecated and returns "" since a setup code is no longer required.
func (s *Server) SetupCode() string {
	return ""
}

// handleSetup creates the first administrator.
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
	if strings.TrimSpace(in.Username) == "" {
		writeErr(w, 400, "username required")
		return
	}
	id, err := s.db.CreateUser(in.Username, in.Password, RoleAdmin, in.Email)
	if err != nil {
		fail(w, err)
		return
	}
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
	// Only this attempt is taken back. The address's other failures stay
	// counted: they may be guesses at someone else's account.
	loginLimiter.forgive(ip)
	s.db.Audit(res.User.Username, ip, "login", "", nil)
	s.setSessionCookie(w, r, tok, int(sessionTTL.Seconds()))
	writeJSON(w, 200, map[string]any{"ok": true, "user": res.User})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, _ := r.Cookie(sessionCookie); c != nil {
		s.db.deleteSession(c.Value)
		// a terminal or remote desktop this session left open ends with it
		s.recheckStreams()
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
	// ... and so does anything those sessions still had open
	s.recheckStreams()
	s.audit(r, "password.changed", u.Username, nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleTOTPBegin(w http.ResponseWriter, r *http.Request) {
	secret, url, err := s.db.beginTOTP(userFrom(r.Context()))
	if errors.Is(err, errTOTPAlreadyOn) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
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
	me := userFrom(r.Context())
	// The stream filters with the account as it was when it opened. End it
	// when the session goes away, and also when the role or organization
	// scope changes: the browser reconnects and the new stream filters with
	// the account as it is now.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	defer s.trackStream(r, func(u *User) bool {
		return me != nil && u.Role == me.Role && slices.Equal(u.OrgScope, me.OrgScope)
	}, cancel)()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case ev := <-ch:
			if me != nil && !me.IsAdmin() {
				agentOrgID := ev.OrgID
				if agentOrgID == "" && ev.AgentID != "" {
					if err := s.db.QueryRow(`SELECT org_id FROM agents WHERE id = ?`, ev.AgentID).Scan(&agentOrgID); err != nil {
						continue
					}
				}
				if agentOrgID != "" {
					if !s.canAccessAgent(me, agentOrgID) {
						continue
					}
				} else if len(me.OrgScope) > 0 || me.IsPOC() {
					// A scoped user must not receive unscoped agent/device events
					switch ev.Kind {
					case "event", "run", "metrics", "inventory", "baseline", "agent_online", "agent_offline":
						continue
					}
				}
			}
			b, _ := json.Marshal(ev)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Kind, b)
			fl.Flush()
		}
	}
}

// ---- dashboard ----

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	agents, err := s.agentsWithLiveness()
	if err != nil {
		fail(w, err)
		return
	}
	reqOrg := r.URL.Query().Get("org_id")
	reqSite := r.URL.Query().Get("site_id")
	me := userFrom(r.Context())

	var scopedAgents []*Agent
	allowedAgentIDs := make(map[string]bool)
	for _, a := range agents {
		if !s.canAccessAgent(me, a.OrgID) {
			continue
		}
		if reqOrg != "" && a.OrgID != reqOrg {
			continue
		}
		if reqSite != "" && a.SiteID != reqSite {
			continue
		}
		scopedAgents = append(scopedAgents, a)
		allowedAgentIDs[a.ID] = true
	}

	var online, offline, reboot, windows, linux int
	for _, a := range scopedAgents {
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

	rawAlerts, _ := s.db.ListAlerts("open", "", 500)
	var openAlerts, critical int
	filteredAlerts := []Alert{}
	for _, al := range rawAlerts {
		if allowedAgentIDs[al.AgentID] {
			openAlerts++
			if al.Severity == "critical" {
				critical++
			}
			if len(filteredAlerts) < 10 {
				filteredAlerts = append(filteredAlerts, al)
			}
		}
	}

	patchAgentSet := make(map[string]bool)
	if patchList, err := s.db.ListPatches("", "available", 2000); err == nil {
		for _, p := range patchList {
			if allowedAgentIDs[p.AgentID] {
				patchAgentSet[p.AgentID] = true
			}
		}
	}
	if appPatchList, err := s.db.ListPatches("", "approved", 2000); err == nil {
		for _, p := range appPatchList {
			if allowedAgentIDs[p.AgentID] {
				patchAgentSet[p.AgentID] = true
			}
		}
	}
	patches := len(patchAgentSet)

	rawRuns, _ := s.db.ListRuns("", 50)
	var runsToday, runsFailed int
	filteredRuns := []Run{}
	dayAgo := now() - 86400
	for _, run := range rawRuns {
		if allowedAgentIDs[run.AgentID] {
			if run.StartedAt > dayAgo {
				runsToday++
				if run.Status == "failed" || run.Status == "timeout" {
					runsFailed++
				}
			}
			if len(filteredRuns) < 10 {
				filteredRuns = append(filteredRuns, run)
			}
		}
	}

	writeJSON(w, 200, map[string]any{
		"agents_online": online, "agents_offline": offline, "pending_reboot": reboot,
		"windows": windows, "linux": linux,
		"open_alerts": openAlerts, "critical_alerts": critical, "devices_need_patches": patches,
		"runs_24h": runsToday, "runs_failed_24h": runsFailed,
		"recent_alerts": filteredAlerts, "recent_runs": filteredRuns,
		"server_version": Version, "uptime": int64(time.Since(s.startedAt).Seconds()),
	})
}

func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	var dbSize int64
	s.db.QueryRow(`SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()`).Scan(&dbSize)
	// The metrics series may live outside rmm.db, so its engine and size are
	// reported next to the database's. telemetry_bytes is -1 when the engine
	// cannot say (SQLite builds without the dbstat table).
	engine, teleBytes := s.cfg.TelemetryEngine(), int64(-1)
	if in, ok := s.db.telemetry.(telemetry.Inspector); ok {
		engine = in.Engine()
		if n, err := in.SizeBytes(); err == nil {
			teleBytes = n
		}
	}
	writeJSON(w, 200, map[string]any{
		"version": Version, "public_url": s.PublicURL(), "fingerprint": s.Fingerprint(), "pin_fingerprint": s.PinFingerprint(),
		"telemetry_engine": engine, "telemetry_bytes": teleBytes,
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
	rows, err := s.db.Query(`SELECT id, ts, user, ip, action, target, details, log_index FROM audit ORDER BY ts DESC, id DESC LIMIT ?`, limit)
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
		// LogIndex is the row's leaf in the transparency log, -1 for rows from
		// before the log or whose append failed.
		LogIndex int64 `json:"log_index"`
	}
	out := []row{}
	for rows.Next() {
		var x row
		rows.Scan(&x.ID, &x.TS, &x.User, &x.IP, &x.Action, &x.Target, &x.Details, &x.LogIndex)
		out = append(out, x)
	}
	writeJSON(w, 200, out)
}
