package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// The client portal is used by people who have no console account: whoever
// is signed in to a managed device. Nothing a browser sends can prove that,
// so the device's agent vouches instead. The tray app asks the local agent
// over a pipe only local processes can open; the agent reads the caller's
// Windows account off the pipe and, authenticated by its own agent key, asks
// POST /api/agent/portal-pass for a pass bound to (device, account). The tray
// opens /portal/start with that pass, which trades it for an rmm_portal
// cookie. Every /api/portal handler takes the device and the account from
// that cookie and never from the request.
//
// Passes and sessions live in memory: a server restart signs every portal
// window out, and the next tray click mints a fresh pass.

const (
	portalCookie     = "rmm_portal"
	portalPassTTL    = time.Minute
	portalSessionTTL = 12 * time.Hour
	maxPortalUserLen = 256
)

// portalIdentity is one device user's portal sign-in.
type portalIdentity struct {
	AgentID     string
	User        string // DOMAIN\name for a domain account, the bare name for a local one
	IsWorkgroup bool   // a local account: tickets are scoped to the device, not the user
	expires     time.Time
}

type portalAuth struct {
	mu       sync.Mutex
	passes   map[string]*portalIdentity
	sessions map[string]*portalIdentity
}

func newPortalAuth() *portalAuth {
	return &portalAuth{passes: map[string]*portalIdentity{}, sessions: map[string]*portalIdentity{}}
}

// sweep drops expired entries. Callers hold mu.
func (p *portalAuth) sweep(now time.Time) {
	for k, v := range p.passes {
		if now.After(v.expires) {
			delete(p.passes, k)
		}
	}
	for k, v := range p.sessions {
		if now.After(v.expires) {
			delete(p.sessions, k)
		}
	}
}

func (p *portalAuth) issuePass(id portalIdentity) string {
	tok := randomToken(32)
	now := time.Now()
	id.expires = now.Add(portalPassTTL)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sweep(now)
	p.passes[tok] = &id
	return tok
}

// redeem consumes a pass (single use) and opens a session for its identity.
func (p *portalAuth) redeem(pass string) (string, bool) {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	id, ok := p.passes[pass]
	delete(p.passes, pass)
	if !ok || now.After(id.expires) {
		return "", false
	}
	sess := *id
	sess.expires = now.Add(portalSessionTTL)
	tok := randomToken(32)
	p.sweep(now)
	p.sessions[tok] = &sess
	return tok, true
}

func (p *portalAuth) session(tok string) *portalIdentity {
	p.mu.Lock()
	defer p.mu.Unlock()
	id, ok := p.sessions[tok]
	if !ok {
		return nil
	}
	if time.Now().After(id.expires) {
		delete(p.sessions, tok)
		return nil
	}
	cp := *id
	return &cp
}

// dropAgent ends every pass and session for a device, for when it is deleted.
func (p *portalAuth) dropAgent(agentID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, v := range p.passes {
		if v.AgentID == agentID {
			delete(p.passes, k)
		}
	}
	for k, v := range p.sessions {
		if v.AgentID == agentID {
			delete(p.sessions, k)
		}
	}
}

// handleAgentPortalPass is called by an agent, authenticated by its agent key,
// on behalf of the account its pipe reported.
func (s *Server) handleAgentPortalPass(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		writeErr(w, http.StatusUnauthorized, "missing agent key")
		return
	}
	agentID, ok := s.db.agentByKey(strings.TrimPrefix(authz, "Bearer "))
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unknown agent key")
		return
	}
	var req struct {
		User        string `json:"user"`
		IsWorkgroup bool   `json:"is_workgroup"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, err)
		return
	}
	req.User = strings.TrimSpace(req.User)
	if req.User == "" || len(req.User) > maxPortalUserLen {
		writeErr(w, http.StatusBadRequest, "user is required")
		return
	}
	pass := s.portal.issuePass(portalIdentity{AgentID: agentID, User: req.User, IsWorkgroup: req.IsWorkgroup})
	writeJSON(w, http.StatusOK, map[string]string{"pass": pass})
}

// handlePortalStart trades a pass for a portal cookie and sends the window on
// to the page the tray asked for.
func (s *Server) handlePortalStart(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tok, ok := s.portal.redeem(q.Get("pass"))
	if !ok {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("This link has expired. Open the window again from the Homelab icon next to the clock."))
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     portalCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || !s.cfg.Insecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(portalSessionTTL / time.Second),
	})
	dest := "/portal/software"
	next := url.Values{}
	if q.Get("tab") == "tickets" {
		dest = "/portal/tickets"
		next.Set("tab", "tickets")
		if q.Get("new") == "1" {
			next.Set("new", "1")
		}
	}
	if len(next) > 0 {
		dest += "?" + next.Encode()
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// portalCaller is who is using the portal: a device user signed in through a
// pass, or a console user (a technician or a client point of contact) signed
// in with their account. Exactly one of the two is set.
type portalCaller struct {
	Device *portalIdentity
	User   *User
}

const portalCallerKey ctxKey = 2

func portalCallerFrom(ctx context.Context) *portalCaller {
	c, _ := ctx.Value(portalCallerKey).(*portalCaller)
	return c
}

// portalGuard refuses a portal request from nobody, and applies the same
// cross-site checks as authGuard to anything that changes state.
func (s *Server) portalGuard(next http.HandlerFunc) http.HandlerFunc {
	return s.authGuard(func(w http.ResponseWriter, r *http.Request) {
		var caller *portalCaller
		if c, _ := r.Cookie(portalCookie); c != nil {
			if id := s.portal.session(c.Value); id != nil {
				caller = &portalCaller{Device: id}
			}
		}
		if caller == nil {
			if c, _ := r.Cookie(sessionCookie); c != nil {
				if u := s.db.userBySession(c.Value); u != nil {
					caller = &portalCaller{User: u}
				}
			}
		}
		if caller == nil {
			writeErr(w, http.StatusUnauthorized, "open this window from the Homelab icon next to the clock")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), portalCallerKey, caller)))
	})
}

var errPortalNoDevice = errors.New("no device selected")

// portalAgent is the device a portal request acts on. A device user only
// ever gets their own device, whatever the request says. A console user names
// one with agent_id (or computer) and must be allowed to see it.
func (s *Server) portalAgent(r *http.Request, c *portalCaller, requested string) (*Agent, error) {
	if c.Device != nil {
		return s.db.GetAgent(c.Device.AgentID)
	}
	var a *Agent
	if requested != "" {
		a, _ = s.db.GetAgent(requested)
	}
	if a == nil {
		if computer := r.URL.Query().Get("computer"); computer != "" {
			var id string
			if err := s.db.QueryRow(`SELECT id FROM agents WHERE hostname = ? ORDER BY online DESC LIMIT 1`, computer).Scan(&id); err == nil {
				a, _ = s.db.GetAgent(id)
			}
		}
	}
	if a == nil || !s.canAccessAgent(c.User, a.OrgID) {
		return nil, errPortalNoDevice
	}
	return a, nil
}

// portalCanSeeTicket is the one access rule for reading or replying to a
// portal ticket. Internal tickets are never visible here.
func (s *Server) portalCanSeeTicket(c *portalCaller, t *Ticket) bool {
	if t.IsInternal {
		return false
	}
	if d := c.Device; d != nil {
		if d.IsWorkgroup {
			return t.AgentID == d.AgentID
		}
		// The same DOMAIN\name can exist at two clients, so the ticket must
		// also belong to this device's organization.
		a, err := s.db.GetAgent(d.AgentID)
		if err != nil {
			return false
		}
		return strings.EqualFold(t.RequesterDomainUser, d.User) && t.OrgID == a.OrgID
	}
	u := c.User
	if u.IsPOC() {
		return u.ContactOrg() != "" && t.OrgID == u.ContactOrg()
	}
	return s.canAccessAgent(u, t.OrgID)
}
