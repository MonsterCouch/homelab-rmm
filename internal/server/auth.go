package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookie = "rmm_session"
	sessionTTL    = 14 * 24 * time.Hour
	RoleAdmin     = "admin"
	RoleTech      = "tech"
	RoleViewer    = "viewer"
	// RoleContact is a client's point of contact: someone at a client
	// business who sees that one organization's tickets in the portal and
	// cannot use the management console at all. Stored as "poc".
	RoleContact = "poc"
)

// A role is valid when it is built in or a custom role that resolves; see
// DB.roleExists in roles.go.

// checkRoleScope is the one rule tying a role to its organizations: a client
// contact belongs to exactly one, which must exist. Everyone else may have
// any scope (none means every organization).
func (d *DB) checkRoleScope(role string, orgScope []string) error {
	if d.resolveRole(role).Base != RoleContact {
		return nil
	}
	if len(orgScope) != 1 {
		return errors.New("a client contact must belong to exactly one organization")
	}
	var one int
	if err := d.QueryRow(`SELECT 1 FROM organizations WHERE id = ?`, orgScope[0]).Scan(&one); err != nil {
		return errors.New("that organization does not exist")
	}
	return nil
}

// User is the authenticated principal attached to a request context.
type User struct {
	ID          int64    `json:"id"`
	Username    string   `json:"username"`
	Role        string   `json:"role"`
	Email       string   `json:"email"`
	OrgScope    []string `json:"org_scope"`
	TOTPEnabled bool     `json:"totp_enabled"`
	CreatedAt   int64    `json:"created_at"`
	LastLogin   int64    `json:"last_login"`
	// What the role works out to (roles.go). Role is a built-in role or a
	// custom role's id; Base is the built-in at the root of its chain, which
	// is what the broad gates go by.
	RoleName        string          `json:"role_name"`
	Base            string          `json:"base_role"`
	Permissions     map[string]bool `json:"permissions"`
	AutomationScope automationScope `json:"automation_scope"`
}

func parseOrgScope(s string) []string {
	var out []string
	if s != "" {
		_ = json.Unmarshal([]byte(s), &out)
	}
	if out == nil {
		out = []string{}
	}
	return out
}

type ctxKey int

const userKey ctxKey = 1

func userFrom(ctx context.Context) *User {
	u, _ := ctx.Value(userKey).(*User)
	return u
}

// CanWrite reports whether the role may change state. Viewers are read-only;
// techs can do everything except manage users and global settings. It names
// the roles that may, so a role added later is read-only until it is listed.
func (u *User) CanWrite() bool {
	b := u.base()
	return b == RoleAdmin || b == RoleTech
}
func (u *User) IsAdmin() bool { return u.base() == RoleAdmin }

// IsPOC reports whether u is a client contact (see RoleContact).
func (u *User) IsPOC() bool { return u.base() == RoleContact }

// ContactOrg is the one organization a client contact belongs to, or "" if
// u is not a contact or (from an old record) has no single organization, in
// which case they see nothing.
func (u *User) ContactOrg() string {
	if !u.IsPOC() || len(u.OrgScope) != 1 {
		return ""
	}
	return u.OrgScope[0]
}

func randomToken(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func hashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	return string(h), err
}

func checkPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// ---- users ----

func (d *DB) CreateUser(username, password, role, email string) (int64, error) {
	return d.CreateUserWithScope(username, password, role, email, nil)
}

func (d *DB) CreateUserWithScope(username, password, role, email string, orgScope []string) (int64, error) {
	if len(password) < 8 {
		return 0, errors.New("password must be at least 8 characters")
	}
	if !d.roleExists(role) {
		return 0, errors.New("invalid role")
	}
	if err := d.checkRoleScope(role, orgScope); err != nil {
		return 0, err
	}
	h, err := hashPassword(password)
	if err != nil {
		return 0, err
	}
	scopeJSON := "[]"
	if len(orgScope) > 0 {
		b, _ := json.Marshal(orgScope)
		scopeJSON = string(b)
	}
	res, err := d.Exec(`INSERT INTO users(username, password_hash, role, email, org_scope, created_at) VALUES(?,?,?,?,?,?)`,
		strings.TrimSpace(username), h, role, email, scopeJSON, now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) UserCount() int {
	var n int
	d.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n
}

func (d *DB) ListUsers() ([]User, error) {
	rows, err := d.Query(`SELECT id, username, role, email, COALESCE(org_scope, '[]'), totp_enabled, created_at, last_login FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var scope string
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.Email, &scope, &u.TOTPEnabled, &u.CreatedAt, &u.LastLogin); err != nil {
			return nil, err
		}
		u.OrgScope = parseOrgScope(scope)
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Resolved after the cursor is done: a role lookup is another query.
	rows.Close()
	for i := range out {
		d.fillRole(&out[i])
	}
	return out, nil
}

type loginResult struct {
	User      *User
	NeedsTOTP bool
}

// authenticate verifies a password and, when the account has TOTP enabled,
// the code. A wrong code with a right password reports NeedsTOTP so the UI
// can prompt for it without leaking whether the password was right to an
// attacker: the same response is produced for an empty code.
func (d *DB) authenticate(username, password, code string) (*loginResult, error) {
	var (
		u      User
		scope  string
		hash   string
		secret string
	)
	err := d.QueryRow(`SELECT id, username, role, email, COALESCE(org_scope, '[]'), totp_enabled, created_at, last_login, password_hash, totp_secret FROM users WHERE username = ?`, username).
		Scan(&u.ID, &u.Username, &u.Role, &u.Email, &scope, &u.TOTPEnabled, &u.CreatedAt, &u.LastLogin, &hash, &secret)
	if err != nil {
		// burn time so a missing user costs as much as a wrong password
		bcrypt.CompareHashAndPassword([]byte("$2a$12$7EqJtq98hPqEX7fNZaFWoOhi5XkKzN0vY7zgQ/1Y6yQ8n6jvJ6Yy6"), []byte(password))
		return nil, errors.New("invalid credentials")
	}
	u.OrgScope = parseOrgScope(scope)
	d.fillRole(&u)
	if !checkPassword(hash, password) {
		return nil, errors.New("invalid credentials")
	}
	if u.TOTPEnabled {
		if code == "" || !totp.Validate(code, secret) {
			return &loginResult{NeedsTOTP: true}, nil
		}
	}
	d.Exec(`UPDATE users SET last_login = ? WHERE id = ?`, now(), u.ID)
	return &loginResult{User: &u}, nil
}

func (d *DB) createSession(userID int64, ip, ua string) (string, error) {
	tok := randomToken(32)
	_, err := d.Exec(`INSERT INTO sessions(token, user_id, created_at, expires_at, ip, user_agent) VALUES(?,?,?,?,?,?)`,
		tok, userID, now(), time.Now().Add(sessionTTL).Unix(), ip, ua)
	return tok, err
}

func (d *DB) userBySession(token string) *User {
	if token == "" {
		return nil
	}
	var u User
	var scope string
	var exp int64
	err := d.QueryRow(`SELECT u.id, u.username, u.role, u.email, COALESCE(u.org_scope, '[]'), u.totp_enabled, u.created_at, u.last_login, s.expires_at
		FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?`, token).
		Scan(&u.ID, &u.Username, &u.Role, &u.Email, &scope, &u.TOTPEnabled, &u.CreatedAt, &u.LastLogin, &exp)
	if err != nil || exp < now() {
		return nil
	}
	u.OrgScope = parseOrgScope(scope)
	d.fillRole(&u)
	return &u
}

func (d *DB) deleteSession(token string) {
	d.Exec(`DELETE FROM sessions WHERE token = ?`, token)
}

func (d *DB) purgeSessions() {
	d.Exec(`DELETE FROM sessions WHERE expires_at < ?`, now())
}

// ---- TOTP ----

// errTOTPAlreadyOn is beginTOTP's refusal to touch a factor that is in use.
var errTOTPAlreadyOn = errors.New("two-step sign-in is already on: turn it off with your password before setting it up again")

// beginTOTP stores a new, not yet confirmed secret. It only does so while
// two-step sign-in is off. Beginning used to clear an enabled factor and
// replace its secret with nothing but a session, while turning it off asks
// for the password: whoever held a session cookie could remove the second
// factor, or swap in a secret only they knew. The condition is in the UPDATE
// so a concurrent confirm cannot slip between a check and the write.
func (d *DB) beginTOTP(u *User) (secret, url string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Homelab RMM", AccountName: u.Username})
	if err != nil {
		return "", "", err
	}
	res, err := d.Exec(`UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ? AND totp_enabled = 0`, key.Secret(), u.ID)
	if err != nil {
		return "", "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", "", errTOTPAlreadyOn
	}
	return key.Secret(), key.URL(), nil
}

func (d *DB) confirmTOTP(u *User, code string) error {
	var secret string
	if err := d.QueryRow(`SELECT totp_secret FROM users WHERE id = ?`, u.ID).Scan(&secret); err != nil {
		return err
	}
	if secret == "" || !totp.Validate(code, secret) {
		return errors.New("invalid code")
	}
	_, err := d.Exec(`UPDATE users SET totp_enabled = 1 WHERE id = ?`, u.ID)
	return err
}

func (d *DB) disableTOTP(userID int64) error {
	_, err := d.Exec(`UPDATE users SET totp_enabled = 0, totp_secret = '' WHERE id = ?`, userID)
	return err
}

// ---- middleware ----

// parseTrustedProxies turns the configured CIDRs (a bare address means a
// single host) into networks. It is kept per Server rather than in a package
// variable so two servers in one process - which is what the tests do - cannot
// overwrite each other's setting.
//
// net.ParseCIDR masks the host bits off, so "10.0.0.5/8" is the whole of
// 10.0.0.0/8 and not one host: that is a much wider grant than the typo
// suggests, so say so out loud rather than trusting a /8 silently.
func parseTrustedProxies(cidrs []string) []*net.IPNet {
	var out []*net.IPNet
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		bare := !strings.Contains(c, "/")
		if bare {
			if strings.Contains(c, ":") {
				c += "/128"
			} else {
				c += "/32"
			}
		}
		ip, n, err := net.ParseCIDR(c)
		if err != nil {
			slog.Warn("ignoring unparsable trusted proxy", "value", c, "err", err)
			continue
		}
		if !bare && !ip.Mask(n.Mask).Equal(n.IP) {
			slog.Warn("trusted proxy has host bits set: the WHOLE network is trusted, not that one address",
				"value", c, "trusts", n.String())
		}
		out = append(out, n)
	}
	return out
}

// isTrustedProxy reports whether ip is one of the configured reverse proxies.
func (s *Server) isTrustedProxy(ip net.IP) bool {
	for _, n := range s.trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// forwardedHop parses one X-Forwarded-For element. Entries are bare addresses
// in practice, but a proxy that writes "1.2.3.4:5678" or "[::1]:5678" should
// not knock the whole chain out.
func forwardedHop(v string) net.IP {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	if ip := net.ParseIP(strings.Trim(v, "[]")); ip != nil {
		return ip
	}
	if h, _, err := net.SplitHostPort(v); err == nil {
		return net.ParseIP(strings.Trim(h, "[]"))
	}
	return nil
}

// clientIP is the peer address, or the nearest address in X-Forwarded-For that
// a trusted proxy did not put there, when the peer is one of the configured
// reverse proxies. An untrusted peer could otherwise forge the header to dodge
// the login limiter and falsify the audit log, so the header is ignored unless
// --trusted-proxies says where the proxy is.
//
// The list is walked from the RIGHT, skipping hops that are themselves trusted
// proxies, because every proxy this project ships a config for APPENDS to the
// header rather than replacing it (nginx's $proxy_add_x_forwarded_for, and
// Caddy by default). The left-most entry is therefore whatever the client
// chose to send - which is exactly the forgery the guard exists to stop - and
// the right-most non-proxy entry is the address the outermost trusted proxy
// actually saw.
func (s *Server) clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" || len(s.trustedProxies) == 0 {
		return host
	}
	peer := net.ParseIP(host)
	if peer == nil || !s.isTrustedProxy(peer) {
		return host
	}
	hops := strings.Split(xff, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		ip := forwardedHop(hops[i])
		if ip == nil {
			// A hop we cannot parse breaks the chain: everything to its left
			// is unattributable, so fall back to the peer rather than guess.
			return host
		}
		if s.isTrustedProxy(ip) {
			continue // another hop of our own proxy chain
		}
		return ip.String()
	}
	// Every hop was one of our proxies (a health check through the chain, say).
	return host
}

// requireUser attaches the session user or rejects with 401. State-changing
// methods must also carry the X-Requested-With header, which a cross-site
// form post cannot set; together with SameSite=Strict on the cookie that is
// the CSRF defence.
func (s *Server) requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie(sessionCookie)
		var u *User
		if c != nil {
			u = s.db.userBySession(c.Value)
		}
		if u == nil {
			writeErr(w, http.StatusUnauthorized, "not signed in")
			return
		}
		if u.IsPOC() && !contactMayUse(r) {
			writeErr(w, http.StatusForbidden, "client contacts can only use the support portal")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-Requested-With") == "" && !isWebSocket(r) {
			writeErr(w, http.StatusForbidden, "missing X-Requested-With header")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	})
}

// contactMayUse is all of the console a client contact may reach: their own
// account (to change their password or set up two-step sign-in). Tickets
// live under /api/portal, which does not come through here.
func contactMayUse(r *http.Request) bool {
	switch r.URL.Path {
	case "/api/me", "/api/me/password", "/api/me/totp/begin", "/api/me/totp/confirm", "/api/me/totp/disable":
		return true
	}
	return false
}

func (s *Server) requireWrite(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !userFrom(r.Context()).CanWrite() {
			writeErr(w, http.StatusForbidden, "read-only account")
			return
		}
		next(w, r)
	}
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !userFrom(r.Context()).IsAdmin() {
			writeErr(w, http.StatusForbidden, "admin only")
			return
		}
		next(w, r)
	}
}

func isWebSocket(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || !s.cfg.Insecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	})
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ResetPassword is the CLI recovery path for a locked-out admin.
func (d *DB) ResetPassword(username, password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	h, err := hashPassword(password)
	if err != nil {
		return err
	}
	res, err := d.Exec(`UPDATE users SET password_hash = ?, totp_enabled = 0, totp_secret = '' WHERE username = ?`, h, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("no such user")
	}
	d.Exec(`DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?)`, username)
	return nil
}
