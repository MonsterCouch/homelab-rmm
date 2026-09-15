package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
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
)

// User is the authenticated principal attached to a request context.
type User struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	Role        string `json:"role"`
	Email       string `json:"email"`
	TOTPEnabled bool   `json:"totp_enabled"`
	CreatedAt   int64  `json:"created_at"`
	LastLogin   int64  `json:"last_login"`
}

type ctxKey int

const userKey ctxKey = 1

func userFrom(ctx context.Context) *User {
	u, _ := ctx.Value(userKey).(*User)
	return u
}

// CanWrite reports whether the role may change state. Viewers are read-only;
// techs can do everything except manage users and global settings.
func (u *User) CanWrite() bool { return u != nil && u.Role != RoleViewer }
func (u *User) IsAdmin() bool  { return u != nil && u.Role == RoleAdmin }

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
	if len(password) < 8 {
		return 0, errors.New("password must be at least 8 characters")
	}
	if role != RoleAdmin && role != RoleTech && role != RoleViewer {
		return 0, errors.New("invalid role")
	}
	h, err := hashPassword(password)
	if err != nil {
		return 0, err
	}
	res, err := d.Exec(`INSERT INTO users(username, password_hash, role, email, created_at) VALUES(?,?,?,?,?)`,
		strings.TrimSpace(username), h, role, email, now())
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
	rows, err := d.Query(`SELECT id, username, role, email, totp_enabled, created_at, last_login FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.Email, &u.TOTPEnabled, &u.CreatedAt, &u.LastLogin); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
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
		hash   string
		secret string
	)
	err := d.QueryRow(`SELECT id, username, role, email, totp_enabled, created_at, last_login, password_hash, totp_secret FROM users WHERE username = ?`, username).
		Scan(&u.ID, &u.Username, &u.Role, &u.Email, &u.TOTPEnabled, &u.CreatedAt, &u.LastLogin, &hash, &secret)
	if err != nil {
		// burn time so a missing user costs as much as a wrong password
		bcrypt.CompareHashAndPassword([]byte("$2a$12$7EqJtq98hPqEX7fNZaFWoOhi5XkKzN0vY7zgQ/1Y6yQ8n6jvJ6Yy6"), []byte(password))
		return nil, errors.New("invalid credentials")
	}
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
	var exp int64
	err := d.QueryRow(`SELECT u.id, u.username, u.role, u.email, u.totp_enabled, u.created_at, u.last_login, s.expires_at
		FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?`, token).
		Scan(&u.ID, &u.Username, &u.Role, &u.Email, &u.TOTPEnabled, &u.CreatedAt, &u.LastLogin, &exp)
	if err != nil || exp < now() {
		return nil
	}
	return &u
}

func (d *DB) deleteSession(token string) {
	d.Exec(`DELETE FROM sessions WHERE token = ?`, token)
}

func (d *DB) purgeSessions() {
	d.Exec(`DELETE FROM sessions WHERE expires_at < ?`, now())
}

// ---- TOTP ----

func (d *DB) beginTOTP(u *User) (secret, url string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Homelab RMM", AccountName: u.Username})
	if err != nil {
		return "", "", err
	}
	if _, err := d.Exec(`UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?`, key.Secret(), u.ID); err != nil {
		return "", "", err
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

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
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
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-Requested-With") == "" && !isWebSocket(r) {
			writeErr(w, http.StatusForbidden, "missing X-Requested-With header")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	})
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
