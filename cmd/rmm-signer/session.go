package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/term"
)

const (
	cookieName = "rmm_session"
	// sessionTTLFallback matches the server's session lifetime and is used
	// only when the login answer carries no expiry of its own.
	sessionTTLFallback = 14 * 24 * time.Hour
)

// session is what login keeps on disk. It has the same power as a logged-in
// browser, so the file is 0600 and logout deletes it.
type session struct {
	Server  string `json:"server"`
	Cookie  string `json:"cookie"`
	Expires int64  `json:"expires"` // unix seconds
}

// defaultSessionFile is %APPDATA%\homelab-rmm\signer.json on Windows and
// <user config dir>/homelab-rmm/signer.json elsewhere.
func defaultSessionFile() (string, error) {
	var dir string
	if runtime.GOOS == "windows" {
		dir = os.Getenv("APPDATA")
	}
	if dir == "" {
		d, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		dir = d
	}
	return filepath.Join(dir, "homelab-rmm", "signer.json"), nil
}

func (a *app) saveSession(s session) error {
	if a.sessionFile == "" {
		return errors.New("there is no user configuration directory to keep the session in")
	}
	if err := os.MkdirAll(filepath.Dir(a.sessionFile), 0o700); err != nil {
		return fmt.Errorf("could not create the session directory: %w", err)
	}
	raw, _ := json.Marshal(s)
	// Written beside the target and renamed so a crash never leaves a
	// half-written cookie file; 0600 so other local users cannot read it.
	tmp := a.sessionFile + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("could not write the session file: %w", err)
	}
	if err := os.Rename(tmp, a.sessionFile); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("could not write the session file: %w", err)
	}
	return nil
}

func (a *app) loadSession() (*session, error) {
	if a.sessionFile == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(a.sessionFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("could not read the session file %s: %w", a.sessionFile, err)
	}
	var s session
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("the session file %s is damaged; run rmm-signer login again", a.sessionFile)
	}
	return &s, nil
}

// normalizeServer reduces a --server value to scheme://host[:port][/prefix]
// and returns the web origin a browser would report for it.
func normalizeServer(raw string) (base, origin string, err error) {
	raw = strings.TrimSpace(raw)
	u, perr := url.Parse(raw)
	if perr != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", "", fmt.Errorf("%q is not a server URL; use the form https://rmm.example.com", raw)
	}
	// A browser reports the origin without the scheme's default port, and the
	// verifier compares the string exactly, so https://host:443 must become
	// https://host or the tool would refuse to sign for a correct server.
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	if port := u.Port(); (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		host = strings.ToLower(strings.TrimSuffix(u.Host, ":"+port))
	}
	origin = scheme + "://" + host
	return origin + strings.TrimRight(u.Path, "/"), origin, nil
}

// target resolves the server from the flag, RMM_SERVER or the saved session.
func (a *app) target(flagVal string) (base, origin string, err error) {
	v := flagVal
	if v == "" {
		v = a.getenv("RMM_SERVER")
	}
	if v == "" {
		if s, _ := a.loadSession(); s != nil {
			v = s.Server
		}
	}
	if v == "" {
		return "", "", usagef("no server given: pass --server URL or set RMM_SERVER.")
	}
	return normalizeServer(v)
}

// authed returns the stored cookie for base, refusing a session that belongs
// to another server or has expired.
func (a *app) authed(base string) (string, error) {
	s, err := a.loadSession()
	if err != nil {
		return "", err
	}
	if s == nil || s.Cookie == "" {
		return "", fmt.Errorf("you are not signed in to %s; run: rmm-signer login --server %s", base, base)
	}
	if s.Server != base {
		return "", fmt.Errorf("the saved session is for %s, not %s; run: rmm-signer login --server %s", s.Server, base, base)
	}
	if s.Expires != 0 && s.Expires <= a.now().Unix() {
		return "", fmt.Errorf("the saved session has expired; run: rmm-signer login --server %s", base)
	}
	return s.Cookie, nil
}

// reply is one answer from the server.
type reply struct {
	status int
	body   []byte
	header http.Header
}

// call performs one API request. Transport problems are errors; HTTP statuses
// are left to the caller, who knows which ones mean something.
func (a *app) call(ctx context.Context, base, cookie, method, path string, body any) (*reply, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// The server's CSRF check wants this on every state-changing request.
	req.Header.Set("X-Requested-With", "rmm-signer")
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: cookie})
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach %s: %w", base, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("the answer from %s was cut off: %w", base, err)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fmt.Errorf("%s redirected the request; check that --server is the console's own address", base)
	}
	return &reply{status: resp.StatusCode, body: raw, header: resp.Header}, nil
}

// apiError turns a non-success answer into a sentence for the operator.
func apiError(r *reply, base string) error {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(r.body, &e)
	msg := e.Error
	if msg == "" {
		msg = strings.TrimSpace(string(r.body))
		if len(msg) > 200 {
			msg = msg[:200]
		}
	}
	if r.status == http.StatusUnauthorized {
		return fmt.Errorf("the server does not accept this session (%s); run: rmm-signer login --server %s", safe(msg), base)
	}
	if msg == "" {
		return fmt.Errorf("the server answered HTTP %d with no message", r.status)
	}
	return fmt.Errorf("the server answered HTTP %d: %s", r.status, safe(msg))
}

func (a *app) cmdLogin(ctx context.Context, args []string) error {
	fs, server := a.newFlags("login")
	user := fs.String("user", "", "user name (asked for when omitted)")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("login takes no arguments.")
	}
	base, _, err := a.target(*server)
	if err != nil {
		return err
	}
	if err := requireSecureLogin(base); err != nil {
		return err
	}
	name := strings.TrimSpace(*user)
	if name == "" {
		fmt.Fprint(a.errw, "User name: ")
		line, err := a.in.ReadString('\n')
		if err != nil && line == "" {
			return errors.New("no user name was given")
		}
		name = strings.TrimSpace(line)
	}
	pw, err := a.readPassword("Password: ")
	if err != nil {
		return err
	}
	code := ""
	for attempt := 0; attempt < 2; attempt++ {
		// The same body the console sends.
		r, err := a.call(ctx, base, "", http.MethodPost, "/api/auth/login",
			map[string]string{"username": name, "password": pw, "code": code})
		if err != nil {
			return err
		}
		if r.status != http.StatusOK {
			return apiError(r, base)
		}
		var res struct {
			NeedsTOTP bool `json:"needs_totp"`
		}
		_ = json.Unmarshal(r.body, &res)
		if res.NeedsTOTP {
			if attempt == 1 {
				return errors.New("the server asked for an authenticator code again; sign-in was not completed")
			}
			c, err := a.readPassword("Authenticator code: ")
			if err != nil {
				return err
			}
			code = strings.TrimSpace(c)
			continue
		}
		cookie, exp := sessionCookieFrom(r.header, a.now())
		if cookie == "" {
			return errors.New("the server accepted the sign-in but sent no session cookie")
		}
		if err := a.saveSession(session{Server: base, Cookie: cookie, Expires: exp}); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "Signed in to %s as %s. The session is kept in %s until %s.\n",
			base, safe(name), a.sessionFile, time.Unix(exp, 0).UTC().Format("2006-01-02 15:04 UTC"))
		return nil
	}
	return errors.New("sign-in was not completed")
}

// sessionCookieFrom extracts the session cookie and its expiry from a login
// answer.
func sessionCookieFrom(h http.Header, now time.Time) (string, int64) {
	resp := http.Response{Header: h}
	for _, c := range resp.Cookies() {
		if c.Name != cookieName || c.Value == "" {
			continue
		}
		switch {
		case c.MaxAge > 0:
			return c.Value, now.Add(time.Duration(c.MaxAge) * time.Second).Unix()
		case !c.Expires.IsZero():
			return c.Value, c.Expires.Unix()
		}
		return c.Value, now.Add(sessionTTLFallback).Unix()
	}
	return "", 0
}

func (a *app) cmdLogout(ctx context.Context, args []string) error {
	fs, server := a.newFlags("logout")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("logout takes no arguments.")
	}
	s, _ := a.loadSession()
	if s == nil {
		fmt.Fprintln(a.out, "No saved session.")
		return nil
	}
	// Ending it on the server makes a copied cookie file worthless too; if
	// the server cannot be reached the local file is deleted regardless.
	base := s.Server
	if *server != "" || a.getenv("RMM_SERVER") != "" {
		if b, _, err := a.target(*server); err == nil && b != s.Server {
			return fmt.Errorf("the saved session is for %s, not %s; nothing was changed", s.Server, b)
		}
	}
	note := ""
	if r, err := a.call(ctx, base, s.Cookie, http.MethodPost, "/api/auth/logout", map[string]string{}); err != nil {
		note = " The server could not be reached, so the session may still be valid there until it expires."
	} else if r.status != http.StatusOK {
		note = fmt.Sprintf(" The server answered HTTP %d to the logout request.", r.status)
	}
	if err := os.Remove(a.sessionFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("could not delete the session file %s: %w", a.sessionFile, err)
	}
	fmt.Fprintf(a.out, "Signed out of %s and deleted %s.%s\n", base, a.sessionFile, note)
	return nil
}

// readSecret reads a password or code without echo from a terminal. When
// stdin is not a terminal (a pipe, a test) it reads one plain line.
func readSecret(w io.Writer, in *bufio.Reader, prompt string) (string, error) {
	fmt.Fprint(w, prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(w)
		if err != nil {
			return "", fmt.Errorf("could not read from the terminal: %w", err)
		}
		return string(b), nil
	}
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New("no input was given")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// requireSecureLogin refuses to send a password and authenticator code over
// plain http. The one exception is a loopback address, where the traffic never
// leaves the machine (a console under development).
func requireSecureLogin(base string) error {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "http" {
		return nil
	}
	h := u.Hostname()
	if ip := net.ParseIP(h); strings.EqualFold(h, "localhost") || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("%s is plain http, so your password and authenticator code would cross the network unencrypted and anyone on the path could read them; use the https address of the console, or a loopback address for a local one", base)
}
