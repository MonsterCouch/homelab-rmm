package server

// Regression tests for the findings of the 2026-09-15 security review. Every
// block fails against the code as it was before the fix it pins; the finding
// id is named in the comment above it so a failure points at the write-up.
//
// loginLimiter is a PACKAGE-LEVEL variable shared by every test in this
// package (handleLogin and handleSetup both count against it), so any test
// that reasons about limiter buckets resets the keys it uses before and after.
// newServerOnly does the same for the loopback buckets. Tests here never call
// t.Parallel, so they run one at a time.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// get fetches a plain (non-JSON) endpoint and returns status, body and headers.
func get(t *testing.T, url string) (int, string, http.Header) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return resp.StatusCode, string(body), resp.Header
}

// ---- sec-01 / inst-01: the install script is a shell script, so the token
// path segment and ?arch= must never reach it unvalidated. ----

func TestInstallScriptRefusesUnknownTokens(t *testing.T) {
	_, ts, b := newTestServerWith(t, Config{})

	// The payload from the review: the token segment closed the shell quote and
	// appended a command, which curl|sudo bash then ran as root.
	injection := "x%27%3B%20echo%20PWNED%3B%20%27"
	for _, bad := range []string{
		injection,
		"nope",                             // too short for the token shape
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // right shape, not a real token
		strings.Repeat("a", 65),            // longer than any token we mint
		"%2E%2E%2Fetc%2Fpasswd",            // traversal that survives as one path segment
		"$(id)",
	} {
		st, body, _ := get(t, ts.URL+"/install/"+bad+"?os=linux")
		if st != http.StatusNotFound {
			t.Errorf("install script for %q should be 404, got %d", bad, st)
		}
		if strings.Contains(body, "PWNED") || strings.Contains(body, "rmm-agent install") {
			t.Errorf("install script for %q leaked a script body: %s", bad, body)
		}
	}

	// A real token renders, on both platforms and every architecture we ship.
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab", "uses": 5}, &tok)
	for _, q := range []string{"?os=linux", "?os=windows", "?os=windows&arch=arm64", "?os=linux&arch=arm", "?os=linux&arch=386"} {
		st, body, hdr := get(t, ts.URL+"/install/"+tok.Token+q)
		if st != http.StatusOK {
			t.Fatalf("install script %s: %d %s", q, st, body)
		}
		if !strings.Contains(body, tok.Token) {
			t.Errorf("install script %s does not carry the token", q)
		}
		if hdr.Get("Cache-Control") != "no-store" {
			t.Errorf("install script %s should not be cacheable, got %q", q, hdr.Get("Cache-Control"))
		}
	}

	// An architecture we do not ship is rejected rather than interpolated.
	for _, bad := range []string{"evil", "amd64; rm -rf /", "x86_64", "$(uname -m)"} {
		st, _, _ := get(t, ts.URL+"/install/"+tok.Token+"?os=windows&arch="+bad)
		if st != http.StatusBadRequest {
			t.Errorf("arch %q should be 400, got %d", bad, st)
		}
	}

	// A token that has been fully consumed stops serving a script too.
	var one struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "single", "uses": 1}, &one)
	if st, _, _ := get(t, ts.URL+"/install/"+one.Token+"?os=linux"); st != http.StatusOK {
		t.Fatalf("fresh single-use token should render, got %d", st)
	}
	dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{one.Token}}, "consumer", "linux")
	if st, _, _ := get(t, ts.URL+"/install/"+one.Token+"?os=linux"); st != http.StatusNotFound {
		t.Errorf("exhausted token should stop serving the install script, got %d", st)
	}
}

func TestInstallScriptQuotesInterpolatedValues(t *testing.T) {
	if got := psQuote("it's"); got != "it''s" {
		t.Errorf(`psQuote("it's") = %q, want "it''s"`, got)
	}
	if got := shQuote("it's"); got != `it'\''s` {
		t.Errorf(`shQuote("it's") = %q, want %q`, got, `it'\''s`)
	}
	for _, s := range []string{"", "plain", "a`b$c", `back\slash`} {
		if psQuote(s) != s || shQuote(s) != s {
			t.Errorf("quoting changed a value with no quote in it: %q", s)
		}
	}

	// The public URL is operator-supplied (Settings -> System) and lands in both
	// templates, so it is the live injection path once the token is validated.
	_, ts, b := newTestServerWith(t, Config{})
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab"}, &tok)
	b.mustJSON("PUT", "/api/settings", map[string]any{"public_url": "http://rmm.lan'; echo PWNED; '"}, nil)

	_, sh, _ := get(t, ts.URL+"/install/"+tok.Token+"?os=linux")
	if !strings.Contains(sh, `SERVER='http://rmm.lan'\''; echo PWNED; '\'''`) {
		t.Errorf("bash script did not escape the quote in the public URL:\n%s", firstLines(sh, 8))
	}
	_, ps, _ := get(t, ts.URL+"/install/"+tok.Token+"?os=windows")
	if !strings.Contains(ps, `$server = 'http://rmm.lan''; echo PWNED; '''`) {
		t.Errorf("powershell script did not escape the quote in the public URL:\n%s", firstLines(ps, 8))
	}
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// ---- sec-02: a viewer is read-only, and a remote shell, a desktop session or
// a file download are not reads. ----

func TestViewerCannotOpenShellDesktopOrDownload(t *testing.T) {
	_, ts, admin := newTestServerWith(t, Config{})
	admin.mustJSON("POST", "/api/users", map[string]string{"username": "ro", "password": "password123", "role": "viewer"}, nil)
	ro := newBrowser(t, ts)
	ro.mustJSON("POST", "/api/auth/login", map[string]string{"username": "ro", "password": "password123"}, nil)

	denied := []string{
		"/ws/shell/x",
		"/ws/desktop/x",
		"/api/agents/x/fs/download?path=/etc/shadow",
	}
	for _, p := range denied {
		st, body := ro.do("GET", p, nil)
		if st != http.StatusForbidden {
			t.Errorf("viewer GET %s should be 403, got %d %s", p, st, body)
		}
	}
	// The 403 is the role gate, not the route: an admin gets past it and is
	// stopped later by the agent being offline.
	for _, p := range denied {
		if st, body := admin.do("GET", p, nil); st == http.StatusForbidden {
			t.Errorf("admin GET %s was refused by the role gate: %d %s", p, st, body)
		}
	}
	// Reading is still allowed.
	if st, _ := ro.do("GET", "/api/agents", nil); st != http.StatusOK {
		t.Errorf("viewer GET /api/agents should be 200, got %d", st)
	}
	if st, _ := ro.do("GET", "/api/agents/x/fs?path=/", nil); st == http.StatusForbidden {
		t.Error("viewer should still be able to list a directory")
	}
}

// ---- sec-03: 30 concurrent enrolments with a one-use token produced 22
// devices and left uses_left at -10, which reads as "unlimited" forever. ----

func TestEnrolTokenIsConsumedAtomically(t *testing.T) {
	s, ts, b := newTestServerWith(t, Config{})
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "one", "uses": 1}, &tok)

	const n = 20
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		welcomed int
	)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // line them all up on the same token
			ws, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/agent", http.Header{"X-Enroll-Token": []string{tok.Token}})
			if err != nil {
				return // refused before the upgrade: the pre-check saw it exhausted
			}
			defer ws.Close()
			if err := ws.WriteJSON(protocol.Envelope{T: protocol.TypeHello, D: protocol.Must(protocol.Hello{
				Hostname: fmt.Sprintf("race-%02d", i), OS: "linux", Version: "test",
			})}); err != nil {
				return
			}
			var env protocol.Envelope
			if err := ws.ReadJSON(&env); err == nil && env.T == "welcome" {
				mu.Lock()
				welcomed++
				mu.Unlock()
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if welcomed != 1 {
		t.Fatalf("a single-use token enrolled %d devices, want 1", welcomed)
	}
	var left int
	if err := s.db.QueryRow(`SELECT uses_left FROM enroll_tokens WHERE token = ?`, tok.Token).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Errorf("uses_left = %d after one enrolment, want 0 (negative reads as unlimited)", left)
	}
	var devices int
	s.db.QueryRow(`SELECT COUNT(*) FROM agents`).Scan(&devices)
	if devices != 1 {
		t.Errorf("%d device records created from a one-use token, want 1", devices)
	}

	// -1 is "unlimited": consuming it must not walk it towards 0.
	var unlimited struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "many", "uses": -1}, &unlimited)
	for i := 0; i < 3; i++ {
		dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{unlimited.Token}}, fmt.Sprintf("unl-%d", i), "linux")
	}
	if err := s.db.QueryRow(`SELECT uses_left FROM enroll_tokens WHERE token = ?`, unlimited.Token).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != -1 {
		t.Errorf("unlimited token moved to uses_left = %d, want -1", left)
	}
}

// ---- sec-04: the login limiter and the audit log keyed on a header the
// client controls, so a forged X-Forwarded-For bought a fresh bucket per
// request and an arbitrary address in the audit trail. ----

func TestForgedForwardedForDoesNotOpenLimiterBuckets(t *testing.T) {
	loginLimiter.reset("127.0.0.1")
	t.Cleanup(func() { loginLimiter.reset("127.0.0.1") })

	_, ts, _ := newTestServerWith(t, Config{}) // no TrustedProxies: header ignored
	var last int
	for i := 0; i < 12; i++ {
		last = failLogin(t, ts, fmt.Sprintf("203.0.113.%d", i+1))
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("limiter should trip on the peer address whatever X-Forwarded-For says, got %d", last)
	}
}

func TestTrustedProxyForwardedForIsHonoured(t *testing.T) {
	loginLimiter.reset("127.0.0.1")
	t.Cleanup(func() {
		loginLimiter.reset("127.0.0.1")
		for i := 0; i < 14; i++ {
			loginLimiter.reset(fmt.Sprintf("198.51.100.%d", i+1))
		}
		loginLimiter.reset("198.51.100.7")
	})

	s, ts, _ := newTestServerWith(t, Config{TrustedProxies: []string{"127.0.0.1"}})
	if len(s.trustedProxies) != 1 {
		t.Fatalf("expected one trusted proxy network, got %v", s.trustedProxies)
	}
	// Behind the proxy each forwarded client gets its own bucket, so twelve
	// different clients are not one attacker.
	for i := 0; i < 12; i++ {
		if st := failLogin(t, ts, fmt.Sprintf("198.51.100.%d", i+1)); st != http.StatusUnauthorized {
			t.Fatalf("attempt %d from a distinct forwarded client should be 401, got %d", i, st)
		}
	}
	// ... and one client hammering is still limited.
	var last int
	for i := 0; i < 12; i++ {
		last = failLogin(t, ts, "198.51.100.7")
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("a single forwarded client should be limited, got %d", last)
	}
	// The audit log records the forwarded client, not the proxy.
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action = 'login.failed' AND ip = ?`, "198.51.100.7").Scan(&n)
	if n == 0 {
		t.Error("failed logins behind a trusted proxy should be audited against the forwarded address")
	}
	s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action = 'login.failed' AND ip = ?`, "127.0.0.1").Scan(&n)
	if n != 0 {
		t.Errorf("%d failed logins were audited against the proxy's own address", n)
	}
}

func TestClientIPIgnoresGarbageFromATrustedProxy(t *testing.T) {
	s := &Server{trustedProxies: parseTrustedProxies([]string{"10.0.0.0/8", "not-a-cidr"})}
	if len(s.trustedProxies) != 1 {
		t.Fatalf("unparsable entry should be dropped, got %v", s.trustedProxies)
	}
	cases := []struct{ remote, xff, want string }{
		{"10.1.2.3:5000", "203.0.113.9", "203.0.113.9"}, // trusted proxy, believed
		// THE regression: every proxy config this repo ships APPENDS the peer
		// to whatever the client sent, so the left-most hop is the attacker's
		// and the right-most non-proxy hop is the real client.
		{"10.1.2.3:5000", "203.0.113.9, 192.168.1.50", "192.168.1.50"},
		{"10.1.2.3:5000", "6.6.6.6, 6.6.6.7, 192.168.1.50", "192.168.1.50"},
		{"10.1.2.3:5000", "203.0.113.9, 192.168.1.50:5000", "192.168.1.50"}, // hop with a port
		{"10.1.2.3:5000", "203.0.113.9, 10.0.0.7", "203.0.113.9"},           // a chain of our own proxies
		{"10.1.2.3:5000", "203.0.113.9, 10.1.2.3", "203.0.113.9"},
		{"10.1.2.3:5000", "10.0.0.7, 10.0.0.8", "10.1.2.3"}, // every hop trusted: the peer
		{"10.1.2.3:5000", "203.0.113.9, bogus", "10.1.2.3"}, // broken chain: the peer
		{"10.1.2.3:5000", "not an address", "10.1.2.3"},     // garbage: fall back
		{"192.0.2.5:5000", "203.0.113.9", "192.0.2.5"},      // untrusted peer: ignored
		{"192.0.2.5:5000", "6.6.6.6, 1.2.3.4", "192.0.2.5"}, // ... however many hops
		{"[2001:db8::1]:443", "203.0.113.9", "2001:db8::1"}, // untrusted v6 peer
		{"192.0.2.5:5000", "", "192.0.2.5"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/api/agents", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := s.clientIP(r); got != c.want {
			t.Errorf("clientIP(remote=%s, xff=%q) = %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
}

// failLogin posts a wrong password with a forged X-Forwarded-For and returns
// the status.
func failLogin(t *testing.T, ts *httptest.Server, xff string) int {
	t.Helper()
	req, err := http.NewRequest("POST", ts.URL+"/api/auth/login", strings.NewReader(`{"username":"admin","password":"wrong-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "fetch")
	req.Header.Set("X-Forwarded-For", xff)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// ---- sec-05: changing your own password left every other session alive, so a
// stolen cookie survived the reaction to the theft. ----

// The header a real proxy produces: the client prepends its own value and
// nginx's $proxy_add_x_forwarded_for (deploy/nginx.conf) appends the peer it
// saw. Taking the LEFT-MOST hop handed the attacker a fresh limiter bucket per
// request and an audit address of their choosing - sec-04, unchanged, in the
// deployment the docs recommend.
func TestForgedLeftHandForwardedForDoesNotBuyBuckets(t *testing.T) {
	keys := []string{"127.0.0.1", "192.168.1.50"}
	for i := 0; i < 16; i++ {
		keys = append(keys, fmt.Sprintf("203.0.113.%d", i+1))
	}
	reset := func() {
		for _, k := range keys {
			loginLimiter.reset(k)
		}
	}
	reset()
	t.Cleanup(reset)

	s, ts, _ := newTestServerWith(t, Config{TrustedProxies: []string{"127.0.0.1"}})
	var last int
	for i := 0; i < 14; i++ {
		last = failLogin(t, ts, fmt.Sprintf("203.0.113.%d, 192.168.1.50", i+1))
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("the limiter must key on the hop the proxy appended, not the one the client chose; got %d after 14 attempts", last)
	}
	var forged, real int
	s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action = 'login.failed' AND ip LIKE '203.0.113.%'`).Scan(&forged)
	s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action = 'login.failed' AND ip = '192.168.1.50'`).Scan(&real)
	if forged != 0 {
		t.Errorf("%d failed logins were audited against an address the client made up", forged)
	}
	if real == 0 {
		t.Error("no failed login was audited against the address the proxy reported")
	}
}

// net.ParseCIDR masks the host bits off, so a typo like 10.0.0.5/8 trusts the
// whole of 10.0.0.0/8. That is worth knowing about rather than discovering.
func TestTrustedProxyHostBitsCoverTheWholeNetwork(t *testing.T) {
	nets := parseTrustedProxies([]string{"10.0.0.5/8"})
	if len(nets) != 1 || nets[0].String() != "10.0.0.0/8" {
		t.Fatalf("expected 10.0.0.5/8 to parse as the network 10.0.0.0/8, got %v", nets)
	}
	s := &Server{trustedProxies: nets}
	if !s.isTrustedProxy(net.ParseIP("10.200.1.1")) {
		t.Error("a /8 with host bits set should still be recognised as the whole network (the warning says so)")
	}
}

func TestPasswordChangeRevokesOtherSessions(t *testing.T) {
	_, ts, a := newTestServerWith(t, Config{})
	bSess := newBrowser(t, ts)
	bSess.mustJSON("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "password123"}, nil)
	if st, _ := bSess.do("GET", "/api/me", nil); st != http.StatusOK {
		t.Fatalf("second session should start signed in, got %d", st)
	}

	a.mustJSON("POST", "/api/me/password", map[string]string{"current": "password123", "new": "password456"}, nil)

	if st, _ := bSess.do("GET", "/api/me", nil); st != http.StatusUnauthorized {
		t.Errorf("the other session should be 401 after a password change, got %d", st)
	}
	if st, _ := a.do("GET", "/api/me", nil); st != http.StatusOK {
		t.Errorf("the session that changed the password should still work, got %d", st)
	}
	// And the new password is the one that works.
	c := newBrowser(t, ts)
	if st, _ := c.do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "password123"}); st != http.StatusUnauthorized {
		t.Errorf("the old password should be refused, got %d", st)
	}
	c.mustJSON("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "password456"}, nil)
}

// ---- sec-06: first-run setup was unauthenticated, so anyone who could reach
// the port between start-up and the operator's browser could claim admin.
//
// The first fix exempted a loopback peer, which is wrong in three ways: a
// same-host reverse proxy makes every LAN request look like 127.0.0.1 (and
// keying that on --trusted-proxies made a security property depend on a flag
// the operator sets for an unrelated reason), any local process on the server
// can reach loopback, and a hostile page in a browser on the server can post
// there cross-origin. There is now no exemption at all. ----

func TestSetupAlwaysNeedsTheCode(t *testing.T) {
	s, ts := newServerOnly(t, Config{})
	code := s.SetupCode()
	if len(code) == 0 {
		t.Fatal("a server that starts with no users must mint a setup code")
	}

	// The state endpoint tells the UI to ask for the code, loopback included.
	local := newBrowser(t, ts)
	st, body := local.do("GET", "/api/auth/state", nil)
	if st != http.StatusOK || !strings.Contains(string(body), `"setup_code_required":true`) {
		t.Fatalf("loopback state should require the code: %d %s", st, body)
	}
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, request(t, "GET", "http://rmm.lan/api/auth/state", "10.0.0.9:1234", ""))
	if !strings.Contains(rec.Body.String(), `"setup_code_required":true`) {
		t.Fatalf("state from the network should require the code: %s", rec.Body.String())
	}

	// requireUser is not in this path: /api/auth/setup hangs off the outer mux.
	setup := func(remote, code string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		body := fmt.Sprintf(`{"username":"admin","password":"password123","code":%q}`, code)
		s.routes().ServeHTTP(rec, request(t, "POST", "http://rmm.lan/api/auth/setup", remote, body))
		return rec
	}
	for _, remote := range []string{"10.0.0.9:1234", "127.0.0.1:45001", "[::1]:45002"} {
		for _, wrong := range []string{"", "0000", strings.ToUpper(code) + "0"} {
			if rec := setup(remote, wrong); rec.Code != http.StatusForbidden {
				t.Fatalf("setup from %s with code %q should be 403, got %d %s", remote, wrong, rec.Code, rec.Body)
			}
		}
	}
	if n := s.db.UserCount(); n != 0 {
		t.Fatalf("a refused setup created %d users", n)
	}

	rec = setup("127.0.0.1:45001", strings.ToUpper(code)) // case-insensitive
	if rec.Code != http.StatusOK {
		t.Fatalf("setup with the right code should succeed, got %d %s", rec.Code, rec.Body)
	}
	if s.db.UserCount() != 1 {
		t.Fatal("setup with the right code did not create the admin")
	}
	if rec.Result().Cookies() == nil {
		t.Error("setup should sign the new admin in")
	}
	// The code is spent the moment the account exists.
	if s.SetupCode() != "" {
		t.Error("the setup code should be cleared once an administrator exists")
	}
	// Setup is a one-shot: a second attempt is refused from anywhere.
	if st, _ := local.do("POST", "/api/auth/setup", map[string]string{"username": "eve", "password": "password123", "code": code}); st != http.StatusForbidden {
		t.Errorf("second setup must be refused, got %d", st)
	}
	if rec := setup("10.0.0.9:1234", code); rec.Code != http.StatusForbidden {
		t.Errorf("second setup from the network must be refused, got %d", rec.Code)
	}
}

// A reverse proxy on the same host makes every request look like it comes from
// 127.0.0.1. That used to be the loopback exemption's blind spot, and keying
// the exemption on --trusted-proxies only closed it for operators who had set
// the flag - deploy/Caddyfile's documented command does not.
func TestSetupBehindALoopbackProxyNeedsTheCode(t *testing.T) {
	for _, cfg := range []Config{{}, {TrustedProxies: []string{"127.0.0.1"}}} {
		s, _ := newServerOnly(t, cfg)
		setup := func(code string) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			body := fmt.Sprintf(`{"username":"admin","password":"password123","code":%q}`, code)
			req := request(t, "POST", "http://rmm.lan/api/auth/setup", "127.0.0.1:45000", body)
			req.Header.Set("X-Forwarded-For", "192.0.2.50")
			s.routes().ServeHTTP(rec, req)
			return rec
		}
		if rec := setup(""); rec.Code != http.StatusForbidden {
			t.Fatalf("setup relayed by a same-host proxy (trusted=%v) must need the code, got %d %s", cfg.TrustedProxies, rec.Code, rec.Body)
		}
		if n := s.db.UserCount(); n != 0 {
			t.Fatalf("a LAN client behind the proxy claimed the admin account (trusted=%v)", cfg.TrustedProxies)
		}
		rec := httptest.NewRecorder()
		req := request(t, "GET", "http://rmm.lan/api/auth/state", "127.0.0.1:45000", "")
		req.Header.Set("X-Forwarded-For", "192.0.2.50")
		s.routes().ServeHTTP(rec, req)
		if !strings.Contains(rec.Body.String(), `"setup_code_required":true`) {
			t.Fatalf("state behind a proxy should require the code: %s", rec.Body.String())
		}
		if rec := setup(s.SetupCode()); rec.Code != http.StatusOK {
			t.Fatalf("the right code should still work through the proxy, got %d %s", rec.Code, rec.Body)
		}
	}
}

// First-run setup checks "are there users yet?" and then spends ~250 ms
// hashing the password before inserting. Every request that entered that
// window used to pass the check, so one first-run window produced eight
// administrators and eight live sessions.
func TestFirstRunSetupIsAtomic(t *testing.T) {
	s, ts := newServerOnly(t, Config{})
	code := s.SetupCode()

	const n = 8 // the limiter allows 10/min per address
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		oks   int
		start = make(chan struct{})
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			b := newBrowser(t, ts)
			<-start
			st, _ := b.do("POST", "/api/auth/setup", map[string]string{
				"username": fmt.Sprintf("u%d", i), "password": "password123", "code": code,
			})
			if st == http.StatusOK {
				mu.Lock()
				oks++
				mu.Unlock()
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if oks != 1 {
		t.Errorf("%d of %d concurrent first-run setups succeeded, want 1", oks, n)
	}
	if got := s.db.UserCount(); got != 1 {
		t.Errorf("one first-run window created %d administrators, want 1", got)
	}
	var sessions int
	s.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&sessions)
	if sessions != 1 {
		t.Errorf("%d sessions were handed out by first-run setup, want 1", sessions)
	}
}

// ---- csrf-01: /api/auth/{setup,login,logout} hang off the OUTER mux, so
// requireUser's X-Requested-With check never ran on them and readJSON ignores
// Content-Type. A cross-origin "simple request" was therefore delivered and
// executed: with the old loopback exemption a hostile page open in a browser
// on the server could claim the first administrator account outright. ----

func TestAuthEndpointsRejectCrossSiteRequests(t *testing.T) {
	s, ts := newServerOnly(t, Config{})
	code := s.SetupCode()

	// A CORS "simple request": no custom header, a safelisted Content-Type.
	simple := func(path, body string, hdrs map[string]string) (int, string) {
		t.Helper()
		req, err := http.NewRequest("POST", ts.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "text/plain;charset=UTF-8")
		for k, v := range hdrs {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	body := fmt.Sprintf(`{"username":"evil","password":"password123","code":%q}`, code)
	for _, tc := range []struct {
		name  string
		hdrs  map[string]string
		wants []int
	}{
		{"no X-Requested-With", nil, []int{http.StatusForbidden}},
		{"hostile origin", map[string]string{"Origin": "https://attacker.example"}, []int{http.StatusForbidden}},
		{"header set, wrong content type", map[string]string{"X-Requested-With": "fetch"}, []int{http.StatusUnsupportedMediaType}},
	} {
		st, out := simple("/api/auth/setup", body, tc.hdrs)
		if st != tc.wants[0] {
			t.Errorf("setup with %s: got %d %s, want %d", tc.name, st, out, tc.wants[0])
		}
		st, out = simple("/api/auth/login", `{"username":"admin","password":"password123"}`, tc.hdrs)
		if st != tc.wants[0] {
			t.Errorf("login with %s: got %d %s, want %d", tc.name, st, out, tc.wants[0])
		}
	}
	if n := s.db.UserCount(); n != 0 {
		t.Fatalf("a cross-site request created %d administrators", n)
	}
	// The console's own fetch still works: same origin, header, JSON body.
	b := newBrowser(t, ts)
	b.mustJSON("POST", "/api/auth/setup", map[string]string{"username": "admin", "password": "password123", "code": code}, nil)
	if s.db.UserCount() != 1 {
		t.Fatal("the legitimate setup request was refused too")
	}
	// ... and so does signing out, which is also on the outer mux.
	if st, out := b.do("POST", "/api/auth/logout", nil); st != http.StatusOK {
		t.Errorf("logout from the console: %d %s", st, out)
	}
}

// ---- sec-08: a re-enrolment that adopts an offline device's record is a
// takeover if the hostname was guessed, so it is audited apart from a fresh
// enrolment and shown on the device's own timeline. ----

func TestReEnrolmentRekeysAndIsAuditedSeparately(t *testing.T) {
	s, ts, b := newTestServerWith(t, Config{})
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab", "uses": 5}, &tok)
	hdr := http.Header{"X-Enroll-Token": []string{tok.Token}}

	first := dialAgentAs(t, ts, hdr, "h1", "linux")
	if first.id == "" || first.key == "" {
		t.Fatal("enrolment returned no identity")
	}
	waitFor(t, "first agent online", func() bool { return s.hub.IsOnline(first.id) })
	first.ws.Close()
	// The re-key only adopts a record marked offline, which happens after the
	// read loop unwinds, so wait for the column and not just the hub.
	waitFor(t, "first agent marked offline in the database", func() bool {
		var online int
		s.db.QueryRow(`SELECT online FROM agents WHERE id = ?`, first.id).Scan(&online)
		return online == 0
	})

	second := dialAgentAs(t, ts, hdr, "h1", "linux")
	if second.id != first.id {
		t.Fatalf("re-enrolment created a second record: %s then %s", first.id, second.id)
	}
	if second.key == first.key {
		t.Error("re-enrolment must issue a new device key")
	}
	// The old key stops working the moment the record is re-keyed.
	if _, ok := s.db.agentByKey(first.key); ok {
		t.Error("the superseded device key still resolves to an agent")
	}

	var rekeys, enrols int
	s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action = 'agent.rekeyed' AND target = ?`, first.id).Scan(&rekeys)
	s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action = 'agent.enrolled' AND target = ?`, first.id).Scan(&enrols)
	if rekeys != 1 {
		t.Errorf("expected exactly one agent.rekeyed audit entry, got %d", rekeys)
	}
	if enrols != 1 {
		t.Errorf("expected the original agent.enrolled entry to stand alone, got %d", enrols)
	}
	var kind, msg string
	if err := s.db.QueryRow(`SELECT kind, message FROM agent_events WHERE agent_id = ? AND kind = 'enrol'`, first.id).Scan(&kind, &msg); err != nil {
		t.Fatalf("no enrol row on the device timeline: %v", err)
	}
	if !strings.Contains(msg, "re-keyed") {
		t.Errorf("device timeline message does not describe the re-key: %q", msg)
	}
}

// ---- sec-07: no Content-Security-Policy. ----

func TestSecurityHeaders(t *testing.T) {
	_, ts, _ := newTestServerWith(t, Config{})
	_, _, hdr := get(t, ts.URL+"/api/auth/state")
	csp := hdr.Get("Content-Security-Policy")
	for _, want := range []string{
		"default-src 'self'",
		"script-src 'self'",
		"object-src 'none'",
		"base-uri 'none'",
		"frame-ancestors 'none'",
		"form-action 'self'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP is missing %q: %q", want, csp)
		}
	}
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("CSP lets scripts run inline: %q", csp)
	}
	if hdr.Get("X-Content-Type-Options") != "nosniff" || hdr.Get("X-Frame-Options") != "DENY" {
		t.Errorf("the older hardening headers went missing: %v", hdr)
	}
}

// ---- sec-03 (second pass): the transaction was right, but "uses_left can
// never go negative" was a claim about new writes only. A row an older server
// had already driven to -10 still read as unlimited, and the create endpoint
// stored whatever `uses` the caller sent, so {"uses": -7} minted a token that
// never ran out by count. ----

func TestDamagedEnrolTokenIsSpentNotUnlimited(t *testing.T) {
	s, ts, b := newTestServerWith(t, Config{})
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab", "uses": 1}, &tok)

	// exactly the state the pre-fix enrolment race left behind
	if _, err := s.db.Exec(`UPDATE enroll_tokens SET uses_left = -10 WHERE token = ?`, tok.Token); err != nil {
		t.Fatal(err)
	}
	if err := s.db.checkEnrollToken(tok.Token); err == nil {
		t.Error("a token at uses_left = -10 still passed the pre-check")
	}
	ws, resp, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/agent", http.Header{"X-Enroll-Token": []string{tok.Token}})
	if err == nil {
		ws.Close()
		t.Fatal("a damaged token enrolled a device")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a damaged token, got %v", resp)
	}
	var devices int
	s.db.QueryRow(`SELECT COUNT(*) FROM agents`).Scan(&devices)
	if devices != 0 {
		t.Errorf("%d devices enrolled on a damaged token", devices)
	}

	// -1 is the operator's "unlimited"; everything else negative is normalised
	// to it rather than stored verbatim.
	var neg struct {
		Token string
		ID    int64
	}
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "sneaky", "uses": -7}, &neg)
	var left int
	if err := s.db.QueryRow(`SELECT uses_left FROM enroll_tokens WHERE token = ?`, neg.Token).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != -1 {
		t.Errorf(`POST /api/enroll {"uses": -7} stored uses_left = %d, want -1`, left)
	}
}

// The rows a pre-fix server already damaged are repaired on upgrade, not left
// for the next reader to interpret.
func TestMigrationClampsNegativeUsesLeft(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rmm.db")
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	// rewind to the schema version that predates the repair and plant the damage
	if _, err := db.Exec(`PRAGMA user_version = 1`); err != nil {
		t.Fatal(err)
	}
	for _, uses := range []int{-10, -1, 0, 3} {
		if _, err := db.Exec(`INSERT INTO enroll_tokens(token, name, uses_left, expires_at, created_by, created_at) VALUES(?,?,?,?,?,?)`,
			fmt.Sprintf("tok%d", uses), "t", uses, now()+3600, "test", now()); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	db2, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	want := map[string]int{"tok-10": 0, "tok-1": -1, "tok0": 0, "tok3": 3}
	for tok, exp := range want {
		var got int
		if err := db2.QueryRow(`SELECT uses_left FROM enroll_tokens WHERE token = ?`, tok).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != exp {
			t.Errorf("token %s: uses_left = %d after migration, want %d", tok, got, exp)
		}
	}
}

// ---- sec-08 (second pass): the re-key branch only adopts an OFFLINE record,
// so a device claiming the hostname of one that is currently ONLINE got a
// brand-new record (hostname is not unique) and was audited as an ordinary
// agent.enrolled. Two "workstation-7" rows is the more confusing outcome, and
// the operator was told to watch for agent.rekeyed. ----

func TestEnrolmentUnderALiveHostnameIsAuditedSeparately(t *testing.T) {
	s, ts, b := newTestServerWith(t, Config{})
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab", "uses": 5}, &tok)
	hdr := http.Header{"X-Enroll-Token": []string{tok.Token}}

	first := dialAgentAs(t, ts, hdr, "workstation-7", "windows")
	waitFor(t, "first agent online", func() bool { return s.hub.IsOnline(first.id) })

	second := dialAgentAs(t, ts, hdr, "workstation-7", "windows")
	if second.id == first.id {
		t.Fatal("an ONLINE record must not be re-keyed out from under the device using it")
	}
	var dupes, rekeys, enrols int
	s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action = 'agent.duplicate_hostname' AND target = ?`, second.id).Scan(&dupes)
	s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action = 'agent.rekeyed'`).Scan(&rekeys)
	s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action = 'agent.enrolled'`).Scan(&enrols)
	if dupes != 1 {
		t.Errorf("expected one agent.duplicate_hostname entry for the second device, got %d", dupes)
	}
	if rekeys != 0 {
		t.Errorf("nothing was re-keyed, but %d agent.rekeyed entries were written", rekeys)
	}
	if enrols != 1 {
		t.Errorf("the duplicate should not be filed as an ordinary enrolment: %d agent.enrolled entries", enrols)
	}
	var msg string
	if err := s.db.QueryRow(`SELECT message FROM agent_events WHERE agent_id = ? AND kind = 'enrol'`, second.id).Scan(&msg); err != nil {
		t.Fatalf("no enrol row on the duplicate's timeline: %v", err)
	}
	if !strings.Contains(msg, "already using") {
		t.Errorf("device timeline message does not describe the collision: %q", msg)
	}
}

// ---- viewer-01: the sec-02 fix closed the terminal, the desktop and file
// downloads for viewers, but GET /api/enroll was never gated - and its body
// carries the token VALUES, which are all anyone needs to add a device of
// their own to the fleet. ----

func TestViewerCannotReadEnrolmentTokens(t *testing.T) {
	_, ts, admin := newTestServerWith(t, Config{})
	var tok struct{ Token string }
	admin.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab", "uses": 5}, &tok)
	admin.mustJSON("POST", "/api/users", map[string]string{"username": "ro", "password": "password123", "role": "viewer"}, nil)
	ro := newBrowser(t, ts)
	ro.mustJSON("POST", "/api/auth/login", map[string]string{"username": "ro", "password": "password123"}, nil)

	st, body := ro.do("GET", "/api/enroll", nil)
	if st != http.StatusForbidden {
		t.Errorf("viewer GET /api/enroll should be 403, got %d", st)
	}
	if strings.Contains(string(body), tok.Token) {
		t.Errorf("the enrolment token leaked to a read-only account: %s", body)
	}
	// A writer still gets it.
	var list struct{ Tokens []struct{ Token string } }
	admin.mustJSON("GET", "/api/enroll", nil, &list)
	if len(list.Tokens) != 1 || list.Tokens[0].Token != tok.Token {
		t.Errorf("an admin should still see the token list, got %+v", list)
	}
}

// ---- inst-02: the install scripts turned certificate validation off and
// fetched the agent from an unauthenticated endpoint with nothing to check it
// against, so anything on-path during enrolment could hand the machine a
// binary of its choosing and get root/SYSTEM. ----

func TestInstallScriptVerifiesTheAgentBinary(t *testing.T) {
	dir := t.TempDir()
	agents := filepath.Join(dir, "agents")
	if err := os.MkdirAll(agents, 0o755); err != nil {
		t.Fatal(err)
	}
	payload := []byte("not really an agent, but it hashes the same way")
	sum := sha256.Sum256(payload)
	want := hex.EncodeToString(sum[:])
	for _, name := range []string{"rmm-agent-windows-amd64.exe", "rmm-agent-linux-amd64", "rmm-agent-linux-arm64"} {
		if err := os.WriteFile(filepath.Join(agents, name), payload, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	_, ts, b := newTestServerWith(t, Config{DataDir: dir})
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab", "uses": 9}, &tok)

	_, ps, _ := get(t, ts.URL+"/install/"+tok.Token+"?os=windows")
	if !strings.Contains(ps, "$sum = '"+want+"'") {
		t.Errorf("the Windows script does not carry the agent's SHA-256:\n%s", firstLines(ps, 10))
	}
	if !strings.Contains(ps, "refusing to install") {
		t.Error("the Windows script downloads the agent without checking the hash it carries")
	}
	if strings.Contains(ps, "ServerCertificateValidationCallback = { $true }") {
		t.Error("the Windows script still accepts any certificate for the download")
	}
	// inst-03: WaitForStatus throws TimeoutException and $ErrorActionPreference
	// is 'Stop', so an unguarded call aborts before the process wait and the
	// Move-Item retries that exist to handle exactly that case.
	if !regexp.MustCompile(`try \{[^}]*WaitForStatus[^}]*\}\s*\n?\s*catch`).MatchString(ps) {
		t.Errorf("WaitForStatus is not inside a try/catch:\n%s", ps)
	}

	_, sh, _ := get(t, ts.URL+"/install/"+tok.Token+"?os=linux")
	for _, arch := range []string{"amd64", "arm64"} {
		if !strings.Contains(sh, "    "+arch+") SUM='"+want+"' ;;") {
			t.Errorf("the Linux script has no SHA-256 for %s:\n%s", arch, sh)
		}
	}
	if strings.Contains(sh, "arm) SUM=") {
		t.Error("the Linux script claims a hash for an architecture the server does not have")
	}
	if !strings.Contains(sh, "refusing to install") {
		t.Error("the Linux script installs whatever it downloaded without checking the hash")
	}
	if strings.Contains(sh, "curl -fsSk -o") {
		t.Error("the Linux script still downloads with validation off and no pin")
	}

	// A binary the server does not have gets no hash, and the script refuses
	// rather than installing something it cannot check.
	if !strings.Contains(sh, "to verify the download against") {
		t.Error("the Linux script does not refuse an architecture it has no hash for")
	}
	_, ps386, _ := get(t, ts.URL+"/install/"+tok.Token+"?os=windows&arch=386")
	if !strings.Contains(ps386, "$sum = ''") {
		t.Error("the Windows script invented a hash for a binary the server does not have")
	}
}

// ---- rd-03 (second pass): only the bridged phase was fixed, and it mapped
// every read failure onto 1000. So a crashed helper, a killed agent and a
// clean end all reported "normal closure", which the viewer cannot tell apart
// either - and web/src/pages/device/Desktop.tsx suppresses its diagnostic text
// for code 1000, so an abrupt death got quieter, not clearer. The four early
// returns before the bridge (no graphical session, helper never connected,
// request cancelled) still dropped the socket with no close frame at all. ----

// wsCookies copies b's session cookie into a WebSocket dial header.
func wsCookies(t *testing.T, ts *httptest.Server, b *browser) http.Header {
	t.Helper()
	hdr := http.Header{}
	u, _ := http.NewRequest("GET", ts.URL, nil)
	for _, c := range b.c.Jar.Cookies(u.URL) {
		hdr.Add("Cookie", c.Name+"="+c.Value)
	}
	hdr.Set("Origin", ts.URL)
	return hdr
}

// desktopAgent is a fake agent whose desktop.start either connects a helper
// socket (handed back on the channel) or fails the way a machine with no
// graphical session does.
func desktopAgent(t *testing.T, ts *httptest.Server, token, hostname string, startErr string) (string, chan *websocket.Conn) {
	t.Helper()
	helpers := make(chan *websocket.Conn, 1)
	ws, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/agent", http.Header{"X-Enroll-Token": []string{token}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.Close() })
	ws.WriteJSON(protocol.Envelope{T: protocol.TypeHello, D: protocol.Must(protocol.Hello{Hostname: hostname, OS: "linux"})})
	var welcome protocol.Envelope
	if err := ws.ReadJSON(&welcome); err != nil {
		t.Fatal(err)
	}
	var w struct {
		AgentID string `json:"agent_id"`
	}
	json.Unmarshal(welcome.D, &w)
	go func() {
		for {
			var env protocol.Envelope
			if err := ws.ReadJSON(&env); err != nil {
				return
			}
			switch env.T {
			case protocol.ReqPing:
				ws.WriteJSON(protocol.Envelope{T: protocol.TypePong, ID: env.ID})
			case protocol.ReqDesktopStart:
				if startErr != "" {
					ws.WriteJSON(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, Err: startErr})
					continue
				}
				var ds protocol.DesktopStart
				json.Unmarshal(env.D, &ds)
				h, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/desktop-agent?token="+ds.Token, nil)
				if err != nil {
					return
				}
				helpers <- h
				ws.WriteJSON(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, D: protocol.Must(protocol.DesktopStartResult{Started: true})})
			}
		}
	}()
	return w.AgentID, helpers
}

// readUntilClose drains text frames and returns the close error.
func readUntilClose(t *testing.T, ws *websocket.Conn) *websocket.CloseError {
	t.Helper()
	for {
		ws.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, _, err := ws.ReadMessage()
		if err == nil {
			continue
		}
		var ce *websocket.CloseError
		if !errors.As(err, &ce) {
			t.Fatalf("expected a websocket close, got %T %v", err, err)
		}
		return ce
	}
}

func TestDesktopStartFailureClosesTheViewerWithAReason(t *testing.T) {
	s, ts, b := newTestServerWith(t, Config{})
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab", "uses": 5}, &tok)
	id, _ := desktopAgent(t, ts, tok.Token, "nodisplay", "cannot find the graphical session")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(id) })

	viewer, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/desktop/"+id, wsCookies(t, ts, b))
	if err != nil {
		t.Fatalf("viewer dial: %v", err)
	}
	defer viewer.Close()

	ce := readUntilClose(t, viewer)
	if ce.Code == websocket.CloseAbnormalClosure {
		t.Fatal("a failed desktop start still drops the socket with no close frame (1006)")
	}
	if ce.Code == websocket.CloseNormalClosure {
		t.Fatalf("a failed desktop start reported itself as a normal close: %v", ce)
	}
	if ce.Code != websocket.CloseInternalServerErr || !strings.Contains(ce.Text, "graphical session") {
		t.Errorf("close frame does not say what went wrong: code=%d text=%q", ce.Code, ce.Text)
	}
}

func TestBridgeDistinguishesACrashedHelperFromACleanEnd(t *testing.T) {
	s, ts, b := newTestServerWith(t, Config{})
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab", "uses": 5}, &tok)
	id, helpers := desktopAgent(t, ts, tok.Token, "deskbox", "")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(id) })

	viewer, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/desktop/"+id, wsCookies(t, ts, b))
	if err != nil {
		t.Fatalf("viewer dial: %v", err)
	}
	defer viewer.Close()
	var helper *websocket.Conn
	select {
	case helper = <-helpers:
	case <-time.After(5 * time.Second):
		t.Fatal("helper never connected")
	}

	// The helper dies without a close frame: a crash, not the end of a session.
	helper.UnderlyingConn().Close()

	ce := readUntilClose(t, viewer)
	if ce.Code == websocket.CloseNormalClosure {
		t.Fatal("a crashed helper was reported to the viewer as a normal close (1000), which the UI then hides")
	}
	if ce.Code != websocket.CloseInternalServerErr {
		t.Errorf("crashed helper: close code = %d, want %d", ce.Code, websocket.CloseInternalServerErr)
	}
	if !strings.Contains(ce.Text, "helper") {
		t.Errorf("close reason does not name the side that went away: %q", ce.Text)
	}
}

// CHANGELOG claimed "Desktop and shell relays send a Close frame"; writeClose
// was only ever called from bridge(), so a terminal still ended at 1006.
func TestShellRelayClosesWithACode(t *testing.T) {
	s, ts, b := newTestServerWith(t, Config{})
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab", "uses": 5}, &tok)
	agent := dialAgent(t, wsURL(ts), http.Header{"X-Enroll-Token": []string{tok.Token}})
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(agent.id) })

	// A session the operator ends: a normal close, said out loud.
	term, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/shell/"+agent.id, wsCookies(t, ts, b))
	if err != nil {
		t.Fatalf("terminal dial: %v", err)
	}
	defer term.Close()
	term.WriteJSON(map[string]any{"t": "open", "shell": "sh", "cols": 80, "rows": 24})
	term.WriteJSON(map[string]any{"t": "close"})
	ce := readUntilClose(t, term)
	if ce.Code != websocket.CloseNormalClosure {
		t.Errorf("a terminal the operator closed reported code %d (%q), want 1000", ce.Code, ce.Text)
	}

	// A session that could not be opened: not a normal close.
	term2, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/shell/"+agent.id, wsCookies(t, ts, b))
	if err != nil {
		t.Fatalf("second terminal dial: %v", err)
	}
	defer term2.Close()
	agent.ws.Close() // the device goes away between the upgrade and the open
	waitFor(t, "agent offline", func() bool { return !s.hub.IsOnline(agent.id) })
	term2.WriteJSON(map[string]any{"t": "open", "shell": "sh", "cols": 80, "rows": 24})
	ce = readUntilClose(t, term2)
	if ce.Code == websocket.CloseAbnormalClosure {
		t.Fatal("a terminal that could not open still drops the socket with no close frame (1006)")
	}
	if ce.Code != websocket.CloseInternalServerErr {
		t.Errorf("a terminal that could not open reported code %d (%q), want %d", ce.Code, ce.Text, websocket.CloseInternalServerErr)
	}
}
