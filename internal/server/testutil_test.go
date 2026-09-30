package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// newServerOnly starts a server and an httptest listener with NO user, so a
// test can drive first-run setup itself. cfg is filled in with the test
// defaults (temp data dir, ephemeral port, plain HTTP, no seed data) for every
// field the caller left empty.
//
// loginLimiter is a package-level variable shared by every test in this
// package, and handleSetup/handleLogin both count against it. The buckets for
// the loopback addresses are cleared here so an unrelated test's failed logins
// cannot make this fixture's setup POST a 429. Tests run sequentially unless
// they call t.Parallel, and none in this package do.
func newServerOnly(t *testing.T, cfg Config) (*Server, *httptest.Server) {
	t.Helper()
	loginLimiter.reset("127.0.0.1")
	loginLimiter.reset("::1")
	if cfg.DataDir == "" {
		cfg.DataDir = t.TempDir()
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:0"
	}
	cfg.Insecure = true
	cfg.SkipSeed = true
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s.sched.start(ctx)
	ts := httptest.NewServer(s.routes())
	t.Cleanup(func() {
		// Release everything that holds rmm.db open before t.TempDir removes
		// it: Windows refuses to delete an open file, so an open SQLite handle
		// turned every passing test in this package into a cleanup failure.
		// Same order as Server.Run's shutdown: stop new work, close the agent
		// sockets, wait for their teardown, then the database.
		cancel()
		ts.Close()
		s.jobCancel()
		s.hub.CloseAll()
		s.hub.waitClosed(3 * time.Second)
		s.waitJobs(5 * time.Second)
		s.db.Close()
	})
	return s, ts
}

// newBrowser is a fresh cookie-jar client for ts (a second signed-in operator,
// or an anonymous one).
func newBrowser(t *testing.T, ts *httptest.Server) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &browser{t: t, c: &http.Client{Jar: jar}, base: ts.URL}
}

// newTestServerWith is newTestServer with a caller-supplied Config: an admin
// exists and the returned browser is signed in as them.
func newTestServerWith(t *testing.T, cfg Config) (*Server, *httptest.Server, *browser) {
	t.Helper()
	s, ts := newServerOnly(t, cfg)
	b := newBrowser(t, ts)
	// Complete first-run setup without needing a code.
	b.mustJSON("POST", "/api/auth/setup", map[string]string{"username": "admin", "password": "password123"}, nil)
	return s, ts, b
}

// request builds a request for s.routes() with a chosen peer address. The mux
// routes on the URL, so only RemoteAddr and the headers matter.
func request(t *testing.T, method, url, remoteAddr, body string) *http.Request {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, url, rd)
	req.RemoteAddr = remoteAddr
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "fetch")
	return req
}

// rawAgent is a bare agent socket: it completes the hello handshake with a
// chosen identity and hands back what the welcome said, without the reply loop
// fakeAgent runs. Enrollment tests need control over the hostname.
type rawAgent struct {
	ws  *websocket.Conn
	id  string
	key string
}

func dialAgentAs(t *testing.T, ts *httptest.Server, hdr http.Header, hostname, osName string) *rawAgent {
	t.Helper()
	ws, resp, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/agent", hdr)
	if err != nil {
		code := 0
		if resp != nil {
			code = resp.StatusCode
		}
		t.Fatalf("dial %s: %v (status %d)", hostname, err, code)
	}
	if err := ws.WriteJSON(protocol.Envelope{T: protocol.TypeHello, D: protocol.Must(protocol.Hello{
		Hostname: hostname, OS: osName, Platform: "Test", Arch: "amd64", Version: "test", ProtocolVersion: protocol.Version,
	})}); err != nil {
		t.Fatalf("hello %s: %v", hostname, err)
	}
	var env protocol.Envelope
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := ws.ReadJSON(&env); err != nil {
		t.Fatalf("welcome %s: %v", hostname, err)
	}
	if env.T != "welcome" {
		t.Fatalf("expected welcome for %s, got %s %s", hostname, env.T, env.Err)
	}
	ws.SetReadDeadline(time.Time{})
	var wl struct {
		AgentID string `json:"agent_id"`
		Key     string `json:"agent_key"`
	}
	json.Unmarshal(env.D, &wl)
	t.Cleanup(func() { ws.Close() })
	return &rawAgent{ws: ws, id: wl.AgentID, key: wl.Key}
}
