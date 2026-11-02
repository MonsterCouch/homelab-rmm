package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/server"
)

// The fixture here is the real server, started through its package API with a
// TLS listener and (optionally) the QUIC listener, and the real agent session
// against it. The server's own tests cover the wire protocol with a hand-built
// client; these cover the half that lives in this package.

type quicFixture struct {
	t      *testing.T
	srv    *server.Server
	url    string
	fp     string
	udp    int
	client *http.Client
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port
}

// udpSink is a UDP socket that counts the datagrams sent to it: a stand-in for
// a QUIC port that never answers, and proof of whether the agent dialled it.
type udpSink struct {
	port int
	n    atomic.Int64
}

func newUDPSink(t *testing.T) *udpSink {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &udpSink{port: l.LocalAddr().(*net.UDPAddr).Port}
	t.Cleanup(func() { l.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := l.ReadFrom(buf); err != nil {
				return
			}
			s.n.Add(1)
		}
	}()
	return s
}

// startQUICFixture runs the server with HTTPS and, when withQUIC is set, QUIC
// on a free UDP port, and signs in an administrator.
func startQUICFixture(t *testing.T, withQUIC bool) *quicFixture {
	t.Helper()
	f := &quicFixture{t: t, udp: freeUDPPort(t)}
	tcp := freeTCPPort(t)
	cfg := server.Config{DataDir: t.TempDir(), Listen: "127.0.0.1:" + strconv.Itoa(tcp), SkipSeed: true}
	if withQUIC {
		cfg.QUIC, cfg.QUICPort = true, f.udp
	}
	s, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.srv = s
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Log("the server did not stop within 20 s")
		}
	})
	f.url = "https://127.0.0.1:" + strconv.Itoa(tcp)
	jar, _ := cookiejar.New(nil)
	f.client = &http.Client{
		Jar:       jar,
		Timeout:   20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	waitUntil(t, "the server to listen", 15*time.Second, func() bool {
		f.fp = s.Fingerprint()
		if f.fp == "" {
			return false
		}
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(tcp), time.Second)
		if err != nil {
			return false
		}
		c.Close()
		return true
	})
	if st, raw := f.do("POST", "/api/auth/setup", map[string]string{"username": "admin", "password": "password123"}, nil); st != 200 && st != 201 {
		t.Fatalf("first-run setup = %d %s", st, raw)
	}
	return f
}

func (f *quicFixture) do(method, path string, body any, out any) (int, []byte) {
	f.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, f.url+path, rd)
	if err != nil {
		f.t.Fatal(err)
	}
	req.Header.Set("X-Requested-With", "fetch")
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		f.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(buf.Bytes(), out); err != nil {
			f.t.Fatalf("%s %s: %v in %s", method, path, err, buf.String())
		}
	}
	return resp.StatusCode, buf.Bytes()
}

func (f *quicFixture) token() string {
	f.t.Helper()
	var tok struct{ Token string }
	if st, raw := f.do("POST", "/api/enroll", map[string]any{"name": "quic", "uses": 5}, &tok); st != 200 && st != 201 {
		f.t.Fatalf("enroll = %d %s", st, raw)
	}
	return tok.Token
}

type agentRow struct {
	ID        string `json:"id"`
	Online    bool   `json:"online"`
	Transport string `json:"transport"`
}

// online returns the first online device and how it is connected.
func (f *quicFixture) online() (agentRow, bool) {
	var rows []agentRow
	f.do("GET", "/api/agents", nil, &rows)
	for _, r := range rows {
		if r.Online {
			return r, true
		}
	}
	return agentRow{}, false
}

func (f *quicFixture) waitOnline(want string) agentRow {
	f.t.Helper()
	var row agentRow
	waitUntil(f.t, "an agent online over "+want, 40*time.Second, func() bool {
		r, ok := f.online()
		if ok && (want == "" || r.Transport == want) {
			row = r
			return true
		}
		return false
	})
	return row
}

func waitUntil(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", d, what)
}

// runAgent starts the real agent loop and stops it with the test.
func runAgent(t *testing.T, cfg *Config) (a *Agent, stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	a = New(cfg)
	go func() { a.Run(ctx); close(done) }()
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Log("the agent did not stop within 15 s")
		}
	}
	t.Cleanup(stop)
	return a, stop
}

func (f *quicFixture) config(tok string) *Config {
	return &Config{ServerURL: f.url, EnrollToken: tok, Fingerprint: f.fp}
}

func TestSessionRunsOverQUIC(t *testing.T) {
	t.Setenv(EnvConfigDir, t.TempDir())
	t.Setenv("RMM_TRANSPORT", "")
	f := startQUICFixture(t, true)
	cfg := f.config(f.token())
	cfg.QUICPort = f.udp
	runAgent(t, cfg)

	row := f.waitOnline("quic")
	if cfg.Key == "" || cfg.AgentID != row.ID {
		t.Fatalf("enrolling over QUIC saved key %q id %q, the server has %q", cfg.Key, cfg.AgentID, row.ID)
	}
	// A request the server makes of the device travels on its own stream and
	// is answered on it: the console's process list is the simplest one.
	var procs json.RawMessage
	if st, raw := f.do("GET", "/api/agents/"+row.ID+"/processes", nil, &procs); st != 200 || len(procs) < 3 {
		t.Fatalf("processes over QUIC = %d %s", st, raw)
	}
}

func TestQUICPortIsLearnedOverWebSocketThenUsed(t *testing.T) {
	t.Setenv(EnvConfigDir, t.TempDir())
	t.Setenv("RMM_TRANSPORT", "")
	f := startQUICFixture(t, true)
	cfg := f.config(f.token())
	_, stop := runAgent(t, cfg) // no port known yet: the first session has to be WebSocket

	f.waitOnline("websocket")
	a2 := &Agent{cfg: cfg}
	waitUntil(t, "the agent to remember the advertised port", 10*time.Second, func() bool {
		p, _ := a2.quicState()
		return p == f.udp
	})
	stop()
	waitUntil(t, "the server to see the device go", 15*time.Second, func() bool { _, ok := f.online(); return !ok })

	runAgent(t, cfg)
	f.waitOnline("quic")
}

func TestQUICFallsBackToWebSocketWhenUDPIsClosed(t *testing.T) {
	t.Setenv(EnvConfigDir, t.TempDir())
	t.Setenv("RMM_TRANSPORT", "")
	f := startQUICFixture(t, true) // offers QUIC, so its welcome keeps the port and the failure memory alive
	cfg := f.config(f.token())
	cfg.QUICPort = freeUDPPort(t) // a closed port: the server's real listener is elsewhere
	a, _ := runAgent(t, cfg)

	f.waitOnline("websocket")
	if _, failedAt := a.quicState(); failedAt == 0 || time.Since(time.Unix(failedAt, 0)) > time.Minute {
		t.Fatalf("QUICFailedAt = %d, want a time just now", failedAt)
	}
}

func TestQUICFailureIsRememberedForTenMinutes(t *testing.T) {
	t.Setenv("RMM_TRANSPORT", "")
	cases := []struct {
		name      string
		age       time.Duration
		wantDials bool
	}{
		{"a minute ago the agent stays on WebSocket without touching UDP", time.Minute, false},
		{"eleven minutes ago it tries QUIC again and falls back again", 11 * time.Minute, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvConfigDir, t.TempDir())
			f := startQUICFixture(t, true)
			sink := newUDPSink(t)
			cfg := f.config(f.token())
			cfg.QUICPort = sink.port
			old := time.Now().Add(-tc.age).Unix()
			cfg.QUICFailedAt = old
			a, _ := runAgent(t, cfg)

			f.waitOnline("websocket")
			dialled := sink.n.Load() > 0
			if dialled != tc.wantDials {
				t.Fatalf("datagrams to the QUIC port: %d, want dials = %v", sink.n.Load(), tc.wantDials)
			}
			_, failedAt := a.quicState()
			if tc.wantDials && failedAt <= old {
				t.Fatalf("QUICFailedAt = %d, want it refreshed after %d", failedAt, old)
			}
			if !tc.wantDials && failedAt != old {
				t.Fatalf("QUICFailedAt = %d, want it untouched at %d", failedAt, old)
			}
		})
	}
}

func TestChooseQUIC(t *testing.T) {
	now := time.Now()
	ago := func(d time.Duration) int64 { return now.Add(-d).Unix() }
	cases := []struct {
		mode     string
		port     int
		failedAt int64
		want     bool
	}{
		{"websocket", 8443, 0, false},
		{"quic", 0, 0, true},
		{"quic", 8443, ago(time.Minute), true},
		{"auto", 0, 0, false},
		{"auto", 8443, 0, true},
		{"auto", 8443, ago(9 * time.Minute), false},
		{"auto", 8443, ago(11 * time.Minute), true},
	}
	for _, c := range cases {
		if got := chooseQUIC(c.mode, c.port, c.failedAt, now); got != c.want {
			t.Errorf("chooseQUIC(%q, %d, %d) = %v, want %v", c.mode, c.port, c.failedAt, got, c.want)
		}
	}
}

func TestWebSocketTransportNeverDialsUDP(t *testing.T) {
	t.Setenv(EnvConfigDir, t.TempDir())
	t.Setenv("RMM_TRANSPORT", "websocket")
	f := startQUICFixture(t, true) // the server offers QUIC; the agent must not use it
	sink := newUDPSink(t)
	cfg := f.config(f.token())
	cfg.QUICPort = sink.port
	cfg.Transport = "quic" // the environment variable wins over the file
	runAgent(t, cfg)

	f.waitOnline("websocket")
	time.Sleep(300 * time.Millisecond)
	if n := sink.n.Load(); n != 0 {
		t.Fatalf("RMM_TRANSPORT=websocket sent %d datagrams to the QUIC port", n)
	}
	if _, failedAt := (&Agent{cfg: cfg}).quicState(); failedAt != 0 {
		t.Fatalf("QUICFailedAt = %d, want 0: WebSocket was the choice, not a fallback", failedAt)
	}
}

func TestQUICKeyRefusalReEnrollsAndIsNotATransportFailure(t *testing.T) {
	t.Setenv(EnvConfigDir, t.TempDir())
	t.Setenv("RMM_TRANSPORT", "")
	f := startQUICFixture(t, true)
	cfg := f.config(f.token())
	cfg.AgentID, cfg.Key = "gone", "not-a-real-key"
	cfg.QUICPort = f.udp
	a, _ := runAgent(t, cfg)

	f.waitOnline("quic")
	if cfg.Key == "not-a-real-key" || cfg.Key == "" {
		t.Fatalf("the refused key was not replaced by a fresh enrollment: %q", cfg.Key)
	}
	if _, failedAt := a.quicState(); failedAt != 0 {
		t.Fatalf("QUICFailedAt = %d: a refused key is a verdict, not a QUIC failure", failedAt)
	}
}

func TestForcedQUICDoesNotFallBack(t *testing.T) {
	t.Setenv(EnvConfigDir, t.TempDir())
	t.Setenv("RMM_TRANSPORT", "quic")
	f := startQUICFixture(t, false)
	cfg := f.config(f.token())
	cfg.QUICPort = freeUDPPort(t)
	a := New(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err := a.session(ctx)
	if err == nil || !strings.Contains(err.Error(), "QUIC dial") {
		t.Fatalf("session = %v, want the QUIC dial error with no WebSocket fallback", err)
	}
	if _, ok := f.online(); ok {
		t.Fatal("the agent reached the server although RMM_TRANSPORT=quic and UDP is closed")
	}
}

func TestApplyConfigRemembersTheQUICPort(t *testing.T) {
	t.Setenv(EnvConfigDir, t.TempDir())
	a := New(&Config{ServerURL: "https://example.invalid"})
	a.applyConfig(protocol.AgentConfig{QUIC: true, QUICPort: 9443}, nil, nil)
	if p, _ := a.quicState(); p != 9443 {
		t.Fatalf("port = %d, want 9443", p)
	}
	a.applyConfigRaw(nil) // an empty welcome config does not forget it
	if p, _ := a.quicState(); p != 9443 {
		t.Fatalf("port after an empty config = %d, want 9443", p)
	}
	a.cfg.QUICFailedAt = 5
	a.applyConfig(protocol.AgentConfig{}, nil, nil) // the server stopped offering QUIC
	if p, failedAt := a.quicState(); p != 0 || failedAt != 0 {
		t.Fatalf("port, failedAt = %d, %d after QUIC was withdrawn, want 0, 0", p, failedAt)
	}
}

func TestFramesRoundTripAndSkipEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, protocol.Envelope{T: protocol.TypeReply, ID: "7", D: protocol.Must("x")}); err != nil {
		t.Fatal(err)
	}
	buf.Write([]byte{0, 0, 0, 0})                // an empty frame
	buf.Write([]byte{0, 0, 0, 3, '{', '{', '{'}) // an unparseable one
	var big [4]byte
	binary.BigEndian.PutUint32(big[:], quicMaxFrame+1)
	r := bytes.NewReader(append(buf.Bytes(), big[:]...))

	env, ok, err := readFrame(r)
	if err != nil || !ok || env.ID != "7" || env.T != protocol.TypeReply {
		t.Fatalf("first frame = %+v %v %v", env, ok, err)
	}
	for i := 0; i < 2; i++ {
		if _, ok, err := readFrame(r); ok || err != nil {
			t.Fatalf("skipped frame %d: ok=%v err=%v, want it skipped without error", i, ok, err)
		}
	}
	if _, _, err := readFrame(r); err == nil {
		t.Fatal("a frame over the size limit was accepted")
	}
}

func TestQUICAddress(t *testing.T) {
	cases := []struct {
		url  string
		port int
		want string
		bad  bool
	}{
		{"https://rmm.lan:8443", 9443, "rmm.lan:9443", false},
		{"https://rmm.lan:8443", 0, "rmm.lan:8443", false},
		{"https://rmm.lan", 0, "rmm.lan:443", false},
		{"rmm.lan:8443", 8443, "rmm.lan:8443", false},
		{"https://[::1]:8443", 8443, "[::1]:8443", false},
		{"http://rmm.lan:8080", 8080, "", true},
	}
	for _, c := range cases {
		got, err := quicAddress(c.url, c.port)
		if (err != nil) != c.bad || got != c.want {
			t.Errorf("quicAddress(%q, %d) = %q, %v; want %q (bad=%v)", c.url, c.port, got, err, c.want, c.bad)
		}
	}
}

// A claimed length with no body behind it must cost nothing: the buffer grows
// as bytes arrive, so a hostile server cannot commit gigabytes of memory by
// writing 4-byte headers on many streams.
func TestReadFrameDoesNotAllocateTheClaimedSize(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], quicMaxFrame)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < 8; i++ {
		_, _, err := readFrame(bytes.NewReader(hdr[:]))
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("readFrame on a header with no body = %v, want an unexpected EOF", err)
		}
	}
	runtime.ReadMemStats(&after)
	if got := after.TotalAlloc - before.TotalAlloc; got > 8<<20 {
		t.Fatalf("eight empty 64 MiB claims allocated %d bytes", got)
	}
}

func TestQUICAbortCodeMatchesTheServersTable(t *testing.T) {
	if quicCodeAbort != 4 {
		t.Fatalf("quicCodeAbort = %d, the server's table (docs/plans/2026-10-24-phase3e-quic.md) says 4", quicCodeAbort)
	}
}

// The request frame's deadline is an idle limit: a sender that keeps sending
// finishes however long it takes, and one that stops is cut off.
func TestIdleReaderRenewsItsDeadlineWhileBytesArrive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tlsConf, _ := testServerTLS(t)
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type accepted struct {
		s   *quic.Stream
		err error
	}
	got := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err != nil {
			got <- accepted{err: err}
			return
		}
		s, err := c.AcceptStream(ctx)
		got <- accepted{s, err}
	}()
	cc, err := quic.DialAddr(ctx, ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"idle-test"}}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.CloseWithError(0, "")
	cs, err := cc.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	// Three bytes, each after most of a 300 ms idle window, so the whole read
	// outlasts the window but no gap does.
	go func() {
		for i := 0; i < 3; i++ {
			cs.Write([]byte{'x'})
			time.Sleep(200 * time.Millisecond)
		}
	}()
	a := <-got
	if a.err != nil {
		t.Fatal(a.err)
	}
	r := &idleReader{s: a.s, wait: 300 * time.Millisecond}
	start := time.Now()
	buf := make([]byte, 3)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("a slow but steady sender was cut off: %v", err)
	}
	if time.Since(start) < 300*time.Millisecond {
		t.Fatalf("the read took %s, want it to outlast one idle window", time.Since(start))
	}
	// Now the sender stops: the next read must time out.
	if _, err := r.Read(buf); err == nil {
		t.Fatal("a stalled sender was not cut off by the idle deadline")
	}
}

// A multi-MiB request reaches the device on its own stream and is applied
// byte for byte.
func TestLargeUploadOverQUICArrivesIntact(t *testing.T) {
	t.Setenv(EnvConfigDir, t.TempDir())
	t.Setenv("RMM_TRANSPORT", "")
	f := startQUICFixture(t, true)
	cfg := f.config(f.token())
	cfg.QUICPort = f.udp
	runAgent(t, cfg)
	row := f.waitOnline("quic")

	data := bytes.Repeat([]byte("quic upload "), 700_000) // ~8 MiB
	dest := filepath.Join(t.TempDir(), "drop", "payload.bin")
	req, _ := http.NewRequest("POST", f.url+"/api/agents/"+row.ID+"/fs/upload?path="+url.QueryEscape(dest), bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Requested-With", "fetch")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	body.ReadFrom(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("upload over QUIC = %d %s", resp.StatusCode, body.String())
	}
	if got, err := os.ReadFile(dest); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("uploaded file: err %v, %d bytes, want %d", err, len(got), len(data))
	}
}

// Stopping the agent while it dials says nothing about the UDP path and must
// not put the device on a ten-minute WebSocket penalty.
func TestStoppedDialIsNotRememberedAsAQUICFailure(t *testing.T) {
	t.Setenv(EnvConfigDir, t.TempDir())
	t.Setenv("RMM_TRANSPORT", "")
	sink := newUDPSink(t) // never answers, so the dial is still in flight when we cancel
	a := New(&Config{ServerURL: "https://127.0.0.1:1", EnrollToken: "t", QUICPort: sink.port})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()
	if err := a.session(ctx); err == nil {
		t.Fatal("session returned nil for a cancelled dial")
	}
	if _, failedAt := a.quicState(); failedAt != 0 {
		t.Fatalf("QUICFailedAt = %d after a cancelled dial, want 0", failedAt)
	}
}

// testServerTLS is a throwaway server certificate for hand-built QUIC servers,
// with its SHA-256 fingerprint in the form the agent pins.
func testServerTLS(t *testing.T) (*tls.Config, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "quic-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"idle-test", protocol.QUICALPN},
	}, hex.EncodeToString(sum[:])
}

// The server consumes an enrollment token before it writes the welcome, so a
// welcome that never arrives must not send the agent to WebSocket with the same
// token: the attempt ends with a plain error and QUIC is tried again later.
func TestLostWelcomeAfterTheEnrollmentTokenDoesNotFallBack(t *testing.T) {
	t.Setenv(EnvConfigDir, t.TempDir())
	t.Setenv("RMM_TRANSPORT", "")
	tlsConf, fp := testServerTLS(t)
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		s, err := c.AcceptStream(context.Background())
		if err != nil {
			return
		}
		io.Copy(io.Discard, s) // read auth and hello, never answer
	}()
	port := ln.Addr().(*net.UDPAddr).Port
	a := New(&Config{ServerURL: "https://127.0.0.1:1", EnrollToken: "single-use", Fingerprint: fp, QUICPort: port})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = a.session(ctx)
	if err == nil || !strings.Contains(err.Error(), "enrollment token was presented") {
		t.Fatalf("session = %v, want the lost-welcome error with no WebSocket fallback", err)
	}
	if _, failedAt := a.quicState(); failedAt != 0 {
		t.Fatalf("QUICFailedAt = %d, want 0: the UDP path worked", failedAt)
	}
}
