package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// This file is the shared QUIC test client: an agent that speaks the 3E wire
// format by hand (uint32 big-endian length + JSON Envelope on every stream),
// independent of the production framing helpers so a mistake there cannot hide
// itself. Its API, for anyone writing another QUIC test against the server:
//
//	q := enableQUIC(t, s)                        // listener on 127.0.0.1:0, test certificate
//	c := dialQUIC(t, q.addr(), s.Fingerprint())  // "" skips verification (the test certificate)
//	wl := c.handshake(protocol.Auth{Token: tok}, testHello("box"))  // auth, hello, welcome
//	c.sendControl(env) / c.readControl(timeout)  // the control stream
//	r, err := c.acceptRequest(timeout)           // a server-opened request stream: r.Env is the request
//	r.stream(v) / r.reply(v) / r.replyErr(msg)   // answer on that stream (reply is final)
//	c.serve(func(r *quicReq) { ... })            // accept requests in a goroutine, one handler goroutine each
//	c.close()
//
// newQUICServer(t) is newTestServer plus enableQUIC; consoleToken mints an
// enrollment token through the admin browser (fixes_test.go has enrollToken for a
// token inserted straight into the database).

// addr is the UDP address the listener is bound to.
func (q *quicServer) addr() string { return q.ln.Addr().String() }

// enableQUIC gives a test server (which runs plain HTTP, so it has no
// certificate of its own) a certificate and a QUIC listener on a loopback
// port. The listener is closed before the server's own cleanup runs.
func enableQUIC(t *testing.T, s *Server) *quicServer {
	t.Helper()
	cert, fp, err := loadOrCreateCert(s.cfg, []string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	s.certMu.Lock()
	s.cert, s.fingerprint = &cert, fp
	s.certMu.Unlock()
	q, err := s.listenQUIC("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(q.close)
	return q
}

// newQUICServer is newTestServer with the QUIC listener enabled.
func newQUICServer(t *testing.T) (*Server, *httptest.Server, *browser, *quicServer) {
	t.Helper()
	s, ts, b := newTestServer(t)
	return s, ts, b, enableQUIC(t, s)
}

// consoleToken mints a one-use enrollment token through the console API.
func consoleToken(t *testing.T, b *browser, name string) string {
	t.Helper()
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": name, "uses": 1}, &tok)
	return tok.Token
}

func testHello(name string) protocol.Hello {
	return protocol.Hello{Hostname: name, OS: "linux", Platform: "Test", Arch: "amd64", Version: "test", ProtocolVersion: protocol.Version}
}

// quicWelcome is what the welcome frame carried.
type quicWelcome struct {
	AgentID string               `json:"agent_id"`
	Key     string               `json:"agent_key"`
	Config  protocol.AgentConfig `json:"config"`
}

type quicClient struct {
	t    *testing.T
	conn *quic.Conn
	ctrl *quic.Stream
}

// pinTLS verifies the server certificate against a fingerprint the way the
// agent does, or accepts any certificate when fingerprint is empty.
func pinTLS(fingerprint string) *tls.Config {
	conf := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{protocol.QUICALPN}, InsecureSkipVerify: true}
	if fingerprint != "" {
		conf.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no server certificate")
			}
			sum := sha256.Sum256(raw[0])
			if hex.EncodeToString(sum[:]) != fingerprint {
				return fmt.Errorf("certificate fingerprint mismatch: %x", sum)
			}
			return nil
		}
	}
	return conf
}

// dialQUIC completes the QUIC handshake and opens the control stream. Nothing
// reaches the server until the first frame is written (QUIC streams are lazy).
func dialQUIC(t *testing.T, addr, fingerprint string) *quicClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, pinTLS(fingerprint), &quic.Config{MaxIdleTimeout: 30 * time.Second, MaxIncomingStreams: 64})
	if err != nil {
		t.Fatalf("QUIC dial %s: %v", addr, err)
	}
	ctrl, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open the control stream: %v", err)
	}
	c := &quicClient{t: t, conn: conn, ctrl: ctrl}
	t.Cleanup(c.close)
	return c
}

func (c *quicClient) close() { c.conn.CloseWithError(0, "test over") }

// writeTestFrame is the framing, written out by hand.
func writeTestFrame(w io.Writer, env protocol.Envelope) error {
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	buf := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body)))
	_, err = w.Write(append(buf, body...))
	return err
}

func readTestFrame(r io.Reader) (protocol.Envelope, error) {
	var env protocol.Envelope
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return env, err
	}
	body := make([]byte, binary.BigEndian.Uint32(hdr[:]))
	if _, err := io.ReadFull(r, body); err != nil {
		return env, err
	}
	return env, json.Unmarshal(body, &env)
}

func (c *quicClient) sendControl(env protocol.Envelope) {
	c.t.Helper()
	c.ctrl.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := writeTestFrame(c.ctrl, env); err != nil {
		c.t.Fatalf("write on the control stream: %v", err)
	}
}

// readControl reads the next control frame, returning the error (timeout,
// stream or connection closed) rather than failing, so a test can expect it.
func (c *quicClient) readControl(timeout time.Duration) (protocol.Envelope, error) {
	c.ctrl.SetReadDeadline(time.Now().Add(timeout))
	return readTestFrame(c.ctrl)
}

// sendAuthHello writes the first two frames without waiting for the answer.
func (c *quicClient) sendAuthHello(auth protocol.Auth, hello protocol.Hello) {
	c.t.Helper()
	c.sendControl(protocol.Envelope{T: protocol.TypeAuth, D: protocol.Must(auth)})
	c.sendControl(protocol.Envelope{T: protocol.TypeHello, D: protocol.Must(hello)})
}

// handshake is auth, hello, welcome. It fails the test if the server answers
// anything but a welcome.
func (c *quicClient) handshake(auth protocol.Auth, hello protocol.Hello) quicWelcome {
	c.t.Helper()
	c.sendAuthHello(auth, hello)
	env, err := c.readControl(5 * time.Second)
	if err != nil {
		c.t.Fatalf("waiting for welcome: %v", err)
	}
	if env.T != "welcome" {
		c.t.Fatalf("expected welcome, got %s %q", env.T, env.Err)
	}
	var wl quicWelcome
	if err := json.Unmarshal(env.D, &wl); err != nil {
		c.t.Fatal(err)
	}
	return wl
}

// quicReq is one request stream the server opened.
type quicReq struct {
	t   *testing.T
	st  *quic.Stream
	Env protocol.Envelope
}

// acceptRequest waits for the next stream the server opens and reads its
// request frame.
func (c *quicClient) acceptRequest(timeout time.Duration) (*quicReq, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	st, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	st.SetReadDeadline(time.Now().Add(timeout))
	env, err := readTestFrame(st)
	if err != nil {
		return nil, err
	}
	st.SetReadDeadline(time.Time{})
	return &quicReq{t: c.t, st: st, Env: env}, nil
}

// serve answers every incoming request stream with fn, each on its own
// goroutine, until the connection ends.
func (c *quicClient) serve(fn func(*quicReq)) {
	go func() {
		for {
			r, err := c.acceptRequest(time.Hour)
			if err != nil {
				return
			}
			go fn(r)
		}
	}()
}

func (r *quicReq) send(env protocol.Envelope) {
	r.t.Helper()
	r.st.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := writeTestFrame(r.st, env); err != nil {
		r.t.Errorf("write on request stream %d: %v", r.st.StreamID(), err)
	}
}

// stream sends a TypeStream chunk for this request.
func (r *quicReq) stream(v any) {
	r.send(protocol.Envelope{T: protocol.TypeStream, ID: r.Env.ID, D: protocol.Must(v)})
}

// reply sends the final reply and closes the agent's side of the stream.
func (r *quicReq) reply(v any) {
	env := protocol.Envelope{T: protocol.TypeReply, ID: r.Env.ID}
	if v != nil {
		env.D = protocol.Must(v)
	}
	r.send(env)
	r.st.Close()
}

// replyEnv is reply with a caller-built envelope (Log, Err).
func (r *quicReq) replyEnv(env protocol.Envelope) {
	env.T, env.ID = protocol.TypeReply, r.Env.ID
	r.send(env)
	r.st.Close()
}

func (r *quicReq) replyErr(msg string) { r.replyEnv(protocol.Envelope{Err: msg}) }

// quicAddrPort is a helper for tests that want the numeric port.
func quicAddrPort(q *quicServer) int {
	return q.ln.Addr().(*net.UDPAddr).Port
}
