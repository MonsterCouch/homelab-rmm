package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// The QUIC agent transport (docs/plans/2026-10-24-phase3e-quic.md).
//
// Wire format, on every stream: a uint32 big-endian length followed by that
// many bytes of the same JSON protocol.Envelope the WebSocket carries. The
// agent opens the first bidirectional stream (the control stream) and sends
// auth then hello on it; the server answers welcome, or an "error" frame and a
// close. The control stream then carries every frame that is not tied to a
// request. For each request that expects an answer the server opens a stream
// of its own, writes exactly one frame (the request) and closes its sending
// side; the agent answers on that same stream with stream frames and one final
// reply, and then closes its side.

// Application error codes carried in QUIC CONNECTION_CLOSE and stream resets.
const (
	quicCodeNormal   = quic.ApplicationErrorCode(0)
	quicCodeProtocol = quic.ApplicationErrorCode(1) // malformed or oversized frame, missing control stream
	quicCodeRefused  = quic.ApplicationErrorCode(2) // authentication refused
	quicCodeShutdown = quic.ApplicationErrorCode(3) // the server is stopping
	quicCodeAbort    = quic.StreamErrorCode(4)      // a request nobody waits for any more
)

// Ordering note: a signed frame carries a transparency log proof that only
// verifies against the heads the agent saw before it, so proofs are made and
// written in one order under the connection's write lock. Request streams are
// read in that order by the agent. A signed notice on the control stream is read
// by a separate goroutine on the agent and can therefore be verified before or
// after a signed request written next to it; the loser is refused with a log
// proof error, which fails closed and costs one retry, and the hub resets its
// high-water mark when it sees that refusal.

// quicHandshakeWait bounds each step of the pre-welcome exchange (opening the
// control stream, the auth frame, the hello frame).
const quicHandshakeWait = 15 * time.Second

// Limits on peers that have finished the QUIC handshake but not yet
// authenticated. Anyone can complete the handshake, so these bound what that is
// worth to an attacker.
// They are variables so a test can lower them.
var (
	// maxPreAuthConns caps connections between the handshake and the welcome
	// (or refusal); the excess is closed at once.
	maxPreAuthConns = 256
	// quicRetryAbove is how many new connection attempts per second, over all
	// sources, the listener answers without first making the source prove its
	// address with a Retry round trip. A fleet reconnecting normally never
	// reaches it.
	quicRetryAbove = 100
	// quicRetryAbovePerIP is the same limit for one source address per minute.
	quicRetryAbovePerIP = 30
)

// maxAuthFrame caps the auth frame, which is read before the peer is known.
const maxAuthFrame = 64 << 10

// errQUICInsecure is why --quic and --insecure cannot be combined.
var errQUICInsecure = errors.New("--quic cannot be used with --insecure: QUIC always carries TLS 1.3, so there is no plain-HTTP mode for it; remove --insecure (and terminate TLS at the server) or leave QUIC off")

// readFrame reads one length-prefixed frame body. A clean end of stream
// before the header returns io.EOF; a frame longer than limit is refused
// before any of it is buffered, and the body grows only as bytes arrive, so a
// peer that claims 16 MiB and sends nothing pins nothing.
func readFrame(r io.Reader, limit int64) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int64(binary.BigEndian.Uint32(hdr[:]))
	if n > limit {
		return nil, fmt.Errorf("frame of %d bytes exceeds the %d byte limit", n, limit)
	}
	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, r, n); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeFrame writes env as one frame, header and body in a single Write.
func writeFrame(w io.Writer, env protocol.Envelope) error {
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if int64(len(body)) > 1<<32-1 {
		return errors.New("frame is too large to send")
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body)))
	copy(buf[4:], body)
	_, err = w.Write(buf)
	return err
}

// ---- listener ----

// quicServer is the UDP listener and the connections it accepted.
type quicServer struct {
	h      *Hub
	ln     *quic.Listener
	tr     *quic.Transport
	udp    *net.UDPConn
	port   int
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	conns  map[*quic.Conn]struct{}
	// preauth holds one token per connection that has not yet authenticated.
	preauth chan struct{}
}

// quicAddr is the UDP address --quic listens on: the host of --listen, and
// --quic-port or, by default, the same port number as HTTPS.
func (s *Server) quicAddr() (string, error) {
	host, port, err := net.SplitHostPort(s.cfg.Listen)
	if err != nil {
		return "", fmt.Errorf("--listen %q: %w", s.cfg.Listen, err)
	}
	if s.cfg.QUICPort != 0 {
		port = strconv.Itoa(s.cfg.QUICPort)
	}
	return net.JoinHostPort(host, port), nil
}

// quicTLSConfig serves the same certificate as HTTPS, through the same hook,
// so a --tailscale-cert renewal reaches new QUIC handshakes too.
func (s *Server) quicTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: s.currentCert,
		MinVersion:     tls.VersionTLS13,
		NextProtos:     []string{protocol.QUICALPN},
	}
}

// CheckQUICConfig is the startup refusal for settings QUIC cannot honour.
func CheckQUICConfig(cfg Config) error {
	if !cfg.QUIC {
		return nil
	}
	if cfg.Insecure {
		return errQUICInsecure
	}
	if cfg.QUICPort < 0 || cfg.QUICPort > 65535 {
		return fmt.Errorf("--quic-port %d is not a valid UDP port", cfg.QUICPort)
	}
	return nil
}

// listenQUIC binds the UDP listener and starts accepting agents.
func (s *Server) listenQUIC(addr string) (*quicServer, error) {
	s.certMu.Lock()
	have := s.cert != nil
	s.certMu.Unlock()
	if !have {
		return nil, errors.New("QUIC needs a server certificate, and none is loaded")
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen for QUIC on %s: %w", addr, err)
	}
	udp, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen for QUIC on %s: %w", addr, err)
	}
	// Without a Retry, spoofed Initial packets make the server build handshake
	// state and answer with its certificate chain. Retry costs every client an
	// extra round trip, so it is switched on only while new connection attempts
	// arrive faster than a real fleet produces them.
	global := newRateLimiter(quicRetryAbove, time.Second)
	perIP := newRateLimiter(quicRetryAbovePerIP, time.Minute)
	tr := &quic.Transport{
		Conn: udp,
		VerifySourceAddress: func(a net.Addr) bool {
			okGlobal := global.allow("all")
			okIP := perIP.allow(remoteIP(a))
			return !okGlobal || !okIP
		},
	}
	ln, err := tr.Listen(s.quicTLSConfig(), &quic.Config{
		// The application-level ping on the control stream is the liveness
		// signal the hub acts on; these keep the path open through NATs and
		// let the transport itself notice a vanished peer.
		MaxIdleTimeout:  90 * time.Second,
		KeepAlivePeriod: 20 * time.Second,
		// The agent opens one stream, the control stream; the server opens
		// every other one. A small bound keeps a hostile peer from asking for
		// state it has no use for.
		MaxIncomingStreams:    8,
		MaxIncomingUniStreams: -1,
	})
	if err != nil {
		udp.Close()
		return nil, fmt.Errorf("listen for QUIC on %s: %w", addr, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	q := &quicServer{h: s.hub, ln: ln, tr: tr, udp: udp, ctx: ctx, cancel: cancel,
		conns: map[*quic.Conn]struct{}{}, preauth: make(chan struct{}, maxPreAuthConns)}
	if ua, ok := ln.Addr().(*net.UDPAddr); ok {
		q.port = ua.Port
	}
	s.quic.Store(q)
	go q.acceptLoop()
	return q, nil
}

func (q *quicServer) acceptLoop() {
	for {
		conn, err := q.ln.Accept(q.ctx)
		if err != nil {
			return
		}
		q.mu.Lock()
		if q.ctx.Err() != nil {
			q.mu.Unlock()
			conn.CloseWithError(quicCodeShutdown, "server shutting down")
			return
		}
		select {
		case q.preauth <- struct{}{}:
		default:
			q.mu.Unlock()
			conn.CloseWithError(quicCodeRefused, "too many connections are waiting to authenticate")
			continue
		}
		q.conns[conn] = struct{}{}
		q.mu.Unlock()
		var once sync.Once
		release := func() { once.Do(func() { <-q.preauth }) }
		go func() {
			defer func() {
				release()
				q.mu.Lock()
				delete(q.conns, conn)
				q.mu.Unlock()
			}()
			q.h.serveQUIC(conn, release)
		}()
	}
}

// close stops accepting and drops every connection, including the ones still
// in their handshake that the hub does not know yet.
func (q *quicServer) close() {
	q.cancel()
	q.ln.Close()
	q.mu.Lock()
	conns := make([]*quic.Conn, 0, len(q.conns))
	for c := range q.conns {
		conns = append(conns, c)
	}
	q.mu.Unlock()
	for _, c := range conns {
		c.CloseWithError(quicCodeShutdown, "server shutting down")
	}
	q.tr.Close()
	q.udp.Close()
}

// ---- one connection ----

// remoteIP is the peer's address without a port, with an IPv4-mapped IPv6
// address shown as plain IPv4.
func remoteIP(addr net.Addr) string {
	if ua, ok := addr.(*net.UDPAddr); ok {
		return ua.AddrPort().Addr().Unmap().String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// refuseQUIC tells the agent why it is being turned away and ends the
// connection. The error frame is given a moment to arrive before the close,
// because a CONNECTION_CLOSE sent at once can overtake stream data.
func refuseQUIC(conn *quic.Conn, ctrl *quic.Stream, msg string) {
	ctrl.SetWriteDeadline(time.Now().Add(5 * time.Second))
	writeFrame(ctrl, protocol.Envelope{T: "error", Err: msg})
	ctrl.Close()
	select {
	case <-conn.Context().Done():
	case <-time.After(2 * time.Second):
	}
	conn.CloseWithError(quicCodeRefused, "refused")
}

// serveQUIC is handleAgentWS for a QUIC connection: the same authentication
// and identification, with the credentials taken from the auth frame instead of
// HTTP headers, then the shared serve. release hands back the connection's
// pre-authentication slot; it is called once the agent is known, and again
// (harmlessly) by the caller when the connection ends.
func (h *Hub) serveQUIC(conn *quic.Conn, release func()) {
	ip := remoteIP(conn.RemoteAddr())
	actx, cancel := context.WithTimeout(conn.Context(), quicHandshakeWait)
	ctrl, err := conn.AcceptStream(actx)
	cancel()
	if err != nil {
		conn.CloseWithError(quicCodeProtocol, "no control stream was opened")
		return
	}
	ctrl.SetReadDeadline(time.Now().Add(quicHandshakeWait))

	var env protocol.Envelope
	body, err := readFrame(ctrl, maxAuthFrame)
	if err != nil || json.Unmarshal(body, &env) != nil {
		conn.CloseWithError(quicCodeProtocol, "no readable auth frame")
		return
	}
	if env.T != protocol.TypeAuth {
		refuseQUIC(conn, ctrl, "expected auth")
		return
	}
	// The credentials live only in these locals: never logged, never stored.
	var auth protocol.Auth
	if err := json.Unmarshal(env.D, &auth); err != nil {
		refuseQUIC(conn, ctrl, "the auth frame is malformed")
		return
	}
	creds := credentials{key: auth.Key, hasKey: auth.Key != "", token: auth.Token}
	agentID, refusal := h.authenticate(creds)
	if refusal != "" {
		refuseQUIC(conn, ctrl, refusal)
		return
	}

	body, err = readFrame(ctrl, maxAgentFrame)
	env = protocol.Envelope{}
	if err != nil || json.Unmarshal(body, &env) != nil || env.T != protocol.TypeHello {
		refuseQUIC(conn, ctrl, "expected hello")
		return
	}
	var hello protocol.Hello
	if err := json.Unmarshal(env.D, &hello); err != nil {
		conn.CloseWithError(quicCodeProtocol, "the hello frame is malformed")
		return
	}

	id, newKey, justEnrolled, err := h.identify(agentID, creds.token, &hello, ip)
	if err != nil {
		refuseQUIC(conn, ctrl, protocol.ErrEnrollmentRefused+err.Error())
		return
	}
	release()
	ac := h.newConn(&quicTransport{conn: conn, ctrl: ctrl}, id, hello, ip)
	h.serve(ac, newKey, justEnrolled)
}

// ---- transport ----

// quicTransport is an agentTransport over one QUIC connection.
type quicTransport struct {
	conn *quic.Conn
	ctrl *quic.Stream
	ac   *agentConn
}

func (t *quicTransport) name() string { return "quic" }

func (t *quicTransport) bind(ac *agentConn) { t.ac = ac }

func (t *quicTransport) writeControl(env protocol.Envelope) error {
	t.ctrl.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if err := writeFrame(t.ctrl, env); err != nil {
		// A frame cut short by the deadline leaves a truncated length-prefixed
		// frame on the stream, and every later frame would be read at the
		// wrong offset. WebSocket never had this problem because a failed
		// write kills the socket; the connection has to go here too, so the
		// agent reconnects instead of waiting for keepalive to notice.
		t.conn.CloseWithError(quicCodeProtocol, "control stream write failed")
		return err
	}
	return nil
}

// openRequest gives the request a stream of its own, so a stalled shell or a
// large transfer cannot delay another request's frames. OpenStream rather than
// OpenStreamSync: the caller holds the connection's write lock, and waiting
// there for the agent to grant more streams would stall the control path too.
func (t *quicTransport) openRequest(env protocol.Envelope) (requestStream, error) {
	st, err := t.conn.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("cannot open a request stream to the agent (too many requests in flight?): %w", err)
	}
	st.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if err := writeFrame(st, env); err != nil {
		st.CancelWrite(quicCodeAbort)
		st.CancelRead(quicCodeAbort)
		return nil, err
	}
	// One request frame per stream: the sending side is done. Follow-ups such
	// as shell input travel on the control stream.
	st.Close()
	go t.pumpRequest(st, env.ID)
	return &quicRequest{st: st}, nil
}

func (t *quicTransport) welcomed() { t.ctrl.SetReadDeadline(time.Time{}) }

// decodeFrame reads and parses one envelope. skip is true for a frame that
// framed correctly but did not parse, which is dropped the way the WebSocket
// path drops it; err is a framing failure that ends the stream.
func decodeFrame(r io.Reader, id string) (env protocol.Envelope, skip bool, err error) {
	body, err := readFrame(r, maxAgentFrame)
	if err != nil {
		return env, false, err
	}
	if len(body) == 0 {
		return env, true, nil
	}
	if err := json.Unmarshal(body, &env); err != nil {
		slog.Warn("bad frame from agent", "id", id, "err", err)
		return env, true, nil
	}
	return env, false, nil
}

func (t *quicTransport) readLoop() {
	for {
		env, skip, err := decodeFrame(t.ctrl, t.ac.id)
		if err != nil {
			t.noteReadError("control stream", err)
			return
		}
		if !skip {
			t.ac.handleFrame(env)
		}
	}
}

// pumpRequest reads one request's answers: stream frames and then the final
// reply. Each request has its own pump, so a sink that blocks (a slow viewer, a
// test holding the stream) delays nothing but this request.
func (t *quicTransport) pumpRequest(st *quic.Stream, id string) {
	defer st.CancelRead(0)
	for {
		env, skip, err := decodeFrame(st, t.ac.id)
		if err != nil {
			t.noteReadError("request stream", err)
			if t.conn.Context().Err() != nil {
				// the whole connection went, which is what every other
				// pending request is told
				t.ac.failRequest(id, "agent disconnected")
			} else if !errors.Is(err, io.EOF) {
				// a stream the agent reset or a frame it could not frame
				t.ac.failRequest(id, "the agent's request stream failed: "+err.Error())
			} else {
				t.ac.failRequest(id, "the agent closed the request stream without replying")
			}
			return
		}
		if skip {
			continue
		}
		t.ac.handleFrame(env)
		if env.T == protocol.TypeReply {
			return // the final reply
		}
	}
}

// noteReadError drops the whole connection when a peer breaks the framing,
// because after an oversized length the rest of the stream cannot be trusted.
func (t *quicTransport) noteReadError(what string, err error) {
	var ae *quic.ApplicationError
	var se *quic.StreamError
	var ie *quic.IdleTimeoutError
	switch {
	case errors.Is(err, io.EOF), errors.As(err, &ae), errors.As(err, &se), errors.As(err, &ie),
		errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, net.ErrClosed), errors.Is(err, context.Canceled):
		return
	}
	if _, ok := err.(net.Error); ok {
		return
	}
	slog.Warn("dropping an agent that broke the QUIC framing", "id", t.ac.id, "stream", what, "err", err)
	t.conn.CloseWithError(quicCodeProtocol, "malformed or oversized frame")
}

func (t *quicTransport) closeGraceful() {
	t.conn.CloseWithError(quicCodeShutdown, "server shutting down")
}

func (t *quicTransport) close() {
	t.conn.CloseWithError(quicCodeNormal, "closed")
}

// quicRequest is a request's stream.
type quicRequest struct{ st *quic.Stream }

func (r *quicRequest) abort() {
	r.st.CancelRead(quicCodeAbort)
	r.st.CancelWrite(quicCodeAbort)
}
