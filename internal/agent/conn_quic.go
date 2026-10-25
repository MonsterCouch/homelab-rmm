package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// This file is the agent's side of the QUIC transport
// (docs/plans/2026-10-24-phase3e-quic.md). The wire format is the WebSocket's,
// byte for byte, with one change of carrier: every frame is a uint32
// big-endian length followed by the JSON protocol.Envelope, and each
// server-to-agent request arrives on a stream of its own so a stalled shell or
// file transfer cannot hold up a reply on another.

const (
	// quicDialTimeout bounds the QUIC handshake. A network that drops UDP
	// otherwise leaves the agent waiting out quic-go's idle timeout before the
	// WebSocket fallback gets a turn, and every device would pay that on every
	// reconnect until the failure memory kicked in.
	quicDialTimeout = 4 * time.Second
	// quicHandshakeTimeout bounds auth, hello and welcome once the connection
	// is up.
	quicHandshakeTimeout = 10 * time.Second
	// quicRetryAfter is how long a failed QUIC attempt keeps the agent on
	// WebSocket in auto mode.
	quicRetryAfter = 10 * time.Minute

	// quicMaxFrame matches the 64 MiB limit the WebSocket reader has always had.
	quicMaxFrame = 64 << 20
	// quicRequestWait is how long an accepted stream may go without delivering
	// another byte of its request frame. It is an idle limit that every read
	// that makes progress renews, so a large body on a slow link finishes while
	// a stalled sender is still cut off.
	quicRequestWait = 15 * time.Second
	quicWriteWait   = 30 * time.Second

	// Application close and abort codes, the server's table: 0 normal,
	// 1 protocol, 2 refused, 3 shutdown, 4 request aborted.
	quicCodeNormal   quic.ApplicationErrorCode = 0
	quicCodeProtocol quic.ApplicationErrorCode = 1
	quicCodeAbort    quic.StreamErrorCode      = 4
)

// quicTransportError marks a failure that says nothing about the credentials:
// no UDP path, a handshake that did not finish, a malformed answer. These are
// the failures the agent answers by falling back to WebSocket. A refusal the
// server wrote on the control stream is a verdict, not a transport failure, and
// is returned as a quicRefusal.
type quicTransportError struct{ err error }

func (e *quicTransportError) Error() string { return e.err.Error() }
func (e *quicTransportError) Unwrap() error { return e.err }

// quicRefusal is the server turning the agent away on the control stream. msg
// is the server's sentence; protocol.ErrUnknownAgentKey is the 401 equivalent.
type quicRefusal struct{ msg string }

func (e *quicRefusal) Error() string { return "server refused: " + e.msg }

// quicTLSConfig is the WebSocket path's pinning, narrowed to what the server's
// QUIC listener accepts: TLS 1.3 and its ALPN.
func quicTLSConfig(fingerprint string) *tls.Config {
	c := TLSConfig(fingerprint)
	c.MinVersion = tls.VersionTLS13
	c.NextProtos = []string{protocol.QUICALPN}
	return c
}

// quicAddress is host:port for the QUIC dial. The host is the one the agent
// already uses for HTTPS; port is the advertised UDP port, or the HTTPS port
// when none is known (a forced RMM_TRANSPORT=quic on a server that listens
// on its default).
func quicAddress(serverURL string, port int) (string, error) {
	raw := serverURL
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("cannot work out the QUIC address from server_url %q", serverURL)
	}
	if u.Scheme == "http" {
		return "", errors.New("QUIC always carries TLS and server_url is http://; use an https:// URL or RMM_TRANSPORT=websocket")
	}
	if port == 0 {
		p := u.Port()
		if p == "" {
			p = "443"
		}
		return net.JoinHostPort(u.Hostname(), p), nil
	}
	return net.JoinHostPort(u.Hostname(), fmt.Sprint(port)), nil
}

// writeFrame writes one length-prefixed envelope in a single Write so a
// deadline cannot split the header from its body on the happy path.
func writeFrame(w io.Writer, env protocol.Envelope) error {
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if len(body) > quicMaxFrame {
		return fmt.Errorf("a %d byte frame is larger than the %d byte limit", len(body), quicMaxFrame)
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body)))
	copy(buf[4:], body)
	_, err = w.Write(buf)
	return err
}

// readFrame reads one frame. ok is false for an empty or unparseable frame,
// which the protocol says to skip; a length above the limit is an error,
// because the stream cannot be resynchronised after it.
func readFrame(r io.Reader) (env protocol.Envelope, ok bool, err error) {
	var hdr [4]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return env, false, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return env, false, nil
	}
	if n > quicMaxFrame {
		return env, false, fmt.Errorf("the server sent a %d byte frame, over the %d byte limit", n, quicMaxFrame)
	}
	// The buffer grows as bytes arrive rather than being sized from the header,
	// so a peer that claims 64 MiB on every stream and sends nothing pins nothing.
	var buf bytes.Buffer
	if _, err = io.CopyN(&buf, r, int64(n)); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return env, false, err
	}
	if json.Unmarshal(buf.Bytes(), &env) != nil {
		return protocol.Envelope{}, false, nil
	}
	return env, true, nil
}

// idleReader renews the stream's read deadline before every read, which turns
// the deadline into an idle limit: a request that keeps arriving is never cut
// off, however large, and one that stops is.
type idleReader struct {
	s    *quic.Stream
	wait time.Duration
}

func (r *idleReader) Read(p []byte) (int, error) {
	r.s.SetReadDeadline(time.Now().Add(r.wait))
	return r.s.Read(p)
}

// reqStream is the agent's end of one server-opened request stream. Its own
// lock keeps a stalled write on this stream from touching any other.
type reqStream struct {
	s  *quic.Stream
	mu sync.Mutex
}

// quicLink is one QUIC connection: the control stream the agent opened and the
// request streams the server opens, indexed by request id so that conn.reply,
// replyErr and stream can find the one a frame belongs to.
type quicLink struct {
	conn *quic.Conn
	ctrl *quic.Stream
	cmu  sync.Mutex // control stream writes

	mu   sync.Mutex
	reqs map[string]*reqStream
}

func (l *quicLink) close(code quic.ApplicationErrorCode, why string) {
	l.conn.CloseWithError(code, why)
}

// send routes an envelope: a reply or stream frame goes to the stream its
// request arrived on, everything else to the control stream. A reply for an id
// with no open stream (a request that came in on the control stream) also
// falls back to control rather than vanishing.
func (l *quicLink) send(env protocol.Envelope) error {
	if env.ID != "" && (env.T == protocol.TypeReply || env.T == protocol.TypeStream) {
		l.mu.Lock()
		rs := l.reqs[env.ID]
		l.mu.Unlock()
		if rs != nil {
			return l.sendRequest(env, rs)
		}
	}
	return l.sendControl(env)
}

func (l *quicLink) sendControl(env protocol.Envelope) error {
	l.cmu.Lock()
	defer l.cmu.Unlock()
	l.ctrl.SetWriteDeadline(time.Now().Add(quicWriteWait))
	if err := writeFrame(l.ctrl, env); err != nil {
		// A frame cut short by a deadline leaves the control stream unusable,
		// so the connection goes with it and the agent reconnects.
		l.close(quicCodeProtocol, "control stream write failed")
		return err
	}
	return nil
}

func (l *quicLink) sendRequest(env protocol.Envelope, rs *reqStream) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.s.SetWriteDeadline(time.Now().Add(quicWriteWait))
	if err := writeFrame(rs.s, env); err != nil {
		rs.s.CancelWrite(quicCodeAbort)
		l.forget(env.ID, rs)
		return err
	}
	if env.T == protocol.TypeReply {
		// The final reply ends the request: close the agent's side and drop
		// the index entry.
		l.forget(env.ID, rs)
		return rs.s.Close()
	}
	return nil
}

func (l *quicLink) forget(id string, rs *reqStream) {
	if id == "" {
		return
	}
	l.mu.Lock()
	if l.reqs[id] == rs {
		delete(l.reqs, id)
	}
	l.mu.Unlock()
}

// serve reads until the connection ends: the control stream in one goroutine,
// request streams accepted in another, both feeding a.dispatch. The request
// frame of each stream is read and dispatched here, in the order the streams
// were opened, before the stream gets a goroutine of its own. QUIC does not
// order streams against each other, and the transparency log proofs the hub
// attaches to signed requests only verify in the order they were written.
func (l *quicLink) serve(ctx context.Context, a *Agent) error {
	errc := make(chan error, 2)
	go func() { errc <- l.readControl(ctx, a) }()
	go func() { errc <- l.acceptLoop(ctx, a) }()
	err := <-errc
	l.close(quicCodeNormal, "session over")
	<-errc
	return err
}

func (l *quicLink) readControl(ctx context.Context, a *Agent) error {
	for {
		env, ok, err := readFrame(l.ctrl)
		if err != nil {
			return err
		}
		if ok {
			a.dispatch(ctx, env)
		}
	}
}

func (l *quicLink) acceptLoop(ctx context.Context, a *Agent) error {
	for {
		s, err := l.conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		rs := &reqStream{s: s}
		idle := &idleReader{s: s, wait: quicRequestWait}
		var env protocol.Envelope
		for {
			var ok bool
			if env, ok, err = readFrame(idle); err != nil || ok {
				break
			}
		}
		if err != nil {
			s.CancelRead(quicCodeAbort)
			s.CancelWrite(quicCodeAbort)
			continue
		}
		s.SetReadDeadline(time.Time{})
		if env.ID != "" {
			l.mu.Lock()
			l.reqs[env.ID] = rs
			l.mu.Unlock()
		}
		a.dispatch(ctx, env)
		go l.drain(ctx, a, env.ID, rs)
	}
}

// drain is the reader goroutine of one request stream. The server normally
// closes its side right after the request, so it mostly waits; it then keeps
// the index entry until the agent's own side is finished or the server aborts
// the stream (a request that timed out).
func (l *quicLink) drain(ctx context.Context, a *Agent, id string, rs *reqStream) {
	defer l.forget(id, rs)
	for {
		env, ok, err := readFrame(rs.s)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				rs.s.CancelWrite(quicCodeAbort)
				return
			}
			break
		}
		if ok {
			a.dispatch(ctx, env)
		}
	}
	if id == "" {
		rs.s.Close()
		return
	}
	select {
	case <-rs.s.Context().Done():
	case <-ctx.Done():
	}
}

// dialQUIC connects, authenticates and reads the welcome. A failure before the
// server has spoken is a *quicTransportError; a refusal the server wrote is a
// *quicRefusal.
func dialQUIC(ctx context.Context, addr, fingerprint string, auth protocol.Auth, hello protocol.Hello) (*quicLink, protocol.Envelope, error) {
	var zero protocol.Envelope
	conf := &quic.Config{
		HandshakeIdleTimeout: quicDialTimeout,
		MaxIdleTimeout:       90 * time.Second,
		KeepAlivePeriod:      20 * time.Second,
		// The server opens one stream per request; the floor it relies on is 64.
		MaxIncomingStreams:    256,
		MaxIncomingUniStreams: -1,
	}
	dctx, cancel := context.WithTimeout(ctx, quicDialTimeout)
	defer cancel()
	qc, err := quic.DialAddr(dctx, addr, quicTLSConfig(fingerprint), conf)
	if err != nil {
		return nil, zero, &quicTransportError{fmt.Errorf("QUIC dial %s: %w", addr, err)}
	}
	fail := func(err error) (*quicLink, protocol.Envelope, error) {
		qc.CloseWithError(quicCodeNormal, "handshake failed")
		return nil, zero, &quicTransportError{err}
	}
	hctx, hcancel := context.WithTimeout(ctx, quicHandshakeTimeout)
	defer hcancel()
	ctrl, err := qc.OpenStreamSync(hctx)
	if err != nil {
		return fail(fmt.Errorf("QUIC control stream: %w", err))
	}
	ctrl.SetWriteDeadline(time.Now().Add(quicHandshakeTimeout))
	if err := writeFrame(ctrl, protocol.Envelope{T: protocol.TypeAuth, D: protocol.Must(auth)}); err != nil {
		return fail(fmt.Errorf("QUIC auth: %w", err))
	}
	if err := writeFrame(ctrl, protocol.Envelope{T: protocol.TypeHello, D: protocol.Must(hello)}); err != nil {
		return fail(fmt.Errorf("QUIC hello: %w", err))
	}
	ctrl.SetWriteDeadline(time.Time{})
	ctrl.SetReadDeadline(time.Now().Add(quicHandshakeTimeout))
	var env protocol.Envelope
	for {
		var ok bool
		if env, ok, err = readFrame(ctrl); err != nil {
			if auth.Key == "" && auth.Token != "" {
				// The server consumes the enrollment token before it writes the
				// welcome, so a lost welcome may mean the token is already
				// spent. Falling back to WebSocket with the same token could
				// fail or enroll the device twice; a plain error ends this
				// attempt and the next one retries QUIC.
				qc.CloseWithError(quicCodeNormal, "welcome not received")
				return nil, zero, fmt.Errorf("QUIC welcome after the enrollment token was presented: %w", err)
			}
			return fail(fmt.Errorf("QUIC welcome: %w", err))
		}
		if ok {
			break
		}
	}
	ctrl.SetReadDeadline(time.Time{})
	switch env.T {
	case "welcome":
		return &quicLink{conn: qc, ctrl: ctrl, reqs: map[string]*reqStream{}}, env, nil
	case "error":
		qc.CloseWithError(quicCodeNormal, "refused")
		return nil, zero, &quicRefusal{msg: env.Err}
	}
	return fail(fmt.Errorf("the server answered the QUIC handshake with %q instead of a welcome", env.T))
}

// chooseQUIC decides whether this session dials QUIC first. websocket never
// does; quic always does (with no fallback, the caller's business); auto does
// when the server has advertised a port and the last failure is old enough.
func chooseQUIC(mode string, port int, failedAt int64, now time.Time) bool {
	switch mode {
	case "websocket":
		return false
	case "quic":
		return true
	}
	if port <= 0 {
		return false
	}
	return failedAt == 0 || now.Sub(time.Unix(failedAt, 0)) >= quicRetryAfter
}
