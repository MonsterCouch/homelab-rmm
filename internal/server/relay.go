package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// ---- remote shell ----
//
// Browser <-WS-> server <-agent socket-> agent. The browser sends JSON:
//   {"t":"open","shell":"powershell","cols":120,"rows":30}
//   {"t":"in","data":"ls\r"}  {"t":"resize","cols":..,"rows":..}
// and receives {"t":"out","data":...}, {"t":"opened","session":..}, {"t":"closed"}.

// Both browser-side relay sockets - the terminal at /ws/shell and the
// desktop viewer at /ws/desktop - are bounded the way their siblings are:
// the agent socket (Hub.keepalive) and the desktop helper
// (internal/agent/desktop) each cap a frame and drop a peer that stops
// answering. An interactive SYSTEM shell is the most valuable thing this
// server hands out, so one operator must not be able to make it buffer
// arbitrary input frames; and a viewer that vanished without a TCP FIN - a
// closed lid, a dropped VPN, a killed VM, a phone that slept behind a NAT
// which then forgot the flow - must not leave a shell running, or a screen
// being captured, on the device for ever. Liveness tracks PONGS, not
// traffic, for the same reason Hub.keepalive does: a peer that floods
// frames but never answers a ping is exactly the one to drop.
//
// The period is 25 s rather than the agent socket's 30 s because this peer
// is a phone. Mobile NAT idle timeouts start at about 30 s, and 25 s is
// what the SSE stream at /api/events already uses for its comment ping, so
// one radio wake serves both.
//
// These are variables rather than constants so the test can compress the
// clock; nothing else writes them.
var (
	// shellFrameLimit is what the desktop viewer uses: a keystroke or a
	// paste is small.
	shellFrameLimit   int64 = 1 << 20
	viewerPingPeriod        = 25 * time.Second
	viewerIdleTimeout       = 90 * time.Second
)

// keepViewerAlive bounds one browser-side socket: the peer is pinged every
// viewerPingPeriod and must answer within viewerIdleTimeout, or its next read
// fails with a timeout. The returned func stops the pinger; defer it after the
// socket's own Close so the ticker goes first, and register the handlers here
// before anything starts reading the socket.
//
// WriteControl is documented as safe alongside the other write methods, so
// this deliberately does not take the wsWriter's lock: a ping must not queue
// behind a tile write parked on its 15 s deadline.
func keepViewerAlive(c *websocket.Conn) func() {
	c.SetReadDeadline(time.Now().Add(viewerIdleTimeout))
	c.SetPongHandler(func(string) error {
		return c.SetReadDeadline(time.Now().Add(viewerIdleTimeout))
	})
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(viewerPingPeriod)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if err := c.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
					return // the socket is gone; the reader reports it
				}
			}
		}
	}()
	return func() { close(stop) }
}

// sameOrigin rejects cross-site WebSocket hijacking: browsers always send
// Origin on WebSocket upgrades, and a legitimate viewer's origin host is the
// host it loaded the console from.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // non-browser client; the cookie check already passed
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func (s *Server) handleShellWS(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if !sameOrigin(r) {
		writeErr(w, 403, "cross-origin websocket refused")
		return
	}
	a, err := s.db.GetAgent(agentID)
	if err != nil {
		writeErr(w, 404, "agent not found")
		return
	}
	u := userFrom(r.Context())
	if !s.canAccessAgent(u, a.OrgID) {
		writeErr(w, 404, "agent not found")
		return
	}
	if !s.hub.IsOnline(agentID) {
		writeErr(w, 409, "agent is offline")
		return
	}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()
	ws.SetReadLimit(shellFrameLimit)
	// Ping the viewer so a browser that went away without closing the socket
	// is noticed within the idle timeout instead of holding the shell open.
	// Registered after defer ws.Close(), so the ticker stops before the
	// socket goes.
	defer keepViewerAlive(ws)()
	sw := &wsWriter{c: ws}
	send := func(v any) { sw.json(v) }
	uName := "technician"
	if u != nil && u.Username != "" {
		uName = u.Username
	}
	s.db.Exec(`INSERT INTO agent_events(agent_id, ts, kind, message, fields) VALUES(?,?,?,?,?)`, agentID, now(), "remote", fmt.Sprintf("Terminal session started by %s", uName), jsonText(map[string]any{"user": uName, "type": "terminal"}))
	s.hub.broadcast(hubEvent{Kind: "event", AgentID: agentID, Data: map[string]any{"ts": now(), "kind": "remote", "message": fmt.Sprintf("Terminal session started by %s", uName)}})

	// Same as the desktop viewer: the terminal used to end by dropping the
	// socket, so every ending - a closed tab, an agent that went away, a shell
	// that would not open - arrived in the browser as 1006. Registered before
	// the request-scoped cleanup below so it runs after it, and after
	// defer ws.Close() so it runs before that.
	closeCode, closeText := websocket.CloseNormalClosure, ""
	defer func() { sw.writeClose(closeCode, closeText) }()

	var (
		session string
		cancel  func()
		// The open handshake below is touched by this goroutine and by the
		// agent's sink, which runs on the hub's read loop.
		openMu   sync.Mutex
		openID   string // the session id, once the agent socket took the request
		haveID   bool
		agentSaw bool  // the agent answered: a shell exists
		refused  bool  // ... and its answer was "no", so one never did
		flowing  bool  // the viewer has the marker; frames go straight out
		queued   []any // what the sink produced while the open was undecided
	)
	defer func() {
		openMu.Lock()
		dead := refused
		openMu.Unlock()
		// A session the device refused was never created, so there is
		// nothing to close - telling it to close that id is a frame about
		// something that does not exist.
		if session != "" && !dead {
			s.hub.Notify(agentID, protocol.ReqShellClose, protocol.ShellClose{Session: session})
		}
		if cancel != nil {
			cancel()
		}
	}()
	s.audit(r, "shell.open", agentID, nil)

	for {
		var msg struct {
			T     string `json:"t"`
			Shell string `json:"shell"`
			Data  string `json:"data"`
			Cols  int    `json:"cols"`
			Rows  int    `json:"rows"`
		}
		if err := ws.ReadJSON(&msg); err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				// The read deadline the pong handler keeps pushing out: this
				// viewer stopped answering, so say so rather than reporting
				// the shell's end as an ordinary close.
				closeCode, closeText = websocket.CloseGoingAway, "terminal closed: the viewer stopped answering"
			}
			return
		}
		switch msg.T {
		case "open":
			if session != "" {
				continue
			}
			// "opened" means a shell exists, so it waits for the device to
			// say so rather than going out on the strength of a write to the
			// agent socket: an open the device refuses (an unsupported shell
			// name, no ConPTY, no /bin/sh) is answered with an error, and
			// announcing success first made every such failure arrive as
			// {"opened"} followed by {"error"}.
			//
			// The sink runs on the hub's read loop, so that answer - or a
			// first prompt - can reach it before Stream has even returned the
			// session id. Anything it produces before the marker is queued
			// and flushed straight after it, in order.
			forward := func(v any) { // caller holds openMu
				if flowing {
					send(v)
					return
				}
				queued = append(queued, v)
			}
			settle := func() { // caller holds openMu
				if flowing {
					return
				}
				if !refused && !(agentSaw && haveID) {
					return // still waiting for the device, or for the id
				}
				if !refused {
					send(map[string]any{"t": "opened", "session": openID})
				}
				flowing = true
				for _, v := range queued {
					send(v)
				}
				queued = nil
			}
			id, c, err := s.hub.Stream(agentID, protocol.ReqShellOpen, protocol.ShellOpen{Shell: msg.Shell, Cols: msg.Cols, Rows: msg.Rows}, func(env protocol.Envelope) {
				openMu.Lock()
				defer openMu.Unlock()
				if env.Err != "" {
					// An error before anything else is the open failing;
					// later it is a session that died with something to say.
					refused = refused || !agentSaw
					agentSaw = true
					forward(map[string]any{"t": "error", "message": env.Err})
					forward(map[string]any{"t": "closed"})
					settle()
					return
				}
				var chunk protocol.ShellChunk
				if json.Unmarshal(env.D, &chunk) != nil {
					return
				}
				agentSaw = true
				if chunk.EOF || env.T == protocol.TypeReply {
					forward(map[string]any{"t": "closed"})
				} else {
					forward(map[string]any{"t": "out", "data": chunk.Data})
				}
				settle()
			})
			if err != nil {
				send(map[string]any{"t": "error", "message": err.Error()})
				closeCode, closeText = websocket.CloseInternalServerErr, "shell could not be opened: "+err.Error()
				return
			}
			session, cancel = id, c
			openMu.Lock()
			openID, haveID = id, true
			settle()
			openMu.Unlock()
		case "in":
			if session != "" {
				s.hub.Notify(agentID, protocol.ReqShellInput, protocol.ShellInput{Session: session, Data: msg.Data})
			}
		case "resize":
			if session != "" {
				s.hub.Notify(agentID, protocol.ReqShellResize, protocol.ShellResize{Session: session, Cols: msg.Cols, Rows: msg.Rows})
			}
		case "close":
			closeText = "session closed"
			return
		}
	}
}

// ---- remote desktop ----
//
// The viewer connects to /ws/desktop/{agent}. The server asks the agent to
// start its desktop helper with a one-time token; the helper connects to
// /ws/desktop-agent?token=... and the two sockets are bridged byte for byte:
// binary frames (screen tiles) flow helper->viewer, text frames (input)
// flow viewer->helper. The server never decodes video.

type desktopBroker struct {
	mu      sync.Mutex
	pending map[string]*desktopSession
}

type desktopSession struct {
	agentID string
	viewer  *websocket.Conn
	helper  chan *websocket.Conn
	created time.Time
	// mu guards done. done is set by the viewer handler on its way out: a
	// helper that connects after that is closed at once instead of being
	// parked in the buffered channel forever, still capturing the screen and
	// streaming into a socket nobody owns.
	mu   sync.Mutex
	done bool
}

// finish marks the session dead and closes a helper that is already waiting.
func (ds *desktopSession) finish() {
	ds.mu.Lock()
	ds.done = true
	ds.mu.Unlock()
	select {
	case h := <-ds.helper:
		h.Close()
	default:
	}
}

// offerHelper hands the helper socket to the waiting viewer. It reports false
// when nobody will ever read it, in which case the caller closes it.
func (ds *desktopSession) offerHelper(c *websocket.Conn) bool {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if ds.done {
		return false
	}
	select {
	case ds.helper <- c:
		return true
	default:
		return false
	}
}

func newDesktopBroker() *desktopBroker { return &desktopBroker{pending: map[string]*desktopSession{}} }

// wsWriter serialises writes: gorilla/websocket permits one concurrent
// writer per connection and the desktop path has three (note, connected,
// bridge pump).
type wsWriter struct {
	c  *websocket.Conn
	mu sync.Mutex
}

func (w *wsWriter) write(mt int, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.c.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return w.c.WriteMessage(mt, data)
}

// writeClose sends a Close control frame. gorilla/websocket documents Close
// and WriteControl as safe to call concurrently with the other write methods,
// so this deliberately does not take w.mu: the pump that is closing must not
// wait behind a peer write that is stuck on its 15 s deadline.
//
// A close frame's payload is capped at 125 bytes (2 of them the code), so the
// reason is trimmed rather than silently failing the whole frame.
func (w *wsWriter) writeClose(code int, reason string) {
	w.c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, closeReason(reason)), time.Now().Add(2*time.Second))
}

func closeReason(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	for len(s) > 120 {
		_, n := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-n]
	}
	return s
}

// closeCodeFor turns a read error into the code the OTHER side should be told.
// A peer that hung up without a close frame (1006, or a bare I/O error) is not
// a finished session: reporting both as 1000 leaves the viewer unable to tell
// "the operator closed the tab" from "the helper crashed", which is the whole
// complaint 1006 raised in the first place.
func closeCodeFor(err error, who string) (int, string) {
	var ce *websocket.CloseError
	if errors.As(err, &ce) {
		switch ce.Code {
		case websocket.CloseAbnormalClosure:
			// no close frame arrived; fall through to the died case
		case websocket.CloseNoStatusReceived:
			return websocket.CloseNormalClosure, "" // a close frame, just no code
		default:
			return ce.Code, ce.Text // a real close: forward it verbatim
		}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		// The read deadline keepViewerAlive keeps pushing out. This peer did
		// not disconnect - it stopped answering pings - and that is the only
		// fact that explains a session ending while nothing looked wrong.
		return websocket.CloseGoingAway, who + " stopped answering"
	}
	return websocket.CloseInternalServerErr, who + " disconnected without closing the session"
}

func (w *wsWriter) json(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return w.write(websocket.TextMessage, b)
}

// wsFrame is one message read from a socket.
type wsFrame struct {
	mt   int
	data []byte
}

// framePump reads a socket from the moment it is upgraded. After a hijack
// net/http stops reading the connection and only cancels the request context
// once the handler returns, so r.Context() can never tell a handler that its
// own viewer went away; a pump can. Frames are queued rather than dropped so
// nothing sent before the bridge starts is lost.
type framePump struct {
	frames chan wsFrame
	done   chan struct{} // closed when the socket ends
	stop   chan struct{} // closed by the consumer to release the pump
	err    error         // read error, valid once done is closed
}

func pumpFrames(c *websocket.Conn) *framePump {
	p := &framePump{frames: make(chan wsFrame, 32), done: make(chan struct{}), stop: make(chan struct{})}
	go func() {
		defer close(p.done)
		for {
			mt, data, err := c.ReadMessage()
			if err != nil {
				p.err = err
				return
			}
			select {
			case p.frames <- wsFrame{mt, data}:
			case <-p.stop:
				return
			}
		}
	}()
	return p
}

func (s *Server) handleDesktopViewerWS(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if !sameOrigin(r) {
		writeErr(w, 403, "cross-origin websocket refused")
		return
	}
	a, err := s.db.GetAgent(agentID)
	if err != nil {
		writeErr(w, 404, "agent not found")
		return
	}
	u := userFrom(r.Context())
	if !s.canAccessAgent(u, a.OrgID) {
		writeErr(w, 404, "agent not found")
		return
	}
	if !s.hub.IsOnline(agentID) {
		writeErr(w, 409, "agent is offline")
		return
	}
	// Every viewer starts its own SYSTEM helper on the device, each capturing
	// and encoding the screen, and nothing bounded how many could run at once:
	// opening the tab repeatedly stacked them up with no complaint from either
	// side. Refuse past the cap rather than let a device be ground down by its
	// own management agent.
	if n := s.desktopCap.acquire(agentID); n < 0 {
		writeErr(w, 429, fmt.Sprintf("this device already has %d remote desktop sessions open", maxDesktopsPerAgent))
		return
	}
	defer s.desktopCap.release(agentID)
	viewer, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer viewer.Close()
	viewer.SetReadLimit(1 << 20)
	// The same bound as the terminal. Without it a phone that slept mid
	// session left this handler bridging into a socket nobody would ever
	// read again, with the helper still capturing the screen on the device.
	// Registered before pumpFrames, so the pong handler that refreshes the
	// read deadline is installed before anything reads this socket.
	defer keepViewerAlive(viewer)()
	vw := &wsWriter{c: viewer}
	// Read the viewer from the moment it is upgraded. The waits below need to
	// know when the viewer goes away, and r.Context() cannot tell them: after
	// the hijack it is only cancelled once this handler returns.
	vp := pumpFrames(viewer)
	defer close(vp.stop)

	// Every way out of this handler before the bridge starts is a failure the
	// operator hit for a reason - no graphical session, a helper that crashed
	// on launch, a locked desktop - and each used to drop the socket without a
	// close frame, so the browser reported 1006 and the viewer's error text was
	// suppressed as "not clean". The JSON {"t":"error"} above says what went
	// wrong; this says the session is over and that it was not a network fault.
	// Registered after defer viewer.Close(), so it runs before it.
	bridged := false
	closeCode, closeText := websocket.CloseInternalServerErr, "desktop session could not be started"
	defer func() {
		if !bridged {
			vw.writeClose(closeCode, closeText)
		}
	}()

	token := randomToken(24)
	ds := &desktopSession{agentID: agentID, viewer: viewer, helper: make(chan *websocket.Conn, 1), created: time.Now()}
	s.desktops.mu.Lock()
	s.desktops.pending[token] = ds
	s.desktops.mu.Unlock()
	defer func() {
		s.desktops.mu.Lock()
		delete(s.desktops.pending, token)
		s.desktops.mu.Unlock()
		// ... and mark the session dead, so a helper that connects in the gap
		// between this handler giving up and the token being forgotten is
		// closed rather than parked in the channel with nobody to read it.
		ds.finish()
	}()
	s.audit(r, "desktop.open", agentID, nil)

	quality := int(queryInt(r, "quality", 60))
	// The viewer asks for WebRTC with ?webrtc=1 and the backstage
	// (administrative, hidden-from-user) desktop with ?mode=backstage. Both
	// default off, so an old viewer keeps the plain tile stream on the
	// console desktop.
	enableWebRTC := r.URL.Query().Get("webrtc") == "1" || r.URL.Query().Get("webrtc") == "true"
	mode := protocol.DesktopModeConsole
	if r.URL.Query().Get("mode") == string(protocol.DesktopModeBackstage) {
		mode = protocol.DesktopModeBackstage
	}
	// Hand the viewer its ICE servers up front: webrtc.ts waits for this
	// before building its offer. Sent before the helper is even launched so
	// the browser can set up its RTCPeerConnection in parallel with the
	// device spawning its helper. Harmless to a non-WebRTC viewer, which
	// ignores unknown message types, but only sent when WebRTC was asked for.
	if enableWebRTC {
		vw.json(map[string]any{"t": "webrtc_config", "ice_servers": s.cfg.iceServersJSON()})
	}
	startErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var res protocol.DesktopStartResult
		err := s.hub.Request(ctx, agentID, protocol.ReqDesktopStart, protocol.DesktopStart{Token: token, Quality: quality, Mode: mode, EnableWebRTC: enableWebRTC}, &res)
		if err != nil {
			vw.json(map[string]string{"t": "error", "message": err.Error()})
			startErr <- err
			return
		}
		if res.Note != "" {
			vw.json(map[string]string{"t": "note", "message": res.Note})
		}
		startErr <- nil
	}()

	var helper *websocket.Conn
	select {
	case helper = <-ds.helper:
	case err := <-startErr:
		if err != nil {
			closeText = "desktop start failed: " + err.Error()
			return
		}
		select {
		case helper = <-ds.helper:
		case <-time.After(30 * time.Second):
			const msg = "desktop helper did not connect within 30 seconds"
			vw.json(map[string]string{"t": "error", "message": msg})
			closeText = msg
			return
		case <-vp.done:
			closeCode, closeText = websocket.CloseGoingAway, "the viewer went away"
			return
		}
	case <-time.After(45 * time.Second):
		const msg = "desktop helper did not connect within 45 seconds"
		vw.json(map[string]string{"t": "error", "message": msg})
		closeText = msg
		return
	case <-vp.done:
		closeCode, closeText = websocket.CloseGoingAway, "the viewer went away"
		return
	}
	defer helper.Close()
	vw.json(map[string]string{"t": "connected"})
	bridged = true // bridge() writes the close frame from here on
	uName := "technician"
	if u != nil && u.Username != "" {
		uName = u.Username
	}
	s.db.Exec(`INSERT INTO agent_events(agent_id, ts, kind, message, fields) VALUES(?,?,?,?,?)`, agentID, now(), "remote", fmt.Sprintf("Remote desktop session started by %s", uName), jsonText(map[string]any{"user": uName, "type": "desktop"}))
	s.hub.broadcast(hubEvent{Kind: "event", AgentID: agentID, Data: map[string]any{"ts": now(), "kind": "remote", "message": fmt.Sprintf("Remote desktop session started by %s", uName), "fields": map[string]any{"user": uName, "type": "desktop"}}})

	bridge(vp, viewer, vw, helper, &wsWriter{c: helper})
}

// handleDesktopAgentWS is where the helper process connects. Its token is the
// only credential: it is single-use, random and expires with the viewer.
func (s *Server) handleDesktopAgentWS(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	s.desktops.mu.Lock()
	ds := s.desktops.pending[token]
	if ds != nil {
		delete(s.desktops.pending, token) // single use
	}
	s.desktops.mu.Unlock()
	if ds == nil {
		writeErr(w, 401, "unknown desktop session")
		return
	}
	helper, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	helper.SetReadLimit(32 << 20)
	if !ds.offerHelper(helper) {
		helper.Close()
		return
	}
	// Return at once and let the bridge own the socket. Waiting on
	// r.Context() here waited for this handler itself: after the hijack
	// net/http only cancels the context once ServeHTTP returns, so every
	// desktop session used to leak this goroutine and the hijacked
	// connection's buffers for the lifetime of the process.
}

// bridge pumps frames both ways until either side closes. viewer/helper name
// the two ends so the survivor is told which of them went away. The viewer
// side is already being read by vp, started when the socket was upgraded, so
// its frames come from that queue rather than from a second reader.
func bridge(vp *framePump, viewer *websocket.Conn, vw *wsWriter, helper *websocket.Conn, hw *wsWriter) {
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			select {
			case f := <-vp.frames:
				if err := hw.write(f.mt, f.data); err != nil {
					return
				}
			case <-vp.done:
				// deliver what was already read, then say why we are going
				for {
					select {
					case f := <-vp.frames:
						if err := hw.write(f.mt, f.data); err != nil {
							return
						}
					default:
						// Tell the surviving side why it is going away,
						// forwarding the peer's close code when there was one.
						// Without this the other end only sees the TCP close
						// and reports 1006 (abnormal), which the browser
						// viewer cannot tell from a network fault.
						hw.writeClose(closeCodeFor(vp.err, "the viewer"))
						return
					}
				}
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			mt, data, err := helper.ReadMessage()
			if err != nil {
				vw.writeClose(closeCodeFor(err, "the desktop helper"))
				return
			}
			if err := vw.write(mt, data); err != nil {
				return
			}
		}
	}()
	<-done
	viewer.Close()
	helper.Close()
	<-done
	slog.Debug("desktop bridge closed")
}

// maxDesktopsPerAgent bounds concurrent remote desktop sessions against one
// device. Each one runs a separate SYSTEM helper on the device that captures
// and encodes the screen, so this is a load limit on the managed machine, not
// on the server. Two is enough for the real case (an operator opening a second
// view, or reconnecting before the first socket has been reaped) without
// letting a stuck client stack helpers up indefinitely.
const maxDesktopsPerAgent = 2

// desktopCount tracks live desktop sessions per agent.
type desktopCount struct {
	mu sync.Mutex
	n  map[string]int
}

func newDesktopCount() *desktopCount { return &desktopCount{n: map[string]int{}} }

// acquire takes a slot and returns the new count, or -1 when the agent is
// already at the cap.
func (d *desktopCount) acquire(agentID string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.n[agentID] >= maxDesktopsPerAgent {
		return -1
	}
	d.n[agentID]++
	return d.n[agentID]
}

func (d *desktopCount) release(agentID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.n[agentID] <= 1 {
		delete(d.n, agentID) // keep the map from growing one key per agent seen
		return
	}
	d.n[agentID]--
}
