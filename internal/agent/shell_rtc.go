package agent

// WebRTC byte path for the remote terminal. The browser is the offerer and
// creates one ordered data channel labelled "term"; this side answers, so the
// pty bytes travel peer to peer instead of through the server relay. The
// WebSocket relay (ShellChunk on the shell.open stream) stays the fallback
// and keeps carrying open/close lifecycle and signaling.
//
// Framing on the channel: a binary message is raw pty bytes in either
// direction (at most 32 KiB per message); a text message is a JSON control
// frame, {"t":"resize","cols":N,"rows":N} or {"t":"close"}.
//
// Output switch ordering: when the channel opens, the agent first streams a
// ShellSignal{Kind:"switch"} over the relay and only then starts routing pty
// output to the channel. Everything the relay carried is therefore ahead of
// the signal on the stream, and everything after it is on the channel, so the
// browser can buffer channel output until it has seen the signal and the
// byte order is preserved. See docs/TERMINAL-PROTOCOL.md.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/pion/webrtc/v4"
)

const (
	// shellDCLabel is the only data channel the agent accepts.
	shellDCLabel = "term"
	// shellDCChunk is the largest binary message written to the channel.
	shellDCChunk = 32 << 10
	// Backpressure: stop writing above shellDCHigh buffered bytes and resume
	// once the channel reports the buffer drained to shellDCLow.
	shellDCHigh = 1 << 20
	shellDCLow  = 256 << 10
)

// defaultShellICE mirrors the desktop helper and the server's default.
var defaultShellICE = []string{"stun:stun.l.google.com:19302"}

// dcSink is the live data channel output is routed to. done is closed when the
// route is torn down so a writer waiting on backpressure lets go.
type dcSink struct {
	dc   *webrtc.DataChannel
	done chan struct{}
	once sync.Once
}

func (s *dcSink) stop() { s.once.Do(func() { close(s.done) }) }

// shellRTC owns the PeerConnection of one terminal session.
type shellRTC struct {
	id      string
	pty     ptySession
	servers []webrtc.ICEServer
	// send streams a frame to the server on the session's relay stream.
	send func(v any) error
	// onClose ends the whole shell session (the channel's {"t":"close"}).
	onClose func()

	// routeMu orders the relay/channel hand-over: pty output is emitted under
	// it, and so is the switch signal that flips the sink.
	routeMu sync.Mutex
	sink    atomic.Pointer[dcSink]

	mu      sync.Mutex
	pc      *webrtc.PeerConnection
	offered bool // one PeerConnection per session, ever
	closed  bool
	dcSeen  bool // the "term" channel was accepted

	low  chan struct{} // OnBufferedAmountLow wake-ups
	done chan struct{} // closed by close()
}

func newShellRTC(id string, p ptySession, servers []protocol.ICEServer, send func(v any) error, onClose func()) *shellRTC {
	r := &shellRTC{
		id: id, pty: p, send: send, onClose: onClose,
		low: make(chan struct{}, 1), done: make(chan struct{}),
	}
	for _, s := range servers {
		if len(s.URLs) == 0 {
			continue
		}
		srv := webrtc.ICEServer{URLs: s.URLs}
		if s.Username != "" || s.Credential != "" {
			srv.Username = s.Username
			srv.Credential = s.Credential
		}
		r.servers = append(r.servers, srv)
	}
	if len(r.servers) == 0 {
		r.servers = []webrtc.ICEServer{{URLs: defaultShellICE}}
	}
	return r
}

func (r *shellRTC) signal(sig *protocol.ShellSignal) {
	r.send(protocol.ShellChunk{Session: r.id, Sig: sig})
}

// handleSignal applies one browser signaling frame.
func (r *shellRTC) handleSignal(sig protocol.ShellRTC) error {
	switch sig.Kind {
	case "offer":
		return r.acceptOffer(sig.SDP)
	case "candidate":
		return r.addCandidate(sig.Candidate)
	case "fallback":
		r.fallback()
		return nil
	}
	return errors.New("unknown shell.rtc kind " + sig.Kind)
}

func (r *shellRTC) acceptOffer(sdp string) error {
	if sdp == "" {
		return errors.New("empty offer")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("session closed")
	}
	if r.offered {
		return errors.New("a peer connection was already negotiated for this session")
	}
	r.offered = true
	// Data channels only: no media engine, no codecs.
	api := webrtc.NewAPI(webrtc.WithSettingEngine(webrtc.SettingEngine{}))
	pc, err := api.NewPeerConnection(webrtc.Configuration{ICEServers: r.servers})
	if err != nil {
		r.signal(&protocol.ShellSignal{Kind: "unavailable", Reason: err.Error()})
		return err
	}
	r.pc = pc
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		b, err := json.Marshal(c.ToJSON())
		if err != nil {
			return
		}
		r.signal(&protocol.ShellSignal{Kind: "candidate", Candidate: b})
	})
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		switch s {
		case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
			r.fallback()
		}
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		if dc.Label() != shellDCLabel {
			return
		}
		r.mu.Lock()
		if r.dcSeen || r.closed {
			r.mu.Unlock()
			return
		}
		r.dcSeen = true
		r.mu.Unlock()
		r.attachChannel(dc)
	})
	fail := func(err error) error {
		r.signal(&protocol.ShellSignal{Kind: "unavailable", Reason: err.Error()})
		r.pc = nil
		go pc.Close()
		return err
	}
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: sdp}); err != nil {
		return fail(err)
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		return fail(err)
	}
	if err := pc.SetLocalDescription(answer); err != nil {
		return fail(err)
	}
	r.signal(&protocol.ShellSignal{Kind: "answer", SDP: answer.SDP})
	return nil
}

func (r *shellRTC) addCandidate(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var init webrtc.ICECandidateInit
	if err := json.Unmarshal(raw, &init); err != nil {
		return err
	}
	r.mu.Lock()
	pc := r.pc
	r.mu.Unlock()
	if pc == nil {
		return nil // before the offer, or after a fallback
	}
	return pc.AddICECandidate(init)
}

func (r *shellRTC) attachChannel(dc *webrtc.DataChannel) {
	dc.SetBufferedAmountLowThreshold(shellDCLow)
	dc.OnBufferedAmountLow(func() {
		select {
		case r.low <- struct{}{}:
		default:
		}
	})
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		if !msg.IsString {
			if len(msg.Data) > 0 {
				r.pty.Write(msg.Data)
			}
			return
		}
		var c struct {
			T    string `json:"t"`
			Cols int    `json:"cols"`
			Rows int    `json:"rows"`
		}
		if json.Unmarshal(msg.Data, &c) != nil {
			return
		}
		switch c.T {
		case "resize":
			if c.Cols > 0 && c.Rows > 0 {
				r.pty.Resize(c.Cols, c.Rows)
			}
		case "close":
			if r.onClose != nil {
				go r.onClose()
			}
		}
	})
	dc.OnClose(func() { r.fallback() })
	dc.OnOpen(func() {
		// The seam: tell the browser over the relay first, then route.
		r.routeMu.Lock()
		defer r.routeMu.Unlock()
		select {
		case <-r.done:
			return
		default:
		}
		if r.send(protocol.ShellChunk{Session: r.id, Sig: &protocol.ShellSignal{Kind: "switch"}}) != nil {
			return
		}
		r.sink.Store(&dcSink{dc: dc, done: make(chan struct{})})
		slog.Info("shell webrtc: output switched to data channel", "session", r.id)
	})
}

// emit delivers one pty read: over the channel when it is the route, else via
// viaStream (the relay). Called from the pty read loop only.
func (r *shellRTC) emit(b []byte, viaStream func([]byte)) {
	r.routeMu.Lock()
	defer r.routeMu.Unlock()
	s := r.sink.Load()
	if s == nil {
		viaStream(b)
		return
	}
	if rest, ok := r.sendDC(s, b); !ok {
		viaStream(rest)
	}
}

// sendDC writes b to the channel in chunks, waiting out backpressure. It
// returns the unsent rest and false if the route died.
func (r *shellRTC) sendDC(s *dcSink, b []byte) ([]byte, bool) {
	for len(b) > 0 {
		n := len(b)
		if n > shellDCChunk {
			n = shellDCChunk
		}
		for s.dc.BufferedAmount() > shellDCHigh {
			select {
			case <-r.low:
			case <-s.done:
				return b, false
			case <-r.done:
				return b, false
			case <-time.After(100 * time.Millisecond):
			}
		}
		select {
		case <-s.done:
			return b, false
		default:
		}
		if err := s.dc.Send(b[:n]); err != nil {
			r.revert()
			return b, false
		}
		b = b[n:]
	}
	return nil, true
}

// revert sends pty output back over the relay. It does not take routeMu (the
// writer may be holding it while waiting on backpressure).
func (r *shellRTC) revert() {
	if s := r.sink.Swap(nil); s != nil {
		s.stop()
		slog.Info("shell webrtc: output reverted to relay", "session", r.id)
	}
}

// fallback reverts to the relay and tears the PeerConnection down.
func (r *shellRTC) fallback() {
	r.revert()
	r.mu.Lock()
	pc := r.pc
	r.pc = nil
	r.mu.Unlock()
	if pc != nil {
		go pc.Close()
	}
}

// close ends the WebRTC side for good. Idempotent.
func (r *shellRTC) close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	close(r.done)
	r.mu.Unlock()
	r.fallback()
}

// drain waits, up to max, for the data channel's send buffer to empty so the
// tail of the pty output is not discarded when the PeerConnection closes. It
// returns early when the route is gone or the session is closed.
func (r *shellRTC) drain(max time.Duration) {
	s := r.sink.Load()
	if s == nil {
		return
	}
	deadline := time.NewTimer(max)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for s.dc.BufferedAmount() > 0 {
		select {
		case <-tick.C:
		case <-deadline.C:
			return
		case <-s.done:
			return
		case <-r.done:
			return
		}
	}
}
