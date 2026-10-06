package desktop

// WebRTC transport for the desktop helper. The viewer is the offerer: it
// creates a recvonly video transceiver and two SCTP data channels
// ("input-unreliable" for pointer motion, "input-reliable" for everything
// else) and sends an SDP offer. This helper answers with a sendonly H.264
// video track and streams hardware-encoded frames over SRTP, so video and
// input travel peer-to-peer over UDP instead of through the server relay.
//
// Signaling (SDP + trickle ICE) rides the existing viewer<->helper WebSocket,
// which the server bridges verbatim; this file never talks to the server
// directly. If ICE never reaches connected, the viewer falls back to the JPEG
// tile stream after its own 4 s watchdog and this session simply never writes
// video samples.
//
// The one non-obvious requirement is the RTCP reader loop: without draining
// RTCP, a browser that drops a UDP packet freezes forever waiting for a
// reference frame. The loop watches for Picture Loss Indication / Full Intra
// Request and forces an IDR so the picture recovers.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

// defaultHelperICE is the STUN server the helper uses to gather its own
// server-reflexive candidate when none is configured. It mirrors the server's
// default (see internal/server/config.go); a restrictive NAT without TURN on
// either side simply fails to connect and the viewer falls back to tiles.
var defaultHelperICE = []string{"stun:stun.l.google.com:19302"}

// Data-channel labels, matched by the frontend (web/src/pages/device/webrtc.ts).
const (
	dcUnreliable = "input-unreliable"
	dcReliable   = "input-reliable"
)

// rtcSignal is one signaling message on the wire (viewer <-> helper). It is a
// superset of what either side sends; unused fields stay zero.
type rtcSignal struct {
	T         string          `json:"t"`
	SDP       string          `json:"sdp,omitempty"`
	Candidate json.RawMessage `json:"candidate,omitempty"`
	Reason    string          `json:"reason,omitempty"`
}

// webRTCSession owns one PeerConnection for one desktop session.
type webRTCSession struct {
	api   *webrtc.API
	cfg   webrtc.Configuration
	track *webrtc.TrackLocalStaticSample

	// sendSignal writes a signaling message back to the viewer (the session's
	// sendJSON, i.e. a text frame over the bridged WebSocket).
	sendSignal func(v any) error
	// onInput queues one decoded viewer event for the injector thread.
	onInput func(viewerMsg)
	// forceKeyframe is invoked from the RTCP loop on PLI/FIR; it asks the
	// encoder for an immediate IDR. Safe to call from any goroutine.
	forceKeyframe func()

	mu        sync.Mutex
	pc        *webrtc.PeerConnection
	sender    *webrtc.RTPSender
	connected atomic.Bool // ICE/DTLS fully up
	closed    atomic.Bool
}

// newWebRTCSession builds the API and video track but does not create the
// PeerConnection yet: that happens when the viewer's offer arrives, so a
// viewer that offered WebRTC but never completes negotiation costs nothing.
func newWebRTCSession(iceURLs []string, sendSignal func(v any) error, onInput func(viewerMsg), forceKeyframe func()) (*webRTCSession, error) {
	if len(iceURLs) == 0 {
		iceURLs = defaultHelperICE
	}
	me := &webrtc.MediaEngine{}
	if err := me.RegisterDefaultCodecs(); err != nil {
		return nil, err
	}
	api := webrtc.NewAPI(webrtc.WithMediaEngine(me))
	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264},
		"video", "homelab-rmm-desktop",
	)
	if err != nil {
		return nil, err
	}
	return &webRTCSession{
		api:           api,
		cfg:           webrtc.Configuration{ICEServers: []webrtc.ICEServer{{URLs: iceURLs}}},
		track:         track,
		sendSignal:    sendSignal,
		onInput:       onInput,
		forceKeyframe: forceKeyframe,
	}, nil
}

// handleSignal processes one signaling message from the viewer. raw is the
// text frame's bytes. It is called from the reader goroutine only.
func (w *webRTCSession) handleSignal(raw []byte) {
	var sig rtcSignal
	if err := json.Unmarshal(raw, &sig); err != nil {
		slog.Debug("desktop webrtc: bad signal", "err", err)
		return
	}
	switch sig.T {
	case "webrtc_offer":
		if err := w.acceptOffer(sig.SDP); err != nil {
			slog.Warn("desktop webrtc: offer rejected", "err", err)
		}
	case "webrtc_candidate":
		w.addCandidate(sig.Candidate)
	}
}

// acceptOffer creates the PeerConnection (once), applies the remote offer,
// adds the video track, and answers.
func (w *webRTCSession) acceptOffer(sdp string) error {
	if sdp == "" {
		return errors.New("empty offer")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed.Load() {
		return errors.New("session closed")
	}
	if w.pc != nil {
		// A renegotiation offer on the existing connection.
		if err := w.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: sdp}); err != nil {
			return err
		}
		return w.answerLocked()
	}
	pc, err := w.api.NewPeerConnection(w.cfg)
	if err != nil {
		return err
	}
	w.pc = pc

	// Send the sendonly H.264 track; keep the RTPSender for the RTCP loop.
	sender, err := pc.AddTrack(w.track)
	if err != nil {
		pc.Close()
		w.pc = nil
		return err
	}
	w.sender = sender
	go w.rtcpLoop(sender)

	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return // gathering finished
		}
		init := c.ToJSON()
		b, err := json.Marshal(init)
		if err != nil {
			return
		}
		w.sendSignal(map[string]any{"t": "webrtc_candidate", "candidate": json.RawMessage(b)})
	})
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		slog.Info("desktop webrtc: connection state", "state", s.String())
		switch s {
		case webrtc.PeerConnectionStateConnected:
			w.connected.Store(true)
		case webrtc.PeerConnectionStateDisconnected, webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
			w.connected.Store(false)
		}
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		label := dc.Label()
		if label != dcUnreliable && label != dcReliable {
			return
		}
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			if msg.IsString {
				w.dispatchInput(msg.Data)
			}
		})
	})

	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: sdp}); err != nil {
		return err
	}
	return w.answerLocked()
}

// answerLocked creates the answer, sets it locally, and sends it. Caller holds
// w.mu.
func (w *webRTCSession) answerLocked() error {
	answer, err := w.pc.CreateAnswer(nil)
	if err != nil {
		return err
	}
	if err := w.pc.SetLocalDescription(answer); err != nil {
		return err
	}
	return w.sendSignal(map[string]any{"t": "webrtc_answer", "sdp": answer.SDP})
}

// addCandidate applies a trickle ICE candidate from the viewer.
func (w *webRTCSession) addCandidate(raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	var init webrtc.ICECandidateInit
	if err := json.Unmarshal(raw, &init); err != nil {
		slog.Debug("desktop webrtc: bad candidate", "err", err)
		return
	}
	w.mu.Lock()
	pc := w.pc
	w.mu.Unlock()
	if pc == nil {
		return // candidate before the offer; the browser always offers first
	}
	if err := pc.AddICECandidate(init); err != nil {
		slog.Debug("desktop webrtc: add candidate", "err", err)
	}
}

// dispatchInput decodes one data-channel message (the same compact viewer-event
// JSON the WebSocket path uses) and queues it for injection.
func (w *webRTCSession) dispatchInput(data []byte) {
	var msg viewerMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}
	switch msg.T {
	case msgMouseMove, msgMouseDown, msgMouseUp, msgWheel, msgKeyDown, msgKeyUp, msgPaste, msgCtrlAltDel:
		if w.onInput != nil {
			w.onInput(msg)
		}
	}
}

// rtcpLoop drains RTCP from the video sender and forces a keyframe on picture
// loss, the anti-freeze requirement. It ends when the sender is closed.
func (w *webRTCSession) rtcpLoop(sender *webrtc.RTPSender) {
	buf := make([]byte, 1500)
	for {
		n, _, err := sender.Read(buf)
		if err != nil {
			return // sender/pc closed
		}
		pkts, err := rtcp.Unmarshal(buf[:n])
		if err != nil {
			continue
		}
		for _, p := range pkts {
			switch p.(type) {
			case *rtcp.PictureLossIndication, *rtcp.FullIntraRequest:
				if w.forceKeyframe != nil {
					w.forceKeyframe()
				}
			}
		}
	}
}

// videoLive reports whether the connection is up and a video track is
// attached, so the capture loop may start feeding H.264 samples.
func (w *webRTCSession) videoLive() bool {
	return w != nil && w.connected.Load() && !w.closed.Load()
}

// writeVideo sends one encoded access unit on the video track. dur is the
// frame's display duration (used by the packetizer for RTP timestamps).
func (w *webRTCSession) writeVideo(nal []byte, dur time.Duration) error {
	if len(nal) == 0 {
		return nil
	}
	return w.track.WriteSample(media.Sample{Data: nal, Duration: dur})
}

func (w *webRTCSession) close() {
	if w == nil || w.closed.Swap(true) {
		return
	}
	w.mu.Lock()
	pc := w.pc
	w.pc = nil
	w.mu.Unlock()
	if pc != nil {
		pc.Close()
	}
}
