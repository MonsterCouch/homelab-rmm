package desktop

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
)

// newViewerPC builds a browser-like peer: a recvonly video transceiver and the
// two input data channels, exactly as web/src/pages/device/webrtc.ts does.
func newViewerPC(t *testing.T) (*webrtc.PeerConnection, *webrtc.DataChannel, *webrtc.DataChannel) {
	t.Helper()
	me := &webrtc.MediaEngine{}
	if err := me.RegisterDefaultCodecs(); err != nil {
		t.Fatal(err)
	}
	api := webrtc.NewAPI(webrtc.WithMediaEngine(me))
	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
		t.Fatal(err)
	}
	unreliable, err := pc.CreateDataChannel(dcUnreliable, nil)
	if err != nil {
		t.Fatal(err)
	}
	reliable, err := pc.CreateDataChannel(dcReliable, nil)
	if err != nil {
		t.Fatal(err)
	}
	return pc, unreliable, reliable
}

// TestWebRTCSessionEndToEnd wires a real Pion viewer to the helper's
// webRTCSession over loopback and checks the whole contract: ICE connects,
// data-channel input reaches onInput, a written video sample arrives as RTP,
// and a Picture Loss Indication drives ForceKeyframe.
func TestWebRTCSessionEndToEnd(t *testing.T) {
	inputCh := make(chan viewerMsg, 8)
	var keyframes atomic.Int32

	// The viewer is created first so the helper's signals can be routed to it.
	viewer, _, reliable := newViewerPC(t)
	defer viewer.Close()

	var helper *webRTCSession
	deliverToViewer := func(v any) error {
		b, _ := json.Marshal(v)
		var sig rtcSignal
		json.Unmarshal(b, &sig)
		switch sig.T {
		case "webrtc_answer":
			if err := viewer.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: sig.SDP}); err != nil {
				t.Errorf("viewer SetRemoteDescription: %v", err)
			}
		case "webrtc_candidate":
			var init webrtc.ICECandidateInit
			if err := json.Unmarshal(sig.Candidate, &init); err == nil {
				viewer.AddICECandidate(init)
			}
		}
		return nil
	}

	var err error
	helper, err = newWebRTCSession(
		[]string{}, // host candidates connect on loopback without STUN
		deliverToViewer,
		func(m viewerMsg) { inputCh <- m },
		func() { keyframes.Add(1) },
	)
	if err != nil {
		t.Fatal(err)
	}
	defer helper.close()

	// Viewer's trickle candidates go to the helper.
	viewer.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		init := c.ToJSON()
		b, _ := json.Marshal(init)
		helper.handleSignal(mustJSON(t, map[string]any{"t": "webrtc_candidate", "candidate": json.RawMessage(b)}))
	})

	// Capture the inbound video track so we can read RTP and send RTCP back.
	trackCh := make(chan *webrtc.TrackRemote, 1)
	viewer.OnTrack(func(tr *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		select {
		case trackCh <- tr:
		default:
		}
	})

	connected := make(chan struct{})
	var once sync.Once
	viewer.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		if s == webrtc.PeerConnectionStateConnected {
			once.Do(func() { close(connected) })
		}
	})

	// Viewer offers; the helper answers through deliverToViewer.
	offer, err := viewer.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := viewer.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	helper.handleSignal(mustJSON(t, map[string]any{"t": "webrtc_offer", "sdp": offer.SDP}))

	select {
	case <-connected:
	case <-time.After(20 * time.Second):
		t.Fatal("peer connection never reached connected")
	}
	// The helper's own state callback may fire a hair after the viewer's.
	deadlineLive := time.After(5 * time.Second)
	for !helper.videoLive() {
		select {
		case <-deadlineLive:
			t.Fatal("helper does not report video live after connect")
		case <-time.After(20 * time.Millisecond):
		}
	}

	// Input over the reliable data channel must reach onInput.
	waitOpen(t, reliable)
	if err := reliable.SendText(`{"t":"mousedown","button":0,"x":42,"y":99}`); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-inputCh:
		if m.T != msgMouseDown || int(m.X) != 42 || int(m.Y) != 99 {
			t.Fatalf("input not relayed correctly: %+v", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("input never reached onInput")
	}

	// Keep writing video so OnTrack (which fires on the first RTP packet) and
	// the subsequent ReadRTP both have traffic to observe. A minimal Annex B
	// access unit is enough; its contents are irrelevant to transport.
	fakeNAL := []byte{0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x65, 0x88}
	stopWriter := make(chan struct{})
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		tk := time.NewTicker(20 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stopWriter:
				return
			case <-tk.C:
				helper.writeVideo(fakeNAL, 33*time.Millisecond)
			}
		}
	}()
	defer func() { close(stopWriter); <-writeDone }()

	var tr *webrtc.TrackRemote
	select {
	case tr = <-trackCh:
	case <-time.After(8 * time.Second):
		t.Fatal("viewer never saw the video track")
	}
	gotRTP := make(chan struct{})
	go func() {
		if _, _, err := tr.ReadRTP(); err == nil {
			close(gotRTP)
		}
	}()
	select {
	case <-gotRTP:
	case <-time.After(8 * time.Second):
		t.Fatal("no RTP video reached the viewer")
	}

	// Picture loss -> ForceKeyframe.
	if err := viewer.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: uint32(tr.SSRC())}}); err != nil {
		t.Fatalf("viewer WriteRTCP: %v", err)
	}
	deadline := time.After(5 * time.Second)
	for keyframes.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("PLI did not trigger ForceKeyframe")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func waitOpen(t *testing.T, dc *webrtc.DataChannel) {
	t.Helper()
	if dc.ReadyState() == webrtc.DataChannelStateOpen {
		return
	}
	open := make(chan struct{})
	dc.OnOpen(func() { close(open) })
	select {
	case <-open:
	case <-time.After(5 * time.Second):
		t.Fatalf("data channel %q never opened", dc.Label())
	}
}
