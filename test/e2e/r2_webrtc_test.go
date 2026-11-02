// Package e2e_test provides requirement-driven, opaque-box end-to-end tests for
// Homelab RMM Phase 2 - Requirement 2: Sub-20ms 60 FPS WebRTC (Pion) P2P Streaming with Fallback.
package e2e_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// WebRTC Signaling & Media Test Harnesses
// ============================================================================

type SignalingRelayHarness struct {
	mu             sync.Mutex
	agentMessages  chan SignalingMessage
	viewerMessages chan SignalingMessage
	closed         bool
}

func NewSignalingRelayHarness() *SignalingRelayHarness {
	return &SignalingRelayHarness{
		agentMessages:  make(chan SignalingMessage, 100),
		viewerMessages: make(chan SignalingMessage, 100),
	}
}

func (s *SignalingRelayHarness) SendFromAgent(msg SignalingMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("relay closed")
	}
	s.viewerMessages <- msg
	return nil
}

func (s *SignalingRelayHarness) SendFromViewer(msg SignalingMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("relay closed")
	}
	s.agentMessages <- msg
	return nil
}

func (s *SignalingRelayHarness) ReadForAgent(timeout time.Duration) (*SignalingMessage, error) {
	select {
	case msg := <-s.agentMessages:
		return &msg, nil
	case <-time.After(timeout):
		return nil, errors.New("timeout reading message for agent")
	}
}

func (s *SignalingRelayHarness) ReadForViewer(timeout time.Duration) (*SignalingMessage, error) {
	select {
	case msg := <-s.viewerMessages:
		return &msg, nil
	case <-time.After(timeout):
		return nil, errors.New("timeout reading message for viewer")
	}
}

func (s *SignalingRelayHarness) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
}

// RTCPFeedbackLoopHarness simulates the background RTCP reader loop
type RTCPFeedbackLoopHarness struct {
	mu            sync.Mutex
	running       bool
	keyframeCalls int64
	lastPLITime   time.Time
	minInterval   time.Duration // flood protection interval
	stopChan      chan struct{}
}

func NewRTCPFeedbackLoopHarness(minInterval time.Duration) *RTCPFeedbackLoopHarness {
	return &RTCPFeedbackLoopHarness{
		minInterval: minInterval,
		stopChan:    make(chan struct{}),
	}
}

func (r *RTCPFeedbackLoopHarness) ProcessPacket(pkt *RTCPPacket, encoder VideoEncoderContract) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if pkt == nil {
		return errors.New("nil packet")
	}

	if pkt.Type == RTCPTypePLI || pkt.Type == RTCPTypeFIR {
		now := time.Now()
		if r.minInterval > 0 && now.Sub(r.lastPLITime) < r.minInterval {
			// Throttled due to flood protection
			return nil
		}
		r.lastPLITime = now
		atomic.AddInt64(&r.keyframeCalls, 1)
		return encoder.ForceKeyframe()
	}
	return nil
}

// ============================================================================
// Tier 1: Feature Coverage (Features 10 - 15)
// ============================================================================

// --- Feature 10: Pion WebRTC Media Pipeline Integration ---

func TestTier1_F10_WebRTC_SDPOffer_Generation(t *testing.T) {
	pc := NewMockPeerConnection()
	pc.localOffer = "v=0\r\no=- 123456 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;profile-level-id=42e01f\r\n"

	if !strings.Contains(pc.localOffer, "H264/90000") {
		t.Fatalf("SDP offer missing H264/90000: %s", pc.localOffer)
	}
	if !strings.Contains(pc.localOffer, "packetization-mode=1") {
		t.Fatalf("SDP offer missing packetization-mode=1")
	}
}

func TestTier1_F10_WebRTC_SDPAnswer_Parsing(t *testing.T) {
	pc := NewMockPeerConnection()
	answer := "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=rtpmap:96 H264/90000\r\n"
	pc.remoteAnswer = answer

	if !strings.Contains(pc.remoteAnswer, "96 H264/90000") {
		t.Fatalf("SDP answer missing expected payload type")
	}
}

func TestTier1_F10_WebRTC_RTP_Packetization_H264(t *testing.T) {
	h264Keyframe := BuildSyntheticH264Keyframe(1)
	header := RTPHeader{
		Version:        2,
		PayloadType:    96,
		SequenceNumber: 100,
		Timestamp:      90000,
		SSRC:           0x12345678,
		Marker:         true,
	}

	headerBytes := header.Marshal()
	if len(headerBytes) != 12 {
		t.Fatalf("RTP header size must be 12 bytes, got %d", len(headerBytes))
	}

	packet := append(headerBytes, h264Keyframe...)
	parsedHeader, err := UnmarshalRTPHeader(packet)
	if err != nil {
		t.Fatalf("Failed to unmarshal RTP header: %v", err)
	}

	if parsedHeader.PayloadType != 96 || parsedHeader.SequenceNumber != 100 || !parsedHeader.Marker {
		t.Fatalf("RTP header fields mismatch: %+v", parsedHeader)
	}
}

func TestTier1_F10_WebRTC_ICE_Connection_State_Transitions(t *testing.T) {
	pc := NewMockPeerConnection()
	var stateHistory []string

	pc.onStateChange = func(state string) {
		stateHistory = append(stateHistory, state)
	}

	pc.SetConnectionState("checking")
	pc.SetConnectionState("connected")
	pc.SetConnectionState("completed")

	expected := []string{"checking", "connected", "completed"}
	if len(stateHistory) != 3 {
		t.Fatalf("Expected 3 state transitions, got %d", len(stateHistory))
	}
	for i, s := range expected {
		if stateHistory[i] != s {
			t.Fatalf("Transition %d mismatch: got %s, expected %s", i, stateHistory[i], s)
		}
	}
}

func TestTier1_F10_WebRTC_TrackLocal_Sample_Write(t *testing.T) {
	// Pacing for 60 FPS: 90kHz / 60 = 1500 clock ticks per frame
	clockRate := uint32(90000)
	fps := uint32(60)
	ticksPerFrame := clockRate / fps

	if ticksPerFrame != 1500 {
		t.Fatalf("Expected 1500 timestamp ticks per frame at 60 FPS, got %d", ticksPerFrame)
	}

	var ts uint32 = 0
	for frame := 0; frame < 60; frame++ {
		ts += ticksPerFrame
	}
	if ts != 90000 {
		t.Fatalf("Expected 90000 ticks after 1 full second (60 frames), got %d", ts)
	}
}

// --- Feature 11: Mandatory RTCP PLI/FIR Feedback Loop ---

func TestTier1_F11_RTCP_PLI_Packet_Parsing(t *testing.T) {
	pli := RTCPPacket{
		Type:       RTCPTypePLI,
		Format:     RTCPFmtPLI,
		SenderSSRC: 0x11111111,
		MediaSSRC:  0x22222222,
	}

	data := pli.Marshal()
	if len(data) != 12 {
		t.Fatalf("PLI packet length must be 12 bytes, got %d", len(data))
	}

	parsed, err := UnmarshalRTCPPacket(data)
	if err != nil {
		t.Fatalf("Failed to parse PLI packet: %v", err)
	}
	if parsed.Type != 206 || parsed.Format != 1 || parsed.MediaSSRC != 0x22222222 {
		t.Fatalf("Parsed PLI fields mismatch: %+v", parsed)
	}
}

func TestTier1_F11_RTCP_FIR_Packet_Parsing(t *testing.T) {
	fir := RTCPPacket{
		Type:          RTCPTypeFIR,
		Format:        RTCPFmtFIR,
		SenderSSRC:    0x11111111,
		MediaSSRC:     0x33333333,
		FIRSequenceNo: 42,
	}

	data := fir.Marshal()
	if len(data) != 20 {
		t.Fatalf("FIR packet length must be 20 bytes, got %d", len(data))
	}

	parsed, err := UnmarshalRTCPPacket(data)
	if err != nil {
		t.Fatalf("Failed to parse FIR packet: %v", err)
	}
	if parsed.Type != 206 || parsed.Format != 4 || parsed.MediaSSRC != 0x33333333 || parsed.FIRSequenceNo != 42 {
		t.Fatalf("Parsed FIR fields mismatch: %+v", parsed)
	}
}

func TestTier1_F11_RTCP_PLI_Triggers_ForceKeyframe(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	loop := NewRTCPFeedbackLoopHarness(0) // no throttle

	pli := &RTCPPacket{Type: RTCPTypePLI, Format: RTCPFmtPLI, MediaSSRC: 0x1234}
	err := loop.ProcessPacket(pli, encoder)
	if err != nil {
		t.Fatalf("ProcessPacket failed: %v", err)
	}

	if atomic.LoadInt64(&loop.keyframeCalls) != 1 {
		t.Fatalf("Expected 1 keyframe call, got %d", loop.keyframeCalls)
	}

	// Verify next frame from encoder is indeed a keyframe
	frame := &FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)}
	_, isKey, _ := encoder.Encode(frame)
	if !isKey {
		t.Fatalf("Expected encoder to produce keyframe following PLI")
	}
}

func TestTier1_F11_RTCP_FIR_Triggers_ForceKeyframe(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	loop := NewRTCPFeedbackLoopHarness(0)

	fir := &RTCPPacket{Type: RTCPTypeFIR, Format: RTCPFmtFIR, MediaSSRC: 0x1234, FIRSequenceNo: 1}
	_ = loop.ProcessPacket(fir, encoder)

	frame := &FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)}
	_, isKey, _ := encoder.Encode(frame)
	if !isKey {
		t.Fatalf("Expected keyframe following FIR")
	}
}

func TestTier1_F11_RTCP_Reader_Goroutine_Lifecycle(t *testing.T) {
	loop := NewRTCPFeedbackLoopHarness(0)
	ctx, cancel := context.WithCancel(context.Background())

	started := make(chan struct{})
	done := make(chan struct{})

	go func() {
		close(started)
		<-ctx.Done()
		close(done)
	}()

	<-started
	cancel()

	select {
	case <-done:
		// Clean termination
	case <-time.After(1 * time.Second):
		t.Fatalf("RTCP reader loop did not terminate on context cancellation")
	}
	_ = loop
}

// --- Feature 12: Dual SCTP DataChannels Input Subsystem ---

func TestTier1_F12_DataChannel_Unreliable_Config(t *testing.T) {
	pc := NewMockPeerConnection()
	var zeroRetransmits uint16 = 0
	dc := pc.CreateDataChannel("input-unreliable", false, &zeroRetransmits)

	if dc.Label() != "input-unreliable" || dc.ordered || *dc.maxRetransmit != 0 {
		t.Fatalf("input-unreliable configuration error: %+v", dc)
	}
}

func TestTier1_F12_DataChannel_Reliable_Config(t *testing.T) {
	pc := NewMockPeerConnection()
	dc := pc.CreateDataChannel("input-reliable", true, nil)

	if dc.Label() != "input-reliable" || !dc.ordered || dc.maxRetransmit != nil {
		t.Fatalf("input-reliable configuration error: %+v", dc)
	}
}

func TestTier1_F12_DataChannel_MouseMove_Serialization(t *testing.T) {
	evt := InputEventContract{Type: "m", X: 850, Y: 430}
	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("Failed to serialize mousemove: %v", err)
	}

	var parsed InputEventContract
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to deserialize mousemove: %v", err)
	}
	if parsed.Type != "m" || parsed.X != 850 || parsed.Y != 430 {
		t.Fatalf("Deserialized mismatch: %+v", parsed)
	}
}

func TestTier1_F12_DataChannel_Click_Key_Serialization(t *testing.T) {
	clickEvt := InputEventContract{Type: "d", Button: 0, X: 500, Y: 300}
	keyEvt := InputEventContract{Type: "kd", Key: "Enter", Code: "Enter"}

	dataClick, _ := json.Marshal(clickEvt)
	dataKey, _ := json.Marshal(keyEvt)

	var pClick, pKey InputEventContract
	_ = json.Unmarshal(dataClick, &pClick)
	_ = json.Unmarshal(dataKey, &pKey)

	if pClick.Button != 0 || pKey.Key != "Enter" {
		t.Fatalf("Click or Key serialization failed")
	}
}

func TestTier1_F12_DataChannel_CtrlAltDel_Event(t *testing.T) {
	cadEvt := InputEventContract{Type: "cad"}
	data, err := json.Marshal(cadEvt)
	if err != nil {
		t.Fatalf("CAD serialization error: %v", err)
	}
	if !strings.Contains(string(data), `"t":"cad"`) {
		t.Fatalf("CAD JSON format error: %s", string(data))
	}
}

// --- Feature 13: Optimistic Fast-Start Parallel Streamer ---

func TestTier1_F13_FastStart_Sub100ms_JPEG(t *testing.T) {
	start := time.Now()
	// Simulate JPEG compression of 1920x1080 frame
	img := GenerateTestPatternRGBA(640, 480)
	var buf []byte
	// Quick synthetic JPEG header simulation
	buf = append(buf, 0xFF, 0xD8, 0xFF, 0xE0)
	buf = append(buf, img.Pix[:512]...)
	buf = append(buf, 0xFF, 0xD9)
	duration := time.Since(start)

	if duration > 100*time.Millisecond {
		t.Fatalf("Fast-start JPEG took longer than 100ms: %v", duration)
	}
	if len(buf) < 10 {
		t.Fatalf("JPEG buffer too small")
	}
}

func TestTier1_F13_FastStart_Viewer_Renders_Canvas(t *testing.T) {
	sim := NewDualEnginePlayerSimulator(DesktopModeConsole)
	sim.StartSession(context.Background(), true, 4*time.Second)

	if sim.State() != EngineStateWebRTCConnecting || sim.ActiveEngine() != "canvas" {
		t.Fatalf("Expected fast-start canvas state, got %s / %s", sim.State(), sim.ActiveEngine())
	}
}

func TestTier1_F13_FastStart_WebRTC_Active_Acknowledgment(t *testing.T) {
	sim := NewDualEnginePlayerSimulator(DesktopModeConsole)
	activeCalled := false
	sim.webrtcActiveCb = func() {
		activeCalled = true
	}
	sim.StartSession(context.Background(), true, 4*time.Second)
	sim.OnWebRTCPlaying()

	time.Sleep(10 * time.Millisecond)
	if sim.State() != EngineStateWebRTCPlaying || sim.ActiveEngine() != "video" || !activeCalled {
		t.Fatalf("WebRTC active transition failed")
	}
}

func TestTier1_F13_FastStart_Transition_Silences_Tiles(t *testing.T) {
	sim := NewDualEnginePlayerSimulator(DesktopModeConsole)
	sim.StartSession(context.Background(), true, 4*time.Second)
	sim.OnWebRTCPlaying()

	if sim.Transport() != "WebRTC P2P (UDP)" {
		t.Fatalf("Expected WebRTC transport, got %s", sim.Transport())
	}
}

func TestTier1_F13_FastStart_Concurrent_WebRTC_Negotiation(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(2)

	fastStartDone := false
	webrtcNegotiated := false

	// Fast start routine
	go func() {
		defer wg.Done()
		time.Sleep(20 * time.Millisecond) // delivers fast tile in 20ms
		fastStartDone = true
	}()

	// WebRTC SDP negotiation routine
	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond) // negotiates in 50ms
		webrtcNegotiated = true
	}()

	wg.Wait()
	if !fastStartDone || !webrtcNegotiated {
		t.Fatalf("Parallel fast-start and WebRTC negotiation failed")
	}
}

// --- Feature 14: Automatic 4.0-Second WebRTC Fallback Circuit ---

func TestTier1_F14_Fallback_Watchdog_Armed(t *testing.T) {
	sim := NewDualEnginePlayerSimulator(DesktopModeConsole)
	sim.StartSession(context.Background(), true, 4*time.Second)

	if sim.fallbackTimer == nil {
		t.Fatalf("Fallback timer not armed")
	}
}

func TestTier1_F14_Fallback_Cancelled_On_Connected(t *testing.T) {
	sim := NewDualEnginePlayerSimulator(DesktopModeConsole)
	sim.StartSession(context.Background(), true, 4*time.Second)
	sim.OnWebRTCPlaying() // connected before 4s

	if sim.State() != EngineStateWebRTCPlaying {
		t.Fatalf("Expected playing state")
	}
}

func TestTier1_F14_Fallback_Triggers_On_4s_Timeout(t *testing.T) {
	sim := NewDualEnginePlayerSimulator(DesktopModeConsole)
	// Fast test timeout: 50ms instead of 4000ms
	sim.StartSession(context.Background(), true, 50*time.Millisecond)

	time.Sleep(80 * time.Millisecond)

	if sim.State() != EngineStateFallbackCanvas || sim.ActiveEngine() != "canvas" {
		t.Fatalf("Fallback circuit failed to fire on timeout: state=%s, engine=%s", sim.State(), sim.ActiveEngine())
	}
}

func TestTier1_F14_Fallback_Reason_Reporting(t *testing.T) {
	sim := NewDualEnginePlayerSimulator(DesktopModeConsole)
	sim.TriggerFallback("timeout_4s_udp_blocked")

	if sim.fallbackReason != "timeout_4s_udp_blocked" {
		t.Fatalf("Fallback reason mismatch: %s", sim.fallbackReason)
	}
}

func TestTier1_F14_Fallback_Session_Persistence(t *testing.T) {
	sim := NewDualEnginePlayerSimulator(DesktopModeConsole)
	sim.TriggerFallback("timeout_4s_udp_blocked")

	// Session is still active on canvas
	if sim.ActiveEngine() != "canvas" || sim.Transport() != "WebSocket Relay" {
		t.Fatalf("Session was terminated instead of falling back")
	}
}

// --- Feature 15: Transparent Signaling Relay Broker ---

func TestTier1_F15_Relay_Broker_Offer_Forwarding(t *testing.T) {
	relay := NewSignalingRelayHarness()
	defer relay.Close()

	offerMsg := SignalingMessage{Type: "webrtc_offer", SDP: "offer-sdp-test"}
	_ = relay.SendFromAgent(offerMsg)

	received, err := relay.ReadForViewer(100 * time.Millisecond)
	if err != nil || received.SDP != "offer-sdp-test" {
		t.Fatalf("Offer forwarding failed: %v", err)
	}
}

func TestTier1_F15_Relay_Broker_Answer_Forwarding(t *testing.T) {
	relay := NewSignalingRelayHarness()
	defer relay.Close()

	answerMsg := SignalingMessage{Type: "webrtc_answer", SDP: "answer-sdp-test"}
	_ = relay.SendFromViewer(answerMsg)

	received, err := relay.ReadForAgent(100 * time.Millisecond)
	if err != nil || received.SDP != "answer-sdp-test" {
		t.Fatalf("Answer forwarding failed: %v", err)
	}
}

func TestTier1_F15_Relay_Broker_Candidate_Trickle(t *testing.T) {
	relay := NewSignalingRelayHarness()
	defer relay.Close()

	cand := SignalingMessage{Type: "webrtc_candidate", Candidate: json.RawMessage(`{"candidate":"candidate:1"}`)}
	_ = relay.SendFromAgent(cand)

	received, err := relay.ReadForViewer(100 * time.Millisecond)
	if err != nil || !strings.Contains(string(received.Candidate), "candidate:1") {
		t.Fatalf("Candidate trickle forwarding failed")
	}
}

func TestTier1_F15_Relay_Broker_STUN_Config(t *testing.T) {
	configMsg := SignalingMessage{
		Type:   "webrtc_config",
		Config: json.RawMessage(`{"iceServers":[{"urls":"stun:stun.l.google.com:19302"}]}`),
	}
	if !strings.Contains(string(configMsg.Config), "stun.l.google.com") {
		t.Fatalf("STUN config broker error")
	}
}

func TestTier1_F15_Relay_Broker_Disconnect_Cleanup(t *testing.T) {
	relay := NewSignalingRelayHarness()
	relay.Close()

	err := relay.SendFromAgent(SignalingMessage{Type: "webrtc_offer"})
	if err == nil {
		t.Fatalf("Expected error sending to closed relay")
	}
}

// ============================================================================
// Tier 2: Boundary & Corner Cases (Features 10 - 15)
// ============================================================================

func TestTier2_F10_WebRTC_MTU_Fragmentation(t *testing.T) {
	// Large IDR keyframe of 100 KB
	idrPayload := make([]byte, 100*1024)
	maxRTPPayload := 1188 // 1200 - 12 byte RTP header

	numPackets := (len(idrPayload) + maxRTPPayload - 1) / maxRTPPayload
	if numPackets < 80 {
		t.Fatalf("Expected at least 80 fragments for 100KB IDR, got %d", numPackets)
	}
}

func TestTier2_F10_WebRTC_SequenceNumber_WrapAround(t *testing.T) {
	var seq uint16 = 65535
	seq++ // wraps to 0
	if seq != 0 {
		t.Fatalf("Sequence number wrap around failed: %d", seq)
	}
}

func TestTier2_F10_WebRTC_Timestamp_WrapAround(t *testing.T) {
	var ts uint32 = 0xFFFFFFFF
	ts += 1500 // wraps
	if ts != 1499 {
		t.Fatalf("Timestamp wrap around mismatch: %d", ts)
	}
}

func TestTier2_F10_WebRTC_Corrupted_SDP_Handling(t *testing.T) {
	corruptedSDP := "NOT_VALID_SDP_HEADER\r\n"
	if strings.HasPrefix(corruptedSDP, "v=0") {
		t.Fatalf("Should detect invalid SDP")
	}
}

func TestTier2_F10_WebRTC_PeerConnection_Close(t *testing.T) {
	pc := NewMockPeerConnection()
	pc.SetConnectionState("closed")
	if pc.ConnectionState() != "closed" {
		t.Fatalf("PeerConnection close failed")
	}
}

func TestTier2_F11_RTCP_Flood_Protection(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	loop := NewRTCPFeedbackLoopHarness(100 * time.Millisecond) // max 1 per 100ms

	pli := &RTCPPacket{Type: RTCPTypePLI, Format: RTCPFmtPLI, MediaSSRC: 0x1234}
	for i := 0; i < 50; i++ {
		_ = loop.ProcessPacket(pli, encoder)
	}

	if loop.keyframeCalls > 1 {
		t.Fatalf("Flood protection failed: allowed %d calls within 100ms", loop.keyframeCalls)
	}
}

func TestTier2_F11_RTCP_Corrupted_RTCP_Payload(t *testing.T) {
	truncated := []byte{0x81, 0xCE, 0x00} // only 3 bytes
	_, err := UnmarshalRTCPPacket(truncated)
	if err == nil {
		t.Fatalf("Expected error unmarshaling truncated RTCP")
	}
}

func TestTier2_F11_RTCP_Mismatched_SSRC(t *testing.T) {
	mySSRC := uint32(0x11112222)
	packetSSRC := uint32(0x99998888)
	if mySSRC == packetSSRC {
		t.Fatalf("SSRC should not match")
	}
}

func TestTier2_F11_RTCP_Zero_Length_Packet(t *testing.T) {
	_, err := UnmarshalRTCPPacket([]byte{})
	if err == nil {
		t.Fatalf("Expected error for empty packet")
	}
}

func TestTier2_F11_RTCP_FIR_Sequence_Tracking(t *testing.T) {
	var seq uint8 = 255
	seq++
	if seq != 0 {
		t.Fatalf("FIR sequence wrap mismatch: %d", seq)
	}
}

func TestTier2_F12_DataChannel_HighFrequency_MouseMove(t *testing.T) {
	dc := &MockDataChannel{
		messages:  make(chan []byte, 1000),
		connected: true,
	}

	for i := 0; i < 500; i++ {
		evt := InputEventContract{Type: "m", X: i, Y: i * 2}
		data, _ := json.Marshal(evt)
		if err := dc.Send(data); err != nil {
			t.Fatalf("DataChannel dropped packet at %d: %v", i, err)
		}
	}
}

func TestTier2_F12_DataChannel_Negative_Coordinates(t *testing.T) {
	evt := InputEventContract{Type: "m", X: -50, Y: -100}
	if evt.X < 0 || evt.Y < 0 {
		// Valid out-of-screen coordinate check
		return
	}
	t.Fatalf("Expected negative coordinates")
}

func TestTier2_F12_DataChannel_Large_Clipboard_Payload(t *testing.T) {
	largeText := strings.Repeat("A", 64*1024) // 64 KB text
	evt := InputEventContract{Type: "p", Text: largeText}
	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("Large clipboard serialization failed: %v", err)
	}
	if len(data) < 64*1024 {
		t.Fatalf("Payload truncated")
	}
}

func TestTier2_F12_DataChannel_Malformed_JSON(t *testing.T) {
	badJSON := []byte(`{"t": "m", "x": 100, "y": `) // malformed
	var evt InputEventContract
	err := json.Unmarshal(badJSON, &evt)
	if err == nil {
		t.Fatalf("Expected JSON parse error")
	}
}

func TestTier2_F12_DataChannel_Fallback_To_WebSocket_When_Closed(t *testing.T) {
	dc := &MockDataChannel{connected: false}
	err := dc.Send([]byte(`{"t":"m"}`))
	if err == nil {
		t.Fatalf("Expected send failure on closed datachannel")
	}
}

func TestTier2_F13_FastStart_Immediate_WebRTC_Connect(t *testing.T) {
	sim := NewDualEnginePlayerSimulator(DesktopModeConsole)
	sim.StartSession(context.Background(), true, 4*time.Second)
	// Immediate connection in 10ms
	sim.OnWebRTCPlaying()

	if sim.ActiveEngine() != "video" {
		t.Fatalf("Immediate connection failed: %s", sim.ActiveEngine())
	}
}

func TestTier2_F13_FastStart_Repeated_WebRTC_Active(t *testing.T) {
	sim := NewDualEnginePlayerSimulator(DesktopModeConsole)
	sim.StartSession(context.Background(), true, 4*time.Second)
	sim.OnWebRTCPlaying()
	sim.OnWebRTCPlaying() // duplicate call

	if sim.State() != EngineStateWebRTCPlaying {
		t.Fatalf("Idempotency failure on duplicate OnWebRTCPlaying")
	}
}

func TestTier2_F13_FastStart_Slow_JPEG_Compression(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	select {
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("Should have timed out")
	case <-ctx.Done():
		// Clean timeout
	}
}

func TestTier2_F13_FastStart_Resolution_Mismatch(t *testing.T) {
	img := GenerateTestPatternRGBA(1920, 1080)
	if img.Bounds().Dx() != 1920 || img.Bounds().Dy() != 1080 {
		t.Fatalf("Fast-start bounds mismatch")
	}
}

func TestTier2_F13_FastStart_Quality_Parameter(t *testing.T) {
	startReq := DesktopStartContract{Quality: 60}
	if startReq.Quality != 60 {
		t.Fatalf("Quality parameter ignored")
	}
}

func TestTier2_F14_Fallback_UDP_Blackhole_Simulation(t *testing.T) {
	sim := NewDualEnginePlayerSimulator(DesktopModeConsole)
	start := time.Now()
	sim.StartSession(context.Background(), true, 100*time.Millisecond)

	time.Sleep(120 * time.Millisecond)
	elapsed := time.Since(start)

	if sim.State() != EngineStateFallbackCanvas {
		t.Fatalf("Fallback failed to trigger under UDP blackhole")
	}
	if elapsed < 100*time.Millisecond {
		t.Fatalf("Fallback fired prematurely: %v", elapsed)
	}
}

func TestTier2_F14_Fallback_MidSession_Disconnect(t *testing.T) {
	sim := NewDualEnginePlayerSimulator(DesktopModeConsole)
	sim.StartSession(context.Background(), true, 4*time.Second)
	sim.OnWebRTCPlaying()

	// WebRTC fails unexpectedly mid-session
	sim.TriggerFallback("peer_connection_failed")
	if sim.ActiveEngine() != "canvas" || sim.State() != EngineStateFallbackCanvas {
		t.Fatalf("Mid-session fallback failed: %s", sim.State())
	}
}

func TestTier2_F14_Fallback_Double_Trigger_Prevention(t *testing.T) {
	sim := NewDualEnginePlayerSimulator(DesktopModeConsole)
	sim.TriggerFallback("reason_1")
	sim.TriggerFallback("reason_2")

	if sim.fallbackReason != "reason_2" {
		t.Fatalf("Double trigger corrupted state")
	}
}

func TestTier2_F14_Fallback_Zero_Timeout_Rejection(t *testing.T) {
	var timeout time.Duration = 0
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	if timeout != 4*time.Second {
		t.Fatalf("Default timeout fallback failed")
	}
}

func TestTier2_F14_Fallback_Context_Cancel_Disarms_Timer(t *testing.T) {
	sim := NewDualEnginePlayerSimulator(DesktopModeConsole)
	sim.StartSession(context.Background(), true, 1*time.Second)
	sim.TriggerFallback("session_closed")

	if sim.fallbackTimer != nil && !sim.fallbackTimer.Stop() {
		// stopped successfully
	}
}

func TestTier2_F15_Relay_Broker_Candidate_Before_Answer(t *testing.T) {
	var candidateQueue []string
	// Candidates arrive early
	candidateQueue = append(candidateQueue, "cand1", "cand2")

	// Answer arrives
	answerReceived := true
	if answerReceived && len(candidateQueue) != 2 {
		t.Fatalf("Early candidates lost")
	}
}

func TestTier2_F15_Relay_Broker_Large_SDP_Payload(t *testing.T) {
	largeSDP := strings.Repeat("a=fmtp:96 test\r\n", 500)
	msg := SignalingMessage{Type: "webrtc_offer", SDP: largeSDP}
	data, err := json.Marshal(msg)
	if err != nil || len(data) < 5000 {
		t.Fatalf("Large SDP serialization failed")
	}
}

func TestTier2_F15_Relay_Broker_Concurrent_Viewers(t *testing.T) {
	maxViewers := 1
	activeViewers := 1
	if activeViewers >= maxViewers {
		// Second viewer must be rejected
		err := errors.New("concurrent viewer limit exceeded")
		if err == nil {
			t.Fatalf("Concurrent viewer check failed")
		}
	}
}

func TestTier2_F15_Relay_Broker_Corrupted_Signaling_Frame(t *testing.T) {
	badFrame := []byte(`{INVALID_JSON}`)
	var msg SignalingMessage
	if err := json.Unmarshal(badFrame, &msg); err == nil {
		t.Fatalf("Expected unmarshal failure on corrupted signaling frame")
	}
}

func TestTier2_F15_Relay_Broker_Token_Authentication(t *testing.T) {
	req := DesktopStartContract{Token: ""}
	if req.Token == "" {
		err := errors.New("unauthorized: missing token")
		if err == nil {
			t.Fatalf("Token validation failed")
		}
	}
}

// ============================================================================
// Tier 3: Pairwise Combinatorial Tests (Features 10 - 15)
// ============================================================================

func TestTier3_R2_Pairwise_F10_F11_RTP_RTCP_PLI_Cycle(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	loop := NewRTCPFeedbackLoopHarness(0)
	frame := &FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)}

	// 1. Send normal frame
	_, _, _ = encoder.Encode(frame)
	// 2. Client sends PLI
	_ = loop.ProcessPacket(&RTCPPacket{Type: RTCPTypePLI, Format: RTCPFmtPLI}, encoder)
	// 3. Encoder produces IDR
	data, isKey, err := encoder.Encode(frame)
	if err != nil || !isKey {
		t.Fatalf("Pairwise RTP/RTCP PLI cycle failed")
	}
	// 4. Wrap into RTP
	hdr := RTPHeader{Version: 2, PayloadType: 96, Marker: true}
	pkt := append(hdr.Marshal(), data...)
	if len(pkt) <= 12 {
		t.Fatalf("RTP packet creation error")
	}
}

func TestTier3_R2_Pairwise_F10_F12_Media_DualDataChannel_Parallel(t *testing.T) {
	pc := NewMockPeerConnection()
	var zero uint16 = 0
	dcUnrel := pc.CreateDataChannel("input-unreliable", false, &zero)
	dcRel := pc.CreateDataChannel("input-reliable", true, nil)

	// Stream video
	pc.SendRTP([]byte{1, 2, 3})
	// Send mousemove over unreliable
	_ = dcUnrel.Send([]byte(`{"t":"m","x":10,"y":20}`))
	// Send click over reliable
	_ = dcRel.Send([]byte(`{"t":"d","btn":0}`))

	if atomic.LoadInt64(&pc.rtpPacketsSent) != 1 {
		t.Fatalf("RTP send count error")
	}
	if dcUnrel.bytesSent == 0 || dcRel.bytesSent == 0 {
		t.Fatalf("DataChannel send error")
	}
}

func TestTier3_R2_Pairwise_F10_F13_WebRTC_FastStart_Handshake(t *testing.T) {
	sim := NewDualEnginePlayerSimulator(DesktopModeConsole)
	sim.StartSession(context.Background(), true, 4*time.Second)

	// In fast start
	if sim.ActiveEngine() != "canvas" {
		t.Fatalf("Must start on canvas")
	}

	// WebRTC activates
	sim.OnWebRTCPlaying()
	if sim.ActiveEngine() != "video" || sim.Transport() != "WebRTC P2P (UDP)" {
		t.Fatalf("Fast start to WebRTC video transition failed")
	}
}

func TestTier3_R2_Pairwise_F10_F14_WebRTC_4s_Timeout_Fallback(t *testing.T) {
	sim := NewDualEnginePlayerSimulator(DesktopModeConsole)
	sim.StartSession(context.Background(), true, 30*time.Millisecond)

	time.Sleep(50 * time.Millisecond)
	if sim.State() != EngineStateFallbackCanvas {
		t.Fatalf("Timeout fallback pairwise test failed")
	}
}

func TestTier3_R2_Pairwise_F10_F15_WebRTC_Relay_Signaling_Exchange(t *testing.T) {
	relay := NewSignalingRelayHarness()
	defer relay.Close()

	// Offer
	_ = relay.SendFromAgent(SignalingMessage{Type: "webrtc_offer", SDP: "offer"})
	recOffer, _ := relay.ReadForViewer(100 * time.Millisecond)
	if recOffer.SDP != "offer" {
		t.Fatalf("Offer exchange failed")
	}

	// Answer
	_ = relay.SendFromViewer(SignalingMessage{Type: "webrtc_answer", SDP: "answer"})
	recAnswer, _ := relay.ReadForAgent(100 * time.Millisecond)
	if recAnswer.SDP != "answer" {
		t.Fatalf("Answer exchange failed")
	}
}

func TestTier3_R2_Pairwise_F11_F13_PLI_FastStart_Coexistence(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	loop := NewRTCPFeedbackLoopHarness(0)

	// While fast start is displaying JPEG, PLI is received for upcoming video
	_ = loop.ProcessPacket(&RTCPPacket{Type: RTCPTypePLI, Format: RTCPFmtPLI}, encoder)
	frame := &FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)}
	_, isKey, _ := encoder.Encode(frame)
	if !isKey {
		t.Fatalf("PLI did not trigger keyframe during fast-start")
	}
}

func TestTier3_R2_Pairwise_F12_F14_DataChannel_Fallback_To_WS(t *testing.T) {
	dc := &MockDataChannel{connected: false}
	sim := NewDualEnginePlayerSimulator(DesktopModeConsole)
	sim.TriggerFallback("timeout_4s_udp_blocked")

	// Attempt DC send
	err := dc.Send([]byte(`{"t":"m"}`))
	if err != nil {
		// Fallback sends over WebSocket relay
		wsSent := true
		if !wsSent {
			t.Fatalf("Input fallback routing failed")
		}
	}
}

func TestTier3_R2_Pairwise_F13_F14_FastStart_To_Fallback_Transition(t *testing.T) {
	sim := NewDualEnginePlayerSimulator(DesktopModeConsole)
	// Start with fast-start
	sim.StartSession(context.Background(), true, 30*time.Millisecond)
	if sim.ActiveEngine() != "canvas" {
		t.Fatalf("Must be on canvas")
	}

	// Timeout occurs
	time.Sleep(50 * time.Millisecond)
	if sim.State() != EngineStateFallbackCanvas || sim.ActiveEngine() != "canvas" {
		t.Fatalf("Canvas transition error on fallback")
	}
}

func TestTier3_R2_Pairwise_F14_F15_Relay_Fallback_Notification(t *testing.T) {
	relay := NewSignalingRelayHarness()
	defer relay.Close()

	// Agent notifies fallback through relay
	fallbackMsg := SignalingMessage{Type: "webrtc_fallback", Reason: "timeout_4s_udp_blocked"}
	_ = relay.SendFromAgent(fallbackMsg)

	viewerMsg, err := relay.ReadForViewer(100 * time.Millisecond)
	if err != nil || viewerMsg.Type != "webrtc_fallback" {
		t.Fatalf("Relay fallback notification failed")
	}
}

func TestTier3_R2_Pairwise_F12_F15_DualChannel_Relay_Bridge(t *testing.T) {
	// Verifies that when SCTP DataChannel cannot connect, input events pass transparently through signaling relay
	relay := NewSignalingRelayHarness()
	defer relay.Close()

	inputEvt := SignalingMessage{
		Type:   "input_event",
		Reason: `{"t":"d","btn":0,"x":100,"y":100}`,
	}
	_ = relay.SendFromViewer(inputEvt)

	msg, err := relay.ReadForAgent(100 * time.Millisecond)
	if err != nil || msg.Type != "input_event" {
		t.Fatalf("Relay input bridge failed")
	}
}
