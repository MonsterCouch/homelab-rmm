// Package e2e_test provides requirement-driven, opaque-box end-to-end tests for
// Homelab RMM Phase 2 - Tier 4: Real-World Application Workload Scenarios.
package e2e_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// Scenario 1: Fullscreen 60 FPS WebRTC Session with Packet Loss Recovery
// (Features 1, 3, 7, 8, 10, 11, 25)
// ============================================================================

func TestTier4_Scenario1_Fullscreen_60FPS_WebRTC_PacketLossRecovery(t *testing.T) {
	// 1. Initialize DXGI Capturer & MFT H.264 Encoder
	capturer := NewMockDXGICapturer(1920, 1080, false)
	defer capturer.Close()
	encoder := NewMockMFTH264Encoder(1920, 1080, 60) // GOP = 60
	defer encoder.Close()

	// 2. Initialize Pion WebRTC PeerConnection & Dual-Engine Player
	pc := NewMockPeerConnection()
	player := NewDualEnginePlayerSimulator(DesktopModeConsole)
	player.StartSession(context.Background(), true, 4*time.Second)

	// 3. Complete WebRTC Handshake & Transition to Playing
	pc.SetConnectionState("connected")
	player.OnWebRTCPlaying()

	if player.ActiveEngine() != "video" || player.Transport() != "WebRTC P2P (UDP)" {
		t.Fatalf("Player failed to transition to WebRTC video playback: engine=%s, transport=%s", player.ActiveEngine(), player.Transport())
	}

	// 4. Stream 60 frames (1 full second at 60 FPS)
	rtcpLoop := NewRTCPFeedbackLoopHarness(50 * time.Millisecond)
	var rtpPacketsSent int64
	var keyframesReceived int64
	clockRate := uint32(90000)
	ticksPerFrame := clockRate / 60 // 1500 ticks per frame
	var currentTimestamp uint32 = 0
	var currentSeq uint16 = 1000

	for frameIdx := 0; frameIdx < 60; frameIdx++ {
		f, err := capturer.Capture(capturer.monitors[0])
		if err != nil {
			t.Fatalf("Frame %d capture failed: %v", frameIdx, err)
		}

		nalData, isKey, err := encoder.Encode(f)
		if err != nil {
			t.Fatalf("Frame %d encode failed: %v", frameIdx, err)
		}
		_ = capturer.ReleaseFrame()

		if isKey {
			atomic.AddInt64(&keyframesReceived, 1)
		}

		// Packetize into RTP
		hdr := RTPHeader{
			Version:        2,
			PayloadType:    96,
			SequenceNumber: currentSeq,
			Timestamp:      currentTimestamp,
			Marker:         true,
			SSRC:           0x12345678,
		}
		currentSeq++
		currentTimestamp += ticksPerFrame

		packet := append(hdr.Marshal(), nalData...)
		pc.SendRTP(packet)
		atomic.AddInt64(&rtpPacketsSent, 1)
	}

	if atomic.LoadInt64(&rtpPacketsSent) != 60 {
		t.Fatalf("Expected 60 RTP packets sent, got %d", rtpPacketsSent)
	}
	if atomic.LoadInt64(&keyframesReceived) != 1 {
		t.Fatalf("Expected exactly 1 IDR keyframe at start of GOP, got %d", keyframesReceived)
	}

	// 5. Inject Network Packet Loss: Drop 10 consecutive frames
	// Client detects freeze and transmits RTCP PLI
	pliPacket := &RTCPPacket{
		Type:       RTCPTypePLI,
		Format:     RTCPFmtPLI,
		SenderSSRC: 0x99999999,
		MediaSSRC:  0x12345678,
	}

	// 6. Agent receives PLI in RTCP background loop -> invokes encoder.ForceKeyframe()
	err := rtcpLoop.ProcessPacket(pliPacket, encoder)
	if err != nil {
		t.Fatalf("RTCP PLI processing failed: %v", err)
	}

	// 7. Verify next captured frame is an IDR keyframe restoring playback
	fRecover, err := capturer.Capture(capturer.monitors[0])
	if err != nil {
		t.Fatalf("Recovery frame capture failed: %v", err)
	}
	nalRecover, isKeyRecover, err := encoder.Encode(fRecover)
	_ = capturer.ReleaseFrame()

	if err != nil || !isKeyRecover {
		t.Fatalf("Expected immediate IDR keyframe after PLI recovery, got isKey=%v, err=%v", isKeyRecover, err)
	}

	nals, err := ParseAnnexBNALs(nalRecover)
	if err != nil || len(nals) < 3 {
		t.Fatalf("Recovery bitstream missing SPS/PPS/IDR: %v", err)
	}
	if nals[len(nals)-1].Type != NALTypeIDR {
		t.Fatalf("Final NAL must be IDR (5), got %d", nals[len(nals)-1].Type)
	}
}

// ============================================================================
// Scenario 2: Automated UDP Firewall Block to WebSocket 4.0s Fallback
// (Features 10, 11, 14, 15, 21, 22)
// ============================================================================

func TestTier4_Scenario2_Automated_UDP_Firewall_Block_To_WebSocket_Fallback(t *testing.T) {
	// 1. Client initiates desktop session via WebSocket relay
	relay := NewSignalingRelayHarness()
	defer relay.Close()
	player := NewDualEnginePlayerSimulator(DesktopModeConsole)

	// Arm 4.0-second fallback circuit (simulated with 60ms fast test timeout)
	timeoutDuration := 60 * time.Millisecond
	player.StartSession(context.Background(), true, timeoutDuration)

	// 2. Optimistic fast-start delivers instant JPEG tile over WebSocket in <100ms
	fastStartImg := GenerateTestPatternRGBA(640, 480)
	var fastStartTile []byte
	fastStartTile = append(fastStartTile, 0xFF, 0xD8, 0xFF, 0xE0)
	fastStartTile = append(fastStartTile, fastStartImg.Pix[:256]...)
	fastStartTile = append(fastStartTile, 0xFF, 0xD9)

	if player.ActiveEngine() != "canvas" {
		t.Fatalf("Player must display fast-start tile on canvas while WebRTC negotiates")
	}

	// 3. Relay brokers STUN configuration and passes SDP offer
	offerMsg := SignalingMessage{
		Type: "webrtc_offer",
		SDP:  "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n",
	}
	_ = relay.SendFromAgent(offerMsg)
	recOffer, err := relay.ReadForViewer(50 * time.Millisecond)
	if err != nil || recOffer.Type != "webrtc_offer" {
		t.Fatalf("Relay failed to forward offer: %v", err)
	}

	// 4. Strict enterprise firewall drops 100% of UDP packets
	// ICE connection state never reaches 'connected'
	time.Sleep(80 * time.Millisecond) // Exceeds timeoutDuration

	// 5. Watchdog fires: triggers automatic failover to WebSocket JPEG tile diffing
	if player.State() != EngineStateFallbackCanvas {
		t.Fatalf("Fallback circuit failed to engage: state=%s", player.State())
	}
	if player.ActiveEngine() != "canvas" {
		t.Fatalf("Active engine must remain canvas after fallback")
	}
	if player.Transport() != "WebSocket Relay" {
		t.Fatalf("Transport must switch to WebSocket Relay: %s", player.Transport())
	}

	// 6. Agent emits fallback reason notification
	fallbackNotification := SignalingMessage{
		Type:   "webrtc_fallback",
		Reason: "timeout_4s_udp_blocked",
	}
	_ = relay.SendFromAgent(fallbackNotification)
	recFallback, err := relay.ReadForViewer(50 * time.Millisecond)
	if err != nil || recFallback.Reason != "timeout_4s_udp_blocked" {
		t.Fatalf("Fallback reason not received: %v", err)
	}

	// 7. Verify session remains persistently alive on canvas
	player.UpdateTelemetry(30.0, 45.0, 1.2)
	fps, rtt, _, transport, _ := player.Telemetry()
	if transport != "WebSocket Relay" || fps != 30.0 || rtt != 45.0 {
		t.Fatalf("Telemetry mismatch on fallback canvas: transport=%s, fps=%f", transport, fps)
	}
}

// ============================================================================
// Scenario 3: Invisible Administrative Backstage Troubleshooting Session
// (Features 16, 17, 18, 19, 20, 29)
// ============================================================================

func TestTier4_Scenario3_Invisible_Administrative_Backstage_Troubleshooting(t *testing.T) {
	// 1. Admin toggles Backstage Mode in viewer
	player := NewDualEnginePlayerSimulator(DesktopModeConsole)
	player.SetMode(DesktopModeBackstage)
	if player.Mode() != DesktopModeBackstage {
		t.Fatalf("Failed setting backstage mode")
	}

	// 2. Session 0 daemon elevates into Console session & creates HomelabRMM_Backstage
	backstage := NewMockBackstageDesktop()
	err := backstage.CreateOrOpen()
	if err != nil {
		t.Fatalf("Failed creating backstage desktop: %v", err)
	}
	defer backstage.Close()

	// Verify DACL restricts access strictly to SYSTEM & Administrators
	expectedDACL := "D:(A;;GA;;;SY)(A;;GA;;;BA)"
	if backstage.dacl != expectedDACL {
		t.Fatalf("DACL security violation: %s", backstage.dacl)
	}

	// 3. Spawns administrative PowerShell with -WindowStyle Hidden
	cmdPowerShell := `powershell.exe -WindowStyle Hidden -NoProfile -Command Write-Host "Backstage Active"`
	err = backstage.SpawnProcess(cmdPowerShell, true)
	if err != nil {
		t.Fatalf("Failed spawning hidden PowerShell: %v", err)
	}

	// 4. Safe Off-screen Memory DC Compositor renders desktop
	compositeImg, err := backstage.CaptureComposite()
	if err != nil || compositeImg == nil {
		t.Fatalf("Memory DC capture composite failed: %v", err)
	}
	if compositeImg.Bounds().Dx() != 1920 || compositeImg.Bounds().Dy() != 1080 {
		t.Fatalf("Invalid composite image bounds: %v", compositeImg.Bounds())
	}

	// 5. Admin types commands into PowerShell window via PostMessageW
	psHWND := backstage.windows[0].HWND
	// Route mouse click to focus PowerShell
	_ = backstage.RouteInput(InputEventContract{Type: "d", X: 150, Y: 150, Button: 0})
	_ = backstage.RouteInput(InputEventContract{Type: "u", X: 150, Y: 150, Button: 0})

	// Route keystrokes "dir" + Enter
	keystrokes := []string{"d", "i", "r", "Enter"}
	for _, k := range keystrokes {
		_ = backstage.RouteInput(InputEventContract{Type: "kd", Key: k, X: 150, Y: 150})
		_ = backstage.RouteInput(InputEventContract{Type: "ku", Key: k, X: 150, Y: 150})
	}

	// Verify messages received by target window
	w := backstage.windows[0]
	if w.HWND != psHWND {
		t.Fatalf("Window HWND mismatch")
	}
	// 2 mouse messages + 8 keyboard messages = 10 messages
	if len(w.Received) != 10 {
		t.Fatalf("Expected 10 routed messages, got %d", len(w.Received))
	}

	// 6. STRICT INVARIANT VERIFICATION:
	// Verify that NO GetDC(NULL) was ever called!
	// Verify that NO SendInput was ever called!
	// Verify that any child process launched specified -WindowStyle Hidden!
	backstage.invariants.AssertInvariants(t)
}

// ============================================================================
// Scenario 4: Wayland Unattended Remote Access with Persistent Token
// (Features 21, 22, 23, 24)
// ============================================================================

func TestTier4_Scenario4_Wayland_Unattended_Remote_Access_With_Persistent_Token(t *testing.T) {
	tmpDir := t.TempDir()
	configStorePath := filepath.Join(tmpDir, "agent.json")

	// 1. Linux session detector detects Wayland
	detector := &WinLinuxSessionDetector{
		xdgSessionType: "wayland",
		pipewireActive: true,
	}
	sessType, err := detector.Detect()
	if err != nil || sessType != "wayland" {
		t.Fatalf("Wayland session auto-detection failed: %s, %v", sessType, err)
	}

	// 2. Initial interactive session: requests persist_mode: 2
	initialSession := NewWinMockPortalScreenCastSession()
	_ = initialSession.SelectSources(map[string]interface{}{
		"persist_mode": uint32(2),
		"cursor_mode":  uint32(1),
		"source_type":  uint32(1),
	})

	nodeID1, restoreToken, err := initialSession.Start()
	if err != nil || nodeID1 == 0 || restoreToken == "" {
		t.Fatalf("Initial ScreenCast portal handshake failed: %v", err)
	}

	// 3. Cache restore_token in agent.json
	cfg := map[string]interface{}{
		"wayland_restore_token": restoreToken,
	}
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(configStorePath, data, 0600); err != nil {
		t.Fatalf("Failed to save restore token: %v", err)
	}

	// 4. Simulate agent daemon restart / host reboot
	readData, err := os.ReadFile(configStorePath)
	if err != nil {
		t.Fatalf("Failed reading config store: %v", err)
	}
	var loadedCfg map[string]interface{}
	_ = json.Unmarshal(readData, &loadedCfg)
	cachedToken := loadedCfg["wayland_restore_token"].(string)

	// 5. Unattended reconnection using cached restore_token
	unattendedSession := NewWinMockPortalScreenCastSession()
	_ = unattendedSession.SelectSources(map[string]interface{}{
		"persist_mode":  uint32(2),
		"restore_token": cachedToken,
	})

	nodeID2, activeToken, err := unattendedSession.Start()
	if err != nil || nodeID2 == 0 {
		t.Fatalf("Unattended reconnection failed: %v", err)
	}
	if activeToken != cachedToken {
		t.Fatalf("Restore token mismatch on unattended reconnect: %s vs %s", activeToken, cachedToken)
	}

	// 6. Inject kernel input via universal /dev/uinput devices
	uinputMouse := NewWinMockUInputDevice("mouse", true)
	uinputKbd := NewWinMockUInputDevice("keyboard", true)
	defer uinputMouse.Close()
	defer uinputKbd.Close()

	// Move mouse
	_ = uinputMouse.Emit(WinLinuxInputEvent{Type: WinLinuxEV_REL, Code: WinLinuxREL_X, Value: 100})
	_ = uinputMouse.Emit(WinLinuxInputEvent{Type: WinLinuxEV_REL, Code: WinLinuxREL_Y, Value: 50})
	_ = uinputMouse.Emit(WinLinuxInputEvent{Type: WinLinuxEV_SYN, Code: 0, Value: 0})

	// Type Enter
	_ = uinputKbd.Emit(WinLinuxInputEvent{Type: WinLinuxEV_KEY, Code: WinLinuxKEY_ENTER, Value: 1})
	_ = uinputKbd.Emit(WinLinuxInputEvent{Type: WinLinuxEV_SYN, Code: 0, Value: 0})
	_ = uinputKbd.Emit(WinLinuxInputEvent{Type: WinLinuxEV_KEY, Code: WinLinuxKEY_ENTER, Value: 0})
	_ = uinputKbd.Emit(WinLinuxInputEvent{Type: WinLinuxEV_SYN, Code: 0, Value: 0})

	if len(uinputMouse.events) != 3 || len(uinputKbd.events) != 4 {
		t.Fatalf("Uinput event injection count mismatch: mouse=%d, kbd=%d", len(uinputMouse.events), len(uinputKbd.events))
	}
}

// ============================================================================
// Scenario 5: Dual-Engine Player Stream Diagnostics and Input Interaction
// (Features 9, 12, 25, 26, 27, 28)
// ============================================================================

func TestTier4_Scenario5_DualEngine_Player_StreamDiagnostics_And_Input_Interaction(t *testing.T) {
	// 1. Launch player and HUD
	player := NewDualEnginePlayerSimulator(DesktopModeConsole)
	hud := NewStreamDiagnosticsHUD()
	inputRouter := NewFrontendInputOverlayRouter(true) // DataChannel open

	player.StartSession(context.Background(), true, 4*time.Second)
	player.OnWebRTCPlaying()

	// 2. Stream diagnostics telemetry under normal 60 FPS streaming
	fps := 60.0
	rtt := 16.5
	bitrate := 2.6
	hud.SetMetrics(fps, rtt, bitrate, player.Transport(), player.Mode())

	if hud.LatencyColor() != "green" {
		t.Fatalf("Target sub-25ms latency must be green: %s (%f ms)", hud.LatencyColor(), rtt)
	}

	// 3. User interaction over dual DataChannels
	// High-frequency mouse movements
	for i := 0; i < 60; i++ {
		_ = inputRouter.Dispatch(InputEventContract{Type: "m", X: 500 + i, Y: 400 + i})
	}
	// Single click
	_ = inputRouter.Dispatch(InputEventContract{Type: "d", Button: 0, X: 560, Y: 460})
	_ = inputRouter.Dispatch(InputEventContract{Type: "u", Button: 0, X: 560, Y: 460})

	if len(inputRouter.dcUnreliable) != 60 {
		t.Fatalf("Expected 60 mousemove events on unreliable channel, got %d", len(inputRouter.dcUnreliable))
	}
	if len(inputRouter.dcReliable) != 2 {
		t.Fatalf("Expected 2 click events on reliable channel, got %d", len(inputRouter.dcReliable))
	}

	// 4. Remote desktop triggers resolution change / GPU reset (DXGI_ERROR_ACCESS_LOST)
	capturer := NewMockDXGICapturer(1920, 1080, false)
	capturer.forceAccessLost = true
	_, err := capturer.Capture(capturer.monitors[0])
	if err == nil {
		t.Fatalf("Expected access lost error on resolution change")
	}

	// Capturer adapts to new 2560x1440 resolution
	capturer.forceAccessLost = false
	capturer.width = 2560
	capturer.height = 1440
	fNew, err := capturer.Capture(capturer.monitors[0])
	if err != nil {
		t.Fatalf("Failed re-acquiring desktop after resolution change: %v", err)
	}
	_ = capturer.ReleaseFrame()

	// 5. Diagnostics HUD updates dynamically with higher bitrate for 1440p
	hud.SetMetrics(60.0, 19.2, 4.2, player.Transport(), player.Mode())
	if fNew.Bounds.Dx() != 2560 || hud.bitrateMbps != 4.2 {
		t.Fatalf("Resolution & bitrate dynamic update failed")
	}
}
