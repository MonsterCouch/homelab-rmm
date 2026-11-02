package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/supervisor"
)

// TestChallengerM6_LiveSession_TriggersNotifyHealthy verifies that a successful
// WebSocket handshake, protocol Hello, and Welcome exchange triggers notifyHealthy()
// over the supervisor IPC channel with valid PID and Version.
func TestChallengerM6_LiveSession_TriggersNotifyHealthy(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	serverHandshakeDone := make(chan struct{})
	serverReceivedHello := make(chan struct{})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade error: %v", err)
			return
		}
		defer ws.Close()

		var env protocol.Envelope
		if err := ws.ReadJSON(&env); err != nil {
			t.Errorf("read hello error: %v", err)
			return
		}
		if env.T != protocol.TypeHello {
			t.Errorf("expected hello type, got: %s", env.T)
			return
		}
		close(serverReceivedHello)

		// Send Welcome envelope
		welcomePayload := map[string]any{
			"agent_id": "test-agent-m6",
			"config":   protocol.AgentConfig{},
		}
		welcomeBytes, _ := json.Marshal(welcomePayload)
		resp := protocol.Envelope{
			T: "welcome",
			D: welcomeBytes,
		}
		if err := ws.WriteJSON(resp); err != nil {
			t.Errorf("write welcome error: %v", err)
			return
		}

		close(serverHandshakeDone)

		// Keep connection open briefly until client cancels
		time.Sleep(500 * time.Millisecond)
	}))
	defer ts.Close()

	// Set up supervisor IPC pipe
	pipe := supervisor.NewInMemoryPipe()
	defer pipe.Close()

	srv := supervisor.NewIPCServer()
	defer srv.Stop()

	healthyCh := make(chan *supervisor.IPCMessage, 1)
	srv.RegisterHandler(supervisor.MsgNotifyHealthy, func(msg *supervisor.IPCMessage) (*supervisor.IPCMessage, error) {
		healthyCh <- msg
		return nil, nil
	})
	if err := srv.Start(pipe); err != nil {
		t.Fatalf("failed to start supervisor IPC server: %v", err)
	}

	clientConn, err := pipe.Dial()
	if err != nil {
		t.Fatalf("dial pipe: %v", err)
	}
	ipcClient := supervisor.NewIPCClient(nil, 2*time.Second)
	_ = ipcClient.Connect(clientConn)
	defer ipcClient.Close()

	cfg := &Config{
		ServerURL: ts.URL,
		Key:       "test-agent-key-secret",
		AgentID:   "test-agent-m6",
	}
	agent := New(cfg)
	agent.SetIPCClient(ipcClient)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sessErrCh := make(chan error, 1)
	go func() {
		sessErrCh <- agent.session(ctx)
	}()

	select {
	case <-serverReceivedHello:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server to receive Hello")
	}

	select {
	case <-serverHandshakeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server handshake")
	}

	// Verify MsgNotifyHealthy is received on supervisor IPC
	select {
	case msg := <-healthyCh:
		if msg.Type != supervisor.MsgNotifyHealthy {
			t.Errorf("expected type MsgNotifyHealthy, got: %s", msg.Type)
		}
		if msg.PID != os.Getpid() {
			t.Errorf("expected PID %d, got: %d", os.Getpid(), msg.PID)
		}
		if msg.Version != Version {
			t.Errorf("expected Version %s, got: %s", Version, msg.Version)
		}
		t.Logf("Verified MsgNotifyHealthy received: PID=%d, Version=%s", msg.PID, msg.Version)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for MsgNotifyHealthy on supervisor IPC")
	}

	cancel()
}

// TestChallengerM6_LiveSession_RejectedServer_DoesNotTriggerNotifyHealthy verifies that
// if the server rejects the connection (e.g. 401 Unauthorized or error envelope),
// notifyHealthy() is NOT called.
func TestChallengerM6_LiveSession_RejectedServer_DoesNotTriggerNotifyHealthy(t *testing.T) {
	// 1. Server returns HTTP 401 Unauthorized
	ts401 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts401.Close()

	pipe := supervisor.NewInMemoryPipe()
	defer pipe.Close()

	srv := supervisor.NewIPCServer()
	defer srv.Stop()

	healthyCh := make(chan *supervisor.IPCMessage, 1)
	srv.RegisterHandler(supervisor.MsgNotifyHealthy, func(msg *supervisor.IPCMessage) (*supervisor.IPCMessage, error) {
		healthyCh <- msg
		return nil, nil
	})
	_ = srv.Start(pipe)

	clientConn, _ := pipe.Dial()
	ipcClient := supervisor.NewIPCClient(nil, 2*time.Second)
	_ = ipcClient.Connect(clientConn)
	defer ipcClient.Close()

	cfg := &Config{
		ServerURL: ts401.URL,
		Key:       "invalid-key",
	}
	agent := New(cfg)
	agent.SetIPCClient(ipcClient)

	err := agent.session(context.Background())
	if err == nil {
		t.Fatal("expected session error on 401, got nil")
	}

	select {
	case msg := <-healthyCh:
		t.Fatalf("unexpected MsgNotifyHealthy emitted on 401 error: %+v", msg)
	case <-time.After(200 * time.Millisecond):
		// Expected: no healthy notification emitted
	}

	// 2. Server accepts WebSocket but returns refused envelope
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	tsRefused := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, _ := upgrader.Upgrade(w, r, nil)
		defer ws.Close()
		var env protocol.Envelope
		_ = ws.ReadJSON(&env)
		_ = ws.WriteJSON(protocol.Envelope{T: "error", Err: "device revoked"})
	}))
	defer tsRefused.Close()

	cfg.ServerURL = tsRefused.URL
	agent = New(cfg)
	agent.SetIPCClient(ipcClient)

	err = agent.session(context.Background())
	if err == nil {
		t.Fatal("expected session error on refused envelope, got nil")
	}

	select {
	case msg := <-healthyCh:
		t.Fatalf("unexpected MsgNotifyHealthy emitted on refused envelope: %+v", msg)
	case <-time.After(200 * time.Millisecond):
		// Expected: no healthy notification emitted
	}
}

// TestChallengerM6_HeartbeatLoop_BrokenPipeResilience tests that when the supervisor
// crashes or closes the IPC connection mid-operation, the heartbeat loop survives
// and does not panic or crash the process.
func TestChallengerM6_HeartbeatLoop_BrokenPipeResilience(t *testing.T) {
	pipe := supervisor.NewInMemoryPipe()

	srv := supervisor.NewIPCServer()
	receivedHeartbeats := make(chan *supervisor.IPCMessage, 10)
	srv.RegisterHandler(supervisor.MsgHeartbeat, func(msg *supervisor.IPCMessage) (*supervisor.IPCMessage, error) {
		receivedHeartbeats <- msg
		return nil, nil
	})
	_ = srv.Start(pipe)

	clientConn, err := pipe.Dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	ipcClient := supervisor.NewIPCClient(nil, 500*time.Millisecond)
	_ = ipcClient.Connect(clientConn)

	agent := New(&Config{})
	agent.SetIPCClient(ipcClient)
	agent.SetHeartbeatInterval(30 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agent.initSupervisorIPC(ctx)

	// Wait for at least one heartbeat
	select {
	case hb := <-receivedHeartbeats:
		if hb.PID != os.Getpid() || hb.RSSBytes == 0 {
			t.Errorf("invalid heartbeat: %+v", hb)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for initial heartbeat")
	}

	// Now abruptly stop supervisor IPC server and close pipe
	_ = srv.Stop()
	_ = pipe.Close()

	// Wait for heartbeat loop to fire several more times against the broken pipe
	time.Sleep(150 * time.Millisecond)

	// Verify closeSupervisorIPC still exits cleanly without hanging or panicking
	done := make(chan struct{})
	go func() {
		agent.closeSupervisorIPC()
		close(done)
	}()

	select {
	case <-done:
		// Clean exit
	case <-time.After(2 * time.Second):
		t.Fatal("closeSupervisorIPC deadlocked after broken IPC pipe")
	}
}

// TestChallengerM6_ConcurrentCloseSupervisorIPC verifies that calling closeSupervisorIPC
// concurrently from multiple goroutines is completely safe and idempotent.
func TestChallengerM6_ConcurrentCloseSupervisorIPC(t *testing.T) {
	pipe := supervisor.NewInMemoryPipe()
	defer pipe.Close()

	srv := supervisor.NewIPCServer()
	defer srv.Stop()
	srv.RegisterHandler(supervisor.MsgHeartbeat, func(msg *supervisor.IPCMessage) (*supervisor.IPCMessage, error) {
		return nil, nil
	})
	_ = srv.Start(pipe)

	clientConn, _ := pipe.Dial()
	ipcClient := supervisor.NewIPCClient(nil, 2*time.Second)
	_ = ipcClient.Connect(clientConn)

	agent := New(&Config{})
	agent.SetIPCClient(ipcClient)
	agent.SetHeartbeatInterval(20 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agent.initSupervisorIPC(ctx)

	time.Sleep(50 * time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			agent.closeSupervisorIPC()
		}()
	}
	wg.Wait()

	if agent.IPCClient() != nil {
		t.Errorf("expected IPCClient to be nil after concurrent close")
	}
}

// TestChallengerM6_StandaloneMode_UpdateRefusal verifies that when running in standalone mode,
// ApplyStagedUpdate refuses updates with a clear error unless legacy mode is enabled.
func TestChallengerM6_StandaloneMode_UpdateRefusal(t *testing.T) {
	origLegacy := os.Getenv("RMM_ALLOW_LEGACY_UPDATE")
	defer func() {
		os.Setenv("RMM_ALLOW_LEGACY_UPDATE", origLegacy)
	}()
	os.Unsetenv("RMM_ALLOW_LEGACY_UPDATE")

	cfg := &Config{
		ServerURL: "https://rmm.lan:8443",
	}
	req := protocol.AgentUpdate{
		URL:     "https://rmm.lan:8443/update.bin",
		SHA256:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Version: "v2.0.0",
	}

	// Without supervisor IPC, update must fail
	err := ApplyStagedUpdate(context.Background(), cfg, req, nil)
	if err == nil {
		t.Fatal("expected update refusal in standalone mode, got nil")
	}
	expectedSub := "agent is running in standalone mode without supervisor IPC"
	if err.Error() != "self-update unavailable: "+expectedSub {
		t.Errorf("got error %q, want substring %q", err.Error(), expectedSub)
	}
}
