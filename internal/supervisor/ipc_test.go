package supervisor

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestIPCMessage_JSONSerialization verifies that all protocol message types
// serialize and deserialize accurately, preserving JSON field tags and omitempty semantics.
func TestIPCMessage_JSONSerialization(t *testing.T) {
	testCases := []struct {
		name     string
		msg      IPCMessage
		expected string
	}{
		{
			name: "heartbeat",
			msg: IPCMessage{
				Type:     MsgHeartbeat,
				PID:      1234,
				RSSBytes: 52428800,
			},
			expected: `{"type":"heartbeat","pid":1234,"rss_bytes":52428800}`,
		},
		{
			name: "notify_healthy",
			msg: IPCMessage{
				Type:    MsgNotifyHealthy,
				Version: "1.0.0",
				PID:     5678,
			},
			expected: `{"type":"notify_healthy","pid":5678,"version":"1.0.0"}`,
		},
		{
			name: "request_restart",
			msg: IPCMessage{
				Type:   MsgRequestRestart,
				Reason: "update_staged",
			},
			expected: `{"type":"request_restart","reason":"update_staged"}`,
		},
		{
			name: "get_inactive_slot",
			msg: IPCMessage{
				Type: MsgGetInactive,
			},
			expected: `{"type":"get_inactive_slot"}`,
		},
		{
			name: "inactive_slot_resp",
			msg: IPCMessage{
				Type: MsgInactiveResp,
				Slot: "slot_b",
				Path: `/opt/homelab-rmm/bin/slot_b/rmm-agent`,
			},
			expected: `{"type":"inactive_slot_resp","slot":"slot_b","path":"/opt/homelab-rmm/bin/slot_b/rmm-agent"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(&tc.msg)
			if err != nil {
				t.Fatalf("Marshal error: %v", err)
			}
			if string(data) != tc.expected {
				t.Errorf("got %s, want %s", string(data), tc.expected)
			}

			var decoded IPCMessage
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Unmarshal error: %v", err)
			}
			if decoded.Type != tc.msg.Type || decoded.PID != tc.msg.PID ||
				decoded.RSSBytes != tc.msg.RSSBytes || decoded.Version != tc.msg.Version ||
				decoded.Reason != tc.msg.Reason || decoded.Slot != tc.msg.Slot ||
				decoded.Path != tc.msg.Path {
				t.Errorf("decoded struct mismatch: got %+v, want %+v", decoded, tc.msg)
			}
		})
	}
}

// TestServer_StartStopIdempotency verifies that the IPCServer lifecycle handles
// multiple starts and stops gracefully without leaking goroutines or panicking.
func TestServer_StartStopIdempotency(t *testing.T) {
	cleanupCalled := false
	server := NewIPCServer(func() {
		cleanupCalled = true
	})

	pipe := NewInMemoryPipe()
	defer pipe.Close()

	if err := server.Start(pipe); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Second Start must return error
	if err := server.Start(pipe); err == nil {
		t.Fatalf("expected second Start to fail, got nil")
	}

	// Verify server address
	if server.Addr() == nil {
		t.Errorf("expected non-nil server address")
	}

	// First Stop must succeed and call cleanup
	if err := server.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if !cleanupCalled {
		t.Errorf("expected cleanup callback to be executed")
	}

	// Second Stop must be idempotent
	if err := server.Stop(); err != nil {
		t.Fatalf("second Stop failed: %v", err)
	}
}

// TestClientServer_OneWaySend verifies that one-way messages (like heartbeats)
// are reliably streamed from worker client to supervisor server.
func TestClientServer_OneWaySend(t *testing.T) {
	pipe := NewInMemoryPipe()
	defer pipe.Close()

	server := NewIPCServer()
	defer server.Stop()

	const count = 10
	received := make(chan *IPCMessage, count)

	server.RegisterHandler(MsgHeartbeat, func(msg *IPCMessage) (*IPCMessage, error) {
		received <- msg
		return nil, nil // one-way message
	})

	if err := server.Start(pipe); err != nil {
		t.Fatalf("server.Start: %v", err)
	}

	client := NewIPCClient(pipe.Dial, 2*time.Second)
	defer client.Close()

	for i := 0; i < count; i++ {
		msg := &IPCMessage{
			Type:     MsgHeartbeat,
			PID:      1000 + i,
			RSSBytes: uint64((i + 1) * 1024 * 1024),
		}
		if err := client.Send(msg); err != nil {
			t.Fatalf("Send message %d: %v", i, err)
		}
	}

	for i := 0; i < count; i++ {
		select {
		case msg := <-received:
			if msg.Type != MsgHeartbeat {
				t.Errorf("msg %d: got type %q, want %q", i, msg.Type, MsgHeartbeat)
			}
			if msg.PID != 1000+i {
				t.Errorf("msg %d: got PID %d, want %d", i, msg.PID, 1000+i)
			}
			expectedRSS := uint64((i + 1) * 1024 * 1024)
			if msg.RSSBytes != expectedRSS {
				t.Errorf("msg %d: got RSS %d, want %d", i, msg.RSSBytes, expectedRSS)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for message %d", i)
		}
	}
}

// TestClientServer_RoundTrip verifies synchronous request-response exchanges
// (such as get_inactive_slot -> inactive_slot_resp).
func TestClientServer_RoundTrip(t *testing.T) {
	pipe := NewInMemoryPipe()
	defer pipe.Close()

	server := NewIPCServer()
	defer server.Stop()

	server.RegisterHandler(MsgGetInactive, func(msg *IPCMessage) (*IPCMessage, error) {
		return &IPCMessage{
			Type: MsgInactiveResp,
			Slot: "slot_b",
			Path: "C:\\Program Files\\HomelabRMM\\bin\\slot_b\\rmm-agent.exe",
		}, nil
	})

	if err := server.Start(pipe); err != nil {
		t.Fatalf("server.Start: %v", err)
	}

	client := NewIPCClient(pipe.Dial, 2*time.Second)
	defer client.Close()

	req := &IPCMessage{
		Type: MsgGetInactive,
	}
	resp, err := client.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}

	if resp.Type != MsgInactiveResp {
		t.Errorf("got type %q, want %q", resp.Type, MsgInactiveResp)
	}
	if resp.Slot != "slot_b" {
		t.Errorf("got slot %q, want %q", resp.Slot, "slot_b")
	}
	if !strings.Contains(resp.Path, "slot_b") {
		t.Errorf("expected slot_b in path, got %q", resp.Path)
	}
}

// TestServer_UnregisteredMessageType verifies that messages with unregistered
// types are ignored without terminating the connection or causing crashes.
func TestServer_UnregisteredMessageType(t *testing.T) {
	pipe := NewInMemoryPipe()
	defer pipe.Close()

	server := NewIPCServer()
	defer server.Stop()

	healthyReceived := make(chan struct{}, 1)
	server.RegisterHandler(MsgNotifyHealthy, func(msg *IPCMessage) (*IPCMessage, error) {
		healthyReceived <- struct{}{}
		return nil, nil
	})

	if err := server.Start(pipe); err != nil {
		t.Fatalf("server.Start: %v", err)
	}

	client := NewIPCClient(pipe.Dial, 2*time.Second)
	defer client.Close()

	// Send unregistered message
	unknownMsg := &IPCMessage{
		Type: MessageType("unknown_custom_type"),
	}
	if err := client.Send(unknownMsg); err != nil {
		t.Fatalf("Send unknown msg: %v", err)
	}

	// Send registered message on same connection
	healthyMsg := &IPCMessage{
		Type:    MsgNotifyHealthy,
		Version: "1.0.0",
	}
	if err := client.Send(healthyMsg); err != nil {
		t.Fatalf("Send healthy msg: %v", err)
	}

	select {
	case <-healthyReceived:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for healthy notification after unregistered message")
	}
}

// TestServer_MalformedJSONRecovery verifies that garbage lines do not kill the connection
// and subsequent valid frames are processed normally.
func TestServer_MalformedJSONRecovery(t *testing.T) {
	pipe := NewInMemoryPipe()
	defer pipe.Close()

	server := NewIPCServer()
	defer server.Stop()

	heartbeatReceived := make(chan int, 1)
	server.RegisterHandler(MsgHeartbeat, func(msg *IPCMessage) (*IPCMessage, error) {
		heartbeatReceived <- msg.PID
		return nil, nil
	})

	if err := server.Start(pipe); err != nil {
		t.Fatalf("server.Start: %v", err)
	}

	conn, err := pipe.Dial()
	if err != nil {
		t.Fatalf("pipe.Dial: %v", err)
	}
	defer conn.Close()

	// Transmit malformed JSON line
	if _, err := conn.Write([]byte("{this is definitely not json}\n")); err != nil {
		t.Fatalf("write malformed json: %v", err)
	}

	// Transmit valid JSON line immediately following
	validJSON := []byte(`{"type":"heartbeat","pid":7777,"rss_bytes":1048576}` + "\n")
	if _, err := conn.Write(validJSON); err != nil {
		t.Fatalf("write valid json: %v", err)
	}

	select {
	case pid := <-heartbeatReceived:
		if pid != 7777 {
			t.Errorf("got pid %d, want 7777", pid)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server failed to recover from malformed JSON frame")
	}
}

// TestServer_HandlerPanicRecovery verifies that a handler panic does not crash the server.
func TestServer_HandlerPanicRecovery(t *testing.T) {
	pipe := NewInMemoryPipe()
	defer pipe.Close()

	server := NewIPCServer()
	defer server.Stop()

	recoveredCount := atomic.Int32{}
	server.RegisterHandler(MsgRequestRestart, func(msg *IPCMessage) (*IPCMessage, error) {
		recoveredCount.Add(1)
		panic("deliberate panic for test verification")
	})

	server.RegisterHandler(MsgHeartbeat, func(msg *IPCMessage) (*IPCMessage, error) {
		return nil, nil
	})

	if err := server.Start(pipe); err != nil {
		t.Fatalf("server.Start: %v", err)
	}

	client := NewIPCClient(pipe.Dial, 2*time.Second)
	defer client.Close()

	// Trigger panic
	_ = client.Send(&IPCMessage{Type: MsgRequestRestart})

	time.Sleep(100 * time.Millisecond)

	// Verify server is still alive and accepting commands
	if err := client.Send(&IPCMessage{Type: MsgHeartbeat, PID: 123}); err != nil {
		t.Fatalf("server failed after handler panic: %v", err)
	}

	if recoveredCount.Load() != 1 {
		t.Errorf("expected 1 panic invocation, got %d", recoveredCount.Load())
	}
}

// TestClient_TimeoutOnUnresponsiveServer verifies that client requests fail
// cleanly with a timeout when the server does not respond within the deadline.
func TestClient_TimeoutOnUnresponsiveServer(t *testing.T) {
	pipe := NewInMemoryPipe()
	defer pipe.Close()

	server := NewIPCServer()
	defer server.Stop()

	server.RegisterHandler(MsgGetInactive, func(msg *IPCMessage) (*IPCMessage, error) {
		// Deliberately delay response longer than client timeout
		time.Sleep(500 * time.Millisecond)
		return &IPCMessage{Type: MsgInactiveResp}, nil
	})

	if err := server.Start(pipe); err != nil {
		t.Fatalf("server.Start: %v", err)
	}

	// Client with short 50ms timeout
	client := NewIPCClient(pipe.Dial, 50*time.Millisecond)
	defer client.Close()

	start := time.Now()
	_, err := client.RoundTrip(&IPCMessage{Type: MsgGetInactive})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error from client, got nil")
	}
	if elapsed > 300*time.Millisecond {
		t.Errorf("RoundTrip took too long to time out: %v", elapsed)
	}
}

// TestClient_AutoReconnect verifies that when a server connection drops,
// subsequent client operations automatically reconnect via the dialer.
func TestClient_AutoReconnect(t *testing.T) {
	pipe := NewInMemoryPipe()
	server := NewIPCServer()

	msgChan := make(chan int, 2)
	server.RegisterHandler(MsgHeartbeat, func(msg *IPCMessage) (*IPCMessage, error) {
		msgChan <- msg.PID
		return nil, nil
	})

	if err := server.Start(pipe); err != nil {
		t.Fatalf("server.Start: %v", err)
	}

	client := NewIPCClient(pipe.Dial, 2*time.Second)
	defer client.Close()

	// Send first message
	if err := client.Send(&IPCMessage{Type: MsgHeartbeat, PID: 111}); err != nil {
		t.Fatalf("Send 1: %v", err)
	}

	select {
	case pid := <-msgChan:
		if pid != 111 {
			t.Errorf("got pid %d, want 111", pid)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for message 1")
	}

	// Stop server to simulate server crash
	_ = server.Stop()
	_ = pipe.Close()

	// Start new server and pipe
	pipe2 := NewInMemoryPipe()
	defer pipe2.Close()

	server2 := NewIPCServer()
	defer server2.Stop()
	server2.RegisterHandler(MsgHeartbeat, func(msg *IPCMessage) (*IPCMessage, error) {
		msgChan <- msg.PID
		return nil, nil
	})
	if err := server2.Start(pipe2); err != nil {
		t.Fatalf("server2.Start: %v", err)
	}

	// Update client dialer to target new pipe
	client.SetDialer(pipe2.Dial)

	// Send on dead connection triggers reconnect to new server
	if err := client.Send(&IPCMessage{Type: MsgHeartbeat, PID: 222}); err != nil {
		// First attempt may fail on broken connection, second reconnects
		if err := client.Send(&IPCMessage{Type: MsgHeartbeat, PID: 222}); err != nil {
			t.Fatalf("Send 2 failed after reconnect: %v", err)
		}
	}

	select {
	case pid := <-msgChan:
		if pid != 222 {
			t.Errorf("got pid %d, want 222", pid)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for message 2 after reconnect")
	}
}

// TestClientServer_ConcurrentLoad executes concurrent one-way and round-trip
// operations across multiple client goroutines to ensure race freedom.
func TestClientServer_ConcurrentLoad(t *testing.T) {
	pipe := NewInMemoryPipe()
	defer pipe.Close()

	server := NewIPCServer()
	defer server.Stop()

	var heartbeatCount atomic.Int64
	var roundtripCount atomic.Int64

	server.RegisterHandler(MsgHeartbeat, func(msg *IPCMessage) (*IPCMessage, error) {
		heartbeatCount.Add(1)
		return nil, nil
	})

	server.RegisterHandler(MsgGetInactive, func(msg *IPCMessage) (*IPCMessage, error) {
		roundtripCount.Add(1)
		return &IPCMessage{
			Type: MsgInactiveResp,
			Slot: "slot_a",
		}, nil
	})

	if err := server.Start(pipe); err != nil {
		t.Fatalf("server.Start: %v", err)
	}

	const goroutines = 8
	const iterations = 50

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*2)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			client := NewIPCClient(pipe.Dial, 3*time.Second)
			defer client.Close()

			for i := 0; i < iterations; i++ {
				// Send heartbeat
				err := client.Send(&IPCMessage{
					Type:     MsgHeartbeat,
					PID:      id*1000 + i,
					RSSBytes: 1024,
				})
				if err != nil {
					errCh <- fmt.Errorf("client %d send err: %w", id, err)
					return
				}

				// RoundTrip request
				resp, err := client.RoundTrip(&IPCMessage{
					Type: MsgGetInactive,
				})
				if err != nil {
					errCh <- fmt.Errorf("client %d roundtrip err: %w", id, err)
					return
				}
				if resp.Type != MsgInactiveResp {
					errCh <- fmt.Errorf("client %d unexpected resp: %s", id, resp.Type)
					return
				}
			}
		}(g)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent test error: %v", err)
	}

	expectedCount := int64(goroutines * iterations)
	if heartbeatCount.Load() != expectedCount {
		t.Errorf("heartbeats = %d, want %d", heartbeatCount.Load(), expectedCount)
	}
	if roundtripCount.Load() != expectedCount {
		t.Errorf("roundtrips = %d, want %d", roundtripCount.Load(), expectedCount)
	}
}

// TestClient_DirectConnect verifies Connect(conn net.Conn) method.
func TestClient_DirectConnect(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	client := NewIPCClient(nil, 2*time.Second)
	if err := client.Connect(c1); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	go func() {
		buf := make([]byte, 128)
		_, _ = c2.Read(buf)
	}()

	if err := client.Send(&IPCMessage{Type: MsgHeartbeat, PID: 42}); err != nil {
		t.Fatalf("Send on direct connection failed: %v", err)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if err := client.Send(&IPCMessage{Type: MsgHeartbeat}); err == nil {
		t.Fatalf("expected error on closed client, got nil")
	}
}
