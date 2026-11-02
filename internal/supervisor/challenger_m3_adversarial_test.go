package supervisor

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAdversarial_InMemory_RapidConnectDisconnect tests rapid client connections and
// immediate disconnects on InMemoryPipe, ensuring channel buffers and goroutines
// are cleanly unblocked without deadlocks.
func TestAdversarial_InMemory_RapidConnectDisconnect(t *testing.T) {
	pipe := NewInMemoryPipe()
	defer pipe.Close()

	server := NewIPCServer()
	var heartbeats atomic.Int64
	server.RegisterHandler(MsgHeartbeat, func(msg *IPCMessage) (*IPCMessage, error) {
		heartbeats.Add(1)
		return nil, nil
	})

	if err := server.Start(pipe); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	defer server.Stop()

	// 100 rapid sequential dials and immediate closes
	for i := 0; i < 100; i++ {
		conn, err := pipe.Dial()
		if err != nil {
			t.Fatalf("cycle %d dial: %v", i, err)
		}
		_ = conn.Close()
	}

	// 50 concurrent dials and immediate closes
	var wg sync.WaitGroup
	errCh := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			conn, err := pipe.Dial()
			if err != nil {
				errCh <- fmt.Errorf("concurrent %d dial: %w", idx, err)
				return
			}
			_ = conn.Close()
		}(i)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("error during concurrent disconnects: %v", err)
	}

	// Legitimate client verification
	client := NewIPCClient(pipe.Dial, 2*time.Second)
	defer client.Close()

	if err := client.Send(&IPCMessage{Type: MsgHeartbeat, PID: 555}); err != nil {
		t.Fatalf("send after rapid disconnect: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	if heartbeats.Load() != 1 {
		t.Fatalf("expected 1 heartbeat, got %d", heartbeats.Load())
	}
}

// TestAdversarial_StressConcurrency_MixedPayloads tests intense concurrency
// mixing heartbeats, roundtrips, invalid types, and malformed frames under -race.
func TestAdversarial_StressConcurrency_MixedPayloads(t *testing.T) {
	pipe := NewInMemoryPipe()
	defer pipe.Close()

	server := NewIPCServer()
	defer server.Stop()

	var heartbeats atomic.Int64
	var roundtrips atomic.Int64
	var restarts atomic.Int64

	server.RegisterHandler(MsgHeartbeat, func(msg *IPCMessage) (*IPCMessage, error) {
		heartbeats.Add(1)
		return nil, nil
	})
	server.RegisterHandler(MsgGetInactive, func(msg *IPCMessage) (*IPCMessage, error) {
		roundtrips.Add(1)
		return &IPCMessage{
			Type: MsgInactiveResp,
			Slot: "slot_a",
			Path: "/test/path/slot_a",
		}, nil
	})
	server.RegisterHandler(MsgRequestRestart, func(msg *IPCMessage) (*IPCMessage, error) {
		restarts.Add(1)
		return nil, nil
	})

	if err := server.Start(pipe); err != nil {
		t.Fatalf("server.Start: %v", err)
	}

	const goroutines = 20
	const iterations = 48

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*2)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			client := NewIPCClient(pipe.Dial, 3*time.Second)
			defer client.Close()

			for i := 0; i < iterations; i++ {
				switch i % 4 {
				case 0:
					// Heartbeat
					err := client.Send(&IPCMessage{
						Type:     MsgHeartbeat,
						PID:      id*1000 + i,
						RSSBytes: uint64(i * 1024),
					})
					if err != nil {
						errCh <- fmt.Errorf("client %d heartbeat %d: %w", id, i, err)
						return
					}
				case 1:
					// RoundTrip
					resp, err := client.RoundTrip(&IPCMessage{
						Type: MsgGetInactive,
					})
					if err != nil {
						errCh <- fmt.Errorf("client %d roundtrip %d: %w", id, i, err)
						return
					}
					if resp.Type != MsgInactiveResp || resp.Slot != "slot_a" {
						errCh <- fmt.Errorf("client %d bad resp: %+v", id, resp)
						return
					}
				case 2:
					// RequestRestart
					err := client.Send(&IPCMessage{
						Type:   MsgRequestRestart,
						Reason: "test_reason",
					})
					if err != nil {
						errCh <- fmt.Errorf("client %d restart %d: %w", id, i, err)
						return
					}
				case 3:
					// Unregistered type (should be safely dropped)
					err := client.Send(&IPCMessage{
						Type: MessageType("unknown_custom_event"),
					})
					if err != nil {
						errCh <- fmt.Errorf("client %d unknown %d: %w", id, i, err)
						return
					}
				}
			}
		}(g)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("mixed concurrency error: %v", err)
	}

	expectedHeartbeats := int64(goroutines * (iterations / 4))
	expectedRoundtrips := int64(goroutines * (iterations / 4))
	expectedRestarts := int64(goroutines * (iterations / 4))

	if heartbeats.Load() != expectedHeartbeats {
		t.Errorf("heartbeats = %d, want %d", heartbeats.Load(), expectedHeartbeats)
	}
	if roundtrips.Load() != expectedRoundtrips {
		t.Errorf("roundtrips = %d, want %d", roundtrips.Load(), expectedRoundtrips)
	}
	if restarts.Load() != expectedRestarts {
		t.Errorf("restarts = %d, want %d", restarts.Load(), expectedRestarts)
	}
}

// TestAdversarial_ServerLifecycleChurn tests rapid Stop/Start cycles on IPCServer.
func TestAdversarial_ServerLifecycleChurn(t *testing.T) {
	for cycle := 0; cycle < 10; cycle++ {
		pipe := NewInMemoryPipe()
		server := NewIPCServer()

		server.RegisterHandler(MsgHeartbeat, func(msg *IPCMessage) (*IPCMessage, error) {
			return nil, nil
		})

		if err := server.Start(pipe); err != nil {
			t.Fatalf("cycle %d start failed: %v", cycle, err)
		}

		client := NewIPCClient(pipe.Dial, 1*time.Second)
		if err := client.Send(&IPCMessage{Type: MsgHeartbeat}); err != nil {
			t.Fatalf("cycle %d send failed: %v", cycle, err)
		}
		_ = client.Close()

		if err := server.Stop(); err != nil {
			t.Fatalf("cycle %d stop failed: %v", cycle, err)
		}
		_ = pipe.Close()
	}
}
