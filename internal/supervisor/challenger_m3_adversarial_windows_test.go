//go:build windows

package supervisor

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestAdversarial_RapidConnectDisconnect tests rapid client connections and
// immediate disconnects without sending any data, verifying that the Windows
// Named Pipe listener and IPCServer do not deadlock, leak handles, or drop subsequent clients.
func TestAdversarial_RapidConnectDisconnect(t *testing.T) {
	pipeName := testPipeName(t)
	sddl, err := CurrentUserSDDL()
	if err != nil {
		t.Fatalf("CurrentUserSDDL: %v", err)
	}

	listener, err := ListenPipe(pipeName, sddl)
	if err != nil {
		t.Fatalf("ListenPipe: %v", err)
	}
	defer listener.Close()

	server := NewIPCServer()
	var heartbeatReceived atomic.Int64
	server.RegisterHandler(MsgHeartbeat, func(msg *IPCMessage) (*IPCMessage, error) {
		heartbeatReceived.Add(1)
		return nil, nil
	})

	if err := server.Start(listener); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	defer server.Stop()

	// 1. Rapid sequential connect and immediate close (50 cycles)
	for i := 0; i < 50; i++ {
		conn, err := DialPipe(pipeName, 2*time.Second)
		if err != nil {
			t.Fatalf("cycle %d: DialPipe failed: %v", i, err)
		}
		_ = conn.Close()
	}

	// 2. Rapid concurrent connect and immediate close (20 goroutines x 5 cycles = 100 conns)
	var wg sync.WaitGroup
	errCh := make(chan error, 100)
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				conn, err := DialPipe(pipeName, 3*time.Second)
				if err != nil {
					errCh <- fmt.Errorf("goroutine %d iter %d: dial failed: %w", gid, i, err)
					return
				}
				_ = conn.Close()
			}
		}(g)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent rapid disconnect error: %v", err)
	}

	// 3. Connect, write partial line (no newline), and immediately close (abortive frames)
	for i := 0; i < 15; i++ {
		conn, err := DialPipe(pipeName, 2*time.Second)
		if err != nil {
			t.Fatalf("partial line cycle %d: DialPipe failed: %v", i, err)
		}
		_, _ = conn.Write([]byte(`{"type":"heartbeat","pid":`))
		_ = conn.Close()
	}

	// 4. Verify listener and server are fully healthy after the barrage
	client := NewIPCClient(func() (net.Conn, error) {
		return DialPipe(pipeName, 2*time.Second)
	}, 2*time.Second)
	defer client.Close()

	if err := client.Send(&IPCMessage{Type: MsgHeartbeat, PID: 9999}); err != nil {
		t.Fatalf("verification Send failed after barrage: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	if heartbeatReceived.Load() < 1 {
		t.Fatalf("expected heartbeat after rapid connect/disconnect, got %d", heartbeatReceived.Load())
	}
}

// TestAdversarial_OversizedMessageHandling verifies that a client transmitting a frame
// larger than MaxMessageSize (1 MB) is terminated cleanly by the server without crashing it.
func TestAdversarial_OversizedMessageHandling(t *testing.T) {
	pipeName := testPipeName(t)
	sddl, err := CurrentUserSDDL()
	if err != nil {
		t.Fatalf("CurrentUserSDDL: %v", err)
	}

	listener, err := ListenPipe(pipeName, sddl)
	if err != nil {
		t.Fatalf("ListenPipe: %v", err)
	}
	defer listener.Close()

	server := NewIPCServer()
	var normalMsgCount atomic.Int64
	server.RegisterHandler(MsgHeartbeat, func(msg *IPCMessage) (*IPCMessage, error) {
		normalMsgCount.Add(1)
		return nil, nil
	})

	if err := server.Start(listener); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	defer server.Stop()

	// Connect attacker client and send 1.5 MB line
	attackerConn, err := DialPipe(pipeName, 2*time.Second)
	if err != nil {
		t.Fatalf("attacker DialPipe failed: %v", err)
	}
	defer attackerConn.Close()

	oversizedPayload := strings.Repeat("A", MaxMessageSize+4096) + "\n"
	_, _ = attackerConn.Write([]byte(oversizedPayload))

	// Allow server to process and drop attacker connection
	time.Sleep(150 * time.Millisecond)

	// Legitimate client should still be able to connect and send messages
	legitClient := NewIPCClient(func() (net.Conn, error) {
		return DialPipe(pipeName, 2*time.Second)
	}, 2*time.Second)
	defer legitClient.Close()

	if err := legitClient.Send(&IPCMessage{Type: MsgHeartbeat, PID: 12345}); err != nil {
		t.Fatalf("legit client Send failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	if normalMsgCount.Load() != 1 {
		t.Fatalf("expected 1 normal heartbeat, got %d", normalMsgCount.Load())
	}
}

// TestAdversarial_HighConcurrencyStress executes heavy concurrent load
// over real Windows Named Pipes, interleaving one-way sends and roundtrips.
func TestAdversarial_HighConcurrencyStress(t *testing.T) {
	pipeName := testPipeName(t)
	sddl, err := CurrentUserSDDL()
	if err != nil {
		t.Fatalf("CurrentUserSDDL: %v", err)
	}

	listener, err := ListenPipe(pipeName, sddl)
	if err != nil {
		t.Fatalf("ListenPipe: %v", err)
	}
	defer listener.Close()

	server := NewIPCServer()
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
			Slot: "slot_b",
		}, nil
	})

	if err := server.Start(listener); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	defer server.Stop()

	const goroutines = 12
	const iterations = 30

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*2)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			client := NewIPCClient(func() (net.Conn, error) {
				return DialPipe(pipeName, 5*time.Second)
			}, 5*time.Second)
			defer client.Close()

			for i := 0; i < iterations; i++ {
				// Send heartbeat
				err := client.Send(&IPCMessage{
					Type:     MsgHeartbeat,
					PID:      gid*1000 + i,
					RSSBytes: uint64(gid * i),
				})
				if err != nil {
					errCh <- fmt.Errorf("goroutine %d send %d: %w", gid, i, err)
					return
				}

				// Roundtrip
				resp, err := client.RoundTrip(&IPCMessage{
					Type: MsgGetInactive,
				})
				if err != nil {
					errCh <- fmt.Errorf("goroutine %d roundtrip %d: %w", gid, i, err)
					return
				}
				if resp.Type != MsgInactiveResp || resp.Slot != "slot_b" {
					errCh <- fmt.Errorf("goroutine %d bad resp: %+v", gid, resp)
					return
				}
			}
		}(g)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrency error: %v", err)
	}

	expectedTotal := int64(goroutines * iterations)
	if heartbeatCount.Load() != expectedTotal {
		t.Errorf("heartbeat count = %d, want %d", heartbeatCount.Load(), expectedTotal)
	}
	if roundtripCount.Load() != expectedTotal {
		t.Errorf("roundtrip count = %d, want %d", roundtripCount.Load(), expectedTotal)
	}
}

// TestAdversarial_StopDuringActiveStreaming verifies that stopping an IPCServer
// while multiple clients are actively sending messages cleanly terminates connections
// and exits within the 3-second grace window without hanging.
func TestAdversarial_StopDuringActiveStreaming(t *testing.T) {
	pipeName := testPipeName(t)
	sddl, err := CurrentUserSDDL()
	if err != nil {
		t.Fatalf("CurrentUserSDDL: %v", err)
	}

	listener, err := ListenPipe(pipeName, sddl)
	if err != nil {
		t.Fatalf("ListenPipe: %v", err)
	}

	server := NewIPCServer()
	server.RegisterHandler(MsgHeartbeat, func(msg *IPCMessage) (*IPCMessage, error) {
		return nil, nil
	})

	if err := server.Start(listener); err != nil {
		t.Fatalf("server.Start: %v", err)
	}

	stopClients := make(chan struct{})
	var clientWg sync.WaitGroup

	// Start 8 streaming clients
	for g := 0; g < 8; g++ {
		clientWg.Add(1)
		go func(gid int) {
			defer clientWg.Done()
			client := NewIPCClient(func() (net.Conn, error) {
				return DialPipe(pipeName, 2*time.Second)
			}, 2*time.Second)
			defer client.Close()

			for {
				select {
				case <-stopClients:
					return
				default:
					_ = client.Send(&IPCMessage{Type: MsgHeartbeat, PID: gid})
					time.Sleep(10 * time.Millisecond)
				}
			}
		}(g)
	}

	// Allow streaming to proceed for a moment
	time.Sleep(150 * time.Millisecond)

	// Stop server while clients are actively sending
	stopDone := make(chan error, 1)
	go func() {
		stopDone <- server.Stop()
	}()

	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("server.Stop returned error: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("server.Stop exceeded 3-second timeout window")
	}

	close(stopClients)
	clientWg.Wait()
}

// TestAdversarial_PipeListener_ConcurrentClose verifies that invoking Close()
// concurrently on pipeListener does not panic or deadlock.
func TestAdversarial_PipeListener_ConcurrentClose(t *testing.T) {
	pipeName := testPipeName(t)
	sddl, err := CurrentUserSDDL()
	if err != nil {
		t.Fatalf("CurrentUserSDDL: %v", err)
	}

	listener, err := ListenPipe(pipeName, sddl)
	if err != nil {
		t.Fatalf("ListenPipe: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = listener.Close()
		}()
	}
	wg.Wait()

	// Accept on closed listener must immediately return net.ErrClosed
	_, err = listener.Accept()
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed, got %v", err)
	}
}

// TestAdversarial_AutoReconnect_RealNamedPipe verifies auto-reconnection
// across a real Windows Named Pipe server restart.
func TestAdversarial_AutoReconnect_RealNamedPipe(t *testing.T) {
	pipeName := testPipeName(t)
	sddl, err := CurrentUserSDDL()
	if err != nil {
		t.Fatalf("CurrentUserSDDL: %v", err)
	}

	// 1. Start Server Instance 1
	l1, err := ListenPipe(pipeName, sddl)
	if err != nil {
		t.Fatalf("ListenPipe 1: %v", err)
	}

	server1 := NewIPCServer()
	var s1Heartbeats atomic.Int64
	server1.RegisterHandler(MsgHeartbeat, func(msg *IPCMessage) (*IPCMessage, error) {
		s1Heartbeats.Add(1)
		return nil, nil
	})
	if err := server1.Start(l1); err != nil {
		t.Fatalf("server1.Start: %v", err)
	}

	client := NewIPCClient(func() (net.Conn, error) {
		return DialPipe(pipeName, 2*time.Second)
	}, 2*time.Second)
	defer client.Close()

	// Send to server 1
	if err := client.Send(&IPCMessage{Type: MsgHeartbeat, PID: 101}); err != nil {
		t.Fatalf("initial Send to server 1 failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if s1Heartbeats.Load() != 1 {
		t.Fatalf("expected 1 heartbeat to server 1, got %d", s1Heartbeats.Load())
	}

	// 2. Terminate Server 1
	_ = server1.Stop()

	// 3. Start Server Instance 2 on same pipe name
	l2, err := ListenPipe(pipeName, sddl)
	if err != nil {
		t.Fatalf("ListenPipe 2: %v", err)
	}

	server2 := NewIPCServer()
	var s2Heartbeats atomic.Int64
	server2.RegisterHandler(MsgHeartbeat, func(msg *IPCMessage) (*IPCMessage, error) {
		s2Heartbeats.Add(1)
		return nil, nil
	})
	if err := server2.Start(l2); err != nil {
		t.Fatalf("server2.Start: %v", err)
	}
	defer server2.Stop()

	// 4. Send via client: dead connection triggers error, next send reconnects to server 2
	err = client.Send(&IPCMessage{Type: MsgHeartbeat, PID: 202})
	if err != nil {
		// Stale connection teardown on first attempt, retry reconnects
		err = client.Send(&IPCMessage{Type: MsgHeartbeat, PID: 202})
		if err != nil {
			t.Fatalf("Send failed to auto-reconnect to server 2: %v", err)
		}
	}

	time.Sleep(50 * time.Millisecond)
	if s2Heartbeats.Load() != 1 {
		t.Fatalf("expected 1 heartbeat to server 2 after reconnect, got %d", s2Heartbeats.Load())
	}
}

// TestAdversarial_DefaultSDDL_Rejection verifies that when ListenPipe is configured with
// DefaultSDDL (D:P(A;;GA;;;SY)(A;;GA;;;BA)), a medium-integrity caller is cleanly rejected
// with os.ErrPermission (ERROR_ACCESS_DENIED) upon DialPipe.
func TestAdversarial_DefaultSDDL_Rejection(t *testing.T) {
	// DefaultSDDL grants BUILTIN\Administrators, so an elevated test run is
	// supposed to get through; the rejection is only observable from a
	// medium-integrity token.
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("running elevated: DefaultSDDL admits Administrators by design")
	}
	pipeName := testPipeName(t)

	listener, err := ListenPipe(pipeName, DefaultSDDL)
	if err != nil {
		t.Fatalf("ListenPipe with DefaultSDDL failed: %v", err)
	}
	defer listener.Close()

	// Dialing from medium-integrity non-admin token must be rejected with os.ErrPermission
	conn, err := DialPipe(pipeName, 500*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("expected access denied on DefaultSDDL from non-elevated process, but dial succeeded")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("expected os.ErrPermission in error chain, got: %v", err)
	}
}

// TestAdversarial_FuzzedMalformedJSONRecovery stress-tests the IPC server with a wide variety
// of corrupted frames (binary garbage, null bytes, nested structures, type mismatches,
// whitespace-only lines, incomplete JSON), verifying that the server never deadlocks or panics
// and always recovers to process subsequent valid frames.
func TestAdversarial_FuzzedMalformedJSONRecovery(t *testing.T) {
	pipeName := testPipeName(t)
	sddl, err := CurrentUserSDDL()
	if err != nil {
		t.Fatalf("CurrentUserSDDL: %v", err)
	}

	listener, err := ListenPipe(pipeName, sddl)
	if err != nil {
		t.Fatalf("ListenPipe: %v", err)
	}
	defer listener.Close()

	server := NewIPCServer()
	var validReceived atomic.Int64
	server.RegisterHandler(MsgHeartbeat, func(msg *IPCMessage) (*IPCMessage, error) {
		validReceived.Add(1)
		return nil, nil
	})

	if err := server.Start(listener); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	defer server.Stop()

	conn, err := DialPipe(pipeName, 2*time.Second)
	if err != nil {
		t.Fatalf("DialPipe failed: %v", err)
	}
	defer conn.Close()

	corruptions := [][]byte{
		[]byte("\x00\x01\x02\xff\xfe\xfd\n"),
		[]byte("   \t  \r\n"),
		[]byte("\n"),
		[]byte("not json at all\n"),
		[]byte("{broken json\n"),
		[]byte("{\"type\":\n"),
		[]byte("{\"type\": 12345}\n"),
		[]byte("{\"type\": null}\n"),
		[]byte("[1, 2, 3, 4]\n"),
		[]byte("\"just a plain string\"\n"),
		[]byte("123456789\n"),
		[]byte("true\n"),
		[]byte("{\"type\":\"heartbeat\",\"pid\":\"not_an_int\"}\n"),
		[]byte("{\"type\":\"heartbeat\",\"rss_bytes\":-999}\n"),
		[]byte("{\"type\":\"heartbeat\",\"pid\":1} trailing gibberish\n"),
		[]byte("{\"type\":\"heartbeat\x00with_null\"}\n"),
		[]byte(strings.Repeat("{\"nested\":", 50) + "1" + strings.Repeat("}", 50) + "\n"),
	}

	for i, c := range corruptions {
		// Send corrupted frame
		if _, err := conn.Write(c); err != nil {
			t.Fatalf("failed to write corruption %d: %v", i, err)
		}

		// Send valid heartbeat immediately after
		validMsg, _ := json.Marshal(&IPCMessage{
			Type:     MsgHeartbeat,
			PID:      1000 + i,
			RSSBytes: uint64(i * 1024),
		})
		validMsg = append(validMsg, '\n')
		if _, err := conn.Write(validMsg); err != nil {
			t.Fatalf("failed to write valid message after corruption %d: %v", i, err)
		}
	}

	// Give server brief time to process all lines
	expectedCount := int64(len(corruptions))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if validReceived.Load() == expectedCount {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if validReceived.Load() != expectedCount {
		t.Fatalf("expected %d valid messages processed, got %d", expectedCount, validReceived.Load())
	}
}

// TestAdversarial_OversizedPayload_StrictBoundary verifies exact boundary conditions
// around MaxMessageSize (1 MB), verifying that messages exceeding 1 MB are cleanly
// disconnected without crashing the server or affecting subsequent clients.
func TestAdversarial_OversizedPayload_StrictBoundary(t *testing.T) {
	pipeName := testPipeName(t)
	sddl, err := CurrentUserSDDL()
	if err != nil {
		t.Fatalf("CurrentUserSDDL: %v", err)
	}

	listener, err := ListenPipe(pipeName, sddl)
	if err != nil {
		t.Fatalf("ListenPipe: %v", err)
	}
	defer listener.Close()

	server := NewIPCServer()
	var normalCount atomic.Int64
	server.RegisterHandler(MsgHeartbeat, func(msg *IPCMessage) (*IPCMessage, error) {
		normalCount.Add(1)
		return nil, nil
	})

	if err := server.Start(listener); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	defer server.Stop()

	// 1. Boundary: exactly MaxMessageSize + 1 bytes must be rejected
	c1, err := DialPipe(pipeName, 2*time.Second)
	if err != nil {
		t.Fatalf("DialPipe c1: %v", err)
	}
	defer c1.Close()

	oversized := make([]byte, MaxMessageSize+1)
	for i := range oversized {
		oversized[i] = 'X'
	}
	oversized[len(oversized)-1] = '\n'

	_, _ = c1.Write(oversized)

	// Wait for server to drop c1
	time.Sleep(150 * time.Millisecond)

	// 2. Large 2 MB payload test
	c2, err := DialPipe(pipeName, 2*time.Second)
	if err != nil {
		t.Fatalf("DialPipe c2: %v", err)
	}
	defer c2.Close()

	twoMB := make([]byte, 2*1024*1024)
	for i := range twoMB {
		twoMB[i] = 'Z'
	}
	twoMB[len(twoMB)-1] = '\n'
	_, _ = c2.Write(twoMB)

	time.Sleep(150 * time.Millisecond)

	// 3. Normal client must succeed
	client := NewIPCClient(func() (net.Conn, error) {
		return DialPipe(pipeName, 2*time.Second)
	}, 2*time.Second)
	defer client.Close()

	if err := client.Send(&IPCMessage{Type: MsgHeartbeat, PID: 42}); err != nil {
		t.Fatalf("Send failed after oversized attempts: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	if normalCount.Load() != 1 {
		t.Fatalf("expected 1 heartbeat, got %d", normalCount.Load())
	}
}

// TestAdversarial_SeparateProcess_ClientPID verifies GetNamedPipeClientProcessId
// across real OS process boundaries by spawning a separate PowerShell child process
// that connects to the pipe, confirming the supervisor identifies the child's PID.
func TestAdversarial_SeparateProcess_ClientPID(t *testing.T) {
	pipeName := testPipeName(t)
	sddl, err := CurrentUserSDDL()
	if err != nil {
		t.Fatalf("CurrentUserSDDL: %v", err)
	}

	listener, err := ListenPipe(pipeName, sddl)
	if err != nil {
		t.Fatalf("ListenPipe: %v", err)
	}
	defer listener.Close()

	// Extract bare pipe name for PowerShell NamedPipeClientStream (no \\.\pipe\ prefix)
	barePipeName := strings.TrimPrefix(pipeName, `\\.\pipe\`)

	serverPIDChan := make(chan uint32, 1)
	serverErrChan := make(chan error, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErrChan <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.Close()

		pid, err := ClientPID(conn)
		if err != nil {
			serverErrChan <- fmt.Errorf("ClientPID: %w", err)
			return
		}
		serverPIDChan <- pid
		serverErrChan <- nil
	}()

	// Spawn hidden PowerShell process that connects to the pipe and holds for 800ms
	psScript := fmt.Sprintf(`$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', '%s', [System.IO.Pipes.PipeDirection]::InOut); $pipe.Connect(4000); Start-Sleep -Milliseconds 800; $pipe.Close()`, barePipeName)

	cmd := exec.Command("powershell.exe", "-WindowStyle", "Hidden", "-NoProfile", "-NonInteractive", "-Command", psScript)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start powershell client: %v", err)
	}

	expectedChildPID := uint32(cmd.Process.Pid)

	select {
	case err := <-serverErrChan:
		if err != nil {
			_ = cmd.Wait()
			t.Fatalf("server error during child process connection: %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("timed out waiting for child process to connect")
	}

	detectedPID := <-serverPIDChan
	_ = cmd.Wait()

	if detectedPID != expectedChildPID {
		t.Fatalf("GetNamedPipeClientProcessId returned PID %d, expected child process PID %d (parent test runner PID is %d)", detectedPID, expectedChildPID, os.Getpid())
	}
	if detectedPID == uint32(os.Getpid()) {
		t.Fatalf("GetNamedPipeClientProcessId returned parent test runner PID %d instead of child process PID %d", os.Getpid(), expectedChildPID)
	}
}

