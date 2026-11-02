//go:build windows

package supervisor

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func testPipeName(t *testing.T) string {
	return fmt.Sprintf(`\\.\pipe\homelab-rmm-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
}

// TestListenPipe_FirstInstanceExclusivity verifies that attempting to bind
// an already-bound pipe name fails immediately (anti-squatting defense).
func TestListenPipe_FirstInstanceExclusivity(t *testing.T) {
	name := testPipeName(t)
	sddl, err := CurrentUserSDDL()
	if err != nil {
		t.Fatalf("CurrentUserSDDL: %v", err)
	}

	l1, err := ListenPipe(name, sddl)
	if err != nil {
		t.Fatalf("ListenPipe 1: %v", err)
	}
	defer l1.Close()

	// Second listener on same name must fail
	l2, err := ListenPipe(name, sddl)
	if err == nil {
		l2.Close()
		t.Fatal("expected second ListenPipe on same name to fail, but succeeded")
	}
}

// TestPipe_DialTimeout verifies that DialPipe respects timeout deadlines when the pipe does not exist.
func TestPipe_DialTimeout(t *testing.T) {
	nonExistent := testPipeName(t)
	start := time.Now()
	timeout := 150 * time.Millisecond
	_, err := DialPipe(nonExistent, timeout)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error dialing non-existent pipe, got nil")
	}
	if elapsed < 100*time.Millisecond || elapsed > 1000*time.Millisecond {
		t.Fatalf("expected dial to timeout in ~150ms, elapsed: %v", elapsed)
	}
}

// TestPipe_AcceptAndDial_RoundTrip verifies end-to-end full duplex communication,
// JSON line streaming, and clean EOF handling over a real Windows Named Pipe.
func TestPipe_AcceptAndDial_RoundTrip(t *testing.T) {
	name := testPipeName(t)
	sddl, err := CurrentUserSDDL()
	if err != nil {
		t.Fatalf("CurrentUserSDDL: %v", err)
	}

	listener, err := ListenPipe(name, sddl)
	if err != nil {
		t.Fatalf("ListenPipe: %v", err)
	}
	defer listener.Close()

	type pingPong struct {
		Msg string `json:"msg"`
	}

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.Close()

		// Read ping
		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil {
			serverDone <- fmt.Errorf("server read ping: %w", err)
			return
		}

		var p pingPong
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &p); err != nil {
			serverDone <- fmt.Errorf("server unmarshal ping: %w", err)
			return
		}
		if p.Msg != "ping" {
			serverDone <- fmt.Errorf("server got %q, want 'ping'", p.Msg)
			return
		}

		// Write pong
		resp, _ := json.Marshal(pingPong{Msg: "pong"})
		if _, err := conn.Write(append(resp, '\n')); err != nil {
			serverDone <- fmt.Errorf("server write pong: %w", err)
			return
		}

		// Await EOF from client close
		buf := make([]byte, 16)
		n, err := conn.Read(buf)
		if err != io.EOF && n != 0 {
			serverDone <- fmt.Errorf("expected EOF after client close, got n=%d err=%v", n, err)
			return
		}

		serverDone <- nil
	}()

	clientConn, err := DialPipe(name, 2*time.Second)
	if err != nil {
		t.Fatalf("DialPipe: %v", err)
	}

	// Send ping
	ping, _ := json.Marshal(pingPong{Msg: "ping"})
	if _, err := clientConn.Write(append(ping, '\n')); err != nil {
		t.Fatalf("client write ping: %v", err)
	}

	// Read pong
	clientReader := bufio.NewReader(clientConn)
	respLine, err := clientReader.ReadString('\n')
	if err != nil {
		t.Fatalf("client read pong: %v", err)
	}

	var resp pingPong
	if err := json.Unmarshal([]byte(strings.TrimSpace(respLine)), &resp); err != nil {
		t.Fatalf("client unmarshal pong: %v", err)
	}
	if resp.Msg != "pong" {
		t.Fatalf("client got %q, want 'pong'", resp.Msg)
	}

	// Close client
	if err := clientConn.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server timed out")
	}
}

// TestPipe_ConcurrentClients verifies that multiple clients can connect concurrently
// without thread starvation or serialization deadlocks.
func TestPipe_ConcurrentClients(t *testing.T) {
	name := testPipeName(t)
	sddl, err := CurrentUserSDDL()
	if err != nil {
		t.Fatalf("CurrentUserSDDL: %v", err)
	}

	listener, err := ListenPipe(name, sddl)
	if err != nil {
		t.Fatalf("ListenPipe: %v", err)
	}
	defer listener.Close()

	const clientCount = 5
	var wg sync.WaitGroup
	serverErrCh := make(chan error, clientCount)

	// Server accept loop
	for i := 0; i < clientCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := listener.Accept()
			if err != nil {
				serverErrCh <- err
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)
			line, err := reader.ReadString('\n')
			if err != nil {
				serverErrCh <- err
				return
			}
			conn.Write([]byte(line)) // echo back
		}()
	}

	// Dial clients concurrently
	clientWg := sync.WaitGroup{}
	clientErrCh := make(chan error, clientCount)

	for i := 0; i < clientCount; i++ {
		clientWg.Add(1)
		nonce := fmt.Sprintf("nonce-%d\n", i)
		go func(msg string) {
			defer clientWg.Done()
			conn, err := DialPipe(name, 3*time.Second)
			if err != nil {
				clientErrCh <- err
				return
			}
			defer conn.Close()

			if _, err := conn.Write([]byte(msg)); err != nil {
				clientErrCh <- err
				return
			}

			echo, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				clientErrCh <- err
				return
			}
			if echo != msg {
				clientErrCh <- fmt.Errorf("echo mismatch: got %q, want %q", echo, msg)
				return
			}
		}(nonce)
	}

	clientWg.Wait()
	wg.Wait()
	close(serverErrCh)
	close(clientErrCh)

	for err := range serverErrCh {
		t.Errorf("server error: %v", err)
	}
	for err := range clientErrCh {
		t.Errorf("client error: %v", err)
	}
}

// TestPipe_CloseUnblocksAccept verifies that calling Close() on a listening
// pipe immediately unblocks a pending Accept() call with net.ErrClosed.
func TestPipe_CloseUnblocksAccept(t *testing.T) {
	name := testPipeName(t)
	sddl, err := CurrentUserSDDL()
	if err != nil {
		t.Fatalf("CurrentUserSDDL: %v", err)
	}

	listener, err := ListenPipe(name, sddl)
	if err != nil {
		t.Fatalf("ListenPipe: %v", err)
	}

	acceptErrCh := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		acceptErrCh <- err
	}()

	// Wait briefly so Accept is blocked in ConnectNamedPipe
	time.Sleep(100 * time.Millisecond)

	if err := listener.Close(); err != nil {
		t.Fatalf("listener.Close: %v", err)
	}

	select {
	case err := <-acceptErrCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected net.ErrClosed, got: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Accept did not unblock within 1s after Close()")
	}
}

// TestPipe_SDDL_SecurityRejection verifies that connecting with an unauthorized or denied
// security token is cleanly rejected by the Windows kernel access check.
func TestPipe_SDDL_SecurityRejection(t *testing.T) {
	name := testPipeName(t)

	// Construct an SDDL that explicitly DENIES the current user SID
	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}
	userSID := tu.User.Sid.String()

	// Deny current user, allow SYSTEM and Administrators
	denySDDL := fmt.Sprintf("D:P(D;;GA;;;%s)(A;;GA;;;SY)(A;;GA;;;BA)", userSID)

	listener, err := ListenPipe(name, denySDDL)
	if err != nil {
		t.Fatalf("ListenPipe with deny SDDL: %v", err)
	}
	defer listener.Close()

	// Dialing should be rejected by the kernel with ERROR_ACCESS_DENIED / os.ErrPermission
	_, err = DialPipe(name, 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected access denied error, got nil")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("expected os.ErrPermission in chain, got: %v", err)
	}
}

// TestPipe_ClientPID verifies that the supervisor listener can accurately
// determine the client's process ID.
func TestPipe_ClientPID(t *testing.T) {
	name := testPipeName(t)
	sddl, err := CurrentUserSDDL()
	if err != nil {
		t.Fatalf("CurrentUserSDDL: %v", err)
	}

	listener, err := ListenPipe(name, sddl)
	if err != nil {
		t.Fatalf("ListenPipe: %v", err)
	}
	defer listener.Close()

	var clientPID uint32
	serverDone := make(chan error, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		pid, err := ClientPID(conn)
		if err != nil {
			serverDone <- err
			return
		}
		clientPID = pid
		serverDone <- nil
	}()

	clientConn, err := DialPipe(name, 2*time.Second)
	if err != nil {
		t.Fatalf("DialPipe: %v", err)
	}
	defer clientConn.Close()

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for client PID check")
	}

	expectedPID := uint32(os.Getpid())
	if clientPID != expectedPID {
		t.Fatalf("ClientPID = %d, want %d", clientPID, expectedPID)
	}

	// Also verify GetNamedPipeClientProcessId parity
	pidAlias, err := GetNamedPipeClientProcessId(clientConn)
	if err != nil {
		t.Logf("GetNamedPipeClientProcessId on client side: %v (expected if client-side handle does not have server info)", err)
	} else {
		t.Logf("GetNamedPipeClientProcessId: %d", pidAlias)
	}
}

// TestPipe_Deadlines verifies that Read deadlines are respected and return timeout errors.
func TestPipe_Deadlines(t *testing.T) {
	name := testPipeName(t)
	sddl, err := CurrentUserSDDL()
	if err != nil {
		t.Fatalf("CurrentUserSDDL: %v", err)
	}

	listener, err := ListenPipe(name, sddl)
	if err != nil {
		t.Fatalf("ListenPipe: %v", err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		// Set short read deadline; client does not send anything
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		buf := make([]byte, 64)
		_, err = conn.Read(buf)
		if err == nil {
			serverDone <- errors.New("expected deadline timeout error, got nil")
			return
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			serverDone <- fmt.Errorf("expected os.ErrDeadlineExceeded, got: %w", err)
			return
		}
		serverDone <- nil
	}()

	clientConn, err := DialPipe(name, 2*time.Second)
	if err != nil {
		t.Fatalf("DialPipe: %v", err)
	}
	defer clientConn.Close()

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("deadline error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server deadline read did not time out")
	}
}

// TestPipe_ServerWithIPCServerAndClient verifies IPCServer and IPCClient over real Named Pipes.
func TestPipe_ServerWithIPCServerAndClient(t *testing.T) {
	name := testPipeName(t)
	sddl, err := CurrentUserSDDL()
	if err != nil {
		t.Fatalf("CurrentUserSDDL: %v", err)
	}

	listener, err := ListenPipe(name, sddl)
	if err != nil {
		t.Fatalf("ListenPipe: %v", err)
	}

	server := NewIPCServer()
	server.RegisterHandler(MsgHeartbeat, func(msg *IPCMessage) (*IPCMessage, error) {
		return nil, nil
	})
	server.RegisterHandler(MsgGetInactive, func(msg *IPCMessage) (*IPCMessage, error) {
		return &IPCMessage{
			Type: MsgInactiveResp,
			Slot: "slot_a",
			Path: `C:\Program Files\HomelabRMM\bin\slot_a\rmm-agent.exe`,
		}, nil
	})

	if err := server.Start(listener); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	defer server.Stop()

	client := NewIPCClient(func() (net.Conn, error) {
		return DialPipe(name, 2*time.Second)
	}, 2*time.Second)
	defer client.Close()

	// Send heartbeat
	err = client.Send(&IPCMessage{
		Type:     MsgHeartbeat,
		PID:      os.Getpid(),
		RSSBytes: 2048,
	})
	if err != nil {
		t.Fatalf("Send heartbeat over Named Pipe failed: %v", err)
	}

	// RoundTrip request
	resp, err := client.RoundTrip(&IPCMessage{
		Type: MsgGetInactive,
	})
	if err != nil {
		t.Fatalf("RoundTrip over Named Pipe failed: %v", err)
	}
	if resp.Type != MsgInactiveResp {
		t.Fatalf("expected inactive_slot_resp, got %s", resp.Type)
	}
	if resp.Slot != "slot_a" {
		t.Fatalf("expected slot_a, got %s", resp.Slot)
	}
}
