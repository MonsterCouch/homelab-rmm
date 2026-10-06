//go:build linux

package supervisor

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestListenDialUDS_RoundTrip verifies that a Unix Domain Socket listener and client
// can perform full duplex communication, validates 0600 file mode and 0700 directory mode,
// and verifies clean unlinking of the socket file upon Close().
func TestListenDialUDS_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	listener, err := ListenUDS(sockPath)
	if err != nil {
		t.Fatalf("ListenUDS failed: %v", err)
	}
	defer listener.Close()

	// Verify file permissions 0600
	fi, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("Stat socket failed: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("expected socket permissions 0600, got %#o", perm)
	}

	// Verify directory permissions 0700
	dirFi, err := os.Stat(tmpDir)
	if err != nil {
		t.Fatalf("Stat directory failed: %v", err)
	}
	if perm := dirFi.Mode().Perm(); perm != 0700 {
		t.Errorf("expected dir permissions 0700, got %#o", perm)
	}

	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- fmt.Errorf("Accept error: %w", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			errCh <- fmt.Errorf("Read error: %w", err)
			return
		}

		if _, err := conn.Write(append([]byte("ACK:"), buf[:n]...)); err != nil {
			errCh <- fmt.Errorf("Write error: %w", err)
			return
		}
		errCh <- nil
	}()

	clientConn, err := DialUDS(sockPath, 2*time.Second)
	if err != nil {
		t.Fatalf("DialUDS failed: %v", err)
	}
	defer clientConn.Close()

	payload := []byte("PING-HEARTBEAT\n")
	if _, err := clientConn.Write(payload); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	reply := make([]byte, 1024)
	n, err := clientConn.Read(reply)
	if err != nil {
		t.Fatalf("client read failed: %v", err)
	}

	expected := append([]byte("ACK:"), payload...)
	if !bytes.Equal(reply[:n], expected) {
		t.Errorf("got %q, expected %q", string(reply[:n]), string(expected))
	}

	if err := <-errCh; err != nil {
		t.Fatalf("server error: %v", err)
	}

	// Close listener and verify socket is unlinked
	if err := listener.Close(); err != nil {
		t.Fatalf("listener Close failed: %v", err)
	}

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Errorf("expected socket file to be unlinked after Close, but it still exists")
	}
}

// TestListenUDS_StaleSocketCleanup verifies that a leftover dead socket is automatically
// detected via probe dial and unlinked during listener startup.
func TestListenUDS_StaleSocketCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "stale.sock")

	// Step 1: Create a listener and abruptly simulate a crash
	rawListener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	rawListener.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = rawListener.Close()

	// Ensure the dead socket file exists
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("expected dead socket file to exist: %v", err)
	}

	// Step 2: ListenUDS should detect that the socket is dead (ECONNREFUSED) and unlink it automatically
	listener, err := ListenUDS(sockPath)
	if err != nil {
		t.Fatalf("ListenUDS failed to clean up stale socket: %v", err)
	}
	defer listener.Close()

	// Verify client can connect to the revived listener
	client, err := DialUDS(sockPath, 1*time.Second)
	if err != nil {
		t.Fatalf("DialUDS failed after stale cleanup: %v", err)
	}
	_ = client.Close()
}

// TestListenUDS_ActiveSocketConflict verifies that if an active supervisor is already
// listening, a second listener attempt fails immediately without corrupting the existing socket.
func TestListenUDS_ActiveSocketConflict(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "active.sock")

	l1, err := ListenUDS(sockPath)
	if err != nil {
		t.Fatalf("first ListenUDS failed: %v", err)
	}
	defer l1.Close()

	// Second instance should fail because an active process is listening
	l2, err := ListenUDS(sockPath)
	if err == nil {
		_ = l2.Close()
		t.Fatalf("expected second ListenUDS to fail, but it succeeded")
	}

	if !strings.Contains(err.Error(), "already running and listening") {
		t.Errorf("expected error about active process, got: %v", err)
	}
}

// TestListenUDS_PathTooLong verifies that paths exceeding 107 bytes fail with a descriptive error.
func TestListenUDS_PathTooLong(t *testing.T) {
	tmpDir := t.TempDir()
	longName := strings.Repeat("x", 120) + ".sock"
	longPath := filepath.Join(tmpDir, longName)

	_, err := ListenUDS(longPath)
	if err == nil {
		t.Fatalf("expected error for path length > 107, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds Linux maximum") {
		t.Errorf("expected path length error, got: %v", err)
	}

	_, err = DialUDS(longPath, 100*time.Millisecond)
	if err == nil {
		t.Fatalf("expected dial error for long path, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds Linux maximum") {
		t.Errorf("expected dial path length error, got: %v", err)
	}
}

// TestLinux_ServerWithIPCServerAndClient verifies IPCServer and IPCClient running over Linux UDS.
func TestLinux_ServerWithIPCServerAndClient(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "ipc.sock")

	listener, err := ListenUDS(sockPath)
	if err != nil {
		t.Fatalf("ListenUDS: %v", err)
	}

	server := NewIPCServer()
	server.RegisterHandler(MsgHeartbeat, func(msg *IPCMessage) (*IPCMessage, error) {
		return nil, nil
	})
	server.RegisterHandler(MsgGetInactive, func(msg *IPCMessage) (*IPCMessage, error) {
		return &IPCMessage{
			Type: MsgInactiveResp,
			Slot: "slot_b",
			Path: "/opt/homelab-rmm/bin/slot_b/rmm-agent",
		}, nil
	})

	if err := server.Start(listener); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	defer server.Stop()

	client := NewIPCClient(func() (net.Conn, error) {
		return DialUDS(sockPath, 2*time.Second)
	}, 2*time.Second)
	defer client.Close()

	// Send heartbeat
	err = client.Send(&IPCMessage{
		Type:     MsgHeartbeat,
		PID:      os.Getpid(),
		RSSBytes: 4096,
	})
	if err != nil {
		t.Fatalf("Send heartbeat over UDS failed: %v", err)
	}

	// RoundTrip request
	resp, err := client.RoundTrip(&IPCMessage{
		Type: MsgGetInactive,
	})
	if err != nil {
		t.Fatalf("RoundTrip over UDS failed: %v", err)
	}
	if resp.Type != MsgInactiveResp {
		t.Fatalf("expected inactive_slot_resp, got %s", resp.Type)
	}
	if resp.Slot != "slot_b" {
		t.Fatalf("expected slot_b, got %s", resp.Slot)
	}
}
