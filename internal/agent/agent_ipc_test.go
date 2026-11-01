package agent

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/supervisor"
)

func TestAgentDetectSupervisorIPC(t *testing.T) {
	origP1 := os.Getenv("HOMELAB_RMM_IPC_PIPE")
	origP2 := os.Getenv("RMM_SUPERVISOR_PIPE")
	origS1 := os.Getenv("HOMELAB_RMM_IPC_SOCKET")
	origS2 := os.Getenv("RMM_SUPERVISOR_SOCKET")
	defer func() {
		os.Setenv("HOMELAB_RMM_IPC_PIPE", origP1)
		os.Setenv("RMM_SUPERVISOR_PIPE", origP2)
		os.Setenv("HOMELAB_RMM_IPC_SOCKET", origS1)
		os.Setenv("RMM_SUPERVISOR_SOCKET", origS2)
	}()

	os.Unsetenv("HOMELAB_RMM_IPC_PIPE")
	os.Unsetenv("RMM_SUPERVISOR_PIPE")
	os.Unsetenv("HOMELAB_RMM_IPC_SOCKET")
	os.Unsetenv("RMM_SUPERVISOR_SOCKET")

	path, ok := detectSupervisorIPC()
	if ok || path != "" {
		t.Fatalf("expected no supervisor IPC detected, got ok=%v, path=%s", ok, path)
	}

	testPipe := `\\.\pipe\test-homelab-pipe`
	os.Setenv("HOMELAB_RMM_IPC_PIPE", testPipe)
	path, ok = detectSupervisorIPC()
	if !ok || path != testPipe {
		t.Fatalf("expected pipe %s, got ok=%v, path=%s", testPipe, ok, path)
	}

	os.Unsetenv("HOMELAB_RMM_IPC_PIPE")
	os.Setenv("RMM_SUPERVISOR_PIPE", testPipe)
	path, ok = detectSupervisorIPC()
	if !ok || path != testPipe {
		t.Fatalf("expected pipe %s via RMM_SUPERVISOR_PIPE, got ok=%v, path=%s", testPipe, ok, path)
	}

	os.Unsetenv("RMM_SUPERVISOR_PIPE")
	testSock := `/run/homelab-rmm/test.sock`
	os.Setenv("HOMELAB_RMM_IPC_SOCKET", testSock)
	path, ok = detectSupervisorIPC()
	if !ok || path != testSock {
		t.Fatalf("expected socket %s, got ok=%v, path=%s", testSock, ok, path)
	}

	os.Unsetenv("HOMELAB_RMM_IPC_SOCKET")
	os.Setenv("RMM_SUPERVISOR_SOCKET", testSock)
	path, ok = detectSupervisorIPC()
	if !ok || path != testSock {
		t.Fatalf("expected socket %s via RMM_SUPERVISOR_SOCKET, got ok=%v, path=%s", testSock, ok, path)
	}
}

func TestAgentHeartbeatLoop(t *testing.T) {
	pipe := supervisor.NewInMemoryPipe()
	defer pipe.Close()

	srv := supervisor.NewIPCServer()
	defer srv.Stop()

	received := make(chan *supervisor.IPCMessage, 10)
	srv.RegisterHandler(supervisor.MsgHeartbeat, func(msg *supervisor.IPCMessage) (*supervisor.IPCMessage, error) {
		received <- msg
		return nil, nil
	})

	if err := srv.Start(pipe); err != nil {
		t.Fatalf("failed to start srv: %v", err)
	}

	clientConn, err := pipe.Dial()
	if err != nil {
		t.Fatalf("dial pipe: %v", err)
	}

	client := supervisor.NewIPCClient(nil, 2*time.Second)
	_ = client.Connect(clientConn)
	defer client.Close()

	agent := New(&Config{})
	agent.SetIPCClient(client)
	agent.SetHeartbeatInterval(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agent.initSupervisorIPC(ctx)
	defer agent.closeSupervisorIPC()

	select {
	case hb := <-received:
		if hb.PID != os.Getpid() {
			t.Errorf("expected PID %d, got %d", os.Getpid(), hb.PID)
		}
		if hb.RSSBytes == 0 {
			t.Errorf("expected non-zero RSS bytes")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for agent heartbeat")
	}
}

func TestAgentNotifyHealthy(t *testing.T) {
	pipe := supervisor.NewInMemoryPipe()
	defer pipe.Close()

	srv := supervisor.NewIPCServer()
	defer srv.Stop()

	received := make(chan *supervisor.IPCMessage, 1)
	srv.RegisterHandler(supervisor.MsgNotifyHealthy, func(msg *supervisor.IPCMessage) (*supervisor.IPCMessage, error) {
		received <- msg
		return nil, nil
	})
	if err := srv.Start(pipe); err != nil {
		t.Fatalf("failed to start srv: %v", err)
	}

	clientConn, err := pipe.Dial()
	if err != nil {
		t.Fatalf("dial pipe: %v", err)
	}

	client := supervisor.NewIPCClient(nil, 2*time.Second)
	_ = client.Connect(clientConn)
	defer client.Close()

	agent := New(&Config{})
	agent.SetIPCClient(client)

	agent.notifyHealthy()

	select {
	case msg := <-received:
		if msg.PID != os.Getpid() {
			t.Errorf("expected PID %d, got %d", os.Getpid(), msg.PID)
		}
		if msg.Version != Version {
			t.Errorf("expected Version %s, got %s", Version, msg.Version)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for notify_healthy")
	}
}

func TestAgentStandaloneFallback(t *testing.T) {
	origP1 := os.Getenv("HOMELAB_RMM_IPC_PIPE")
	origP2 := os.Getenv("RMM_SUPERVISOR_PIPE")
	origS1 := os.Getenv("HOMELAB_RMM_IPC_SOCKET")
	origS2 := os.Getenv("RMM_SUPERVISOR_SOCKET")
	defer func() {
		os.Setenv("HOMELAB_RMM_IPC_PIPE", origP1)
		os.Setenv("RMM_SUPERVISOR_PIPE", origP2)
		os.Setenv("HOMELAB_RMM_IPC_SOCKET", origS1)
		os.Setenv("RMM_SUPERVISOR_SOCKET", origS2)
	}()

	os.Unsetenv("HOMELAB_RMM_IPC_PIPE")
	os.Unsetenv("RMM_SUPERVISOR_PIPE")
	os.Unsetenv("HOMELAB_RMM_IPC_SOCKET")
	os.Unsetenv("RMM_SUPERVISOR_SOCKET")

	agent := New(&Config{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Run should exit cleanly without panicking
	err := agent.Run(ctx)
	if err != nil {
		t.Errorf("expected nil error on cancelled context, got %v", err)
	}
	if agent.IPCClient() != nil {
		t.Errorf("expected nil IPCClient in standalone mode")
	}

	// Calling notifyHealthy in standalone mode should be a safe no-op
	agent.notifyHealthy()
}

func TestGetProcessRSS(t *testing.T) {
	rss := getProcessRSS()
	if rss == 0 {
		t.Errorf("getProcessRSS returned 0")
	}
}

// TestAgentDetectSupervisorIPCPrefersPlatformEndpoint: when both kinds are
// exported, the worker must dial the one its platform listens on. A Linux
// worker that took the Windows pipe name ran standalone and was killed by the
// watchdog every 30 seconds.
func TestAgentDetectSupervisorIPCPrefersPlatformEndpoint(t *testing.T) {
	t.Setenv("HOMELAB_RMM_IPC_PIPE", `\\.\pipe\test-homelab-pipe`)
	t.Setenv("RMM_SUPERVISOR_PIPE", `\\.\pipe\test-homelab-pipe`)
	t.Setenv("HOMELAB_RMM_IPC_SOCKET", "/run/homelab-rmm/test.sock")
	t.Setenv("RMM_SUPERVISOR_SOCKET", "/run/homelab-rmm/test.sock")
	want := "/run/homelab-rmm/test.sock"
	if runtime.GOOS == "windows" {
		want = `\\.\pipe\test-homelab-pipe`
	}
	path, ok := detectSupervisorIPC()
	if !ok || path != want {
		t.Fatalf("detectSupervisorIPC() = %q, %v; want %q on %s", path, ok, want, runtime.GOOS)
	}
}
