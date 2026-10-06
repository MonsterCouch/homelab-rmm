package supervisor

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestHelperWorkerProcess is the entry point for simulated worker subprocesses.
// It is invoked by executing the test binary with GO_TEST_WORKER_SUBPROCESS=1.
func TestHelperWorkerProcess(t *testing.T) {
	if os.Getenv("GO_TEST_WORKER_SUBPROCESS") != "1" {
		return
	}

	mode := os.Getenv("MOCK_WORKER_MODE")
	if mode == "" {
		// Attempt to read mode.txt from the binary directory (or through the current junction)
		dir := filepath.Dir(os.Args[0])
		if data, err := os.ReadFile(filepath.Join(dir, "mode.txt")); err == nil {
			mode = strings.TrimSpace(string(data))
		}
	}
	if mode == "" {
		mode = "healthy"
	}

	if mode == "crash" {
		os.Exit(1)
	}

	pipeName := os.Getenv("RMM_SUPERVISOR_PIPE")
	if pipeName == "" {
		pipeName = os.Getenv("HOMELAB_RMM_IPC_PIPE")
	}
	sockPath := os.Getenv("RMM_SUPERVISOR_SOCKET")
	if sockPath == "" {
		sockPath = os.Getenv("HOMELAB_RMM_IPC_SOCKET")
	}

	// Dial supervisor IPC with retry
	var conn net.Conn
	var err error
	for i := 0; i < 50; i++ {
		if runtime.GOOS == "windows" && pipeName != "" {
			conn, err = DialPipe(pipeName, 2*time.Second)
		} else if sockPath != "" {
			conn, err = DialUDS(sockPath, 2*time.Second)
		}
		if err == nil && conn != nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if conn == nil {
		os.Exit(2)
	}
	defer conn.Close()

	client := NewIPCClient(nil, 2*time.Second)
	_ = client.Connect(conn)
	defer client.Close()

	version := os.Getenv("MOCK_WORKER_VERSION")
	if version == "" {
		version = "v1.0.0"
	}

	switch mode {
	case "healthy":
		_ = client.Send(&IPCMessage{
			Type:    MsgNotifyHealthy,
			Version: version,
			PID:     os.Getpid(),
		})
		for {
			_ = client.Send(&IPCMessage{
				Type:     MsgHeartbeat,
				PID:      os.Getpid(),
				RSSBytes: 1024 * 1024 * 25,
			})
			time.Sleep(40 * time.Millisecond)
		}

	case "heartbeat_only", "no_healthy":
		for {
			_ = client.Send(&IPCMessage{
				Type:     MsgHeartbeat,
				PID:      os.Getpid(),
				RSSBytes: 1024 * 1024 * 25,
			})
			time.Sleep(40 * time.Millisecond)
		}

	case "hung":
		_ = client.Send(&IPCMessage{
			Type:     MsgHeartbeat,
			PID:      os.Getpid(),
			RSSBytes: 1024 * 1024 * 25,
		})
		// Block indefinitely without sending further heartbeats
		select {}

	case "request_restart":
		_ = client.Send(&IPCMessage{
			Type:    MsgRequestRestart,
			Reason:  "update_staged",
			Version: "v2.0.0",
			PID:     os.Getpid(),
		})
		time.Sleep(100 * time.Millisecond)
		os.Exit(0)

	case "get_inactive":
		resp, err := client.RoundTrip(&IPCMessage{
			Type: MsgGetInactive,
		})
		if err != nil || resp == nil {
			os.Exit(3)
		}
		os.Exit(0)
	}
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return os.Chmod(dst, 0755)
}

func setupSupervisorTest(t *testing.T, customMode ...string) (*Supervisor, *SlotManager, string) {
	t.Helper()
	baseDir := t.TempDir()

	slots, err := InitSlots(baseDir)
	if err != nil {
		t.Fatalf("InitSlots: %v", err)
	}

	slotABin := filepath.Join(slots.GetActiveSlotDir(), BinaryExecutableName)
	slotBBin := filepath.Join(slots.GetInactiveSlotDir(), BinaryExecutableName)

	// Copy current test executable to slot_a and slot_b
	if err := copyExecutable(os.Args[0], slotABin); err != nil {
		t.Fatalf("copy executable to slot_a: %v", err)
	}
	if err := copyExecutable(os.Args[0], slotBBin); err != nil {
		t.Fatalf("copy executable to slot_b: %v", err)
	}

	initialMode := "healthy"
	if len(customMode) > 0 && customMode[0] != "" {
		initialMode = customMode[0]
	}

	_ = os.WriteFile(filepath.Join(slots.GetActiveSlotDir(), "mode.txt"), []byte(initialMode), 0644)
	_ = os.WriteFile(filepath.Join(slots.GetInactiveSlotDir(), "mode.txt"), []byte("healthy"), 0644)

	var pipeName string
	var socketPath string
	if runtime.GOOS == "windows" {
		pipeName = fmt.Sprintf(`\\.\pipe\test-sup-%d-%d`, os.Getpid(), time.Now().UnixNano())
	} else {
		socketPath = filepath.Join(baseDir, "supervisor.sock")
	}

	cfg := SupervisorConfig{
		BaseDir:                baseDir,
		Slots:                  slots,
		PipeName:               pipeName,
		SocketPath:             socketPath,
		WorkerArgs:             []string{"-test.run=^TestHelperWorkerProcess$", "--"},
		Env:                    []string{"GO_TEST_WORKER_SUBPROCESS=1"},
		RestartDelay:           50 * time.Millisecond,
		MaxRestartDelay:        500 * time.Millisecond,
		ResetCrashAfter:        2 * time.Second,
		HeartbeatTimeout:       400 * time.Millisecond,
		HeartbeatCheckInterval: 40 * time.Millisecond,
		RollbackTimeout:        600 * time.Millisecond,
		RollbackCheckInterval:  40 * time.Millisecond,
	}

	sup, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	return sup, slots, baseDir
}

func requireCondition(t *testing.T, timeout time.Duration, cond func() bool, errMsg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("condition timed out after %v: %s", timeout, errMsg)
}

// TestSupervisor_StartAndReceiveHeartbeats verifies normal worker launch and heartbeat receipt.
func TestSupervisor_StartAndReceiveHeartbeats(t *testing.T) {
	sup, _, _ := setupSupervisorTest(t, "healthy")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- sup.Start(ctx)
	}()

	<-sup.Ready()

	requireCondition(t, 4*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.HeartbeatCount() >= 1
	}, "worker failed to report heartbeats")

	if sup.State() != StateRunning {
		t.Errorf("Expected state running, got %s", sup.State())
	}
	if time.Since(sup.LastHeartbeat()) > 2*time.Second {
		t.Errorf("Heartbeat timestamp is stale: %v", sup.LastHeartbeat())
	}

	if err := sup.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	<-done
	if sup.State() != StateStopped {
		t.Errorf("Expected state stopped, got %s", sup.State())
	}
}

// TestSupervisor_RestartOnWorkerKill kills worker process and verifies supervisor restarts it in <= 5 seconds.
func TestSupervisor_RestartOnWorkerKill(t *testing.T) {
	sup, _, _ := setupSupervisorTest(t, "healthy")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	requireCondition(t, 4*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.HeartbeatCount() >= 1
	}, "initial worker failed to start")

	initialPID := sup.WorkerPID()
	killTime := time.Now()

	// Terminate the worker process forcibly (simulating taskkill /F /PID)
	proc, err := os.FindProcess(initialPID)
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	_ = proc.Kill()

	// Verify supervisor restarts worker in <= 5 seconds per Requirement R1
	requireCondition(t, 5*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.WorkerPID() != initialPID && sup.RestartCount() >= 1
	}, "supervisor failed to restart killed worker in <= 5 seconds")

	latency := time.Since(killTime)
	if latency > 5*time.Second {
		t.Fatalf("restart latency exceeded 5 seconds: %v", latency)
	}
	t.Logf("Worker killed (PID %d) and restarted (PID %d) in %v", initialPID, sup.WorkerPID(), latency)

	// Verify restarted worker sends heartbeats
	currentHB := sup.HeartbeatCount()
	requireCondition(t, 3*time.Second, func() bool {
		return sup.HeartbeatCount() > currentHB
	}, "restarted worker failed to send heartbeats")

	_ = sup.Stop()
}

// TestSupervisor_WatchdogKillsHungWorker verifies watchdog terminates hung worker and supervisor restarts it.
func TestSupervisor_WatchdogKillsHungWorker(t *testing.T) {
	sup, _, _ := setupSupervisorTest(t, "hung")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	requireCondition(t, 3*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.HeartbeatCount() >= 1
	}, "initial worker failed to start")

	initialPID := sup.WorkerPID()

	// Wait for watchdog to detect absence of heartbeats and kill hung worker
	requireCondition(t, 4*time.Second, func() bool {
		return sup.WatchdogKills() >= 1
	}, "watchdog failed to kill hung worker")

	t.Logf("Watchdog terminated hung worker (PID %d). Kills: %d", initialPID, sup.WatchdogKills())

	// Wait for supervisor to restart worker
	requireCondition(t, 4*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.WorkerPID() != initialPID
	}, "supervisor failed to restart worker after watchdog kill")

	_ = sup.Stop()
}

// TestSupervisor_RollbackCircuitOnCandidateTimeout verifies rollback when candidate fails to send notify_healthy.
func TestSupervisor_RollbackCircuitOnCandidateTimeout(t *testing.T) {
	sup, slots, _ := setupSupervisorTest(t, "healthy")

	// slot_a is healthy, slot_b will send heartbeats but NEVER send notify_healthy
	_ = os.WriteFile(filepath.Join(slots.GetActiveSlotDir(), "mode.txt"), []byte("healthy"), 0644)
	_ = os.WriteFile(filepath.Join(slots.GetInactiveSlotDir(), "mode.txt"), []byte("heartbeat_only"), 0644)

	// Promote slot_b to pending
	if err := slots.PromotePending("v2.0.0"); err != nil {
		t.Fatalf("PromotePending: %v", err)
	}
	if slots.GetState().PendingSlot != "slot_b" {
		t.Fatalf("Expected PendingSlot slot_b, got %s", slots.GetState().PendingSlot)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	// Wait for candidate worker to start
	requireCondition(t, 3*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.HeartbeatCount() >= 1
	}, "candidate worker failed to start")

	// Wait for rollback circuit to trigger upon RollbackTimeout (600ms)
	requireCondition(t, 5*time.Second, func() bool {
		st := slots.GetState()
		return st.ActiveSlot == "slot_a" && st.PendingSlot == "" && st.RollbackCount >= 1
	}, "rollback circuit failed to trigger on candidate timeout")

	st := slots.GetState()
	if st.ActiveSlot != "slot_a" {
		t.Errorf("Expected active slot slot_a, got %s", st.ActiveSlot)
	}
	if st.RollbackCount != 1 {
		t.Errorf("Expected rollback count 1, got %d", st.RollbackCount)
	}

	t.Logf("Rollback circuit successfully triggered on candidate timeout! Active slot reverted to %s", st.ActiveSlot)
	_ = sup.Stop()
}

// TestSupervisor_RollbackCircuitOnCandidateCrash verifies immediate rollback when candidate crashes.
func TestSupervisor_RollbackCircuitOnCandidateCrash(t *testing.T) {
	sup, slots, _ := setupSupervisorTest(t, "healthy")

	_ = os.WriteFile(filepath.Join(slots.GetActiveSlotDir(), "mode.txt"), []byte("healthy"), 0644)
	_ = os.WriteFile(filepath.Join(slots.GetInactiveSlotDir(), "mode.txt"), []byte("crash"), 0644)

	// Promote slot_b to pending
	if err := slots.PromotePending("v2.0.0"); err != nil {
		t.Fatalf("PromotePending: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	// Candidate will crash immediately, triggering immediate rollback and respawn of slot_a
	requireCondition(t, 5*time.Second, func() bool {
		st := slots.GetState()
		return st.ActiveSlot == "slot_a" && st.PendingSlot == "" && st.RollbackCount >= 1 && sup.HeartbeatCount() >= 1
	}, "immediate rollback on candidate crash failed")

	st := slots.GetState()
	if st.ActiveSlot != "slot_a" {
		t.Errorf("Expected active slot slot_a, got %s", st.ActiveSlot)
	}
	if st.RollbackCount != 1 {
		t.Errorf("Expected rollback count 1, got %d", st.RollbackCount)
	}

	t.Logf("Immediate rollback on candidate crash successful! Reverted to %s with count %d", st.ActiveSlot, st.RollbackCount)
	_ = sup.Stop()
}

// TestSupervisor_ConfirmHealthyCommitsUpdate verifies that candidate sending notify_healthy commits update.
func TestSupervisor_ConfirmHealthyCommitsUpdate(t *testing.T) {
	sup, slots, _ := setupSupervisorTest(t, "healthy")

	_ = os.WriteFile(filepath.Join(slots.GetActiveSlotDir(), "mode.txt"), []byte("healthy"), 0644)
	_ = os.WriteFile(filepath.Join(slots.GetInactiveSlotDir(), "mode.txt"), []byte("healthy"), 0644)

	// Promote slot_b to pending
	if err := slots.PromotePending("v2.0.0"); err != nil {
		t.Fatalf("PromotePending: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	// Wait for candidate to send notify_healthy and commit slot_b
	requireCondition(t, 4*time.Second, func() bool {
		st := slots.GetState()
		return st.ActiveSlot == "slot_b" && st.PendingSlot == ""
	}, "update failed to commit upon notify_healthy")

	st := slots.GetState()
	if st.ActiveSlot != "slot_b" {
		t.Errorf("Expected active slot slot_b, got %s", st.ActiveSlot)
	}
	if st.RollbackCount != 0 {
		t.Errorf("Expected rollback count 0, got %d", st.RollbackCount)
	}

	t.Logf("Update successfully committed to slot_b upon health notification!")
	_ = sup.Stop()
}

// TestSupervisor_RequestRestartPromotesAndRestarts verifies update staged request promotes slot and restarts worker.
func TestSupervisor_RequestRestartPromotesAndRestarts(t *testing.T) {
	sup, slots, _ := setupSupervisorTest(t, "request_restart")

	_ = os.WriteFile(filepath.Join(slots.GetActiveSlotDir(), "mode.txt"), []byte("request_restart"), 0644)
	_ = os.WriteFile(filepath.Join(slots.GetInactiveSlotDir(), "mode.txt"), []byte("healthy"), 0644)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	// Worker in slot_a emits request_restart with reason update_staged.
	// Supervisor handles this by calling PromotePending and restarting the worker into trial.
	requireCondition(t, 4*time.Second, func() bool {
		st := slots.GetState()
		return st.PendingSlot == "slot_b"
	}, "supervisor failed to promote pending slot on request_restart")

	t.Logf("Request restart successfully promoted slot_b to pending!")
	_ = sup.Stop()
}

// TestSupervisor_GetInactiveSlot verifies querying inactive slot name and staging directory over IPC.
func TestSupervisor_GetInactiveSlot(t *testing.T) {
	sup, slots, _ := setupSupervisorTest(t, "healthy")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	requireCondition(t, 3*time.Second, func() bool {
		return sup.WorkerPID() > 0
	}, "worker started")

	var conn net.Conn
	var err error
	for i := 0; i < 20; i++ {
		if runtime.GOOS == "windows" {
			conn, err = DialPipe(sup.cfg.PipeName, 2*time.Second)
		} else {
			conn, err = DialUDS(sup.cfg.SocketPath, 2*time.Second)
		}
		if err == nil {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("Dial supervisor IPC: %v", err)
	}
	defer conn.Close()

	client := NewIPCClient(nil, 2*time.Second)
	_ = client.Connect(conn)
	defer client.Close()

	resp, err := client.RoundTrip(&IPCMessage{Type: MsgGetInactive})
	if err != nil {
		t.Fatalf("RoundTrip MsgGetInactive: %v", err)
	}

	if resp.Type != MsgInactiveResp {
		t.Errorf("Expected MsgInactiveResp, got %s", resp.Type)
	}
	if resp.Slot != slots.GetInactiveSlot() {
		t.Errorf("Expected slot %s, got %s", slots.GetInactiveSlot(), resp.Slot)
	}
	if resp.Path != slots.GetInactiveSlotDir() {
		t.Errorf("Expected path %s, got %s", slots.GetInactiveSlotDir(), resp.Path)
	}

	t.Logf("GetInactiveSlot verified: slot=%s, path=%s", resp.Slot, resp.Path)
	_ = sup.Stop()
}

// TestSupervisor_GracefulShutdown verifies clean worker and supervisor termination on context cancellation.
func TestSupervisor_GracefulShutdown(t *testing.T) {
	sup, _, _ := setupSupervisorTest(t, "healthy")

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- sup.Start(ctx)
	}()

	<-sup.Ready()

	requireCondition(t, 3*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.HeartbeatCount() >= 1
	}, "worker running")

	workerPID := sup.WorkerPID()

	// Cancel context to initiate shutdown
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("supervisor failed to stop within 4 seconds")
	}

	if sup.State() != StateStopped {
		t.Errorf("Expected supervisor state stopped, got %s", sup.State())
	}

	// Verify child process was terminated cleanly
	requireCondition(t, 3*time.Second, func() bool {
		return !isProcessRunning(workerPID)
	}, "worker process was not terminated on supervisor shutdown")

	t.Logf("Graceful shutdown confirmed: worker PID %d terminated cleanly", workerPID)
}

// TestSupervisor_StaleBootRollback verifies stale pending update rolls back on boot before worker spawns.
func TestSupervisor_StaleBootRollback(t *testing.T) {
	sup, slots, _ := setupSupervisorTest(t, "healthy")

	// Set pending update that expired 10 minutes ago
	if err := slots.PromotePending("v2.0.0"); err != nil {
		t.Fatalf("PromotePending: %v", err)
	}
	if err := slots.SetPendingStartedAtForTest(time.Now().Add(-10 * time.Minute)); err != nil {
		t.Fatalf("SetPendingStartedAtForTest: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	// Supervisor on startup should immediately roll back stale update
	requireCondition(t, 3*time.Second, func() bool {
		st := slots.GetState()
		return st.ActiveSlot == "slot_a" && st.PendingSlot == "" && st.RollbackCount >= 1
	}, "stale boot rollback failed")

	st := slots.GetState()
	if st.ActiveSlot != "slot_a" {
		t.Errorf("Expected active slot slot_a, got %s", st.ActiveSlot)
	}
	if st.RollbackCount != 1 {
		t.Errorf("Expected rollback count 1, got %d", st.RollbackCount)
	}

	t.Logf("Stale boot rollback verified successfully: rollback count %d", st.RollbackCount)
	_ = sup.Stop()
}
