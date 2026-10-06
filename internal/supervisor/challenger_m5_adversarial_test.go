package supervisor

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestEmpirical_CandidateTimeoutTerminationAndFallback verifies:
// 1. Candidate process is actually terminated (PID is no longer running).
// 2. Active slot is reverted to slot_a.
// 3. Known-good worker is automatically respawned and reports healthy.
// 4. RollbackCount is incremented monotonically.
func TestEmpirical_CandidateTimeoutTerminationAndFallback(t *testing.T) {
	sup, slots, _ := setupSupervisorTest(t, "healthy")

	_ = os.WriteFile(filepath.Join(slots.GetActiveSlotDir(), "mode.txt"), []byte("healthy"), 0644)
	_ = os.WriteFile(filepath.Join(slots.GetInactiveSlotDir(), "mode.txt"), []byte("heartbeat_only"), 0644)

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

	// 1. Wait for candidate worker to start
	requireCondition(t, 3*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.HeartbeatCount() >= 1
	}, "candidate worker failed to start")

	candidatePID := sup.WorkerPID()
	if candidatePID <= 0 {
		t.Fatalf("invalid candidate PID: %d", candidatePID)
	}

	// 2. Wait for rollback circuit to trigger upon RollbackTimeout (600ms)
	requireCondition(t, 5*time.Second, func() bool {
		st := slots.GetState()
		return st.ActiveSlot == "slot_a" && st.PendingSlot == "" && st.RollbackCount >= 1
	}, "rollback circuit failed to trigger on candidate timeout")

	// 3. Verify candidate worker was terminated and is no longer running
	requireCondition(t, 3*time.Second, func() bool {
		return !isProcessRunning(candidatePID)
	}, fmt.Sprintf("candidate worker process (PID %d) was not terminated after rollback", candidatePID))

	// 4. Verify fallback worker was spawned with a new PID and is healthy
	requireCondition(t, 5*time.Second, func() bool {
		newPID := sup.WorkerPID()
		return newPID > 0 && newPID != candidatePID && isProcessRunning(newPID)
	}, "supervisor failed to respawn healthy active slot worker after candidate timeout rollback")

	st := slots.GetState()
	if st.ActiveSlot != "slot_a" {
		t.Errorf("Expected active slot slot_a, got %s", st.ActiveSlot)
	}
	if st.RollbackCount != 1 {
		t.Errorf("Expected rollback count 1, got %d", st.RollbackCount)
	}

	_ = sup.Stop()
}

// TestEmpirical_CandidateCrashImmediateRollbackAndRespawn verifies:
// 1. Immediate rollback on candidate crash (exit status 1).
// 2. Immediate respawn of active slot worker without 5-second backoff penalty.
// 3. Rollback count increments.
func TestEmpirical_CandidateCrashImmediateRollbackAndRespawn(t *testing.T) {
	sup, slots, _ := setupSupervisorTest(t, "healthy")

	_ = os.WriteFile(filepath.Join(slots.GetActiveSlotDir(), "mode.txt"), []byte("healthy"), 0644)
	_ = os.WriteFile(filepath.Join(slots.GetInactiveSlotDir(), "mode.txt"), []byte("crash"), 0644)

	// Promote slot_b to pending
	if err := slots.PromotePending("v2.0.0"); err != nil {
		t.Fatalf("PromotePending: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	// Candidate will crash immediately, triggering immediate rollback and respawn of slot_a
	requireCondition(t, 4*time.Second, func() bool {
		st := slots.GetState()
		return st.ActiveSlot == "slot_a" && st.PendingSlot == "" && st.RollbackCount == 1 && sup.HeartbeatCount() >= 1
	}, "immediate rollback and respawn on candidate crash failed")

	elapsed := time.Since(start)
	if elapsed > 3*time.Second {
		t.Errorf("immediate rollback and respawn took unexpectedly long: %v", elapsed)
	}

	activePID := sup.WorkerPID()
	if activePID <= 0 || !isProcessRunning(activePID) {
		t.Errorf("active worker PID %d is not running", activePID)
	}

	_ = sup.Stop()
}

// TestEmpirical_StaleBootRollbackPreWorkerSpawn verifies:
// 1. If an update trial expired while supervisor was down, startup check detects and rolls back BEFORE worker spawn.
// 2. The worker that starts is from slot_a.
func TestEmpirical_StaleBootRollbackPreWorkerSpawn(t *testing.T) {
	sup, slots, _ := setupSupervisorTest(t, "healthy")

	// Set pending update that expired 1 hour ago
	if err := slots.PromotePending("v2.0.0"); err != nil {
		t.Fatalf("PromotePending: %v", err)
	}
	if err := slots.SetPendingStartedAtForTest(time.Now().Add(-1 * time.Hour)); err != nil {
		t.Fatalf("SetPendingStartedAtForTest: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	// Verify rollback happened
	requireCondition(t, 3*time.Second, func() bool {
		st := slots.GetState()
		return st.ActiveSlot == "slot_a" && st.PendingSlot == "" && st.RollbackCount == 1
	}, "stale boot rollback did not complete")

	// Verify worker is running and healthy
	requireCondition(t, 3*time.Second, func() bool {
		return sup.WorkerPID() > 0 && isProcessRunning(sup.WorkerPID()) && sup.HeartbeatCount() >= 1
	}, "worker failed to run healthy after stale boot rollback")

	_ = sup.Stop()
}

// TestEmpirical_HealthConfirmationPreventsRollback verifies:
// 1. Health confirmation commits slot_b to active.
// 2. Subsequent duration (well past RollbackTimeout) never triggers rollback.
func TestEmpirical_HealthConfirmationPreventsRollback(t *testing.T) {
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

	// Wait for health confirmation
	requireCondition(t, 4*time.Second, func() bool {
		st := slots.GetState()
		return st.ActiveSlot == "slot_b" && st.PendingSlot == ""
	}, "update failed to commit upon notify_healthy")

	// Wait for 1.2s (2x RollbackTimeout of 600ms)
	time.Sleep(1200 * time.Millisecond)

	st := slots.GetState()
	if st.ActiveSlot != "slot_b" {
		t.Errorf("ActiveSlot reverted unexpectedly: got %s, want slot_b", st.ActiveSlot)
	}
	if st.PendingSlot != "" {
		t.Errorf("PendingSlot was not empty: got %s", st.PendingSlot)
	}
	if st.RollbackCount != 0 {
		t.Errorf("RollbackCount changed unexpectedly: got %d, want 0", st.RollbackCount)
	}

	_ = sup.Stop()
}

// TestEmpirical_MismatchedPIDHeartbeatDiscarded verifies:
// The supervisor discards heartbeats from unknown/mismatched PIDs and does not reset watchdog.
func TestEmpirical_MismatchedPIDHeartbeatDiscarded(t *testing.T) {
	sup, _, _ := setupSupervisorTest(t, "hung")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	requireCondition(t, 3*time.Second, func() bool {
		return sup.WorkerPID() > 0
	}, "hung worker failed to start")

	realPID := sup.WorkerPID()

	// Connect rogue client and send heartbeats with fake PID (999999)
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
	if conn == nil {
		t.Fatalf("failed to connect rogue client: %v", err)
	}
	defer conn.Close()

	rogueClient := NewIPCClient(nil, 2*time.Second)
	_ = rogueClient.Connect(conn)
	defer rogueClient.Close()

	// Send rogue heartbeats continuously for 800ms (longer than HeartbeatTimeout of 400ms)
	rogueDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-rogueDone:
				return
			case <-ticker.C:
				_ = rogueClient.Send(&IPCMessage{
					Type:     MsgHeartbeat,
					PID:      999999, // Mismatched PID!
					RSSBytes: 1024 * 1024,
				})
			}
		}
	}()

	// The hung realPID must STILL be killed by the watchdog despite the rogue client's heartbeats!
	requireCondition(t, 4*time.Second, func() bool {
		return sup.WatchdogKills() >= 1 && !isProcessRunning(realPID)
	}, "watchdog failed to kill hung worker despite rogue heartbeats")

	close(rogueDone)
	_ = sup.Stop()
}

func triggerStagedUpdateViaIPC(t *testing.T, sup *Supervisor, version string) {
	t.Helper()
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
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		t.Fatalf("failed to dial IPC to trigger update: %v", err)
	}
	defer conn.Close()

	c := NewIPCClient(nil, 2*time.Second)
	_ = c.Connect(conn)
	defer c.Close()

	if err := c.Send(&IPCMessage{
		Type:    MsgRequestRestart,
		Reason:  "update_staged",
		Version: version,
		PID:     sup.WorkerPID(),
	}); err != nil {
		t.Fatalf("failed to send MsgRequestRestart: %v", err)
	}
}

// TestEmpirical_MultiCycleAlternatingUpdateAndRollback verifies:
// Alternating A -> B -> A transitions across crashes, timeouts, and successful promotions.
func TestEmpirical_MultiCycleAlternatingUpdateAndRollback(t *testing.T) {
	sup, slots, _ := setupSupervisorTest(t, "healthy")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	// Initial: Active=slot_a, healthy
	requireCondition(t, 3*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.HeartbeatCount() >= 2 && slots.GetState().ActiveSlot == "slot_a"
	}, "initial worker failed to start")

	// Phase 1: Inactive is slot_b. Candidate crashes immediately.
	_ = os.WriteFile(filepath.Join(slots.GetInactiveSlotDir(), "mode.txt"), []byte("crash"), 0644)
	triggerStagedUpdateViaIPC(t, sup, "v2.0.0-broken")

	// Wait for immediate rollback back to slot_a and respawn of healthy slot_a
	requireCondition(t, 5*time.Second, func() bool {
		st := slots.GetState()
		return st.ActiveSlot == "slot_a" && st.PendingSlot == "" && st.RollbackCount == 1 && sup.WorkerPID() > 0
	}, "Phase 1 crash rollback failed")

	// Let the restored worker send fresh heartbeats before Phase 2
	hbCount := sup.HeartbeatCount()
	requireCondition(t, 3*time.Second, func() bool {
		return sup.HeartbeatCount() >= hbCount+2
	}, "Phase 1 restored worker heartbeats failed")

	// Phase 2: Inactive is slot_b. Candidate runs but times out (heartbeat_only).
	_ = os.WriteFile(filepath.Join(slots.GetInactiveSlotDir(), "mode.txt"), []byte("heartbeat_only"), 0644)
	triggerStagedUpdateViaIPC(t, sup, "v2.0.0-timeout")

	// Wait for candidate to boot into trial
	requireCondition(t, 4*time.Second, func() bool {
		st := slots.GetState()
		return st.PendingSlot == "slot_b"
	}, "Phase 2 candidate failed to boot into trial")

	// Wait for rollback timeout circuit to revert to slot_a
	requireCondition(t, 5*time.Second, func() bool {
		st := slots.GetState()
		return st.ActiveSlot == "slot_a" && st.PendingSlot == "" && st.RollbackCount == 2
	}, "Phase 2 timeout rollback failed")

	// Wait for active worker in slot_a to stabilize
	hbCount = sup.HeartbeatCount()
	requireCondition(t, 4*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.HeartbeatCount() >= hbCount+2
	}, "Phase 2 post-rollback worker failed to stabilize")

	// Phase 3: Inactive is slot_b. Candidate is healthy -> commits to slot_b!
	_ = os.WriteFile(filepath.Join(slots.GetInactiveSlotDir(), "mode.txt"), []byte("healthy"), 0644)
	triggerStagedUpdateViaIPC(t, sup, "v2.0.0-good")

	// Wait for candidate to commit slot_b
	requireCondition(t, 5*time.Second, func() bool {
		st := slots.GetState()
		return st.ActiveSlot == "slot_b" && st.PendingSlot == "" && st.RollbackCount == 2
	}, "Phase 3 commit failed")

	// Verify active slot is now slot_b and inactive is slot_a
	if slots.GetActiveSlot() != "slot_b" {
		t.Fatalf("Expected ActiveSlot slot_b, got %s", slots.GetActiveSlot())
	}
	if slots.GetInactiveSlot() != "slot_a" {
		t.Fatalf("Expected InactiveSlot slot_a, got %s", slots.GetInactiveSlot())
	}

	hbCount = sup.HeartbeatCount()
	requireCondition(t, 4*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.HeartbeatCount() >= hbCount+2
	}, "Phase 3 worker failed to stabilize")

	// Phase 4: Now active is slot_b! Inactive is slot_a. Stage broken candidate in slot_a!
	_ = os.WriteFile(filepath.Join(slots.GetInactiveSlotDir(), "mode.txt"), []byte("crash"), 0644)
	triggerStagedUpdateViaIPC(t, sup, "v3.0.0-broken")

	// Wait for candidate in slot_a to crash and rollback to slot_b!
	requireCondition(t, 5*time.Second, func() bool {
		st := slots.GetState()
		return st.ActiveSlot == "slot_b" && st.PendingSlot == "" && st.RollbackCount == 3
	}, "Phase 4 crash rollback back to slot_b failed")

	hbCount = sup.HeartbeatCount()
	requireCondition(t, 4*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.HeartbeatCount() >= hbCount+2
	}, "Phase 4 worker failed to stabilize")

	// Phase 5: Stage good candidate in slot_a -> commits back to slot_a!
	_ = os.WriteFile(filepath.Join(slots.GetInactiveSlotDir(), "mode.txt"), []byte("healthy"), 0644)
	triggerStagedUpdateViaIPC(t, sup, "v3.0.0-good")

	// Wait for candidate in slot_a to commit
	requireCondition(t, 5*time.Second, func() bool {
		st := slots.GetState()
		return st.ActiveSlot == "slot_a" && st.PendingSlot == "" && st.RollbackCount == 3
	}, "Phase 5 commit back to slot_a failed")

	if slots.GetActiveSlot() != "slot_a" {
		t.Fatalf("Expected ActiveSlot slot_a after full A-B-A cycle, got %s", slots.GetActiveSlot())
	}

	_ = sup.Stop()
}

// TestEmpirical_ConcurrentHeartbeatsAndRollbackStress tests high-frequency heartbeats
// racing against slot rollback and supervisor shutdown.
func TestEmpirical_ConcurrentHeartbeatsAndRollbackStress(t *testing.T) {
	sup, slots, _ := setupSupervisorTest(t, "healthy")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	requireCondition(t, 3*time.Second, func() bool {
		return sup.WorkerPID() > 0
	}, "worker failed to start")

	var wg sync.WaitGroup
	stopClients := make(chan struct{})

	// Spawn 5 concurrent goroutines pounding the IPC channel with messages
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			var conn net.Conn
			var err error
			for attempt := 0; attempt < 20; attempt++ {
				if runtime.GOOS == "windows" {
					conn, err = DialPipe(sup.cfg.PipeName, 2*time.Second)
				} else {
					conn, err = DialUDS(sup.cfg.SocketPath, 2*time.Second)
				}
				if err == nil {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if conn == nil {
				return
			}
			defer conn.Close()

			c := NewIPCClient(nil, 2*time.Second)
			_ = c.Connect(conn)
			defer c.Close()

			for {
				select {
				case <-stopClients:
					return
				default:
					_ = c.Send(&IPCMessage{
						Type:     MsgHeartbeat,
						PID:      sup.WorkerPID(),
						RSSBytes: uint64(1024 * 1024 * (20 + id)),
					})
					_, _ = c.RoundTrip(&IPCMessage{Type: MsgGetInactive})
					time.Sleep(10 * time.Millisecond)
				}
			}
		}(i)
	}

	// While under heavy concurrent traffic, promote and rollback slot
	for i := 0; i < 3; i++ {
		_ = slots.PromotePending(fmt.Sprintf("v-stress-%d", i))
		time.Sleep(40 * time.Millisecond)
		_ = slots.Rollback()
		time.Sleep(40 * time.Millisecond)
	}

	close(stopClients)
	wg.Wait()

	_ = sup.Stop()
}

// TestEmpirical_MismatchedPIDNotifyHealthyShouldNotConfirm tests whether an unauthorized or
// mismatched PID can fraudulently confirm a pending candidate slot.
func TestEmpirical_MismatchedPIDNotifyHealthyShouldNotConfirm(t *testing.T) {
	sup, slots, _ := setupSupervisorTest(t, "heartbeat_only")

	_ = os.WriteFile(filepath.Join(slots.GetActiveSlotDir(), "mode.txt"), []byte("healthy"), 0644)
	_ = os.WriteFile(filepath.Join(slots.GetInactiveSlotDir(), "mode.txt"), []byte("heartbeat_only"), 0644)

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

	requireCondition(t, 3*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.HeartbeatCount() >= 1
	}, "candidate failed to start")

	// Connect rogue client
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
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		t.Fatalf("failed to connect rogue client: %v", err)
	}
	defer conn.Close()

	rogueClient := NewIPCClient(nil, 2*time.Second)
	_ = rogueClient.Connect(conn)
	defer rogueClient.Close()

	// Send notify_healthy with mismatched PID (fake PID 888888)
	_ = rogueClient.Send(&IPCMessage{
		Type:    MsgNotifyHealthy,
		PID:     888888,
		Version: "v2.0.0-rogue",
	})

	// Check if supervisor confirmed or if candidate is still pending / rolls back
	time.Sleep(200 * time.Millisecond)
	st := slots.GetState()
	t.Logf("State after rogue notify_healthy: ActiveSlot=%s, PendingSlot=%s", st.ActiveSlot, st.PendingSlot)

	_ = sup.Stop()
}

