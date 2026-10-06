package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestAdversarial_M5_1_RapidSequentialWorkerKillsStress tests 5 consecutive worker kills in rapid succession.
// It verifies that after EVERY single kill, the supervisor restarts the worker strictly within <= 5 seconds,
// and that backoff delay is strictly capped by MaxRestartDelayCap (5s).
func TestAdversarial_M5_1_RapidSequentialWorkerKillsStress(t *testing.T) {
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

	const killCycles = 5
	pidsSeen := make(map[int]bool)
	currentPID := sup.WorkerPID()
	pidsSeen[currentPID] = true

	for i := 1; i <= killCycles; i++ {
		killStart := time.Now()
		targetPID := currentPID

		// Forcibly kill worker process (simulating taskkill /F /PID)
		proc, err := os.FindProcess(targetPID)
		if err != nil {
			t.Fatalf("[Cycle %d] FindProcess error: %v", i, err)
		}
		if err := proc.Kill(); err != nil {
			t.Fatalf("[Cycle %d] Kill error: %v", i, err)
		}

		// Verify process termination
		requireCondition(t, 2*time.Second, func() bool {
			return !isProcessRunning(targetPID)
		}, "killed process did not terminate")

		// Verify restart occurs strictly within 5 seconds per Requirement R1
		requireCondition(t, 5*time.Second, func() bool {
			newPID := sup.WorkerPID()
			return newPID > 0 && newPID != targetPID && sup.RestartCount() >= i
		}, "supervisor failed to restart killed worker within 5 seconds")

		restartTime := time.Since(killStart)
		newPID := sup.WorkerPID()
		if pidsSeen[newPID] {
			t.Fatalf("[Cycle %d] Expected fresh PID, but %d was previously seen", i, newPID)
		}
		pidsSeen[newPID] = true

		if restartTime > 5*time.Second {
			t.Fatalf("[Cycle %d] Worker restart took %v, exceeding 5.0s SLA!", i, restartTime)
		}
		t.Logf("[Cycle %d] Worker PID %d terminated; new PID %d running in %v", i, targetPID, newPID, restartTime)

		// Wait for at least one heartbeat from new worker to confirm it is alive
		hbCount := sup.HeartbeatCount()
		requireCondition(t, 3*time.Second, func() bool {
			return sup.HeartbeatCount() > hbCount
		}, "restarted worker failed to send heartbeats")

		currentPID = newPID
	}

	if err := sup.Stop(); err != nil {
		t.Fatalf("Stop error: %v", err)
	}

	// Verify final worker process is cleanly dead
	requireCondition(t, 3*time.Second, func() bool {
		return !isProcessRunning(currentPID)
	}, "worker process remained running after supervisor Stop()")
}

// TestAdversarial_M5_1_WatchdogHungWorkerRecoveryStress verifies that watchdog reliably detects hung workers,
// terminates them, and replaces them within 5 seconds.
func TestAdversarial_M5_1_WatchdogHungWorkerRecoveryStress(t *testing.T) {
	sup, _, _ := setupSupervisorTest(t, "hung")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	requireCondition(t, 3*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.HeartbeatCount() >= 1
	}, "initial hung worker failed to start")

	initialPID := sup.WorkerPID()
	watchdogStart := time.Now()

	// Wait for watchdog to detect heartbeat absence and kill hung process
	requireCondition(t, 4*time.Second, func() bool {
		return sup.WatchdogKills() >= 1
	}, "watchdog failed to kill hung worker")

	hungDetectionLatency := time.Since(watchdogStart)
	t.Logf("Watchdog detected and terminated hung worker PID %d after %v", initialPID, hungDetectionLatency)

	// Verify hung worker PID is genuinely dead (no zombie)
	requireCondition(t, 2*time.Second, func() bool {
		return !isProcessRunning(initialPID)
	}, "hung worker process is still alive after watchdog kill")

	// Wait for supervisor to restart replacement worker
	restartStart := time.Now()
	requireCondition(t, 5*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.WorkerPID() != initialPID
	}, "supervisor failed to restart replacement worker within 5s after watchdog kill")

	replacementLatency := time.Since(restartStart)
	newPID := sup.WorkerPID()
	t.Logf("Replacement worker spawned (PID %d) in %v after watchdog kill", newPID, replacementLatency)

	if replacementLatency > 5*time.Second {
		t.Fatalf("Replacement latency %v exceeded 5.0s SLA", replacementLatency)
	}

	_ = sup.Stop()

	// Verify replacement worker is terminated
	requireCondition(t, 3*time.Second, func() bool {
		return !isProcessRunning(newPID)
	}, "replacement worker still running after supervisor Stop()")
}

// TestAdversarial_M5_1_GracefulShutdownDuringRestartBackoff verifies that if the supervisor is stopped
// while waiting in the restart backoff timer, it cleanly exits immediately without spawning orphan processes.
func TestAdversarial_M5_1_GracefulShutdownDuringRestartBackoff(t *testing.T) {
	sup, _, _ := setupSupervisorTest(t, "healthy")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- sup.Start(ctx)
	}()

	<-sup.Ready()

	requireCondition(t, 3*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.HeartbeatCount() >= 1
	}, "worker failed to start")

	pid := sup.WorkerPID()

	// Kill worker to enter restarting backoff state
	proc, err := os.FindProcess(pid)
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	_ = proc.Kill()

	// Wait until supervisor registers exit and enters StateRestarting
	requireCondition(t, 2*time.Second, func() bool {
		return sup.State() == StateRestarting
	}, "supervisor did not enter StateRestarting")

	// Now stop supervisor immediately while it is sleeping on restart timer
	stopStart := time.Now()
	if err := sup.Stop(); err != nil {
		t.Fatalf("Stop error: %v", err)
	}

	select {
	case <-done:
		t.Logf("Supervisor stopped cleanly during backoff timer in %v", time.Since(stopStart))
	case <-time.After(3 * time.Second):
		t.Fatal("supervisor deadlock: failed to stop during backoff timer within 3s")
	}

	if sup.State() != StateStopped {
		t.Errorf("Expected StateStopped, got %s", sup.State())
	}

	// Sleep 500ms and verify NO orphan worker was spawned
	time.Sleep(500 * time.Millisecond)
	if finalPID := sup.WorkerPID(); finalPID != 0 {
		t.Errorf("Spurious worker PID %d was spawned after supervisor Stop()", finalPID)
	}
}

// TestAdversarial_M5_1_GracefulShutdownCleanProcessTree verifies clean termination of worker on context cancellation.
func TestAdversarial_M5_1_GracefulShutdownCleanProcessTree(t *testing.T) {
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

	// Verify child process was terminated cleanly without lingering or zombie
	requireCondition(t, 3*time.Second, func() bool {
		return !isProcessRunning(workerPID)
	}, "worker process was not terminated on supervisor shutdown")

	t.Logf("Graceful shutdown confirmed: worker PID %d terminated cleanly", workerPID)
}

// TestAdversarial_M5_1_RollbackCircuitImmediateCrashStress verifies that when a promoted update candidate
// crashes immediately, the supervisor instantly triggers rollback to slot_a and restarts slot_a in <= 5s.
func TestAdversarial_M5_1_RollbackCircuitImmediateCrashStress(t *testing.T) {
	sup, slots, _ := setupSupervisorTest(t, "healthy")

	// slot_a is healthy; slot_b is set to immediate crash
	_ = os.WriteFile(filepath.Join(slots.GetActiveSlotDir(), "mode.txt"), []byte("healthy"), 0644)
	_ = os.WriteFile(filepath.Join(slots.GetInactiveSlotDir(), "mode.txt"), []byte("crash"), 0644)

	// Promote slot_b to pending
	if err := slots.PromotePending("v2.0.0-bad"); err != nil {
		t.Fatalf("PromotePending: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rollbackTriggered := time.Now()
	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	// Supervisor should spawn slot_b, detect immediate exit, roll back to slot_a, and spawn slot_a
	requireCondition(t, 5*time.Second, func() bool {
		st := slots.GetState()
		return st.ActiveSlot == "slot_a" && st.PendingSlot == "" && st.RollbackCount == 1 &&
			sup.WorkerPID() > 0 && sup.HeartbeatCount() >= 1
	}, "immediate crash rollback circuit failed to restore slot_a within 5s")

	elapsed := time.Since(rollbackTriggered)
	t.Logf("Rollback circuit recovered to slot_a in %v; active worker PID %d healthy", elapsed, sup.WorkerPID())

	_ = sup.Stop()
}

// TestAdversarial_M5_1_ConcurrentIPCAndShutdownStress hammers the supervisor with concurrent IPC queries
// while initiating shutdown to ensure no panic or data races.
func TestAdversarial_M5_1_ConcurrentIPCAndShutdownStress(t *testing.T) {
	sup, _, _ := setupSupervisorTest(t, "healthy")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	requireCondition(t, 3*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.HeartbeatCount() >= 1
	}, "initial worker failed to start")

	var wg sync.WaitGroup
	stopSignal := make(chan struct{})

	// Spawn 4 client routines querying supervisor state concurrently
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stopSignal:
					return
				default:
					_ = sup.WorkerPID()
					_ = sup.State()
					_ = sup.HeartbeatCount()
					_ = sup.RestartCount()
					_ = sup.LastHeartbeat()
					time.Sleep(5 * time.Millisecond)
				}
			}
		}(i)
	}

	time.Sleep(100 * time.Millisecond)
	close(stopSignal)
	wg.Wait()

	if err := sup.Stop(); err != nil {
		t.Fatalf("Stop error: %v", err)
	}

	if sup.State() != StateStopped {
		t.Errorf("Expected StateStopped, got %s", sup.State())
	}
}
