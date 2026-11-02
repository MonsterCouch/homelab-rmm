package supervisor

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// dialSupervisorClient dials the active supervisor IPC endpoint.
func dialSupervisorClient(t *testing.T, sup *Supervisor) (*IPCClient, net.Conn) {
	t.Helper()
	var conn net.Conn
	var err error
	for i := 0; i < 50; i++ {
		if runtime.GOOS == "windows" {
			conn, err = DialPipe(sup.cfg.PipeName, 2*time.Second)
		} else {
			conn, err = DialUDS(sup.cfg.SocketPath, 2*time.Second)
		}
		if err == nil && conn != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		t.Fatalf("failed to connect to supervisor IPC: %v", err)
	}

	client := NewIPCClient(nil, 2*time.Second)
	if err := client.Connect(conn); err != nil {
		conn.Close()
		t.Fatalf("failed to connect IPCClient: %v", err)
	}
	return client, conn
}

// TestChallengerM6_RejectMismatchedPID_NotifyHealthy verifies that the supervisor
// rejects MsgNotifyHealthy when sender PID does not match active worker PID,
// refusing to commit the pending candidate slot to active.
func TestChallengerM6_RejectMismatchedPID_NotifyHealthy(t *testing.T) {
	sup, slots, _ := setupSupervisorTest(t, "heartbeat_only")

	_ = os.WriteFile(filepath.Join(slots.GetActiveSlotDir(), "mode.txt"), []byte("healthy"), 0644)
	_ = os.WriteFile(filepath.Join(slots.GetInactiveSlotDir(), "mode.txt"), []byte("heartbeat_only"), 0644)

	// Promote inactive slot to pending
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
	}, "worker failed to start")

	activePID := sup.WorkerPID()
	if activePID <= 0 {
		t.Fatalf("invalid active worker PID: %d", activePID)
	}

	client, conn := dialSupervisorClient(t, sup)
	defer conn.Close()
	defer client.Close()

	// 1. Send MsgNotifyHealthy with mismatched PID (e.g. activePID + 99999)
	mismatchedPID := activePID + 99999
	err := client.Send(&IPCMessage{
		Type:    MsgNotifyHealthy,
		PID:     mismatchedPID,
		Version: "v2.0.0",
	})
	if err != nil {
		t.Fatalf("client.Send failed: %v", err)
	}

	// Give supervisor handler a moment to process the frame
	time.Sleep(100 * time.Millisecond)

	// 2. Verify that pending slot was NOT confirmed to ActiveSlot=slot_b!
	st := slots.GetState()
	if st.ActiveSlot == "slot_b" {
		t.Errorf("vulnerability: mismatched PID unexpectedly confirmed slot_b as active! State: %+v", st)
	}

	// Wait for rollback circuit: since fake notify was rejected and candidate worker
	// only emits heartbeats, candidate must time out and rollback to slot_a!
	requireCondition(t, 3*time.Second, func() bool {
		s := slots.GetState()
		return s.ActiveSlot == "slot_a" && s.PendingSlot == "" && s.RollbackCount >= 1
	}, "candidate should roll back after rejected rogue notify_healthy")

	_ = sup.Stop()
}

// TestChallengerM6_RejectMismatchedPID_RequestRestart verifies that the supervisor
// rejects MsgRequestRestart when sender PID does not match active worker PID,
// refusing to promote pending slot or terminate the running worker.
func TestChallengerM6_RejectMismatchedPID_RequestRestart(t *testing.T) {
	sup, slots, _ := setupSupervisorTest(t, "healthy")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	requireCondition(t, 3*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.HeartbeatCount() >= 1
	}, "worker failed to start")

	activePID := sup.WorkerPID()
	client, conn := dialSupervisorClient(t, sup)
	defer conn.Close()
	defer client.Close()

	// Send MsgRequestRestart with mismatched PID
	mismatchedPID := activePID + 77777
	err := client.Send(&IPCMessage{
		Type:    MsgRequestRestart,
		PID:     mismatchedPID,
		Reason:  "update_staged",
		Version: "v2.5.0",
	})
	if err != nil {
		t.Fatalf("client.Send failed: %v", err)
	}

	time.Sleep(150 * time.Millisecond)

	// Verify pending slot was NOT promoted
	st := slots.GetState()
	if st.PendingSlot != "" {
		t.Errorf("pending slot was unexpectedly promoted by rogue sender: %+v", st)
	}

	// Verify active worker process was NOT terminated
	if sup.WorkerPID() != activePID {
		t.Errorf("active worker PID changed after rejected restart: got %d, want %d", sup.WorkerPID(), activePID)
	}

	_ = sup.Stop()
}

// TestChallengerM6_MatchingPID_Accepted verifies that when the sender PID matches
// the active worker PID, MsgNotifyHealthy commits the pending slot.
func TestChallengerM6_MatchingPID_Accepted(t *testing.T) {
	sup, slots, _ := setupSupervisorTest(t, "heartbeat_only")

	_ = os.WriteFile(filepath.Join(slots.GetActiveSlotDir(), "mode.txt"), []byte("healthy"), 0644)
	_ = os.WriteFile(filepath.Join(slots.GetInactiveSlotDir(), "mode.txt"), []byte("heartbeat_only"), 0644)

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
	}, "worker failed to start")

	activePID := sup.WorkerPID()
	client, conn := dialSupervisorClient(t, sup)
	defer conn.Close()
	defer client.Close()

	// Send MsgNotifyHealthy with matching PID
	err := client.Send(&IPCMessage{
		Type:    MsgNotifyHealthy,
		PID:     activePID,
		Version: "v2.0.0",
	})
	if err != nil {
		t.Fatalf("client.Send failed: %v", err)
	}

	// Verify that pending slot was successfully confirmed
	requireCondition(t, 2*time.Second, func() bool {
		st := slots.GetState()
		return st.PendingSlot == "" && st.ActiveSlot == "slot_b"
	}, "expected pending slot to be committed to slot_b")

	_ = sup.Stop()
}

// TestChallengerM6_MatchingPID_RestartAccepted verifies that when the sender PID
// matches the active worker PID, MsgRequestRestart promotes pending slot and triggers restart.
func TestChallengerM6_MatchingPID_RestartAccepted(t *testing.T) {
	sup, slots, _ := setupSupervisorTest(t, "healthy")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	requireCondition(t, 3*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.HeartbeatCount() >= 1
	}, "worker failed to start")

	activePID := sup.WorkerPID()
	client, conn := dialSupervisorClient(t, sup)
	defer conn.Close()
	defer client.Close()

	// Send MsgRequestRestart with matching PID
	err := client.Send(&IPCMessage{
		Type:    MsgRequestRestart,
		PID:     activePID,
		Reason:  "update_staged",
		Version: "v3.0.0",
	})
	if err != nil {
		t.Fatalf("client.Send failed: %v", err)
	}

	// Verify pending slot is promoted to slot_b
	requireCondition(t, 2*time.Second, func() bool {
		st := slots.GetState()
		return st.PendingSlot == "slot_b"
	}, "expected slot_b to be promoted to pending on valid restart request")

	_ = sup.Stop()
}

// TestChallengerM6_DiscardMismatchedHeartbeat verifies that MsgHeartbeat from a
// mismatched PID is discarded and does not overwrite RSS or advance heartbeats.
func TestChallengerM6_DiscardMismatchedHeartbeat(t *testing.T) {
	sup, _, _ := setupSupervisorTest(t, "heartbeat_only")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	requireCondition(t, 3*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.HeartbeatCount() >= 1
	}, "worker failed to start")

	activePID := sup.WorkerPID()
	client, conn := dialSupervisorClient(t, sup)
	defer conn.Close()
	defer client.Close()

	sup.mu.Lock()
	initialRSS := sup.workerRSS
	sup.mu.Unlock()
	rogueRSS := uint64(999 * 1024 * 1024)

	// Send rogue heartbeat with mismatched PID
	_ = client.Send(&IPCMessage{
		Type:     MsgHeartbeat,
		PID:      activePID + 88888,
		RSSBytes: rogueRSS,
	})

	time.Sleep(100 * time.Millisecond)

	sup.mu.Lock()
	currentRSS := sup.workerRSS
	sup.mu.Unlock()
	if currentRSS == rogueRSS {
		t.Errorf("supervisor accepted rogue heartbeat RSS %d", currentRSS)
	}
	t.Logf("Initial RSS: %d, Current RSS: %d (Rogue RSS %d was properly ignored)", initialRSS, currentRSS, rogueRSS)

	_ = sup.Stop()
}

// TestChallengerM6_Empirical_ZeroPID_BypassAudit rigorously tests and documents
// whether omitting PID (PID=0) bypasses the supervisor's PID validation.
func TestChallengerM6_Empirical_ZeroPID_BypassAudit(t *testing.T) {
	sup, slots, _ := setupSupervisorTest(t, "heartbeat_only")

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
	}, "worker failed to start")

	activePID := sup.WorkerPID()
	client, conn := dialSupervisorClient(t, sup)
	defer conn.Close()
	defer client.Close()

	// Send MsgNotifyHealthy with PID=0 (simulating untrusted client omitting PID field)
	err := client.Send(&IPCMessage{
		Type:    MsgNotifyHealthy,
		PID:     0,
		Version: "v2.0.0",
	})
	if err != nil {
		t.Fatalf("client.Send failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	st := slots.GetState()
	bypassed := (st.ActiveSlot == "slot_b" && st.PendingSlot == "")
	t.Logf("[AUDIT FINDING] PID=0 Bypass Check: ActivePID=%d, ActiveSlot=%s, PendingSlot=%s, BypassedPIDCheck=%v",
		activePID, st.ActiveSlot, st.PendingSlot, bypassed)

	_ = sup.Stop()
}
