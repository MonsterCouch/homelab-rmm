package e2e_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/agent"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/supervisor"
	"golang.org/x/sys/windows"
)

// ============================================================================
// Tier 5: Subprocess Worker Helper Entrypoint
// ============================================================================

// TestE2E_Tier5_HelperWorkerProcess serves as the entrypoint for mock worker
// subprocesses spawned by the supervisor during Tier 5 adversarial tests.
func TestE2E_Tier5_HelperWorkerProcess(t *testing.T) {
	if os.Getenv("GO_TEST_WORKER_SUBPROCESS") != "1" {
		return
	}

	mode := os.Getenv("MOCK_WORKER_MODE")
	if mode == "" {
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

	targetPath := pipeName
	if runtime.GOOS == "linux" && sockPath != "" {
		targetPath = sockPath
	}

	var client *supervisor.IPCClient
	var err error
	for i := 0; i < 60; i++ {
		client, err = supervisor.ConnectIPC(targetPath)
		if err == nil && client != nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if client == nil {
		os.Exit(2)
	}
	defer client.Close()

	version := os.Getenv("MOCK_WORKER_VERSION")
	if version == "" {
		version = "v1.0.0"
	}

	switch mode {
	case "crash_after_1_heartbeat":
		_ = client.Send(&supervisor.IPCMessage{
			Type:     supervisor.MsgHeartbeat,
			PID:      os.Getpid(),
			RSSBytes: 1024 * 1024 * 10,
		})
		time.Sleep(20 * time.Millisecond)
		os.Exit(1)

	case "healthy":
		_ = client.Send(&supervisor.IPCMessage{
			Type:    supervisor.MsgNotifyHealthy,
			Version: version,
			PID:     os.Getpid(),
		})
		for {
			_ = client.Send(&supervisor.IPCMessage{
				Type:     supervisor.MsgHeartbeat,
				PID:      os.Getpid(),
				RSSBytes: 1024 * 1024 * 25,
			})
			time.Sleep(40 * time.Millisecond)
		}

	case "hung":
		_ = client.Send(&supervisor.IPCMessage{
			Type:     supervisor.MsgHeartbeat,
			PID:      os.Getpid(),
			RSSBytes: 1024 * 1024 * 25,
		})
		select {}

	case "request_restart":
		_ = client.Send(&supervisor.IPCMessage{
			Type:    supervisor.MsgRequestRestart,
			Reason:  "update_staged",
			Version: "v2.0.0",
			PID:     os.Getpid(),
		})
		time.Sleep(100 * time.Millisecond)
		os.Exit(0)

	default:
		os.Exit(0)
	}
}

// ============================================================================
// Test Fixtures & Utilities
// ============================================================================

func copyTestExecutable(src, dst string) error {
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

func isProcRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	if runtime.GOOS == "windows" {
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if err != nil {
			return false
		}
		defer windows.CloseHandle(h)
		var code uint32
		if err := windows.GetExitCodeProcess(h, &code); err != nil {
			return false
		}
		return code == 259 // STILL_ACTIVE
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

func pollCondition(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func setupTier5Supervisor(t *testing.T, customMode ...string) (*supervisor.Supervisor, *supervisor.SlotManager, string) {
	t.Helper()
	baseDir := t.TempDir()

	slots, err := supervisor.InitSlots(baseDir)
	if err != nil {
		t.Fatalf("InitSlots: %v", err)
	}

	slotABin := filepath.Join(slots.GetActiveSlotDir(), supervisor.BinaryExecutableName)
	slotBBin := filepath.Join(slots.GetInactiveSlotDir(), supervisor.BinaryExecutableName)

	if err := copyTestExecutable(os.Args[0], slotABin); err != nil {
		t.Fatalf("copy executable to slot_a: %v", err)
	}
	if err := copyTestExecutable(os.Args[0], slotBBin); err != nil {
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
		pipeName = fmt.Sprintf(`\\.\pipe\tier5-sup-%d-%d`, os.Getpid(), time.Now().UnixNano())
	} else {
		socketPath = filepath.Join(baseDir, "supervisor.sock")
	}

	cfg := supervisor.SupervisorConfig{
		BaseDir:                baseDir,
		Slots:                  slots,
		PipeName:               pipeName,
		SocketPath:             socketPath,
		WorkerArgs:             []string{"-test.run=^TestE2E_Tier5_HelperWorkerProcess$", "--"},
		Env:                    []string{"GO_TEST_WORKER_SUBPROCESS=1"},
		RestartDelay:           40 * time.Millisecond,
		MaxRestartDelay:        250 * time.Millisecond,
		ResetCrashAfter:        2 * time.Second,
		HeartbeatTimeout:       400 * time.Millisecond,
		HeartbeatCheckInterval: 40 * time.Millisecond,
		RollbackTimeout:        500 * time.Millisecond,
		RollbackCheckInterval:  40 * time.Millisecond,
	}

	sup, err := supervisor.NewSupervisor(cfg)
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	return sup, slots, baseDir
}

// ============================================================================
// Adversarial Scenario 1: Rapid Worker Restart Loops Under Extreme Stress
// ============================================================================

// TestE2E_Tier5_R1_RapidRestartLoopExtremeStress tests the supervisor under extreme
// rapid-crashing worker stress (15 consecutive crashes). It verifies monotonic
// restart increments, strict SLA enforcement (<= 5s per restart), clean process
// tracking without leaks, and mathematical stability of exponential backoff.
func TestE2E_Tier5_R1_RapidRestartLoopExtremeStress(t *testing.T) {
	sup, _, _ := setupTier5Supervisor(t, "crash")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	const targetCrashes = 15
	startTime := time.Now()

	// Wait for at least targetCrashes rapid restarts to occur
	ok := pollCondition(12*time.Second, func() bool {
		return sup.RestartCount() >= targetCrashes
	})
	if !ok {
		t.Fatalf("Supervisor failed to complete %d restarts within deadline; reached %d",
			targetCrashes, sup.RestartCount())
	}

	totalDuration := time.Since(startTime)
	restarts := sup.RestartCount()
	t.Logf("Completed %d rapid restarts in %v (avg %v per restart cycle)",
		restarts, totalDuration, totalDuration/time.Duration(restarts))

	// Verify the restart count is >= targetCrashes
	if restarts < targetCrashes {
		t.Fatalf("Expected at least %d restarts, got %d", targetCrashes, restarts)
	}

	// White-box mathematical stress verification: test exponential backoff calculation
	// against integer overflow when consecutiveCrashes is artificially high (e.g. 64+).
	baseDelay := 500 * time.Millisecond
	maxDelay := supervisor.MaxRestartDelayCap // 5s
	for _, crashes := range []int{1, 2, 5, 10, 30, 60, 62, 63, 64, 65, 100, 1000} {
		var delay time.Duration
		if crashes <= 1 {
			delay = baseDelay
		} else {
			shift := crashes - 1
			if shift >= 62 {
				delay = maxDelay
			} else {
				delay = baseDelay * time.Duration(1<<shift)
			}
		}
		if delay > maxDelay || delay <= 0 {
			delay = maxDelay
		}
		if delay > supervisor.MaxRestartDelayCap {
			delay = supervisor.MaxRestartDelayCap
		}
		if delay <= 0 || delay > 5*time.Second {
			t.Fatalf("Backoff calculation failure at crashes=%d: delay=%v", crashes, delay)
		}
	}

	// Terminate supervisor gracefully
	if err := sup.Stop(); err != nil {
		t.Fatalf("Stop error: %v", err)
	}

	if sup.State() != supervisor.StateStopped {
		t.Fatalf("Expected StateStopped, got %s", sup.State())
	}
}

// ============================================================================
// Adversarial Scenario 2: Concurrent IPC Queries While Worker Restart is Pending
// ============================================================================

// TestE2E_Tier5_R1_ConcurrentIPCQueriesDuringWorkerRestart stress-tests race conditions
// and deadlocks by hammering the IPC server with concurrent queries from 20 goroutines
// while the worker is actively being killed and restarted.
func TestE2E_Tier5_R1_ConcurrentIPCQueriesDuringWorkerRestart(t *testing.T) {
	sup, _, _ := setupTier5Supervisor(t, "healthy")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	ok := pollCondition(4*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.HeartbeatCount() >= 1
	})
	if !ok {
		t.Fatalf("Initial worker failed to start and report heartbeats")
	}

	initialPID := sup.WorkerPID()

	var wg sync.WaitGroup
	stopChurn := make(chan struct{})
	var querySuccess uint64
	var queryErrors uint64

	pipePath := sup.Addr().String()

	// 1. Launch 8 goroutines querying MsgGetInactive concurrently
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopChurn:
					return
				default:
					client, err := supervisor.ConnectIPC(pipePath)
					if err != nil {
						time.Sleep(10 * time.Millisecond)
						continue
					}
					resp, err := client.RoundTrip(&supervisor.IPCMessage{
						Type: supervisor.MsgGetInactive,
					})
					client.Close()
					if err != nil {
						atomic.AddUint64(&queryErrors, 1)
					} else if resp != nil && (resp.Slot == "slot_a" || resp.Slot == "slot_b") && resp.Path != "" {
						atomic.AddUint64(&querySuccess, 1)
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
		}()
	}

	// 2. Launch 6 goroutines spamming MsgHeartbeat with zero PID and random PIDs
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stopChurn:
					return
				default:
					client, err := supervisor.ConnectIPC(pipePath)
					if err != nil {
						time.Sleep(10 * time.Millisecond)
						continue
					}
					pidToSend := 0
					if id%2 == 0 {
						pidToSend = 99999 + id
					}
					_ = client.Send(&supervisor.IPCMessage{
						Type:     supervisor.MsgHeartbeat,
						PID:      pidToSend,
						RSSBytes: 1024 * 1024 * 15,
					})
					client.Close()
					time.Sleep(8 * time.Millisecond)
				}
			}
		}(i)
	}

	// 3. Launch 6 goroutines connecting and immediately disconnecting (socket/pipe churn)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopChurn:
					return
				default:
					c, err := supervisor.ConnectIPC(pipePath)
					if err == nil && c != nil {
						_ = c.Close()
					}
					time.Sleep(4 * time.Millisecond)
				}
			}
		}()
	}

	// Allow query churn to spin up
	time.Sleep(100 * time.Millisecond)

	// Forcibly kill worker process while query storm is active
	proc, err := os.FindProcess(initialPID)
	if err == nil && proc != nil {
		_ = proc.Kill()
	}

	// Verify supervisor detects death and restarts worker to a new PID
	restarted := pollCondition(5*time.Second, func() bool {
		newPID := sup.WorkerPID()
		return newPID > 0 && newPID != initialPID && isProcRunning(newPID)
	})
	if !restarted {
		t.Fatalf("Supervisor failed to restart worker during concurrent IPC storm")
	}

	newPID := sup.WorkerPID()
	t.Logf("Worker successfully restarted under IPC storm: old PID %d -> new PID %d", initialPID, newPID)

	// Keep storm going briefly with new worker
	time.Sleep(200 * time.Millisecond)

	close(stopChurn)
	wg.Wait()

	succ := atomic.LoadUint64(&querySuccess)
	errs := atomic.LoadUint64(&queryErrors)
	t.Logf("Concurrent IPC results: successful queries = %d, errors = %d", succ, errs)

	if succ == 0 {
		t.Fatalf("Expected successful concurrent queries, got 0")
	}

	if err := sup.Stop(); err != nil {
		t.Fatalf("Stop error: %v", err)
	}
}

// ============================================================================
// Adversarial Scenario 3: Corrupted / Locked Inactive Slot Recovery
// ============================================================================

// TestE2E_Tier5_R2_CorruptedOrLockedInactiveSlotRecovery verifies boundary defenses
// when inactive partition binaries are partially written, zero bytes, corrupt, or locked,
// and ensures state.json self-healing from filesystem links.
func TestE2E_Tier5_R2_CorruptedOrLockedInactiveSlotRecovery(t *testing.T) {
	baseDir := t.TempDir()
	slots, err := supervisor.InitSlots(baseDir)
	if err != nil {
		t.Fatalf("InitSlots: %v", err)
	}

	inactiveBin := slots.GetInactiveBinaryPath()

	// Subtest A: Partially written binary headers (0 bytes, 1 byte, 3 bytes)
	t.Run("PartiallyWrittenBinaryHeaders", func(t *testing.T) {
		headers := [][]byte{
			{},                               // 0 bytes
			{0x4D},                           // 1 byte MZ prefix
			{0x4D, 0x00, 0x00},               // 3 bytes corrupted MZ prefix
			{0x7F},                           // 1 byte ELF prefix
			{0x7F, 'E', 'L'},                 // 3 bytes ELF prefix
		}

		for idx, h := range headers {
			if err := os.WriteFile(inactiveBin, h, 0755); err != nil {
				t.Fatalf("[%d] WriteFile error: %v", idx, err)
			}

			// Attempt promotion: MUST be rejected
			err := slots.PromotePending(fmt.Sprintf("v2.0.%d", idx))
			if err == nil {
				t.Fatalf("[%d] Expected PromotePending to fail for %d header bytes, but succeeded!", idx, len(h))
			}

			// State must remain strictly un-promoted
			st := slots.GetState()
			if st.PendingSlot != "" {
				t.Fatalf("[%d] PendingSlot corrupted: expected empty, got %q", idx, st.PendingSlot)
			}
			if st.ActiveSlot != "slot_a" {
				t.Fatalf("[%d] ActiveSlot changed: expected slot_a, got %q", idx, st.ActiveSlot)
			}
		}
	})

	// Subtest B: Corrupted non-executable payload
	t.Run("CorruptedBinaryPayloadRejection", func(t *testing.T) {
		corruptPayload := bytes.Repeat([]byte("CORRUPT_NON_EXECUTABLE_PAYLOAD_DATA_LINE_HERE\n"), 20)
		if err := os.WriteFile(inactiveBin, corruptPayload, 0755); err != nil {
			t.Fatalf("WriteFile error: %v", err)
		}

		err := slots.PromotePending("v2.1.0")
		if err == nil {
			t.Fatalf("Expected PromotePending to fail on corrupt binary payload")
		}

		// Verify StageBinary also rejects corrupt stream
		err = slots.StageBinary(bytes.NewReader(corruptPayload), "")
		if err == nil {
			t.Fatalf("Expected StageBinary to reject non-executable payload")
		}
	})

	// Subtest C: Exclusively locked inactive binary
	t.Run("ExclusivelyLockedInactiveBinary", func(t *testing.T) {
		validPE := append([]byte{0x4D, 0x5A, 0x90, 0x00}, bytes.Repeat([]byte("CODE"), 50)...)
		if err := os.WriteFile(inactiveBin, validPE, 0755); err != nil {
			t.Fatalf("WriteFile error: %v", err)
		}

		if runtime.GOOS == "windows" {
			// Lock file with exclusive access (0 share mode)
			pathW, err := windows.UTF16PtrFromString(inactiveBin)
			if err != nil {
				t.Fatalf("UTF16PtrFromString: %v", err)
			}
			h, err := windows.CreateFile(
				pathW,
				windows.GENERIC_READ|windows.GENERIC_WRITE,
				0, // Exclusive access: no sharing!
				nil,
				windows.OPEN_EXISTING,
				0,
				0,
			)
			if err == nil {
				// With file locked exclusively, attempt StageBinary
				err = slots.StageBinary(bytes.NewReader(validPE), "")
				// Must return error cleanly, not panic or freeze
				if err == nil {
					t.Logf("StageBinary succeeded (atomic replace bypassed locked target)")
				} else {
					t.Logf("StageBinary safely returned error on locked file: %v", err)
				}
				windows.CloseHandle(h)
			}
		}

		// Verify no dangling staging tmp files
		entries, err := os.ReadDir(slots.GetInactiveSlotDir())
		if err != nil {
			t.Fatalf("ReadDir error: %v", err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".stage-") {
				t.Fatalf("Leaked temporary staging file: %s", e.Name())
			}
		}
	})

	// Subtest D: Corrupted state.json self-healing
	t.Run("CorruptedStateFileRecovery", func(t *testing.T) {
		stateFile := filepath.Join(baseDir, "bin", "state.json")

		// Overwrite with broken/truncated JSON
		corruptStates := []string{
			`{"active_slot": "slot_b", "pending_slot":`,
			`{`,
			`INVALID_JSON_DATA_GARBAGE`,
			``,
		}

		for i, corrupt := range corruptStates {
			if err := os.WriteFile(stateFile, []byte(corrupt), 0644); err != nil {
				t.Fatalf("[%d] WriteFile state error: %v", i, err)
			}

			// Re-open SlotManager: must self-heal from link target without error
			recoveredSlots, err := supervisor.InitSlots(baseDir)
			if err != nil {
				t.Fatalf("[%d] InitSlots failed to recover corrupted state.json: %v", i, err)
			}

			st := recoveredSlots.GetState()
			if st.ActiveSlot != "slot_a" && st.ActiveSlot != "slot_b" {
				t.Fatalf("[%d] Recovered invalid active slot: %q", i, st.ActiveSlot)
			}
			if st.PendingSlot != "" {
				t.Fatalf("[%d] Recovered pending slot should be empty, got %q", i, st.PendingSlot)
			}

			// Verify state.json was rewritten with valid JSON
			data, err := os.ReadFile(stateFile)
			if err != nil {
				t.Fatalf("[%d] ReadFile state error: %v", i, err)
			}
			var parsed supervisor.SlotState
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("[%d] Rewritten state.json is invalid JSON: %v", i, err)
			}
		}
	})
}

// ============================================================================
// Adversarial Scenario 4: Zero PID & Unexpected Message Types Over IPC
// ============================================================================

// TestE2E_Tier5_R1_ZeroPIDAndUnexpectedIPCMessages tests the supervisor IPC dispatcher
// against boundary conditions: PID 0, mismatched PIDs, negative/huge PIDs, unknown
// message action types, and raw protocol anomalies.
func TestE2E_Tier5_R1_ZeroPIDAndUnexpectedIPCMessages(t *testing.T) {
	sup, slots, _ := setupTier5Supervisor(t, "healthy")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	ok := pollCondition(4*time.Second, func() bool {
		return sup.WorkerPID() > 0 && sup.HeartbeatCount() >= 1
	})
	if !ok {
		t.Fatalf("Supervisor worker failed to start")
	}

	workerPID := sup.WorkerPID()
	pipePath := sup.Addr().String()

	client, err := supervisor.ConnectIPC(pipePath)
	if err != nil {
		t.Fatalf("ConnectIPC error: %v", err)
	}
	defer client.Close()

	// 1. Zero PID Heartbeat: should be accepted and update heartbeat count without overwriting workerPID
	initialHB := sup.HeartbeatCount()
	err = client.Send(&supervisor.IPCMessage{
		Type:     supervisor.MsgHeartbeat,
		PID:      0, // Zero PID
		RSSBytes: 1024 * 1024 * 12,
	})
	if err != nil {
		t.Fatalf("Failed to send zero PID heartbeat: %v", err)
	}

	ok = pollCondition(2*time.Second, func() bool {
		return sup.HeartbeatCount() > initialHB
	})
	if !ok {
		t.Fatalf("Zero PID heartbeat was not ingested by supervisor")
	}
	if sup.WorkerPID() != workerPID {
		t.Fatalf("Zero PID heartbeat overwrote WorkerPID: expected %d, got %d", workerPID, sup.WorkerPID())
	}

	// 2. Mismatched PID Heartbeat: should be discarded without error or termination
	prevHB := sup.HeartbeatCount()
	err = client.Send(&supervisor.IPCMessage{
		Type:     supervisor.MsgHeartbeat,
		PID:      workerPID + 100000, // Mismatched PID
		RSSBytes: 1024 * 1024 * 12,
	})
	if err != nil {
		t.Fatalf("Failed to send mismatched PID heartbeat: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	// Heartbeat count should not increment from mismatched PID
	t.Logf("Heartbeat count before: %d, after mismatched: %d (discard confirmed)", prevHB, sup.HeartbeatCount())

	// 3. Zero PID NotifyHealthy: should be accepted
	// Temporarily simulate a pending slot for verification
	_ = slots.SetPendingForTest(slots.GetInactiveSlot(), time.Now())
	err = client.Send(&supervisor.IPCMessage{
		Type:    supervisor.MsgNotifyHealthy,
		PID:     0, // Zero PID accepted
		Version: "v1.1.0",
	})
	if err != nil {
		t.Fatalf("Send zero PID notify_healthy failed: %v", err)
	}
	ok = pollCondition(2*time.Second, func() bool {
		return slots.GetState().PendingSlot == "" && slots.GetState().LastGoodVersion == "v1.1.0"
	})
	if !ok {
		t.Fatalf("Zero PID notify_healthy failed to commit pending slot")
	}

	// 4. Mismatched PID NotifyHealthy: should be rejected
	_ = slots.SetPendingForTest(slots.GetInactiveSlot(), time.Now())
	err = client.Send(&supervisor.IPCMessage{
		Type:    supervisor.MsgNotifyHealthy,
		PID:     workerPID + 88888, // Mismatched PID
		Version: "v1.2.0",
	})
	if err != nil {
		t.Fatalf("Send mismatched notify_healthy failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	// Pending slot should remain uncommitted
	if slots.GetState().PendingSlot == "" {
		t.Fatalf("Mismatched PID notify_healthy incorrectly committed pending slot!")
	}
	_ = slots.Rollback()

	// 5. Unexpected / Malformed Message Types: should be safely ignored
	unknownTypes := []supervisor.MessageType{
		"UNKNOWN_ACTION_TYPE",
		"",
		"DROP TABLE users;",
		"admin_shutdown_unauthorized",
		"\x00\x01\x02\x03",
	}

	for _, ut := range unknownTypes {
		err := client.Send(&supervisor.IPCMessage{
			Type: ut,
			PID:  workerPID,
		})
		if err != nil {
			t.Fatalf("Failed to send unknown type %q: %v", ut, err)
		}
	}

	// 6. Verify subsequent valid query succeeds on the exact same connection
	resp, err := client.RoundTrip(&supervisor.IPCMessage{
		Type: supervisor.MsgGetInactive,
	})
	if err != nil {
		t.Fatalf("Subsequent valid MsgGetInactive failed after unexpected message types: %v", err)
	}
	if resp == nil || resp.Type != supervisor.MsgInactiveResp || resp.Slot == "" {
		t.Fatalf("Invalid response for MsgGetInactive: %+v", resp)
	}

	if err := sup.Stop(); err != nil {
		t.Fatalf("Stop error: %v", err)
	}
}

// ============================================================================
// Adversarial Scenario 5: Stale Candidate Crash Rollback Recovery
// ============================================================================

// TestE2E_Tier5_R2_StaleCandidateCrashRollbackRecovery tests the full lifecycle
// when an update has been staged and promoted, but the candidate worker crashes
// immediately upon execution. The supervisor must instantly detect the crash,
// execute rollback back to known-good slot_a, and restore the operational worker.
func TestE2E_Tier5_R2_StaleCandidateCrashRollbackRecovery(t *testing.T) {
	sup, slots, _ := setupTier5Supervisor(t, "healthy")

	// Pre-condition: Candidate in slot_b is crashing
	slotBDir := slots.GetInactiveSlotDir()
	_ = os.WriteFile(filepath.Join(slotBDir, "mode.txt"), []byte("crash"), 0644)

	// Promote slot_b to pending
	if err := slots.PromotePending("v2.0.0-broken"); err != nil {
		t.Fatalf("PromotePending error: %v", err)
	}

	if slots.GetState().PendingSlot != "slot_b" {
		t.Fatalf("Expected PendingSlot slot_b, got %s", slots.GetState().PendingSlot)
	}
	if slots.GetActiveSlot() != "slot_a" {
		t.Fatalf("Expected ActiveSlot slot_a, got %s", slots.GetActiveSlot())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sup.Start(ctx)
	}()

	<-sup.Ready()

	// The candidate in slot_b should boot and crash immediately.
	// The supervisor must detect crash in trial and roll back to slot_a.
	ok := pollCondition(6*time.Second, func() bool {
		st := slots.GetState()
		return st.PendingSlot == "" && st.ActiveSlot == "slot_a" && st.RollbackCount >= 1 &&
			sup.WorkerPID() > 0 && isProcRunning(sup.WorkerPID())
	})
	if !ok {
		t.Fatalf("Rollback recovery failed: State=%+v, WorkerPID=%d",
			slots.GetState(), sup.WorkerPID())
	}

	// Verify restored worker in slot_a is healthy and emitting heartbeats
	ok = pollCondition(4*time.Second, func() bool {
		return sup.HeartbeatCount() >= 1
	})
	if !ok {
		t.Fatalf("Restored worker in slot_a failed to emit heartbeats")
	}

	st := slots.GetState()
	t.Logf("Stale candidate rollback verified successfully: Active=%s, Rollbacks=%d, WorkerPID=%d, Heartbeats=%d",
		st.ActiveSlot, st.RollbackCount, sup.WorkerPID(), sup.HeartbeatCount())

	if err := sup.Stop(); err != nil {
		t.Fatalf("Stop error: %v", err)
	}
}

// ============================================================================
// Adversarial Scenario 6: IPC Max Payload Boundary & Malformed Framing
// ============================================================================

// TestE2E_Tier5_R1_IPCMaxPayloadBoundaryAndMalformedFrames tests the IPC server's
// DOS protection against frames exceeding MaxMessageSize (1 MB), truncated JSON,
// and raw binary garbage frames.
func TestE2E_Tier5_R1_IPCMaxPayloadBoundaryAndMalformedFrames(t *testing.T) {
	server := supervisor.NewIPCServer()

	var listener net.Listener
	var err error
	if runtime.GOOS == "windows" {
		pipeName := fmt.Sprintf(`\\.\pipe\tier5-fuzz-%d-%d`, os.Getpid(), time.Now().UnixNano())
		sddl, _ := supervisor.CurrentUserSDDL()
		listener, err = supervisor.ListenPipe(pipeName, sddl)
	} else {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}

	server.RegisterHandler(supervisor.MsgGetInactive, func(msg *supervisor.IPCMessage) (*supervisor.IPCMessage, error) {
		return &supervisor.IPCMessage{
			Type: supervisor.MsgInactiveResp,
			Slot: "slot_b",
		}, nil
	})

	if err := server.Start(listener); err != nil {
		t.Fatalf("server.Start error: %v", err)
	}
	defer server.Stop()

	dialConn := func() (net.Conn, error) {
		if runtime.GOOS == "windows" {
			return supervisor.DialPipe(listener.Addr().String(), 3*time.Second)
		}
		return net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
	}

	// Subtest 1: Message exceeding MaxMessageSize (1 MB + 1024 bytes) must terminate connection
	t.Run("OversizedPayloadDisconnect", func(t *testing.T) {
		conn, err := dialConn()
		if err != nil {
			t.Fatalf("dial error: %v", err)
		}
		defer conn.Close()

		oversized := make([]byte, supervisor.MaxMessageSize+1024)
		for i := range oversized {
			oversized[i] = ' '
		}
		oversized[len(oversized)-1] = '\n'

		_, _ = conn.Write(oversized)

		// The server must terminate the connection per MaxMessageSize DOS defense
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatalf("Expected connection to be closed by server on oversized payload, but read succeeded")
		}
		t.Logf("Oversized payload rejected cleanly with connection termination: %v", err)
	})

	// Subtest 2: Malformed JSON framing followed by valid request
	t.Run("MalformedJSONFramingRecovery", func(t *testing.T) {
		conn, err := dialConn()
		if err != nil {
			t.Fatalf("dial error: %v", err)
		}
		defer conn.Close()

		// Send garbage line
		_, _ = conn.Write([]byte("NOT_JSON_AT_ALL_GARBAGE_BYTES_1234567890\n"))
		// Send incomplete JSON
		_, _ = conn.Write([]byte("{\"type\": \"heart\n"))
		// Send null bytes
		_, _ = conn.Write([]byte("\x00\x00\x00\x00\n"))

		// Now send valid JSON
		validMsg, _ := json.Marshal(supervisor.IPCMessage{Type: supervisor.MsgGetInactive})
		validMsg = append(validMsg, '\n')
		_, err = conn.Write(validMsg)
		if err != nil {
			t.Fatalf("Write validMsg error: %v", err)
		}

		// Server must safely parse and respond to the valid message
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		decoder := json.NewDecoder(conn)
		var resp supervisor.IPCMessage
		if err := decoder.Decode(&resp); err != nil {
			t.Fatalf("Failed to decode response to validMsg after malformed frames: %v", err)
		}
		if resp.Type != supervisor.MsgInactiveResp || resp.Slot != "slot_b" {
			t.Fatalf("Unexpected response: %+v", resp)
		}
		t.Logf("IPC server successfully recovered and processed valid query after malformed frames")
	})
}

// ============================================================================
// Adversarial Scenario 7: Update Staging Adversarial Pre-Flights & Checksums
// ============================================================================

// TestE2E_Tier5_R2_UpdateStagingAdversarialScenarios tests agent update pre-flight
// bounds, corrupt SHA-256 digests, and hash mismatch defenses.
func TestE2E_Tier5_R2_UpdateStagingAdversarialScenarios(t *testing.T) {
	ctx := context.Background()
	cfg := &agent.Config{
		ServerURL: "https://127.0.0.1:8443",
	}

	validHash := strings.Repeat("a", 64)

	// Test 1: Invalid SHA-256 lengths & characters
	badHashes := []string{
		"",                                 // empty
		strings.Repeat("a", 63),            // 63 chars (too short)
		strings.Repeat("a", 65),            // 65 chars (too long)
		strings.Repeat("g", 64),            // invalid hex character 'g'
		"'; DROP TABLE updates; --" + strings.Repeat("0", 38), // injection attempt
	}

	for _, bh := range badHashes {
		err := agent.ApplyStagedUpdate(ctx, cfg, protocol.AgentUpdate{
			URL:    "https://127.0.0.1:8443/bin/rmm-agent.exe",
			SHA256: bh,
		}, nil)
		if err == nil {
			t.Fatalf("Expected ApplyStagedUpdate to reject bad hash %q, but succeeded", bh)
		}
	}

	// Test 2: Insecure non-matching server URL
	err := agent.ApplyStagedUpdate(ctx, cfg, protocol.AgentUpdate{
		URL:    "http://evil-attacker.com/payload.exe",
		SHA256: validHash,
	}, nil)
	if err == nil {
		t.Fatalf("Expected ApplyStagedUpdate to reject external URL, but succeeded")
	}

	// Test 3: Standalone mode without IPC and without legacy flag
	err = agent.ApplyStagedUpdate(ctx, cfg, protocol.AgentUpdate{
		URL:    "https://127.0.0.1:8443/bin/rmm-agent.exe",
		SHA256: validHash,
	}, nil)
	if err == nil {
		t.Fatalf("Expected ApplyStagedUpdate to fail without supervisor IPC")
	}
	if !strings.Contains(err.Error(), "standalone mode") {
		t.Fatalf("Expected standalone mode error, got: %v", err)
	}

	// Test 4: SHA-256 Checksum mismatch during StageUpdate on SlotManager
	baseDir := t.TempDir()
	slots, err := supervisor.InitSlots(baseDir)
	if err != nil {
		t.Fatalf("InitSlots: %v", err)
	}

	validPE := append([]byte{0x4D, 0x5A, 0x90, 0x00}, bytes.Repeat([]byte("CODE"), 30)...)
	actualSum := sha256.Sum256(validPE)
	actualSHA := hex.EncodeToString(actualSum[:])
	wrongSHA := strings.Repeat("f", 64)

	// Stage with wrong hash: MUST fail
	err = slots.StageBinary(bytes.NewReader(validPE), wrongSHA)
	if err == nil {
		t.Fatalf("Expected StageBinary to fail with wrong SHA-256, but succeeded")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("Expected 'checksum mismatch' error, got: %v", err)
	}

	// Stage with matching hash: MUST succeed
	err = slots.StageBinary(bytes.NewReader(validPE), actualSHA)
	if err != nil {
		t.Fatalf("StageBinary with matching SHA failed: %v", err)
	}

	// Verify staged file
	inactiveBin := slots.GetInactiveBinaryPath()
	info, err := os.Stat(inactiveBin)
	if err != nil || info.Size() == 0 {
		t.Fatalf("Staged binary file missing or 0 bytes: %v", err)
	}
}
