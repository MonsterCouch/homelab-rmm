package supervisor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// makeMockPayload creates a valid or invalid binary payload for testing.
func makeMockPayload(version string, valid bool) (string, []byte) {
	var payload []byte
	if valid {
		if runtime.GOOS == "windows" {
			payload = append([]byte{0x4D, 0x5A, 0x90, 0x00}, []byte("TestAppBinary-"+version)...)
		} else {
			payload = append([]byte{0x7F, 'E', 'L', 'F'}, []byte("TestAppBinary-"+version)...)
		}
	} else {
		payload = []byte("MALFORMED_HEADER_" + version)
	}
	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:]), payload
}

// TestAdversarial_FullLifecycleAlternatingCycles rigorously tests complete A -> B -> A transitions.
func TestAdversarial_FullLifecycleAlternatingCycles(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	// Initial State: Active = slot_a, Pending = "", RollbackCount = 0
	if mgr.GetActiveSlot() != "slot_a" || mgr.GetInactiveSlot() != "slot_b" {
		t.Fatalf("Unexpected initial slots: active=%s, inactive=%s", mgr.GetActiveSlot(), mgr.GetInactiveSlot())
	}
	hA1, bA1 := makeMockPayload("v1.0.0", true)
	if err := os.WriteFile(mgr.GetActiveBinaryPath(), bA1, 0755); err != nil {
		t.Fatalf("Failed to seed active binary: %v", err)
	}
	_ = hA1

	// Stage v2.0.0 to inactive (slot_b)
	hB2, bB2 := makeMockPayload("v2.0.0", true)
	if err := mgr.StageBinary(bytes.NewReader(bB2), hB2); err != nil {
		t.Fatalf("StageBinary v2.0.0 failed: %v", err)
	}

	// Promote v2.0.0 -> Active MUST REMAIN slot_a, Pending MUST BE slot_b
	if err := mgr.PromotePending("v2.0.0"); err != nil {
		t.Fatalf("PromotePending v2.0.0 failed: %v", err)
	}
	state := mgr.GetState()
	if state.ActiveSlot != "slot_a" {
		t.Fatalf("INVARIANCE VIOLATION: ActiveSlot changed to %s during pending trial", state.ActiveSlot)
	}
	if state.PendingSlot != "slot_b" {
		t.Fatalf("INVARIANCE VIOLATION: PendingSlot expected slot_b, got %s", state.PendingSlot)
	}

	// ConfirmHealthy -> Active MUST BECOME slot_b, Pending cleared
	if err := mgr.ConfirmHealthy("v2.0.0"); err != nil {
		t.Fatalf("ConfirmHealthy v2.0.0 failed: %v", err)
	}
	state = mgr.GetState()
	if state.ActiveSlot != "slot_b" {
		t.Fatalf("INVARIANCE VIOLATION: ActiveSlot expected slot_b after confirmation, got %s", state.ActiveSlot)
	}
	if state.PendingSlot != "" {
		t.Fatalf("INVARIANCE VIOLATION: PendingSlot not cleared, got %s", state.PendingSlot)
	}
	if state.LastGoodVersion != "v2.0.0" {
		t.Fatalf("LastGoodVersion mismatch: expected v2.0.0, got %s", state.LastGoodVersion)
	}

	// Now Inactive is slot_a! Stage v3.0.0-broken into slot_a
	hA3, bA3 := makeMockPayload("v3.0.0-broken", true)
	if err := mgr.StageBinary(bytes.NewReader(bA3), hA3); err != nil {
		t.Fatalf("StageBinary v3.0.0-broken failed: %v", err)
	}

	// Promote v3.0.0 -> Active MUST REMAIN slot_b, Pending MUST BE slot_a
	if err := mgr.PromotePending("v3.0.0-broken"); err != nil {
		t.Fatalf("PromotePending v3.0.0-broken failed: %v", err)
	}
	state = mgr.GetState()
	if state.ActiveSlot != "slot_b" {
		t.Fatalf("INVARIANCE VIOLATION: ActiveSlot expected slot_b during pending trial, got %s", state.ActiveSlot)
	}
	if state.PendingSlot != "slot_a" {
		t.Fatalf("INVARIANCE VIOLATION: PendingSlot expected slot_a, got %s", state.PendingSlot)
	}

	// Broken candidate: Rollback()!
	if err := mgr.Rollback(); err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}
	state = mgr.GetState()
	if state.ActiveSlot != "slot_b" {
		t.Fatalf("INVARIANCE VIOLATION: ActiveSlot expected slot_b after rollback, got %s", state.ActiveSlot)
	}
	if state.PendingSlot != "" {
		t.Fatalf("INVARIANCE VIOLATION: PendingSlot not cleared after rollback, got %s", state.PendingSlot)
	}
	if state.RollbackCount != 1 {
		t.Fatalf("RollbackCount expected 1, got %d", state.RollbackCount)
	}

	// Current link MUST point back to slot_b
	target, err := readLinkTarget(mgr.GetCurrentDir())
	if err != nil {
		t.Fatalf("readLinkTarget failed: %v", err)
	}
	if filepath.Base(target) != "slot_b" {
		t.Fatalf("Current link target expected slot_b, got %s", target)
	}

	// Inactive is STILL slot_a! Stage fixed candidate v3.1.0 into slot_a
	hA31, bA31 := makeMockPayload("v3.1.0-fixed", true)
	if err := mgr.StageBinary(bytes.NewReader(bA31), hA31); err != nil {
		t.Fatalf("StageBinary v3.1.0-fixed failed: %v", err)
	}
	if err := mgr.PromotePending("v3.1.0-fixed"); err != nil {
		t.Fatalf("PromotePending v3.1.0-fixed failed: %v", err)
	}
	if err := mgr.ConfirmHealthy("v3.1.0-fixed"); err != nil {
		t.Fatalf("ConfirmHealthy v3.1.0-fixed failed: %v", err)
	}

	// Final verification: Active is slot_a, Pending is empty, RollbackCount is 1, LastGoodVersion is v3.1.0-fixed
	state = mgr.GetState()
	if state.ActiveSlot != "slot_a" {
		t.Fatalf("Final ActiveSlot expected slot_a, got %s", state.ActiveSlot)
	}
	if state.PendingSlot != "" {
		t.Fatalf("Final PendingSlot not empty, got %s", state.PendingSlot)
	}
	if state.RollbackCount != 1 {
		t.Fatalf("Final RollbackCount expected 1, got %d", state.RollbackCount)
	}
	if state.LastGoodVersion != "v3.1.0-fixed" {
		t.Fatalf("Final LastGoodVersion mismatch: %s", state.LastGoodVersion)
	}

	// Read content from current link
	content, err := os.ReadFile(mgr.GetCurrentBinaryPath())
	if err != nil {
		t.Fatalf("Failed to read current binary: %v", err)
	}
	if !bytes.Equal(content, bA31) {
		t.Fatalf("Current binary content does not match v3.1.0-fixed payload")
	}
}

// TestAdversarial_RollbackCircuitBoundaries tests edge cases and boundary conditions for 60s timeout.
func TestAdversarial_RollbackCircuitBoundaries(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	_, bA := makeMockPayload("v1.0.0", true)
	_ = os.WriteFile(mgr.GetActiveBinaryPath(), bA, 0755)

	hB, bB := makeMockPayload("v2.0.0", true)
	_ = mgr.StageBinary(bytes.NewReader(bB), hB)

	// Subtest 1: Default timeout fallback when timeout <= 0
	t.Run("Default60sFallback", func(t *testing.T) {
		if err := mgr.PromotePending("v2.0.0"); err != nil {
			t.Fatalf("PromotePending failed: %v", err)
		}

		// At 59s elapsed with timeout=0, must NOT rollback (default is 60s)
		_ = mgr.SetPendingStartedAtForTest(time.Now().Add(-59 * time.Second))
		triggered, err := mgr.CheckRollbackCircuit(0)
		if err != nil {
			t.Fatalf("CheckRollbackCircuit(0) failed: %v", err)
		}
		if triggered {
			t.Fatalf("CheckRollbackCircuit(0) prematurely triggered at 59s")
		}

		// At 61s elapsed with timeout=-10s, MUST rollback
		_ = mgr.SetPendingStartedAtForTest(time.Now().Add(-61 * time.Second))
		triggered, err = mgr.CheckRollbackCircuit(-10 * time.Second)
		if err != nil {
			t.Fatalf("CheckRollbackCircuit(-10s) failed: %v", err)
		}
		if !triggered {
			t.Fatalf("CheckRollbackCircuit(-10s) failed to trigger at 61s")
		}
		if mgr.GetState().RollbackCount != 1 {
			t.Errorf("RollbackCount mismatch: %d", mgr.GetState().RollbackCount)
		}
	})

	// Subtest 2: Zero PendingStartedAt should not trigger rollback
	t.Run("ZeroPendingStartedAt", func(t *testing.T) {
		_ = mgr.SetPendingForTest("slot_b", time.Time{})
		triggered, err := mgr.CheckRollbackCircuit(1 * time.Nanosecond)
		if err != nil {
			t.Fatalf("CheckRollbackCircuit failed: %v", err)
		}
		if triggered {
			t.Fatalf("CheckRollbackCircuit triggered when PendingStartedAt is zero time")
		}
		// Reset pending slot
		_ = mgr.SetPendingForTest("", time.Time{})
	})

	// Subtest 3: Multiple Rollback Cycles Monotonically Increment Counter
	t.Run("MonotonicRollbackCounter", func(t *testing.T) {
		initialCount := mgr.GetState().RollbackCount
		for i := 1; i <= 3; i++ {
			_ = mgr.StageBinary(bytes.NewReader(bB), hB)
			if err := mgr.PromotePending(fmt.Sprintf("v2.0.%d", i)); err != nil {
				t.Fatalf("Promote failed at cycle %d: %v", i, err)
			}
			_ = mgr.SetPendingStartedAtForTest(time.Now().Add(-100 * time.Second))
			triggered, err := mgr.CheckRollbackCircuit(60 * time.Second)
			if err != nil || !triggered {
				t.Fatalf("Circuit failed at cycle %d: triggered=%v, err=%v", i, triggered, err)
			}
			if mgr.GetState().RollbackCount != initialCount+i {
				t.Fatalf("RollbackCount expected %d, got %d", initialCount+i, mgr.GetState().RollbackCount)
			}
		}
	})

	// Subtest 4: Fast Millisecond Circuit
	t.Run("FastMillisecondCircuit", func(t *testing.T) {
		_ = mgr.StageBinary(bytes.NewReader(bB), hB)
		if err := mgr.PromotePending("v2.1.0"); err != nil {
			t.Fatalf("PromotePending failed: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
		triggered, err := mgr.CheckRollbackCircuit(10 * time.Millisecond)
		if err != nil || !triggered {
			t.Fatalf("Fast circuit expected true, got %v (err: %v)", triggered, err)
		}
	})
}

// TestAdversarial_StagingValidationTampering verifies that invalid or poisoned binaries are rejected.
func TestAdversarial_StagingValidationTampering(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	// Establish known good binary in inactive slot first
	hGood, bGood := makeMockPayload("vGood", true)
	if err := mgr.StageBinary(bytes.NewReader(bGood), hGood); err != nil {
		t.Fatalf("Initial stage good failed: %v", err)
	}

	testCases := []struct {
		name        string
		data        []byte
		checksum    string
		expectError string
	}{
		{
			name:        "EmptyPayload",
			data:        []byte{},
			checksum:    "",
			expectError: "binary header",
		},
		{
			name:        "SingleBytePayload",
			data:        []byte{0x4D},
			checksum:    "",
			expectError: "too small",
		},
		{
			name:        "InvalidMagicBytes",
			data:        []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			checksum:    "",
			expectError: "header",
		},
		{
			name:        "TamperedChecksum",
			data:        bGood,
			checksum:    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			expectError: "checksum mismatch",
		},
		{
			name:        "UppercaseChecksumMatches",
			data:        bGood,
			checksum:    strings.ToUpper(hGood),
			expectError: "", // should succeed (case insensitive)
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := mgr.StageBinary(bytes.NewReader(tc.data), tc.checksum)
			if tc.expectError != "" {
				if err == nil {
					t.Fatalf("Expected error containing %q, got nil", tc.expectError)
				}
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.expectError)) {
					t.Fatalf("Expected error containing %q, got %q", tc.expectError, err.Error())
				}
				// Verify inactive binary was NOT modified or deleted
				existing, readErr := os.ReadFile(mgr.GetInactiveBinaryPath())
				if readErr != nil {
					t.Fatalf("Inactive binary corrupted or deleted: %v", readErr)
				}
				if !bytes.Equal(existing, bGood) {
					t.Fatalf("Inactive binary was modified during failed stage!")
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
			}

			// Verify no stray temp files left in inactive slot directory
			entries, _ := os.ReadDir(mgr.GetInactiveSlotDir())
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), ".stage-") {
					t.Errorf("Leaked staging temp file: %s", e.Name())
				}
			}
		})
	}
}

// TestAdversarial_SlotHighConcurrencyStress executes massive concurrent read/write/promote/rollback load
// under -race to detect data races, deadlocks, and file locking issues.
func TestAdversarial_SlotHighConcurrencyStress(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	_, bA := makeMockPayload("v1.0.0", true)
	_, bB := makeMockPayload("v2.0.0", true)
	_ = os.WriteFile(mgr.GetActiveBinaryPath(), bA, 0755)
	_ = os.WriteFile(mgr.GetInactiveBinaryPath(), bB, 0755)

	var wg sync.WaitGroup
	stopCh := make(chan struct{})
	var readOps, writeOps, fileReadOps atomic.Uint64

	// 1. Concurrent State Readers (40 goroutines)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					_ = mgr.GetActiveSlot()
					_ = mgr.GetInactiveSlot()
					_ = mgr.GetActiveSlotDir()
					_ = mgr.GetInactiveSlotDir()
					_ = mgr.GetActiveBinaryPath()
					_ = mgr.GetInactiveBinaryPath()
					_ = mgr.GetCurrentBinaryPath()
					state := mgr.GetState()
					if state.ActiveSlot != "slot_a" && state.ActiveSlot != "slot_b" {
						panic(fmt.Sprintf("Invalid active slot observed: %s", state.ActiveSlot))
					}
					readOps.Add(1)
					time.Sleep(100 * time.Microsecond)
				}
			}
		}()
	}

	// 2. Concurrent Disk Binary Readers via Current Link (15 goroutines)
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					currBin := mgr.GetCurrentBinaryPath()
					// Reading binary file concurrently while link is switching
					data, err := os.ReadFile(currBin)
					if err == nil && len(data) > 0 {
						fileReadOps.Add(1)
					}
					time.Sleep(500 * time.Microsecond)
				}
			}
		}()
	}

	// 3. Concurrent Stagers (5 goroutines)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					ver := fmt.Sprintf("vStage-%d", id)
					h, b := makeMockPayload(ver, true)
					_ = mgr.StageBinary(bytes.NewReader(b), h)
					writeOps.Add(1)
					time.Sleep(2 * time.Millisecond)
				}
			}
		}(i)
	}

	// 4. Concurrent Mutators: Promote / Confirm / Rollback / Circuit (10 goroutines)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					switch id % 4 {
					case 0:
						_ = mgr.PromotePending(fmt.Sprintf("vMut-%d", id))
					case 1:
						_ = mgr.ConfirmHealthy(fmt.Sprintf("vMut-%d", id))
					case 2:
						_ = mgr.Rollback()
					case 3:
						_, _ = mgr.CheckRollbackCircuit(1 * time.Millisecond)
					}
					writeOps.Add(1)
					time.Sleep(1 * time.Millisecond)
				}
			}
		}(i)
	}

	// 5. Concurrent InitSlots Readers (5 goroutines initializing on same dir)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					m2, err := InitSlots(tmpDir)
					if err == nil {
						_ = m2.GetActiveSlot()
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
		}()
	}

	// Stress for 2.5 seconds
	time.Sleep(2500 * time.Millisecond)
	close(stopCh)
	wg.Wait()

	t.Logf("Stress test complete. State reads: %d, File reads: %d, Mutations: %d",
		readOps.Load(), fileReadOps.Load(), writeOps.Load())

	// Final integrity assertion
	finalState := mgr.GetState()
	if finalState.ActiveSlot != "slot_a" && finalState.ActiveSlot != "slot_b" {
		t.Fatalf("Corrupt final state: %+v", finalState)
	}
	target, err := readLinkTarget(mgr.GetCurrentDir())
	if err != nil {
		t.Fatalf("Failed to read current link after stress test: %v", err)
	}
	if filepath.Base(target) != "slot_a" && filepath.Base(target) != "slot_b" {
		t.Fatalf("Corrupted link target: %s", target)
	}
}

// TestAdversarial_IdempotentOperations confirms that calling operations out-of-order does not corrupt state.
func TestAdversarial_IdempotentOperations(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	// 1. ConfirmHealthy when no pending slot
	if err := mgr.ConfirmHealthy("v1.0.0"); err != nil {
		t.Fatalf("ConfirmHealthy on empty pending slot failed: %v", err)
	}
	if mgr.GetState().ActiveSlot != "slot_a" {
		t.Fatalf("ActiveSlot unexpectedly changed: %s", mgr.GetState().ActiveSlot)
	}

	// 2. Rollback when no pending slot
	if err := mgr.Rollback(); err != nil {
		t.Fatalf("Rollback on empty pending slot failed: %v", err)
	}
	if mgr.GetState().RollbackCount != 0 {
		t.Fatalf("RollbackCount unexpectedly incremented: %d", mgr.GetState().RollbackCount)
	}

	// 3. CheckRollbackCircuit when no pending slot
	rolledBack, err := mgr.CheckRollbackCircuit(1 * time.Second)
	if err != nil {
		t.Fatalf("CheckRollbackCircuit on empty pending slot failed: %v", err)
	}
	if rolledBack {
		t.Fatalf("CheckRollbackCircuit reported rollback when no pending slot")
	}

	// 4. Repeated Rollbacks after single promotion
	hB, bB := makeMockPayload("v2.0.0", true)
	_ = mgr.StageBinary(bytes.NewReader(bB), hB)
	_ = mgr.PromotePending("v2.0.0")

	// First rollback
	if err := mgr.Rollback(); err != nil {
		t.Fatalf("First rollback failed: %v", err)
	}
	if mgr.GetState().RollbackCount != 1 {
		t.Fatalf("RollbackCount expected 1, got %d", mgr.GetState().RollbackCount)
	}

	// Second rollback (idempotent no-op)
	if err := mgr.Rollback(); err != nil {
		t.Fatalf("Second rollback failed: %v", err)
	}
	if mgr.GetState().RollbackCount != 1 {
		t.Fatalf("RollbackCount should not increment on second rollback: %d", mgr.GetState().RollbackCount)
	}
}

// TestAdversarial_CorruptedLinkRecovery verifies InitSlots properly recovers when current link is broken.
func TestAdversarial_CorruptedLinkRecovery(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	currentLink := mgr.GetCurrentDir()

	// Deliberately remove current link while state.json says active is slot_b
	mgr.mu.Lock()
	mgr.state.ActiveSlot = "slot_b"
	_ = mgr.saveStateLocked()
	mgr.mu.Unlock()

	_ = os.Remove(currentLink)

	// Reinitialize SlotManager
	mgr2, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed to recover from missing link: %v", err)
	}

	if mgr2.GetActiveSlot() != "slot_b" {
		t.Errorf("Expected active slot 'slot_b' preserved from state.json, got %q", mgr2.GetActiveSlot())
	}

	// Verify link was recreated pointing to slot_b
	target, err := readLinkTarget(mgr2.GetCurrentDir())
	if err != nil {
		t.Fatalf("readLinkTarget failed after recreation: %v", err)
	}
	if filepath.Base(target) != "slot_b" {
		t.Errorf("Recreated link expected slot_b, got %s", target)
	}
}

// TestAdversarial_PromotePendingEdgeCases checks binary verification on promotion.
func TestAdversarial_PromotePendingEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	_, bA := makeMockPayload("v1.0.0", true)
	_ = os.WriteFile(mgr.GetActiveBinaryPath(), bA, 0755)

	// 1. Promote when inactive binary has invalid magic header
	inactiveBin := mgr.GetInactiveBinaryPath()
	_ = os.WriteFile(inactiveBin, []byte("NOT_A_VALID_HEADER_FOR_PE_OR_ELF"), 0755)

	err = mgr.PromotePending("vInvalid")
	if err == nil {
		t.Fatalf("PromotePending should fail when candidate has invalid header")
	}
	if !strings.Contains(err.Error(), "header") {
		t.Fatalf("Expected header error, got %v", err)
	}

	// Verify state and link completely untouched
	if mgr.GetState().PendingSlot != "" {
		t.Errorf("PendingSlot should be empty after failed promotion")
	}
	target, err := readLinkTarget(mgr.GetCurrentDir())
	if err != nil || filepath.Base(target) != "slot_a" {
		t.Errorf("Current link target should still be slot_a, got %s (err: %v)", target, err)
	}

	// 2. Promote valid candidate, then re-promote before confirm
	hB, bB := makeMockPayload("v2.0.0", true)
	_ = mgr.StageBinary(bytes.NewReader(bB), hB)
	if err := mgr.PromotePending("v2.0.0"); err != nil {
		t.Fatalf("First promote failed: %v", err)
	}
	firstStart := mgr.GetState().PendingStartedAt

	time.Sleep(10 * time.Millisecond)

	// Re-promote (e.g. re-staged or updated candidate)
	hB2, bB2 := makeMockPayload("v2.1.0", true)
	_ = mgr.StageBinary(bytes.NewReader(bB2), hB2)
	if err := mgr.PromotePending("v2.1.0"); err != nil {
		t.Fatalf("Re-promote failed: %v", err)
	}

	state := mgr.GetState()
	if state.ActiveSlot != "slot_a" {
		t.Errorf("ActiveSlot should still be slot_a, got %s", state.ActiveSlot)
	}
	if state.PendingSlot != "slot_b" {
		t.Errorf("PendingSlot should still be slot_b, got %s", state.PendingSlot)
	}
	if !state.PendingStartedAt.After(firstStart) {
		t.Errorf("PendingStartedAt was not refreshed on re-promote")
	}
}
