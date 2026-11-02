package supervisor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// writeTestBinary creates an executable test binary payload with valid or invalid header.
func writeTestBinary(t *testing.T, targetPath string, version string, valid bool) (string, []byte) {
	t.Helper()
	var payload []byte
	if valid {
		if runtime.GOOS == "windows" {
			// PE MZ header: 0x4D, 0x5A
			payload = append([]byte{0x4D, 0x5A, 0x90, 0x00}, []byte("HomelabRMM-Binary-"+version)...)
		} else {
			// ELF header: \x7fELF
			payload = append([]byte{0x7F, 'E', 'L', 'F'}, []byte("HomelabRMM-Binary-"+version)...)
		}
	} else {
		payload = []byte("INVALID_HEADER_DATA_" + version)
	}

	if targetPath != "" {
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			t.Fatalf("Failed to create dir: %v", err)
		}
		if err := os.WriteFile(targetPath, payload, 0755); err != nil {
			t.Fatalf("Failed to write test binary: %v", err)
		}
	}

	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:]), payload
}

func TestSlotManager_InitSlots(t *testing.T) {
	tmpDir := t.TempDir()

	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	if mgr.GetActiveSlot() != "slot_a" {
		t.Errorf("Expected active slot 'slot_a', got %q", mgr.GetActiveSlot())
	}
	if mgr.GetInactiveSlot() != "slot_b" {
		t.Errorf("Expected inactive slot 'slot_b', got %q", mgr.GetInactiveSlot())
	}

	state := mgr.GetState()
	if state.ActiveSlot != "slot_a" {
		t.Errorf("State ActiveSlot mismatch: %q", state.ActiveSlot)
	}
	if state.PendingSlot != "" {
		t.Errorf("Expected empty PendingSlot, got %q", state.PendingSlot)
	}
	if state.RollbackCount != 0 {
		t.Errorf("Expected RollbackCount 0, got %d", state.RollbackCount)
	}

	// Verify filesystem paths
	if _, err := os.Stat(mgr.GetActiveSlotDir()); err != nil {
		t.Errorf("Active slot dir stat failed: %v", err)
	}
	if _, err := os.Stat(mgr.GetInactiveSlotDir()); err != nil {
		t.Errorf("Inactive slot dir stat failed: %v", err)
	}
	if _, err := os.Stat(mgr.GetCurrentDir()); err != nil {
		t.Errorf("Current link stat failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "bin", "state.json")); err != nil {
		t.Errorf("state.json stat failed: %v", err)
	}

	// Idempotency check: re-initialize existing base dir
	mgr2, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("Second InitSlots failed: %v", err)
	}
	if mgr2.GetActiveSlot() != "slot_a" {
		t.Errorf("Second InitSlots ActiveSlot mismatch: %q", mgr2.GetActiveSlot())
	}
}

func TestSlotManager_InactiveSlotRouting(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	// Active slot_a -> inactive slot_b
	if mgr.GetActiveSlot() != "slot_a" {
		t.Errorf("Expected active 'slot_a', got %q", mgr.GetActiveSlot())
	}
	if mgr.GetInactiveSlot() != "slot_b" {
		t.Errorf("Expected inactive 'slot_b', got %q", mgr.GetInactiveSlot())
	}
	if !strings.HasSuffix(mgr.GetActiveSlotDir(), "slot_a") {
		t.Errorf("Active dir should end with 'slot_a': %s", mgr.GetActiveSlotDir())
	}
	if !strings.HasSuffix(mgr.GetInactiveSlotDir(), "slot_b") {
		t.Errorf("Inactive dir should end with 'slot_b': %s", mgr.GetInactiveSlotDir())
	}

	// Simulate active slot_b
	mgr.mu.Lock()
	mgr.state.ActiveSlot = "slot_b"
	_ = mgr.saveStateLocked()
	mgr.mu.Unlock()

	if mgr.GetActiveSlot() != "slot_b" {
		t.Errorf("Expected active 'slot_b', got %q", mgr.GetActiveSlot())
	}
	if mgr.GetInactiveSlot() != "slot_a" {
		t.Errorf("Expected inactive 'slot_a', got %q", mgr.GetInactiveSlot())
	}
	if !strings.HasSuffix(mgr.GetActiveSlotDir(), "slot_b") {
		t.Errorf("Active dir should end with 'slot_b': %s", mgr.GetActiveSlotDir())
	}
	if !strings.HasSuffix(mgr.GetInactiveSlotDir(), "slot_a") {
		t.Errorf("Inactive dir should end with 'slot_a': %s", mgr.GetInactiveSlotDir())
	}

	// Check binary path naming
	activeBin := mgr.GetActiveBinaryPath()
	inactiveBin := mgr.GetInactiveBinaryPath()
	currentBin := mgr.GetCurrentBinaryPath()

	if runtime.GOOS == "windows" {
		if !strings.HasSuffix(activeBin, "rmm-agent.exe") {
			t.Errorf("Expected active bin to end with rmm-agent.exe: %s", activeBin)
		}
		if !strings.HasSuffix(inactiveBin, "rmm-agent.exe") {
			t.Errorf("Expected inactive bin to end with rmm-agent.exe: %s", inactiveBin)
		}
		if !strings.HasSuffix(currentBin, "rmm-agent.exe") {
			t.Errorf("Expected current bin to end with rmm-agent.exe: %s", currentBin)
		}
	} else {
		if !strings.HasSuffix(activeBin, "rmm-agent") {
			t.Errorf("Expected active bin to end with rmm-agent: %s", activeBin)
		}
		if !strings.HasSuffix(inactiveBin, "rmm-agent") {
			t.Errorf("Expected inactive bin to end with rmm-agent: %s", inactiveBin)
		}
		if !strings.HasSuffix(currentBin, "rmm-agent") {
			t.Errorf("Expected current bin to end with rmm-agent: %s", currentBin)
		}
	}
}

func TestSlotManager_BinaryValidation(t *testing.T) {
	tmpDir := t.TempDir()
	validPath := filepath.Join(tmpDir, "valid_app")
	invalidPath := filepath.Join(tmpDir, "invalid_app")
	shortPath := filepath.Join(tmpDir, "short_app")

	_, validBytes := writeTestBinary(t, validPath, "v1", true)
	_, invalidBytes := writeTestBinary(t, invalidPath, "v1", false)
	_ = os.WriteFile(shortPath, []byte{0x01}, 0755)

	// ValidateBinaryHeader unit checks
	if err := ValidateBinaryHeader(validBytes[:4]); err != nil {
		t.Errorf("Valid header failed: %v", err)
	}
	if err := ValidateBinaryHeader(invalidBytes[:4]); err == nil {
		t.Errorf("Invalid header unexpectedly passed")
	}
	if err := ValidateBinaryHeader([]byte{0x01}); err == nil {
		t.Errorf("Short header unexpectedly passed")
	}

	// ValidateBinaryFile / ValidateBinary
	if err := ValidateBinaryFile(validPath); err != nil {
		t.Errorf("ValidateBinaryFile(valid) failed: %v", err)
	}
	if err := ValidateBinary(validPath); err != nil {
		t.Errorf("ValidateBinary(valid) failed: %v", err)
	}
	if err := ValidateBinaryFile(invalidPath); err == nil {
		t.Errorf("ValidateBinaryFile(invalid) unexpectedly succeeded")
	}
	if err := ValidateBinaryFile(shortPath); err == nil {
		t.Errorf("ValidateBinaryFile(short) unexpectedly succeeded")
	}
	if err := ValidateBinaryFile(filepath.Join(tmpDir, "non_existent")); err == nil {
		t.Errorf("ValidateBinaryFile(non_existent) unexpectedly succeeded")
	}
}

func TestSlotManager_StageBinary(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	// 1. Stage valid update
	validHash, validBytes := writeTestBinary(t, "", "v1.1.0", true)
	if err := mgr.StageBinary(bytes.NewReader(validBytes), validHash); err != nil {
		t.Fatalf("StageBinary valid failed: %v", err)
	}

	// Verify inactive binary exists and matches content
	inactiveBin := mgr.GetInactiveBinaryPath()
	content, err := os.ReadFile(inactiveBin)
	if err != nil {
		t.Fatalf("Failed to read inactive binary: %v", err)
	}
	if !bytes.Equal(content, validBytes) {
		t.Errorf("Inactive binary content mismatch")
	}

	// 2. Stage with hash mismatch
	badHash := "0000000000000000000000000000000000000000000000000000000000000000"
	if err := mgr.StageBinary(bytes.NewReader(validBytes), badHash); err == nil {
		t.Fatalf("StageBinary with checksum mismatch unexpectedly succeeded")
	}

	// 3. Stage with invalid binary header
	_, invalidBytes := writeTestBinary(t, "", "v1.1.0", false)
	invHash := hex.EncodeToString(sha256.New().Sum(invalidBytes))
	if err := mgr.StageBinary(bytes.NewReader(invalidBytes), invHash); err == nil {
		t.Fatalf("StageBinary with invalid header unexpectedly succeeded")
	}

	// 4. Verify StageUpdate convenience method
	validHash2, validBytes2 := writeTestBinary(t, "", "v1.2.0", true)
	if err := mgr.StageUpdate(validBytes2, validHash2); err != nil {
		t.Fatalf("StageUpdate failed: %v", err)
	}
}

func TestSlotManager_PromoteConfirmHealthyLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	// Stable binary in slot_a
	slotABin := mgr.GetActiveBinaryPath()
	writeTestBinary(t, slotABin, "v1.0.0-stable", true)

	// Stage candidate into slot_b
	hashB, bytesB := writeTestBinary(t, "", "v2.0.0-candidate", true)
	if err := mgr.StageBinary(bytes.NewReader(bytesB), hashB); err != nil {
		t.Fatalf("StageBinary failed: %v", err)
	}

	// Promote pending
	if err := mgr.PromotePending("v2.0.0-candidate"); err != nil {
		t.Fatalf("PromotePending failed: %v", err)
	}

	// State invariants during pending trial:
	// ActiveSlot is STILL slot_a!
	state := mgr.GetState()
	if state.ActiveSlot != "slot_a" {
		t.Errorf("ActiveSlot should still be 'slot_a' during pending trial, got %q", state.ActiveSlot)
	}
	if state.PendingSlot != "slot_b" {
		t.Errorf("PendingSlot should be 'slot_b', got %q", state.PendingSlot)
	}
	if state.PendingStartedAt.IsZero() {
		t.Errorf("PendingStartedAt should be non-zero")
	}

	// bin/current should now point to slot_b
	currTarget, err := readLinkTarget(mgr.GetCurrentDir())
	if err != nil {
		t.Fatalf("readLinkTarget failed: %v", err)
	}
	if filepath.Base(currTarget) != "slot_b" {
		t.Errorf("Current link target should be slot_b, got %s", currTarget)
	}

	// Reading through bin/current yields v2.0.0-candidate
	currentContent, err := os.ReadFile(mgr.GetCurrentBinaryPath())
	if err != nil {
		t.Fatalf("Failed to read current binary: %v", err)
	}
	if !strings.Contains(string(currentContent), "v2.0.0-candidate") {
		t.Fatalf("Current binary does not contain promoted payload: %s", string(currentContent))
	}

	// Confirm healthy
	if err := mgr.ConfirmHealthy("v2.0.0-candidate"); err != nil {
		t.Fatalf("ConfirmHealthy failed: %v", err)
	}

	// State invariants after healthy confirmation:
	// ActiveSlot is now slot_b!
	state = mgr.GetState()
	if state.ActiveSlot != "slot_b" {
		t.Errorf("ActiveSlot should be 'slot_b' after confirm, got %q", state.ActiveSlot)
	}
	if state.PendingSlot != "" {
		t.Errorf("PendingSlot should be cleared, got %q", state.PendingSlot)
	}
	if state.LastGoodVersion != "v2.0.0-candidate" {
		t.Errorf("LastGoodVersion not updated: %q", state.LastGoodVersion)
	}
	if state.RollbackCount != 0 {
		t.Errorf("RollbackCount unexpectedly changed: %d", state.RollbackCount)
	}

	// ConfirmHealthy with no pending slot is an idempotent no-op
	if err := mgr.ConfirmHealthy("v2.0.0"); err != nil {
		t.Errorf("Second ConfirmHealthy should be no-op: %v", err)
	}
}

func TestSlotManager_PromoteRollbackLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	// Stable v1.0.0 in slot_a
	slotABin := mgr.GetActiveBinaryPath()
	writeTestBinary(t, slotABin, "v1.0.0-stable", true)

	// Stage broken candidate in slot_b
	hashB, bytesB := writeTestBinary(t, "", "v1.2.0-broken", true)
	if err := mgr.StageBinary(bytes.NewReader(bytesB), hashB); err != nil {
		t.Fatalf("StageBinary failed: %v", err)
	}

	// Promote broken candidate
	if err := mgr.PromotePending("v1.2.0-broken"); err != nil {
		t.Fatalf("PromotePending failed: %v", err)
	}

	// Trigger Rollback
	if err := mgr.Rollback(); err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	// State invariants after rollback:
	// ActiveSlot is retained as slot_a, PendingSlot cleared, RollbackCount incremented
	state := mgr.GetState()
	if state.ActiveSlot != "slot_a" {
		t.Errorf("ActiveSlot mismatch after rollback: got %q, want 'slot_a'", state.ActiveSlot)
	}
	if state.PendingSlot != "" {
		t.Errorf("PendingSlot not cleared after rollback: %q", state.PendingSlot)
	}
	if state.RollbackCount != 1 {
		t.Errorf("RollbackCount should be 1, got %d", state.RollbackCount)
	}

	// bin/current points back to slot_a
	currTarget, err := readLinkTarget(mgr.GetCurrentDir())
	if err != nil {
		t.Fatalf("readLinkTarget failed: %v", err)
	}
	if filepath.Base(currTarget) != "slot_a" {
		t.Errorf("Current link target should be reverted to slot_a, got %s", currTarget)
	}

	// Reading current binary yields stable v1.0.0
	currentContent, err := os.ReadFile(mgr.GetCurrentBinaryPath())
	if err != nil {
		t.Fatalf("Failed to read current binary: %v", err)
	}
	if !strings.Contains(string(currentContent), "v1.0.0-stable") {
		t.Fatalf("Current binary not reverted: %s", string(currentContent))
	}

	// Rollback with no pending is an idempotent no-op
	if err := mgr.Rollback(); err != nil {
		t.Errorf("Second Rollback should be no-op: %v", err)
	}
	if mgr.GetState().RollbackCount != 1 {
		t.Errorf("RollbackCount should not increment on no-op rollback: %d", mgr.GetState().RollbackCount)
	}
}

func TestSlotManager_CheckRollbackCircuit(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	// Populate slot_a with stable binary
	writeTestBinary(t, mgr.GetActiveBinaryPath(), "v1.0.0-stable", true)

	// Stage and promote slot_b
	hashB, bytesB := writeTestBinary(t, "", "v1.1.0-pending", true)
	_ = mgr.StageBinary(bytes.NewReader(bytesB), hashB)
	if err := mgr.PromotePending("v1.1.0-pending"); err != nil {
		t.Fatalf("PromotePending failed: %v", err)
	}

	// 1. Immediately check circuit: timeout not reached
	rolledBack, err := mgr.CheckRollbackCircuit(60 * time.Second)
	if err != nil {
		t.Fatalf("CheckRollbackCircuit failed: %v", err)
	}
	if rolledBack {
		t.Fatalf("Circuit prematurely rolled back before timeout!")
	}

	// 2. Simulate 59 seconds elapsed: still no rollback
	_ = mgr.SetPendingStartedAtForTest(time.Now().Add(-59 * time.Second))
	rolledBack, err = mgr.CheckRollbackCircuit(60 * time.Second)
	if err != nil {
		t.Fatalf("CheckRollbackCircuit failed: %v", err)
	}
	if rolledBack {
		t.Fatalf("Circuit rolled back at 59 seconds!")
	}

	// 3. Simulate 61 seconds elapsed: triggers rollback!
	_ = mgr.SetPendingStartedAtForTest(time.Now().Add(-61 * time.Second))
	rolledBack, err = mgr.CheckRollbackCircuit(60 * time.Second)
	if err != nil {
		t.Fatalf("CheckRollbackCircuit failed: %v", err)
	}
	if !rolledBack {
		t.Fatalf("Circuit failed to roll back after 61 seconds elapsed!")
	}

	// Verify rollback state
	state := mgr.GetState()
	if state.ActiveSlot != "slot_a" {
		t.Errorf("ActiveSlot mismatch: got %q, want 'slot_a'", state.ActiveSlot)
	}
	if state.PendingSlot != "" {
		t.Errorf("PendingSlot not cleared on circuit rollback")
	}
	if state.RollbackCount != 1 {
		t.Errorf("RollbackCount mismatch: got %d, want 1", state.RollbackCount)
	}

	// 4. Checking circuit again when PendingSlot is empty returns false, nil
	rolledBack, err = mgr.CheckRollbackCircuit(60 * time.Second)
	if err != nil {
		t.Fatalf("CheckRollbackCircuit error on empty pending: %v", err)
	}
	if rolledBack {
		t.Errorf("Circuit triggered on empty pending")
	}
}

func TestSlotManager_CorruptStateRecovery(t *testing.T) {
	// Case 1: 0-byte state.json
	t.Run("ZeroByteFile", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := InitSlots(tmpDir)
		if err != nil {
			t.Fatalf("InitSlots failed: %v", err)
		}

		// Truncate state.json to 0 bytes
		stateFile := filepath.Join(tmpDir, "bin", "state.json")
		if err := os.WriteFile(stateFile, []byte{}, 0644); err != nil {
			t.Fatalf("Failed to truncate state.json: %v", err)
		}

		// Reinitialize - should recover from current link
		mgr2, err := InitSlots(tmpDir)
		if err != nil {
			t.Fatalf("InitSlots failed to recover from 0-byte file: %v", err)
		}
		if mgr2.GetActiveSlot() != "slot_a" {
			t.Errorf("Recovered active slot mismatch: got %q, want 'slot_a'", mgr2.GetActiveSlot())
		}
		if mgr2.GetState().PendingSlot != "" {
			t.Errorf("PendingSlot not cleared on recovery")
		}

		// Verify state.json was rewritten with valid JSON
		data, err := os.ReadFile(stateFile)
		if err != nil || len(data) == 0 {
			t.Errorf("state.json was not rewritten cleanly: %v", err)
		}
	})

	// Case 2: Corrupted non-JSON syntax
	t.Run("CorruptJSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := InitSlots(tmpDir)
		if err != nil {
			t.Fatalf("InitSlots failed: %v", err)
		}

		stateFile := filepath.Join(tmpDir, "bin", "state.json")
		if err := os.WriteFile(stateFile, []byte("{CORRUPTED_JSON_BLAH"), 0644); err != nil {
			t.Fatalf("Failed to write corrupt JSON: %v", err)
		}

		mgr2, err := InitSlots(tmpDir)
		if err != nil {
			t.Fatalf("InitSlots failed to recover from corrupt JSON: %v", err)
		}
		if mgr2.GetActiveSlot() != "slot_a" {
			t.Errorf("Recovered active slot mismatch: %q", mgr2.GetActiveSlot())
		}
	})

	// Case 3: Missing state.json
	t.Run("MissingStateFile", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := InitSlots(tmpDir)
		if err != nil {
			t.Fatalf("InitSlots failed: %v", err)
		}

		stateFile := filepath.Join(tmpDir, "bin", "state.json")
		if err := os.Remove(stateFile); err != nil {
			t.Fatalf("Failed to remove state.json: %v", err)
		}

		mgr2, err := InitSlots(tmpDir)
		if err != nil {
			t.Fatalf("InitSlots failed to recover from missing state.json: %v", err)
		}
		if mgr2.GetActiveSlot() != "slot_a" {
			t.Errorf("Recovered active slot mismatch: %q", mgr2.GetActiveSlot())
		}
	})

	// Case 4: Recover ActiveSlot from slot_b link
	t.Run("RecoverFromSlotBLink", func(t *testing.T) {
		tmpDir := t.TempDir()
		binDir := filepath.Join(tmpDir, "bin")
		slotB := filepath.Join(binDir, "slot_b")
		current := filepath.Join(binDir, "current")

		_ = os.MkdirAll(slotB, 0755)
		if err := createOrUpdateLink(current, slotB); err != nil {
			t.Fatalf("createOrUpdateLink failed: %v", err)
		}

		// No state.json exists, but current points to slot_b
		mgr, err := InitSlots(tmpDir)
		if err != nil {
			t.Fatalf("InitSlots failed to recover slot_b link: %v", err)
		}
		if mgr.GetActiveSlot() != "slot_b" {
			t.Errorf("Expected recovery of 'slot_b' from link, got %q", mgr.GetActiveSlot())
		}
	})
}

func TestSlotManager_PromotePending_WithoutCandidateFails(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	// Inactive slot (slot_b) has no binary staged
	if err := mgr.PromotePending("v2.0.0"); err == nil {
		t.Fatalf("PromotePending should fail when inactive candidate is missing")
	}

	// Write empty file
	inactiveBin := mgr.GetInactiveBinaryPath()
	_ = os.WriteFile(inactiveBin, []byte{}, 0755)
	if err := mgr.PromotePending("v2.0.0"); err == nil {
		t.Fatalf("PromotePending should fail when inactive candidate is empty")
	}

	// Verify state and current link remain unchanged
	if mgr.GetState().PendingSlot != "" {
		t.Errorf("PendingSlot should remain empty after failed promotion")
	}
	target, err := readLinkTarget(mgr.GetCurrentDir())
	if err != nil {
		t.Fatalf("readLinkTarget failed: %v", err)
	}
	if filepath.Base(target) != "slot_a" {
		t.Errorf("Current link should still point to slot_a: %s", target)
	}
}

func TestSlotManager_ConcurrentAccess(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	// Write test binaries into both slots
	writeTestBinary(t, mgr.GetActiveBinaryPath(), "v1.0.0", true)
	writeTestBinary(t, mgr.GetInactiveBinaryPath(), "v2.0.0", true)

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	// Readers
	for i := 0; i < 20; i++ {
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
					_ = mgr.GetState()
					time.Sleep(500 * time.Microsecond)
				}
			}
		}()
	}

	// State mutations
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_ = mgr.PromotePending("v2.0.0")
				_ = mgr.ConfirmHealthy("v2.0.0")
				_ = mgr.PromotePending("v3.0.0")
				_ = mgr.Rollback()
				_, _ = mgr.CheckRollbackCircuit(1 * time.Millisecond)
				time.Sleep(2 * time.Millisecond)
			}
		}(i)
	}

	// Wait 250ms then stop readers
	time.Sleep(250 * time.Millisecond)
	close(stopCh)
	wg.Wait()
}
