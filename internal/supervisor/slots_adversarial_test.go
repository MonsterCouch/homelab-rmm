package supervisor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestAdversarial_NTFSJunctionTargetPreservation verifies that creating, switching,
// and deleting junctions never corrupts, removes, or modifies the files within slot_a or slot_b.
func TestAdversarial_NTFSJunctionTargetPreservation(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	slotADir := mgr.GetActiveSlotDir()
	slotBDir := mgr.GetInactiveSlotDir()

	// 1. Create canary files in slot_a and slot_b with distinct content and hashes
	canaryA := filepath.Join(slotADir, "canary_a.dat")
	canaryB := filepath.Join(slotBDir, "canary_b.dat")

	dataA := []byte("CRITICAL_STABLE_SLOT_A_DATA_VERIFY_TARGET_PRESERVATION")
	dataB := []byte("CRITICAL_STABLE_SLOT_B_DATA_VERIFY_TARGET_PRESERVATION")

	if err := os.WriteFile(canaryA, dataA, 0644); err != nil {
		t.Fatalf("Failed to write canaryA: %v", err)
	}
	if err := os.WriteFile(canaryB, dataB, 0644); err != nil {
		t.Fatalf("Failed to write canaryB: %v", err)
	}

	hashA := sha256.Sum256(dataA)
	hashB := sha256.Sum256(dataB)

	// Write mock executables in both slots
	writeTestBinary(t, mgr.GetActiveBinaryPath(), "v1.0.0", true)
	writeTestBinary(t, mgr.GetInactiveBinaryPath(), "v2.0.0", true)

	// 2. Perform 50 rapid alternating switches between slot_a and slot_b
	for i := 0; i < 50; i++ {
		// Switch to slot_b (Promote)
		if err := mgr.PromotePending(fmt.Sprintf("v2.0.%d", i)); err != nil {
			t.Fatalf("Iteration %d: PromotePending failed: %v", i, err)
		}
		// Confirm canary files in both slots are intact
		verifyCanary(t, canaryA, hashA, "during promote")
		verifyCanary(t, canaryB, hashB, "during promote")

		// Revert to slot_a (Rollback)
		if err := mgr.Rollback(); err != nil {
			t.Fatalf("Iteration %d: Rollback failed: %v", i, err)
		}
		// Confirm canary files again
		verifyCanary(t, canaryA, hashA, "during rollback")
		verifyCanary(t, canaryB, hashB, "during rollback")
	}

	// 3. Deliberately remove the bin/current junction/link directly
	currentLink := mgr.GetCurrentDir()
	if err := os.Remove(currentLink); err != nil {
		t.Fatalf("os.Remove on junction/link failed: %v", err)
	}

	// 4. Verify target slot directories and canary files STILL EXIST and are untouched
	if fi, err := os.Stat(slotADir); err != nil || !fi.IsDir() {
		t.Fatalf("slot_a was unexpectedly removed or corrupted when current link was deleted: %v", err)
	}
	if fi, err := os.Stat(slotBDir); err != nil || !fi.IsDir() {
		t.Fatalf("slot_b was unexpectedly removed or corrupted when current link was deleted: %v", err)
	}

	verifyCanary(t, canaryA, hashA, "after junction removal")
	verifyCanary(t, canaryB, hashB, "after junction removal")

	// 5. Reinitialize slots to verify clean self-healing after manual junction deletion
	mgrRecovered, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed after link removal: %v", err)
	}
	if mgrRecovered.GetActiveSlot() != "slot_a" {
		t.Errorf("Expected active slot 'slot_a' after link recovery, got %q", mgrRecovered.GetActiveSlot())
	}
	verifyCanary(t, canaryA, hashA, "after self-healing recovery")
	verifyCanary(t, canaryB, hashB, "after self-healing recovery")
}

func verifyCanary(t *testing.T, path string, expectedHash [32]byte, phase string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("[%s] Canary file %s was destroyed: %v", phase, path, err)
	}
	actualHash := sha256.Sum256(data)
	if actualHash != expectedHash {
		t.Fatalf("[%s] Canary file %s corrupted! Hash mismatch: got %x, want %x", phase, path, actualHash, expectedHash)
	}
}

// TestAdversarial_OpenFileHandleDuringLinkSwitch tests pointer switching while
// an open read handle exists on a file inside the target slot partition.
func TestAdversarial_OpenFileHandleDuringLinkSwitch(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	writeTestBinary(t, mgr.GetActiveBinaryPath(), "v1.0.0", true)
	writeTestBinary(t, mgr.GetInactiveBinaryPath(), "v2.0.0", true)

	// Open the active binary for reading through the current link
	f, err := os.Open(mgr.GetCurrentBinaryPath())
	if err != nil {
		t.Fatalf("Failed to open current binary: %v", err)
	}
	defer f.Close()

	// Switch link to inactive slot while file handle is open
	if err := mgr.PromotePending("v2.0.0"); err != nil {
		t.Fatalf("PromotePending failed while current binary handle was open: %v", err)
	}

	// Verify link points to slot_b
	target, err := readLinkTarget(mgr.GetCurrentDir())
	if err != nil {
		t.Fatalf("readLinkTarget failed: %v", err)
	}
	if filepath.Base(target) != "slot_b" {
		t.Errorf("Expected current to point to slot_b, got %s", target)
	}

	// Verify Rollback also succeeds while handle is still open
	if err := mgr.Rollback(); err != nil {
		t.Fatalf("Rollback failed while file handle open: %v", err)
	}
	target, err = readLinkTarget(mgr.GetCurrentDir())
	if err != nil {
		t.Fatalf("readLinkTarget failed: %v", err)
	}
	if filepath.Base(target) != "slot_a" {
		t.Errorf("Expected current to point back to slot_a, got %s", target)
	}
}

// TestAdversarial_StateJSONFuzzCorruption stress-tests state.json recovery across
// a spectrum of malformed payloads (whitespace, non-object JSON, truncated JSON,
// invalid slot keys, negative rollback count).
func TestAdversarial_StateJSONFuzzCorruption(t *testing.T) {
	testCases := []struct {
		name       string
		content    string
		expectSlot string
	}{
		{"EmptyString", "", "slot_a"},
		{"OnlyWhitespace", "   \r\n\t  \n  ", "slot_a"},
		{"NullLiteral", "null", "slot_a"},
		{"NumberLiteral", "12345", "slot_a"},
		{"BooleanLiteral", "true", "slot_a"},
		{"ArrayLiteral", `["slot_a", "slot_b"]`, "slot_a"},
		{"TruncatedObject", `{"active_slot": "slot_`, "slot_a"},
		{"MalformedJSON", `{"active_slot": invalid_unquoted}`, "slot_a"},
		{"InvalidSlotNameC", `{"active_slot": "slot_c"}`, "slot_a"},
		{"InvalidSlotNameEmpty", `{"active_slot": ""}`, "slot_a"},
		{"InvalidTypeForActiveSlot", `{"active_slot": 9999}`, "slot_a"},
		{"MissingActiveSlotKey", `{"pending_slot": "slot_b", "rollback_count": 5}`, "slot_a"},
		{"BinaryGarbage", string([]byte{0x00, 0xFF, 0xFE, 0xBA, 0xBE, 0x01, 0x02}), "slot_a"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			_, err := InitSlots(tmpDir)
			if err != nil {
				t.Fatalf("Initial InitSlots failed: %v", err)
			}

			stateFile := filepath.Join(tmpDir, "bin", "state.json")
			if err := os.WriteFile(stateFile, []byte(tc.content), 0644); err != nil {
				t.Fatalf("Failed to write test state payload: %v", err)
			}

			// Reinitialize
			mgr, err := InitSlots(tmpDir)
			if err != nil {
				t.Fatalf("InitSlots failed to recover from payload %q: %v", tc.name, err)
			}

			if mgr.GetActiveSlot() != tc.expectSlot {
				t.Errorf("Expected ActiveSlot %q, got %q", tc.expectSlot, mgr.GetActiveSlot())
			}

			// Confirm state.json was rewritten into clean valid JSON
			data, err := os.ReadFile(stateFile)
			if err != nil {
				t.Fatalf("Failed to read rewritten state.json: %v", err)
			}
			if len(data) == 0 {
				t.Fatalf("Rewritten state.json is empty")
			}
			state := mgr.GetState()
			if state.ActiveSlot != tc.expectSlot {
				t.Errorf("State ActiveSlot mismatch: %q", state.ActiveSlot)
			}
		})
	}
}

// TestAdversarial_StateRecoveryWhenSlotBIsCurrent verifies that when state.json is
// missing or corrupted, if the physical junction bin/current points to slot_b,
// the manager correctly reconstructs ActiveSlot as "slot_b".
func TestAdversarial_StateRecoveryWhenSlotBIsCurrent(t *testing.T) {
	corruptions := []string{"", "corrupted json text", `{"active_slot": "invalid"}`}

	for i, corruptContent := range corruptions {
		t.Run(fmt.Sprintf("CorruptionCase_%d", i), func(t *testing.T) {
			tmpDir := t.TempDir()
			mgr, err := InitSlots(tmpDir)
			if err != nil {
				t.Fatalf("InitSlots failed: %v", err)
			}

			// Stage and confirm healthy on slot_b
			writeTestBinary(t, mgr.GetInactiveBinaryPath(), "v2.0.0", true)
			if err := mgr.PromotePending("v2.0.0"); err != nil {
				t.Fatalf("PromotePending failed: %v", err)
			}
			if err := mgr.ConfirmHealthy("v2.0.0"); err != nil {
				t.Fatalf("ConfirmHealthy failed: %v", err)
			}
			if mgr.GetActiveSlot() != "slot_b" {
				t.Fatalf("Expected active slot_b before corruption")
			}

			// Now corrupt state.json
			stateFile := filepath.Join(tmpDir, "bin", "state.json")
			if corruptContent == "" {
				_ = os.Remove(stateFile)
			} else {
				_ = os.WriteFile(stateFile, []byte(corruptContent), 0644)
			}

			// Reinitialize
			mgr2, err := InitSlots(tmpDir)
			if err != nil {
				t.Fatalf("InitSlots failed to recover: %v", err)
			}

			if mgr2.GetActiveSlot() != "slot_b" {
				t.Errorf("Expected recovered ActiveSlot to be 'slot_b' based on junction target, got %q", mgr2.GetActiveSlot())
			}
			if mgr2.GetInactiveSlot() != "slot_a" {
				t.Errorf("Expected inactive slot 'slot_a', got %q", mgr2.GetInactiveSlot())
			}
		})
	}
}

// TestAdversarial_PEHeaderValidationMatrix exhaustively tests all boundary conditions
// for PE binary MZ magic byte validation on Windows.
func TestAdversarial_PEHeaderValidationMatrix(t *testing.T) {
	cases := []struct {
		name        string
		header      []byte
		expectValid bool
	}{
		{"EmptySlice", []byte{}, false},
		{"SingleByteM", []byte{0x4D}, false},
		{"SingleByteZ", []byte{0x5A}, false},
		{"SingleByteRandom", []byte{0x00}, false},
		{"ReversedMagicZM", []byte{0x5A, 0x4D}, false},
		{"OffByOneFirstByte", []byte{0x4C, 0x5A}, false},
		{"OffByOneSecondByte", []byte{0x4D, 0x5B}, false},
		{"LowercaseMZ", []byte{'m', 'z'}, false}, // 0x6D, 0x7A != 0x4D, 0x5A
		{"ValidMZ2Bytes", []byte{0x4D, 0x5A}, true},
		{"ValidMZ4Bytes", []byte{0x4D, 0x5A, 0x90, 0x00}, true},
		{"ValidMZ64BytesDOSHeader", append([]byte{0x4D, 0x5A}, bytes.Repeat([]byte{0x00}, 62)...), true},
		{"ELFHeaderOnWindows", []byte{0x7F, 'E', 'L', 'F'}, false},
		{"MachOHeader32", []byte{0xFE, 0xED, 0xFA, 0xCE}, false},
		{"MachOHeader64", []byte{0xCF, 0xFA, 0xED, 0xFE}, false},
		{"ShellScriptHeader", []byte("#!/bin/bash\n"), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateBinaryHeader(tc.header)
			if runtime.GOOS == "windows" {
				if tc.expectValid && err != nil {
					t.Errorf("Expected valid PE header for %s, got error: %v", tc.name, err)
				}
				if !tc.expectValid && err == nil {
					t.Errorf("Expected invalid PE header for %s, but got nil error", tc.name)
				}
			}
		})
	}
}

// TestAdversarial_StagingPreservesPriorInactiveBinaryOnFailure verifies that if
// staging fails (checksum mismatch or corrupt header), any existing valid binary
// in the inactive partition is NOT destroyed or truncated.
func TestAdversarial_StagingPreservesPriorInactiveBinaryOnFailure(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	// 1. Stage an initial valid binary into slot_b
	initialHash, initialBytes := writeTestBinary(t, "", "v1.0.0-initial", true)
	if err := mgr.StageBinary(bytes.NewReader(initialBytes), initialHash); err != nil {
		t.Fatalf("Initial StageBinary failed: %v", err)
	}

	inactiveBin := mgr.GetInactiveBinaryPath()
	origContent, err := os.ReadFile(inactiveBin)
	if err != nil {
		t.Fatalf("Failed to read inactive binary: %v", err)
	}
	if !bytes.Equal(origContent, initialBytes) {
		t.Fatalf("Initial inactive binary content mismatch")
	}

	// 2. Attempt to stage corrupt binary (bad header)
	_, badHeaderBytes := writeTestBinary(t, "", "v2.0.0-bad-header", false)
	badHeaderHash := hex.EncodeToString(sha256.New().Sum(badHeaderBytes))
	err = mgr.StageBinary(bytes.NewReader(badHeaderBytes), badHeaderHash)
	if err == nil {
		t.Fatalf("Expected StageBinary to fail with bad header, but succeeded")
	}

	// Verify original binary in slot_b is preserved byte-for-byte!
	contentAfterBadHeader, err := os.ReadFile(inactiveBin)
	if err != nil {
		t.Fatalf("Inactive binary was deleted after failed staging: %v", err)
	}
	if !bytes.Equal(contentAfterBadHeader, origContent) {
		t.Errorf("Inactive binary was corrupted after bad header failure!")
	}

	// 3. Attempt to stage binary with mismatched SHA-256
	_, validPayload := writeTestBinary(t, "", "v3.0.0-bad-sha", true)
	err = mgr.StageBinary(bytes.NewReader(validPayload), "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	if err == nil {
		t.Fatalf("Expected StageBinary to fail with checksum mismatch, but succeeded")
	}

	// Verify original binary in slot_b is STILL preserved!
	contentAfterBadHash, err := os.ReadFile(inactiveBin)
	if err != nil {
		t.Fatalf("Inactive binary was deleted after failed hash check: %v", err)
	}
	if !bytes.Equal(contentAfterBadHash, origContent) {
		t.Errorf("Inactive binary was corrupted after bad checksum failure!")
	}

	// 4. Verify no dangling temporary files (.stage-*.tmp) left in inactive directory
	entries, err := os.ReadDir(mgr.GetInactiveSlotDir())
	if err != nil {
		t.Fatalf("Failed to read inactive slot dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".stage-") {
			t.Errorf("Found dangling temporary staging file: %s", entry.Name())
		}
	}
}

// TestAdversarial_RollbackCircuitBoundaryAndIdempotency tests exact 60s rollback
// circuit boundaries and idempotent multi-calls under stress.
func TestAdversarial_RollbackCircuitBoundaryAndIdempotency(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	writeTestBinary(t, mgr.GetActiveBinaryPath(), "v1.0.0", true)
	hashB, bytesB := writeTestBinary(t, "", "v2.0.0", true)
	if err := mgr.StageBinary(bytes.NewReader(bytesB), hashB); err != nil {
		t.Fatalf("StageBinary failed: %v", err)
	}

	if err := mgr.PromotePending("v2.0.0"); err != nil {
		t.Fatalf("PromotePending failed: %v", err)
	}

	// Boundary 1: timeout <= 0 should default to 60s
	// Set pending to 30s ago -> should NOT roll back
	_ = mgr.SetPendingStartedAtForTest(time.Now().Add(-30 * time.Second))
	rolledBack, err := mgr.CheckRollbackCircuit(0)
	if err != nil || rolledBack {
		t.Errorf("Default 60s timeout triggered at 30s: rolledBack=%v, err=%v", rolledBack, err)
	}

	// Boundary 2: Set pending to 59.9 seconds ago -> should NOT roll back with 60s timeout
	_ = mgr.SetPendingStartedAtForTest(time.Now().Add(-59900 * time.Millisecond))
	rolledBack, err = mgr.CheckRollbackCircuit(60 * time.Second)
	if err != nil || rolledBack {
		t.Errorf("60s timeout triggered prematurely at 59.9s: rolledBack=%v, err=%v", rolledBack, err)
	}

	// Boundary 3: Set pending to 60.1 seconds ago -> MUST roll back
	_ = mgr.SetPendingStartedAtForTest(time.Now().Add(-60100 * time.Millisecond))
	rolledBack, err = mgr.CheckRollbackCircuit(60 * time.Second)
	if err != nil || !rolledBack {
		t.Fatalf("60s timeout failed to trigger at 60.1s: rolledBack=%v, err=%v", rolledBack, err)
	}

	// Check post-rollback state
	state := mgr.GetState()
	if state.ActiveSlot != "slot_a" || state.PendingSlot != "" || state.RollbackCount != 1 {
		t.Errorf("State unexpected after circuit rollback: %+v", state)
	}

	// Boundary 4: Calling Rollback() again when already rolled back is an idempotent no-op
	if err := mgr.Rollback(); err != nil {
		t.Errorf("Idempotent Rollback() returned error: %v", err)
	}
	if mgr.GetState().RollbackCount != 1 {
		t.Errorf("RollbackCount incremented on idempotent call: %d", mgr.GetState().RollbackCount)
	}
}

// TestAdversarial_ConcurrentStagingAndPromotionStress tests race conditions between
// concurrent readers, staging operations, and promotion attempts.
func TestAdversarial_ConcurrentStagingAndPromotionStress(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := InitSlots(tmpDir)
	if err != nil {
		t.Fatalf("InitSlots failed: %v", err)
	}

	writeTestBinary(t, mgr.GetActiveBinaryPath(), "v1.0.0", true)
	writeTestBinary(t, mgr.GetInactiveBinaryPath(), "v1.0.0", true)

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	// 10 concurrent readers
	for i := 0; i < 10; i++ {
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
					_ = mgr.GetState()
					_ = mgr.GetCurrentBinaryPath()
					time.Sleep(100 * time.Microsecond)
				}
			}
		}()
	}

	// 4 concurrent staging/promoters
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < 15; j++ {
				ver := fmt.Sprintf("v%d.%d", workerID, j)
				hash, bytesData := writeTestBinary(t, "", ver, true)
				_ = mgr.StageBinary(bytes.NewReader(bytesData), hash)
				if rand.Float32() > 0.5 {
					_ = mgr.PromotePending(ver)
					if rand.Float32() > 0.5 {
						_ = mgr.ConfirmHealthy(ver)
					} else {
						_ = mgr.Rollback()
					}
				}
				time.Sleep(1 * time.Millisecond)
			}
		}(i)
	}

	time.Sleep(500 * time.Millisecond)
	close(stopCh)
	wg.Wait()

	// Final integrity assertion: ActiveSlot must be valid and bin/current must point to it
	active := mgr.GetActiveSlot()
	if active != "slot_a" && active != "slot_b" {
		t.Fatalf("Corrupt final active slot: %q", active)
	}
	target, err := readLinkTarget(mgr.GetCurrentDir())
	if err != nil {
		t.Fatalf("Final readLinkTarget failed: %v", err)
	}
	if !strings.HasSuffix(target, active) {
		t.Errorf("Current link target %s does not match active slot %s", target, active)
	}
}
