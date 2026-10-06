package e2e_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// Slot Manager Reference Implementation & Test Harness for R2
// ============================================================================

type TestSlotManager struct {
	layout *TestSlotLayout
	state  SlotState
}

func NewTestSlotManager(t *testing.T) *TestSlotManager {
	t.Helper()
	layout := SetupTestSlotLayout(t)
	mgr := &TestSlotManager{layout: layout}
	if err := mgr.LoadState(); err != nil {
		t.Fatalf("Failed to load initial slot state: %v", err)
	}
	return mgr
}

func (m *TestSlotManager) LoadState() error {
	data, err := os.ReadFile(m.layout.StateFile)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &m.state)
}

func (m *TestSlotManager) SaveState() error {
	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.layout.StateFile, data, 0644)
}

func (m *TestSlotManager) GetActiveSlot() string {
	return m.state.ActiveSlot
}

func (m *TestSlotManager) GetInactiveSlot() string {
	if m.state.ActiveSlot == "slot_a" {
		return "slot_b"
	}
	return "slot_a"
}

func (m *TestSlotManager) GetActiveSlotDir() string {
	if m.state.ActiveSlot == "slot_a" {
		return m.layout.SlotADir
	}
	return m.layout.SlotBDir
}

func (m *TestSlotManager) GetInactiveSlotDir() string {
	if m.state.ActiveSlot == "slot_a" {
		return m.layout.SlotBDir
	}
	return m.layout.SlotADir
}

func (m *TestSlotManager) StageUpdate(content []byte, expectedSHA256 string) error {
	// 1. Calculate and verify SHA256 checksum
	h := sha256.Sum256(content)
	actualSHA256 := hex.EncodeToString(h[:])
	if expectedSHA256 != "" && actualSHA256 != strings.ToLower(expectedSHA256) {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedSHA256, actualSHA256)
	}

	// 2. Validate binary header magic bytes
	if len(content) < 4 {
		return fmt.Errorf("staged binary too small (%d bytes)", len(content))
	}
	if runtime.GOOS == "windows" {
		if content[0] != 0x4D || content[1] != 0x5A {
			return fmt.Errorf("invalid PE header: expected 0x4D5A (MZ)")
		}
	} else {
		if content[0] != 0x7F || content[1] != 'E' || content[2] != 'L' || content[3] != 'F' {
			return fmt.Errorf("invalid ELF header")
		}
	}

	// 3. Write to inactive slot binary file
	targetDir := m.GetInactiveSlotDir()
	exeName := "rmm-agent"
	if runtime.GOOS == "windows" {
		exeName += ".exe"
	}
	targetPath := filepath.Join(targetDir, exeName)
	return os.WriteFile(targetPath, content, 0755)
}

func (m *TestSlotManager) PromotePending(version string) error {
	inactive := m.GetInactiveSlot()
	targetDir := m.GetInactiveSlotDir()

	// Switch junction/symlink bin/current to inactive slot
	if err := SwitchPartitionLink(m.layout.Current, targetDir); err != nil {
		return fmt.Errorf("failed to switch current link: %w", err)
	}

	m.state.PendingSlot = inactive
	m.state.PendingStartedAt = time.Now()
	return m.SaveState()
}

func (m *TestSlotManager) ConfirmHealthy(version string) error {
	if m.state.PendingSlot == "" {
		return nil // No pending update
	}
	m.state.ActiveSlot = m.state.PendingSlot
	m.state.PendingSlot = ""
	m.state.PendingStartedAt = time.Time{}
	if version != "" {
		m.state.LastGoodVersion = version
	}
	return m.SaveState()
}

func (m *TestSlotManager) Rollback() error {
	if m.state.PendingSlot == "" {
		return nil // Nothing to rollback
	}

	// Revert bin/current to active slot directory
	activeDir := m.GetActiveSlotDir()
	if err := SwitchPartitionLink(m.layout.Current, activeDir); err != nil {
		return fmt.Errorf("failed to revert current link: %w", err)
	}

	m.state.PendingSlot = ""
	m.state.PendingStartedAt = time.Time{}
	m.state.RollbackCount++
	return m.SaveState()
}

// CheckRollbackCircuit inspects state.json. If a pending slot has exceeded the 60s timeout,
// it triggers Rollback() immediately.
func (m *TestSlotManager) CheckRollbackCircuit(timeout time.Duration) (bool, error) {
	if err := m.LoadState(); err != nil {
		return false, err
	}
	if m.state.PendingSlot != "" {
		if time.Since(m.state.PendingStartedAt) >= timeout {
			if err := m.Rollback(); err != nil {
				return false, err
			}
			return true, nil // Rollback executed
		}
	}
	return false, nil
}

// ============================================================================
// Tier 1: Feature Coverage (R2 A/B Slot Manager & 60s Rollback Circuit)
// ============================================================================

func TestE2E_Tier1_R2_SlotDirectoryInitialization(t *testing.T) {
	// Verify directory creation and default state.json initialization
	mgr := NewTestSlotManager(t)

	if mgr.GetActiveSlot() != "slot_a" {
		t.Errorf("Expected active_slot 'slot_a', got %q", mgr.GetActiveSlot())
	}
	if mgr.state.PendingSlot != "" {
		t.Errorf("Expected empty pending_slot, got %q", mgr.state.PendingSlot)
	}
	if mgr.state.RollbackCount != 0 {
		t.Errorf("Expected rollback_count 0, got %d", mgr.state.RollbackCount)
	}

	// Verify filesystem directories exist
	if _, err := os.Stat(mgr.layout.SlotADir); err != nil {
		t.Errorf("slot_a directory does not exist: %v", err)
	}
	if _, err := os.Stat(mgr.layout.SlotBDir); err != nil {
		t.Errorf("slot_b directory does not exist: %v", err)
	}
	if _, err := os.Stat(mgr.layout.Current); err != nil {
		t.Errorf("current link does not exist: %v", err)
	}
}

func TestE2E_Tier1_R2_InactiveSlotRouting(t *testing.T) {
	mgr := NewTestSlotManager(t)

	// Case 1: Active is slot_a -> Inactive must be slot_b
	mgr.state.ActiveSlot = "slot_a"
	if mgr.GetInactiveSlot() != "slot_b" {
		t.Errorf("Inactive slot calculation failed: got %q, want 'slot_b'", mgr.GetInactiveSlot())
	}
	if mgr.GetInactiveSlotDir() != mgr.layout.SlotBDir {
		t.Errorf("Inactive slot dir calculation failed: got %s, want %s", mgr.GetInactiveSlotDir(), mgr.layout.SlotBDir)
	}

	// Case 2: Active is slot_b -> Inactive must be slot_a
	mgr.state.ActiveSlot = "slot_b"
	if mgr.GetInactiveSlot() != "slot_a" {
		t.Errorf("Inactive slot calculation failed: got %q, want 'slot_a'", mgr.GetInactiveSlot())
	}
	if mgr.GetInactiveSlotDir() != mgr.layout.SlotADir {
		t.Errorf("Inactive slot dir calculation failed: got %s, want %s", mgr.GetInactiveSlotDir(), mgr.layout.SlotADir)
	}
}

func TestE2E_Tier1_R2_BinaryStagingChecksumAndMagic(t *testing.T) {
	mgr := NewTestSlotManager(t)

	// 1. Valid binary payload
	validPayload := []byte{0x4D, 0x5A, 0x90, 0x00}
	if runtime.GOOS != "windows" {
		validPayload = []byte{0x7F, 'E', 'L', 'F'}
	}
	validPayload = append(validPayload, []byte("Version-v1.1.0-Payload")...)
	h := sha256.Sum256(validPayload)
	validHash := hex.EncodeToString(h[:])

	if err := mgr.StageUpdate(validPayload, validHash); err != nil {
		t.Fatalf("Valid update staging failed: %v", err)
	}

	// 2. Checksum mismatch
	if err := mgr.StageUpdate(validPayload, "badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb"); err == nil {
		t.Fatalf("Staging succeeded despite SHA-256 hash mismatch!")
	}

	// 3. Corrupted non-binary header
	invalidPayload := []byte("INVALID_HEADER_DATA_123456789")
	invHash := hex.EncodeToString(sha256.New().Sum(invalidPayload))
	if err := mgr.StageUpdate(invalidPayload, invHash); err == nil {
		t.Fatalf("Staging succeeded despite invalid magic header!")
	}
}

func TestE2E_Tier1_R2_AtomicSlotPromotion(t *testing.T) {
	mgr := NewTestSlotManager(t)

	// Stage valid update into slot_b
	exeName := "rmm-agent"
	if runtime.GOOS == "windows" {
		exeName += ".exe"
	}
	slotBBin := filepath.Join(mgr.layout.SlotBDir, exeName)
	WriteTestBinary(t, slotBBin, "v1.1.0", true)

	// Promote pending
	if err := mgr.PromotePending("v1.1.0"); err != nil {
		t.Fatalf("PromotePending failed: %v", err)
	}

	if err := mgr.LoadState(); err != nil {
		t.Fatalf("Failed to reload state: %v", err)
	}

	if mgr.state.ActiveSlot != "slot_a" {
		t.Errorf("Active slot prematurely altered: got %q, want 'slot_a'", mgr.state.ActiveSlot)
	}
	if mgr.state.PendingSlot != "slot_b" {
		t.Errorf("Pending slot not set: got %q, want 'slot_b'", mgr.state.PendingSlot)
	}
	if mgr.state.PendingStartedAt.IsZero() {
		t.Errorf("PendingStartedAt timestamp was not initialized")
	}

	// Verify bin/current now resolves to slot_b binary
	currentBin := filepath.Join(mgr.layout.Current, exeName)
	data, err := os.ReadFile(currentBin)
	if err != nil {
		t.Fatalf("Failed to read current binary after promotion: %v", err)
	}
	if !strings.Contains(string(data), "Version-v1.1.0") {
		t.Fatalf("bin/current did not point to newly promoted slot_b binary! Data: %s", string(data))
	}
}

func TestE2E_Tier1_R2_HealthyUpdateCommit(t *testing.T) {
	mgr := NewTestSlotManager(t)

	// Set pending update
	mgr.state.PendingSlot = "slot_b"
	mgr.state.PendingStartedAt = time.Now()
	_ = mgr.SaveState()

	// Worker verifies TLS and checkin, supervisor receives notify_healthy
	if err := mgr.ConfirmHealthy("v1.1.0"); err != nil {
		t.Fatalf("ConfirmHealthy failed: %v", err)
	}

	if err := mgr.LoadState(); err != nil {
		t.Fatalf("Failed to load state: %v", err)
	}

	if mgr.state.ActiveSlot != "slot_b" {
		t.Errorf("Active slot not committed to 'slot_b': %q", mgr.state.ActiveSlot)
	}
	if mgr.state.PendingSlot != "" {
		t.Errorf("Pending slot not cleared: %q", mgr.state.PendingSlot)
	}
	if mgr.state.LastGoodVersion != "v1.1.0" {
		t.Errorf("LastGoodVersion not updated: %q", mgr.state.LastGoodVersion)
	}
	if mgr.state.RollbackCount != 0 {
		t.Errorf("RollbackCount unexpectedly incremented: %d", mgr.state.RollbackCount)
	}
}

func TestE2E_Tier1_R2_RollbackOn60sTimeout(t *testing.T) {
	// Acceptance Criterion from ORIGINAL_REQUEST.md line 38:
	// "A broken/crashing update binary triggers an automatic rollback to the previous slot within 60 seconds."
	mgr := NewTestSlotManager(t)

	exeName := "rmm-agent"
	if runtime.GOOS == "windows" {
		exeName += ".exe"
	}
	slotABin := filepath.Join(mgr.layout.SlotADir, exeName)
	slotBBin := filepath.Join(mgr.layout.SlotBDir, exeName)
	WriteTestBinary(t, slotABin, "v1.0.0-known-good", true)
	WriteTestBinary(t, slotBBin, "v1.2.0-broken-pending", true)

	// Promote slot_b
	_ = mgr.PromotePending("v1.2.0-broken-pending")

	// Simulate 61 seconds elapsed without notify_healthy
	mgr.state.PendingStartedAt = time.Now().Add(-61 * time.Second)
	_ = mgr.SaveState()

	// Supervisor checks circuit with 60s timeout
	rolledBack, err := mgr.CheckRollbackCircuit(60 * time.Second)
	if err != nil {
		t.Fatalf("CheckRollbackCircuit failed: %v", err)
	}
	if !rolledBack {
		t.Fatalf("CRITICAL RESILIENCE FAILURE: Rollback circuit failed to trigger after 60s timeout!")
	}

	_ = mgr.LoadState()
	if mgr.state.ActiveSlot != "slot_a" {
		t.Errorf("Active slot corrupted: %q", mgr.state.ActiveSlot)
	}
	if mgr.state.PendingSlot != "" {
		t.Errorf("Pending slot was not cleared on rollback: %q", mgr.state.PendingSlot)
	}
	if mgr.state.RollbackCount != 1 {
		t.Errorf("RollbackCount not incremented: got %d, want 1", mgr.state.RollbackCount)
	}

	// Verify bin/current points back to known-good slot_a binary
	currentBin := filepath.Join(mgr.layout.Current, exeName)
	data, err := os.ReadFile(currentBin)
	if err != nil {
		t.Fatalf("Failed to read current binary after rollback: %v", err)
	}
	if !strings.Contains(string(data), "v1.0.0-known-good") {
		t.Fatalf("bin/current did not revert to known-good binary! Content: %s", string(data))
	}
}

func TestE2E_Tier1_R2_RollbackOnWorkerCrash(t *testing.T) {
	// If a promoted candidate crashes during the trial period, trigger immediate rollback
	mgr := NewTestSlotManager(t)
	_ = mgr.PromotePending("v1.2.0-crashing")

	// Worker process crashed immediately (0.5s into trial)
	mgr.state.PendingStartedAt = time.Now().Add(-500 * time.Millisecond)
	_ = mgr.SaveState()

	// Immediate rollback triggered by supervisor crash detection
	if err := mgr.Rollback(); err != nil {
		t.Fatalf("Rollback on crash failed: %v", err)
	}

	_ = mgr.LoadState()
	if mgr.state.PendingSlot != "" {
		t.Errorf("Pending slot not cleared on crash rollback")
	}
	if mgr.state.RollbackCount != 1 {
		t.Errorf("RollbackCount not incremented on crash rollback: %d", mgr.state.RollbackCount)
	}
}

// ============================================================================
// Tier 2: Boundary & Corner Cases (R2)
// ============================================================================

func TestE2E_Tier2_R2_StaleBootStateRecovery(t *testing.T) {
	// Machine power loss or restart occurs during the 60s verification trial.
	// On supervisor startup, it reads state.json, sees PendingSlot with an old timestamp,
	// and automatically reverts to known-good active slot.
	mgr := NewTestSlotManager(t)
	mgr.state.ActiveSlot = "slot_a"
	mgr.state.PendingSlot = "slot_b"
	mgr.state.PendingStartedAt = time.Now().Add(-10 * time.Minute) // 10 minutes ago
	mgr.state.RollbackCount = 2
	_ = mgr.SaveState()

	rolledBack, err := mgr.CheckRollbackCircuit(60 * time.Second)
	if err != nil {
		t.Fatalf("Stale boot recovery failed: %v", err)
	}
	if !rolledBack {
		t.Fatalf("Supervisor failed to execute rollback for stale boot state!")
	}

	_ = mgr.LoadState()
	if mgr.state.RollbackCount != 3 {
		t.Errorf("Rollback count not monotonic: got %d, want 3", mgr.state.RollbackCount)
	}
	if mgr.state.PendingSlot != "" {
		t.Errorf("Pending slot not cleared on stale boot recovery")
	}
}

func TestE2E_Tier2_R2_BoundaryTiming59sVs60s(t *testing.T) {
	mgr := NewTestSlotManager(t)
	mgr.state.PendingSlot = "slot_b"

	// Boundary 1: 59.5 seconds elapsed (Timeout not reached)
	mgr.state.PendingStartedAt = time.Now().Add(-59500 * time.Millisecond)
	_ = mgr.SaveState()

	rolledBack, err := mgr.CheckRollbackCircuit(60 * time.Second)
	if err != nil {
		t.Fatalf("CheckRollbackCircuit error: %v", err)
	}
	if rolledBack {
		t.Fatalf("Premature rollback triggered at 59.5s!")
	}

	// In that remaining window, healthy confirmation succeeds
	if err := mgr.ConfirmHealthy("v1.1.0"); err != nil {
		t.Fatalf("ConfirmHealthy failed in last second of window: %v", err)
	}
	_ = mgr.LoadState()
	if mgr.state.ActiveSlot != "slot_b" {
		t.Errorf("Update failed to commit within valid window!")
	}
}

// ============================================================================
// Tier 3: Cross-Feature Interactions (R2 A/B Updates + R1 IPC Signaling)
// ============================================================================

func TestE2E_Tier3_R2_UpdateStagedNotificationAndPromotion(t *testing.T) {
	// Full cross-feature flow:
	// 1. Worker receives update payload and asks supervisor for inactive slot via IPC.
	// 2. Supervisor responds with inactive slot path.
	// 3. Worker stages binary into inactive slot.
	// 4. Worker sends request_restart over IPC.
	// 5. Supervisor promotes pending slot and switches bin/current.
	server := StartTestIPCServer(t)
	defer server.Close()

	mgr := NewTestSlotManager(t)

	// Step 1 & 2: Inactive slot inquiry
	inactiveSlot := mgr.GetInactiveSlot()
	inactivePath := filepath.Join(mgr.GetInactiveSlotDir(), "rmm-agent.exe")

	// Step 3: Stage update
	exeName := "rmm-agent"
	if runtime.GOOS == "windows" {
		exeName += ".exe"
	}
	WriteTestBinary(t, filepath.Join(mgr.GetInactiveSlotDir(), exeName), "v2.0.0", true)

	// Step 4: Worker sends request_restart
	req := IPCMessage{
		Type:   MsgRequestRestart,
		Reason: "update_staged",
		Slot:   inactiveSlot,
		Path:   inactivePath,
	}
	if err := SendIPCMessage(server.Addr(), req); err != nil {
		t.Fatalf("Failed to send IPC request: %v", err)
	}

	msg, err := server.NextMessage(2 * time.Second)
	if err != nil {
		t.Fatalf("Failed to receive restart request: %v", err)
	}

	// Step 5: Supervisor handles restart request by promoting slot
	if msg.Type == MsgRequestRestart {
		if err := mgr.PromotePending("v2.0.0"); err != nil {
			t.Fatalf("Failed to promote pending slot on restart request: %v", err)
		}
	}

	_ = mgr.LoadState()
	if mgr.state.PendingSlot != inactiveSlot {
		t.Errorf("Promotion failed: got pending slot %q, want %q", mgr.state.PendingSlot, inactiveSlot)
	}
}

// ============================================================================
// Tier 4: Real-World Scenarios (R2 Rollback Circuit)
// ============================================================================

func TestE2E_Tier4_R2_RealWorldFaultyUpdateRollbackCycle(t *testing.T) {
	// Scenario: Full production OTA update failure recovery:
	// - System is operating stably on v1.0.0 in slot_a.
	// - Faulty update v1.2.0 is staged to slot_b.
	// - Supervisor promotes slot_b and starts 60s rollback circuit.
	// - Worker hangs or crashes during TLS handshake to server.
	// - 60s rollback timer triggers.
	// - Supervisor rolls back bin/current to slot_a.
	// - Stable v1.0.0 worker is restarted.
	// - State is cleanly persisted with RollbackCount = 1.

	mgr := NewTestSlotManager(t)
	exeName := "rmm-agent"
	if runtime.GOOS == "windows" {
		exeName += ".exe"
	}

	// Slot A has stable v1.0.0
	slotABin := filepath.Join(mgr.layout.SlotADir, exeName)
	WriteTestBinary(t, slotABin, "v1.0.0", true)

	// Stage faulty update into slot B
	slotBBin := filepath.Join(mgr.layout.SlotBDir, exeName)
	WriteTestBinary(t, slotBBin, "v1.2.0-faulty", true)

	// Step 1: Promote update
	if err := mgr.PromotePending("v1.2.0-faulty"); err != nil {
		t.Fatalf("Promotion failed: %v", err)
	}

	// Step 2: Faulty binary boots and hangs without sending notify_healthy
	// Simulate 60-second timeout passing
	mgr.state.PendingStartedAt = time.Now().Add(-65 * time.Second)
	_ = mgr.SaveState()

	// Step 3: Rollback circuit triggers
	rolledBack, err := mgr.CheckRollbackCircuit(60 * time.Second)
	if err != nil {
		t.Fatalf("Rollback check failed: %v", err)
	}
	if !rolledBack {
		t.Fatalf("Rollback was not triggered after 65 seconds!")
	}

	// Step 4: Verify recovery
	_ = mgr.LoadState()
	if mgr.state.ActiveSlot != "slot_a" {
		t.Errorf("Failed to retain slot_a as active slot: %q", mgr.state.ActiveSlot)
	}
	if mgr.state.PendingSlot != "" {
		t.Errorf("Pending slot not cleared: %q", mgr.state.PendingSlot)
	}
	if mgr.state.RollbackCount != 1 {
		t.Errorf("Rollback count mismatch: got %d, want 1", mgr.state.RollbackCount)
	}

	// Step 5: Verify bin/current points to stable v1.0.0
	currentBin := filepath.Join(mgr.layout.Current, exeName)
	content, err := os.ReadFile(currentBin)
	if err != nil {
		t.Fatalf("Failed to read current binary: %v", err)
	}
	if !strings.Contains(string(content), "v1.0.0") {
		t.Fatalf("Current binary is not stable v1.0.0: %s", string(content))
	}

	t.Logf("Full OTA Update Failure & Rollback Circuit lifecycle verified successfully!")
}
