package supervisor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SlotState tracks active and pending binary partitions for A/B staging.
type SlotState struct {
	ActiveSlot       string    `json:"active_slot"`        // "slot_a" or "slot_b"
	PendingSlot      string    `json:"pending_slot"`       // "" or slot awaiting verification
	PendingStartedAt time.Time `json:"pending_started_at"` // Timestamp when pending slot booted
	LastGoodVersion  string    `json:"last_good_version"`  // Last verified healthy version
	RollbackCount    int       `json:"rollback_count"`     // Monotonically increasing rollback count
}

// SlotManager manages A/B partition directories (bin/slot_a, bin/slot_b),
// active link (bin/current), and state persistence (bin/state.json).
type SlotManager struct {
	mu        sync.RWMutex
	baseDir   string
	binDir    string
	slotADir  string
	slotBDir  string
	current   string
	stateFile string
	state     SlotState
}

// InitSlots initializes the slot directories, state.json, and the current partition link.
func InitSlots(baseDir string) (*SlotManager, error) {
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("resolve base dir: %w", err)
	}

	binDir := filepath.Join(absBase, "bin")
	if filepath.Base(absBase) == "bin" {
		binDir = absBase
		absBase = filepath.Dir(binDir)
	} else if fi, err := os.Stat(filepath.Join(absBase, "slot_a")); err == nil && fi.IsDir() {
		binDir = absBase
		absBase = filepath.Dir(binDir)
	}

	slotADir := filepath.Join(binDir, "slot_a")
	slotBDir := filepath.Join(binDir, "slot_b")
	current := filepath.Join(binDir, "current")
	stateFile := filepath.Join(binDir, "state.json")

	if err := os.MkdirAll(slotADir, 0755); err != nil {
		return nil, fmt.Errorf("create slot_a: %w", err)
	}
	if err := os.MkdirAll(slotBDir, 0755); err != nil {
		return nil, fmt.Errorf("create slot_b: %w", err)
	}

	mgr := &SlotManager{
		baseDir:   absBase,
		binDir:    binDir,
		slotADir:  slotADir,
		slotBDir:  slotBDir,
		current:   current,
		stateFile: stateFile,
	}

	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	if err := mgr.loadOrRecoverStateLocked(); err != nil {
		return nil, fmt.Errorf("load or recover state: %w", err)
	}

	return mgr, nil
}

// loadOrRecoverStateLocked loads state.json or reconstructs state if missing or corrupted.
func (s *SlotManager) loadOrRecoverStateLocked() error {
	data, err := os.ReadFile(s.stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return s.recoverStateFromLinkLocked()
		}
		return fmt.Errorf("read state file: %w", err)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return s.recoverStateFromLinkLocked()
	}

	var state SlotState
	if err := json.Unmarshal(trimmed, &state); err != nil {
		return s.recoverStateFromLinkLocked()
	}

	if state.ActiveSlot != "slot_a" && state.ActiveSlot != "slot_b" {
		return s.recoverStateFromLinkLocked()
	}

	s.state = state

	// Ensure bin/current exists and points to appropriate target
	targetSlot := s.state.ActiveSlot
	if s.state.PendingSlot != "" {
		targetSlot = s.state.PendingSlot
	}
	expectedTarget := s.slotADir
	if targetSlot == "slot_b" {
		expectedTarget = s.slotBDir
	}

	if _, err := os.Lstat(s.current); os.IsNotExist(err) {
		if err := createOrUpdateLink(s.current, expectedTarget); err != nil {
			return fmt.Errorf("initialize current link: %w", err)
		}
	}

	return nil
}

// recoverStateFromLinkLocked recovers active slot state from filesystem link target.
func (s *SlotManager) recoverStateFromLinkLocked() error {
	activeSlot := "slot_a"
	if target, err := readLinkTarget(s.current); err == nil {
		base := filepath.Base(target)
		if strings.EqualFold(base, "slot_b") {
			activeSlot = "slot_b"
		}
	}

	s.state = SlotState{
		ActiveSlot:       activeSlot,
		PendingSlot:      "",
		PendingStartedAt: time.Time{},
		LastGoodVersion:  "",
		RollbackCount:    0,
	}

	targetDir := s.slotADir
	if activeSlot == "slot_b" {
		targetDir = s.slotBDir
	}

	if err := createOrUpdateLink(s.current, targetDir); err != nil {
		return fmt.Errorf("ensure current link points to %s: %w", targetDir, err)
	}

	return s.saveStateLocked()
}

// saveStateLocked atomically saves the current state to state.json.
func (s *SlotManager) saveStateLocked() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal slot state: %w", err)
	}

	tmpFile := filepath.Join(s.binDir, fmt.Sprintf(".state.json.tmp.%d", time.Now().UnixNano()))
	f, err := os.OpenFile(tmpFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpFile)
		return fmt.Errorf("write temp state file: %w", err)
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpFile)
		return fmt.Errorf("sync temp state file: %w", err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("close temp state file: %w", err)
	}

	if err := replaceFileAtomic(tmpFile, s.stateFile); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("replace state file atomically: %w", err)
	}

	return nil
}

// GetActiveSlot returns the active slot identifier ("slot_a" or "slot_b").
func (s *SlotManager) GetActiveSlot() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.ActiveSlot
}

// GetInactiveSlot returns the inactive slot identifier ("slot_b" if active is "slot_a").
func (s *SlotManager) GetInactiveSlot() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getInactiveSlotLocked()
}

func (s *SlotManager) getInactiveSlotLocked() string {
	if s.state.ActiveSlot == "slot_a" {
		return "slot_b"
	}
	return "slot_a"
}

// GetActiveSlotDir returns the absolute path to the active slot directory.
func (s *SlotManager) GetActiveSlotDir() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getActiveSlotDirLocked()
}

func (s *SlotManager) getActiveSlotDirLocked() string {
	if s.state.ActiveSlot == "slot_a" {
		return s.slotADir
	}
	return s.slotBDir
}

// GetInactiveSlotDir returns the absolute path to the inactive slot directory.
func (s *SlotManager) GetInactiveSlotDir() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getInactiveSlotDirLocked()
}

func (s *SlotManager) getInactiveSlotDirLocked() string {
	if s.state.ActiveSlot == "slot_a" {
		return s.slotBDir
	}
	return s.slotADir
}

// GetCurrentDir returns the path to the bin/current partition link.
func (s *SlotManager) GetCurrentDir() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// GetActiveBinaryPath returns the path to the binary in the active slot.
func (s *SlotManager) GetActiveBinaryPath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return filepath.Join(s.getActiveSlotDirLocked(), BinaryExecutableName)
}

// GetInactiveBinaryPath returns the path to the binary in the inactive slot.
func (s *SlotManager) GetInactiveBinaryPath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return filepath.Join(s.getInactiveSlotDirLocked(), BinaryExecutableName)
}

// GetCurrentBinaryPath returns the path to the binary accessed through the bin/current link.
func (s *SlotManager) GetCurrentBinaryPath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return filepath.Join(s.current, BinaryExecutableName)
}

// GetState returns a snapshot copy of the current slot state.
func (s *SlotManager) GetState() SlotState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// PromotePending promotes the inactive slot candidate to pending status and flips bin/current.
// The active slot remains unchanged until ConfirmHealthy is called.
func (s *SlotManager) PromotePending(version string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	inactiveSlot := s.getInactiveSlotLocked()
	inactiveDir := s.getInactiveSlotDirLocked()
	inactiveBin := filepath.Join(inactiveDir, BinaryExecutableName)

	fi, err := os.Stat(inactiveBin)
	if err != nil {
		return fmt.Errorf("inactive candidate binary not found at %s: %w", inactiveBin, err)
	}
	if fi.IsDir() || fi.Size() == 0 {
		return fmt.Errorf("inactive candidate binary %s is invalid or empty", inactiveBin)
	}

	if err := ValidateBinaryFile(inactiveBin); err != nil {
		return fmt.Errorf("validate inactive binary header: %w", err)
	}

	if err := createOrUpdateLink(s.current, inactiveDir); err != nil {
		return fmt.Errorf("switch current link to %s: %w", inactiveDir, err)
	}

	s.state.PendingSlot = inactiveSlot
	s.state.PendingStartedAt = time.Now()
	// ActiveSlot remains unchanged!

	if err := s.saveStateLocked(); err != nil {
		return fmt.Errorf("save state after promotion: %w", err)
	}
	return nil
}

// ConfirmHealthy commits PendingSlot into ActiveSlot and clears pending fields.
// If PendingSlot is empty, it is an idempotent no-op.
func (s *SlotManager) ConfirmHealthy(version string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state.PendingSlot == "" {
		return nil
	}

	s.state.ActiveSlot = s.state.PendingSlot
	s.state.PendingSlot = ""
	s.state.PendingStartedAt = time.Time{}
	if version != "" {
		s.state.LastGoodVersion = version
	}

	return s.saveStateLocked()
}

// Rollback reverts bin/current link to ActiveSlot and increments RollbackCount.
// If PendingSlot is empty, it is an idempotent no-op.
func (s *SlotManager) Rollback() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.rollbackLocked()
}

func (s *SlotManager) rollbackLocked() error {
	if s.state.PendingSlot == "" {
		return nil
	}

	activeDir := s.getActiveSlotDirLocked()
	if err := createOrUpdateLink(s.current, activeDir); err != nil {
		return fmt.Errorf("revert current link to %s: %w", activeDir, err)
	}

	s.state.PendingSlot = ""
	s.state.PendingStartedAt = time.Time{}
	s.state.RollbackCount++

	return s.saveStateLocked()
}

// CheckRollbackCircuit checks whether a pending update has exceeded timeout.
// If timed out, it triggers Rollback() and returns (true, nil).
func (s *SlotManager) CheckRollbackCircuit(timeout time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state.PendingSlot == "" {
		return false, nil
	}

	effectiveTimeout := timeout
	if effectiveTimeout <= 0 {
		effectiveTimeout = 60 * time.Second
	}

	if !s.state.PendingStartedAt.IsZero() && time.Since(s.state.PendingStartedAt) >= effectiveTimeout {
		if err := s.rollbackLocked(); err != nil {
			return false, fmt.Errorf("rollback circuit trigger failed: %w", err)
		}
		return true, nil
	}

	return false, nil
}

// StageBinary streams an executable update payload into the inactive partition,
// verifying its SHA-256 checksum and binary header magic bytes, and setting 0755 permissions.
func (s *SlotManager) StageBinary(r io.Reader, expectedSHA256 string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	inactiveDir := s.getInactiveSlotDirLocked()
	inactiveBin := filepath.Join(inactiveDir, BinaryExecutableName)

	tmpFile, err := os.CreateTemp(inactiveDir, ".stage-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp staging file: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanedUp := false
	defer func() {
		if !cleanedUp {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	hasher := sha256.New()
	tee := io.TeeReader(r, hasher)

	// Read and validate binary header
	header := make([]byte, 4)
	n, err := io.ReadFull(tee, header)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("read binary header: %w", err)
	}
	if n < 2 {
		return fmt.Errorf("staged binary too small (%d bytes)", n)
	}
	if err := validateBinaryHeader(header[:n]); err != nil {
		return fmt.Errorf("validate binary header: %w", err)
	}

	// Write header bytes to temp file
	if _, err := tmpFile.Write(header[:n]); err != nil {
		return fmt.Errorf("write staged binary header: %w", err)
	}

	// Stream remaining binary content
	if _, err := io.Copy(tmpFile, tee); err != nil {
		return fmt.Errorf("stream staged binary: %w", err)
	}

	// Verify SHA-256 checksum if provided
	actualSHA256 := hex.EncodeToString(hasher.Sum(nil))
	if expectedSHA256 != "" && !strings.EqualFold(actualSHA256, expectedSHA256) {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedSHA256, actualSHA256)
	}

	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("sync staged binary: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close staged binary: %w", err)
	}

	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("chmod staged binary: %w", err)
	}

	if err := replaceFileAtomic(tmpPath, inactiveBin); err != nil {
		return fmt.Errorf("replace staged binary: %w", err)
	}

	cleanedUp = true
	return nil
}

// StageUpdate is a convenience helper accepting byte slice content.
func (s *SlotManager) StageUpdate(content []byte, expectedSHA256 string) error {
	return s.StageBinary(bytes.NewReader(content), expectedSHA256)
}

// SetPendingStartedAtForTest allows deterministic timing tests by adjusting PendingStartedAt.
func (s *SlotManager) SetPendingStartedAtForTest(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.PendingStartedAt = t
	return s.saveStateLocked()
}

// SetPendingForTest sets pending slot and timestamp directly for testing.
func (s *SlotManager) SetPendingForTest(slot string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.PendingSlot = slot
	s.state.PendingStartedAt = t
	return s.saveStateLocked()
}

// ValidateBinaryHeader validates binary header magic bytes for the current OS.
func ValidateBinaryHeader(header []byte) error {
	return validateBinaryHeader(header)
}

// ValidateBinaryFile opens a binary file and validates its header magic bytes.
func ValidateBinaryFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open binary file: %w", err)
	}
	defer f.Close()

	header := make([]byte, 4)
	n, err := io.ReadFull(f, header)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("read binary header: %w", err)
	}
	return validateBinaryHeader(header[:n])
}

// ValidateBinary is an alias for ValidateBinaryFile matching the SlotManager interface.
func ValidateBinary(path string) error {
	return ValidateBinaryFile(path)
}

// ValidateBinary validates binary file at path on SlotManager instance.
func (s *SlotManager) ValidateBinary(path string) error {
	return ValidateBinaryFile(path)
}

// ValidateBinaryFile validates binary file at path on SlotManager instance.
func (s *SlotManager) ValidateBinaryFile(path string) error {
	return ValidateBinaryFile(path)
}

// ValidateBinaryHeader validates header bytes on SlotManager instance.
func (s *SlotManager) ValidateBinaryHeader(header []byte) error {
	return validateBinaryHeader(header)
}
