// Package e2e_test provides requirement-driven, opaque-box end-to-end tests for
// Homelab RMM Phase 1 (Agent Resilience & Hardening).
//
// These tests verify:
//   - R1: Unified Agent Supervisor & Local IPC
//   - R2: Atomic A/B Slot Manager & 60-Second Rollback Circuit
//   - R3: Process Sandboxing & Resource Quotas
//   - R4: Real-Time Secret Redaction
//
// The test suite is organized into 4 verification tiers:
//   - Tier 1: Feature Coverage (>=5 test cases per feature for R1, R2, R3, R4)
//   - Tier 2: Boundary & Corner Cases
//   - Tier 3: Cross-Feature Interactions
//   - Tier 4: Real-World Scenarios
package e2e_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/agent"
)

// ============================================================================
// Authoritative Interface Contracts (from PROJECT.md & ORIGINAL_REQUEST.md)
// ============================================================================

// MessageType defines local IPC message action categories.
type MessageType string

const (
	MsgHeartbeat      MessageType = "heartbeat"
	MsgNotifyHealthy  MessageType = "notify_healthy"
	MsgRequestRestart MessageType = "request_restart"
	MsgGetInactive    MessageType = "get_inactive_slot"
	MsgInactiveResp   MessageType = "inactive_slot_resp"
)

// IPCMessage defines the wire format for Supervisor <-> Worker communication.
type IPCMessage struct {
	Type         MessageType `json:"type"`
	PID          int         `json:"pid,omitempty"`
	RSSBytes     uint64      `json:"rss_bytes,omitempty"`
	Version      string      `json:"version,omitempty"`
	Reason       string      `json:"reason,omitempty"`
	Slot         string      `json:"slot,omitempty"`
	Path         string      `json:"path,omitempty"`
	ActiveSlot   string      `json:"active_slot,omitempty"`
	InactiveSlot string      `json:"inactive_slot,omitempty"`
}

// SlotState tracks active and pending binary partitions for A/B staging.
type SlotState struct {
	ActiveSlot       string    `json:"active_slot"`        // "slot_a" or "slot_b"
	PendingSlot      string    `json:"pending_slot"`       // "" or slot awaiting verification
	PendingStartedAt time.Time `json:"pending_started_at"` // Timestamp when pending slot booted
	LastGoodVersion  string    `json:"last_good_version"`
	RollbackCount    int       `json:"rollback_count"`
}

// ScriptRunContract defines the resource sandboxed script execution contract.
type ScriptRunContract struct {
	RunID           string            `json:"run_id"`
	Language        string            `json:"language"`
	Body            string            `json:"body"`
	Args            []string          `json:"args,omitempty"`
	Env             map[string]string `json:"env,omitempty"`
	Timeout         int               `json:"timeout_sec"`
	RunAs           string            `json:"run_as,omitempty"`
	MaxMemoryMB     uint64            `json:"max_memory_mb,omitempty"`     // 0 = default 1024 MB
	CPULimitPercent uint32            `json:"cpu_limit_percent,omitempty"` // 0 = default 80%
}

// ============================================================================
// Canonical Secret Redactor Specification (Oracle / Authoritative Reference)
// ============================================================================

// RedactSecretsOracle delegates directly to production agent.RedactSecrets.
func RedactSecretsOracle(input string) string {
	return agent.RedactSecrets(input)
}

// StreamingRedactHarness buffers streaming writes until newlines and applies redaction
// using the production agent.StreamRedactor.
type StreamingRedactHarness struct {
	mu       sync.Mutex
	pending  []byte
	lines    []string
	redactor *agent.StreamRedactor
}

func NewStreamingRedactHarness() *StreamingRedactHarness {
	return &StreamingRedactHarness{
		pending:  make([]byte, 0, 4096),
		lines:    make([]string, 0),
		redactor: agent.NewStreamRedactor(),
	}
}

func (s *StreamingRedactHarness) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pending = append(s.pending, p...)
	for {
		i := bytes.IndexByte(s.pending, '\n')
		if i < 0 {
			break
		}
		rawLine := string(s.pending[:i])
		rawLine = strings.TrimSuffix(rawLine, "\r")

		cleanLine := s.redactor.RedactLine(rawLine)

		s.lines = append(s.lines, cleanLine)
		s.pending = s.pending[i+1:]
	}
	return len(p), nil
}

func (s *StreamingRedactHarness) FlushRemainder() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) > 0 {
		rawLine := strings.TrimSuffix(string(s.pending), "\r")
		s.lines = append(s.lines, s.redactor.RedactLine(rawLine))
		s.pending = s.pending[:0]
	}
	s.redactor.Reset()
}

func (s *StreamingRedactHarness) Lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]string, len(s.lines))
	copy(result, s.lines)
	return result
}

// ============================================================================
// A/B Partition Filesystem Harness
// ============================================================================

type TestSlotLayout struct {
	BaseDir   string
	BinDir    string
	SlotADir  string
	SlotBDir  string
	Current   string
	StateFile string
}

// SetupTestSlotLayout sets up the canonical directory structure:
// <BaseDir>/bin/
//
//	├── slot_a/
//	├── slot_b/
//	├── current -> slot_a
//	└── state.json
func SetupTestSlotLayout(t *testing.T) *TestSlotLayout {
	t.Helper()
	base := t.TempDir()
	binDir := filepath.Join(base, "bin")
	slotA := filepath.Join(binDir, "slot_a")
	slotB := filepath.Join(binDir, "slot_b")
	current := filepath.Join(binDir, "current")
	stateFile := filepath.Join(binDir, "state.json")

	if err := os.MkdirAll(slotA, 0755); err != nil {
		t.Fatalf("Failed to create slot_a: %v", err)
	}
	if err := os.MkdirAll(slotB, 0755); err != nil {
		t.Fatalf("Failed to create slot_b: %v", err)
	}

	// Create initial junction or symlink
	if err := createPartitionLink(current, slotA); err != nil {
		t.Fatalf("Failed to create initial partition link: %v", err)
	}

	// Initialize default state.json
	initialState := SlotState{
		ActiveSlot:       "slot_a",
		PendingSlot:      "",
		PendingStartedAt: time.Time{},
		LastGoodVersion:  "v1.0.0",
		RollbackCount:    0,
	}
	data, err := json.MarshalIndent(initialState, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal initial state: %v", err)
	}
	if err := os.WriteFile(stateFile, data, 0644); err != nil {
		t.Fatalf("Failed to write state.json: %v", err)
	}

	return &TestSlotLayout{
		BaseDir:   base,
		BinDir:    binDir,
		SlotADir:  slotA,
		SlotBDir:  slotB,
		Current:   current,
		StateFile: stateFile,
	}
}

// createPartitionLink creates an NTFS junction or symlink on Windows, or a symlink on Unix.
func createPartitionLink(linkPath, targetPath string) error {
	// Remove existing if present
	_ = os.Remove(linkPath)

	if runtime.GOOS == "windows" {
		// Prefer cmd /c mklink /J for junction (does not require admin elevation)
		cmd := exec.Command("cmd", "/c", "mklink", "/J", linkPath, targetPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			// Fallback to os.Symlink if junction fails
			if symErr := os.Symlink(targetPath, linkPath); symErr != nil {
				return fmt.Errorf("mklink /J failed (%s: %v) and os.Symlink failed: %w", string(output), err, symErr)
			}
		}
		return nil
	}
	return os.Symlink(targetPath, linkPath)
}

// SwitchPartitionLink atomically switches linkPath to targetPath.
func SwitchPartitionLink(linkPath, targetPath string) error {
	if runtime.GOOS == "windows" {
		// On Windows, remove junction directory and re-create pointing to new target
		_ = os.Remove(linkPath)
		cmd := exec.Command("cmd", "/c", "mklink", "/J", linkPath, targetPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			if symErr := os.Symlink(targetPath, linkPath); symErr != nil {
				return fmt.Errorf("junction switch failed (%s): %w", string(output), symErr)
			}
		}
		return nil
	}
	// On Unix, atomic rename symlink
	tmpLink := linkPath + ".tmp"
	_ = os.Remove(tmpLink)
	if err := os.Symlink(targetPath, tmpLink); err != nil {
		return err
	}
	return os.Rename(tmpLink, linkPath)
}

// WriteTestBinary writes a mock binary executable file with valid PE MZ or ELF magic bytes.
func WriteTestBinary(t *testing.T, filePath string, version string, isValid bool) string {
	t.Helper()
	var content []byte
	if isValid {
		if runtime.GOOS == "windows" {
			// PE binary header: MZ (0x4D, 0x5A)
			content = append([]byte{0x4D, 0x5A, 0x90, 0x00}, []byte("HomelabRMM-Binary-Payload-Version-"+version)...)
		} else {
			// ELF header: \x7fELF (0x7F, 0x45, 0x4C, 0x46)
			content = append([]byte{0x7F, 'E', 'L', 'F'}, []byte("HomelabRMM-Binary-Payload-Version-"+version)...)
		}
	} else {
		content = []byte("CORRUPTED-NON-EXECUTABLE-DATA-" + version)
	}

	if err := os.WriteFile(filePath, content, 0755); err != nil {
		t.Fatalf("Failed to write test binary %s: %v", filePath, err)
	}

	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}

// ValidateBinaryHeader checks magic bytes for PE MZ on Windows or ELF on Linux.
func ValidateBinaryHeader(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	header := make([]byte, 4)
	n, err := f.Read(header)
	if err != nil && err != io.EOF {
		return err
	}
	if n < 2 {
		return fmt.Errorf("file too short (%d bytes) for executable header", n)
	}

	if runtime.GOOS == "windows" {
		if header[0] != 0x4D || header[1] != 0x5A {
			return fmt.Errorf("invalid PE header: expected 0x4D5A (MZ), got 0x%02X%02X", header[0], header[1])
		}
		return nil
	}

	if n < 4 || header[0] != 0x7F || header[1] != 'E' || header[2] != 'L' || header[3] != 'F' {
		return fmt.Errorf("invalid ELF header: expected \\x7fELF, got %q", header)
	}
	return nil
}

// ============================================================================
// IPC Duplex Protocol Test Harness
// ============================================================================

// IPCServerHarness represents an active IPC test server simulating supervisor IPC.
type IPCServerHarness struct {
	listener net.Listener
	addr     string
	messages chan IPCMessage
	done     chan struct{}
}

func (s *IPCServerHarness) Addr() string {
	return s.addr
}

func (s *IPCServerHarness) NextMessage(timeout time.Duration) (*IPCMessage, error) {
	select {
	case msg := <-s.messages:
		return &msg, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout waiting for IPC message after %v", timeout)
	}
}

func (s *IPCServerHarness) Close() error {
	close(s.done)
	return s.listener.Close()
}

// StartTestIPCServer starts a local loopback TCP or named pipe/socket listener for IPC testing.
func StartTestIPCServer(t *testing.T) *IPCServerHarness {
	t.Helper()
	// Using loopback TCP for cross-platform IPC framing test
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to bind IPC test server: %v", err)
	}

	harness := &IPCServerHarness{
		listener: l,
		addr:     l.Addr().String(),
		messages: make(chan IPCMessage, 100),
		done:     make(chan struct{}),
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-harness.done:
					return
				default:
					return
				}
			}
			go harness.handleConn(conn)
		}
	}()

	return harness
}

func (s *IPCServerHarness) handleConn(conn net.Conn) {
	defer conn.Close()
	decoder := json.NewDecoder(conn)
	for {
		var msg IPCMessage
		if err := decoder.Decode(&msg); err != nil {
			return
		}
		s.messages <- msg
	}
}

// SendIPCMessage connects to an IPC server and sends a JSON message frame.
func SendIPCMessage(addr string, msg IPCMessage) error {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = conn.Write(data)
	return err
}
