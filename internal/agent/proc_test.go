package agent

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// TestSuperviseSandboxedCommandNilProcess verifies that superviseSandboxedCommand
// is completely safe on nil command pointers and unstarted commands across all platforms.
func TestSuperviseSandboxedCommandNilProcess(t *testing.T) {
	// 1. Nil command
	releaseNil := superviseSandboxedCommand(nil, 512, 50)
	if releaseNil == nil {
		t.Fatal("releaseNil must not be nil")
	}
	releaseNil()

	// 2. Unstarted command (cmd.Process is nil)
	cmd := exec.CommandContext(context.Background(), "echo", "hello")
	releaseUnstarted := superviseSandboxedCommand(cmd, 1024, 80)
	if releaseUnstarted == nil {
		t.Fatal("releaseUnstarted must not be nil")
	}
	releaseUnstarted()
	releaseUnstarted() // idempotent
}

// TestSuperviseCommandCompatibility confirms that the legacy superviseCommand
// function delegates cleanly and returns an idempotent release closure.
func TestSuperviseCommandCompatibility(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), "echo", "hello")
	release := superviseCommand(cmd)
	if release == nil {
		t.Fatal("superviseCommand release must not be nil")
	}
	release()
	release() // idempotent
}

// TestProtocolScriptRunQuotaDefaults verifies protocol constants and JSON serialization/deserialization.
func TestProtocolScriptRunQuotaDefaults(t *testing.T) {
	if protocol.DefaultScriptMaxMemoryMB != 1024 {
		t.Errorf("DefaultScriptMaxMemoryMB = %d, want 1024", protocol.DefaultScriptMaxMemoryMB)
	}
	if protocol.DefaultScriptCPULimitPercent != 80 {
		t.Errorf("DefaultScriptCPULimitPercent = %d, want 80", protocol.DefaultScriptCPULimitPercent)
	}

	// 1. Serialization with explicit quotas
	req := protocol.ScriptRun{
		RunID:           "test-run-1",
		Language:        "bash",
		Body:            "echo 1",
		MaxMemoryMB:     2048,
		CPULimitPercent: 50,
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var roundtrip protocol.ScriptRun
	if err := json.Unmarshal(b, &roundtrip); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if roundtrip.MaxMemoryMB != 2048 || roundtrip.CPULimitPercent != 50 {
		t.Errorf("roundtrip quotas = %d/%d, want 2048/50", roundtrip.MaxMemoryMB, roundtrip.CPULimitPercent)
	}

	// 2. Backward compatibility: zero values omitted from wire
	reqZero := protocol.ScriptRun{
		RunID:    "test-run-2",
		Language: "bash",
		Body:     "echo 2",
	}
	bZero, err := json.Marshal(reqZero)
	if err != nil {
		t.Fatalf("Marshal zero: %v", err)
	}
	sZero := string(bZero)
	if strings.Contains(sZero, "max_memory_mb") {
		t.Errorf("expected max_memory_mb omitted, got: %s", sZero)
	}
	if strings.Contains(sZero, "cpu_limit_percent") {
		t.Errorf("expected cpu_limit_percent omitted, got: %s", sZero)
	}
}
