package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/agent"
)

// TestChallenger_SpecArgsDefaultAndNonDefault verifies spec().Args is ["supervisor"]
// by default and appends --config-dir when non-default.
func TestChallenger_SpecArgsDefaultAndNonDefault(t *testing.T) {
	t.Setenv(agent.EnvConfigDir, "")
	s := spec()
	if len(s.Args) != 1 || s.Args[0] != "supervisor" {
		t.Fatalf("default spec().Args = %v, want [\"supervisor\"]", s.Args)
	}

	customDir := filepath.Join(t.TempDir(), "custom-conf")
	t.Setenv(agent.EnvConfigDir, customDir)
	sCustom := spec()
	if len(sCustom.Args) != 3 || sCustom.Args[0] != "supervisor" || sCustom.Args[1] != "--config-dir" || sCustom.Args[2] != customDir {
		t.Fatalf("custom spec().Args = %v, want [\"supervisor\", \"--config-dir\", %q]", sCustom.Args, customDir)
	}
}

// TestChallenger_CLIRouting_ExhaustiveMatrix tests every combination of CLI arguments
// across interactive and non-interactive (service manager) modes.
func TestChallenger_CLIRouting_ExhaustiveMatrix(t *testing.T) {
	// 1. Interactive with no args -> MUST return errUsage (which leads to exit code 2)
	cmd, _, err := parseAndRoute([]string{}, true)
	if !errors.Is(err, errUsage) {
		t.Fatalf("interactive no args: got cmd=%q, err=%v, want errUsage", cmd, err)
	}

	cmd, _, err = parseAndRoute(nil, true)
	if !errors.Is(err, errUsage) {
		t.Fatalf("interactive nil args: got cmd=%q, err=%v, want errUsage", cmd, err)
	}

	// 2. Non-interactive (service manager) with no args -> MUST default to "supervisor"
	cmd, args, err := parseAndRoute([]string{}, false)
	if err != nil || cmd != "supervisor" || len(args) != 0 {
		t.Fatalf("non-interactive no args: got (%q, %v, %v), want (\"supervisor\", nil, nil)", cmd, args, err)
	}

	cmd, args, err = parseAndRoute(nil, false)
	if err != nil || cmd != "supervisor" || len(args) != 0 {
		t.Fatalf("non-interactive nil args: got (%q, %v, %v), want (\"supervisor\", nil, nil)", cmd, args, err)
	}

	// 3. Subcommand "supervisor" routing
	subArgs := []string{"--base-dir", "C:\\temp\\rmm", "--pipe-name", "\\\\.\\pipe\\test"}
	cmd, parsedArgs, err := parseAndRoute(append([]string{"supervisor"}, subArgs...), true)
	if err != nil || cmd != "supervisor" || len(parsedArgs) != len(subArgs) {
		t.Fatalf("interactive 'supervisor' routing failed: got (%q, %v, %v)", cmd, parsedArgs, err)
	}

	// 4. Subcommand "run" routing
	runArgs := []string{"--config-dir", "C:\\temp\\rmm\\conf"}
	cmd, parsedArgs, err = parseAndRoute(append([]string{"run"}, runArgs...), true)
	if err != nil || cmd != "run" || len(parsedArgs) != len(runArgs) {
		t.Fatalf("interactive 'run' routing failed: got (%q, %v, %v)", cmd, parsedArgs, err)
	}

	// 5. Non-interactive explicit "run" routing (backwards compatibility)
	cmd, parsedArgs, err = parseAndRoute(append([]string{"run"}, runArgs...), false)
	if err != nil || cmd != "run" || len(parsedArgs) != len(runArgs) {
		t.Fatalf("non-interactive 'run' routing failed: got (%q, %v, %v)", cmd, parsedArgs, err)
	}

	// 6. Non-interactive with service flags only (e.g. SCM ImagePath: "rmm-agent.exe --config-dir D:\c")
	cmd, parsedArgs, err = parseAndRoute(runArgs, false)
	if err != nil || cmd != "supervisor" || len(parsedArgs) != len(runArgs) {
		t.Fatalf("non-interactive service flags routing failed: got (%q, %v, %v), want supervisor", cmd, parsedArgs, err)
	}

	// 7. Interactive flags without subcommand: helpful hint for install
	_, _, err = parseAndRoute([]string{"--server", "https://rmm.lan:8443", "--token", "abc"}, true)
	if err == nil || !strings.Contains(err.Error(), "Did you mean 'rmm-agent install") {
		t.Fatalf("interactive --server without subcommand expected install hint, got: %v", err)
	}

	// 8. Interactive unknown command
	_, _, err = parseAndRoute([]string{"invalid-subcommand"}, true)
	if err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("interactive unknown command expected error, got: %v", err)
	}

	// 9. All standard lifecycle subcommands
	standardSubcommands := []string{"install", "uninstall", "start", "stop", "restart", "status", "desktop-helper"}
	for _, sub := range standardSubcommands {
		c, _, err := parseAndRoute([]string{sub}, true)
		if err != nil || c != sub {
			t.Errorf("parseAndRoute(%q) = (%q, %v), want %q", sub, c, err, sub)
		}
	}
}

// TestChallenger_EnsureSlotsPopulated_InitializesAndCopiesBinary verifies that
// ensureSlotsPopulated creates the A/B slot directory hierarchy, state.json,
// and ensures a binary exists in the active slot.
func TestChallenger_EnsureSlotsPopulated_Structure(t *testing.T) {
	baseDir := t.TempDir()

	mgr, err := ensureSlotsPopulated(baseDir)
	if err != nil {
		t.Fatalf("ensureSlotsPopulated failed: %v", err)
	}

	slotADir := mgr.GetActiveSlotDir()
	slotBDir := mgr.GetInactiveSlotDir()

	if _, err := os.Stat(slotADir); os.IsNotExist(err) {
		t.Errorf("active slot directory %s does not exist", slotADir)
	}
	if _, err := os.Stat(slotBDir); os.IsNotExist(err) {
		t.Errorf("inactive slot directory %s does not exist", slotBDir)
	}

	stateFile := filepath.Join(baseDir, "bin", "state.json")
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		t.Errorf("state.json was not created at %s", stateFile)
	}

	state := mgr.GetState()
	if state.ActiveSlot != "slot_a" {
		t.Errorf("expected initial active slot 'slot_a', got %q", state.ActiveSlot)
	}
	if state.PendingSlot != "" {
		t.Errorf("expected initial pending slot empty, got %q", state.PendingSlot)
	}

	// Re-calling ensureSlotsPopulated on an existing structure must be idempotent
	mgr2, err := ensureSlotsPopulated(baseDir)
	if err != nil {
		t.Fatalf("idempotent ensureSlotsPopulated failed: %v", err)
	}
	if mgr2.GetState().ActiveSlot != "slot_a" {
		t.Errorf("state altered on idempotent call")
	}
}
