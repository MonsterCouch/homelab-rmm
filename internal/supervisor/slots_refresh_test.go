package supervisor

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSlotRefresh_StaleSlotIsReplaced(t *testing.T) {
	base := t.TempDir()
	mgr, err := InitSlots(base)
	if err != nil {
		t.Fatal(err)
	}
	slotBin := filepath.Join(mgr.GetActiveSlotDir(), BinaryExecutableName)
	writeTestBinary(t, slotBin, "old", true)
	_, newPayload := writeTestBinary(t, filepath.Join(t.TempDir(), "rmm-agent"), "new", true)
	src := filepath.Join(t.TempDir(), "rmm-agent")
	if err := os.WriteFile(src, newPayload, 0644); err != nil {
		t.Fatal(err)
	}

	changed, err := mgr.RefreshActiveFromFile(src, "v9.9.9")
	if err != nil || !changed {
		t.Fatalf("RefreshActiveFromFile = %v, %v; want true, nil", changed, err)
	}
	got, err := os.ReadFile(slotBin)
	if err != nil || !bytes.Equal(got, newPayload) {
		t.Fatalf("slot binary not replaced (err %v)", err)
	}
	// Supervisor spawns through bin/current; it must resolve to the new bytes.
	viaCurrent, err := os.ReadFile(mgr.GetCurrentBinaryPath())
	if err != nil || !bytes.Equal(viaCurrent, newPayload) {
		t.Fatalf("bin/current does not serve the refreshed binary (err %v)", err)
	}
	if fi, _ := os.Stat(slotBin); fi != nil && filepath.Separator == '/' && fi.Mode().Perm() != 0755 {
		t.Errorf("mode = %v, want 0755", fi.Mode().Perm())
	}
	leftovers, _ := filepath.Glob(filepath.Join(mgr.GetActiveSlotDir(), ".refresh-*"))
	if len(leftovers) != 0 {
		t.Errorf("temp files left behind: %v", leftovers)
	}

	st := mgr.GetState()
	if st.ActiveSlot != "slot_a" || st.PendingSlot != "" || st.RollbackCount != 0 || st.LastGoodVersion != "v9.9.9" {
		t.Errorf("unexpected state %+v", st)
	}
	re, err := InitSlots(base) // state.json must reload to the same thing
	if err != nil {
		t.Fatal(err)
	}
	if re.GetState().LastGoodVersion != "v9.9.9" || re.GetActiveSlot() != "slot_a" {
		t.Errorf("reloaded state %+v", re.GetState())
	}
}

func TestSlotRefresh_IdenticalBinaryChangesNothing(t *testing.T) {
	mgr, err := InitSlots(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	slotBin := filepath.Join(mgr.GetActiveSlotDir(), BinaryExecutableName)
	_, payload := writeTestBinary(t, slotBin, "same", true)
	src := filepath.Join(t.TempDir(), "rmm-agent")
	if err := os.WriteFile(src, payload, 0644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(slotBin)
	stateBefore, _ := os.ReadFile(filepath.Join(mgr.binDir, "state.json"))

	changed, err := mgr.RefreshActiveFromFile(src, "v1")
	if err != nil || changed {
		t.Fatalf("RefreshActiveFromFile = %v, %v; want false, nil", changed, err)
	}
	after, _ := os.Stat(slotBin)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("identical binary was rewritten")
	}
	stateAfter, _ := os.ReadFile(filepath.Join(mgr.binDir, "state.json"))
	if !bytes.Equal(stateBefore, stateAfter) {
		t.Error("state.json changed for an identical binary")
	}
}

func TestSlotRefresh_RefusedWhilePending(t *testing.T) {
	mgr, err := InitSlots(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestBinary(t, filepath.Join(mgr.GetActiveSlotDir(), BinaryExecutableName), "old", true)
	writeTestBinary(t, filepath.Join(mgr.GetInactiveSlotDir(), BinaryExecutableName), "cand", true)
	if err := mgr.PromotePending("cand"); err != nil {
		t.Fatal(err)
	}
	_, payload := writeTestBinary(t, "", "new", true)
	src := filepath.Join(t.TempDir(), "rmm-agent")
	if err := os.WriteFile(src, payload, 0644); err != nil {
		t.Fatal(err)
	}
	before := mgr.GetState()
	changed, err := mgr.RefreshActiveFromFile(src, "")
	if changed || !errors.Is(err, ErrUpdatePending) {
		t.Fatalf("RefreshActiveFromFile = %v, %v; want false, ErrUpdatePending", changed, err)
	}
	st := mgr.GetState()
	if st != before || st.PendingSlot == "" {
		t.Errorf("state changed by refused refresh: before %+v after %+v", before, st)
	}
	got, _ := os.ReadFile(filepath.Join(mgr.GetActiveSlotDir(), BinaryExecutableName))
	if bytes.Equal(got, payload) {
		t.Error("active slot binary was replaced despite pending update")
	}
}

func TestSlotRefresh_RejectsNonBinarySource(t *testing.T) {
	mgr, err := InitSlots(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	slotBin := filepath.Join(mgr.GetActiveSlotDir(), BinaryExecutableName)
	_, old := writeTestBinary(t, slotBin, "old", true)
	src := filepath.Join(t.TempDir(), "junk")
	if err := os.WriteFile(src, []byte("not an executable"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.RefreshActiveFromFile(src, ""); err == nil {
		t.Fatal("expected an error for a non-executable source")
	}
	got, _ := os.ReadFile(slotBin)
	if !bytes.Equal(got, old) {
		t.Error("slot binary modified despite rejected source")
	}
}
