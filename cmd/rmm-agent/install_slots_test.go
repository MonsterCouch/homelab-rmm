package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/supervisor"
)

func fakeExe(t *testing.T, dir, tag string) (string, []byte) {
	t.Helper()
	magic := []byte{0x7F, 'E', 'L', 'F'}
	if runtime.GOOS == "windows" {
		magic = []byte{'M', 'Z', 0x90, 0x00}
	}
	payload := append(magic, []byte("exe-"+tag)...)
	p := filepath.Join(dir, "rmm-agent-"+tag)
	if err := os.WriteFile(p, payload, 0755); err != nil {
		t.Fatal(err)
	}
	return p, payload
}

func TestInstallSeedsEmptySlotLayout(t *testing.T) {
	base := t.TempDir()
	exe, payload := fakeExe(t, t.TempDir(), "seed")
	mgr, err := ensureSlotsPopulatedFrom(base, exe)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(mgr.GetActiveSlotDir(), supervisor.BinaryExecutableName))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("empty slot not seeded (err %v)", err)
	}
}

func TestInstallRefreshesStaleSlotAndSkipsIdentical(t *testing.T) {
	base := t.TempDir()
	oldExe, _ := fakeExe(t, t.TempDir(), "old")
	if _, err := ensureSlotsPopulatedFrom(base, oldExe); err != nil {
		t.Fatal(err)
	}
	newExe, newPayload := fakeExe(t, t.TempDir(), "new")
	mgr, err := ensureSlotsPopulatedFrom(base, newExe)
	if err != nil {
		t.Fatal(err)
	}
	via, err := os.ReadFile(mgr.GetCurrentBinaryPath())
	if err != nil || !bytes.Equal(via, newPayload) {
		t.Fatalf("service path (bin/current) still stale (err %v)", err)
	}
	slotBin := filepath.Join(mgr.GetActiveSlotDir(), supervisor.BinaryExecutableName)
	before, _ := os.Stat(slotBin)
	if _, err := ensureSlotsPopulatedFrom(base, newExe); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(slotBin)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("identical reinstall rewrote the slot binary")
	}
}
