package svc

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type uinputCalls struct{ calls []string }

func setupUinput(t *testing.T, goos string) (*uinputCalls, string) {
	t.Helper()
	dir := t.TempDir()
	rec := &uinputCalls{}
	oldOS, oldDir, oldDev, oldRun := uinputGOOS, uinputRulesDir, uinputDevPath, uinputRunTool
	t.Cleanup(func() { uinputGOOS, uinputRulesDir, uinputDevPath, uinputRunTool = oldOS, oldDir, oldDev, oldRun })
	uinputGOOS = goos
	uinputRulesDir = filepath.Join(dir, "rules.d") // does not exist yet
	uinputDevPath = filepath.Join(dir, "uinput")
	if err := os.WriteFile(uinputDevPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	uinputRunTool = func(name string, args ...string) error {
		rec.calls = append(rec.calls, name+" "+strings.Join(args, " "))
		return nil
	}
	return rec, filepath.Join(uinputRulesDir, UinputRuleName)
}

func TestUinputRuleContent(t *testing.T) {
	const want = "KERNEL==\"uinput\", GROUP=\"input\", MODE=\"0660\", TAG+=\"uaccess\"\n"
	if UinputRule != want {
		t.Fatalf("rule = %q, want %q", UinputRule, want)
	}
}

func TestInstallUinputRuleWritesAndReloads(t *testing.T) {
	rec, path := setupUinput(t, "linux")
	if w := InstallUinputRule(); len(w) != 0 {
		t.Fatalf("warnings: %v", w)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != UinputRule {
		t.Fatalf("rule file = %q, %v", got, err)
	}
	want := []string{"udevadm control --reload-rules", "udevadm trigger --name-match=uinput"}
	if strings.Join(rec.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %v, want %v", rec.calls, want)
	}
	// Idempotent.
	if w := InstallUinputRule(); len(w) != 0 {
		t.Fatalf("second install warnings: %v", w)
	}
}

func TestInstallUinputRuleModprobesWhenDeviceMissing(t *testing.T) {
	rec, _ := setupUinput(t, "linux")
	os.Remove(uinputDevPath)
	InstallUinputRule()
	if len(rec.calls) != 3 || rec.calls[0] != "modprobe uinput" {
		t.Fatalf("calls = %v", rec.calls)
	}
}

func TestInstallUinputRuleWarnsNeverFails(t *testing.T) {
	_, path := setupUinput(t, "linux")
	uinputRunTool = func(name string, args ...string) error { return errors.New("boom") }
	w := InstallUinputRule()
	if len(w) != 2 || !strings.Contains(w[0], "boom") || !strings.Contains(w[0], "udevadm trigger --name-match=uinput") {
		t.Fatalf("warnings = %v", w)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("rule file should still be written:", err)
	}
	// Unwritable rules dir: a warning, no tool calls.
	rec2, _ := setupUinput(t, "linux")
	if err := os.WriteFile(uinputRulesDir, nil, 0o644); err != nil { // a file where the dir should be
		t.Fatal(err)
	}
	if w := InstallUinputRule(); len(w) != 1 || len(rec2.calls) != 0 {
		t.Fatalf("warnings = %v, calls = %v", w, rec2.calls)
	}
}

func TestRemoveUinputRule(t *testing.T) {
	rec, path := setupUinput(t, "linux")
	if w := RemoveUinputRule(); len(w) != 0 || len(rec.calls) != 0 {
		t.Fatalf("absent file: warnings %v calls %v", w, rec.calls)
	}
	InstallUinputRule()
	rec.calls = nil
	if w := RemoveUinputRule(); len(w) != 0 {
		t.Fatalf("warnings: %v", w)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rule file still present: %v", err)
	}
	if len(rec.calls) != 1 || rec.calls[0] != "udevadm control --reload-rules" {
		t.Fatalf("calls = %v", rec.calls)
	}
}

func TestUinputRuleSkippedOffLinux(t *testing.T) {
	rec, path := setupUinput(t, "windows")
	if w := InstallUinputRule(); w != nil {
		t.Fatal(w)
	}
	if w := RemoveUinputRule(); w != nil {
		t.Fatal(w)
	}
	if _, err := os.Stat(path); err == nil || len(rec.calls) != 0 {
		t.Fatal("nothing should run off Linux")
	}
}
