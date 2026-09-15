//go:build windows

package agent

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// These exercise the Windows-only pure helpers. They cannot run on the Linux
// build box, but `GOOS=windows go vet` type-checks them, which catches a
// signature drift against x/sys/windows the cross-compile would otherwise
// miss until it ran on a real device.

func TestWevtutilArgs(t *testing.T) {
	got := wevtutilArgs("System", 200, "*[System[(Level=1 or Level=2)]]")
	want := []string{"qe", "System", "/c:200", "/rd:true", "/f:RenderedXml", "/q:*[System[(Level=1 or Level=2)]]"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("with filter = %v", got)
	}
	got = wevtutilArgs("Application", 50, "")
	want = []string{"qe", "Application", "/c:50", "/rd:true", "/f:RenderedXml"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("no filter = %v", got)
	}
}

func TestPowershellArgs(t *testing.T) {
	got := powershellArgs(`C:\Temp\wua.ps1`, []string{"guid1", "guid2"})
	want := []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", `C:\Temp\wua.ps1`, "guid1", "guid2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("powershellArgs = %v", got)
	}
}

func TestClampPTYSize(t *testing.T) {
	if c, r := clampPTYSize(0, 0); c != 10 || r != 2 {
		t.Errorf("zero clamp = %d,%d", c, r)
	}
	if c, r := clampPTYSize(120, 30); c != 120 || r != 30 {
		t.Errorf("normal = %d,%d", c, r)
	}
	if c, r := clampPTYSize(5000, 5000); c != 1000 || r != 1000 {
		t.Errorf("huge clamp = %d,%d", c, r)
	}
}

func TestShellCommandLine(t *testing.T) {
	// powershell resolves to some interpreter with -NoLogo; cmd resolves to
	// cmd.exe; anything else is rejected.
	if cl, err := shellCommandLine("powershell"); err != nil || !strings.Contains(cl, "-NoLogo") {
		t.Errorf("powershell = %q %v", cl, err)
	}
	if cl, err := shellCommandLine("cmd"); err != nil || !strings.Contains(strings.ToLower(cl), "cmd.exe") {
		t.Errorf("cmd = %q %v", cl, err)
	}
	if _, err := shellCommandLine("bash"); err == nil {
		t.Error("bash should be rejected on Windows")
	}
}

func TestWinDecodeOutput(t *testing.T) {
	// valid UTF-8 (pwsh 7, winget, ASCII tools) passes through untouched
	for _, s := range []string{"", "plain ascii\r\n", "déjà vu — ok"} {
		if got := winDecodeOutput([]byte(s)); got != s {
			t.Errorf("utf-8 %q mangled to %q", s, got)
		}
	}
	// a lone high byte is not UTF-8: it is decoded from the OEM code page
	// and never surfaces as U+FFFD
	got := winDecodeOutput([]byte{'a', 0x82, 'b'})
	if strings.ContainsRune(got, '�') || len([]rune(got)) != 3 {
		t.Errorf("OEM byte decoded to %q", got)
	}
}

func TestDetachedDeadline(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	ctx, done := detachedDeadline(parent, time.Hour)
	defer done()
	cancel()
	if ctx.Err() != nil {
		t.Fatal("detached context must survive the parent's cancellation")
	}
	if d, ok := ctx.Deadline(); !ok || time.Until(d) > time.Hour || time.Until(d) < 59*time.Minute {
		t.Fatalf("fallback deadline wrong: %v %v", d, ok)
	}
	want := time.Now().Add(5 * time.Minute)
	parent2, cancel2 := context.WithDeadline(context.Background(), want)
	defer cancel2()
	ctx2, done2 := detachedDeadline(parent2, time.Hour)
	defer done2()
	if d, _ := ctx2.Deadline(); !d.Equal(want) {
		t.Fatalf("parent deadline not kept: %v want %v", d, want)
	}
}

func TestServiceAccessFor(t *testing.T) {
	if a, ok := serviceAccessFor("start"); !ok || a&windows.SERVICE_START == 0 {
		t.Errorf("start access = %#x ok=%v", a, ok)
	}
	if a, ok := serviceAccessFor("stop"); !ok || a&windows.SERVICE_STOP == 0 || a&windows.SERVICE_ENUMERATE_DEPENDENTS == 0 {
		t.Errorf("stop access = %#x ok=%v", a, ok)
	}
	if a, ok := serviceAccessFor("disable"); !ok || a&windows.SERVICE_CHANGE_CONFIG == 0 {
		t.Errorf("disable access = %#x ok=%v", a, ok)
	}
	if _, ok := serviceAccessFor("frobnicate"); ok {
		t.Error("unknown action should not be ok")
	}
}
