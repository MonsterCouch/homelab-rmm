//go:build windows

package agent

import (
	"context"
	"os"
	"path/filepath"
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

// The logged-in-users fallback exists for builds without the Terminal
// Services stack - and query.exe is part of that same stack, so Home
// editions ship none. Launching it by name there only produces "is not
// recognized" while the real WTS error goes unreported, so the tool is
// probed in System32 first and PATH is never consulted.
func TestQueryUserExe(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SystemRoot", dir)
	if got := queryUserExe(); got != "" {
		t.Fatalf("query.exe is absent but resolved to %q", got)
	}
	want := filepath.Join(dir, "System32", "query.exe")
	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(want, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := queryUserExe(); got != want {
		t.Fatalf("queryUserExe = %q want %q", got, want)
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

func TestWinCodePages(t *testing.T) {
	// The two constants are Windows' CP_ACP and CP_OEMCP. Swapping them
	// would not fail anything loudly, it would only mangle non-ASCII
	// output, so pin the values.
	if cpACP != 0 || cpOEM != 1 {
		t.Fatalf("code pages drifted: cpACP=%d cpOEM=%d", cpACP, cpOEM)
	}
}

func TestWinDecodeOutput(t *testing.T) {
	// valid UTF-8 (pwsh 7, winget, ASCII tools) passes through untouched,
	// whichever code page the capture names
	for _, cp := range []uint32{cpACP, cpOEM} {
		for _, s := range []string{"", "plain ascii\r\n", "déjà vu — ok"} {
			if got := winDecodeOutput([]byte(s), cp); got != s {
				t.Errorf("utf-8 %q mangled to %q (cp %d)", s, got, cp)
			}
		}
	}
	// a lone high byte is not UTF-8: it is decoded from the named code page
	// and never surfaces as U+FFFD
	for _, cp := range []uint32{cpACP, cpOEM} {
		got := winDecodeOutput([]byte{'a', 0x82, 'b'}, cp)
		if got == "" || strings.ContainsRune(got, '\ufffd') {
			t.Errorf("high byte decoded to %q (cp %d)", got, cp)
		}
	}
	// The exact letters only hold on a Western install, where ACP is 1252
	// and OEM is 437/850. There 0x82 is U+201A in ANSI and "é" in OEM: the
	// same byte, two different characters, which is the whole of evt-01 -
	// wevtutil writes ANSI when redirected and used to be read as OEM.
	if acp := windows.GetACP(); acp != 1252 {
		t.Logf("ACP is %d, not 1252: skipping the exact-letter check", acp)
		return
	}
	if got := winDecodeOutput([]byte{0x82}, cpACP); got != "\u201a" {
		t.Errorf("ANSI 0x82 = %q, want U+201A", got)
	}
	if got := winDecodeOutput([]byte{0x82}, cpOEM); got != "é" {
		t.Errorf("OEM 0x82 = %q, want é", got)
	}
}

// The code page is a property of the capture: an outputBuffer decodes what it
// collected once, at String time, with the code page the runner gave it.
func TestOutputBufferDecodesWithItsCodePage(t *testing.T) {
	acp := &outputBuffer{limit: 64, cp: cpACP}
	oem := &outputBuffer{limit: 64, cp: cpOEM}
	for _, b := range []*outputBuffer{acp, oem} {
		if n, err := b.Write([]byte{0x82}); n != 1 || err != nil {
			t.Fatalf("write = %d %v", n, err)
		}
	}
	if windows.GetACP() != 1252 {
		return // the two code pages need not differ on this byte elsewhere
	}
	if acp.String() == oem.String() {
		t.Errorf("both buffers decoded to %q: cp is not reaching winDecodeOutput", acp.String())
	}
}

// A runaway tool is truncated, never killed by a short write, and says so.
func TestOutputBufferTruncates(t *testing.T) {
	b := &outputBuffer{limit: 4, cp: cpOEM}
	for _, chunk := range []string{"ab", "cdef", "gh"} {
		if n, err := b.Write([]byte(chunk)); n != len(chunk) || err != nil {
			t.Fatalf("write %q = %d %v (a short write kills the child)", chunk, n, err)
		}
	}
	got := b.String()
	if !strings.HasPrefix(got, "abcd") || !strings.Contains(got, "[output truncated]") {
		t.Errorf("truncated capture = %q", got)
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
