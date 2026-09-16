//go:build windows

package agent

import (
	"context"
	"reflect"
	"slices"
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
	got := wevtutilArgs("System", 200, "*[System[(Level=1 or Level=2)]]", wevtFormatRendered)
	want := []string{"qe", "System", "/c:200", "/rd:true", "/f:RenderedXml", "/uni:true", "/q:*[System[(Level=1 or Level=2)]]"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("with filter = %v", got)
	}
	got = wevtutilArgs("Application", 50, "", wevtFormatRaw)
	want = []string{"qe", "Application", "/c:50", "/rd:true", "/f:XML", "/uni:true"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("no filter = %v", got)
	}
	// evt-01: without /uni:true wevtutil writes the console code page and
	// every character it cannot hold is "?" before the agent reads a byte.
	for _, format := range []string{wevtFormatRendered, wevtFormatRaw} {
		if !slices.Contains(wevtutilArgs("System", 1, "", format), "/uni:true") {
			t.Errorf("%s query must ask for Unicode output", format)
		}
	}
}

// evt-03: the search window is a property of the query, not of the page size
// the operator happens to have selected - a match must not disappear because
// the limit dropdown moved from 50 to 20.
func TestWinEventLogFetchIsIndependentOfLimit(t *testing.T) {
	for _, limit := range []int{1, 20, 50, 1000} {
		if got := winEventLogFetch(limit, "boot"); got != eventLogSearchWindow {
			t.Errorf("search window at limit %d = %d, want %d", limit, got, eventLogSearchWindow)
		}
		if got := winEventLogFetch(limit, "  "); got != limit {
			t.Errorf("no search at limit %d fetched %d", limit, got)
		}
	}
	// A page bigger than the window still reads the whole page.
	if got := winEventLogFetch(eventLogMaxLimit+1000, "boot"); got != eventLogMaxLimit+1000 {
		t.Errorf("oversized page = %d", got)
	}
}

// evt-07: the caps are a documented contract, and the same request must not
// read five times more of the log on Windows than on Linux.
func TestWinEventLogLimit(t *testing.T) {
	if eventLogDefaultLimit != 200 || eventLogMaxLimit != 5000 {
		t.Fatalf("the documented caps drifted: default=%d max=%d", eventLogDefaultLimit, eventLogMaxLimit)
	}
	if got := winEventLogLimit(0); got != eventLogDefaultLimit {
		t.Errorf("unset limit = %d", got)
	}
	if got := winEventLogLimit(-5); got != eventLogDefaultLimit {
		t.Errorf("negative limit = %d", got)
	}
	if got := winEventLogLimit(100_000); got != eventLogMaxLimit {
		t.Errorf("huge limit = %d", got)
	}
	if got := winEventLogLimit(37); got != 37 {
		t.Errorf("ordinary limit = %d", got)
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

// evt-01: a capture marked cpUTF16LE is decoded as UTF-16, whatever the
// system code page is. The branch has to come before the UTF-8 shortcut,
// because an ASCII-only UTF-16 buffer is valid UTF-8 made of NUL-separated
// letters.
func TestWinDecodeOutputUTF16(t *testing.T) {
	if cpUTF16LE <= 65535 {
		t.Fatalf("cpUTF16LE = %d collides with a real Windows code page", cpUTF16LE)
	}
	const text = "<Event>Ω-日本語-Привет-✓</Event>"
	raw := utf16Bytes(utf16BOM + text)
	if got := winDecodeOutput(raw, cpUTF16LE); got != text {
		t.Errorf("utf-16 capture = %q", got)
	}
	if got := winDecodeOutput(utf16Bytes("plain ascii\r\n"), cpUTF16LE); got != "plain ascii\r\n" {
		t.Errorf("ascii utf-16 capture = %q", got)
	}
	b := &outputBuffer{limit: 1 << 20, cp: cpUTF16LE}
	if _, err := b.Write(raw); err != nil {
		t.Fatal(err)
	}
	if got := b.String(); got != text {
		t.Errorf("buffer = %q", got)
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
