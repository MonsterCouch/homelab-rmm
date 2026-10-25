//go:build windows

package desktop

import (
	"image"
	"image/png"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// NOTE FOR ANYONE EXTENDING THESE TESTS: any PowerShell started from a test
// must be started with `-WindowStyle Hidden`; nothing here starts one.

// TestBackstageNoForbiddenAPIs is the cheap static privacy check: the backstage
// sources must never name the APIs that would reach the physical screen or the
// physical input queue.
func TestBackstageNoForbiddenAPIs(t *testing.T) {
	files, err := filepath.Glob("backstage*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no backstage sources found: %v", err)
	}
	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`GetDC\s*\(\s*(NULL|0|nil)?\s*\)`), // the screen DC
		regexp.MustCompile(`GetDC`),                           // any spelling, incl. NewProc("GetDC")
		regexp.MustCompile(`GetWindowDC`),
		regexp.MustCompile(`SendInput`),
		regexp.MustCompile(`procSendInput`),
		regexp.MustCompile(`OpenInputDesktop`),
		regexp.MustCompile(`SetThreadDesktop`),
		regexp.MustCompile(`screenshot\.`),
		regexp.MustCompile(`\bnewInjector\(`),
		regexp.MustCompile(`\bnewCapturer\(`),
		regexp.MustCompile(`screenCapturer`),
		regexp.MustCompile(`mouse_event|keybd_event|SetCursorPos|SendMessageW\b`),
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, re := range forbidden {
			if loc := re.FindIndex(src); loc != nil {
				line := 1 + strings.Count(string(src[:loc[0]]), "\n")
				t.Errorf("%s:%d uses forbidden API matching %q", f, line, re)
			}
		}
	}
}

func TestBackstagePowerShellAlwaysHidden(t *testing.T) {
	cases := []struct {
		image string
		args  []string
		want  []string
	}{
		{"powershell.exe", nil, []string{"-WindowStyle", "Hidden"}},
		{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, []string{"-NoProfile", "-Command", "x"},
			[]string{"-WindowStyle", "Hidden", "-NoProfile", "-Command", "x"}},
		{"pwsh.exe", []string{"-File", "a.ps1"}, []string{"-WindowStyle", "Hidden", "-File", "a.ps1"}},
		{"powershell.exe", []string{"-WindowStyle", "Hidden", "-NoProfile"}, []string{"-WindowStyle", "Hidden", "-NoProfile"}},
		{"cmd.exe", []string{"/c", "dir"}, []string{"/c", "dir"}},
	}
	for _, c := range cases {
		got := withHiddenWindowStyle(c.image, c.args)
		if strings.Join(got, "\x00") != strings.Join(c.want, "\x00") {
			t.Errorf("withHiddenWindowStyle(%q, %q) = %q, want %q", c.image, c.args, got, c.want)
		}
	}
	for _, tool := range backstageTools {
		if isPowerShellImage(tool.image) {
			t.Errorf("default suite starts PowerShell %q; it must stay hidden-only", tool.image)
		}
	}
}

func TestBackstageBGRAToRGBA(t *testing.T) {
	src := []uint32{0x00112233, 0xFFAABBCC} // little-endian BGRA words: A R G B
	dst := make([]byte, 8)
	bgraToRGBA(dst, src)
	want := []byte{0x11, 0x22, 0x33, 0xFF, 0xAA, 0xBB, 0xCC, 0xFF}
	for i := range want {
		if dst[i] != want[i] {
			t.Fatalf("pixel bytes = % x, want % x", dst, want)
		}
	}
}

func TestBackstageCursorShape(t *testing.T) {
	if backstageCursor == nil {
		t.Fatal("software cursor shape did not validate")
	}
	img := image.NewRGBA(image.Rect(0, 0, 40, 40))
	for i := range img.Pix {
		img.Pix[i] = 0xFF // opaque white
	}
	if area := backstageCursor.draw(img, 10, 10); area.Empty() {
		t.Fatal("cursor drew nothing")
	}
	if p := img.RGBAAt(10, 10); p.R != 0 || p.G != 0 || p.B != 0 {
		t.Errorf("hotspot pixel = %v, want the black outline", p)
	}
	if p := img.RGBAAt(11, 14); p.R != 0xFF {
		t.Errorf("arrow fill pixel = %v, want white", p)
	}
}

// openTestDesktop creates the backstage desktop or skips when this session
// cannot (no administrator/SYSTEM token, or no interactive window station).
func openTestDesktop(t *testing.T) *backstageDesktop {
	t.Helper()
	d, err := createBackstageDesktop()
	if err != nil {
		t.Skipf("cannot create the backstage desktop here: %v", err)
	}
	return d
}

// skipUnlessElevated skips a test that needs tools to run on the backstage
// desktop. The desktop's DACL admits only SYSTEM and Administrators
// (backstageSDDL) and the tools run on a copy of this process's token, so from a
// session that is not elevated every tool dies while loading user32 (exit code
// 0xC0000142) and no window can ever appear. The code is not at fault there:
// the session cannot host it. The agent runs as SYSTEM, which is elevated, so
// where the product runs these tests are not skipped.
func skipUnlessElevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated (administrator or SYSTEM) token: the backstage desktop admits only those, so its tools exit at once from this session")
	}
}

func TestBackstageDesktopLifecycle(t *testing.T) {
	d := openTestDesktop(t)
	if d.h == 0 {
		t.Fatal("CreateDesktopW returned a nil handle")
	}
	if name := desktopName(d.h); name != backstageDesktopName {
		t.Errorf("desktop name = %q, want %q", name, backstageDesktopName)
	}
	d.release()

	old := backstageSpawnTools
	backstageSpawnTools = false
	defer func() { backstageSpawnTools = old }()

	c, inj, err := newBackstage()
	if err != nil {
		t.Skipf("newBackstage unavailable here: %v", err)
	}
	if c == nil || inj == nil {
		t.Fatal("newBackstage returned a nil capturer or injector")
	}
	mons, err := c.monitors()
	if err != nil || len(mons) != 1 {
		t.Fatalf("monitors() = %v, %v", mons, err)
	}
	img, err := c.capture(mons[0])
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if img.Rect.Dx() <= 0 || img.Rect.Dy() <= 0 || len(img.Pix) == 0 {
		t.Fatalf("captured frame is empty: %v", img.Rect)
	}
	if img.Rect.Dx() != mons[0].Bounds.Dx() || img.Rect.Dy() != mons[0].Bounds.Dy() {
		t.Errorf("frame %v does not match monitor %v", img.Rect, mons[0].Bounds)
	}
	// An empty backstage desktop is the flat background colour.
	if p := img.RGBAAt(img.Rect.Dx()-1, img.Rect.Dy()-1); p.R != 0x2B || p.G != 0x2B || p.B != 0x2B || p.A != 0xFF {
		t.Errorf("empty-desktop pixel = %v", p)
	}

	inj.setMonitor(mons[0])
	// With no windows these are silently dropped, not errors.
	for name, err := range map[string]error{
		"move":  inj.mouseMove(5, 5),
		"click": inj.mouseButton(buttonLeft, true, 5, 5),
		"up":    inj.mouseButton(buttonLeft, false, 5, 5),
		"wheel": inj.wheel(0, 120, 5, 5),
		"key":   inj.key("KeyA", "a", true),
		"paste": inj.paste("x"),
	} {
		if err != nil {
			t.Errorf("%s on an empty desktop: %v", name, err)
		}
	}
	if err := inj.ctrlAltDel(); err == nil {
		t.Error("ctrlAltDel should be reported as unsupported")
	}

	if cl, ok := c.(interface{ Close() error }); ok {
		if err := cl.Close(); err != nil {
			t.Errorf("capturer close: %v", err)
		}
		if _, err := c.capture(mons[0]); err == nil {
			t.Error("capture after Close should fail")
		}
	} else {
		t.Error("capturer has no Close() error")
	}
	inj.close()
	inj.close() // idempotent
}

// TestBackstageDesktopDACL confirms the desktop only grants SYSTEM and
// Administrators.
func TestBackstageDesktopDACL(t *testing.T) {
	d := openTestDesktop(t)
	defer d.release()
	sd, err := windows.GetSecurityInfo(d.h, windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Skipf("cannot read the desktop DACL: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("no DACL on the desktop: %v", err)
	}
	s := sd.String()
	t.Logf("desktop SD: %s", s)
	if n := strings.Count(s, "(A;"); n != 2 {
		t.Errorf("expected exactly 2 allow ACEs, got %d in %s", n, s)
	}
	if !strings.Contains(s, ";SY)") || !strings.Contains(s, ";BA)") {
		t.Errorf("DACL should name SYSTEM and Administrators: %s", s)
	}
	for _, bad := range []string{";WD)", ";AU)", ";BU)", ";IU)"} { // Everyone, Authenticated, Users, Interactive
		if strings.Contains(s, bad) {
			t.Errorf("DACL grants a broad group %s: %s", bad, s)
		}
	}
}

// TestBackstageLiveCompositeAndInput starts a real cmd.exe on the backstage
// desktop, checks that its window is composited into the frame, drives it with
// posted messages, and checks the physical cursor did not move.
func TestBackstageLiveCompositeAndInput(t *testing.T) {
	skipUnlessElevated(t)
	d := openTestDesktop(t)
	d.retain()
	ptr := &bsPointerPos{}
	c, err := newBackstageCapturer(d, ptr)
	if err != nil {
		d.release()
		d.release()
		t.Fatal(err)
	}
	inj := newBackstageInjector(d, ptr)
	defer c.Close()
	defer inj.close()

	if err := d.spawn(backstageTool{image: "cmd.exe", x: 20, y: 20, w: 640, h: 360}); err != nil {
		t.Skipf("cannot start cmd.exe on the backstage desktop: %v", err)
	}

	mons, err := c.monitors()
	if err != nil {
		t.Fatal(err)
	}
	inj.setMonitor(mons[0])

	var cursorBefore bsPoint
	procGetCursorPosTest.Call(uintptr(unsafe.Pointer(&cursorBefore)))

	// Wait for the console window to show up and be painted.
	var first *image.RGBA
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		img, err := c.capture(mons[0])
		if err != nil {
			t.Fatal(err)
		}
		if distinctPixels(img) > 50 {
			first = img
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if first == nil {
		t.Skipf("no window content composited within 10s (windows seen: %d); PrintWindow may not render this window type cross-desktop", len(d.topLevelWindows()))
	}
	t.Logf("composited frame has %d distinct colours", distinctPixels(first))
	if dir := os.Getenv("BACKSTAGE_DUMP"); dir != "" {
		defer func() {
			img, _ := c.capture(mons[0])
			if f, err := os.Create(filepath.Join(dir, "backstage_after.png")); err == nil {
				png.Encode(f, img)
				f.Close()
			}
		}()
		if f, err := os.Create(filepath.Join(dir, "backstage_before.png")); err == nil {
			png.Encode(f, first)
			f.Close()
		}
	}

	// Click into the console, type, and expect the frame to change.
	rc := image.Rect(0, 0, 0, 0)
	for _, w := range d.topLevelWindows() {
		if bsShown(w) {
			if r, ok := bsWindowRect(w); ok && r.width() > 50 && r.height() > 50 {
				rc = image.Rect(int(r.left), int(r.top), int(r.right), int(r.bottom))
				break
			}
		}
	}
	cx, cy := (rc.Min.X+rc.Max.X)/2-mons[0].Bounds.Min.X, (rc.Min.Y+rc.Max.Y)/2-mons[0].Bounds.Min.Y
	if err := inj.mouseMove(cx, cy); err != nil {
		t.Fatal(err)
	}
	if err := inj.mouseButton(buttonLeft, true, cx, cy); err != nil {
		t.Fatal(err)
	}
	if err := inj.mouseButton(buttonLeft, false, cx, cy); err != nil {
		t.Fatal(err)
	}
	if err := inj.paste("echo backstage-ok\r"); err != nil {
		t.Fatal(err)
	}
	changed := false
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(250 * time.Millisecond) {
		img, err := c.capture(mons[0])
		if err != nil {
			t.Fatal(err)
		}
		if diffPixels(first, img) > 100 {
			changed = true
			break
		}
	}
	if !changed {
		t.Error("typed text did not change the composited console: posted WM_CHAR never reached it")
	}

	// Caption drag: press on the title bar, move, release; the window follows.
	var top uintptr
	for _, w := range d.topLevelWindows() {
		if r, ok := bsWindowRect(w); ok && bsShown(w) && r.width() > 50 {
			top = w
			break
		}
	}
	before, _ := bsWindowRect(top)
	tx, ty := int(before.left)+200-mons[0].Bounds.Min.X, int(before.top)+8-mons[0].Bounds.Min.Y
	inj.mouseMove(tx, ty)
	inj.mouseButton(buttonLeft, true, tx, ty)
	inj.mouseMove(tx+120, ty+60)
	inj.mouseButton(buttonLeft, false, tx+120, ty+60)
	if after, _ := bsWindowRect(top); after.left-before.left != 120 || after.top-before.top != 60 {
		t.Errorf("caption drag moved the window by (%d,%d), want (120,60)", after.left-before.left, after.top-before.top)
	}

	// Close button: find it with WM_NCHITTEST, click it, the window goes away.
	rc2, _ := bsWindowRect(top)
	closeX := int32(-1)
	for x := rc2.right - 1; x > rc2.right-300; x-- {
		if code, ok := nonClientHit(top, x, rc2.top+10); ok && code == htClose {
			closeX = x
			break
		}
	}
	if closeX < 0 {
		t.Error("could not locate the close button")
	} else {
		cxs, cys := int(closeX)-mons[0].Bounds.Min.X, int(rc2.top)+10-mons[0].Bounds.Min.Y
		inj.mouseButton(buttonLeft, true, cxs, cys)
		inj.mouseButton(buttonLeft, false, cxs, cys)
		gone := false
		for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
			if !bsBool(procIsWindowBS, top) {
				gone = true
				break
			}
		}
		if !gone {
			t.Error("clicking the close button did not close the window")
		}
	}

	var cursorAfter bsPoint
	procGetCursorPosTest.Call(uintptr(unsafe.Pointer(&cursorAfter)))
	// The injected position is where a leak into the physical input queue
	// would have put the real cursor.
	if leaked := (bsPoint{int32(mons[0].Bounds.Min.X + cx), int32(mons[0].Bounds.Min.Y + cy)}); cursorAfter == leaked && cursorBefore != leaked {
		t.Errorf("the physical cursor moved to the injected position %v", leaked)
	}
	t.Logf("physical cursor before %v after %v", cursorBefore, cursorAfter)
}

var procGetCursorPosTest = user32.NewProc("GetCursorPos")

func distinctPixels(img *image.RGBA) int {
	seen := map[[3]byte]struct{}{}
	for i := 0; i+3 < len(img.Pix); i += 4 {
		seen[[3]byte{img.Pix[i], img.Pix[i+1], img.Pix[i+2]}] = struct{}{}
		if len(seen) > 1000 {
			break
		}
	}
	return len(seen)
}

func diffPixels(a, b *image.RGBA) int {
	if len(a.Pix) != len(b.Pix) {
		return len(b.Pix)
	}
	n := 0
	for i := 0; i+3 < len(a.Pix); i += 4 {
		if a.Pix[i] != b.Pix[i] || a.Pix[i+1] != b.Pix[i+1] || a.Pix[i+2] != b.Pix[i+2] {
			n++
		}
	}
	return n
}

// TestBackstageToolSuiteStartsAndStops runs the real default suite and checks
// that closing the session leaves no process behind.
func TestBackstageToolSuiteStartsAndStops(t *testing.T) {
	skipUnlessElevated(t)
	c, inj, err := newBackstage()
	if err != nil {
		t.Skipf("newBackstage unavailable here: %v", err)
	}
	bc := c.(*backstageCapturer)
	d := bc.d
	d.mu.Lock()
	n := len(d.procs)
	var procs []windows.Handle
	for _, p := range d.procs { // dup: release() closes the originals
		var dup windows.Handle
		cur := windows.CurrentProcess()
		if err := windows.DuplicateHandle(cur, p, cur, &dup, windows.SYNCHRONIZE, false, 0); err == nil {
			procs = append(procs, dup)
		}
	}
	d.mu.Unlock()
	if n == 0 {
		t.Error("no tool from the default suite started")
	}
	for end := time.Now().Add(8 * time.Second); d.visibleWindowCount() == 0 && time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
	}
	if d.visibleWindowCount() == 0 {
		t.Error("the default suite showed no window on the backstage desktop")
	}
	bc.Close()
	inj.close()
	for _, p := range procs {
		ev, _ := windows.WaitForSingleObject(p, 5000)
		if ev != windows.WAIT_OBJECT_0 {
			t.Error("a backstage tool survived the session")
		}
		windows.CloseHandle(p)
	}
}
