//go:build linux

package desktop

import (
	"errors"
	"image"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bendahl/uinput"
	"github.com/godbus/dbus/v5"
)

// ---- fakes ----

type fakePad struct {
	log    []string
	moves  [][2]int32
	failMv error
}

func (f *fakePad) MoveTo(x, y int32) error {
	if f.failMv != nil {
		return f.failMv
	}
	f.moves = append(f.moves, [2]int32{x, y})
	f.log = append(f.log, "move")
	return nil
}
func (f *fakePad) LeftPress() error    { f.log = append(f.log, "L+"); return nil }
func (f *fakePad) LeftRelease() error  { f.log = append(f.log, "L-"); return nil }
func (f *fakePad) RightPress() error   { f.log = append(f.log, "R+"); return nil }
func (f *fakePad) RightRelease() error { f.log = append(f.log, "R-"); return nil }
func (f *fakePad) Close() error        { f.log = append(f.log, "pad.close"); return nil }

type fakeMouse struct {
	log    []string
	wheels []int32
	hwheel []int32
}

func (f *fakeMouse) MiddlePress() error   { f.log = append(f.log, "M+"); return nil }
func (f *fakeMouse) MiddleRelease() error { f.log = append(f.log, "M-"); return nil }
func (f *fakeMouse) Wheel(h bool, d int32) error {
	if h {
		f.hwheel = append(f.hwheel, d)
	} else {
		f.wheels = append(f.wheels, d)
	}
	return nil
}
func (f *fakeMouse) Close() error { f.log = append(f.log, "mouse.close"); return nil }

type fakeKbd struct{ ev []string } // "+29" down, "-29" up

func (f *fakeKbd) KeyDown(k int) error { f.ev = append(f.ev, "+"+itoa(k)); return nil }
func (f *fakeKbd) KeyUp(k int) error   { f.ev = append(f.ev, "-"+itoa(k)); return nil }
func (f *fakeKbd) Close() error        { f.ev = append(f.ev, "kbd.close"); return nil }

func newFakeInjector() (*uinputInjector, *fakePad, *fakeMouse, *fakeKbd) {
	p, m, k := &fakePad{}, &fakeMouse{}, &fakeKbd{}
	u := newUinputInjectorFromDevices(p, m, k)
	u.setMonitor(monitor{Bounds: image.Rect(0, 0, 1920, 1080)})
	return u, p, m, k
}

func evs(codes ...int) string {
	var b []string
	for _, c := range codes {
		b = append(b, itoa(c))
	}
	return strings.Join(b, ",")
}

// ---- key mapping ----

func TestUinputKeyCodesCoverTheKeymap(t *testing.T) {
	for code := range keymap {
		if _, ok := uinputKeyCodes[code]; !ok {
			t.Errorf("keymap code %s has no Linux key code", code)
		}
	}
}

func TestUinputKeyCodesAreValidAndSpotChecked(t *testing.T) {
	for name, kc := range uinputKeyCodes {
		if kc <= 0 || kc > 0x2ff {
			t.Errorf("%s -> %d is not a plausible KEY_* code", name, kc)
		}
	}
	// Values from linux/input-event-codes.h.
	for name, want := range map[string]int{
		"KeyA": 30, "KeyQ": 16, "KeyZ": 44, "KeyM": 50, "KeyP": 25, "KeyL": 38,
		"Digit1": 2, "Digit0": 11, "Numpad0": 82, "Numpad7": 71,
		"F1": 59, "F10": 68, "F11": 87, "F12": 88, "F13": 183, "F24": 194,
		"Enter": 28, "Escape": 1, "Space": 57, "Backspace": 14, "Tab": 15,
		"ControlLeft": 29, "ShiftLeft": 42, "AltLeft": 56, "MetaLeft": 125,
		"ArrowLeft": 105, "ArrowUp": 103, "Delete": 111, "NumpadEnter": 96,
	} {
		if got := uinputKeyCodes[name]; got != want {
			t.Errorf("%s = %d want %d", name, got, want)
		}
	}
	// No two letters may share a code.
	seen := map[int]string{}
	for c := 'A'; c <= 'Z'; c++ {
		n := "Key" + string(c)
		if o, dup := seen[uinputKeyCodes[n]]; dup {
			t.Errorf("%s and %s share code %d", n, o, uinputKeyCodes[n])
		}
		seen[uinputKeyCodes[n]] = n
	}
}

func TestUsKeyForRune(t *testing.T) {
	type want struct {
		code  int
		shift bool
		ok    bool
	}
	for r, w := range map[rune]want{
		'a': {uinput.KeyA, false, true}, 'A': {uinput.KeyA, true, true},
		'1': {uinput.Key1, false, true}, '!': {uinput.Key1, true, true},
		'0': {uinput.Key0, false, true}, ')': {uinput.Key0, true, true},
		'@': {uinput.Key2, true, true}, '_': {uinput.KeyMinus, true, true},
		'?': {uinput.KeySlash, true, true}, ' ': {uinput.KeySpace, false, true},
		'"': {uinput.KeyApostrophe, true, true}, '~': {uinput.KeyGrave, true, true},
		'|': {uinput.KeyBackslash, true, true},
		'é': {0, false, false}, '€': {0, false, false}, '\x7f': {0, false, false},
	} {
		code, shift, ok := usKeyForRune(r)
		if code != w.code || shift != w.shift || ok != w.ok {
			t.Errorf("usKeyForRune(%q) = %d,%v,%v want %d,%v,%v", r, code, shift, ok, w.code, w.shift, w.ok)
		}
	}
	// Every printable ASCII character must be typeable.
	for r := rune(0x20); r < 0x7f; r++ {
		if _, _, ok := usKeyForRune(r); !ok {
			t.Errorf("printable %q is not typeable", r)
		}
	}
}

func TestUinputKeyPhysicalAndTyped(t *testing.T) {
	u, _, _, k := newFakeInjector()
	if err := u.key("KeyA", "a", true); err != nil {
		t.Fatal(err)
	}
	if err := u.key("KeyA", "a", false); err != nil {
		t.Fatal(err)
	}
	// Unknown code, printable key: typed by character with auto-Shift.
	if err := u.key("Unidentified", "A", true); err != nil {
		t.Fatal(err)
	}
	if err := u.key("Unidentified", "A", false); err != nil {
		t.Fatal(err)
	}
	want := "+30 -30 +42 +30 -30 -42"
	if got := strings.Join(k.ev, " "); got != want {
		t.Fatalf("events %q want %q", got, want)
	}
	if len(u.held) != 0 {
		t.Fatalf("keys left held: %v", u.held)
	}
	if err := u.key("Dead", "Dead", true); err == nil {
		t.Fatal("unknown named key accepted")
	}
	if err := u.key("Unidentified", "é", true); err == nil {
		t.Fatal("non-ASCII character accepted")
	}
}

func TestUinputTypedKeyDoesNotDoubleShift(t *testing.T) {
	u, _, _, k := newFakeInjector()
	u.key("ShiftLeft", "Shift", true)
	u.key("Unidentified", "A", true)
	u.key("Unidentified", "A", false)
	u.key("ShiftLeft", "Shift", false)
	if got, want := strings.Join(k.ev, " "), "+42 +30 -30 -42"; got != want {
		t.Fatalf("events %q want %q", got, want)
	}
}

func TestUinputPaste(t *testing.T) {
	u, _, _, k := newFakeInjector()
	if err := u.paste("aB\r\n\t"); err != nil {
		t.Fatal(err)
	}
	// a, Shift+b, Enter (CRLF once), Tab
	want := "+30 -30 +42 +48 -48 -42 +28 -28 +15 -15"
	if got := strings.Join(k.ev, " "); got != want {
		t.Fatalf("events %q want %q", got, want)
	}
	// Non-typeable characters are reported, the rest still typed.
	k.ev = nil
	err := u.paste("a€")
	if err == nil || !strings.Contains(err.Error(), "1 character") {
		t.Fatalf("err = %v", err)
	}
	if got := strings.Join(k.ev, " "); got != "+30 -30" {
		t.Fatalf("events %q", got)
	}
}

func TestUinputCtrlAltDel(t *testing.T) {
	u, _, _, k := newFakeInjector()
	if err := u.ctrlAltDel(); err != nil {
		t.Fatal(err)
	}
	want := "+29 +56 +111 -111 -56 -29"
	if got := strings.Join(k.ev, " "); got != want {
		t.Fatalf("events %q want %q", got, want)
	}
}

// ---- coordinate scaling ----

func TestAbsPointSingleMonitor(t *testing.T) {
	r := image.Rect(0, 0, 1920, 1080)
	ax, ay := absPoint(r, r, 0, 0, uinputAbsMax)
	if ax <= 0 || ay <= 0 || ax > 20 || ay > 20 {
		t.Fatalf("top-left = %d,%d (pixel centre of the first pixel expected, never the 0,0 quirk)", ax, ay)
	}
	ax, ay = absPoint(r, r, 1919, 1079, uinputAbsMax)
	if ax < uinputAbsMax-20 || ay < uinputAbsMax-20 || ax > uinputAbsMax || ay > uinputAbsMax {
		t.Fatalf("bottom-right = %d,%d", ax, ay)
	}
	ax, ay = absPoint(r, r, 960, 540, uinputAbsMax)
	if d := int(ax) - uinputAbsMax/2; d < -20 || d > 20 {
		t.Fatalf("centre x = %d", ax)
	}
	_ = ay
	// Hostile coordinates clamp to the edges.
	ax, ay = absPoint(r, r, -5000, 99999, uinputAbsMax)
	if ax > 20 || ay < uinputAbsMax-20 {
		t.Fatalf("clamp = %d,%d", ax, ay)
	}
}

func TestAbsPointSecondMonitorOnDesktop(t *testing.T) {
	left := image.Rect(0, 0, 1920, 1080)
	right := image.Rect(1920, 0, 3840, 1080)
	desk := left.Union(right)
	// The left edge of the right monitor is the middle of the desktop.
	ax, _ := absPoint(desk, right, 0, 0, uinputAbsMax)
	if d := int(ax) - uinputAbsMax/2; d < -20 || d > 20 {
		t.Fatalf("right monitor x origin maps to %d", ax)
	}
	// The same monitor-relative point on the left monitor is far left.
	ax, _ = absPoint(desk, left, 0, 0, uinputAbsMax)
	if ax > 20 {
		t.Fatalf("left monitor x origin maps to %d", ax)
	}
	// Negative monitor origins (a monitor left of the primary) work too.
	neg := image.Rect(-1920, 0, 0, 1080)
	desk = neg.Union(left)
	ax, _ = absPoint(desk, neg, 0, 0, uinputAbsMax)
	if ax > 20 {
		t.Fatalf("negative-origin monitor maps to %d", ax)
	}
}

func TestSetMonitorUsesDesktopHint(t *testing.T) {
	defer setDesktopHint(image.Rectangle{})
	left := image.Rect(0, 0, 1920, 1080)
	right := image.Rect(1920, 0, 3840, 1080)
	setDesktopHint(monitorUnion([]monitor{{Bounds: left}, {Bounds: right}}))
	u := newUinputInjectorFromDevices(&fakePad{}, nil, &fakeKbd{})
	u.setMonitor(monitor{Index: 1, Bounds: right})
	if u.desk != left.Union(right) {
		t.Fatalf("desk = %v", u.desk)
	}
	// A hint that does not contain the monitor is ignored.
	setDesktopHint(image.Rect(0, 0, 100, 100))
	u.setMonitor(monitor{Bounds: right})
	if u.desk != right {
		t.Fatalf("desk = %v", u.desk)
	}
}

// ---- pointer and wheel behaviour ----

func TestUinputMouseButtonsAndMoveDedup(t *testing.T) {
	u, p, m, _ := newFakeInjector()
	if err := u.mouseButton(buttonLeft, true, 100, 100); err != nil {
		t.Fatal(err)
	}
	if err := u.mouseButton(buttonLeft, false, 100, 100); err != nil { // same spot: no second move
		t.Fatal(err)
	}
	if err := u.mouseButton(buttonRight, true, 100, 100); err != nil {
		t.Fatal(err)
	}
	if err := u.mouseButton(buttonMiddle, true, 100, 100); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(p.log, " "), "move L+ L- R+"; got != want {
		t.Fatalf("pad log %q want %q", got, want)
	}
	if got := strings.Join(m.log, " "); got != "M+" {
		t.Fatalf("mouse log %q", got)
	}
	if err := u.mouseButton(7, true, 0, 0); err == nil {
		t.Fatal("unknown button accepted")
	}
	// close releases what is still held.
	u.close()
	if !strings.Contains(strings.Join(p.log, " "), "R- pad.close") || !strings.Contains(strings.Join(m.log, " "), "M- mouse.close") {
		t.Fatalf("close did not release: pad=%v mouse=%v", p.log, m.log)
	}
}

func TestUinputMouseMoveError(t *testing.T) {
	u, p, _, _ := newFakeInjector()
	p.failMv = errors.New("boom")
	if err := u.mouseMove(1, 1); err == nil {
		t.Fatal("error swallowed")
	}
}

func TestUinputWheelDirection(t *testing.T) {
	u, _, m, _ := newFakeInjector()
	// Browser dy>0 scrolls down: REL_WHEEL must be negative.
	if err := u.wheel(0, 120, 10, 10); err != nil {
		t.Fatal(err)
	}
	if err := u.wheel(0, -100, 10, 10); err != nil {
		t.Fatal(err)
	}
	// dx>0 scrolls right: REL_HWHEEL positive.
	if err := u.wheel(100, 0, 10, 10); err != nil {
		t.Fatal(err)
	}
	if len(m.wheels) != 2 || m.wheels[0] != -1 || m.wheels[1] != 1 {
		t.Fatalf("wheels = %v", m.wheels)
	}
	if len(m.hwheel) != 1 || m.hwheel[0] != 1 {
		t.Fatalf("hwheel = %v", m.hwheel)
	}
	// Sub-notch deltas accumulate instead of firing.
	m.wheels = nil
	for i := 0; i < 3; i++ {
		u.wheel(0, 10, 10, 10)
	}
	if len(m.wheels) != 0 {
		t.Fatalf("sub-notch deltas fired: %v", m.wheels)
	}
}

func TestUinputWheelWithoutRelativeDevice(t *testing.T) {
	u := newUinputInjectorFromDevices(&fakePad{}, nil, &fakeKbd{})
	u.setMonitor(monitor{Bounds: image.Rect(0, 0, 100, 100)})
	if err := u.wheel(0, 100, 1, 1); err == nil {
		t.Fatal("wheel succeeded without a relative device")
	}
	if err := u.wheel(0, 5, 1, 1); err != nil { // sub-notch: nothing to send
		t.Fatalf("no-op wheel: %v", err)
	}
	if err := u.mouseButton(buttonMiddle, true, 1, 1); err == nil {
		t.Fatal("middle button succeeded without a relative device")
	}
}

func TestUinputSelectionOffWaylandAndInterface(t *testing.T) {
	var _ injector = (*uinputInjector)(nil)
	waylandMode.Store(false)
	if _, ok := tryUinputInjector(); ok {
		t.Fatal("uinput chosen on an X11 session")
	}
}

func TestCheckUinputWritableErrorIsClear(t *testing.T) {
	if f, err := os.OpenFile(uinputPath, os.O_WRONLY, 0); err == nil {
		f.Close()
		t.Skip("/dev/uinput is writable here; the failure message cannot be exercised")
	}
	err := checkUinputWritable()
	if err == nil || !strings.Contains(err.Error(), uinputPath) {
		t.Fatalf("err = %v", err)
	}
}

// ---- portal messages ----

func TestRequestPath(t *testing.T) {
	got := requestPath(":1.234", "rmm7")
	if want := dbus.ObjectPath("/org/freedesktop/portal/desktop/request/1_234/rmm7"); got != want {
		t.Fatalf("requestPath = %s want %s", got, want)
	}
}

func TestSelectSourcesOptions(t *testing.T) {
	o := selectSourcesOptions("h1", "tok", true)
	if o["types"].Value() != uint32(1) || o["persist_mode"].Value() != uint32(2) || o["restore_token"].Value() != "tok" || o["handle_token"].Value() != "h1" {
		t.Fatalf("options = %v", o)
	}
	if o["multiple"].Value() != false {
		t.Fatalf("multiple = %v", o["multiple"])
	}
	// No stored token: do not send an empty one (the portal rejects it).
	if _, ok := selectSourcesOptions("h", "", true)["restore_token"]; ok {
		t.Fatal("empty restore_token sent")
	}
	// Old portals reject persist options.
	o = selectSourcesOptions("h", "tok", false)
	if _, ok := o["persist_mode"]; ok {
		t.Fatal("persist_mode sent to a portal without it")
	}
	if _, ok := o["restore_token"]; ok {
		t.Fatal("restore_token sent to a portal without persist support")
	}
	if co := createSessionOptions("a", "b"); co["handle_token"].Value() != "a" || co["session_handle_token"].Value() != "b" {
		t.Fatalf("createSessionOptions = %v", co)
	}
}

func TestParseStreams(t *testing.T) {
	// The wire decoder delivers a(ua{sv}) as [][]interface{} and (ii) as []interface{}.
	results := map[string]dbus.Variant{
		"restore_token": dbus.MakeVariant("newtok"),
		"streams": dbus.MakeVariant([][]interface{}{
			{uint32(42), map[string]dbus.Variant{
				"position": dbus.MakeVariant([]interface{}{int32(0), int32(0)}),
				"size":     dbus.MakeVariant([]interface{}{int32(1920), int32(1080)}),
			}},
			{uint32(43), map[string]dbus.Variant{
				"position": dbus.MakeVariant([]interface{}{int32(1920), int32(0)}),
				"size":     dbus.MakeVariant([]interface{}{int32(1280), int32(1024)}),
			}},
			{uint32(44), map[string]dbus.Variant{}}, // no geometry reported
		}),
	}
	streams, tok, err := parseStreams(results)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "newtok" || len(streams) != 3 {
		t.Fatalf("tok=%q streams=%v", tok, streams)
	}
	if streams[0].Node != 42 || streams[0].Bounds != image.Rect(0, 0, 1920, 1080) {
		t.Fatalf("stream 0 = %+v", streams[0])
	}
	if streams[1].Bounds != image.Rect(1920, 0, 3200, 1024) {
		t.Fatalf("stream 1 = %+v", streams[1])
	}
	mons := monitorsFromStreams(streams)
	if len(mons) != 2 || !mons[0].Primary || mons[1].Primary || mons[1].Index != 1 {
		t.Fatalf("monitors = %+v", mons)
	}
	if u := monitorUnion(mons); u != image.Rect(0, 0, 3200, 1080) {
		t.Fatalf("union = %v", u)
	}

	if _, _, err := parseStreams(map[string]dbus.Variant{}); err == nil {
		t.Fatal("missing streams accepted")
	}
	if _, _, err := parseStreams(map[string]dbus.Variant{"streams": dbus.MakeVariant([][]interface{}{})}); err == nil {
		t.Fatal("empty streams accepted")
	}
}

func TestDecodeResponse(t *testing.T) {
	res := map[string]dbus.Variant{"session_handle": dbus.MakeVariant("/s")}
	got, err := decodeResponse("m", []interface{}{uint32(0), res})
	if err != nil || got["session_handle"].Value() != "/s" {
		t.Fatalf("ok response: %v %v", got, err)
	}
	if _, err := decodeResponse("m", []interface{}{uint32(1), res}); err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := decodeResponse("m", []interface{}{uint32(2), res}); err == nil {
		t.Fatal("code 2 accepted")
	}
	if _, err := decodeResponse("m", nil); err == nil {
		t.Fatal("empty body accepted")
	}
}

func TestRestoreTokenRoundTrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if got := loadRestoreToken(); got != "" {
		t.Fatalf("token before save = %q", got)
	}
	if err := saveRestoreToken("abc-123"); err != nil {
		t.Fatal(err)
	}
	if got := loadRestoreToken(); got != "abc-123" {
		t.Fatalf("token = %q", got)
	}
	p, _ := restoreTokenPath()
	if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("token file %s: %v %v", p, st, err)
	}
	if filepath.Base(p) != "screencast-restore-token" {
		t.Fatalf("path = %s", p)
	}
	// A newer token replaces the old one (they are single use).
	if err := saveRestoreToken("def-456"); err != nil || loadRestoreToken() != "def-456" {
		t.Fatalf("replace failed: %v %q", err, loadRestoreToken())
	}
	// An empty token never clobbers a good one.
	if err := saveRestoreToken(""); err != nil || loadRestoreToken() != "def-456" {
		t.Fatalf("empty token clobbered: %v %q", err, loadRestoreToken())
	}
}

func TestPipeWireCaptureWithoutSessionFailsWithoutFrames(t *testing.T) {
	c := &pipewireCapturer{}
	img, err := c.capture(monitor{Bounds: image.Rect(0, 0, 10, 10)})
	if img != nil || err == nil {
		t.Fatalf("capture = %v, %v", img, err)
	}
	if _, err := c.monitors(); err == nil {
		t.Fatal("monitors on an unnegotiated capturer succeeded")
	}
}

// ---- Wayland launch helpers ----

func TestSelectWaylandSession(t *testing.T) {
	props := map[string]map[string]string{
		"1": {"Type": "wayland", "Class": "greeter", "Active": "yes", "User": "0", "Name": "root"},
		"2": {"Type": "x11", "Class": "user", "Active": "yes", "User": "0", "Name": "root"},
		"3": {"Type": "wayland", "Class": "user", "Active": "no", "User": "0", "Name": "root"},
		"4": {"Type": "wayland", "Class": "user", "Active": "yes", "User": "0", "Name": "root"},
	}
	show := func(id string) (map[string]string, error) { return props[id], nil }
	s, err := selectWaylandSession("1 1000 a seat0\n2 1000 a seat0\n3 1000 a seat0\n4 0 root seat0\n", show)
	if err != nil {
		t.Fatal(err)
	}
	if s.id != "4" || s.uid != 0 || s.wayland == "" || s.dbus == "" {
		t.Fatalf("session = %+v", s)
	}
	if _, err := selectWaylandSession("1 0 a seat0\n", show); err == nil {
		t.Fatal("greeter-only list produced a session")
	}
}

func TestApplyWaylandEnvAndHelperEnv(t *testing.T) {
	s := &x11Session{uid: 1000, user: "alice", home: "/home/alice"}
	applyWaylandEnv(s, nil)
	if s.wayland != "wayland-0" || s.dbus != "unix:path=/run/user/1000/bus" || s.display != "" {
		t.Fatalf("defaults = %+v", s)
	}
	env := strings.Join(helperEnvWayland(s, "tok"), "\n")
	for _, want := range []string{"XDG_SESSION_TYPE=wayland", "WAYLAND_DISPLAY=wayland-0", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus", TokenEnv + "=tok"} {
		if !strings.Contains(env, want) {
			t.Errorf("env lacks %s:\n%s", want, env)
		}
	}
	if strings.Contains(env, "DISPLAY=\n") || strings.Contains(env, "XDG_SESSION_TYPE=x11") || strings.Contains(env, "\nDISPLAY=") {
		t.Errorf("env carries an X display for a session without Xwayland:\n%s", env)
	}

	applyWaylandEnv(s, map[string]string{"WAYLAND_DISPLAY": "wayland-1", "DISPLAY": ":1", "XAUTHORITY": "/run/user/1000/xauth"})
	if s.wayland != "wayland-1" || s.display != ":1" || s.xauth != "/run/user/1000/xauth" {
		t.Fatalf("env applied = %+v", s)
	}
	env = strings.Join(helperEnvWayland(s, ""), "\n")
	if !strings.Contains(env, "DISPLAY=:1") || !strings.Contains(env, "XAUTHORITY=/run/user/1000/xauth") {
		t.Errorf("Xwayland variables dropped:\n%s", env)
	}
}

func TestParseEnviron(t *testing.T) {
	blob := []byte("PATH=/bin\x00WAYLAND_DISPLAY=wayland-0\x00DISPLAY=\x00XAUTHORITY=/x\x00junk\x00")
	got := parseEnviron(blob, sessionEnvKeys)
	if got["WAYLAND_DISPLAY"] != "wayland-0" || got["XAUTHORITY"] != "/x" {
		t.Fatalf("env = %v", got)
	}
	if _, ok := got["DISPLAY"]; ok {
		t.Fatal("empty DISPLAY kept")
	}
	if _, ok := got["PATH"]; ok {
		t.Fatal("unrequested key kept")
	}
}
