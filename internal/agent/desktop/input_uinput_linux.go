//go:build linux

package desktop

// /dev/uinput injector: synthetic input that works on every Linux session
// type, Wayland included, because it feeds the kernel's input layer instead of
// talking to a display server. The compositor (or X server, via evdev/libinput)
// then sees three ordinary USB-style devices:
//
//   - an absolute pointer (bendahl/uinput TouchPad: ABS_X/ABS_Y, BTN_LEFT,
//     BTN_RIGHT). udev classifies a device with absolute axes and BTN_MOUSE as a
//     mouse (the same class as a VM's "USB tablet"), so libinput treats it as an
//     absolute pointer spanning the whole desktop;
//   - a relative mouse used only for what the TouchPad cannot do in this library
//     version: BTN_MIDDLE and the wheel axes;
//   - a keyboard that registers every key code.
//
// Selection seam: newInjector() lives in input_linux.go (the X11/XTEST
// backend) and is not edited. A Wayland session is routed here by
// tryUinputInjector(), which input_linux.go's newInjector() is meant to call
// first (see preferUinput). Nothing in this file touches an X display.
//
// Permissions: /dev/uinput must be writable by the helper's user. On systemd
// hosts the stock udev rule tags uinput with "uaccess", which grants the user
// at the active seat an ACL; otherwise a rule such as
// KERNEL=="uinput", GROUP="input", MODE="0660" plus group membership is needed.
// newUinputInjector() reports a clear error when it is not writable so the
// caller can fall back to XTEST.

import (
	"errors"
	"fmt"
	"image"
	"log/slog"
	"math"
	"os"
	"sync"
	"syscall"
	"unicode/utf8"

	"github.com/bendahl/uinput"
)

const (
	uinputPath = "/dev/uinput"

	// The absolute pointer axis range. The kernel gives integer coordinates,
	// so a coarse range such as 0..1024 would quantise a 4K desktop to 4
	// pixels per step; 32767 is far finer than any display and still well
	// inside what libinput and X evdev accept.
	uinputAbsMax = 32767
)

// uinputPointer, uinputRelMouse and uinputKeyboard are the slices of the
// bendahl/uinput device interfaces this injector uses; tests substitute fakes.
type uinputPointer interface {
	MoveTo(x, y int32) error
	LeftPress() error
	LeftRelease() error
	RightPress() error
	RightRelease() error
	Close() error
}

type uinputRelMouse interface {
	MiddlePress() error
	MiddleRelease() error
	Wheel(horizontal bool, delta int32) error
	Close() error
}

type uinputKeyboard interface {
	KeyDown(key int) error
	KeyUp(key int) error
	Close() error
}

// uinputInjector implements injector. Like the other backends it is driven
// from one goroutine, so it keeps its state without locking.
type uinputInjector struct {
	pad   uinputPointer
	mouse uinputRelMouse // nil when the relative device could not be created
	kbd   uinputKeyboard

	mon  monitor
	desk image.Rectangle // virtual desktop the absolute axes span
	acc  wheelAccumulator

	lastAX, lastAY int32 // last absolute position sent, -1 before the first
	buttons        [3]bool
	held           map[int]bool
	autoMods       map[int][]int // modifiers added for a typed-by-character key
}

// ---- construction ----

// newUinputInjector opens /dev/uinput and creates the virtual devices. It
// returns a descriptive error when uinput is unavailable or not writable.
func newUinputInjector() (injector, error) {
	if err := checkUinputWritable(); err != nil {
		return nil, err
	}
	pad, err := uinput.CreateTouchPad(uinputPath, []byte("RMM Virtual Pointer"), 0, uinputAbsMax, 0, uinputAbsMax)
	if err != nil {
		return nil, fmt.Errorf("create uinput pointer: %w", err)
	}
	kbd, err := uinput.CreateKeyboard(uinputPath, []byte("RMM Virtual Keyboard"))
	if err != nil {
		pad.Close()
		return nil, fmt.Errorf("create uinput keyboard: %w", err)
	}
	var mouse uinputRelMouse
	m, err := uinput.CreateMouse(uinputPath, []byte("RMM Virtual Wheel"))
	if err != nil {
		// Clicks and typing still work; only the wheel and the middle
		// button are lost.
		slog.Warn("desktop: uinput relative device unavailable; wheel and middle button disabled", "err", err)
	} else {
		mouse = m
	}
	return newUinputInjectorFromDevices(pad, mouse, kbd), nil
}

func newUinputInjectorFromDevices(pad uinputPointer, mouse uinputRelMouse, kbd uinputKeyboard) *uinputInjector {
	return &uinputInjector{
		pad: pad, mouse: mouse, kbd: kbd,
		lastAX: -1, lastAY: -1,
		held:     map[int]bool{},
		autoMods: map[int][]int{},
	}
}

// checkUinputWritable explains why uinput cannot be used, so the fallback
// decision (and the operator) get an actionable message.
func checkUinputWritable() error {
	f, err := os.OpenFile(uinputPath, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err == nil {
		return f.Close()
	}
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("%s does not exist (is the uinput kernel module loaded? try `modprobe uinput`)", uinputPath)
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("%s is not writable by uid %d (`rmm-agent install` writes /etc/udev/rules.d/70-homelab-rmm-uinput.rules for this; otherwise grant access with a udev rule such as KERNEL==\"uinput\", GROUP=\"input\", MODE=\"0660\", TAG+=\"uaccess\" and reload udev, or add the user to that group): %w", uinputPath, os.Geteuid(), err)
	}
	return fmt.Errorf("open %s: %w", uinputPath, err)
}

// uinputSelectorWired records whether input_linux.go's newInjector() calls
// tryUinputInjector(). Until it does, Wayland sessions must keep being
// refused by platformInit: accepting them would hand them to the XTEST
// injector, which cannot reach native Wayland clients. Flip to true together
// with that one-line call.
const uinputSelectorWired = true

// preferUinput reports whether the session being served needs the uinput
// backend: true on Wayland (set by platformInit), where XTEST would reach
// only XWayland clients.
func preferUinput() bool { return waylandMode.Load() }

// tryUinputInjector is the selection seam for input_linux.go's newInjector():
//
//	if inj, ok := tryUinputInjector(); ok { return inj, nil }
//
// It returns ok=false on X11 sessions (use XTEST) and when uinput cannot be
// opened (the error is logged; fall back to XTEST, which at least drives
// XWayland clients).
func tryUinputInjector() (injector, bool) {
	if !preferUinput() {
		return nil, false
	}
	inj, err := newUinputInjector()
	if err != nil {
		slog.Warn("desktop: uinput input unavailable on this Wayland session; falling back to XTEST", "err", err)
		return nil, false
	}
	slog.Info("desktop: using /dev/uinput for input")
	return inj, true
}

// ---- desktop geometry ----

var (
	deskMu   sync.Mutex
	deskHint image.Rectangle
)

// setDesktopHint records the bounding box of all monitors, as the capturer
// reports them. The absolute axes span the whole desktop, so a pointer
// position on one monitor must be scaled against this box, not that monitor.
func setDesktopHint(r image.Rectangle) {
	deskMu.Lock()
	deskHint = r
	deskMu.Unlock()
}

func desktopHint() image.Rectangle {
	deskMu.Lock()
	defer deskMu.Unlock()
	return deskHint
}

// monitorUnion is the smallest rectangle containing every monitor.
func monitorUnion(mons []monitor) image.Rectangle {
	var u image.Rectangle
	for _, m := range mons {
		u = u.Union(m.Bounds)
	}
	return u
}

func (u *uinputInjector) setMonitor(m monitor) {
	u.mon = m
	u.desk = m.Bounds
	if h := desktopHint(); !h.Empty() && m.Bounds.In(h) {
		u.desk = h
	}
	u.acc.reset()
	u.lastAX, u.lastAY = -1, -1
}

// absPoint scales a point relative to monitor mon (viewer coordinates) into
// the 0..absMax axis space spanning desk. It aims at the pixel centre and
// clamps, so a hostile coordinate lands on an edge of the desktop.
func absPoint(desk, mon image.Rectangle, px, py int, absMax int32) (int32, int32) {
	if desk.Empty() {
		desk = mon
	}
	if desk.Empty() {
		return 0, 0
	}
	scale := func(v, origin, deskMin, size int) int32 {
		d := v + origin - deskMin
		if d < 0 {
			d = 0
		}
		if d > size-1 {
			d = size - 1
		}
		a := int32(math.Round((float64(d) + 0.5) / float64(size) * float64(absMax)))
		if a > absMax {
			a = absMax
		}
		return a
	}
	return scale(px, mon.Min.X, desk.Min.X, desk.Dx()), scale(py, mon.Min.Y, desk.Min.Y, desk.Dy())
}

// ---- pointer ----

func (u *uinputInjector) mouseMove(px, py int) error {
	ax, ay := absPoint(u.desk, u.mon.Bounds, px, py, uinputAbsMax)
	if ax == u.lastAX && ay == u.lastAY {
		return nil
	}
	if err := u.pad.MoveTo(ax, ay); err != nil {
		return err
	}
	u.lastAX, u.lastAY = ax, ay
	return nil
}

func (u *uinputInjector) mouseButton(button int, down bool, px, py int) error {
	if button < buttonLeft || button > buttonRight {
		return fmt.Errorf("unknown mouse button %d", button)
	}
	if err := u.mouseMove(px, py); err != nil {
		return err
	}
	var err error
	switch button {
	case buttonLeft:
		err = pick(down, u.pad.LeftPress, u.pad.LeftRelease)
	case buttonRight:
		err = pick(down, u.pad.RightPress, u.pad.RightRelease)
	case buttonMiddle:
		if u.mouse == nil {
			return errors.New("middle button unavailable: relative uinput device was not created")
		}
		err = pick(down, u.mouse.MiddlePress, u.mouse.MiddleRelease)
	}
	if err == nil {
		u.buttons[button] = down
	}
	return err
}

func pick(down bool, press, release func() error) error {
	if down {
		return press()
	}
	return release()
}

// wheel scrolls via the relative device. The accumulator yields positive
// notches for right/down (browser convention); REL_WHEEL is positive for
// "away from the user" (up), so the vertical axis is inverted. REL_HWHEEL is
// positive to the right and passes through.
func (u *uinputInjector) wheel(dx, dy float64, px, py int) error {
	nx, ny := u.acc.add(dx, dy)
	if nx == 0 && ny == 0 {
		return nil
	}
	if u.mouse == nil {
		return errors.New("wheel unavailable: relative uinput device was not created")
	}
	if err := u.mouseMove(px, py); err != nil {
		return err
	}
	if ny != 0 {
		if err := u.mouse.Wheel(false, int32(-ny)); err != nil {
			return err
		}
	}
	if nx != 0 {
		return u.mouse.Wheel(true, int32(nx))
	}
	return nil
}

// ---- keyboard ----

func (u *uinputInjector) press(code int, down bool) error {
	var err error
	if down {
		err = u.kbd.KeyDown(code)
	} else {
		err = u.kbd.KeyUp(code)
	}
	if err == nil {
		if down {
			u.held[code] = true
		} else {
			delete(u.held, code)
		}
	}
	return err
}

// key handles a viewer keydown/keyup. A known physical code is pressed bare
// (the viewer sends its own modifier presses; the compositor's layout turns
// the code into a character). An unknown code with a printable ASCII key is
// typed by character assuming a US layout, adding Shift when needed.
func (u *uinputInjector) key(code, key string, down bool) error {
	if kc, ok := uinputKeyCodes[code]; ok {
		return u.press(kc, down)
	}
	r, ok := printableKey(key)
	if !ok {
		return fmt.Errorf("unknown key %q", code)
	}
	kc, shift, ok := usKeyForRune(r)
	if !ok {
		return fmt.Errorf("cannot type %q: uinput sends key codes, not Unicode", r)
	}
	return u.typeKey(kc, shift, down)
}

// typeKey presses or releases kc, wrapping it in Shift when asked unless a
// Shift key is already held. The Shift it added is released with the key.
func (u *uinputInjector) typeKey(kc int, shift, down bool) error {
	if !down {
		err := u.press(kc, false)
		for _, m := range u.autoMods[kc] {
			u.press(m, false)
		}
		delete(u.autoMods, kc)
		return err
	}
	var added []int
	if shift && !u.held[uinput.KeyLeftshift] && !u.held[uinput.KeyRightshift] {
		if err := u.press(uinput.KeyLeftshift, true); err != nil {
			return err
		}
		added = append(added, uinput.KeyLeftshift)
	}
	u.autoMods[kc] = added
	return u.press(kc, true)
}

// paste types text as key events (US layout; uinput cannot send Unicode, so
// non-ASCII characters are skipped and reported). CR/LF is one Enter and Tab
// is Tab; other control characters are dropped.
func (u *uinputInjector) paste(text string) error {
	prev := rune(0)
	skipped := 0
	for _, r := range text {
		var (
			kc    int
			shift bool
			ok    bool
		)
		switch {
		case r == '\n' && prev == '\r':
			prev = r
			continue
		case r == '\n' || r == '\r':
			kc, ok = uinput.KeyEnter, true
		case r == '\t':
			kc, ok = uinput.KeyTab, true
		case r < 0x20 || (r >= 0x7f && r < 0xa0):
			prev = r
			continue
		default:
			kc, shift, ok = usKeyForRune(r)
		}
		prev = r
		if !ok {
			skipped++
			continue
		}
		if err := u.typeKey(kc, shift, true); err != nil {
			return err
		}
		if err := u.typeKey(kc, shift, false); err != nil {
			return err
		}
	}
	if skipped > 0 {
		return fmt.Errorf("pasted text had %d character(s) that cannot be typed through uinput (non-US-layout characters were skipped)", skipped)
	}
	return nil
}

// ctrlAltDel presses Ctrl+Alt+Delete. There is no secure attention sequence
// on Linux; desktop environments typically show a logout/power dialog.
func (u *uinputInjector) ctrlAltDel() error {
	seq := []int{uinput.KeyLeftctrl, uinput.KeyLeftalt, uinput.KeyDelete}
	var err error
	pressed := 0
	for _, k := range seq {
		if err = u.press(k, true); err != nil {
			break
		}
		pressed++
	}
	for i := pressed - 1; i >= 0; i-- {
		if rerr := u.press(seq[i], false); rerr != nil && err == nil {
			err = rerr
		}
	}
	return err
}

// close releases anything still held, then destroys the devices.
func (u *uinputInjector) close() {
	for kc := range u.held {
		u.kbd.KeyUp(kc)
	}
	if u.buttons[buttonLeft] {
		u.pad.LeftRelease()
	}
	if u.buttons[buttonRight] {
		u.pad.RightRelease()
	}
	if u.mouse != nil {
		if u.buttons[buttonMiddle] {
			u.mouse.MiddleRelease()
		}
		u.mouse.Close()
	}
	u.pad.Close()
	u.kbd.Close()
}

// ---- key tables ----

// uinputKeyCodes maps W3C "code" values (keymap.go's keys) to Linux KEY_*
// event codes.
var uinputKeyCodes = map[string]int{}

// usLetterCodes are the QWERTY rows in evdev order; evdev letter codes are
// not alphabetical.
var usLetterCodes = map[rune]int{}

func init() {
	for i, c := range "qwertyuiop" {
		usLetterCodes[c] = uinput.KeyQ + i
	}
	for i, c := range "asdfghjkl" {
		usLetterCodes[c] = uinput.KeyA + i
	}
	for i, c := range "zxcvbnm" {
		usLetterCodes[c] = uinput.KeyZ + i
	}
	for c, kc := range usLetterCodes {
		uinputKeyCodes["Key"+string(c-'a'+'A')] = kc
	}
	digits := [10]int{uinput.Key0, uinput.Key1, uinput.Key2, uinput.Key3, uinput.Key4, uinput.Key5, uinput.Key6, uinput.Key7, uinput.Key8, uinput.Key9}
	pad := [10]int{uinput.KeyKp0, uinput.KeyKp1, uinput.KeyKp2, uinput.KeyKp3, uinput.KeyKp4, uinput.KeyKp5, uinput.KeyKp6, uinput.KeyKp7, uinput.KeyKp8, uinput.KeyKp9}
	for i := 0; i < 10; i++ {
		uinputKeyCodes["Digit"+itoa(i)] = digits[i]
		uinputKeyCodes["Numpad"+itoa(i)] = pad[i]
	}
	// F1..F10 are 59..68, F11/F12 are 87/88, F13..F24 are 183..194.
	for i := 1; i <= 24; i++ {
		var kc int
		switch {
		case i <= 10:
			kc = uinput.KeyF1 + i - 1
		case i <= 12:
			kc = uinput.KeyF11 + i - 11
		default:
			kc = uinput.KeyF13 + i - 13
		}
		uinputKeyCodes["F"+itoa(i)] = kc
	}
	for name, kc := range map[string]int{
		"Enter": uinput.KeyEnter, "Escape": uinput.KeyEsc, "Backspace": uinput.KeyBackspace,
		"Tab": uinput.KeyTab, "Space": uinput.KeySpace,

		"Minus": uinput.KeyMinus, "Equal": uinput.KeyEqual,
		"BracketLeft": uinput.KeyLeftbrace, "BracketRight": uinput.KeyRightbrace,
		"Backslash": uinput.KeyBackslash, "Semicolon": uinput.KeySemicolon,
		"Quote": uinput.KeyApostrophe, "Backquote": uinput.KeyGrave,
		"Comma": uinput.KeyComma, "Period": uinput.KeyDot, "Slash": uinput.KeySlash,
		"IntlBackslash": uinput.Key102Nd,

		"CapsLock":  uinput.KeyCapslock,
		"ShiftLeft": uinput.KeyLeftshift, "ShiftRight": uinput.KeyRightshift,
		"ControlLeft": uinput.KeyLeftctrl, "ControlRight": uinput.KeyRightctrl,
		"AltLeft": uinput.KeyLeftalt, "AltRight": uinput.KeyRightalt,
		"MetaLeft": uinput.KeyLeftmeta, "MetaRight": uinput.KeyRightmeta,
		"ContextMenu": uinput.KeyCompose, // KEY_COMPOSE is the keyboard "Menu" key

		"ArrowUp": uinput.KeyUp, "ArrowDown": uinput.KeyDown,
		"ArrowLeft": uinput.KeyLeft, "ArrowRight": uinput.KeyRight,
		"Home": uinput.KeyHome, "End": uinput.KeyEnd,
		"PageUp": uinput.KeyPageup, "PageDown": uinput.KeyPagedown,
		"Insert": uinput.KeyInsert, "Delete": uinput.KeyDelete,

		"PrintScreen": uinput.KeySysrq, "ScrollLock": uinput.KeyScrolllock,
		"Pause": uinput.KeyPause, "NumLock": uinput.KeyNumlock,

		"NumpadAdd": uinput.KeyKpplus, "NumpadSubtract": uinput.KeyKpminus,
		"NumpadMultiply": uinput.KeyKpasterisk, "NumpadDivide": uinput.KeyKpslash,
		"NumpadDecimal": uinput.KeyKpdot, "NumpadEnter": uinput.KeyKpenter,

		"AudioVolumeMute": uinput.KeyMute, "AudioVolumeDown": uinput.KeyVolumedown,
		"AudioVolumeUp":  uinput.KeyVolumeup,
		"MediaPlayPause": uinput.KeyPlaypause, "MediaStop": uinput.KeyStopcd,
		"MediaTrackPrevious": uinput.KeyPrevioussong, "MediaTrackNext": uinput.KeyNextsong,
		"BrowserBack": uinput.KeyBack, "BrowserForward": uinput.KeyForward,
		"Sleep": uinput.KeySleep,
	} {
		uinputKeyCodes[name] = kc
	}
}

// usKeyForRune returns the key (and whether Shift is needed) that types r on
// a US layout. The compositor applies its own layout to the key code, so on a
// non-US layout typing by character is approximate; physical codes (the
// normal path) are unaffected.
func usKeyForRune(r rune) (code int, shift bool, ok bool) {
	if r >= 'a' && r <= 'z' {
		return usLetterCodes[r], false, true
	}
	if r >= 'A' && r <= 'Z' {
		return usLetterCodes[r-'A'+'a'], true, true
	}
	if r > utf8.RuneSelf {
		return 0, false, false
	}
	const shiftedDigits = ")!@#$%^&*(" // Shift+0 .. Shift+9
	if r >= '0' && r <= '9' {
		return uinputKeyCodes["Digit"+itoa(int(r-'0'))], false, true
	}
	for i, c := range shiftedDigits {
		if r == c {
			return uinputKeyCodes["Digit"+itoa(i)], true, true
		}
	}
	type sym struct {
		base, shifted rune
		code          int
	}
	for _, s := range [...]sym{
		{'-', '_', uinput.KeyMinus}, {'=', '+', uinput.KeyEqual},
		{'[', '{', uinput.KeyLeftbrace}, {']', '}', uinput.KeyRightbrace},
		{'\\', '|', uinput.KeyBackslash}, {';', ':', uinput.KeySemicolon},
		{'\'', '"', uinput.KeyApostrophe}, {'`', '~', uinput.KeyGrave},
		{',', '<', uinput.KeyComma}, {'.', '>', uinput.KeyDot}, {'/', '?', uinput.KeySlash},
	} {
		if r == s.base {
			return s.code, false, true
		}
		if r == s.shifted {
			return s.code, true, true
		}
	}
	if r == ' ' {
		return uinput.KeySpace, false, true
	}
	return 0, false, false
}
