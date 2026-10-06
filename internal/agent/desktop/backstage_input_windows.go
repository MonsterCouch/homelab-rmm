//go:build windows

package desktop

import (
	"errors"
	"fmt"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Window-targeted input for the backstage desktop.
//
// Nothing here goes through the system input stream, so the physical cursor
// does not move and no keystroke reaches the logged-in user. A pointer or key
// event is turned into a window message and posted to a window handle taken
// from the backstage desktop's own window tree.
//
// WindowFromPoint is not usable for the hit test: it resolves against the
// calling thread's desktop (the one the user is looking at). The injector
// therefore walks EnumDesktopWindows(hBackstage) topmost-first, finds the
// first shown window whose rectangle holds the point, and descends with
// ChildWindowFromPointEx, which only looks at the window tree below the
// handle it is given.
//
// Known limits of message posting, inherent to the approach: the physical
// keyboard / cursor state APIs (GetKeyState, GetCursorPos) do not see the
// posted events, so Ctrl/Alt chords that an application checks through
// GetKeyState, hover effects, window-edge resizing and menu tracking that need
// a real pointer are only partly available. Text, clicks, drags inside a
// window, scrolling, caption dragging and the caption buttons work.

// Window messages (winuser.h).
const (
	wmNCHitTest   = 0x0084
	wmKeyDown     = 0x0100
	wmKeyUp       = 0x0101
	wmChar        = 0x0102
	wmSysKeyDown  = 0x0104
	wmSysKeyUp    = 0x0105
	wmSysChar     = 0x0106
	wmSysCommand  = 0x0112
	wmMouseMove   = 0x0200
	wmLButtonDown = 0x0201
	wmLButtonUp   = 0x0202
	wmLButtonDbl  = 0x0203
	wmRButtonDown = 0x0204
	wmRButtonUp   = 0x0205
	wmRButtonDbl  = 0x0206
	wmMButtonDown = 0x0207
	wmMButtonUp   = 0x0208
	wmMButtonDbl  = 0x0209
	wmMouseWheel  = 0x020A
	wmMouseHWheel = 0x020E

	// Key-state flags in a mouse message's wParam.
	mkLButton = 0x0001
	mkRButton = 0x0002
	mkShift   = 0x0004
	mkControl = 0x0008
	mkMButton = 0x0010

	// WM_NCHITTEST results.
	htClient    = 1
	htCaption   = 2
	htMinButton = 8
	htMaxButton = 9
	htClose     = 20

	// WM_SYSCOMMAND values.
	scMinimize = 0xF020
	scMaximize = 0xF030
	scClose    = 0xF060
	scRestore  = 0xF120

	cwpSkipInvisible   = 0x0001
	cwpSkipTransparent = 0x0004

	swpNoSize     = 0x0001
	swpNoMove     = 0x0002
	swpNoZOrder   = 0x0004
	swpNoActivate = 0x0010

	smtoAbortIfHung = 0x0002
	csDblClks       = 0x0008 // class style: the window wants double-click messages

	vkShift   = 0x10
	vkControl = 0x11
	vkMenu    = 0x12
	vkF10     = 0x79

	errNotEnoughQuota = 1816 // PostMessage: the target's queue is full

	dblClickSlop = 4 // pixels
)

// bsInjector implements injector by posting messages to backstage windows.
// All methods run on the input goroutine.
type bsInjector struct {
	d   *backstageDesktop
	ptr *bsPointerPos

	closeOnce sync.Once
	mon       monitor
	acc       wheelAccumulator

	buttons       uintptr // MK_*BUTTON bits currently held
	shift, ctrl   bool
	alt           bool
	down          map[uint16]bool // message-level VKs currently held (auto-repeat bit)
	focus         uintptr         // window that last took a click: keyboard target
	capture       uintptr         // window that took the button-down: gets moves until release
	drag          uintptr         // top-level window being moved by its caption
	dragDX        int32
	dragDY        int32
	ncDown        uintptr // non-client hit code the left button went down on
	ncTop         uintptr
	lastClickBtn  int
	lastClickWnd  uintptr
	lastClickAt   time.Time
	lastClickX    int32
	lastClickY    int32
	haveLastClick bool
}

func newBackstageInjector(d *backstageDesktop, ptr *bsPointerPos) *bsInjector {
	return &bsInjector{d: d, ptr: ptr, down: map[uint16]bool{}}
}

func (i *bsInjector) close() {
	i.closeOnce.Do(i.d.release)
}

func (i *bsInjector) setMonitor(m monitor) {
	i.mon = m
	i.acc.reset()
}

// ---- posting ----

func makeLParam(lo, hi int32) uintptr {
	return uintptr(uint32(uint16(lo)) | uint32(uint16(hi))<<16)
}

// post is PostMessageW with a short back-off when the target's 10 000
// message queue is full (a long paste can outrun the application).
//
//	BOOL PostMessageW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
func post(hwnd uintptr, msg uint32, wParam, lParam uintptr) error {
	var err error
	for try := 0; try < 100; try++ {
		var r uintptr
		r, _, err = procPostMessageW.Call(hwnd, uintptr(msg), wParam, lParam)
		if r != 0 {
			return nil
		}
		if !errors.Is(err, windows.Errno(errNotEnoughQuota)) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("PostMessage 0x%04X to %#x: %w", msg, hwnd, err)
}

// ---- hit testing ----

func screenToClient(hwnd uintptr, sx, sy int32) bsPoint {
	p := bsPoint{sx, sy}
	procScreenToClientBS.Call(hwnd, uintptr(unsafe.Pointer(&p)))
	return p
}

// hitTest finds the backstage window under the screen point: the top-level
// window, and the deepest visible child at that point. Both are 0 when the
// point lies over the bare desktop.
func (i *bsInjector) hitTest(sx, sy int32) (top, leaf uintptr) {
	for _, w := range i.d.topLevelWindows() { // topmost first
		if !bsShown(w) {
			continue
		}
		rc, ok := bsWindowRect(w)
		if !ok || sx < rc.left || sx >= rc.right || sy < rc.top || sy >= rc.bottom {
			continue
		}
		leaf = w
		for depth := 0; depth < 32; depth++ {
			p := screenToClient(leaf, sx, sy)
			// HWND ChildWindowFromPointEx(HWND hwndParent, POINT pt, UINT flags):
			// searches the window tree under hwndParent only.
			c := childFromPoint(leaf, p)
			if c == 0 || c == leaf {
				break
			}
			leaf = c
		}
		return w, leaf
	}
	return 0, 0
}

// childFromPoint wraps ChildWindowFromPointEx, whose POINT parameter is
// passed by value: one register on 64-bit (x in the low half), two stack
// slots on 32-bit.
func childFromPoint(parent uintptr, p bsPoint) uintptr {
	const flags = cwpSkipInvisible | cwpSkipTransparent
	var c uintptr
	if unsafe.Sizeof(uintptr(0)) == 8 {
		c, _, _ = procChildWindowFromPointEx.Call(parent, uintptr(uint32(p.x))|uintptr(uint32(p.y))<<32, flags)
	} else {
		c, _, _ = procChildWindowFromPointEx.Call(parent, uintptr(uint32(p.x)), uintptr(uint32(p.y)), flags)
	}
	return c
}

// insideClient reports whether the screen point is in top's client area.
func insideClient(top uintptr, sx, sy int32) bool {
	var cr bsRect
	if r, _, _ := procGetClientRectBS.Call(top, uintptr(unsafe.Pointer(&cr))); r == 0 {
		return true
	}
	p := screenToClient(top, sx, sy)
	return p.x >= 0 && p.y >= 0 && p.x < cr.right && p.y < cr.bottom
}

// nonClientHit asks the window what the point is over (title bar, caption
// buttons, border). ok is false when the window did not answer in time.
func nonClientHit(top uintptr, sx, sy int32) (code uintptr, ok bool) {
	var res uintptr
	r, _, _ := procSendMessageTimeoutWBS.Call(top, wmNCHitTest, 0, makeLParam(sx, sy),
		smtoAbortIfHung, 100, uintptr(unsafe.Pointer(&res)))
	if r == 0 {
		return 0, false
	}
	return uintptr(int16(res)), true // HTxxx values fit a signed short (HTERROR is -2)
}

func (i *bsInjector) abs(x, y int) (int32, int32) {
	return int32(i.mon.Bounds.Min.X + x), int32(i.mon.Bounds.Min.Y + y)
}

func (i *bsInjector) keyFlags() uintptr {
	f := i.buttons
	if i.shift {
		f |= mkShift
	}
	if i.ctrl {
		f |= mkControl
	}
	return f
}

// postMouse sends a client-coordinate mouse message for a screen point.
func (i *bsInjector) postMouse(msg uint32, hwnd uintptr, sx, sy int32, extra uintptr) error {
	p := screenToClient(hwnd, sx, sy)
	return post(hwnd, msg, i.keyFlags()|extra, makeLParam(p.x, p.y))
}

// raise brings a top-level window to the front of the backstage Z-order
// without activating it (activation across desktops is not available).
func raise(top uintptr) {
	if bsBool(procIsHungAppWindowBS, top) {
		return
	}
	// HWND_TOP == 0
	procSetWindowPosBS.Call(top, 0, 0, 0, 0, 0, swpNoMove|swpNoSize|swpNoActivate)
}

// ---- injector ----

func (i *bsInjector) mouseMove(x, y int) error {
	i.ptr.set(x, y)
	sx, sy := i.abs(x, y)
	if i.drag != 0 {
		// Caption drag: the modal move loop needs a real pointer, so move the
		// window directly.
		procSetWindowPosBS.Call(i.drag, 0, uintptr(sx-i.dragDX), uintptr(sy-i.dragDY), 0, 0,
			swpNoSize|swpNoZOrder|swpNoActivate)
		return nil
	}
	target := i.capture
	if target == 0 || i.buttons&(mkLButton|mkRButton|mkMButton) == 0 {
		_, target = i.hitTest(sx, sy)
	}
	if target == 0 {
		return nil // bare desktop
	}
	return i.postMouse(wmMouseMove, target, sx, sy, 0)
}

func (i *bsInjector) mouseButton(button int, down bool, x, y int) error {
	var mk uintptr
	var msgDown, msgUp, msgDbl uint32
	switch button {
	case buttonLeft:
		mk, msgDown, msgUp, msgDbl = mkLButton, wmLButtonDown, wmLButtonUp, wmLButtonDbl
	case buttonRight:
		mk, msgDown, msgUp, msgDbl = mkRButton, wmRButtonDown, wmRButtonUp, wmRButtonDbl
	case buttonMiddle:
		mk, msgDown, msgUp, msgDbl = mkMButton, wmMButtonDown, wmMButtonUp, wmMButtonDbl
	default:
		return fmt.Errorf("unknown mouse button %d", button)
	}
	i.ptr.set(x, y)
	sx, sy := i.abs(x, y)

	if !down {
		return i.buttonUp(button, mk, msgUp, sx, sy)
	}

	top, leaf := i.hitTest(sx, sy)
	if top == 0 {
		return nil // bare desktop
	}
	raise(top)

	// A click on the title bar or its buttons is non-client: client messages
	// would be meaningless there.
	if !insideClient(top, sx, sy) {
		if button != buttonLeft {
			return nil
		}
		code, ok := nonClientHit(top, sx, sy)
		if !ok {
			return nil
		}
		switch code {
		case htCaption:
			if rc, ok := bsWindowRect(top); ok {
				i.drag, i.dragDX, i.dragDY = top, sx-rc.left, sy-rc.top
			}
		case htClose, htMinButton, htMaxButton:
			i.ncDown, i.ncTop = code, top
		}
		return nil
	}

	i.focus = leaf
	i.capture = leaf
	i.buttons |= mk
	// Hover first so the application knows where the click lands.
	if err := i.postMouse(wmMouseMove, leaf, sx, sy, 0); err != nil {
		return err
	}
	msg := msgDown
	if i.isDoubleClick(button, leaf, sx, sy) {
		msg = msgDbl
		i.haveLastClick = false
	} else {
		i.lastClickBtn, i.lastClickWnd, i.lastClickAt = button, leaf, time.Now()
		i.lastClickX, i.lastClickY, i.haveLastClick = sx, sy, true
	}
	return i.postMouse(msg, leaf, sx, sy, 0)
}

func (i *bsInjector) buttonUp(button int, mk uintptr, msgUp uint32, sx, sy int32) error {
	if button == buttonLeft {
		if i.drag != 0 {
			i.drag = 0
			return nil
		}
		if i.ncDown != 0 {
			code, top := i.ncDown, i.ncTop
			i.ncDown, i.ncTop = 0, 0
			// Act only when released over the same button it was pressed on.
			if now, ok := nonClientHit(top, sx, sy); ok && now == code {
				return post(top, wmSysCommand, i.sysCommand(top, code), 0)
			}
			return nil
		}
	}
	if i.buttons&mk == 0 {
		return nil // its down was swallowed (non-client or bare desktop)
	}
	target := i.capture
	if target == 0 || !bsBool(procIsWindowBS, target) {
		_, target = i.hitTest(sx, sy)
	}
	i.buttons &^= mk
	if i.buttons&(mkLButton|mkRButton|mkMButton) == 0 {
		i.capture = 0
	}
	if target == 0 {
		return nil
	}
	return i.postMouse(msgUp, target, sx, sy, 0)
}

func (i *bsInjector) sysCommand(top, code uintptr) uintptr {
	switch code {
	case htClose:
		return scClose
	case htMinButton:
		return scMinimize
	default: // htMaxButton toggles
		if bsBool(procIsZoomedBS, top) {
			return scRestore
		}
		return scMaximize
	}
}

// isDoubleClick applies the system double-click rules. A window only gets
// WM_xBUTTONDBLCLK when its class has CS_DBLCLKS; sending one to any other
// window would lose the click.
func (i *bsInjector) isDoubleClick(button int, hwnd uintptr, sx, sy int32) bool {
	if !i.haveLastClick || button != i.lastClickBtn || hwnd != i.lastClickWnd {
		return false
	}
	limit, _, _ := procGetDoubleClickTimeBS.Call() // milliseconds
	if time.Since(i.lastClickAt) > time.Duration(limit)*time.Millisecond {
		return false
	}
	if abs32(sx-i.lastClickX) > dblClickSlop || abs32(sy-i.lastClickY) > dblClickSlop {
		return false
	}
	gcl := -26 // GCL_STYLE
	style, _, _ := procGetClassLongWBS.Call(hwnd, uintptr(gcl))
	return style&csDblClks != 0
}

func abs32(v int32) int32 {
	if v < 0 {
		return -v
	}
	return v
}

func (i *bsInjector) wheel(dx, dy float64, x, y int) error {
	nx, ny := i.acc.add(dx, dy)
	if nx == 0 && ny == 0 {
		return nil
	}
	i.ptr.set(x, y)
	sx, sy := i.abs(x, y)
	_, target := i.hitTest(sx, sy)
	if target == 0 {
		return nil
	}
	send := func(msg uint32, notches int) error {
		// WM_MOUSEWHEEL: wParam = key flags | wheel delta << 16 (a signed
		// short, 120 per notch, positive = away from the user); lParam is in
		// SCREEN coordinates, unlike every other mouse message.
		for n := 0; n < abs(notches); n++ {
			delta := int16(wheelDelta)
			if notches < 0 {
				delta = -delta
			}
			w := i.keyFlags() | uintptr(uint16(delta))<<16
			if err := post(target, msg, w, makeLParam(sx, sy)); err != nil {
				return err
			}
		}
		return nil
	}
	// Browser dy > 0 is "scroll down", which is a negative wheel delta.
	if err := send(wmMouseWheel, -ny); err != nil {
		return err
	}
	return send(wmMouseHWheel, nx)
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// ---- keyboard ----

// keyTarget is the window keyboard messages go to: the last one clicked, or
// the topmost shown window when nothing has been clicked yet (or the clicked
// one has gone away). 0 means the desktop is empty.
func (i *bsInjector) keyTarget() uintptr {
	if i.focus != 0 && bsBool(procIsWindowBS, i.focus) {
		return i.focus
	}
	i.focus = 0
	for _, w := range i.d.topLevelWindows() {
		if bsShown(w) {
			return w
		}
	}
	return 0
}

// msgVK is the virtual key a keyboard message carries: Windows reports the
// generic Shift/Control/Menu there, never the left/right variants.
func msgVK(vk uint16) uint16 {
	switch vk {
	case vkLShift, vkRShift:
		return vkShift
	case vkLControl, vkRControl:
		return vkControl
	case vkLMenu, vkRMenu:
		return vkMenu
	}
	return vk
}

// keyLParam builds a keyboard message's lParam (winuser.h, WM_KEYDOWN):
// bits 0-15 repeat count, 16-23 scan code, 24 extended key, 29 Alt held,
// 30 previous key state, 31 transition (1 = being released).
func keyLParam(vk uint16, extended, up, wasDown, alt bool) uintptr {
	scan, _, _ := procMapVirtualKeyW.Call(uintptr(vk), mapvkVkToVsc)
	l := uint32(1) | uint32(scan&0xFF)<<16
	if extended {
		l |= 1 << 24
	}
	if alt {
		l |= 1 << 29
	}
	if up || wasDown {
		l |= 1 << 30
	}
	if up {
		l |= 1 << 31
	}
	return uintptr(l)
}

func isModifierVK(vk uint16) bool {
	switch vk {
	case vkLShift, vkRShift, vkLControl, vkRControl, vkLMenu, vkRMenu, vkLWin, vkRWin:
		return true
	}
	return false
}

func (i *bsInjector) trackModifier(vk uint16, down bool) {
	switch vk {
	case vkLShift, vkRShift:
		i.shift = down
	case vkLControl, vkRControl:
		i.ctrl = down
	case vkLMenu, vkRMenu:
		i.alt = down
	}
}

// key delivers one key event.
//
// Posted WM_KEYDOWNs are run through TranslateMessage by the receiving
// application's own message loop, which turns them into WM_CHAR using that
// thread's (real, un-pressed) keyboard state: an 'A' typed with Shift held
// would arrive as 'a', and a WM_CHAR posted on top would double it. So
// characters are posted as WM_CHAR only, using the character the viewer
// reports in "key" (which already reflects Shift / CapsLock / layout), and
// WM_KEYDOWN / WM_KEYUP are used for keys that are not characters (arrows,
// function keys, Enter, Tab, Backspace, modifiers) and for Alt chords.
func (i *bsInjector) key(code, key string, down bool) error {
	d, mapped := keymap[code]
	if mapped {
		i.trackModifier(d.vk, down)
	}
	target := i.keyTarget()
	if target == 0 {
		return nil // nothing on the desktop to type into
	}
	r, printable := printableKey(key)

	switch {
	case printable && !i.alt:
		if !down {
			return nil
		}
		if i.ctrl {
			// Ctrl+letter is the control character; edit controls and
			// console windows act on WM_CHAR 0x01-0x1A (copy, paste, ^C ...).
			if c := ctrlChar(r); c != 0 {
				return post(target, wmChar, uintptr(c), 1)
			}
			return nil
		}
		return postRune(target, wmChar, r)

	case mapped:
		vk := msgVK(d.vk)
		sys := i.alt || vk == vkMenu || vk == vkF10
		msg := uint32(wmKeyDown)
		switch {
		case sys && down:
			msg = wmSysKeyDown
		case sys:
			msg = wmSysKeyUp
		case !down:
			msg = wmKeyUp
		}
		was := i.down[vk]
		if down {
			i.down[vk] = true
		} else {
			delete(i.down, vk)
		}
		// Bit 29 (context code) is set when Alt is held while another key
		// is pressed; for the Alt key itself it is 0 on press.
		ctx := i.alt && vk != vkMenu
		return post(target, msg, uintptr(vk), keyLParam(d.vk, d.extended, !down, was && down, ctx))

	case printable: // Alt+character with no physical-key code
		if !down {
			return nil
		}
		return postRune(target, wmSysChar, r)
	}
	return fmt.Errorf("unknown key %q", code)
}

// ctrlChar is the ASCII control character for Ctrl+r, or 0.
func ctrlChar(r rune) rune {
	switch {
	case r >= 'a' && r <= 'z':
		return r - 'a' + 1
	case r >= 'A' && r <= 'Z':
		return r - 'A' + 1
	}
	return 0
}

// postRune posts r as one message per UTF-16 unit (surrogate pairs are two
// WM_CHARs, which is how Windows delivers supplementary characters).
func postRune(hwnd uintptr, msg uint32, r rune) error {
	if r > 0xFFFF {
		hi, lo := utf16.EncodeRune(r)
		if err := post(hwnd, msg, uintptr(hi), 1); err != nil {
			return err
		}
		return post(hwnd, msg, uintptr(lo), 1)
	}
	return post(hwnd, msg, uintptr(r), 1)
}

// paste types text into the focused window as WM_CHAR messages, so it works
// whatever the keyboard layout. Newlines become carriage returns (what
// Enter produces).
func (i *bsInjector) paste(text string) error {
	target := i.keyTarget()
	if target == 0 {
		return nil
	}
	prev := rune(0)
	for _, r := range text {
		if r == '\n' {
			if prev == '\r' {
				prev = r
				continue // CRLF is one Enter
			}
			r = '\r'
		}
		prev = r
		if err := postRune(target, wmChar, r); err != nil {
			return err
		}
	}
	return nil
}

// ctrlAltDel has no meaning here: the secure attention sequence belongs to
// the physical console, and the backstage desktop has no winlogon.
func (i *bsInjector) ctrlAltDel() error {
	return errors.New("Ctrl+Alt+Del is not available on the backstage desktop; use Task Manager (taskmgr.exe) there")
}
