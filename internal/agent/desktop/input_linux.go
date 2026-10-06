//go:build linux

package desktop

import (
	"errors"
	"fmt"
	"image"
	"log/slog"
	"math"
	"sync/atomic"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xinerama"
	"github.com/jezek/xgb/xproto"
	"github.com/jezek/xgb/xtest"
)

// X pointer buttons.
const (
	xButtonLeft       = 1
	xButtonMiddle     = 2
	xButtonRight      = 3
	xButtonWheelUp    = 4
	xButtonWheelDown  = 5
	xButtonWheelLeft  = 6
	xButtonWheelRight = 7
)

// x11Injector drives the XTEST extension. It owns one X connection and is
// used from a single goroutine; the only concurrent touch is the event
// drain goroutine setting mappingDirty.
type x11Injector struct {
	c      *xgb.Conn
	root   xproto.Window
	screen image.Rectangle // root window size, for clamping
	xin    bool            // Xinerama usable, for monitor origins

	mon    monitor
	origin image.Point // root-window coordinates of the monitor's top-left
	acc    wheelAccumulator

	// keyboard mapping as the server reports it
	minKC, maxKC xproto.Keycode
	perKC        int
	syms         []xproto.Keysym
	mappingDirty atomic.Bool

	shiftKC xproto.Keycode

	// spare keycodes we may rebind to type characters the layout lacks
	spare     []xproto.Keycode
	spareNext int
	remapped  map[uint32]xproto.Keycode // keysym -> keycode we bound it to
	remapKeys map[xproto.Keycode]uint32 // reverse, to evict

	// held tracks every keycode currently pressed (by the viewer or by us)
	// so a modifier is never pressed twice and everything is released on
	// close; autoMods remembers the modifiers we added for a viewer key
	// so its keyup releases them again.
	held     map[xproto.Keycode]bool
	autoMods map[xproto.Keycode][]xproto.Keycode
}

func newInjector() (injector, error) {
	// On Wayland, XTEST reaches only XWayland clients, so prefer the kernel
	// /dev/uinput backend (see input_uinput_linux.go). It falls through to
	// XTEST when uinput cannot be opened or the session is X11.
	if inj, ok := tryUinputInjector(); ok {
		return inj, nil
	}
	c, err := xgb.NewConn()
	if err != nil {
		return nil, fmt.Errorf("connect to X display: %w", err)
	}
	inj, err := newX11Injector(c)
	if err != nil {
		c.Close()
		return nil, err
	}
	return inj, nil
}

func newX11Injector(c *xgb.Conn) (*x11Injector, error) {
	if err := xtest.Init(c); err != nil {
		return nil, fmt.Errorf("XTEST extension: %w", err)
	}
	if _, err := xtest.GetVersion(c, 2, 2).Reply(); err != nil {
		return nil, fmt.Errorf("XTEST version: %w", err)
	}
	setup := xproto.Setup(c)
	screen := setup.DefaultScreen(c)
	inj := &x11Injector{
		c:         c,
		root:      screen.Root,
		screen:    image.Rect(0, 0, int(screen.WidthInPixels), int(screen.HeightInPixels)),
		minKC:     setup.MinKeycode,
		maxKC:     setup.MaxKeycode,
		remapped:  map[uint32]xproto.Keycode{},
		remapKeys: map[xproto.Keycode]uint32{},
		held:      map[xproto.Keycode]bool{},
		autoMods:  map[xproto.Keycode][]xproto.Keycode{},
	}
	inj.xin = xinerama.Init(c) == nil
	if err := inj.loadMapping(); err != nil {
		return nil, err
	}
	// xgb queues every event and error on a channel that blocks the reader
	// when full; MappingNotify is broadcast to all clients, so drain it.
	go inj.drainEvents()
	return inj, nil
}

func (x *x11Injector) drainEvents() {
	for {
		ev, xerr := x.c.WaitForEvent()
		if ev == nil && xerr == nil {
			return // connection closed
		}
		if xerr != nil {
			slog.Debug("desktop: X error", "err", xerr)
			continue
		}
		if _, ok := ev.(xproto.MappingNotifyEvent); ok {
			x.mappingDirty.Store(true)
		}
	}
}

// loadMapping (re)reads the keyboard mapping and derives the modifier and
// spare keycodes from it. Remaps we made earlier stay valid only if the
// server still shows our keysym on that keycode.
func (x *x11Injector) loadMapping() error {
	count := int(x.maxKC) - int(x.minKC) + 1
	if count <= 0 || count > 256 {
		return fmt.Errorf("keycode range %d..%d is invalid", x.minKC, x.maxKC)
	}
	reply, err := xproto.GetKeyboardMapping(x.c, x.minKC, byte(count)).Reply()
	if err != nil {
		return fmt.Errorf("GetKeyboardMapping: %w", err)
	}
	x.perKC = int(reply.KeysymsPerKeycode)
	if x.perKC == 0 || len(reply.Keysyms) < count*x.perKC {
		return errors.New("GetKeyboardMapping returned a truncated mapping")
	}
	x.syms = reply.Keysyms
	x.mappingDirty.Store(false)

	x.shiftKC = x.findKeycode(xkShiftL, -1)
	if x.shiftKC == 0 {
		x.shiftKC = x.findKeycode(xkShiftR, -1)
	}
	// Verify earlier remaps, then collect keycodes with no symbols at all.
	for ks, kc := range x.remapped {
		if x.keysymAt(kc, 0) != xproto.Keysym(ks) {
			delete(x.remapped, ks)
			delete(x.remapKeys, kc)
		}
	}
	x.spare = x.spare[:0]
	for kc := int(x.maxKC); kc >= int(x.minKC); kc-- {
		if _, ours := x.remapKeys[xproto.Keycode(kc)]; ours {
			continue
		}
		empty := true
		for col := 0; col < x.perKC; col++ {
			if x.keysymAt(xproto.Keycode(kc), col) != 0 {
				empty = false
				break
			}
		}
		if empty {
			x.spare = append(x.spare, xproto.Keycode(kc))
		}
	}
	x.spareNext = 0
	return nil
}

func (x *x11Injector) keysymAt(kc xproto.Keycode, col int) xproto.Keysym {
	i := (int(kc)-int(x.minKC))*x.perKC + col
	if i < 0 || i >= len(x.syms) {
		return 0
	}
	return x.syms[i]
}

// findKeycode returns the keycode carrying keysym in column col, or in any
// column when col is -1 (lowest column wins). 0 means not found.
func (x *x11Injector) findKeycode(keysym uint32, col int) xproto.Keycode {
	ks := xproto.Keysym(keysym)
	if col >= 0 {
		for kc := int(x.minKC); kc <= int(x.maxKC); kc++ {
			if x.keysymAt(xproto.Keycode(kc), col) == ks {
				return xproto.Keycode(kc)
			}
		}
		return 0
	}
	for c := 0; c < x.perKC; c++ {
		if kc := x.findKeycode(keysym, c); kc != 0 {
			return kc
		}
	}
	return 0
}

// resolve finds how to type keysym: which keycode and which modifier
// keycodes must be held. Only the first two columns of the core mapping are
// trusted: column 0 is the base level and column 1 the shifted one on every
// server, whereas what follows differs (XKB exports the second *group*
// there, legacy xmodmap layouts the Mode_switch level), so a keysym found
// only further right is typed through a spare keycode instead of guessing
// which modifier reaches it.
func (x *x11Injector) resolve(keysym uint32) (xproto.Keycode, []xproto.Keycode, error) {
	if x.mappingDirty.Load() {
		if err := x.loadMapping(); err != nil {
			return 0, nil, err
		}
	}
	if kc, ok := x.remapped[keysym]; ok {
		return kc, nil, nil
	}
	if kc := x.findKeycode(keysym, 0); kc != 0 {
		return kc, nil, nil
	}
	if x.perKC > 1 && x.shiftKC != 0 {
		if kc := x.findKeycode(keysym, 1); kc != 0 {
			return kc, []xproto.Keycode{x.shiftKC}, nil
		}
	}
	kc, err := x.remap(keysym)
	return kc, nil, err
}

// remap binds keysym to a spare keycode (round robin over the spares, so a
// long paste of exotic characters keeps cycling instead of running out).
func (x *x11Injector) remap(keysym uint32) (xproto.Keycode, error) {
	if len(x.spare) == 0 {
		return 0, fmt.Errorf("no spare keycode to type keysym 0x%x", keysym)
	}
	kc := x.spare[x.spareNext%len(x.spare)]
	x.spareNext++
	if old, ok := x.remapKeys[kc]; ok {
		delete(x.remapped, old)
	}
	row := make([]xproto.Keysym, x.perKC)
	row[0] = xproto.Keysym(keysym)
	if x.perKC > 1 {
		row[1] = xproto.Keysym(keysym)
	}
	if err := xproto.ChangeKeyboardMappingChecked(x.c, 1, kc, byte(x.perKC), row).Check(); err != nil {
		return 0, fmt.Errorf("ChangeKeyboardMapping: %w", err)
	}
	// Keep our copy in step so the MappingNotify this triggers does not
	// make loadMapping() forget the binding.
	base := (int(kc) - int(x.minKC)) * x.perKC
	copy(x.syms[base:base+x.perKC], row)
	x.remapped[keysym] = kc
	x.remapKeys[kc] = keysym
	x.mappingDirty.Store(false)
	return kc, nil
}

func (x *x11Injector) close() {
	for kc := range x.held {
		x.fakeKey(kc, false)
	}
	for kc := range x.remapKeys {
		xproto.ChangeKeyboardMapping(x.c, 1, kc, byte(x.perKC), make([]xproto.Keysym, x.perKC))
	}
	x.c.Sync()
	x.c.Close()
}

// ---- pointer ----

func (x *x11Injector) setMonitor(m monitor) {
	x.mon = m
	x.origin = m.Bounds.Min
	x.acc.reset()
	// The session calls this whenever the display geometry changes, which
	// is also when the root window may have been resized by RandR; the
	// clamp must follow or the far edge of a grown screen is unreachable.
	if g, err := xproto.GetGeometry(x.c, xproto.Drawable(x.root)).Reply(); err == nil && g.Width > 0 && g.Height > 0 {
		x.screen = image.Rect(0, 0, int(g.Width), int(g.Height))
	}
	if !x.xin {
		return
	}
	// kbinani reports monitors relative to Xinerama screen 0; XTEST wants
	// root-window coordinates, which differ when screen 0 is not at the
	// root origin.
	reply, err := xinerama.QueryScreens(x.c).Reply()
	if err != nil || int(reply.Number) == 0 {
		return
	}
	if m.Index < len(reply.ScreenInfo) {
		s := reply.ScreenInfo[m.Index]
		x.origin = image.Pt(int(s.XOrg), int(s.YOrg))
	} else {
		p := reply.ScreenInfo[0]
		x.origin = m.Bounds.Min.Add(image.Pt(int(p.XOrg), int(p.YOrg)))
	}
}

func (x *x11Injector) rootPoint(px, py int) (int16, int16) {
	rx := clampInt(float64(x.origin.X+px), 0, max(0, x.screen.Dx()-1))
	ry := clampInt(float64(x.origin.Y+py), 0, max(0, x.screen.Dy()-1))
	return int16(min(rx, math.MaxInt16)), int16(min(ry, math.MaxInt16))
}

func (x *x11Injector) fake(typ byte, detail byte, rx, ry int16) error {
	return xtest.FakeInputChecked(x.c, typ, detail, 0, x.root, rx, ry, 0).Check()
}

func (x *x11Injector) mouseMove(px, py int) error {
	rx, ry := x.rootPoint(px, py)
	return x.fake(xproto.MotionNotify, 0, rx, ry)
}

func (x *x11Injector) mouseButton(button int, down bool, px, py int) error {
	var detail byte
	switch button {
	case buttonLeft:
		detail = xButtonLeft
	case buttonMiddle:
		detail = xButtonMiddle
	case buttonRight:
		detail = xButtonRight
	default:
		return fmt.Errorf("unknown mouse button %d", button)
	}
	if err := x.mouseMove(px, py); err != nil {
		return err
	}
	typ := byte(xproto.ButtonRelease)
	if down {
		typ = xproto.ButtonPress
	}
	return x.fake(typ, detail, 0, 0)
}

func (x *x11Injector) wheel(dx, dy float64, px, py int) error {
	nx, ny := x.acc.add(dx, dy)
	if nx == 0 && ny == 0 {
		return nil
	}
	if err := x.mouseMove(px, py); err != nil {
		return err
	}
	click := func(button byte, n int) error {
		for i := 0; i < n; i++ {
			if err := x.fake(xproto.ButtonPress, button, 0, 0); err != nil {
				return err
			}
			if err := x.fake(xproto.ButtonRelease, button, 0, 0); err != nil {
				return err
			}
		}
		return nil
	}
	if ny > 0 {
		if err := click(xButtonWheelDown, ny); err != nil {
			return err
		}
	} else if ny < 0 {
		if err := click(xButtonWheelUp, -ny); err != nil {
			return err
		}
	}
	if nx > 0 {
		return click(xButtonWheelRight, nx)
	} else if nx < 0 {
		return click(xButtonWheelLeft, -nx)
	}
	return nil
}

// ---- keyboard ----

func (x *x11Injector) fakeKey(kc xproto.Keycode, down bool) error {
	typ := byte(xproto.KeyRelease)
	if down {
		typ = xproto.KeyPress
	}
	err := x.fake(typ, byte(kc), 0, 0)
	if err == nil {
		if down {
			x.held[kc] = true
		} else {
			delete(x.held, kc)
		}
	}
	return err
}

// key handles a viewer keydown/keyup. Physical codes go through the table
// and are pressed bare: the viewer sends its own Shift/AltGr presses. An
// unknown code with a printable key is typed by character, adding the
// modifiers the layout needs unless the viewer already holds them.
func (x *x11Injector) key(code, key string, down bool) error {
	if x.mappingDirty.Load() {
		if err := x.loadMapping(); err != nil {
			return err
		}
	}
	if d, ok := keymap[code]; ok {
		kc := x.findKeycode(d.keysym, -1)
		if kc == 0 {
			// The layout has no such key (a Cyrillic layout lacks "a"):
			// bind it to a spare keycode so the physical key still works.
			var err error
			if kc, err = x.remap(d.keysym); err != nil {
				return err
			}
		}
		return x.fakeKey(kc, down)
	}
	r, ok := printableKey(key)
	if !ok {
		return fmt.Errorf("unknown key %q", code)
	}
	return x.typeKeysym(runeKeysym(r), down)
}

// typeKeysym presses (or releases) whatever produces keysym, wrapping it in
// the modifiers resolve() asked for. Modifiers already held (by the viewer
// or by an earlier auto-press) are not pressed again.
func (x *x11Injector) typeKeysym(keysym uint32, down bool) error {
	kc, mods, err := x.resolve(keysym)
	if err != nil {
		return err
	}
	if !down {
		err := x.fakeKey(kc, false)
		for _, m := range x.autoMods[kc] {
			x.fakeKey(m, false)
		}
		delete(x.autoMods, kc)
		return err
	}
	var added []xproto.Keycode
	for _, m := range mods {
		if x.held[m] {
			continue
		}
		if err := x.fakeKey(m, true); err != nil {
			return err
		}
		added = append(added, m)
	}
	x.autoMods[kc] = added
	return x.fakeKey(kc, true)
}

// paste types text character by character. Control characters that mean
// something on a keyboard (newline, tab) become the matching key; the rest
// are skipped rather than injected as garbage.
func (x *x11Injector) paste(text string) error {
	prev := rune(0)
	for _, r := range text {
		var keysym uint32
		switch {
		case r == '\n' && prev == '\r':
			prev = r
			continue // CRLF is one Enter
		case r == '\n' || r == '\r':
			keysym = xkReturn
		case r == '\t':
			keysym = xkTab
		case r < 0x20 || (r >= 0x7f && r < 0xa0):
			prev = r
			continue
		default:
			keysym = runeKeysym(r)
		}
		prev = r
		if err := x.typeKeysym(keysym, true); err != nil {
			return err
		}
		if err := x.typeKeysym(keysym, false); err != nil {
			return err
		}
	}
	return nil
}

// ctrlAltDel has no X11 equivalent (the SAS is a Windows concept); the
// request is accepted and ignored so the viewer button is harmless.
func (x *x11Injector) ctrlAltDel() error { return nil }
