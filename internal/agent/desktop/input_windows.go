//go:build windows

package desktop

import (
	"errors"
	"fmt"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SendInput constants (winuser.h).
const (
	inputMouse    = 0
	inputKeyboard = 1

	mouseEventMove       = 0x0001
	mouseEventLeftDown   = 0x0002
	mouseEventLeftUp     = 0x0004
	mouseEventRightDown  = 0x0008
	mouseEventRightUp    = 0x0010
	mouseEventMiddleDown = 0x0020
	mouseEventMiddleUp   = 0x0040
	mouseEventWheel      = 0x0800
	mouseEventHWheel     = 0x1000
	mouseEventVirtualDsk = 0x4000
	mouseEventAbsolute   = 0x8000
	wheelDelta           = 120

	keyEventExtendedKey = 0x0001
	keyEventKeyUp       = 0x0002
	keyEventUnicode     = 0x0004
	keyEventScanCode    = 0x0008

	mapvkVkToVsc = 0

	smXVirtualScreen  = 76
	smYVirtualScreen  = 77
	smCxVirtualScreen = 78
	smCyVirtualScreen = 79

	// sendInputBatch bounds one SendInput call; long pastes are chunked so
	// a single hostile message cannot ask for a multi-megabyte array.
	sendInputBatch = 128
)

// mouseInput is MOUSEINPUT: 24 bytes on 32-bit, 32 on 64-bit (the pointer
// member forces 8-byte alignment and a 4-byte hole before it).
type mouseInput struct {
	dx        int32
	dy        int32
	mouseData uint32
	flags     uint32
	time      uint32
	extraInfo uintptr
}

// keybdInput is KEYBDINPUT: 16 bytes on 32-bit, 24 on 64-bit. It is written
// over the union area of input, which is sized for the larger MOUSEINPUT.
type keybdInput struct {
	vk        uint16
	scan      uint16
	flags     uint32
	time      uint32
	extraInfo uintptr
}

// input is INPUT: a DWORD type followed by the union. Because mouseInput
// has pointer alignment, Go inserts the same 4-byte hole after typ that the
// C compiler does on 64-bit, giving sizeof 40 (amd64/arm64) and 28 (386/arm).
type input struct {
	typ uint32
	mi  mouseInput
}

func (in *input) keyboard() *keybdInput { return (*keybdInput)(unsafe.Pointer(&in.mi)) }

// winInjector injects through SendInput. All calls come from one thread that
// threadDesktop keeps on the input desktop.
type winInjector struct {
	mon monitor
	acc wheelAccumulator
	// isSystem decides the SendSAS flavour: services call it with
	// AsUser=FALSE, interactive processes with TRUE.
	isSystem bool
}

func newInjector() (injector, error) {
	if err := procSendInput.Find(); err != nil {
		return nil, fmt.Errorf("SendInput unavailable: %w", err)
	}
	return &winInjector{isSystem: currentUserIsSystem()}, nil
}

func (w *winInjector) close() {}

func (w *winInjector) setMonitor(m monitor) {
	w.mon = m
	w.acc.reset()
}

// sendInputs calls SendInput once for the batch and reports a short count as
// an error (UIPI or a desktop we cannot reach).
func sendInputs(ins []input) error {
	if len(ins) == 0 {
		return nil
	}
	n, _, err := procSendInput.Call(uintptr(len(ins)), uintptr(unsafe.Pointer(&ins[0])), unsafe.Sizeof(ins[0]))
	if int(n) != len(ins) {
		if err != nil && err != windows.ERROR_SUCCESS {
			return fmt.Errorf("SendInput inserted %d of %d events: %w", n, len(ins), err)
		}
		return fmt.Errorf("SendInput inserted %d of %d events (input blocked)", n, len(ins))
	}
	return nil
}

func getSystemMetrics(index int) int {
	r, _, _ := procGetSystemMetrics.Call(uintptr(index))
	return int(int32(r))
}

// absoluteMove builds the MOUSEINPUT that puts the pointer on monitor pixel
// (x, y): the virtual screen is the union of all monitors and SendInput
// wants its coordinates normalised to 0..65535. Rounding up makes the
// kernel's (n * width) >> 16 land exactly on the requested pixel.
func (w *winInjector) absoluteMove(x, y int) (mouseInput, error) {
	vx, vy := getSystemMetrics(smXVirtualScreen), getSystemMetrics(smYVirtualScreen)
	vw, vh := getSystemMetrics(smCxVirtualScreen), getSystemMetrics(smCyVirtualScreen)
	if vw <= 0 || vh <= 0 {
		return mouseInput{}, errors.New("virtual screen has no size")
	}
	px := w.mon.Bounds.Min.X + x - vx
	py := w.mon.Bounds.Min.Y + y - vy
	norm := func(p, extent int) int32 {
		if p < 0 {
			p = 0
		}
		if p >= extent {
			p = extent - 1
		}
		n := (p*65536 + extent - 1) / extent
		if n > 65535 {
			n = 65535
		}
		return int32(n)
	}
	return mouseInput{
		dx:    norm(px, vw),
		dy:    norm(py, vh),
		flags: mouseEventMove | mouseEventAbsolute | mouseEventVirtualDsk,
	}, nil
}

func (w *winInjector) mouseMove(x, y int) error {
	mi, err := w.absoluteMove(x, y)
	if err != nil {
		return err
	}
	return sendInputs([]input{{typ: inputMouse, mi: mi}})
}

func (w *winInjector) mouseButton(button int, down bool, x, y int) error {
	var flag uint32
	switch {
	case button == buttonLeft && down:
		flag = mouseEventLeftDown
	case button == buttonLeft:
		flag = mouseEventLeftUp
	case button == buttonMiddle && down:
		flag = mouseEventMiddleDown
	case button == buttonMiddle:
		flag = mouseEventMiddleUp
	case button == buttonRight && down:
		flag = mouseEventRightDown
	case button == buttonRight:
		flag = mouseEventRightUp
	default:
		return fmt.Errorf("unknown mouse button %d", button)
	}
	mi, err := w.absoluteMove(x, y)
	if err != nil {
		return err
	}
	// Move first so the click lands where the viewer's pointer is even
	// if a mousemove was dropped under load.
	return sendInputs([]input{
		{typ: inputMouse, mi: mi},
		{typ: inputMouse, mi: mouseInput{flags: flag}},
	})
}

func (w *winInjector) wheel(dx, dy float64, x, y int) error {
	nx, ny := w.acc.add(dx, dy)
	if nx == 0 && ny == 0 {
		return nil
	}
	mi, err := w.absoluteMove(x, y)
	if err != nil {
		return err
	}
	ins := []input{{typ: inputMouse, mi: mi}}
	if ny != 0 {
		// Browser dy > 0 is "scroll down"; Windows wheel data > 0 is "away
		// from the user" (scroll up), so the sign flips.
		ins = append(ins, input{typ: inputMouse, mi: mouseInput{mouseData: uint32(int32(-ny * wheelDelta)), flags: mouseEventWheel}})
	}
	if nx != 0 {
		ins = append(ins, input{typ: inputMouse, mi: mouseInput{mouseData: uint32(int32(nx * wheelDelta)), flags: mouseEventHWheel}})
	}
	return sendInputs(ins)
}

func (w *winInjector) key(code, key string, down bool) error {
	if d, ok := keymap[code]; ok {
		return sendInputs([]input{keyInput(d, down)})
	}
	if r, ok := printableKey(key); ok {
		return sendInputs(unicodeInputs(nil, r, down))
	}
	return fmt.Errorf("unknown key %q", code)
}

// keyInput builds the INPUT for a physical key. Scan codes are preferred
// over virtual keys because games and low-level hooks only see the former;
// they come from MapVirtualKey so the remote layout decides what the key
// means. Pause has no clean single scan code (E1 1D 45), so it goes by VK.
func keyInput(d keyDef, down bool) input {
	var in input
	in.typ = inputKeyboard
	ki := in.keyboard()
	ki.vk = d.vk
	scan, _, _ := procMapVirtualKeyW.Call(uintptr(d.vk), mapvkVkToVsc)
	if scan != 0 && d.vk != vkPause {
		ki.scan = uint16(scan)
		ki.flags |= keyEventScanCode
		if d.extended {
			ki.flags |= keyEventExtendedKey
		}
	}
	if !down {
		ki.flags |= keyEventKeyUp
	}
	return in
}

// unicodeInputs appends KEYEVENTF_UNICODE events for r (two for a
// supplementary-plane character: Windows expects the UTF-16 surrogates).
func unicodeInputs(ins []input, r rune, down bool) []input {
	var units []uint16
	if r > 0xFFFF {
		hi, lo := utf16.EncodeRune(r)
		units = []uint16{uint16(hi), uint16(lo)}
	} else {
		units = []uint16{uint16(r)}
	}
	for _, u := range units {
		var in input
		in.typ = inputKeyboard
		ki := in.keyboard()
		ki.scan = u
		ki.flags = keyEventUnicode
		if !down {
			ki.flags |= keyEventKeyUp
		}
		ins = append(ins, in)
	}
	return ins
}

// paste types text as Unicode key events, so it works regardless of the
// remote keyboard layout. Newlines become carriage returns, which is what a
// physical Enter delivers.
func (w *winInjector) paste(text string) error {
	var ins []input
	flush := func() error {
		err := sendInputs(ins)
		ins = ins[:0]
		return err
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
		ins = unicodeInputs(ins, r, true)
		ins = unicodeInputs(ins, r, false)
		if len(ins) >= sendInputBatch {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}

// ctrlAltDel asks winlogon for the secure attention sequence. It only works
// when the SoftwareSASGeneration policy allows it; the call is void, so
// failure is silent by design.
func (w *winInjector) ctrlAltDel() error {
	if err := procSendSAS.Find(); err != nil {
		return fmt.Errorf("SendSAS unavailable: %w", err)
	}
	asUser := uintptr(1)
	if w.isSystem {
		asUser = 0
	}
	procSendSAS.Call(asUser)
	return nil
}

// currentUserIsSystem reports whether the process token is LocalSystem.
func currentUserIsSystem() bool {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || u == nil || u.User.Sid == nil {
		return false
	}
	return u.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}
