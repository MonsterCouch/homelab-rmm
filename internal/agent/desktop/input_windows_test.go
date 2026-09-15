//go:build windows

package desktop

import (
	"runtime"
	"testing"
	"unsafe"
)

// The INPUT layout is the classic SendInput bug: the union must be 8-byte
// aligned on 64-bit Windows, giving 40 bytes, not 36.
func TestInputStructLayout(t *testing.T) {
	var in input
	want := uintptr(28)
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		want = 40
	}
	if got := unsafe.Sizeof(in); got != want {
		t.Fatalf("sizeof(INPUT) = %d want %d", got, want)
	}
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		if unsafe.Sizeof(mouseInput{}) != 32 || unsafe.Sizeof(keybdInput{}) != 24 {
			t.Fatalf("MOUSEINPUT=%d KEYBDINPUT=%d", unsafe.Sizeof(mouseInput{}), unsafe.Sizeof(keybdInput{}))
		}
		if unsafe.Offsetof(in.mi) != 8 {
			t.Fatalf("union offset %d want 8", unsafe.Offsetof(in.mi))
		}
	}
	ki := in.keyboard()
	if unsafe.Pointer(ki) != unsafe.Pointer(&in.mi) {
		t.Fatal("keyboard view must overlay the union")
	}
}

func TestKeyInputFlags(t *testing.T) {
	up := keyInput(keymap["ArrowLeft"], false)
	ki := up.keyboard()
	if ki.flags&keyEventKeyUp == 0 {
		t.Fatal("keyup flag missing")
	}
	if ki.flags&keyEventScanCode != 0 && ki.flags&keyEventExtendedKey == 0 {
		t.Fatal("ArrowLeft by scan code must be extended")
	}
	pause := keyInput(keymap["Pause"], true)
	if pause.keyboard().flags&keyEventScanCode != 0 {
		t.Fatal("Pause must go by virtual key")
	}
	ins := unicodeInputs(nil, '😀', true)
	if len(ins) != 2 || ins[0].keyboard().flags != keyEventUnicode || ins[0].keyboard().scan != 0xD83D || ins[1].keyboard().scan != 0xDE00 {
		t.Fatalf("surrogates: %+v", ins)
	}
}
