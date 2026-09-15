package desktop

import (
	"regexp"
	"testing"
)

// W3C "code" values are PascalCase identifiers: a letter followed by letters
// and digits, nothing else.
var codeSyntax = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)

func TestKeymapNamesAreW3CCodes(t *testing.T) {
	for name, d := range keymap {
		if !codeSyntax.MatchString(name) {
			t.Errorf("%q is not a valid W3C code", name)
		}
		if d.vk == 0 {
			t.Errorf("%s has no virtual key", name)
		}
		if d.keysym == 0 {
			t.Errorf("%s has no keysym", name)
		}
	}
}

func TestKeymapEssentials(t *testing.T) {
	essentials := []string{
		"KeyA", "KeyZ", "Digit0", "Digit9", "F1", "F12", "F24",
		"Enter", "Escape", "Backspace", "Tab", "Space",
		"Minus", "Equal", "BracketLeft", "BracketRight", "Backslash", "Semicolon", "Quote",
		"Backquote", "Comma", "Period", "Slash", "IntlBackslash",
		"CapsLock", "ShiftLeft", "ShiftRight", "ControlLeft", "ControlRight",
		"AltLeft", "AltRight", "MetaLeft", "MetaRight", "ContextMenu",
		"ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Home", "End", "PageUp", "PageDown",
		"Insert", "Delete", "PrintScreen", "ScrollLock", "Pause", "NumLock",
		"Numpad0", "Numpad9", "NumpadAdd", "NumpadSubtract", "NumpadMultiply", "NumpadDivide",
		"NumpadDecimal", "NumpadEnter",
		"AudioVolumeMute", "AudioVolumeDown", "AudioVolumeUp",
	}
	for _, name := range essentials {
		if _, ok := keymap[name]; !ok {
			t.Errorf("keymap lacks %s", name)
		}
	}
	// Spot-check values that are easy to get wrong.
	checks := map[string]keyDef{
		"KeyA":         {vk: 0x41, keysym: 'a'},
		"Digit1":       {vk: 0x31, keysym: '1'},
		"Enter":        {vk: 0x0D, keysym: 0xff0d},
		"NumpadEnter":  {vk: 0x0D, keysym: 0xff8d, extended: true},
		"ArrowLeft":    {vk: 0x25, keysym: 0xff51, extended: true},
		"ControlRight": {vk: 0xA3, keysym: 0xffe4, extended: true},
		"ControlLeft":  {vk: 0xA2, keysym: 0xffe3},
		"Numpad5":      {vk: 0x65, keysym: 0xffb5},
		"F12":          {vk: 0x7B, keysym: 0xffc9},
		"Delete":       {vk: 0x2E, keysym: 0xffff, extended: true},
	}
	for name, want := range checks {
		if got := keymap[name]; got != want {
			t.Errorf("%s = %+v want %+v", name, got, want)
		}
	}
	// The extended set from the Windows docs: right ctrl/alt, the
	// navigation cluster, numpad divide/enter, print screen, numlock.
	for _, name := range []string{"ControlRight", "AltRight", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight",
		"Insert", "Delete", "Home", "End", "PageUp", "PageDown", "NumpadDivide", "NumpadEnter", "PrintScreen", "NumLock"} {
		if !keymap[name].extended {
			t.Errorf("%s must be an extended key", name)
		}
	}
	for _, name := range []string{"ShiftRight", "ShiftLeft", "ControlLeft", "AltLeft", "Numpad7", "Enter"} {
		if keymap[name].extended {
			t.Errorf("%s must not be an extended key", name)
		}
	}
}

func TestPrintableKey(t *testing.T) {
	for key, want := range map[string]rune{"a": 'a', "A": 'A', "€": '€', "ü": 'ü', " ": ' ', "😀": '😀'} {
		r, ok := printableKey(key)
		if !ok || r != want {
			t.Errorf("printableKey(%q) = %q,%v", key, r, ok)
		}
	}
	for _, key := range []string{"", "Shift", "Dead", "Unidentified", "\n", "\x7f", "ab"} {
		if _, ok := printableKey(key); ok {
			t.Errorf("printableKey(%q) accepted", key)
		}
	}
}

func TestRuneKeysym(t *testing.T) {
	cases := map[rune]uint32{'a': 0x61, 'A': 0x41, ' ': 0x20, 'ü': 0xfc, '€': 0x0100_20ac, 'Ж': 0x0100_0416, '😀': 0x0101_f600}
	for r, want := range cases {
		if got := runeKeysym(r); got != want {
			t.Errorf("runeKeysym(%q) = %#x want %#x", r, got, want)
		}
	}
}
