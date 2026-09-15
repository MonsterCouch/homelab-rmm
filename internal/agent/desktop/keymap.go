package desktop

// keyDef describes one physical key as both platforms need it: the Windows
// virtual-key code (sent through SendInput as a scan code obtained from
// MapVirtualKey) and the X11 keysym (resolved to a keycode through the
// server's keyboard mapping). extended marks the keys whose PC scan code
// carries the 0xE0 prefix, which SendInput must be told about explicitly or
// the arrows become keypad digits.
type keyDef struct {
	vk       uint16
	keysym   uint32
	extended bool
}

// Windows virtual-key codes used below (winuser.h).
const (
	vkBack       = 0x08
	vkTab        = 0x09
	vkReturn     = 0x0D
	vkPause      = 0x13
	vkCapital    = 0x14
	vkEscape     = 0x1B
	vkSpace      = 0x20
	vkPrior      = 0x21
	vkNext       = 0x22
	vkEnd        = 0x23
	vkHome       = 0x24
	vkLeft       = 0x25
	vkUp         = 0x26
	vkRight      = 0x27
	vkDown       = 0x28
	vkSnapshot   = 0x2C
	vkInsert     = 0x2D
	vkDelete     = 0x2E
	vkLWin       = 0x5B
	vkRWin       = 0x5C
	vkApps       = 0x5D
	vkNumpad0    = 0x60
	vkMultiply   = 0x6A
	vkAdd        = 0x6B
	vkSubtract   = 0x6D
	vkDecimal    = 0x6E
	vkDivide     = 0x6F
	vkF1         = 0x70
	vkNumLock    = 0x90
	vkScroll     = 0x91
	vkLShift     = 0xA0
	vkRShift     = 0xA1
	vkLControl   = 0xA2
	vkRControl   = 0xA3
	vkLMenu      = 0xA4
	vkRMenu      = 0xA5
	vkVolMute    = 0xAD
	vkVolDown    = 0xAE
	vkVolUp      = 0xAF
	vkMediaNext  = 0xB0
	vkMediaPrev  = 0xB1
	vkMediaStop  = 0xB2
	vkMediaPlay  = 0xB3
	vkOem1       = 0xBA // ;:
	vkOemPlus    = 0xBB // =+
	vkOemComma   = 0xBC // ,<
	vkOemMinus   = 0xBD // -_
	vkOemPeriod  = 0xBE // .>
	vkOem2       = 0xBF // /?
	vkOem3       = 0xC0 // `~
	vkOem4       = 0xDB // [{
	vkOem5       = 0xDC // \|
	vkOem6       = 0xDD // ]}
	vkOem7       = 0xDE // '"
	vkOem102     = 0xE2 // <> on 102-key layouts
	vkSleep      = 0x5F
	vkBrowserBk  = 0xA6
	vkBrowserFwd = 0xA7
)

// X11 keysyms used below (keysymdef.h, XF86keysym.h).
const (
	xkBackSpace     = 0xff08
	xkTab           = 0xff09
	xkReturn        = 0xff0d
	xkPause         = 0xff13
	xkScrollLock    = 0xff14
	xkEscape        = 0xff1b
	xkHome          = 0xff50
	xkLeft          = 0xff51
	xkUp            = 0xff52
	xkRight         = 0xff53
	xkDown          = 0xff54
	xkPrior         = 0xff55
	xkNext          = 0xff56
	xkEnd           = 0xff57
	xkPrint         = 0xff61
	xkInsert        = 0xff63
	xkMenu          = 0xff67
	xkNumLock       = 0xff7f
	xkKPEnter       = 0xff8d
	xkKPMultiply    = 0xffaa
	xkKPAdd         = 0xffab
	xkKPSubtract    = 0xffad
	xkKPDecimal     = 0xffae
	xkKPDivide      = 0xffaf
	xkKP0           = 0xffb0
	xkF1            = 0xffbe
	xkShiftL        = 0xffe1
	xkShiftR        = 0xffe2
	xkControlL      = 0xffe3
	xkControlR      = 0xffe4
	xkCapsLock      = 0xffe5
	xkAltL          = 0xffe9
	xkAltR          = 0xffea
	xkSuperL        = 0xffeb
	xkSuperR        = 0xffec
	xkDelete        = 0xffff
	xkISOLevel3     = 0xfe03
	xkXF86VolDown   = 0x1008ff11
	xkXF86VolMute   = 0x1008ff12
	xkXF86VolUp     = 0x1008ff13
	xkXF86Play      = 0x1008ff14
	xkXF86Stop      = 0x1008ff15
	xkXF86Prev      = 0x1008ff16
	xkXF86Next      = 0x1008ff17
	xkXF86Sleep     = 0x1008ff2f
	xkXF86Back      = 0x1008ff26
	xkXF86Forward   = 0x1008ff27
	xkUnicodePrefix = 0x01000000 // keysym for an arbitrary Unicode code point
)

// keymap maps W3C UI Events "code" values (the physical key, layout
// independent) to both platforms' key identifiers. It is the single source
// of truth for what the viewer may send; both injectors consult it.
var keymap = map[string]keyDef{}

func init() {
	// Letters: VK_A..VK_Z are the ASCII uppercase codes; the X keysym is the
	// lowercase letter (the base, unshifted, level of the key).
	for c := byte('A'); c <= 'Z'; c++ {
		keymap["Key"+string(c)] = keyDef{vk: uint16(c), keysym: uint32(c + 'a' - 'A')}
	}
	for c := byte('0'); c <= '9'; c++ {
		keymap["Digit"+string(c)] = keyDef{vk: uint16(c), keysym: uint32(c)}
		keymap["Numpad"+string(c)] = keyDef{vk: vkNumpad0 + uint16(c-'0'), keysym: xkKP0 + uint32(c-'0')}
	}
	for i := 1; i <= 24; i++ {
		keymap["F"+itoa(i)] = keyDef{vk: vkF1 + uint16(i-1), keysym: xkF1 + uint32(i-1)}
	}
	for name, d := range map[string]keyDef{
		"Enter":     {vk: vkReturn, keysym: xkReturn},
		"Escape":    {vk: vkEscape, keysym: xkEscape},
		"Backspace": {vk: vkBack, keysym: xkBackSpace},
		"Tab":       {vk: vkTab, keysym: xkTab},
		"Space":     {vk: vkSpace, keysym: ' '},

		"Minus":         {vk: vkOemMinus, keysym: '-'},
		"Equal":         {vk: vkOemPlus, keysym: '='},
		"BracketLeft":   {vk: vkOem4, keysym: '['},
		"BracketRight":  {vk: vkOem6, keysym: ']'},
		"Backslash":     {vk: vkOem5, keysym: '\\'},
		"Semicolon":     {vk: vkOem1, keysym: ';'},
		"Quote":         {vk: vkOem7, keysym: '\''},
		"Backquote":     {vk: vkOem3, keysym: '`'},
		"Comma":         {vk: vkOemComma, keysym: ','},
		"Period":        {vk: vkOemPeriod, keysym: '.'},
		"Slash":         {vk: vkOem2, keysym: '/'},
		"IntlBackslash": {vk: vkOem102, keysym: '<'},

		"CapsLock":     {vk: vkCapital, keysym: xkCapsLock},
		"ShiftLeft":    {vk: vkLShift, keysym: xkShiftL},
		"ShiftRight":   {vk: vkRShift, keysym: xkShiftR},
		"ControlLeft":  {vk: vkLControl, keysym: xkControlL},
		"ControlRight": {vk: vkRControl, keysym: xkControlR, extended: true},
		"AltLeft":      {vk: vkLMenu, keysym: xkAltL},
		"AltRight":     {vk: vkRMenu, keysym: xkAltR, extended: true},
		"MetaLeft":     {vk: vkLWin, keysym: xkSuperL, extended: true},
		"MetaRight":    {vk: vkRWin, keysym: xkSuperR, extended: true},
		"ContextMenu":  {vk: vkApps, keysym: xkMenu, extended: true},

		"ArrowUp":    {vk: vkUp, keysym: xkUp, extended: true},
		"ArrowDown":  {vk: vkDown, keysym: xkDown, extended: true},
		"ArrowLeft":  {vk: vkLeft, keysym: xkLeft, extended: true},
		"ArrowRight": {vk: vkRight, keysym: xkRight, extended: true},
		"Home":       {vk: vkHome, keysym: xkHome, extended: true},
		"End":        {vk: vkEnd, keysym: xkEnd, extended: true},
		"PageUp":     {vk: vkPrior, keysym: xkPrior, extended: true},
		"PageDown":   {vk: vkNext, keysym: xkNext, extended: true},
		"Insert":     {vk: vkInsert, keysym: xkInsert, extended: true},
		"Delete":     {vk: vkDelete, keysym: xkDelete, extended: true},

		"PrintScreen": {vk: vkSnapshot, keysym: xkPrint, extended: true},
		"ScrollLock":  {vk: vkScroll, keysym: xkScrollLock},
		"Pause":       {vk: vkPause, keysym: xkPause, extended: true},
		"NumLock":     {vk: vkNumLock, keysym: xkNumLock, extended: true},

		"NumpadAdd":      {vk: vkAdd, keysym: xkKPAdd},
		"NumpadSubtract": {vk: vkSubtract, keysym: xkKPSubtract},
		"NumpadMultiply": {vk: vkMultiply, keysym: xkKPMultiply},
		"NumpadDivide":   {vk: vkDivide, keysym: xkKPDivide, extended: true},
		"NumpadDecimal":  {vk: vkDecimal, keysym: xkKPDecimal},
		"NumpadEnter":    {vk: vkReturn, keysym: xkKPEnter, extended: true},

		"AudioVolumeMute":    {vk: vkVolMute, keysym: xkXF86VolMute, extended: true},
		"AudioVolumeDown":    {vk: vkVolDown, keysym: xkXF86VolDown, extended: true},
		"AudioVolumeUp":      {vk: vkVolUp, keysym: xkXF86VolUp, extended: true},
		"MediaPlayPause":     {vk: vkMediaPlay, keysym: xkXF86Play, extended: true},
		"MediaStop":          {vk: vkMediaStop, keysym: xkXF86Stop, extended: true},
		"MediaTrackPrevious": {vk: vkMediaPrev, keysym: xkXF86Prev, extended: true},
		"MediaTrackNext":     {vk: vkMediaNext, keysym: xkXF86Next, extended: true},
		"BrowserBack":        {vk: vkBrowserBk, keysym: xkXF86Back, extended: true},
		"BrowserForward":     {vk: vkBrowserFwd, keysym: xkXF86Forward, extended: true},
		"Sleep":              {vk: vkSleep, keysym: xkXF86Sleep, extended: true},
	} {
		keymap[name] = d
	}
}

// itoa is strconv.Itoa for small positive numbers without the import in a
// table file.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}

// printableKey returns the single printable rune behind a viewer "key" value
// ("a", "€", "Ü"), or false for named keys ("Shift", "Dead", "Unidentified")
// and control characters. It is the fallback when "code" is unknown.
func printableKey(key string) (rune, bool) {
	runes := []rune(key)
	if len(runes) != 1 {
		return 0, false
	}
	r := runes[0]
	if r < 0x20 || (r >= 0x7f && r < 0xa0) || r == 0xfffd {
		return 0, false
	}
	return r, true
}

// runeKeysym converts a Unicode code point into the X keysym that carries it:
// Latin-1 characters are their own keysym, everything else uses the
// 0x01000000 | codepoint form every modern X server understands.
func runeKeysym(r rune) uint32 {
	if r >= 0x20 && r <= 0x7e || r >= 0xa0 && r <= 0xff {
		return uint32(r)
	}
	return xkUnicodePrefix | uint32(r)
}
