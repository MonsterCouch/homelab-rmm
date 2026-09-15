package desktop

import (
	"image"
	"math"
)

// viewerMsg is every JSON message the viewer may send, decoded leniently:
// numeric fields are float64 so a viewer that forwards fractional mouse
// coordinates or wheel deltas (browsers produce both) is not rejected, and
// the values are clamped before they reach the OS.
type viewerMsg struct {
	T      string  `json:"t"`
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Button float64 `json:"button"`
	DX     float64 `json:"dx"`
	DY     float64 `json:"dy"`
	Code   string  `json:"code"`
	Key    string  `json:"key"`
	Ctrl   bool    `json:"ctrl"`
	Alt    bool    `json:"alt"`
	Shift  bool    `json:"shift"`
	Meta   bool    `json:"meta"`
	Text   string  `json:"text"`
	Index  float64 `json:"index"`
	Q      float64 `json:"q"`
	Frame  float64 `json:"frame"`

	// mon is set on the internal message the capture loop queues when the
	// current monitor changes, so the injector learns the new origin in
	// order with the input events around it.
	mon *monitor
}

// Viewer message types.
const (
	msgMouseMove  = "mousemove"
	msgMouseDown  = "mousedown"
	msgMouseUp    = "mouseup"
	msgWheel      = "wheel"
	msgKeyDown    = "keydown"
	msgKeyUp      = "keyup"
	msgPaste      = "paste"
	msgMonitor    = "monitor"
	msgQuality    = "quality"
	msgRefresh    = "refresh"
	msgAck        = "ack"
	msgCtrlAltDel = "ctrlaltdel"
)

// Mouse buttons as the viewer numbers them.
const (
	buttonLeft   = 0
	buttonMiddle = 1
	buttonRight  = 2
)

// Bounds on what the viewer may ask for.
const (
	maxPasteLen = 64 << 10 // runes typed per paste message
	minQuality  = 1
	maxQuality  = 100
)

// injector is the platform input backend. All methods are called from one
// goroutine (the input loop) that is locked to its OS thread, so
// implementations may keep thread-affine state (X connection, thread
// desktop handle) without locking.
type injector interface {
	// setMonitor tells the injector which monitor viewer coordinates refer
	// to; x/y in every later call are relative to its top-left corner.
	setMonitor(m monitor)
	mouseMove(x, y int) error
	mouseButton(button int, down bool, x, y int) error
	// wheel receives browser deltas in pixels (dy > 0 scrolls down).
	wheel(dx, dy float64, x, y int) error
	key(code, key string, down bool) error
	paste(text string) error
	ctrlAltDel() error
	close()
}

// clampPoint converts viewer coordinates into a pixel inside the monitor.
// Out-of-range values (a viewer bug, or a hostile client) land on the nearest
// edge instead of escaping to another monitor.
func clampPoint(x, y float64, bounds image.Rectangle) (int, int) {
	w, h := bounds.Dx(), bounds.Dy()
	if w <= 0 || h <= 0 {
		return 0, 0
	}
	return clampInt(x, 0, w-1), clampInt(y, 0, h-1)
}

// clampInt rounds v and confines it to [lo, hi]; NaN and infinities map to
// lo because they cannot be trusted at all.
func clampInt(v float64, lo, hi int) int {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return lo
	}
	i := int(math.Round(v))
	if i < lo {
		return lo
	}
	if i > hi {
		return hi
	}
	return i
}

// wheelPixelsPerNotch is the browser deltaY the protocol defines as one
// wheel notch. Browsers disagree about what a notch is worth: Chrome on
// Windows sends 120, Chrome on Linux 100 or 53, Firefox in line mode a
// multiple of the line height. Anything inside [wheelNotchMin,
// wheelNotchMax] is therefore taken to *mean* one notch whatever its
// magnitude, and only the smaller deltas a trackpad produces are
// accumulated. Without that window a 120 px browser double-scrolls every
// fifth notch (the carried 20 px reach 100) and a 57 px one swallows every
// other notch.
const (
	wheelPixelsPerNotch = 100
	wheelNotchMin       = 40
	wheelNotchMax       = 200
)

// wheelAccumulator turns pixel deltas into whole notches, carrying the
// remainder of sub-notch (trackpad) deltas between events. Positive results
// mean right / down, matching the browser's sign convention; the platform
// code flips as needed.
type wheelAccumulator struct {
	x, y float64
}

func (a *wheelAccumulator) add(dx, dy float64) (nx, ny int) {
	nx, a.x = notches(dx, a.x)
	ny, a.y = notches(dy, a.y)
	return nx, ny
}

// notches converts one axis of one wheel event into whole notches, given
// (and returning) the remainder carried from earlier events on that axis.
func notches(d, carry float64) (n int, rest float64) {
	if math.IsNaN(d) || math.IsInf(d, 0) {
		return 0, carry
	}
	// A single event never scrolls more than a screenful of notches: a
	// hostile viewer could otherwise queue thousands of wheel clicks.
	d = math.Max(-20*wheelPixelsPerNotch, math.Min(20*wheelPixelsPerNotch, d))
	if abs := math.Abs(d); abs >= wheelNotchMin && abs <= wheelNotchMax {
		// One deliberate notch from a mouse wheel. It is authoritative, so
		// any trackpad remainder is dropped rather than added to it.
		if d < 0 {
			return -1, 0
		}
		return 1, 0
	}
	carry += d
	n = int(carry / wheelPixelsPerNotch)
	return n, carry - float64(n)*wheelPixelsPerNotch
}

// reset drops any carried remainder (used when the pointer changes
// direction after a pause so stale fractions do not fire later).
func (a *wheelAccumulator) reset() { a.x, a.y = 0, 0 }
