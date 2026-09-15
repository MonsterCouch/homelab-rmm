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

// wheelPixelsPerNotch is the browser deltaY that equals one wheel notch.
// Chrome reports 100 per notch, Firefox less; accumulating remainders lets
// trackpads that send tiny deltas still scroll.
const wheelPixelsPerNotch = 100

// wheelAccumulator turns pixel deltas into whole notches, carrying the
// remainder between events. Positive results mean right / down, matching
// the browser's sign convention; the platform code flips as needed.
type wheelAccumulator struct {
	x, y float64
}

func (a *wheelAccumulator) add(dx, dy float64) (nx, ny int) {
	if math.IsNaN(dx) || math.IsInf(dx, 0) {
		dx = 0
	}
	if math.IsNaN(dy) || math.IsInf(dy, 0) {
		dy = 0
	}
	// A single event never scrolls more than a screenful of notches: a
	// hostile viewer could otherwise queue thousands of wheel clicks.
	dx = math.Max(-20*wheelPixelsPerNotch, math.Min(20*wheelPixelsPerNotch, dx))
	dy = math.Max(-20*wheelPixelsPerNotch, math.Min(20*wheelPixelsPerNotch, dy))
	a.x += dx
	a.y += dy
	nx = int(a.x / wheelPixelsPerNotch)
	ny = int(a.y / wheelPixelsPerNotch)
	a.x -= float64(nx) * wheelPixelsPerNotch
	a.y -= float64(ny) * wheelPixelsPerNotch
	return nx, ny
}

// reset drops any carried remainder (used when the pointer changes
// direction after a pause so stale fractions do not fire later).
func (a *wheelAccumulator) reset() { a.x, a.y = 0, 0 }
