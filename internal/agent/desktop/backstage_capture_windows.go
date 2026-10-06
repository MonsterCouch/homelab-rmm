//go:build windows

package desktop

import (
	"errors"
	"fmt"
	"image"
	"sync"
	"unsafe"
)

// Off-screen compositing of the backstage desktop.
//
// A desktop other than the input desktop is not on any display, so there is
// nothing to BitBlt from. Instead every top-level window is asked to paint
// itself (PrintWindow) into a private memory DC, and those images are
// stacked bottom-to-top into a frame-sized DIB. No DC belonging to a display
// is requested anywhere: the memory DCs are made with CreateCompatibleDC(0)
// and backed by CreateDIBSection, which hands back the pixel pointer
// directly.
//
// (The brief suggested CreateCompatibleBitmap + GetDIBits. CreateCompatibleBitmap
// on a memory DC yields a 1-bit monochrome bitmap, and getting a colour one
// needs the display's DC, which this code must never ask for. A 32-bit
// DIB section is colour, top-down, and readable in place, so GetDIBits would
// only add a copy.)

const (
	pwRenderFullContent = 0x2        // PW_RENDERFULLCONTENT (winuser.h)
	srcCopy             = 0x00CC0020 // SRCCOPY (wingdi.h)
	biRGB               = 0          // BI_RGB
	dibRGBColors        = 0          // DIB_RGB_COLORS

	// maxBackstageDim / maxBackstagePixels bound allocation from a corrupt
	// metrics answer.
	maxBackstageDim    = 16384
	maxBackstagePixels = 64 << 20

	// backstageBG is the empty-desktop colour (BGRA in memory: B,G,R,A).
	backstageBG = 0xFF2B2B2B
)

// bitmapInfoHeader is BITMAPINFOHEADER (wingdi.h), 40 bytes.
type bitmapInfoHeader struct {
	size          uint32
	width         int32
	height        int32 // negative: top-down rows
	planes        uint16
	bitCount      uint16
	compression   uint32
	sizeImage     uint32
	xPelsPerMeter int32
	yPelsPerMeter int32
	clrUsed       uint32
	clrImportant  uint32
}

// dibSurface is a memory DC with a 32-bit top-down DIB section selected in.
type dibSurface struct {
	dc, bmp, old uintptr
	bits         unsafe.Pointer
	w, h         int
}

func newDIBSurface(w, h int) (*dibSurface, error) {
	if w <= 0 || h <= 0 || w > maxBackstageDim || h > maxBackstageDim || w*h > maxBackstagePixels {
		return nil, fmt.Errorf("backstage surface %dx%d out of range", w, h)
	}
	// CreateCompatibleDC(NULL): a memory DC, not a display DC.
	dc, _, err := procCreateCompatibleDCBS.Call(0)
	if dc == 0 {
		return nil, fmt.Errorf("CreateCompatibleDC: %w", err)
	}
	bi := bitmapInfoHeader{
		size: uint32(unsafe.Sizeof(bitmapInfoHeader{})), width: int32(w), height: -int32(h),
		planes: 1, bitCount: 32, compression: biRGB,
	}
	var bits unsafe.Pointer
	// HBITMAP CreateDIBSection(HDC, const BITMAPINFO*, UINT usage, VOID** ppvBits, HANDLE hSection, DWORD offset)
	bmp, _, err := procCreateDIBSectionBS.Call(dc, uintptr(unsafe.Pointer(&bi)), dibRGBColors,
		uintptr(unsafe.Pointer(&bits)), 0, 0)
	if bmp == 0 || bits == nil {
		procDeleteDCBS.Call(dc)
		return nil, fmt.Errorf("CreateDIBSection %dx%d: %w", w, h, err)
	}
	old, _, _ := procSelectObject.Call(dc, bmp)
	return &dibSurface{dc: dc, bmp: bmp, old: old, bits: bits, w: w, h: h}, nil
}

// pixels is the surface as little-endian BGRA words (valid until free()).
func (s *dibSurface) pixels() []uint32 {
	return unsafe.Slice((*uint32)(s.bits), s.w*s.h)
}

func (s *dibSurface) free() {
	if s == nil {
		return
	}
	procSelectObject.Call(s.dc, s.old)
	procDeleteObject.Call(s.bmp)
	procDeleteDCBS.Call(s.dc)
	*s = dibSurface{}
}

// backstageCapturer implements capturer for the backstage desktop.
type backstageCapturer struct {
	d   *backstageDesktop
	ptr *bsPointerPos

	mu      sync.Mutex
	closed  bool
	frame   *dibSurface // the composited desktop
	scratch *dibSurface // one window at a time, grown on demand
}

func newBackstageCapturer(d *backstageDesktop, ptr *bsPointerPos) (*backstageCapturer, error) {
	if d == nil || d.h == 0 {
		return nil, errBackstageClosed
	}
	return &backstageCapturer{d: d, ptr: ptr}, nil
}

// monitors reports one display: the virtual-screen rectangle the backstage
// windows are laid out in. GetSystemMetrics only reads configuration, it does
// not capture anything.
func (c *backstageCapturer) monitors() ([]monitor, error) {
	vx, vy := getSystemMetrics(smXVirtualScreen), getSystemMetrics(smYVirtualScreen)
	vw, vh := getSystemMetrics(smCxVirtualScreen), getSystemMetrics(smCyVirtualScreen)
	if vw <= 0 || vh <= 0 {
		vx, vy, vw, vh = 0, 0, getSystemMetrics(0 /*SM_CXSCREEN*/), getSystemMetrics(1 /*SM_CYSCREEN*/)
	}
	if vw <= 0 || vh <= 0 {
		return nil, errors.New("backstage: the window station reports no screen size")
	}
	if vw > maxBackstageDim || vh > maxBackstageDim || vw*vh > maxBackstagePixels {
		return nil, fmt.Errorf("backstage: virtual screen %dx%d is implausibly large", vw, vh)
	}
	return []monitor{{Index: 0, Bounds: image.Rect(vx, vy, vx+vw, vy+vh), Primary: true}}, nil
}

func (c *backstageCapturer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.frame.free()
	c.scratch.free()
	c.frame, c.scratch = nil, nil
	c.d.release()
	return nil
}

func (c *backstageCapturer) capture(m monitor) (*image.RGBA, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errBackstageClosed
	}
	w, h := m.Bounds.Dx(), m.Bounds.Dy()
	if c.frame == nil || c.frame.w != w || c.frame.h != h {
		c.frame.free()
		f, err := newDIBSurface(w, h)
		if err != nil {
			c.frame = nil
			return nil, err
		}
		c.frame = f
	}
	px := c.frame.pixels()
	for i := range px {
		px[i] = backstageBG
	}

	// EnumDesktopWindows is topmost-first; paint back to front.
	wins := c.d.topLevelWindows()
	for i := len(wins) - 1; i >= 0; i-- {
		c.paintWindow(wins[i], m.Bounds.Min)
	}
	procGdiFlushBS.Call() // make sure queued GDI drawing has reached the DIB bits

	img := image.NewRGBA(image.Rect(0, 0, w, h))
	bgraToRGBA(img.Pix, px)
	if cx, cy := c.ptr.get(); cx >= 0 && cy >= 0 && cx < w && cy < h {
		backstageCursor.draw(img, cx, cy)
	}
	return img, nil
}

// paintWindow renders one top-level window into the frame at its position.
// Windows that cannot be painted (hung, zero-sized, PrintWindow refusing) are
// skipped; the desktop background shows through instead.
func (c *backstageCapturer) paintWindow(hwnd uintptr, origin image.Point) {
	if !bsShown(hwnd) || bsBool(procIsHungAppWindowBS, hwnd) {
		return // IsHungAppWindow: PrintWindow would block this thread on a stuck app
	}
	rc, ok := bsWindowRect(hwnd)
	if !ok {
		return
	}
	ww, wh := rc.width(), rc.height()
	if ww <= 0 || wh <= 0 || ww > maxBackstageDim || wh > maxBackstageDim || ww*wh > maxBackstagePixels {
		return
	}
	dst := image.Rect(int(rc.left), int(rc.top), int(rc.right), int(rc.bottom)).Sub(origin)
	if !dst.Overlaps(image.Rect(0, 0, c.frame.w, c.frame.h)) {
		return
	}
	if c.scratch == nil || c.scratch.w < ww || c.scratch.h < wh {
		nw, nh := ww, wh
		if c.scratch != nil {
			nw, nh = max(nw, c.scratch.w), max(nh, c.scratch.h)
			c.scratch.free()
		}
		s, err := newDIBSurface(nw, nh)
		if err != nil {
			c.scratch = nil
			return
		}
		c.scratch = s
	}
	// BOOL PrintWindow(HWND, HDC hdcBlt, UINT nFlags): the window paints
	// itself, non-client area included, at the DC origin.
	if r, _, _ := procPrintWindowBS.Call(hwnd, c.scratch.dc, pwRenderFullContent); r == 0 {
		return
	}
	procBitBltBS.Call(c.frame.dc, uintptr(dst.Min.X), uintptr(dst.Min.Y), uintptr(ww), uintptr(wh),
		c.scratch.dc, 0, 0, srcCopy)
}

// bgraToRGBA converts the DIB's little-endian BGRA words into RGBA bytes and
// forces opaque alpha (PrintWindow leaves alpha at 0 for many windows).
func bgraToRGBA(dst []byte, src []uint32) {
	for i, v := range src {
		o := i * 4
		dst[o] = byte(v >> 16)
		dst[o+1] = byte(v >> 8)
		dst[o+2] = byte(v)
		dst[o+3] = 0xFF
	}
}

// ---- software cursor ----

// backstageArrow is the classic 12x19 arrow: X is the black outline, . the
// white fill.
var backstageArrow = [...]string{
	"X           ",
	"XX          ",
	"X.X         ",
	"X..X        ",
	"X...X       ",
	"X....X      ",
	"X.....X     ",
	"X......X    ",
	"X.......X   ",
	"X........X  ",
	"X.....XXXXX ",
	"X..X..X     ",
	"X.X X..X    ",
	"XX  X..X    ",
	"X    X..X   ",
	"     X..X   ",
	"      X..X  ",
	"      X..X  ",
	"       XX   ",
}

// backstageCursor is the arrow as a pointerColor shape so the shared,
// unit-tested compositor in cursor.go draws it.
var backstageCursor = func() *pointerShape {
	const w, h = 12, 19
	data := make([]byte, w*h*4) // B,G,R,A
	for y, row := range backstageArrow {
		for x := 0; x < w; x++ {
			o := (y*w + x) * 4
			switch row[x] {
			case 'X':
				data[o+3] = 0xFF
			case '.':
				data[o], data[o+1], data[o+2], data[o+3] = 0xFF, 0xFF, 0xFF, 0xFF
			}
		}
	}
	return newPointerShape(pointerColor, w, h, w*4, 0, 0, data)
}()
