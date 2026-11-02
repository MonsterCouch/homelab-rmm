//go:build windows

package desktop

import (
	"errors"
	"image"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// dxgiCapturer is the Windows capture backend: DXGI Desktop Duplication with
// the GDI backend (kbinani/screenshot) as the fallback for everything
// duplication cannot do - Session 0, headless VMs without a virtual GPU,
// rotated outputs, the secure desktop behind UAC, an output that keeps
// losing access. It implements capturer, dirtyProvider (driver-supplied
// dirty rectangles replace the CPU tile diff) and frameSource (the VRAM
// frame the H.264 encoder consumes without any readback).
type dxgiCapturer struct {
	gdi screenCapturer

	mu     sync.Mutex // Close may race the session ending
	closed bool
	outs   map[string]*dupState // by device name (\\.\DISPLAY1)

	lastDirty   []image.Rectangle
	lastDirtyOK bool
	backend     string // "dxgi" or "gdi", whichever served the last frame
}

func newDXGICapturer() *dxgiCapturer {
	return &dxgiCapturer{outs: map[string]*dupState{}, backend: "gdi"}
}

// Backend names the engine that served the most recent frame; it is for the
// diagnostics HUD and for logs.
func (c *dxgiCapturer) Backend() string { return c.backend }

// gdiBackoff is how long an output stays on GDI after duplication failed,
// doubling per consecutive failure up to the cap. Retrying is cheap, but
// each failed attempt creates a D3D device, so it is not done every frame.
func gdiBackoff(failures int) time.Duration {
	d := 500 * time.Millisecond << min(max(failures-1, 0), 4)
	return min(d, 8*time.Second)
}

// dupState is everything kept per duplicated output.
type dupState struct {
	info outputInfo
	d    *duplicator

	snap    com // BGRA default texture: the last frame, stable after ReleaseFrame
	staging com // BGRA staging texture for CPU readback

	shadow, view *image.RGBA // shadow: desktop only; view: desktop + cursor
	pending      []image.Rectangle
	fullDirty    bool // the CPU copy must be refreshed completely
	haveSnap     bool
	freshGPU     bool // snap changed since it was last handed to the encoder
	freshCPU     bool // snap changed since it was last read back

	shape      *pointerShape
	px, py     int
	pvisible   bool
	cursorArea image.Rectangle // where the cursor is drawn in view right now

	failures int
	gdiUntil time.Time
}

func (s *dupState) close() {
	s.d.close()
	s.d = nil
	s.snap.release()
	s.staging.release()
	s.haveSnap = false
}

// monitors enumerates displays through DXGI so each one is tied to the
// adapter that owns it; on any trouble it defers to GDI.
func (c *dxgiCapturer) monitors() ([]monitor, error) {
	outs, err := listOutputs()
	if err != nil || len(outs) == 0 {
		if err != nil {
			slog.Debug("desktop: DXGI enumeration failed, using GDI", "err", err)
		}
		return c.gdi.monitors()
	}
	// One display can be listed by two adapters (a hybrid laptop's
	// dGPU passes frames through the iGPU); keep the hardware one.
	byBounds := map[image.Rectangle]outputInfo{}
	for _, o := range outs {
		if prev, ok := byBounds[o.bounds]; ok && !prev.software {
			continue
		}
		byBounds[o.bounds] = o
	}
	uniq := make([]outputInfo, 0, len(byBounds))
	for _, o := range byBounds {
		uniq = append(uniq, o)
	}
	sort.Slice(uniq, func(i, j int) bool {
		a, b := uniq[i].bounds.Min, uniq[j].bounds.Min
		if (a == image.Point{}) != (b == image.Point{}) {
			return a == image.Point{} // the primary first
		}
		if a.X != b.X {
			return a.X < b.X
		}
		return a.Y < b.Y
	})
	if len(uniq) > maxMonitors {
		uniq = uniq[:maxMonitors]
	}
	mons := make([]monitor, len(uniq))
	c.mu.Lock()
	seen := map[string]bool{}
	for i, o := range uniq {
		mons[i] = monitor{Index: i, Bounds: o.bounds}
		seen[o.deviceName] = true
		if st := c.outs[o.deviceName]; st != nil && st.info.bounds != o.bounds {
			st.close() // resolution or layout changed: the duplication is stale
			delete(c.outs, o.deviceName)
		} else if st != nil {
			st.info = o
		}
	}
	for name, st := range c.outs {
		if !seen[name] {
			st.close()
			delete(c.outs, name)
		}
	}
	for _, o := range uniq {
		if c.outs[o.deviceName] == nil {
			c.outs[o.deviceName] = &dupState{info: o, fullDirty: true}
		}
	}
	c.mu.Unlock()
	markPrimary(mons)
	return mons, nil
}

// state finds the per-output state for m.
func (c *dxgiCapturer) state(m monitor) *dupState {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, st := range c.outs {
		if st.info.bounds == m.Bounds {
			return st
		}
	}
	return nil
}

// advance makes sure st has a live duplication and pulls the next desktop
// update into it. fresh reports that new pixels arrived. An error means this
// output cannot be duplicated right now and the caller should use GDI.
func (c *dxgiCapturer) advance(st *dupState, timeoutMs int) (fresh bool, err error) {
	if time.Now().Before(st.gdiUntil) {
		return false, errors.New("duplication backing off")
	}
	if st.d == nil {
		d, err := openDuplicator(st.info)
		if err != nil {
			return false, c.failed(st, err)
		}
		st.d = d
		st.fullDirty = true
		st.haveSnap = false
		slog.Info("desktop: DXGI duplication started", "output", st.info.deviceName, "adapter", st.info.adapterName, "size", st.info.bounds.Size())
	}
	fr, err := st.d.acquire(timeoutMs)
	if err != nil {
		if isHR(err, hrDXGIWaitTimeout) {
			return false, nil
		}
		// ACCESS_LOST is routine (mode change, UAC, lock screen, a
		// full-screen exclusive app); anything else is unexpected. Both
		// end the duplication and re-create it after a pause.
		st.close()
		return false, c.failed(st, err)
	}
	defer fr.close()
	st.failures = 0

	if fr.hasPointerUpdate {
		st.px, st.py, st.pvisible = int(fr.info.PointerX), int(fr.info.PointerY), fr.info.PointerVisible != 0
		if fr.shape != nil {
			st.shape = fr.shape
		}
	}
	if fr.tex.nil() {
		return false, nil // pointer-only update
	}
	if st.snap.nil() {
		// RENDER_TARGET as well as SHADER_RESOURCE: the H.264 encoder's D3D11
		// video processor needs a render-target-capable BGRA input to create
		// an input view directly (some Intel drivers reject a shader-resource-
		// only surface with E_INVALIDARG), which keeps the BGRA->NV12 path
		// zero-copy instead of forcing an extra CopyResource.
		st.snap, err = st.d.dev.createTexture(st.d.w, st.d.h, dxgiFormatB8G8R8A8, d3d11UsageDefault, d3d11BindShaderResource|d3d11BindRenderTarget, 0)
		if err != nil {
			st.close()
			return false, c.failed(st, err)
		}
	}
	st.d.dev.copyResource(st.snap, fr.tex)
	st.d.releaseFrame() // hand the surface back to DWM as soon as it is copied
	st.haveSnap, st.freshGPU, st.freshCPU = true, true, true
	if fr.dirty == nil {
		st.fullDirty = true // new image with no metadata: assume everything changed
	} else if !st.fullDirty {
		st.pending = append(st.pending, fr.dirty...)
		if len(st.pending) > 512 {
			st.pending, st.fullDirty = nil, true
		}
	}
	return true, nil
}

// failed records a duplication failure and starts the GDI backoff.
func (c *dxgiCapturer) failed(st *dupState, err error) error {
	st.failures++
	st.gdiUntil = time.Now().Add(gdiBackoff(st.failures))
	if st.failures == 1 || st.failures%10 == 0 {
		slog.Info("desktop: DXGI duplication unavailable, using GDI", "output", st.info.deviceName, "err", err, "failures", st.failures)
	}
	return err
}

// capture is the CPU path: an RGBA image of the monitor, cursor included.
func (c *dxgiCapturer) capture(m monitor) (*image.RGBA, error) {
	c.lastDirtyOK = false
	st := c.state(m)
	if st == nil {
		c.backend = "gdi"
		return c.gdi.capture(m)
	}
	if _, err := c.advance(st, 50); err != nil || !st.haveSnap || st.d == nil {
		c.backend = "gdi"
		st.fullDirty = true // the CPU copy is no longer maintained
		return c.gdi.capture(m)
	}
	img, err := c.readback(st)
	if err != nil {
		st.close()
		c.failed(st, err)
		c.backend = "gdi"
		return c.gdi.capture(m)
	}
	c.backend = "dxgi"
	return img, nil
}

// readback brings the CPU copy up to date with the snapshot texture, applies
// the cursor and records what changed.
func (c *dxgiCapturer) readback(st *dupState) (*image.RGBA, error) {
	w, h := st.d.w, st.d.h
	full := st.fullDirty || st.shadow == nil || st.shadow.Rect.Dx() != w || st.shadow.Rect.Dy() != h
	if full {
		st.shadow = image.NewRGBA(image.Rect(0, 0, w, h))
		st.view = image.NewRGBA(image.Rect(0, 0, w, h))
		st.cursorArea = image.Rectangle{}
	}
	var changed []image.Rectangle
	if st.freshCPU || full {
		if st.staging.nil() {
			var err error
			st.staging, err = st.d.dev.createTexture(w, h, dxgiFormatB8G8R8A8, d3d11UsageStaging, 0, d3d11CPUAccessRead)
			if err != nil {
				return nil, err
			}
		}
		st.d.dev.copyResource(st.staging, st.snap)
		mp, err := st.d.dev.mapRead(st.staging)
		if err != nil {
			return nil, err
		}
		rects := st.pending
		if full {
			rects = []image.Rectangle{st.shadow.Rect}
		}
		src := unsafeBytes(mp.Data, int(mp.RowPitch)*h)
		for _, r := range rects {
			r = r.Intersect(st.shadow.Rect)
			if r.Empty() {
				continue
			}
			swizzleBGRAtoRGBA(st.shadow, st.view, src, int(mp.RowPitch), r)
			changed = append(changed, r)
		}
		st.d.dev.unmap(st.staging)
		st.freshCPU = false
	}
	// Cursor: restore what it covered, then draw it at its new place.
	if !st.cursorArea.Empty() {
		copyRect(st.view, st.shadow, st.cursorArea)
		changed = append(changed, st.cursorArea)
		st.cursorArea = image.Rectangle{}
	}
	if st.pvisible && st.shape != nil {
		if a := st.shape.draw(st.view, st.px, st.py); !a.Empty() {
			st.cursorArea = a
			changed = append(changed, a)
		}
	}
	st.pending = st.pending[:0]
	st.fullDirty = false
	if full {
		c.lastDirty = fullRects(st.view.Rect)
	} else {
		c.lastDirty = coalesceDirty(changed, st.view.Rect)
	}
	c.lastDirtyOK = true
	return st.view, nil
}

// takeDirty returns what changed in the frame capture just produced. ok is
// false when that frame came from GDI, in which case the caller must diff.
func (c *dxgiCapturer) takeDirty() ([]image.Rectangle, bool) {
	rects, ok := c.lastDirty, c.lastDirtyOK
	c.lastDirty, c.lastDirtyOK = nil, false
	return rects, ok
}

// captureFrame is the video path: the VRAM snapshot for the encoder, or a CPU
// image when duplication is unavailable (the encoder uploads it).
func (c *dxgiCapturer) captureFrame(m monitor) (videoFrame, error) {
	st := c.state(m)
	if st == nil {
		img, err := c.gdi.capture(m)
		return videoFrame{rgba: img, w: m.Bounds.Dx(), h: m.Bounds.Dy(), fresh: true}, err
	}
	fresh, err := c.advance(st, 33)
	if err != nil || !st.haveSnap || st.d == nil {
		c.backend = "gdi"
		st.fullDirty = true
		img, gerr := c.gdi.capture(m)
		return videoFrame{rgba: img, w: m.Bounds.Dx(), h: m.Bounds.Dy(), fresh: true}, gerr
	}
	c.backend = "dxgi"
	// The CPU copy is not maintained on this path; a later switch back to
	// tiles must refresh it completely.
	st.fullDirty = true
	f := videoFrame{
		gpu:   &gpuSurface{dev: st.d.dev, tex: st.snap, w: st.d.w, h: st.d.h},
		w:     st.d.w,
		h:     st.d.h,
		fresh: fresh || st.freshGPU,
	}
	st.freshGPU = false
	return f, nil
}

// Close releases every duplication and D3D device.
func (c *dxgiCapturer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	for name, st := range c.outs {
		st.close()
		delete(c.outs, name)
	}
	return nil
}

// swizzleBGRAtoRGBA converts r of a mapped BGRA surface into shadow and
// copies the result into view as well.
func swizzleBGRAtoRGBA(shadow, view *image.RGBA, src []byte, pitch int, r image.Rectangle) {
	for y := r.Min.Y; y < r.Max.Y; y++ {
		so := y*pitch + r.Min.X*4
		if so < 0 || so+r.Dx()*4 > len(src) {
			return
		}
		s := src[so : so+r.Dx()*4]
		do := shadow.PixOffset(r.Min.X, y)
		d := shadow.Pix[do : do+r.Dx()*4]
		for i := 0; i+3 < len(s); i += 4 {
			d[i], d[i+1], d[i+2], d[i+3] = s[i+2], s[i+1], s[i], 0xff
		}
		copy(view.Pix[do:do+r.Dx()*4], d)
	}
}

// copyRect copies r from src into dst (same geometry).
func copyRect(dst, src *image.RGBA, r image.Rectangle) {
	r = r.Intersect(dst.Rect).Intersect(src.Rect)
	for y := r.Min.Y; y < r.Max.Y; y++ {
		o := dst.PixOffset(r.Min.X, y)
		copy(dst.Pix[o:o+r.Dx()*4], src.Pix[o:o+r.Dx()*4])
	}
}
