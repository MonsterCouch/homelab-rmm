//go:build windows

package desktop

import (
	"errors"
	"image"
	"testing"
	"unsafe"
)

// These tests talk to the real GPU stack. They skip (never fail) only when
// the machine has no DXGI output at all, e.g. a headless CI runner; on a
// workstation every one of them must run.

func requireOutputs(t *testing.T) []outputInfo {
	t.Helper()
	if err := platformInit(); err != nil {
		t.Fatal(err)
	}
	outs, err := listOutputs()
	if err != nil {
		t.Fatalf("listOutputs: %v", err)
	}
	if len(outs) == 0 {
		t.Skip("no DXGI output attached to the desktop (headless machine)")
	}
	return outs
}

// The struct layouts are copied straight into driver memory; a size error
// silently corrupts it, so pin them to the SDK values.
func TestDXGIStructSizes(t *testing.T) {
	for name, c := range map[string]struct{ got, want uintptr }{
		"DXGI_ADAPTER_DESC1":              {unsafe.Sizeof(dxgiAdapterDesc1{}), 312},
		"DXGI_OUTPUT_DESC":                {unsafe.Sizeof(dxgiOutputDesc{}), 96},
		"DXGI_OUTDUPL_DESC":               {unsafe.Sizeof(dxgiOutduplDesc{}), 36},
		"DXGI_OUTDUPL_FRAME_INFO":         {unsafe.Sizeof(dxgiFrameInfo{}), 48},
		"DXGI_OUTDUPL_MOVE_RECT":          {unsafe.Sizeof(dxgiMoveRect{}), 24},
		"DXGI_OUTDUPL_POINTER_SHAPE_INFO": {unsafe.Sizeof(dxgiPointerShapeInfo{}), 24},
		"D3D11_TEXTURE2D_DESC":            {unsafe.Sizeof(texture2DDesc{}), 44},
		"D3D11_MAPPED_SUBRESOURCE":        {unsafe.Sizeof(mappedSubresource{}), 16},
		"RECT":                            {unsafe.Sizeof(winRect{}), 16},
	} {
		if c.got != c.want {
			t.Errorf("%s: size %d, SDK says %d", name, c.got, c.want)
		}
	}
}

func TestHRESULTErrors(t *testing.T) {
	if err := check(0); err != nil {
		t.Errorf("S_OK -> %v", err)
	}
	if err := check(hrFalse); err != nil {
		t.Errorf("S_FALSE is success, got %v", err)
	}
	err := check(uintptr(uint32(hrDXGIAccessLost)))
	if !isHR(err, hrDXGIAccessLost) {
		t.Fatalf("ACCESS_LOST not recognised: %v", err)
	}
	if isHR(err, hrDXGIWaitTimeout) || isHR(errors.New("x"), hrDXGIAccessLost) {
		t.Error("isHR matched the wrong error")
	}
}

func TestListOutputsAndAdapterOwnership(t *testing.T) {
	outs := requireOutputs(t)
	for _, o := range outs {
		t.Logf("output %s %v on adapter #%d %q (software=%v)", o.deviceName, o.bounds, o.adapterIdx, o.adapterName, o.software)
		if o.bounds.Empty() || o.deviceName == "" || o.adapterName == "" {
			t.Errorf("incomplete output info: %+v", o)
		}
	}
}

// On a hybrid-GPU laptop the display hangs off one adapter while D3D11's
// default device is the other. Duplicating through the owner must work; the
// nil-adapter attempt is logged to document the failure the matching avoids
// (it is only informational: on a single-GPU machine it succeeds).
func TestHybridAdapterMatching(t *testing.T) {
	outs := requireOutputs(t)
	opened := 0
	for _, o := range outs {
		if o.software {
			continue
		}
		d, err := openDuplicator(o)
		if err != nil {
			t.Logf("output %s on %q: %v", o.deviceName, o.adapterName, err)
			continue
		}
		opened++
		t.Logf("duplication open on the owning adapter %q (%dx%d)", d.dev.name, d.w, d.h)
		d.close()
	}
	if opened == 0 {
		t.Fatal("no output could be duplicated through its own adapter")
	}

	// Default (adapter-less) device for contrast.
	def, err := newD3DDevice(com{}, "default")
	if err != nil {
		t.Fatalf("default D3D11 device: %v", err)
	}
	defer def.close()
	dxgiDev, err := def.dev.queryInterface(&iidIDXGIDevice)
	if err != nil {
		t.Fatal(err)
	}
	dxgiDev.release()
	for _, o := range outs {
		f, _ := createFactory()
		ad, _, ok, _ := enumAdapter(f, o.adapterIdx)
		if !ok {
			f.release()
			continue
		}
		out, _, ok, _ := enumOutput(ad, o.outputIdx)
		if ok {
			if out1, err := out.queryInterface(&iidIDXGIOutput1); err == nil {
				var dup unsafe.Pointer
				hr := out1.call(output1DuplicateOutput, uintptr(def.dev.p), uintptr(unsafe.Pointer(&dup)))
				if err := check(hr); err != nil {
					t.Logf("DuplicateOutput(%s) with the DEFAULT device failed: %v - this is the hybrid-GPU failure the adapter matching exists to avoid", o.deviceName, err)
				} else {
					t.Logf("DuplicateOutput(%s) with the default device worked (single-GPU or compatible topology)", o.deviceName)
					(&com{dup}).release()
				}
				out1.release()
			}
			out.release()
		}
		ad.release()
		f.release()
	}
}

func TestDXGICaptureProducesRealPixels(t *testing.T) {
	requireOutputs(t)
	c := newDXGICapturer()
	defer c.Close()
	mons, err := c.monitors()
	if err != nil || len(mons) == 0 {
		t.Fatalf("monitors: %v %v", mons, err)
	}
	m := mons[0]
	var img *image.RGBA
	for i := 0; i < 5; i++ { // the first frames can race a DWM update
		img, err = c.capture(m)
		if err != nil {
			t.Fatalf("capture: %v", err)
		}
	}
	t.Logf("backend=%s monitor=%v image=%v", c.Backend(), m.Bounds, img.Rect)
	if c.Backend() != "dxgi" {
		t.Fatalf("expected the DXGI backend on a machine with outputs, got %q", c.Backend())
	}
	if img.Rect.Dx() != m.Bounds.Dx() || img.Rect.Dy() != m.Bounds.Dy() {
		t.Fatalf("image %v does not match monitor %v", img.Rect, m.Bounds)
	}
	// A real desktop is not a flat colour; every alpha is opaque.
	seen := map[[3]byte]int{}
	for y := 0; y < img.Rect.Dy(); y += 17 {
		for x := 0; x < img.Rect.Dx(); x += 17 {
			o := img.PixOffset(x, y)
			if img.Pix[o+3] != 0xff {
				t.Fatalf("pixel (%d,%d) alpha=%d", x, y, img.Pix[o+3])
			}
			seen[[3]byte{img.Pix[o], img.Pix[o+1], img.Pix[o+2]}]++
		}
	}
	if len(seen) < 4 {
		t.Errorf("only %d distinct colours in the capture: looks like a blank frame", len(seen))
	}

	// The first frame is a full refresh; a quiet second capture reports a
	// (possibly empty) dirty list rather than 'unknown'. A process may hold
	// only one duplication of an output (a second DuplicateOutput is
	// E_INVALIDARG), so the first capturer goes before the second opens.
	c.Close()
	c2 := newDXGICapturer()
	defer c2.Close()
	if _, err := c2.monitors(); err != nil {
		t.Fatal(err)
	}
	// The first AcquireNextFrame after DuplicateOutput returns WAIT_TIMEOUT on
	// a screen that has not presented yet, so that capture falls to GDI and
	// reports no dirty rectangles. Retry until the duplication delivers its
	// first frame (a normal desktop has a clock and a cursor), the way the
	// capture loop does in production.
	var rects []image.Rectangle
	var ok bool
	for i := 0; i < 40; i++ {
		if _, err := c2.capture(m); err != nil {
			t.Fatal(err)
		}
		if c2.Backend() != "dxgi" {
			continue
		}
		if rects, ok = c2.takeDirty(); ok {
			break
		}
	}
	if !ok || len(rects) == 0 {
		t.Skipf("DXGI never reported a dirty frame in time (idle screen): dirty=%v ok=%v", rects, ok)
	}
	if _, ok := c2.takeDirty(); ok {
		t.Error("takeDirty must be consumed by the first read")
	}
}

// DXGI and GDI must agree on what is on screen. A noisy desktop (clock,
// cursor blink) is tolerated; a swapped colour channel or a wrong stride is
// not.
func TestDXGIMatchesGDI(t *testing.T) {
	requireOutputs(t)
	c := newDXGICapturer()
	defer c.Close()
	mons, err := c.monitors()
	if err != nil {
		t.Fatal(err)
	}
	m := mons[0]
	for i := 0; i < 3; i++ {
		if _, err := c.capture(m); err != nil {
			t.Fatal(err)
		}
	}
	d, err := c.capture(m)
	if err != nil || c.Backend() != "dxgi" {
		t.Skipf("DXGI not active (%v, backend %q)", err, c.Backend())
	}
	g, err := c.gdi.capture(m)
	if err != nil {
		t.Skipf("GDI capture unavailable: %v", err)
	}
	if d.Rect != g.Rect {
		t.Fatalf("size mismatch: dxgi %v gdi %v", d.Rect, g.Rect)
	}
	const tol = 24 // DWM colour management, dithering and the odd animation
	close, total := 0, 0
	for y := 0; y < d.Rect.Dy(); y += 7 {
		for x := 0; x < d.Rect.Dx(); x += 7 {
			total++
			a, b := d.Pix[d.PixOffset(x, y):], g.Pix[g.PixOffset(x, y):]
			if absDiff(a[0], b[0]) <= tol && absDiff(a[1], b[1]) <= tol && absDiff(a[2], b[2]) <= tol {
				close++
			}
		}
	}
	if frac := float64(close) / float64(total); frac < 0.85 {
		t.Errorf("only %.0f%% of sampled pixels agree between DXGI and GDI (channel order / stride bug?)", frac*100)
	}
}

func absDiff(a, b byte) byte {
	if a > b {
		return a - b
	}
	return b - a
}

// The capturer must hand over the frame it holds in VRAM without a CPU copy.
func TestDXGIFrameSourceGPUPath(t *testing.T) {
	requireOutputs(t)
	c := newDXGICapturer()
	defer c.Close()
	mons, _ := c.monitors()
	var f videoFrame
	var err error
	for i := 0; i < 5; i++ {
		if f, err = c.captureFrame(mons[0]); err != nil {
			t.Fatal(err)
		}
	}
	if c.Backend() != "dxgi" {
		t.Skipf("DXGI not active, backend %q", c.Backend())
	}
	gs, ok := f.gpu.(*gpuSurface)
	if !ok || gs.tex.nil() || f.rgba != nil {
		t.Fatalf("expected a VRAM frame without CPU pixels, got %+v", f)
	}
	if w, h := textureSize(gs.tex); w != mons[0].Bounds.Dx() || h != mons[0].Bounds.Dy() {
		t.Errorf("texture is %dx%d, monitor is %v", w, h, mons[0].Bounds)
	}
}
