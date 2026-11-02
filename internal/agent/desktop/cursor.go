package desktop

import "image"

// Desktop Duplication does not draw the mouse into the frame: the pointer is
// reported separately as a position plus a shape bitmap. The three shape
// formats below are the DXGI_OUTDUPL_POINTER_SHAPE_TYPE values, and the
// compositing rules are the documented ones. This file is deliberately
// platform-neutral so the maths is unit-tested on every OS.
const (
	pointerMonochrome  = 0x1 // 1bpp AND mask stacked on a 1bpp XOR mask
	pointerColor       = 0x2 // 32bpp BGRA, alpha blended
	pointerMaskedColor = 0x4 // 32bpp BGRA, alpha selects replace (0) or XOR (0xFF)
)

// maxPointerDim bounds a reported shape. Real cursors are at most a few
// hundred pixels; a driver returning more is corrupt and must not be trusted
// to size an allocation or a loop.
const maxPointerDim = 512

// pointerShape is one cursor bitmap as the driver delivered it.
type pointerShape struct {
	kind       int
	w, h       int // h is the visible height (half the reported height for monochrome)
	pitch      int
	hotX, hotY int
	data       []byte
}

// newPointerShape validates the raw DXGI description. It returns nil when
// the shape is unusable, which callers treat as "no cursor".
func newPointerShape(kind, width, height, pitch, hotX, hotY int, data []byte) *pointerShape {
	if width <= 0 || height <= 0 || width > maxPointerDim || height > maxPointerDim || pitch <= 0 {
		return nil
	}
	h := height
	switch kind {
	case pointerMonochrome:
		h = height / 2 // AND mask followed by XOR mask
		if h <= 0 || len(data) < pitch*h*2 || pitch < (width+7)/8 {
			return nil
		}
	case pointerColor, pointerMaskedColor:
		if len(data) < pitch*h || pitch < width*4 {
			return nil
		}
	default:
		return nil
	}
	return &pointerShape{kind: kind, w: width, h: h, pitch: pitch, hotX: hotX, hotY: hotY, data: data}
}

// rect is the area the cursor covers when its hotspot sits at (px, py),
// before clipping to the screen.
func (s *pointerShape) rect(px, py int) image.Rectangle {
	x, y := px-s.hotX, py-s.hotY
	return image.Rect(x, y, x+s.w, y+s.h)
}

// draw composites the cursor into dst (whose pixels are R,G,B,A in memory
// order) and returns the clipped area it touched.
func (s *pointerShape) draw(dst *image.RGBA, px, py int) image.Rectangle {
	area := s.rect(px, py).Intersect(dst.Rect)
	if area.Empty() {
		return image.Rectangle{}
	}
	org := s.rect(px, py).Min
	for y := area.Min.Y; y < area.Max.Y; y++ {
		sy := y - org.Y
		d := dst.Pix[dst.PixOffset(area.Min.X, y):]
		for x := area.Min.X; x < area.Max.X; x++ {
			sx := x - org.X
			o := (x - area.Min.X) * 4
			switch s.kind {
			case pointerMonochrome:
				bit := byte(0x80) >> (uint(sx) & 7)
				andSet := s.data[sy*s.pitch+sx/8]&bit != 0
				xorSet := s.data[(s.h+sy)*s.pitch+sx/8]&bit != 0
				switch {
				case !andSet && !xorSet:
					d[o], d[o+1], d[o+2] = 0, 0, 0
				case !andSet && xorSet:
					d[o], d[o+1], d[o+2] = 255, 255, 255
				case andSet && xorSet:
					d[o], d[o+1], d[o+2] = ^d[o], ^d[o+1], ^d[o+2]
				}
			case pointerColor:
				p := s.data[sy*s.pitch+sx*4:]
				a := uint32(p[3])
				if a == 0 {
					continue
				}
				// p is B,G,R,A; dst is R,G,B,A.
				d[o] = byte((uint32(p[2])*a + uint32(d[o])*(255-a) + 127) / 255)
				d[o+1] = byte((uint32(p[1])*a + uint32(d[o+1])*(255-a) + 127) / 255)
				d[o+2] = byte((uint32(p[0])*a + uint32(d[o+2])*(255-a) + 127) / 255)
			case pointerMaskedColor:
				p := s.data[sy*s.pitch+sx*4:]
				if p[3] == 0 {
					d[o], d[o+1], d[o+2] = p[2], p[1], p[0]
				} else {
					d[o] ^= p[2]
					d[o+1] ^= p[1]
					d[o+2] ^= p[0]
				}
			}
		}
	}
	return area
}

// coalesceDirty turns the driver's dirty and move-destination rectangles into
// the bands the tile encoder takes. Rectangles are clipped to bounds
// (monitor-local, origin 0,0), overlapping or touching ones are merged, and
// the result is split into maxRectHeight bands. When the driver reports
// either nothing sensible or so much that tiling it costs more than sending
// the lot, the whole frame is returned.
func coalesceDirty(rects []image.Rectangle, bounds image.Rectangle) []image.Rectangle {
	const (
		maxRects      = 48 // beyond this, per-rect overhead beats the saving
		fullThreshold = 2  // dirty area above 1/2 of the screen: send everything
	)
	var in []image.Rectangle
	var area int
	for _, r := range rects {
		r = r.Canon().Intersect(bounds)
		if r.Empty() {
			continue
		}
		in = append(in, r)
		area += r.Dx() * r.Dy()
	}
	if len(in) == 0 {
		return nil
	}
	if len(in) > maxRects*4 || area*fullThreshold > bounds.Dx()*bounds.Dy() {
		return fullRects(bounds)
	}
	// Greedy merge until stable. Counts are small (hundreds at most) so the
	// quadratic pass is cheaper than anything cleverer.
	for changed := true; changed && len(in) > 1; {
		changed = false
		for i := 0; i < len(in); i++ {
			for j := i + 1; j < len(in); j++ {
				if touches(in[i], in[j]) {
					in[i] = in[i].Union(in[j])
					in = append(in[:j], in[j+1:]...)
					j--
					changed = true
				}
			}
		}
	}
	if len(in) > maxRects {
		return fullRects(bounds)
	}
	var out []image.Rectangle
	for _, r := range in {
		for y := r.Min.Y; y < r.Max.Y; y += maxRectHeight {
			out = append(out, image.Rect(r.Min.X, y, r.Max.X, min(y+maxRectHeight, r.Max.Y)))
		}
	}
	return out
}

// touches reports whether two rectangles overlap or share an edge, so that
// merging them wastes no area.
func touches(a, b image.Rectangle) bool {
	return a.Min.X <= b.Max.X && b.Min.X <= a.Max.X && a.Min.Y <= b.Max.Y && b.Min.Y <= a.Max.Y
}
