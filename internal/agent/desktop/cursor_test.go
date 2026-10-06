package desktop

import (
	"image"
	"image/color"
	"testing"
)

func solidRGBA(w, h int, c color.RGBA) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = c.R, c.G, c.B, c.A
	}
	return img
}

func TestNewPointerShapeRejectsGarbage(t *testing.T) {
	cases := []struct {
		name                                string
		kind, w, h, pitch, hotX, hotY, size int
	}{
		{"unknown type", 9, 8, 8, 32, 0, 0, 256},
		{"zero width", pointerColor, 0, 8, 32, 0, 0, 256},
		{"oversized", pointerColor, maxPointerDim + 1, 8, 4 * (maxPointerDim + 1), 0, 0, 1 << 20},
		{"short colour data", pointerColor, 8, 8, 32, 0, 0, 10},
		{"pitch below row size", pointerColor, 8, 8, 16, 0, 0, 256},
		{"short mono data", pointerMonochrome, 8, 16, 1, 0, 0, 3},
		{"odd mono height of one", pointerMonochrome, 8, 1, 1, 0, 0, 8},
	}
	for _, c := range cases {
		if s := newPointerShape(c.kind, c.w, c.h, c.pitch, c.hotX, c.hotY, make([]byte, c.size)); s != nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

func TestColorCursorBlend(t *testing.T) {
	// 2x1 cursor, BGRA: an opaque red pixel and a half-transparent blue one.
	data := []byte{0, 0, 255, 255, 255, 0, 0, 128}
	s := newPointerShape(pointerColor, 2, 1, 8, 0, 0, data)
	if s == nil {
		t.Fatal("shape rejected")
	}
	dst := solidRGBA(4, 4, color.RGBA{0, 200, 0, 255})
	area := s.draw(dst, 1, 1)
	if area != image.Rect(1, 1, 3, 2) {
		t.Fatalf("area = %v", area)
	}
	if got := dst.RGBAAt(1, 1); got != (color.RGBA{255, 0, 0, 255}) {
		t.Errorf("opaque pixel = %v", got)
	}
	got := dst.RGBAAt(2, 1)
	if got.B < 120 || got.B > 135 || got.G < 95 || got.G > 105 {
		t.Errorf("half-blended pixel = %v, want roughly (0,100,128)", got)
	}
	if got := dst.RGBAAt(0, 0); got != (color.RGBA{0, 200, 0, 255}) {
		t.Errorf("pixel outside the cursor changed: %v", got)
	}
}

func TestMonochromeCursorRules(t *testing.T) {
	// 4x1 cursor drawn from a 4x2 mask: AND row then XOR row, MSB first.
	//   px0: AND0 XOR0 -> black        px1: AND0 XOR1 -> white
	//   px2: AND1 XOR0 -> transparent  px3: AND1 XOR1 -> invert
	and := byte(0b0011_0000)
	xor := byte(0b0101_0000)
	s := newPointerShape(pointerMonochrome, 4, 2, 1, 0, 0, []byte{and, xor})
	if s == nil {
		t.Fatal("shape rejected")
	}
	dst := solidRGBA(4, 1, color.RGBA{10, 20, 30, 255})
	s.draw(dst, 0, 0)
	want := []color.RGBA{{0, 0, 0, 255}, {255, 255, 255, 255}, {10, 20, 30, 255}, {245, 235, 225, 255}}
	for x, w := range want {
		if got := dst.RGBAAt(x, 0); got != w {
			t.Errorf("px%d = %v, want %v", x, got, w)
		}
	}
}

func TestMaskedColorCursor(t *testing.T) {
	// alpha 0 replaces; alpha 0xff XORs.
	data := []byte{0, 0, 255, 0, 0xff, 0xff, 0xff, 0xff}
	s := newPointerShape(pointerMaskedColor, 2, 1, 8, 0, 0, data)
	dst := solidRGBA(2, 1, color.RGBA{1, 2, 3, 255})
	s.draw(dst, 0, 0)
	if got := dst.RGBAAt(0, 0); got != (color.RGBA{255, 0, 0, 255}) {
		t.Errorf("replace pixel = %v", got)
	}
	if got := dst.RGBAAt(1, 0); got != (color.RGBA{^byte(1), ^byte(2), ^byte(3), 255}) {
		t.Errorf("xor pixel = %v", got)
	}
}

func TestCursorClippedAtScreenEdgeAndHotspot(t *testing.T) {
	data := make([]byte, 4*4*4)
	for i := 3; i < len(data); i += 4 {
		data[i] = 255
	}
	s := newPointerShape(pointerColor, 4, 4, 16, 1, 1, data)
	dst := solidRGBA(8, 8, color.RGBA{0, 0, 0, 255})
	// Hotspot (1,1) at the origin: the cursor starts at (-1,-1) and is clipped.
	if a := s.draw(dst, 0, 0); a != image.Rect(0, 0, 3, 3) {
		t.Errorf("clipped area = %v", a)
	}
	// Entirely off screen draws nothing and must not panic.
	if a := s.draw(dst, 100, 100); !a.Empty() {
		t.Errorf("off-screen area = %v", a)
	}
	if a := s.draw(dst, -100, -100); !a.Empty() {
		t.Errorf("negative off-screen area = %v", a)
	}
}

func TestCoalesceDirty(t *testing.T) {
	bounds := image.Rect(0, 0, 1920, 1080)
	t.Run("empty and clipped away", func(t *testing.T) {
		if got := coalesceDirty(nil, bounds); got != nil {
			t.Errorf("nil input -> %v", got)
		}
		if got := coalesceDirty([]image.Rectangle{image.Rect(5000, 5000, 6000, 6000)}, bounds); got != nil {
			t.Errorf("off-screen rect -> %v", got)
		}
	})
	t.Run("overlapping merge", func(t *testing.T) {
		got := coalesceDirty([]image.Rectangle{image.Rect(0, 0, 100, 100), image.Rect(50, 50, 200, 150)}, bounds)
		if len(got) != 1 || got[0] != image.Rect(0, 0, 200, 150) {
			t.Errorf("got %v", got)
		}
	})
	t.Run("distant rects stay separate", func(t *testing.T) {
		got := coalesceDirty([]image.Rectangle{image.Rect(0, 0, 10, 10), image.Rect(1000, 800, 1010, 810)}, bounds)
		if len(got) != 2 {
			t.Errorf("got %v", got)
		}
	})
	t.Run("tall rect split into bands", func(t *testing.T) {
		got := coalesceDirty([]image.Rectangle{image.Rect(0, 0, 100, 600)}, bounds)
		if len(got) != 3 || got[0].Dy() != maxRectHeight || got[2].Max.Y != 600 {
			t.Errorf("got %v", got)
		}
	})
	t.Run("most of the screen becomes a full frame", func(t *testing.T) {
		got := coalesceDirty([]image.Rectangle{image.Rect(0, 0, 1920, 700)}, bounds)
		want := fullRects(bounds)
		if len(got) != len(want) {
			t.Errorf("got %d rects, want %d", len(got), len(want))
		}
	})
	t.Run("a confetti of rects becomes a full frame", func(t *testing.T) {
		var in []image.Rectangle
		for i := 0; i < 400; i++ {
			x, y := (i%40)*40, (i/40)*100
			in = append(in, image.Rect(x, y, x+5, y+5))
		}
		if got := coalesceDirty(in, bounds); len(got) > 48 {
			t.Errorf("returned %d rects", len(got))
		}
	})
	t.Run("inverted rects are canonicalised", func(t *testing.T) {
		got := coalesceDirty([]image.Rectangle{{Min: image.Point{X: 20, Y: 20}, Max: image.Point{X: 10, Y: 10}}}, bounds)
		if len(got) != 1 || got[0] != image.Rect(10, 10, 20, 20) {
			t.Errorf("got %v", got)
		}
	})
}
