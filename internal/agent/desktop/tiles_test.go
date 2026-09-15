package desktop

import (
	"image"
	"image/color"
	"testing"
)

func solid(w, h int, c color.RGBA) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = c.R, c.G, c.B, c.A
	}
	return img
}

func clone(img *image.RGBA) *image.RGBA {
	out := image.NewRGBA(img.Rect)
	copy(out.Pix, img.Pix)
	return out
}

// coverage checks that rects exactly tile the area they claim: no overlap,
// and the union equals want (when want is non-empty).
func coverage(t *testing.T, rects []image.Rectangle, want image.Rectangle) {
	t.Helper()
	area := 0
	for i, a := range rects {
		if a.Empty() {
			t.Fatalf("rect %d is empty", i)
		}
		area += a.Dx() * a.Dy()
		for j, b := range rects {
			if i != j && a.Overlaps(b) {
				t.Fatalf("rects overlap: %v %v", a, b)
			}
		}
		if !a.In(want) {
			t.Fatalf("rect %v outside %v", a, want)
		}
	}
	if area != want.Dx()*want.Dy() {
		t.Fatalf("rects cover %d px, want %d (%v)", area, want.Dx()*want.Dy(), rects)
	}
}

func TestDiffUnchanged(t *testing.T) {
	a := solid(300, 200, color.RGBA{10, 20, 30, 255})
	if rects := diffRects(a, clone(a)); len(rects) != 0 {
		t.Fatalf("unchanged frame produced %v", rects)
	}
}

func TestDiffFirstFrameCoversScreen(t *testing.T) {
	img := solid(1920, 1080, color.RGBA{1, 2, 3, 255})
	rects := diffRects(nil, img)
	coverage(t, rects, img.Rect)
	for _, r := range rects {
		if r.Dy() > maxRectHeight || r.Dx() != 1920 {
			t.Fatalf("full-frame band %v is not a full-width band <= %d rows", r, maxRectHeight)
		}
	}
	// fullRects is what a refresh uses; it must agree.
	coverage(t, fullRects(img.Rect), img.Rect)
	if fullRects(image.Rectangle{}) != nil {
		t.Fatal("fullRects of an empty rect should be nil")
	}
}

func TestDiffSinglePixelIsOneTile(t *testing.T) {
	prev := solid(640, 480, color.RGBA{0, 0, 0, 255})
	cur := clone(prev)
	cur.SetRGBA(70, 130, color.RGBA{255, 0, 0, 255}) // tile column 1, row 2
	rects := diffRects(prev, cur)
	if len(rects) != 1 {
		t.Fatalf("got %v, want one rect", rects)
	}
	if want := image.Rect(64, 128, 128, 192); rects[0] != want {
		t.Fatalf("got %v want %v", rects[0], want)
	}
}

func TestDiffAdjacentTilesCoalesce(t *testing.T) {
	prev := solid(640, 480, color.RGBA{0, 0, 0, 255})
	cur := clone(prev)
	cur.SetRGBA(70, 10, color.RGBA{255, 0, 0, 255})  // tile (1,0)
	cur.SetRGBA(130, 10, color.RGBA{255, 0, 0, 255}) // tile (2,0)
	rects := diffRects(prev, cur)
	if len(rects) != 1 || rects[0] != image.Rect(64, 0, 192, 64) {
		t.Fatalf("got %v, want one 128x64 rect at (64,0)", rects)
	}

	// Two separated tiles stay separate.
	cur2 := clone(prev)
	cur2.SetRGBA(10, 10, color.RGBA{255, 0, 0, 255})
	cur2.SetRGBA(300, 10, color.RGBA{255, 0, 0, 255})
	rects = diffRects(prev, cur2)
	if len(rects) != 2 || rects[0] != image.Rect(0, 0, 64, 64) || rects[1] != image.Rect(256, 0, 320, 64) {
		t.Fatalf("got %v, want two separate tiles", rects)
	}
}

func TestDiffStacksVertically(t *testing.T) {
	prev := solid(640, 480, color.RGBA{0, 0, 0, 255})
	cur := clone(prev)
	// A vertical strip of changes in tile column 3, all rows.
	for y := 0; y < 480; y += 64 {
		cur.SetRGBA(200, y+1, color.RGBA{0, 255, 0, 255})
	}
	rects := diffRects(prev, cur)
	coverage(t, rects, image.Rect(192, 0, 256, 480))
	for _, r := range rects {
		if r.Dy() > maxRectHeight {
			t.Fatalf("stacked rect %v exceeds the height cap", r)
		}
	}
	if len(rects) != 2 { // 480 rows = 256 + 224
		t.Fatalf("expected two stacked rects, got %v", rects)
	}
}

func TestDiffEdgeTiles(t *testing.T) {
	// A screen whose size is not a multiple of 64: the last column/row
	// tiles are narrower and must still be reported within bounds.
	prev := solid(100, 70, color.RGBA{0, 0, 0, 255})
	cur := clone(prev)
	cur.SetRGBA(99, 69, color.RGBA{255, 255, 255, 255})
	rects := diffRects(prev, cur)
	if len(rects) != 1 || rects[0] != image.Rect(64, 64, 100, 70) {
		t.Fatalf("got %v, want the 36x6 corner tile", rects)
	}
	// Every changed pixel: the whole screen, in bounds.
	all := solid(100, 70, color.RGBA{9, 9, 9, 255})
	coverage(t, diffRects(prev, all), all.Rect)
}

func TestDiffSizeChangeIsFull(t *testing.T) {
	prev := solid(640, 480, color.RGBA{0, 0, 0, 255})
	cur := solid(800, 600, color.RGBA{0, 0, 0, 255})
	coverage(t, diffRects(prev, cur), cur.Rect)
	if diffRects(prev, nil) != nil {
		t.Fatal("nil current image should yield nothing")
	}
}

func BenchmarkDiff1080p(b *testing.B) {
	prev := solid(1920, 1080, color.RGBA{0, 0, 0, 255})
	cur := clone(prev)
	cur.SetRGBA(1000, 500, color.RGBA{1, 1, 1, 255})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		diffRects(prev, cur)
	}
}
