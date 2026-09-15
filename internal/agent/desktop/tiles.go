package desktop

import (
	"bytes"
	"image"
)

// tileSize is the side of the square grid the differ works on. 64 px keeps
// the per-frame compare cheap (a 1080p screen is 30x17 tiles) while a single
// blinking cursor still costs one small JPEG rather than a whole band.
const tileSize = 64

// maxRectHeight caps how tall a merged rectangle may grow. Larger rectangles
// mean fewer messages, but each one is encoded by a single worker, so a full
// 1080p frame is cut into ~4 bands that the encoder pool handles in parallel.
const maxRectHeight = 256

// fullRects covers bounds completely with full-width bands of at most
// maxRectHeight rows. It is what the first frame, a refresh and a monitor
// switch send.
func fullRects(bounds image.Rectangle) []image.Rectangle {
	bounds = bounds.Canon()
	if bounds.Empty() {
		return nil
	}
	var out []image.Rectangle
	for y := bounds.Min.Y; y < bounds.Max.Y; y += maxRectHeight {
		y1 := min(y+maxRectHeight, bounds.Max.Y)
		out = append(out, image.Rect(bounds.Min.X, y, bounds.Max.X, y1))
	}
	return out
}

// diffRects compares cur against prev on a tileSize grid and returns the
// changed area as rectangles (in cur's coordinate space, origin at
// cur.Rect.Min). Both images must have the same bounds; when they do not (or
// prev is nil) the whole of cur is returned, which is what a resolution
// change needs anyway.
//
// Runs of horizontally adjacent changed tiles become one rectangle; identical
// runs on consecutive tile rows are then stacked (up to maxRectHeight) so a
// scrolling window costs a handful of messages instead of hundreds.
func diffRects(prev, cur *image.RGBA) []image.Rectangle {
	if cur == nil {
		return nil
	}
	if prev == nil || prev.Rect != cur.Rect || prev.Stride != cur.Stride {
		return fullRects(image.Rect(0, 0, cur.Rect.Dx(), cur.Rect.Dy()))
	}
	w, h := cur.Rect.Dx(), cur.Rect.Dy()
	if w <= 0 || h <= 0 {
		return nil
	}
	cols := (w + tileSize - 1) / tileSize
	rows := (h + tileSize - 1) / tileSize

	var rects []image.Rectangle
	// prevRow holds the rectangles produced by the previous tile row so a
	// run with the same x-extent can be stacked on top of it.
	var prevRow []int // indexes into rects
	for ty := 0; ty < rows; ty++ {
		y0 := ty * tileSize
		y1 := min(y0+tileSize, h)
		var thisRow []int
		runStart := -1 // first changed tile column of the current run
		flush := func(endCol int) {
			if runStart < 0 {
				return
			}
			r := image.Rect(runStart*tileSize, y0, min(endCol*tileSize, w), y1)
			runStart = -1
			// Stack onto the rectangle directly above when the x-range matches
			// and the height cap allows it.
			for _, pi := range prevRow {
				p := &rects[pi]
				if p.Min.X == r.Min.X && p.Max.X == r.Max.X && p.Max.Y == r.Min.Y && r.Max.Y-p.Min.Y <= maxRectHeight {
					p.Max.Y = r.Max.Y
					thisRow = append(thisRow, pi)
					return
				}
			}
			rects = append(rects, r)
			thisRow = append(thisRow, len(rects)-1)
		}
		for tx := 0; tx < cols; tx++ {
			x0 := tx * tileSize
			x1 := min(x0+tileSize, w)
			if tileChanged(prev, cur, x0, y0, x1, y1) {
				if runStart < 0 {
					runStart = tx
				}
				continue
			}
			flush(tx)
		}
		flush(cols)
		prevRow = thisRow
	}
	return rects
}

// tileChanged reports whether any pixel in [x0,x1)x[y0,y1) differs. It
// compares raw rows, which is far cheaper than going through image.At.
func tileChanged(prev, cur *image.RGBA, x0, y0, x1, y1 int) bool {
	n := (x1 - x0) * 4
	for y := y0; y < y1; y++ {
		off := (y-cur.Rect.Min.Y)*cur.Stride + (x0-cur.Rect.Min.X)*4
		if !bytes.Equal(prev.Pix[off:off+n], cur.Pix[off:off+n]) {
			return true
		}
	}
	return false
}
