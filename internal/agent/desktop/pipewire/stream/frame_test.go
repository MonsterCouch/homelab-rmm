package stream

import (
	"encoding/binary"
	"image/color"
	"strings"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/pod"
)

// framePix builds a w by h picture in a data block with the given stride and
// start offset. Pixel (x, y) has channel values r=x+1, g=y+1, b=x+y+10 and
// fourth byte a4. Padding bytes are 0xEE. order says how the channels are
// laid out in memory.
func framePix(w, h, stride, start int, bgr bool, a4 byte) []byte {
	pix := make([]byte, start+h*stride)
	for i := range pix {
		pix[i] = 0xEE
	}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r, g, b := byte(x+1), byte(y+1), byte(x+y+10)
			p := pix[start+y*stride+x*4:]
			if bgr {
				p[0], p[1], p[2] = b, g, r
			} else {
				p[0], p[1], p[2] = r, g, b
			}
			p[3] = a4
		}
	}
	return pix
}

func TestDecodeFrameFormats(t *testing.T) {
	const w, h, stride = 5, 3, 32
	cases := []struct {
		name   string
		format uint32
		bgr    bool
		a4     byte
		wantA  byte
	}{
		{"BGRx", pod.VideoFormatBGRx, true, 0x11, 255},
		{"BGRA", pod.VideoFormatBGRA, true, 0x80, 0x80},
		{"RGBx", pod.VideoFormatRGBx, false, 0x22, 255},
		{"RGBA", pod.VideoFormatRGBA, false, 0x40, 0x40},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pix := framePix(w, h, stride, 0, c.bgr, c.a4)
			img, err := decodeFrame(pix, chunk{size: uint32(len(pix)), stride: stride}, w, h, c.format, nil)
			if err != nil {
				t.Fatal(err)
			}
			if img.Bounds().Dx() != w || img.Bounds().Dy() != h {
				t.Fatalf("size = %v", img.Bounds())
			}
			for y := 0; y < h; y++ {
				for x := 0; x < w; x++ {
					want := color.RGBA{R: byte(x + 1), G: byte(y + 1), B: byte(x + y + 10), A: c.wantA}
					if got := img.RGBAAt(x, y); got != want {
						t.Fatalf("pixel (%d,%d) = %v, want %v", x, y, got, want)
					}
				}
			}
		})
	}
}

func TestDecodeFrameOffsetStrideAndCrop(t *testing.T) {
	const w, h, stride, start = 6, 4, 40, 24
	pix := framePix(w, h, stride, start, true, 0)
	// chunk.offset is taken modulo the data size, so an offset of one full
	// block plus start reads at start.
	ch := chunk{offset: uint32(len(pix)) + start, size: uint32(len(pix)), stride: stride}
	img, err := decodeFrame(pix, ch, w, h, pod.VideoFormatBGRx, &region{x: 2, y: 1, w: 3, h: 2})
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds().Dx() != 3 || img.Bounds().Dy() != 2 {
		t.Fatalf("cropped size = %v", img.Bounds())
	}
	for y := 0; y < 2; y++ {
		for x := 0; x < 3; x++ {
			sx, sy := x+2, y+1
			want := color.RGBA{R: byte(sx + 1), G: byte(sy + 1), B: byte(sx + sy + 10), A: 255}
			if got := img.RGBAAt(x, y); got != want {
				t.Fatalf("cropped pixel (%d,%d) = %v, want %v", x, y, got, want)
			}
		}
	}

	// A crop that runs past the frame is clipped; one outside it is ignored.
	img, err = decodeFrame(pix, ch, w, h, pod.VideoFormatBGRx, &region{x: 4, y: 2, w: 100, h: 100})
	if err != nil || img.Bounds().Dx() != 2 || img.Bounds().Dy() != 2 {
		t.Fatalf("clipped crop: %v, %v", img.Bounds(), err)
	}
	img, err = decodeFrame(pix, ch, w, h, pod.VideoFormatBGRx, &region{x: 50, y: 50, w: 3, h: 3})
	if err != nil || img.Bounds().Dx() != w || img.Bounds().Dy() != h {
		t.Fatalf("outside crop: %v, %v", img.Bounds(), err)
	}
	img, err = decodeFrame(pix, ch, w, h, pod.VideoFormatBGRx, &region{x: 1, y: 1})
	if err != nil || img.Bounds().Dx() != w {
		t.Fatalf("invalid crop region should be ignored: %v, %v", img.Bounds(), err)
	}
}

func TestDecodeFrameZeroStrideUsesChunkSize(t *testing.T) {
	const w, h, stride = 4, 3, 20
	pix := framePix(w, h, stride, 0, false, 0)
	img, err := decodeFrame(pix, chunk{size: uint32(h * stride)}, w, h, pod.VideoFormatRGBx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := img.RGBAAt(3, 2), (color.RGBA{R: 4, G: 3, B: 15, A: 255}); got != want {
		t.Fatalf("pixel = %v, want %v", got, want)
	}
}

func TestDecodeFrameRejects(t *testing.T) {
	const w, h, stride = 5, 3, 32
	pix := framePix(w, h, stride, 0, true, 0)
	cases := []struct {
		name string
		pix  []byte
		ch   chunk
		w, h int
		want string
	}{
		{"stride below width", pix, chunk{size: 96, stride: 16}, w, h, "smaller than"},
		{"negative stride", pix, chunk{size: 96, stride: -32}, w, h, "smaller than"},
		{"rows run past the data", pix[:60], chunk{size: 60, stride: stride}, w, h, "needs"},
		{"empty data", nil, chunk{stride: stride}, w, h, "holds 0 bytes"},
		{"zero size and stride", pix, chunk{}, w, h, "smaller than"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := decodeFrame(c.pix, c.ch, c.w, c.h, pod.VideoFormatBGRx, nil)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
	if _, err := decodeFrame(pix, chunk{size: 96, stride: stride}, w, h, 9999, nil); err == nil {
		t.Fatal("an unknown format was accepted")
	}
}

func TestDecodeFrameSkipsCorruptedAndEmpty(t *testing.T) {
	pix := framePix(2, 2, 8, 0, true, 0)
	for _, flags := range []int32{chunkFlagCorrupted, chunkFlagEmpty} {
		_, err := decodeFrame(pix, chunk{size: 32, stride: 8, flags: flags}, 2, 2, pod.VideoFormatBGRx, nil)
		if _, ok := err.(skipFrame); !ok {
			t.Fatalf("flags %d: err = %v, want skipFrame", flags, err)
		}
	}
}

func TestReadChunkAndRegion(t *testing.T) {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:], 7)
	binary.LittleEndian.PutUint32(b[4:], 9)
	binary.LittleEndian.PutUint32(b[8:], 0xfffffff0)
	binary.LittleEndian.PutUint32(b[12:], 3)
	if c := readChunk(b); c != (chunk{offset: 7, size: 9, stride: -16, flags: 3}) {
		t.Fatalf("chunk = %+v", c)
	}
	if r := readRegion(b); r.x != 7 || r.y != 9 || r.w != 0xfffffff0 || r.h != 3 || !r.valid() {
		t.Fatalf("region = %+v", r)
	}
}

func TestDecodeFrameClampsChunkSize(t *testing.T) {
	const w, h, stride = 4, 4, 16
	pix := make([]byte, h*stride)
	img, err := decodeFrame(pix, chunk{size: uint32(len(pix)) + 4096, stride: stride}, w, h, pod.VideoFormatBGRx, nil)
	if err != nil {
		t.Fatalf("a chunk larger than the data block must be clamped, got %v", err)
	}
	if img.Bounds().Dx() != w || img.Bounds().Dy() != h {
		t.Fatalf("size = %v", img.Bounds())
	}
}
