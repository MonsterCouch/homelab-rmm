package stream

import (
	"encoding/binary"
	"fmt"
	"image"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/pod"
)

// struct spa_chunk is {u32 offset, u32 size, i32 stride, i32 flags}.
const (
	chunkSize = 16

	chunkFlagCorrupted int32 = 1 << 0
	chunkFlagEmpty     int32 = 1 << 1
)

// struct spa_meta_region is {i32 x, i32 y, u32 width, u32 height}.
const regionSize = 16

// chunk is a decoded struct spa_chunk.
type chunk struct {
	offset uint32
	size   uint32
	stride int32
	flags  int32
}

func readChunk(b []byte) chunk {
	return chunk{
		offset: binary.LittleEndian.Uint32(b[0:]),
		size:   binary.LittleEndian.Uint32(b[4:]),
		stride: int32(binary.LittleEndian.Uint32(b[8:])),
		flags:  int32(binary.LittleEndian.Uint32(b[12:])),
	}
}

// region is a decoded struct spa_meta_region.
type region struct {
	x, y int32
	w, h uint32
}

func readRegion(b []byte) region {
	return region{
		x: int32(binary.LittleEndian.Uint32(b[0:])),
		y: int32(binary.LittleEndian.Uint32(b[4:])),
		w: binary.LittleEndian.Uint32(b[8:]),
		h: binary.LittleEndian.Uint32(b[12:]),
	}
}

// valid is spa_meta_region_is_valid: both sizes are non-zero.
func (r region) valid() bool { return r.w != 0 && r.h != 0 }

// pixelOrder says how a 4-byte pixel of a negotiated format maps to RGBA.
type pixelOrder struct {
	bgr   bool // bytes are B, G, R rather than R, G, B
	alpha bool // the fourth byte is alpha, not padding
}

// orderFor returns the byte order of the four formats the stream offers. The
// order in memory comes from the naming convention in spa/param/video/raw.h
// (BGRx means the lowest address holds B), not from a captured frame.
func orderFor(format uint32) (pixelOrder, bool) {
	switch format {
	case pod.VideoFormatBGRx:
		return pixelOrder{bgr: true}, true
	case pod.VideoFormatBGRA:
		return pixelOrder{bgr: true, alpha: true}, true
	case pod.VideoFormatRGBx:
		return pixelOrder{}, true
	case pod.VideoFormatRGBA:
		return pixelOrder{alpha: true}, true
	}
	return pixelOrder{}, false
}

// formatName names a video format id for messages.
func formatName(format uint32) string {
	switch format {
	case pod.VideoFormatRGBx:
		return "RGBx"
	case pod.VideoFormatBGRx:
		return "BGRx"
	case pod.VideoFormatRGBA:
		return "RGBA"
	case pod.VideoFormatBGRA:
		return "BGRA"
	}
	return fmt.Sprintf("format id %d", format)
}

// skipFrame is returned by decodeFrame for a buffer that carries no picture
// (corrupted or empty). The caller drops it without counting an error.
type skipFrame struct{ why string }

func (s skipFrame) Error() string { return s.why }

// decodeFrame copies one frame out of a buffer's pixel memory into a new
// RGBA image. pix is the data block (maxsize bytes), ch its chunk, w and h
// the negotiated size. A non-nil crop whose rectangle overlaps the frame
// selects the visible part, and the image has that part's size; otherwise
// the image is w by h. Rows start chunk.offset (modulo maxsize) bytes into
// pix and are chunk.stride bytes apart. Formats with an x byte get alpha 255.
func decodeFrame(pix []byte, ch chunk, w, h int, format uint32, crop *region) (*image.RGBA, error) {
	order, ok := orderFor(format)
	if !ok {
		return nil, fmt.Errorf("the stream has no converter for %s", formatName(format))
	}
	if ch.flags&chunkFlagCorrupted != 0 {
		return nil, skipFrame{"the producer marked the frame corrupted"}
	}
	if ch.flags&chunkFlagEmpty != 0 {
		return nil, skipFrame{"the producer marked the frame empty"}
	}
	maxsize := len(pix)
	if maxsize == 0 || w <= 0 || h <= 0 {
		return nil, fmt.Errorf("the buffer holds %d bytes for a %dx%d frame", maxsize, w, h)
	}
	// spa_chunk says size should be clamped to maxsize; the geometry check
	// below still bounds every read.
	if int64(ch.size) > int64(maxsize) {
		ch.size = uint32(maxsize)
	}
	start := int64(ch.offset) % int64(maxsize)
	stride := int64(ch.stride)
	if stride == 0 {
		stride = int64(ch.size) / int64(h)
	}
	if stride < int64(w)*4 {
		return nil, fmt.Errorf("the row stride %d is smaller than %d pixels of 4 bytes", stride, w)
	}

	x0, y0, x1, y1 := 0, 0, w, h
	if crop != nil && crop.valid() {
		cx0, cy0 := int64(crop.x), int64(crop.y)
		cx1, cy1 := cx0+int64(crop.w), cy0+int64(crop.h)
		cx0, cy0 = max(cx0, 0), max(cy0, 0)
		cx1, cy1 = min(cx1, int64(w)), min(cy1, int64(h))
		if cx1 > cx0 && cy1 > cy0 {
			x0, y0, x1, y1 = int(cx0), int(cy0), int(cx1), int(cy1)
		}
	}
	if end := start + int64(y1-1)*stride + int64(x1)*4; end > int64(maxsize) {
		return nil, fmt.Errorf("a %dx%d frame with stride %d at offset %d needs %d bytes but the data block has %d", w, h, stride, start, end, maxsize)
	}

	img := image.NewRGBA(image.Rect(0, 0, x1-x0, y1-y0))
	n := x1 - x0
	for row := y0; row < y1; row++ {
		so := int(start + int64(row)*stride + int64(x0)*4)
		src := pix[so : so+n*4]
		dst := img.Pix[(row-y0)*img.Stride : (row-y0)*img.Stride+n*4]
		convertRow(dst, src, order)
	}
	return img, nil
}

func convertRow(dst, src []byte, order pixelOrder) {
	switch {
	case order.bgr && order.alpha:
		for i := 0; i+3 < len(src); i += 4 {
			dst[i], dst[i+1], dst[i+2], dst[i+3] = src[i+2], src[i+1], src[i], src[i+3]
		}
	case order.bgr:
		for i := 0; i+3 < len(src); i += 4 {
			dst[i], dst[i+1], dst[i+2], dst[i+3] = src[i+2], src[i+1], src[i], 255
		}
	case order.alpha:
		copy(dst, src)
	default:
		for i := 0; i+3 < len(src); i += 4 {
			dst[i], dst[i+1], dst[i+2], dst[i+3] = src[i], src[i+1], src[i+2], 255
		}
	}
}
