//go:build windows

package desktop

import (
	"bytes"
	"image"
	"testing"
	"unsafe"
)

// The struct layouts below are handed to driver code by pointer; a size error
// silently corrupts memory, so pin them to the SDK values.
func TestMFStructSizes(t *testing.T) {
	ptrSize := unsafe.Sizeof(uintptr(0))
	outBuf := uintptr(32) // DWORD + pad + ptr + DWORD + pad + ptr on 64-bit
	stream := uintptr(72) // 5 UINTs, 4 bytes padding, 6 pointers (d3d11.h)
	if ptrSize == 4 {
		outBuf, stream = 16, 44
	}
	for name, c := range map[string]struct{ got, want uintptr }{
		"MFT_REGISTER_TYPE_INFO":                 {unsafe.Sizeof(mftRegisterTypeInfo{}), 32},
		"MFT_OUTPUT_STREAM_INFO":                 {unsafe.Sizeof(mftOutputStreamInfo{}), 12},
		"MFT_OUTPUT_DATA_BUFFER":                 {unsafe.Sizeof(mftOutputDataBuffer{}), outBuf},
		"VARIANT":                                {unsafe.Sizeof(variant{}), 24}, // 64-bit layout
		"DXGI_RATIONAL":                          {unsafe.Sizeof(dxgiRational{}), 8},
		"D3D11_VIDEO_PROCESSOR_CONTENT_DESC":     {unsafe.Sizeof(vpContentDesc{}), 40},
		"D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC":  {unsafe.Sizeof(vpInputViewDesc{}), 16},
		"D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC": {unsafe.Sizeof(vpOutputViewDesc{}), 16},
		"D3D11_VIDEO_PROCESSOR_STREAM":           {unsafe.Sizeof(vpStream{}), stream},
		"GUID":                                   {unsafe.Sizeof(guid{}), 16},
	} {
		if ptrSize == 4 && name == "VARIANT" {
			continue
		}
		if c.got != c.want {
			t.Errorf("%s: size %d, SDK says %d", name, c.got, c.want)
		}
	}
}

func TestMFTNV12Conversion(t *testing.T) {
	const w, h = 4, 4
	fill := func(r, g, b byte, bgra bool) []byte {
		pix := make([]byte, w*h*4)
		for i := 0; i < w*h; i++ {
			if bgra {
				pix[i*4], pix[i*4+1], pix[i*4+2] = b, g, r
			} else {
				pix[i*4], pix[i*4+1], pix[i*4+2] = r, g, b
			}
			pix[i*4+3] = 255
		}
		return pix
	}
	conv := func(pix []byte, ri, bi int, bt709 bool) (y, u, v byte) {
		dst := make([]byte, w*h*3/2)
		packedToNV12(dst, pix, w*4, w, h, ri, bi, bt709)
		for i := 0; i < w*h; i++ {
			if dst[i] != dst[0] {
				t.Fatalf("flat colour gave a non-flat luma plane: %v", dst[:w*h])
			}
		}
		return dst[0], dst[w*h], dst[w*h+1]
	}
	for _, m709 := range []bool{false, true} {
		if y, u, v := conv(fill(255, 255, 255, false), 0, 2, m709); y != 235 || u != 128 || v != 128 {
			t.Errorf("white (709=%v): Y=%d U=%d V=%d, want 235/128/128", m709, y, u, v)
		}
		if y, u, v := conv(fill(0, 0, 0, false), 0, 2, m709); y != 16 || u != 128 || v != 128 {
			t.Errorf("black (709=%v): Y=%d U=%d V=%d, want 16/128/128", m709, y, u, v)
		}
	}
	// BT.601 pure red is the textbook Y=82 Cb=90 Cr=240.
	y, u, v := conv(fill(255, 0, 0, false), 0, 2, false)
	if y != 82 || u != 90 || v != 240 {
		t.Errorf("red 601: Y=%d U=%d V=%d, want 82/90/240", y, u, v)
	}
	// The same colour read from BGRA bytes must give the same answer.
	y2, u2, v2 := conv(fill(255, 0, 0, true), 2, 0, false)
	if y != y2 || u != u2 || v != v2 {
		t.Errorf("BGRA red %d/%d/%d differs from RGBA red %d/%d/%d", y2, u2, v2, y, u, v)
	}
}

func TestMFTAnnexB(t *testing.T) {
	annexB := []byte{0, 0, 0, 1, 0x67, 1, 2, 0, 0, 1, 0x65, 9}
	if !bytes.Equal(toAnnexB(annexB), annexB) {
		t.Error("an Annex B stream must pass through unchanged")
	}
	avcc := []byte{0, 0, 0, 2, 0x67, 1, 0, 0, 0, 3, 0x65, 8, 9}
	want := []byte{0, 0, 0, 1, 0x67, 1, 0, 0, 0, 1, 0x65, 8, 9}
	if got := toAnnexB(avcc); !bytes.Equal(got, want) {
		t.Errorf("AVCC -> Annex B: got % x want % x", got, want)
	}
	junk := []byte{9, 9, 9, 9, 9}
	if !bytes.Equal(toAnnexB(junk), junk) {
		t.Error("an unparseable stream must be returned as is")
	}
	if !hasNAL(annexB, 5) || !hasNAL(annexB, 7) || hasNAL(annexB, 1) {
		t.Error("hasNAL misreads the NAL types")
	}
}

// synthetic returns a frame with a gradient and a moving box, so every frame
// differs and a P-frame carries data.
func syntheticFrame(w, h, i int) videoFrame {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			o := img.PixOffset(x, y)
			img.Pix[o], img.Pix[o+1], img.Pix[o+2], img.Pix[o+3] = byte(x), byte(y), byte(x+y)/2, 255
		}
	}
	bx := (i * 13) % (w - 80)
	for y := 100; y < 180 && y < h; y++ {
		for x := bx; x < bx+80; x++ {
			o := img.PixOffset(x, y)
			img.Pix[o], img.Pix[o+1], img.Pix[o+2] = 255, 255, 0
		}
	}
	return videoFrame{rgba: img, w: w, h: h, fresh: true}
}

type encOut struct {
	nal []byte
	key bool
}

func feedFrames(t *testing.T, enc videoEncoder, n int, mk func(i int) videoFrame) []encOut {
	t.Helper()
	var outs []encOut
	for i := 0; i < n; i++ {
		nal, key, err := enc.Encode(mk(i))
		if err != nil {
			t.Fatalf("Encode frame %d: %v", i, err)
		}
		if len(nal) > 0 {
			outs = append(outs, encOut{nal, key})
		}
	}
	return outs
}

func checkStream(t *testing.T, outs []encOut) {
	t.Helper()
	if len(outs) == 0 {
		t.Fatal("encoder produced no output")
	}
	if !hasStartCode(outs[0].nal) {
		t.Fatalf("first unit does not start with an Annex B start code: % x", outs[0].nal[:min(16, len(outs[0].nal))])
	}
	if !outs[0].key {
		t.Error("first unit is not flagged as a keyframe")
	}
	if !hasNAL(outs[0].nal, 5) {
		t.Error("first unit has no IDR slice")
	}
	if !hasNAL(outs[0].nal, 7) || !hasNAL(outs[0].nal, 8) {
		t.Error("first unit is missing SPS/PPS")
	}
	for i, o := range outs {
		if !hasStartCode(o.nal) {
			t.Errorf("unit %d lacks a start code", i)
		}
		if o.key != hasNAL(o.nal, 5) {
			t.Errorf("unit %d: keyframe=%v but IDR slice present=%v", i, o.key, hasNAL(o.nal, 5))
		}
	}
}

func testEncoderCPU(t *testing.T, hw bool) {
	enc, err := newMFT(640, 480, 30, 2000, hw)
	if err != nil {
		t.Skipf("no H.264 encoder here: %v", err)
	}
	defer enc.Close()
	mk := func(i int) videoFrame { return syntheticFrame(640, 480, i) }
	outs := feedFrames(t, enc, 30, mk)
	checkStream(t, outs)
	t.Logf("%d units from 30 frames; first %d bytes", len(outs), len(outs[0].nal))
	if len(outs) < 20 {
		t.Errorf("only %d of 30 frames produced output", len(outs))
	}

	// A mismatched frame is rejected, not encoded wrongly.
	if _, _, err := enc.Encode(syntheticFrame(320, 240, 0)); err == nil {
		t.Error("a frame of the wrong size must be an error")
	}

	// ForceKeyframe takes effect within a few frames.
	if err := enc.ForceKeyframe(); err != nil {
		t.Fatal(err)
	}
	seen := false
	for i := 30; i < 50 && !seen; i++ {
		nal, key, err := enc.Encode(mk(i))
		if err != nil {
			t.Fatal(err)
		}
		seen = key && len(nal) > 0
	}
	if !seen {
		t.Error("no keyframe followed ForceKeyframe within 20 frames")
	}

	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Errorf("Close must be idempotent: %v", err)
	}
	if _, _, err := enc.Encode(mk(0)); err == nil {
		t.Error("Encode after Close must fail")
	}
	if err := enc.ForceKeyframe(); err == nil {
		t.Error("ForceKeyframe after Close must fail")
	}
}

// Real encoder, CPU pixels: whatever MFT is preferred on this machine.
func TestMFTEncoderCPUFrames(t *testing.T) { testEncoderCPU(t, true) }

// The Microsoft software encoder specifically, so it is exercised on machines
// that also have a hardware MFT.
func TestMFTEncoderSoftwareCPUFrames(t *testing.T) { testEncoderCPU(t, false) }

// Frames in VRAM: the video processor (and, on a hardware MFT, a zero-copy
// sample) path, falling back to a staging readback.
func TestMFTEncoderGPUFrames(t *testing.T) {
	for _, hw := range []bool{true, false} {
		name := "software"
		if hw {
			name = "preferred"
		}
		t.Run(name, func(t *testing.T) {
			const w, h = 640, 480
			dev, err := newD3DDevice(com{}, "test")
			if err != nil {
				t.Skipf("no D3D11 device: %v", err)
			}
			defer dev.close()
			tex, err := dev.createTexture(w, h, dxgiFormatB8G8R8A8, d3d11UsageDefault, d3d11BindShaderResource, 0)
			if err != nil {
				t.Skipf("no BGRA texture: %v", err)
			}
			defer tex.release()
			gs := &gpuSurface{dev: dev, tex: tex, w: w, h: h}

			enc, err := newMFT(w, h, 30, 2000, hw)
			if err != nil {
				t.Skipf("no H.264 encoder here: %v", err)
			}
			defer enc.Close()

			outs := feedFrames(t, enc, 30, func(i int) videoFrame {
				src := syntheticFrame(w, h, i).rgba
				bgra := make([]byte, len(src.Pix))
				for p := 0; p < len(bgra); p += 4 {
					bgra[p], bgra[p+1], bgra[p+2], bgra[p+3] = src.Pix[p+2], src.Pix[p+1], src.Pix[p], 255
				}
				dev.updateTexture(tex, bgra, w*4)
				return videoFrame{gpu: gs, w: w, h: h, fresh: true}
			})
			checkStream(t, outs)
			m := enc.(*mftEncoder)
			t.Logf("%d units from 30 GPU frames; mft=%q hardware=%v zeroCopy=%v", len(outs), m.src.name, m.src.hw, m.zeroCopy && m.d3d != nil)
			if len(outs) < 20 {
				t.Errorf("only %d of 30 frames produced output", len(outs))
			}
		})
	}
}
