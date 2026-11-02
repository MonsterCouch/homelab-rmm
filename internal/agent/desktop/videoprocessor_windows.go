//go:build windows

package desktop

import (
	"errors"
	"fmt"
	"unsafe"
)

// BGRA -> NV12 conversion on the GPU with the D3D11 video processor, so a
// frame captured into VRAM reaches the encoder without ever visiting system
// memory.

// ID3D11Device and ID3D11DeviceContext are reached through ID3D11VideoDevice
// and ID3D11VideoContext (d3d11.h); slots below are counted from those
// declarations.
const (
	vdevCreateVideoProcessor        = 4  // ID3D11VideoDevice::CreateVideoProcessor
	vdevCreateInputView             = 8  // CreateVideoProcessorInputView
	vdevCreateOutputView            = 9  // CreateVideoProcessorOutputView
	vdevCreateProcessorEnum         = 10 // CreateVideoProcessorEnumerator
	vctxSetOutputTargetRect         = 13 // ID3D11VideoContext::VideoProcessorSetOutputTargetRect
	vctxSetOutputColorSpace         = 15 // VideoProcessorSetOutputColorSpace
	vctxSetStreamFrameFormat        = 27 // VideoProcessorSetStreamFrameFormat
	vctxSetStreamColorSpace         = 28 // VideoProcessorSetStreamColorSpace
	vctxSetStreamSourceRect         = 30 // VideoProcessorSetStreamSourceRect
	vctxSetStreamDestRect           = 31 // VideoProcessorSetStreamDestRect
	vctxVideoProcessorBlt           = 53 // VideoProcessorBlt
	vpUsageOptimalSpeed             = 1  // D3D11_VIDEO_USAGE_OPTIMAL_SPEED
	vpFrameFormatProgressive        = 0  // D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE
	vpvDimensionTexture2D           = 1  // D3D11_VPIV_DIMENSION_TEXTURE2D
	vpovDimensionTexture2D          = 1  // D3D11_VPOV_DIMENSION_TEXTURE2D
	vpColorBT709                    = 1 << 2
	vpColorNominal16235             = 1 << 4 // Nominal_Range = D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_16_235
	nv12RingSize                    = 4
	nv12BindFlags            uint32 = d3d11BindRenderTarget | d3d11BindShaderResource
)

// dxgiRational is DXGI_RATIONAL.
type dxgiRational struct{ Numerator, Denominator uint32 }

// vpContentDesc is D3D11_VIDEO_PROCESSOR_CONTENT_DESC (40 bytes).
type vpContentDesc struct {
	InputFrameFormat uint32
	InputFrameRate   dxgiRational
	InputWidth       uint32
	InputHeight      uint32
	OutputFrameRate  dxgiRational
	OutputWidth      uint32
	OutputHeight     uint32
	Usage            uint32
}

// vpInputViewDesc is D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC (16 bytes).
type vpInputViewDesc struct {
	FourCC        uint32
	ViewDimension uint32
	MipSlice      uint32
	ArraySlice    uint32
}

// vpOutputViewDesc is D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC (16 bytes; the
// union is as large as D3D11_TEX2D_ARRAY_VPOV).
type vpOutputViewDesc struct {
	ViewDimension uint32
	MipSlice      uint32
	FirstSlice    uint32
	ArraySize     uint32
}

// vpStream is D3D11_VIDEO_PROCESSOR_STREAM (64 bytes on 64-bit).
type vpStream struct {
	Enable             int32
	OutputIndex        uint32
	InputFrameOrField  uint32
	PastFrames         uint32
	FutureFrames       uint32
	PastSurfaces       unsafe.Pointer
	InputSurface       unsafe.Pointer
	FutureSurfaces     unsafe.Pointer
	PastSurfacesRight  unsafe.Pointer
	InputSurfaceRight  unsafe.Pointer
	FutureSurfacesRght unsafe.Pointer
}

// vpConverter owns the video processor for one (device, source size, encode
// size) combination and a small ring of NV12 destination textures. A ring
// matters because the encoder may still be reading the previous frame's
// texture when the next conversion starts.
type vpConverter struct {
	dev        *d3dDevice
	vdev, vctx com
	enum, proc com

	ring     []com
	outViews []com
	next     int

	inTex  unsafe.Pointer // the texture inView was made for
	inView com
	mid    com // render-target copy of the source, when the source itself is not accepted

	srcW, srcH int
	encW, encH int
}

// newVPConverter builds the converter. It fails (cleanly) on a device that was
// created without video support or a driver that cannot do BGRA->NV12.
func newVPConverter(dev *d3dDevice, srcW, srcH, encW, encH, fps int, bt709 bool) (*vpConverter, error) {
	v := &vpConverter{dev: dev, srcW: srcW, srcH: srcH, encW: encW, encH: encH}
	ok := false
	defer func() {
		if !ok {
			v.close()
		}
	}()
	var err error
	if v.vdev, err = dev.dev.queryInterface(&iidID3D11VideoDevice); err != nil {
		return nil, fmt.Errorf("device has no video support: %w", err)
	}
	if v.vctx, err = dev.ctx.queryInterface(&iidID3D11VideoCtx); err != nil {
		return nil, fmt.Errorf("context has no video support: %w", err)
	}

	desc := heapNew[vpContentDesc]()
	*desc = vpContentDesc{
		InputFrameFormat: vpFrameFormatProgressive,
		InputFrameRate:   dxgiRational{uint32(fps), 1},
		InputWidth:       uint32(srcW), InputHeight: uint32(srcH),
		OutputFrameRate: dxgiRational{uint32(fps), 1},
		OutputWidth:     uint32(encW), OutputHeight: uint32(encH),
		Usage: vpUsageOptimalSpeed,
	}
	out := heapNew[unsafe.Pointer]()
	if err := check(v.vdev.call(vdevCreateProcessorEnum, ptr(desc), ptr(out))); err != nil {
		return nil, fmt.Errorf("CreateVideoProcessorEnumerator: %w", err)
	}
	v.enum = com{*out}
	*out = nil
	if err := check(v.vdev.call(vdevCreateVideoProcessor, uintptr(v.enum.p), 0, ptr(out))); err != nil {
		return nil, fmt.Errorf("CreateVideoProcessor: %w", err)
	}
	v.proc = com{*out}

	// Colour: RGB full range in, limited-range YCbCr out. The matrix follows
	// the height the same way decoders guess it when a stream does not say.
	cs := heapNew[uint32]()
	*cs = vpColorNominal16235
	if bt709 {
		*cs |= vpColorBT709
	}
	v.vctx.call(vctxSetOutputColorSpace, uintptr(v.proc.p), ptr(cs))
	in := heapNew[uint32]()
	v.vctx.call(vctxSetStreamColorSpace, uintptr(v.proc.p), 0, ptr(in))
	v.vctx.call(vctxSetStreamFrameFormat, uintptr(v.proc.p), 0, vpFrameFormatProgressive)
	if srcW != encW || srcH != encH { // odd source size: crop to the even encode size
		r := heapNew[winRect]()
		*r = winRect{0, 0, int32(encW), int32(encH)}
		v.vctx.call(vctxSetStreamSourceRect, uintptr(v.proc.p), 0, 1, ptr(r))
		v.vctx.call(vctxSetStreamDestRect, uintptr(v.proc.p), 0, 1, ptr(r))
		v.vctx.call(vctxSetOutputTargetRect, uintptr(v.proc.p), 1, ptr(r))
	}

	for i := 0; i < nv12RingSize; i++ {
		tex, err := dev.createTexture(encW, encH, dxgiFormatNV12, d3d11UsageDefault, nv12BindFlags, 0)
		if err != nil {
			return nil, err
		}
		v.ring = append(v.ring, tex)
		od := heapNew[vpOutputViewDesc]()
		*od = vpOutputViewDesc{ViewDimension: vpovDimensionTexture2D}
		if err := check(v.vdev.call(vdevCreateOutputView, uintptr(tex.p), uintptr(v.enum.p), ptr(od), ptr(out))); err != nil {
			return nil, fmt.Errorf("CreateVideoProcessorOutputView: %w", err)
		}
		v.outViews = append(v.outViews, com{*out})
	}
	ok = true
	return v, nil
}

// convert blits src (a BGRA texture on v.dev) into the next NV12 ring texture
// and returns it. The texture stays owned by the converter.
//
// Some drivers (Intel) refuse a video-processor input view over a texture whose
// only bind flag is D3D11_BIND_SHADER_RESOURCE, which is exactly how the DXGI
// capturer creates its snapshot. When that happens the frame is first copied,
// on the GPU, into a render-target texture the processor does accept.
func (v *vpConverter) convert(src com) (com, error) {
	if src.nil() {
		return com{}, errors.New("nil source texture")
	}
	in := src
	if !v.mid.nil() {
		v.dev.copyResource(v.mid, src)
		in = v.mid
	}
	if v.inTex != in.p {
		err := v.makeInputView(in)
		if err != nil && v.mid.nil() {
			mid, merr := v.dev.createTexture(v.srcW, v.srcH, dxgiFormatB8G8R8A8, d3d11UsageDefault, d3d11BindRenderTarget, 0)
			if merr != nil {
				return com{}, err
			}
			v.mid = mid
			v.dev.copyResource(v.mid, src)
			in = v.mid
			err = v.makeInputView(in)
		}
		if err != nil {
			return com{}, err
		}
	}
	i := v.next
	v.next = (v.next + 1) % len(v.ring)
	st := heapNew[vpStream]()
	*st = vpStream{Enable: 1, InputSurface: v.inView.p}
	if err := check(v.vctx.call(vctxVideoProcessorBlt, uintptr(v.proc.p), uintptr(v.outViews[i].p), 0, 1, ptr(st))); err != nil {
		return com{}, fmt.Errorf("VideoProcessorBlt: %w", err)
	}
	return v.ring[i], nil
}

// makeInputView (re)creates the processor input view over tex.
func (v *vpConverter) makeInputView(tex com) error {
	v.inView.release()
	v.inTex = nil
	id := heapNew[vpInputViewDesc]()
	*id = vpInputViewDesc{ViewDimension: vpvDimensionTexture2D}
	out := heapNew[unsafe.Pointer]()
	if err := check(v.vdev.call(vdevCreateInputView, uintptr(tex.p), uintptr(v.enum.p), ptr(id), ptr(out))); err != nil {
		return fmt.Errorf("CreateVideoProcessorInputView: %w", err)
	}
	v.inView = com{*out}
	v.inTex = tex.p
	return nil
}

func (v *vpConverter) close() {
	if v == nil {
		return
	}
	v.inView.release()
	v.mid.release()
	for i := range v.outViews {
		v.outViews[i].release()
	}
	for i := range v.ring {
		v.ring[i].release()
	}
	v.proc.release()
	v.enum.release()
	v.vctx.release()
	v.vdev.release()
}
