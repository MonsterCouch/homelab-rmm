//go:build windows

package desktop

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Direct3D 11 plumbing shared by the DXGI capturer and the H.264 encoder's
// colour-space converter. Everything is raw vtable dispatch (see com_windows.go).

var (
	d3d11DLL           = windows.NewLazySystemDLL("d3d11.dll")
	procD3D11CreateDev = d3d11DLL.NewProc("D3D11CreateDevice")
)

// DXGI formats and D3D11 flags (dxgiformat.h, d3d11.h).
const (
	dxgiFormatB8G8R8A8 = 87
	dxgiFormatNV12     = 103

	d3d11UsageDefault = 0
	d3d11UsageStaging = 3

	d3d11BindShaderResource = 0x8
	d3d11BindRenderTarget   = 0x20

	d3d11CPUAccessWrite = 0x10000
	d3d11CPUAccessRead  = 0x20000

	d3d11MapRead  = 1
	d3d11MapWrite = 2

	d3d11CreateBGRASupport  = 0x20
	d3d11CreateVideoSupport = 0x800
	d3d11SDKVersion         = 7
	d3dDriverTypeUnknown    = 0
	d3dDriverTypeHardware   = 1
	d3dFeatureLevel11_1     = 0xb100
	d3dFeatureLevel11_0     = 0xb000
	d3dFeatureLevel10_1     = 0xa100
	d3dFeatureLevel10_0     = 0xa000
)

// ID3D11Device / ID3D11DeviceContext vtable slots used here.
const (
	devCreateTexture2D = 5

	ctxMap                   = 14
	ctxUnmap                 = 15
	ctxCopySubresourceRegion = 46
	ctxCopyResource          = 47
	ctxUpdateSubresource     = 48
	ctxFlush                 = 111

	tex2DGetDesc = 10
)

// texture2DDesc is D3D11_TEXTURE2D_DESC (44 bytes).
type texture2DDesc struct {
	Width, Height  uint32
	MipLevels      uint32
	ArraySize      uint32
	Format         uint32
	SampleCount    uint32
	SampleQuality  uint32
	Usage          uint32
	BindFlags      uint32
	CPUAccessFlags uint32
	MiscFlags      uint32
}

// mappedSubresource is D3D11_MAPPED_SUBRESOURCE.
type mappedSubresource struct {
	Data       unsafe.Pointer
	RowPitch   uint32
	DepthPitch uint32
}

// d3dDevice is a D3D11 device and its immediate context. The immediate
// context is not thread-safe: every method must be called from one OS thread
// (the capture loop is already locked to one).
type d3dDevice struct {
	dev  com
	ctx  com
	name string // adapter description, for logs
}

// newD3DDevice creates a device on adapter, or on the default hardware
// adapter when adapter is nil. Passing the adapter that owns the display
// being duplicated is what avoids DXGI_ERROR_UNSUPPORTED on hybrid-GPU
// laptops: with a nil adapter D3D11 picks the high-performance GPU, while
// the output is wired to the integrated one, and DuplicateOutput then
// refuses a device that is not on the output's adapter.
func newD3DDevice(adapter com, name string) (*d3dDevice, error) {
	if err := procD3D11CreateDev.Find(); err != nil {
		return nil, fmt.Errorf("d3d11.dll: %w", err)
	}
	driver := uintptr(d3dDriverTypeHardware)
	if !adapter.nil() {
		driver = d3dDriverTypeUnknown // required whenever an adapter is given
	}
	levels := [][]uint32{
		{d3dFeatureLevel11_1, d3dFeatureLevel11_0, d3dFeatureLevel10_1, d3dFeatureLevel10_0},
		{d3dFeatureLevel11_0, d3dFeatureLevel10_1, d3dFeatureLevel10_0}, // Windows 7: no 11_1 -> E_INVALIDARG
	}
	var lastErr error
	for _, flags := range []uint32{d3d11CreateBGRASupport | d3d11CreateVideoSupport, d3d11CreateBGRASupport} {
		for _, fl := range levels {
			var dev, ctx unsafe.Pointer
			var got uint32
			r, _, _ := procD3D11CreateDev.Call(
				uintptr(adapter.p), driver, 0, uintptr(flags),
				uintptr(unsafe.Pointer(&fl[0])), uintptr(len(fl)), d3d11SDKVersion,
				uintptr(unsafe.Pointer(&dev)), uintptr(unsafe.Pointer(&got)), uintptr(unsafe.Pointer(&ctx)))
			if err := check(r); err != nil {
				lastErr = err
				continue
			}
			return &d3dDevice{dev: com{dev}, ctx: com{ctx}, name: name}, nil
		}
	}
	return nil, fmt.Errorf("D3D11CreateDevice: %w", lastErr)
}

func (d *d3dDevice) close() {
	if d == nil {
		return
	}
	d.ctx.release()
	d.dev.release()
}

// createTexture makes a 2-D texture with one mip level and no multisampling.
func (d *d3dDevice) createTexture(w, h int, format, usage, bind, cpu uint32) (com, error) {
	if w <= 0 || h <= 0 {
		return com{}, errors.New("texture has no size")
	}
	desc := texture2DDesc{
		Width: uint32(w), Height: uint32(h), MipLevels: 1, ArraySize: 1, Format: format,
		SampleCount: 1, Usage: usage, BindFlags: bind, CPUAccessFlags: cpu,
	}
	var tex unsafe.Pointer
	if err := check(d.dev.call(devCreateTexture2D, uintptr(unsafe.Pointer(&desc)), 0, uintptr(unsafe.Pointer(&tex)))); err != nil {
		return com{}, fmt.Errorf("CreateTexture2D %dx%d format %d: %w", w, h, format, err)
	}
	return com{tex}, nil
}

// copyResource copies src to dst on the GPU (same size and format).
func (d *d3dDevice) copyResource(dst, src com) {
	d.ctx.call(ctxCopyResource, uintptr(dst.p), uintptr(src.p))
}

// mapTexture maps a staging texture for reading. The call blocks until the
// GPU has finished any pending copy into it.
func (d *d3dDevice) mapRead(tex com) (mappedSubresource, error) {
	var m mappedSubresource
	if err := check(d.ctx.call(ctxMap, uintptr(tex.p), 0, d3d11MapRead, 0, uintptr(unsafe.Pointer(&m)))); err != nil {
		return m, fmt.Errorf("Map: %w", err)
	}
	return m, nil
}

func (d *d3dDevice) unmap(tex com) { d.ctx.call(ctxUnmap, uintptr(tex.p), 0) }

// updateTexture uploads tightly-packed or pitched system-memory pixels into a
// default-usage texture.
func (d *d3dDevice) updateTexture(tex com, pix []byte, rowPitch int) {
	if len(pix) == 0 {
		return
	}
	d.ctx.call(ctxUpdateSubresource, uintptr(tex.p), 0, 0, uintptr(unsafe.Pointer(&pix[0])), uintptr(rowPitch), 0)
}

// textureSize reads a texture's dimensions.
func textureSize(tex com) (w, h int) {
	var desc texture2DDesc
	tex.call(tex2DGetDesc, uintptr(unsafe.Pointer(&desc)))
	return int(desc.Width), int(desc.Height)
}

// gpuSurface is a BGRA texture living in VRAM, tied to the device it was
// created on. It is the payload of videoFrame.gpu on Windows.
type gpuSurface struct {
	dev  *d3dDevice
	tex  com
	w, h int
}

// unsafeBytes views n bytes of driver-owned memory (a mapped texture) as a
// slice. The slice must not outlive the Unmap.
func unsafeBytes(p unsafe.Pointer, n int) []byte {
	if p == nil || n <= 0 {
		return nil
	}
	return unsafe.Slice((*byte)(p), n)
}
