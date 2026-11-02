//go:build windows

package desktop

import (
	"errors"
	"fmt"
	"image"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DXGI Desktop Duplication through raw COM. Pipeline:
//
//	CreateDXGIFactory1 -> EnumAdapters1 -> EnumOutputs (target monitor)
//	-> D3D11CreateDevice(that adapter) -> IDXGIOutput1 -> DuplicateOutput

var (
	dxgiDLL               = windows.NewLazySystemDLL("dxgi.dll")
	procCreateDXGIFactory = dxgiDLL.NewProc("CreateDXGIFactory1")
)

// vtable slots (generated from dxgi.h / dxgi1_2.h).
const (
	factEnumAdapters1 = 12

	adapterEnumOutputs = 7
	adapterGetDesc1    = 10

	outputGetDesc          = 7
	output1DuplicateOutput = 22

	dupGetDesc          = 7
	dupAcquireNextFrame = 8
	dupGetDirtyRects    = 9
	dupGetMoveRects     = 10
	dupGetPointerShape  = 11
	dupReleaseFrame     = 14
)

// DXGI_MODE_ROTATION.
const (
	dxgiRotationUnspecified = 0
	dxgiRotationIdentity    = 1
)

// DXGI_ADAPTER_FLAG_SOFTWARE: the Microsoft Basic Render Driver and friends.
const dxgiAdapterFlagSoftware = 2

// dxgiAdapterDesc1 is DXGI_ADAPTER_DESC1 (x64 layout, 312 bytes).
type dxgiAdapterDesc1 struct {
	Description           [128]uint16
	VendorID              uint32
	DeviceID              uint32
	SubSysID              uint32
	Revision              uint32
	DedicatedVideoMemory  uintptr
	DedicatedSystemMemory uintptr
	SharedSystemMemory    uintptr
	LuidLow               uint32
	LuidHigh              int32
	Flags                 uint32
	_                     uint32
}

// dxgiOutputDesc is DXGI_OUTPUT_DESC (96 bytes on x64).
type dxgiOutputDesc struct {
	DeviceName        [32]uint16
	Left, Top         int32
	Right, Bottom     int32
	AttachedToDesktop int32
	Rotation          uint32
	Monitor           uintptr
}

// dxgiOutduplDesc is DXGI_OUTDUPL_DESC (36 bytes).
type dxgiOutduplDesc struct {
	Width, Height              uint32
	RefreshNum, RefreshDen     uint32
	Format                     uint32
	ScanlineOrdering           uint32
	Scaling                    uint32
	Rotation                   uint32
	DesktopImageInSystemMemory int32
}

// dxgiFrameInfo is DXGI_OUTDUPL_FRAME_INFO (48 bytes).
type dxgiFrameInfo struct {
	LastPresentTime           int64
	LastMouseUpdateTime       int64
	AccumulatedFrames         uint32
	RectsCoalesced            int32
	ProtectedContentMaskedOut int32
	PointerX, PointerY        int32
	PointerVisible            int32
	TotalMetadataBufferSize   uint32
	PointerShapeBufferSize    uint32
}

// dxgiMoveRect is DXGI_OUTDUPL_MOVE_RECT.
type dxgiMoveRect struct {
	SrcX, SrcY                           int32
	DstLeft, DstTop, DstRight, DstBottom int32
}

// dxgiPointerShapeInfo is DXGI_OUTDUPL_POINTER_SHAPE_INFO.
type dxgiPointerShapeInfo struct {
	Type          uint32
	Width, Height uint32
	Pitch         uint32
	HotX, HotY    int32
}

type winRect struct{ Left, Top, Right, Bottom int32 }

// outputInfo describes one display attached to the desktop, and where it
// lives so the duplicator can be created on the right adapter.
type outputInfo struct {
	adapterIdx, outputIdx int
	adapterName           string
	adapterLuid           uint64
	software              bool
	deviceName            string // \\.\DISPLAY1
	bounds                image.Rectangle
	rotation              uint32
}

func utf16Name(s []uint16) string { return windows.UTF16ToString(s) }

func createFactory() (com, error) {
	if err := procCreateDXGIFactory.Find(); err != nil {
		return com{}, fmt.Errorf("dxgi.dll: %w", err)
	}
	var f unsafe.Pointer
	r, _, _ := procCreateDXGIFactory.Call(uintptr(unsafe.Pointer(&iidIDXGIFactory1)), uintptr(unsafe.Pointer(&f)))
	if err := check(r); err != nil {
		return com{}, fmt.Errorf("CreateDXGIFactory1: %w", err)
	}
	return com{f}, nil
}

// enumAdapter returns adapter i (a new reference) or ok=false past the end.
func enumAdapter(factory com, i int) (adapter com, desc dxgiAdapterDesc1, ok bool, err error) {
	var a unsafe.Pointer
	r := factory.call(factEnumAdapters1, u32(i), uintptr(unsafe.Pointer(&a)))
	if uint32(r) == hrDXGINotFound {
		return com{}, desc, false, nil
	}
	if err := check(r); err != nil {
		return com{}, desc, false, fmt.Errorf("EnumAdapters1(%d): %w", i, err)
	}
	ad := com{a}
	if err := check(ad.call(adapterGetDesc1, uintptr(unsafe.Pointer(&desc)))); err != nil {
		ad.release()
		return com{}, desc, false, fmt.Errorf("GetDesc1: %w", err)
	}
	return ad, desc, true, nil
}

// enumOutput returns output j of adapter (a new reference) or ok=false past the end.
func enumOutput(adapter com, j int) (output com, desc dxgiOutputDesc, ok bool, err error) {
	var o unsafe.Pointer
	r := adapter.call(adapterEnumOutputs, u32(j), uintptr(unsafe.Pointer(&o)))
	if uint32(r) == hrDXGINotFound {
		return com{}, desc, false, nil
	}
	if err := check(r); err != nil {
		return com{}, desc, false, fmt.Errorf("EnumOutputs(%d): %w", j, err)
	}
	out := com{o}
	if err := check(out.call(outputGetDesc, uintptr(unsafe.Pointer(&desc)))); err != nil {
		out.release()
		return com{}, desc, false, fmt.Errorf("IDXGIOutput::GetDesc: %w", err)
	}
	return out, desc, true, nil
}

// listOutputs walks every adapter's outputs and returns those attached to
// the desktop. Outputs on software adapters are included but flagged, so the
// caller can prefer a hardware owner when both claim the same display.
func listOutputs() ([]outputInfo, error) {
	f, err := createFactory()
	if err != nil {
		return nil, err
	}
	defer f.release()
	var res []outputInfo
	for i := 0; i < 16; i++ {
		ad, adDesc, ok, err := enumAdapter(f, i)
		if err != nil {
			return res, err
		}
		if !ok {
			break
		}
		name := utf16Name(adDesc.Description[:])
		for j := 0; j < 16; j++ {
			out, od, ok, err := enumOutput(ad, j)
			if err != nil || !ok {
				break
			}
			out.release()
			if od.AttachedToDesktop == 0 {
				continue
			}
			b := image.Rect(int(od.Left), int(od.Top), int(od.Right), int(od.Bottom))
			if b.Empty() {
				continue
			}
			res = append(res, outputInfo{
				adapterIdx: i, outputIdx: j, adapterName: name,
				adapterLuid: uint64(adDesc.LuidLow) | uint64(uint32(adDesc.LuidHigh))<<32,
				software:    adDesc.Flags&dxgiAdapterFlagSoftware != 0,
				deviceName:  utf16Name(od.DeviceName[:]),
				bounds:      b, rotation: od.Rotation,
			})
		}
		ad.release()
	}
	return res, nil
}

// duplicator owns one IDXGIOutputDuplication and the D3D11 device it was
// created on.
type duplicator struct {
	dev  *d3dDevice
	dup  com
	info outputInfo
	w, h int
	held bool // a frame is acquired and not yet released
	meta []byte
}

// errDuplicationUnsupported marks configurations where Desktop Duplication
// cannot work and the GDI path should be used instead.
var errDuplicationUnsupported = errors.New("desktop duplication unsupported for this output")

// openDuplicator creates the duplication for the output at info, on the
// adapter that owns it (the hybrid-GPU fix).
func openDuplicator(info outputInfo) (*duplicator, error) {
	if info.rotation > dxgiRotationIdentity {
		// Rotated displays deliver the surface unrotated and would need a
		// rotation pass; the GDI path gets those right already.
		return nil, fmt.Errorf("%w: output is rotated", errDuplicationUnsupported)
	}
	f, err := createFactory()
	if err != nil {
		return nil, err
	}
	defer f.release()
	ad, adDesc, ok, err := enumAdapter(f, info.adapterIdx)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("adapter disappeared")
	}
	defer ad.release()
	if got := uint64(adDesc.LuidLow) | uint64(uint32(adDesc.LuidHigh))<<32; got != info.adapterLuid {
		return nil, errors.New("adapter order changed while opening the duplication")
	}
	out, _, ok, err := enumOutput(ad, info.outputIdx)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("output disappeared")
	}
	defer out.release()

	dev, err := newD3DDevice(ad, info.adapterName)
	if err != nil {
		return nil, err
	}
	out1, err := out.queryInterface(&iidIDXGIOutput1)
	if err != nil {
		dev.close()
		return nil, fmt.Errorf("IDXGIOutput1: %w", err)
	}
	defer out1.release()

	var dup unsafe.Pointer
	if err := check(out1.call(output1DuplicateOutput, uintptr(dev.dev.p), uintptr(unsafe.Pointer(&dup)))); err != nil {
		dev.close()
		if isHR(err, hrEInvalidArg) {
			// Documented meaning: this process already duplicates the
			// output. Only one capturer per output may be live at a time.
			return nil, fmt.Errorf("DuplicateOutput on %s: output already duplicated by this process: %w", info.deviceName, err)
		}
		return nil, fmt.Errorf("DuplicateOutput on %s (%s): %w", info.deviceName, info.adapterName, err)
	}
	d := &duplicator{dev: dev, dup: com{dup}, info: info}
	var desc dxgiOutduplDesc
	d.dup.call(dupGetDesc, uintptr(unsafe.Pointer(&desc)))
	d.w, d.h = int(desc.Width), int(desc.Height)
	if desc.DesktopImageInSystemMemory != 0 || desc.Format != dxgiFormatB8G8R8A8 {
		d.close()
		return nil, fmt.Errorf("%w: surface is not a BGRA texture (format %d, system memory %d)",
			errDuplicationUnsupported, desc.Format, desc.DesktopImageInSystemMemory)
	}
	if d.w != info.bounds.Dx() || d.h != info.bounds.Dy() {
		d.close()
		return nil, fmt.Errorf("duplication is %dx%d but the output is %v", d.w, d.h, info.bounds)
	}
	return d, nil
}

func (d *duplicator) close() {
	if d == nil {
		return
	}
	d.releaseFrame()
	d.dup.release()
	d.dev.close()
}

func (d *duplicator) releaseFrame() {
	if d.held {
		d.dup.call(dupReleaseFrame)
		d.held = false
	}
}

// acquiredFrame is the metadata of one AcquireNextFrame.
type acquiredFrame struct {
	info             dxgiFrameInfo
	tex              com // ID3D11Texture2D; valid until releaseFrame; owned by the duplicator
	resource         com
	dirty            []image.Rectangle // monitor-local, only when metadata was reported
	moves            []dxgiMoveRect
	shape            *pointerShape // non-nil when the cursor image changed
	hasPointerUpdate bool
}

// acquire waits up to timeoutMs for the next desktop update. A timeout is
// returned as an error satisfying isHR(err, hrDXGIWaitTimeout); the caller
// then keeps the last frame. The returned texture belongs to DXGI until
// releaseFrame, so copy out of it promptly.
func (d *duplicator) acquire(timeoutMs int) (*acquiredFrame, error) {
	d.releaseFrame()
	var fr acquiredFrame
	var res unsafe.Pointer
	if err := check(d.dup.call(dupAcquireNextFrame, u32(timeoutMs), uintptr(unsafe.Pointer(&fr.info)), uintptr(unsafe.Pointer(&res)))); err != nil {
		return nil, err
	}
	d.held = true
	fr.resource = com{res}
	defer fr.resource.release()
	fr.hasPointerUpdate = fr.info.LastMouseUpdateTime != 0

	// A frame that only moved the mouse has no new desktop image to read.
	if fr.info.LastPresentTime != 0 {
		tex, err := fr.resource.queryInterface(&iidID3D11Texture2D)
		if err != nil {
			d.releaseFrame()
			return nil, fmt.Errorf("frame is not a texture: %w", err)
		}
		fr.tex = tex // released by the caller via frame.close()
	}
	if fr.info.TotalMetadataBufferSize > 0 {
		fr.dirty, fr.moves = d.readRects(int(fr.info.TotalMetadataBufferSize))
	}
	if fr.info.PointerShapeBufferSize > 0 {
		fr.shape = d.readShape(int(fr.info.PointerShapeBufferSize))
	}
	// resource is released by the deferred call; tex holds its own reference.
	r := fr
	r.resource = com{}
	return &r, nil
}

func (f *acquiredFrame) close() { f.tex.release() }

// readRects reads the driver's move rectangles then dirty rectangles into
// monitor-local image rectangles. Move destinations count as dirty too: the
// pixels there changed even though the driver did not repaint them.
func (d *duplicator) readRects(total int) (dirty []image.Rectangle, moves []dxgiMoveRect) {
	if total <= 0 || total > 8<<20 {
		return nil, nil
	}
	if cap(d.meta) < total {
		d.meta = make([]byte, total)
	}
	buf := d.meta[:total]

	var moveBytes uint32
	if err := check(d.dup.call(dupGetMoveRects, u32(total), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&moveBytes)))); err == nil && moveBytes > 0 {
		n := int(moveBytes) / int(unsafe.Sizeof(dxgiMoveRect{}))
		moves = make([]dxgiMoveRect, n)
		copy(moves, unsafe.Slice((*dxgiMoveRect)(unsafe.Pointer(&buf[0])), n))
		for _, m := range moves {
			dirty = append(dirty, image.Rect(int(m.DstLeft), int(m.DstTop), int(m.DstRight), int(m.DstBottom)))
		}
	}
	var dirtyBytes uint32
	if err := check(d.dup.call(dupGetDirtyRects, u32(total), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&dirtyBytes)))); err == nil && dirtyBytes > 0 {
		n := int(dirtyBytes) / int(unsafe.Sizeof(winRect{}))
		for _, r := range unsafe.Slice((*winRect)(unsafe.Pointer(&buf[0])), n) {
			dirty = append(dirty, image.Rect(int(r.Left), int(r.Top), int(r.Right), int(r.Bottom)))
		}
	}
	if len(dirty) == 0 {
		// Metadata was announced but nothing readable came back: say
		// "everything changed" rather than "nothing", which would freeze
		// the picture.
		dirty = []image.Rectangle{image.Rect(0, 0, d.w, d.h)}
	}
	return dirty, moves
}

// readShape fetches the cursor bitmap.
func (d *duplicator) readShape(size int) *pointerShape {
	if size <= 0 || size > 4<<20 {
		return nil
	}
	buf := make([]byte, size)
	var need uint32
	var info dxgiPointerShapeInfo
	if err := check(d.dup.call(dupGetPointerShape, u32(size), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&need)), uintptr(unsafe.Pointer(&info)))); err != nil {
		return nil
	}
	return newPointerShape(int(info.Type), int(info.Width), int(info.Height), int(info.Pitch), int(info.HotX), int(info.HotY), buf[:min(int(need), size)])
}
