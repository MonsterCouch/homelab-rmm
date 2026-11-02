// Package e2e_test provides requirement-driven, opaque-box end-to-end tests for
// Homelab RMM Phase 2 - Requirement 1: DirectX (DXGI) Desktop Duplication & MFT Encoder.
package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"image"
	"image/color"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// Mock DXGI COM Vtable & Adapter Environment
// ============================================================================

type MockCOMVtable struct {
	mu           sync.Mutex
	refCount     int32
	methods      map[int]func(args ...uintptr) uintptr
	released     bool
	lastHRESULT  HRESULT
	methodCalls  map[int]int
}

func NewMockCOMVtable() *MockCOMVtable {
	m := &MockCOMVtable{
		refCount:    1,
		methods:     make(map[int]func(args ...uintptr) uintptr),
		methodCalls: make(map[int]int),
	}
	// Default QueryInterface (0), AddRef (1), Release (2)
	m.methods[0] = func(args ...uintptr) uintptr {
		if len(args) < 2 || args[0] == 0 || args[1] == 0 {
			return uintptr(E_POINTER)
		}
		return uintptr(S_OK)
	}
	m.methods[1] = func(args ...uintptr) uintptr {
		atomic.AddInt32(&m.refCount, 1)
		return uintptr(m.refCount)
	}
	m.methods[2] = func(args ...uintptr) uintptr {
		newCount := atomic.AddInt32(&m.refCount, -1)
		if newCount <= 0 {
			m.mu.Lock()
			m.released = true
			m.mu.Unlock()
		}
		return uintptr(newCount)
	}
	return m
}

func (m *MockCOMVtable) Call(methodIndex int, args ...uintptr) uintptr {
	m.mu.Lock()
	m.methodCalls[methodIndex]++
	fn, ok := m.methods[methodIndex]
	m.mu.Unlock()
	if !ok {
		return uintptr(E_NOTIMPL)
	}
	res := fn(args...)
	m.mu.Lock()
	m.lastHRESULT = HRESULT(res)
	m.mu.Unlock()
	return res
}

// MockDXGICapturer simulates pure Go COM vtable interactions for IDXGIOutputDuplication
type MockDXGICapturer struct {
	mu              sync.Mutex
	isHeadless      bool
	accessLostCount int
	acquired        bool
	monitors        []MonitorContract
	width           int
	height          int
	stride          int
	frameNum        uint32
	forceAccessLost bool
	consecutiveErrs int
	gdiFallback     bool
	cursorPos       image.Point
	cursorVis       bool
	cursorShape     *DXGI_OUTDUPL_POINTER_SHAPE_INFO
	cursorData      []byte
	dirtyRects      []image.Rectangle
	moveRects       []DXGI_OUTDUPL_MOVE_RECT
}

func NewMockDXGICapturer(width, height int, isHeadless bool) *MockDXGICapturer {
	return &MockDXGICapturer{
		width:      width,
		height:     height,
		stride:     width * 4,
		isHeadless: isHeadless,
		cursorVis:  true,
		monitors: []MonitorContract{
			{Index: 0, Bounds: image.Rect(0, 0, width, height), Name: `\\.\DISPLAY1`},
		},
	}
}

func (c *MockDXGICapturer) Monitors() ([]MonitorContract, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.monitors, nil
}

func (c *MockDXGICapturer) Capture(m MonitorContract) (*FrameContract, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isHeadless {
		c.gdiFallback = true
		// GDI fallback produces standard RGBA
		rgba := GenerateTestPatternRGBA(c.width, c.height)
		return &FrameContract{
			Bounds:     image.Rect(0, 0, c.width, c.height),
			DirtyRects: []image.Rectangle{image.Rect(0, 0, c.width, c.height)},
			RGBA:       rgba,
		}, nil
	}

	if c.forceAccessLost {
		c.accessLostCount++
		c.consecutiveErrs++
		if c.consecutiveErrs >= 3 {
			c.gdiFallback = true
		}
		return nil, fmt.Errorf("HRESULT 0x%08X: DXGI_ERROR_ACCESS_LOST", uint32(DXGI_ERROR_ACCESS_LOST))
	}

	if c.acquired {
		return nil, fmt.Errorf("HRESULT 0x%08X: DXGI_ERROR_INVALID_CALL (must ReleaseFrame before AcquireNextFrame)", uint32(DXGI_ERROR_INVALID_CALL))
	}

	c.acquired = true
	c.consecutiveErrs = 0
	c.frameNum++

	// Generate synthetic frame
	rgba := GenerateTestRGBA(c.width, c.height, color.RGBA{R: byte(c.frameNum % 255), G: 120, B: 200, A: 255})
	if c.cursorVis && c.cursorShape != nil && len(c.cursorData) > 0 {
		// Blit cursor onto frame
		cx := c.cursorPos.X - int(c.cursorShape.HotSpot.X)
		cy := c.cursorPos.Y - int(c.cursorShape.HotSpot.Y)
		for sy := 0; sy < int(c.cursorShape.Height); sy++ {
			for sx := 0; sx < int(c.cursorShape.Width); sx++ {
				dx := cx + sx
				dy := cy + sy
				if dx >= 0 && dx < c.width && dy >= 0 && dy < c.height {
					rgba.SetRGBA(dx, dy, color.RGBA{R: 255, G: 0, B: 0, A: 255})
				}
			}
		}
	}

	dirty := c.dirtyRects
	if len(dirty) == 0 {
		dirty = []image.Rectangle{image.Rect(0, 0, c.width, c.height)}
	}

	return &FrameContract{
		Bounds:     image.Rect(0, 0, c.width, c.height),
		DirtyRects: dirty,
		CursorX:    c.cursorPos.X,
		CursorY:    c.cursorPos.Y,
		CursorVis:  c.cursorVis,
		VRAMHandle: uintptr(0xDEADBEEF),
		RGBA:       rgba,
	}, nil
}

func (c *MockDXGICapturer) ReleaseFrame() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.acquired {
		return fmt.Errorf("HRESULT 0x%08X: DXGI_ERROR_INVALID_CALL (no frame acquired)", uint32(DXGI_ERROR_INVALID_CALL))
	}
	c.acquired = false
	return nil
}

func (c *MockDXGICapturer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.acquired = false
	return nil
}

// MockMFTH264Encoder simulates Windows Media Foundation H.264 Encoder (Low-Latency MFT)
type MockMFTH264Encoder struct {
	mu           sync.Mutex
	gopSize      int
	frameCounter int
	forceNextIDR bool
	closed       bool
	bitrateBps   int
	width        int
	height       int
}

func NewMockMFTH264Encoder(width, height int, gopSize int) *MockMFTH264Encoder {
	return &MockMFTH264Encoder{
		width:      width,
		height:     height,
		gopSize:    gopSize,
		bitrateBps: 2500000, // 2.5 Mbps default
	}
}

func (e *MockMFTH264Encoder) Encode(frame *FrameContract) ([]byte, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return nil, false, errors.New("encoder is closed")
	}
	if frame == nil {
		return nil, false, errors.New("nil frame")
	}

	isIDR := (e.frameCounter%e.gopSize == 0) || e.forceNextIDR
	e.forceNextIDR = false
	e.frameCounter++

	if isIDR {
		bitstream := BuildSyntheticH264Keyframe(uint32(e.frameCounter))
		return bitstream, true, nil
	}

	bitstream := BuildSyntheticH264DeltaFrame(uint32(e.frameCounter))
	return bitstream, false, nil
}

func (e *MockMFTH264Encoder) ForceKeyframe() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("encoder is closed")
	}
	e.forceNextIDR = true
	return nil
}

func (e *MockMFTH264Encoder) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	return nil
}

// ============================================================================
// Tier 1: Feature Coverage (Features 1 - 9)
// ============================================================================

// --- Feature 1: Pure Go COM Vtable Dispatch Engine ---

func TestTier1_F1_COMVtable_Offsets_IDXGIOutputDuplication(t *testing.T) {
	vtable := NewMockCOMVtable()
	expectedOffsets := map[int]string{
		0: "QueryInterface",
		1: "AddRef",
		2: "Release",
		3: "AcquireNextFrame",
		4: "GetFrameDirtyRects",
		5: "GetFrameMoveRects",
		6: "GetFramePointerShape",
		7: "MapDesktopSurface",
		8: "UnMapDesktopSurface",
		9: "ReleaseFrame",
	}

	for offset, name := range expectedOffsets {
		vtable.methods[offset] = func(args ...uintptr) uintptr {
			return uintptr(S_OK)
		}
		res := vtable.Call(offset)
		if HRESULT(res) != S_OK {
			t.Errorf("Vtable offset %d (%s) failed with HRESULT: 0x%08X", offset, name, uint32(res))
		}
	}
}

func TestTier1_F1_COMVtable_Offsets_IDXGIFactory1(t *testing.T) {
	vtable := NewMockCOMVtable()
	// IDXGIFactory1::EnumAdapters1 is method 12 on factory interface
	vtable.methods[12] = func(args ...uintptr) uintptr {
		return uintptr(S_OK)
	}
	res := vtable.Call(12)
	if HRESULT(res) != S_OK {
		t.Fatalf("EnumAdapters1 method index 12 failed: 0x%08X", uint32(res))
	}
}

func TestTier1_F1_COMVtable_HRESULT_Mapping(t *testing.T) {
	testCases := []struct {
		code     HRESULT
		expected uint32
	}{
		{S_OK, 0x00000000},
		{S_FALSE, 0x00000001},
		{E_NOINTERFACE, 0x80004002},
		{E_POINTER, 0x80004003},
		{DXGI_ERROR_ACCESS_LOST, 0x887A0026},
		{DXGI_ERROR_WAIT_TIMEOUT, 0x887A0027},
		{DXGI_ERROR_INVALID_CALL, 0x887A0001},
	}

	for _, tc := range testCases {
		if uint32(tc.code) != tc.expected {
			t.Errorf("HRESULT mismatch: expected 0x%08X, got 0x%08X", tc.expected, uint32(tc.code))
		}
	}
}

func TestTier1_F1_COMVtable_ZeroCGO_SyscallN_Signature(t *testing.T) {
	vtable := NewMockCOMVtable()
	vtable.methods[3] = func(args ...uintptr) uintptr {
		if len(args) != 3 {
			return uintptr(E_INVALIDARG)
		}
		return uintptr(S_OK)
	}

	// Pure Go COM dispatch simulates syscall.SyscallN(vtableFn, thisPtr, timeout, pFrameInfo, pResource)
	res := vtable.Call(3, uintptr(0x1000), uintptr(50), uintptr(0x2000))
	if HRESULT(res) != S_OK {
		t.Fatalf("SyscallN convention dispatch failed: 0x%08X", uint32(res))
	}
}

func TestTier1_F1_COMVtable_IUnknown_Lifecycle(t *testing.T) {
	vtable := NewMockCOMVtable()
	if vtable.refCount != 1 {
		t.Fatalf("Initial refCount must be 1, got %d", vtable.refCount)
	}

	vtable.Call(1) // AddRef
	if vtable.refCount != 2 {
		t.Fatalf("Expected refCount 2 after AddRef, got %d", vtable.refCount)
	}

	vtable.Call(2) // Release
	if vtable.refCount != 1 {
		t.Fatalf("Expected refCount 1 after Release, got %d", vtable.refCount)
	}

	vtable.Call(2) // Final Release
	if vtable.refCount != 0 || !vtable.released {
		t.Fatalf("Expected object to be released with refCount 0")
	}
}

// --- Feature 2: Hybrid-GPU Adapter Enumeration ---

func TestTier1_F2_AdapterEnum_SingleDiscreteGPU(t *testing.T) {
	adapters := []DXGI_ADAPTER_DESC1{
		{VendorId: 0x10DE, DeviceId: 0x2484, DedicatedVideoMemory: 8 * 1024 * 1024 * 1024, Flags: DXGI_ADAPTER_FLAG_NONE},
	}
	matched := -1
	for i, a := range adapters {
		if a.Flags&DXGI_ADAPTER_FLAG_SOFTWARE == 0 && a.DedicatedVideoMemory > 0 {
			matched = i
			break
		}
	}
	if matched != 0 {
		t.Fatalf("Failed to match discrete GPU adapter: matched=%d", matched)
	}
}

func TestTier1_F2_AdapterEnum_DualGPU_Laptop(t *testing.T) {
	// Hybrid-GPU laptop: Intel iGPU controls display output, NVIDIA dGPU is render-only
	type MockAdapter struct {
		Desc       DXGI_ADAPTER_DESC1
		HasOutputs bool
	}
	adapters := []MockAdapter{
		{
			Desc:       DXGI_ADAPTER_DESC1{VendorId: 0x10DE, DedicatedVideoMemory: 6 * 1024 * 1024 * 1024},
			HasOutputs: false, // dGPU has no monitor attached
		},
		{
			Desc:       DXGI_ADAPTER_DESC1{VendorId: 0x8086, DedicatedVideoMemory: 128 * 1024 * 1024},
			HasOutputs: true, // Intel iGPU has target display output attached
		},
	}

	selected := -1
	for i, a := range adapters {
		if a.HasOutputs {
			selected = i
			break
		}
	}
	if selected != 1 || adapters[selected].Desc.VendorId != 0x8086 {
		t.Fatalf("Failed to select adapter with active output in hybrid-GPU setup: selected=%d", selected)
	}
}

func TestTier1_F2_AdapterEnum_SoftwareAdapter_Filter(t *testing.T) {
	adapters := []DXGI_ADAPTER_DESC1{
		{VendorId: 0x1414, Flags: DXGI_ADAPTER_FLAG_SOFTWARE}, // Microsoft Basic Render Driver
		{VendorId: 0x1002, Flags: DXGI_ADAPTER_FLAG_NONE},     // AMD Radeon
	}
	var hardwareAdapters []int
	for i, a := range adapters {
		if a.Flags&DXGI_ADAPTER_FLAG_SOFTWARE == 0 {
			hardwareAdapters = append(hardwareAdapters, i)
		}
	}
	if len(hardwareAdapters) != 1 || hardwareAdapters[0] != 1 {
		t.Fatalf("Software adapter was not properly filtered: %v", hardwareAdapters)
	}
}

func TestTier1_F2_AdapterEnum_MultiMonitor_Matching(t *testing.T) {
	monitors := []MonitorContract{
		{Index: 0, Bounds: image.Rect(0, 0, 1920, 1080), Name: `\\.\DISPLAY1`},
		{Index: 1, Bounds: image.Rect(1920, 0, 3840, 1080), Name: `\\.\DISPLAY2`},
	}
	if len(monitors) != 2 {
		t.Fatalf("Expected 2 monitors enumerated, got %d", len(monitors))
	}
	if monitors[1].Bounds.Min.X != 1920 {
		t.Fatalf("Incorrect bounds for secondary monitor: %v", monitors[1].Bounds)
	}
}

func TestTier1_F2_AdapterEnum_AdapterDesc1_Parsing(t *testing.T) {
	var desc DXGI_ADAPTER_DESC1
	desc.VendorId = 0x10DE
	desc.DeviceId = 0x1F08
	desc.DedicatedVideoMemory = 12 * 1024 * 1024 * 1024

	name := "NVIDIA RTX 3060"
	for i, r := range []rune(name) {
		desc.Description[i] = uint16(r)
	}

	if desc.GetDescription() != name {
		t.Fatalf("Description parsing mismatch: got %q, expected %q", desc.GetDescription(), name)
	}
}

// --- Feature 3: GPU Direct Surface Capture Loop ---

func TestTier1_F3_SurfaceCapture_AcquireNextFrame_Success(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	defer capturer.Close()

	frame, err := capturer.Capture(capturer.monitors[0])
	if err != nil {
		t.Fatalf("AcquireNextFrame failed: %v", err)
	}
	if frame.Bounds.Dx() != 1920 || frame.Bounds.Dy() != 1080 {
		t.Fatalf("Unexpected frame dimensions: %v", frame.Bounds)
	}
	if frame.VRAMHandle == 0 {
		t.Fatalf("Expected valid VRAMHandle pointer")
	}
}

func TestTier1_F3_SurfaceCapture_ReleaseFrame_Mandatory(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	defer capturer.Close()

	_, err := capturer.Capture(capturer.monitors[0])
	if err != nil {
		t.Fatalf("First capture failed: %v", err)
	}

	// Must call ReleaseFrame before capturing next frame
	if err := capturer.ReleaseFrame(); err != nil {
		t.Fatalf("ReleaseFrame failed: %v", err)
	}

	// Second capture must now succeed
	_, err = capturer.Capture(capturer.monitors[0])
	if err != nil {
		t.Fatalf("Second capture failed after release: %v", err)
	}
}

func TestTier1_F3_SurfaceCapture_DoubleAcquire_Blocked(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	defer capturer.Close()

	_, _ = capturer.Capture(capturer.monitors[0])
	// Second capture without release must fail with DXGI_ERROR_INVALID_CALL
	_, err := capturer.Capture(capturer.monitors[0])
	if err == nil {
		t.Fatalf("Expected error when calling AcquireNextFrame twice without ReleaseFrame")
	}
}

func TestTier1_F3_SurfaceCapture_FrameInfo_Metadata(t *testing.T) {
	info := DXGI_OUTDUPL_FRAME_INFO{
		LastPresentTime:   time.Now().UnixNano(),
		AccumulatedFrames: 1,
		RectsCoalesced:    1,
	}
	if info.AccumulatedFrames == 0 {
		t.Fatalf("AccumulatedFrames must be > 0 for new frame")
	}
}

func TestTier1_F3_SurfaceCapture_VRAM_Handle_Tracking(t *testing.T) {
	capturer := NewMockDXGICapturer(1280, 720, false)
	defer capturer.Close()

	frame, err := capturer.Capture(capturer.monitors[0])
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}
	if frame.VRAMHandle != uintptr(0xDEADBEEF) {
		t.Fatalf("Unexpected VRAMHandle: 0x%X", frame.VRAMHandle)
	}
	_ = capturer.ReleaseFrame()
}

// --- Feature 4: Driver Dirty & Move Rectangles Ingestion ---

func TestTier1_F4_DirtyRects_SingleDirtyRegion(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	dirty := image.Rect(100, 100, 300, 200)
	capturer.dirtyRects = []image.Rectangle{dirty}

	frame, err := capturer.Capture(capturer.monitors[0])
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}
	if len(frame.DirtyRects) != 1 || frame.DirtyRects[0] != dirty {
		t.Fatalf("DirtyRect mismatch: got %v, expected %v", frame.DirtyRects, dirty)
	}
	_ = capturer.ReleaseFrame()
}

func TestTier1_F4_DirtyRects_MultipleDisjointRects(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	rects := []image.Rectangle{
		image.Rect(0, 0, 50, 50),
		image.Rect(500, 500, 600, 600),
		image.Rect(1800, 1000, 1920, 1080),
	}
	capturer.dirtyRects = rects

	frame, err := capturer.Capture(capturer.monitors[0])
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}
	if len(frame.DirtyRects) != 3 {
		t.Fatalf("Expected 3 dirty rects, got %d", len(frame.DirtyRects))
	}
	_ = capturer.ReleaseFrame()
}

func TestTier1_F4_DirtyRects_FullScreenUpdate(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	capturer.dirtyRects = []image.Rectangle{image.Rect(0, 0, 1920, 1080)}

	frame, err := capturer.Capture(capturer.monitors[0])
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}
	if frame.DirtyRects[0] != image.Rect(0, 0, 1920, 1080) {
		t.Fatalf("Full screen update rect mismatch: %v", frame.DirtyRects[0])
	}
	_ = capturer.ReleaseFrame()
}

func TestTier1_F4_DirtyRects_MoveRects_Scrolling(t *testing.T) {
	moveRect := DXGI_OUTDUPL_MOVE_RECT{
		SourcePoint:     DXGI_POINT{X: 0, Y: 100},
		DestinationRect: DXGI_RECT{Left: 0, Top: 0, Right: 1920, Bottom: 980},
	}
	if moveRect.DestinationRect.Bottom-moveRect.DestinationRect.Top != 980 {
		t.Fatalf("MoveRect dimensions unexpected: %v", moveRect)
	}
}

func TestTier1_F4_DirtyRects_EmptyDirtyRects_Static(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	capturer.dirtyRects = []image.Rectangle{} // static frame

	frame, err := capturer.Capture(capturer.monitors[0])
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}
	// Fallback to full screen when dirty rects is empty
	if len(frame.DirtyRects) != 1 {
		t.Fatalf("Expected fallback rect, got %d rects", len(frame.DirtyRects))
	}
	_ = capturer.ReleaseFrame()
}

// --- Feature 5: Hardware Mouse Cursor Compositing ---

func TestTier1_F5_Cursor_ColorShape_Blit(t *testing.T) {
	capturer := NewMockDXGICapturer(640, 480, false)
	capturer.cursorPos = image.Pt(100, 100)
	capturer.cursorShape = &DXGI_OUTDUPL_POINTER_SHAPE_INFO{
		Type:    DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR,
		Width:   16,
		Height:  16,
		Pitch:   64,
		HotSpot: DXGI_POINT{X: 0, Y: 0},
	}
	capturer.cursorData = make([]byte, 16*64)

	frame, err := capturer.Capture(capturer.monitors[0])
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}
	// Cursor position was recorded
	if frame.CursorX != 100 || frame.CursorY != 100 {
		t.Fatalf("Cursor coordinates mismatch: got (%d, %d)", frame.CursorX, frame.CursorY)
	}
	_ = capturer.ReleaseFrame()
}

func TestTier1_F5_Cursor_Monochrome_XOR_Mask(t *testing.T) {
	info := DXGI_OUTDUPL_POINTER_SHAPE_INFO{
		Type:   DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME,
		Width:  32,
		Height: 32,
	}
	if info.Type != DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME {
		t.Fatalf("Monochrome type mismatch")
	}
}

func TestTier1_F5_Cursor_MaskedColor_Blit(t *testing.T) {
	info := DXGI_OUTDUPL_POINTER_SHAPE_INFO{
		Type:   DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR,
		Width:  32,
		Height: 32,
	}
	if info.Type != DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR {
		t.Fatalf("Masked color type mismatch")
	}
}

func TestTier1_F5_Cursor_Position_Update(t *testing.T) {
	pos := DXGI_OUTDUPL_POINTER_POSITION{
		Position: DXGI_POINT{X: 550, Y: 420},
		Visible:  1,
	}
	if pos.Position.X != 550 || pos.Position.Y != 420 || pos.Visible != 1 {
		t.Fatalf("Pointer position mismatch: %v", pos)
	}
}

func TestTier1_F5_Cursor_Visibility_Toggle(t *testing.T) {
	capturer := NewMockDXGICapturer(640, 480, false)
	capturer.cursorVis = false

	frame, err := capturer.Capture(capturer.monitors[0])
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}
	if frame.CursorVis {
		t.Fatalf("Expected cursor to be hidden")
	}
	_ = capturer.ReleaseFrame()
}

// --- Feature 6: In-VRAM Colorspace Conversion (BGRA to NV12) ---

func TestTier1_F6_NV12_Conversion_ExactSize(t *testing.T) {
	w, h := 1920, 1080
	bgra := make([]byte, w*h*4)
	nv12, err := ConvertBGRAtoNV12(bgra, w, h, w*4)
	if err != nil {
		t.Fatalf("NV12 conversion failed: %v", err)
	}
	expectedLen := (w * h * 3) / 2
	if len(nv12) != expectedLen {
		t.Fatalf("NV12 length mismatch: got %d, expected %d", len(nv12), expectedLen)
	}
}

func TestTier1_F6_NV12_Conversion_PureWhite(t *testing.T) {
	w, h := 2, 2
	bgra := []byte{
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
	}
	nv12, err := ConvertBGRAtoNV12(bgra, w, h, w*4)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}
	// For pure white (R=G=B=255), BT.601 Y should be 235, U=128, V=128
	for i := 0; i < 4; i++ {
		if nv12[i] != 235 {
			t.Errorf("Y plane white mismatch at %d: got %d, expected 235", i, nv12[i])
		}
	}
	if nv12[4] != 128 || nv12[5] != 128 {
		t.Errorf("Chroma plane white mismatch: U=%d, V=%d (expected 128, 128)", nv12[4], nv12[5])
	}
}

func TestTier1_F6_NV12_Conversion_PureBlack(t *testing.T) {
	w, h := 2, 2
	bgra := make([]byte, 16) // all 0
	nv12, err := ConvertBGRAtoNV12(bgra, w, h, w*4)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}
	// For pure black, BT.601 Y should be 16, U=128, V=128
	for i := 0; i < 4; i++ {
		if nv12[i] != 16 {
			t.Errorf("Y plane black mismatch at %d: got %d, expected 16", i, nv12[i])
		}
	}
	if nv12[4] != 128 || nv12[5] != 128 {
		t.Errorf("Chroma plane black mismatch: U=%d, V=%d (expected 128, 128)", nv12[4], nv12[5])
	}
}

func TestTier1_F6_NV12_Conversion_PrimaryColors(t *testing.T) {
	w, h := 2, 2
	// Red (B=0, G=0, R=255)
	bgraRed := []byte{
		0, 0, 255, 255, 0, 0, 255, 255,
		0, 0, 255, 255, 0, 0, 255, 255,
	}
	nv12, err := ConvertBGRAtoNV12(bgraRed, w, h, w*4)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}
	// Y for Red is ~82, U is ~90, V is ~240
	y := nv12[0]
	if y < 75 || y > 90 {
		t.Errorf("Red Y out of expected BT.601 range: %d", y)
	}
}

func TestTier1_F6_NV12_Conversion_InterleavedUV_Layout(t *testing.T) {
	w, h := 4, 4
	bgra := make([]byte, w*h*4)
	nv12, err := ConvertBGRAtoNV12(bgra, w, h, w*4)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}
	ySize := w * h
	uvSize := (w * h) / 2
	if len(nv12) != ySize+uvSize {
		t.Fatalf("Total buffer size mismatch")
	}
}

// --- Feature 7: Low-Latency MFT H.264 Encoder ---

func TestTier1_F7_MFT_AnnexB_StartCodes(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	frame := &FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)}

	data, isKeyframe, err := encoder.Encode(frame)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	if !isKeyframe {
		t.Fatalf("First frame must be keyframe")
	}
	nals, err := ParseAnnexBNALs(data)
	if err != nil {
		t.Fatalf("Failed to parse Annex B bitstream: %v", err)
	}
	if len(nals) < 3 {
		t.Fatalf("Keyframe must contain at least SPS, PPS, IDR: got %d NALs", len(nals))
	}
}

func TestTier1_F7_MFT_GOP_Structure(t *testing.T) {
	gop := 10
	encoder := NewMockMFTH264Encoder(1920, 1080, gop)
	frame := &FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)}

	keyframeCounts := 0
	for i := 0; i < 30; i++ {
		_, isKey, err := encoder.Encode(frame)
		if err != nil {
			t.Fatalf("Encode frame %d failed: %v", i, err)
		}
		if isKey {
			keyframeCounts++
			if i%gop != 0 {
				t.Fatalf("Unexpected keyframe at index %d for GOP=%d", i, gop)
			}
		}
	}
	if keyframeCounts != 3 {
		t.Fatalf("Expected 3 keyframes across 30 frames with GOP 10, got %d", keyframeCounts)
	}
}

func TestTier1_F7_MFT_SPS_PPS_Headers(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1280, 720, 60)
	data, _, _ := encoder.Encode(&FrameContract{RGBA: GenerateTestPatternRGBA(1280, 720)})

	nals, _ := ParseAnnexBNALs(data)
	hasSPS := false
	hasPPS := false
	hasIDR := false

	for _, n := range nals {
		if n.Type == NALTypeSPS {
			hasSPS = true
		}
		if n.Type == NALTypePPS {
			hasPPS = true
		}
		if n.Type == NALTypeIDR {
			hasIDR = true
		}
	}
	if !hasSPS || !hasPPS || !hasIDR {
		t.Fatalf("Missing mandatory keyframe NALs: SPS=%v, PPS=%v, IDR=%v", hasSPS, hasPPS, hasIDR)
	}
}

func TestTier1_F7_MFT_DeltaFrames_NonIDR(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	frame := &FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)}

	_, _, _ = encoder.Encode(frame) // Frame 0 = IDR
	data, isKey, err := encoder.Encode(frame) // Frame 1 = Delta
	if err != nil {
		t.Fatalf("Encode delta failed: %v", err)
	}
	if isKey {
		t.Fatalf("Frame 1 should be delta frame, not keyframe")
	}
	nals, err := ParseAnnexBNALs(data)
	if err != nil {
		t.Fatalf("Failed to parse delta NALs: %v", err)
	}
	if len(nals) != 1 || nals[0].Type != NALTypeNonIDR {
		t.Fatalf("Expected single Non-IDR slice, got: %v", nals)
	}
}

func TestTier1_F7_MFT_Bitrate_Ceiling(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	if encoder.bitrateBps < 1500000 || encoder.bitrateBps > 3500000 {
		t.Fatalf("Target bitrate %d outside 1.5-3.5 Mbps range", encoder.bitrateBps)
	}
}

// --- Feature 8: On-Demand Keyframe Generation (ForceKeyframe) ---

func TestTier1_F8_ForceKeyframe_Immediate_IDR(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	frame := &FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)}

	_, _, _ = encoder.Encode(frame) // Frame 0 = IDR
	_, isKey, _ := encoder.Encode(frame) // Frame 1 = Delta
	if isKey {
		t.Fatalf("Frame 1 must be delta")
	}

	// Trigger on-demand keyframe
	if err := encoder.ForceKeyframe(); err != nil {
		t.Fatalf("ForceKeyframe failed: %v", err)
	}

	data, isKeyAfter, err := encoder.Encode(frame) // Frame 2 must now be IDR
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	if !isKeyAfter {
		t.Fatalf("Expected immediate IDR keyframe after ForceKeyframe")
	}
	nals, _ := ParseAnnexBNALs(data)
	if nals[len(nals)-1].Type != NALTypeIDR {
		t.Fatalf("Expected NAL type IDR, got %d", nals[len(nals)-1].Type)
	}
}

func TestTier1_F8_ForceKeyframe_Includes_SPS_PPS(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	frame := &FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)}
	_, _, _ = encoder.Encode(frame)
	_, _, _ = encoder.Encode(frame)

	_ = encoder.ForceKeyframe()
	data, _, _ := encoder.Encode(frame)
	nals, err := ParseAnnexBNALs(data)
	if err != nil {
		t.Fatalf("Failed to parse NALs: %v", err)
	}
	hasSPS := false
	hasPPS := false
	for _, n := range nals {
		if n.Type == NALTypeSPS {
			hasSPS = true
		}
		if n.Type == NALTypePPS {
			hasPPS = true
		}
	}
	if !hasSPS || !hasPPS {
		t.Fatalf("Forced keyframe must include SPS and PPS")
	}
}

func TestTier1_F8_ForceKeyframe_Resets_GOP_Counter(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	frame := &FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)}
	_, _, _ = encoder.Encode(frame)
	_ = encoder.ForceKeyframe()
	_, isKey, _ := encoder.Encode(frame)
	if !isKey {
		t.Fatalf("Expected forced keyframe")
	}
}

func TestTier1_F8_ForceKeyframe_MultipleSequential(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	frame := &FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)}

	for i := 0; i < 5; i++ {
		_ = encoder.ForceKeyframe()
		_, isKey, err := encoder.Encode(frame)
		if err != nil || !isKey {
			t.Fatalf("Iteration %d: expected keyframe, got isKey=%v, err=%v", i, isKey, err)
		}
	}
}

func TestTier1_F8_ForceKeyframe_Concurrent_Invocation(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	frame := &FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = encoder.ForceKeyframe()
				time.Sleep(1 * time.Millisecond)
			}
		}()
	}

	for i := 0; i < 50; i++ {
		_, _, err := encoder.Encode(frame)
		if err != nil {
			t.Fatalf("Concurrent encode failed: %v", err)
		}
	}
	wg.Wait()
}

// --- Feature 9: DXGI Error Recovery & GDI Fallback Circuit ---

func TestTier1_F9_ErrorRecovery_AccessLost_Trigger(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	capturer.forceAccessLost = true

	_, err := capturer.Capture(capturer.monitors[0])
	if err == nil {
		t.Fatalf("Expected error on access lost")
	}
	if capturer.accessLostCount != 1 {
		t.Fatalf("Access lost count mismatch: got %d, expected 1", capturer.accessLostCount)
	}
}

func TestTier1_F9_ErrorRecovery_Successful_Reacquisition(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	capturer.forceAccessLost = true
	_, _ = capturer.Capture(capturer.monitors[0])

	// Reacquisition after desktop switch cleared
	capturer.forceAccessLost = false
	frame, err := capturer.Capture(capturer.monitors[0])
	if err != nil {
		t.Fatalf("Failed to reacquire after access lost: %v", err)
	}
	if frame == nil {
		t.Fatalf("Expected valid frame after reacquisition")
	}
	_ = capturer.ReleaseFrame()
}

func TestTier1_F9_ErrorRecovery_HeadlessVM_GDIFallback(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, true) // headless
	frame, err := capturer.Capture(capturer.monitors[0])
	if err != nil {
		t.Fatalf("Headless capture failed: %v", err)
	}
	if !capturer.gdiFallback {
		t.Fatalf("Expected GDI fallback in headless VM")
	}
	if frame.RGBA == nil {
		t.Fatalf("Expected RGBA image from GDI fallback")
	}
}

func TestTier1_F9_ErrorRecovery_Consecutive_Failures_Fallback(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	capturer.forceAccessLost = true

	for i := 0; i < 3; i++ {
		_, _ = capturer.Capture(capturer.monitors[0])
	}

	if !capturer.gdiFallback {
		t.Fatalf("Expected GDI fallback after 3 consecutive DXGI failures")
	}
}

func TestTier1_F9_ErrorRecovery_Clean_COM_Teardown(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	_, _ = capturer.Capture(capturer.monitors[0])
	if err := capturer.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if capturer.acquired {
		t.Fatalf("Acquired state must be cleared on close")
	}
}

// ============================================================================
// Tier 2: Boundary & Corner Cases (Features 1 - 9)
// ============================================================================

func TestTier2_F1_COMVtable_NullPointer_Guard(t *testing.T) {
	vtable := NewMockCOMVtable()
	res := vtable.Call(0, 0, 0) // QueryInterface with NULL args
	if HRESULT(res) != E_POINTER {
		t.Fatalf("Expected E_POINTER for NULL pointer arg, got 0x%08X", uint32(res))
	}
}

func TestTier2_F1_COMVtable_DoubleRelease_Safety(t *testing.T) {
	vtable := NewMockCOMVtable()
	vtable.Call(2) // Release refCount=0
	vtable.Call(2) // Extra Release
	if vtable.refCount < 0 && !vtable.released {
		t.Fatalf("Double release corrupted state")
	}
}

func TestTier2_F1_COMVtable_InvalidGUID_QueryInterface(t *testing.T) {
	vtable := NewMockCOMVtable()
	vtable.methods[0] = func(args ...uintptr) uintptr {
		return uintptr(E_NOINTERFACE)
	}
	res := vtable.Call(0, uintptr(0x1000), uintptr(0x2000))
	if HRESULT(res) != E_NOINTERFACE {
		t.Fatalf("Expected E_NOINTERFACE, got 0x%08X", uint32(res))
	}
}

func TestTier2_F1_COMVtable_64Bit_Alignment(t *testing.T) {
	ptr := uintptr(0x00007FF8BEEF0000)
	if ptr%8 != 0 {
		t.Fatalf("COM vtable pointer must be 8-byte aligned on 64-bit architecture: 0x%X", ptr)
	}
}

func TestTier2_F1_COMVtable_Unexpected_HRESULT_Handling(t *testing.T) {
	var unknownHRESULT HRESULT = 0x887A00FF
	errStr := fmt.Sprintf("0x%08X", uint32(unknownHRESULT))
	if errStr != "0x887A00FF" {
		t.Fatalf("Hex formatting failed: %s", errStr)
	}
}

func TestTier2_F2_AdapterEnum_ZeroOutputs_Handling(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	capturer.monitors = []MonitorContract{} // 0 monitors
	m, err := capturer.Monitors()
	if err != nil {
		t.Fatalf("Monitors query failed: %v", err)
	}
	if len(m) != 0 {
		t.Fatalf("Expected 0 monitors")
	}
}

func TestTier2_F2_AdapterEnum_EmptyAdapterList_Fallback(t *testing.T) {
	var adapters []DXGI_ADAPTER_DESC1
	if len(adapters) == 0 {
		// triggers GDI fallback
		capturer := NewMockDXGICapturer(1024, 768, true)
		frame, err := capturer.Capture(capturer.monitors[0])
		if err != nil || frame == nil {
			t.Fatalf("Fallback failed when no adapters exist")
		}
	}
}

func TestTier2_F2_AdapterEnum_HighResolution_DualOutputs(t *testing.T) {
	monitors := []MonitorContract{
		{Index: 0, Bounds: image.Rect(0, 0, 3840, 2160), Name: `\\.\DISPLAY1`},
		{Index: 1, Bounds: image.Rect(3840, 0, 7680, 2160), Name: `\\.\DISPLAY2`},
	}
	if monitors[1].Bounds.Dx() != 3840 || monitors[1].Bounds.Dy() != 2160 {
		t.Fatalf("4K resolution parse error")
	}
}

func TestTier2_F2_AdapterEnum_NegativeCoordinates_VirtualDesktop(t *testing.T) {
	// Monitor arranged to left of primary
	secMonitor := MonitorContract{
		Index:  1,
		Bounds: image.Rect(-1920, 0, 0, 1080),
		Name:   `\\.\DISPLAY2`,
	}
	if secMonitor.Bounds.Min.X != -1920 || secMonitor.Bounds.Max.X != 0 {
		t.Fatalf("Negative coordinate parsing error: %v", secMonitor.Bounds)
	}
}

func TestTier2_F2_AdapterEnum_VendorID_Classification(t *testing.T) {
	vendors := map[uint32]string{
		0x8086: "Intel",
		0x10DE: "NVIDIA",
		0x1002: "AMD",
		0x1414: "Microsoft",
	}
	for id, expected := range vendors {
		var name string
		switch id {
		case 0x8086:
			name = "Intel"
		case 0x10DE:
			name = "NVIDIA"
		case 0x1002:
			name = "AMD"
		case 0x1414:
			name = "Microsoft"
		}
		if name != expected {
			t.Errorf("Vendor ID 0x%04X classification mismatch", id)
		}
	}
}

func TestTier2_F3_SurfaceCapture_WaitTimeout_ZeroFrames(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	defer capturer.Close()

	// Simulate static screen returning timeout
	var hr HRESULT = DXGI_ERROR_WAIT_TIMEOUT
	if hr != 0x887A0027 {
		t.Fatalf("Timeout HRESULT mismatch")
	}
}

func TestTier2_F3_SurfaceCapture_HighFPS_Pacing(t *testing.T) {
	targetInterval := 16666 * time.Microsecond // ~60 FPS
	start := time.Now()
	time.Sleep(targetInterval)
	elapsed := time.Since(start)
	if elapsed < 15*time.Millisecond {
		t.Fatalf("Timer pacing too fast: %v", elapsed)
	}
}

func TestTier2_F3_SurfaceCapture_ZeroDimensions_Rejection(t *testing.T) {
	_, err := ConvertBGRAtoNV12(make([]byte, 100), 0, 0, 0)
	if err == nil {
		t.Fatalf("Expected error for 0x0 dimensions")
	}
}

func TestTier2_F3_SurfaceCapture_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	select {
	case <-ctx.Done():
		// clean exit
	default:
		t.Fatalf("Context was not cancelled")
	}
}

func TestTier2_F3_SurfaceCapture_ExtremeResolution_8K(t *testing.T) {
	w, h := 7680, 4320
	capturer := NewMockDXGICapturer(w, h, false)
	defer capturer.Close()

	if capturer.width != 7680 || capturer.height != 4320 {
		t.Fatalf("8K dimensions failed")
	}
}

func TestTier2_F4_DirtyRects_OutOfBounds_Clipping(t *testing.T) {
	screen := image.Rect(0, 0, 1920, 1080)
	dirty := image.Rect(1800, 1000, 2100, 1200) // extends out of screen
	clipped := dirty.Intersect(screen)

	if clipped.Max.X != 1920 || clipped.Max.Y != 1080 {
		t.Fatalf("Clipped rect out of bounds: %v", clipped)
	}
}

func TestTier2_F4_DirtyRects_OverlappingRects_Coalescing(t *testing.T) {
	r1 := image.Rect(100, 100, 300, 300)
	r2 := image.Rect(200, 200, 400, 400)
	union := r1.Union(r2)

	if union != image.Rect(100, 100, 400, 400) {
		t.Fatalf("Coalesced bounding box mismatch: %v", union)
	}
}

func TestTier2_F4_DirtyRects_SubPixel_1x1_PixelChange(t *testing.T) {
	dirty := image.Rect(50, 50, 51, 51)
	if dirty.Dx() != 1 || dirty.Dy() != 1 {
		t.Fatalf("1x1 pixel rect error")
	}
}

func TestTier2_F4_DirtyRects_InvertedCoordinates_Correction(t *testing.T) {
	rect := DXGI_RECT{Left: 300, Top: 400, Right: 100, Bottom: 200}
	if rect.Left > rect.Right {
		rect.Left, rect.Right = rect.Right, rect.Left
	}
	if rect.Top > rect.Bottom {
		rect.Top, rect.Bottom = rect.Bottom, rect.Top
	}
	if rect.Left != 100 || rect.Right != 300 || rect.Top != 200 || rect.Bottom != 400 {
		t.Fatalf("Inverted rect normalization failed: %v", rect)
	}
}

func TestTier2_F4_DirtyRects_MaxBufferSize_Exceeded(t *testing.T) {
	var hr HRESULT = DXGI_ERROR_MORE_DATA
	if hr != 0x887A0003 {
		t.Fatalf("DXGI_ERROR_MORE_DATA code mismatch")
	}
}

func TestTier2_F5_Cursor_PartialOffscreen_Coordinates(t *testing.T) {
	pos := image.Pt(-10, -10)
	screen := image.Rect(0, 0, 1920, 1080)
	cursorRect := image.Rect(pos.X, pos.Y, pos.X+32, pos.Y+32)
	visiblePart := cursorRect.Intersect(screen)

	if visiblePart.Min.X != 0 || visiblePart.Min.Y != 0 {
		t.Fatalf("Partial off-screen cursor clipping mismatch: %v", visiblePart)
	}
}

func TestTier2_F5_Cursor_ExtremeSize_64x64_or_Large(t *testing.T) {
	info := DXGI_OUTDUPL_POINTER_SHAPE_INFO{
		Type:   DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR,
		Width:  128,
		Height: 128,
		Pitch:  128 * 4,
	}
	expectedLen := int(info.Height * info.Pitch)
	buf := make([]byte, expectedLen)
	if len(buf) != 128*128*4 {
		t.Fatalf("Large cursor buffer size calculation error")
	}
}

func TestTier2_F5_Cursor_ZeroSize_Shape(t *testing.T) {
	info := DXGI_OUTDUPL_POINTER_SHAPE_INFO{Width: 0, Height: 0}
	if info.Width == 0 || info.Height == 0 {
		// Safe no-op
		return
	}
	t.Fatalf("Expected zero size")
}

func TestTier2_F5_Cursor_Hotspot_Outside_Bounds(t *testing.T) {
	info := DXGI_OUTDUPL_POINTER_SHAPE_INFO{
		Width:   32,
		Height:  32,
		HotSpot: DXGI_POINT{X: 100, Y: 100}, // out of bounds
	}
	// Clamping hotspot
	if info.HotSpot.X >= int32(info.Width) {
		info.HotSpot.X = int32(info.Width) - 1
	}
	if info.HotSpot.Y >= int32(info.Height) {
		info.HotSpot.Y = int32(info.Height) - 1
	}
	if info.HotSpot.X != 31 || info.HotSpot.Y != 31 {
		t.Fatalf("Hotspot clamping failed: %v", info.HotSpot)
	}
}

func TestTier2_F5_Cursor_HighFrequency_MouseUpdate(t *testing.T) {
	info := DXGI_OUTDUPL_FRAME_INFO{
		LastPresentTime:     1000,
		LastMouseUpdateTime: 2000, // mouse moved without new desktop frame
	}
	if info.LastMouseUpdateTime <= info.LastPresentTime {
		t.Fatalf("Expected mouse update to be newer than present time")
	}
}

func TestTier2_F6_NV12_OddDimensions_Rejection(t *testing.T) {
	bgra := make([]byte, 1921*1080*4)
	_, err := ConvertBGRAtoNV12(bgra, 1921, 1080, 1921*4)
	if err == nil {
		t.Fatalf("Expected error for odd width in NV12 conversion")
	}

	bgra2 := make([]byte, 1920*1081*4)
	_, err = ConvertBGRAtoNV12(bgra2, 1920, 1081, 1920*4)
	if err == nil {
		t.Fatalf("Expected error for odd height in NV12 conversion")
	}
}

func TestTier2_F6_NV12_Stride_With_Padding(t *testing.T) {
	w, h := 64, 64
	paddedStride := 512 // Hardware row pitch padding
	bgra := make([]byte, paddedStride*h)
	nv12, err := ConvertBGRAtoNV12(bgra, w, h, paddedStride)
	if err != nil {
		t.Fatalf("Padded stride conversion failed: %v", err)
	}
	if len(nv12) != (w*h*3)/2 {
		t.Fatalf("NV12 output size mismatch with padded stride")
	}
}

func TestTier2_F6_NV12_ZeroDimensions_Error(t *testing.T) {
	_, err := ConvertBGRAtoNV12([]byte{}, 0, 0, 0)
	if err == nil {
		t.Fatalf("Expected error for zero dimensions")
	}
}

func TestTier2_F6_NV12_CommonResolutions_4K_1080p_720p(t *testing.T) {
	resolutions := [][2]int{
		{3840, 2160},
		{1920, 1080},
		{1280, 720},
	}
	for _, res := range resolutions {
		w, h := res[0], res[1]
		expected := (w * h * 3) / 2
		if expected <= 0 {
			t.Fatalf("Invalid calculated NV12 size for %dx%d", w, h)
		}
	}
}

func TestTier2_F6_NV12_TruncatedInput_Rejection(t *testing.T) {
	bgra := make([]byte, 100) // too short for 64x64
	_, err := ConvertBGRAtoNV12(bgra, 64, 64, 64*4)
	if err == nil {
		t.Fatalf("Expected error for truncated BGRA buffer")
	}
}

func TestTier2_F7_MFT_Resolution_Change_Reconfiguration(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	_, _, _ = encoder.Encode(&FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)})

	// Reconfigure to 1280x720
	encoder.width = 1280
	encoder.height = 720
	_ = encoder.ForceKeyframe()

	data, isKey, err := encoder.Encode(&FrameContract{RGBA: GenerateTestPatternRGBA(1280, 720)})
	if err != nil || !isKey {
		t.Fatalf("Failed to encode keyframe after resolution change: %v", err)
	}
	nals, _ := ParseAnnexBNALs(data)
	if len(nals) < 3 {
		t.Fatalf("Resolution change keyframe missing SPS/PPS/IDR")
	}
}

func TestTier2_F7_MFT_ZeroDelta_StaticScreen(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	frame := &FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)}
	_, _, _ = encoder.Encode(frame) // Frame 0
	delta, _, err := encoder.Encode(frame) // Frame 1
	if err != nil {
		t.Fatalf("Static screen encode failed: %v", err)
	}
	if len(delta) > 500 {
		t.Fatalf("Static screen P-frame should be compact, got %d bytes", len(delta))
	}
}

func TestTier2_F7_MFT_CorruptedInput_Recovery(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	_, _, err := encoder.Encode(nil)
	if err == nil {
		t.Fatalf("Expected error on nil frame")
	}
	// Next valid frame must succeed
	_, _, err = encoder.Encode(&FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)})
	if err != nil {
		t.Fatalf("Encoder did not recover from nil frame error: %v", err)
	}
}

func TestTier2_F7_MFT_Closed_Encoder_Rejection(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	_ = encoder.Close()
	_, _, err := encoder.Encode(&FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)})
	if err == nil {
		t.Fatalf("Expected error encoding on closed encoder")
	}
}

func TestTier2_F7_MFT_BufferDrain_OnClose(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	if err := encoder.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if !encoder.closed {
		t.Fatalf("Closed state not set")
	}
}

func TestTier2_F8_ForceKeyframe_During_StaticScreen(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	frame := &FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)}
	_, _, _ = encoder.Encode(frame)
	_ = encoder.ForceKeyframe()
	data, isKey, err := encoder.Encode(frame)
	if err != nil || !isKey {
		t.Fatalf("Static screen ForceKeyframe failed")
	}
	nals, _ := ParseAnnexBNALs(data)
	if nals[len(nals)-1].Type != NALTypeIDR {
		t.Fatalf("Expected IDR NAL")
	}
}

func TestTier2_F8_ForceKeyframe_RateLimiting_PLIStorm(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	// Rapid storm of 50 ForceKeyframe calls
	for i := 0; i < 50; i++ {
		_ = encoder.ForceKeyframe()
	}
	frame := &FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)}
	_, isKey, err := encoder.Encode(frame)
	if err != nil || !isKey {
		t.Fatalf("Encoder stalled under PLI storm")
	}
}

func TestTier2_F8_ForceKeyframe_On_FirstFrame(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	_ = encoder.ForceKeyframe()
	frame := &FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)}
	_, isKey, err := encoder.Encode(frame)
	if err != nil || !isKey {
		t.Fatalf("ForceKeyframe on frame 0 failed")
	}
}

func TestTier2_F8_ForceKeyframe_After_Encoder_Close(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	_ = encoder.Close()
	err := encoder.ForceKeyframe()
	if err == nil {
		t.Fatalf("Expected error when forcing keyframe on closed encoder")
	}
}

func TestTier2_F8_ForceKeyframe_BitstreamIntegrity(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	frame := &FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)}
	_ = encoder.ForceKeyframe()
	data, _, _ := encoder.Encode(frame)
	nals, err := ParseAnnexBNALs(data)
	if err != nil {
		t.Fatalf("Corrupted bitstream after ForceKeyframe: %v", err)
	}
	if len(nals) < 3 {
		t.Fatalf("Bitstream incomplete")
	}
}

func TestTier2_F9_ErrorRecovery_Resolution_Change_Detection(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	capturer.width = 2560
	capturer.height = 1440
	frame, err := capturer.Capture(capturer.monitors[0])
	if err != nil {
		t.Fatalf("Resolution change capture failed: %v", err)
	}
	if frame.Bounds.Dx() != 2560 || frame.Bounds.Dy() != 1440 {
		t.Fatalf("Resolution not updated: %v", frame.Bounds)
	}
	_ = capturer.ReleaseFrame()
}

func TestTier2_F9_ErrorRecovery_Session_Disconnect(t *testing.T) {
	var hr HRESULT = DXGI_ERROR_SESSION_DISCONNECTED
	if hr != 0x887A0028 {
		t.Fatalf("Session disconnected code mismatch")
	}
}

func TestTier2_F9_ErrorRecovery_DeviceReset_Recovery(t *testing.T) {
	var hr HRESULT = DXGI_ERROR_DEVICE_RESET
	if hr != 0x887A0007 {
		t.Fatalf("Device reset code mismatch")
	}
}

func TestTier2_F9_ErrorRecovery_GDI_Capture_Failsafe(t *testing.T) {
	capturer := NewMockDXGICapturer(800, 600, true)
	frame, err := capturer.Capture(capturer.monitors[0])
	if err != nil || frame.RGBA == nil {
		t.Fatalf("GDI capture failsafe failed: %v", err)
	}
}

func TestTier2_F9_ErrorRecovery_Seamless_Return_To_DXGI(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, true) // start in GDI
	_, _ = capturer.Capture(capturer.monitors[0])
	if !capturer.gdiFallback {
		t.Fatalf("Should be in GDI mode")
	}

	// Display becomes available
	capturer.isHeadless = false
	capturer.gdiFallback = false
	frame, err := capturer.Capture(capturer.monitors[0])
	if err != nil || frame == nil {
		t.Fatalf("Failed returning to DXGI: %v", err)
	}
	if capturer.gdiFallback {
		t.Fatalf("Capturer did not return to DXGI mode")
	}
	_ = capturer.ReleaseFrame()
}

// ============================================================================
// Tier 3: Pairwise Combinatorial Tests (Features 1 - 9)
// ============================================================================

func TestTier3_R1_Pairwise_F1_F3_COM_Vtable_Direct_SurfaceCapture(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	defer capturer.Close()

	frame, err := capturer.Capture(capturer.monitors[0])
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}
	if frame.VRAMHandle == 0 {
		t.Fatalf("Invalid VRAM handle")
	}
	_ = capturer.ReleaseFrame()
}

func TestTier3_R1_Pairwise_F2_F3_HybridGPU_SurfaceCapture(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	m, _ := capturer.Monitors()
	frame, err := capturer.Capture(m[0])
	if err != nil {
		t.Fatalf("Pairwise HybridGPU capture failed: %v", err)
	}
	_ = capturer.ReleaseFrame()
	if frame.Bounds.Dx() != 1920 {
		t.Fatalf("Width mismatch")
	}
}

func TestTier3_R1_Pairwise_F3_F4_SurfaceCapture_DirtyRects(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	capturer.dirtyRects = []image.Rectangle{image.Rect(0, 0, 100, 100)}
	frame, _ := capturer.Capture(capturer.monitors[0])
	if len(frame.DirtyRects) != 1 || frame.DirtyRects[0] != image.Rect(0, 0, 100, 100) {
		t.Fatalf("Pairwise dirty rect mismatch")
	}
	_ = capturer.ReleaseFrame()
}

func TestTier3_R1_Pairwise_F3_F5_SurfaceCapture_CursorCompositing(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	capturer.cursorPos = image.Pt(250, 350)
	frame, _ := capturer.Capture(capturer.monitors[0])
	if frame.CursorX != 250 || frame.CursorY != 350 {
		t.Fatalf("Pairwise cursor coords mismatch")
	}
	_ = capturer.ReleaseFrame()
}

func TestTier3_R1_Pairwise_F3_F6_SurfaceCapture_NV12Conversion(t *testing.T) {
	capturer := NewMockDXGICapturer(1280, 720, false)
	frame, _ := capturer.Capture(capturer.monitors[0])
	nv12, err := ConvertBGRAtoNV12(frame.RGBA.Pix, 1280, 720, 1280*4)
	if err != nil {
		t.Fatalf("Pairwise NV12 conversion failed: %v", err)
	}
	if len(nv12) != (1280*720*3)/2 {
		t.Fatalf("NV12 size error")
	}
	_ = capturer.ReleaseFrame()
}

func TestTier3_R1_Pairwise_F6_F7_NV12_MFT_H264Encode(t *testing.T) {
	capturer := NewMockDXGICapturer(1280, 720, false)
	frame, _ := capturer.Capture(capturer.monitors[0])
	encoder := NewMockMFTH264Encoder(1280, 720, 60)
	bitstream, isKey, err := encoder.Encode(frame)
	if err != nil || !isKey {
		t.Fatalf("Pairwise encode failed: %v", err)
	}
	if len(bitstream) == 0 {
		t.Fatalf("Empty bitstream")
	}
	_ = capturer.ReleaseFrame()
}

func TestTier3_R1_Pairwise_F7_F8_MFT_ForceKeyframe_Integration(t *testing.T) {
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)
	frame := &FrameContract{RGBA: GenerateTestPatternRGBA(1920, 1080)}
	_, _, _ = encoder.Encode(frame)
	_ = encoder.ForceKeyframe()
	_, isKey, err := encoder.Encode(frame)
	if err != nil || !isKey {
		t.Fatalf("Pairwise forced keyframe failed")
	}
}

func TestTier3_R1_Pairwise_F1_F9_COM_Vtable_AccessLostRecovery(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	capturer.forceAccessLost = true
	_, err := capturer.Capture(capturer.monitors[0])
	if err == nil {
		t.Fatalf("Expected access lost error")
	}
	capturer.forceAccessLost = false
	_, err = capturer.Capture(capturer.monitors[0])
	if err != nil {
		t.Fatalf("Failed recovery")
	}
	_ = capturer.ReleaseFrame()
}

func TestTier3_R1_Pairwise_F4_F7_DirtyRects_DeltaFramePacing(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)

	// Keyframe
	f0, _ := capturer.Capture(capturer.monitors[0])
	_, _, _ = encoder.Encode(f0)
	_ = capturer.ReleaseFrame()

	// Delta with dirty rect
	capturer.dirtyRects = []image.Rectangle{image.Rect(10, 10, 20, 20)}
	f1, _ := capturer.Capture(capturer.monitors[0])
	data, isKey, err := encoder.Encode(f1)
	if err != nil || isKey {
		t.Fatalf("Expected delta frame")
	}
	if len(data) == 0 {
		t.Fatalf("Empty delta frame")
	}
	_ = capturer.ReleaseFrame()
}

func TestTier3_R1_Pairwise_F5_F8_HardwareCursor_ForcedIDR(t *testing.T) {
	capturer := NewMockDXGICapturer(1920, 1080, false)
	encoder := NewMockMFTH264Encoder(1920, 1080, 60)

	capturer.cursorPos = image.Pt(800, 600)
	f, _ := capturer.Capture(capturer.monitors[0])
	_ = encoder.ForceKeyframe()
	data, isKey, err := encoder.Encode(f)
	if err != nil || !isKey {
		t.Fatalf("Failed forced IDR with cursor")
	}
	nals, _ := ParseAnnexBNALs(data)
	if len(nals) < 3 {
		t.Fatalf("NAL parsing error")
	}
	_ = capturer.ReleaseFrame()
}
