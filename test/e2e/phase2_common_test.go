// Package e2e_test provides requirement-driven, opaque-box end-to-end tests for
// Homelab RMM Phase 2 (Remote Control & Streaming Overhaul).
package e2e_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"math"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// Phase 2 Interface Contracts (from PROJECT.md § Interface Contracts)
// ============================================================================

type DesktopMode string

const (
	DesktopModeConsole   DesktopMode = "console"
	DesktopModeBackstage DesktopMode = "backstage"
)

type DesktopStartContract struct {
	Token        string      `json:"token"`
	Quality      int         `json:"quality"`
	Mode         DesktopMode `json:"mode,omitempty"`
	EnableWebRTC bool        `json:"enable_webrtc,omitempty"`
}

type DesktopStartResultContract struct {
	Started     bool        `json:"started"`
	Note        string      `json:"note,omitempty"`
	Mode        DesktopMode `json:"mode"`
	WebRTCAvail bool        `json:"webrtc_avail"`
}

type MonitorContract struct {
	Index  int             `json:"index"`
	Bounds image.Rectangle `json:"bounds"`
	Name   string          `json:"name"`
}

type FrameContract struct {
	Bounds     image.Rectangle
	DirtyRects []image.Rectangle
	CursorX    int
	CursorY    int
	CursorVis  bool
	CursorImg  image.Image
	VRAMHandle uintptr
	RGBA       *image.RGBA
}

type CapturerContract interface {
	Monitors() ([]MonitorContract, error)
	Capture(m MonitorContract) (*FrameContract, error)
	Close() error
}

type VideoEncoderContract interface {
	Encode(frame *FrameContract) ([]byte, bool, error) // Returns NAL units, isKeyframe, error
	ForceKeyframe() error
	Close() error
}

type InputEventContract struct {
	Type      string  `json:"t"` // "m" (move), "d" (down), "u" (up), "w" (wheel), "kd" (keydown), "ku" (keyup), "p" (paste), "cad" (Ctrl+Alt+Del)
	X         int     `json:"x,omitempty"`
	Y         int     `json:"y,omitempty"`
	Button    int     `json:"btn,omitempty"`
	Key       string  `json:"key,omitempty"`
	Code      string  `json:"code,omitempty"`
	Modifiers int     `json:"mod,omitempty"`
	DeltaX    int     `json:"dx,omitempty"`
	DeltaY    int     `json:"dy,omitempty"`
	Text      string  `json:"text,omitempty"`
}

type BackstageDesktopContract interface {
	CreateOrOpen() error
	CaptureComposite() (*image.RGBA, error) // Strictly EnumDesktopWindows + PrintWindow, NO GetDC(NULL)
	RouteInput(event InputEventContract) error // Strictly WindowFromPoint + ScreenToClient + PostMessageW, NO SendInput
	SpawnProcess(cmd string, hidden bool) error // lpDesktop = "winsta0\HomelabRMM_Backstage"
	Close() error
}

// ============================================================================
// DXGI COM Vtable & Data Structures (Feature 1 - Feature 9)
// ============================================================================

type HRESULT uint32

const (
	S_OK                    HRESULT = 0x00000000
	S_FALSE                 HRESULT = 0x00000001
	E_UNEXPECTED            HRESULT = 0x8000FFFF
	E_NOTIMPL               HRESULT = 0x80004001
	E_OUTOFMEMORY           HRESULT = 0x8007000E
	E_INVALIDARG            HRESULT = 0x80070057
	E_NOINTERFACE           HRESULT = 0x80004002
	E_POINTER               HRESULT = 0x80004003
	E_HANDLE                HRESULT = 0x80070006
	E_ABORT                 HRESULT = 0x80004004
	E_FAIL                  HRESULT = 0x80004005
	E_ACCESSDENIED          HRESULT = 0x80070005
	DXGI_ERROR_INVALID_CALL HRESULT = 0x887A0001
	DXGI_ERROR_NOT_FOUND    HRESULT = 0x887A0002
	DXGI_ERROR_MORE_DATA    HRESULT = 0x887A0003
	DXGI_ERROR_UNSUPPORTED  HRESULT = 0x887A0004
	DXGI_ERROR_DEVICE_REMOVED HRESULT = 0x887A0005
	DXGI_ERROR_DEVICE_HUNG  HRESULT = 0x887A0006
	DXGI_ERROR_DEVICE_RESET HRESULT = 0x887A0007
	DXGI_ERROR_WAS_STILL_DRAWING HRESULT = 0x887A000A
	DXGI_ERROR_FRAME_STATISTICS_DISJOINT HRESULT = 0x887A000B
	DXGI_ERROR_GRAPHICS_VIDPN_SOURCE_IN_USE HRESULT = 0x887A000C
	DXGI_ERROR_DRIVER_INTERNAL_ERROR HRESULT = 0x887A0020
	DXGI_ERROR_NONEXCLUSIVE HRESULT = 0x887A0021
	DXGI_ERROR_NOT_CURRENTLY_AVAILABLE HRESULT = 0x887A0022
	DXGI_ERROR_REMOTE_CLIENT_DISCONNECTED HRESULT = 0x887A0023
	DXGI_ERROR_REMOTE_OUTOFMEMORY HRESULT = 0x887A0024
	DXGI_ERROR_ACCESS_LOST  HRESULT = 0x887A0026
	DXGI_ERROR_WAIT_TIMEOUT HRESULT = 0x887A0027
	DXGI_ERROR_SESSION_DISCONNECTED HRESULT = 0x887A0028
	DXGI_ERROR_RESTRICT_TO_OUTPUT_STALE HRESULT = 0x887A0029
	DXGI_ERROR_CANNOT_PROTECT_CONTENT HRESULT = 0x887A002A
	DXGI_ERROR_ACCESS_DENIED HRESULT = 0x887A002B
	DXGI_ERROR_NAME_ALREADY_EXISTS HRESULT = 0x887A002C
	DXGI_ERROR_SDK_COMPONENT_MISSING HRESULT = 0x887A002D
)

const (
	DXGI_ADAPTER_FLAG_NONE     uint32 = 0
	DXGI_ADAPTER_FLAG_REMOTE   uint32 = 1
	DXGI_ADAPTER_FLAG_SOFTWARE uint32 = 2
)

type DXGI_POINT struct {
	X int32
	Y int32
}

type DXGI_RECT struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

func (r DXGI_RECT) ToImageRect() image.Rectangle {
	return image.Rect(int(r.Left), int(r.Top), int(r.Right), int(r.Bottom))
}

type DXGI_OUTDUPL_POINTER_POSITION struct {
	Position DXGI_POINT
	Visible  int32 // BOOL
}

type DXGI_OUTDUPL_FRAME_INFO struct {
	LastPresentTime           int64
	LastMouseUpdateTime       int64
	AccumulatedFrames         uint32
	RectsCoalesced            int32 // BOOL
	ProtectedContentMaskedOut int32 // BOOL
	PointerPosition           DXGI_OUTDUPL_POINTER_POSITION
	TotalMetadataBufferSize   uint32
	PointerShapeBufferSize    uint32
}

type DXGI_OUTDUPL_MOVE_RECT struct {
	SourcePoint     DXGI_POINT
	DestinationRect DXGI_RECT
}

const (
	DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME   uint32 = 1
	DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR        uint32 = 2
	DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR uint32 = 4
)

type DXGI_OUTDUPL_POINTER_SHAPE_INFO struct {
	Type    uint32
	Width   uint32
	Height  uint32
	Pitch   uint32
	HotSpot DXGI_POINT
}

type DXGI_ADAPTER_DESC1 struct {
	Description           [128]uint16
	VendorId              uint32
	DeviceId              uint32
	SubSysId              uint32
	Revision              uint32
	DedicatedVideoMemory  uint64
	DedicatedSystemMemory uint64
	SharedSystemMemory    uint64
	AdapterLuidLow        uint32
	AdapterLuidHigh       int32
	Flags                 uint32
}

func (d *DXGI_ADAPTER_DESC1) GetDescription() string {
	var n int
	for n = 0; n < len(d.Description); n++ {
		if d.Description[n] == 0 {
			break
		}
	}
	runes := make([]rune, n)
	for i := 0; i < n; i++ {
		runes[i] = rune(d.Description[i])
	}
	return string(runes)
}

// ============================================================================
// Pure Go Colorspace Conversion (BGRA -> NV12) Oracle
// ============================================================================

// ConvertBGRAtoNV12 converts 32-bit BGRA bytes into planar NV12 (Y plane followed by interleaved UV plane).
// Dimensions must be even. Returns NV12 byte slice of size: width * height * 3 / 2.
func ConvertBGRAtoNV12(bgra []byte, width, height int, stride int) ([]byte, error) {
	if width <= 0 || height <= 0 {
		return nil, fmt.Errorf("invalid dimensions: %dx%d", width, height)
	}
	if width%2 != 0 || height%2 != 0 {
		return nil, fmt.Errorf("dimensions must be even for NV12: %dx%d", width, height)
	}
	if stride < width*4 {
		stride = width * 4
	}
	expectedBgraLen := stride * height
	if len(bgra) < expectedBgraLen {
		return nil, fmt.Errorf("bgra buffer too small: got %d, expected %d", len(bgra), expectedBgraLen)
	}

	ySize := width * height
	uvSize := (width * height) / 2
	nv12 := make([]byte, ySize+uvSize)

	// BT.601 coefficients:
	// Y = 0.257*R + 0.504*G + 0.098*B + 16
	// U = -0.148*R - 0.291*G + 0.439*B + 128
	// V = 0.439*R - 0.368*G - 0.071*B + 128
	for y := 0; y < height; y++ {
		rowOffset := y * stride
		yOutOffset := y * width
		for x := 0; x < width; x++ {
			px := rowOffset + x*4
			b := float64(bgra[px])
			g := float64(bgra[px+1])
			r := float64(bgra[px+2])

			yVal := 0.257*r + 0.504*g + 0.098*b + 16.0
			if yVal < 16 {
				yVal = 16
			} else if yVal > 235 {
				yVal = 235
			}
			nv12[yOutOffset+x] = byte(math.Round(yVal))

			// Subsample U and V 2x2
			if y%2 == 0 && x%2 == 0 {
				uVal := -0.148*r - 0.291*g + 0.439*b + 128.0
				vVal := 0.439*r - 0.368*g - 0.071*b + 128.0
				if uVal < 16 {
					uVal = 16
				} else if uVal > 240 {
					uVal = 240
				}
				if vVal < 16 {
					vVal = 16
				} else if vVal > 240 {
					vVal = 240
				}

				uvIdx := ySize + (y/2)*width + x
				nv12[uvIdx] = byte(math.Round(uVal))
				nv12[uvIdx+1] = byte(math.Round(vVal))
			}
		}
	}

	return nv12, nil
}

// ============================================================================
// H.264 NAL Unit Framing & Bitstream Parsing
// ============================================================================

type NALType uint8

const (
	NALTypeUnspecified NALType = 0
	NALTypeNonIDR      NALType = 1
	NALTypeDataPartA   NALType = 2
	NALTypeDataPartB   NALType = 3
	NALTypeDataPartC   NALType = 4
	NALTypeIDR         NALType = 5
	NALTypeSEI         NALType = 6
	NALTypeSPS         NALType = 7
	NALTypePPS         NALType = 8
	NALTypeAUD         NALType = 9
)

type NALUnit struct {
	Type    NALType
	RefIdc  uint8
	Payload []byte
}

// ParseAnnexBNALs extracts NAL units from an Annex B formatted byte stream (0x00000001 or 0x000001 start codes).
func ParseAnnexBNALs(data []byte) ([]NALUnit, error) {
	var nals []NALUnit
	n := len(data)
	if n < 4 {
		return nil, errors.New("data too short for Annex B NAL")
	}

	// Find start codes
	var indices []int
	for i := 0; i <= n-3; i++ {
		if data[i] == 0 && data[i+1] == 0 {
			if data[i+2] == 1 {
				indices = append(indices, i+3)
				i += 2
			} else if i <= n-4 && data[i+2] == 0 && data[i+3] == 1 {
				indices = append(indices, i+4)
				i += 3
			}
		}
	}

	if len(indices) == 0 {
		return nil, errors.New("no Annex B start codes found")
	}

	for idx, start := range indices {
		var end int
		if idx+1 < len(indices) {
			// Find preceding 0x00 bytes before next start
			end = indices[idx+1]
			for end > start && data[end-1] == 0 {
				end--
			}
			// remove the '1'
			if end > start && (data[end-1] == 1) {
				end--
			}
			for end > start && data[end-1] == 0 {
				end--
			}
		} else {
			end = n
		}

		if end <= start {
			continue
		}

		nalHeader := data[start]
		nalType := NALType(nalHeader & 0x1F)
		refIdc := (nalHeader >> 5) & 0x03

		nals = append(nals, NALUnit{
			Type:    nalType,
			RefIdc:  refIdc,
			Payload: data[start:end],
		})
	}

	return nals, nil
}

// CreateAnnexBBitstream creates an Annex B byte stream containing the specified NAL units.
func CreateAnnexBBitstream(nals []NALUnit) []byte {
	var buf bytes.Buffer
	startCode := []byte{0x00, 0x00, 0x00, 0x01}
	for _, n := range nals {
		buf.Write(startCode)
		buf.Write(n.Payload)
	}
	return buf.Bytes()
}

// BuildSyntheticH264Keyframe constructs a synthetic H.264 IDR keyframe containing SPS (type 7), PPS (type 8), and IDR (type 5).
func BuildSyntheticH264Keyframe(frameNum uint32) []byte {
	sps := NALUnit{
		Type:    NALTypeSPS,
		RefIdc:  3,
		Payload: []byte{0x67, 0x42, 0xC0, 0x1E, 0xD9, 0x00, 0xA0, 0x4B, 0x42, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x03, 0x00, 0x79},
	}
	pps := NALUnit{
		Type:    NALTypePPS,
		RefIdc:  3,
		Payload: []byte{0x68, 0xCE, 0x3C, 0x80},
	}
	idrPayload := make([]byte, 128)
	idrPayload[0] = 0x65 // NAL type 5 (IDR), ref 3
	binary.BigEndian.PutUint32(idrPayload[1:5], frameNum)
	for i := 5; i < 128; i++ {
		idrPayload[i] = byte((int(frameNum) + i) & 0xFF)
	}
	idr := NALUnit{
		Type:    NALTypeIDR,
		RefIdc:  3,
		Payload: idrPayload,
	}
	return CreateAnnexBBitstream([]NALUnit{sps, pps, idr})
}

// BuildSyntheticH264DeltaFrame constructs a synthetic H.264 delta slice (NAL type 1, non-IDR).
func BuildSyntheticH264DeltaFrame(frameNum uint32) []byte {
	pPayload := make([]byte, 64)
	pPayload[0] = 0x41 // NAL type 1 (Non-IDR), ref 2
	binary.BigEndian.PutUint32(pPayload[1:5], frameNum)
	for i := 5; i < 64; i++ {
		pPayload[i] = byte((int(frameNum) + i) & 0xFF)
	}
	pSlice := NALUnit{
		Type:    NALTypeNonIDR,
		RefIdc:  2,
		Payload: pPayload,
	}
	return CreateAnnexBBitstream([]NALUnit{pSlice})
}

// ============================================================================
// RTP Packetization (RFC 3550) & RTCP (RFC 4585 / RFC 5104) Framing
// ============================================================================

type RTPHeader struct {
	Version        uint8  // 2
	Padding        bool   // false
	Extension      bool   // false
	Marker         bool   // true on last packet of frame
	PayloadType    uint8  // 96
	SequenceNumber uint16 // increments by 1
	Timestamp      uint32 // 90kHz clock ticks
	SSRC           uint32 // 0x12345678
}

func (h *RTPHeader) Marshal() []byte {
	buf := make([]byte, 12)
	buf[0] = (h.Version << 6)
	if h.Padding {
		buf[0] |= 0x20
	}
	if h.Extension {
		buf[0] |= 0x10
	}
	buf[1] = h.PayloadType & 0x7F
	if h.Marker {
		buf[1] |= 0x80
	}
	binary.BigEndian.PutUint16(buf[2:4], h.SequenceNumber)
	binary.BigEndian.PutUint32(buf[4:8], h.Timestamp)
	binary.BigEndian.PutUint32(buf[8:12], h.SSRC)
	return buf
}

func UnmarshalRTPHeader(data []byte) (*RTPHeader, error) {
	if len(data) < 12 {
		return nil, errors.New("data too short for RTP header")
	}
	h := &RTPHeader{
		Version:        (data[0] >> 6) & 0x03,
		Padding:        (data[0] & 0x20) != 0,
		Extension:      (data[0] & 0x10) != 0,
		Marker:         (data[1] & 0x80) != 0,
		PayloadType:    data[1] & 0x7F,
		SequenceNumber: binary.BigEndian.Uint16(data[2:4]),
		Timestamp:      binary.BigEndian.Uint32(data[4:8]),
		SSRC:           binary.BigEndian.Uint32(data[8:12]),
	}
	return h, nil
}

// RTCP Packet Types
const (
	RTCPTypePLI uint8 = 206 // Payload-Specific Feedback (RFC 4585)
	RTCPTypeFIR uint8 = 206 // Full Intra Request (RFC 5104)
)

const (
	RTCPFmtPLI uint8 = 1 // Picture Loss Indication FMT=1
	RTCPFmtFIR uint8 = 4 // Full Intra Request FMT=4
)

type RTCPPacket struct {
	Type          uint8
	Format        uint8
	SenderSSRC    uint32
	MediaSSRC     uint32
	FIRSequenceNo uint8 // Only used when Type==206 && Format==4
}

func (p *RTCPPacket) Marshal() []byte {
	if p.Format == RTCPFmtPLI {
		buf := make([]byte, 12)
		buf[0] = 0x80 | (p.Format & 0x1F) // V=2, P=0, FMT=1
		buf[1] = p.Type                    // 206
		binary.BigEndian.PutUint16(buf[2:4], 2) // length in 32-bit words - 1 = 2 (12 bytes)
		binary.BigEndian.PutUint32(buf[4:8], p.SenderSSRC)
		binary.BigEndian.PutUint32(buf[8:12], p.MediaSSRC)
		return buf
	} else if p.Format == RTCPFmtFIR {
		buf := make([]byte, 20)
		buf[0] = 0x80 | (p.Format & 0x1F) // V=2, P=0, FMT=4
		buf[1] = p.Type                    // 206
		binary.BigEndian.PutUint16(buf[2:4], 4) // length in 32-bit words - 1 = 4 (20 bytes)
		binary.BigEndian.PutUint32(buf[4:8], p.SenderSSRC)
		binary.BigEndian.PutUint32(buf[8:12], 0) // media SSRC is typically 0 for FCI
		binary.BigEndian.PutUint32(buf[12:16], p.MediaSSRC)
		buf[16] = p.FIRSequenceNo
		buf[17] = 0 // reserved
		buf[18] = 0 // reserved
		buf[19] = 0 // reserved
		return buf
	}
	return nil
}

func UnmarshalRTCPPacket(data []byte) (*RTCPPacket, error) {
	if len(data) < 12 {
		return nil, errors.New("data too short for RTCP packet")
	}
	version := (data[0] >> 6) & 0x03
	if version != 2 {
		return nil, fmt.Errorf("invalid RTCP version: %d", version)
	}
	fmtCode := data[0] & 0x1F
	pt := data[1]
	lengthWords := binary.BigEndian.Uint16(data[2:4])
	totalLen := int((lengthWords + 1) * 4)
	if len(data) < totalLen {
		return nil, fmt.Errorf("data too short: got %d, expected %d", len(data), totalLen)
	}

	p := &RTCPPacket{
		Type:       pt,
		Format:     fmtCode,
		SenderSSRC: binary.BigEndian.Uint32(data[4:8]),
		MediaSSRC:  binary.BigEndian.Uint32(data[8:12]),
	}

	if pt == RTCPTypeFIR && fmtCode == RTCPFmtFIR && len(data) >= 20 {
		p.MediaSSRC = binary.BigEndian.Uint32(data[12:16])
		p.FIRSequenceNo = data[16]
	}

	return p, nil
}

// ============================================================================
// WebRTC Signaling Protocol Types & Mocks
// ============================================================================

type SignalingMessage struct {
	Type      string          `json:"t"` // "webrtc_offer", "webrtc_answer", "webrtc_candidate", "webrtc_active", "webrtc_fallback", "webrtc_config"
	SDP       string          `json:"sdp,omitempty"`
	Candidate json.RawMessage `json:"candidate,omitempty"`
	Reason    string          `json:"reason,omitempty"`
	Config    json.RawMessage `json:"config,omitempty"`
}

// MockPeerConnection simulates the state transitions and callbacks of a Pion PeerConnection.
type MockPeerConnection struct {
	mu              sync.Mutex
	connectionState string // "new", "checking", "connected", "completed", "failed", "disconnected", "closed"
	iceState        string // "new", "checking", "connected", "completed", "failed", "disconnected", "closed"
	onStateChange   func(state string)
	onICECandidate  func(c string)
	dataChannels    map[string]*MockDataChannel
	localOffer      string
	remoteAnswer    string
	rtpPacketsSent  int64
	rtcpPacketsRecv int64
	keyframeTrigger chan struct{}
}

func NewMockPeerConnection() *MockPeerConnection {
	return &MockPeerConnection{
		connectionState: "new",
		iceState:        "new",
		dataChannels:    make(map[string]*MockDataChannel),
		keyframeTrigger: make(chan struct{}, 100),
	}
}

func (m *MockPeerConnection) CreateDataChannel(label string, ordered bool, maxRetransmits *uint16) *MockDataChannel {
	m.mu.Lock()
	defer m.mu.Unlock()

	dc := &MockDataChannel{
		label:          label,
		ordered:        ordered,
		maxRetransmit:  maxRetransmits,
		messages:       make(chan []byte, 1000),
		connected:      true,
	}
	m.dataChannels[label] = dc
	return dc
}

func (m *MockPeerConnection) SetConnectionState(state string) {
	m.mu.Lock()
	m.connectionState = state
	cb := m.onStateChange
	m.mu.Unlock()

	if cb != nil {
		cb(state)
	}
}

func (m *MockPeerConnection) ConnectionState() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connectionState
}

func (m *MockPeerConnection) SendRTP(pkt []byte) {
	atomic.AddInt64(&m.rtpPacketsSent, 1)
}

func (m *MockPeerConnection) InjectRTCP(pkt []byte) error {
	rtcpPkt, err := UnmarshalRTCPPacket(pkt)
	if err != nil {
		return err
	}
	atomic.AddInt64(&m.rtcpPacketsRecv, 1)
	if rtcpPkt.Type == RTCPTypePLI || rtcpPkt.Type == RTCPTypeFIR {
		select {
		case m.keyframeTrigger <- struct{}{}:
		default:
		}
	}
	return nil
}

type MockDataChannel struct {
	mu            sync.Mutex
	label         string
	ordered       bool
	maxRetransmit *uint16
	messages      chan []byte
	connected     bool
	bytesSent     int64
	bytesReceived int64
}

func (d *MockDataChannel) Label() string {
	return d.label
}

func (d *MockDataChannel) Send(data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.connected {
		return errors.New("datachannel closed")
	}
	d.bytesSent += int64(len(data))
	select {
	case d.messages <- data:
	default:
		return errors.New("datachannel buffer overflow")
	}
	return nil
}

func (d *MockDataChannel) Read(timeout time.Duration) ([]byte, error) {
	select {
	case msg := <-d.messages:
		d.mu.Lock()
		d.bytesReceived += int64(len(msg))
		d.mu.Unlock()
		return msg, nil
	case <-time.After(timeout):
		return nil, errors.New("timeout reading from datachannel")
	}
}

// ============================================================================
// Backstage Non-Intrusive Invariant Checker
// ============================================================================

type BackstageInvariantTracker struct {
	mu                sync.Mutex
	getDCCallCount    int
	sendInputCount    int
	postMessageCount  int
	printWindowCount  int
	windowFromPointCount int
	spawnedProcesses  []string
}

func (b *BackstageInvariantTracker) RecordGetDC(hwnd uintptr) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.getDCCallCount++
}

func (b *BackstageInvariantTracker) RecordSendInput() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sendInputCount++
}

func (b *BackstageInvariantTracker) RecordPostMessage(hwnd uintptr, msg uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.postMessageCount++
}

func (b *BackstageInvariantTracker) RecordPrintWindow(hwnd uintptr) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.printWindowCount++
}

func (b *BackstageInvariantTracker) RecordWindowFromPoint(pt image.Point) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.windowFromPointCount++
}

func (b *BackstageInvariantTracker) RecordSpawnProcess(cmd string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.spawnedProcesses = append(b.spawnedProcesses, cmd)
}

func (b *BackstageInvariantTracker) AssertInvariants(t *testing.T) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.getDCCallCount > 0 {
		t.Fatalf("VIOLATION: GetDC(NULL) was called %d times! Must strictly use off-screen memory DC with EnumDesktopWindows + PrintWindow", b.getDCCallCount)
	}
	if b.sendInputCount > 0 {
		t.Fatalf("VIOLATION: SendInput was called %d times! Must strictly route input via WindowFromPoint + ScreenToClient + PostMessageW", b.sendInputCount)
	}
	for _, cmd := range b.spawnedProcesses {
		lower := strings.ToLower(cmd)
		if strings.Contains(lower, "powershell") && !strings.Contains(lower, "-windowstyle hidden") {
			t.Fatalf("VIOLATION: PowerShell launched without '-WindowStyle Hidden': %q", cmd)
		}
	}
}

// ============================================================================
// Windows -WindowStyle Hidden Verification Helper
// ============================================================================

// VerifyHiddenWindowConstraint checks that any command launching PowerShell includes -WindowStyle Hidden.
func VerifyHiddenWindowConstraint(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	fullCmd := strings.ToLower(strings.Join(cmd.Args, " "))
	if strings.Contains(fullCmd, "powershell") {
		if !strings.Contains(fullCmd, "-windowstyle hidden") {
			t.Fatalf("Constraint violation: PowerShell execution missing '-WindowStyle Hidden': %s", fullCmd)
		}
	}
}

// ============================================================================
// Frontend Dual-Engine Player State Machine
// ============================================================================

type PlayerEngineState string

const (
	EngineStateInitial          PlayerEngineState = "initial"
	EngineStateFastStartCanvas  PlayerEngineState = "fast_start_canvas"
	EngineStateWebRTCConnecting PlayerEngineState = "webrtc_connecting"
	EngineStateWebRTCPlaying    PlayerEngineState = "webrtc_playing"
	EngineStateFallbackCanvas   PlayerEngineState = "fallback_canvas"
)

type DualEnginePlayerSimulator struct {
	mu             sync.Mutex
	currentState   PlayerEngineState
	activeEngine   string // "video" or "canvas"
	fps            float64
	rttMs          float64
	bitrateKbps    float64
	transport      string // "WebRTC P2P (UDP)" or "WebSocket Relay"
	mode           DesktopMode
	fallbackTimer  *time.Timer
	fallbackReason string
	webrtcActiveCb func()
}

func NewDualEnginePlayerSimulator(mode DesktopMode) *DualEnginePlayerSimulator {
	return &DualEnginePlayerSimulator{
		currentState: EngineStateInitial,
		activeEngine: "canvas",
		mode:         mode,
		transport:    "WebSocket Relay",
	}
}

func (p *DualEnginePlayerSimulator) StartSession(ctx context.Context, enableWebRTC bool, timeout time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 1. Immediately enter fast-start canvas
	p.currentState = EngineStateFastStartCanvas
	p.activeEngine = "canvas"
	p.transport = "WebSocket Relay"

	if enableWebRTC {
		p.currentState = EngineStateWebRTCConnecting
		// Arm 4.0-second fallback circuit
		p.fallbackTimer = time.AfterFunc(timeout, func() {
			p.TriggerFallback("timeout_4s_udp_blocked")
		})
	}
}

func (p *DualEnginePlayerSimulator) OnWebRTCPlaying() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.currentState == EngineStateFallbackCanvas {
		return // already timed out
	}
	if p.fallbackTimer != nil {
		p.fallbackTimer.Stop()
	}
	p.currentState = EngineStateWebRTCPlaying
	p.activeEngine = "video"
	p.transport = "WebRTC P2P (UDP)"
	if p.webrtcActiveCb != nil {
		go p.webrtcActiveCb()
	}
}

func (p *DualEnginePlayerSimulator) TriggerFallback(reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.fallbackTimer != nil {
		p.fallbackTimer.Stop()
	}
	p.currentState = EngineStateFallbackCanvas
	p.activeEngine = "canvas"
	p.transport = "WebSocket Relay"
	p.fallbackReason = reason
}

func (p *DualEnginePlayerSimulator) State() PlayerEngineState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.currentState
}

func (p *DualEnginePlayerSimulator) ActiveEngine() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.activeEngine
}

func (p *DualEnginePlayerSimulator) Transport() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.transport
}

func (p *DualEnginePlayerSimulator) Mode() DesktopMode {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mode
}

func (p *DualEnginePlayerSimulator) SetMode(m DesktopMode) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.mode = m
}

func (p *DualEnginePlayerSimulator) UpdateTelemetry(fps, rttMs, bitrateKbps float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fps = fps
	p.rttMs = rttMs
	p.bitrateKbps = bitrateKbps
}

func (p *DualEnginePlayerSimulator) Telemetry() (fps, rttMs, bitrateKbps float64, transport string, mode DesktopMode) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.fps, p.rttMs, p.bitrateKbps, p.transport, p.mode
}

// ============================================================================
// Synthetic Test Image Generator Helper
// ============================================================================

func GenerateTestRGBA(w, h int, fill color.RGBA) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, fill)
		}
	}
	return img
}

func GenerateTestPatternRGBA(w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := color.RGBA{
				R: byte((x * 255) / w),
				G: byte((y * 255) / h),
				B: byte(((x + y) * 255) / (w + h)),
				A: 255,
			}
			img.SetRGBA(x, y, c)
		}
	}
	return img
}
