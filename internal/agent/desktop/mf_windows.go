//go:build windows

package desktop

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Media Foundation plumbing for the H.264 encoder: DLL entry points, GUIDs,
// vtable slots and the handful of structs that cross the ABI. Every GUID and
// every vtable slot below was checked against the SDK headers (mfapi.h,
// mfobjects.h, mftransform.h, mfidl.h, codecapi.h, icodecapi.h, d3d11.h,
// d3d10.h); the interface named in each comment is the declaration whose
// order the index was counted from (IUnknown's three methods come first).

var (
	mfplatDLL = windows.NewLazySystemDLL("mfplat.dll")
	ole32DLL  = windows.NewLazySystemDLL("ole32.dll")

	procMFStartup                = mfplatDLL.NewProc("MFStartup")
	procMFTEnumEx                = mfplatDLL.NewProc("MFTEnumEx")
	procMFCreateMemoryBuffer     = mfplatDLL.NewProc("MFCreateMemoryBuffer")
	procMFCreateSample           = mfplatDLL.NewProc("MFCreateSample")
	procMFCreateMediaType        = mfplatDLL.NewProc("MFCreateMediaType")
	procMFCreateDXGISurfaceBuf   = mfplatDLL.NewProc("MFCreateDXGISurfaceBuffer")
	procMFCreateDXGIDeviceManger = mfplatDLL.NewProc("MFCreateDXGIDeviceManager")

	procCoInitializeEx   = ole32DLL.NewProc("CoInitializeEx")
	procCoCreateInstance = ole32DLL.NewProc("CoCreateInstance")
	procCoTaskMemFree    = ole32DLL.NewProc("CoTaskMemFree")
)

const (
	mfVersion      = 0x00020070 // MF_VERSION (MF_SDK_VERSION 2 << 16 | MF_API_VERSION 0x70)
	mfStartupLite  = 0x1        // MFSTARTUP_LITE == MFSTARTUP_NOSOCKET
	coinitMTA      = 0x0        // COINIT_MULTITHREADED
	clsctxInproc   = 0x1        // CLSCTX_INPROC_SERVER
	mfEventNoWait  = 0x1        // MF_EVENT_FLAG_NO_WAIT
	hrMFNoEvents   = 0xC00D3E80 // MF_E_NO_EVENTS_AVAILABLE
	mfEnumHardware = 0x4        // MFT_ENUM_FLAG_HARDWARE
	mfEnumTransc   = 0x20       // MFT_ENUM_FLAG_TRANSCODE_ONLY
	mfEnumSort     = 0x40       // MFT_ENUM_FLAG_SORTANDFILTER
)

// GUIDs (mfapi.h, mftransform.h, codecapi.h, wmcodecdsp.h).
var (
	mfMediaTypeVideo   = mkGUID(0x73646976, 0x0000, 0x0010, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71) // MFMediaType_Video
	mfVideoFormatH264  = mkGUID(0x34363248, 0x0000, 0x0010, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71) // MFVideoFormat_H264 ('H264')
	mfVideoFormatNV12  = mkGUID(0x3231564E, 0x0000, 0x0010, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71) // MFVideoFormat_NV12 ('NV12')
	mftCategoryVideoEn = mkGUID(0xf79eac7d, 0xe545, 0x4387, 0xbd, 0xee, 0xd6, 0x47, 0xd7, 0xbd, 0xe4, 0x2a) // MFT_CATEGORY_VIDEO_ENCODER
	clsidMSH264Encoder = mkGUID(0x6ca50344, 0x051a, 0x4ded, 0x97, 0x79, 0xa4, 0x33, 0x05, 0x16, 0x5e, 0x35) // CLSID_CMSH264EncoderMFT
	iidIMFTransform    = mkGUID(0xbf94c121, 0x5b05, 0x4e6f, 0x80, 0x00, 0xba, 0x59, 0x89, 0x61, 0x41, 0x4d)
	iidIMFEventGen     = mkGUID(0x2cd0bd52, 0xbcd5, 0x4b89, 0xb6, 0x2c, 0xea, 0xdc, 0x0c, 0x03, 0x1e, 0x7d) // IID_IMFMediaEventGenerator
	iidIMF2DBuffer     = mkGUID(0x7dc9d5f9, 0x9ed9, 0x44ec, 0x9b, 0xbf, 0x06, 0x00, 0xbb, 0x58, 0x9f, 0xbb)
	iidID3D10MT        = mkGUID(0x9b7e4e00, 0x342c, 0x4106, 0xa1, 0x9f, 0x4f, 0x27, 0x04, 0xf6, 0x89, 0xf0) // IID_ID3D10Multithread

	// Media type / sample / transform attribute keys.
	mfMTMajorType       = mkGUID(0x48eba18e, 0xf8c9, 0x4687, 0xbf, 0x11, 0x0a, 0x74, 0xc9, 0xf9, 0x6a, 0x8f)
	mfMTSubtype         = mkGUID(0xf7e34c9a, 0x42e8, 0x4714, 0xb7, 0x4b, 0xcb, 0x29, 0xd7, 0x2c, 0x35, 0xe5)
	mfMTAvgBitrate      = mkGUID(0x20332624, 0xfb0d, 0x4d9e, 0xbd, 0x0d, 0xcb, 0xf6, 0x78, 0x6c, 0x10, 0x2e)
	mfMTFrameSize       = mkGUID(0x1652c33d, 0xd6b2, 0x4012, 0xb8, 0x34, 0x72, 0x03, 0x08, 0x49, 0xa3, 0x7d)
	mfMTFrameRate       = mkGUID(0xc459a2e8, 0x3d2c, 0x4e44, 0xb1, 0x32, 0xfe, 0xe5, 0x15, 0x6c, 0x7b, 0xb0)
	mfMTPixelAspect     = mkGUID(0xc6376a1e, 0x8d0a, 0x4027, 0xbe, 0x45, 0x6d, 0x9a, 0x0a, 0xd3, 0x9b, 0xb6)
	mfMTInterlaceMode   = mkGUID(0xe2724bb8, 0xe676, 0x4806, 0xb4, 0xb2, 0xa8, 0xd6, 0xef, 0xb4, 0x4c, 0xcd)
	mfMTMPEG2Profile    = mkGUID(0xad76a80b, 0x2d5c, 0x4e0b, 0xb3, 0x75, 0x64, 0xe5, 0x20, 0x13, 0x70, 0x36)
	mfMTSeqHeader       = mkGUID(0x3c036de7, 0x3ad0, 0x4c9e, 0x92, 0x16, 0xee, 0x6d, 0x6a, 0xc2, 0x1c, 0xb3) // MF_MT_MPEG_SEQUENCE_HEADER
	mfSampleCleanPoint  = mkGUID(0x9cdf01d8, 0xa0f0, 0x43ba, 0xb0, 0x77, 0xea, 0xa0, 0x6c, 0xbd, 0x72, 0x8a) // MFSampleExtension_CleanPoint
	mfTransformAsyncUnl = mkGUID(0xe5666d6b, 0x3422, 0x4eb6, 0xa4, 0x21, 0xda, 0x7d, 0xb1, 0xf8, 0xe2, 0x07) // MF_TRANSFORM_ASYNC_UNLOCK
	mfLowLatency        = mkGUID(0x9c27891a, 0xed7a, 0x40e1, 0x88, 0xe8, 0xb2, 0x27, 0x27, 0xa0, 0x24, 0xee) // MF_LOW_LATENCY (== CODECAPI_AVLowLatencyMode)
	mftFriendlyName     = mkGUID(0x314ffbae, 0x5b41, 0x4c95, 0x9c, 0x19, 0x4e, 0x7d, 0x58, 0x6f, 0xac, 0xe3) // MFT_FRIENDLY_NAME_Attribute

	// ICodecAPI property keys (codecapi.h).
	codecLowLatency   = mfLowLatency
	codecRateControl  = mkGUID(0x1c0608e9, 0x370c, 0x4710, 0x8a, 0x58, 0xcb, 0x61, 0x81, 0xc4, 0x24, 0x23) // AVEncCommonRateControlMode
	codecMeanBitRate  = mkGUID(0xf7222374, 0x2144, 0x4815, 0xb5, 0x50, 0xa3, 0x7f, 0x8e, 0x12, 0xee, 0x52) // AVEncCommonMeanBitRate
	codecRealTime     = mkGUID(0x143a0ff6, 0xa131, 0x43da, 0xb8, 0x1e, 0x98, 0xfb, 0xb8, 0xec, 0x37, 0x8e) // AVEncCommonRealTime
	codecGOPSize      = mkGUID(0x95f31b26, 0x95a4, 0x41aa, 0x93, 0x03, 0x24, 0x6a, 0x7f, 0xc6, 0xee, 0xf1) // AVEncMPVGOPSize
	codecBPictures    = mkGUID(0x8d390aac, 0xdc5c, 0x4200, 0xb5, 0x7f, 0x81, 0x4d, 0x04, 0xba, 0xba, 0xb2) // AVEncMPVDefaultBPictureCount
	codecForceKeyFram = mkGUID(0x398c1b98, 0x8353, 0x475a, 0x9e, 0xf2, 0x8f, 0x26, 0x5d, 0x26, 0x03, 0x45) // AVEncVideoForceKeyFrame
)

// IMFAttributes vtable slots (mfobjects.h). IMFMediaType, IMFSample,
// IMFActivate, IMFMediaEvent and the transform's attribute store all derive
// from it, so these are valid on every one of them.
const (
	attrGetUINT32 = 7
	attrGetBlobSz = 14
	attrGetBlob   = 15
	attrGetString = 12
	attrSetUINT32 = 21
	attrSetUINT64 = 22
	attrSetGUID   = 24
)

// IMFTransform vtable slots (mftransform.h).
const (
	mftGetInputStreamInfo   = 6
	mftGetOutputStreamInfo  = 7
	mftGetAttributes        = 8
	mftGetOutputAvailType   = 14
	mftSetInputType         = 15
	mftSetOutputType        = 16
	mftGetOutputCurrentType = 18
	mftProcessMessage       = 23
	mftProcessInput         = 24
	mftProcessOutput        = 25
)

// IMFSample vtable slots (mfobjects.h; its own methods follow IMFAttributes' 30).
const (
	sampleSetTime       = 36 // SetSampleTime
	sampleSetDuration   = 38 // SetSampleDuration
	sampleConvertContig = 41 // ConvertToContiguousBuffer
	sampleAddBuffer     = 42 // AddBuffer
)

// IMFMediaBuffer (mfobjects.h), IMF2DBuffer, IMFMediaEventGenerator,
// IMFMediaEvent, IMFActivate, IMFDXGIDeviceManager, ID3D10Multithread, ICodecAPI.
const (
	bufLock             = 3
	bufUnlock           = 4
	bufGetCurrentLength = 5
	bufSetCurrentLength = 6

	buf2DGetContigLen = 7 // IMF2DBuffer::GetContiguousLength

	evgenGetEvent = 3  // IMFMediaEventGenerator::GetEvent
	eventGetType  = 33 // IMFMediaEvent::GetType (after IMFAttributes' 30)
	eventGetStat  = 35 // IMFMediaEvent::GetStatus

	activateObject = 33 // IMFActivate::ActivateObject
	activateShutdn = 34 // IMFActivate::ShutdownObject

	dxgiMgrResetDevice = 7 // IMFDXGIDeviceManager::ResetDevice

	mt10SetProtected = 5 // ID3D10Multithread::SetMultithreadProtected

	codecSetValue = 9 // ICodecAPI::SetValue (IsSupported=3 ... GetValue=8)
)

// MFT messages (MFT_MESSAGE_TYPE, mftransform.h) and event types (mfobjects.h).
const (
	mftMsgFlush          = 0x0
	mftMsgSetD3DManager  = 0x2
	mftMsgBeginStreaming = 0x10000000
	mftMsgEndStreaming   = 0x10000001
	mftMsgStartOfStream  = 0x10000003

	meError              = 1
	meTransformNeedInput = 601
	meTransformHaveOut   = 602

	mftOutProvidesSamples = 0x100 // MFT_OUTPUT_STREAM_PROVIDES_SAMPLES
	mftOutCanProvide      = 0x200 // MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES
)

const (
	mfInterlaceProgressive = 2
	mfH264ProfileBaseline  = 66 // eAVEncH264VProfile_Base
	mfH264ProfileMain      = 77 // eAVEncH264VProfile_Main
	vtBool                 = 11
	vtUI4                  = 19
)

// mftRegisterTypeInfo is MFT_REGISTER_TYPE_INFO (two GUIDs, 32 bytes).
type mftRegisterTypeInfo struct{ MajorType, Subtype guid }

// mftOutputStreamInfo is MFT_OUTPUT_STREAM_INFO (12 bytes).
type mftOutputStreamInfo struct{ Flags, CbSize, CbAlignment uint32 }

// mftOutputDataBuffer is MFT_OUTPUT_DATA_BUFFER (32 bytes on 64-bit; the
// compiler supplies the same padding the C struct has).
type mftOutputDataBuffer struct {
	StreamID uint32
	Sample   unsafe.Pointer
	Status   uint32
	Events   unsafe.Pointer
}

// variant is the 64-bit VARIANT (24 bytes) ICodecAPI::SetValue takes by pointer.
type variant struct {
	VT        uint16
	_         [3]uint16
	Val, Val2 uint64
}

func variantBool(b bool) *variant {
	v := heapNew[variant]()
	v.VT = vtBool
	if b {
		v.Val = 0xFFFF // VARIANT_TRUE
	}
	return v
}

func variantU32(u uint32) *variant {
	v := heapNew[variant]()
	v.VT = vtUI4
	v.Val = uint64(u)
	return v
}

// escapeSink exists only to make heapNew's allocations escape.
var escapeSink atomic.Pointer[byte]

// heapNew allocates T on the heap. Out-parameters and structs whose address
// is handed to the driver as a uintptr must not live on a goroutine stack: the
// stack can move (grow) between taking the address and the syscall, leaving the
// uintptr dangling. Storing the pointer in a global forces it onto the heap.
//
//go:noinline
func heapNew[T any]() *T {
	p := new(T)
	escapeSink.Store((*byte)(unsafe.Pointer(p)))
	return p
}

func ptr[T any](p *T) uintptr { return uintptr(unsafe.Pointer(p)) }

func packU64(hi, lo uint32) uint64 { return uint64(hi)<<32 | uint64(lo) }

func (c com) setU32(key *guid, v uint32) error {
	return check(c.call(attrSetUINT32, ptr(key), uintptr(v)))
}

func (c com) setU64(key *guid, v uint64) error {
	return check(c.call(attrSetUINT64, ptr(key), uintptr(v)))
}

func (c com) setGUID(key, v *guid) error {
	return check(c.call(attrSetGUID, ptr(key), ptr(v)))
}

func (c com) getU32(key *guid) (uint32, error) {
	out := heapNew[uint32]()
	if err := check(c.call(attrGetUINT32, ptr(key), ptr(out))); err != nil {
		return 0, err
	}
	return *out, nil
}

func (c com) getBlob(key *guid) ([]byte, error) {
	n := heapNew[uint32]()
	if err := check(c.call(attrGetBlobSz, ptr(key), ptr(n))); err != nil {
		return nil, err
	}
	if *n == 0 || *n > 1<<20 {
		return nil, errors.New("blob has no usable size")
	}
	buf := make([]byte, *n)
	got := heapNew[uint32]()
	// buf is heap memory the GC will not move, but it must be reachable:
	if err := check(c.call(attrGetBlob, ptr(key), uintptr(unsafe.Pointer(&buf[0])), uintptr(*n), ptr(got))); err != nil {
		return nil, err
	}
	return buf[:*got], nil
}

// codecSet sets one ICodecAPI property.
func (c com) codecSet(key *guid, v *variant) error {
	return check(c.call(codecSetValue, ptr(key), ptr(v)))
}

var (
	mfOnce sync.Once
	mfErr  error
)

// mfInit loads Media Foundation and starts it, once per process. MFShutdown is
// deliberately never called: the agent keeps the platform for its lifetime.
func mfInit() error {
	mfOnce.Do(func() {
		for _, p := range []*windows.LazyProc{
			procMFStartup, procMFTEnumEx, procMFCreateMemoryBuffer, procMFCreateSample,
			procMFCreateMediaType, procMFCreateDXGISurfaceBuf, procMFCreateDXGIDeviceManger,
			procCoInitializeEx, procCoCreateInstance, procCoTaskMemFree,
		} {
			if err := p.Find(); err != nil {
				mfErr = fmt.Errorf("media foundation unavailable: %w", err)
				return
			}
		}
		if err := mfStartup(); err != nil {
			mfErr = fmt.Errorf("MFStartup: %w", err)
		}
	})
	return mfErr
}

func mfStartup() error {
	r, _, _ := procMFStartup.Call(mfVersion, mfStartupLite)
	return check(r)
}

// coInit joins the calling thread to the multithreaded apartment. S_FALSE
// (already initialised) and RPC_E_CHANGED_MODE (the thread is already an STA)
// are both fine: the MFTs here are free-threaded.
func coInit() {
	procCoInitializeEx.Call(0, coinitMTA)
}

func mfCreateMediaType() (com, error) {
	var mt unsafe.Pointer
	out := heapNew[unsafe.Pointer]()
	r, _, _ := procMFCreateMediaType.Call(ptr(out))
	if err := check(r); err != nil {
		return com{}, fmt.Errorf("MFCreateMediaType: %w", err)
	}
	mt = *out
	return com{mt}, nil
}

func mfCreateSample() (com, error) {
	out := heapNew[unsafe.Pointer]()
	r, _, _ := procMFCreateSample.Call(ptr(out))
	if err := check(r); err != nil {
		return com{}, fmt.Errorf("MFCreateSample: %w", err)
	}
	return com{*out}, nil
}

func mfCreateMemoryBuffer(n int) (com, error) {
	out := heapNew[unsafe.Pointer]()
	r, _, _ := procMFCreateMemoryBuffer.Call(uintptr(uint32(n)), ptr(out))
	if err := check(r); err != nil {
		return com{}, fmt.Errorf("MFCreateMemoryBuffer(%d): %w", n, err)
	}
	return com{*out}, nil
}
