//go:build windows

package desktop

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Media Foundation H.264 encoder. A hardware MFT (NVENC, Quick Sync, AMF) is
// preferred; the synchronous Microsoft software encoder is the fallback. Any
// failure is returned from newMFTEncoder so the session stays on JPEG tiles.
//
// Frames arrive either as a BGRA texture in VRAM (videoFrame.gpu) or as CPU
// pixels (videoFrame.rgba):
//   - GPU frame, hardware MFT: the video processor converts to NV12 in VRAM and
//     the NV12 texture is wrapped in an IMFSample (zero copy). This needs the
//     MFT to share the capture device, so the transform is (re)built with an
//     IMFDXGIDeviceManager for that device when the first GPU frame shows up.
//   - everything else: BGRA/RGBA is converted to NV12 in Go into a memory
//     buffer. A GPU frame that cannot take the zero-copy path is read back
//     through a staging texture first.

var (
	errEncoderClosed = errors.New("h264 encoder closed")
	errMFTBusy       = errors.New("h264 encoder busy")
)

// mftHardwareEnabled lets tests force the software encoder.
var mftHardwareEnabled atomic.Bool

func init() { mftHardwareEnabled.Store(true) }

func newMFTEncoder(width, height, fps, bitrateKbps int) (videoEncoder, error) {
	return newMFT(width, height, fps, bitrateKbps, mftHardwareEnabled.Load())
}

// mftSource says how to (re)create the transform: from an enumerated
// IMFActivate (hardware) or straight from the software encoder's CLSID.
type mftSource struct {
	act  com // nil for the software encoder
	name string
	hw   bool
}

func (s *mftSource) create() (com, error) {
	if !s.act.nil() {
		out := heapNew[unsafe.Pointer]()
		if err := check(s.act.call(activateObject, ptr(&iidIMFTransform), ptr(out))); err != nil {
			return com{}, fmt.Errorf("ActivateObject: %w", err)
		}
		return com{*out}, nil
	}
	out := heapNew[unsafe.Pointer]()
	r, _, _ := procCoCreateInstance.Call(ptr(&clsidMSH264Encoder), 0, clsctxInproc, ptr(&iidIMFTransform), ptr(out))
	if err := check(r); err != nil {
		return com{}, fmt.Errorf("CoCreateInstance(CMSH264EncoderMFT): %w", err)
	}
	return com{*out}, nil
}

func (s *mftSource) shutdown() {
	if !s.act.nil() {
		s.act.call(activateShutdn)
	}
}

func (s *mftSource) release() {
	s.shutdown()
	s.act.release()
}

type mftEncoder struct {
	mu     sync.Mutex // serialises Encode and Close
	closed atomic.Bool
	forceK atomic.Bool

	w, h   int // size the caller asked for (and sends)
	ew, eh int // even-sized encode area (4:2:0 needs even dimensions)
	fps    int
	kbps   int
	bt709  bool

	src mftSource

	// pipeline: rebuilt by open()
	mft       com
	codec     com
	evgen     com // non-nil for an asynchronous (hardware) MFT
	mgr       com // IMFDXGIDeviceManager when in zero-copy mode
	d3d       *d3dDevice
	streaming bool
	provides  bool // the MFT allocates its own output samples
	outSize   int
	outSample com
	seqHdr    []byte // SPS+PPS, Annex B

	needInput  int
	haveOutput int
	frameIdx   int64

	// pending output accumulated while waiting for the MFT to take input
	pend    []byte
	pendKey bool

	vp        *vpConverter
	zeroCopy  bool // false once the DXGI path failed
	devTried  *d3dDevice
	staging   com
	stagingW  int
	stagingH  int
	stagingOn *d3dDevice
}

func newMFT(width, height, fps, bitrateKbps int, allowHW bool) (videoEncoder, error) {
	if width < 16 || height < 16 || fps <= 0 || bitrateKbps <= 0 {
		return nil, fmt.Errorf("invalid encoder parameters %dx%d@%d %dkbps", width, height, fps, bitrateKbps)
	}
	if err := mfInit(); err != nil {
		return nil, err
	}
	coInit()

	e := &mftEncoder{
		w: width, h: height, ew: width &^ 1, eh: height &^ 1,
		fps: fps, kbps: bitrateKbps, bt709: height >= 720, zeroCopy: true,
	}

	var cands []mftSource
	if allowHW {
		cands = append(cands, enumHardwareMFTs()...)
	}
	cands = append(cands, mftSource{name: "Microsoft H.264 Encoder MFT (software)"})

	var lastErr error
	for i := range cands {
		e.src = cands[i]
		if err := e.open(nil); err != nil {
			slog.Debug("desktop: H.264 MFT unusable", "mft", e.src.name, "hardware", e.src.hw, "err", err)
			lastErr = err
			e.closePipeline()
			continue
		}
		// Keep the winner's activation, drop the rest.
		for j := range cands {
			if j != i {
				cands[j].release()
			}
		}
		slog.Info("desktop: H.264 encoder ready", "mft", e.src.name, "hardware", e.src.hw,
			"async", !e.evgen.nil(), "size", fmt.Sprintf("%dx%d", e.ew, e.eh), "fps", fps, "kbps", bitrateKbps)
		return e, nil
	}
	for i := range cands {
		cands[i].release()
	}
	return nil, fmt.Errorf("%w: %v", errNoVideoEncoder, lastErr)
}

// enumHardwareMFTs lists hardware H.264 encoder activations, best first.
func enumHardwareMFTs() []mftSource {
	out := heapNew[mftRegisterTypeInfo]()
	out.MajorType, out.Subtype = mfMediaTypeVideo, mfVideoFormatH264
	arr := heapNew[unsafe.Pointer]()
	n := heapNew[uint32]()
	r, _, _ := procMFTEnumEx.Call(ptr(&mftCategoryVideoEn), mfEnumHardware|mfEnumTransc|mfEnumSort, 0, ptr(out), ptr(arr), ptr(n))
	if err := check(r); err != nil || *arr == nil {
		slog.Debug("desktop: no hardware H.264 MFT enumerated", "err", err)
		return nil
	}
	defer procCoTaskMemFree.Call(uintptr(*arr))
	var res []mftSource
	for _, p := range unsafe.Slice((*unsafe.Pointer)(*arr), int(*n)) {
		act := com{p}
		res = append(res, mftSource{act: act, hw: true, name: friendlyName(act)})
	}
	return res
}

func friendlyName(act com) string {
	buf := heapNew[[128]uint16]()
	n := heapNew[uint32]()
	if err := check(act.call(attrGetString, ptr(&mftFriendlyName), ptr(buf), 128, ptr(n))); err != nil {
		return "hardware H.264 MFT"
	}
	return windows.UTF16ToString(buf[:])
}

// open creates and configures the transform. dev, when non-nil, is the D3D11
// device the MFT must share (zero-copy mode).
func (e *mftEncoder) open(dev *d3dDevice) (err error) {
	defer func() {
		if err != nil {
			e.closePipeline()
		}
	}()
	if e.mft, err = e.src.create(); err != nil {
		return err
	}
	if c, qerr := e.mft.queryInterface(&iidICodecAPI); qerr == nil {
		e.codec = c
	}
	if g, qerr := e.mft.queryInterface(&iidIMFEventGen); qerr == nil {
		e.evgen = g
	}

	// Unlock asynchronous MFTs and ask for low latency. A synchronous MFT may
	// not expose an attribute store at all; neither call is fatal.
	attrs := heapNew[unsafe.Pointer]()
	if check(e.mft.call(mftGetAttributes, ptr(attrs))) == nil && *attrs != nil {
		a := com{*attrs}
		if !e.evgen.nil() {
			if err := a.setU32(&mfTransformAsyncUnl, 1); err != nil {
				a.release()
				return fmt.Errorf("unlocking async MFT: %w", err)
			}
		}
		if err := a.setU32(&mfLowLatency, 1); err != nil {
			slog.Debug("desktop: MF_LOW_LATENCY rejected", "err", err)
		}
		a.release()
	} else if !e.evgen.nil() {
		return errors.New("async MFT has no attribute store")
	}

	if dev != nil {
		if err := e.attachManager(dev); err != nil {
			return err
		}
	}

	e.applyCodecProps()

	if err := e.setTypes(); err != nil {
		return err
	}

	info := heapNew[mftOutputStreamInfo]()
	if err := check(e.mft.call(mftGetOutputStreamInfo, 0, ptr(info))); err != nil {
		return fmt.Errorf("GetOutputStreamInfo: %w", err)
	}
	e.provides = info.Flags&(mftOutProvidesSamples|mftOutCanProvide) != 0
	e.outSize = int(info.CbSize)
	if e.outSize <= 0 {
		e.outSize = e.ew * e.eh * 2
	}
	e.refreshSeqHeader()
	e.streaming, e.needInput, e.haveOutput = false, 0, 0
	return nil
}

// attachManager gives the MFT an IMFDXGIDeviceManager over dev so it can read
// that device's textures directly.
func (e *mftEncoder) attachManager(dev *d3dDevice) error {
	// MF drives the device from its own threads: it must be multithread safe.
	if mt, err := dev.dev.queryInterface(&iidID3D10MT); err == nil {
		mt.call(mt10SetProtected, 1)
		mt.release()
	}
	token := heapNew[uint32]()
	out := heapNew[unsafe.Pointer]()
	r, _, _ := procMFCreateDXGIDeviceManger.Call(ptr(token), ptr(out))
	if err := check(r); err != nil {
		return fmt.Errorf("MFCreateDXGIDeviceManager: %w", err)
	}
	mgr := com{*out}
	if err := check(mgr.call(dxgiMgrResetDevice, uintptr(dev.dev.p), uintptr(*token))); err != nil {
		mgr.release()
		return fmt.Errorf("IMFDXGIDeviceManager.ResetDevice: %w", err)
	}
	if err := check(e.mft.call(mftProcessMessage, mftMsgSetD3DManager, uintptr(mgr.p))); err != nil {
		mgr.release()
		return fmt.Errorf("MFT_MESSAGE_SET_D3D_MANAGER: %w", err)
	}
	e.mgr = mgr
	e.d3d = dev
	return nil
}

func (e *mftEncoder) applyCodecProps() {
	if e.codec.nil() {
		return
	}
	for _, p := range []struct {
		name string
		key  *guid
		val  *variant
	}{
		{"low latency", &codecLowLatency, variantBool(true)},
		{"rate control CBR", &codecRateControl, variantU32(0)}, // eAVEncCommonRateControlMode_CBR
		{"mean bitrate", &codecMeanBitRate, variantU32(uint32(e.kbps) * 1000)},
		{"real time", &codecRealTime, variantU32(1)},
		{"GOP size", &codecGOPSize, variantU32(uint32(e.fps) * 2)},
		{"B pictures", &codecBPictures, variantU32(0)},
	} {
		if err := e.codec.codecSet(p.key, p.val); err != nil {
			slog.Debug("desktop: H.264 codec property not applied", "property", p.name, "err", err)
		}
	}
}

// setTypes sets the H.264 output type (trying Baseline, then Main, then the
// MFT's own choice of profile) and then the NV12 input type.
func (e *mftEncoder) setTypes() error {
	var last error
	for _, profile := range []uint32{mfH264ProfileBaseline, mfH264ProfileMain, 0} {
		mt, err := mfCreateMediaType()
		if err != nil {
			return err
		}
		mt.setGUID(&mfMTMajorType, &mfMediaTypeVideo)
		mt.setGUID(&mfMTSubtype, &mfVideoFormatH264)
		mt.setU32(&mfMTAvgBitrate, uint32(e.kbps)*1000)
		e.frameAttrs(mt)
		if profile != 0 {
			mt.setU32(&mfMTMPEG2Profile, profile)
		}
		err = check(e.mft.call(mftSetOutputType, 0, uintptr(mt.p), 0))
		mt.release()
		if err == nil {
			last = nil
			break
		}
		last = fmt.Errorf("SetOutputType(profile %d): %w", profile, err)
	}
	if last != nil {
		return last
	}

	mt, err := mfCreateMediaType()
	if err != nil {
		return err
	}
	defer mt.release()
	mt.setGUID(&mfMTMajorType, &mfMediaTypeVideo)
	mt.setGUID(&mfMTSubtype, &mfVideoFormatNV12)
	e.frameAttrs(mt)
	if err := check(e.mft.call(mftSetInputType, 0, uintptr(mt.p), 0)); err != nil {
		return fmt.Errorf("SetInputType(NV12): %w", err)
	}
	return nil
}

func (e *mftEncoder) frameAttrs(mt com) {
	mt.setU64(&mfMTFrameSize, packU64(uint32(e.ew), uint32(e.eh)))
	mt.setU64(&mfMTFrameRate, packU64(uint32(e.fps), 1))
	mt.setU64(&mfMTPixelAspect, packU64(1, 1))
	mt.setU32(&mfMTInterlaceMode, mfInterlaceProgressive)
}

// refreshSeqHeader reads SPS/PPS from the current output type, if it has them.
func (e *mftEncoder) refreshSeqHeader() {
	mt := heapNew[unsafe.Pointer]()
	if check(e.mft.call(mftGetOutputCurrentType, 0, ptr(mt))) != nil || *mt == nil {
		return
	}
	t := com{*mt}
	defer t.release()
	blob, err := t.getBlob(&mfMTSeqHeader)
	if err != nil {
		return
	}
	if ab := toAnnexB(blob); hasStartCode(ab) {
		e.seqHdr = ab
	}
}

// ---------------------------------------------------------------- Encode

func (e *mftEncoder) Encode(f videoFrame) ([]byte, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed.Load() {
		return nil, false, errEncoderClosed
	}
	gs, _ := f.gpu.(*gpuSurface)
	if gs == nil && f.rgba == nil {
		return nil, false, errors.New("frame has neither GPU nor CPU pixels")
	}
	fw, fh := f.w, f.h
	if fw == 0 && f.rgba != nil {
		fw, fh = f.rgba.Rect.Dx(), f.rgba.Rect.Dy()
	}
	if fw != e.w || fh != e.h {
		return nil, false, fmt.Errorf("frame is %dx%d but the encoder was created for %dx%d", fw, fh, e.w, e.h)
	}
	if f.rgba != nil && (f.rgba.Rect.Dx() < e.ew || f.rgba.Rect.Dy() < e.eh) {
		return nil, false, fmt.Errorf("image %v is smaller than the %dx%d encode area", f.rgba.Rect, e.ew, e.eh)
	}
	if f.rgba == nil && (gs.w < e.ew || gs.h < e.eh) {
		return nil, false, fmt.Errorf("surface %dx%d is smaller than the %dx%d encode area", gs.w, gs.h, e.ew, e.eh)
	}

	// First GPU frame on a hardware MFT: rebuild it around that frame's device.
	if gs != nil && e.src.hw && e.zeroCopy && e.devTried != gs.dev {
		e.devTried = gs.dev
		e.attachDevice(gs.dev)
	}

	sample, dxgi, err := e.buildSample(f, gs)
	if err != nil {
		return nil, false, err
	}
	if e.forceK.Swap(false) && !e.codec.nil() {
		if err := e.codec.codecSet(&codecForceKeyFram, variantU32(1)); err != nil {
			slog.Debug("desktop: ForceKeyFrame not accepted", "err", err)
		}
	}

	err = e.feed(sample)
	sample.release()
	if err != nil && dxgi {
		// The MFT would not take the VRAM sample: stop trying and use memory.
		slog.Info("desktop: H.264 zero-copy path failed, using system memory", "err", err)
		e.disableZeroCopy()
		sample, _, err = e.buildSample(f, gs)
		if err == nil {
			err = e.feed(sample)
			sample.release()
		}
	}
	if err != nil && !errors.Is(err, errMFTBusy) {
		return nil, false, err
	}
	e.frameIdx++

	// Give the MFT its chance to produce output for this frame.
	if werr := e.collect(true); werr != nil {
		return nil, false, werr
	}
	nal, key := e.pend, e.pendKey
	e.pend, e.pendKey = nil, false
	if len(nal) == 0 {
		return nil, false, nil
	}
	return nal, key, nil
}

func (e *mftEncoder) ForceKeyframe() error {
	if e.closed.Load() {
		return errEncoderClosed
	}
	e.forceK.Store(true)
	return nil
}

// attachDevice rebuilds the hardware MFT around dev; if that fails it rebuilds
// it without a device and turns zero-copy off.
func (e *mftEncoder) attachDevice(dev *d3dDevice) {
	e.closePipeline()
	if err := e.open(dev); err != nil {
		slog.Info("desktop: hardware H.264 encoder cannot share the capture device, using system memory", "mft", e.src.name, "err", err)
		e.zeroCopy = false
		e.closePipeline()
		if err := e.open(nil); err != nil {
			slog.Warn("desktop: H.264 encoder could not be rebuilt", "err", err)
			e.closed.Store(true)
		}
	}
}

func (e *mftEncoder) disableZeroCopy() {
	e.zeroCopy = false
	e.vp.close()
	e.vp = nil
	e.closePipeline()
	if err := e.open(nil); err != nil {
		slog.Warn("desktop: H.264 encoder could not be rebuilt", "err", err)
		e.closed.Store(true)
	}
}

// buildSample returns an IMFSample holding the frame as NV12. dxgi reports
// whether it is a VRAM sample (zero-copy).
func (e *mftEncoder) buildSample(f videoFrame, gs *gpuSurface) (sample com, dxgi bool, err error) {
	if e.closed.Load() {
		return com{}, false, errEncoderClosed
	}
	if gs != nil && e.zeroCopy && e.d3d != nil && gs.dev == e.d3d {
		if s, err := e.gpuSample(gs); err == nil {
			return s, true, nil
		} else {
			slog.Info("desktop: GPU colour conversion failed, using system memory", "err", err)
			e.disableZeroCopy()
			if e.closed.Load() {
				return com{}, false, errEncoderClosed
			}
		}
	}
	s, err := e.cpuSample(f, gs)
	return s, false, err
}

func (e *mftEncoder) gpuSample(gs *gpuSurface) (com, error) {
	if e.vp != nil && (e.vp.dev != gs.dev || e.vp.srcW != gs.w || e.vp.srcH != gs.h) {
		e.vp.close()
		e.vp = nil
	}
	if e.vp == nil {
		vp, err := newVPConverter(gs.dev, gs.w, gs.h, e.ew, e.eh, e.fps, e.bt709)
		if err != nil {
			return com{}, err
		}
		e.vp = vp
	}
	nv12, err := e.vp.convert(gs.tex)
	if err != nil {
		return com{}, err
	}

	out := heapNew[unsafe.Pointer]()
	r, _, _ := procMFCreateDXGISurfaceBuf.Call(ptr(&iidID3D11Texture2D), uintptr(nv12.p), 0, 0, ptr(out))
	if err := check(r); err != nil {
		return com{}, fmt.Errorf("MFCreateDXGISurfaceBuffer: %w", err)
	}
	buf := com{*out}
	defer buf.release()
	length := uint32(e.ew * e.eh * 3 / 2)
	if b2, err := buf.queryInterface(&iidIMF2DBuffer); err == nil {
		l := heapNew[uint32]()
		if check(b2.call(buf2DGetContigLen, ptr(l))) == nil && *l > 0 {
			length = *l
		}
		b2.release()
	}
	buf.call(bufSetCurrentLength, uintptr(length))
	return e.wrapSample(buf)
}

// wrapSample puts buf into a new IMFSample stamped with the next timestamp.
func (e *mftEncoder) wrapSample(buf com) (com, error) {
	s, err := mfCreateSample()
	if err != nil {
		return com{}, err
	}
	if err := check(s.call(sampleAddBuffer, uintptr(buf.p))); err != nil {
		s.release()
		return com{}, fmt.Errorf("IMFSample.AddBuffer: %w", err)
	}
	dur := int64(10_000_000 / e.fps)
	s.call(sampleSetTime, uintptr(e.frameIdx*dur))
	s.call(sampleSetDuration, uintptr(dur))
	return s, nil
}

// cpuSample converts the frame to NV12 in a system-memory buffer.
func (e *mftEncoder) cpuSample(f videoFrame, gs *gpuSurface) (com, error) {
	buf, err := mfCreateMemoryBuffer(e.ew * e.eh * 3 / 2)
	if err != nil {
		return com{}, err
	}
	pp := heapNew[unsafe.Pointer]()
	if err := check(buf.call(bufLock, ptr(pp), 0, 0)); err != nil {
		buf.release()
		return com{}, fmt.Errorf("IMFMediaBuffer.Lock: %w", err)
	}
	dst := unsafeBytes(*pp, e.ew*e.eh*3/2)
	if f.rgba != nil {
		img := f.rgba
		pix := img.Pix[img.PixOffset(img.Rect.Min.X, img.Rect.Min.Y):]
		packedToNV12(dst, pix, img.Stride, e.ew, e.eh, 0, 2, e.bt709) // R,G,B,A
		err = nil
	} else {
		err = e.readbackNV12(dst, gs)
	}
	buf.call(bufUnlock)
	if err != nil {
		buf.release()
		return com{}, err
	}
	buf.call(bufSetCurrentLength, uintptr(e.ew*e.eh*3/2))
	s, err := e.wrapSample(buf)
	buf.release()
	return s, err
}

// readbackNV12 copies a VRAM frame through a staging texture and converts it.
func (e *mftEncoder) readbackNV12(dst []byte, gs *gpuSurface) error {
	if e.stagingOn != gs.dev || e.stagingW != gs.w || e.stagingH != gs.h {
		e.staging.release()
		tex, err := gs.dev.createTexture(gs.w, gs.h, dxgiFormatB8G8R8A8, d3d11UsageStaging, 0, d3d11CPUAccessRead)
		if err != nil {
			return err
		}
		e.staging, e.stagingW, e.stagingH, e.stagingOn = tex, gs.w, gs.h, gs.dev
	}
	gs.dev.copyResource(e.staging, gs.tex)
	m, err := gs.dev.mapRead(e.staging)
	if err != nil {
		return err
	}
	defer gs.dev.unmap(e.staging)
	pix := unsafeBytes(m.Data, int(m.RowPitch)*gs.h)
	packedToNV12(dst, pix, int(m.RowPitch), e.ew, e.eh, 2, 0, e.bt709) // B,G,R,A
	return nil
}

// ---------------------------------------------------------------- MFT I/O

const mftWait = 250 * time.Millisecond

func (e *mftEncoder) beginStreaming() {
	if e.streaming {
		return
	}
	e.mft.call(mftProcessMessage, mftMsgBeginStreaming, 0)
	e.mft.call(mftProcessMessage, mftMsgStartOfStream, 0)
	e.streaming = true
}

// feed hands one sample to the MFT.
func (e *mftEncoder) feed(sample com) error {
	e.beginStreaming()
	if !e.evgen.nil() {
		deadline := time.Now().Add(mftWait)
		for {
			if err := e.pump(); err != nil {
				return err
			}
			if e.needInput > 0 {
				break
			}
			if e.haveOutput > 0 { // free up the MFT by taking its output
				if err := e.takeOutputs(); err != nil {
					return err
				}
				continue
			}
			if time.Now().After(deadline) {
				return errMFTBusy
			}
			time.Sleep(500 * time.Microsecond)
		}
		if err := check(e.mft.call(mftProcessInput, 0, uintptr(sample.p), 0)); err != nil {
			return fmt.Errorf("ProcessInput: %w", err)
		}
		e.needInput--
		return nil
	}

	err := check(e.mft.call(mftProcessInput, 0, uintptr(sample.p), 0))
	if isHR(err, hrMFNotAccepting) {
		if derr := e.takeOutputs(); derr != nil {
			return derr
		}
		err = check(e.mft.call(mftProcessInput, 0, uintptr(sample.p), 0))
	}
	if err != nil {
		return fmt.Errorf("ProcessInput: %w", err)
	}
	return nil
}

// collect drains whatever the MFT has produced. With wait set an asynchronous
// MFT is given up to mftWait to deliver the frame just fed.
func (e *mftEncoder) collect(wait bool) error {
	if e.evgen.nil() {
		return e.takeOutputs()
	}
	deadline := time.Now().Add(mftWait)
	for {
		if err := e.pump(); err != nil {
			return err
		}
		if e.haveOutput > 0 {
			return e.takeOutputs()
		}
		if !wait || time.Now().After(deadline) {
			return nil
		}
		time.Sleep(500 * time.Microsecond)
	}
}

// pump reads the async MFT's pending events without blocking.
func (e *mftEncoder) pump() error {
	for {
		ev := heapNew[unsafe.Pointer]()
		hr := e.evgen.call(evgenGetEvent, mfEventNoWait, ptr(ev))
		if uint32(hr) == hrMFNoEvents {
			return nil
		}
		if err := check(hr); err != nil {
			return fmt.Errorf("GetEvent: %w", err)
		}
		c := com{*ev}
		typ := heapNew[uint32]()
		c.call(eventGetType, ptr(typ))
		switch *typ {
		case meTransformNeedInput:
			e.needInput++
		case meTransformHaveOut:
			e.haveOutput++
		case meError:
			st := heapNew[uint32]()
			c.call(eventGetStat, ptr(st))
			c.release()
			return fmt.Errorf("MFT reported an error event: %w", hresult(*st))
		}
		c.release()
	}
}

// takeOutputs pulls every available output sample into e.pend.
func (e *mftEncoder) takeOutputs() error {
	async := !e.evgen.nil()
	for i := 0; i < 16; i++ {
		if async && e.haveOutput <= 0 {
			return nil
		}
		nal, key, got, err := e.processOutput()
		if err != nil {
			return err
		}
		if async {
			e.haveOutput--
		}
		if !got {
			if !async {
				return nil
			}
			continue
		}
		e.pend = append(e.pend, nal...)
		e.pendKey = e.pendKey || key
	}
	return nil
}

// processOutput makes one ProcessOutput call.
func (e *mftEncoder) processOutput() (nal []byte, key, got bool, err error) {
	for attempt := 0; attempt < 3; attempt++ {
		buf := heapNew[mftOutputDataBuffer]()
		status := heapNew[uint32]()
		if !e.provides {
			if e.outSample.nil() {
				if e.outSample, err = e.newOutputSample(); err != nil {
					return nil, false, false, err
				}
			}
			e.resetOutputSample()
			buf.Sample = e.outSample.p
		}
		hr := e.mft.call(mftProcessOutput, 0, 1, ptr(buf), ptr(status))
		if buf.Events != nil {
			(&com{buf.Events}).release()
		}
		sample := com{buf.Sample}
		release := func() {
			if e.provides {
				sample.release()
			}
		}
		switch {
		case uint32(hr) == hrMFNeedMoreInput:
			release()
			return nil, false, false, nil
		case uint32(hr) == hrMFStreamChange:
			release()
			if err := e.renegotiateOutput(); err != nil {
				return nil, false, false, err
			}
			if !e.evgen.nil() {
				// An asynchronous MFT spends its pending METransformHaveOutput
				// on the format change and signals the sample with a new one.
				return nil, false, false, nil
			}
			continue
		}
		if err := check(hr); err != nil {
			release()
			return nil, false, false, fmt.Errorf("ProcessOutput: %w", err)
		}
		if sample.nil() {
			return nil, false, false, nil
		}
		raw, clean, err := readSample(sample)
		release()
		if err != nil {
			return nil, false, false, err
		}
		if len(raw) == 0 {
			return nil, false, false, nil
		}
		nal = toAnnexB(raw)
		key = clean || hasNAL(nal, 5)
		if key && !hasNAL(nal, 7) {
			if len(e.seqHdr) == 0 {
				e.refreshSeqHeader()
			}
			if len(e.seqHdr) > 0 {
				nal = append(append(make([]byte, 0, len(e.seqHdr)+len(nal)), e.seqHdr...), nal...)
			}
		}
		return nal, key, true, nil
	}
	return nil, false, false, errors.New("MFT kept changing its output type")
}

func (e *mftEncoder) newOutputSample() (com, error) {
	buf, err := mfCreateMemoryBuffer(e.outSize)
	if err != nil {
		return com{}, err
	}
	defer buf.release()
	s, err := mfCreateSample()
	if err != nil {
		return com{}, err
	}
	if err := check(s.call(sampleAddBuffer, uintptr(buf.p))); err != nil {
		s.release()
		return com{}, err
	}
	return s, nil
}

func (e *mftEncoder) resetOutputSample() {
	b := heapNew[unsafe.Pointer]()
	if check(e.outSample.call(sampleConvertContig, ptr(b))) == nil {
		(com{*b}).call(bufSetCurrentLength, 0)
		(&com{*b}).release()
	}
}

// renegotiateOutput accepts the MFT's new preferred output type.
func (e *mftEncoder) renegotiateOutput() error {
	mt := heapNew[unsafe.Pointer]()
	if err := check(e.mft.call(mftGetOutputAvailType, 0, 0, ptr(mt))); err != nil {
		return fmt.Errorf("GetOutputAvailableType after stream change: %w", err)
	}
	t := com{*mt}
	err := check(e.mft.call(mftSetOutputType, 0, uintptr(t.p), 0))
	t.release()
	if err != nil {
		return fmt.Errorf("SetOutputType after stream change: %w", err)
	}
	e.seqHdr = nil
	e.refreshSeqHeader()
	return nil
}

// readSample copies an output sample's bytes and reads its clean-point flag.
func readSample(s com) (data []byte, cleanPoint bool, err error) {
	if v, gerr := s.getU32(&mfSampleCleanPoint); gerr == nil {
		cleanPoint = v != 0
	}
	b := heapNew[unsafe.Pointer]()
	if err := check(s.call(sampleConvertContig, ptr(b))); err != nil {
		return nil, false, fmt.Errorf("ConvertToContiguousBuffer: %w", err)
	}
	buf := com{*b}
	defer buf.release()
	pp := heapNew[unsafe.Pointer]()
	maxLen := heapNew[uint32]()
	cur := heapNew[uint32]()
	if err := check(buf.call(bufLock, ptr(pp), ptr(maxLen), ptr(cur))); err != nil {
		return nil, false, fmt.Errorf("output Lock: %w", err)
	}
	data = append([]byte(nil), unsafeBytes(*pp, int(*cur))...)
	buf.call(bufUnlock)
	return data, cleanPoint, nil
}

// ---------------------------------------------------------------- teardown

// closePipeline releases the transform and everything tied to it (the encoder
// can then be reopened).
func (e *mftEncoder) closePipeline() {
	if !e.mft.nil() && e.streaming {
		e.mft.call(mftProcessMessage, mftMsgEndStreaming, 0)
		e.mft.call(mftProcessMessage, mftMsgFlush, 0)
	}
	e.streaming = false
	e.outSample.release()
	e.codec.release()
	e.evgen.release()
	if !e.mft.nil() && !e.mgr.nil() {
		e.mft.call(mftProcessMessage, mftMsgSetD3DManager, 0)
	}
	e.mgr.release()
	e.mft.release()
	e.src.shutdown() // so a later ActivateObject yields a fresh instance
	e.d3d = nil
	e.needInput, e.haveOutput = 0, 0
	e.pend, e.pendKey = nil, false
}

func (e *mftEncoder) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed.Swap(true) {
		return nil
	}
	e.closePipeline()
	e.vp.close()
	e.vp = nil
	e.staging.release()
	e.src.act.release()
	return nil
}

// ---------------------------------------------------------------- pixels

// packedToNV12 converts w×h (both even) 4-byte-per-pixel pixels, stride bytes
// per row, into NV12 in dst (w*h luma bytes, then interleaved CbCr at half
// resolution). ri and bi are the byte offsets of red and blue within a pixel.
// Limited ("TV") range; BT.709 when bt709, otherwise BT.601. Chroma is the
// average of each 2×2 block.
func packedToNV12(dst, src []byte, stride, w, h, ri, bi int, bt709 bool) {
	gi := 1
	var yr, yg, yb, ur, ug, ub, vr, vg, vb int
	if bt709 {
		yr, yg, yb = 47, 157, 16
		ur, ug, ub = -25, -87, 112
		vr, vg, vb = 112, -102, -10
	} else {
		yr, yg, yb = 66, 129, 25
		ur, ug, ub = -38, -74, 112
		vr, vg, vb = 112, -94, -18
	}
	yPlane := dst[:w*h]
	uv := dst[w*h:]
	for y := 0; y < h; y += 2 {
		r0 := src[y*stride:]
		r1 := src[(y+1)*stride:]
		yo0 := y * w
		yo1 := yo0 + w
		uo := (y / 2) * w
		for x := 0; x < w; x += 2 {
			p0 := r0[x*4 : x*4+8] // pixels (x,y) and (x+1,y)
			p10 := r1[x*4 : x*4+8]
			rA, gA, bA := int(p0[ri]), int(p0[gi]), int(p0[bi])
			rB, gB, bB := int(p0[4+ri]), int(p0[4+gi]), int(p0[4+bi])
			rC, gC, bC := int(p10[ri]), int(p10[gi]), int(p10[bi])
			rD, gD, bD := int(p10[4+ri]), int(p10[4+gi]), int(p10[4+bi])
			yPlane[yo0+x] = clamp8(((yr*rA + yg*gA + yb*bA + 128) >> 8) + 16)
			yPlane[yo0+x+1] = clamp8(((yr*rB + yg*gB + yb*bB + 128) >> 8) + 16)
			yPlane[yo1+x] = clamp8(((yr*rC + yg*gC + yb*bC + 128) >> 8) + 16)
			yPlane[yo1+x+1] = clamp8(((yr*rD + yg*gD + yb*bD + 128) >> 8) + 16)
			r := (rA + rB + rC + rD + 2) >> 2
			g := (gA + gB + gC + gD + 2) >> 2
			b := (bA + bB + bC + bD + 2) >> 2
			uv[uo+x] = clamp8(((ur*r + ug*g + ub*b + 128) >> 8) + 128)
			uv[uo+x+1] = clamp8(((vr*r + vg*g + vb*b + 128) >> 8) + 128)
		}
	}
}

func clamp8(v int) byte {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return byte(v)
}

// ---------------------------------------------------------------- bitstream

func hasStartCode(b []byte) bool {
	return len(b) >= 4 && b[0] == 0 && b[1] == 0 && (b[2] == 1 || (b[2] == 0 && b[3] == 1))
}

// toAnnexB returns b as an Annex B stream. Microsoft's encoder (and most
// hardware MFTs) already emit start codes; a length-prefixed (AVCC, 4-byte
// lengths) stream is rewritten. Anything else is returned untouched.
func toAnnexB(b []byte) []byte {
	if hasStartCode(b) {
		return b
	}
	out := make([]byte, 0, len(b)+16)
	for p := 0; p < len(b); {
		if p+4 > len(b) {
			return b
		}
		n := int(b[p])<<24 | int(b[p+1])<<16 | int(b[p+2])<<8 | int(b[p+3])
		p += 4
		if n <= 0 || p+n > len(b) {
			return b
		}
		out = append(out, 0, 0, 0, 1)
		out = append(out, b[p:p+n]...)
		p += n
	}
	if len(out) == 0 {
		return b
	}
	return out
}

// hasNAL reports whether the Annex B stream contains a NAL of the given type.
func hasNAL(b []byte, nalType byte) bool {
	for i := 0; i+3 < len(b); i++ {
		if b[i] == 0 && b[i+1] == 0 && b[i+2] == 1 {
			if b[i+3]&0x1f == nalType {
				return true
			}
			i += 2
		}
	}
	return false
}
