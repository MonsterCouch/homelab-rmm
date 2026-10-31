package stream

import (
	"context"
	"errors"
	"image/color"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/pod"
	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/proto"
)

// Descriptors, memory block ids and ids the fake server uses.
const (
	fdAct, fdDrv, fdIO, fdBuf, fdPix = 10, 11, 12, 13, 14
	fdRead, fdWrite                  = 200, 201
	fdDrvSig, fdSelfSig              = 202, 203

	memAct, memDrv, memIO, memBuf, memPix = 1, 2, 3, 4, 5

	portalNode = 77
	ourGlobal  = 91
	driverNode = 50

	frameW, frameH = 5, 3
	frameStride    = 32 // larger than frameW*4 on purpose
	pixBytes       = frameStride * frameH

	// Buffer block layout: VideoCrop meta (16), Busy meta (8), one chunk
	// (16), then the pixels.
	cropOff, busyOff, chunkOff, pixOff = 0, 16, 24, 40
	bufBlockSize                       = pixOff + pixBytes
	bufFirstOffset                     = 104 // not page aligned, 8-aligned
)

func bufOffset(i int) int { return bufFirstOffset + i*bufBlockSize }

type fakeServer struct {
	t    *testing.T
	tr   *proto.MemTransport
	mu   sync.Mutex
	seq  uint32
	msgs chan any
	conn *proto.Conn // set by newScenario, only used to explain failures
}

func newFakeServer(t *testing.T, tr *proto.MemTransport) *fakeServer {
	s := &fakeServer{t: t, tr: tr, msgs: make(chan any, 64)}
	go s.read()
	return s
}

func (s *fakeServer) send(id uint32, m proto.Message) {
	s.t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	h, payload, fds, err := proto.BuildMessage(id, s.seq, m)
	if err != nil {
		s.t.Error(err)
		return
	}
	s.seq++
	if err := s.tr.Send(h, payload, fds); err != nil {
		s.t.Errorf("server send: %v", err)
	}
}

// read decodes everything the client sends and queues it. It answers Sync
// by itself so Open can get past its barrier.
func (s *fakeServer) read() {
	defer close(s.msgs)
	for {
		h, payload, fds, err := s.tr.Recv()
		if err != nil {
			return
		}
		st, _, err := proto.SplitPayload(payload)
		if err != nil {
			s.t.Errorf("server: bad payload: %v", err)
			return
		}
		var msg any
		fl := proto.NewFdList(fds)
		switch h.ID {
		case proto.IDCore:
			msg, err = proto.DecodeCoreMethod(h.Opcode, st, fl)
		case proto.IDClient:
			msg, err = proto.DecodeClientMethod(h.Opcode, st, fl)
		default:
			msg, err = proto.DecodeClientNodeMethod(h.Opcode, st, fl)
		}
		if err != nil {
			s.t.Errorf("server: decoding id %d opcode %d: %v", h.ID, h.Opcode, err)
			return
		}
		if sy, ok := msg.(proto.CoreSync); ok {
			s.send(proto.IDCore, proto.CoreDone{ID: sy.ID, Seq: sy.Seq})
		}
		s.msgs <- msg
	}
}

func want[T any](s *fakeServer) T {
	s.t.Helper()
	var zero T
	select {
	case m, ok := <-s.msgs:
		if !ok {
			s.t.Fatalf("the connection ended while the server waited for %T (client side: %v)", zero, s.connErr())
		}
		v, ok := m.(T)
		if !ok {
			s.t.Fatalf("server expected %T, the client sent %T (%+v)", zero, m, m)
		}
		return v
	case <-time.After(5 * time.Second):
		s.t.Fatalf("the client sent no %T within 5 seconds", zero)
	}
	return zero
}

type dataKind int

const (
	kindMemPtr dataKind = iota
	kindMemID
)

type config struct {
	kind  dataKind
	async bool
}

// scenario is a stream under test, a fake server and the memory they share.
type scenario struct {
	t    *testing.T
	cfg  config
	srv  *fakeServer
	conn *proto.Conn
	mem  *MemFiles
	sig  *MemSignals
	// onNow, when set, runs once inside the next clock read of the process
	// loop, which happens while the node is AWAKE.
	onNow atomic.Pointer[func()]
	// nformat counts the second PortUpdates checked so far; the SERIAL bit of
	// the Format and Buffers infos is set on every odd one.
	nformat int

	// Server-side views of the shared memory.
	act, drv, io, buf, pix []byte

	open chan openResult
}

// hookSignal runs the scenario's onNow hook from Now.
type hookSignal struct {
	*MemSignals
	sc *scenario
}

func (h *hookSignal) Now() int64 {
	if f := h.sc.onNow.Swap(nil); f != nil {
		(*f)()
	}
	return h.MemSignals.Now()
}

type openResult struct {
	s   *Stream
	err error
}

func newScenario(t *testing.T, cfg config) *scenario {
	t.Helper()
	sc := &scenario{t: t, cfg: cfg, mem: NewMemFiles(), sig: NewMemSignals()}
	sc.act = make([]byte, 4096)
	sc.drv = make([]byte, 4096)
	sc.io = make([]byte, 4096)
	sc.buf = make([]byte, 4096)
	sc.pix = make([]byte, 8192)
	for fd, b := range map[int][]byte{fdAct: sc.act, fdDrv: sc.drv, fdIO: sc.io, fdBuf: sc.buf, fdPix: sc.pix} {
		sc.mem.Add(fd, b)
	}
	cl, sv := proto.NewMemPair()
	sc.conn = proto.NewConn(cl, proto.Config{})
	sc.srv = newFakeServer(t, sv)
	sc.srv.conn = sc.conn
	t.Cleanup(func() { sc.conn.Close(); sv.Close() })

	sc.open = make(chan openResult, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	go func() {
		s, err := Open(ctx, sc.conn, Options{NodeID: portalNode, Name: "rmm-test", Mem: sc.mem, Signal: &hookSignal{MemSignals: sc.sig, sc: sc}, Async: cfg.async})
		sc.open <- openResult{s, err}
	}()
	return sc
}

func (sc *scenario) result() openResult {
	sc.t.Helper()
	select {
	case r := <-sc.open:
		return r
	case <-time.After(10 * time.Second):
		sc.t.Fatal("Open did not return within 10 seconds")
	}
	return openResult{}
}

func (sc *scenario) opened() *Stream {
	sc.t.Helper()
	r := sc.result()
	if r.err != nil {
		sc.t.Fatalf("Open: %v", r.err)
	}
	sc.t.Cleanup(func() { r.s.Close() })
	return r.s
}

func dictGet(t *testing.T, d proto.Dict, key, value string) {
	t.Helper()
	if got, ok := d.Get(key); !ok || got != value {
		t.Fatalf("property %s = %q (present %v), want %q", key, got, ok, value)
	}
}

// hello checks Hello, UpdateProperties and Sync, the first thing Open sends.
func (sc *scenario) hello() {
	t, s := sc.t, sc.srv
	t.Helper()
	if h := want[proto.CoreHello](s); h.Version != 4 {
		t.Fatalf("hello = %+v", h)
	}
	up := want[proto.ClientUpdateProperties](s)
	dictGet(t, up.Props, "media.type", "Video")
	dictGet(t, up.Props, "media.category", "Capture")
	dictGet(t, up.Props, "media.role", "Screen")
	dictGet(t, up.Props, "node.name", "rmm-test")
	want[proto.CoreSync](s)
}

// createObject checks CreateObject and answers with BoundProps.
func (sc *scenario) createObject() {
	t, s := sc.t, sc.srv
	t.Helper()
	co := want[proto.CoreCreateObject](s)
	if co.FactoryName != "client-node" || co.Type != "PipeWire:Interface:ClientNode" || co.Version != 6 || co.NewID != 2 {
		t.Fatalf("create object = %+v", co)
	}
	dictGet(t, co.Props, "node.target", "77")
	dictGet(t, co.Props, "media.class", "Stream/Input/Video")
	dictGet(t, co.Props, "node.autoconnect", "true")
	_, async := co.Props.Get("node.async")
	if async != sc.cfg.async {
		t.Fatalf("node.async present = %v, want %v", async, sc.cfg.async)
	}
	s.send(proto.IDCore, proto.CoreBoundProps{ID: 2, GlobalID: ourGlobal})
}

// updates checks the node Update and the first PortUpdate.
func (sc *scenario) updates() {
	t, s := sc.t, sc.srv
	t.Helper()
	nu := want[proto.ClientNodeUpdate](s)
	if nu.ChangeMask != 3 || len(nu.Params) != 1 || nu.Info == nil {
		t.Fatalf("node update = %+v", nu)
	}
	wantFlags := int64(1)
	if sc.cfg.async {
		wantFlags |= 64
	}
	if nu.Info.MaxInputPorts != 1 || nu.Info.MaxOutputPorts != 0 || nu.Info.Flags != wantFlags || nu.Info.ChangeMask != 7 {
		t.Fatalf("node info = %+v", nu.Info)
	}
	wantInfos := []proto.ParamInfo{{ID: 1, Flags: 0}, {ID: 2, Flags: 4}, {ID: 3, Flags: 2}, {ID: 4, Flags: 4}}
	if !reflect.DeepEqual(nu.Info.Params, wantInfos) {
		t.Fatalf("node param infos = %+v", nu.Info.Params)
	}
	enum, _ := pod.AsObject(nu.Params[0])
	if enum.ObjType != pod.ObjectFormat || enum.ID != pod.ParamEnumFormat {
		t.Fatalf("EnumFormat object = %+v", enum)
	}
	kind, vals, err := enum.Values(pod.FormatVideoFormat)
	if err != nil || kind != pod.ChoiceKindEnum {
		t.Fatalf("format choice: %v %v", kind, err)
	}
	var ids []uint32
	for _, v := range vals {
		ids = append(ids, uint32(v.(pod.Id)))
	}
	if !reflect.DeepEqual(ids, []uint32{8, 8, 12, 7, 11}) {
		t.Fatalf("offered formats = %v, want BGRx (default), BGRx, BGRA, RGBx, RGBA", ids)
	}

	pu := want[proto.ClientNodePortUpdate](s)
	if pu.Direction != 0 || pu.PortID != 0 || pu.ChangeMask != 3 || pu.Info == nil {
		t.Fatalf("port update = %+v", pu)
	}
	// EnumFormat, two metas, IO; no Format or Buffers yet.
	if len(pu.Params) != 4 {
		t.Fatalf("first port update has %d params, want 4", len(pu.Params))
	}
	var metaTypes []uint32
	var gotIO bool
	for _, p := range pu.Params {
		o, _ := pod.AsObject(p)
		switch o.ObjType {
		case pod.ObjectParamMeta:
			id, _ := o.GetId(pod.ParamMetaType)
			metaTypes = append(metaTypes, id)
		case pod.ObjectParamIO:
			id, _ := o.GetId(pod.ParamIOId)
			if id != pod.IOBuffers {
				t.Fatalf("IO param id = %d, want Buffers", id)
			}
			gotIO = true
		}
	}
	if !reflect.DeepEqual(metaTypes, []uint32{pod.MetaBusy, pod.MetaVideoCrop}) || !gotIO {
		t.Fatalf("meta params %v, IO %v", metaTypes, gotIO)
	}
	if pu.Info.ChangeMask != 15 || pu.Info.RateDenom != 1 {
		t.Fatalf("port info = %+v", pu.Info)
	}
	dictGet(t, pu.Info.Props, "port.group", "stream.0")
	wantPortInfos := []proto.ParamInfo{{ID: 3, Flags: 2}, {ID: 6, Flags: 2}, {ID: 7, Flags: 2}, {ID: 4, Flags: 4}, {ID: 5, Flags: 0}}
	if !reflect.DeepEqual(pu.Info.Params, wantPortInfos) {
		t.Fatalf("port param infos = %+v", pu.Info.Params)
	}
}

// memoryAndTransport announces the memory blocks, sends Transport and the two
// SetActivation events (one for the driver, one for the node itself), and
// checks the client activates the node.
func (sc *scenario) memoryAndTransport() {
	t, s := sc.t, sc.srv
	t.Helper()
	for _, m := range []proto.CoreAddMem{
		{ID: memAct, Type: pod.DataMemFd, Fd: fdAct, Flags: 3},
		{ID: memDrv, Type: pod.DataMemFd, Fd: fdDrv, Flags: 3},
		{ID: memIO, Type: pod.DataMemFd, Fd: fdIO, Flags: 3},
		{ID: memBuf, Type: pod.DataMemFd, Fd: fdBuf, Flags: 3},
		{ID: memPix, Type: pod.DataMemFd, Fd: fdPix, Flags: 3},
	} {
		s.send(proto.IDCore, m)
	}
	s.send(2, proto.ClientNodeTransport{ReadFd: fdRead, WriteFd: fdWrite, MemID: memAct, Offset: 0, Size: actSize})
	s.send(2, proto.ClientNodeSetActivation{NodeID: driverNode, SignalFd: fdDrvSig, MemID: memDrv, Offset: 0, Size: actSize})
	s.send(2, proto.ClientNodeSetActivation{NodeID: ourGlobal, SignalFd: fdSelfSig, MemID: memAct, Offset: 0, Size: actSize})

	if sa := want[proto.ClientNodeSetActive](s); !sa.Active {
		t.Fatal("the client sent SetActive(false) instead of true")
	}
	if v := atomic.LoadUint32(atomicWord(sc.act, actClientVersion)); v != 1 {
		t.Fatalf("client_version = %d, want 1", v)
	}
	if st := atomic.LoadUint32(atomicWord(sc.act, actStatus)); st != actFinished {
		t.Fatalf("activation status after SetActive = %d, want FINISHED (3)", st)
	}
}

func formatObject(id uint32) pod.Object {
	return pod.NewObject(pod.ObjectFormat, pod.ParamFormat,
		pod.P(pod.FormatMediaType, pod.Id(pod.MediaTypeVideo)),
		pod.P(pod.FormatMediaSubtype, pod.Id(pod.MediaSubtypeRaw)),
		pod.P(pod.FormatVideoFormat, pod.Id(id)),
		pod.P(pod.FormatVideoSize, pod.Rect(frameW, frameH)),
		pod.P(pod.FormatVideoFramerate, pod.Frac(30, 1)),
	)
}

// setFormat sends the chosen format and checks the second PortUpdate, then
// the Ping/Pong the server uses to confirm it.
func (sc *scenario) setFormat(id uint32) {
	t, s := sc.t, sc.srv
	t.Helper()
	s.send(2, proto.ClientNodePortSetMixInfo{Direction: 0, PortID: 0, MixID: 0, PeerID: proto.InvalidID})
	s.send(2, proto.ClientNodePortSetParam{Direction: 0, PortID: 0, ParamID: pod.ParamFormat, Param: formatObject(id)})
}

func (sc *scenario) secondPortUpdate() {
	t, s := sc.t, sc.srv
	t.Helper()
	pu := want[proto.ClientNodePortUpdate](s)
	var gotFormat, gotBuffers bool
	for _, p := range pu.Params {
		o, _ := pod.AsObject(p)
		switch o.ObjType {
		case pod.ObjectFormat:
			if o.ID == pod.ParamFormat {
				gotFormat = true
				if r, _ := o.GetRectangle(pod.FormatVideoSize); r != pod.Rect(frameW, frameH) {
					t.Fatalf("echoed format size = %v", r)
				}
			}
		case pod.ObjectParamBuffers:
			gotBuffers = true
			for key, want := range map[uint32]int32{
				pod.ParamBuffersBlocks: 1,
				pod.ParamBuffersSize:   frameW * 4 * frameH,
				pod.ParamBuffersStride: frameW * 4,
			} {
				if got, err := o.GetInt(key); err != nil || got != want {
					t.Fatalf("Buffers key %d = %d (%v), want %d", key, got, err, want)
				}
			}
			// Data types: MemPtr (bit 2) and MemFd (bit 4), never DmaBuf (bit 8).
			if mask, err := o.GetInt(pod.ParamBuffersDataType); err != nil || mask != 6 {
				t.Fatalf("dataType mask = %d (%v), want 6", mask, err)
			}
		}
	}
	if !gotFormat || !gotBuffers {
		t.Fatalf("second port update lacks Format (%v) or Buffers (%v)", gotFormat, gotBuffers)
	}
	sc.nformat++
	serial := uint32(sc.nformat % 2)
	wantInfos := []proto.ParamInfo{{ID: 3, Flags: 2}, {ID: 6, Flags: 2}, {ID: 7, Flags: 2}, {ID: 4, Flags: 6 | serial}, {ID: 5, Flags: 2 | serial}}
	if !reflect.DeepEqual(pu.Info.Params, wantInfos) {
		t.Fatalf("param infos with a format = %+v", pu.Info.Params)
	}
	s.send(proto.IDCore, proto.CorePing{ID: 2, Seq: 7})
	if pong := want[proto.CorePong](s); pong.ID != 2 || pong.Seq != 7 {
		t.Fatalf("pong = %+v", pong)
	}
}

func (sc *scenario) buffers(memID uint32) proto.ClientNodePortUseBuffers {
	ev := proto.ClientNodePortUseBuffers{Direction: 0, PortID: 0, MixID: 0}
	for i := 0; i < 2; i++ {
		ub := proto.UseBuffer{
			MemID: memID, Offset: uint32(bufOffset(i)), Size: bufBlockSize,
			Metas: []proto.BufferMeta{{Type: pod.MetaVideoCrop, Size: 16}, {Type: pod.MetaBusy, Size: 8}},
		}
		if sc.cfg.kind == kindMemPtr {
			ub.Datas = []proto.UseBufferData{{Type: pod.DataMemPtr, DataID: pixOff, MaxSize: pixBytes}}
		} else {
			ub.Datas = []proto.UseBufferData{{Type: pod.DataMemId, DataID: memPix, MapOffset: uint32(i * 4096), MaxSize: pixBytes}}
		}
		ev.Buffers = append(ev.Buffers, ub)
	}
	return ev
}

func (sc *scenario) useBuffersAndIO() {
	sc.srv.send(2, sc.buffers(memBuf))
	sc.srv.send(2, proto.ClientNodePortSetIO{Direction: 0, PortID: 0, MixID: 0, IOID: pod.IOBuffers, MemID: memIO, Offset: 0, Size: 8})
}

func (sc *scenario) command(id uint32) {
	sc.srv.send(2, proto.ClientNodeCommand{Command: pod.NewObject(pod.TypeCommandNode, id)})
}

// toStreaming plays the whole sequence up to Command Start.
func (sc *scenario) toStreaming() *Stream {
	sc.t.Helper()
	sc.hello()
	sc.createObject()
	sc.updates()
	sc.memoryAndTransport()
	sc.setFormat(pod.VideoFormatBGRx)
	sc.secondPortUpdate()
	sc.useBuffersAndIO()
	sc.command(pod.NodeCommandStart)
	return sc.opened()
}

// Server-side views of one buffer.
func (sc *scenario) chunk(i int) []byte { return sc.buf[bufOffset(i)+chunkOff:][:16] }
func (sc *scenario) crop(i int) []byte  { return sc.buf[bufOffset(i)+cropOff:][:16] }
func (sc *scenario) busy(i int) []byte  { return sc.buf[bufOffset(i)+busyOff:][:8] }
func (sc *scenario) pixels(i int) []byte {
	if sc.cfg.kind == kindMemPtr {
		return sc.buf[bufOffset(i)+pixOff:][:pixBytes]
	}
	return sc.pix[i*4096:][:pixBytes]
}

func putU32(b []byte, off int, v uint32) {
	b[off], b[off+1], b[off+2], b[off+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

// fillBGRx writes the pattern for frame k: pixel (x, y) is B=x*10+k,
// G=y*20+k, R=x+y*5, x=0xEE. Padding between rows stays 0xEE.
func (sc *scenario) fillBGRx(i, k int) {
	p := sc.pixels(i)
	for j := range p {
		p[j] = 0xEE
	}
	for y := 0; y < frameH; y++ {
		for x := 0; x < frameW; x++ {
			o := y*frameStride + x*4
			p[o], p[o+1], p[o+2], p[o+3] = byte(x*10+k), byte(y*20+k), byte(x+y*5), 0xEE
		}
	}
	c := sc.chunk(i)
	putU32(c, 0, 0)
	putU32(c, 4, pixBytes)
	putU32(c, 8, frameStride)
	putU32(c, 12, 0)
}

func expectedPixel(k, x, y int) color.RGBA {
	return color.RGBA{R: byte(x + y*5), G: byte(y*20 + k), B: byte(x*10 + k), A: 255}
}

// wake plays one driver cycle: the producer has put buffer id in the I/O
// area, the driver has prepared its own activation (pending 1, status
// NOT_TRIGGERED) and triggers the node. It returns once the node woke the
// driver again, or reports that it did not within the wait.
func (sc *scenario) wake(id uint32, expectDriverWake bool) {
	sc.t.Helper()
	sc.wakeVia(sc.io, id, expectDriverWake)
}

// wakeVia is wake with the producer using the given I/O area.
func (sc *scenario) wakeVia(io []byte, id uint32, expectDriverWake bool) {
	t := sc.t
	t.Helper()
	atomic.StoreUint32(atomicWord(io, ioBuffersBufferID), id)
	atomic.StoreInt32(atomicInt(io, ioBuffersStatus), statusHaveData)
	atomic.StoreInt32(atomicInt(sc.drv, actState0Pending), 1)
	atomic.StoreUint32(atomicWord(sc.drv, actStatus), actNotTriggered)
	atomic.StoreUint32(atomicWord(sc.act, actStatus), actTriggered)
	if err := sc.sig.Notify(fdRead); err != nil {
		t.Fatal(err)
	}
	wait := 5 * time.Second
	if !expectDriverWake {
		wait = 300 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	err := sc.sig.Wait(ctx, fdDrvSig)
	if expectDriverWake && err != nil {
		t.Fatalf("the node did not wake the driver: %v", err)
	}
	if !expectDriverWake {
		if err == nil {
			t.Fatal("an async node woke the driver")
		}
		// Let the cycle finish before the caller looks at the state.
		deadline := time.Now().Add(5 * time.Second)
		for atomic.LoadUint32(atomicWord(sc.act, actStatus)) != actFinished && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}
	if st := atomic.LoadUint32(atomicWord(sc.act, actStatus)); st != actFinished {
		t.Fatalf("node activation status = %d, want FINISHED (3)", st)
	}
	if v := atomic.LoadInt32(atomicInt(sc.act, actState0Status)); v != 3 {
		t.Fatalf("state[0].status = %d, want NEED_DATA|HAVE_DATA (3)", v)
	}
	if sc.act[actAwakeTime] == 0 && sc.act[actAwakeTime+1] == 0 && sc.act[actAwakeTime+2] == 0 {
		t.Fatal("awake_time was not written")
	}
}

func (sc *scenario) checkDriverTriggered() {
	t := sc.t
	t.Helper()
	if st := atomic.LoadUint32(atomicWord(sc.drv, actStatus)); st != actTriggered {
		t.Fatalf("driver status = %d, want TRIGGERED (1)", st)
	}
	if p := atomic.LoadInt32(atomicInt(sc.drv, actState0Pending)); p != 0 {
		t.Fatalf("driver pending = %d, want 0", p)
	}
	if sc.drv[actSignalTime] == 0 && sc.drv[actSignalTime+1] == 0 && sc.drv[actSignalTime+2] == 0 {
		t.Fatal("the driver's signal_time was not written")
	}
}

func TestStreamFramesActivationAndClose(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind dataKind
	}{{"MemPtr data", kindMemPtr}, {"MemId data", kindMemID}} {
		t.Run(tc.name, func(t *testing.T) {
			sc := newScenario(t, config{kind: tc.kind})
			s := sc.toStreaming()

			if f, ok := s.Format(); !ok || f != (Format{PixelFormat: pod.VideoFormatBGRx, Width: frameW, Height: frameH}) {
				t.Fatalf("Format = %+v, %v", f, ok)
			}
			if img, seq := s.Latest(); img != nil || seq != 0 {
				t.Fatalf("Latest before any frame = %v, %d", img, seq)
			}
			// Start puts NEED_DATA into the I/O area.
			if st := atomic.LoadInt32(atomicInt(sc.io, ioBuffersStatus)); st != statusNeedData {
				t.Fatalf("I/O status after Start = %d, want NEED_DATA", st)
			}
			// The node itself was not registered as a peer: its eventfd was closed.
			if closed := sc.sig.Closed(); !reflect.DeepEqual(closed, []int{fdSelfSig}) {
				t.Fatalf("descriptors closed so far = %v, want only the self activation's", closed)
			}

			// Three frames of a known pattern, alternating buffers.
			for k := 0; k < 3; k++ {
				bufID := k % 2
				sc.fillBGRx(bufID, k)
				sc.wake(uint32(bufID), true)
				sc.checkDriverTriggered()
				if st := atomic.LoadInt32(atomicInt(sc.io, ioBuffersStatus)); st != statusNeedData {
					t.Fatalf("frame %d: I/O status = %d, want NEED_DATA (1)", k, st)
				}
				if c := atomic.LoadUint32(atomicWord(sc.busy(bufID), 4)); c != 0 {
					t.Fatalf("frame %d: busy count = %d, want 0 after the copy", k, c)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				img, seq, err := s.Wait(ctx, uint64(k))
				cancel()
				if err != nil {
					t.Fatalf("frame %d: %v", k, err)
				}
				if seq != uint64(k+1) {
					t.Fatalf("frame %d: seq = %d", k, seq)
				}
				if got := img.Bounds(); got.Dx() != frameW || got.Dy() != frameH {
					t.Fatalf("frame %d: size %v", k, got)
				}
				for y := 0; y < frameH; y++ {
					for x := 0; x < frameW; x++ {
						if got, want := img.RGBAAt(x, y), expectedPixel(k, x, y); got != want {
							t.Fatalf("frame %d pixel (%d,%d) = %v, want %v", k, x, y, got, want)
						}
					}
				}
				if l, lseq := s.Latest(); l != img || lseq != seq {
					t.Fatalf("Latest does not return the newest frame")
				}
			}

			// A VideoCrop meta selects the visible rectangle.
			sc.fillBGRx(1, 3)
			crop := sc.crop(1)
			putU32(crop, 0, 1)
			putU32(crop, 4, 1)
			putU32(crop, 8, 3)
			putU32(crop, 12, 2)
			sc.wake(1, true)
			sc.checkDriverTriggered()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			img, seq, err := s.Wait(ctx, 3)
			cancel()
			if err != nil || seq != 4 {
				t.Fatalf("cropped frame: seq %d, %v", seq, err)
			}
			if got := img.Bounds(); got.Dx() != 3 || got.Dy() != 2 {
				t.Fatalf("cropped size = %v, want 3x2", got)
			}
			for y := 0; y < 2; y++ {
				for x := 0; x < 3; x++ {
					if got, want := img.RGBAAt(x, y), expectedPixel(3, x+1, y+1); got != want {
						t.Fatalf("cropped pixel (%d,%d) = %v, want %v", x, y, got, want)
					}
				}
			}
			if st := s.Stats(); st.Frames != 4 || st.Dropped != 0 || st.Skipped != 0 {
				t.Fatalf("stats = %+v", st)
			}

			// Close sends SetActive(false) and Destroy and releases everything.
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if sa := want[proto.ClientNodeSetActive](sc.srv); sa.Active {
				t.Fatal("Close sent SetActive(true)")
			}
			if d := want[proto.CoreDestroy](sc.srv); d.ID != 2 {
				t.Fatalf("destroy = %+v", d)
			}
			if st := atomic.LoadUint32(atomicWord(sc.act, actStatus)); st != actInactive {
				t.Fatalf("activation status after Close = %d, want INACTIVE (4)", st)
			}
			if n := sc.mem.Mapped(); n != 0 {
				t.Fatalf("%d mappings left after Close", n)
			}
			closed := map[int]bool{}
			for _, fd := range sc.sig.Closed() {
				closed[fd] = true
			}
			for _, fd := range []int{fdRead, fdWrite, fdDrvSig, fdSelfSig} {
				if !closed[fd] {
					t.Fatalf("descriptor %d was not closed; closed = %v", fd, sc.sig.Closed())
				}
			}
			select {
			case <-s.Done():
			default:
				t.Fatal("Done is not closed after Close")
			}
			if s.Err() != nil {
				t.Fatalf("Err after an orderly Close = %v", s.Err())
			}
			if _, _, err := s.Wait(context.Background(), 4); !errors.Is(err, ErrClosed) {
				t.Fatalf("Wait after Close = %v, want ErrClosed", err)
			}
			if err := s.Close(); err != nil {
				t.Fatalf("second Close: %v", err)
			}
		})
	}
}

func TestStreamPauseStopsFramesButFinishesCycles(t *testing.T) {
	sc := newScenario(t, config{kind: kindMemPtr})
	s := sc.toStreaming()
	sc.fillBGRx(0, 0)
	sc.wake(0, true)
	if _, seq := s.Latest(); seq != 1 {
		t.Fatalf("seq = %d, want 1", seq)
	}

	sc.command(pod.NodeCommandPause)
	// The command is handled on the read loop; a Sync round trip orders it
	// before the next wake-up.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sc.conn.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	sc.fillBGRx(1, 1)
	sc.wake(1, true) // the cycle still completes and wakes the driver
	if _, seq := s.Latest(); seq != 1 {
		t.Fatalf("a paused stream published frame %d", seq)
	}
	if st := atomic.LoadInt32(atomicInt(sc.io, ioBuffersStatus)); st != statusHaveData {
		t.Fatalf("a paused stream touched the I/O area: status %d", st)
	}

	sc.command(pod.NodeCommandStart)
	if err := sc.conn.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	sc.fillBGRx(1, 2)
	sc.wake(1, true)
	if _, seq := s.Latest(); seq != 2 {
		t.Fatalf("seq after restart = %d, want 2", seq)
	}
}

func TestStreamAsyncNodeDoesNotWakeDriver(t *testing.T) {
	sc := newScenario(t, config{kind: kindMemPtr, async: true})
	s := sc.toStreaming()
	sc.fillBGRx(0, 0)
	sc.wake(0, false)
	if _, seq := s.Latest(); seq != 1 {
		t.Fatalf("seq = %d, want 1", seq)
	}
	if st := atomic.LoadUint32(atomicWord(sc.drv, actStatus)); st != actNotTriggered {
		t.Fatalf("an async node changed the driver status to %d", st)
	}
	if p := atomic.LoadInt32(atomicInt(sc.drv, actState0Pending)); p != 1 {
		t.Fatalf("an async node changed the driver's pending count to %d", p)
	}
}

func TestStreamDropsBadFramesThenGivesUp(t *testing.T) {
	sc := newScenario(t, config{kind: kindMemPtr})
	s := sc.toStreaming()
	sc.fillBGRx(0, 0)
	putU32(sc.chunk(0), 8, 8) // stride smaller than a row
	for i := 0; i < maxBadFrames-1; i++ {
		sc.wake(0, true)
	}
	if st := s.Stats(); st.Dropped != maxBadFrames-1 || !strings.Contains(st.LastDrop, "stride") {
		t.Fatalf("stats = %+v", st)
	}
	if s.Err() != nil {
		t.Fatalf("the stream ended early: %v", s.Err())
	}
	// A good frame resets the count.
	sc.fillBGRx(0, 0)
	sc.wake(0, true)
	putU32(sc.chunk(0), 8, 8)
	for i := 0; i < maxBadFrames-1; i++ {
		sc.wake(0, true)
	}
	if s.Err() != nil {
		t.Fatalf("the count was not reset by a good frame: %v", s.Err())
	}
	atomic.StoreUint32(atomicWord(sc.io, ioBuffersBufferID), 0)
	atomic.StoreInt32(atomicInt(sc.io, ioBuffersStatus), statusHaveData)
	atomic.StoreInt32(atomicInt(sc.drv, actState0Pending), 1)
	atomic.StoreUint32(atomicWord(sc.drv, actStatus), actNotTriggered)
	atomic.StoreUint32(atomicWord(sc.act, actStatus), actTriggered)
	sc.sig.Notify(fdRead)
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the stream did not end after repeated bad frames")
	}
	if err := s.Err(); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("Err = %v", err)
	}
}

func TestStreamUnknownMemBlockEndsOpen(t *testing.T) {
	sc := newScenario(t, config{kind: kindMemPtr})
	sc.hello()
	sc.createObject()
	sc.updates()
	sc.memoryAndTransport()
	sc.setFormat(pod.VideoFormatBGRx)
	sc.secondPortUpdate()
	sc.srv.send(2, sc.buffers(99)) // block 99 was never announced

	r := sc.result()
	if r.err == nil || !strings.Contains(r.err.Error(), "memory block 99") {
		t.Fatalf("Open error = %v, want it to name memory block 99", r.err)
	}
	// The stream tells the server it is gone.
	if sa := want[proto.ClientNodeSetActive](sc.srv); sa.Active {
		t.Fatal("expected SetActive(false)")
	}
	if d := want[proto.CoreDestroy](sc.srv); d.ID != 2 {
		t.Fatalf("destroy = %+v", d)
	}
	if n := sc.mem.Mapped(); n != 0 {
		t.Fatalf("%d mappings left", n)
	}
}

func TestStreamUnknownMemBlockEndsRunningStream(t *testing.T) {
	sc := newScenario(t, config{kind: kindMemPtr})
	s := sc.toStreaming()
	sc.srv.send(2, sc.buffers(98))
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the stream did not end")
	}
	if err := s.Err(); err == nil || !strings.Contains(err.Error(), "memory block 98") {
		t.Fatalf("Err = %v", err)
	}
	if _, _, err := s.Wait(context.Background(), 0); err == nil || !strings.Contains(err.Error(), "memory block 98") {
		t.Fatalf("Wait = %v", err)
	}
	if n := sc.mem.Mapped(); n != 0 {
		t.Fatalf("%d mappings left", n)
	}
}

func TestStreamRejectsBufferRangesOutsideTheBlock(t *testing.T) {
	cases := []struct {
		name string
		edit func(ev *proto.ClientNodePortUseBuffers)
		want string
	}{
		{"block beyond the memory", func(ev *proto.ClientNodePortUseBuffers) { ev.Buffers[0].Offset = 4000 }, "holds 4096"},
		{"pixels beyond the block", func(ev *proto.ClientNodePortUseBuffers) { ev.Buffers[0].Datas[0].DataID = 100 }, "runs past"},
		{"meta beyond the block", func(ev *proto.ClientNodePortUseBuffers) { ev.Buffers[0].Metas[0].Size = 4000 }, "runs past"},
		{"no data", func(ev *proto.ClientNodePortUseBuffers) { ev.Buffers[0].Datas = nil }, "no data block"},
		{"dmabuf data", func(ev *proto.ClientNodePortUseBuffers) { ev.Buffers[0].Datas[0].Type = pod.DataDmaBuf }, "did not offer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sc := newScenario(t, config{kind: kindMemPtr})
			sc.hello()
			sc.createObject()
			sc.updates()
			sc.memoryAndTransport()
			sc.setFormat(pod.VideoFormatBGRx)
			sc.secondPortUpdate()
			ev := sc.buffers(memBuf)
			c.edit(&ev)
			sc.srv.send(2, ev)
			r := sc.result()
			if r.err == nil || !strings.Contains(r.err.Error(), c.want) {
				t.Fatalf("Open error = %v, want it to mention %q", r.err, c.want)
			}
			// Wait for teardown, then check nothing stays mapped.
			want[proto.ClientNodeSetActive](sc.srv)
			want[proto.CoreDestroy](sc.srv)
			if n := sc.mem.Mapped(); n != 0 {
				t.Fatalf("%d mappings left", n)
			}
		})
	}
}

func TestStreamFormatNotOfferedEndsOpen(t *testing.T) {
	sc := newScenario(t, config{kind: kindMemPtr})
	sc.hello()
	sc.createObject()
	sc.updates()
	sc.memoryAndTransport()
	sc.setFormat(9) // xRGB, which the client did not offer
	r := sc.result()
	if r.err == nil || !strings.Contains(r.err.Error(), "did not offer") {
		t.Fatalf("Open error = %v", r.err)
	}
}

func TestStreamCoreErrorEndsOpen(t *testing.T) {
	sc := newScenario(t, config{kind: kindMemPtr})
	sc.hello()
	want[proto.CoreCreateObject](sc.srv)
	sc.srv.send(proto.IDCore, proto.CoreErrorEvent{ID: 2, Seq: 3, Res: -13, Message: "permission denied"})

	r := sc.result()
	if r.err == nil {
		t.Fatal("Open succeeded after a Core Error")
	}
	var se *proto.ServerError
	if !errors.As(r.err, &se) || se.Res != -13 || se.Message != "permission denied" {
		t.Fatalf("Open error = %v, want a ServerError for permission denied", r.err)
	}
	if sc.conn.Err() != nil {
		t.Fatalf("an error on the stream ended the shared connection: %v", sc.conn.Err())
	}
	if !strings.Contains(r.err.Error(), "the PipeWire server reported an error on object 2") {
		t.Fatalf("Open error = %q", r.err)
	}
}

func TestStreamOpenTimesOutWithoutStart(t *testing.T) {
	cl, sv := proto.NewMemPair()
	conn := proto.NewConn(cl, proto.Config{})
	srv := newFakeServer(t, sv)
	t.Cleanup(func() { conn.Close(); sv.Close() })
	mem, sig := NewMemFiles(), NewMemSignals()
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	_, err := Open(ctx, conn, Options{NodeID: portalNode, Mem: mem, Signal: sig})
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "did not start the stream") {
		t.Fatalf("Open error = %v", err)
	}
	want[proto.CoreHello](srv)
	want[proto.ClientUpdateProperties](srv)
	want[proto.CoreSync](srv)
	co := want[proto.CoreCreateObject](srv)
	if co.NewID != 2 {
		t.Fatalf("create object = %+v", co)
	}
	want[proto.ClientNodeUpdate](srv)
	want[proto.ClientNodePortUpdate](srv)
	// The node never became active, so only Destroy follows.
	if d := want[proto.CoreDestroy](srv); d.ID != 2 {
		t.Fatalf("destroy = %+v", d)
	}
}

func TestStreamEndsWhenConnectionEnds(t *testing.T) {
	sc := newScenario(t, config{kind: kindMemPtr})
	s := sc.toStreaming()
	sc.srv.tr.Close()
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the stream did not end with the connection")
	}
	if s.Err() == nil {
		t.Fatal("Err is nil after the server closed the connection")
	}
	if n := sc.mem.Mapped(); n != 0 {
		t.Fatalf("%d mappings left", n)
	}
}

func TestStreamServerRemovesNode(t *testing.T) {
	sc := newScenario(t, config{kind: kindMemPtr})
	s := sc.toStreaming()
	sc.srv.send(proto.IDCore, proto.CoreRemoveId{ID: 2})
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the stream did not end")
	}
	if err := s.Err(); err == nil || !strings.Contains(err.Error(), "removed the stream's node") {
		t.Fatalf("Err = %v", err)
	}
}

func TestOpenWithoutPlatformImplementation(t *testing.T) {
	if platformMem() != nil {
		t.Skip("this platform has a shared memory implementation")
	}
	cl, _ := proto.NewMemPair()
	conn := proto.NewConn(cl, proto.Config{})
	defer conn.Close()
	_, err := Open(context.Background(), conn, Options{NodeID: 1})
	if err == nil || !strings.Contains(err.Error(), "only available on Linux") {
		t.Fatalf("Open error = %v", err)
	}
}

func (s *fakeServer) connErr() error {
	if s.conn == nil {
		return nil
	}
	return s.conn.Err()
}

func TestStreamDoesNotWakeDriverWhenCycleWasTakenOver(t *testing.T) {
	sc := newScenario(t, config{kind: kindMemPtr})
	s := sc.toStreaming()
	sc.fillBGRx(0, 0)
	// The server sets the node INACTIVE while the cycle runs, so the
	// AWAKE to FINISHED exchange fails and process_node triggers nobody.
	hook := func() { atomic.StoreUint32(atomicWord(sc.act, actStatus), actInactive) }
	sc.onNow.Store(&hook)
	atomic.StoreUint32(atomicWord(sc.io, ioBuffersBufferID), 0)
	atomic.StoreInt32(atomicInt(sc.io, ioBuffersStatus), statusHaveData)
	atomic.StoreInt32(atomicInt(sc.drv, actState0Pending), 1)
	atomic.StoreUint32(atomicWord(sc.drv, actStatus), actNotTriggered)
	atomic.StoreUint32(atomicWord(sc.act, actStatus), actTriggered)
	if err := sc.sig.Notify(fdRead); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := s.Wait(ctx, 0); err != nil {
		t.Fatal(err)
	}
	wctx, wcancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer wcancel()
	if err := sc.sig.Wait(wctx, fdDrvSig); err == nil {
		t.Fatal("the node woke the driver after losing its cycle")
	}
	if p := atomic.LoadInt32(atomicInt(sc.drv, actState0Pending)); p != 1 {
		t.Fatalf("driver pending = %d, want 1 (untouched)", p)
	}
}

func TestStreamCloseWakesDriverWhenNodeWasTriggered(t *testing.T) {
	for _, old := range []uint32{actTriggered, actAwake, actFinished} {
		sc := newScenario(t, config{kind: kindMemPtr})
		s := sc.toStreaming()
		atomic.StoreInt32(atomicInt(sc.drv, actState0Pending), 1)
		atomic.StoreUint32(atomicWord(sc.drv, actStatus), actNotTriggered)
		atomic.StoreUint32(atomicWord(sc.act, actStatus), old)
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		woke := atomic.LoadUint32(atomicWord(sc.drv, actStatus)) == actTriggered
		if want := old <= actAwake; woke != want {
			t.Fatalf("old status %d: driver woken = %v, want %v", old, woke, want)
		}
		if st := atomic.LoadUint32(atomicWord(sc.act, actStatus)); st != actInactive {
			t.Fatalf("status after Close = %d", st)
		}
	}
}

// A second format negotiation re-announces Format and Buffers with the same
// READ and WRITE bits, so the SERIAL bit must flip or the server ignores the
// update (impl-port.c update_info compares the flags).
func TestStreamFormatChangeFlipsParamSerial(t *testing.T) {
	sc := newScenario(t, config{kind: kindMemPtr})
	s := sc.toStreaming()
	_ = s
	sc.setFormat(pod.VideoFormatBGRx)
	sc.secondPortUpdate() // checks serial 0 again after two toggles
	if sc.nformat != 2 {
		t.Fatalf("nformat = %d", sc.nformat)
	}
}

func TestStreamReportsRunningAndLastFrameTime(t *testing.T) {
	sc := newScenario(t, config{kind: kindMemPtr})
	s := sc.toStreaming()
	if !s.Running() {
		t.Fatal("a started stream is not Running")
	}
	if !s.LastFrame().IsZero() {
		t.Fatalf("LastFrame before any frame = %v", s.LastFrame())
	}
	before := time.Now()
	sc.fillBGRx(0, 0)
	sc.wake(0, true)
	if at := s.LastFrame(); at.Before(before) || at.After(time.Now()) {
		t.Fatalf("LastFrame = %v, want a time since %v", at, before)
	}
	sc.command(pod.NodeCommandPause)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sc.conn.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if s.Running() {
		t.Fatal("a paused stream is still Running")
	}
}

// Second I/O area for the mix tests: a link the server sets up while the
// first one is still alive.
const (
	fdIO2  = 15
	memIO2 = 6
)

func (sc *scenario) addIO2() []byte {
	io2 := make([]byte, 4096)
	sc.mem.Add(fdIO2, io2)
	sc.srv.send(proto.IDCore, proto.CoreAddMem{ID: memIO2, Type: pod.DataMemFd, Fd: fdIO2, Flags: 3})
	return io2
}

// syncConn orders everything the server sent before the next step.
func (sc *scenario) syncConn() {
	sc.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sc.conn.Sync(ctx); err != nil {
		sc.t.Fatal(err)
	}
}

// newMix announces mix id with its own buffers and the second I/O area.
func (sc *scenario) newMix(id uint32) {
	ev := sc.buffers(memBuf)
	ev.MixID = id
	sc.srv.send(2, proto.ClientNodePortSetMixInfo{Direction: 0, PortID: 0, MixID: id, PeerID: 90})
	sc.srv.send(2, ev)
	sc.srv.send(2, proto.ClientNodePortSetIO{Direction: 0, PortID: 0, MixID: id, IOID: pod.IOBuffers, MemID: memIO2, Offset: 0, Size: 8})
}

func (sc *scenario) expectFrame(s *Stream, k int, wantSeq uint64) {
	sc.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	img, seq, err := s.Wait(ctx, wantSeq-1)
	if err != nil || seq != wantSeq {
		sc.t.Fatalf("frame %d: seq %d, %v, want %d", k, seq, err, wantSeq)
	}
	for y := 0; y < frameH; y++ {
		for x := 0; x < frameW; x++ {
			if got, want := img.RGBAAt(x, y), expectedPixel(k, x, y); got != want {
				sc.t.Fatalf("frame %d pixel (%d,%d) = %v, want %v", k, x, y, got, want)
			}
		}
	}
}

func TestStreamMakeBeforeBreakKeepsNewMix(t *testing.T) {
	sc := newScenario(t, config{kind: kindMemPtr})
	s := sc.toStreaming()
	sc.fillBGRx(0, 0)
	sc.wake(0, true)
	sc.expectFrame(s, 0, 1)

	io2 := sc.addIO2()
	sc.newMix(1)
	sc.syncConn()
	// Both links are active; the newest one wins.
	sc.fillBGRx(1, 1)
	sc.wakeVia(io2, 1, true)
	sc.expectFrame(s, 1, 2)

	// The old link is torn down after the new one is up.
	sc.srv.send(2, proto.ClientNodePortSetIO{Direction: 0, PortID: 0, MixID: 0, IOID: pod.IOBuffers, MemID: proto.InvalidID})
	sc.srv.send(2, proto.ClientNodePortUseBuffers{Direction: 0, PortID: 0, MixID: 0})
	sc.srv.send(2, proto.ClientNodePortSetMixInfo{Direction: 0, PortID: 0, MixID: 0, PeerID: proto.InvalidID})
	sc.syncConn()
	if err := s.Err(); err != nil {
		t.Fatalf("the stream failed: %v", err)
	}
	sc.fillBGRx(0, 2)
	sc.wakeVia(io2, 0, true)
	sc.expectFrame(s, 2, 3)

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if n := sc.mem.Mapped(); n != 0 {
		t.Fatalf("%d mappings left after Close", n)
	}
}

func TestStreamRemovingOneMixLeavesTheOther(t *testing.T) {
	sc := newScenario(t, config{kind: kindMemPtr})
	s := sc.toStreaming()
	sc.syncConn()
	before := sc.mem.Mapped()

	sc.addIO2()
	sc.newMix(1)
	sc.syncConn()
	if sc.mem.Mapped() <= before {
		t.Fatalf("mix 1 mapped nothing: %d mappings before, %d after", before, sc.mem.Mapped())
	}
	sc.srv.send(2, proto.ClientNodePortSetMixInfo{Direction: 0, PortID: 0, MixID: 1, PeerID: proto.InvalidID})
	sc.syncConn()
	if n := sc.mem.Mapped(); n != before {
		t.Fatalf("removing mix 1 left %d mappings, want %d", n, before)
	}
	// Mix 0 still works.
	sc.fillBGRx(0, 0)
	sc.wake(0, true)
	sc.expectFrame(s, 0, 1)
	if err := s.Err(); err != nil {
		t.Fatalf("the stream failed: %v", err)
	}
}

func TestStreamUnknownMixDoesNotEndTheStream(t *testing.T) {
	sc := newScenario(t, config{kind: kindMemPtr})
	s := sc.toStreaming()
	sc.addIO2()
	sc.srv.send(2, proto.ClientNodePortSetIO{Direction: 0, PortID: 0, MixID: 7, IOID: pod.IOBuffers, MemID: memIO2, Offset: 0, Size: 8})
	sc.srv.send(2, proto.ClientNodePortSetIO{Direction: 0, PortID: 0, MixID: 9, IOID: pod.IOBuffers, MemID: proto.InvalidID})
	sc.syncConn()
	if err := s.Err(); err != nil {
		t.Fatalf("an unknown mix ended the stream: %v", err)
	}
	sc.fillBGRx(0, 0)
	sc.wake(0, true)
	sc.expectFrame(s, 0, 1)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if n := sc.mem.Mapped(); n != 0 {
		t.Fatalf("%d mappings left after Close, the unknown mix's I/O area leaked", n)
	}
}
