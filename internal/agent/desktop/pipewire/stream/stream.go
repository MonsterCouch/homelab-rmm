// Package stream receives video frames from a PipeWire node without CGO. It
// exports a client-node on an existing proto.Conn, one input port that asks
// the server to link the node to a portal screencast node, and serves the
// events the server sends until the stream ends. Frames come out as
// *image.RGBA.
//
// The sequence and every layout follow docs/plans/2026-10-25-pipewire-
// protocol-notes.md, which was read from PipeWire 1.2.7. No PipeWire daemon
// was available when this was written; the tests run against a fake server
// that behaves as the notes describe. The first run against a real
// compositor is the actual check.
//
// Shared memory and eventfds sit behind the Mem and Signal interfaces. The
// Linux implementations use mmap and eventfd; MemFiles and MemSignals keep
// everything in memory for tests.
package stream

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/pod"
	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/proto"
)

// ErrClosed is returned by Wait after Close.
var ErrClosed = errors.New("the PipeWire video stream was closed")

// maxBadFrames is how many frames in a row may fail validation before the
// stream gives up.
const maxBadFrames = 10

// errno values for Core.Error replies.
const errNotSupported = -95

// Options configure Open.
type Options struct {
	// NodeID is the PipeWire node the portal returned. The new node asks the
	// session manager to link to it.
	NodeID uint32
	// Name is the node name. It defaults to "homelab-rmm-screen".
	Name string

	// Mem and Signal default to the Linux implementations. Open fails on
	// other systems when they are nil.
	Mem    Mem
	Signal Signal

	// SkipHello leaves out Core.Hello, Client.UpdateProperties and the Sync
	// that follows them. Set it for a second stream on a Conn that already
	// said hello.
	SkipHello bool

	// Async declares the node as asynchronous (node.async and the ASYNC node
	// flag). The driver then resumes the graph by itself and the stream does
	// not wake it after a frame. By default the stream is a synchronous node
	// and wakes the driver as the notes describe in section 4.5.
	Async bool
}

// Stats counts what the stream has done.
type Stats struct {
	Frames   uint64 // frames published
	Skipped  uint64 // frames the producer marked corrupted or empty
	Dropped  uint64 // frames that failed validation
	LastDrop string // why the last frame was dropped
}

type transportState struct {
	readFd, writeFd int
	memID, offset   uint32
	act             *mapping
	waiter          Waiter
}

// mix is the state of one link into the input port, keyed by mix id as
// remote-node.c keys its pw_mix by (direction, port_id, mix_id). The server
// sets a new link up before it tears the old one down, so each mix keeps its
// own Buffers I/O area and buffer set.
type mix struct {
	io      *mapping
	buffers []*buffer
	seq     uint64 // when the mix last gained an I/O area or a buffer set
}

// active reports whether frames can be read through the mix.
func (m *mix) active() bool { return m.io != nil && len(m.buffers) > 0 }

type peer struct {
	fd  int
	act *mapping
}

// Stream is a running video input stream.
type Stream struct {
	conn  *proto.Conn
	opts  Options
	mem   Mem
	sig   Signal
	ctx   context.Context
	stop  context.CancelFunc
	setup sync.Mutex // held by Open while it sends the first requests

	once     sync.Once
	done     chan struct{} // closed when shutdown has finished
	loopDone chan struct{} // closed when the process loop has returned
	started  chan struct{} // closed when the server sent Start
	startOne sync.Once

	mu         sync.Mutex // guards everything below
	proxy      uint32
	global     uint32
	haveGlobal bool
	closing    bool
	failed     error
	format     *Format
	formatPod  pod.Pod
	serials    paramSerials
	mixes      map[uint32]*mix // per-link state of the input port, by mix id
	mixSeq     uint64          // last value handed out as mix.seq
	multiMix   bool            // the "several active mixes" Debug line was written
	transport  *transportState
	position   *mapping // the driver's Position area from SetIO, read for clock.id
	peers      map[uint32]*peer
	running    bool
	activeSent bool
	loopOn     bool
	badFrames  int
	wakes      uint64 // wake-ups seen, for traceWake
	stats      Stats

	fmu     sync.Mutex // guards the published frame
	frame   *image.RGBA
	seq     uint64
	frameCh chan struct{}
	lastAt  time.Time // when the newest frame was published
}

// Open connects a video input stream on conn and waits until the server has
// started it. It sends Hello, Client.UpdateProperties and a Sync (unless
// SkipHello is set), creates the client-node, sends the node and port
// updates, and then serves the server's events. It returns once the server
// sends Command Start, with the first frame still to come. ctx only bounds
// Open; the stream lives until Close, an error, or the end of the
// connection. The stream does not own conn and never closes it.
func Open(ctx context.Context, conn *proto.Conn, opts Options) (*Stream, error) {
	if opts.Name == "" {
		opts.Name = "homelab-rmm-screen"
	}
	if opts.Mem == nil {
		opts.Mem = platformMem()
	}
	if opts.Signal == nil {
		opts.Signal = platformSignal()
	}
	if opts.Mem == nil || opts.Signal == nil {
		return nil, errors.New("PipeWire shared memory and eventfds are only available on Linux")
	}
	sctx, stop := context.WithCancel(context.Background())
	s := &Stream{
		conn: conn, opts: opts, mem: opts.Mem, sig: opts.Signal,
		ctx: sctx, stop: stop,
		done: make(chan struct{}), loopDone: make(chan struct{}), started: make(chan struct{}),
		peers: map[uint32]*peer{}, mixes: map[uint32]*mix{proto.InvalidID: {}}, frameCh: make(chan struct{}),
	}
	go func() {
		select {
		case <-conn.Done():
			s.fail(conn.Err())
		case <-s.done:
		}
	}()

	if err := s.begin(ctx); err != nil {
		s.fail(err)
	}
	select {
	case <-s.started:
		return s, nil
	case <-s.done:
	case <-ctx.Done():
		s.fail(fmt.Errorf("the PipeWire server did not start the stream: %w", ctx.Err()))
		<-s.done
	}
	err := s.Err()
	if err == nil {
		err = ErrClosed
	}
	return nil, fmt.Errorf("opening the PipeWire video stream failed: %w", err)
}

// begin runs the client's side of the setup sequence in notes 4.2.
func (s *Stream) begin(ctx context.Context) error {
	if !s.opts.SkipHello {
		if err := s.conn.Hello(clientProps(s.opts.Name)); err != nil {
			return err
		}
		if err := s.conn.Sync(ctx); err != nil {
			return err
		}
	}
	s.setup.Lock()
	defer s.setup.Unlock()
	id, err := s.conn.CreateClientNode(nodeProps(s.opts), s.handle)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.proxy = id
	s.mu.Unlock()
	if err := s.conn.Send(id, nodeUpdate(s.opts)); err != nil {
		return err
	}
	pu, err := portUpdate(nil, nil, s.serials)
	if err != nil {
		return err
	}
	return s.conn.Send(id, pu)
}

// Latest returns the newest frame and its sequence number, which starts at 1
// and grows by one per frame. It returns nil and 0 before the first frame.
// The image is never modified after it is returned.
func (s *Stream) Latest() (*image.RGBA, uint64) {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	return s.frame, s.seq
}

// Wait blocks until a frame newer than sequence number after exists and
// returns it. It returns the stream's error when the stream ends, ErrClosed
// after an orderly Close, or ctx.Err().
func (s *Stream) Wait(ctx context.Context, after uint64) (*image.RGBA, uint64, error) {
	for {
		s.fmu.Lock()
		img, seq, ch := s.frame, s.seq, s.frameCh
		s.fmu.Unlock()
		if seq > after {
			return img, seq, nil
		}
		select {
		case <-ch:
		case <-s.done:
			if err := s.Err(); err != nil {
				return nil, 0, err
			}
			return nil, 0, ErrClosed
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		}
	}
}

// Format returns the negotiated format, if one has been chosen.
func (s *Stream) Format() (Format, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.format == nil {
		return Format{}, false
	}
	return *s.format, true
}

// Stats returns the frame counters.
func (s *Stream) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// Done is closed when the stream has ended and released its resources.
func (s *Stream) Done() <-chan struct{} { return s.done }

// Err returns why the stream ended, or nil while it runs or after an orderly
// Close.
func (s *Stream) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failed
}

// Close stops the stream: it marks the activation inactive, sends
// SetActive(false) and Core.Destroy for the node, and unmaps and closes
// everything the stream holds. It is safe to call more than once and after
// an error. The Conn stays open.
func (s *Stream) Close() error {
	s.shutdown()
	<-s.done
	return nil
}

// fail ends the stream with err unless it already ended.
func (s *Stream) fail(err error) {
	s.mu.Lock()
	if s.failed == nil && !s.closing {
		s.failed = err
	}
	s.mu.Unlock()
	go s.shutdown()
}

func (s *Stream) shutdown() {
	s.once.Do(func() {
		s.stop()
		s.mu.Lock()
		s.closing = true
		loopOn := s.loopOn
		s.mu.Unlock()
		if loopOn {
			<-s.loopDone
		}

		s.mu.Lock()
		proxy, activeSent := s.proxy, s.activeSent
		var wake bool
		if t := s.transport; t != nil && t.act != nil {
			// do_node_unprepare: a node that was still waiting for or in a
			// cycle must wake its targets or the driver's cycle stalls.
			old := atomic.SwapUint32(atomicWord(t.act.data, actStatus), actInactive)
			wake = old <= actAwake && !s.opts.Async
		}
		if wake {
			_ = s.triggerPeers()
		}
		s.mu.Unlock()
		select {
		case <-s.conn.Done():
		default:
			if activeSent {
				_ = s.conn.Send(proxy, proto.ClientNodeSetActive{Active: false})
			}
			if proxy != 0 {
				_ = s.conn.Destroy(proxy)
			}
		}

		s.mu.Lock()
		s.releaseAllLocked()
		s.mu.Unlock()
		close(s.done)
	})
}

// releaseAllLocked unmaps every mapping and closes every descriptor the
// stream owns.
func (s *Stream) releaseAllLocked() {
	for id := range s.mixes {
		s.removeMixLocked(id)
	}
	for id := range s.peers {
		s.removePeerLocked(id)
	}
	s.unmap(s.position)
	s.position = nil
	if t := s.transport; t != nil {
		_ = t.waiter.Close()
		s.unmap(t.act)
		_ = s.sig.Close(t.readFd)
		_ = s.sig.Close(t.writeFd)
		s.transport = nil
	}
}

func (s *Stream) removePeerLocked(id uint32) {
	if p := s.peers[id]; p != nil {
		s.unmap(p.act)
		_ = s.sig.Close(p.fd)
		delete(s.peers, id)
	}
}

// handle receives every event of the client-node proxy and the Core events
// addressed to it. A protocol or validation error ends the stream, not the
// connection.
func (s *Stream) handle(ev any) error {
	s.setup.Lock()
	s.setup.Unlock()
	s.mu.Lock()
	if s.closing || s.failed != nil {
		s.mu.Unlock()
		s.discardFds(ev)
		return nil
	}
	err := s.dispatch(ev)
	s.mu.Unlock()
	if err != nil {
		s.fail(err)
	}
	return nil
}

// discardFds closes the descriptors of an event nobody will use.
func (s *Stream) discardFds(ev any) {
	switch e := ev.(type) {
	case proto.ClientNodeTransport:
		s.closeFd(e.ReadFd)
		s.closeFd(e.WriteFd)
	case proto.ClientNodeSetActivation:
		s.closeFd(e.SignalFd)
	}
}

func (s *Stream) closeFd(fd int) {
	if fd >= 0 {
		_ = s.sig.Close(fd)
	}
}

// dispatch runs with s.mu held.
func (s *Stream) dispatch(ev any) error {
	s.trace(ev)
	switch e := ev.(type) {
	case proto.CoreBoundProps:
		s.global, s.haveGlobal = e.GlobalID, true
	case proto.CoreBoundId:
		s.global, s.haveGlobal = e.GlobalID, true
	case proto.CoreRemoveId:
		return errors.New("the PipeWire server removed the stream's node")
	case proto.CoreErrorEvent:
		// The Conn delivers an error on this proxy here and stays up, so
		// other streams on the same connection keep running.
		return &proto.ServerError{ID: e.ID, Seq: e.Seq, Res: e.Res, Message: e.Message}
	case proto.ClientNodeTransport:
		return s.onTransport(e)
	case proto.ClientNodeSetActivation:
		return s.onSetActivation(e)
	case proto.ClientNodeCommand:
		s.onCommand(e)
	case proto.ClientNodeSetIO:
		return s.onSetIO(e)
	case proto.ClientNodeAddPort:
		_ = s.conn.ReportError(s.proxy, errNotSupported, "adding ports is not supported")
	case proto.ClientNodeRemovePort:
		_ = s.conn.ReportError(s.proxy, errNotSupported, "removing ports is not supported")
	case proto.ClientNodePortSetParam:
		return s.onPortSetParam(e)
	case proto.ClientNodePortSetMixInfo:
		s.onSetMixInfo(e)
	case proto.ClientNodePortUseBuffers:
		return s.onUseBuffers(e)
	case proto.ClientNodePortSetIO:
		return s.onPortSetIO(e)
	}
	return nil
}

// onTransport maps the node's activation block, prepares it as do_node_prepare
// does (client_version 1, stale wake-ups drained, status FINISHED), sends
// SetActive(true) and starts the process loop.
func (s *Stream) onTransport(e proto.ClientNodeTransport) error {
	closeBoth := func() { s.closeFd(e.ReadFd); s.closeFd(e.WriteFd) }
	if s.transport != nil {
		closeBoth()
		return errors.New("the server sent a second Transport event")
	}
	if e.ReadFd < 0 || e.WriteFd < 0 {
		closeBoth()
		return errors.New("the server's Transport event came without its two eventfds")
	}
	if e.Size < actSize {
		closeBoth()
		return fmt.Errorf("the activation block is %d bytes, smaller than the %d bytes of struct pw_node_activation", e.Size, actSize)
	}
	m, err := s.mapRegion(e.MemID, e.Offset, e.Size, mapReadMust)
	if err != nil {
		closeBoth()
		return fmt.Errorf("mapping the activation block failed: %w", err)
	}
	if err := checkAtomic("activation", m.data, actStatus, actState0Status, actState0Pending, actClientVersion); err != nil {
		s.unmap(m)
		closeBoth()
		return err
	}
	w, err := s.sig.Watch(e.ReadFd)
	if err != nil {
		s.unmap(m)
		closeBoth()
		return fmt.Errorf("watching the node's wake-up eventfd failed: %w", err)
	}
	atomic.StoreUint32(atomicWord(m.data, actClientVersion), 1)
	_ = w.Drain()
	atomic.StoreUint32(atomicWord(m.data, actStatus), actFinished)
	s.transport = &transportState{readFd: e.ReadFd, writeFd: e.WriteFd, memID: e.MemID, offset: e.Offset, act: m, waiter: w}
	s.publishActiveDriver()

	if err := s.conn.Send(s.proxy, proto.ClientNodeSetActive{Active: true}); err != nil {
		return err
	}
	s.activeSent = true
	s.loopOn = true
	go s.loop(w)
	go s.traceActivation()
	return nil
}

// traceActivation logs, once a second for the first half minute and then once
// a minute, the scheduling state of this node's activation block and of every
// peer's: status, state[0].required and pending, and the three timestamps.
// It is Debug-only and exists because a node that is never woken leaves no
// other trace.
func (s *Stream) traceActivation() {
	if !slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	dump := func(name string, b []byte) []any {
		return []any{
			name, fmt.Sprintf("status=%d result=%d required=%d pending=%d signal=%d awake=%d finish=%d",
				atomic.LoadUint32(atomicWord(b, actStatus)),
				atomic.LoadInt32(atomicInt(b, actState0Status)),
				atomic.LoadInt32(atomicInt(b, actState0Status+4)),
				atomic.LoadInt32(atomicInt(b, actState0Pending)),
				binary.LittleEndian.Uint64(b[actSignalTime:]),
				binary.LittleEndian.Uint64(b[actAwakeTime:]),
				binary.LittleEndian.Uint64(b[actFinishTime:])),
		}
	}
	for i := 0; ; i++ {
		d := time.Second
		if i >= 30 {
			d = time.Minute
		}
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(d):
		}
		s.mu.Lock()
		attrs := []any{"wakes", s.wakes, "frames", s.stats.Frames, "running", s.running}
		if t := s.transport; t != nil {
			attrs = append(attrs, dump("self", t.act.data)...)
		}
		for id, p := range s.peers {
			attrs = append(attrs, dump(fmt.Sprintf("peer_%d", id), p.act.data)...)
		}
		s.mu.Unlock()
		slog.Debug("pipewire: activation", attrs...)
	}
}

// onSetIO handles the node-level I/O areas. Only Position matters: it lives
// inside the driver's activation block, and its clock.id names the driver.
// pw_impl_node_set_io copies that id into the node's own active_driver_id,
// which the driver checks against its own id before it schedules the node.
// Clock and the other areas are not needed to receive frames.
func (s *Stream) onSetIO(e proto.ClientNodeSetIO) error {
	if e.IOID != pod.IOPosition {
		return nil
	}
	s.unmap(s.position)
	s.position = nil
	if e.MemID == proto.InvalidID {
		return nil
	}
	if e.Size < posClockID+4 {
		return fmt.Errorf("the Position I/O area is %d bytes, too small for struct spa_io_position", e.Size)
	}
	m, err := s.mapRegion(e.MemID, e.Offset, e.Size, mapRead)
	if err != nil {
		return fmt.Errorf("mapping the Position I/O area failed: %w", err)
	}
	s.position = m
	s.publishActiveDriver()
	return nil
}

// publishActiveDriver writes the driver's id from the mapped Position area
// into this node's activation, once both are known.
func (s *Stream) publishActiveDriver() {
	if s.position == nil || s.transport == nil {
		return
	}
	id := atomic.LoadUint32(atomicWord(s.position.data, posClockID))
	atomic.StoreUint32(atomicWord(s.transport.act.data, actActiveDriverID), id)
	slog.Debug("pipewire: active driver published", "driver", id)
}

// onSetActivation records a peer's activation block and its eventfd so the
// stream can wake the driver after a frame. The entry for the node itself is
// ignored.
func (s *Stream) onSetActivation(e proto.ClientNodeSetActivation) error {
	if e.MemID == proto.InvalidID {
		s.removePeerLocked(e.NodeID)
		s.closeFd(e.SignalFd)
		return nil
	}
	if t := s.transport; (t != nil && t.memID == e.MemID && t.offset == e.Offset) || (s.haveGlobal && s.global == e.NodeID) {
		s.closeFd(e.SignalFd)
		return nil
	}
	if e.SignalFd < 0 {
		return fmt.Errorf("the server's activation for node %d came without an eventfd", e.NodeID)
	}
	if e.Size < actSize {
		s.closeFd(e.SignalFd)
		return fmt.Errorf("the activation block of node %d is %d bytes, smaller than %d", e.NodeID, e.Size, actSize)
	}
	m, err := s.mapRegion(e.MemID, e.Offset, e.Size, mapReadMust)
	if err != nil {
		s.closeFd(e.SignalFd)
		return fmt.Errorf("mapping the activation block of node %d failed: %w", e.NodeID, err)
	}
	if err := checkAtomic("peer activation", m.data, actStatus, actState0Pending); err != nil {
		s.unmap(m)
		s.closeFd(e.SignalFd)
		return err
	}
	s.removePeerLocked(e.NodeID)
	s.peers[e.NodeID] = &peer{fd: e.SignalFd, act: m}
	return nil
}

// onCommand handles Start, Pause and Suspend. Start also writes NEED_DATA
// into the Buffers area as pw_stream does for a paused input stream.
func (s *Stream) onCommand(e proto.ClientNodeCommand) {
	id, ok := e.NodeCommandID()
	if !ok {
		return
	}
	switch id {
	case pod.NodeCommandStart:
		s.running = true
		for _, m := range s.mixes {
			if m.io != nil {
				atomic.StoreInt32(atomicInt(m.io.data, ioBuffersStatus), statusNeedData)
			}
		}
		s.startOne.Do(func() { close(s.started) })
	case pod.NodeCommandPause, pod.NodeCommandSuspend:
		s.running = false
	}
}

// onPortSetParam handles the Format param. A format the client did not offer
// ends the stream. A valid one clears the buffers and answers with a second
// PortUpdate that carries the Format and Buffers params.
func (s *Stream) onPortSetParam(e proto.ClientNodePortSetParam) error {
	if e.Direction != proto.DirectionInput || e.PortID != 0 || e.ParamID != pod.ParamFormat {
		return nil
	}
	s.releaseBuffers()
	// The server skips a param whose flags did not change, so a new Format or
	// Buffers param flips the SERIAL bit as pw_stream does (stream.c:565-590).
	s.serials.toggle()
	if proto.IsNone(e.Param) {
		s.format, s.formatPod = nil, nil
		pu, err := portUpdate(nil, nil, s.serials)
		if err != nil {
			return err
		}
		return s.conn.Send(s.proxy, pu)
	}
	f, err := parseFormat(e.Param)
	if err != nil {
		return err
	}
	s.format, s.formatPod = &f, e.Param
	pu, err := portUpdate(&f, e.Param, s.serials)
	if err != nil {
		return err
	}
	return s.conn.Send(s.proxy, pu)
}

// mixLocked returns the mix with the given id. One the server never announced
// is created on the fly: the server knows the links, the stream does not
// fail over it.
func (s *Stream) mixLocked(id uint32) *mix {
	m := s.mixes[id]
	if m == nil {
		slog.Debug("pipewire: input port used a mix the server did not announce", "mix", id)
		m = &mix{}
		s.mixes[id] = m
	}
	return m
}

// removeMixLocked unmaps the mix's I/O area and buffers and forgets it.
func (s *Stream) removeMixLocked(id uint32) {
	if m := s.mixes[id]; m != nil {
		s.unmap(m.io)
		m.io = nil
		s.releaseMixBuffers(m)
		delete(s.mixes, id)
	}
}

// onSetMixInfo handles PortSetMixInfo (notes 3.3): a peer id other than
// InvalidID adds or keeps the mix, InvalidID removes it. Other mixes are
// untouched.
func (s *Stream) onSetMixInfo(e proto.ClientNodePortSetMixInfo) {
	if e.Direction != proto.DirectionInput || e.PortID != 0 {
		return
	}
	if e.PeerID == proto.InvalidID {
		s.removeMixLocked(e.MixID)
		return
	}
	if s.mixes[e.MixID] == nil {
		s.mixes[e.MixID] = &mix{}
	}
}

// onUseBuffers replaces the buffer set of the mix the event names. Every
// range is checked against the mapped memory; an unknown memory block ends
// the stream.
func (s *Stream) onUseBuffers(e proto.ClientNodePortUseBuffers) error {
	if e.Direction != proto.DirectionInput || e.PortID != 0 {
		return nil
	}
	if len(e.Buffers) == 0 {
		if m := s.mixes[e.MixID]; m != nil {
			s.releaseMixBuffers(m)
		}
		return nil
	}
	m := s.mixLocked(e.MixID)
	s.releaseMixBuffers(m)
	if s.format == nil {
		return errors.New("the server sent buffers before it chose a format")
	}
	var out []*buffer
	for i, ub := range e.Buffers {
		b, err := s.buildBuffer(i, ub)
		if err != nil {
			for _, p := range out {
				s.releaseBuffer(p)
			}
			return err
		}
		out = append(out, b)
	}
	m.buffers = out
	s.mixSeq++
	m.seq = s.mixSeq
	return nil
}

// onPortSetIO maps the Buffers area of the mix the event names. AsyncBuffers
// was not offered, so a server that picks it ends the stream.
func (s *Stream) onPortSetIO(e proto.ClientNodePortSetIO) error {
	if e.Direction != proto.DirectionInput || e.PortID != 0 {
		return nil
	}
	switch e.IOID {
	case pod.IOBuffers:
		if e.MemID == proto.InvalidID {
			if m := s.mixes[e.MixID]; m != nil {
				s.unmap(m.io)
				m.io = nil
			}
			return nil
		}
		m := s.mixLocked(e.MixID)
		s.unmap(m.io)
		m.io = nil
		if e.Size < ioBuffersSize {
			return fmt.Errorf("the Buffers I/O area is %d bytes, smaller than %d", e.Size, ioBuffersSize)
		}
		mp, err := s.mapRegion(e.MemID, e.Offset, e.Size, mapReadMust)
		if err != nil {
			return fmt.Errorf("mapping the Buffers I/O area failed: %w", err)
		}
		if err := checkAtomic("Buffers I/O", mp.data, ioBuffersStatus, ioBuffersBufferID); err != nil {
			s.unmap(mp)
			return err
		}
		m.io = mp
		s.mixSeq++
		m.seq = s.mixSeq
	case pod.IOAsyncBuffers:
		if e.MemID != proto.InvalidID {
			return errors.New("the server chose AsyncBuffers I/O, which this client did not offer")
		}
	}
	return nil
}

// activeMixLocked returns the mix the process loop reads from: the one with
// both an I/O area and buffers, the most recently completed if several
// qualify. It returns nil when none does.
func (s *Stream) activeMixLocked() *mix {
	var best *mix
	n := 0
	for _, m := range s.mixes {
		if !m.active() {
			continue
		}
		n++
		if best == nil || m.seq > best.seq {
			best = m
		}
	}
	if n > 1 && !s.multiMix {
		s.multiMix = true
		slog.Debug("pipewire: several mixes of the input port are active; reading the newest")
	}
	return best
}

// loop is the process loop: wait for the driver to wake the node, run one
// cycle, repeat.
func (s *Stream) loop(w Waiter) {
	defer close(s.loopDone)
	for {
		if err := w.Wait(s.ctx); err != nil {
			if s.ctx.Err() == nil {
				s.fail(fmt.Errorf("waiting for the node's wake-up eventfd failed: %w", err))
			}
			return
		}
		if err := s.cycle(); err != nil {
			s.fail(err)
			return
		}
	}
}

// cycle is one wake-up as node_on_fd_events and process_node run it (notes
// 4.5): TRIGGERED to AWAKE, read the frame, store the process result, AWAKE to
// FINISHED, and for a synchronous node wake the peers that depend on it.
func (s *Stream) cycle() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.transport
	if t == nil {
		return nil
	}
	act := t.act.data
	s.traceWake(act)
	if !casStatus(act, actTriggered, actAwake) {
		return nil
	}
	putU64(act, actAwakeTime, uint64(s.sig.Now()))

	var ferr error
	if s.running {
		if m := s.activeMixLocked(); m != nil {
			ferr = s.readFrame(m)
		}
	}
	atomic.StoreInt32(atomicInt(act, actState0Status), statusNeedData|statusHaveData)
	wasAwake := casStatus(act, actAwake, actFinished)
	putU64(act, actFinishTime, uint64(s.sig.Now()))
	if ferr != nil {
		return ferr
	}
	// process_node only triggers the targets when it moved the node from
	// AWAKE to FINISHED itself.
	if wasAwake && !s.opts.Async {
		return s.triggerPeers()
	}
	return nil
}

// readFrame takes the buffer the producer marked HAVE_DATA, publishes a copy
// as the newest frame and hands the buffer back by writing NEED_DATA. The
// copy happens first because the producer may reuse the buffer right after.
func (s *Stream) readFrame(m *mix) error {
	io := m.io.data
	if atomic.LoadInt32(atomicInt(io, ioBuffersStatus))&statusHaveData == 0 {
		return nil
	}
	id := atomic.LoadUint32(atomicWord(io, ioBuffersBufferID))
	var b *buffer
	if int64(id) < int64(len(m.buffers)) {
		b = m.buffers[id]
	}
	var img *image.RGBA
	var err error
	if b == nil || s.format == nil {
		err = fmt.Errorf("the producer returned buffer %d but %d buffers are set", id, len(m.buffers))
	} else {
		b.busyAdd(1)
		img, err = decodeFrame(b.pix, readChunk(b.chunk), s.format.Width, s.format.Height, s.format.PixelFormat, b.crop())
		b.busyAdd(-1)
	}
	atomic.StoreInt32(atomicInt(io, ioBuffersStatus), statusNeedData)

	var skip skipFrame
	switch {
	case err == nil:
		s.badFrames = 0
		s.stats.Frames++
		s.publish(img)
		return nil
	case errors.As(err, &skip):
		s.stats.Skipped++
		return nil
	}
	s.stats.Dropped++
	s.stats.LastDrop = err.Error()
	s.badFrames++
	if s.badFrames >= maxBadFrames {
		return fmt.Errorf("the last %d frames were invalid, the latest because: %w", s.badFrames, err)
	}
	return nil
}

func (s *Stream) publish(img *image.RGBA) {
	s.fmu.Lock()
	s.frame = img
	s.lastAt = time.Now()
	s.seq++
	close(s.frameCh)
	s.frameCh = make(chan struct{})
	s.fmu.Unlock()
}

// triggerPeers wakes the peers that wait for this node, as trigger_target_v1
// does: decrement the peer's pending counter, and when it reaches zero move
// its status from NOT_TRIGGERED to TRIGGERED, stamp signal_time and write 1
// to its eventfd.
func (s *Stream) triggerPeers() error {
	ids := make([]uint32, 0, len(s.peers))
	for id := range s.peers {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		p := s.peers[id]
		if atomic.AddInt32(atomicInt(p.act.data, actState0Pending), -1) != 0 {
			continue
		}
		if !casStatus(p.act.data, actNotTriggered, actTriggered) {
			continue
		}
		putU64(p.act.data, actSignalTime, uint64(s.sig.Now()))
		if err := s.sig.Notify(p.fd); err != nil {
			return fmt.Errorf("waking node %d failed: %w", id, err)
		}
	}
	return nil
}

// LastFrame returns when the newest frame was published, or the zero time
// before the first frame.
func (s *Stream) LastFrame() time.Time {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	return s.lastAt
}

// Running reports whether the server has started the stream and not paused or
// suspended it since. A running stream that stays silent for long is either
// an idle screen or a compositor that stopped sending.
func (s *Stream) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// trace logs every server event at Debug level: the first run against a real
// compositor showed that nothing else tells an operator which step of the
// negotiation the server took. Fields are kept short on purpose.
func (s *Stream) trace(ev any) {
	if !slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	switch e := ev.(type) {
	case proto.ClientNodeTransport:
		slog.Debug("pipewire: event Transport", "mem", e.MemID, "offset", e.Offset, "size", e.Size, "read_fd", e.ReadFd, "write_fd", e.WriteFd)
	case proto.ClientNodeSetActivation:
		slog.Debug("pipewire: event SetActivation", "node", e.NodeID, "mem", e.MemID, "signal_fd", e.SignalFd)
	case proto.ClientNodeCommand:
		id, ok := e.NodeCommandID()
		slog.Debug("pipewire: event Command", "id", id, "known", ok)
	case proto.ClientNodePortSetParam:
		slog.Debug("pipewire: event PortSetParam", "dir", e.Direction, "port", e.PortID, "param", e.ParamID, "none", proto.IsNone(e.Param))
	case proto.ClientNodePortSetMixInfo:
		slog.Debug("pipewire: event PortSetMixInfo", "dir", e.Direction, "port", e.PortID, "mix", e.MixID, "peer", e.PeerID)
	case proto.ClientNodePortUseBuffers:
		slog.Debug("pipewire: event PortUseBuffers", "dir", e.Direction, "port", e.PortID, "mix", e.MixID, "n", len(e.Buffers))
	case proto.ClientNodePortSetIO:
		slog.Debug("pipewire: event PortSetIO", "dir", e.Direction, "port", e.PortID, "mix", e.MixID, "io", e.IOID, "mem", e.MemID, "size", e.Size)
	case proto.ClientNodeSetIO:
		slog.Debug("pipewire: event SetIO", "io", e.IOID, "mem", e.MemID, "offset", e.Offset, "size", e.Size)
	default:
		slog.Debug("pipewire: event", "type", fmt.Sprintf("%T", ev))
	}
}

// traceWake logs the first wake-ups and then one in every 300, with the
// activation status seen before the TRIGGERED to AWAKE swap and the state of
// every mix, so a stream that wakes but never reads a frame explains itself.
func (s *Stream) traceWake(act []byte) {
	s.wakes++
	if s.wakes > 20 && s.wakes%300 != 0 {
		return
	}
	if !slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	attrs := []any{"wake", s.wakes, "status", atomic.LoadUint32(atomicWord(act, actStatus)), "running", s.running, "format", s.format != nil, "mixes", len(s.mixes), "peers", len(s.peers)}
	for id, m := range s.mixes {
		attrs = append(attrs, fmt.Sprintf("mix_%d", id), fmt.Sprintf("io=%v buffers=%d", m.io != nil, len(m.buffers)))
		if m.io != nil {
			attrs = append(attrs, fmt.Sprintf("mix_%d_io", id), fmt.Sprintf("status=%d buffer_id=%d", atomic.LoadInt32(atomicInt(m.io.data, ioBuffersStatus)), atomic.LoadUint32(atomicWord(m.io.data, ioBuffersBufferID))))
		}
	}
	slog.Debug("pipewire: wake-up", attrs...)
}
