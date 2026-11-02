package proto

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/pod"
)

// Kind says how a proxy's events are decoded.
type Kind int

const (
	// KindClientNode proxies receive the ClientNode events.
	KindClientNode Kind = iota + 1
)

// Handler receives the decoded events of one proxy: the ClientNode* event
// structs, CoreBoundId and CoreBoundProps for its own id, CoreRemoveId when
// the server removes it, and CoreErrorEvent when the server reports an error
// on it (the handler decides whether that ends its own work; the connection
// stays up). It runs on the read loop, one event at a time,
// so it must not wait for a reply from this Conn (for example by calling
// Sync). An error it returns ends the connection. File descriptors inside an
// event belong to the handler.
type Handler func(ev any) error

// MemBlock is a memory block announced by Core.AddMem. The Conn owns Fd and
// closes it on RemoveMem or when the connection ends.
type MemBlock struct {
	ID    uint32
	Type  uint32
	Fd    int
	Flags uint32
}

// Config tunes a Conn. Every field is optional.
type Config struct {
	// CloseFd closes a file descriptor the Conn owns. With a nil CloseFd the
	// descriptors are left alone, which is right for the in-memory transport.
	CloseFd func(fd int)
	// OnCore sees every Core event after the Conn handled it: CoreInfo,
	// CoreDone, CorePing, CoreRemoveId, CoreBoundId, CoreBoundProps,
	// CoreAddMem and CoreRemoveMem. It runs on the read loop.
	OnCore func(ev any) error
	// OnClient sees the Client events (ClientInfo, ClientPermissions).
	OnClient func(ev any) error
	// OnSkip, when set, is told about each message the Conn dropped because
	// it did not decode or did not match its header. PipeWire's own client
	// logs such a message and keeps reading, and so does the Conn.
	OnSkip func(h Header, err error)
}

type proxyEntry struct {
	kind Kind
	h    Handler
}

// Conn is a client connection to a PipeWire server. NewConn starts a read
// loop; the connection ends on the first error, on Close, or when the
// transport reaches end of input.
type Conn struct {
	t   Transport
	cfg Config

	sendMu  sync.Mutex
	sendSeq uint32

	mu         sync.Mutex
	proxies    map[uint32]*proxyEntry
	usedIDs    map[uint32]bool
	pending    map[uint32]chan struct{}
	mems       map[uint32]MemBlock
	bound      map[uint32]uint32
	coreInfo   *CoreInfo
	clientInfo *ClientInfo
	generation int64
	recvSeq    uint32
	err        error

	done     chan struct{}
	loopDone chan struct{}
	failOnce sync.Once
}

// NewConn starts a connection over t. It takes ownership of t. Nothing is
// sent until the caller calls Hello.
func NewConn(t Transport, cfg Config) *Conn {
	c := &Conn{
		t:        t,
		cfg:      cfg,
		proxies:  map[uint32]*proxyEntry{},
		usedIDs:  map[uint32]bool{IDCore: true, IDClient: true},
		pending:  map[uint32]chan struct{}{},
		mems:     map[uint32]MemBlock{},
		bound:    map[uint32]uint32{},
		done:     make(chan struct{}),
		loopDone: make(chan struct{}),
	}
	go c.readLoop()
	return c
}

// Done is closed when the connection has ended. Err then says why.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err returns the reason the connection ended, or nil while it is open. After
// Close it is ErrClosed.
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Close ends the connection, closes the transport and every memory block and
// waits for the read loop to stop.
func (c *Conn) Close() error {
	c.fail(ErrClosed)
	<-c.loopDone
	return nil
}

func (c *Conn) fail(err error) {
	c.failOnce.Do(func() {
		c.mu.Lock()
		c.err = err
		mems := c.mems
		c.mems = map[uint32]MemBlock{}
		c.mu.Unlock()
		close(c.done)
		_ = c.t.Close()
		for _, m := range mems {
			c.closeFd(m.Fd)
		}
	})
}

func (c *Conn) closeFd(fd int) {
	if fd >= 0 && c.cfg.CloseFd != nil {
		c.cfg.CloseFd(fd)
	}
}

// sendWith assigns the next sequence number, builds the message with it and
// sends it. The sequence number starts at 0 and wraps at 30 bits.
func (c *Conn) sendWith(id uint32, build func(seq uint32) Message) error {
	select {
	case <-c.done:
		return c.Err()
	default:
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	seq := c.sendSeq
	h, payload, fds, err := BuildMessage(id, seq, build(seq))
	if err != nil {
		return err
	}
	c.sendSeq = (seq + 1) & SeqMask
	if err := c.t.Send(h, payload, fds); err != nil {
		c.fail(fmt.Errorf("sending to the PipeWire server failed: %w", err))
		return c.Err()
	}
	return nil
}

// Send sends m to the object id. File descriptors in m stay owned by the caller.
func (c *Conn) Send(id uint32, m Message) error {
	return c.sendWith(id, func(uint32) Message { return m })
}

// Hello starts the session as the native protocol does: Core.Hello with the
// Core version, then Client.UpdateProperties with props. Neither waits for a
// reply.
func (c *Conn) Hello(props Dict) error {
	if err := c.Send(IDCore, CoreHello{Version: VersionCore}); err != nil {
		return err
	}
	return c.Send(IDClient, ClientUpdateProperties{Props: props})
}

// Sync sends Core.Sync and waits until the matching Core.Done arrives, which
// tells the caller the server has handled everything sent before it.
func (c *Conn) Sync(ctx context.Context) error {
	var key uint32
	wait := make(chan struct{})
	err := c.sendWith(IDCore, func(seq uint32) Message {
		key = AsyncBit | seq
		c.mu.Lock()
		c.pending[key] = wait
		c.mu.Unlock()
		return CoreSync{ID: int32(IDCore), Seq: int32(key)}
	})
	if err != nil {
		return err
	}
	select {
	case <-wait:
		return nil
	case <-c.done:
		return c.Err()
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, key)
		c.mu.Unlock()
		return ctx.Err()
	}
}

// AllocID returns the lowest unused proxy id from 2 up. Ids 0 (core) and 1
// (client) are always taken. The id is free again after the server's RemoveId.
func (c *Conn) AllocID() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.allocLocked()
}

func (c *Conn) allocLocked() uint32 {
	for id := uint32(2); ; id++ {
		if !c.usedIDs[id] {
			c.usedIDs[id] = true
			return id
		}
	}
}

// Register attaches a handler to a proxy id so its events are decoded and
// delivered. Events for an id with no handler are dropped.
func (c *Conn) Register(id uint32, kind Kind, h Handler) {
	c.mu.Lock()
	c.usedIDs[id] = true
	c.proxies[id] = &proxyEntry{kind: kind, h: h}
	c.mu.Unlock()
}

// CreateObject allocates a proxy id, registers h for it and sends
// Core.CreateObject. The server answers with BoundProps (or BoundId) for the
// new id, or with Error and RemoveId.
func (c *Conn) CreateObject(factory, typ string, version uint32, props Dict, kind Kind, h Handler) (uint32, error) {
	id := c.AllocID()
	c.Register(id, kind, h)
	err := c.Send(IDCore, CoreCreateObject{FactoryName: factory, Type: typ, Version: version, Props: props, NewID: id})
	if err != nil {
		c.release(id)
		return 0, err
	}
	return id, nil
}

// CreateClientNode creates a ClientNode proxy with the factory name and
// version PipeWire's own node export uses.
func (c *Conn) CreateClientNode(props Dict, h Handler) (uint32, error) {
	return c.CreateObject("client-node", InterfaceClientNode, VersionClientNode, props, KindClientNode, h)
}

// Destroy asks the server to destroy a proxy. The id is reusable after the
// server answers with RemoveId.
func (c *Conn) Destroy(id uint32) error {
	return c.Send(IDCore, CoreDestroy{ID: id})
}

// ReportError sends Core.Error for a proxy, with the sequence number of the
// last message received, as pw_proxy_error does. res is a negative errno.
func (c *Conn) ReportError(id uint32, res int32, message string) error {
	c.mu.Lock()
	seq := c.recvSeq
	c.mu.Unlock()
	return c.Send(IDCore, CoreError{ID: int32(id), Seq: int32(seq), Res: res, Message: message})
}

func (c *Conn) release(id uint32) {
	if id < 2 {
		return
	}
	c.mu.Lock()
	delete(c.proxies, id)
	delete(c.usedIDs, id)
	delete(c.bound, id)
	c.mu.Unlock()
}

// Mem returns the memory block the server announced with this id.
func (c *Conn) Mem(id uint32) (MemBlock, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m, ok := c.mems[id]
	return m, ok
}

// GlobalID returns the global id the server bound to a proxy id.
func (c *Conn) GlobalID(id uint32) (uint32, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	g, ok := c.bound[id]
	return g, ok
}

// CoreInfo returns the last Core.Info the server sent.
func (c *Conn) CoreInfo() (CoreInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.coreInfo == nil {
		return CoreInfo{}, false
	}
	return *c.coreInfo, true
}

// ClientInfo returns the last Client.Info the server sent.
func (c *Conn) ClientInfo() (ClientInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.clientInfo == nil {
		return ClientInfo{}, false
	}
	return *c.clientInfo, true
}

// Generation returns the registry generation from the last message footer
// that carried one.
func (c *Conn) Generation() (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.generation, c.generation != 0
}

func (c *Conn) readLoop() {
	defer close(c.loopDone)
	for {
		h, payload, fds, err := c.t.Recv()
		if err != nil {
			c.closeAll(fds)
			c.fail(describeRecvError(err))
			return
		}
		if err := c.dispatch(h, payload, fds); err != nil {
			c.fail(err)
			return
		}
	}
}

func describeRecvError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("the PipeWire server closed the connection: %w", err)
	}
	if errors.Is(err, ErrClosed) {
		return ErrClosed
	}
	return fmt.Errorf("reading from the PipeWire server failed: %w", err)
}

func (c *Conn) closeAll(fds []int) {
	for _, fd := range fds {
		c.closeFd(fd)
	}
}

// dispatch decodes one message and routes it. It returns an error only when
// the connection must end.
func (c *Conn) dispatch(h Header, payload []byte, fds []int) error {
	if int(h.NFds) != len(fds) {
		c.closeAll(fds)
		c.skip(h, fmt.Errorf("a PipeWire message for object %d announced %d file descriptors but carried %d", h.ID, h.NFds, len(fds)))
		return nil
	}
	st, footer, err := SplitPayload(payload)
	if err != nil {
		c.closeAll(fds)
		c.skip(h, fmt.Errorf("the PipeWire server sent a malformed message for object %d (opcode %d): %w", h.ID, h.Opcode, err))
		return nil
	}
	c.mu.Lock()
	c.recvSeq = h.Seq
	if footer.HasGeneration {
		c.generation = footer.Generation
	}
	c.mu.Unlock()

	fl := NewFdList(fds)
	var derr error
	switch h.ID {
	case IDCore:
		var ev any
		ev, derr = DecodeCoreEvent(h.Opcode, st, fl)
		if derr == nil {
			derr = c.handleCore(ev)
		}
	case IDClient:
		var ev any
		ev, derr = DecodeClientEvent(h.Opcode, st, fl)
		if derr == nil {
			derr = c.handleClient(ev)
		}
	default:
		derr = c.handleProxy(h, st, fl)
	}
	var de *decodeError
	if errors.As(derr, &de) {
		// A message that does not decode is dropped, as the C client does
		// (protocol-native.c sets res = 0 after "invalid message received"),
		// so one bad message for one stream cannot end the shared connection.
		c.closeAll(fds)
		c.skip(h, derr)
		return nil
	} else {
		c.closeAll(fl.Unused())
	}
	if derr != nil && IsUnknownOpcode(derr) {
		return nil
	}
	if derr != nil {
		var se *ServerError
		if errors.As(derr, &se) {
			return derr
		}
		return fmt.Errorf("handling a PipeWire message for object %d (opcode %d) failed: %w", h.ID, h.Opcode, derr)
	}
	return nil
}

func (c *Conn) skip(h Header, err error) {
	if c.cfg.OnSkip != nil {
		c.cfg.OnSkip(h, err)
	}
}

// errPipe is -EPIPE, the result PipeWire's client treats as a lost server.
const errPipe = -32

func (c *Conn) handleCore(ev any) error {
	switch e := ev.(type) {
	case CoreInfo:
		c.mu.Lock()
		c.coreInfo = &e
		c.mu.Unlock()
	case CoreDone:
		if uint32(e.ID) != InvalidID {
			c.mu.Lock()
			ch, ok := c.pending[uint32(e.Seq)]
			delete(c.pending, uint32(e.Seq))
			c.mu.Unlock()
			if ok {
				close(ch)
			}
		}
	case CorePing:
		if err := c.Send(IDCore, CorePong{ID: e.ID, Seq: e.Seq}); err != nil {
			return err
		}
	case CoreErrorEvent:
		// core_event_error looks the proxy up by id and reports the error
		// on that proxy only. Only -EPIPE on the core itself means the
		// connection is gone.
		if e.ID == int32(IDCore) && e.Res == errPipe {
			return &ServerError{ID: e.ID, Seq: e.Seq, Res: e.Res, Message: e.Message}
		}
		if e.ID >= 0 {
			c.mu.Lock()
			p := c.proxies[uint32(e.ID)]
			c.mu.Unlock()
			if p != nil && p.h != nil {
				if err := p.h(e); err != nil {
					return err
				}
			}
		}
	case CoreRemoveId:
		c.mu.Lock()
		p := c.proxies[e.ID]
		c.mu.Unlock()
		if p != nil && p.h != nil {
			if err := p.h(e); err != nil {
				return err
			}
		}
		c.release(e.ID)
	case CoreBoundId:
		if err := c.bindProxy(e.ID, e.GlobalID, e); err != nil {
			return err
		}
	case CoreBoundProps:
		if err := c.bindProxy(e.ID, e.GlobalID, e); err != nil {
			return err
		}
	case CoreAddMem:
		c.mu.Lock()
		old, had := c.mems[e.ID]
		c.mems[e.ID] = MemBlock{ID: e.ID, Type: e.Type, Fd: e.Fd, Flags: e.Flags}
		c.mu.Unlock()
		if had && old.Fd != e.Fd {
			c.closeFd(old.Fd)
		}
	case CoreRemoveMem:
		c.mu.Lock()
		old, had := c.mems[e.ID]
		delete(c.mems, e.ID)
		c.mu.Unlock()
		if had {
			c.closeFd(old.Fd)
		}
	}
	if c.cfg.OnCore != nil {
		return c.cfg.OnCore(ev)
	}
	return nil
}

func (c *Conn) bindProxy(id, global uint32, ev any) error {
	c.mu.Lock()
	c.bound[id] = global
	p := c.proxies[id]
	c.mu.Unlock()
	if p != nil && p.h != nil {
		return p.h(ev)
	}
	return nil
}

func (c *Conn) handleClient(ev any) error {
	if e, ok := ev.(ClientInfo); ok {
		c.mu.Lock()
		c.clientInfo = &e
		c.mu.Unlock()
	}
	if c.cfg.OnClient != nil {
		return c.cfg.OnClient(ev)
	}
	return nil
}

func (c *Conn) handleProxy(h Header, st pod.Struct, fl *FdList) error {
	c.mu.Lock()
	p := c.proxies[h.ID]
	c.mu.Unlock()
	if p == nil || p.h == nil {
		return nil
	}
	var ev any
	var err error
	switch p.kind {
	case KindClientNode:
		ev, err = DecodeClientNodeEvent(h.Opcode, st, fl)
	default:
		return nil
	}
	if err != nil {
		return err
	}
	return p.h(ev)
}
