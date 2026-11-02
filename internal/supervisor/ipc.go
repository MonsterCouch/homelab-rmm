package supervisor

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MessageType defines local IPC message action categories.
type MessageType string

const (
	// MsgHeartbeat is periodically emitted by the worker (default: 5s) to indicate
	// active liveness and report current process memory RSS.
	MsgHeartbeat MessageType = "heartbeat"

	// MsgNotifyHealthy is emitted by the worker once it has successfully established
	// its TLS connection and WebSocket authenticated session with the RMM server.
	MsgNotifyHealthy MessageType = "notify_healthy"

	// MsgRequestRestart is emitted by the worker after staging an update
	// in the inactive slot, requesting the supervisor perform the slot flip and process restart.
	MsgRequestRestart MessageType = "request_restart"

	// MsgGetInactive is sent by the worker to query the supervisor for the inactive
	// slot identifier and target filesystem path where a pending update should be staged.
	MsgGetInactive MessageType = "get_inactive_slot"

	// MsgInactiveResp is sent by the supervisor in response to MsgGetInactive.
	MsgInactiveResp MessageType = "inactive_slot_resp"
)

// IPCMessage defines the wire format for Supervisor <-> Worker communication.
type IPCMessage struct {
	Type         MessageType `json:"type"`
	PID          int         `json:"pid,omitempty"`
	RSSBytes     uint64      `json:"rss_bytes,omitempty"`
	Version      string      `json:"version,omitempty"`
	Reason       string      `json:"reason,omitempty"`
	Slot         string      `json:"slot,omitempty"`
	Path         string      `json:"path,omitempty"`
	ActiveSlot   string      `json:"active_slot,omitempty"`
	InactiveSlot string      `json:"inactive_slot,omitempty"`
}

// MaxMessageSize is the maximum size in bytes of a single JSON line to prevent DoS.
const MaxMessageSize = 1024 * 1024 // 1 MB

// HandlerFunc handles an incoming IPCMessage.
// Returns (resp, nil) to send a response message back to client.
// Returns (nil, nil) for one-way messages (no response).
// Returns (nil, err) to log error and omit response.
type HandlerFunc func(msg *IPCMessage) (*IPCMessage, error)

// IPCServer manages local IPC connections, message deserialization, and handler dispatch.
type IPCServer struct {
	listener net.Listener
	cleanup  func()

	handlers map[MessageType]HandlerFunc
	mu       sync.RWMutex

	conns   map[net.Conn]struct{}
	connsMu sync.Mutex
	wg      sync.WaitGroup

	stopCh  chan struct{}
	started atomic.Bool
	stopped atomic.Bool
}

// NewIPCServer creates an IPCServer with an optional cleanup callback.
func NewIPCServer(cleanup ...func()) *IPCServer {
	var cl func()
	if len(cleanup) > 0 {
		cl = cleanup[0]
	}
	return &IPCServer{
		cleanup:  cl,
		handlers: make(map[MessageType]HandlerFunc),
		conns:    make(map[net.Conn]struct{}),
		stopCh:   make(chan struct{}),
	}
}

// RegisterHandler registers a handler function for a given MessageType.
// Handler registration is thread-safe and can be done before or after Start.
func (s *IPCServer) RegisterHandler(msgType MessageType, handler HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[msgType] = handler
}

// Start begins accepting connections on the provided listener.
// If a listener was already provided or is passed here, it launches the accept loop.
func (s *IPCServer) Start(listeners ...net.Listener) error {
	if s.started.Swap(true) {
		return errors.New("ipc server already started")
	}
	if len(listeners) > 0 && listeners[0] != nil {
		s.listener = listeners[0]
	}
	if s.listener == nil {
		s.started.Store(false)
		return errors.New("listener cannot be nil")
	}

	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

// Addr returns the network address of the server's listener, if listening.
func (s *IPCServer) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

func (s *IPCServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				if s.stopped.Load() {
					return
				}
				slog.Debug("ipc server accept error", "err", err)
				return
			}
		}

		s.trackConn(conn)
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer s.untrackConn(c)
			defer c.Close()
			s.serveConn(c)
		}(conn)
	}
}

func (s *IPCServer) trackConn(c net.Conn) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	if !s.stopped.Load() {
		s.conns[c] = struct{}{}
	}
}

func (s *IPCServer) untrackConn(c net.Conn) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	delete(s.conns, c)
}

func (s *IPCServer) serveConn(conn net.Conn) {
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) && !s.stopped.Load() {
				slog.Debug("ipc connection read error", "err", err)
			}
			return
		}

		if len(line) > MaxMessageSize {
			slog.Warn("ipc message exceeds max size, terminating connection", "len", len(line))
			return
		}

		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}

		var msg IPCMessage
		if err := json.Unmarshal(trimmed, &msg); err != nil {
			slog.Warn("ipc received malformed json, skipping frame", "err", err, "raw", string(trimmed))
			continue
		}

		s.mu.RLock()
		handler, exists := s.handlers[msg.Type]
		s.mu.RUnlock()

		if !exists || handler == nil {
			slog.Debug("ipc no handler registered for message type", "type", msg.Type)
			continue
		}

		resp := func() *IPCMessage {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("panic recovered in ipc handler", "type", msg.Type, "recover", r)
				}
			}()
			r, err := handler(&msg)
			if err != nil {
				slog.Error("ipc handler returned error", "type", msg.Type, "err", err)
				return nil
			}
			return r
		}()

		if resp != nil {
			data, err := json.Marshal(resp)
			if err != nil {
				slog.Error("failed to marshal ipc response", "err", err)
				continue
			}
			data = append(data, '\n')
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write(data); err != nil {
				slog.Debug("failed to write ipc response", "err", err)
				return
			}
		}
	}
}

// Stop gracefully shuts down the IPC server, closes all active connections,
// waits for active goroutines to finish, and invokes cleanup.
func (s *IPCServer) Stop() error {
	if s.stopped.Swap(true) {
		return nil
	}

	close(s.stopCh)

	var err error
	if s.listener != nil {
		err = s.listener.Close()
	}

	s.connsMu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.conns = make(map[net.Conn]struct{})
	s.connsMu.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		slog.Warn("ipc server stop timed out waiting for handlers")
	}

	if s.cleanup != nil {
		s.cleanup()
	}

	return err
}

// IPCClient provides a thread-safe client for communicating with IPCServer over net.Conn.
type IPCClient struct {
	dialer  func() (net.Conn, error)
	timeout time.Duration
	mu      sync.Mutex
	conn    net.Conn
	reader  *bufio.Reader
	closed  bool
}

// NewIPCClient creates an IPCClient.
// dialer is an optional function to dial or reconnect; if nil, caller must call Connect(conn).
// timeout defaults to 5 seconds if non-positive.
func NewIPCClient(dialer func() (net.Conn, error), timeout time.Duration) *IPCClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &IPCClient{
		dialer:  dialer,
		timeout: timeout,
	}
}

// Connect sets or replaces the active network connection on the client.
func (c *IPCClient) Connect(conn net.Conn) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn = conn
	if conn != nil {
		c.reader = bufio.NewReader(conn)
	} else {
		c.reader = nil
	}
	c.closed = false
	return nil
}

// SetDialer configures the dialer function for establishing or reconnecting the transport.
func (c *IPCClient) SetDialer(dialer func() (net.Conn, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dialer = dialer
}

func (c *IPCClient) connectLocked() error {
	if c.closed {
		return errors.New("ipc client is closed")
	}
	if c.conn != nil {
		return nil
	}
	if c.dialer == nil {
		return errors.New("ipc client not connected and no dialer provided")
	}
	conn, err := c.dialer()
	if err != nil {
		return fmt.Errorf("dial ipc: %w", err)
	}
	c.conn = conn
	c.reader = bufio.NewReader(conn)
	return nil
}

// Close closes the underlying client connection.
func (c *IPCClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.reader = nil
		return err
	}
	return nil
}

// Send transmits a one-way message (such as a heartbeat or health notification) without awaiting a response.
// If disconnected and a dialer is configured, it automatically establishes a connection.
func (c *IPCClient) Send(msg *IPCMessage) error {
	if msg == nil {
		return errors.New("msg cannot be nil")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.connectLocked(); err != nil {
		return err
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal ipc message: %w", err)
	}
	data = append(data, '\n')

	_ = c.conn.SetWriteDeadline(time.Now().Add(c.timeout))
	_, err = c.conn.Write(data)
	if err != nil {
		_ = c.conn.Close()
		c.conn = nil
		c.reader = nil
		return fmt.Errorf("write ipc message: %w", err)
	}
	return nil
}

// RoundTrip sends a request message and waits for the correlated response message from the server.
// The client mutex is held during the entire request-response cycle to prevent concurrent interleaving.
func (c *IPCClient) RoundTrip(req *IPCMessage) (*IPCMessage, error) {
	if req == nil {
		return nil, errors.New("req cannot be nil")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.connectLocked(); err != nil {
		return nil, err
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal ipc request: %w", err)
	}
	data = append(data, '\n')

	deadline := time.Now().Add(c.timeout)
	_ = c.conn.SetDeadline(deadline)

	if _, err := c.conn.Write(data); err != nil {
		_ = c.conn.Close()
		c.conn = nil
		c.reader = nil
		return nil, fmt.Errorf("write ipc request: %w", err)
	}

	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		_ = c.conn.Close()
		c.conn = nil
		c.reader = nil
		return nil, fmt.Errorf("read ipc response: %w", err)
	}

	trimmed := bytes.TrimSpace(line)
	var resp IPCMessage
	if err := json.Unmarshal(trimmed, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal ipc response: %w (raw: %s)", err, string(trimmed))
	}

	return &resp, nil
}

// InMemoryPipe provides an in-memory transport implementing net.Listener.
// It allows transport-independent testing of IPCServer and IPCClient without OS handles or elevated privileges.
type InMemoryPipe struct {
	conns   chan net.Conn
	closeCh chan struct{}
	closed  atomic.Bool
}

var _ net.Listener = (*InMemoryPipe)(nil)

// NewInMemoryPipe creates a new in-memory transport helper.
// The returned *InMemoryPipe implements net.Listener and provides a Dial() method.
func NewInMemoryPipe() *InMemoryPipe {
	return &InMemoryPipe{
		conns:   make(chan net.Conn, 64),
		closeCh: make(chan struct{}),
	}
}

// Accept returns the next simulated client connection.
func (p *InMemoryPipe) Accept() (net.Conn, error) {
	select {
	case c, ok := <-p.conns:
		if !ok {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-p.closeCh:
		return nil, net.ErrClosed
	}
}

// Close closes the in-memory listener and unblocks pending Accept/Dial calls.
func (p *InMemoryPipe) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		close(p.closeCh)
		p.drain()
	}
	return nil
}

func (p *InMemoryPipe) drain() {
	for {
		select {
		case c := <-p.conns:
			_ = c.Close()
		default:
			return
		}
	}
}

// Addr returns the simulated in-memory address.
func (p *InMemoryPipe) Addr() net.Addr {
	return inMemAddr("in-memory-pipe")
}

// Dial creates a paired client-server connection, queueing the server end into Accept().
func (p *InMemoryPipe) Dial() (net.Conn, error) {
	if p.closed.Load() {
		return nil, net.ErrClosed
	}
	clientConn, serverConn := net.Pipe()
	select {
	case p.conns <- serverConn:
		return clientConn, nil
	case <-p.closeCh:
		_ = clientConn.Close()
		_ = serverConn.Close()
		return nil, net.ErrClosed
	}
}

type inMemAddr string

func (a inMemAddr) Network() string { return "inmem" }
func (a inMemAddr) String() string  { return string(a) }
