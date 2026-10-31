package proto

import (
	"errors"
	"fmt"
	"io"
	"sync"
)

// Transport moves whole messages. The header's Size and NFds always match
// len(payload) and len(fds). On Send the file descriptors stay owned by the
// caller; on Recv they belong to the receiver.
type Transport interface {
	Send(hdr Header, payload []byte, fds []int) error
	Recv() (hdr Header, payload []byte, fds []int, err error)
	Close() error
}

// ErrClosed is returned by a Transport or Conn that was closed locally.
var ErrClosed = errors.New("the PipeWire connection was closed")

// Reader turns a byte stream plus a queue of file descriptors into messages.
// Bytes and descriptors may arrive in any split: a descriptor can come with an
// earlier or later read than the bytes of its message, and one read can hold
// several messages. Feed adds what a read returned; Next returns a message
// once all of its bytes and descriptors are present.
type Reader struct {
	buf []byte
	fds []int
}

// Feed appends bytes and descriptors from one read. It fails when the queue
// would hold more than MaxFds descriptors; the caller should close the
// descriptors it passed in that case.
func (r *Reader) Feed(data []byte, fds []int) error {
	if len(r.fds)+len(fds) > MaxFds {
		return fmt.Errorf("the PipeWire server queued more than %d file descriptors", MaxFds)
	}
	r.buf = append(r.buf, data...)
	r.fds = append(r.fds, fds...)
	return nil
}

// Next returns the next complete message. ok is false when more input is
// needed. The payload and fds are copies the caller owns.
func (r *Reader) Next() (h Header, payload []byte, fds []int, ok bool, err error) {
	if len(r.buf) < HeaderSize {
		return Header{}, nil, nil, false, nil
	}
	h, _ = UnpackHeader(r.buf)
	if h.NFds > MaxFds {
		return Header{}, nil, nil, false, fmt.Errorf("a message claims %d file descriptors, over the limit of %d", h.NFds, MaxFds)
	}
	if h.Size%8 != 0 {
		return Header{}, nil, nil, false, fmt.Errorf("a message payload of %d bytes is not a multiple of 8", h.Size)
	}
	total := HeaderSize + int(h.Size)
	if len(r.buf) < total || len(r.fds) < int(h.NFds) {
		return Header{}, nil, nil, false, nil
	}
	payload = append([]byte(nil), r.buf[HeaderSize:total]...)
	fds = append([]int(nil), r.fds[:h.NFds]...)
	r.buf = r.buf[:copy(r.buf, r.buf[total:])]
	r.fds = r.fds[:copy(r.fds, r.fds[h.NFds:])]
	return h, payload, fds, true, nil
}

// Queued returns the descriptors still waiting for a message, so a closing
// transport can close them.
func (r *Reader) Queued() []int { return r.fds }

// WriteMessage appends the header and payload of one message to dst. Size is
// taken from the payload.
func WriteMessage(dst []byte, h Header, payload []byte) []byte {
	h.Size = uint32(len(payload))
	dst = h.AppendTo(dst)
	return append(dst, payload...)
}

// memMsg is one message in flight on a MemTransport.
type memMsg struct {
	h       Header
	payload []byte
	fds     []int
}

// MemTransport is one end of an in-memory pair. File descriptors travel as
// plain integers and are never duplicated or closed, so tests can use any
// number as a descriptor.
type MemTransport struct {
	in     chan memMsg
	peer   *MemTransport
	closed chan struct{}
	once   sync.Once
}

// NewMemPair returns two connected ends. A message sent on one is received on
// the other. Closing an end makes the other end's Recv return io.EOF once the
// queued messages are read.
func NewMemPair() (*MemTransport, *MemTransport) {
	a := &MemTransport{in: make(chan memMsg, 256), closed: make(chan struct{})}
	b := &MemTransport{in: make(chan memMsg, 256), closed: make(chan struct{})}
	a.peer, b.peer = b, a
	return a, b
}

// Send queues a copy of the message for the peer.
func (m *MemTransport) Send(h Header, payload []byte, fds []int) error {
	h.Size = uint32(len(payload))
	h.NFds = uint32(len(fds))
	msg := memMsg{h: h, payload: append([]byte(nil), payload...), fds: append([]int(nil), fds...)}
	select {
	case <-m.closed:
		return ErrClosed
	case <-m.peer.closed:
		return io.ErrClosedPipe
	default:
	}
	select {
	case m.peer.in <- msg:
		return nil
	case <-m.closed:
		return ErrClosed
	case <-m.peer.closed:
		return io.ErrClosedPipe
	}
}

// Recv blocks for the next message from the peer.
func (m *MemTransport) Recv() (Header, []byte, []int, error) {
	select {
	case msg := <-m.in:
		return msg.h, msg.payload, msg.fds, nil
	case <-m.closed:
		return Header{}, nil, nil, ErrClosed
	case <-m.peer.closed:
		select {
		case msg := <-m.in:
			return msg.h, msg.payload, msg.fds, nil
		default:
			return Header{}, nil, nil, io.EOF
		}
	}
}

// Close closes this end. It is safe to call more than once.
func (m *MemTransport) Close() error {
	m.once.Do(func() { close(m.closed) })
	return nil
}
