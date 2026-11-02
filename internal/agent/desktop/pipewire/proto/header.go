// Package proto speaks the PipeWire native protocol (module-protocol-native,
// protocol version 3) over a Transport. It marshals and unmarshals the Core,
// Client and ClientNode messages with the pod package and runs the connection
// state a client needs: Hello, Ping and Pong, Sync and Done, Error, proxy ids
// and the table of memory blocks announced by AddMem.
//
// The layouts follow docs/plans/2026-10-25-pipewire-protocol-notes.md, which
// was read from PipeWire 1.2.7. No PipeWire daemon was available when this was
// written, so nothing here has been checked against a real server. The tests
// use a fake server that speaks the protocol as the notes describe it.
package proto

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/pod"
)

// Wire constants of the native protocol, protocol version 3.
const (
	// HeaderSize is the size of the message header in bytes.
	HeaderSize = 16
	// MaxPayload is the largest payload the 24-bit size field can carry.
	MaxPayload = 1<<24 - 1
	// SeqMask is applied to the per-direction sequence number.
	SeqMask = 0x3fffffff
	// AsyncBit marks a sequence number used as an async result (SPA_RESULT_RETURN_ASYNC).
	AsyncBit = 0x40000000
	// MaxFds is the most file descriptors one connection may have queued.
	MaxFds = 1024
	// InvalidID is SPA_ID_INVALID, used for "no id" and "no memory block".
	InvalidID uint32 = 0xffffffff
)

// Proxy ids that exist from the start of every connection.
const (
	IDCore   uint32 = 0
	IDClient uint32 = 1
)

// Header is the 16-byte header in front of every message. Size is the
// payload length in bytes after the header; NFds is the number of file
// descriptors that belong to the message.
type Header struct {
	ID     uint32
	Opcode uint8
	Size   uint32
	Seq    uint32
	NFds   uint32
}

// Pack returns the 16 wire bytes of h: id, opcode<<24|size, seq, n_fds, all
// little endian. Size is masked to 24 bits and Seq to 30 bits as the C
// connection code does.
func (h Header) Pack() [HeaderSize]byte {
	var b [HeaderSize]byte
	binary.LittleEndian.PutUint32(b[0:], h.ID)
	binary.LittleEndian.PutUint32(b[4:], uint32(h.Opcode)<<24|h.Size&MaxPayload)
	binary.LittleEndian.PutUint32(b[8:], h.Seq&SeqMask)
	binary.LittleEndian.PutUint32(b[12:], h.NFds)
	return b
}

// AppendTo appends the packed header to dst.
func (h Header) AppendTo(dst []byte) []byte {
	b := h.Pack()
	return append(dst, b[:]...)
}

// UnpackHeader reads a header from the first 16 bytes of b. The sequence
// number is returned as sent.
func UnpackHeader(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, fmt.Errorf("proto: a message header needs %d bytes and only %d are available", HeaderSize, len(b))
	}
	w := binary.LittleEndian.Uint32(b[4:])
	return Header{
		ID:     binary.LittleEndian.Uint32(b[0:]),
		Opcode: uint8(w >> 24),
		Size:   w & MaxPayload,
		Seq:    binary.LittleEndian.Uint32(b[8:]),
		NFds:   binary.LittleEndian.Uint32(b[12:]),
	}, nil
}

// Message is a method or event that can be sent. Marshal returns the one
// Struct that carries its arguments and adds any file descriptors to fds.
type Message interface {
	Opcode() uint8
	Marshal(fds *FdSet) pod.Struct
}

// FdSet collects the file descriptors of one outgoing message. The same fd
// added twice gets the same index, as the C sender does.
type FdSet struct {
	fds []int
}

// Index returns the pod Fd value for fd. A negative fd is written as NoFd.
func (s *FdSet) Index(fd int) pod.Fd {
	if fd < 0 {
		return pod.NoFd
	}
	for i, f := range s.fds {
		if f == fd {
			return pod.Fd(i)
		}
	}
	s.fds = append(s.fds, fd)
	return pod.Fd(len(s.fds) - 1)
}

// List returns the collected descriptors in index order.
func (s *FdSet) List() []int { return s.fds }

// FdList is the receive side: the descriptors that arrived with one message.
// Decoders mark the ones they use; Unused returns the rest so the caller can
// close them.
type FdList struct {
	fds  []int
	used []bool
}

// NewFdList wraps the descriptors of a received message.
func NewFdList(fds []int) *FdList {
	return &FdList{fds: fds, used: make([]bool, len(fds))}
}

// Get resolves a pod Fd index to a descriptor. NoFd and negative indexes give -1.
func (l *FdList) Get(index int64) (int, error) {
	if index < 0 || index == int64(pod.NoFd) {
		return -1, nil
	}
	if index >= int64(len(l.fds)) {
		return -1, fmt.Errorf("the message refers to fd index %d but carries %d fds", index, len(l.fds))
	}
	l.used[index] = true
	return l.fds[index], nil
}

// Unused returns the descriptors no decoder asked for.
func (l *FdList) Unused() []int {
	var out []int
	for i, f := range l.fds {
		if !l.used[i] {
			out = append(out, f)
		}
	}
	return out
}

// BuildMessage encodes m for the object id with the given sequence number and
// returns the header, payload and descriptors ready for Transport.Send.
func BuildMessage(id, seq uint32, m Message) (Header, []byte, []int, error) {
	var fds FdSet
	st := m.Marshal(&fds)
	payload, err := pod.EncodeErr(st)
	if err != nil {
		return Header{}, nil, nil, fmt.Errorf("proto: encoding opcode %d for object %d: %w", m.Opcode(), id, err)
	}
	if len(payload) > MaxPayload {
		return Header{}, nil, nil, fmt.Errorf("proto: opcode %d for object %d is %d bytes, over the %d byte limit", m.Opcode(), id, len(payload), MaxPayload)
	}
	h := Header{ID: id, Opcode: m.Opcode(), Size: uint32(len(payload)), Seq: seq & SeqMask, NFds: uint32(len(fds.List()))}
	return h, payload, fds.List(), nil
}

// Footer is what a message footer carried. Only the generation entry exists
// in PipeWire 1.2.7.
type Footer struct {
	Generation    int64
	HasGeneration bool
}

// footerOpcodeGeneration is FOOTER_CORE_OPCODE_GENERATION.
const footerOpcodeGeneration = 0

// SplitPayload decodes the argument Struct at the start of a message payload
// and reads the footer that may follow it. Bytes after the Struct are never an
// error: a footer that does not parse is ignored, as PipeWire does.
func SplitPayload(payload []byte) (pod.Struct, Footer, error) {
	p, rest, err := pod.Decode(payload)
	if err != nil {
		return pod.Struct{}, Footer{}, err
	}
	st, ok := p.(pod.Struct)
	if !ok {
		return pod.Struct{}, Footer{}, fmt.Errorf("proto: the payload starts with a %s pod, not a Struct", pod.TypeName(p.PodType()))
	}
	return st, parseFooter(rest), nil
}

func parseFooter(rest []byte) Footer {
	rest = rest[:len(rest)&^7]
	if len(rest) < 8 {
		return Footer{}
	}
	p, _, err := pod.Decode(rest)
	if err != nil {
		return Footer{}
	}
	outer, ok := p.(pod.Struct)
	if !ok {
		return Footer{}
	}
	sp := outer.Parser()
	var f Footer
	for sp.Remaining() > 0 {
		op, err := sp.Id()
		if err != nil {
			return f
		}
		entry, err := sp.Struct()
		if err != nil {
			return f
		}
		if op == footerOpcodeGeneration {
			if g, err := entry.Long(); err == nil {
				f.Generation, f.HasGeneration = g, true
			}
		}
	}
	return f
}

// AppendFooterGeneration appends a footer carrying the registry generation to
// a payload. A client does not need it; a fake server uses it.
func AppendFooterGeneration(payload []byte, generation int64) []byte {
	entry := pod.NewStruct(pod.Long(generation))
	footer := pod.NewStruct(pod.Id(footerOpcodeGeneration), entry)
	return append(payload, pod.Encode(footer)...)
}

// errUnknownOpcode is returned by the decoders for an opcode they do not
// know. A connection ignores such messages, as PipeWire does.
var errUnknownOpcode = errors.New("proto: unknown opcode")

// IsUnknownOpcode reports whether err came from an opcode the decoders do not
// implement.
func IsUnknownOpcode(err error) bool { return errors.Is(err, errUnknownOpcode) }
