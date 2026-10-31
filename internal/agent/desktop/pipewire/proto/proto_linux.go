//go:build linux

package proto

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
)

// Limits of one sendmsg and one recvmsg. PipeWire attaches at most 28
// descriptors to a sendmsg (MAX_FDS_MSG); the receive buffer is sized for far
// more so a peer that sends more cannot truncate the control data.
const (
	maxFdsPerSend = 28
	recvBufSize   = 64 * 1024
	recvOOBFds    = 253
)

// SocketTransport is a Transport over a connected SOCK_STREAM Unix socket.
// Descriptors travel as SCM_RIGHTS control data of the same sendmsg and
// recvmsg calls as the message bytes. Recv keeps a byte buffer and a
// descriptor queue, so it copes with a message split over several reads, with
// two messages in one read, and with descriptors that arrive before or after
// their bytes.
type SocketTransport struct {
	conn *net.UnixConn

	sendMu sync.Mutex

	rd     Reader
	rbuf   []byte
	roob   []byte
	closed sync.Once
}

// NewSocketTransport wraps an already connected Unix stream socket, such as
// the descriptor the ScreenCast portal returns. It takes ownership of fd: the
// descriptor is duplicated into the Go runtime's poller and the original is
// closed.
func NewSocketTransport(fd int) (*SocketTransport, error) {
	f := os.NewFile(uintptr(fd), "pipewire-socket")
	if f == nil {
		return nil, fmt.Errorf("file descriptor %d is not valid", fd)
	}
	defer f.Close()
	nc, err := net.FileConn(f)
	if err != nil {
		return nil, fmt.Errorf("the PipeWire descriptor is not a usable socket: %w", err)
	}
	uc, ok := nc.(*net.UnixConn)
	if !ok {
		nc.Close()
		return nil, errors.New("the PipeWire descriptor is not a Unix socket")
	}
	return &SocketTransport{
		conn: uc,
		rbuf: make([]byte, recvBufSize),
		roob: make([]byte, syscall.CmsgSpace(4*recvOOBFds)),
	}, nil
}

// Send writes the message. The first sendmsg carries the descriptors, up to
// maxFdsPerSend at a time; more are sent with the following bytes.
func (s *SocketTransport) Send(h Header, payload []byte, fds []int) error {
	h.Size = uint32(len(payload))
	h.NFds = uint32(len(fds))
	data := WriteMessage(nil, h, payload)

	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	for len(fds) > 0 {
		n := len(fds)
		if n > maxFdsPerSend {
			n = maxFdsPerSend
		}
		chunk := len(data)
		if len(fds) > n && chunk > 4 {
			chunk = 4
		}
		if chunk == 0 {
			return errors.New("the message has more file descriptors than bytes to carry them")
		}
		oob := syscall.UnixRights(fds[:n]...)
		w, _, err := s.conn.WriteMsgUnix(data[:chunk], oob, nil)
		if err != nil {
			return err
		}
		data = data[w:]
		fds = fds[n:]
	}
	for len(data) > 0 {
		w, err := s.conn.Write(data)
		if err != nil {
			return err
		}
		data = data[w:]
	}
	return nil
}

// Recv blocks until a whole message and its descriptors are available.
func (s *SocketTransport) Recv() (Header, []byte, []int, error) {
	for {
		h, payload, fds, ok, err := s.rd.Next()
		if err != nil {
			s.dropQueued()
			return Header{}, nil, nil, err
		}
		if ok {
			return h, payload, fds, nil
		}
		n, oobn, flags, _, err := s.conn.ReadMsgUnix(s.rbuf, s.roob)
		var fds2 []int
		if oobn > 0 {
			fds2, _ = parseRights(s.roob[:oobn])
		}
		if flags&syscall.MSG_CTRUNC != 0 {
			closeFds(fds2)
			s.dropQueued()
			return Header{}, nil, nil, errors.New("the PipeWire server sent more file descriptors than one read can hold")
		}
		if ferr := s.rd.Feed(s.rbuf[:n], fds2); ferr != nil {
			closeFds(fds2)
			s.dropQueued()
			return Header{}, nil, nil, ferr
		}
		if err != nil {
			s.dropQueued()
			return Header{}, nil, nil, err
		}
		if n == 0 && oobn == 0 {
			s.dropQueued()
			return Header{}, nil, nil, io.EOF
		}
	}
}

// parseRights extracts the descriptors from SCM_RIGHTS control messages.
func parseRights(oob []byte) ([]int, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	var out []int
	for i := range msgs {
		fds, err := syscall.ParseUnixRights(&msgs[i])
		if err != nil {
			continue
		}
		out = append(out, fds...)
	}
	return out, nil
}

func closeFds(fds []int) {
	for _, fd := range fds {
		_ = syscall.Close(fd)
	}
}

// Close closes the socket. Descriptors that arrived without a complete message
// are closed by the Recv call that sees the socket end.
// It is safe to call more than once.
func (s *SocketTransport) Close() error {
	var err error
	s.closed.Do(func() {
		err = s.conn.Close()
	})
	return err
}

// CloseFd closes a descriptor received from a SocketTransport. It is the
// Config.CloseFd for a Conn over a SocketTransport.
func CloseFd(fd int) { _ = syscall.Close(fd) }

// dropQueued closes descriptors that never got a complete message.
func (s *SocketTransport) dropQueued() {
	closeFds(s.rd.Queued())
	s.rd = Reader{}
}
