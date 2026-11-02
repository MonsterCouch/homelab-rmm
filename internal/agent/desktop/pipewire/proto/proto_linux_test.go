//go:build linux

package proto

import (
	"bytes"
	"os"
	"syscall"
	"testing"
	"time"
)

// socketPair returns two SocketTransports over a socketpair.
func socketPair(t *testing.T) (*SocketTransport, *SocketTransport) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("no socketpair: %v", err)
	}
	a, err := NewSocketTransport(fds[0])
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSocketTransport(fds[1])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func TestSocketTransportCarriesBytesAndFds(t *testing.T) {
	a, b := socketPair(t)
	var p [2]int
	if err := syscall.Pipe(p[:]); err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(p[0])
	defer syscall.Close(p[1])

	h, payload, fds, err := BuildMessage(2, 3, ClientNodeTransport{ReadFd: p[1], WriteFd: p[1], MemID: 1, Size: 2312})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Send(h, payload, fds); err != nil {
		t.Fatal(err)
	}
	// Two plain messages right behind it, to test coalesced reads.
	for i := 0; i < 2; i++ {
		h2, p2, f2, _ := BuildMessage(0, uint32(4+i), CorePing{ID: 1, Seq: int32(i)})
		if err := a.Send(h2, p2, f2); err != nil {
			t.Fatal(err)
		}
	}

	gh, gp, gf, err := b.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if gh.ID != 2 || gh.Seq != 3 || gh.NFds != 1 || !bytes.Equal(gp, payload) || len(gf) != 1 {
		t.Fatalf("got %+v fds %v", gh, gf)
	}
	defer syscall.Close(gf[0])
	// The received fd is a new descriptor for the same pipe.
	if _, err := syscall.Write(gf[0], []byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if n, err := syscall.Read(p[0], buf); err != nil || n != 1 || buf[0] != 'x' {
		t.Fatalf("pipe read = %d %v %q", n, err, buf)
	}
	for i := 0; i < 2; i++ {
		if h3, _, _, err := b.Recv(); err != nil || h3.Seq != uint32(4+i) {
			t.Fatalf("message %d: %+v %v", i, h3, err)
		}
	}
}

func TestSocketTransportEOF(t *testing.T) {
	a, b := socketPair(t)
	a.Close()
	if _, _, _, err := b.Recv(); err == nil {
		t.Fatal("Recv after the peer closed returned no error")
	}
}

// A Recv that fails on the descriptor limit must close the descriptors that
// earlier reads queued, or they stay open for the life of the process.
func TestSocketTransportRecvErrorClosesQueuedFds(t *testing.T) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Skipf("no rlimit: %v", err)
	}
	if lim.Cur < 3*MaxFds {
		lim.Cur = 3 * MaxFds
		if lim.Max < lim.Cur || syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim) != nil {
			t.Skip("the descriptor limit is too low for this test")
		}
	}
	a, b := socketPair(t)
	var p [2]int
	if err := syscall.Pipe(p[:]); err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(p[0])
	defer syscall.Close(p[1])
	before := openFdCount(t)
	// A header that promises a payload which never arrives, then one byte and
	// one descriptor per sendmsg, so the reader never has a complete message
	// and keeps queueing descriptors. (Bare zero bytes would not do: sixteen of
	// them are a valid empty message.) The kernel hands these back one per
	// read and each holds a socket-buffer slot, so they are written while Recv
	// drains them; written up front, the writer blocks long before the limit.
	hdr := Header{ID: 1, Opcode: 1, Size: 64 * 1024}.Pack()
	if _, err := a.conn.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	oob := syscall.UnixRights(p[0])
	wrote := make(chan error, 1)
	go func() {
		for i := 0; i < MaxFds+1; i++ {
			if _, _, err := a.conn.WriteMsgUnix([]byte{0}, oob, nil); err != nil {
				wrote <- err
				return
			}
		}
		wrote <- nil
	}()
	_, _, _, err := b.Recv()
	// Should Recv stop early for another reason, unblock the writer rather
	// than hang on a full socket.
	_ = a.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err == nil {
		t.Fatal("Recv succeeded with more descriptors than the limit")
	}
	if werr := <-wrote; werr != nil {
		t.Fatalf("write %v (Recv: %v)", werr, err)
	}
	if after := openFdCount(t); after > before {
		t.Fatalf("%d descriptors stayed open after the failed Recv", after-before)
	}
}

func openFdCount(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	return len(ents)
}
