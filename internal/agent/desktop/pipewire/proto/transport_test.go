package proto

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

func wire(t *testing.T, id, seq uint32, m Message) ([]byte, Header, []byte, []int) {
	t.Helper()
	h, payload, fds, err := BuildMessage(id, seq, m)
	if err != nil {
		t.Fatal(err)
	}
	return WriteMessage(nil, h, payload), h, payload, fds
}

func TestReaderOneByteAtATime(t *testing.T) {
	a, ha, pa, _ := wire(t, 0, 0, CoreHello{Version: 4})
	b, hb, pb, _ := wire(t, 0, 1, CoreSync{ID: 0, Seq: int32(AsyncBit | 1)})
	stream := append(append([]byte(nil), a...), b...)

	var r Reader
	type msg struct {
		h Header
		p []byte
	}
	var got []msg
	for _, c := range stream {
		if err := r.Feed([]byte{c}, nil); err != nil {
			t.Fatal(err)
		}
		for {
			h, p, _, ok, err := r.Next()
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				break
			}
			got = append(got, msg{h, p})
		}
	}
	if len(got) != 2 {
		t.Fatalf("got %d messages, want 2", len(got))
	}
	if got[0].h != ha || !bytes.Equal(got[0].p, pa) || got[1].h != hb || !bytes.Equal(got[1].p, pb) {
		t.Fatalf("messages differ: %+v", got)
	}
}

func TestReaderTwoMessagesInOneRead(t *testing.T) {
	a, _, pa, _ := wire(t, 0, 0, CoreHello{Version: 4})
	b, hb, pb, _ := wire(t, 1, 1, ClientUpdateProperties{Props: Dict{{"a", "b"}}})
	var r Reader
	if err := r.Feed(append(append([]byte(nil), a...), b...), nil); err != nil {
		t.Fatal(err)
	}
	_, p1, _, ok, err := r.Next()
	if err != nil || !ok || !bytes.Equal(p1, pa) {
		t.Fatalf("first: ok=%v err=%v", ok, err)
	}
	h2, p2, _, ok, err := r.Next()
	if err != nil || !ok || h2 != hb || !bytes.Equal(p2, pb) {
		t.Fatalf("second: ok=%v err=%v h=%+v", ok, err, h2)
	}
	if _, _, _, ok, _ := r.Next(); ok {
		t.Fatal("a third message appeared")
	}
}

func TestReaderSplitInsideHeaderAndPayload(t *testing.T) {
	a, _, pa, _ := wire(t, 0, 0, CoreHello{Version: 4})
	for cut := 1; cut < len(a); cut++ {
		var r Reader
		_ = r.Feed(a[:cut], nil)
		if _, _, _, ok, err := r.Next(); ok || err != nil {
			t.Fatalf("cut %d: ok=%v err=%v before the message was complete", cut, ok, err)
		}
		_ = r.Feed(a[cut:], nil)
		_, p, _, ok, err := r.Next()
		if !ok || err != nil || !bytes.Equal(p, pa) {
			t.Fatalf("cut %d: ok=%v err=%v", cut, ok, err)
		}
	}
}

func TestReaderPairsFdsByCount(t *testing.T) {
	// Two messages: the first carries 2 fds, the second 1. The fds arrive
	// before the bytes of the first message and the third one after the bytes
	// of the second.
	m1, _, _, _ := wire(t, 2, 0, ClientNodeTransport{ReadFd: 10, WriteFd: 11, MemID: 3, Size: 2312})
	m2, _, _, _ := wire(t, 2, 1, ClientNodeSetActivation{NodeID: 5, SignalFd: 12, MemID: 4, Size: 8})
	var r Reader
	_ = r.Feed(nil, []int{100, 101})
	_ = r.Feed(m1, nil)
	_ = r.Feed(m2, nil)
	h, _, fds, ok, err := r.Next()
	if !ok || err != nil || h.NFds != 2 || !reflect.DeepEqual(fds, []int{100, 101}) {
		t.Fatalf("first: ok=%v err=%v h=%+v fds=%v", ok, err, h, fds)
	}
	if _, _, _, ok, _ := r.Next(); ok {
		t.Fatal("second message returned before its fd arrived")
	}
	_ = r.Feed(nil, []int{102})
	_, _, fds, ok, err = r.Next()
	if !ok || err != nil || !reflect.DeepEqual(fds, []int{102}) {
		t.Fatalf("second: ok=%v err=%v fds=%v", ok, err, fds)
	}
	if len(r.Queued()) != 0 {
		t.Fatalf("queued = %v", r.Queued())
	}
}

func TestReaderRejectsBadHeaders(t *testing.T) {
	var r Reader
	bad := Header{ID: 0, Opcode: 1, Size: 12}.Pack() // not a multiple of 8
	_ = r.Feed(bad[:], nil)
	if _, _, _, _, err := r.Next(); err == nil {
		t.Fatal("a payload size that is not a multiple of 8 was accepted")
	}
	r = Reader{}
	bad = Header{ID: 0, Opcode: 1, Size: 0, NFds: MaxFds + 1}.Pack()
	_ = r.Feed(bad[:], nil)
	if _, _, _, _, err := r.Next(); err == nil {
		t.Fatal("more than MaxFds fds in one message was accepted")
	}
	r = Reader{}
	if err := r.Feed(nil, make([]int, MaxFds+1)); err == nil {
		t.Fatal("a queue over MaxFds was accepted")
	}
}

func TestMemPairCarriesFdsAsIntegers(t *testing.T) {
	a, b := NewMemPair()
	defer a.Close()
	defer b.Close()
	fds := []int{7, 8}
	if err := a.Send(Header{ID: 2, Opcode: 9}, []byte{1, 2, 3, 4, 5, 6, 7, 8}, fds); err != nil {
		t.Fatal(err)
	}
	fds[0] = 99 // the transport must have copied
	h, p, got, err := b.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != 2 || h.Opcode != 9 || h.Size != 8 || h.NFds != 2 || len(p) != 8 || !reflect.DeepEqual(got, []int{7, 8}) {
		t.Fatalf("got %+v % x %v", h, p, got)
	}
}

func TestMemPairClose(t *testing.T) {
	a, b := NewMemPair()
	if err := a.Send(Header{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	a.Close()
	// The queued message is still delivered, then EOF.
	if _, _, _, err := b.Recv(); err != nil {
		t.Fatalf("queued message lost: %v", err)
	}
	if _, _, _, err := b.Recv(); err != io.EOF {
		t.Fatalf("Recv after peer close = %v, want io.EOF", err)
	}
	if err := b.Send(Header{}, nil, nil); err == nil {
		t.Fatal("Send to a closed peer succeeded")
	}
	if _, _, _, err := a.Recv(); err != ErrClosed {
		t.Fatalf("Recv on a closed end = %v, want ErrClosed", err)
	}
	b.Close()
	b.Close()
}
