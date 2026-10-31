package proto

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/pod"
)

// fakeServer is the server end of a MemTransport. It decodes what the client
// sends and writes events the way the notes describe the server doing it.
type fakeServer struct {
	t   *testing.T
	tr  *MemTransport
	seq uint32
}

type fromClient struct {
	h   Header
	msg any
	fds []int
}

func (s *fakeServer) recv() fromClient {
	s.t.Helper()
	type res struct {
		h       Header
		payload []byte
		fds     []int
		err     error
	}
	ch := make(chan res, 1)
	go func() {
		h, p, f, err := s.tr.Recv()
		ch <- res{h, p, f, err}
	}()
	var r res
	select {
	case r = <-ch:
	case <-time.After(5 * time.Second):
		s.t.Fatal("the client sent nothing within 5 seconds")
	}
	if r.err != nil {
		s.t.Fatalf("server Recv: %v", r.err)
	}
	st, _, err := SplitPayload(r.payload)
	if err != nil {
		s.t.Fatal(err)
	}
	var msg any
	fl := NewFdList(r.fds)
	switch {
	case r.h.ID == IDCore:
		msg, err = DecodeCoreMethod(r.h.Opcode, st, fl)
	case r.h.ID == IDClient:
		msg, err = DecodeClientMethod(r.h.Opcode, st, fl)
	default:
		msg, err = DecodeClientNodeMethod(r.h.Opcode, st, fl)
	}
	if err != nil {
		s.t.Fatalf("server decode of id %d opcode %d: %v", r.h.ID, r.h.Opcode, err)
	}
	return fromClient{r.h, msg, r.fds}
}

func (s *fakeServer) send(id uint32, m Message) {
	s.t.Helper()
	h, payload, fds, err := BuildMessage(id, s.seq, m)
	if err != nil {
		s.t.Fatal(err)
	}
	s.seq++
	if err := s.tr.Send(h, payload, fds); err != nil {
		s.t.Fatalf("server Send: %v", err)
	}
}

// sendRaw sends a message with a payload and fd list the caller built.
func (s *fakeServer) sendRaw(id uint32, op uint8, payload []byte, fds []int) {
	s.t.Helper()
	if err := s.tr.Send(Header{ID: id, Opcode: op, Seq: s.seq}, payload, fds); err != nil {
		s.t.Fatalf("server Send: %v", err)
	}
	s.seq++
}

type fdRecorder struct {
	mu     sync.Mutex
	closed []int
}

func (r *fdRecorder) close(fd int) {
	r.mu.Lock()
	r.closed = append(r.closed, fd)
	r.mu.Unlock()
}

func (r *fdRecorder) list() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int(nil), r.closed...)
}

func newPair(t *testing.T, cfg Config) (*Conn, *fakeServer) {
	t.Helper()
	cl, sv := NewMemPair()
	c := NewConn(cl, cfg)
	t.Cleanup(func() { c.Close(); sv.Close() })
	return c, &fakeServer{t: t, tr: sv}
}

// barrier makes the client Sync and has the server answer. Every message the
// server sent before the barrier has been handled when it returns.
func barrier(t *testing.T, c *Conn, s *fakeServer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- c.Sync(ctx) }()
	got := s.recv()
	sync, ok := got.msg.(CoreSync)
	if !ok {
		t.Fatalf("expected Core.Sync, got %T", got.msg)
	}
	s.send(IDCore, CoreDone{ID: sync.ID, Seq: sync.Seq})
	if err := <-errc; err != nil {
		t.Fatalf("Sync: %v", err)
	}
}

func TestConnHelloInfoAndSync(t *testing.T) {
	c, s := newPair(t, Config{})
	props := Dict{{"media.type", "Video"}, {"application.name", "rmm-agent"}}
	if err := c.Hello(props); err != nil {
		t.Fatal(err)
	}

	hello := s.recv()
	if hello.h.ID != IDCore || hello.h.Opcode != CoreMethodHello || hello.h.Seq != 0 {
		t.Fatalf("first message header = %+v", hello.h)
	}
	if hello.msg != any(CoreHello{Version: 4}) {
		t.Fatalf("hello = %+v", hello.msg)
	}
	up := s.recv()
	if up.h.ID != IDClient || up.h.Opcode != ClientMethodUpdateProperties || up.h.Seq != 1 {
		t.Fatalf("second message header = %+v", up.h)
	}
	if !reflect.DeepEqual(up.msg, ClientUpdateProperties{Props: props}) {
		t.Fatalf("update properties = %+v", up.msg)
	}

	// The server answers Hello with Core.Info and Client.Info.
	s.send(IDCore, CoreInfo{ID: 0, Cookie: 7, UserName: "u", HostName: "h", Version: "1.2.7", Name: "pipewire-0", ChangeMask: 1, Props: Dict{{"a", "b"}}})
	s.send(IDClient, ClientInfo{ID: 1, ChangeMask: 1, Props: Dict{{"pipewire.access", "unrestricted"}}})

	// Sync gets seq 2 on the wire and 0x40000002 as its argument.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- c.Sync(ctx) }()
	sy := s.recv()
	if sy.h.Opcode != CoreMethodSync || sy.h.Seq != 2 {
		t.Fatalf("sync header = %+v", sy.h)
	}
	if sy.msg != any(CoreSync{ID: 0, Seq: 0x40000002}) {
		t.Fatalf("sync = %+v", sy.msg)
	}
	select {
	case err := <-errc:
		t.Fatalf("Sync returned %v before Done", err)
	case <-time.After(20 * time.Millisecond):
	}
	s.send(IDCore, CoreDone{ID: 0, Seq: 0x40000002})
	if err := <-errc; err != nil {
		t.Fatal(err)
	}

	ci, ok := c.CoreInfo()
	if !ok || ci.Name != "pipewire-0" || ci.Cookie != 7 {
		t.Fatalf("CoreInfo = %+v, %v", ci, ok)
	}
	cli, ok := c.ClientInfo()
	if !ok || cli.ID != 1 {
		t.Fatalf("ClientInfo = %+v, %v", cli, ok)
	}
}

func TestConnSyncIgnoresOtherDoneAndHonoursContext(t *testing.T) {
	c, s := newPair(t, Config{})
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- c.Sync(ctx) }()
	sy := s.recv().msg.(CoreSync)
	// A Done for a different seq, and one for the invalid id, must not release it.
	s.send(IDCore, CoreDone{ID: 0, Seq: sy.Seq + 1})
	s.send(IDCore, CoreDone{ID: int32(-1), Seq: sy.Seq})
	select {
	case err := <-errc:
		t.Fatalf("Sync returned %v on an unrelated Done", err)
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("Sync after cancel = %v", err)
	}
}

func TestConnAnswersPingWithPong(t *testing.T) {
	c, s := newPair(t, Config{})
	_ = c
	s.send(IDCore, CorePing{ID: 2, Seq: 1234})
	got := s.recv()
	if got.h.ID != IDCore || got.h.Opcode != CoreMethodPong {
		t.Fatalf("reply header = %+v", got.h)
	}
	if got.msg != any(CorePong{ID: 2, Seq: 1234}) {
		t.Fatalf("pong = %+v", got.msg)
	}
}

func TestConnCreateClientNodeAndBoundProps(t *testing.T) {
	c, s := newPair(t, Config{})
	var mu sync.Mutex
	var events []any
	h := func(ev any) error {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
		return nil
	}
	props := Dict{{"media.class", "Stream/Input/Video"}, {"node.target", "42"}}
	id, err := c.CreateClientNode(props, h)
	if err != nil {
		t.Fatal(err)
	}
	if id != 2 {
		t.Fatalf("first proxy id = %d, want 2", id)
	}
	got := s.recv()
	want := CoreCreateObject{FactoryName: "client-node", Type: "PipeWire:Interface:ClientNode", Version: 6, Props: props, NewID: 2}
	if got.h.ID != IDCore || got.h.Opcode != CoreMethodCreateObject || !reflect.DeepEqual(got.msg, want) {
		t.Fatalf("CreateObject = %+v %+v", got.h, got.msg)
	}
	if id2 := c.AllocID(); id2 != 3 {
		t.Fatalf("next id = %d, want 3", id2)
	}

	s.send(IDCore, CoreBoundProps{ID: 2, GlobalID: 55, Props: Dict{{"object.serial", "9"}}})
	s.send(2, ClientNodeTransport{ReadFd: 60, WriteFd: 61, MemID: 3, Size: 2312})
	s.send(2, ClientNodeCommand{Command: pod.NewObject(pod.TypeCommandNode, pod.NodeCommandStart)})
	barrier(t, c, s)

	if g, ok := c.GlobalID(2); !ok || g != 55 {
		t.Fatalf("GlobalID(2) = %d, %v", g, ok)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 3 {
		t.Fatalf("handler saw %d events: %+v", len(events), events)
	}
	if bp, ok := events[0].(CoreBoundProps); !ok || bp.GlobalID != 55 {
		t.Fatalf("first event = %+v", events[0])
	}
	if tr, ok := events[1].(ClientNodeTransport); !ok || tr.ReadFd != 60 || tr.WriteFd != 61 {
		t.Fatalf("second event = %+v", events[1])
	}
	if cmd, ok := events[2].(ClientNodeCommand); !ok {
		t.Fatalf("third event = %+v", events[2])
	} else if cid, _ := cmd.NodeCommandID(); cid != pod.NodeCommandStart {
		t.Fatalf("command id = %d", cid)
	}
}

func TestConnBoundIdIsDelivered(t *testing.T) {
	c, s := newPair(t, Config{})
	got := make(chan any, 1)
	id, err := c.CreateClientNode(nil, func(ev any) error { got <- ev; return nil })
	if err != nil {
		t.Fatal(err)
	}
	s.recv()
	s.send(IDCore, CoreBoundId{ID: id, GlobalID: 77})
	select {
	case ev := <-got:
		if ev != any(CoreBoundId{ID: id, GlobalID: 77}) {
			t.Fatalf("event = %+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("BoundId was not delivered")
	}
	barrier(t, c, s)
	if g, _ := c.GlobalID(id); g != 77 {
		t.Fatalf("GlobalID = %d", g)
	}
}

func TestConnAddMemKeepsFdUntilRemoveMem(t *testing.T) {
	rec := &fdRecorder{}
	c, s := newPair(t, Config{CloseFd: rec.close})
	s.send(IDCore, CoreAddMem{ID: 7, Type: pod.DataMemFd, Fd: 100, Flags: 3})
	barrier(t, c, s)
	m, ok := c.Mem(7)
	if !ok || m.Fd != 100 || m.Type != pod.DataMemFd || m.Flags != 3 {
		t.Fatalf("Mem(7) = %+v, %v", m, ok)
	}
	if len(rec.list()) != 0 {
		t.Fatalf("an fd was closed early: %v", rec.list())
	}
	s.send(IDCore, CoreRemoveMem{ID: 7})
	barrier(t, c, s)
	if _, ok := c.Mem(7); ok {
		t.Fatal("Mem(7) survived RemoveMem")
	}
	if !reflect.DeepEqual(rec.list(), []int{100}) {
		t.Fatalf("closed fds = %v, want [100]", rec.list())
	}
}

func TestConnAddMemUsesTheFdIndexNotTheNumber(t *testing.T) {
	// The server puts two fds on the message and the Fd pod points at index 1.
	c, s := newPair(t, Config{})
	body := pod.NewBuilder().Int(9).Id(pod.DataMemFd).Fd(1).Int(0).Build()
	s.sendRaw(IDCore, CoreEventAddMem, pod.Encode(body), []int{500, 501})
	barrier(t, c, s)
	if m, ok := c.Mem(9); !ok || m.Fd != 501 {
		t.Fatalf("Mem(9) = %+v, %v; want fd 501", m, ok)
	}
}

func TestConnClosesFdsNobodyUsed(t *testing.T) {
	rec := &fdRecorder{}
	c, s := newPair(t, Config{CloseFd: rec.close})
	// A message for a proxy nobody registered, and a Ping with a stray fd.
	s.send(5, ClientNodeTransport{ReadFd: 70, WriteFd: 71})
	s.sendRaw(IDCore, CoreEventPing, pod.Encode(pod.NewStruct(pod.Int(1), pod.Int(2))), []int{72})
	if got := s.recv(); got.msg != any(CorePong{ID: 1, Seq: 2}) {
		t.Fatalf("pong = %+v", got.msg)
	}
	barrier(t, c, s)
	closed := rec.list()
	for _, want := range []int{70, 71, 72} {
		found := false
		for _, fd := range closed {
			found = found || fd == want
		}
		if !found {
			t.Fatalf("fd %d was not closed; closed = %v", want, closed)
		}
	}
}

func TestConnErrorOnCoreWithEpipeEndsConnection(t *testing.T) {
	rec := &fdRecorder{}
	c, s := newPair(t, Config{CloseFd: rec.close})
	s.send(IDCore, CoreAddMem{ID: 1, Type: pod.DataMemFd, Fd: 200})
	barrier(t, c, s)
	s.send(IDCore, CoreErrorEvent{ID: 0, Seq: 3, Res: -32, Message: "broken pipe"})
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the connection did not end on Core.Error with -EPIPE on the core")
	}
	err := c.Err()
	var se *ServerError
	if !errors.As(err, &se) || se.ID != 0 || se.Res != -32 {
		t.Fatalf("Err() = %v", err)
	}
	want := "the PipeWire server reported an error on object 0 (result -32): broken pipe"
	if err.Error() != want {
		t.Fatalf("Err() text = %q, want %q", err.Error(), want)
	}
	if err := c.Send(IDCore, CoreHello{Version: 4}); err == nil || err.Error() != want {
		t.Fatalf("Send after the error = %v", err)
	}
	if err := c.Sync(context.Background()); err == nil || err.Error() != want {
		t.Fatalf("Sync after the error = %v", err)
	}
	if !reflect.DeepEqual(rec.list(), []int{200}) {
		t.Fatalf("mem fd was not closed on the way out: %v", rec.list())
	}
}

func TestConnErrorOnProxyReachesOnlyThatProxy(t *testing.T) {
	c, s := newPair(t, Config{})
	got1 := make(chan any, 4)
	got2 := make(chan any, 4)
	id1, _ := c.CreateClientNode(nil, func(ev any) error { got1 <- ev; return nil })
	s.recv()
	id2, _ := c.CreateClientNode(nil, func(ev any) error { got2 <- ev; return nil })
	s.recv()
	s.send(IDCore, CoreErrorEvent{ID: int32(id1), Seq: 3, Res: -22, Message: "too many metas"})
	// An error for an unknown id and a non-fatal error on the core are dropped.
	s.send(IDCore, CoreErrorEvent{ID: 77, Seq: 4, Res: -2, Message: "gone"})
	s.send(IDCore, CoreErrorEvent{ID: 0, Seq: 5, Res: -22, Message: "bad request"})
	barrier(t, c, s)
	if c.Err() != nil {
		t.Fatalf("an error on one proxy ended the connection: %v", c.Err())
	}
	select {
	case ev := <-got1:
		if e, ok := ev.(CoreErrorEvent); !ok || e.Res != -22 || e.Message != "too many metas" {
			t.Fatalf("proxy %d got %+v", id1, ev)
		}
	default:
		t.Fatalf("proxy %d did not receive its error", id1)
	}
	select {
	case ev := <-got2:
		t.Fatalf("proxy %d received %+v meant for another proxy", id2, ev)
	default:
	}
}

func TestConnErrorWakesPendingSync(t *testing.T) {
	c, s := newPair(t, Config{})
	errc := make(chan error, 1)
	go func() { errc <- c.Sync(context.Background()) }()
	s.recv()
	s.send(IDCore, CoreErrorEvent{ID: 0, Seq: 0, Res: -32, Message: "broken"})
	select {
	case err := <-errc:
		var se *ServerError
		if !errors.As(err, &se) {
			t.Fatalf("Sync = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Sync stayed blocked after the connection ended")
	}
}

func TestConnRemoveIdFreesTheId(t *testing.T) {
	c, s := newPair(t, Config{})
	removed := make(chan any, 1)
	id, err := c.CreateClientNode(nil, func(ev any) error {
		if r, ok := ev.(CoreRemoveId); ok {
			removed <- r
		}
		return nil
	})
	if err != nil || id != 2 {
		t.Fatalf("id=%d err=%v", id, err)
	}
	s.recv()
	s.send(IDCore, CoreRemoveId{ID: 2})
	select {
	case <-removed:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not see RemoveId")
	}
	barrier(t, c, s)
	if again := c.AllocID(); again != 2 {
		t.Fatalf("AllocID after RemoveId = %d, want 2", again)
	}
}

func TestConnSendNumbersMessages(t *testing.T) {
	c, s := newPair(t, Config{})
	for i := 0; i < 4; i++ {
		if err := c.Send(IDCore, CoreSync{ID: 0, Seq: int32(i)}); err != nil {
			t.Fatal(err)
		}
	}
	for i := uint32(0); i < 4; i++ {
		if h := s.recv().h; h.Seq != i {
			t.Fatalf("message %d has seq %d", i, h.Seq)
		}
	}
}

func TestConnSkipsFootersAndRecordsGeneration(t *testing.T) {
	c, s := newPair(t, Config{})
	payload := AppendFooterGeneration(pod.Encode(pod.NewStruct(pod.Int(0), pod.Int(7))), 5)
	s.sendRaw(IDCore, CoreEventPing, payload, nil)
	if got := s.recv(); got.msg != any(CorePong{ID: 0, Seq: 7}) {
		t.Fatalf("pong = %+v", got.msg)
	}
	if g, ok := c.Generation(); !ok || g != 5 {
		t.Fatalf("Generation = %d, %v", g, ok)
	}
}

func TestConnIgnoresUnknownOpcodes(t *testing.T) {
	c, s := newPair(t, Config{})
	s.sendRaw(IDCore, 99, pod.Encode(pod.NewStruct()), nil)
	s.sendRaw(IDClient, 99, pod.Encode(pod.NewStruct()), nil)
	id, _ := c.CreateClientNode(nil, func(any) error { return nil })
	s.recv()
	s.sendRaw(id, 99, pod.Encode(pod.NewStruct()), nil)
	barrier(t, c, s)
	if c.Err() != nil {
		t.Fatalf("an unknown opcode ended the connection: %v", c.Err())
	}
}

func TestConnMalformedMessageIsSkipped(t *testing.T) {
	cases := map[string]struct {
		payload []byte
		fds     []int
	}{
		"payload is not a struct": {pod.Encode(pod.Int(1)), nil},
		"truncated pod":           {[]byte{0x20, 0, 0, 0, 0x0e, 0, 0, 0}, nil},
		"wrong field type":        {pod.Encode(pod.NewStruct(pod.String("x"), pod.Int(1))), nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := &fdRecorder{}
			var skipped int
			var mu sync.Mutex
			c, s := newPair(t, Config{CloseFd: rec.close, OnSkip: func(h Header, err error) {
				mu.Lock()
				skipped++
				mu.Unlock()
				if !strings.Contains(err.Error(), "PipeWire") && !strings.Contains(err.Error(), "proto") {
					t.Errorf("skip error %q names neither PipeWire nor proto", err)
				}
			}})
			s.sendRaw(IDCore, CoreEventDone, tc.payload, tc.fds)
			barrier(t, c, s)
			if c.Err() != nil {
				t.Fatalf("a message that does not decode ended the connection: %v", c.Err())
			}
			mu.Lock()
			defer mu.Unlock()
			if skipped != 1 {
				t.Fatalf("OnSkip ran %d times, want 1", skipped)
			}
		})
	}
}

func TestConnUndecodableProxyEventKeepsConnectionAndClosesFds(t *testing.T) {
	rec := &fdRecorder{}
	c, s := newPair(t, Config{CloseFd: rec.close})
	id, _ := c.CreateClientNode(nil, func(any) error { return nil })
	s.recv()
	// Transport needs two fds and a struct; this carries a stray fd and a wrong body.
	s.sendRaw(id, ClientNodeEventTransport, pod.Encode(pod.NewStruct(pod.String("x"))), []int{91})
	barrier(t, c, s)
	if c.Err() != nil {
		t.Fatalf("connection ended: %v", c.Err())
	}
	if !reflect.DeepEqual(rec.list(), []int{91}) {
		t.Fatalf("closed fds = %v, want [91]", rec.list())
	}
}

func TestConnHandlerErrorEndsConnection(t *testing.T) {
	c, s := newPair(t, Config{})
	boom := errors.New("buffer references an unknown memory block")
	id, _ := c.CreateClientNode(nil, func(ev any) error {
		if _, ok := ev.(ClientNodePortUseBuffers); ok {
			return boom
		}
		return nil
	})
	s.recv()
	s.send(id, ClientNodePortUseBuffers{Buffers: []UseBuffer{{MemID: 99}}})
	<-c.Done()
	if !errors.Is(c.Err(), boom) {
		t.Fatalf("Err() = %v", c.Err())
	}
}

func TestConnServerCloseEndsConnection(t *testing.T) {
	c, s := newPair(t, Config{})
	s.tr.Close()
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the connection stayed open after the server closed")
	}
	if err := c.Err(); !errors.Is(err, io.EOF) || !strings.Contains(err.Error(), "closed the connection") {
		t.Fatalf("Err() = %v", err)
	}
}

func TestConnCloseIsIdempotentAndReportsErrClosed(t *testing.T) {
	c, _ := newPair(t, Config{})
	c.Close()
	c.Close()
	if !errors.Is(c.Err(), ErrClosed) {
		t.Fatalf("Err() = %v", c.Err())
	}
	if err := c.Send(IDCore, CoreHello{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Send after Close = %v", err)
	}
}

func TestConnReportErrorUsesLastReceivedSeq(t *testing.T) {
	c, s := newPair(t, Config{})
	s.seq = 41
	s.send(IDCore, CoreDone{ID: 0, Seq: 1})
	barrier(t, c, s) // the barrier's Done has seq 42
	if err := c.ReportError(2, -95, "format not offered"); err != nil {
		t.Fatal(err)
	}
	got := s.recv()
	e, ok := got.msg.(CoreError)
	if !ok || e.ID != 2 || e.Res != -95 || e.Message != "format not offered" || e.Seq != 42 {
		t.Fatalf("Core.Error = %+v", got.msg)
	}
}
