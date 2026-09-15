package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeCapturer serves synthetic monitors. Each capture paints frame number
// n so consecutive frames differ when changing is set.
type fakeCapturer struct {
	mu       sync.Mutex
	mons     []monitor
	changing bool
	failNext int
	n        int
	captures int
	// hook runs at the end of every capture, on the capture goroutine and
	// with mu held, so it must not call back into the capturer. It exists
	// to land an event (a cancellation) at a precise point of the loop.
	hook func()
}

func (f *fakeCapturer) monitors() ([]monitor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]monitor, len(f.mons))
	copy(out, f.mons)
	return out, nil
}

func (f *fakeCapturer) capture(m monitor) (*image.RGBA, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.captures++
	if f.failNext > 0 {
		f.failNext--
		return nil, errors.New("synthetic capture failure")
	}
	var cur monitor
	found := false
	for _, mm := range f.mons {
		if mm.Index == m.Index {
			cur, found = mm, true
		}
	}
	if !found {
		return nil, errors.New("no such monitor")
	}
	if f.changing {
		f.n++
	}
	img := solid(cur.Bounds.Dx(), cur.Bounds.Dy(), color.RGBA{uint8(f.n * 7), uint8(m.Index * 50), 40, 255})
	if f.hook != nil {
		f.hook()
	}
	return img, nil
}

func (f *fakeCapturer) setMonitors(mons []monitor) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mons = mons
}

func (f *fakeCapturer) setHook(h func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hook = h
}

func (f *fakeCapturer) setChanging(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.changing = v
}

type injected struct {
	kind string
	x, y int
	text string
	mon  monitor
}

type fakeInjector struct {
	mu     sync.Mutex
	mon    monitor
	events []injected
	closed bool
}

func (f *fakeInjector) record(kind string, x, y int, text string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, injected{kind: kind, x: x, y: y, text: text, mon: f.mon})
}

func (f *fakeInjector) setMonitor(m monitor) { f.mu.Lock(); f.mon = m; f.mu.Unlock() }
func (f *fakeInjector) mouseMove(x, y int) error {
	f.record("move", x, y, "")
	return nil
}
func (f *fakeInjector) mouseButton(button int, down bool, x, y int) error {
	f.record("button", x, y, map[bool]string{true: "down", false: "up"}[down])
	return nil
}
func (f *fakeInjector) wheel(dx, dy float64, x, y int) error {
	f.record("wheel", x, y, "")
	return nil
}
func (f *fakeInjector) key(code, key string, down bool) error {
	f.record("key", 0, 0, code+"/"+key)
	return nil
}
func (f *fakeInjector) paste(text string) error {
	f.record("paste", 0, 0, text)
	return nil
}
func (f *fakeInjector) ctrlAltDel() error {
	f.record("sas", 0, 0, "")
	return nil
}
func (f *fakeInjector) close() { f.mu.Lock(); f.closed = true; f.mu.Unlock() }

func (f *fakeInjector) waitFor(t *testing.T, kind string, timeout time.Duration) injected {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		for _, e := range f.events {
			if e.kind == kind {
				f.mu.Unlock()
				return e
			}
		}
		f.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no %q event injected within %v", kind, timeout)
	return injected{}
}

// harness runs a session against an in-process "viewer" WebSocket. A
// goroutine pumps the viewer's inbound messages into msgs so tests can wait
// with timeouts (gorilla treats a read deadline as a fatal socket error).
type harness struct {
	t      *testing.T
	viewer *websocket.Conn
	sess   *session
	done   chan error
	result chan error // done, cached for repeated waits
	cancel context.CancelFunc
	srv    *httptest.Server
	msgs   chan wsMsg
}

type wsMsg struct {
	mt   int
	data []byte
}

func startHarness(t *testing.T, cap capturer, inj injector, quality int) *harness {
	t.Helper()
	return startHarnessWith(t, cap, inj, quality, nil)
}

// startHarnessWith is startHarness with a hook that configures the viewer
// socket (handlers must be installed before its reader starts).
func startHarnessWith(t *testing.T, cap capturer, inj injector, quality int, setup func(viewer *websocket.Conn)) *harness {
	t.Helper()
	connCh := make(chan *websocket.Conn, 1)
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		connCh <- c
		<-r.Context().Done()
	}))
	ws, err := dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), "")
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}
	viewer := <-connCh
	if setup != nil {
		setup(viewer)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{t: t, viewer: viewer, sess: newSession(ws, cap, inj, quality), done: make(chan error, 1),
		result: make(chan error, 1), cancel: cancel, srv: srv, msgs: make(chan wsMsg, 1024)}
	go func() {
		err := h.sess.run(ctx)
		h.done <- err
	}()
	go func() {
		defer close(h.msgs)
		for {
			mt, data, err := viewer.ReadMessage()
			if err != nil {
				return
			}
			h.msgs <- wsMsg{mt, data}
		}
	}()
	t.Cleanup(func() {
		cancel()
		if err := h.wait(5 * time.Second); errors.Is(err, errTimeout) {
			t.Error("session did not stop")
		}
		viewer.Close()
		srv.Close()
	})
	return h
}

var errTimeout = errors.New("timeout")

// wait returns run's result, waiting at most d; the result is cached so
// the cleanup can wait again after the test did.
func (h *harness) wait(d time.Duration) error {
	select {
	case err := <-h.result:
		h.result <- err
		return err
	case err := <-h.done:
		h.result <- err
		return err
	case <-time.After(d):
		return errTimeout
	}
}

func (h *harness) send(v any) {
	h.t.Helper()
	if err := h.viewer.WriteJSON(v); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) ack(frame uint32) { h.send(map[string]any{"t": "ack", "frame": frame}) }

// frame is one capture pass as the viewer sees it.
type frame struct {
	texts []map[string]any
	tiles []tileFrame
	id    uint32
}

// readFrame collects messages until a frame-end. ok is false when no
// frame-end arrived before the timeout (a partial frame is a failure).
func (h *harness) readFrame(timeout time.Duration) (fr frame, ok bool) {
	h.t.Helper()
	deadline := time.After(timeout)
	for {
		var m wsMsg
		select {
		case <-deadline:
			if len(fr.texts) > 0 || len(fr.tiles) > 0 {
				h.t.Fatalf("partial frame: %d texts, %d tiles, no frame end", len(fr.texts), len(fr.tiles))
			}
			return fr, false
		case msg, open := <-h.msgs:
			if !open {
				if len(fr.texts) > 0 || len(fr.tiles) > 0 {
					h.t.Fatalf("socket closed mid-frame")
				}
				return fr, false
			}
			m = msg
		}
		switch m.mt {
		case websocket.TextMessage:
			var v map[string]any
			if err := json.Unmarshal(m.data, &v); err != nil {
				h.t.Fatalf("bad text frame %q", m.data)
			}
			fr.texts = append(fr.texts, v)
		case websocket.BinaryMessage:
			switch m.data[0] {
			case kindTile:
				tf, err := decodeTile(m.data)
				if err != nil {
					h.t.Fatal(err)
				}
				fr.tiles = append(fr.tiles, tf)
			case kindFrameEnd:
				id, err := decodeFrameEnd(m.data)
				if err != nil {
					h.t.Fatal(err)
				}
				fr.id = id
				return fr, true
			default:
				h.t.Fatalf("unknown binary kind %#x", m.data[0])
			}
		}
	}
}

func (fr frame) screen(t *testing.T) map[string]any {
	t.Helper()
	for _, m := range fr.texts {
		if m["t"] == "screen" {
			return m
		}
	}
	return nil
}

func rects(tiles []tileFrame) []image.Rectangle {
	out := make([]image.Rectangle, len(tiles))
	for i, tf := range tiles {
		out[i] = tf.Rect
	}
	return out
}

func twoMonitors() []monitor {
	return []monitor{
		{Index: 0, Bounds: image.Rect(0, 0, 320, 200), Primary: true},
		{Index: 1, Bounds: image.Rect(320, 0, 320+256, 128)},
	}
}

func TestSessionFirstFrame(t *testing.T) {
	cap := &fakeCapturer{mons: twoMonitors()}
	inj := &fakeInjector{}
	h := startHarness(t, cap, inj, 60)

	fr, ok := h.readFrame(3 * time.Second)
	if !ok {
		t.Fatal("no first frame")
	}
	sc := fr.screen(t)
	if sc == nil {
		t.Fatalf("first frame lacks a screen message: %v", fr.texts)
	}
	if sc["w"] != 320.0 || sc["h"] != 200.0 || sc["monitor"] != 0.0 {
		t.Fatalf("screen = %v", sc)
	}
	mons := sc["monitors"].([]any)
	if len(mons) != 2 {
		t.Fatalf("monitors = %v", mons)
	}
	m1 := mons[1].(map[string]any)
	if m1["index"] != 1.0 || m1["x"] != 320.0 || m1["w"] != 256.0 || m1["h"] != 128.0 || m1["primary"] != false {
		t.Fatalf("monitor 1 = %v", m1)
	}
	if mons[0].(map[string]any)["primary"] != true {
		t.Fatal("monitor 0 should be primary")
	}
	if fr.id != 1 {
		t.Fatalf("first frame id %d", fr.id)
	}
	coverage(t, rects(fr.tiles), image.Rect(0, 0, 320, 200))
	for _, tf := range fr.tiles {
		if tf.Codec != codecJPEG {
			t.Fatalf("codec %d", tf.Codec)
		}
		img, err := jpeg.Decode(bytes.NewReader(tf.Data))
		if err != nil {
			t.Fatalf("tile %v is not a JPEG: %v", tf.Rect, err)
		}
		if img.Bounds().Dx() != tf.Rect.Dx() || img.Bounds().Dy() != tf.Rect.Dy() {
			t.Fatalf("tile %v decoded to %v", tf.Rect, img.Bounds())
		}
	}
	// Nothing changes, so no further frame arrives.
	if fr2, ok := h.readFrame(400 * time.Millisecond); ok {
		t.Fatalf("unexpected second frame %d with %d tiles", fr2.id, len(fr2.tiles))
	}
	// The injector learnt the monitor before any input.
	inj.mu.Lock()
	mon := inj.mon
	inj.mu.Unlock()
	if mon.Bounds != image.Rect(0, 0, 320, 200) {
		t.Fatalf("injector monitor %v", mon)
	}
}

func TestSessionFlowControl(t *testing.T) {
	old := ackTimeout
	ackTimeout = 400 * time.Millisecond
	t.Cleanup(func() { ackTimeout = old })

	cap := &fakeCapturer{mons: twoMonitors()[:1], changing: true}
	h := startHarness(t, cap, &fakeInjector{}, 60)

	var ids []uint32
	for i := 0; i < 2; i++ {
		fr, ok := h.readFrame(2 * time.Second)
		if !ok {
			t.Fatalf("frame %d missing", i+1)
		}
		ids = append(ids, fr.id)
	}
	if ids[0] != 1 || ids[1] != 2 {
		t.Fatalf("ids %v", ids)
	}
	// Two unacked frames: the helper must pause even though every capture
	// differs.
	if fr, ok := h.readFrame(250 * time.Millisecond); ok {
		t.Fatalf("frame %d sent with 2 unacked", fr.id)
	}
	h.ack(1)
	fr, ok := h.readFrame(2 * time.Second)
	if !ok || fr.id != 3 {
		t.Fatalf("after ack 1: ok=%v id=%d", ok, fr.id)
	}
	if fr.screen(t) != nil {
		t.Fatal("a diff frame must not carry a screen message")
	}
	// Frames 2 and 3 unacked; the safety timeout releases the stream.
	fr, ok = h.readFrame(2 * time.Second)
	if !ok || fr.id != 4 {
		t.Fatalf("after ack timeout: ok=%v id=%d", ok, fr.id)
	}
	// An ack from the future must not underflow the unacked counter and
	// stall the stream forever: it means "caught up", so frames keep
	// flowing (capped by the frame rate) rather than the window jamming.
	h.ack(999)
	if _, ok := h.readFrame(2 * time.Second); !ok {
		t.Fatal("future ack stalled the stream")
	}
}

func TestSessionMonitorSwitchRefreshAndInput(t *testing.T) {
	cap := &fakeCapturer{mons: twoMonitors()}
	inj := &fakeInjector{}
	h := startHarness(t, cap, inj, 60)

	fr, ok := h.readFrame(3 * time.Second)
	if !ok {
		t.Fatal("no first frame")
	}
	h.ack(fr.id)

	h.send(map[string]any{"t": "monitor", "index": 1})
	fr, ok = h.readFrame(3 * time.Second)
	if !ok {
		t.Fatal("no frame after monitor switch")
	}
	sc := fr.screen(t)
	if sc == nil || sc["monitor"] != 1.0 || sc["w"] != 256.0 || sc["h"] != 128.0 {
		t.Fatalf("screen after switch = %v", sc)
	}
	coverage(t, rects(fr.tiles), image.Rect(0, 0, 256, 128))
	h.ack(fr.id)

	// Input is clamped to the current monitor and tagged with it.
	h.send(map[string]any{"t": "mousemove", "x": 1000, "y": -3})
	ev := inj.waitFor(t, "move", 2*time.Second)
	if ev.x != 255 || ev.y != 0 || ev.mon.Index != 1 {
		t.Fatalf("move = %+v", ev)
	}
	h.send(map[string]any{"t": "mousedown", "button": 2, "x": 10.4, "y": 20.6})
	ev = inj.waitFor(t, "button", 2*time.Second)
	if ev.x != 10 || ev.y != 21 || ev.text != "down" {
		t.Fatalf("button = %+v", ev)
	}
	h.send(map[string]any{"t": "keydown", "code": "KeyA", "key": "a"})
	if ev = inj.waitFor(t, "key", 2*time.Second); ev.text != "KeyA/a" {
		t.Fatalf("key = %+v", ev)
	}
	h.send(map[string]any{"t": "paste", "text": "hello"})
	if ev = inj.waitFor(t, "paste", 2*time.Second); ev.text != "hello" {
		t.Fatalf("paste = %+v", ev)
	}
	h.send(map[string]any{"t": "ctrlaltdel"})
	inj.waitFor(t, "sas", 2*time.Second)

	// Quality is applied to later frames.
	h.send(map[string]any{"t": "quality", "q": 20})
	deadline := time.Now().Add(2 * time.Second)
	for h.sess.quality.Load() != 20 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if q := h.sess.quality.Load(); q != 20 {
		t.Fatalf("quality %d", q)
	}
	h.send(map[string]any{"t": "quality", "q": 500})
	deadline = time.Now().Add(2 * time.Second)
	for h.sess.quality.Load() != 100 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if q := h.sess.quality.Load(); q != 100 {
		t.Fatalf("quality clamp %d", q)
	}

	// Refresh: a full frame even though nothing changed.
	h.send(map[string]any{"t": "refresh"})
	fr, ok = h.readFrame(3 * time.Second)
	if !ok {
		t.Fatal("no frame after refresh")
	}
	coverage(t, rects(fr.tiles), image.Rect(0, 0, 256, 128))
	h.ack(fr.id)

	// Garbage and unknown messages are ignored, not fatal.
	if err := h.viewer.WriteMessage(websocket.TextMessage, []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	h.send(map[string]any{"t": "bogus"})
	if err := h.viewer.WriteMessage(websocket.BinaryMessage, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	h.send(map[string]any{"t": "refresh"})
	if _, ok = h.readFrame(3 * time.Second); !ok {
		t.Fatal("session died on hostile input")
	}
}

func TestSessionResolutionChange(t *testing.T) {
	old := monitorRecheck
	monitorRecheck = 50 * time.Millisecond
	t.Cleanup(func() { monitorRecheck = old })

	cap := &fakeCapturer{mons: twoMonitors()[:1]}
	h := startHarness(t, cap, &fakeInjector{}, 60)
	fr, ok := h.readFrame(3 * time.Second)
	if !ok {
		t.Fatal("no first frame")
	}
	h.ack(fr.id)

	cap.setMonitors([]monitor{{Index: 0, Bounds: image.Rect(0, 0, 400, 300), Primary: true}})
	fr, ok = h.readFrame(3 * time.Second)
	if !ok {
		t.Fatal("no frame after resolution change")
	}
	sc := fr.screen(t)
	if sc == nil || sc["w"] != 400.0 || sc["h"] != 300.0 {
		t.Fatalf("screen after resize = %v", sc)
	}
	coverage(t, rects(fr.tiles), image.Rect(0, 0, 400, 300))
	h.ack(fr.id)

	// Transient capture failures are retried, not fatal.
	cap.mu.Lock()
	cap.failNext = 3
	cap.mu.Unlock()
	cap.setChanging(true)
	fr, ok = h.readFrame(5 * time.Second)
	if !ok {
		t.Fatal("stream did not recover from capture failures")
	}
	h.ack(fr.id)
}

func TestSessionEndsWhenViewerCloses(t *testing.T) {
	cap := &fakeCapturer{mons: twoMonitors()[:1], changing: true}
	inj := &fakeInjector{}
	h := startHarness(t, cap, inj, 60)
	if _, ok := h.readFrame(3 * time.Second); !ok {
		t.Fatal("no first frame")
	}
	h.viewer.Close()
	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("run returned %v on viewer close", err)
	}
	inj.mu.Lock()
	defer inj.mu.Unlock()
	if inj.closed {
		t.Fatal("the session must not close the injector; Serve owns it")
	}
}

func TestSessionEndsOnContextCancel(t *testing.T) {
	cap := &fakeCapturer{mons: twoMonitors()[:1]}
	h := startHarness(t, cap, &fakeInjector{}, 60)
	if _, ok := h.readFrame(3 * time.Second); !ok {
		t.Fatal("no first frame")
	}
	h.cancel()
	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("run returned %v on cancel", err)
	}
	// The viewer sees the socket close.
	select {
	case <-time.After(2 * time.Second):
		t.Fatal("viewer socket still open after the helper stopped")
	case _, open := <-h.msgs:
		for open {
			_, open = <-h.msgs
		}
	}
}

// Cancelling mid-frame is still just a stop. The capture loop learns about
// cancellation from the error sendFrame returns once the frame is on the
// wire, so a viewer that disappears while tiles are being written used to
// make run report "context canceled" - and the helper process exit with an
// error - for what is the ordinary end of every session. The hook lands the
// cancellation inside the capture that precedes a send, which is the window
// TestSessionEndsWhenViewerCloses only hits under load.
func TestSessionCancelledMidFrameReportsNoError(t *testing.T) {
	cap := &fakeCapturer{mons: twoMonitors()[:1], changing: true}
	h := startHarness(t, cap, &fakeInjector{}, 60)
	if _, ok := h.readFrame(3 * time.Second); !ok {
		t.Fatal("no first frame")
	}
	var once sync.Once
	cap.setHook(func() { once.Do(h.cancel) })
	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("run returned %v when the session was cancelled mid-frame", err)
	}
}

func TestSessionKeepalive(t *testing.T) {
	oldPing, oldRead := pingInterval, readTimeout
	pingInterval, readTimeout = 40*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { pingInterval, readTimeout = oldPing, oldRead })

	// A viewer whose transport answers pings (gorilla's default handler)
	// keeps the session alive well past readTimeout even though it sends
	// no messages of its own and the screen never changes.
	var pings atomic.Int32
	cap := &fakeCapturer{mons: twoMonitors()[:1]}
	h := startHarnessWith(t, cap, &fakeInjector{}, 60, func(viewer *websocket.Conn) {
		def := viewer.PingHandler()
		viewer.SetPingHandler(func(data string) error {
			pings.Add(1)
			return def(data)
		})
	})
	if _, ok := h.readFrame(3 * time.Second); !ok {
		t.Fatal("no first frame")
	}
	if err := h.wait(3 * readTimeout); !errors.Is(err, errTimeout) {
		t.Fatalf("session ended (%v) although the viewer answered pings", err)
	}
	if pings.Load() == 0 {
		t.Fatal("the helper never pinged the viewer")
	}
	h.cancel()
	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("run returned %v on cancel", err)
	}

	// A peer that stopped answering (a dead link the OS has not noticed)
	// must end the session after readTimeout instead of leaving the helper
	// running in the user's session forever.
	cap = &fakeCapturer{mons: twoMonitors()[:1]}
	h = startHarnessWith(t, cap, &fakeInjector{}, 60, func(viewer *websocket.Conn) {
		viewer.SetPingHandler(func(string) error { return nil })
	})
	if _, ok := h.readFrame(3 * time.Second); !ok {
		t.Fatal("no first frame")
	}
	start := time.Now()
	err := h.wait(10 * readTimeout)
	if errors.Is(err, errTimeout) {
		t.Fatal("session survived a silent peer")
	}
	if err != nil {
		t.Fatalf("silent peer ended the session with %v, want nil (a normal end)", err)
	}
	if took := time.Since(start); took < readTimeout/2 {
		t.Fatalf("session ended after %v, before the read timeout could expire", took)
	}
}

// fakeFollower stands in for the platform's input-desktop tracker: it works
// for failAt calls and then reports the desktop as unreachable, which is
// what a Windows lock screen or a UAC secure desktop does to a helper that
// is not SYSTEM.
type fakeFollower struct {
	calls  int
	failAt int
	err    error
}

func (f *fakeFollower) follow() error {
	f.calls++
	if f.calls > f.failAt {
		return f.err
	}
	return nil
}

func (f *fakeFollower) close() {}

// A desktop the helper cannot follow must end the session with a message
// the viewer can act on — never a silently frozen picture of the old
// desktop.
func TestSessionEndsWhenTheInputDesktopIsUnreachable(t *testing.T) {
	locked := errors.New("session locked or secure desktop active; reconnect to attach as SYSTEM")
	old := newFollower
	newFollower = func() desktopFollower { return &fakeFollower{failAt: 1, err: locked} }
	t.Cleanup(func() { newFollower = old })

	cap := &fakeCapturer{mons: twoMonitors()[:1], changing: true}
	h := startHarness(t, cap, &fakeInjector{}, 60)

	deadline := time.After(5 * time.Second)
	var got string
	for got == "" {
		select {
		case <-deadline:
			t.Fatal("no error message reached the viewer")
		case msg, open := <-h.msgs:
			if !open {
				t.Fatal("socket closed without an error message")
			}
			if msg.mt != websocket.TextMessage {
				continue
			}
			var v map[string]any
			if err := json.Unmarshal(msg.data, &v); err != nil {
				t.Fatalf("bad text frame %q", msg.data)
			}
			if v["t"] == "error" {
				got, _ = v["message"].(string)
			}
		}
	}
	if !strings.Contains(got, "reconnect to attach as SYSTEM") {
		t.Fatalf("error message = %q", got)
	}
	if err := h.wait(5 * time.Second); !errors.Is(err, locked) {
		t.Fatalf("run returned %v", err)
	}
}

// The viewer's messages split in two: control (ack, quality, monitor,
// refresh) and input (pointer, keys, paste, SAS). Only the second half moves
// the remote machine, and an observe-only session is exactly the first half
// — a gate that lets control through and drops input streams a live screen
// without touching it. This pins that split from the helper's side: the
// control messages must reach the capture loop and never the injector, so a
// filter that mirrors this list cannot be defeated by a control message and
// cannot break a view-only session's picture.
func TestSessionControlMessagesNeverReachTheInjector(t *testing.T) {
	cap := &fakeCapturer{mons: twoMonitors()}
	inj := &fakeInjector{}
	h := startHarness(t, cap, inj, 60)

	fr, ok := h.readFrame(3 * time.Second)
	if !ok {
		t.Fatal("no first frame")
	}
	h.ack(fr.id)

	// Every control message the protocol defines, plus one the helper does
	// not know: none of them is input.
	h.send(map[string]any{"t": "quality", "q": 40})
	h.send(map[string]any{"t": "monitor", "index": 1})
	if fr, ok = h.readFrame(3 * time.Second); !ok {
		t.Fatal("no frame after the monitor switch")
	}
	if sc := fr.screen(t); sc == nil || sc["monitor"] != 1.0 {
		t.Fatalf("screen after switch = %v", sc)
	}
	h.ack(fr.id)
	h.send(map[string]any{"t": "refresh"})
	if fr, ok = h.readFrame(3 * time.Second); !ok {
		t.Fatal("no frame after refresh")
	}
	h.ack(fr.id)
	h.send(map[string]any{"t": "bogus", "x": 5, "y": 5})

	// A round trip after the last control message: the input loop has had
	// its turn by the time this frame arrives.
	h.send(map[string]any{"t": "refresh"})
	if fr, ok = h.readFrame(3 * time.Second); !ok {
		t.Fatal("no frame after the final refresh")
	}
	h.ack(fr.id)

	inj.mu.Lock()
	events := append([]injected(nil), inj.events...)
	inj.mu.Unlock()
	if len(events) != 0 {
		t.Fatalf("control messages injected %d event(s): %+v", len(events), events)
	}

	// ... and the session is still healthy: input after the control run is
	// injected as usual, so the split is a split and not a dead injector.
	h.send(map[string]any{"t": "mousemove", "x": 10, "y": 20})
	if ev := inj.waitFor(t, "move", 2*time.Second); ev.x != 10 || ev.y != 20 {
		t.Fatalf("move = %+v", ev)
	}
}
