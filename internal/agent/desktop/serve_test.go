package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"image"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// blockingCapturer's monitors() waits for release, like a Wayland capturer
// waiting for the screen-share prompt.
type blockingCapturer struct {
	events  *eventLog
	release chan struct{}
	err     error
	closed  chan struct{}
	once    sync.Once
}

func (b *blockingCapturer) monitors() ([]monitor, error) {
	b.events.add("monitors")
	select {
	case <-b.release:
	case <-b.closed:
		return nil, errCapturerClosed
	}
	if b.err != nil {
		return nil, b.err
	}
	return []monitor{{Index: 0, Bounds: image.Rect(0, 0, 64, 64), Primary: true}}, nil
}

func (b *blockingCapturer) capture(m monitor) (*image.RGBA, error) {
	return image.NewRGBA(image.Rect(0, 0, 64, 64)), nil
}

func (b *blockingCapturer) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

type eventLog struct {
	mu sync.Mutex
	ev []string
}

func (l *eventLog) add(e string) { l.mu.Lock(); l.ev = append(l.ev, e); l.mu.Unlock() }
func (l *eventLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.ev...)
}

// serveRig is a bridge-side websocket server plus fake platform deps.
type serveRig struct {
	srv    *httptest.Server
	msgs   chan map[string]any
	events *eventLog
	cap    *blockingCapturer
	deps   serveDeps
}

func newServeRig(t *testing.T, notice string) *serveRig {
	t.Helper()
	r := &serveRig{msgs: make(chan map[string]any, 64), events: &eventLog{}}
	r.cap = &blockingCapturer{events: r.events, release: make(chan struct{}), closed: make(chan struct{})}
	up := websocket.Upgrader{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		c, err := up.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			mt, data, err := c.ReadMessage()
			if err != nil {
				return
			}
			if mt != websocket.TextMessage {
				continue
			}
			var m map[string]any
			if json.Unmarshal(data, &m) == nil {
				r.msgs <- m
			}
		}
	}))
	t.Cleanup(r.srv.Close)
	r.deps = serveDeps{
		platformInit: func() error { r.events.add("platformInit"); return nil },
		newInjector:  func() (injector, error) { r.events.add("newInjector"); return &fakeInjector{}, nil },
		newCapturer:  func() capturer { r.events.add("newCapturer"); return r.cap },
		newBackstage: func() (capturer, injector, error) { return nil, nil, errors.New("no backstage") },
		dial: func(ctx context.Context, url, fp string) (*websocket.Conn, error) {
			r.events.add("dial")
			return dial(ctx, url, fp)
		},
		setupNotice: func() string { return notice },
		showBanner:  func() func() { return func() {} },
	}
	return r
}

func (r *serveRig) cfg() Config {
	return Config{ServerURL: "http" + strings.TrimPrefix(r.srv.URL, "http"), Token: "tok", Quality: 60}
}

func (r *serveRig) next(t *testing.T) map[string]any {
	t.Helper()
	select {
	case m := <-r.msgs:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no message from the helper within 5s")
		return nil
	}
}

func TestServeDialsBeforeCapturerSetupAndTellsViewer(t *testing.T) {
	const notice = "Waiting for the person at rmm-wayland to allow screen sharing"
	r := newServeRig(t, notice)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, r.cfg(), r.deps) }()

	// The note arrives while monitors() is still blocked: the helper is
	// connected and the viewer is informed during the prompt.
	m := r.next(t)
	if m["t"] != "note" || m["message"] != notice || m["pending"] != true {
		t.Fatalf("first message = %v", m)
	}
	ev := r.events.all()
	if len(ev) == 0 || ev[0] != "dial" {
		t.Fatalf("dial must come first, got %v", ev)
	}
	idx := func(name string) int {
		for i, e := range ev {
			if e == name {
				return i
			}
		}
		return -1
	}
	if !(idx("dial") < idx("platformInit") && idx("newInjector") < idx("newCapturer")) {
		t.Fatalf("order = %v", ev)
	}

	close(r.cap.release)
	if m := r.next(t); m["t"] != "note" || m["message"] != "" || m["pending"] != true {
		t.Fatalf("expected the pending note to be withdrawn, got %v", m)
	}
	if m := r.next(t); m["t"] != "screen" {
		t.Fatalf("expected the screen message, got %v", m)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop after cancel")
	}
}

func TestServeNoNoticeWhenSetupDoesNotWait(t *testing.T) {
	r := newServeRig(t, "")
	close(r.cap.release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go serve(ctx, r.cfg(), r.deps)
	if m := r.next(t); m["t"] != "screen" {
		t.Fatalf("first message = %v, want screen", m)
	}
}

func TestServeCapturerFailureReportedAfterDial(t *testing.T) {
	r := newServeRig(t, "Waiting for the person at x to allow screen sharing")
	r.cap.err = errors.New("the user cancelled the screen-sharing request")
	close(r.cap.release)
	done := make(chan error, 1)
	go func() { done <- serve(context.Background(), r.cfg(), r.deps) }()
	var got map[string]any
	for {
		m := r.next(t)
		if m["t"] == "error" {
			got = m
			break
		}
	}
	if !strings.Contains(got["message"].(string), "cancelled") {
		t.Fatalf("error message = %v", got)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("serve returned nil after a capturer failure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return")
	}
}

func TestServeCancelDuringPromptClosesCapturer(t *testing.T) {
	r := newServeRig(t, "Waiting for the person at x to allow screen sharing")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, r.cfg(), r.deps) }()
	r.next(t) // the pending note: set-up is now blocked
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serve stayed blocked in capturer set-up after cancel")
	}
	select {
	case <-r.cap.closed:
	default:
		t.Fatal("capturer was not closed")
	}
}

func TestServeDialFailureSkipsSetup(t *testing.T) {
	r := newServeRig(t, "")
	r.deps.dial = func(ctx context.Context, url, fp string) (*websocket.Conn, error) {
		r.events.add("dial")
		return nil, errors.New("HTTP 401")
	}
	if err := serve(context.Background(), r.cfg(), r.deps); err == nil {
		t.Fatal("expected the dial error")
	}
	if ev := r.events.all(); len(ev) != 1 {
		t.Fatalf("nothing but the dial may run after a failed dial, got %v", ev)
	}
}

func TestSetupNoticeText(t *testing.T) {
	if got := setupNoticeFor("rmm-wayland"); got != "Waiting for the person at rmm-wayland to allow screen sharing" {
		t.Fatalf("got %q", got)
	}
}
