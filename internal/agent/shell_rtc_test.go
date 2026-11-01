package agent

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/pion/webrtc/v4"
)

// fakePTY is a ptySession backed by channels: out feeds Read, writes and
// resizes are recorded. With gen set, Read produces 32 KiB of 'x' forever.
type fakePTY struct {
	out    chan []byte
	closed chan struct{}
	once   sync.Once
	gen    bool

	mu      sync.Mutex
	written bytes.Buffer
	cols    int
	rows    int
}

func newFakePTY() *fakePTY {
	return &fakePTY{out: make(chan []byte, 16), closed: make(chan struct{})}
}

func (f *fakePTY) Read(p []byte) (int, error) {
	if f.gen {
		select {
		case <-f.closed:
			return 0, io.EOF
		default:
		}
		n := len(p)
		if n > 32<<10 {
			n = 32 << 10
		}
		for i := 0; i < n; i++ {
			p[i] = 'x'
		}
		return n, nil
	}
	select {
	case b := <-f.out:
		return copy(p, b), nil
	case <-f.closed:
		return 0, io.EOF
	}
}

func (f *fakePTY) Write(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.written.Write(b)
}

func (f *fakePTY) Resize(cols, rows int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cols, f.rows = cols, rows
	return nil
}

func (f *fakePTY) Close() error { f.once.Do(func() { close(f.closed) }); return nil }

func (f *fakePTY) got() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.written.String()
}

func (f *fakePTY) size() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cols, f.rows
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// rtcHarness wires a manager session to a loopback pion viewer, playing the
// part of the server and the browser.
type rtcHarness struct {
	t      *testing.T
	m      *shellManager
	pty    *fakePTY
	viewer *webrtc.PeerConnection
	term   *webrtc.DataChannel

	mu       sync.Mutex
	relay    bytes.Buffer // ShellChunk.Data seen on the stream
	signals  []string     // Sig kinds in arrival order
	eof      chan struct{}
	dcMu     sync.Mutex
	dcData   bytes.Buffer // binary bytes the viewer received
	dcOpened chan struct{}
	dcSlow   time.Duration
	pre      string // output fed and seen on the relay before the offer
}

const testSession = "s1"

func newRTCHarness(t *testing.T, gen bool) *rtcHarness {
	t.Helper()
	old := defaultShellICE
	defaultShellICE = []string{"stun:127.0.0.1:1"}
	t.Cleanup(func() { defaultShellICE = old })

	h := &rtcHarness{t: t, m: newShellManager(), pty: newFakePTY(), eof: make(chan struct{}), dcOpened: make(chan struct{})}
	h.pty.gen = gen
	viewer, err := webrtc.NewAPI().NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { viewer.Close() })
	h.viewer = viewer
	h.term, err = viewer.CreateDataChannel("term", &webrtc.DataChannelInit{Ordered: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	h.term.OnOpen(func() { close(h.dcOpened) })
	h.term.OnMessage(h.onDC)
	viewer.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		b, _ := json.Marshal(c.ToJSON())
		h.m.rtcSignal(protocol.ShellRTC{Session: testSession, Kind: "candidate", Candidate: b})
	})
	return h
}

func boolPtr(b bool) *bool { return &b }

func (h *rtcHarness) onDC(msg webrtc.DataChannelMessage) {
	if h.dcSlow > 0 {
		time.Sleep(h.dcSlow)
	}
	h.dcMu.Lock()
	defer h.dcMu.Unlock()
	if !msg.IsString {
		h.dcData.Write(msg.Data)
	}
}

func (h *rtcHarness) dcGot() string {
	h.dcMu.Lock()
	defer h.dcMu.Unlock()
	return h.dcData.String()
}

func (h *rtcHarness) relayGot() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.relay.String()
}

func (h *rtcHarness) sigs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.signals...)
}

func (h *rtcHarness) stream(id string, v any) error {
	chunk, ok := v.(protocol.ShellChunk)
	if !ok {
		return nil
	}
	if sig := chunk.Sig; sig != nil {
		h.mu.Lock()
		h.signals = append(h.signals, sig.Kind)
		h.mu.Unlock()
		switch sig.Kind {
		case "answer":
			go func() {
				if err := h.viewer.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: sig.SDP}); err != nil {
					h.t.Errorf("viewer answer: %v", err)
				}
			}()
		case "candidate":
			var init webrtc.ICECandidateInit
			json.Unmarshal(sig.Candidate, &init)
			go func() {
				// The answer is applied on another goroutine; retry until the
				// remote description exists.
				for i := 0; i < 200; i++ {
					if h.viewer.RemoteDescription() != nil {
						h.viewer.AddICECandidate(init)
						return
					}
					time.Sleep(5 * time.Millisecond)
				}
			}()
		}
		return nil
	}
	h.mu.Lock()
	h.relay.WriteString(chunk.Data)
	h.mu.Unlock()
	return nil
}

func (h *rtcHarness) reply(id string, v any) error {
	if c, ok := v.(protocol.ShellChunk); ok && c.EOF {
		close(h.eof)
	}
	return nil
}

// start attaches the session and runs the offer; it returns once the viewer's
// term channel is open.
func (h *rtcHarness) start() {
	h.t.Helper()
	h.m.attach(testSession, h.pty, protocol.ShellOpen{RTC: true}, h.stream, h.reply)
	if h.pre != "" {
		h.pty.out <- []byte(h.pre)
		waitFor(h.t, "relay output", func() bool { return strings.Contains(h.relayGot(), h.pre) })
	}
	offer, err := h.viewer.CreateOffer(nil)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.viewer.SetLocalDescription(offer); err != nil {
		h.t.Fatal(err)
	}
	if err := h.m.rtcSignal(protocol.ShellRTC{Session: testSession, Kind: "offer", SDP: offer.SDP}); err != nil {
		h.t.Fatalf("offer: %v", err)
	}
	select {
	case <-h.dcOpened:
	case <-time.After(15 * time.Second):
		h.t.Fatal("data channel never opened")
	}
}

func (h *rtcHarness) rtc() *shellRTC {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	return h.m.rtcs[testSession]
}

func (h *rtcHarness) waitSwitched() {
	h.t.Helper()
	waitFor(h.t, "output switch", func() bool { return h.rtc() != nil && h.rtc().sink.Load() != nil })
}

func TestShellRTCSwitchInputOutputResizeAndRevert(t *testing.T) {
	h := newRTCHarness(t, false)
	defer h.m.closeAll()
	// Output before the switch uses the relay.
	h.pre = "pre-"
	h.start()

	h.waitSwitched()
	sigs := h.sigs()
	if len(sigs) == 0 || sigs[len(sigs)-1] != "switch" && !contains(sigs, "switch") {
		t.Fatalf("no switch signal on the stream: %v", sigs)
	}
	if !contains(sigs, "answer") {
		t.Fatalf("no answer signal: %v", sigs)
	}

	// Binary input reaches the pty.
	if err := h.term.Send([]byte("ls\r")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "pty input", func() bool { return h.pty.got() == "ls\r" })

	// Resize arrives as JSON text.
	if err := h.term.SendText(`{"t":"resize","cols":91,"rows":33}`); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "resize", func() bool { c, r := h.pty.size(); return c == 91 && r == 33 })

	// Output now goes over the channel, not the relay, byte for byte
	// (including bytes that are not valid UTF-8).
	raw := []byte{0xff, 0xfe, 'o', 'k', 0x00, 0x80}
	h.pty.out <- raw
	waitFor(t, "dc output", func() bool { return h.dcGot() == string(raw) })
	if strings.Contains(h.relayGot(), "ok") {
		t.Fatalf("output leaked onto the relay after the switch: %q", h.relayGot())
	}

	// Closing the channel reverts output to the relay.
	h.term.Close()
	waitFor(t, "revert", func() bool { return h.rtc().sink.Load() == nil })
	h.pty.out <- []byte("after")
	waitFor(t, "relay after revert", func() bool { return strings.Contains(h.relayGot(), "after") })
}

func TestShellRTCFallbackSignalReverts(t *testing.T) {
	h := newRTCHarness(t, false)
	defer h.m.closeAll()
	h.start()
	h.waitSwitched()
	if err := h.m.rtcSignal(protocol.ShellRTC{Session: testSession, Kind: "fallback"}); err != nil {
		t.Fatal(err)
	}
	if h.rtc().sink.Load() != nil {
		t.Fatal("sink still set after fallback")
	}
	h.pty.out <- []byte("relay-again")
	waitFor(t, "relay output", func() bool { return strings.Contains(h.relayGot(), "relay-again") })
	// A second offer is refused: one peer connection per session.
	if err := h.m.rtcSignal(protocol.ShellRTC{Session: testSession, Kind: "offer", SDP: "v=0"}); err == nil {
		t.Fatal("second offer accepted")
	}
}

func TestShellRTCIgnoresOtherChannels(t *testing.T) {
	h := newRTCHarness(t, false)
	defer h.m.closeAll()
	h.start()
	h.waitSwitched()

	other, err := h.viewer.CreateDataChannel("other", nil)
	if err != nil {
		t.Fatal(err)
	}
	dup, err := h.viewer.CreateDataChannel("term", nil)
	if err != nil {
		t.Fatal(err)
	}
	opened := make(chan struct{}, 2)
	other.OnOpen(func() { opened <- struct{}{} })
	dup.OnOpen(func() { opened <- struct{}{} })
	for i := 0; i < 2; i++ {
		select {
		case <-opened:
		case <-time.After(10 * time.Second):
			t.Fatal("extra channels never opened")
		}
	}
	other.Send([]byte("EVIL-other"))
	dup.Send([]byte("EVIL-dup"))
	time.Sleep(200 * time.Millisecond)
	h.term.Send([]byte("good"))
	waitFor(t, "pty input", func() bool { return strings.Contains(h.pty.got(), "good") })
	if got := h.pty.got(); got != "good" {
		t.Fatalf("pty received %q, want only the accepted channel's bytes", got)
	}
}

func TestShellRTCUnknownSessionRefused(t *testing.T) {
	m := newShellManager()
	for _, kind := range []string{"offer", "candidate", "fallback"} {
		err := m.rtcSignal(protocol.ShellRTC{Session: "nope", Kind: kind, SDP: "v=0"})
		if err != errNoShell {
			t.Fatalf("%s for unknown session: err = %v, want errNoShell", kind, err)
		}
	}
	// A session opened without RTC refuses signals too.
	h := newRTCHarness(t, false)
	h.m.attach("plain", h.pty, protocol.ShellOpen{}, h.stream, h.reply)
	defer h.m.closeAll()
	if err := h.m.rtcSignal(protocol.ShellRTC{Session: "plain", Kind: "offer", SDP: "v=0"}); err != errNoShell {
		t.Fatalf("offer for non-RTC session: %v", err)
	}
}

func TestShellRTCBadOfferSignalsUnavailable(t *testing.T) {
	h := newRTCHarness(t, false)
	defer h.m.closeAll()
	h.m.attach(testSession, h.pty, protocol.ShellOpen{RTC: true}, h.stream, h.reply)
	if err := h.m.rtcSignal(protocol.ShellRTC{Session: testSession, Kind: "offer", SDP: "this is not sdp"}); err == nil {
		t.Fatal("garbage offer accepted")
	}
	if !contains(h.sigs(), "unavailable") {
		t.Fatalf("no unavailable signal: %v", h.sigs())
	}
}

// A fast pty on a slow channel must neither grow without bound nor wedge the
// session: closing it while the writer is waiting on backpressure ends the
// read loop promptly.
func TestShellRTCBackpressureDoesNotDeadlockOnClose(t *testing.T) {
	h := newRTCHarness(t, true)
	h.dcSlow = 2 * time.Millisecond
	// The generator must not start before the switch, or it would fill the relay.
	h.pty.gen = false
	h.start()
	h.waitSwitched()
	h.pty.gen = true
	h.pty.out <- []byte("kick") // wake the blocked Read so it sees gen

	waitFor(t, "channel traffic", func() bool { return len(h.dcGot()) > 2<<20 })
	if got := h.rtc().sink.Load(); got != nil && got.dc.BufferedAmount() > shellDCHigh+shellDCChunk {
		t.Fatalf("buffered amount %d exceeded the high-water mark", got.dc.BufferedAmount())
	}
	h.m.close(testSession)
	select {
	case <-h.eof:
	case <-time.After(10 * time.Second):
		t.Fatal("pty read loop did not end after close while waiting on backpressure")
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func TestShellRTCDrainWaitsForBufferedTail(t *testing.T) {
	h := newRTCHarness(t, false)
	h.dcSlow = time.Millisecond
	h.start()
	h.waitSwitched()

	var tail string
	for i := 0; i < 8; i++ {
		piece := strings.Repeat("x", 30<<10)
		if i == 7 {
			piece += "LAST-PROMPT$ "
		}
		tail += piece
		h.pty.out <- []byte(piece)
	}
	// Close only once the read loop has taken every piece, then simulate the
	// shell exiting: the loop drains, closes the PeerConnection, replies EOF.
	waitFor(t, "pty reads", func() bool { return len(h.pty.out) == 0 })
	h.pty.Close()
	select {
	case <-h.eof:
	case <-time.After(10 * time.Second):
		t.Fatal("no EOF reply")
	}
	// The viewer handler is slow, so give delivery time; what must not happen
	// is the PeerConnection having been closed with the tail still buffered.
	waitFor(t, "full tail on the channel", func() bool { return len(h.dcGot()) >= len(tail) })
	if got := h.dcGot(); !strings.HasSuffix(got, "LAST-PROMPT$ ") {
		t.Fatalf("tail lost on close: received %d of %d bytes", len(got), len(tail))
	}
}
