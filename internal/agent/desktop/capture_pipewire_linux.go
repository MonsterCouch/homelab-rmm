//go:build linux

package desktop

// Wayland screen capture through the XDG ScreenCast portal and PipeWire.
//
// WHAT IS IMPLEMENTED
//
// The portal negotiation, in pure Go over godbus: CreateSession,
// SelectSources (types=MONITOR, persist_mode=2 so the grant is remembered),
// Start, and OpenPipeWireRemote (a file descriptor for a private PipeWire
// connection). The restore_token from Start is saved (see restoreTokenPath)
// and offered on the next SelectSources, so an unattended session is restored
// without a prompt where the compositor supports it.
//
// Frames are read by a pure-Go PipeWire client, with no CGO and no
// libpipewire. The pieces, all under internal/agent/desktop/pipewire:
//
//	pod     the SPA POD binary format (bytes only, tested everywhere)
//	proto   the native protocol over the portal's fd (SCM_RIGHTS), behind a
//	        Transport interface
//	stream  one video input stream, a client-node object that links to the
//	        portal's node, negotiates a raw format, maps the buffers and
//	        copies each frame out as *image.RGBA; shared memory and eventfds
//	        sit behind the Mem and Signal interfaces, so the state machine is
//	        tested on Windows against a fake server
//
// pipewireCapturer opens the transport on the OpenPipeWireRemote fd once and
// starts one stream per portal node, lazily, on the first capture of that
// monitor. capture returns the newest frame. The first call waits up to
// firstFrameTimeout for a frame to arrive; later calls return the newest
// frame without waiting, so a screen that has not changed returns the same
// image. A first-frame timeout is transient (GNOME and KDE send buffers only
// on damage) and breaks nothing. A stream error or a failed Open marks that
// node broken, and waylandCapturer then closes the capturer and switches to
// the screenshot fallback. The same happens when the portal sends
// Session.Closed (the share was revoked or the portal restarted) and when a
// running stream has sent no frame for staleFrameLimit, which cannot be told
// apart from a screen that stays idle. While on the fallback, a goroutine
// probes the portal again with a growing delay, but only when a restore token
// is saved, so no approval dialog appears unasked; when a probe works,
// PipeWire is used again. The monitor sizes are corrected from the first frame
// of each stream, because the portal reports logical sizes and the stream
// delivers pixels. Close cancels a portal negotiation in progress and is not
// treated as a failure.
//
// SELECTION AND THE KILL SWITCH
//
// newWaylandCapturer starts the portal by default. RMM_WAYLAND_PORTAL=0 turns
// it off and goes straight to the fallback; any other value, including 1,
// means the default. On any portal or stream failure, at start-up or later,
// it logs one line with the reason and uses screenCapturer (kbinani, which on
// a Wayland session takes real pixels from the Screenshot portal and uses
// Xwayland for geometry). Without a DISPLAY there is no fallback and the
// error is returned. The pure parts of the decision are in
// capture_pipewire_select.go and are tested on every platform.
//
// NOT VERIFIED
//
// None of this has run against a real compositor or PipeWire daemon. The
// portal code was written against the specification and the stream against
// PipeWire's source; both are tested only with fakes. The first run on GNOME
// or KDE with RMM_DEBUG=1 is the check. Open questions are listed in
// docs/plans/2026-10-25-loose-ends.md and the stream package's notes, mainly
// whether the server accepts a client-node created through the portal's
// restricted connection and links it to the portal node.

import (
	"context"
	"errors"
	"fmt"
	"image"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/proto"
	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/stream"
)

// pipewireIngestImplemented says whether pipewireCapturer.capture can produce
// frames.
const pipewireIngestImplemented = true

const (
	// firstFrameTimeout bounds the wait for a stream's first frame.
	firstFrameTimeout = 2 * time.Second
	// streamOpenTimeout bounds stream.Open (Hello, CreateObject, negotiation
	// up to Command Start).
	streamOpenTimeout = 10 * time.Second
)

// waylandMode is set by platformInit when the helper serves a Wayland
// session; input selection (preferUinput) and capture selection read it.
var waylandMode atomic.Bool

const (
	portalName        = "org.freedesktop.portal.Desktop"
	portalPath        = dbus.ObjectPath("/org/freedesktop/portal/desktop")
	ifaceScreenCast   = "org.freedesktop.portal.ScreenCast"
	ifacePortalReq    = "org.freedesktop.portal.Request"
	ifacePortalSess   = "org.freedesktop.portal.Session"
	sourceTypeMonitor = uint32(1)
	cursorEmbedded    = uint32(2)
	persistUntilRevok = uint32(2) // persist_mode: keep until the user revokes
	persistMinVersion = 4         // ScreenCast interface version that has persist_mode

	startTimeout   = 2 * time.Minute // the user may have to pick a screen
	requestTimeout = 30 * time.Second
)

// ---- message construction (pure; unit tested) ----

// requestPath is the object path the portal gives a request, derived from the
// caller's unique bus name and handle_token, so the Response signal can be
// matched before the method call returns.
func requestPath(uniqueName, token string) dbus.ObjectPath {
	sender := strings.ReplaceAll(strings.TrimPrefix(uniqueName, ":"), ".", "_")
	return dbus.ObjectPath("/org/freedesktop/portal/desktop/request/" + sender + "/" + token)
}

func createSessionOptions(handleToken, sessionToken string) map[string]dbus.Variant {
	return map[string]dbus.Variant{
		"handle_token":         dbus.MakeVariant(handleToken),
		"session_handle_token": dbus.MakeVariant(sessionToken),
	}
}

// selectSourcesOptions asks for one monitor, remembered across sessions. The
// persist options are only valid on interface version >= persistMinVersion;
// older portals reject unknown options, so the caller passes persist=false.
func selectSourcesOptions(handleToken, restoreToken string, persist bool) map[string]dbus.Variant {
	o := map[string]dbus.Variant{
		"handle_token": dbus.MakeVariant(handleToken),
		"types":        dbus.MakeVariant(sourceTypeMonitor),
		"multiple":     dbus.MakeVariant(false),
		"cursor_mode":  dbus.MakeVariant(cursorEmbedded),
	}
	if persist {
		o["persist_mode"] = dbus.MakeVariant(persistUntilRevok)
		if restoreToken != "" {
			o["restore_token"] = dbus.MakeVariant(restoreToken)
		}
	}
	return o
}

func startOptions(handleToken string) map[string]dbus.Variant {
	return map[string]dbus.Variant{"handle_token": dbus.MakeVariant(handleToken)}
}

// parseStreams decodes Start's results: streams (a(ua{sv})) and the optional
// restore_token (s).
func parseStreams(results map[string]dbus.Variant) (streams []pwStream, restoreToken string, err error) {
	if v, ok := results["restore_token"]; ok {
		restoreToken, _ = v.Value().(string)
	}
	sv, ok := results["streams"]
	if !ok {
		return nil, restoreToken, errors.New("portal Start returned no streams")
	}
	var raw []struct {
		Node  uint32
		Props map[string]dbus.Variant
	}
	if err := sv.Store(&raw); err != nil {
		return nil, restoreToken, fmt.Errorf("decode portal streams: %w", err)
	}
	for _, r := range raw {
		s := pwStream{Node: r.Node}
		pos, hasPos := variantPair(r.Props["position"])
		size, hasSize := variantPair(r.Props["size"])
		if hasSize && size[0] > 0 && size[1] > 0 {
			if !hasPos {
				pos = [2]int32{}
			}
			s.Bounds = image.Rect(int(pos[0]), int(pos[1]), int(pos[0]+size[0]), int(pos[1]+size[1]))
		}
		streams = append(streams, s)
	}
	if len(streams) == 0 {
		return nil, restoreToken, errors.New("portal Start returned an empty stream list")
	}
	return streams, restoreToken, nil
}

// variantPair reads an (ii) struct as the wire decoder delivers it.
func variantPair(v dbus.Variant) ([2]int32, bool) {
	f, ok := v.Value().([]interface{})
	if !ok || len(f) != 2 {
		return [2]int32{}, false
	}
	a, ok1 := f[0].(int32)
	b, ok2 := f[1].(int32)
	return [2]int32{a, b}, ok1 && ok2
}

// ---- restore token persistence ----

// restoreTokenPath is where the portal's restore_token is kept. agent.json
// lives in a root-owned directory (and holds the device key), while the helper
// runs as the session user and must not write there, so the token goes in the
// user's own config directory instead: $XDG_CONFIG_HOME/homelab-rmm/
// screencast-restore-token (mode 0600).
func restoreTokenPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "homelab-rmm", "screencast-restore-token"), nil
}

func loadRestoreToken() string {
	p, err := restoreTokenPath()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// saveRestoreToken replaces the stored token. Restore tokens are single use:
// every successful Start returns a fresh one that supersedes the last.
func saveRestoreToken(tok string) error {
	if tok == "" {
		return nil
	}
	p, err := restoreTokenPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(tok+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// ---- portal session ----

type portalConn struct {
	conn    *dbus.Conn
	obj     dbus.BusObject
	sigs    chan *dbus.Signal
	pending map[dbus.ObjectPath][]interface{} // Response bodies that arrived early
	tokens  int
}

func (p *portalConn) token(prefix string) string {
	p.tokens++
	return fmt.Sprintf("%s%d_%d", prefix, os.Getpid(), p.tokens)
}

// request performs one portal call that answers through a Request/Response
// signal. build receives the handle_token to embed in the options and returns
// the call's arguments.
func (p *portalConn) request(ctx context.Context, method string, timeout time.Duration, build func(handleToken string) []interface{}) (map[string]dbus.Variant, error) {
	tok := p.token("rmm")
	var handle dbus.ObjectPath
	if err := p.obj.CallWithContext(ctx, method, 0, build(tok)...).Store(&handle); err != nil {
		return nil, fmt.Errorf("%s: %w", method, err)
	}
	if expect := requestPath(p.conn.Names()[0], tok); handle != expect {
		slog.Debug("desktop: portal request handle differs from the predicted one", "got", handle, "want", expect)
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		if body, ok := p.pending[handle]; ok {
			delete(p.pending, handle)
			return decodeResponse(method, body)
		}
		select {
		case s := <-p.sigs:
			if s == nil {
				return nil, fmt.Errorf("%s: bus connection closed", method)
			}
			if s.Name == ifacePortalReq+".Response" {
				p.pending[s.Path] = s.Body
			}
		case <-ctx.Done():
			return nil, fmt.Errorf("%s: %w", method, ctx.Err())
		case <-deadline.C:
			return nil, fmt.Errorf("%s: no response from the portal within %s", method, timeout)
		}
	}
}

func decodeResponse(method string, body []interface{}) (map[string]dbus.Variant, error) {
	if len(body) != 2 {
		return nil, fmt.Errorf("%s: malformed portal response", method)
	}
	code, _ := body[0].(uint32)
	results, _ := body[1].(map[string]dbus.Variant)
	switch code {
	case 0:
		return results, nil
	case 1:
		return nil, fmt.Errorf("%s: the user cancelled the screen-sharing request", method)
	default:
		return nil, fmt.Errorf("%s: the portal ended the request (code %d)", method, code)
	}
}

// pipewireCapturer holds a negotiated ScreenCast session and the PipeWire
// connection opened on its fd. It satisfies capturer.
type pipewireCapturer struct {
	pc      *portalConn
	session dbus.ObjectPath
	streams []pwStream
	mons    []monitor
	conn    *proto.Conn // PipeWire connection from OpenPipeWireRemote; owns the fd
	closer  sync.Once

	mu     sync.Mutex
	opened map[uint32]*stream.Stream // by portal node id
	hello  bool                      // Core.Hello was sent by the first stream
	broken map[uint32]error          // by portal node id; set once, later captures of that node return it
	closed bool
	lost   error // set when the portal ends the session; every later capture returns it

	quit     chan struct{} // closed by Close; stops the signal watcher
	watching sync.WaitGroup

	monMu sync.Mutex // guards mons, which capture corrects from the frame size
}

// newPipeWireCapturer runs the portal negotiation and opens the PipeWire
// connection. It may block until the user approves the screen-share dialog
// (bounded by startTimeout) when no valid restore token exists. Cancelling ctx
// ends the wait. No stream is started yet.
func newPipeWireCapturer(ctx context.Context) (*pipewireCapturer, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, fmt.Errorf("connect to the session bus: %w", err)
	}
	pc := &portalConn{
		conn:    conn,
		obj:     conn.Object(portalName, portalPath),
		sigs:    make(chan *dbus.Signal, 32),
		pending: map[dbus.ObjectPath][]interface{}{},
	}
	c := &pipewireCapturer{pc: pc, opened: map[uint32]*stream.Stream{}, broken: map[uint32]error{}, quit: make(chan struct{})}
	fail := func(err error) (*pipewireCapturer, error) {
		c.Close()
		return nil, err
	}
	if err := conn.AddMatchSignal(dbus.WithMatchInterface(ifacePortalReq), dbus.WithMatchMember("Response")); err != nil {
		return fail(fmt.Errorf("subscribe to portal responses: %w", err))
	}
	conn.Signal(pc.sigs)

	ver, types, err := screenCastProps(pc.obj)
	if err != nil {
		return fail(fmt.Errorf("the ScreenCast portal is not available: %w", err))
	}
	if types&sourceTypeMonitor == 0 {
		return fail(errors.New("the ScreenCast portal cannot share monitors"))
	}
	persist := ver >= persistMinVersion

	res, err := pc.request(ctx, ifaceScreenCast+".CreateSession", requestTimeout, func(tok string) []interface{} {
		return []interface{}{createSessionOptions(tok, pc.token("rmms"))}
	})
	if err != nil {
		return fail(err)
	}
	switch h := res["session_handle"].Value().(type) {
	case string:
		c.session = dbus.ObjectPath(h)
	case dbus.ObjectPath:
		c.session = h
	}
	if c.session == "" {
		return fail(errors.New("CreateSession returned no session handle"))
	}
	// Session.Closed arrives when the user revokes the share or the portal or
	// compositor restarts; without it a dead session looks like an idle screen.
	if err := conn.AddMatchSignal(dbus.WithMatchInterface(ifacePortalSess), dbus.WithMatchMember("Closed"), dbus.WithMatchObjectPath(c.session)); err != nil {
		return fail(fmt.Errorf("subscribe to portal session close: %w", err))
	}

	restore := ""
	if persist {
		restore = loadRestoreToken()
	}
	if _, err := pc.request(ctx, ifaceScreenCast+".SelectSources", requestTimeout, func(tok string) []interface{} {
		return []interface{}{c.session, selectSourcesOptions(tok, restore, persist)}
	}); err != nil {
		return fail(err)
	}

	res, err = pc.request(ctx, ifaceScreenCast+".Start", startTimeout, func(tok string) []interface{} {
		return []interface{}{c.session, "", startOptions(tok)}
	})
	if err != nil {
		return fail(err)
	}
	streams, newToken, err := parseStreams(res)
	if err != nil {
		return fail(err)
	}
	c.streams = streams
	if persist && newToken != "" {
		if err := saveRestoreToken(newToken); err != nil {
			slog.Warn("desktop: could not save the screen-share restore token; the next session will prompt again", "err", err)
		}
	}

	var fd dbus.UnixFD
	if err := pc.obj.CallWithContext(ctx, ifaceScreenCast+".OpenPipeWireRemote", 0, c.session, map[string]dbus.Variant{}).Store(&fd); err != nil {
		return fail(fmt.Errorf("OpenPipeWireRemote: %w", err))
	}
	// The transport takes ownership of fd and closes it on failure.
	tr, err := proto.NewSocketTransport(int(fd))
	if err != nil {
		return fail(fmt.Errorf("open the PipeWire connection: %w", err))
	}
	c.conn = proto.NewConn(tr, proto.Config{CloseFd: proto.CloseFd})

	c.mons = monitorsFromStreams(streams)
	c.watching.Add(1)
	go c.watchSignals()
	slog.Info("desktop: ScreenCast portal session ready", "nodes", len(streams), "monitors", len(c.mons), "persist", persist)
	return c, nil
}

// watchSignals reads the bus signals after setup: Session.Closed for this
// session marks the capturer lost, and stray Request.Response signals are
// discarded so the channel never fills up.
func (c *pipewireCapturer) watchSignals() {
	defer c.watching.Done()
	for {
		select {
		case <-c.quit:
			return
		case s := <-c.pc.sigs:
			if s == nil {
				c.markLost(errors.New("the session bus connection closed"))
				return
			}
			if s.Name == ifacePortalSess+".Closed" && s.Path == c.session {
				c.markLost(errPortalSessionClosed)
			}
		}
	}
}

// markLost records that the session cannot deliver frames any more.
func (c *pipewireCapturer) markLost(err error) {
	c.mu.Lock()
	if c.lost == nil && !c.closed {
		c.lost = err
	}
	c.mu.Unlock()
}

// lostErr returns why the session ended, or nil.
func (c *pipewireCapturer) lostErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lost
}

// screenCastProps reads the interface version and the supported source types.
func screenCastProps(obj dbus.BusObject) (version uint32, types uint32, err error) {
	v, err := obj.GetProperty(ifaceScreenCast + ".version")
	if err != nil {
		return 0, 0, err
	}
	version, _ = v.Value().(uint32)
	if t, err := obj.GetProperty(ifaceScreenCast + ".AvailableSourceTypes"); err == nil {
		types, _ = t.Value().(uint32)
	} else {
		return 0, 0, err
	}
	return version, types, nil
}

func (c *pipewireCapturer) monitors() ([]monitor, error) {
	c.monMu.Lock()
	defer c.monMu.Unlock()
	if len(c.mons) == 0 {
		return nil, errors.New("the portal did not report a stream with a usable size")
	}
	return c.mons, nil
}

// noteFrameSize makes the monitor's bounds the size of the frame the stream
// delivers, so a scaled or HiDPI output does not disagree with its portal
// geometry forever.
func (c *pipewireCapturer) noteFrameSize(idx int, img *image.RGBA) {
	c.monMu.Lock()
	defer c.monMu.Unlock()
	if mons, changed := withFrameSize(c.mons, idx, img.Rect.Dx(), img.Rect.Dy()); changed {
		slog.Info("desktop: PipeWire frame size differs from the portal's monitor size; using the frame size",
			"monitor", idx, "frame", img.Rect.Size())
		c.mons = mons
	}
}

// streamFor returns the running stream for monitor m, starting it on first
// use. It holds c.mu while the stream opens (at most streamOpenTimeout), so a
// concurrent Close waits for that.
func (c *pipewireCapturer) streamFor(m monitor) (*stream.Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.conn == nil {
		return nil, errCapturerClosed
	}
	node, ok := nodeForMonitor(c.streams, m.Index)
	if !ok {
		return nil, fmt.Errorf("the portal has no PipeWire node for monitor %d", m.Index)
	}
	if err := c.broken[node]; err != nil {
		return nil, err
	}
	if st := c.opened[node]; st != nil {
		return st, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), streamOpenTimeout)
	defer cancel()
	st, err := stream.Open(ctx, c.conn, stream.Options{NodeID: node, SkipHello: c.hello})
	if err != nil {
		c.broken[node] = fmt.Errorf("open the PipeWire stream for node %d: %w", node, err)
		return nil, c.broken[node]
	}
	c.hello = true
	c.opened[node] = st
	return st, nil
}

// markBroken records the first failure of a node's stream and returns it. A
// failure of one monitor's stream does not affect the others.
func (c *pipewireCapturer) markBroken(node uint32, err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errCapturerClosed
	}
	if c.broken[node] == nil {
		c.broken[node] = err
	}
	return c.broken[node]
}

// capture returns the newest frame of the stream serving monitor m. The
// returned image is shared and must not be modified. It never returns a
// synthetic frame. A stream that is open but has sent nothing within
// firstFrameTimeout gives errNoFrameYet and stays usable; only an Open failure
// or a stream error marks that node broken.
func (c *pipewireCapturer) capture(m monitor) (*image.RGBA, error) {
	if err := c.lostErr(); err != nil {
		return nil, err
	}
	st, err := c.streamFor(m)
	if err != nil {
		return nil, err
	}
	node, _ := nodeForMonitor(c.streams, m.Index)
	if err := st.Err(); err != nil {
		return nil, c.markBroken(node, fmt.Errorf("PipeWire stream ended: %w", err))
	}
	img, _ := st.Latest()
	if img == nil {
		ctx, cancel := context.WithTimeout(context.Background(), firstFrameTimeout)
		defer cancel()
		img, _, err = st.Wait(ctx, 0)
		if err != nil {
			switch {
			case errors.Is(err, stream.ErrClosed):
				return nil, errCapturerClosed
			case errors.Is(err, context.DeadlineExceeded) && st.Err() == nil:
				return nil, noFrameYet(firstFrameTimeout)
			}
			return nil, c.markBroken(node, err)
		}
	}
	if streamStale(st.Running(), st.LastFrame(), time.Now(), staleFrameLimit) {
		return nil, c.markBroken(node, errStreamStalled)
	}
	c.noteFrameSize(m.Index, img)
	return img, nil
}

// Close stops the streams, closes the PipeWire connection, ends the portal
// session and releases the bus connection.
func (c *pipewireCapturer) Close() error {
	c.closer.Do(func() {
		c.mu.Lock()
		c.closed = true
		close(c.quit)
		open := c.opened
		c.opened = map[uint32]*stream.Stream{}
		c.mu.Unlock()
		for _, st := range open {
			st.Close()
		}
		if c.conn != nil {
			c.conn.Close()
		}
		if c.pc != nil && c.pc.conn != nil {
			if c.session != "" {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				c.pc.conn.Object(portalName, c.session).CallWithContext(ctx, ifacePortalSess+".Close", 0)
				cancel()
			}
			c.pc.conn.RemoveSignal(c.pc.sigs)
			c.pc.conn.Close()
			c.watching.Wait()
		}
	})
	return nil
}

// ---- Wayland capture selection ----

// waylandCapturer picks the capture backend lazily on first use (newCapturer
// cannot return an error, and Serve already treats a monitors() error as "no
// usable display"): PipeWire when the portal and a first frame work,
// otherwise the screenCapturer fallback if a DISPLAY exists, otherwise an
// explicit error. A PipeWire failure after start-up switches to the fallback
// once.
type waylandCapturer struct {
	once   sync.Once
	ctx    context.Context // cancelled by Close; ends a portal negotiation in progress
	cancel context.CancelFunc

	mu       sync.Mutex
	backend  capturer
	err      error
	retrying bool // a goroutine is trying to bring PipeWire back
}

func newWaylandCapturer() capturer {
	ctx, cancel := context.WithCancel(context.Background())
	return &waylandCapturer{ctx: ctx, cancel: cancel}
}

func (w *waylandCapturer) init() {
	w.once.Do(func() {
		on := portalEnabled(os.Getenv("RMM_WAYLAND_PORTAL"))
		var pw *pipewireCapturer
		var perr error
		if on {
			pw, perr = probePipeWire(w.ctx)
			if perr != nil {
				slog.Warn("desktop: PipeWire capture unavailable; falling back to the Screenshot portal", "err", perr)
			}
		} else {
			slog.Info("desktop: PipeWire capture disabled by RMM_WAYLAND_PORTAL=0; using the Screenshot portal")
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		// Checked under w.mu: Close cancels the context before it reads
		// w.backend under the same lock, so a probe that finishes while Close
		// runs is either seen by Close or closed here, never left open.
		if pw != nil && w.ctx.Err() != nil {
			pw.Close() // Close ran while the probe did
			pw, perr = nil, errCapturerClosed
		}
		choice, err := chooseWaylandBackend(on, perr, os.Getenv("DISPLAY"))
		switch choice {
		case backendPortal:
			w.backend = pw
			slog.Info("desktop: Wayland capture uses PipeWire")
		case backendScreenshot:
			w.backend = screenCapturer{}
		default:
			w.err = err
		}
		if on && perr != nil && fallBackWanted(perr) {
			w.startRetryLocked()
		}
	})
}

// probePipeWire negotiates the portal and waits for the first frame of the
// first monitor, so a stream that cannot deliver is found before the session
// starts. A stream that opened but has not sent a frame yet (an idle screen)
// passes, since the portal and the connection work. The capturer is closed on
// any other failure.
func probePipeWire(ctx context.Context) (*pipewireCapturer, error) {
	pw, err := newPipeWireCapturer(ctx)
	if err != nil {
		return nil, err
	}
	mons, err := pw.monitors()
	if err == nil {
		_, err = pw.capture(mons[0])
		if errors.Is(err, errNoFrameYet) {
			slog.Info("desktop: the PipeWire stream is open but the screen has not changed yet; capture continues", "err", err)
			err = nil
		}
	}
	if err != nil {
		pw.Close()
		return nil, err
	}
	return pw, nil
}

// current returns the backend, or the error that left none.
func (w *waylandCapturer) current() (capturer, error) {
	w.init()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return nil, w.err
	}
	return w.backend, nil
}

// fallBack replaces a failed PipeWire backend with the screenshot path. It
// reports false when there is no DISPLAY to fall back to. The failed capturer
// is closed after w.mu is released, because ending the portal session waits
// for the portal and must not hold up other capture calls. A retry loop tries
// to bring PipeWire back.
func (w *waylandCapturer) fallBack(failed capturer, cause error) bool {
	w.mu.Lock()
	if w.backend != failed {
		ok := w.err == nil // another call already switched
		w.mu.Unlock()
		return ok
	}
	_, derr := chooseWaylandBackend(false, cause, os.Getenv("DISPLAY"))
	if derr != nil {
		w.backend, w.err = nil, derr
	} else {
		w.backend = screenCapturer{}
	}
	w.startRetryLocked()
	w.mu.Unlock()

	if c, ok := failed.(interface{ Close() error }); ok {
		c.Close()
	}
	if derr != nil {
		slog.Warn("desktop: PipeWire capture failed and there is no X display to fall back to", "err", cause)
		return false
	}
	slog.Warn("desktop: PipeWire capture failed; falling back to the Screenshot portal until PipeWire can be restored", "err", cause)
	return true
}

// startRetryLocked starts the goroutine that retries the portal, unless one
// runs already or capture is closed. w.mu must be held.
func (w *waylandCapturer) startRetryLocked() {
	if w.retrying || w.ctx.Err() != nil {
		return
	}
	w.retrying = true
	go w.retryPipeWire()
}

// retryPipeWire probes the portal again with a growing delay and switches back
// to PipeWire when a probe works. It only retries while a restore token
// exists, because a new share would pop up the approval dialog on the user's
// screen at a time they did not ask for. It stops when capture is closed.
func (w *waylandCapturer) retryPipeWire() {
	var delay time.Duration
	for {
		delay = nextRetryDelay(delay)
		t := time.NewTimer(delay)
		select {
		case <-w.ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if loadRestoreToken() == "" {
			w.mu.Lock()
			w.retrying = false
			w.mu.Unlock()
			slog.Info("desktop: not retrying PipeWire capture: there is no saved screen-share permission to restore silently")
			return
		}
		pw, err := probePipeWire(w.ctx)
		if err != nil {
			slog.Debug("desktop: PipeWire capture is still unavailable", "err", err, "next_try_in", nextRetryDelay(delay))
			continue
		}
		w.mu.Lock()
		if w.ctx.Err() != nil {
			w.mu.Unlock()
			pw.Close()
			return
		}
		w.backend, w.err, w.retrying = pw, nil, false
		w.mu.Unlock()
		slog.Info("desktop: PipeWire capture is back")
		return
	}
}

func (w *waylandCapturer) monitors() ([]monitor, error) {
	b, err := w.current()
	if err != nil {
		return nil, err
	}
	mons, err := b.monitors()
	if err == nil {
		setDesktopHint(monitorUnion(mons))
	}
	return mons, err
}

func (w *waylandCapturer) capture(m monitor) (*image.RGBA, error) {
	b, err := w.current()
	if err != nil {
		return nil, err
	}
	img, err := b.capture(m)
	if err == nil {
		return img, nil
	}
	if _, isPW := b.(*pipewireCapturer); !isPW {
		return nil, err
	}
	if w.ctx.Err() != nil {
		return nil, errCapturerClosed
	}
	if !fallBackWanted(err) {
		return nil, err
	}
	if !w.fallBack(b, err) {
		return nil, err
	}
	b, err = w.current()
	if err != nil {
		return nil, err
	}
	return b.capture(m)
}

func (w *waylandCapturer) Close() error {
	w.cancel()
	w.mu.Lock()
	b := w.backend
	w.mu.Unlock()
	if c, ok := b.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

// capturerSetupNotice is the sentence the viewer sees while newCapturer's
// first monitors() call may be waiting for the person at the machine: on a
// Wayland session with the portal enabled and no saved restore token, the
// ScreenCast portal shows a "Share Screen" prompt (GNOME) that has to be
// accepted. With a token the next session is silent, so no notice. A token
// the compositor no longer honours still prompts, without a notice.
func capturerSetupNotice() string {
	if !waylandMode.Load() || !portalEnabled(os.Getenv("RMM_WAYLAND_PORTAL")) || loadRestoreToken() != "" {
		return ""
	}
	return setupNoticeFor(hostnameOrDevice())
}

func hostnameOrDevice() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "this device"
}
