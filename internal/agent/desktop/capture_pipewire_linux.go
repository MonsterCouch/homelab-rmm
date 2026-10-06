//go:build linux

package desktop

// Wayland screen capture through the XDG ScreenCast portal and PipeWire.
//
// WHAT IS IMPLEMENTED
//
// The full portal negotiation, in pure Go over godbus: CreateSession,
// SelectSources (types=MONITOR, persist_mode=2 so the grant is remembered),
// Start, and OpenPipeRemote (which yields a file descriptor for a private
// PipeWire connection). The restore_token the portal returns from Start is
// persisted (see restoreTokenPath) and offered on the next SelectSources, so
// an unattended session is restored without a prompt where the compositor
// supports it. The result is a PipeWire node id, the remote fd and the
// geometry of each stream.
//
// WHAT IS NOT IMPLEMENTED (honest limit)
//
// Reading frames from that node. PipeWire has no stable pure-Go client: the
// native protocol is a binary SPA-POD protocol over the fd, and consuming a
// video stream means implementing the client-node object, param negotiation
// (EnumFormat/Format/Buffers), receiving memfd/DMA-BUF buffers by SCM_RIGHTS
// and driving them through eventfd-signalled activations. That is
// libpipewire's job, and linking it needs CGO, which this build forbids. So
// pipewireCapturer.capture always returns errPipeWireNoIngest. It never
// returns synthetic frames.
//
// CONSEQUENCE FOR THE CALLER
//
// newWaylandCapturer() therefore does not start a portal session by default:
// that would put a permission dialog on the user's screen only to discard the
// result. It goes straight to the fallback (screenCapturer, i.e. kbinani,
// which on a Wayland session uses the Screenshot portal for real pixels and
// Xwayland/Xinerama for geometry). Set RMM_WAYLAND_PORTAL=1 to run the portal
// negotiation anyway (it is still followed by the fallback because capture()
// fails); that is how to exercise this code on a real compositor and to see
// the restore token being saved. If an ingest implementation is ever added,
// flip pipewireIngestImplemented.
//
// NOT VERIFIED: none of this has been run against a real portal; it was
// written against the portal specification and cross-compiled only.

import (
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
)

// pipewireIngestImplemented says whether pipewireCapturer.capture can produce
// frames. It is false: see the file comment.
const pipewireIngestImplemented = false

var errPipeWireNoIngest = errors.New("PipeWire frame ingestion is not available in this CGO-free build (portal session negotiated, but no pure-Go PipeWire client exists)")

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

// pwStream is one entry of Start's "streams" result.
type pwStream struct {
	Node   uint32
	Bounds image.Rectangle // position and size in compositor coordinates; empty if not reported
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

// monitorsFromStreams turns stream geometry into monitors (Index in stream
// order; the one at the desktop origin, else the first, is primary).
func monitorsFromStreams(streams []pwStream) []monitor {
	var mons []monitor
	for _, s := range streams {
		if s.Bounds.Empty() || len(mons) >= maxMonitors {
			continue
		}
		mons = append(mons, monitor{Index: len(mons), Bounds: s.Bounds})
	}
	if len(mons) > 0 {
		markPrimary(mons)
	}
	return mons
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
func (p *portalConn) request(method string, timeout time.Duration, build func(handleToken string) []interface{}) (map[string]dbus.Variant, error) {
	tok := p.token("rmm")
	var handle dbus.ObjectPath
	if err := p.obj.Call(method, 0, build(tok)...).Store(&handle); err != nil {
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

// pipewireCapturer holds a negotiated ScreenCast session. It satisfies
// capturer, but capture() cannot deliver frames (see the file comment).
type pipewireCapturer struct {
	pc      *portalConn
	session dbus.ObjectPath
	streams []pwStream
	mons    []monitor
	remote  *os.File // PipeWire connection from OpenPipeRemote
	closer  sync.Once
}

// newPipeWireCapturer runs the portal negotiation. It may block until the
// user approves the screen-share dialog (bounded by startTimeout) when no
// valid restore token exists.
func newPipeWireCapturer() (*pipewireCapturer, error) {
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
	c := &pipewireCapturer{pc: pc}
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

	res, err := pc.request(ifaceScreenCast+".CreateSession", requestTimeout, func(tok string) []interface{} {
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

	restore := ""
	if persist {
		restore = loadRestoreToken()
	}
	if _, err := pc.request(ifaceScreenCast+".SelectSources", requestTimeout, func(tok string) []interface{} {
		return []interface{}{c.session, selectSourcesOptions(tok, restore, persist)}
	}); err != nil {
		return fail(err)
	}

	res, err = pc.request(ifaceScreenCast+".Start", startTimeout, func(tok string) []interface{} {
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
	if err := pc.obj.Call(ifaceScreenCast+".OpenPipeRemote", 0, c.session, map[string]dbus.Variant{}).Store(&fd); err != nil {
		return fail(fmt.Errorf("OpenPipeRemote: %w", err))
	}
	c.remote = os.NewFile(uintptr(fd), "pipewire-remote")

	c.mons = monitorsFromStreams(streams)
	slog.Info("desktop: ScreenCast portal session ready", "nodes", len(streams), "monitors", len(c.mons), "persist", persist)
	return c, nil
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
	if len(c.mons) == 0 {
		return nil, errors.New("the portal did not report a stream with a usable size")
	}
	return c.mons, nil
}

// capture always fails: the node and fd are negotiated but there is no
// CGO-free PipeWire client to read buffers from them.
func (c *pipewireCapturer) capture(m monitor) (*image.RGBA, error) {
	return nil, errPipeWireNoIngest
}

// nodeFor returns the PipeWire node serving monitor index i (for logging and
// for a future ingest implementation).
func (c *pipewireCapturer) nodeFor(i int) (uint32, bool) {
	n := 0
	for _, s := range c.streams {
		if s.Bounds.Empty() {
			continue
		}
		if n == i {
			return s.Node, true
		}
		n++
	}
	return 0, false
}

// Close ends the portal session and releases the fd and bus connection.
func (c *pipewireCapturer) Close() error {
	c.closer.Do(func() {
		if c.remote != nil {
			c.remote.Close()
		}
		if c.pc != nil && c.pc.conn != nil {
			if c.session != "" {
				c.pc.conn.Object(portalName, c.session).Call(ifacePortalSess+".Close", 0)
			}
			c.pc.conn.RemoveSignal(c.pc.sigs)
			c.pc.conn.Close()
		}
	})
	return nil
}

// ---- Wayland capture selection ----

// portalAttemptEnabled says whether to start a ScreenCast session at all.
func portalAttemptEnabled() bool {
	return pipewireIngestImplemented || os.Getenv("RMM_WAYLAND_PORTAL") == "1"
}

// waylandCapturer picks the capture backend lazily on first use (newCapturer
// cannot return an error, and Serve already treats a monitors() error as "no
// usable display"): PipeWire when it really yields frames, otherwise the
// screenCapturer fallback if a DISPLAY exists, otherwise an explicit error.
type waylandCapturer struct {
	once    sync.Once
	backend capturer
	err     error
}

func newWaylandCapturer() capturer { return &waylandCapturer{} }

func (w *waylandCapturer) init() {
	w.once.Do(func() {
		if portalAttemptEnabled() {
			pw, err := newPipeWireCapturer()
			if err == nil {
				if mons, merr := pw.monitors(); merr == nil {
					if _, cerr := pw.capture(mons[0]); cerr == nil {
						w.backend = pw
						return
					} else {
						err = cerr
					}
				} else {
					err = merr
				}
				pw.Close()
			}
			slog.Warn("desktop: PipeWire capture unavailable; falling back", "err", err)
		}
		if os.Getenv("DISPLAY") == "" {
			w.err = errors.New("Wayland screen capture needs PipeWire, which is not available in this build, and there is no Xwayland DISPLAY to fall back to")
			return
		}
		// XDG_SESSION_TYPE stays "wayland" on purpose: kbinani then takes the
		// Screenshot-portal path for the pixels (real compositor output; a
		// plain XGetImage on Xwayland returns black for native windows) and
		// uses the X display only for monitor geometry.
		slog.Warn("desktop: Wayland capture falls back to the Screenshot portal via the X display (slow, per-frame request)")
		w.backend = screenCapturer{}
	})
}

func (w *waylandCapturer) monitors() ([]monitor, error) {
	w.init()
	if w.err != nil {
		return nil, w.err
	}
	mons, err := w.backend.monitors()
	if err == nil {
		setDesktopHint(monitorUnion(mons))
	}
	return mons, err
}

func (w *waylandCapturer) capture(m monitor) (*image.RGBA, error) {
	w.init()
	if w.err != nil {
		return nil, w.err
	}
	return w.backend.capture(m)
}

func (w *waylandCapturer) Close() error {
	if c, ok := w.backend.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}
