package desktop

// Pieces of the Wayland capture path that have no Linux dependency, so their
// tests run on every platform: the stream-to-monitor mapping and the decision
// between the PipeWire portal and the screenshot fallback. The Linux file
// capture_pipewire_linux.go uses them.

import (
	"errors"
	"fmt"
	"image"
	"strings"
	"time"
)

// pwStream is one entry of the ScreenCast portal's Start result.
type pwStream struct {
	Node   uint32
	Bounds image.Rectangle // position and size in compositor coordinates; empty if not reported
}

// monitorsFromStreams turns stream geometry into monitors (Index in stream
// order; the one at the desktop origin, else the first, is primary). A stream
// that reports no size is not a monitor.
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

// nodeForMonitor returns the PipeWire node serving monitor index i, counting
// the same streams monitorsFromStreams counts.
func nodeForMonitor(streams []pwStream, i int) (uint32, bool) {
	n := 0
	for _, s := range streams {
		if s.Bounds.Empty() || n >= maxMonitors {
			continue
		}
		if n == i {
			return s.Node, true
		}
		n++
	}
	return 0, false
}

// portalEnabled reports whether to start a ScreenCast portal session. It is
// on unless RMM_WAYLAND_PORTAL is "0" (the kill switch); "1", unset and any
// other value mean on.
func portalEnabled(env string) bool {
	return strings.TrimSpace(env) != "0"
}

type waylandBackend int

const (
	backendPortal     waylandBackend = iota // PipeWire frames from the portal
	backendScreenshot                       // screenCapturer through the X display
	backendNone                             // nothing usable
)

var errNoWaylandCapture = errors.New("Wayland screen capture through PipeWire is not available and there is no Xwayland DISPLAY to fall back to")

// chooseWaylandBackend decides the backend once the portal attempt is over.
// portalOn says whether the attempt was made, portalErr is its failure (nil
// when it produced a working capturer) and display is $DISPLAY.
func chooseWaylandBackend(portalOn bool, portalErr error, display string) (waylandBackend, error) {
	if portalOn && portalErr == nil {
		return backendPortal, nil
	}
	if display == "" {
		return backendNone, errNoWaylandCapture
	}
	return backendScreenshot, nil
}

// errCapturerClosed is returned by a capture that ran into an orderly Close.
// It is not a PipeWire failure and must not trigger the screenshot fallback.
var errCapturerClosed = errors.New("the PipeWire capturer was closed")

// errNoFrameYet is returned when a healthy stream has sent no frame within the
// wait. GNOME and KDE only send buffers on damage, so an idle screen is not a
// failure and the capturer is not marked broken.
var errNoFrameYet = errors.New("the PipeWire stream has not delivered a frame yet")

func noFrameYet(wait fmt.Stringer) error {
	return fmt.Errorf("%w (waited %s)", errNoFrameYet, wait)
}

// fallBackWanted says whether a PipeWire capture error means the backend is
// broken. Closing and an idle screen do not.
func fallBackWanted(err error) bool {
	return err != nil && !errors.Is(err, errCapturerClosed) && !errors.Is(err, errNoFrameYet)
}

// withFrameSize returns mons with monitor idx resized to the w by h frame the
// stream actually delivers, keeping its top-left corner. The portal reports
// logical size while the stream is negotiated in pixels, so with scaling they
// differ. changed is false, and mons is returned as is, when they agree or idx
// is unknown.
func withFrameSize(mons []monitor, idx, w, h int) (out []monitor, changed bool) {
	if w <= 0 || h <= 0 {
		return mons, false
	}
	for i, m := range mons {
		if m.Index != idx {
			continue
		}
		if m.Bounds.Dx() == w && m.Bounds.Dy() == h {
			return mons, false
		}
		out = append([]monitor(nil), mons...)
		out[i].Bounds = image.Rect(m.Bounds.Min.X, m.Bounds.Min.Y, m.Bounds.Min.X+w, m.Bounds.Min.Y+h)
		return out, true
	}
	return mons, false
}

// staleFrameLimit is how long a running stream may stay silent before the
// capturer treats it as stalled. GNOME and KDE send buffers only on damage, so
// an idle screen looks the same as a compositor that stopped; the limit is long
// so that only a screen idle for minutes pays for the check, which costs a
// switch to the screenshot path until the portal answers again.
const staleFrameLimit = 2 * time.Minute

// Backoff between attempts to bring the PipeWire path back after a failure.
const (
	retryInitialDelay = 30 * time.Second
	retryMaxDelay     = 10 * time.Minute
)

// errStreamStalled means a running stream sent nothing for staleFrameLimit.
var errStreamStalled = errors.New("the PipeWire stream is running but has sent no frame for too long")

// errPortalSessionClosed means the portal ended the ScreenCast session (the
// user revoked the share, or the compositor or portal restarted).
var errPortalSessionClosed = errors.New("the ScreenCast portal closed the screen-share session")

// streamStale reports whether a stream that was running and has produced a
// frame before has been silent for longer than limit. A stream that never
// produced a frame is not stale, because the first-frame wait covers it.
func streamStale(running bool, lastFrame, now time.Time, limit time.Duration) bool {
	if !running || lastFrame.IsZero() {
		return false
	}
	return now.Sub(lastFrame) > limit
}

// nextRetryDelay doubles the delay up to retryMaxDelay. A zero or negative
// previous delay gives retryInitialDelay.
func nextRetryDelay(prev time.Duration) time.Duration {
	if prev <= 0 {
		return retryInitialDelay
	}
	if prev >= retryMaxDelay/2 {
		return retryMaxDelay
	}
	return prev * 2
}
