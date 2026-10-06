//go:build linux

package desktop

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"

	"github.com/jezek/xgb"
)

var xgbQuietOnce sync.Once

// platformInit checks that an X display is reachable, or that a Wayland
// session can be served through uinput (see below). Anything else fails with
// an explicit error rather than a mystery capture failure.
func platformInit() error {
	// xgb logs "could not get authority info" at every connection, and
	// kbinani opens a connection per call; route that noise away.
	xgbQuietOnce.Do(func() { xgb.Logger = log.New(io.Discard, "", 0) })

	// A Wayland session with DISPLAY set is XWayland: XGetImage there
	// returns black for every native window and XTEST reaches only X11
	// clients. Wayland is therefore served only through /dev/uinput (input,
	// compositor independent) plus waylandCapturer (capture); without a
	// writable uinput the helper still refuses, rather than "working" into
	// a black screen. The launcher never picks such a session for the X11
	// path; this also guards the manual `desktop-helper` run.
	if os.Getenv("XDG_SESSION_TYPE") == "wayland" {
		if !uinputSelectorWired {
			return errWayland
		}
		if err := checkUinputWritable(); err != nil {
			return fmt.Errorf("%w: input needs /dev/uinput: %v", errWayland, err)
		}
		waylandMode.Store(true)
		return nil
	}
	waylandMode.Store(false)
	if os.Getenv("DISPLAY") == "" {
		if os.Getenv("WAYLAND_DISPLAY") != "" {
			return errWayland
		}
		return errors.New("DISPLAY is not set; no X11 display to capture")
	}
	// kbinani takes the portal path whenever this is "wayland"; pin the
	// X11 path we are built for (the value is unset in the helper's
	// minimal environment, and "x11" or "tty" in developer mode).
	os.Setenv("XDG_SESSION_TYPE", "x11")
	return nil
}

// threadDesktop is a Windows concept (input desktops); nothing to follow
// on X11.
type threadDesktop struct{}

func newThreadDesktop() *threadDesktop { return &threadDesktop{} }
func (*threadDesktop) follow() error   { return nil }
func (*threadDesktop) close()          {}

// newCapturer returns the screen-capture backend. The X11 backend
// (kbinani/screenshot over XShm) is the default; a Wayland session (see
// platformInit) gets waylandCapturer, which tries the PipeWire portal and
// falls back (capture_pipewire_linux.go).
func newCapturer() capturer {
	if waylandMode.Load() {
		return newWaylandCapturer()
	}
	return screenCapturer{}
}
