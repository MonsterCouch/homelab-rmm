//go:build linux

package desktop

import (
	"errors"
	"io"
	"log"
	"os"
	"sync"

	"github.com/jezek/xgb"
)

var xgbQuietOnce sync.Once

// platformInit checks that an X display is reachable. Wayland compositors
// hide the screen and the input path behind portals the helper does not
// speak yet, so the error is explicit rather than a mystery capture failure.
func platformInit() error {
	// xgb logs "could not get authority info" at every connection, and
	// kbinani opens a connection per call; route that noise away.
	xgbQuietOnce.Do(func() { xgb.Logger = log.New(io.Discard, "", 0) })

	// A Wayland session with DISPLAY set is XWayland: XGetImage there
	// returns black for every native window and XTEST reaches only X11
	// clients, so "works" would mean a black screen. Fail fast instead; the
	// launcher never picks such a session, this guards the manual
	// `desktop-helper` run.
	if os.Getenv("XDG_SESSION_TYPE") == "wayland" {
		return errWayland
	}
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
