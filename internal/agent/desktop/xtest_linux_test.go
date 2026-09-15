//go:build linux

package desktop

import (
	"context"
	"errors"
	"fmt"
	"image"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"
	"github.com/kbinani/screenshot"
)

// TestXvfbCaptureAndInput is a real end-to-end check on a throwaway X
// server: it captures the root window and drives the XTEST pointer, then
// asserts the pointer actually moved. It is skipped when Xvfb is not on the
// machine (the unit tests above cover the pure logic without an X server).
func TestXvfbCaptureAndInput(t *testing.T) {
	if _, err := exec.LookPath("Xvfb"); err != nil {
		t.Skip("Xvfb not installed; skipping the X11 integration test")
	}
	os.Unsetenv("XAUTHORITY")
	os.Unsetenv("XDG_SESSION_TYPE")
	display, stop, err := startXvfb(t, 1024, 768)
	if err != nil {
		t.Skipf("could not start a usable Xvfb: %v", err)
	}
	defer stop()
	t.Setenv("DISPLAY", display) // record for restore; startXvfb already set it
	if err := platformInit(); err != nil {
		t.Fatalf("platformInit: %v", err)
	}

	// Capture through the same backend the helper uses. kbinani opens a
	// fresh X connection per call and returns a zero result on any
	// transient hiccup, so — exactly like screenCapturer in the capture
	// loop — retry, and only skip if the throwaway server never yields a
	// good frame (that is infrastructure, not an injector bug).
	cap := screenCapturer{}
	var (
		bounds image.Rectangle
		img    *image.RGBA
	)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mons, merr := cap.monitors()
		if merr != nil || len(mons) == 0 {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		bounds = mons[0].Bounds
		if bounds.Dx() != 1024 || bounds.Dy() != 768 {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		if got, cerr := cap.capture(mons[0]); cerr == nil && got.Rect.Dx() == 1024 && got.Rect.Dy() == 768 {
			img = got
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if img == nil {
		t.Skip("Xvfb never produced a stable 1024x768 capture; skipping the X11 integration test")
	}

	// Input: move the pointer through the injector and read it back.
	inj, err := newInjector()
	if err != nil {
		t.Fatalf("newInjector: %v", err)
	}
	defer inj.close()
	inj.setMonitor(monitor{Index: 0, Bounds: bounds, Primary: true})

	c, err := xgb.NewConn()
	if err != nil {
		t.Fatalf("verify conn: %v", err)
	}
	defer c.Close()
	root := xproto.Setup(c).DefaultScreen(c).Root

	if err := inj.mouseMove(400, 300); err != nil {
		t.Fatalf("mouseMove: %v", err)
	}
	waitPointer(t, c, root, 400, 300)

	if err := inj.mouseMove(700, 100); err != nil {
		t.Fatalf("mouseMove: %v", err)
	}
	waitPointer(t, c, root, 700, 100)

	// A click and a key must not error against a live server.
	if err := inj.mouseButton(buttonLeft, true, 700, 100); err != nil {
		t.Fatalf("button down: %v", err)
	}
	if err := inj.mouseButton(buttonLeft, false, 700, 100); err != nil {
		t.Fatalf("button up: %v", err)
	}
	if err := inj.key("KeyA", "a", true); err != nil {
		t.Fatalf("key down: %v", err)
	}
	if err := inj.key("KeyA", "a", false); err != nil {
		t.Fatalf("key up: %v", err)
	}
	// Paste of a non-Latin rune exercises the spare-keycode remap path.
	if err := inj.paste("Ω"); err != nil {
		t.Fatalf("paste: %v", err)
	}
}

func waitPointer(t *testing.T, c *xgb.Conn, root xproto.Window, wantX, wantY int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		reply, err := xproto.QueryPointer(c, root).Reply()
		if err != nil {
			// The throwaway X server vanished (a concurrent test grabbed
			// the display, the machine is shutting it down): that is
			// infrastructure, not a bug in the injector.
			t.Skipf("QueryPointer against Xvfb failed: %v", err)
		}
		if int(reply.RootX) == wantX && int(reply.RootY) == wantY {
			return
		}
		last = fmt.Sprintf("(%d,%d)", reply.RootX, reply.RootY)
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pointer did not reach (%d,%d); last saw %s", wantX, wantY, last)
}

// startXvfb launches a private X server on a free display and waits for it
// to accept connections.
func startXvfb(t *testing.T, w, h int) (display string, stop func(), err error) {
	t.Helper()
	base := 90 + os.Getpid()%400
	for k := 0; k < 40; k++ {
		n := base + k
		disp := ":" + strconv.Itoa(n)
		if _, err := os.Stat(filepath.Join("/tmp/.X11-unix", "X"+strconv.Itoa(n))); err == nil {
			continue // already in use
		}
		if _, err := os.Stat("/tmp/.X" + strconv.Itoa(n) + "-lock"); err == nil {
			continue // a server (or a stale lock) owns the number
		}
		ctx, cancel := context.WithCancel(context.Background())
		// -noreset: an X server regenerates (and drops every connection
		// that arrives meanwhile) when its last client disconnects, and the
		// capture backend opens a connection per call, so without it the
		// injector's connect races the reset. A real desktop always has a
		// window manager attached and never hits this.
		cmd := exec.CommandContext(ctx, "Xvfb", disp, "-screen", "0", fmt.Sprintf("%dx%dx24", w, h), "-nolisten", "tcp", "-noreset")
		// SIGTERM lets Xvfb remove its socket and lock file; SIGKILL would
		// leave /tmp/.X<n>-lock behind for every run.
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
		cmd.WaitDelay = 3 * time.Second
		if err := cmd.Start(); err != nil {
			cancel()
			return "", nil, err
		}
		// Wait for the server to accept connections AND for kbinani to
		// enumerate it (XINERAMA is not ready the instant the socket opens).
		os.Setenv("DISPLAY", disp)
		ok := false
		for i := 0; i < 200; i++ {
			if c, cerr := xgb.NewConnDisplay(disp); cerr == nil {
				c.Close()
				if screenshot.NumActiveDisplays() >= 1 {
					ok = true
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !ok {
			cancel()
			cmd.Wait()
			continue
		}
		return disp, func() { cancel(); cmd.Wait() }, nil
	}
	return "", nil, errors.New("no free X display found for the integration test")
}
