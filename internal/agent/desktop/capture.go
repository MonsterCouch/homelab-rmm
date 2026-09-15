package desktop

import (
	"errors"
	"fmt"
	"image"

	"github.com/kbinani/screenshot"
)

// monitor is one display as the capture backend sees it. Bounds are in the
// backend's virtual-desktop coordinates (Windows: the virtual screen; X11:
// relative to the primary Xinerama screen), which is also the space the
// "screen" message reports.
type monitor struct {
	Index   int
	Bounds  image.Rectangle
	Primary bool
}

// capturer enumerates displays and grabs their pixels. The session drives it
// from a goroutine locked to one OS thread (Windows GDI needs the thread's
// desktop to be the input desktop).
type capturer interface {
	monitors() ([]monitor, error)
	capture(m monitor) (*image.RGBA, error)
}

// screenCapturer is the real backend on top of kbinani/screenshot (GDI
// BitBlt on Windows, XShm/XGetImage on X11).
type screenCapturer struct{}

// maxMonitors bounds enumeration so a misbehaving driver cannot make the
// screen message unbounded.
const maxMonitors = 16

func (screenCapturer) monitors() ([]monitor, error) {
	n := screenshot.NumActiveDisplays()
	if n <= 0 {
		return nil, errors.New("no active display found")
	}
	if n > maxMonitors {
		n = maxMonitors
	}
	mons := make([]monitor, 0, n)
	for i := 0; i < n; i++ {
		b := screenshot.GetDisplayBounds(i)
		if b.Dx() <= 0 || b.Dy() <= 0 {
			continue // a display that vanished between the two calls
		}
		mons = append(mons, monitor{Index: len(mons), Bounds: b})
	}
	if len(mons) == 0 {
		return nil, errors.New("no display with a usable size")
	}
	markPrimary(mons)
	return mons, nil
}

// markPrimary flags the display at the virtual-desktop origin (where Windows
// puts the primary monitor and kbinani puts Xinerama screen 0), falling back
// to the first one.
func markPrimary(mons []monitor) {
	for i := range mons {
		if mons[i].Bounds.Min == (image.Point{}) {
			mons[i].Primary = true
			return
		}
	}
	if len(mons) > 0 {
		mons[0].Primary = true
	}
}

func (screenCapturer) capture(m monitor) (*image.RGBA, error) {
	img, err := screenshot.CaptureRect(m.Bounds)
	if err != nil {
		return nil, fmt.Errorf("capture monitor %d: %w", m.Index, err)
	}
	if img == nil || img.Rect.Dx() <= 0 || img.Rect.Dy() <= 0 {
		return nil, fmt.Errorf("capture monitor %d: empty image", m.Index)
	}
	return img, nil
}

// screenMsg is the JSON "screen" message.
type screenMsg struct {
	T        string        `json:"t"`
	W        int           `json:"w"`
	H        int           `json:"h"`
	Monitor  int           `json:"monitor"`
	Monitors []monitorInfo `json:"monitors"`
}

type monitorInfo struct {
	Index   int  `json:"index"`
	X       int  `json:"x"`
	Y       int  `json:"y"`
	W       int  `json:"w"`
	H       int  `json:"h"`
	Primary bool `json:"primary"`
}

func newScreenMsg(mons []monitor, current int) screenMsg {
	msg := screenMsg{T: "screen", Monitor: current, Monitors: make([]monitorInfo, 0, len(mons))}
	for _, m := range mons {
		msg.Monitors = append(msg.Monitors, monitorInfo{
			Index: m.Index, X: m.Bounds.Min.X, Y: m.Bounds.Min.Y,
			W: m.Bounds.Dx(), H: m.Bounds.Dy(), Primary: m.Primary,
		})
		if m.Index == current {
			msg.W, msg.H = m.Bounds.Dx(), m.Bounds.Dy()
		}
	}
	return msg
}
