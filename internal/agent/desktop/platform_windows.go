//go:build windows

package desktop

import (
	"log/slog"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// user32 entry points that x/sys/windows does not wrap. Lazy DLLs resolve on
// first use, so a missing export (SetProcessDpiAwarenessContext before
// Windows 10 1703) is a per-call error rather than a load failure.
var (
	user32                         = windows.NewLazySystemDLL("user32.dll")
	procSendInput                  = user32.NewProc("SendInput")
	procMapVirtualKeyW             = user32.NewProc("MapVirtualKeyW")
	procGetSystemMetrics           = user32.NewProc("GetSystemMetrics")
	procOpenInputDesktop           = user32.NewProc("OpenInputDesktop")
	procSetThreadDesktop           = user32.NewProc("SetThreadDesktop")
	procCloseDesktop               = user32.NewProc("CloseDesktop")
	procGetUserObjectInformationW  = user32.NewProc("GetUserObjectInformationW")
	procSetProcessDPIAware         = user32.NewProc("SetProcessDPIAware")
	procSetProcessDpiAwarenessCtx  = user32.NewProc("SetProcessDpiAwarenessContext")
	sasDLL                         = windows.NewLazySystemDLL("sas.dll")
	procSendSAS                    = sasDLL.NewProc("SendSAS")
	dpiAwarenessContextPerMonitor2 = ^uintptr(3) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 == (HANDLE)-4
)

const (
	genericAll = 0x10000000
	// The desktop rights capture and SendInput actually need; asked for
	// when GENERIC_ALL (which adds WRITE_DAC/WRITE_OWNER) is refused to a
	// non-admin user on its own desktop.
	desktopBasic = 0x0001 | 0x0002 | 0x0040 | 0x0080 // READOBJECTS | CREATEWINDOW | ENUMERATE | WRITEOBJECTS
	uoiName      = 2                                 // GetUserObjectInformation: the object name
)

var dpiOnce sync.Once

// platformInit makes GDI report physical pixels. Without DPI awareness a
// 150 % display would be captured at two thirds of its size and every click
// would land in the wrong place. Per-monitor v2 is preferred (mixed-DPI
// setups); the process-wide call is the fallback for old builds. Both may
// only be called once per process, hence the Once.
func platformInit() error {
	dpiOnce.Do(func() {
		if procSetProcessDpiAwarenessCtx.Find() == nil {
			if r, _, _ := procSetProcessDpiAwarenessCtx.Call(dpiAwarenessContextPerMonitor2); r != 0 {
				return
			}
		}
		procSetProcessDPIAware.Call()
	})
	return nil
}

// threadDesktop keeps the calling OS thread attached to the input desktop.
// When the machine is at the UAC prompt or the lock screen the input desktop
// is "Winlogon"; GDI captures and SendInput only reach it from a thread that
// switched there, and only when the process is SYSTEM (a user token gets
// access denied, which follow() treats as "stay where you are").
type threadDesktop struct {
	h    windows.Handle
	name string
}

func newThreadDesktop() *threadDesktop { return &threadDesktop{} }

// follow switches the thread to the current input desktop when it differs
// from the one it is on. It is cheap enough to run before every capture and
// every injected event: one OpenInputDesktop plus a name query.
func (t *threadDesktop) follow() {
	h, _, _ := procOpenInputDesktop.Call(0, 0, genericAll)
	if h == 0 {
		h, _, _ = procOpenInputDesktop.Call(0, 0, desktopBasic)
	}
	if h == 0 {
		return // a user-token helper while winlogon owns the screen: stay put
	}
	name := desktopName(windows.Handle(h))
	if name != "" && name == t.name {
		procCloseDesktop.Call(h)
		return
	}
	if r, _, err := procSetThreadDesktop.Call(h); r == 0 {
		slog.Debug("desktop: SetThreadDesktop failed", "desktop", name, "err", err)
		procCloseDesktop.Call(h)
		return
	}
	if t.h != 0 {
		procCloseDesktop.Call(uintptr(t.h))
	}
	t.h, t.name = windows.Handle(h), name
	slog.Info("desktop: thread now on desktop", "name", name)
}

func (t *threadDesktop) close() {
	if t.h != 0 {
		procCloseDesktop.Call(uintptr(t.h))
		t.h = 0
	}
}

// desktopName returns the object name ("Default", "Winlogon", ...) of a
// desktop handle, or "" when it cannot be read.
func desktopName(h windows.Handle) string {
	var buf [64]uint16
	var n uint32
	r, _, _ := procGetUserObjectInformationW.Call(uintptr(h), uoiName, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:])
}
