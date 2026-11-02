//go:build windows

package desktop

// Backstage mode: an isolated administrative desktop.
//
// The technician works on a private Win32 desktop ("HomelabRMM_Backstage" on
// the interactive window station) that the logged-in user never sees. Nothing
// here may touch the physical screen or the physical input queue, so the
// implementation is built from window-handle based APIs only:
//
//   - capture (backstage_capture_windows.go) lists the desktop's top-level
//     windows with EnumDesktopWindows(hDesktop, ...) and asks each one to
//     paint itself into an off-screen DIB with PrintWindow, then composites
//     them bottom-to-top. No device context of the physical display is ever
//     requested.
//   - input (backstage_input_windows.go) hit-tests the backstage window tree
//     itself and PostMessageW's mouse / keyboard messages to the resulting
//     window handle. Nothing is injected into the system input stream, so the
//     physical cursor never moves and physical keystrokes are never faked.
//
// The privacy invariants are enforced by TestBackstageNoForbiddenAPIs, which
// scans these source files for the APIs that would break them.

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	backstageDesktopName = "HomelabRMM_Backstage"
	// backstageDesktopPath is the STARTUPINFO.lpDesktop form: window station
	// and desktop, so CreateProcessAsUser places the child there.
	backstageDesktopPath = `winsta0\` + backstageDesktopName

	// backstageSDDL is the desktop's DACL: GENERIC_ALL for LocalSystem (SY)
	// and BUILTIN\Administrators (BA), and nobody else. The interactive user
	// (unless an administrator) therefore cannot open, enumerate or hook it.
	backstageSDDL = "D:(A;;GA;;;SY)(A;;GA;;;BA)"
)

// user32 / gdi32 entry points used by backstage. user32, gdi32,
// procPostMessageW, procSelectObject, procDeleteObject, procMapVirtualKeyW
// and procCloseDesktop are shared with the console code paths; everything
// else is declared here under bs-prefixed names.
var (
	procCreateDesktopW         = user32.NewProc("CreateDesktopW")
	procEnumDesktopWindowsBS   = user32.NewProc("EnumDesktopWindows")
	procIsWindowVisibleBS      = user32.NewProc("IsWindowVisible")
	procIsIconicBS             = user32.NewProc("IsIconic")
	procIsZoomedBS             = user32.NewProc("IsZoomed")
	procIsWindowBS             = user32.NewProc("IsWindow")
	procIsHungAppWindowBS      = user32.NewProc("IsHungAppWindow")
	procGetWindowRectBS        = user32.NewProc("GetWindowRect")
	procGetClientRectBS        = user32.NewProc("GetClientRect")
	procScreenToClientBS       = user32.NewProc("ScreenToClient")
	procChildWindowFromPointEx = user32.NewProc("ChildWindowFromPointEx")
	procPrintWindowBS          = user32.NewProc("PrintWindow")
	procSetWindowPosBS         = user32.NewProc("SetWindowPos")
	procGetClassLongWBS        = user32.NewProc("GetClassLongW")
	procSendMessageTimeoutWBS  = user32.NewProc("SendMessageTimeoutW")
	procGetDoubleClickTimeBS   = user32.NewProc("GetDoubleClickTime")
	procVkKeyScanWBS           = user32.NewProc("VkKeyScanW")

	procCreateCompatibleDCBS = gdi32.NewProc("CreateCompatibleDC")
	procCreateDIBSectionBS   = gdi32.NewProc("CreateDIBSection")
	procBitBltBS             = gdi32.NewProc("BitBlt")
	procGdiFlushBS           = gdi32.NewProc("GdiFlush")
	procDeleteDCBS           = gdi32.NewProc("DeleteDC")
)

// bsRect is RECT (windef.h): four LONGs.
type bsRect struct{ left, top, right, bottom int32 }

func (r bsRect) width() int  { return int(r.right - r.left) }
func (r bsRect) height() int { return int(r.bottom - r.top) }

// bsPoint is POINT (windef.h): two LONGs.
type bsPoint struct{ x, y int32 }

// ---- the desktop object ----

// backstageDesktop owns the HDESK and the processes started on it. The
// capturer and the injector each hold one reference; the desktop and
// everything running on it are torn down when the last one lets go.
type backstageDesktop struct {
	h    windows.Handle
	refs atomic.Int32

	mu    sync.Mutex
	job   windows.Handle   // KILL_ON_JOB_CLOSE job holding every spawned tool
	procs []windows.Handle // spawned process handles
}

// createBackstageDesktop makes (or opens, when it already exists)
// HomelabRMM_Backstage on the calling process's window station with
// GENERIC_ALL and the SYSTEM + Administrators-only DACL. The returned desktop
// has one reference.
//
// CreateDesktopW (winuser.h):
//
//	HDESK CreateDesktopW(LPCWSTR lpszDesktop, LPCWSTR lpszDevice /*NULL*/,
//	    LPDEVMODEW pDevmode /*NULL*/, DWORD dwFlags, ACCESS_MASK dwDesiredAccess,
//	    LPSECURITY_ATTRIBUTES lpsa);
func createBackstageDesktop() (*backstageDesktop, error) {
	sd, err := windows.SecurityDescriptorFromString(backstageSDDL)
	if err != nil {
		return nil, fmt.Errorf("backstage DACL: %w", err)
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	name, err := windows.UTF16PtrFromString(backstageDesktopName)
	if err != nil {
		return nil, err
	}
	h, _, callErr := procCreateDesktopW.Call(
		uintptr(unsafe.Pointer(name)), 0, 0, 0, genericAll, uintptr(unsafe.Pointer(&sa)))
	if h == 0 {
		return nil, fmt.Errorf("CreateDesktopW(%s): %w (needs an administrator or SYSTEM token on an interactive window station)", backstageDesktopName, callErr)
	}
	d := &backstageDesktop{h: windows.Handle(h)}
	d.refs.Store(1)
	return d, nil
}

func (d *backstageDesktop) retain() { d.refs.Add(1) }

// release drops one reference; the last one kills the tools that were
// started on the desktop (the job object takes their whole process tree with
// it) and closes the handle, which lets Windows destroy the desktop.
func (d *backstageDesktop) release() {
	if d.refs.Add(-1) != 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.job != 0 {
		windows.CloseHandle(d.job) // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		d.job = 0
	}
	for _, p := range d.procs {
		windows.TerminateProcess(p, 0) // no-op for processes the job already killed
		windows.CloseHandle(p)
	}
	d.procs = nil
	if d.h != 0 {
		procCloseDesktop.Call(uintptr(d.h))
		d.h = 0
	}
}

// ---- window enumeration ----

// EnumDesktopWindows calls back through a C function pointer, and Go limits
// the number of callbacks a process may ever create, so there is exactly one;
// the per-call result list is found through the lParam token.
var (
	bsEnumMu      sync.Mutex
	bsEnumNext    uintptr
	bsEnumResults = map[uintptr]*[]uintptr{}
	bsEnumCB      = windows.NewCallback(func(hwnd, token uintptr) uintptr {
		bsEnumMu.Lock()
		if out := bsEnumResults[token]; out != nil {
			*out = append(*out, hwnd)
		}
		bsEnumMu.Unlock()
		return 1 // continue enumeration
	})
)

// topLevelWindows lists the desktop's top-level windows, topmost first
// (EnumDesktopWindows walks the Z-order from the top).
//
//	BOOL EnumDesktopWindows(HDESK hDesktop, WNDENUMPROC lpfn, LPARAM lParam);
func (d *backstageDesktop) topLevelWindows() []uintptr {
	var out []uintptr
	bsEnumMu.Lock()
	bsEnumNext++
	token := bsEnumNext
	bsEnumResults[token] = &out
	bsEnumMu.Unlock()

	procEnumDesktopWindowsBS.Call(uintptr(d.h), bsEnumCB, token)

	bsEnumMu.Lock()
	delete(bsEnumResults, token)
	bsEnumMu.Unlock()
	return out
}

func bsBool(proc *windows.LazyProc, hwnd uintptr) bool {
	r, _, _ := proc.Call(hwnd)
	return r != 0
}

func bsWindowRect(hwnd uintptr) (bsRect, bool) {
	var r bsRect
	ok, _, _ := procGetWindowRectBS.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	return r, ok != 0
}

// bsShown reports whether a window should take part in capture and hit
// testing: visible and not minimised.
func bsShown(hwnd uintptr) bool {
	return bsBool(procIsWindowVisibleBS, hwnd) && !bsBool(procIsIconicBS, hwnd)
}

// visibleWindowCount is how many shown top-level windows the desktop has.
func (d *backstageDesktop) visibleWindowCount() int {
	n := 0
	for _, w := range d.topLevelWindows() {
		if bsShown(w) {
			n++
		}
	}
	return n
}

// ---- tools ----

// backstageSpawnTools is false in tests that only want the desktop.
var backstageSpawnTools = true

// backstageTool is one program of the default administrative suite.
//
// PowerShell is deliberately not in the default suite: the window-style rule
// is that every PowerShell the agent starts is started with
// `-WindowStyle Hidden`, which makes it invisible, and an invisible shell is
// no use to someone watching the desktop. The technician starts PowerShell
// (or anything else) from the cmd.exe on the desktop. spawn() nevertheless
// enforces the rule for any PowerShell image passed to it.
type backstageTool struct {
	image      string
	args       []string
	x, y, w, h int32 // initial window geometry hint (STARTF_USEPOSITION|SIZE)
}

var backstageTools = []backstageTool{
	{image: "cmd.exe", x: 40, y: 40, w: 900, h: 520},
	{image: "taskmgr.exe", x: 140, y: 120, w: 920, h: 640},
}

// isPowerShellImage reports whether image is Windows PowerShell or pwsh.
func isPowerShellImage(image string) bool {
	switch strings.ToLower(filepath.Base(image)) {
	case "powershell.exe", "powershell", "pwsh.exe", "pwsh":
		return true
	}
	return false
}

// withHiddenWindowStyle returns args with `-WindowStyle Hidden` prepended
// unless the caller already chose a window style. Every PowerShell this
// package starts goes through it.
func withHiddenWindowStyle(image string, args []string) []string {
	if !isPowerShellImage(image) {
		return args
	}
	for _, a := range args {
		l := strings.ToLower(a)
		if l == "-windowstyle" || l == "-w" || strings.HasPrefix(l, "-windowstyle:") {
			return args
		}
	}
	return append([]string{"-WindowStyle", "Hidden"}, args...)
}

const (
	startfUseShowWindow = 0x1
	startfUseSize       = 0x2
	startfUsePosition   = 0x4
)

// startTools launches the default suite once, when the desktop has no
// windows yet (a reconnecting technician finds the old ones instead of a
// second copy).
func (d *backstageDesktop) startTools() {
	if d.visibleWindowCount() > 0 {
		return
	}
	for _, t := range backstageTools {
		if err := d.spawn(t); err != nil {
			slog.Warn("backstage: cannot start tool", "tool", t.image, "err", err)
		}
	}
}

// ensureJob creates the job object that kills spawned tools with the desktop.
func (d *backstageDesktop) ensureJob() {
	if d.job != 0 {
		return
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		slog.Debug("backstage: no job object; tools are terminated individually", "err", err)
		return
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		slog.Debug("backstage: cannot configure job object", "err", err)
		windows.CloseHandle(job)
		return
	}
	d.job = job
}

// spawn starts one tool on the backstage desktop with CreateProcessAsUser and
// STARTUPINFO.lpDesktop = winsta0\HomelabRMM_Backstage. The child runs on a
// primary-token duplicate of our own token, which already lives in the
// console session. It is created suspended, put in the kill-on-close job, and
// only then resumed, so nothing it spawns can escape the job.
func (d *backstageDesktop) spawn(t backstageTool) error {
	sysDir, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	exe := filepath.Join(sysDir, t.image)
	args := withHiddenWindowStyle(t.image, t.args)
	cmdline, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{exe}, args...)))
	if err != nil {
		return err
	}
	exe16, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	dir16, err := windows.UTF16PtrFromString(sysDir)
	if err != nil {
		return err
	}
	desk16, err := windows.UTF16PtrFromString(backstageDesktopPath)
	if err != nil {
		return err
	}

	var self windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY, &self); err != nil {
		return fmt.Errorf("open process token: %w", err)
	}
	defer self.Close()
	var tok windows.Token
	if err := windows.DuplicateTokenEx(self, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityImpersonation, windows.TokenPrimary, &tok); err != nil {
		return fmt.Errorf("duplicate token: %w", err)
	}
	defer tok.Close()

	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, tok, false); err != nil {
		return fmt.Errorf("CreateEnvironmentBlock: %w", err)
	}
	defer windows.DestroyEnvironmentBlock(env)

	si := windows.StartupInfo{Desktop: desk16}
	si.Cb = uint32(unsafe.Sizeof(si))
	if t.w > 0 && t.h > 0 {
		si.Flags |= startfUsePosition | startfUseSize
		si.X, si.Y, si.XSize, si.YSize = uint32(t.x), uint32(t.y), uint32(t.w), uint32(t.h)
	}
	if isPowerShellImage(t.image) {
		si.Flags |= startfUseShowWindow
		si.ShowWindow = windows.SW_HIDE
	}
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NEW_CONSOLE | windows.CREATE_SUSPENDED)

	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(tok, exe16, cmdline, nil, nil, false, flags, env, dir16, &si, &pi); err != nil {
		// Same token, same session: plain CreateProcess is equivalent and
		// needs no extra privilege when the helper is not SYSTEM.
		if err2 := windows.CreateProcess(exe16, cmdline, nil, nil, false, flags, env, dir16, &si, &pi); err2 != nil {
			return fmt.Errorf("CreateProcessAsUser on %s: %w", backstageDesktopPath, err)
		}
	}

	d.mu.Lock()
	d.ensureJob()
	if d.job != 0 {
		if err := windows.AssignProcessToJobObject(d.job, pi.Process); err != nil {
			slog.Debug("backstage: cannot assign tool to job", "tool", t.image, "err", err)
		}
	}
	d.procs = append(d.procs, pi.Process)
	d.mu.Unlock()

	windows.ResumeThread(pi.Thread)
	windows.CloseHandle(pi.Thread)
	slog.Info("backstage: tool started", "tool", t.image, "pid", pi.ProcessId, "desktop", backstageDesktopPath)
	return nil
}

// ---- entry point ----

// bsPointerPos is the injector's last pointer position, shared with the
// capturer, which draws a software cursor there (the physical cursor is not
// on this desktop). Coordinates are relative to the monitor's top-left.
type bsPointerPos struct{ x, y atomic.Int32 }

func (p *bsPointerPos) set(x, y int) { p.x.Store(int32(x)); p.y.Store(int32(y)) }
func (p *bsPointerPos) get() (int, int) {
	return int(p.x.Load()), int(p.y.Load())
}

// newBackstage creates the backstage desktop, starts the default tools on it
// and returns the off-screen capturer and the window-targeted injector.
func newBackstage() (capturer, injector, error) {
	d, err := createBackstageDesktop()
	if err != nil {
		return nil, nil, err
	}
	d.retain() // one reference for the capturer, one for the injector
	if backstageSpawnTools {
		d.startTools()
	}
	ptr := &bsPointerPos{}
	c, err := newBackstageCapturer(d, ptr)
	if err != nil {
		d.release()
		d.release()
		return nil, nil, err
	}
	return c, newBackstageInjector(d, ptr), nil
}

var errBackstageClosed = errors.New("backstage desktop is closed")
