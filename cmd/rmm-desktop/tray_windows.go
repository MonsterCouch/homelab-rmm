//go:build windows

package main

import (
	_ "embed"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"

	"github.com/MonsterCouch/homelab-rmm/internal/portalpipe"
)

//go:embed icon_agent.ico
var embeddedAgentIcon []byte

//go:embed icon_server.ico
var embeddedServerIcon []byte

const (
	GWLP_WNDPROC = -4
	WM_DESTROY   = 0x0002
	WM_CLOSE     = 0x0010
	WM_SETICON   = 0x0080
	WM_APP       = 0x8000
	WM_TRAYICON  = WM_APP + 100
	WM_NULL      = 0x0000

	WM_LBUTTONUP     = 0x0202
	WM_LBUTTONDBLCLK = 0x0203
	WM_RBUTTONUP     = 0x0205

	SW_HIDE       = 0
	SW_SHOWNORMAL = 1
	SW_SHOW       = 5
	SW_RESTORE    = 9

	NIM_ADD    = 0x00000000
	NIM_MODIFY = 0x00000001
	NIM_DELETE = 0x00000002

	NIF_MESSAGE = 0x00000001
	NIF_ICON    = 0x00000002
	NIF_TIP     = 0x00000004

	MF_STRING    = 0x00000000
	MF_SEPARATOR = 0x00000800

	TPM_RETURNCMD   = 0x0100
	TPM_RIGHTBUTTON = 0x0002

	IMAGE_ICON      = 1
	LR_LOADFROMFILE = 0x00000010
	LR_DEFAULTSIZE  = 0x00000040

	ICON_SMALL = 0
	ICON_BIG   = 1

	CMD_TRAY_OPEN         = 1001
	CMD_TRAY_EXIT         = 1002
	CMD_TRAY_SOFTWARE     = 1003
	CMD_TRAY_TICKETS_NEW  = 1004
	CMD_TRAY_TICKETS_LIST = 1005
)

var (
	user32  = windows.NewLazySystemDLL("user32.dll")
	shell32 = windows.NewLazySystemDLL("shell32.dll")

	procSetWindowLongPtrW   = user32.NewProc("SetWindowLongPtrW")
	procSetWindowLongW      = user32.NewProc("SetWindowLongW")
	procCallWindowProcW     = user32.NewProc("CallWindowProcW")
	procShowWindow          = user32.NewProc("ShowWindow")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procCreatePopupMenu     = user32.NewProc("CreatePopupMenu")
	procAppendMenuW         = user32.NewProc("AppendMenuW")
	procTrackPopupMenuEx    = user32.NewProc("TrackPopupMenuEx")
	procDestroyMenu         = user32.NewProc("DestroyMenu")
	procGetCursorPos        = user32.NewProc("GetCursorPos")
	procPostMessageW        = user32.NewProc("PostMessageW")
	procSendMessageW        = user32.NewProc("SendMessageW")
	procDestroyWindow       = user32.NewProc("DestroyWindow")
	procLoadImageW          = user32.NewProc("LoadImageW")

	procShellNotifyIconW = shell32.NewProc("Shell_NotifyIconW")
)

type NOTIFYICONDATAW struct {
	CbSize            uint32
	_                 uint32 // 4-byte padding before 8-byte pointer HWnd on 64-bit
	HWnd              windows.HWND
	UID               uint32
	UFlags            uint32
	UCallbackMessage  uint32
	_                 uint32 // 4-byte padding before 8-byte pointer HIcon on 64-bit
	HIcon             windows.Handle
	SzTip             [128]uint16
	DwState           uint32
	DwStateMask       uint32
	SzInfo            [256]uint16
	UTimeoutOrVersion uint32
	SzInfoTitle       [64]uint16
	DwInfoFlags       uint32
	GuidItem          windows.GUID
	HBalloonIcon      windows.Handle
}

type POINT struct {
	X int32
	Y int32
}

var (
	trayMu           sync.Mutex
	oldWndProc       uintptr
	mainHwnd         windows.HWND
	agentIconHandle  windows.Handle
	serverIconHandle windows.Handle
	currentWebview   webview2.WebView
	currentMode      string // "agent" or "server"
	currentServerURL string
	isQuitting       bool
	trayActive       bool
)

func setWindowLongPtr(hwnd windows.HWND, index int32, value uintptr) (uintptr, error) {
	if procSetWindowLongPtrW.Find() == nil {
		r, _, err := procSetWindowLongPtrW.Call(uintptr(hwnd), uintptr(index), value)
		return r, err
	}
	r, _, err := procSetWindowLongW.Call(uintptr(hwnd), uintptr(index), value)
	return r, err
}

func getAppIcon(mode ...string) windows.Handle {
	m := currentMode
	if len(mode) > 0 && mode[0] != "" {
		m = mode[0]
	}
	if m == "" {
		m = "server"
	}

	if m == "agent" && agentIconHandle != 0 {
		return agentIconHandle
	}
	if m == "server" && serverIconHandle != 0 {
		return serverIconHandle
	}

	var iconBytes []byte
	var fileName string
	if m == "agent" {
		iconBytes = embeddedAgentIcon
		fileName = "homelab-rmm-agent.ico"
	} else {
		iconBytes = embeddedServerIcon
		fileName = "homelab-rmm-server.ico"
	}

	tempIconPath := filepath.Join(os.TempDir(), fileName)
	if len(iconBytes) > 0 {
		_ = os.WriteFile(tempIconPath, iconBytes, 0o644)
	}

	pathPtr, err := windows.UTF16PtrFromString(tempIconPath)
	if err == nil {
		hIcon, _, _ := procLoadImageW.Call(
			0,
			uintptr(unsafe.Pointer(pathPtr)),
			IMAGE_ICON,
			0,
			0,
			LR_LOADFROMFILE|LR_DEFAULTSIZE,
		)
		if hIcon != 0 {
			handle := windows.Handle(hIcon)
			if m == "agent" {
				agentIconHandle = handle
			} else {
				serverIconHandle = handle
			}
			return handle
		}
	}

	// Fallback to system application icon
	hIcon, _, _ := procLoadImageW.Call(0, 32512, IMAGE_ICON, 0, 0, LR_DEFAULTSIZE)
	return windows.Handle(hIcon)
}

func restoreWindow(hwnd windows.HWND) {
	procShowWindow.Call(uintptr(hwnd), SW_SHOW)
	procShowWindow.Call(uintptr(hwnd), SW_RESTORE)
	procSetForegroundWindow.Call(uintptr(hwnd))
}

// portalStartURL is the address that trades a pass for a portal sign-in and
// lands on tab. The pass is the only thing the server believes: which device
// and which Windows user this is were decided by the agent, not by us.
func portalStartURL(serverURL, pass, tab string, newTicket bool) string {
	params := url.Values{}
	params.Set("pass", pass)
	if tab == "tickets" {
		params.Set("tab", "tickets")
		if newTicket {
			params.Set("new", "1")
		}
	}
	return strings.TrimRight(serverURL, "/") + "/portal/start?" + params.Encode()
}

// openPortal asks the local agent for a fresh pass and opens the portal with
// it. Asking can take a server round trip, so it runs off the window thread.
func openPortal(tab string, newTicket bool) {
	wv := currentWebview
	if wv == nil || currentServerURL == "" {
		return
	}
	go func() {
		pass, err := portalpipe.Ask(portalpipe.Name)
		wv.Dispatch(func() {
			if err != nil {
				wv.SetHtml(renderPortalErrorPage(err.Error()))
				return
			}
			wv.Navigate(portalStartURL(currentServerURL, pass, tab, newTicket))
		})
	}()
}

// navigateServer opens a console page (server mode).
func navigateServer(path string) {
	wv := currentWebview
	if wv == nil || currentServerURL == "" {
		return
	}
	wv.Dispatch(func() {
		wv.Navigate(strings.TrimRight(currentServerURL, "/") + path)
	})
}

func showTrayMenu(hwnd windows.HWND) {
	var pt POINT
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))

	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hMenu)

	if currentMode == "agent" {
		// Client-facing agent menu: ONLY software drawer and scoped support tickets.
		// "Open Dashboard" is strictly NOT shown to the client.
		drawerText, _ := windows.UTF16PtrFromString("Self-Service Software Drawer…")
		procAppendMenuW.Call(hMenu, MF_STRING, uintptr(CMD_TRAY_SOFTWARE), uintptr(unsafe.Pointer(drawerText)))

		ticketNewText, _ := windows.UTF16PtrFromString("Submit Support Ticket…")
		procAppendMenuW.Call(hMenu, MF_STRING, uintptr(CMD_TRAY_TICKETS_NEW), uintptr(unsafe.Pointer(ticketNewText)))

		ticketsListText, _ := windows.UTF16PtrFromString("View Support Tickets…")
		procAppendMenuW.Call(hMenu, MF_STRING, uintptr(CMD_TRAY_TICKETS_LIST), uintptr(unsafe.Pointer(ticketsListText)))
	} else {
		// Server console menu
		openText, _ := windows.UTF16PtrFromString("Open Dashboard")
		procAppendMenuW.Call(hMenu, MF_STRING, uintptr(CMD_TRAY_OPEN), uintptr(unsafe.Pointer(openText)))

		catalogText, _ := windows.UTF16PtrFromString("Software Catalog…")
		procAppendMenuW.Call(hMenu, MF_STRING, uintptr(CMD_TRAY_SOFTWARE), uintptr(unsafe.Pointer(catalogText)))

		ticketsText, _ := windows.UTF16PtrFromString("Helpdesk Tickets…")
		procAppendMenuW.Call(hMenu, MF_STRING, uintptr(CMD_TRAY_TICKETS_LIST), uintptr(unsafe.Pointer(ticketsText)))
	}

	procAppendMenuW.Call(hMenu, MF_SEPARATOR, 0, 0)
	exitText, _ := windows.UTF16PtrFromString("Exit")
	procAppendMenuW.Call(hMenu, MF_STRING, uintptr(CMD_TRAY_EXIT), uintptr(unsafe.Pointer(exitText)))

	// Bring window to foreground before TrackPopupMenuEx so clicking outside closes menu
	procSetForegroundWindow.Call(uintptr(hwnd))

	cmd, _, _ := procTrackPopupMenuEx.Call(
		hMenu,
		uintptr(TPM_RETURNCMD|TPM_RIGHTBUTTON),
		uintptr(pt.X),
		uintptr(pt.Y),
		uintptr(hwnd),
		0,
	)

	procPostMessageW.Call(uintptr(hwnd), WM_NULL, 0, 0)

	switch cmd {
	case CMD_TRAY_OPEN:
		restoreWindow(hwnd)
		if currentMode == "agent" {
			openPortal("software", false)
		} else {
			navigateServer("")
		}
	case CMD_TRAY_SOFTWARE:
		restoreWindow(hwnd)
		if currentMode == "agent" {
			openPortal("software", false)
		} else {
			navigateServer("/software-catalog")
		}
	case CMD_TRAY_TICKETS_NEW:
		restoreWindow(hwnd)
		if currentMode == "agent" {
			openPortal("tickets", true)
		} else {
			navigateServer("/portal/tickets?tab=tickets&new=1")
		}
	case CMD_TRAY_TICKETS_LIST:
		restoreWindow(hwnd)
		if currentMode == "agent" {
			openPortal("tickets", false)
		} else {
			navigateServer("/tickets")
		}
	case CMD_TRAY_EXIT:
		exitApp()
	}
}

func exitApp() {
	trayMu.Lock()
	if isQuitting {
		trayMu.Unlock()
		return
	}
	isQuitting = true
	trayMu.Unlock()

	removeTrayIcon()

	if currentWebview != nil {
		currentWebview.Dispatch(func() {
			currentWebview.Terminate()
		})
	}
}

func addTrayIcon(hwnd windows.HWND) bool {
	trayMu.Lock()
	defer trayMu.Unlock()

	icon := getAppIcon()
	var nid NOTIFYICONDATAW
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = hwnd
	nid.UID = 1
	nid.UFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
	nid.UCallbackMessage = WM_TRAYICON
	nid.HIcon = icon

	tip := "Homelab RMM Server"
	if currentMode == "agent" {
		tip = "Homelab Agent"
	}
	copy(nid.SzTip[:], windows.StringToUTF16(tip))

	r, _, _ := procShellNotifyIconW.Call(NIM_ADD, uintptr(unsafe.Pointer(&nid)))
	trayActive = r != 0
	return trayActive
}

func removeTrayIcon() {
	trayMu.Lock()
	defer trayMu.Unlock()

	if !trayActive || mainHwnd == 0 {
		return
	}
	var nid NOTIFYICONDATAW
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = mainHwnd
	nid.UID = 1
	procShellNotifyIconW.Call(NIM_DELETE, uintptr(unsafe.Pointer(&nid)))
	trayActive = false
}

func subclassWndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case WM_CLOSE:
		trayMu.Lock()
		quitting := isQuitting
		trayMu.Unlock()

		if !quitting {
			// Minimize / hide to tray instead of closing
			procShowWindow.Call(hwnd, SW_HIDE)
			return 0
		}

	case WM_TRAYICON:
		event := uint32(lParam & 0xFFFF)
		switch event {
		case WM_LBUTTONUP, WM_LBUTTONDBLCLK:
			restoreWindow(windows.HWND(hwnd))
			if currentMode == "agent" {
				openPortal("software", false)
			} else {
				navigateServer("")
			}
			return 0
		case WM_RBUTTONUP:
			showTrayMenu(windows.HWND(hwnd))
			return 0
		}
	}

	r, _, _ := procCallWindowProcW.Call(oldWndProc, hwnd, uintptr(msg), wParam, lParam)
	return r
}

func setupTray(wv webview2.WebView, mode, srvURL string) {
	hwnd := windows.HWND(wv.Window())
	mainHwnd = hwnd
	currentWebview = wv
	currentMode = mode
	currentServerURL = srvURL

	// Set window icons (Blue for agent, Black for server)
	icon := getAppIcon(mode)
	if icon != 0 {
		procSendMessageW.Call(uintptr(hwnd), WM_SETICON, ICON_BIG, uintptr(icon))
		procSendMessageW.Call(uintptr(hwnd), WM_SETICON, ICON_SMALL, uintptr(icon))
	}

	// Register tray icon
	addTrayIcon(hwnd)

	// Subclass window procedure
	cb := windows.NewCallback(subclassWndProc)
	old, err := setWindowLongPtr(hwnd, GWLP_WNDPROC, cb)
	if err == nil || old != 0 {
		oldWndProc = old
	}
}
