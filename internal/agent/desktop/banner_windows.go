//go:build windows

package desktop

import (
	"log/slog"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	gdi32 = windows.NewLazySystemDLL("gdi32.dll")

	procRegisterClassExW          = user32.NewProc("RegisterClassExW")
	procCreateWindowExW           = user32.NewProc("CreateWindowExW")
	procDefWindowProcW            = user32.NewProc("DefWindowProcW")
	procDestroyWindow             = user32.NewProc("DestroyWindow")
	procSetLayeredWindowAttrs     = user32.NewProc("SetLayeredWindowAttributes")
	procShowWindow                = user32.NewProc("ShowWindow")
	procUpdateWindow              = user32.NewProc("UpdateWindow")
	procGetMessageW               = user32.NewProc("GetMessageW")
	procTranslateMessage          = user32.NewProc("TranslateMessage")
	procDispatchMessageW          = user32.NewProc("DispatchMessageW")
	procPostMessageW              = user32.NewProc("PostMessageW")
	procPostQuitMessage           = user32.NewProc("PostQuitMessage")
	procBeginPaint                = user32.NewProc("BeginPaint")
	procEndPaint                  = user32.NewProc("EndPaint")
	procDrawTextW                 = user32.NewProc("DrawTextW")

	procCreateSolidBrush          = gdi32.NewProc("CreateSolidBrush")
	procDeleteObject              = gdi32.NewProc("DeleteObject")
	procSetBkMode                 = gdi32.NewProc("SetBkMode")
	procSetTextColor              = gdi32.NewProc("SetTextColor")
	procCreateFontW               = gdi32.NewProc("CreateFontW")
	procSelectObject              = gdi32.NewProc("SelectObject")
	procRoundRect                 = gdi32.NewProc("RoundRect")
	procCreatePen                 = gdi32.NewProc("CreatePen")
)

const (
	WS_POPUP              = 0x80000000
	WS_VISIBLE            = 0x10000000

	WS_EX_TOPMOST         = 0x00000008
	WS_EX_TRANSPARENT     = 0x00000020
	WS_EX_TOOLWINDOW      = 0x00000080
	WS_EX_LAYERED         = 0x00080000
	WS_EX_NOACTIVATE      = 0x08000000

	SW_SHOWNA             = 8
	LWA_ALPHA             = 0x00000002

	DT_CENTER             = 0x00000001
	DT_VCENTER            = 0x00000004
	DT_SINGLELINE         = 0x00000020

	SM_CXSCREEN           = 0
	SM_CYSCREEN           = 1

	WM_PAINT              = 0x000F
	WM_CLOSE              = 0x0010
	WM_DESTROY            = 0x0002
)

type wndClassExW struct {
	size       uint32
	style      uint32
	wndProc    uintptr
	clsExtra   int32
	wndExtra   int32
	instance   windows.Handle
	icon       windows.Handle
	cursor     windows.Handle
	background windows.Handle
	menuName   *uint16
	className  *uint16
	iconSm     windows.Handle
}

type paintStruct struct {
	hdc         uintptr
	erase       int32
	rcPaint     rect
	restore     int32
	incUpdate   int32
	rgbReserved [32]byte
}

type rect struct {
	left, top, right, bottom int32
}

var (
	bannerClassRegistered sync.Once
	bannerClassName       = windows.StringToUTF16Ptr("HomelabRMM_ConnectionBanner")
)

func bannerWndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case WM_PAINT:
		var ps paintStruct
		hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		if hdc != 0 {
			w := int32(360)
			h := int32(36)

			// Background rounded rect: sleek dark slate #0F172A
			bgBrush, _, _ := procCreateSolidBrush.Call(uintptr(0x002A170F))
			borderPen, _, _ := procCreatePen.Call(0, 1, uintptr(0x0047321E)) // border #1E3247
			oldBrush, _, _ := procSelectObject.Call(hdc, bgBrush)
			oldPen, _, _ := procSelectObject.Call(hdc, borderPen)

			procRoundRect.Call(hdc, 0, 0, uintptr(w), uintptr(h), 12, 12)

			procSelectObject.Call(hdc, oldBrush)
			procSelectObject.Call(hdc, oldPen)
			procDeleteObject.Call(bgBrush)
			procDeleteObject.Call(borderPen)

			// Draw green connection indicator circle/bullet & text
			procSetBkMode.Call(hdc, 1) // TRANSPARENT

			// Segoe UI font
			fontName := windows.StringToUTF16Ptr("Segoe UI")
			font, _, _ := procCreateFontW.Call(
				uintptr(16), 0, 0, 0,
				600, // FW_SEMIBOLD
				0, 0, 0, 1, 0, 0, 2, 0,
				uintptr(unsafe.Pointer(fontName)),
			)
			oldFont, _, _ := procSelectObject.Call(hdc, font)

			// Green dot and text: "● IT Support is connected"
			procSetTextColor.Call(hdc, uintptr(0x0048DE5B)) // bright green bullet
			bulletText := windows.StringToUTF16Ptr("●")
			bulletRc := rect{left: 12, top: 0, right: 30, bottom: h}
			procDrawTextW.Call(
				hdc,
				uintptr(unsafe.Pointer(bulletText)),
				uintptr(len("●")),
				uintptr(unsafe.Pointer(&bulletRc)),
				DT_CENTER|DT_VCENTER|DT_SINGLELINE,
			)

			// Text in crisp white
			procSetTextColor.Call(hdc, uintptr(0x00F8FAFC))
			bannerText := windows.StringToUTF16Ptr("IT Support is connected")
			textRc := rect{left: 32, top: 0, right: w - 12, bottom: h}
			procDrawTextW.Call(
				hdc,
				uintptr(unsafe.Pointer(bannerText)),
				uintptr(len("IT Support is connected")),
				uintptr(unsafe.Pointer(&textRc)),
				DT_VCENTER|DT_SINGLELINE,
			)

			procSelectObject.Call(hdc, oldFont)
			procDeleteObject.Call(font)

			procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		}
		return 0

	case WM_CLOSE:
		procDestroyWindow.Call(hwnd)
		return 0

	case WM_DESTROY:
		procPostQuitMessage.Call(0)
		return 0
	}

	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
}

func registerBannerClass() {
	var wc wndClassExW
	wc.size = uint32(unsafe.Sizeof(wc))
	wc.style = 0x0003 // CS_HREDRAW | CS_VREDRAW
	wc.wndProc = syscall.NewCallback(bannerWndProc)
	wc.instance = 0
	wc.className = bannerClassName
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
}

// showBanner creates a lightweight floating non-interactive top banner in the
// user's interactive desktop indicating that IT Support is connected.
// Returns a stop function that closes the banner.
func showBanner() func() {
	bannerClassRegistered.Do(registerBannerClass)

	hwndChan := make(chan uintptr, 1)

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		screenWidth, _, _ := procGetSystemMetrics.Call(SM_CXSCREEN)
		if screenWidth == 0 {
			screenWidth = 1920
		}

		w := int32(360)
		h := int32(36)
		x := (int32(screenWidth) - w) / 2
		y := int32(10)

		hwnd, _, _ := procCreateWindowExW.Call(
			uintptr(WS_EX_TOPMOST|WS_EX_TOOLWINDOW|WS_EX_NOACTIVATE|WS_EX_LAYERED|WS_EX_TRANSPARENT),
			uintptr(unsafe.Pointer(bannerClassName)),
			0,
			uintptr(WS_POPUP|WS_VISIBLE),
			uintptr(x), uintptr(y),
			uintptr(w), uintptr(h),
			0, 0, 0, 0,
		)

		if hwnd == 0 {
			slog.Debug("could not create remote connection banner window")
			hwndChan <- 0
			return
		}

		// 95% opacity
		procSetLayeredWindowAttrs.Call(hwnd, 0, 240, LWA_ALPHA)
		procShowWindow.Call(hwnd, SW_SHOWNA)
		procUpdateWindow.Call(hwnd)

		hwndChan <- hwnd

		// Message loop
		type msgStruct struct {
			hwnd    uintptr
			message uint32
			wParam  uintptr
			lParam  uintptr
			time    uint32
			pt      struct{ x, y int32 }
		}

		var m msgStruct
		for {
			r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
			if int32(r) <= 0 {
				break
			}
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
		}
	}()

	var hwnd uintptr
	select {
	case hwnd = <-hwndChan:
	case <-time.After(2 * time.Second):
	}

	return func() {
		if hwnd != 0 {
			procPostMessageW.Call(hwnd, WM_CLOSE, 0, 0)
		}
	}
}
