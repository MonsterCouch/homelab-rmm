//go:build windows

package agent

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procIsProcessCritical = modKernel32.NewProc("IsProcessCritical")
)

// isCriticalProcess reports whether Windows would bugcheck if this process
// ended. The flag is not a name - a driver, a security product or a service
// can set it on itself - so a deny list of names is not enough on its own;
// this is the machine's own answer. It needs only
// PROCESS_QUERY_LIMITED_INFORMATION, which the SYSTEM service always has.
//
// Anything that cannot be determined (the call is Windows 8 / Server 2012 and
// later, the process may be gone, the handle may be refused) reports false:
// the name list above and the pid floor still stand, and refusing every
// process we cannot query would break the Kill button on a protected process
// an operator legitimately needs to end.
func isCriticalProcess(pid int32) bool {
	if err := procIsProcessCritical.Find(); err != nil {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var critical int32
	r, _, _ := procIsProcessCritical.Call(uintptr(h), uintptr(unsafe.Pointer(&critical)))
	return r != 0 && critical != 0
}
