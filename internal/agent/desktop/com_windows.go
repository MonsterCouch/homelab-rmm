//go:build windows

package desktop

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Pure-Go COM. Everything the DXGI capture path, the D3D11 video processor
// and the Media Foundation encoder need is reached through vtable calls made
// with syscall.SyscallN, so the agent stays a single CGO-free binary. Method
// indices below were generated from the Windows SDK header vtable
// declarations (d3d11.h, dxgi*.h, mftransform.h, mfobjects.h, codecapi.h)
// rather than typed from memory; a wrong index calls the wrong driver entry
// point, so they are worth re-deriving if one is ever added.

// guid is a COM GUID in its in-memory layout.
type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func mkGUID(d1 uint32, d2, d3 uint16, d4 ...byte) guid {
	g := guid{Data1: d1, Data2: d2, Data3: d3}
	copy(g.Data4[:], d4)
	return g
}

var (
	iidIDXGIFactory1     = mkGUID(0x770aae78, 0xf26f, 0x4dba, 0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87)
	iidIDXGIOutput1      = mkGUID(0x00cddea8, 0x939b, 0x4b83, 0xa3, 0x40, 0xa6, 0x85, 0x22, 0x66, 0x66, 0xcc)
	iidIDXGIDevice       = mkGUID(0x54ec77fa, 0x1377, 0x44e6, 0x8c, 0x32, 0x88, 0xfd, 0x5f, 0x44, 0xc8, 0x4c)
	iidID3D11Texture2D   = mkGUID(0x6f15aaf2, 0xd208, 0x4e89, 0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c)
	iidID3D11VideoDevice = mkGUID(0x10ec4d5b, 0x975a, 0x4689, 0xb9, 0xe4, 0xd0, 0xaa, 0xc3, 0x0f, 0xe3, 0x33)
	iidID3D11VideoCtx    = mkGUID(0x61f21c45, 0x3c0e, 0x4a74, 0x9c, 0xea, 0x67, 0x10, 0x0d, 0x9a, 0xd5, 0xe4)
	iidICodecAPI         = mkGUID(0x901db4c7, 0x31ce, 0x41a2, 0x85, 0xdc, 0x8f, 0xa0, 0xbf, 0x41, 0xb8, 0xda)
)

// HRESULTs the capture and encode paths branch on.
const (
	hrOK                  = 0x00000000
	hrFalse               = 0x00000001
	hrAccessDenied        = 0x80070005
	hrDXGIWaitTimeout     = 0x887A0027
	hrDXGIAccessLost      = 0x887A0026
	hrDXGINotFound        = 0x887A0002
	hrDXGIUnsupported     = 0x887A0004
	hrDXGIDeviceRemoved   = 0x887A0005
	hrDXGIDeviceReset     = 0x887A0007
	hrDXGINotCurrentlyAvl = 0x887A0022
	hrDXGISessionDisc     = 0x887A0028
	hrMFNeedMoreInput     = 0xC00D6D72 // MF_E_TRANSFORM_NEED_MORE_INPUT
	hrMFStreamChange      = 0xC00D6D61 // MF_E_TRANSFORM_STREAM_CHANGE
	hrMFTypeNotSet        = 0xC00D6D60 // MF_E_TRANSFORM_TYPE_NOT_SET
	hrMFNotAccepting      = 0xC00D36B5 // MF_E_NOTACCEPTING
	hrMFNoMoreTypes       = 0xC00D36B9 // MF_E_NO_MORE_TYPES
	hrEInvalidArg         = 0x80070057
	hrENoInterface        = 0x80004002
	hrENotImpl            = 0x80004001
	hrRPCChangedMode      = 0x80010106 // RPC_E_CHANGED_MODE: COM already initialised the other way
)

// hresult is an error carrying a failed HRESULT.
type hresult uint32

func (h hresult) Error() string {
	switch uint32(h) {
	case hrDXGIAccessLost:
		return "DXGI_ERROR_ACCESS_LOST (0x887A0026)"
	case hrDXGIWaitTimeout:
		return "DXGI_ERROR_WAIT_TIMEOUT (0x887A0027)"
	case hrDXGIUnsupported:
		return "DXGI_ERROR_UNSUPPORTED (0x887A0004)"
	case hrDXGIDeviceRemoved:
		return "DXGI_ERROR_DEVICE_REMOVED (0x887A0005)"
	case hrDXGINotCurrentlyAvl:
		return "DXGI_ERROR_NOT_CURRENTLY_AVAILABLE (0x887A0022)"
	case hrAccessDenied:
		return "E_ACCESSDENIED (0x80070005)"
	}
	return fmt.Sprintf("HRESULT 0x%08X", uint32(h))
}

// check turns a raw HRESULT return value into an error.
func check(r uintptr) error {
	if int32(uint32(r)) < 0 {
		return hresult(uint32(r))
	}
	return nil
}

// isHR reports whether err is the given failed HRESULT.
func isHR(err error, want uint32) bool {
	h, ok := err.(hresult)
	return ok && uint32(h) == want
}

// com is one COM interface pointer: the address of a pointer to a vtable.
// The zero value is a nil interface and every method on it is a no-op.
type com struct{ p unsafe.Pointer }

func (c com) nil() bool { return c.p == nil }

// call invokes vtable method idx. The interface pointer is passed as the
// implicit first argument.
func (c com) call(idx int, args ...uintptr) uintptr {
	vtbl := *(*unsafe.Pointer)(c.p)
	fn := *(*uintptr)(unsafe.Add(vtbl, idx*int(unsafe.Sizeof(uintptr(0)))))
	var buf [14]uintptr
	a := append(buf[:0], uintptr(c.p))
	a = append(a, args...)
	r, _, _ := syscall.SyscallN(fn, a...)
	return r
}

// release drops one reference. Safe on a nil interface.
func (c *com) release() {
	if c.p != nil {
		c.call(2)
		c.p = nil
	}
}

// addRef takes one more reference.
func (c com) addRef() { c.call(1) }

// queryInterface returns c as another interface.
func (c com) queryInterface(iid *guid) (com, error) {
	var out unsafe.Pointer
	if err := check(c.call(0, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&out)))); err != nil {
		return com{}, err
	}
	return com{out}, nil
}

// u32 narrows a Go int to the unsigned the API wants.
func u32(i int) uintptr { return uintptr(uint32(i)) }

// b2u is the Win32 BOOL for a Go bool.
func b2u(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}
