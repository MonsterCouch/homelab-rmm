package winwebauthn

import (
	"errors"
	"fmt"
)

// ErrUnsupported is returned on platforms without the Windows WebAuthn API.
var ErrUnsupported = errors.New("the Windows WebAuthn API is not available on this platform; signing needs Windows 10 version 1903 or later")

// Sentinel causes a caller can test with errors.Is to decide whether to
// retry, give up quietly or show the operator a message.
var (
	ErrCancelled     = errors.New("the signing prompt was cancelled")
	ErrTimeout       = errors.New("the signing prompt timed out before a key or Windows Hello answered")
	ErrNoCredentials = errors.New("none of the registered security keys or Windows Hello credentials for this account were found on this computer")
)

// HRESULT values the API reports for the outcomes above (winerror.h, ncrypt.h).
const (
	hrErrorCancelled   = 0x800704C7 // HRESULT_FROM_WIN32(ERROR_CANCELLED)
	hrErrorTimeout     = 0x800705B4 // HRESULT_FROM_WIN32(ERROR_TIMEOUT)
	hrUserCancelled    = 0x80090036 // NTE_USER_CANCELLED
	hrNotFound         = 0x80090011 // NTE_NOT_FOUND
	hrDeviceNotFound   = 0x80090035 // NTE_DEVICE_NOT_FOUND
	hrInvalidParameter = 0x80090027 // NTE_INVALID_PARAMETER
	hrNotSupported     = 0x80090029 // NTE_NOT_SUPPORTED
	hrExists           = 0x8009000F // NTE_EXISTS
)

// Error is a failed WebAuthn call: the raw HRESULT, the W3C error name the DLL
// gives it (when the DLL could be asked) and a sentence for the operator.
type Error struct {
	Func    string
	HResult uint32
	Name    string // WebAuthNGetErrorName, for example "NotAllowedError"; may be empty
}

// Error returns a full sentence.
func (e *Error) Error() string {
	return fmt.Sprintf("%s failed: %s (HRESULT 0x%08X)", e.Func, describeHResult(e.HResult, e.Name), e.HResult)
}

// Is lets errors.Is match the sentinel causes.
func (e *Error) Is(target error) bool {
	switch target {
	case ErrCancelled:
		return e.HResult == hrErrorCancelled || e.HResult == hrUserCancelled
	case ErrTimeout:
		return e.HResult == hrErrorTimeout
	case ErrNoCredentials:
		return e.HResult == hrNotFound || e.HResult == hrDeviceNotFound
	}
	return false
}

// describeHResult turns the common outcomes into something an operator can act
// on. NTE_NOT_FOUND and NTE_DEVICE_NOT_FOUND share the W3C name
// "NotAllowedError" with cancel and timeout, so the HRESULT decides.
func describeHResult(hr uint32, name string) string {
	switch hr {
	case hrErrorCancelled, hrUserCancelled:
		return ErrCancelled.Error()
	case hrErrorTimeout:
		return ErrTimeout.Error()
	case hrNotFound, hrDeviceNotFound:
		return ErrNoCredentials.Error()
	case hrInvalidParameter:
		return "Windows rejected the request as invalid, which usually means the relying party id does not match the registered credential"
	case hrNotSupported:
		return "the authenticator does not support this request"
	case hrExists:
		return "the credential already exists"
	}
	if name != "" && name != "UnknownError" {
		return "Windows reported " + name
	}
	return "Windows reported an unknown WebAuthn error"
}
