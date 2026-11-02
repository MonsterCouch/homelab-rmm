//go:build windows

package winwebauthn

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Options describes one assertion request.
type Options struct {
	RPID               string
	Origin             string
	Challenge          []byte
	AllowCredentialIDs [][]byte
	UserVerification   string // required, preferred or discouraged; empty lets Windows decide
	Timeout            time.Duration
}

// Assertion is the authenticator's answer, copied out of Windows memory.
type Assertion struct {
	CredentialID      []byte
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
}

var (
	webauthnDLL = windows.NewLazySystemDLL("webauthn.dll")

	procGetAPIVersion   = webauthnDLL.NewProc("WebAuthNGetApiVersionNumber")
	procPlatformAvail   = webauthnDLL.NewProc("WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable")
	procGetAssertion    = webauthnDLL.NewProc("WebAuthNAuthenticatorGetAssertion")
	procFreeAssertion   = webauthnDLL.NewProc("WebAuthNFreeAssertion")
	procGetCancelID     = webauthnDLL.NewProc("WebAuthNGetCancellationId")
	procCancelOperation = webauthnDLL.NewProc("WebAuthNCancelCurrentOperation")
	procGetErrorName    = webauthnDLL.NewProc("WebAuthNGetErrorName")

	user32DLL               = windows.NewLazySystemDLL("user32.dll")
	procGetForegroundWindow = user32DLL.NewProc("GetForegroundWindow")
	kernel32DLL             = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleWindow    = kernel32DLL.NewProc("GetConsoleWindow")
)

// Constants from webauthn.h.
const (
	clientDataVersion1    = 1 // WEBAUTHN_CLIENT_DATA_CURRENT_VERSION
	credentialVersion1    = 1 // WEBAUTHN_CREDENTIAL_CURRENT_VERSION
	getAssertionOptionsV1 = 1 // WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1
	getAssertionOptionsV3 = 3 // first version with pCancellationId

	// WEBAUTHN_API_VERSION_3 is the first API version whose get-assertion
	// options accept a cancellation id.
	apiVersionCancellation = 3

	uvAny         = 0 // WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY
	uvRequired    = 1
	uvPreferred   = 2
	uvDiscouraged = 3

	defaultTimeout = 2 * time.Minute
)

// webauthnClientData is WEBAUTHN_CLIENT_DATA version 1 (24 bytes).
type webauthnClientData struct {
	Version      uint32  // 0
	ClientDataSz uint32  // 4
	ClientData   *byte   // 8
	HashAlgID    *uint16 // 16, L"SHA-256"
}

// webauthnCredential is WEBAUTHN_CREDENTIAL version 1 (24 bytes).
type webauthnCredential struct {
	Version uint32  // 0
	IDSize  uint32  // 4
	ID      *byte   // 8
	Type    *uint16 // 16, L"public-key"
}

// webauthnCredentials is WEBAUTHN_CREDENTIALS (16 bytes: count, 4 bytes of
// padding the C compiler inserts before the pointer, pointer).
type webauthnCredentials struct {
	Count       uint32              // 0
	_           uint32              // 4
	Credentials *webauthnCredential // 8
}

// webauthnExtensions is WEBAUTHN_EXTENSIONS (16 bytes), the same shape as the
// credential list. It is always left empty here.
type webauthnExtensions struct {
	Count      uint32         // 0
	_          uint32         // 4
	Extensions unsafe.Pointer // 8
}

// getAssertionOptions is WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS through
// version 3 (80 bytes). dwVersion tells the DLL how much of it to read, so the
// same struct serves version 1 on Windows builds that predate cancellation.
type getAssertionOptions struct {
	Version        uint32              // 0
	TimeoutMillis  uint32              // 4
	CredentialList webauthnCredentials // 8
	Extensions     webauthnExtensions  // 24
	Attachment     uint32              // 40
	UserVerif      uint32              // 44
	Flags          uint32              // 48
	_              uint32              // 52
	U2fAppID       *uint16             // 56 (v2)
	U2fAppIDUsed   *int32              // 64 (v2)
	CancellationID *windows.GUID       // 72 (v3)
}

// webauthnAssertion is the WEBAUTHN_ASSERTION version 1 prefix (72 bytes). The
// DLL returns a newer version, but later versions only append fields, so
// reading the prefix is valid for any of them; the client data is our own.
type webauthnAssertion struct {
	Version     uint32             // 0
	AuthDataSz  uint32             // 4
	AuthData    *byte              // 8
	SignatureSz uint32             // 16
	_           uint32             // 20
	Signature   *byte              // 24
	Credential  webauthnCredential // 32
	UserIDSz    uint32             // 56
	_           uint32             // 60
	UserID      *byte              // 64
}

func find(p *windows.LazyProc) error {
	if err := p.Find(); err != nil {
		return fmt.Errorf("webauthn.dll does not provide %s, so this Windows version is too old for WebAuthn signing: %w", p.Name, err)
	}
	return nil
}

// APIVersion returns WebAuthNGetApiVersionNumber.
func APIVersion() (uint32, error) {
	if err := find(procGetAPIVersion); err != nil {
		return 0, err
	}
	r, _, _ := syscall.SyscallN(procGetAPIVersion.Addr())
	return uint32(r), nil
}

// PlatformAuthenticatorAvailable reports whether Windows Hello can verify the
// user on this machine. It shows no UI.
func PlatformAuthenticatorAvailable() (bool, error) {
	if err := find(procPlatformAvail); err != nil {
		return false, err
	}
	var avail int32
	r, _, _ := syscall.SyscallN(procPlatformAvail.Addr(), uintptr(unsafe.Pointer(&avail)))
	if hr := uint32(r); int32(hr) < 0 {
		return false, newError("WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable", hr)
	}
	return avail != 0, nil
}

// ownerWindow picks the window that parents Windows' prompt: the foreground
// window (normally the terminal the operator is typing in), else the console
// window. Zero is accepted by the API but the prompt may then open behind
// other windows.
func ownerWindow() uintptr {
	if procGetForegroundWindow.Find() == nil {
		if h, _, _ := syscall.SyscallN(procGetForegroundWindow.Addr()); h != 0 {
			return h
		}
	}
	if procGetConsoleWindow.Find() == nil {
		if h, _, _ := syscall.SyscallN(procGetConsoleWindow.Addr()); h != 0 {
			return h
		}
	}
	return 0
}

func userVerification(s string) (uint32, error) {
	switch s {
	case "":
		return uvAny, nil
	case "required":
		return uvRequired, nil
	case "preferred":
		return uvPreferred, nil
	case "discouraged":
		return uvDiscouraged, nil
	}
	return 0, fmt.Errorf("user verification %q is not one of required, preferred or discouraged", s)
}

// GetAssertion asks Windows for an assertion over SHA-256 of
// ClientDataJSON(o.Challenge, o.Origin). It blocks while Windows shows its
// prompt. When ctx ends first, the prompt is cancelled through
// WebAuthNCancelCurrentOperation if this Windows build supports it; otherwise
// the call returns only when the prompt does.
func GetAssertion(ctx context.Context, o Options) (*Assertion, error) {
	if o.RPID == "" {
		return nil, errors.New("a relying party id is required to request a WebAuthn assertion")
	}
	if len(o.Challenge) == 0 {
		return nil, errors.New("a challenge is required to request a WebAuthn assertion")
	}
	for _, p := range []*windows.LazyProc{procGetAssertion, procFreeAssertion} {
		if err := find(p); err != nil {
			return nil, err
		}
	}
	uv, err := userVerification(o.UserVerification)
	if err != nil {
		return nil, err
	}
	apiVer, err := APIVersion()
	if err != nil {
		return nil, err
	}

	timeout := o.Timeout
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); timeout <= 0 || left < timeout {
			timeout = left
		}
	}
	if timeout == 0 {
		timeout = defaultTimeout
	}
	if timeout < time.Millisecond {
		return nil, ErrTimeout
	}

	rpid, err := windows.UTF16PtrFromString(o.RPID)
	if err != nil {
		return nil, fmt.Errorf("the relying party id contains a NUL character: %w", err)
	}
	hashAlg, _ := windows.UTF16PtrFromString("SHA-256")
	credType, _ := windows.UTF16PtrFromString("public-key")

	clientJSON := ClientDataJSON(o.Challenge, o.Origin)
	cd := webauthnClientData{
		Version:      clientDataVersion1,
		ClientDataSz: uint32(len(clientJSON)),
		ClientData:   &clientJSON[0],
		HashAlgID:    hashAlg,
	}

	creds := make([]webauthnCredential, len(o.AllowCredentialIDs))
	for i, id := range o.AllowCredentialIDs {
		if len(id) == 0 {
			return nil, errors.New("an allowed credential id is empty")
		}
		creds[i] = webauthnCredential{Version: credentialVersion1, IDSize: uint32(len(id)), ID: &id[0], Type: credType}
	}

	opts := getAssertionOptions{
		Version:       getAssertionOptionsV1,
		TimeoutMillis: uint32(timeout / time.Millisecond),
		UserVerif:     uv,
	}
	if len(creds) > 0 {
		opts.CredentialList = webauthnCredentials{Count: uint32(len(creds)), Credentials: &creds[0]}
	}

	var cancelID windows.GUID
	cancellable := apiVer >= apiVersionCancellation &&
		procGetCancelID.Find() == nil && procCancelOperation.Find() == nil
	if cancellable {
		r, _, _ := syscall.SyscallN(procGetCancelID.Addr(), uintptr(unsafe.Pointer(&cancelID)))
		if int32(uint32(r)) >= 0 {
			opts.Version = getAssertionOptionsV3
			opts.CancellationID = &cancelID
		} else {
			cancellable = false
		}
	}

	// A context that ended during setup must not open a prompt nobody can dismiss.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	done := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
		case <-done:
			return
		}
		if !cancellable {
			<-done
			return
		}
		// The cancel can land before GetAssertion has registered the operation,
		// in which case Windows ignores it; repeat it until the call returns.
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			syscall.SyscallN(procCancelOperation.Addr(), uintptr(unsafe.Pointer(&cancelID)))
			select {
			case <-done:
				return
			case <-tick.C:
			}
		}
	}()

	var out *webauthnAssertion
	r, _, _ := syscall.SyscallN(procGetAssertion.Addr(),
		ownerWindow(),
		uintptr(unsafe.Pointer(rpid)),
		uintptr(unsafe.Pointer(&cd)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&out)))
	close(done)
	<-watcherDone
	// Everything the DLL read through pointers must outlive the call.
	runtime.KeepAlive(rpid)
	runtime.KeepAlive(hashAlg)
	runtime.KeepAlive(credType)
	runtime.KeepAlive(clientJSON)
	runtime.KeepAlive(&cd)
	runtime.KeepAlive(creds)
	runtime.KeepAlive(o.AllowCredentialIDs)
	runtime.KeepAlive(&opts)
	runtime.KeepAlive(&cancelID)

	if hr := uint32(r); int32(hr) < 0 {
		werr := newError("WebAuthNAuthenticatorGetAssertion", hr)
		if cerr := ctx.Err(); cerr != nil && errors.Is(werr, ErrCancelled) {
			return nil, fmt.Errorf("%w: %w", werr, cerr)
		}
		return nil, werr
	}
	if out == nil {
		return nil, errors.New("Windows reported success but returned no assertion")
	}
	// Copy before freeing: the DLL owns every buffer the struct points to.
	defer syscall.SyscallN(procFreeAssertion.Addr(), uintptr(unsafe.Pointer(out)))
	return &Assertion{
		CredentialID:      copyBytes(out.Credential.ID, out.Credential.IDSize),
		AuthenticatorData: copyBytes(out.AuthData, out.AuthDataSz),
		ClientDataJSON:    append([]byte(nil), clientJSON...),
		Signature:         copyBytes(out.Signature, out.SignatureSz),
	}, nil
}

func copyBytes(p *byte, n uint32) []byte {
	if p == nil || n == 0 {
		return nil
	}
	return append([]byte(nil), unsafe.Slice(p, n)...)
}

// newError wraps hr with the DLL's own W3C error name when it can be fetched.
func newError(fn string, hr uint32) *Error {
	e := &Error{Func: fn, HResult: hr}
	if procGetErrorName.Find() == nil {
		if p, _, _ := syscall.SyscallN(procGetErrorName.Addr(), uintptr(hr)); p != 0 {
			e.Name = windows.UTF16PtrToString(*(**uint16)(unsafe.Pointer(&p))) // p points into read-only DLL memory, not the Go heap
		}
	}
	return e
}
