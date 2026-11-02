// Package winwebauthn calls the native Windows WebAuthn API (webauthn.dll)
// without cgo, so a command-line program can ask Windows Hello or a security
// key for a WebAuthn assertion over bytes it chose itself.
//
// The point of doing this outside a browser is that the caller, not a web page,
// decides what the challenge is and what the operator saw before approving it.
// The struct layouts follow webauthn.h from github.com/microsoft/webauthn
// (WEBAUTHN_API_CURRENT_VERSION 9); only the lowest struct versions that carry
// what an assertion needs are used, so the package works on any Windows build
// whose webauthn.dll reports API version 1 or later. The package is 64-bit
// only: every layout is written out for 64-bit pointers and checked by a test.
//
// On other platforms every function that would reach the DLL returns
// ErrUnsupported; ClientDataJSON is portable.
package winwebauthn
