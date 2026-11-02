//go:build windows

package winwebauthn

import (
	"testing"
	"unsafe"
)

// The expectations below are computed by hand from webauthn.h for 64-bit
// Windows (LLP64: DWORD and BOOL are 4 bytes, pointers 8, structs align to
// their widest member). They are written as literals on purpose: the test
// exists to catch a Go struct drifting from the C layout.

func check(t *testing.T, name string, got, want uintptr) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %d, want %d", name, got, want)
	}
}

func TestLayoutClientData(t *testing.T) {
	// dwVersion@0 cbClientDataJSON@4 pbClientDataJSON@8 pwszHashAlgId@16 -> 24
	var s webauthnClientData
	check(t, "sizeof", unsafe.Sizeof(s), 24)
	check(t, "Version", unsafe.Offsetof(s.Version), 0)
	check(t, "ClientDataSz", unsafe.Offsetof(s.ClientDataSz), 4)
	check(t, "ClientData", unsafe.Offsetof(s.ClientData), 8)
	check(t, "HashAlgID", unsafe.Offsetof(s.HashAlgID), 16)
}

func TestLayoutCredential(t *testing.T) {
	// dwVersion@0 cbId@4 pbId@8 pwszCredentialType@16 -> 24
	var s webauthnCredential
	check(t, "sizeof", unsafe.Sizeof(s), 24)
	check(t, "Version", unsafe.Offsetof(s.Version), 0)
	check(t, "IDSize", unsafe.Offsetof(s.IDSize), 4)
	check(t, "ID", unsafe.Offsetof(s.ID), 8)
	check(t, "Type", unsafe.Offsetof(s.Type), 16)
}

func TestLayoutCredentialsAndExtensions(t *testing.T) {
	// cCredentials@0, 4 bytes padding, pCredentials@8 -> 16 (same for extensions)
	var c webauthnCredentials
	check(t, "credentials sizeof", unsafe.Sizeof(c), 16)
	check(t, "Count", unsafe.Offsetof(c.Count), 0)
	check(t, "Credentials", unsafe.Offsetof(c.Credentials), 8)
	var e webauthnExtensions
	check(t, "extensions sizeof", unsafe.Sizeof(e), 16)
	check(t, "Extensions", unsafe.Offsetof(e.Extensions), 8)
}

func TestLayoutGetAssertionOptions(t *testing.T) {
	// dwVersion@0 dwTimeoutMilliseconds@4 CredentialList@8(16) Extensions@24(16)
	// dwAuthenticatorAttachment@40 dwUserVerificationRequirement@44 dwFlags@48,
	// 4 bytes padding, then the version 2 and 3 pointers at 56, 64 and 72 -> 80.
	var s getAssertionOptions
	check(t, "sizeof", unsafe.Sizeof(s), 80)
	check(t, "Version", unsafe.Offsetof(s.Version), 0)
	check(t, "TimeoutMillis", unsafe.Offsetof(s.TimeoutMillis), 4)
	check(t, "CredentialList", unsafe.Offsetof(s.CredentialList), 8)
	check(t, "Extensions", unsafe.Offsetof(s.Extensions), 24)
	check(t, "Attachment", unsafe.Offsetof(s.Attachment), 40)
	check(t, "UserVerif", unsafe.Offsetof(s.UserVerif), 44)
	check(t, "Flags", unsafe.Offsetof(s.Flags), 48)
	check(t, "U2fAppID", unsafe.Offsetof(s.U2fAppID), 56)
	check(t, "U2fAppIDUsed", unsafe.Offsetof(s.U2fAppIDUsed), 64)
	check(t, "CancellationID", unsafe.Offsetof(s.CancellationID), 72)
}

func TestLayoutAssertion(t *testing.T) {
	// dwVersion@0 cbAuthenticatorData@4 pbAuthenticatorData@8 cbSignature@16,
	// 4 bytes padding, pbSignature@24 Credential@32(24) cbUserId@56, 4 bytes
	// padding, pbUserId@64 -> 72 (the version 1 prefix).
	var s webauthnAssertion
	check(t, "sizeof", unsafe.Sizeof(s), 72)
	check(t, "AuthDataSz", unsafe.Offsetof(s.AuthDataSz), 4)
	check(t, "AuthData", unsafe.Offsetof(s.AuthData), 8)
	check(t, "SignatureSz", unsafe.Offsetof(s.SignatureSz), 16)
	check(t, "Signature", unsafe.Offsetof(s.Signature), 24)
	check(t, "Credential", unsafe.Offsetof(s.Credential), 32)
	check(t, "UserIDSz", unsafe.Offsetof(s.UserIDSz), 56)
	check(t, "UserID", unsafe.Offsetof(s.UserID), 64)
}

func TestUserVerificationValues(t *testing.T) {
	for in, want := range map[string]uint32{"": 0, "required": 1, "preferred": 2, "discouraged": 3} {
		got, err := userVerification(in)
		if err != nil || got != want {
			t.Errorf("userVerification(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	if _, err := userVerification("maybe"); err == nil {
		t.Error("an unknown user verification value was accepted")
	}
}

func TestSelftestRuns(t *testing.T) {
	r, err := Selftest()
	if err != nil {
		t.Skipf("webauthn.dll unavailable here: %v", err)
	}
	if r.APIVersion == 0 {
		t.Error("API version is zero")
	}
}
