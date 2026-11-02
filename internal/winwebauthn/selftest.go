package winwebauthn

// SelftestResult is what Selftest learned without showing any prompt.
type SelftestResult struct {
	APIVersion                 uint32
	PlatformAuthenticatorFound bool
}

// Selftest reports the WebAuthn API version and whether Windows Hello (a
// user-verifying platform authenticator) is available. It shows no UI, so it is
// safe to run from a script or a support call.
func Selftest() (SelftestResult, error) {
	var r SelftestResult
	v, err := APIVersion()
	if err != nil {
		return r, err
	}
	r.APIVersion = v
	ok, err := PlatformAuthenticatorAvailable()
	if err != nil {
		return r, err
	}
	r.PlatformAuthenticatorFound = ok
	return r, nil
}
