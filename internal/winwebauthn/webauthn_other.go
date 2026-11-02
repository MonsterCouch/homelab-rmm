//go:build !windows

package winwebauthn

import (
	"context"
	"time"
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

// APIVersion always fails off Windows.
func APIVersion() (uint32, error) { return 0, ErrUnsupported }

// PlatformAuthenticatorAvailable always fails off Windows.
func PlatformAuthenticatorAvailable() (bool, error) { return false, ErrUnsupported }

// GetAssertion always fails off Windows.
func GetAssertion(ctx context.Context, o Options) (*Assertion, error) {
	return nil, ErrUnsupported
}
