package actionauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// WebAuthn assertions as signatures. A browser's navigator.credentials.get
// with challenge = SHA-256(document) yields an assertion whose signature
// covers authenticatorData || SHA-256(clientDataJSON), and clientDataJSON
// carries the challenge. Verifying the assertion therefore proves that the
// credential's holder approved exactly that document, on the relying party
// and origin the bundle names. No CBOR is involved: public keys arrive as
// SubjectPublicKeyInfo in the bundle.

// authenticatorData flag bits (WebAuthn §6.1).
const (
	flagUP = 0x01 // user present
	flagUV = 0x04 // user verified
)

// credKey is a parsed bundle credential.
type credKey struct {
	alg   int
	pub   crypto.PublicKey
	owner string
}

func parseCredKey(alg int, pubB64 string) (*credKey, error) {
	der, err := decodeB64(pubB64)
	if err != nil {
		return nil, fmt.Errorf("public key encoding: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	switch alg {
	case AlgES256:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P256() {
			return nil, errors.New("ES256 needs a P-256 ECDSA key")
		}
	case AlgEdDSA:
		if _, ok := pub.(ed25519.PublicKey); !ok {
			return nil, errors.New("EdDSA needs an Ed25519 key")
		}
	case AlgRS256:
		k, ok := pub.(*rsa.PublicKey)
		if !ok || k.N.BitLen() < 2048 {
			return nil, errors.New("RS256 needs an RSA key of at least 2048 bits")
		}
	default:
		return nil, fmt.Errorf("unsupported algorithm %d", alg)
	}
	return &credKey{alg: alg, pub: pub}, nil
}

// canonicalCredID normalises a base64url credential ID (padding and all) to
// its unpadded form so lookups do not depend on who encoded it.
func canonicalCredID(s string) (string, error) {
	raw, err := decodeB64(s)
	if err != nil || len(raw) == 0 {
		return "", errors.New("credential ID is not base64url")
	}
	return b64.EncodeToString(raw), nil
}

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// verifyAssertion checks one assertion over doc against bundle b and returns
// the owner of the credential that made it.
func verifyAssertion(a protocol.Assertion, doc []byte, b *Bundle) (string, error) {
	id, err := canonicalCredID(a.Cred)
	if err != nil {
		return "", err
	}
	k := b.creds[id]
	if k == nil {
		return "", errors.New("credential is not in the trust bundle")
	}
	cdRaw, err := decodeB64(a.CD)
	if err != nil {
		return "", errors.New("clientDataJSON is not base64url")
	}
	ad, err := decodeB64(a.AD)
	if err != nil {
		return "", errors.New("authenticatorData is not base64url")
	}
	sig, err := decodeB64(a.Sig)
	if err != nil {
		return "", errors.New("signature is not base64url")
	}

	var cd clientData
	if err := json.Unmarshal(cdRaw, &cd); err != nil {
		return "", errors.New("clientDataJSON is not JSON")
	}
	if cd.Type != "webauthn.get" {
		return "", fmt.Errorf("clientData type %q is not webauthn.get", cd.Type)
	}
	chal, err := decodeB64(cd.Challenge)
	if err != nil || subtle.ConstantTimeCompare(chal, Challenge(doc)) != 1 {
		return "", errors.New("assertion was made for a different document")
	}
	if cd.CrossOrigin || !b.trustsOrigin(cd.Origin) {
		return "", fmt.Errorf("origin %q is not trusted", cd.Origin)
	}

	// authenticatorData: rpIdHash(32) | flags(1) | signCount(4) | ...
	if len(ad) < 37 {
		return "", errors.New("authenticatorData is too short")
	}
	rp := sha256.Sum256([]byte(b.RPID))
	if subtle.ConstantTimeCompare(ad[:32], rp[:]) != 1 {
		return "", errors.New("assertion was made for a different relying party")
	}
	if ad[32]&flagUP == 0 {
		return "", errors.New("user presence was not asserted")
	}
	if b.Policy.RequireUV && ad[32]&flagUV == 0 {
		return "", errors.New("user verification is required")
	}
	// The sign counter is deliberately ignored: passkeys report 0, and
	// clone detection would buy nothing here.

	cdHash := sha256.Sum256(cdRaw)
	signed := append(append([]byte(nil), ad...), cdHash[:]...)
	if !verifySig(k, signed, sig) {
		return "", errors.New("signature does not verify")
	}
	return k.owner, nil
}

func verifySig(k *credKey, signed, sig []byte) bool {
	switch k.alg {
	case AlgES256:
		h := sha256.Sum256(signed)
		return ecdsa.VerifyASN1(k.pub.(*ecdsa.PublicKey), h[:], sig)
	case AlgEdDSA:
		return ed25519.Verify(k.pub.(ed25519.PublicKey), signed, sig)
	case AlgRS256:
		h := sha256.Sum256(signed)
		return rsa.VerifyPKCS1v15(k.pub.(*rsa.PublicKey), crypto.SHA256, h[:], sig) == nil
	}
	return false
}

// trustsOrigin compares origins exactly, ignoring only a trailing slash on
// either side (browsers never send one; a configured origin might have one).
func (b *Bundle) trustsOrigin(origin string) bool {
	origin = strings.TrimRight(origin, "/")
	return slices.ContainsFunc(b.Origins, func(o string) bool { return strings.TrimRight(o, "/") == origin })
}

// verifyAll checks every assertion and returns the distinct owners with a
// valid one, plus the reasons the others failed (for the security event).
func verifyAll(sigs []protocol.Assertion, doc []byte, b *Bundle) (owners []string, errs []string) {
	seen := map[string]bool{}
	for _, a := range sigs {
		owner, err := verifyAssertion(a, doc, b)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if !seen[owner] {
			seen[owner] = true
			owners = append(owners, owner)
		}
	}
	return owners, errs
}

func thresholdError(have, need int, errs []string) error {
	msg := fmt.Sprintf("%d of %d required signer(s)", have, need)
	if len(errs) > 0 {
		msg += ": " + strings.Join(errs, "; ")
	} else if have == 0 {
		msg += ": no signatures presented"
	}
	return fmt.Errorf("%w: %s", ErrSignature, msg)
}

// Signers verifies assertions over doc against bundle b and returns the
// distinct owners with a valid assertion and the reasons the others failed.
// The server uses it to reject a bad signature before relaying; the agent's
// decision (Verifier.Check) is the one that counts.
func Signers(doc []byte, sigs []protocol.Assertion, b *Bundle) (owners []string, errs []string) {
	return verifyAll(sigs, doc, b)
}

// Owners lists the bundle's signer names.
func (b *Bundle) Owners() []string {
	out := make([]string, 0, len(b.Signers))
	for _, s := range b.Signers {
		out = append(out, s.Owner)
	}
	return out
}
