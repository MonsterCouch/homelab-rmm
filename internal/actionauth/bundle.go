package actionauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// Modes, from the bundle's policy.
const (
	ModeOff     = "off"
	ModeAudit   = "audit"
	ModeEnforce = "enforce"
)

// COSE algorithm identifiers a WebAuthn credential may use.
const (
	AlgES256 = -7
	AlgEdDSA = -8
	AlgRS256 = -257
)

// Bundle is the agent's root of trust: who may sign, for which relying party
// and origins, with which policy. It is pinned on first use and afterwards
// replaced only by a successor signed by the current bundle's signers or a
// recovery key (VerifyUpdate).
type Bundle struct {
	V        int           `json:"v"`
	Epoch    int64         `json:"epoch"`
	Prev     string        `json:"prev,omitempty"` // hex SHA-256 of the previous bundle's bytes
	Org      string        `json:"org"`
	RPID     string        `json:"rp_id"`
	Origins  []string      `json:"origins"`
	Signers  []Signer      `json:"signers"`
	Recovery []RecoveryKey `json:"recovery,omitempty"`
	LogKey   string        `json:"log_key,omitempty"` // Phase 3C: the transparency log's public key
	Policy   Policy        `json:"policy"`

	raw   []byte
	hash  [32]byte
	creds map[string]*credKey // canonical credential ID -> key
}

// Signer is one operator and the credentials (security keys, passkeys) they
// may sign with. A signer with several credentials counts once toward a
// threshold.
type Signer struct {
	Owner string       `json:"owner"`
	Creds []Credential `json:"creds"`
}

// Credential is a WebAuthn public key: ID is the base64url credential ID, Pub
// the base64url SubjectPublicKeyInfo DER, Alg its COSE algorithm.
type Credential struct {
	ID  string `json:"id"`
	Alg int    `json:"alg"`
	Pub string `json:"pub"`
}

// RecoveryKey is an offline Ed25519 key that may sign bundle updates only.
type RecoveryKey struct {
	ID  string `json:"id"`
	Alg string `json:"alg"` // "ed25519"
	Pub string `json:"pub"` // base64url raw 32-byte public key
}

// Policy is the enforcement configuration carried (and signed) in the bundle.
type Policy struct {
	Mode            string `json:"mode"`
	RequireUV       bool   `json:"require_uv,omitempty"`
	HighThreshold   int    `json:"high_threshold"`
	BundleThreshold int    `json:"bundle_threshold"`
	BulkLimit       int    `json:"bulk_limit"`
}

// ParseBundle decodes and validates bundle bytes, parsing every public key
// up front so a bundle with an unusable key is refused as a whole rather
// than failing later on the request it was supposed to authorize.
func ParseBundle(raw []byte) (*Bundle, error) {
	if _, err := parseStrict(raw); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var b Bundle
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	switch {
	case b.V != 1:
		return nil, fmt.Errorf("bundle: unsupported version %d", b.V)
	case b.Epoch < 1:
		return nil, errors.New("bundle: epoch must be at least 1")
	case b.Org == "" || b.RPID == "" || len(b.Origins) == 0:
		return nil, errors.New("bundle: org, rp_id and origins are required")
	case b.Policy.Mode != ModeOff && b.Policy.Mode != ModeAudit && b.Policy.Mode != ModeEnforce:
		return nil, fmt.Errorf("bundle: unknown mode %q", b.Policy.Mode)
	case b.Policy.HighThreshold < 1 || b.Policy.BundleThreshold < 1 || b.Policy.BulkLimit < 1:
		return nil, errors.New("bundle: thresholds and bulk_limit must be at least 1")
	case b.Policy.Mode == ModeEnforce && len(b.Recovery) == 0:
		// Enforcing without a way back is how a lost key becomes a fleet
		// nobody can manage. Refuse it here as well as in the server UI.
		return nil, errors.New("bundle: enforce mode requires a recovery key")
	}
	b.raw = append([]byte(nil), raw...)
	b.hash = sha256.Sum256(raw)
	b.creds = map[string]*credKey{}
	owners := map[string]bool{}
	for _, s := range b.Signers {
		if s.Owner == "" || owners[s.Owner] {
			return nil, fmt.Errorf("bundle: signer owner %q is empty or repeated", s.Owner)
		}
		owners[s.Owner] = true
		for _, c := range s.Creds {
			id, err := canonicalCredID(c.ID)
			if err != nil {
				return nil, fmt.Errorf("bundle: credential of %s: %w", s.Owner, err)
			}
			if b.creds[id] != nil {
				return nil, fmt.Errorf("bundle: credential %s listed twice", c.ID)
			}
			k, err := parseCredKey(c.Alg, c.Pub)
			if err != nil {
				return nil, fmt.Errorf("bundle: credential %s of %s: %w", c.ID, s.Owner, err)
			}
			k.owner = s.Owner
			b.creds[id] = k
		}
	}
	if len(owners) < b.Policy.BundleThreshold || len(owners) < b.Policy.HighThreshold {
		return nil, errors.New("bundle: thresholds exceed the number of signers")
	}
	ids := map[string]bool{}
	for _, r := range b.Recovery {
		pub, err := decodeB64(r.Pub)
		if r.Alg != "ed25519" || err != nil || len(pub) != ed25519.PublicKeySize || r.ID == "" || ids[r.ID] {
			return nil, fmt.Errorf("bundle: recovery key %q is not a usable ed25519 key", r.ID)
		}
		ids[r.ID] = true
	}
	return &b, nil
}

// Raw returns the exact bundle bytes.
func (b *Bundle) Raw() []byte { return b.raw }

// Hash returns the hex SHA-256 of the bundle bytes (what a successor's Prev
// must equal).
func (b *Bundle) Hash() string { return hex.EncodeToString(b.hash[:]) }

// Mode returns the policy mode; a nil bundle is "off".
func (b *Bundle) Mode() string {
	if b == nil {
		return ModeOff
	}
	return b.Policy.Mode
}

// VerifyUpdate checks a proposed successor of cur. With no current bundle the
// first valid bundle is accepted (trust on first use; the caller reports it).
// Otherwise the successor must continue the chain (epoch+1 and prev = hash of
// cur, so neither a rollback nor a skipped, unseen epoch is possible), keep
// the organisation, and carry either bundle_threshold distinct owners' valid
// assertions from cur, or one valid recovery-key signature from cur.
func VerifyUpdate(cur *Bundle, raw []byte, sigs []protocol.Assertion, rsigs []protocol.RecoverySig) (*Bundle, error) {
	nb, err := ParseBundle(raw)
	if err != nil {
		return nil, err
	}
	if cur == nil {
		return nb, nil
	}
	if nb.Epoch != cur.Epoch+1 {
		return nil, fmt.Errorf("bundle: epoch %d does not follow %d", nb.Epoch, cur.Epoch)
	}
	if nb.Prev != cur.Hash() {
		return nil, errors.New("bundle: prev does not match the current bundle")
	}
	if nb.Org != cur.Org {
		return nil, errors.New("bundle: the organisation cannot change")
	}
	for _, rs := range rsigs {
		if verifyRecovery(cur, rs, raw) == nil {
			return nb, nil
		}
	}
	owners, errs := verifyAll(sigs, raw, cur)
	if len(owners) >= cur.Policy.BundleThreshold {
		return nb, nil
	}
	return nil, thresholdError(len(owners), cur.Policy.BundleThreshold, errs)
}

func verifyRecovery(cur *Bundle, rs protocol.RecoverySig, raw []byte) error {
	sig, err := decodeB64(rs.Sig)
	if err != nil {
		return err
	}
	for _, r := range cur.Recovery {
		if subtle.ConstantTimeCompare([]byte(r.ID), []byte(rs.ID)) != 1 {
			continue
		}
		pub, _ := decodeB64(r.Pub) // validated by ParseBundle
		if ed25519.Verify(ed25519.PublicKey(pub), raw, sig) {
			return nil
		}
		return errors.New("recovery signature does not verify")
	}
	return fmt.Errorf("unknown recovery key %q", rs.ID)
}

// RecoveryKeyPrefix starts the printable form of a recovery private key:
// "rmm-recovery-v1:" followed by the base64url 32-byte Ed25519 seed. The
// console generates it (WebCrypto) and shows it once; `rmm-server trust
// sign-bundle` reads it.
const RecoveryKeyPrefix = "rmm-recovery-v1:"

// RecoveryKeyID derives a recovery key's ID from its raw public key:
// "recovery-" and the first 12 hex digits of SHA-256(pub). The console
// computes the same value.
func RecoveryKeyID(pub []byte) string {
	h := sha256.Sum256(pub)
	return "recovery-" + hex.EncodeToString(h[:6])
}
