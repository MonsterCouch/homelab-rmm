// Package authtest is a software WebAuthn authenticator and bundle/manifest
// builder for tests. It produces real assertions (authenticatorData,
// clientDataJSON, ES256/EdDSA/RS256 signatures), so tests exercise the same
// verification path a hardware key does. Never use it outside tests.
package authtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// Defaults shared by tests.
const (
	RPID   = "rmm.test"
	Origin = "https://rmm.test:8443"
	Org    = "org_test"
)

// Key is one software credential.
type Key struct {
	Owner string
	ID    []byte
	Alg   int
	priv  crypto.Signer
	count uint32
}

// NewKey creates a credential for owner with a COSE algorithm
// (actionauth.AlgES256, AlgEdDSA or AlgRS256).
func NewKey(owner string, alg int) *Key {
	id := make([]byte, 16)
	rand.Read(id)
	var priv crypto.Signer
	var err error
	switch alg {
	case actionauth.AlgES256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case actionauth.AlgEdDSA:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case actionauth.AlgRS256:
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		panic(fmt.Sprintf("authtest: unsupported alg %d", alg))
	}
	if err != nil {
		panic(err)
	}
	return &Key{Owner: owner, ID: id, Alg: alg, priv: priv}
}

// Credential is the key's bundle entry.
func (k *Key) Credential() actionauth.Credential {
	der, err := x509.MarshalPKIXPublicKey(k.priv.Public())
	if err != nil {
		panic(err)
	}
	return actionauth.Credential{ID: actionauth.EncodeB64(k.ID), Alg: k.Alg, Pub: actionauth.EncodeB64(der)}
}

// SignOpts adjusts an assertion so tests can produce each failure.
type SignOpts struct {
	Type        string // default "webauthn.get"
	Origin      string // default Origin
	RPID        string // default RPID
	CrossOrigin bool
	NoUP        bool // clear the user-present flag
	UV          bool // set the user-verified flag
	Challenge   []byte
	// ClientData, when set, is signed as the clientDataJSON instead of the one
	// Sign builds, so a test can check bytes another client produced (the
	// native Windows signer) against the verifier.
	ClientData []byte
}

// Sign produces an assertion over doc (challenge = SHA-256(doc)).
func (k *Key) Sign(doc []byte, o SignOpts) protocol.Assertion {
	if o.Type == "" {
		o.Type = "webauthn.get"
	}
	if o.Origin == "" {
		o.Origin = Origin
	}
	if o.RPID == "" {
		o.RPID = RPID
	}
	chal := o.Challenge
	if chal == nil {
		chal = actionauth.Challenge(doc)
	}
	cd := o.ClientData
	if cd == nil {
		cd, _ = json.Marshal(map[string]any{
			"type": o.Type, "challenge": actionauth.EncodeB64(chal), "origin": o.Origin, "crossOrigin": o.CrossOrigin,
		})
	}
	rp := sha256.Sum256([]byte(o.RPID))
	flags := byte(0x01)
	if o.NoUP {
		flags = 0
	}
	if o.UV {
		flags |= 0x04
	}
	k.count++
	ad := append(rp[:], flags)
	ad = binary.BigEndian.AppendUint32(ad, k.count)
	cdHash := sha256.Sum256(cd)
	signed := append(append([]byte(nil), ad...), cdHash[:]...)

	var sig []byte
	var err error
	switch k.Alg {
	case actionauth.AlgEdDSA:
		sig, err = k.priv.Sign(rand.Reader, signed, crypto.Hash(0))
	default:
		h := sha256.Sum256(signed)
		sig, err = k.priv.Sign(rand.Reader, h[:], crypto.SHA256) // ECDSA: ASN.1 DER; RSA: PKCS#1 v1.5
	}
	if err != nil {
		panic(err)
	}
	return protocol.Assertion{
		Cred: actionauth.EncodeB64(k.ID), AD: actionauth.EncodeB64(ad),
		CD: actionauth.EncodeB64(cd), Sig: actionauth.EncodeB64(sig),
	}
}

// RecoveryKey is an offline Ed25519 recovery key.
type RecoveryKey struct {
	ID   string
	priv ed25519.PrivateKey
}

// NewRecoveryKey creates a recovery key. An empty id derives the ID the way
// real clients do (actionauth.RecoveryKeyID); tests that need a specific ID
// (an unknown or mislabelled key) pass one.
func NewRecoveryKey(id string) *RecoveryKey {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if id == "" {
		id = actionauth.RecoveryKeyID(priv.Public().(ed25519.PublicKey))
	}
	return &RecoveryKey{ID: id, priv: priv}
}

func (r *RecoveryKey) Entry() actionauth.RecoveryKey {
	return actionauth.RecoveryKey{ID: r.ID, Alg: "ed25519", Pub: actionauth.EncodeB64(r.priv.Public().(ed25519.PublicKey))}
}

func (r *RecoveryKey) Sign(doc []byte) protocol.RecoverySig {
	return protocol.RecoverySig{ID: r.ID, Sig: actionauth.EncodeB64(ed25519.Sign(r.priv, doc))}
}

// BundleSpec describes a bundle to build.
type BundleSpec struct {
	Epoch    int64
	Prev     string
	Org      string
	Keys     []*Key
	Recovery []*RecoveryKey
	Policy   actionauth.Policy
}

// Bundle builds bundle bytes. Keys sharing an Owner become one signer.
func Bundle(s BundleSpec) []byte {
	if s.Epoch == 0 {
		s.Epoch = 1
	}
	if s.Org == "" {
		s.Org = Org
	}
	if s.Policy.Mode == "" {
		s.Policy.Mode = actionauth.ModeEnforce
	}
	if s.Policy.HighThreshold == 0 {
		s.Policy.HighThreshold = 1
	}
	if s.Policy.BundleThreshold == 0 {
		s.Policy.BundleThreshold = 1
	}
	if s.Policy.BulkLimit == 0 {
		s.Policy.BulkLimit = 10
	}
	var signers []actionauth.Signer
	idx := map[string]int{}
	for _, k := range s.Keys {
		i, ok := idx[k.Owner]
		if !ok {
			i = len(signers)
			idx[k.Owner] = i
			signers = append(signers, actionauth.Signer{Owner: k.Owner})
		}
		signers[i].Creds = append(signers[i].Creds, k.Credential())
	}
	var rec []actionauth.RecoveryKey
	for _, r := range s.Recovery {
		rec = append(rec, r.Entry())
	}
	b := actionauth.Bundle{V: 1, Epoch: s.Epoch, Prev: s.Prev, Org: s.Org, RPID: RPID,
		Origins: []string{Origin}, Signers: signers, Recovery: rec, Policy: s.Policy}
	raw, err := json.Marshal(b)
	if err != nil {
		panic(err)
	}
	return raw
}

// Manifest builds manifest bytes with sensible defaults: a fresh nonce,
// issued now, valid for five minutes, in the test org.
func Manifest(m actionauth.Manifest) []byte {
	if m.V == 0 {
		m.V = 1
	}
	if m.Org == "" {
		m.Org = Org
	}
	if m.ID == "" {
		m.ID = randID()
	}
	if m.Nonce == "" {
		m.Nonce = randID()
	}
	if m.IAT == 0 {
		m.IAT = time.Now().Unix()
	}
	if m.Exp == 0 {
		m.Exp = m.IAT + 300
	}
	raw, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return raw
}

// Auth wraps manifest bytes and assertions for an envelope.
func Auth(manifest []byte, sigs ...protocol.Assertion) *protocol.ActionAuth {
	return &protocol.ActionAuth{M: actionauth.EncodeB64(manifest), S: sigs}
}

func randID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return actionauth.EncodeB64(b)
}
