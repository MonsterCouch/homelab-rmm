package actionauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Manifest kinds.
const (
	// KindAction authorizes one request, once: the agent executes the
	// manifest's payload (not whatever the envelope carries) and consumes
	// the nonce.
	KindAction = "action"
	// KindGrant opens a short capability on its targets for the listed
	// grant-class operations; it is reusable until it expires.
	KindGrant = "grant"
	// KindStanding is a long-lived approval for unattended runs: the
	// concrete payload must satisfy its constraints (a script body's hash,
	// a baseline spec's hash, a power action).
	KindStanding = "standing"
)

// Lifetime ceilings per kind. A manifest whose exp-iat exceeds these is
// refused whatever it says, so a stolen signing flow cannot mint a
// year-long one-shot action.
var maxLifetime = map[string]time.Duration{
	KindAction:   10 * time.Minute,
	KindGrant:    60 * time.Minute,
	KindStanding: 365 * 24 * time.Hour,
}

// clockSkew is how far in the future iat may be. Agents with a wrong clock
// get an explicit error rather than a generic refusal.
const clockSkew = 5 * time.Minute

// Manifest is one signed authorization. Field names are short on purpose:
// the manifest travels with every protected request.
type Manifest struct {
	V           int             `json:"v"`
	Kind        string          `json:"kind"`
	ID          string          `json:"id"`
	Org         string          `json:"org"`
	Targets     []string        `json:"targets"`
	Op          string          `json:"op,omitempty"`          // action
	Ops         []string        `json:"ops,omitempty"`         // grant
	Payload     json.RawMessage `json:"payload,omitempty"`     // action: the request to execute
	Constraints *Constraints    `json:"constraints,omitempty"` // standing
	Nonce       string          `json:"nonce"`
	IAT         int64           `json:"iat"`
	Exp         int64           `json:"exp"`
	Issuer      string          `json:"issuer,omitempty"`
}

// Constraints restrict what a standing approval allows. Only the fields that
// matter for Op are set; an unset field allows nothing it would constrain
// (see Constraints.check).
type Constraints struct {
	Op          string   `json:"op"`
	BodySHA256  string   `json:"body_sha256,omitempty"`  // script.run: hex SHA-256 of the body
	Language    string   `json:"language,omitempty"`     // script.run
	Args        []string `json:"args,omitempty"`         // script.run: exact args
	PowerAction string   `json:"power_action,omitempty"` // power: e.g. "reboot"
	SpecSHA256  string   `json:"spec_sha256,omitempty"`  // baseline spec: hex SHA-256 of its canonical JSON
	Steps       []string `json:"steps,omitempty"`        // servicing.repair: exact step list
	Reboot      string   `json:"reboot,omitempty"`       // servicing.repair: "never" or "if_required"
}

// ParseManifest decodes and structurally validates manifest bytes. It does
// not check signatures, time or targeting; Verifier does.
func ParseManifest(raw []byte) (*Manifest, error) {
	if _, err := parseStrict(raw); err != nil { // duplicate keys, bad UTF-8, trailing data
		return nil, fmt.Errorf("manifest: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Unknown fields are refused: a newer server must not send an older
	// agent a constraint it would silently ignore and so enforce less than
	// the operator signed.
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.V != 1 {
		return nil, fmt.Errorf("manifest: unsupported version %d", m.V)
	}
	if m.ID == "" || m.Org == "" || m.Nonce == "" {
		return nil, errors.New("manifest: id, org and nonce are required")
	}
	if len(m.Targets) == 0 {
		return nil, errors.New("manifest: no targets")
	}
	if slices.Contains(m.Targets, "*") && (m.Kind != KindStanding || len(m.Targets) != 1) {
		// "*" (every agent of the organisation) exists so an approved
		// script or baseline also covers devices enrolled later. Only a
		// standing approval, whose content is pinned by hash, may use it.
		return nil, errors.New(`manifest: "*" is only allowed as the sole target of a standing approval`)
	}
	if m.Exp <= m.IAT {
		return nil, errors.New("manifest: exp must be after iat")
	}
	max, ok := maxLifetime[m.Kind]
	if !ok {
		return nil, fmt.Errorf("manifest: unknown kind %q", m.Kind)
	}
	if time.Duration(m.Exp-m.IAT)*time.Second > max {
		return nil, fmt.Errorf("manifest: a %s may live at most %s", m.Kind, max)
	}
	switch m.Kind {
	case KindAction:
		if m.Op == "" || len(m.Payload) == 0 || len(m.Ops) > 0 || m.Constraints != nil {
			return nil, errors.New("manifest: an action needs op and payload, and nothing else")
		}
	case KindGrant:
		if len(m.Ops) == 0 || m.Op != "" || len(m.Payload) > 0 || m.Constraints != nil {
			return nil, errors.New("manifest: a grant needs ops, and nothing else")
		}
		for _, op := range m.Ops {
			if ClassOf(op) != ClassGrant {
				return nil, fmt.Errorf("manifest: %q cannot be granted", op)
			}
		}
	case KindStanding:
		if m.Constraints == nil || m.Constraints.Op == "" || m.Op != "" || len(m.Ops) > 0 || len(m.Payload) > 0 {
			return nil, errors.New("manifest: a standing approval needs constraints, and nothing else")
		}
	}
	return &m, nil
}

// Challenge is the WebAuthn challenge that signs doc: SHA-256 of its exact
// bytes.
func Challenge(doc []byte) []byte {
	h := sha256.Sum256(doc)
	return h[:]
}

// targets reports whether the manifest names agentID.
func (m *Manifest) targets(agentID string) bool {
	return slices.Contains(m.Targets, agentID) || slices.Contains(m.Targets, "*")
}

// b64 is the encoding of every binary field on the wire.
var b64 = base64.RawURLEncoding

// decodeB64 accepts unpadded base64url, and tolerates padding (browsers'
// helpers differ).
func decodeB64(s string) ([]byte, error) {
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return b64.DecodeString(s)
}

// EncodeB64 is the wire encoding, exported for the server and tests.
func EncodeB64(b []byte) string { return b64.EncodeToString(b) }

// BuildManifest validates m and returns its canonical bytes, the form that is
// signed, sent and stored. Producers must use this rather than json.Marshal
// so independent producers agree byte for byte.
func BuildManifest(m Manifest) ([]byte, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	canon, err := CanonicalizeJSON(raw)
	if err != nil {
		return nil, err
	}
	if _, err := ParseManifest(canon); err != nil {
		return nil, err
	}
	return canon, nil
}
