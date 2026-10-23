package actionauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// Failure categories. Decision.Err wraps one of these, so the agent can
// report a precise reason and tests can assert on the category.
var (
	ErrUnsigned  = errors.New("signature required")
	ErrManifest  = errors.New("invalid manifest")
	ErrTarget    = errors.New("manifest is not addressed to this agent")
	ErrScope     = errors.New("manifest does not authorize this request")
	ErrExpired   = errors.New("manifest expired")
	ErrClock     = errors.New("manifest issued in the future")
	ErrSignature = errors.New("insufficient valid signatures")
	ErrReplay    = errors.New("manifest already used")
)

// SpecOp is the constraint op of a standing approval for a baseline spec. It
// is not a request type: specs arrive inside agent.config.
const SpecOp = "baseline.spec"

// Verifier makes the authorization decision for one agent.
type Verifier struct {
	AgentID string
	Bundle  *Bundle // nil: no trust established yet, nothing is checked
	Nonces  NonceStore
	Now     func() time.Time
}

// Decision is the outcome of Check.
type Decision struct {
	Op    string
	Class Class
	Mode  string
	// Allow says whether the request may run. It is false only in enforce
	// mode, and only when authorization was required and failed.
	Allow bool
	// Payload is what to execute: the signed payload for an action
	// manifest, the envelope's own payload otherwise.
	Payload json.RawMessage
	// Verified is true when a valid authorization was presented.
	Verified bool
	// Err explains why authorization was missing or invalid. In audit mode
	// the request still runs and Err is what gets reported.
	Err        error
	ManifestID string
	Signers    []string
}

// Report reports whether the decision should be sent to the server as a
// security event: authorization was needed and did not verify.
func (d Decision) Report() bool { return d.Err != nil && d.Mode != ModeOff }

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Check decides whether request op with envelope payload d and authorization
// auth may run. trust.update is self-authenticating (VerifyUpdate) and
// agent.config is filtered spec by spec (ApproveSpec); both pass here.
func (v *Verifier) Check(op string, d json.RawMessage, auth *protocol.ActionAuth) Decision {
	dec := Decision{Op: op, Class: ClassOf(op), Mode: v.Bundle.Mode(), Allow: true, Payload: d}
	if dec.Mode == ModeOff || dec.Class == ClassRead || dec.Class == ClassConfig || op == protocol.ReqTrustUpdate {
		return dec
	}
	m, owners, err := v.verify(op, d, auth)
	if m != nil {
		dec.ManifestID = m.ID
	}
	if err != nil {
		dec.Err = err
		dec.Allow = dec.Mode != ModeEnforce
		return dec
	}
	dec.Verified, dec.Signers = true, owners
	if m.Kind == KindAction {
		// Run what was signed, not what was sent, apart from the
		// correlation IDs that differ per target (see correlationFields).
		dec.Payload = withCorrelation(op, m.Payload, d)
	}
	return dec
}

// correlationFields are payload fields that only correlate a request with
// the server's bookkeeping and so legitimately differ per target of one
// signed manifest: a script sent to fifty agents is one signature but fifty
// run IDs. They are taken from the envelope; everything else comes from the
// signed payload. Nothing that changes what executes may be listed here.
var correlationFields = map[string][]string{
	protocol.ReqScriptRun: {"run_id"},
}

func withCorrelation(op string, signed, envelope json.RawMessage) json.RawMessage {
	fields := correlationFields[op]
	if len(fields) == 0 || len(envelope) == 0 {
		return signed
	}
	var s, e map[string]json.RawMessage
	if json.Unmarshal(signed, &s) != nil || json.Unmarshal(envelope, &e) != nil {
		return signed
	}
	changed := false
	for _, f := range fields {
		if v, ok := e[f]; ok {
			s[f] = v
			changed = true
		}
	}
	if op == protocol.ReqScriptRun {
		if env, ok := mergeDeviceEnv(s["env"], e["env"]); ok {
			s["env"] = env
			changed = true
		}
	}
	if !changed {
		return signed
	}
	out, err := json.Marshal(s)
	if err != nil {
		return signed
	}
	return out
}

// ApproveSpec checks the standing approval of one baseline spec (its JSON as
// received). A nil error means the spec may be kept.
func (v *Verifier) ApproveSpec(spec json.RawMessage, auth *protocol.ActionAuth) error {
	if v.Bundle.Mode() == ModeOff {
		return nil
	}
	_, _, err := v.verify(SpecOp, spec, auth)
	return err
}

// verify runs every check in an order that never consumes a nonce for a
// manifest that fails anything else.
func (v *Verifier) verify(op string, d json.RawMessage, auth *protocol.ActionAuth) (*Manifest, []string, error) {
	if auth == nil || auth.M == "" {
		return nil, nil, fmt.Errorf("%w for %s", ErrUnsigned, op)
	}
	raw, err := decodeB64(auth.M)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: not base64url", ErrManifest)
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrManifest, err)
	}
	b := v.Bundle
	if m.Org != b.Org {
		return m, nil, fmt.Errorf("%w: organisation %q", ErrTarget, m.Org)
	}
	if !m.targets(v.AgentID) {
		return m, nil, ErrTarget
	}
	now := v.now().Unix()
	if now+int64(clockSkew/time.Second) < m.IAT {
		return m, nil, fmt.Errorf("%w (agent clock %s, issued %s): check this device's clock",
			ErrClock, time.Unix(now, 0).UTC().Format(time.RFC3339), time.Unix(m.IAT, 0).UTC().Format(time.RFC3339))
	}
	if now >= m.Exp {
		return m, nil, ErrExpired
	}
	if err := scopeCheck(m, op, d); err != nil {
		return m, nil, err
	}

	need := 1
	if ClassOf(op) == ClassHighRisk || m.bulk(b.Policy.BulkLimit) {
		need = b.Policy.HighThreshold
	}
	owners, errs := verifyAll(auth.S, raw, b)
	if len(owners) < need {
		return m, owners, thresholdError(len(owners), need, errs)
	}

	if m.Kind == KindAction {
		if err := v.Nonces.Consume(m.Nonce, time.Unix(m.Exp, 0)); err != nil {
			return m, owners, err
		}
	}
	return m, owners, nil
}

// bulk reports whether the manifest reaches more agents than the bulk limit
// (an org-wide "*" always does).
func (m *Manifest) bulk(limit int) bool {
	return len(m.Targets) > limit || slices.Contains(m.Targets, "*")
}

// scopeCheck confirms the manifest authorizes this op with this payload.
func scopeCheck(m *Manifest, op string, d json.RawMessage) error {
	switch m.Kind {
	case KindAction:
		if m.Op != op {
			return fmt.Errorf("%w: it authorizes %s, not %s", ErrScope, m.Op, op)
		}
	case KindGrant:
		if !slices.Contains(m.Ops, op) {
			return fmt.Errorf("%w: the grant does not include %s", ErrScope, op)
		}
	case KindStanding:
		if m.Constraints.Op != op {
			return fmt.Errorf("%w: it approves %s, not %s", ErrScope, m.Constraints.Op, op)
		}
		return m.Constraints.check(d)
	}
	return nil
}

// DeviceEnvPrefix marks the environment variables the server sets per device
// (RMM_DEVICE_ID, RMM_HOSTNAME, RMM_CF_*, ...). They differ per target, so
// one signed script for many devices cannot carry them, and an unattended run
// gets nothing else. They are data a script reads; variables an interpreter
// acts on (PATH, PSModulePath, PYTHONPATH, ...) never have this prefix, which
// is what makes it safe to take these, and only these, from the server.
const DeviceEnvPrefix = "RMM_"

// mergeDeviceEnv adds the envelope's device variables to the signed env
// without overriding any variable the operator signed (compared without case,
// as Windows does).
func mergeDeviceEnv(signed, envelope json.RawMessage) (json.RawMessage, bool) {
	var e map[string]string
	if len(envelope) == 0 || json.Unmarshal(envelope, &e) != nil || len(e) == 0 {
		return nil, false
	}
	s := map[string]string{}
	if len(signed) > 0 && json.Unmarshal(signed, &s) != nil {
		return nil, false
	}
	added := false
	for k, v := range e {
		if !strings.HasPrefix(k, DeviceEnvPrefix) || hasKeyFold(s, k) {
			continue
		}
		s[k] = v
		added = true
	}
	if !added {
		return nil, false
	}
	out, err := json.Marshal(s)
	return out, err == nil
}

func hasKeyFold(m map[string]string, key string) bool {
	for k := range m {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}

// check confirms a concrete payload satisfies a standing approval. Every op
// a standing approval may cover binds content; anything else is refused so
// an approval can never become a blank cheque.
func (c *Constraints) check(d json.RawMessage) error {
	switch c.Op {
	case protocol.ReqScriptRun:
		var run protocol.ScriptRun
		if err := json.Unmarshal(d, &run); err != nil {
			return fmt.Errorf("%w: unreadable script payload", ErrScope)
		}
		sum := sha256.Sum256([]byte(run.Body))
		switch {
		case c.BodySHA256 == "" || c.BodySHA256 != hex.EncodeToString(sum[:]):
			return fmt.Errorf("%w: the script body is not the approved one", ErrScope)
		case c.Language == "" || c.Language != run.Language:
			return fmt.Errorf("%w: the script language is not the approved one", ErrScope)
		case !slices.Equal(c.Args, run.Args) && (len(c.Args) > 0 || len(run.Args) > 0):
			return fmt.Errorf("%w: the script arguments are not the approved ones", ErrScope)
		}
		// The approval binds body, language and args but not the
		// environment, so an unattended run may carry only the server's
		// per-device variables: anything else (PATH, PSModulePath, ...)
		// could make the approved script load code nobody approved.
		for k := range run.Env {
			if !strings.HasPrefix(k, DeviceEnvPrefix) {
				return fmt.Errorf("%w: environment variable %q is not covered by the approval", ErrScope, k)
			}
		}
	case protocol.ReqPower:
		var p protocol.Power
		if err := json.Unmarshal(d, &p); err != nil || c.PowerAction == "" || p.Action != c.PowerAction {
			return fmt.Errorf("%w: the power action is not the approved one", ErrScope)
		}
	case protocol.ReqUpdatesInstall:
		// The agent installs only through the OS update service, so the
		// update IDs cannot carry code; the approval is the decision to
		// patch at all.
	case SpecOp:
		canon, err := CanonicalizeJSON(d)
		if err != nil {
			return fmt.Errorf("%w: unreadable baseline spec: %v", ErrScope, err)
		}
		sum := sha256.Sum256(canon)
		if c.SpecSHA256 == "" || c.SpecSHA256 != hex.EncodeToString(sum[:]) {
			return fmt.Errorf("%w: the baseline spec is not the approved one", ErrScope)
		}
	default:
		return fmt.Errorf("%w: standing approvals cannot cover %s", ErrScope, c.Op)
	}
	return nil
}

// SpecHash is the hex SHA-256 of a baseline spec's canonical JSON, the value
// a standing approval's spec_sha256 must carry.
func SpecHash(spec json.RawMessage) (string, error) {
	canon, err := CanonicalizeJSON(spec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}
