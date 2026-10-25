package agent

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// trustState is the agent's side of Phase 3: the pinned trust bundle, the
// consumed-nonce file and the bookkeeping that keeps security events from
// repeating. The server never writes any of it except through trust.update,
// which VerifyUpdate authenticates against the bundle already pinned here.
type trustState struct {
	mu     sync.RWMutex
	path   string
	bundle *actionauth.Bundle
	// failed is set when trust.json exists but cannot be used. Treating an
	// unreadable pin as "no bundle" would let anyone who can corrupt one
	// file turn enforcement off, so every protected request is refused
	// until an operator deletes the file on the device.
	failed error
	nonces actionauth.NonceStore
	now    func() time.Time

	reportMu sync.Mutex
	reported map[string]bool

	// logState is the Phase 3C log head and executed.log; see translog.go.
	logState
}

func trustPath() string  { return filepath.Join(ConfigDir(), "trust.json") }
func noncesPath() string { return filepath.Join(ConfigDir(), "nonces.json") }

// failedNonces is the store used when nonces.json cannot be opened: it
// refuses every consume, so signed actions fail verification (and run
// anyway in audit mode, which is what Check's Allow already says).
type failedNonces struct{ err error }

func (f failedNonces) Consume(string, time.Time) error { return f.err }

// loadTrust reads the pinned bundle and opens the nonce store. It never
// fails: a problem becomes a fail-closed state, logged loudly.
func loadTrust() *trustState {
	t := &trustState{path: trustPath(), reported: map[string]bool{}}
	raw, err := os.ReadFile(t.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		t.failed = fmt.Errorf("trust.json cannot be read: %w", err)
	default:
		b, perr := actionauth.ParseBundle(raw)
		if perr != nil {
			t.failed = fmt.Errorf("trust.json was rejected: %w", perr)
		} else {
			t.bundle = b
		}
	}
	if t.failed != nil {
		slog.Error("TRUST BUNDLE UNUSABLE: refusing every action until it is re-pinned; delete trust.json on this device to re-pin",
			"path", t.path, "err", t.failed)
	}
	t.loadLogHead()
	t.loadExecuted()
	ns, err := actionauth.OpenFileNonceStore(noncesPath())
	if err != nil {
		slog.Error("nonce store unusable: signed actions cannot be verified", "err", err)
		t.nonces = failedNonces{err}
	} else {
		t.nonces = ns
	}
	return t
}

// verifier snapshots the current bundle into a Verifier. A fail-closed
// state is returned separately so callers cannot forget it.
func (t *trustState) verifier(agentID string) (*actionauth.Verifier, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return &actionauth.Verifier{AgentID: agentID, Bundle: t.bundle, Nonces: t.nonces, Now: t.now}, t.failed
}

// epochHash is what hello advertises so the server can send what is missing.
func (t *trustState) epochHash() (int64, string) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.bundle == nil {
		return 0, ""
	}
	return t.bundle.Epoch, t.bundle.Hash()
}

// once reports whether key has not been reported in this process yet, and
// remembers it. A reconnect must not re-raise the same alert.
func (t *trustState) once(key string) bool {
	t.reportMu.Lock()
	defer t.reportMu.Unlock()
	if t.reported[key] {
		return false
	}
	t.reported[key] = true
	return true
}

// persist writes trust.json with the same tmp+rename pattern as Config.Save.
func (t *trustState) persist(raw []byte) error {
	if err := EnsureConfigDir(); err != nil {
		return err
	}
	tmp := t.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, t.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func (a *Agent) agentID() string {
	if a.cfg == nil {
		return ""
	}
	return a.cfg.AgentID
}

// securityEvent tells the server what the agent refused or allowed to slip
// through. Losing one (no socket) is acceptable: the log line stays.
func (a *Agent) securityEvent(op, mode string, executed bool, reason, manifest, msg string) {
	slog.Warn("security: "+msg, "op", op, "mode", mode, "executed", executed, "reason", reason, "manifest", manifest)
	c := a.socket()
	if c == nil {
		return
	}
	c.event(protocol.EventKindSecurity, msg, map[string]string{
		"op": op, "mode": mode, "executed": strconv.FormatBool(executed), "reason": reason, "manifest": manifest,
	})
}

// authorize is the single gate every server request passes before anything
// else in dispatch, including the fast path that handles agent.config and
// shell input. It returns the envelope to run (with the SIGNED payload when
// one was verified) and whether to run it at all. Failures reply with an
// error and never touch networking: a bad manifest, a bug or clock skew must
// not be able to cut a device off from the channel needed to fix it.
func (a *Agent) authorize(c *conn, env protocol.Envelope) (protocol.Envelope, bool) {
	t := a.trust
	if t == nil {
		return env, true
	}
	v, failed := t.verifier(a.agentID())
	var dec actionauth.Decision
	if failed != nil {
		class := actionauth.ClassOf(env.T)
		dec = actionauth.Decision{Op: env.T, Class: class, Mode: actionauth.ModeEnforce, Allow: true, Payload: env.D}
		if class != actionauth.ClassRead && class != actionauth.ClassConfig {
			dec.Allow = false
			dec.Err = fmt.Errorf("%w; delete trust.json on the device to re-pin", failed)
		}
	} else {
		dec = v.Check(env.T, env.D, env.A)
	}
	if dec.Report() {
		msg := "unauthorized " + env.T + " refused"
		if dec.Allow {
			msg = "unauthorized " + env.T + " executed (audit mode)"
		}
		a.securityEvent(env.T, dec.Mode, dec.Allow, dec.Err.Error(), dec.ManifestID, msg)
	}
	if !dec.Allow {
		if env.ID != "" {
			c.replyErr(env.ID, errors.New("refused: "+dec.Err.Error()))
		}
		return env, false
	}
	logIndex := int64(-1)
	if failed == nil && dec.Allow && dec.Mode != actionauth.ModeOff &&
		dec.Class != actionauth.ClassRead && dec.Class != actionauth.ClassConfig && env.T != protocol.ReqTrustUpdate {
		// A manifest that did not verify (audit mode) has nothing to prove;
		// the damaged-head rule still applies to the request itself.
		var auth *protocol.ActionAuth
		if dec.Verified {
			auth = env.A
		}
		idx, lerr := t.checkLogProof(v.Bundle, auth)
		if lerr != nil {
			allow := dec.Mode != actionauth.ModeEnforce
			if !allow || t.once("logproof/"+dec.ManifestID+"/"+lerr.Error()) {
				msg := "log proof for " + env.T + " refused"
				if allow {
					msg = "log proof for " + env.T + " failed, executed anyway (audit mode)"
				}
				a.securityEvent(env.T, dec.Mode, allow, "log proof: "+lerr.Error(), dec.ManifestID, msg)
			}
			if !allow {
				if env.ID != "" {
					c.replyErr(env.ID, errors.New("refused: log proof: "+lerr.Error()))
				}
				return env, false
			}
		} else {
			logIndex = idx
		}
	}
	if dec.ManifestID != "" {
		t.recordExecuted(dec.ManifestID, env.T, logIndex)
	}
	env.D = dec.Payload
	return env, true
}

// autoUpdateAllowed gates the unattended update poll, the one path that
// installs a server-supplied binary without passing authorize. The chore
// carries no signature, so it is judged as the unsigned agent.update it is:
// audit mode installs it and reports it, enforce refuses it and reports it
// (the build is pushed from the console as a signed agent.update instead), and
// a damaged trust.json refuses it like every other protected request. The poll
// repeats every few minutes, so each advertised binary is reported once per
// process and mode.
func (a *Agent) autoUpdateAllowed(req protocol.AgentUpdate) bool {
	t := a.trust
	if t == nil {
		return true
	}
	v, failed := t.verifier(a.agentID())
	var dec actionauth.Decision
	if failed != nil {
		dec = actionauth.Decision{
			Op: protocol.ReqAgentUpdate, Class: actionauth.ClassOf(protocol.ReqAgentUpdate),
			Mode: actionauth.ModeEnforce, Allow: false,
			Err: fmt.Errorf("%w; delete trust.json on the device to re-pin", failed),
		}
	} else {
		dec = v.Check(protocol.ReqAgentUpdate, protocol.Must(req), nil)
	}
	if !dec.Report() {
		return dec.Allow
	}
	if t.once("autoupdate/" + strings.ToLower(req.SHA256) + "/" + dec.Mode) {
		// The alert the server raises shows the reason, not the message, so
		// the reason says which path this was: an operator reading that
		// agent.update was refused must be able to tell the unattended poll
		// from a push somebody forged.
		reason := "unattended update check: " + dec.Err.Error()
		msg := "unattended agent.update refused: this organization signs actions, so new builds are pushed from the console"
		if dec.Allow {
			msg = "unattended agent.update executed unsigned (audit mode)"
		} else {
			reason += "; push this build from the console"
		}
		a.securityEvent(protocol.ReqAgentUpdate, dec.Mode, dec.Allow, reason, "", msg)
	}
	return dec.Allow
}

// trustUpdate handles trust.update: first-use pinning or a signed rotation.
func (a *Agent) trustUpdate(env protocol.Envelope) (any, error) {
	t := a.trust
	if t == nil {
		return nil, errors.New("trust is not available on this agent")
	}
	// mode is read before the write lock is taken and is only for the event:
	// the lock is held while fail runs.
	mode := t.modeNow()
	fail := func(err error) (any, error) {
		a.securityEvent(protocol.ReqTrustUpdate, mode, false, err.Error(), "", "trust bundle update refused")
		return nil, err
	}
	var in protocol.TrustUpdate
	if err := json.Unmarshal(env.D, &in); err != nil {
		return fail(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(in.Bundle, "="))
	if err != nil {
		return fail(errors.New("bundle is not base64url"))
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failed != nil {
		return fail(fmt.Errorf("%w; a successor cannot be verified: delete trust.json on the device to re-pin", t.failed))
	}
	nb, err := actionauth.VerifyUpdate(t.bundle, raw, in.S, in.R)
	if err != nil {
		return fail(err)
	}
	if err := t.persist(nb.Raw()); err != nil {
		return fail(fmt.Errorf("cannot save trust.json: %w", err))
	}
	first := t.bundle == nil
	t.bundle = nb
	reason := fmt.Sprintf("trust bundle rotated to epoch %d", nb.Epoch)
	if first {
		reason = fmt.Sprintf("trust bundle pinned on first use, epoch %d", nb.Epoch)
	}
	a.securityEvent(protocol.ReqTrustUpdate, nb.Mode(), true, reason, "", reason)
	return map[string]any{"epoch": nb.Epoch, "hash": nb.Hash()}, nil
}

func (t *trustState) modeNow() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.bundle.Mode()
}

// ---- baseline specs ----

// splitConfig decodes an agent.config frame twice: typed, and again to keep
// each baseline spec's JSON exactly as received, because a standing approval
// binds the hash of those bytes.
func splitConfig(data json.RawMessage) (cfg protocol.AgentConfig, raws []json.RawMessage, auth map[string]*protocol.ActionAuth, err error) {
	if err = json.Unmarshal(data, &cfg); err != nil {
		return
	}
	var aux struct {
		Baselines    []json.RawMessage
		BaselineAuth map[string]*protocol.ActionAuth `json:"baseline_auth"`
	}
	if err = json.Unmarshal(data, &aux); err != nil {
		return
	}
	if len(aux.Baselines) != len(cfg.Baselines) {
		err = errors.New("baseline list is inconsistent")
		return
	}
	return cfg, aux.Baselines, aux.BaselineAuth, nil
}

// specMayRun decides whether one baseline spec (its raw JSON and stored
// approval) may be kept or evaluated now. It is asked both when a config
// arrives and right before every pass, so a restart, an approval that
// expired while the device was offline, or a switch to enforce all take
// effect without waiting for the server. Enforce refuses and reports; audit
// allows and reports; no bundle checks nothing. Reports are deduplicated per
// spec ID, version and reason for the life of the process.
func (a *Agent) specMayRun(id int64, version int, raw json.RawMessage, auth *protocol.ActionAuth) bool {
	t := a.trust
	if t == nil {
		return true
	}
	v, failed := t.verifier(a.agentID())
	var err error
	mode := v.Bundle.Mode()
	switch {
	case failed != nil:
		// Specs are code the agent runs on its own; with the pin unusable
		// they cannot be vouched for.
		err, mode = fmt.Errorf("%w; delete trust.json on the device to re-pin", failed), actionauth.ModeEnforce
	case v.Bundle == nil:
		return true
	default:
		err = v.ApproveSpec(raw, auth)
	}
	if err == nil {
		return true
	}
	allow := mode != actionauth.ModeEnforce
	if t.once(fmt.Sprintf("spec/%d/%d/%s", id, version, err.Error())) {
		msg := fmt.Sprintf("baseline %d v%d is not approved and was dropped", id, version)
		if allow {
			msg = fmt.Sprintf("baseline %d v%d is not approved and runs anyway (audit mode)", id, version)
		}
		a.securityEvent(protocol.ReqAgentConfig, mode, allow, err.Error(), "", msg)
	}
	return allow
}

// filterSpecs keeps the specs that may run and returns, for those, the raw
// JSON and approval the engine stores for later re-verification.
func (a *Agent) filterSpecs(cfg protocol.AgentConfig, raws []json.RawMessage, auth map[string]*protocol.ActionAuth) ([]protocol.BaselineSpec, map[int64]json.RawMessage, map[int64]*protocol.ActionAuth) {
	keep := make([]protocol.BaselineSpec, 0, len(cfg.Baselines))
	rm := map[int64]json.RawMessage{}
	am := map[int64]*protocol.ActionAuth{}
	for i, s := range cfg.Baselines {
		var raw json.RawMessage
		if i < len(raws) {
			raw = raws[i]
		}
		ap := auth[strconv.FormatInt(s.ID, 10)]
		if !a.specMayRun(s.ID, s.Version, raw, ap) {
			continue
		}
		keep = append(keep, s)
		rm[s.ID], am[s.ID] = raw, ap
	}
	return keep, rm, am
}
