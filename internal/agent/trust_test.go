package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/actionauth/authtest"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

const testAgentID = "agent_1"

// trustHarness is an agent wired to a fake server over a real WebSocket, so
// dispatch is driven exactly as session() drives it and every frame the
// agent sends can be inspected.
type trustHarness struct {
	t      *testing.T
	dir    string
	a      *Agent
	frames chan protocol.Envelope
	srv    *httptest.Server
	ws     *websocket.Conn
}

func newTrustHarness(t *testing.T, dir string) *trustHarness {
	t.Helper()
	t.Setenv(EnvConfigDir, dir)
	h := &trustHarness{t: t, dir: dir, frames: make(chan protocol.Envelope, 256)}
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		for {
			var env protocol.Envelope
			if ws.ReadJSON(&env) != nil {
				return
			}
			h.frames <- env
		}
	}))
	t.Cleanup(h.srv.Close)
	h.restart()
	return h
}

// restart simulates a process restart: a new Agent over the same directory.
func (h *trustHarness) restart() {
	h.t.Helper()
	if h.ws != nil {
		h.ws.Close()
	}
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(h.srv.URL, "http"), nil)
	if err != nil {
		h.t.Fatal(err)
	}
	h.ws = ws
	h.t.Cleanup(func() { ws.Close() })
	h.a = New(&Config{AgentID: testAgentID})
	h.a.setConn(&conn{ws: ws})
}

func (h *trustHarness) send(env protocol.Envelope) {
	h.t.Helper()
	h.a.dispatch(context.Background(), env)
}

// until reads frames until match returns true, collecting security events on
// the way.
func (h *trustHarness) until(match func(protocol.Envelope) bool) (protocol.Envelope, []protocol.Event, string) {
	h.t.Helper()
	var evs []protocol.Event
	var streamed strings.Builder
	timeout := time.After(60 * time.Second)
	for {
		select {
		case f := <-h.frames:
			switch f.T {
			case protocol.TypeEvent:
				var ev protocol.Event
				json.Unmarshal(f.D, &ev)
				if ev.Kind == protocol.EventKindSecurity {
					evs = append(evs, ev)
				}
			case protocol.TypeStream:
				streamed.Write(f.D)
			}
			if match(f) {
				return f, evs, streamed.String()
			}
		case <-timeout:
			h.t.Fatal("timed out waiting for a frame")
		}
	}
}

func (h *trustHarness) reply(id string) (protocol.Envelope, []protocol.Event, string) {
	h.t.Helper()
	return h.until(func(f protocol.Envelope) bool { return f.T == protocol.TypeReply && f.ID == id })
}

// drainSecurity returns the security events sent so far, after a ping round
// trip makes sure everything earlier has been read.
func (h *trustHarness) drainSecurity() []protocol.Event {
	h.t.Helper()
	h.send(protocol.Envelope{T: protocol.ReqPing, ID: "drain"})
	_, evs, _ := h.until(func(f protocol.Envelope) bool { return f.T == protocol.TypePong && f.ID == "drain" })
	return evs
}

func scriptPayload(marker, runID string) json.RawMessage {
	lang, body := "sh", "echo "+marker
	if runtime.GOOS == "windows" {
		lang, body = "powershell", "Write-Output "+marker
	}
	return protocol.Must(protocol.ScriptRun{RunID: runID, Language: lang, Body: body, Timeout: 60})
}

type trustKit struct {
	key *authtest.Key
	rec *authtest.RecoveryKey
}

func newKit() trustKit {
	return trustKit{key: authtest.NewKey("alice", actionauth.AlgES256), rec: authtest.NewRecoveryKey("")}
}

func (k trustKit) bundle(mode string) []byte {
	return authtest.Bundle(authtest.BundleSpec{
		Keys: []*authtest.Key{k.key}, Recovery: []*authtest.RecoveryKey{k.rec},
		Policy: actionauth.Policy{Mode: mode},
	})
}

func writeTrust(t *testing.T, dir string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "trust.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (k trustKit) signedAction(op string, payload json.RawMessage) *protocol.ActionAuth {
	m := authtest.Manifest(actionauth.Manifest{Kind: actionauth.KindAction, Targets: []string{testAgentID}, Op: op, Payload: payload})
	return authtest.Auth(m, k.key.Sign(m, authtest.SignOpts{}))
}

func TestTrustNoBundleRunsUnsigned(t *testing.T) {
	h := newTrustHarness(t, t.TempDir())
	h.send(protocol.Envelope{T: protocol.ReqScriptRun, ID: "r1", D: scriptPayload("PLAINMARK", "run1")})
	rep, evs, out := h.reply("r1")
	if rep.Err != "" || len(evs) != 0 {
		t.Fatalf("no bundle must behave as before, got err %q, events %v", rep.Err, evs)
	}
	if !strings.Contains(out+string(rep.D), "PLAINMARK") {
		t.Fatalf("the script did not run: %s", out)
	}
	if e, hash := h.a.trust.epochHash(); e != 0 || hash != "" {
		t.Fatalf("hello must carry no bundle, got %d %q", e, hash)
	}
}

func TestTrustEnforce(t *testing.T) {
	dir := t.TempDir()
	kit := newKit()
	writeTrust(t, dir, kit.bundle(actionauth.ModeEnforce))
	h := newTrustHarness(t, dir)

	if e, hash := h.a.trust.epochHash(); e != 1 || hash == "" {
		t.Fatalf("hello must carry the pinned bundle, got %d %q", e, hash)
	}

	// Unsigned: refused with an error reply and a security event.
	h.send(protocol.Envelope{T: protocol.ReqScriptRun, ID: "u1", D: scriptPayload("UNSIGNEDMARK", "run1")})
	rep, evs, out := h.reply("u1")
	if !strings.HasPrefix(rep.Err, "refused: ") || strings.Contains(out, "UNSIGNEDMARK") {
		t.Fatalf("unsigned script.run must be refused, got %q / %q", rep.Err, out)
	}
	if len(evs) != 1 || evs[0].Fields["executed"] != "false" || evs[0].Fields["op"] != protocol.ReqScriptRun ||
		evs[0].Fields["mode"] != actionauth.ModeEnforce || evs[0].Fields["reason"] == "" {
		t.Fatalf("expected one security event, got %+v", evs)
	}

	// Signed: the SIGNED payload runs even though the envelope differs.
	auth := kit.signedAction(protocol.ReqScriptRun, scriptPayload("SIGNEDMARK", "ignored"))
	h.send(protocol.Envelope{T: protocol.ReqScriptRun, ID: "s1", D: scriptPayload("FORGEDMARK", "run2"), A: auth})
	rep, evs, out = h.reply("s1")
	all := out + string(rep.D)
	if rep.Err != "" || len(evs) != 0 || !strings.Contains(all, "SIGNEDMARK") || strings.Contains(all, "FORGEDMARK") {
		t.Fatalf("signed run: err %q events %v output %q", rep.Err, evs, all)
	}

	// Replay is refused, and still is after a restart.
	h.send(protocol.Envelope{T: protocol.ReqScriptRun, ID: "p1", D: scriptPayload("SIGNEDMARK", "run3"), A: auth})
	if rep, _, _ = h.reply("p1"); !strings.Contains(rep.Err, "already used") {
		t.Fatalf("replay must be refused, got %q", rep.Err)
	}
	h.restart()
	h.send(protocol.Envelope{T: protocol.ReqScriptRun, ID: "p2", D: scriptPayload("SIGNEDMARK", "run4"), A: auth})
	if rep, _, _ = h.reply("p2"); !strings.Contains(rep.Err, "already used") {
		t.Fatalf("replay after a restart must be refused, got %q", rep.Err)
	}

	// Read operations and shell input never need a signature.
	h.send(protocol.Envelope{T: protocol.ReqPing, ID: "ping"})
	h.until(func(f protocol.Envelope) bool { return f.T == protocol.TypePong && f.ID == "ping" })
	h.send(protocol.Envelope{T: protocol.ReqProcList, ID: "pl"})
	if rep, _, _ = h.reply("pl"); rep.Err != "" {
		t.Fatalf("proc.list must not need a signature: %q", rep.Err)
	}
	h.send(protocol.Envelope{T: protocol.ReqShellInput, D: protocol.Must(protocol.ShellInput{Session: "none", Data: "x"})})
	h.send(protocol.Envelope{T: protocol.ReqShellResize, D: protocol.Must(protocol.ShellResize{Session: "none", Cols: 80, Rows: 24})})
	if evs := h.drainSecurity(); len(evs) != 0 {
		t.Fatalf("read ops raised security events: %+v", evs)
	}
}

func TestTrustAuditRunsAndReports(t *testing.T) {
	dir := t.TempDir()
	kit := newKit()
	writeTrust(t, dir, kit.bundle(actionauth.ModeAudit))
	h := newTrustHarness(t, dir)

	h.send(protocol.Envelope{T: protocol.ReqScriptRun, ID: "a1", D: scriptPayload("AUDITMARK", "run1")})
	rep, evs, out := h.reply("a1")
	if rep.Err != "" || !strings.Contains(out+string(rep.D), "AUDITMARK") {
		t.Fatalf("audit mode must still run the request: %q %q", rep.Err, out)
	}
	if len(evs) != 1 || evs[0].Fields["executed"] != "true" || evs[0].Fields["mode"] != actionauth.ModeAudit {
		t.Fatalf("audit mode must report the unsigned run, got %+v", evs)
	}
}

func TestTrustUnusableNonceStoreFailsVerification(t *testing.T) {
	dir := t.TempDir()
	kit := newKit()
	writeTrust(t, dir, kit.bundle(actionauth.ModeEnforce))
	os.WriteFile(filepath.Join(dir, "nonces.json"), []byte("{not json"), 0o600)
	h := newTrustHarness(t, dir)

	auth := kit.signedAction(protocol.ReqScriptRun, scriptPayload("SIGNEDMARK", "r"))
	h.send(protocol.Envelope{T: protocol.ReqScriptRun, ID: "n1", D: scriptPayload("SIGNEDMARK", "r"), A: auth})
	if rep, _, _ := h.reply("n1"); !strings.HasPrefix(rep.Err, "refused: ") || !strings.Contains(rep.Err, "nonce store") {
		t.Fatalf("an unusable nonce store must fail verification, got %q", rep.Err)
	}
}

func trustUpdateEnv(id string, bundle []byte, sigs ...protocol.Assertion) protocol.Envelope {
	return protocol.Envelope{T: protocol.ReqTrustUpdate, ID: id, D: protocol.Must(protocol.TrustUpdate{
		Bundle: actionauth.EncodeB64(bundle), S: sigs,
	})}
}

func TestTrustUpdate(t *testing.T) {
	dir := t.TempDir()
	kit := newKit()
	h := newTrustHarness(t, dir)

	// First use: pinned and persisted.
	b1 := kit.bundle(actionauth.ModeAudit)
	h.send(trustUpdateEnv("t1", b1))
	rep, evs, _ := h.reply("t1")
	if rep.Err != "" || len(evs) != 1 || !strings.Contains(evs[0].Fields["reason"], "pinned on first use, epoch 1") {
		t.Fatalf("first-use pin: err %q events %+v", rep.Err, evs)
	}
	saved, err := os.ReadFile(filepath.Join(dir, "trust.json"))
	if err != nil || string(saved) != string(b1) {
		t.Fatalf("trust.json must hold the exact bundle bytes: %v", err)
	}
	cur, _ := actionauth.ParseBundle(b1)
	if e, hash := h.a.trust.epochHash(); e != 1 || hash != cur.Hash() {
		t.Fatalf("in-memory bundle not swapped: %d %s", e, hash)
	}
	h.restart()
	if e, _ := h.a.trust.epochHash(); e != 1 {
		t.Fatal("the pin must survive a restart")
	}

	// A successor that only a key it introduces signed is refused.
	k2 := authtest.NewKey("mallory", actionauth.AlgES256)
	evil := authtest.Bundle(authtest.BundleSpec{Epoch: 2, Prev: cur.Hash(), Keys: []*authtest.Key{k2},
		Recovery: []*authtest.RecoveryKey{kit.rec}, Policy: actionauth.Policy{Mode: actionauth.ModeAudit}})
	h.send(trustUpdateEnv("t2", evil, k2.Sign(evil, authtest.SignOpts{})))
	rep, evs, _ = h.reply("t2")
	if rep.Err == "" || len(evs) != 1 || evs[0].Fields["executed"] != "false" {
		t.Fatalf("a bundle signed only by its own new key must be refused: %q %+v", rep.Err, evs)
	}
	if e, _ := h.a.trust.epochHash(); e != 1 {
		t.Fatal("a refused update must not change the bundle")
	}

	// A rotation signed by a current signer is accepted.
	good := authtest.Bundle(authtest.BundleSpec{Epoch: 2, Prev: cur.Hash(), Keys: []*authtest.Key{kit.key, k2},
		Recovery: []*authtest.RecoveryKey{kit.rec}, Policy: actionauth.Policy{Mode: actionauth.ModeEnforce}})
	h.send(trustUpdateEnv("t3", good, kit.key.Sign(good, authtest.SignOpts{})))
	rep, evs, _ = h.reply("t3")
	if rep.Err != "" || len(evs) != 1 || !strings.Contains(evs[0].Fields["reason"], "rotated to epoch 2") {
		t.Fatalf("rotation: err %q events %+v", rep.Err, evs)
	}
	var got struct {
		Epoch int64  `json:"epoch"`
		Hash  string `json:"hash"`
	}
	json.Unmarshal(rep.D, &got)
	if got.Epoch != 2 || got.Hash == "" {
		t.Fatalf("reply %s", rep.D)
	}
	// The new mode applies at once.
	h.send(protocol.Envelope{T: protocol.ReqScriptRun, ID: "x", D: scriptPayload("M", "r")})
	if rep, _, _ = h.reply("x"); !strings.HasPrefix(rep.Err, "refused: ") {
		t.Fatalf("enforce must apply after rotation: %q", rep.Err)
	}
}

func TestTrustCorruptBundleFailsClosed(t *testing.T) {
	dir := t.TempDir()
	writeTrust(t, dir, []byte(`{"v":1,"epoch":`))
	h := newTrustHarness(t, dir)

	h.send(protocol.Envelope{T: protocol.ReqScriptRun, ID: "c1", D: scriptPayload("M", "r")})
	rep, evs, _ := h.reply("c1")
	if !strings.HasPrefix(rep.Err, "refused: ") || !strings.Contains(rep.Err, "delete trust.json") || len(evs) != 1 {
		t.Fatalf("a corrupt trust.json must refuse actions: %q %+v", rep.Err, evs)
	}
	kit := newKit()
	h.send(trustUpdateEnv("c2", kit.bundle(actionauth.ModeAudit)))
	if rep, _, _ = h.reply("c2"); rep.Err == "" {
		t.Fatal("trust.update must be refused while the pin is unusable")
	}
	if _, err := os.Stat(filepath.Join(dir, "trust.json.tmp")); err == nil {
		t.Fatal("nothing may be written")
	}
	h.send(protocol.Envelope{T: protocol.ReqProcList, ID: "c3"})
	if rep, _, _ = h.reply("c3"); rep.Err != "" {
		t.Fatalf("read ops still work: %q", rep.Err)
	}
}

// ---- baselines ----

func specJSON(t *testing.T, id int64, name string) json.RawMessage {
	t.Helper()
	s := protocol.BaselineSpec{ID: id, Name: name, Version: 1, IntervalSec: 3600,
		Checks: []protocol.BaselineCheck{{ID: id * 10, Name: "c", Kind: "fake", Params: json.RawMessage(`{}`), TimeoutSec: 30}}}
	return protocol.Must(s)
}

func (k trustKit) approveSpec(t *testing.T, raw json.RawMessage) *protocol.ActionAuth {
	t.Helper()
	sum, err := actionauth.SpecHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	m := authtest.Manifest(actionauth.Manifest{Kind: actionauth.KindStanding, Targets: []string{testAgentID},
		Constraints: &actionauth.Constraints{Op: actionauth.SpecOp, SpecSHA256: sum}})
	return authtest.Auth(m, k.key.Sign(m, authtest.SignOpts{}))
}

func configFrame(t *testing.T, specs []json.RawMessage, auth map[string]*protocol.ActionAuth) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"metrics_interval_sec": 30, "inventory_interval_sec": 3600,
		"baselines": specs, "baseline_auth": auth,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func engineSpecs(a *Agent) map[int64]bool {
	a.baselines.mu.Lock()
	defer a.baselines.mu.Unlock()
	out := map[int64]bool{}
	for id := range a.baselines.specs {
		out[id] = true
	}
	return out
}

func TestTrustBaselinesEnforce(t *testing.T) {
	dir := t.TempDir()
	kit := newKit()
	writeTrust(t, dir, kit.bundle(actionauth.ModeEnforce))
	h := newTrustHarness(t, dir)

	approved := specJSON(t, 1, "approved")
	unapproved := specJSON(t, 2, "unapproved")
	// Approval for spec 3 was signed over different content: a tampered spec.
	tampered := specJSON(t, 3, "tampered")
	original := specJSON(t, 3, "original")
	auth := map[string]*protocol.ActionAuth{
		"1": kit.approveSpec(t, approved),
		"3": kit.approveSpec(t, original),
	}
	cfg := configFrame(t, []json.RawMessage{approved, unapproved, tampered}, auth)

	// Through dispatch's fast path, as the server pushes it.
	h.send(protocol.Envelope{T: protocol.ReqAgentConfig, D: cfg})
	got := engineSpecs(h.a)
	if !got[1] || got[2] || got[3] || len(got) != 1 {
		t.Fatalf("enforce must keep only the approved spec, kept %v", got)
	}
	evs := h.drainSecurity()
	if len(evs) != 2 {
		t.Fatalf("expected one event per dropped spec, got %+v", evs)
	}
	// A reconnect re-pushes the same config: no new alerts.
	h.send(protocol.Envelope{T: protocol.ReqAgentConfig, D: cfg})
	if evs := h.drainSecurity(); len(evs) != 0 {
		t.Fatalf("duplicate reports: %+v", evs)
	}

	// The approval is stored with the engine state and survives a restart.
	h.restart()
	h.a.baselines.load()
	if !engineSpecs(h.a)[1] || !h.a.baselines.mayRun(h.a.baselines.specs[1]) {
		t.Fatal("an approved spec must still run after a restart")
	}
}

func TestTrustBaselinesAudit(t *testing.T) {
	dir := t.TempDir()
	kit := newKit()
	writeTrust(t, dir, kit.bundle(actionauth.ModeAudit))
	h := newTrustHarness(t, dir)

	approved := specJSON(t, 1, "approved")
	unapproved := specJSON(t, 2, "unapproved")
	cfg := configFrame(t, []json.RawMessage{approved, unapproved}, map[string]*protocol.ActionAuth{"1": kit.approveSpec(t, approved)})
	h.a.applyConfigRaw(cfg)
	if got := engineSpecs(h.a); !got[1] || !got[2] {
		t.Fatalf("audit keeps every spec, kept %v", got)
	}
	evs := h.drainSecurity()
	if len(evs) != 1 || evs[0].Fields["executed"] != "true" {
		t.Fatalf("audit reports the unapproved spec once: %+v", evs)
	}
	h.a.applyConfigRaw(cfg)
	if evs := h.drainSecurity(); len(evs) != 0 {
		t.Fatalf("duplicate reports: %+v", evs)
	}
}

// A spec saved before Phase 3 has no approval: enforce does not run it, audit
// runs it and says so once.
func TestTrustStoredSpecWithoutApproval(t *testing.T) {
	dir := t.TempDir()
	kit := newKit()
	t.Setenv(EnvConfigDir, dir)
	var sp protocol.BaselineSpec
	json.Unmarshal(specJSON(t, 1, "legacy"), &sp)
	old, _ := json.Marshal(baselineStateFile{Specs: []protocol.BaselineSpec{sp}})
	if err := os.WriteFile(filepath.Join(dir, "baselines.json"), old, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, mode := range []string{actionauth.ModeEnforce, actionauth.ModeAudit} {
		writeTrust(t, dir, kit.bundle(mode))
		h := newTrustHarness(t, dir)
		fk := &fakeKind{}
		e := h.a.baselines
		e.kinds = func(string) *kindImpl { return fk.impl() }
		e.load()
		if !engineSpecs(h.a)[1] {
			t.Fatal("the stored spec must load")
		}
		e.mu.Lock()
		e.due[1] = time.Now().Add(-time.Second)
		e.mu.Unlock()
		e.runDue(context.Background())
		checks, _ := fk.counts()
		evs := h.drainSecurity()
		switch mode {
		case actionauth.ModeEnforce:
			if checks != 0 || len(evs) != 1 || evs[0].Fields["executed"] != "false" {
				t.Fatalf("enforce must not run an unapproved stored spec: checks %d events %+v", checks, evs)
			}
		default:
			if checks == 0 || len(evs) != 1 || evs[0].Fields["executed"] != "true" {
				t.Fatalf("audit runs and reports it once: checks %d events %+v", checks, evs)
			}
		}
	}
}
