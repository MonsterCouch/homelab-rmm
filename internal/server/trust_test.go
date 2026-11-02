package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/actionauth/authtest"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

const trustOrg = "org_default"

// signerIn is one signer of a proposal: the user and the keys of theirs the
// bundle should list.
func signerIn(owner string, keys ...*authtest.Key) map[string]any {
	ids := []string{}
	for _, k := range keys {
		ids = append(ids, k.Credential().ID)
	}
	return map[string]any{"owner": owner, "credential_ids": ids}
}

type proposed struct {
	ID     string
	Bundle []byte
	Need   int
	Epoch  int64
}

// propose creates a proposal and returns the status and, on success, its parts.
func propose(t *testing.T, b *browser, in map[string]any) (int, string, *proposed) {
	t.Helper()
	st, body := b.do("POST", "/api/organizations/"+trustOrg+"/trust/proposals", in)
	if st != 201 {
		return st, string(body), nil
	}
	var r struct {
		ID     string `json:"id"`
		Epoch  int64  `json:"epoch"`
		Bundle string `json:"bundle"`
		Need   int    `json:"need"`
		Have   int    `json:"have"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatal(err)
	}
	raw, err := b64dec(r.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if r.Have != 0 {
		t.Fatalf("a fresh proposal has %d signatures", r.Have)
	}
	return st, string(body), &proposed{ID: r.ID, Bundle: raw, Need: r.Need, Epoch: r.Epoch}
}

type signResult struct {
	Have   int  `json:"have"`
	Need   int  `json:"need"`
	Active bool `json:"active"`
}

func signWith(t *testing.T, b *browser, p *proposed, k *authtest.Key, o authtest.SignOpts) (int, string, signResult) {
	t.Helper()
	a := k.Sign(p.Bundle, o)
	st, body := b.do("POST", "/api/trust/proposals/"+p.ID+"/sign", map[string]any{"assertion": a})
	var r signResult
	json.Unmarshal(body, &r)
	return st, string(body), r
}

// activate proposes and signs until the proposal is active.
func activate(t *testing.T, b *browser, in map[string]any, keys ...*authtest.Key) *proposed {
	t.Helper()
	st, body, p := propose(t, b, in)
	if p == nil {
		t.Fatalf("propose = %d %s", st, body)
	}
	for _, k := range keys {
		st, body, r := signWith(t, b, p, k, authtest.SignOpts{})
		if st != 200 {
			t.Fatalf("sign = %d %s", st, body)
		}
		if r.Active {
			return p
		}
	}
	t.Fatalf("proposal %s never became active", p.ID)
	return nil
}

func currentEpoch(t *testing.T, s *Server) int64 {
	t.Helper()
	row, err := s.db.currentTrust(trustOrg)
	if err != nil {
		t.Fatal(err)
	}
	if row == nil {
		return 0
	}
	return row.Epoch
}

func TestTrustFirstBundleAndRotation(t *testing.T) {
	s, ts, admin := newTestServerWith(t, Config{WebAuthnRPID: authtest.RPID, WebAuthnOrigins: []string{authtest.Origin}})
	admin.mustJSON("POST", "/api/users", map[string]string{"username": "bob", "password": "password123", "role": "tech"}, nil)
	bob := newBrowser(t, ts)
	bob.mustJSON("POST", "/api/auth/login", map[string]string{"username": "bob", "password": "password123"}, nil)

	ka := authtest.NewKey("admin", actionauth.AlgES256)
	kb := authtest.NewKey("bob", actionauth.AlgEdDSA)
	registerKey(t, admin, ka)
	registerKey(t, bob, kb)

	// ---- authorization ----
	if st, _ := bob.do("GET", "/api/organizations/"+trustOrg+"/trust", nil); st != 403 {
		t.Fatalf("a technician reading the trust state = %d", st)
	}
	if st, _ := bob.do("POST", "/api/organizations/"+trustOrg+"/trust/proposals", map[string]any{"signers": []any{signerIn("bob", kb)}}); st != 403 {
		t.Fatalf("a technician proposing = %d", st)
	}
	if st, _ := admin.do("POST", "/api/organizations/org_nope/trust/proposals", map[string]any{}); st != 404 {
		t.Fatalf("unknown organization = %d", st)
	}
	var state struct {
		Current   any            `json:"current"`
		Proposals []any          `json:"proposals"`
		Agents    map[string]int `json:"agents"`
	}
	admin.mustJSON("GET", "/api/organizations/"+trustOrg+"/trust", nil, &state)
	if state.Current != nil || len(state.Proposals) != 0 {
		t.Fatalf("a fresh organization has trust state %+v", state)
	}

	// ---- building: refusals come from the same parser the agents use ----
	for _, c := range []struct {
		name string
		in   map[string]any
		want string
	}{
		{"enforce needs a recovery key", map[string]any{"mode": "enforce", "signers": []any{signerIn("admin", ka)}}, "recovery"},
		{"no signers", map[string]any{"mode": "audit"}, "signers"},
		{"threshold above the signers", map[string]any{"mode": "audit", "bundle_threshold": 2, "signers": []any{signerIn("admin", ka)}}, "thresholds exceed"},
		{"unknown mode", map[string]any{"mode": "yolo", "signers": []any{signerIn("admin", ka)}}, "unknown mode"},
		{"someone else's key", map[string]any{"mode": "audit", "signers": []any{signerIn("admin", kb)}}, "not a registered key of admin"},
		{"unknown user", map[string]any{"mode": "audit", "signers": []any{signerIn("nobody", ka)}}, "not a user"},
		{"signer without keys", map[string]any{"mode": "audit", "signers": []any{map[string]any{"owner": "admin"}}}, "at least one security key"},
		{"bad recovery key", map[string]any{"mode": "audit", "signers": []any{signerIn("admin", ka)}, "recovery": []any{map[string]string{"id": "r", "pub": "AAAA"}}}, "recovery key"},
	} {
		st, body, _ := propose(t, admin, c.in)
		if st != 400 || !strings.Contains(body, c.want) {
			t.Errorf("%s: %d %s, want 400 containing %q", c.name, st, body, c.want)
		}
	}

	// ---- the first bundle (no current one to check against) ----
	st, body, p1 := propose(t, admin, map[string]any{"mode": "audit", "signers": []any{signerIn("admin", ka)}})
	if p1 == nil {
		t.Fatalf("first proposal = %d %s", st, body)
	}
	if p1.Epoch != 1 || p1.Need != 1 {
		t.Fatalf("first proposal epoch %d need %d", p1.Epoch, p1.Need)
	}
	nb, err := actionauth.ParseBundle(p1.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	canon, _ := actionauth.CanonicalizeJSON(p1.Bundle)
	if string(canon) != string(p1.Bundle) {
		t.Fatal("the proposed bundle is not in canonical form")
	}
	if nb.Org != trustOrg || nb.RPID != authtest.RPID || len(nb.Origins) != 1 || nb.Origins[0] != authtest.Origin || nb.Prev != "" {
		t.Fatalf("bundle = %+v", nb)
	}
	if nb.Policy.Mode != "audit" || nb.Policy.BulkLimit != 10 || nb.Policy.HighThreshold != 1 {
		t.Fatalf("policy defaults = %+v", nb.Policy)
	}
	// the proposal can be fetched for offline signing
	var got struct {
		Bundle string `json:"bundle"`
		Hash   string `json:"hash"`
		Epoch  int64  `json:"epoch"`
	}
	admin.mustJSON("GET", "/api/trust/proposals/"+p1.ID, nil, &got)
	if got.Bundle == "" || got.Hash != nb.Hash() || got.Epoch != 1 {
		t.Fatalf("GET proposal = %+v", got)
	}
	if st, _ := bob.do("GET", "/api/trust/proposals/"+p1.ID, nil); st != 403 {
		t.Fatalf("a technician fetching a proposal = %d", st)
	}

	// a key that is not in the proposed bundle proves nothing
	if st, body, _ := signWith(t, admin, p1, kb, authtest.SignOpts{}); st != 400 || !strings.Contains(body, "not in the trust bundle") {
		t.Fatalf("first bundle signed by an outsider = %d %s", st, body)
	}
	// wrong origin, wrong document, missing presence: each refused with its reason
	if st, body, _ := signWith(t, admin, p1, ka, authtest.SignOpts{Origin: "https://evil.example"}); st != 400 || !strings.Contains(body, "origin") {
		t.Fatalf("wrong origin = %d %s", st, body)
	}
	if st, body, _ := signWith(t, admin, p1, ka, authtest.SignOpts{Challenge: make([]byte, 32)}); st != 400 || !strings.Contains(body, "different document") {
		t.Fatalf("wrong challenge = %d %s", st, body)
	}
	if st, body, _ := signWith(t, admin, p1, ka, authtest.SignOpts{NoUP: true}); st != 400 || !strings.Contains(body, "presence") {
		t.Fatalf("no user presence = %d %s", st, body)
	}
	if e := currentEpoch(t, s); e != 0 {
		t.Fatalf("a bad signature activated epoch %d", e)
	}
	if st, body, r := signWith(t, admin, p1, ka, authtest.SignOpts{}); st != 200 || !r.Active || r.Have != 1 || r.Need != 1 {
		t.Fatalf("sign = %d %s", st, body)
	}
	if e := currentEpoch(t, s); e != 1 {
		t.Fatalf("epoch = %d after activation", e)
	}
	// the proposal is consumed
	if st, _ := admin.do("GET", "/api/trust/proposals/"+p1.ID, nil); st != 404 {
		t.Fatalf("an activated proposal is still there: %d", st)
	}
	row, _ := s.db.currentTrust(trustOrg)
	if string(row.Bundle) != string(p1.Bundle) || row.Hash != nb.Hash() || len(row.Sigs) != 1 || row.ActivatedBy != "admin" {
		t.Fatalf("stored epoch 1 = %+v", row)
	}

	// the key is now pinned: it cannot be deleted until a bundle drops it
	var creds []Credential
	admin.mustJSON("GET", "/api/webauthn/credentials", nil, &creds)
	for _, c := range creds {
		if c.Owner == "admin" && (!c.InBundle || len(c.BundleOrgs) != 1 || c.BundleOrgs[0] != trustOrg) {
			t.Fatalf("admin's key not flagged in_bundle: %+v", c)
		}
		if c.Owner == "bob" && c.InBundle {
			t.Fatalf("bob's key flagged in_bundle: %+v", c)
		}
	}
	if st, body := admin.do("DELETE", "/api/webauthn/credentials/"+ka.Credential().ID, nil); st != 409 || !strings.Contains(string(body), "trust bundle") {
		t.Fatalf("deleting a pinned key = %d %s", st, body)
	}

	// ---- epoch 2: add bob. Only a CURRENT signer's signature counts ----
	two := map[string]any{"mode": "audit", "signers": []any{signerIn("admin", ka), signerIn("bob", kb)}}
	_, _, p2 := propose(t, admin, two)
	if p2 == nil || p2.Epoch != 2 {
		t.Fatalf("second proposal = %+v", p2)
	}
	nb2, _ := actionauth.ParseBundle(p2.Bundle)
	if nb2.Prev != nb.Hash() {
		t.Fatalf("epoch 2 prev = %q, want %q", nb2.Prev, nb.Hash())
	}
	if st, body, _ := signWith(t, admin, p2, kb, authtest.SignOpts{}); st != 400 || !strings.Contains(body, "not in the trust bundle") {
		t.Fatalf("a newly added signer signing their own addition = %d %s", st, body)
	}
	if e := currentEpoch(t, s); e != 1 {
		t.Fatalf("epoch = %d after a signature by a newly added signer", e)
	}
	if st, body, r := signWith(t, admin, p2, ka, authtest.SignOpts{}); st != 200 || !r.Active {
		t.Fatalf("a current signer signing epoch 2 = %d %s", st, body)
	}
	if e := currentEpoch(t, s); e != 2 {
		t.Fatalf("epoch = %d", e)
	}

	// ---- epoch 3: add a recovery key, then enforce is allowed ----
	rk := authtest.NewRecoveryKey("")
	rec := []any{map[string]string{"id": rk.ID, "pub": rk.Entry().Pub}}
	// Filed under any ID but the derived one, the CLI's signatures (labelled
	// with the derived ID) would never match: refuse it up front.
	mislabelled := []any{map[string]string{"id": "recovery-0", "pub": rk.Entry().Pub}}
	if st, body, _ := propose(t, admin, map[string]any{"mode": "audit", "signers": []any{signerIn("admin", ka)}, "recovery": mislabelled}); st != 400 || !strings.Contains(body, "does not match its public key") {
		t.Fatalf("mislabelled recovery key: %d %s", st, body)
	}
	three := map[string]any{"mode": "enforce", "signers": []any{signerIn("admin", ka), signerIn("bob", kb)}, "recovery": rec}
	activate(t, admin, three, kb)
	if e := currentEpoch(t, s); e != 3 {
		t.Fatalf("epoch = %d", e)
	}

	// ---- epoch 4 by recovery key alone, with every operator key "lost" ----
	four := map[string]any{"mode": "enforce", "signers": []any{signerIn("admin", ka)}, "recovery": rec}
	_, _, p4 := propose(t, admin, four)
	if p4 == nil {
		t.Fatal("no epoch 4 proposal")
	}
	badSig := rk.Sign([]byte("some other bundle"))
	for name, rs := range map[string]protocol.RecoverySig{
		"bad signature": {ID: rk.ID, Sig: badSig.Sig},
		"unknown key":   {ID: "nope", Sig: rk.Sign(p4.Bundle).Sig},
	} {
		if st, body := admin.do("POST", "/api/trust/proposals/"+p4.ID+"/recovery", rs); st != 400 {
			t.Errorf("%s = %d %s", name, st, body)
		}
	}
	if e := currentEpoch(t, s); e != 3 {
		t.Fatalf("a bad recovery signature activated epoch %d", e)
	}
	var rr signResult
	admin.mustJSON("POST", "/api/trust/proposals/"+p4.ID+"/recovery", rk.Sign(p4.Bundle), &rr)
	if !rr.Active || currentEpoch(t, s) != 4 {
		t.Fatalf("recovery signature did not activate: %+v epoch %d", rr, currentEpoch(t, s))
	}
	row4, _ := s.db.trustAt(trustOrg, 4)
	if len(row4.RSigs) != 1 || len(row4.Sigs) != 0 {
		t.Fatalf("epoch 4 stored sigs %d recovery %d", len(row4.Sigs), len(row4.RSigs))
	}

	// ---- recovery keys are carried forward; removal is explicit ----
	// (epoch 4 above sent no new keys of its own beyond rec1, and the
	// next proposal sends none at all)
	_, _, keep := propose(t, admin, map[string]any{"mode": "enforce", "signers": []any{signerIn("admin", ka)}})
	if keep == nil {
		t.Fatal("a proposal without a recovery list was refused")
	}
	kb2, _ := actionauth.ParseBundle(keep.Bundle)
	if len(kb2.Recovery) != 1 || kb2.Recovery[0].ID != rk.ID {
		t.Fatalf("recovery keys not carried forward: %+v", kb2.Recovery)
	}
	// adding a second key keeps the first
	rk2 := authtest.NewRecoveryKey("")
	_, _, add := propose(t, admin, map[string]any{"mode": "enforce", "signers": []any{signerIn("admin", ka)},
		"recovery": []any{map[string]string{"id": rk2.ID, "pub": rk2.Entry().Pub}}})
	ab, _ := actionauth.ParseBundle(add.Bundle)
	if len(ab.Recovery) != 2 {
		t.Fatalf("recovery after adding = %+v", ab.Recovery)
	}
	// removing the only key while enforcing is refused with the parser's reason
	if st, body, _ := propose(t, admin, map[string]any{"mode": "enforce", "signers": []any{signerIn("admin", ka)}, "remove_recovery_ids": []string{rk.ID}}); st != 400 || !strings.Contains(body, "recovery key") {
		t.Fatalf("removing the last recovery key under enforce = %d %s", st, body)
	}
	// but it may go when another remains, or when not enforcing
	_, _, rm := propose(t, admin, map[string]any{"mode": "audit", "signers": []any{signerIn("admin", ka)}, "remove_recovery_ids": []string{rk.ID}})
	rb, _ := actionauth.ParseBundle(rm.Bundle)
	if len(rb.Recovery) != 0 {
		t.Fatalf("recovery after removal = %+v", rb.Recovery)
	}
	if st, body, _ := propose(t, admin, map[string]any{"mode": "audit", "signers": []any{signerIn("admin", ka)}, "remove_recovery_ids": []string{"ghost"}}); st != 400 || !strings.Contains(body, "ghost") {
		t.Fatalf("removing an unknown recovery key = %d %s", st, body)
	}
	// the state lists the IDs of the keys in force
	var rstate struct {
		Current struct {
			RecoveryIDs []string `json:"recovery_ids"`
		} `json:"current"`
	}
	admin.mustJSON("GET", "/api/organizations/"+trustOrg+"/trust", nil, &rstate)
	if len(rstate.Current.RecoveryIDs) != 1 || rstate.Current.RecoveryIDs[0] != rk.ID {
		t.Fatalf("recovery_ids = %v", rstate.Current.RecoveryIDs)
	}

	// ---- a recovery key cannot start the chain ----
	// (no current bundle exists in another organization)
	org := struct{ ID string }{}
	admin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Other"}, &org)
	if org.ID == "" {
		t.Fatal("no org created")
	}
	st, raw := admin.do("POST", "/api/organizations/"+org.ID+"/trust/proposals", map[string]any{"mode": "audit", "signers": []any{signerIn("admin", ka)}})
	if st != 201 {
		t.Fatalf("proposal in a second org = %d %s", st, raw)
	}
	var op struct{ ID string }
	json.Unmarshal(raw, &op)
	if st, _ := admin.do("POST", "/api/trust/proposals/"+op.ID+"/recovery", rk.Sign(nil)); st != 400 {
		t.Fatalf("recovery signature on a first bundle = %d", st)
	}

	// ---- epoch 5: a two-signer threshold counts distinct owners ----
	five := map[string]any{"mode": "enforce", "bundle_threshold": 2, "signers": []any{signerIn("admin", ka), signerIn("bob", kb)}, "recovery": rec}
	_, _, p5 := propose(t, admin, five)
	// epoch 4 listed only admin, so bob cannot sign yet; admin alone meets
	// epoch 4's threshold of 1
	if st, _, _ := signWith(t, admin, p5, kb, authtest.SignOpts{}); st != 400 {
		t.Fatalf("bob signing before being in the bundle = %d", st)
	}
	if st, body, r := signWith(t, admin, p5, ka, authtest.SignOpts{}); st != 200 || !r.Active {
		t.Fatalf("epoch 5 = %d %s", st, body)
	}
	// epoch 6 now needs two distinct owners
	six := map[string]any{"mode": "enforce", "bundle_threshold": 2, "bulk_limit": 20, "signers": []any{signerIn("admin", ka), signerIn("bob", kb)}, "recovery": rec}
	_, _, p6 := propose(t, admin, six)
	if p6.Need != 2 {
		t.Fatalf("need = %d, want 2", p6.Need)
	}
	if _, body, r := signWith(t, admin, p6, ka, authtest.SignOpts{}); r.Active || r.Have != 1 || r.Need != 2 {
		t.Fatalf("one of two signers: %s", body)
	}
	// signing again with the same key (or a second key of the same owner)
	// does not add a second owner
	if _, body, r := signWith(t, admin, p6, ka, authtest.SignOpts{}); r.Active || r.Have != 1 {
		t.Fatalf("the same signer twice: %s", body)
	}
	if e := currentEpoch(t, s); e != 5 {
		t.Fatalf("epoch = %d before the second owner signed", e)
	}
	if _, body, r := signWith(t, admin, p6, kb, authtest.SignOpts{}); !r.Active || r.Have != 2 {
		t.Fatalf("two signers: %s", body)
	}
	if e := currentEpoch(t, s); e != 6 {
		t.Fatalf("epoch = %d", e)
	}

	// ---- a proposal for an epoch that was overtaken is refused ----
	seven := map[string]any{"mode": "audit", "signers": []any{signerIn("admin", ka), signerIn("bob", kb)}, "bundle_threshold": 1}
	_, _, a := propose(t, admin, seven)
	_, _, other := propose(t, admin, seven)
	if _, _, r := signWith(t, admin, a, ka, authtest.SignOpts{}); r.Active { // threshold 2 in force
		t.Fatal("one signature met a threshold of two")
	}
	signWith(t, admin, a, kb, authtest.SignOpts{})
	if currentEpoch(t, s) != 7 {
		t.Fatalf("epoch = %d, want 7", currentEpoch(t, s))
	}
	if st, body := admin.do("POST", "/api/trust/proposals/"+other.ID+"/sign", map[string]any{"assertion": ka.Sign(other.Bundle, authtest.SignOpts{})}); st != 404 && st != 409 {
		t.Fatalf("signing an overtaken proposal = %d %s", st, body)
	}

	// the listing reflects history
	admin.mustJSON("GET", "/api/organizations/"+trustOrg+"/trust", nil, &state)
	cur, _ := state.Current.(map[string]any)
	if cur == nil || cur["epoch"].(float64) != 7 || cur["mode"] != "audit" {
		t.Fatalf("current = %v", state.Current)
	}
	// audit trail
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action = 'trust.activate'`).Scan(&n)
	if n != 7 {
		t.Fatalf("%d trust.activate audit rows, want 7", n)
	}
}

// ---- sync ----

// trustAgent is an agent socket that reports a chosen trust epoch and records
// the trust.update requests the server sends it.
type trustAgent struct {
	t       *testing.T
	ws      *websocket.Conn
	id, key string
	updates chan protocol.TrustUpdate
}

func dialTrustAgent(t *testing.T, ts *httptest.Server, hdr http.Header, host string, epoch int64, hash string) *trustAgent {
	t.Helper()
	ws, resp, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/agent", hdr)
	if err != nil {
		code := 0
		if resp != nil {
			code = resp.StatusCode
		}
		t.Fatalf("dial %s: %v (%d)", host, err, code)
	}
	if err := ws.WriteJSON(protocol.Envelope{T: protocol.TypeHello, D: protocol.Must(protocol.Hello{
		Hostname: host, OS: "linux", Platform: "Test", Arch: "amd64", Version: "test", ProtocolVersion: protocol.Version,
		TrustEpoch: epoch, TrustHash: hash,
	})}); err != nil {
		t.Fatal(err)
	}
	var env protocol.Envelope
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := ws.ReadJSON(&env); err != nil || env.T != "welcome" {
		t.Fatalf("welcome for %s: %v %s %s", host, err, env.T, env.Err)
	}
	ws.SetReadDeadline(time.Time{})
	var wl struct {
		ID  string `json:"agent_id"`
		Key string `json:"agent_key"`
	}
	json.Unmarshal(env.D, &wl)
	a := &trustAgent{t: t, ws: ws, id: wl.ID, key: wl.Key, updates: make(chan protocol.TrustUpdate, 16)}
	t.Cleanup(func() { ws.Close() })
	go func() {
		for {
			var e protocol.Envelope
			if err := ws.ReadJSON(&e); err != nil {
				return
			}
			switch {
			case e.T == protocol.ReqPing:
				ws.WriteJSON(protocol.Envelope{T: protocol.TypePong, ID: e.ID})
			case e.T == protocol.ReqTrustUpdate:
				var u protocol.TrustUpdate
				json.Unmarshal(e.D, &u)
				a.updates <- u
				ws.WriteJSON(protocol.Envelope{T: protocol.TypeReply, ID: e.ID})
			case e.ID != "":
				ws.WriteJSON(protocol.Envelope{T: protocol.TypeReply, ID: e.ID})
			}
		}
	}()
	return a
}

// enrollTrustAgent enrolls a fresh agent that reports the given bundle.
func enrollTrustAgent(t *testing.T, ts *httptest.Server, b *browser, host string, epoch int64, hash string) *trustAgent {
	t.Helper()
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": host, "uses": 1}, &tok)
	return dialTrustAgent(t, ts, http.Header{"X-Enroll-Token": []string{tok.Token}}, host, epoch, hash)
}

// reconnect drops the agent and reconnects it with its key, as a real agent
// does, reporting the bundle it holds now.
func (a *trustAgent) reconnect(s *Server, ts *httptest.Server, host string, epoch int64, hash string) *trustAgent {
	a.t.Helper()
	a.ws.Close()
	waitFor(a.t, "agent offline", func() bool { return !s.hub.IsOnline(a.id) })
	n := dialTrustAgent(a.t, ts, http.Header{"Authorization": []string{"Bearer " + a.key}}, host, epoch, hash)
	n.id, n.key = a.id, a.key
	return n
}

func (a *trustAgent) expect(n int) []protocol.TrustUpdate {
	a.t.Helper()
	var out []protocol.TrustUpdate
	for len(out) < n {
		select {
		case u := <-a.updates:
			out = append(out, u)
		case <-time.After(5 * time.Second):
			a.t.Fatalf("got %d trust.update(s), wanted %d", len(out), n)
		}
	}
	return out
}

func (a *trustAgent) expectNone() {
	a.t.Helper()
	select {
	case u := <-a.updates:
		a.t.Fatalf("unexpected trust.update: %+v", u)
	case <-time.After(400 * time.Millisecond):
	}
}

func bundleHash(t *testing.T, raw []byte) string {
	t.Helper()
	b, err := actionauth.ParseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	return b.Hash()
}

func trustEpochOf(s *Server, agentID string) int64 {
	var e int64
	s.db.QueryRow(`SELECT trust_epoch FROM agents WHERE id = ?`, agentID).Scan(&e)
	return e
}

func openAlertTitled(t *testing.T, s *Server, agentID, contains string) *Alert {
	t.Helper()
	list, err := s.db.ListAlerts("open", agentID, 50)
	if err != nil {
		t.Fatal(err)
	}
	for i := range list {
		if strings.Contains(list[i].Title, contains) {
			return &list[i]
		}
	}
	return nil
}

func TestTrustBundleSync(t *testing.T) {
	s, ts, admin := newTestServerWith(t, Config{WebAuthnRPID: authtest.RPID, WebAuthnOrigins: []string{authtest.Origin}})
	ka := authtest.NewKey("admin", actionauth.AlgES256)
	registerKey(t, admin, ka)
	in := func(bulk int) map[string]any {
		return map[string]any{"mode": "audit", "bulk_limit": bulk, "signers": []any{signerIn("admin", ka)}}
	}

	// An agent online BEFORE any bundle exists gets the first one pushed at
	// activation (trust on first use).
	early := enrollTrustAgent(t, ts, admin, "early", 0, "")
	waitFor(t, "early online", func() bool { return s.hub.IsOnline(early.id) })
	early.expectNone() // no bundle yet: nothing to sync

	b1 := activate(t, admin, in(10), ka)
	got := early.expect(1)
	if got[0].Bundle != actionauth.EncodeB64(b1.Bundle) {
		t.Fatal("the agent was not sent epoch 1")
	}
	waitFor(t, "epoch recorded", func() bool { return trustEpochOf(s, early.id) == 1 })

	b2 := activate(t, admin, in(20), ka)
	b3 := activate(t, admin, in(30), ka)
	// the online agent is walked forward one epoch at a time, in order
	steps := early.expect(2)
	if steps[0].Bundle != actionauth.EncodeB64(b2.Bundle) || steps[1].Bundle != actionauth.EncodeB64(b3.Bundle) {
		t.Fatal("epochs 2 and 3 were not delivered in order")
	}
	if len(steps[0].S) != 1 || len(steps[1].S) != 1 {
		t.Fatalf("the stored signatures were not sent with the bundles: %d %d", len(steps[0].S), len(steps[1].S))
	}
	waitFor(t, "epoch 3 recorded", func() bool { return trustEpochOf(s, early.id) == 3 })

	// a fresh agent holding nothing receives the CURRENT bundle only
	fresh := enrollTrustAgent(t, ts, admin, "fresh", 0, "")
	if u := fresh.expect(1); u[0].Bundle != actionauth.EncodeB64(b3.Bundle) {
		t.Fatal("a new agent was not sent the current bundle")
	}
	fresh.expectNone()
	waitFor(t, "fresh epoch recorded", func() bool { return trustEpochOf(s, fresh.id) == 3 })

	// an agent at epoch 1 with the right hash is brought to 3 through 2
	h1, h2, h3 := bundleHash(t, b1.Bundle), bundleHash(t, b2.Bundle), bundleHash(t, b3.Bundle)
	old := early.reconnect(s, ts, "early", 1, h1)
	steps = old.expect(2)
	if steps[0].Bundle != actionauth.EncodeB64(b2.Bundle) || steps[1].Bundle != actionauth.EncodeB64(b3.Bundle) {
		t.Fatal("a reconnecting agent at epoch 1 was not given epochs 2 then 3")
	}
	if a := openAlertTitled(t, s, old.id, "trust bundle mismatch"); a != nil {
		t.Fatalf("an honest agent raised %+v", a)
	}

	// an agent at epoch 2 gets only epoch 3
	one := old.reconnect(s, ts, "early", 2, h2)
	if u := one.expect(1); u[0].Bundle != actionauth.EncodeB64(b3.Bundle) {
		t.Fatal("agent at epoch 2 was not sent epoch 3")
	}
	one.expectNone()

	// an agent already current is left alone
	cur := one.reconnect(s, ts, "early", 3, h3)
	cur.expectNone()
	if a := openAlertTitled(t, s, cur.id, "trust bundle mismatch"); a != nil {
		t.Fatalf("a current agent raised %+v", a)
	}

	// a wrong hash for a known epoch is an alert and nothing is pushed
	bad := cur.reconnect(s, ts, "early", 2, strings.Repeat("ab", 32))
	bad.expectNone()
	waitFor(t, "mismatch alert", func() bool { return openAlertTitled(t, s, bad.id, "trust bundle mismatch on") != nil })
	al := openAlertTitled(t, s, bad.id, "trust bundle mismatch")
	if al.Severity != "critical" || !strings.Contains(al.Message, "not the one this server issued") {
		t.Fatalf("alert = %+v", al)
	}

	// an epoch from the future is an alert too
	ahead := enrollTrustAgent(t, ts, admin, "ahead", 9, strings.Repeat("cd", 32))
	ahead.expectNone()
	waitFor(t, "ahead alert", func() bool { return openAlertTitled(t, s, ahead.id, "trust bundle mismatch") != nil })

	// the same hash at the current epoch but a different one is also an alert
	same := enrollTrustAgent(t, ts, admin, "forked", 3, strings.Repeat("ef", 32))
	same.expectNone()
	waitFor(t, "forked alert", func() bool { return openAlertTitled(t, s, same.id, "trust bundle mismatch") != nil })

	// the console's view of the fleet
	var state struct {
		Agents map[string]int `json:"agents"`
	}
	admin.mustJSON("GET", "/api/organizations/"+trustOrg+"/trust", nil, &state)
	// early reconnected claiming a wrong hash (mismatched), ahead and forked
	// are mismatched; fresh is current; nothing is behind or without a bundle
	waitFor(t, "counts", func() bool {
		admin.mustJSON("GET", "/api/organizations/"+trustOrg+"/trust", nil, &state)
		return state.Agents["at_current"] == 1 && state.Agents["mismatched"] == 3
	})
	if state.Agents["behind"] != 0 || state.Agents["none"] != 0 {
		t.Fatalf("agent counts = %v", state.Agents)
	}
}

func TestPlanTrustSync(t *testing.T) {
	hashes := map[int64]string{1: "h1", 2: "h2", 3: "h3"}
	cases := []struct {
		name  string
		epoch int64
		hash  string
		cur   int64
		send  []int64
		alert bool
	}{
		{"no bundle, agent has none", 0, "", 0, nil, false},
		{"no bundle, agent has one", 2, "h2", 0, nil, false},
		{"agent has none", 0, "", 3, []int64{3}, false},
		{"agent behind", 1, "h1", 3, []int64{2, 3}, false},
		{"agent one behind", 2, "H2", 3, []int64{3}, false}, // hashes compare case-insensitively
		{"agent current", 3, "h3", 3, nil, false},
		{"hash differs at a known epoch", 2, "zz", 3, nil, true},
		{"hash differs at the current epoch", 3, "zz", 3, nil, true},
		{"agent ahead of the server", 4, "h4", 3, nil, true},
		{"epoch the server never issued", 0 + 7, "x", 3, nil, true},
	}
	for _, c := range cases {
		p := planTrustSync(c.epoch, c.hash, c.cur, hashes)
		if (p.Alert != "") != c.alert || len(p.Send) != len(c.send) {
			t.Errorf("%s: %+v, want send %v alert %v", c.name, p, c.send, c.alert)
			continue
		}
		for i := range c.send {
			if p.Send[i] != c.send[i] {
				t.Errorf("%s: send %v, want %v", c.name, p.Send, c.send)
			}
		}
		if p.Alert != "" && len(p.Send) != 0 {
			t.Errorf("%s: an alert must not also push", c.name)
		}
	}
}

// ---- security events ----

func TestSecurityEventsStoreAndAlert(t *testing.T) {
	s, ts, b := newTestServer(t)
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab", "uses": 1}, &tok)
	agent := dialAgent(t, wsURL(ts), http.Header{"X-Enroll-Token": []string{tok.Token}})
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(agent.id) })

	send := func(f map[string]string, msg string) {
		agent.send(protocol.Envelope{T: protocol.TypeEvent, D: protocol.Must(protocol.Event{Kind: protocol.EventKindSecurity, Message: msg, Fields: f})})
	}
	send(map[string]string{"op": "script.run", "mode": "enforce", "executed": "false", "reason": "signature required: no signatures presented", "manifest": "m1"}, "refused")
	send(map[string]string{"op": "power", "mode": "audit", "executed": "true", "reason": "signature required: no signatures presented"}, "ran unsigned")

	waitFor(t, "alerts", func() bool {
		return openAlertTitled(t, s, agent.id, "script.run") != nil && openAlertTitled(t, s, agent.id, "power") != nil
	})
	enf := openAlertTitled(t, s, agent.id, "script.run")
	if enf.Severity != "critical" || enf.RuleKind != "security" || !strings.Contains(enf.Message, "signature required") || !strings.Contains(enf.Message, "m1") ||
		!strings.Contains(enf.Title, "refused") {
		t.Fatalf("enforce alert = %+v", enf)
	}
	aud := openAlertTitled(t, s, agent.id, "power")
	if aud.Severity != "warning" || !strings.Contains(aud.Title, "without a valid signature") {
		t.Fatalf("audit alert = %+v", aud)
	}

	// stored like every other event, so it is in the device's timeline
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM agent_events WHERE agent_id = ? AND kind = 'security'`, agent.id).Scan(&n)
	if n != 2 {
		t.Fatalf("%d security events stored, want 2", n)
	}

	// a repeat of the same refusal does not open a second alert
	send(map[string]string{"op": "script.run", "mode": "enforce", "executed": "false", "reason": "again"}, "refused")
	waitFor(t, "third event stored", func() bool {
		s.db.QueryRow(`SELECT COUNT(*) FROM agent_events WHERE agent_id = ? AND kind = 'security'`, agent.id).Scan(&n)
		return n == 3
	})
	list, _ := s.db.ListAlerts("open", agent.id, 50)
	if len(list) != 2 {
		t.Fatalf("%d open alerts, want 2: %+v", len(list), list)
	}

	// a maintenance window does not hide a security alert
	s.db.Exec(`UPDATE agents SET maintenance_until = ? WHERE id = ?`, now()+3600, agent.id)
	send(map[string]string{"op": "fs.delete", "mode": "enforce", "executed": "false", "reason": "x"}, "refused")
	waitFor(t, "alert during maintenance", func() bool { return openAlertTitled(t, s, agent.id, "fs.delete") != nil })

	// other event kinds are untouched: no alert without a matching rule
	agent.send(protocol.Envelope{T: protocol.TypeEvent, D: protocol.Must(protocol.Event{Kind: "service", Message: "x stopped"})})
	time.Sleep(200 * time.Millisecond)
	if openAlertTitled(t, s, agent.id, "service") != nil {
		t.Fatal("a non-security event raised a security alert")
	}
}
