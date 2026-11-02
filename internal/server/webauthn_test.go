package server

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/actionauth/authtest"
)

// trustTestServer is a test server whose relying party is the one the
// software authenticator signs for (authtest.RPID / authtest.Origin), the way
// a deployment would pin it with RMM_WEBAUTHN_RP_ID and RMM_WEBAUTHN_ORIGINS.
func trustTestServer(t *testing.T) (*Server, *browser) {
	t.Helper()
	s, _, b := newTestServerWith(t, Config{WebAuthnRPID: authtest.RPID, WebAuthnOrigins: []string{authtest.Origin}})
	return s, b
}

// regParts are the pieces of a registration response, each of which a test can
// corrupt before it is assembled into the finish body.
type regParts struct {
	typ       string
	origin    string
	rp        string
	flags     byte
	cross     bool
	challenge []byte
	alg       int
	pub       string
	id        string
	name      string
}

func newRegParts(k *authtest.Key, challenge []byte) regParts {
	c := k.Credential()
	return regParts{typ: "webauthn.create", origin: authtest.Origin, rp: authtest.RPID, flags: 0x41,
		challenge: challenge, alg: c.Alg, pub: c.Pub, id: c.ID, name: "test key"}
}

func (p regParts) body() map[string]any {
	cd, _ := json.Marshal(map[string]any{
		"type": p.typ, "challenge": actionauth.EncodeB64(p.challenge), "origin": p.origin, "crossOrigin": p.cross,
	})
	h := sha256.Sum256([]byte(p.rp))
	// rpIdHash | flags | signCount; the attested credential data that follows
	// in a real response is never parsed by the server.
	ad := binary.BigEndian.AppendUint32(append(h[:], p.flags), 0)
	return map[string]any{
		"name": p.name, "id": p.id, "clientDataJSON": actionauth.EncodeB64(cd), "authenticatorData": actionauth.EncodeB64(ad),
		"publicKey": p.pub, "publicKeyAlgorithm": p.alg,
	}
}

// beginReg starts a registration and returns the challenge the server issued.
func beginReg(t *testing.T, b *browser) []byte {
	t.Helper()
	var opts struct {
		Challenge string `json:"challenge"`
	}
	b.mustJSON("POST", "/api/webauthn/register/begin", nil, &opts)
	ch, err := b64dec(opts.Challenge)
	if err != nil || len(ch) != 32 {
		t.Fatalf("challenge %q: %v", opts.Challenge, err)
	}
	return ch
}

// registerKey runs a full, valid registration of k as the browser's user.
func registerKey(t *testing.T, b *browser, k *authtest.Key) {
	t.Helper()
	p := newRegParts(k, beginReg(t, b))
	b.mustJSON("POST", "/api/webauthn/register/finish", p.body(), nil)
}

func credCount(t *testing.T, s *Server) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM webauthn_credentials`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestWebAuthnRegistrationOptions(t *testing.T) {
	s, b := trustTestServer(t)
	var opts map[string]any
	b.mustJSON("POST", "/api/webauthn/register/begin", nil, &opts)
	rp := opts["rp"].(map[string]any)
	if rp["id"] != authtest.RPID || rp["name"] != "Homelab RMM" {
		t.Fatalf("rp = %v", rp)
	}
	if opts["attestation"] != "none" || opts["timeout"].(float64) != 60000 {
		t.Fatalf("options = %v", opts)
	}
	algs := []float64{}
	for _, a := range opts["pubKeyCredParams"].([]any) {
		algs = append(algs, a.(map[string]any)["alg"].(float64))
	}
	if len(algs) != 3 || algs[0] != -7 || algs[1] != -8 || algs[2] != -257 {
		t.Fatalf("algs = %v", algs)
	}
	sel := opts["authenticatorSelection"].(map[string]any)
	if sel["residentKey"] != "preferred" || sel["userVerification"] != "preferred" {
		t.Fatalf("selection = %v", sel)
	}
	user := opts["user"].(map[string]any)
	if user["name"] != "admin" || user["id"] == "" {
		t.Fatalf("user = %v", user)
	}
	// the user handle is stable across registrations
	var again map[string]any
	b.mustJSON("POST", "/api/webauthn/register/begin", nil, &again)
	if again["user"].(map[string]any)["id"] != user["id"] {
		t.Fatal("user handle changed between registrations")
	}
	if opts["challenge"] == again["challenge"] {
		t.Fatal("challenge was reused")
	}

	// a registered key is excluded from the next registration
	k := authtest.NewKey("admin", actionauth.AlgES256)
	registerKey(t, b, k)
	var third map[string]any
	b.mustJSON("POST", "/api/webauthn/register/begin", nil, &third)
	ex := third["excludeCredentials"].([]any)
	if len(ex) != 1 || ex[0].(map[string]any)["id"] != k.Credential().ID {
		t.Fatalf("excludeCredentials = %v", ex)
	}
	_ = s
}

func TestWebAuthnRefusesAnIPAddress(t *testing.T) {
	// no override and an address as the public URL: browsers refuse an IP as an
	// RP ID, so say so up front instead of failing in the authenticator
	_, _, b := newTestServerWith(t, Config{PublicURL: "https://192.168.1.10:8443"})
	st, body := b.do("POST", "/api/webauthn/register/begin", nil)
	if st != 400 || !strings.Contains(string(body), "DNS name") || !strings.Contains(string(body), "RMM_WEBAUTHN_RP_ID") {
		t.Fatalf("begin on an IP = %d %s", st, body)
	}
	// and an explicit RP ID makes it work
	_, _, b2 := newTestServerWith(t, Config{PublicURL: "https://192.168.1.10:8443", WebAuthnRPID: "rmm.lan"})
	if st, body := b2.do("POST", "/api/webauthn/register/begin", nil); st != 200 {
		t.Fatalf("begin with an RP override = %d %s", st, body)
	}
}

func TestWebAuthnRPDerivedFromPublicURL(t *testing.T) {
	for _, c := range []struct{ url, rp, origin string }{
		{"https://rmm.example.com", "rmm.example.com", "https://rmm.example.com"},
		{"https://RMM.Example.com:443/", "rmm.example.com", "https://rmm.example.com"},
		{"https://rmm.lan:8443", "rmm.lan", "https://rmm.lan:8443"},
	} {
		s, _, _ := newTestServerWith(t, Config{PublicURL: c.url})
		rp, origins, err := s.webauthnRP()
		if err != nil || rp != c.rp || len(origins) != 1 || origins[0] != c.origin {
			t.Errorf("%s -> %q %v %v, want %q %q", c.url, rp, origins, err, c.rp, c.origin)
		}
	}
	// origins can be pinned separately from the RP ID
	s, _, _ := newTestServerWith(t, Config{PublicURL: "https://rmm.lan:8443", WebAuthnOrigins: []string{"https://a.lan:8443", "https://b.lan"}})
	if _, origins, err := s.webauthnRP(); err != nil || len(origins) != 2 || origins[1] != "https://b.lan" {
		t.Fatalf("origins = %v %v", origins, err)
	}
}

func TestWebAuthnRegistrationAlgorithms(t *testing.T) {
	s, b := trustTestServer(t)
	for _, alg := range []int{actionauth.AlgES256, actionauth.AlgEdDSA, actionauth.AlgRS256} {
		registerKey(t, b, authtest.NewKey("admin", alg))
	}
	if n := credCount(t, s); n != 3 {
		t.Fatalf("stored %d credentials, want 3", n)
	}
	var list []Credential
	b.mustJSON("GET", "/api/webauthn/credentials", nil, &list)
	if len(list) != 3 || list[0].Owner != "admin" || list[0].Name != "test key" || list[0].InBundle {
		t.Fatalf("list = %+v", list)
	}
}

func TestWebAuthnRegistrationRejections(t *testing.T) {
	s, b := trustTestServer(t)
	other := authtest.NewKey("admin", actionauth.AlgEdDSA)

	cases := []struct {
		name string
		tune func(p *regParts)
		want string
	}{
		{"wrong type", func(p *regParts) { p.typ = "webauthn.get" }, "webauthn.create"},
		{"wrong challenge", func(p *regParts) { p.challenge = make([]byte, 32) }, "different challenge"},
		{"wrong origin", func(p *regParts) { p.origin = "https://evil.example" }, "origin"},
		{"cross origin", func(p *regParts) { p.cross = true }, "cross-origin"},
		{"wrong rp hash", func(p *regParts) { p.rp = "evil.example" }, "relying party"},
		{"no user presence", func(p *regParts) { p.flags = 0x40 }, "presence"},
		{"alg does not match the key", func(p *regParts) { p.alg = actionauth.AlgEdDSA }, "EdDSA needs"},
		{"unsupported alg", func(p *regParts) { p.alg = -999 }, "unsupported"},
		{"key is not SPKI", func(p *regParts) { p.pub = actionauth.EncodeB64([]byte("not a key")) }, "public key"},
		{"key and alg are ed25519 vs es256", func(p *regParts) { p.pub = other.Credential().Pub }, "ES256 needs"},
		{"empty id", func(p *regParts) { p.id = "" }, "credential id"},
	}
	for _, c := range cases {
		k := authtest.NewKey("admin", actionauth.AlgES256)
		p := newRegParts(k, beginReg(t, b))
		c.tune(&p)
		st, body := b.do("POST", "/api/webauthn/register/finish", p.body())
		if st != 400 || !strings.Contains(string(body), c.want) {
			t.Errorf("%s: %d %s, want 400 containing %q", c.name, st, body, c.want)
		}
		if n := credCount(t, s); n != 0 {
			t.Fatalf("%s: a credential was stored", c.name)
		}
	}

	// a refused attempt burns the challenge: it cannot be ground against
	k := authtest.NewKey("admin", actionauth.AlgES256)
	ch := beginReg(t, b)
	bad := newRegParts(k, ch)
	bad.origin = "https://evil.example"
	b.do("POST", "/api/webauthn/register/finish", bad.body())
	if st, body := b.do("POST", "/api/webauthn/register/finish", newRegParts(k, ch).body()); st != 400 || !strings.Contains(string(body), "no registration is in progress") {
		t.Fatalf("retry after a failed attempt = %d %s", st, body)
	}

	// replay: a good response works once, then the challenge is gone
	ch = beginReg(t, b)
	good := newRegParts(k, ch).body()
	if st, body := b.do("POST", "/api/webauthn/register/finish", good); st != 201 {
		t.Fatalf("good registration = %d %s", st, body)
	}
	if st, body := b.do("POST", "/api/webauthn/register/finish", good); st != 400 || !strings.Contains(string(body), "no registration is in progress") {
		t.Fatalf("replay = %d %s", st, body)
	}

	// the same key cannot be registered twice
	ch = beginReg(t, b)
	if st, body := b.do("POST", "/api/webauthn/register/finish", newRegParts(k, ch).body()); st != 409 {
		t.Fatalf("duplicate credential = %d %s", st, body)
	}

	// an expired challenge is refused
	ch = beginReg(t, b)
	s.regs.mu.Lock()
	for id, p := range s.regs.pending {
		p.expires = time.Now().Add(-time.Second)
		s.regs.pending[id] = p
	}
	s.regs.mu.Unlock()
	k2 := authtest.NewKey("admin", actionauth.AlgES256)
	if st, body := b.do("POST", "/api/webauthn/register/finish", newRegParts(k2, ch).body()); st != 400 {
		t.Fatalf("expired challenge = %d %s", st, body)
	}

	// finish with nothing pending
	if st, _ := b.do("POST", "/api/webauthn/register/finish", newRegParts(k2, make([]byte, 32)).body()); st != 400 {
		t.Fatalf("finish with no begin = %d", st)
	}
}

func TestWebAuthnCredentialOwnership(t *testing.T) {
	s, ts, admin := newTestServerWith(t, Config{WebAuthnRPID: authtest.RPID, WebAuthnOrigins: []string{authtest.Origin}})
	admin.mustJSON("POST", "/api/users", map[string]string{"username": "bob", "password": "password123", "role": "tech"}, nil)
	bob := newBrowser(t, ts)
	bob.mustJSON("POST", "/api/auth/login", map[string]string{"username": "bob", "password": "password123"}, nil)

	ka := authtest.NewKey("admin", actionauth.AlgES256)
	kb := authtest.NewKey("bob", actionauth.AlgEdDSA)
	registerKey(t, admin, ka)
	registerKey(t, bob, kb)

	var mine, all []Credential
	bob.mustJSON("GET", "/api/webauthn/credentials", nil, &mine)
	admin.mustJSON("GET", "/api/webauthn/credentials", nil, &all)
	if len(mine) != 1 || mine[0].Owner != "bob" {
		t.Fatalf("bob sees %+v", mine)
	}
	if len(all) != 2 {
		t.Fatalf("admin sees %+v", all)
	}

	// bob may not touch admin's key, and cannot tell it exists
	if st, _ := bob.do("DELETE", "/api/webauthn/credentials/"+ka.Credential().ID, nil); st != 404 {
		t.Fatalf("bob deleting admin's key = %d", st)
	}
	if n := credCount(t, s); n != 2 {
		t.Fatalf("%d credentials left", n)
	}
	// an admin may remove anyone's, an owner their own
	if st, _ := admin.do("DELETE", "/api/webauthn/credentials/"+kb.Credential().ID, nil); st != 200 {
		t.Fatalf("admin deleting bob's key = %d", st)
	}
	if st, _ := admin.do("DELETE", "/api/webauthn/credentials/"+ka.Credential().ID, nil); st != 200 {
		t.Fatalf("owner deleting own key = %d", st)
	}
	if st, _ := admin.do("DELETE", "/api/webauthn/credentials/"+ka.Credential().ID, nil); st != 404 {
		t.Fatalf("deleting a missing key = %d", st)
	}
	// anonymous
	anon := newBrowser(t, ts)
	if st, _ := anon.do("POST", "/api/webauthn/register/begin", nil); st != 401 {
		t.Fatalf("anonymous begin = %d", st)
	}
}
