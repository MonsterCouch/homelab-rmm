package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/winwebauthn"
)

const scriptBody = "$ErrorActionPreference = 'Stop'\nGet-Service | Where-Object Status -eq 'Running'\nRestart-Service Spooler\n"

func buildScriptManifest(t *testing.T, id string) []byte {
	t.Helper()
	payload, _ := json.Marshal(protocol.ScriptRun{
		RunID: "run1", Language: "powershell", Body: scriptBody, Timeout: 90,
		Env: map[string]string{"ZED": "last", "ALPHA": "first"},
	})
	now := time.Now().Unix()
	raw, err := actionauth.BuildManifest(actionauth.Manifest{
		V: 1, Kind: actionauth.KindAction, ID: id, Org: "org_default",
		Targets: []string{"agent-1", "agent-2"}, Op: protocol.ReqScriptRun, Payload: payload,
		Nonce: "nonce-" + id, IAT: now, Exp: now + 600, Issuer: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type fakeServer struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	entries map[string]map[string]any
	order   []string
	signs   []string // ids posted to, in order
	posted  map[string]protocol.Assertion
	failID  string // sign answers 400 for this id
	needTOT bool
}

func newFakeServer(t *testing.T) *fakeServer {
	f := &fakeServer{t: t, entries: map[string]map[string]any{}, posted: map[string]protocol.Assertion{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Requested-With") == "" {
			http.Error(w, `{"error":"missing X-Requested-With header"}`, 403)
			return
		}
		var in struct{ Username, Password, Code string }
		json.NewDecoder(r.Body).Decode(&in)
		if in.Password != "pw" {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"invalid credentials"}`))
			return
		}
		if f.needTOT && in.Code == "" {
			w.Write([]byte(`{"needs_totp":true}`))
			return
		}
		if f.needTOT && in.Code != "123456" {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"invalid credentials"}`))
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "rmm_session", Value: "tok-" + in.Username, Path: "/", MaxAge: 3600})
		w.Write([]byte(`{"ok":true}`))
	})
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if c, err := r.Cookie("rmm_session"); err != nil || c.Value != "tok-bob" {
				w.WriteHeader(401)
				w.Write([]byte(`{"error":"unauthorized"}`))
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /api/approvals", authed(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		out := []map[string]any{}
		for _, id := range f.order {
			out = append(out, f.entries[id])
		}
		json.NewEncoder(w).Encode(out)
	}))
	mux.HandleFunc("GET /api/approvals/{id}", authed(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		e, ok := f.entries[r.PathValue("id")]
		if !ok {
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"no signing request with this id is waiting for your signature"}`))
			return
		}
		json.NewEncoder(w).Encode(e)
	}))
	mux.HandleFunc("POST /api/approvals/{id}/sign", authed(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		id := r.PathValue("id")
		var in struct {
			Assertion protocol.Assertion `json:"assertion"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		f.signs = append(f.signs, id)
		f.posted[id] = in.Assertion
		if id == f.failID {
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"assertion was made for a different document"}`))
			return
		}
		e := f.entries[id]
		if e["have"].(int)+1 < e["need"].(int) {
			w.WriteHeader(202)
			json.NewEncoder(w).Encode(map[string]any{"pending": true, "manifest_id": id, "have": e["have"].(int) + 1, "need": e["need"]})
			return
		}
		w.Write([]byte(`{"summary":"script run started on 2 devices"}`))
	}))
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServer) add(id string, raw []byte, have, need int, origins ...string) {
	if len(origins) == 0 {
		origins = []string{f.srv.URL}
	}
	f.entries[id] = map[string]any{
		"manifest_id": id, "manifest": base64.RawURLEncoding.EncodeToString(raw),
		"summary": "Run a script on 2 devices (server summary)", "have": have, "need": need,
		"issuer": "admin", "org": "org_default", "created_at": 1, "expires_at": 2,
		"target_names": map[string]string{"agent-1": "FRONT-DESK-PC"},
		"rp_id":        "rmm.example.com", "origins": origins,
		"allow_credentials": []string{base64.RawURLEncoding.EncodeToString([]byte("cred-bob"))},
		"user_verification": "required", "signers": []string{"admin"},
	}
	f.order = append(f.order, id)
}

type fakeSigner struct {
	calls []winwebauthn.Options
	err   error
}

func (s *fakeSigner) GetAssertion(_ context.Context, o winwebauthn.Options) (*winwebauthn.Assertion, error) {
	s.calls = append(s.calls, o)
	if s.err != nil {
		return nil, s.err
	}
	return &winwebauthn.Assertion{
		CredentialID:      []byte("cred-bob"),
		AuthenticatorData: bytes.Repeat([]byte{7}, 37),
		ClientDataJSON:    winwebauthn.ClientDataJSON(o.Challenge, o.Origin),
		Signature:         []byte("sig"),
	}, nil
}

type harness struct {
	app     *app
	out     *bytes.Buffer
	errw    *bytes.Buffer
	signer  *fakeSigner
	server  *fakeServer
	prompts []string
}

func newHarness(t *testing.T, stdin string) *harness {
	f := newFakeServer(t)
	h := &harness{out: &bytes.Buffer{}, errw: &bytes.Buffer{}, signer: &fakeSigner{}, server: f}
	secrets := []string{"pw", "123456"}
	h.app = &app{
		out: h.out, errw: h.errw, in: bufio.NewReader(strings.NewReader(stdin)),
		getenv: func(string) string { return "" }, signer: h.signer, client: f.srv.Client(),
		sessionFile: filepath.Join(t.TempDir(), "homelab-rmm", "signer.json"),
		now:         time.Now,
		readPassword: func(prompt string) (string, error) {
			h.prompts = append(h.prompts, prompt)
			s := secrets[0]
			secrets = append(secrets[1:], "")
			return s, nil
		},
		selftest: func() (string, error) { return "WebAuthn API version: 9", nil },
	}
	return h
}

func (h *harness) run(args ...string) int {
	return h.app.run(context.Background(), args)
}

func (h *harness) login(t *testing.T) {
	t.Helper()
	if code := h.run("login", "--server", h.server.srv.URL, "--user", "bob"); code != 0 {
		t.Fatalf("login exit %d: %s", code, h.errw.String())
	}
	h.out.Reset()
	h.errw.Reset()
}

func TestLoginPromptsForTOTPAndKeepsSession(t *testing.T) {
	h := newHarness(t, "")
	h.server.needTOT = true
	if code := h.run("login", "--server", h.server.srv.URL+"/", "--user", "bob"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errw.String())
	}
	raw, err := os.ReadFile(h.app.sessionFile)
	if err != nil {
		t.Fatal(err)
	}
	var s session
	json.Unmarshal(raw, &s)
	if s.Cookie != "tok-bob" || s.Server != h.server.srv.URL || s.Expires <= time.Now().Unix() {
		t.Fatalf("session = %+v", s)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(h.app.sessionFile); fi.Mode().Perm() != 0o600 {
			t.Fatalf("session file mode %v, want 0600", fi.Mode().Perm())
		}
	}
	if len(h.prompts) != 2 || !strings.Contains(h.prompts[1], "Authenticator code") {
		t.Fatalf("prompts = %q", h.prompts)
	}
	// logout deletes the file
	if code := h.run("logout"); code != 0 {
		t.Fatalf("logout exit %d: %s", code, h.errw.String())
	}
	if _, err := os.Stat(h.app.sessionFile); !os.IsNotExist(err) {
		t.Fatalf("session file survived logout: %v", err)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	h := newHarness(t, "")
	h.app.readPassword = func(string) (string, error) { return "nope", nil }
	if code := h.run("login", "--server", h.server.srv.URL, "--user", "bob"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.errw.String(), "invalid credentials") {
		t.Fatalf("stderr: %s", h.errw.String())
	}
	if _, err := os.Stat(h.app.sessionFile); err == nil {
		t.Fatal("a session was saved after a failed login")
	}
}

func TestListRequiresLoginThenShowsEntries(t *testing.T) {
	h := newHarness(t, "")
	h.server.add("m1", buildScriptManifest(t, "m1"), 1, 2)
	if code := h.run("list", "--server", h.server.srv.URL); code != 1 || !strings.Contains(h.errw.String(), "not signed in") {
		t.Fatalf("exit %d: %s", code, h.errw.String())
	}
	h.login(t)
	if code := h.run("list"); code != 0 { // server comes from the saved session
		t.Fatalf("exit %d: %s", code, h.errw.String())
	}
	out := h.out.String()
	for _, want := range []string{"m1", "script.run", "1 of 2 signed", "by admin"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output lacks %q:\n%s", want, out)
		}
	}
}

func TestSessionForAnotherServerIsNotSent(t *testing.T) {
	h := newHarness(t, "")
	h.login(t)
	if code := h.run("list", "--server", "https://other.example.com"); code != 1 || !strings.Contains(h.errw.String(), "saved session is for") {
		t.Fatalf("exit %d: %s", code, h.errw.String())
	}
}

func TestShowRendersScriptBodyInFull(t *testing.T) {
	h := newHarness(t, "")
	raw := buildScriptManifest(t, "m1")
	h.server.add("m1", raw, 1, 2)
	h.login(t)
	if code := h.run("show", "m1", "--server", h.server.srv.URL); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errw.String())
	}
	out := h.out.String()
	for _, line := range strings.Split(strings.TrimRight(scriptBody, "\n"), "\n") {
		if !strings.Contains(out, "| "+line) {
			t.Errorf("body line %q missing:\n%s", line, out)
		}
	}
	for _, want := range []string{
		"Kind          action", "Organization  org_default", "Issuer        admin",
		"Language      powershell", "Timeout       90 seconds",
		"ALPHA=first", "ZED=last", "agent-1  \"FRONT-DESK-PC\" (name from the server)",
		"  agent-2\n", "Server's summary (the server's words", "Run a script on 2 devices (server summary)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "ALPHA=") > strings.Index(out, "ZED=") {
		t.Error("environment is not sorted")
	}
	if strings.Index(out, "Server's summary") < strings.Index(out, "| Restart-Service") {
		t.Error("the server's summary must come last")
	}
}

func TestShowNeutralizesTerminalEscapes(t *testing.T) {
	h := newHarness(t, "")
	payload, _ := json.Marshal(protocol.ScriptRun{RunID: "r", Language: "sh", Body: "echo hi\x1b[2J\x1b[1Fecho safe", Timeout: 5})
	now := time.Now().Unix()
	raw, err := actionauth.BuildManifest(actionauth.Manifest{V: 1, Kind: actionauth.KindAction, ID: "m1", Org: "o",
		Targets: []string{"a"}, Op: protocol.ReqScriptRun, Payload: payload, Nonce: "n", IAT: now, Exp: now + 60})
	if err != nil {
		t.Fatal(err)
	}
	h.server.add("m1", raw, 0, 1)
	h.login(t)
	h.run("show", "--server", h.server.srv.URL, "m1")
	if strings.ContainsRune(h.out.String(), 0x1b) || !strings.Contains(h.out.String(), `\x1b[2J`) {
		t.Fatalf("escape sequence reached the terminal:\n%q", h.out.String())
	}
}

func TestShowRefusesManifestUnderAnotherID(t *testing.T) {
	h := newHarness(t, "")
	h.server.add("m-other", buildScriptManifest(t, "m1"), 0, 1)
	h.login(t)
	if code := h.run("show", "--server", h.server.srv.URL, "m-other"); code != 1 || !strings.Contains(h.errw.String(), "refusing") {
		t.Fatalf("exit %d: %s", code, h.errw.String())
	}
}

func TestSignPostsAssertionForManifestBytes(t *testing.T) {
	h := newHarness(t, "y\n")
	raw := buildScriptManifest(t, "m1")
	h.server.add("m1", raw, 0, 1)
	h.login(t)
	if code := h.run("sign", "--server", h.server.srv.URL, "m1"); code != 0 {
		t.Fatalf("exit %d: %s\n%s", code, h.errw.String(), h.out.String())
	}
	if len(h.signer.calls) != 1 {
		t.Fatalf("signer called %d times", len(h.signer.calls))
	}
	o := h.signer.calls[0]
	sum := sha256.Sum256(raw)
	if !bytes.Equal(o.Challenge, sum[:]) || o.RPID != "rmm.example.com" || o.Origin != h.server.srv.URL ||
		o.UserVerification != "required" || len(o.AllowCredentialIDs) != 1 || string(o.AllowCredentialIDs[0]) != "cred-bob" {
		t.Fatalf("options = %+v", o)
	}
	a := h.server.posted["m1"]
	cd, err := base64.RawURLEncoding.DecodeString(a.CD)
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Type, Challenge, Origin string
		CrossOrigin             bool
	}
	json.Unmarshal(cd, &c)
	if c.Type != "webauthn.get" || c.Challenge != base64.RawURLEncoding.EncodeToString(sum[:]) || c.Origin != h.server.srv.URL || c.CrossOrigin {
		t.Fatalf("clientDataJSON = %s", cd)
	}
	// The same check the server makes: the challenge verifies against the bytes.
	chal, _ := base64.RawURLEncoding.DecodeString(c.Challenge)
	if !bytes.Equal(chal, actionauth.Challenge(raw)) {
		t.Fatal("challenge does not match actionauth.Challenge of the manifest bytes")
	}
	if a.Cred != base64.RawURLEncoding.EncodeToString([]byte("cred-bob")) || a.Sig != base64.RawURLEncoding.EncodeToString([]byte("sig")) {
		t.Fatalf("assertion = %+v", a)
	}
	if !strings.Contains(h.out.String(), "script run started on 2 devices") {
		t.Fatalf("response summary not printed:\n%s", h.out.String())
	}
}

func TestSignPartialShowsHaveAndNeed(t *testing.T) {
	h := newHarness(t, "")
	h.server.add("m1", buildScriptManifest(t, "m1"), 0, 3)
	h.login(t)
	if code := h.run("sign", "--yes", "--server", h.server.srv.URL, "m1"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errw.String())
	}
	if !strings.Contains(h.out.String(), "1 of 3 signatures are in") {
		t.Fatalf("output:\n%s", h.out.String())
	}
}

func TestSignDeclinedSendsNothing(t *testing.T) {
	h := newHarness(t, "\n")
	h.server.add("m1", buildScriptManifest(t, "m1"), 0, 1)
	h.login(t)
	if code := h.run("sign", "--server", h.server.srv.URL, "m1"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errw.String())
	}
	if len(h.signer.calls) != 0 || len(h.server.signs) != 0 || !strings.Contains(h.out.String(), "Not signed.") {
		t.Fatalf("declined sign still acted: calls=%d posts=%d", len(h.signer.calls), len(h.server.signs))
	}
}

func TestSignRefusesUntrustedOrigin(t *testing.T) {
	h := newHarness(t, "y\n")
	h.server.add("m1", buildScriptManifest(t, "m1"), 0, 1, "https://rmm.example.com")
	h.login(t)
	code := h.run("sign", "--yes", "--server", h.server.srv.URL, "m1")
	if code != 1 || !strings.Contains(h.errw.String(), "not one the organization's trust bundle accepts") {
		t.Fatalf("exit %d: %s", code, h.errw.String())
	}
	if len(h.signer.calls) != 0 || len(h.server.signs) != 0 {
		t.Fatal("signed despite an untrusted origin")
	}
}

func TestSignAllStopsOnFirstFailure(t *testing.T) {
	h := newHarness(t, "")
	for _, id := range []string{"m1", "m2", "m3"} {
		h.server.add(id, buildScriptManifest(t, id), 0, 1)
	}
	h.server.failID = "m2"
	h.login(t)
	code := h.run("sign", "--all", "--yes", "--server", h.server.srv.URL)
	if code != 1 {
		t.Fatalf("exit %d, want 1; stderr: %s", code, h.errw.String())
	}
	if got := strings.Join(h.server.signs, ","); got != "m1,m2" {
		t.Fatalf("posted to %s, want m1,m2 (m3 must not be tried)", got)
	}
	if len(h.signer.calls) != 2 || !strings.Contains(h.errw.String(), "m2") {
		t.Fatalf("signer calls %d, stderr %s", len(h.signer.calls), h.errw.String())
	}
}

func TestSignAllWalksEveryEntry(t *testing.T) {
	h := newHarness(t, "")
	for _, id := range []string{"m1", "m2"} {
		h.server.add(id, buildScriptManifest(t, id), 0, 1)
	}
	h.login(t)
	if code := h.run("sign", "--all", "--yes", "--server", h.server.srv.URL); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errw.String())
	}
	if got := strings.Join(h.server.signs, ","); got != "m1,m2" || !strings.Contains(h.out.String(), "Signed 2 of 2") {
		t.Fatalf("posted %s\n%s", got, h.out.String())
	}
}

func TestSignCancelledAtPrompt(t *testing.T) {
	h := newHarness(t, "")
	h.signer.err = winwebauthn.ErrCancelled
	h.server.add("m1", buildScriptManifest(t, "m1"), 0, 1)
	h.login(t)
	if code := h.run("sign", "--yes", "--server", h.server.srv.URL, "m1"); code != 1 || !strings.Contains(h.errw.String(), "cancelled") {
		t.Fatalf("exit %d: %s", code, h.errw.String())
	}
	if len(h.server.signs) != 0 {
		t.Fatal("posted after a cancel")
	}
}

func TestSignNeedsWindowsElsewhere(t *testing.T) {
	h := newHarness(t, "")
	h.app.needWindows = true
	if code := h.run("sign", "--server", h.server.srv.URL, "m1"); code != 1 || !strings.Contains(h.errw.String(), "signing needs Windows") {
		t.Fatalf("exit %d: %s", code, h.errw.String())
	}
}

func TestSignUsage(t *testing.T) {
	h := newHarness(t, "")
	if code := h.run("sign", "--server", h.server.srv.URL); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if code := h.run("nonsense"); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
}

func TestSelftestPrints(t *testing.T) {
	h := newHarness(t, "")
	if code := h.run("selftest"); code != 0 || !strings.Contains(h.out.String(), "API version") {
		t.Fatalf("exit %d: %s%s", code, h.out.String(), h.errw.String())
	}
}

// TestRealSelftest runs the real WebAuthn probe, which shows no UI. Elsewhere
// it must say the tool needs Windows.
func TestRealSelftest(t *testing.T) {
	s, err := realSelftest()
	if runtime.GOOS != "windows" {
		if err == nil || !strings.Contains(err.Error(), "needs Windows") {
			t.Fatalf("got %q, %v", s, err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "WebAuthn API version:") || !strings.Contains(s, "Platform authenticator") {
		t.Fatalf("selftest printed %q", s)
	}
}
