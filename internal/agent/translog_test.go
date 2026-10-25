package agent

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/actionauth/authtest"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/translog"
)

// logBundle is kit.bundle with a pinned log key and the log-proof policy.
func (k trustKit) logBundle(mode, logKey string, require bool) []byte {
	raw := authtest.Bundle(authtest.BundleSpec{
		Keys: []*authtest.Key{k.key}, Recovery: []*authtest.RecoveryKey{k.rec},
		Policy: actionauth.Policy{Mode: mode, RequireLogProof: require},
	})
	if logKey == "" {
		return raw
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		panic(err)
	}
	m["log_key"] = logKey
	out, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return out
}

// testLog is a server-side log on memory storage, as the hub would hold it.
type testLog struct {
	t   *testing.T
	log *translog.Log
}

func newTestLog(t *testing.T) *testLog {
	t.Helper()
	l, err := translog.Open(translog.NewMemStorage(), filepath.Join(t.TempDir(), "log.key"))
	if err != nil {
		t.Fatal(err)
	}
	return &testLog{t: t, log: l}
}

// filler appends n leaves that no device ever sees.
func (l *testLog) filler(n int) {
	l.t.Helper()
	for i := 0; i < n; i++ {
		size, _ := l.size()
		if _, err := l.log.Append("audit", []byte(fmt.Sprintf(`{"kind":"audit","n":%d}`, size))); err != nil {
			l.t.Fatal(err)
		}
	}
}

func (l *testLog) size() (int64, error) {
	tree, _, err := l.log.Head()
	return tree.N, err
}

// release signs an action, logs its leaf and returns the auth (without L) and
// the leaf index, as signing.go does at release.
func (l *testLog) release(kit trustKit, marker string) (*protocol.ActionAuth, int64) {
	l.t.Helper()
	auth := kit.signedAction(protocol.ReqScriptRun, scriptPayload(marker, "x"))
	leaf, err := actionauth.ManifestLeaf(auth)
	if err != nil {
		l.t.Fatal(err)
	}
	idx, err := l.log.Append("manifest", leaf)
	if err != nil {
		l.t.Fatal(err)
	}
	return auth, idx
}

// prove is what the hub's send adds: the current head, the inclusion proof at
// it and, when from is non-zero, a consistency proof from that size.
func (l *testLog) prove(idx, from int64) *protocol.LogProof {
	l.t.Helper()
	tree, note, err := l.log.Head()
	if err != nil {
		l.t.Fatal(err)
	}
	inc, err := l.log.ProveInclusion(idx, tree.N)
	if err != nil {
		l.t.Fatal(err)
	}
	lp := &protocol.LogProof{Head: base64.StdEncoding.EncodeToString(note), Index: idx, Proof: translog.EncodeProof(inc)}
	if from > 0 && from < tree.N {
		cp, err := l.log.ProveConsistency(from, tree.N)
		if err != nil {
			l.t.Fatal(err)
		}
		lp.From, lp.Consistency = from, translog.EncodeProof(cp)
	}
	return lp
}

func storedHead(t *testing.T, dir string) logHead {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "log_head.json"))
	if err != nil {
		t.Fatalf("log_head.json was not written: %v", err)
	}
	var h logHead
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

// sendSigned dispatches a script.run carrying auth and returns the reply, the
// security events seen before it and the script output.
func (h *trustHarness) sendSigned(id string, auth *protocol.ActionAuth) (protocol.Envelope, []protocol.Event, string) {
	h.t.Helper()
	h.send(protocol.Envelope{T: protocol.ReqScriptRun, ID: id, D: scriptPayload("ENVELOPE", "r-"+id), A: auth})
	return h.reply(id)
}

func TestLogProofAcceptedAndPersisted(t *testing.T) {
	dir := t.TempDir()
	kit, lg := newKit(), newTestLog(t)
	writeTrust(t, dir, kit.logBundle(actionauth.ModeEnforce, lg.log.VerifierKey(), true))
	h := newTrustHarness(t, dir)

	lg.filler(3)
	a1, i1 := lg.release(kit, "ONE")
	a1.L = lg.prove(i1, 0)
	rep, evs, out := h.sendSigned("l1", a1)
	if rep.Err != "" || len(evs) != 0 || !strings.Contains(out+string(rep.D), "ONE") {
		t.Fatalf("a valid proof must be accepted: err %q events %v out %q", rep.Err, evs, out)
	}
	if rep.Log != i1+1 {
		t.Fatalf("the reply must carry the size the device holds (%d), got %d", i1+1, rep.Log)
	}
	if hd := storedHead(t, dir); hd.Size != i1+1 || hd.Note != a1.L.Head {
		t.Fatalf("head not persisted: %+v", hd)
	}

	lg.filler(2)
	a2, i2 := lg.release(kit, "TWO")
	a2.L = lg.prove(i2, i1+1)
	if a2.L.From != i1+1 || len(a2.L.Consistency) == 0 {
		t.Fatalf("test setup: expected a consistency proof from %d", i1+1)
	}
	rep, evs, _ = h.sendSigned("l2", a2)
	if rep.Err != "" || len(evs) != 0 || rep.Log != i2+1 {
		t.Fatalf("a consistent newer head must be accepted: err %q events %v log %d", rep.Err, evs, rep.Log)
	}
	if hd := storedHead(t, dir); hd.Size != i2+1 {
		t.Fatalf("newer head not persisted: %+v", hd)
	}

	// A restart keeps the head and advertises it in hello.
	h.restart()
	if got := h.a.hello().LogSize; got != i2+1 {
		t.Fatalf("hello log_size = %d, want %d", got, i2+1)
	}
	// The same head size with the same hash is fine (the manifest is already inside it).
	a3, i3 := lg.release(kit, "THREE")
	a3.L = lg.prove(i3, i2+1)
	if rep, _, _ = h.sendSigned("l3", a3); rep.Err != "" {
		t.Fatalf("after a restart: %q", rep.Err)
	}
}

func TestLogProofSameSizeRequiresSameHash(t *testing.T) {
	dir := t.TempDir()
	kit, lg := newKit(), newTestLog(t)
	writeTrust(t, dir, kit.logBundle(actionauth.ModeEnforce, lg.log.VerifierKey(), false))
	h := newTrustHarness(t, dir)

	// Three manifests are logged, then all are presented against the same head.
	a1, i1 := lg.release(kit, "A")
	a2, i2 := lg.release(kit, "B")
	a3, i3 := lg.release(kit, "C")
	a1.L, a2.L, a3.L = lg.prove(i1, 0), lg.prove(i2, 0), lg.prove(i3, 0)
	if rep, _, _ := h.sendSigned("s1", a1); rep.Err != "" {
		t.Fatal(rep.Err)
	}
	if rep, evs, _ := h.sendSigned("s2", a2); rep.Err != "" || len(evs) != 0 {
		t.Fatalf("an equal head must be accepted: %q %v", rep.Err, evs)
	}

	// The device holds a different hash for the same size (a fork, simulated by
	// editing the stored head): refused even though the proof itself is valid.
	hd := storedHead(t, dir)
	hd.Hash = strings.Repeat("A", 43) + "="
	raw, _ := json.Marshal(hd)
	if err := os.WriteFile(filepath.Join(dir, "log_head.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	h.restart()
	if rep, evs, _ := h.sendSigned("s3", a3); !strings.Contains(rep.Err, "different log head for size") || len(evs) != 1 {
		t.Fatalf("a same-size head with another hash must be refused, got %q %v", rep.Err, evs)
	}
}

func TestLogProofRefusedOrReported(t *testing.T) {
	type tc struct {
		name  string
		reqLP bool   // require_log_proof in the bundle
		want  string // substring of the reason
		// build returns the auth to send once the device holds a head of size s.
		build func(t *testing.T, h *trustHarness, lg *testLog, kit trustKit, s int64) *protocol.ActionAuth
	}
	cases := []tc{
		{name: "wrong From", want: "consistency proof starts at size", build: func(t *testing.T, h *trustHarness, lg *testLog, kit trustKit, s int64) *protocol.ActionAuth {
			lg.filler(3)
			a, i := lg.release(kit, "LPMARK")
			a.L = lg.prove(i, s)
			a.L.From = s + 1
			return a
		}},
		{name: "no consistency proof", want: "consistency proof starts at size", build: func(t *testing.T, h *trustHarness, lg *testLog, kit trustKit, s int64) *protocol.ActionAuth {
			lg.filler(3)
			a, i := lg.release(kit, "LPMARK")
			a.L = lg.prove(i, 0)
			return a
		}},
		{name: "tampered inclusion proof", want: "not in the log", build: func(t *testing.T, h *trustHarness, lg *testLog, kit trustKit, s int64) *protocol.ActionAuth {
			lg.filler(3)
			a, i := lg.release(kit, "LPMARK")
			a.L = lg.prove(i, s)
			p, err := translog.DecodeProof(a.L.Proof)
			if err != nil || len(p) == 0 {
				t.Fatalf("setup: proof %v %v", p, err)
			}
			p[0][0] ^= 0xff
			a.L.Proof = translog.EncodeProof(p)
			return a
		}},
		{name: "tampered consistency proof", want: "does not extend", build: func(t *testing.T, h *trustHarness, lg *testLog, kit trustKit, s int64) *protocol.ActionAuth {
			lg.filler(3)
			a, i := lg.release(kit, "LPMARK")
			a.L = lg.prove(i, s)
			p, err := translog.DecodeProof(a.L.Consistency)
			if err != nil || len(p) == 0 {
				t.Fatalf("setup: proof %v %v", p, err)
			}
			p[0][0] ^= 0xff
			a.L.Consistency = translog.EncodeProof(p)
			return a
		}},
		{name: "head signed by another key", want: "not signed by the pinned log key", build: func(t *testing.T, h *trustHarness, lg *testLog, kit trustKit, s int64) *protocol.ActionAuth {
			lg.filler(3)
			a, i := lg.release(kit, "LPMARK")
			// Same leaves, different key: refused on the signature alone.
			other := newTestLog(t)
			for j := int64(0); j <= i; j++ {
				k, d, _, err := lg.log.Leaf(j)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := other.log.Append(k, d); err != nil {
					t.Fatal(err)
				}
			}
			a.L = other.prove(i, s)
			return a
		}},
		{name: "head older than the stored one", want: "older than the last one", build: func(t *testing.T, h *trustHarness, lg *testLog, kit trustKit, s int64) *protocol.ActionAuth {
			// a is valid against a head smaller than the one b will move the device to.
			a, i := lg.release(kit, "LPMARK")
			a.L = lg.prove(i, 0)
			lg.filler(4)
			b, j := lg.release(kit, "ADVANCE")
			b.L = lg.prove(j, s)
			if rep, _, _ := h.sendSigned("adv", b); rep.Err != "" {
				t.Fatalf("setup: the newer head must be accepted, got %q", rep.Err)
			}
			return a
		}},
		{name: "missing proof under require_log_proof", reqLP: true, want: "carried no proof", build: func(t *testing.T, h *trustHarness, lg *testLog, kit trustKit, s int64) *protocol.ActionAuth {
			a, _ := lg.release(kit, "LPMARK")
			return a
		}},
	}
	for _, mode := range []string{actionauth.ModeEnforce, actionauth.ModeAudit} {
		for _, c := range cases {
			t.Run(mode+"/"+c.name, func(t *testing.T) {
				dir := t.TempDir()
				kit, lg := newKit(), newTestLog(t)
				writeTrust(t, dir, kit.logBundle(mode, lg.log.VerifierKey(), c.reqLP))
				h := newTrustHarness(t, dir)

				// The device accepts a first head so every case runs against S > 0.
				lg.filler(2)
				first, fi := lg.release(kit, "FIRST")
				first.L = lg.prove(fi, 0)
				if rep, evs, _ := h.sendSigned("first", first); rep.Err != "" || len(evs) != 0 {
					t.Fatalf("setup: %q %v", rep.Err, evs)
				}
				s := storedHead(t, dir).Size

				auth := c.build(t, h, lg, kit, s)
				held := storedHead(t, dir)
				rep, evs, out := h.sendSigned("bad", auth)

				if len(evs) != 1 || !strings.Contains(evs[0].Fields["reason"], "log proof: ") || !strings.Contains(evs[0].Fields["reason"], c.want) {
					t.Fatalf("expected one log proof security event containing %q, got %+v", c.want, evs)
				}
				if evs[0].Fields["manifest"] == "" || evs[0].Fields["mode"] != mode {
					t.Fatalf("the event must name the manifest and mode: %+v", evs[0].Fields)
				}
				if mode == actionauth.ModeEnforce {
					if !strings.HasPrefix(rep.Err, "refused: log proof: ") || !strings.Contains(rep.Err, c.want) || strings.Contains(out, "LPMARK") {
						t.Fatalf("enforce must refuse: err %q out %q", rep.Err, out)
					}
					if evs[0].Fields["executed"] != "false" {
						t.Fatalf("event must say not executed: %+v", evs[0].Fields)
					}
				} else {
					if rep.Err != "" || !strings.Contains(out+string(rep.D), "LPMARK") || evs[0].Fields["executed"] != "true" {
						t.Fatalf("audit must run the request and report it: err %q out %q ev %+v", rep.Err, out, evs[0].Fields)
					}
				}
				if after := storedHead(t, dir); after != held {
					t.Fatalf("a failed proof must not move the stored head: %+v -> %+v", held, after)
				}
			})
		}
	}
}

func TestLogProofIgnoredWithoutLogKey(t *testing.T) {
	dir := t.TempDir()
	kit, lg := newKit(), newTestLog(t)
	writeTrust(t, dir, kit.logBundle(actionauth.ModeEnforce, "", false))
	h := newTrustHarness(t, dir)

	a, i := lg.release(kit, "NOKEY")
	a.L = lg.prove(i, 0)
	a.L.Proof = []string{"garbage"}
	rep, evs, out := h.sendSigned("n1", a)
	if rep.Err != "" || len(evs) != 0 || !strings.Contains(out+string(rep.D), "NOKEY") {
		t.Fatalf("proofs must be ignored without log_key: err %q events %v", rep.Err, evs)
	}
	if _, err := os.Stat(filepath.Join(dir, "log_head.json")); err == nil {
		t.Fatal("no head may be stored without a pinned log key")
	}
	if rep.Log != 0 {
		t.Fatalf("a device holding no head reports none, got %d", rep.Log)
	}
}

func TestLogProofRequiredButNoLogKey(t *testing.T) {
	dir := t.TempDir()
	kit := newKit()
	writeTrust(t, dir, kit.logBundle(actionauth.ModeEnforce, "", true))
	h := newTrustHarness(t, dir)
	rep, evs, _ := h.sendSigned("k1", kit.signedAction(protocol.ReqScriptRun, scriptPayload("X", "x")))
	// ParseBundle refuses such a bundle, so the device never pins it and
	// refuses protected requests until a good bundle is installed.
	if !strings.Contains(rep.Err, "require_log_proof needs a log_key") || len(evs) != 1 {
		t.Fatalf("got %q / %v", rep.Err, evs)
	}
}

func TestLogHeadDamagedFailsClosed(t *testing.T) {
	dir := t.TempDir()
	kit, lg := newKit(), newTestLog(t)
	writeTrust(t, dir, kit.logBundle(actionauth.ModeEnforce, lg.log.VerifierKey(), false))
	if err := os.WriteFile(filepath.Join(dir, "log_head.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newTrustHarness(t, dir)

	a, i := lg.release(kit, "DAMAGED")
	a.L = lg.prove(i, 0)
	rep, evs, out := h.sendSigned("d1", a)
	if !strings.HasPrefix(rep.Err, "refused: log proof: log_head.json is damaged") || !strings.Contains(rep.Err, "delete it on the device") ||
		strings.Contains(out, "DAMAGED") || len(evs) != 1 {
		t.Fatalf("a damaged head must refuse protected requests: %q / %v", rep.Err, evs)
	}
	// Reads still work, so the device stays manageable.
	h.send(protocol.Envelope{T: protocol.ReqProcList, ID: "pl"})
	if rep, _, _ := h.reply("pl"); rep.Err != "" {
		t.Fatalf("reads must not need a log head: %q", rep.Err)
	}
	// Deleting the file is the documented way out.
	os.Remove(filepath.Join(dir, "log_head.json"))
	h.restart()
	// The refused manifest's nonce is spent, so the retry is a new manifest.
	a, i = lg.release(kit, "DAMAGED2")
	a.L = lg.prove(i, 0)
	if rep, _, _ := h.sendSigned("d2", a); rep.Err != "" {
		t.Fatalf("after deleting log_head.json: %q", rep.Err)
	}
}

// readChain verifies executed.log line by line and returns the head a device
// would report and the parsed lines.
func readChain(t *testing.T, path string) (string, []executedLine) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []executedLine
	prev := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		raw := sc.Bytes()
		var l executedLine
		if err := json.Unmarshal(raw, &l); err != nil {
			t.Fatalf("line %d is not JSON: %v", len(lines)+1, err)
		}
		if l.Prev != prev {
			t.Fatalf("line %d breaks the chain: prev %q, want %q", len(lines)+1, l.Prev, prev)
		}
		prev = lineHash(append([]byte(nil), raw...))
		lines = append(lines, l)
	}
	return prev, lines
}

func TestExecutedLogChainsAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	kit, lg := newKit(), newTestLog(t)
	writeTrust(t, dir, kit.logBundle(actionauth.ModeEnforce, lg.log.VerifierKey(), false))
	h := newTrustHarness(t, dir)
	path := filepath.Join(dir, "executed.log")

	if h.a.hello().ExecutedHead != "" {
		t.Fatal("a device that executed nothing reports no head")
	}
	var ids []string
	run := func(id, marker string) {
		a, i := lg.release(kit, marker)
		a.L = lg.prove(i, h.a.trust.logSize())
		if rep, _, _ := h.sendSigned(id, a); rep.Err != "" {
			t.Fatalf("%s: %q", id, rep.Err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(a.M, "="))
		if err != nil {
			t.Fatal(err)
		}
		m, err := actionauth.ParseManifest(raw)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, m.ID)
	}
	run("e1", "E1")
	run("e2", "E2")
	head1, lines := readChain(t, path)
	if len(lines) != 2 || lines[0].Prev != "" || h.a.hello().ExecutedHead != head1 {
		t.Fatalf("after two runs: %d lines, hello head %q, recomputed %q", len(lines), h.a.hello().ExecutedHead, head1)
	}

	h.restart()
	if got := h.a.hello().ExecutedHead; got != head1 {
		t.Fatalf("the head must survive a restart: %q vs %q", got, head1)
	}
	run("e3", "E3")
	head2, lines := readChain(t, path)
	if len(lines) != 3 || head2 == head1 || h.a.hello().ExecutedHead != head2 {
		t.Fatalf("after the restart: %d lines, head %q", len(lines), h.a.hello().ExecutedHead)
	}
	for i, l := range lines {
		if l.ManifestID != ids[i] || l.Op != protocol.ReqScriptRun || l.LogIndex < 0 {
			t.Fatalf("line %d = %+v, want manifest %s", i, l, ids[i])
		}
	}

	// A refused request is not executed and adds nothing.
	bad, i := lg.release(kit, "REFUSED")
	bad.L = lg.prove(i, 0)
	if rep, _, _ := h.sendSigned("e4", bad); rep.Err == "" {
		t.Fatal("setup: expected a refusal")
	}
	if _, lines = readChain(t, path); len(lines) != 3 {
		t.Fatalf("a refused request must not be recorded, have %d lines", len(lines))
	}

	// A torn last line starts a new chain without corrupting what came before.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"prev":"x`)
	f.Close()
	h.restart()
	if h.a.hello().ExecutedHead != "" {
		t.Fatalf("an unreadable last line must start a new chain, head %q", h.a.hello().ExecutedHead)
	}
	h.a.trust.recordExecuted("m_new", protocol.ReqScriptRun, -1)
	raw, _ := os.ReadFile(path)
	last := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var nl executedLine
	if err := json.Unmarshal([]byte(last[len(last)-1]), &nl); err != nil || nl.Prev != "" || nl.LogIndex != -1 {
		t.Fatalf("the new chain must start on its own line with an empty prev: %q", last[len(last)-1])
	}

	// A missing file starts a new chain too.
	os.Remove(path)
	h.restart()
	if h.a.hello().ExecutedHead != "" {
		t.Fatal("a missing executed.log must start a new chain")
	}
}
