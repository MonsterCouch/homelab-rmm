package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/actionauth/authtest"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// recoveryFixture is a bundle in force that lists a recovery key, the
// successor an operator wants to install, and the key's printable form.
type recoveryFixture struct {
	cur     *actionauth.Bundle
	next    []byte
	keyText string
}

func newRecoveryFixture(t *testing.T) recoveryFixture {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	rec := actionauth.RecoveryKey{ID: actionauth.RecoveryKeyID(pub), Alg: "ed25519", Pub: actionauth.EncodeB64(pub)}

	lost := authtest.NewKey("alice", actionauth.AlgES256)
	build := func(epoch int64, prev string, keys ...*authtest.Key) []byte {
		var b actionauth.Bundle
		if err := json.Unmarshal(authtest.Bundle(authtest.BundleSpec{Epoch: epoch, Prev: prev, Keys: keys, Policy: actionauth.Policy{Mode: actionauth.ModeAudit}}), &b); err != nil {
			t.Fatal(err)
		}
		b.Recovery = []actionauth.RecoveryKey{rec}
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	cur, err := actionauth.ParseBundle(build(1, "", lost))
	if err != nil {
		t.Fatal(err)
	}
	// the replacement is signed for by a different key: the original is gone
	next := build(2, cur.Hash(), authtest.NewKey("alice", actionauth.AlgEdDSA))
	return recoveryFixture{cur: cur, next: next, keyText: actionauth.RecoveryKeyPrefix + actionauth.EncodeB64(seed)}
}

func TestSignBundleProducesARecoverySignatureAgentsAccept(t *testing.T) {
	f := newRecoveryFixture(t)
	out, err := signBundle(f.keyText+"\n", actionauth.EncodeB64(f.next)+"\n")
	if err != nil {
		t.Fatal(err)
	}
	var rs protocol.RecoverySig
	if err := json.Unmarshal(out, &rs); err != nil || rs.ID == "" || rs.Sig == "" {
		t.Fatalf("output %s: %v", out, err)
	}
	if rs.ID != f.cur.Recovery[0].ID {
		t.Fatalf("id = %q, want %q", rs.ID, f.cur.Recovery[0].ID)
	}
	// exactly what an agent holding the current bundle checks
	nb, err := actionauth.VerifyUpdate(f.cur, f.next, nil, []protocol.RecoverySig{rs})
	if err != nil || nb.Epoch != 2 {
		t.Fatalf("VerifyUpdate: %v", err)
	}
	// and the signature covers those bytes only
	tampered := append([]byte(nil), f.next...)
	tampered[len(tampered)-2] ^= 1
	if _, err := actionauth.VerifyUpdate(f.cur, tampered, nil, []protocol.RecoverySig{rs}); err == nil {
		t.Fatal("the signature verified over different bundle bytes")
	}
}

func TestSignBundleRefusals(t *testing.T) {
	f := newRecoveryFixture(t)
	bundle := actionauth.EncodeB64(f.next)
	for name, c := range map[string]struct{ key, bundle, want string }{
		"not a recovery key":     {"hello", bundle, "recovery key"},
		"damaged seed":           {actionauth.RecoveryKeyPrefix + "AAAA", bundle, "damaged"},
		"bundle not base64":      {f.keyText, "!!!", "bundle"},
		"bytes are not a bundle": {f.keyText, actionauth.EncodeB64([]byte(`{"v":1}`)), "bundle"},
	} {
		if _, err := signBundle(c.key, c.bundle); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, c.want)
		}
	}
}

func TestTrustSignBundleCommand(t *testing.T) {
	f := newRecoveryFixture(t)
	dir := t.TempDir()
	keyFile, bundleFile, outFile := filepath.Join(dir, "key"), filepath.Join(dir, "bundle"), filepath.Join(dir, "sig.json")
	os.WriteFile(keyFile, []byte(f.keyText+"\n"), 0o600)
	os.WriteFile(bundleFile, []byte(actionauth.EncodeB64(f.next)), 0o600)

	if code := run([]string{"trust", "sign-bundle", "--key", keyFile, "--bundle", bundleFile, "--out", outFile}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	raw, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	var rs protocol.RecoverySig
	if err := json.Unmarshal(raw, &rs); err != nil {
		t.Fatal(err)
	}
	if _, err := actionauth.VerifyUpdate(f.cur, f.next, nil, []protocol.RecoverySig{rs}); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"trust", "sign-bundle", "--key", keyFile}); code != 2 {
		t.Fatalf("missing --bundle exit %d, want 2", code)
	}
	if code := run([]string{"trust", "sign-bundle", "--key", filepath.Join(dir, "nope"), "--bundle", bundleFile}); code != 1 {
		t.Fatalf("missing key file exit %d, want 1", code)
	}
	if code := run([]string{"trust"}); code != 2 {
		t.Fatalf("bare trust exit %d, want 2", code)
	}
}
