package main

import (
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/actionauth/authtest"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/winwebauthn"
)

// The native signer builds clientDataJSON itself and hands it to webauthn.dll
// to sign, so the bytes it builds must be exactly what the server's verifier
// accepts: the challenge is the digest of the manifest, the origin is the
// server's, and crossOrigin is false. This signs those bytes with a software
// key in place of the authenticator and runs them through the real verifier.
func TestSignerClientDataIsAcceptedByTheVerifier(t *testing.T) {
	key := authtest.NewKey("alice", actionauth.AlgES256)
	b, err := actionauth.ParseBundle(authtest.Bundle(authtest.BundleSpec{Keys: []*authtest.Key{key}, Policy: actionauth.Policy{Mode: actionauth.ModeAudit}}))
	if err != nil {
		t.Fatal(err)
	}
	raw := authtest.Manifest(actionauth.Manifest{Kind: actionauth.KindAction, Op: protocol.ReqScriptRun, Targets: []string{"box1"}, Payload: []byte(`{"body":"echo hi"}`)})

	cd := winwebauthn.ClientDataJSON(actionauth.Challenge(raw), authtest.Origin)
	a := key.Sign(raw, authtest.SignOpts{ClientData: cd})
	owners, errs := actionauth.Signers(raw, []protocol.Assertion{a}, b)
	if len(owners) != 1 || owners[0] != "alice" {
		t.Fatalf("the verifier did not accept the signer's clientDataJSON %s: owners %v, errors %v", cd, owners, errs)
	}

	// The origin is part of what is signed and must match the bundle exactly;
	// a different one is the sign of a manifest meant for another server.
	bad := winwebauthn.ClientDataJSON(actionauth.Challenge(raw), "https://other.test")
	if owners, _ := actionauth.Signers(raw, []protocol.Assertion{key.Sign(raw, authtest.SignOpts{ClientData: bad})}, b); len(owners) != 0 {
		t.Fatalf("an assertion for another origin was accepted: %v", owners)
	}
	// And the challenge binds the manifest bytes: the same clientDataJSON
	// cannot vouch for a manifest with one byte changed.
	other := authtest.Manifest(actionauth.Manifest{Kind: actionauth.KindAction, Op: protocol.ReqScriptRun, Targets: []string{"box1"}, Payload: []byte(`{"body":"echo bye"}`)})
	if owners, _ := actionauth.Signers(other, []protocol.Assertion{a}, b); len(owners) != 0 {
		t.Fatalf("an assertion over one manifest was accepted for another: %v", owners)
	}
}
