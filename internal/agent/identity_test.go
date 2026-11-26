package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/actionauth/authtest"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// Signed manifests and grants name the devices they are for by agent ID. The
// ID comes from the server, so these tests pin down when the server may set
// it: on an enrollment, and under an enforcing trust bundle only to the
// identity the device already had.

// identityAgent is an agent in a throwaway config directory, with an
// enforcing trust bundle pinned when key is not nil.
func identityAgent(t *testing.T, cfg *Config, key *authtest.Key) *Agent {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(EnvConfigDir, dir)
	if key != nil {
		raw := authtest.Bundle(authtest.BundleSpec{Keys: []*authtest.Key{key}, Recovery: []*authtest.RecoveryKey{authtest.NewRecoveryKey("")}})
		if err := os.WriteFile(filepath.Join(dir, "trust.json"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a := New(cfg)
	if got := a.trust.identityPinned(); got != (key != nil) {
		t.Fatalf("fixture: identityPinned = %v with enforcing bundle = %v", got, key != nil)
	}
	return a
}

func welcomeAs(id, key string) protocol.Envelope {
	return protocol.Envelope{T: "welcome", D: json.RawMessage(fmt.Sprintf(`{"agent_id":%q,"agent_key":%q}`, id, key))}
}

// grantAllowed reports whether a shell grant signed for target would be
// accepted by this device as it is now.
func grantAllowed(t *testing.T, a *Agent, k *authtest.Key, target string) bool {
	t.Helper()
	m := authtest.Manifest(actionauth.Manifest{Kind: "grant", Targets: []string{target}, Ops: []string{protocol.ReqShellOpen}})
	v, failed := a.trust.verifier(a.agentID())
	if failed != nil {
		t.Fatalf("trust state unusable: %v", failed)
	}
	return v.Check(protocol.ReqShellOpen, json.RawMessage(`{}`), authtest.Auth(m, k.Sign(m, authtest.SignOpts{}))).Allow
}

// A device that dialled with its key is enrolled. A welcome that carries a
// new key on that session is the server renaming it, and is refused whatever
// the trust mode: the honest server never sends one.
func TestWelcomeCannotRenameAnEnrolledDevice(t *testing.T) {
	k := authtest.NewKey("alice", actionauth.AlgES256)
	for _, tc := range []struct {
		name string
		key  *authtest.Key
	}{{"no trust bundle", nil}, {"enforcing bundle", k}} {
		t.Run(tc.name, func(t *testing.T) {
			a := identityAgent(t, &Config{AgentID: "A", Key: "kA"}, tc.key)
			if err := a.welcomed(welcomeAs("B", "kB")); err == nil {
				t.Fatal("a welcome that renamed an enrolled device was accepted")
			}
			if a.cfg.AgentID != "A" || a.cfg.Key != "kA" {
				t.Fatalf("identity is now %q/%q, want it unchanged", a.cfg.AgentID, a.cfg.Key)
			}
			if _, err := os.Stat(filepath.Join(ConfigDir(), "agent.json")); !os.IsNotExist(err) {
				t.Fatal("the refused identity was written to agent.json")
			}
			// The ordinary welcome of a keyed session still works.
			if err := a.welcomed(welcomeAs("A", "")); err != nil {
				t.Fatalf("an ordinary welcome was refused: %v", err)
			}
			if tc.key == nil {
				return
			}
			// What the rename was for: a grant an operator signed for
			// device B must not open a shell here.
			if grantAllowed(t, a, k, "B") {
				t.Fatal("a grant signed for another device is accepted")
			}
			if !grantAllowed(t, a, k, "A") {
				t.Fatal("fixture: a grant signed for this device is refused")
			}
		})
	}
}

// Re-enrolling after a rejected key is the other way to be renamed: the
// server decides both that the key is rejected and which ID comes back.
func TestReenrollmentKeepsIdentityUnderEnforcingBundle(t *testing.T) {
	k := authtest.NewKey("alice", actionauth.AlgES256)
	a := identityAgent(t, &Config{EnrollToken: "tok", AgentID: "A", Key: "kA"}, k)

	a.forgetKey() // what a 401 or an unknown-key refusal does
	if a.cfg.Key != "" || a.cfg.AgentID != "" || a.cfg.PrevAgentID != "A" {
		t.Fatalf("after the rejected key: id=%q key=%q prev=%q", a.cfg.AgentID, a.cfg.Key, a.cfg.PrevAgentID)
	}

	if err := a.welcomed(welcomeAs("B", "kB")); err == nil {
		t.Fatal("re-enrollment under another identity was accepted with an enforcing bundle pinned")
	}
	if a.cfg.Key != "" || a.cfg.AgentID != "" || a.cfg.PrevAgentID != "A" {
		t.Fatalf("after the refusal: id=%q key=%q prev=%q, want the device still un-enrolled and remembering A", a.cfg.AgentID, a.cfg.Key, a.cfg.PrevAgentID)
	}
	// The refusal survives a restart: it is in agent.json, not in memory.
	var saved Config
	raw, err := os.ReadFile(ConfigPath())
	if err == nil {
		err = json.Unmarshal(raw, &saved)
	}
	if err != nil || saved.PrevAgentID != "A" || saved.Key != "" || saved.AgentID != "" {
		t.Fatalf("agent.json after the refusal: %+v, %v", saved, err)
	}

	// Being given its own record back, with a fresh key, is fine.
	if err := a.welcomed(welcomeAs("A", "kA2")); err != nil {
		t.Fatalf("re-enrollment under the same identity was refused: %v", err)
	}
	if a.cfg.AgentID != "A" || a.cfg.Key != "kA2" || a.cfg.PrevAgentID != "" {
		t.Fatalf("after re-enrollment: id=%q key=%q prev=%q", a.cfg.AgentID, a.cfg.Key, a.cfg.PrevAgentID)
	}
	if grantAllowed(t, a, k, "B") || !grantAllowed(t, a, k, "A") {
		t.Fatal("the device does not answer to exactly its own identity")
	}
}

// Without an enforcing bundle nothing is signed for an identity, so a device
// that was deleted on the server and re-enrolls takes the new record as it
// always has.
func TestReenrollmentWithoutEnforcingBundleTakesNewIdentity(t *testing.T) {
	a := identityAgent(t, &Config{EnrollToken: "tok", AgentID: "A", Key: "kA"}, nil)
	a.forgetKey()
	if err := a.welcomed(welcomeAs("B", "kB")); err != nil {
		t.Fatalf("re-enrollment was refused: %v", err)
	}
	if a.cfg.AgentID != "B" || a.cfg.Key != "kB" || a.cfg.PrevAgentID != "" {
		t.Fatalf("after re-enrollment: id=%q key=%q prev=%q", a.cfg.AgentID, a.cfg.Key, a.cfg.PrevAgentID)
	}
}

// A first enrollment has no earlier identity to keep, bundle or not.
func TestFirstEnrollmentIsAccepted(t *testing.T) {
	a := identityAgent(t, &Config{EnrollToken: "tok"}, authtest.NewKey("alice", actionauth.AlgES256))
	if err := a.welcomed(welcomeAs("A", "kA")); err != nil {
		t.Fatalf("first enrollment was refused: %v", err)
	}
	if a.cfg.AgentID != "A" || a.cfg.Key != "kA" {
		t.Fatalf("after enrollment: id=%q key=%q", a.cfg.AgentID, a.cfg.Key)
	}
}
