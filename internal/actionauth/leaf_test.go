package actionauth

import (
	"strings"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

func TestManifestLeaf(t *testing.T) {
	a := &protocol.ActionAuth{M: "bWFuaWZlc3Q", S: []protocol.Assertion{{Cred: "c", AD: "a", CD: "d", Sig: "s"}}}
	got, err := ManifestLeaf(a)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"kind":"manifest","manifest":"bWFuaWZlc3Q","sigs":[{"ad":"a","cd":"d","cred":"c","sig":"s"}]}`
	if string(got) != want {
		t.Fatalf("leaf = %s, want %s", got, want)
	}
	// The proof field must not change the leaf.
	a.L = &protocol.LogProof{Index: 3}
	again, _ := ManifestLeaf(a)
	if string(again) != want {
		t.Fatal("log proof leaked into the leaf")
	}
	empty, err := ManifestLeaf(&protocol.ActionAuth{M: "x"})
	if err != nil || !strings.Contains(string(empty), `"sigs":[]`) {
		t.Fatalf("nil signature set: %s %v", empty, err)
	}
	if _, err := ManifestLeaf(nil); err == nil {
		t.Fatal("nil auth accepted")
	}
	if _, err := ManifestLeaf(&protocol.ActionAuth{}); err == nil {
		t.Fatal("empty manifest accepted")
	}
}
