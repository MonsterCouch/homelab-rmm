package server

import (
	"crypto/sha256"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/translog"
)

// Two protected requests written to one device before either reply arrives
// must chain: the second proof starts at the head the first carried, not at
// the size the device reported earlier.
func TestWithLogProofChainsBackToBackSends(t *testing.T) {
	l, err := translog.Open(translog.NewMemStorage(), filepath.Join(t.TempDir(), "log.key"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := l.Append("x", []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	ac := &agentConn{tl: l}
	ac.logSize.Store(2)
	ac.logSent.Store(2)
	req := func() protocol.Envelope {
		return protocol.Envelope{A: &protocol.ActionAuth{M: "m", L: &protocol.LogProof{Index: 0}}}
	}
	first, err := ac.withLogProof(req())
	if err != nil {
		t.Fatal(err)
	}
	if first.A.L.From != 2 {
		t.Fatalf("first proof starts at %d, want the device's size 2", first.A.L.From)
	}
	if _, err := l.Append("x", []byte{9}); err != nil {
		t.Fatal(err)
	}
	second, err := ac.withLogProof(req())
	if err != nil {
		t.Fatal(err)
	}
	if second.A.L.From != 3 {
		t.Fatalf("second proof starts at %d, want 3 (the head the first send carried)", second.A.L.From)
	}
}

func TestSetExecutedHeadChecksShape(t *testing.T) {
	s, _, _ := newTestServer(t)
	var id string
	if err := s.db.QueryRow(`SELECT id FROM agents LIMIT 1`).Scan(&id); err != nil {
		if _, err := s.db.Exec(`INSERT INTO agents(id, key_hash, hostname) VALUES('a1','k','h')`); err != nil {
			t.Skipf("cannot seed an agent row: %v", err)
		}
		id = "a1"
	}
	sum := sha256.Sum256([]byte("one"))
	good := base64.StdEncoding.EncodeToString(sum[:])
	read := func() string {
		var h string
		s.db.QueryRow(`SELECT executed_head FROM agents WHERE id = ?`, id).Scan(&h)
		return h
	}
	s.db.setExecutedHead(id, strings.Repeat("A", 4096))
	if read() != "" {
		t.Fatal("an oversized head was stored")
	}
	s.db.setExecutedHead(id, good)
	if read() != good {
		t.Fatal("a genuine head was not stored")
	}
}

func TestBackfillApprovalLog(t *testing.T) {
	s, _, _ := newTestServer(t)
	if s.db.logAppend == nil {
		t.Skip("no log attached")
	}
	orig := s.db.logAppend
	s.db.logAppend = nil
	row := approvalRow{Org: "o", Type: "task", ID: "1", Purpose: "p", Hash: "h", Manifest: []byte(`{}`), Need: 1, CreatedAt: now(), ExpiresAt: now() + 100}
	err := s.db.putApproval(row)
	s.db.logAppend = orig
	if err != nil {
		t.Fatal(err)
	}
	got := s.db.approvalsFor("o", "task", "1")
	if len(got) != 1 || got[0].LogIndex != -1 {
		t.Fatalf("expected one unlogged approval, got %+v", got)
	}
	a := &protocol.ActionAuth{M: actionauth.EncodeB64(got[0].Manifest), S: got[0].Sigs}
	idx := s.db.backfillApprovalLog(got[0], a)
	if idx < 0 {
		t.Fatal("the approval was not logged")
	}
	if again := s.db.approvalsFor("o", "task", "1"); again[0].LogIndex != idx {
		t.Fatalf("stored index %d, want %d", again[0].LogIndex, idx)
	}
}
