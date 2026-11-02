package server

import (
	"encoding/json"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/actionauth/authtest"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

type auditEntry struct{ User, IP, Target string }

// auditEntries reads the audit entries for one action, oldest first.
func auditEntries(t *testing.T, s *Server, action string) []auditEntry {
	t.Helper()
	rs, err := s.db.Query(`SELECT user, ip, target FROM audit WHERE action = ? ORDER BY id`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var rows []auditEntry
	for rs.Next() {
		var r auditEntry
		if err := rs.Scan(&r.User, &r.IP, &r.Target); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, r)
	}
	return rows
}

// What a signed action audits is attributed to the operator who asked for it,
// at the address they asked from. With several signers the action runs on the
// request of whoever signs last, another operator at another address, and the
// entry used to take its address from that request. The signatures themselves
// stay attributed to whoever gave them.
func TestSignedRunIsAuditedAtTheAddressOfWhoAsked(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeAudit, 2, 1)
	a1, a2 := f.addAgent("box1"), f.addAgent("box2")
	// The test server sits behind the loopback address, so this is how the
	// operators' own addresses reach the audit log.
	f.s.trustedProxies = parseTrustedProxies([]string{"127.0.0.0/8"})
	const path = "/api/scripts/run"
	body := map[string]any{"agent_ids": []string{a1.ID(), a2.ID()}, "language": "bash", "body": "echo hi"}
	from := func(ip string) map[string]string { return map[string]string{"X-Forwarded-For": ip} }

	// The administrator asks from 10.0.0.1 and signs from there ...
	st, data := f.admin.doHdr("POST", path, body, from("10.0.0.1"))
	var c challenge
	if json.Unmarshal(data, &c) != nil || st != 428 || c.ManifestID == "" {
		t.Fatalf("asking = %d %s, want 428", st, data)
	}
	hdr := c.signedBy(t, f.ka)
	hdr["X-Forwarded-For"] = "10.0.0.1"
	if st, data := f.admin.doHdr("POST", path, body, hdr); st != 202 {
		t.Fatalf("first signature = %d %s", st, data)
	}
	// ... and bob completes it from 10.0.0.2, which is what runs the script.
	st, data = f.bob.doHdr("POST", "/api/approvals/"+c.ManifestID+"/sign", map[string]any{"assertion": f.kb.Sign(c.bytes(t), authtest.SignOpts{})}, from("10.0.0.2"))
	if st != 200 {
		t.Fatalf("completing signature = %d %s", st, data)
	}
	a1.wait(protocol.ReqScriptRun, 1)
	a2.wait(protocol.ReqScriptRun, 1)

	if rows := auditEntries(t, f.s, "script.run"); len(rows) != 1 || rows[0].User != "admin" || rows[0].IP != "10.0.0.1" {
		t.Fatalf("script.run audit = %+v, want one entry by admin from 10.0.0.1, where the run was asked for", rows)
	}
	// Each signature is the act of whoever gave it, from where they gave it.
	signed := auditEntries(t, f.s, "action.sign")
	if len(signed) != 2 || signed[0].User != "admin" || signed[0].IP != "10.0.0.1" || signed[1].User != "bob" || signed[1].IP != "10.0.0.2" {
		t.Fatalf("action.sign audit = %+v, want admin from 10.0.0.1 and then bob from 10.0.0.2", signed)
	}
}
