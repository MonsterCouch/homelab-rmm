package server

import (
	"net/http"
	"slices"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/actionauth/authtest"
)

type oobEntry struct {
	ManifestID       string            `json:"manifest_id"`
	Manifest         string            `json:"manifest"`
	Have             int               `json:"have"`
	Need             int               `json:"need"`
	Kind             string            `json:"kind"`
	Op               string            `json:"op"`
	Ops              []string          `json:"ops"`
	Targets          []string          `json:"targets"`
	TargetNames      map[string]string `json:"target_names"`
	RPID             string            `json:"rp_id"`
	Origins          []string          `json:"origins"`
	AllowCredentials []string          `json:"allow_credentials"`
	UV               string            `json:"user_verification"`
	Signers          []string          `json:"signers"`
	Issuer           string            `json:"issuer"`
}

func oobHas(list []oobEntry, id string) *oobEntry {
	for i := range list {
		if list[i].ManifestID == id {
			return &list[i]
		}
	}
	return nil
}

// A challenge the operator did not sign is reachable by that operator alone,
// and carries what an out-of-band signer needs to sign it.
func TestApprovalsOutOfBandEntries(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeAudit, 2, 1)
	a1, a2 := f.addAgent("box1"), f.addAgent("box2")
	body := map[string]any{"agent_ids": []string{a1.ID(), a2.ID()}, "language": "bash", "body": "echo hi"}
	c := ask(t, f.admin, "POST", "/api/scripts/run", body)

	var mine, theirs []oobEntry
	f.admin.mustJSON("GET", "/api/approvals", nil, &mine)
	f.bob.mustJSON("GET", "/api/approvals", nil, &theirs)
	e := oobHas(mine, c.ManifestID)
	if e == nil || e.Have != 0 || e.Need != 2 || len(e.Signers) != 0 {
		t.Fatalf("the issuer's list = %+v, want the unsigned challenge with have 0", mine)
	}
	if oobHas(theirs, c.ManifestID) != nil {
		t.Fatal("another operator can see a challenge nobody has signed")
	}
	if st, _ := f.bob.do("GET", "/api/approvals/"+c.ManifestID, nil); st != http.StatusNotFound {
		t.Fatalf("another operator reading an unsigned challenge = %d, want 404", st)
	}

	if st, body := f.admin.doHdr("POST", "/api/scripts/run", body, c.signedBy(t, f.ka)); st != 202 {
		t.Fatalf("first signature = %d %s", st, body)
	}
	f.admin.mustJSON("GET", "/api/approvals", nil, &mine)
	if oobHas(mine, c.ManifestID) != nil {
		t.Fatal("the operator who signed still sees the entry as waiting for them")
	}
	f.bob.mustJSON("GET", "/api/approvals", nil, &theirs)
	e = oobHas(theirs, c.ManifestID)
	if e == nil {
		t.Fatalf("bob's list = %+v, want the half-signed entry", theirs)
	}
	checkOOBShape(t, f, e, c, a1, a2)

	var one oobEntry
	f.bob.mustJSON("GET", "/api/approvals/"+c.ManifestID, nil, &one)
	checkOOBShape(t, f, &one, c, a1, a2)

	if st, _ := f.admin.do("GET", "/api/approvals/"+c.ManifestID, nil); st != http.StatusNotFound {
		t.Fatalf("the operator who already signed reading the entry = %d, want 404", st)
	}
	if st, _ := f.bob.do("GET", "/api/approvals/nope", nil); st != http.StatusNotFound {
		t.Fatalf("unknown id = %d, want 404", st)
	}

	org, err := f.s.db.CreateOrganization("Elsewhere")
	if err != nil {
		t.Fatal(err)
	}
	f.admin.mustJSON("POST", "/api/users", map[string]any{"username": "carol", "password": "password123", "role": RoleTech, "org_scope": []string{org.ID}}, nil)
	carol := newBrowser(t, f.ts)
	carol.mustJSON("POST", "/api/auth/login", map[string]string{"username": "carol", "password": "password123"}, nil)
	if st, _ := carol.do("GET", "/api/approvals/"+c.ManifestID, nil); st != http.StatusNotFound {
		t.Fatalf("a user outside the organization reading the entry = %d, want 404", st)
	}
	var carols []oobEntry
	carol.mustJSON("GET", "/api/approvals", nil, &carols)
	if len(carols) != 0 {
		t.Fatalf("a user outside the organization lists %+v", carols)
	}

	if st, data := f.bob.do("POST", "/api/approvals/"+c.ManifestID+"/sign", map[string]any{"assertion": f.kb.Sign(c.bytes(t), authtest.SignOpts{})}); st != 200 {
		t.Fatalf("completing signature = %d %s", st, data)
	}
	if st, _ := f.bob.do("GET", "/api/approvals/"+c.ManifestID, nil); st != http.StatusNotFound {
		t.Fatalf("a completed entry = %d, want 404", st)
	}
	f.bob.mustJSON("GET", "/api/approvals", nil, &theirs)
	if oobHas(theirs, c.ManifestID) != nil {
		t.Fatal("a completed entry is still listed")
	}
}

func checkOOBShape(t *testing.T, f *signFixture, e *oobEntry, c challenge, a1, a2 *sigAgent) {
	t.Helper()
	if e.Have != 1 || e.Need != 2 || !slices.Equal(e.Signers, []string{"admin"}) || e.Issuer != "admin" {
		t.Fatalf("entry progress = %+v", e)
	}
	if e.Manifest != c.Manifest || e.Kind != actionauth.KindAction || e.Op == "" || len(e.Targets) != 2 {
		t.Fatalf("entry identity = %+v", e)
	}
	if e.RPID != authtest.RPID || !slices.Contains(e.Origins, authtest.Origin) || e.UV != "preferred" {
		t.Fatalf("entry relying party = %+v", e)
	}
	if !slices.Equal(e.AllowCredentials, []string{f.kb.Credential().ID}) {
		t.Fatalf("allow_credentials = %v, want only bob's key", e.AllowCredentials)
	}
	if e.TargetNames[a1.ID()] == "" || e.TargetNames[a2.ID()] == "" {
		t.Fatalf("target_names = %v", e.TargetNames)
	}
}
