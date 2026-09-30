package server

import (
	"net/http"
	"testing"
)

func TestOrganizationsAndSites(t *testing.T) {
	_, _, b := newTestServer(t)

	// 1. Initial listing contains default organization
	var orgs []Organization
	b.mustJSON("GET", "/api/organizations", nil, &orgs)
	if len(orgs) == 0 {
		t.Fatal("expected at least default organization")
	}
	foundDefault := false
	for _, o := range orgs {
		if o.ID == "org_default" {
			foundDefault = true
			if o.Name != "Default Organization" {
				t.Fatalf("expected Default Organization, got %q", o.Name)
			}
		}
	}
	if !foundDefault {
		t.Fatal("org_default not found in /api/organizations")
	}

	// 2. Default sites under org_default
	var sites []Site
	b.mustJSON("GET", "/api/organizations/org_default/sites", nil, &sites)
	if len(sites) == 0 {
		t.Fatal("expected at least default site under org_default")
	}
	if sites[0].ID != "site_default" {
		t.Fatalf("expected site_default, got %q", sites[0].ID)
	}

	// 3. Create a new Organization
	var createdOrg Organization
	b.mustJSON("POST", "/api/organizations", map[string]string{"name": "Acme Corp"}, &createdOrg)
	if createdOrg.ID == "" || createdOrg.Name != "Acme Corp" {
		t.Fatalf("unexpected created org: %+v", createdOrg)
	}

	// 4. Listing sites of the new organization should show the auto-created "Main Site"
	var acmeSites []Site
	b.mustJSON("GET", "/api/organizations/"+createdOrg.ID+"/sites", nil, &acmeSites)
	if len(acmeSites) != 1 || acmeSites[0].Name != "Main Site" {
		t.Fatalf("expected 1 auto-created Main Site, got %+v", acmeSites)
	}

	// 5. Create a second site under Acme Corp
	var newSite Site
	b.mustJSON("POST", "/api/organizations/"+createdOrg.ID+"/sites", map[string]string{"name": "Branch Office"}, &newSite)
	if newSite.Name != "Branch Office" {
		t.Fatalf("unexpected new site: %+v", newSite)
	}

	// 6. Delete newly created site
	st, _ := b.do("DELETE", "/api/sites/"+newSite.ID, nil)
	if st != http.StatusOK {
		t.Fatalf("delete site failed: status=%d", st)
	}

	// 7. Attempting to delete default org must be forbidden
	st, _ = b.do("DELETE", "/api/organizations/org_default", nil)
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 when deleting org_default, got %d", st)
	}

	// 8. Delete the custom organization
	st, _ = b.do("DELETE", "/api/organizations/"+createdOrg.ID, nil)
	if st != http.StatusOK {
		t.Fatalf("expected 200 when deleting Acme Corp, got %d", st)
	}
}
