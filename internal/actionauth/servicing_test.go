package actionauth_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/actionauth/authtest"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

func TestServicingRepairIsAnAction(t *testing.T) {
	if got := actionauth.ClassOf(protocol.ReqServicingRepair); got != actionauth.ClassAction {
		t.Errorf("servicing.repair class = %v, want action", got)
	}
}

// A standing approval for servicing.repair names the exact steps and reboot
// setting, and never covers a package download.
func TestStandingServicingRepairBindsStepsRebootAndPackage(t *testing.T) {
	f := newFixture(t, actionauth.Policy{})
	steps := []string{"dism_restore", "reset_components", "rescan"}
	m := authtest.Manifest(actionauth.Manifest{Kind: actionauth.KindStanding, Targets: []string{"*"}, Exp: time.Now().Unix() + 86400,
		Constraints: &actionauth.Constraints{Op: protocol.ReqServicingRepair, Steps: steps, Reboot: "never"}})
	auth := authtest.Auth(m, f.alice.Sign(m, authtest.SignOpts{}))
	payload := func(r protocol.ServicingRepair) json.RawMessage {
		b, _ := json.Marshal(r)
		return b
	}
	if d := f.v.Check(protocol.ReqServicingRepair, payload(protocol.ServicingRepair{Steps: steps, Reboot: "never"}), auth); !d.Allow {
		t.Fatalf("the approved repair was refused: %v", d.Err)
	}
	for name, p := range map[string]protocol.ServicingRepair{
		"extra step":     {Steps: append(append([]string{}, steps...), "sfc"), Reboot: "never"},
		"fewer steps":    {Steps: steps[:2], Reboot: "never"},
		"no steps":       {Reboot: "never"},
		"other reboot":   {Steps: steps, Reboot: "if_required"},
		"with a package": {Steps: steps, Reboot: "never", Package: &protocol.ServicingPackage{URL: "https://x/a.cab", SHA256: "00"}},
	} {
		if d := f.v.Check(protocol.ReqServicingRepair, payload(p), auth); d.Allow || !errors.Is(d.Err, actionauth.ErrScope) {
			t.Errorf("%s: %+v", name, d)
		}
	}
}
