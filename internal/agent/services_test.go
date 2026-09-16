package agent

import (
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// TestWinApplyServiceConfig is F073: a service whose description is an
// "@dll,-N" MUI reference that no longer resolves (WaaSMedicSvc,
// workfolderssvc, IsolationSession on a stock Windows 11) used to lose its
// start type too, because the configuration was read all-or-nothing. A
// cosmetic description must never cost the start type.
func TestWinApplyServiceConfig(t *testing.T) {
	// Description query failed, QueryServiceConfig succeeded.
	s := protocol.Service{Name: "WaaSMedicSvc", DisplayName: "WaaSMedicSvc", State: "stopped", StartType: "unknown"}
	winApplyServiceConfig(&s, winServiceConfig{HaveStartType: true, StartType: 3})
	if s.StartType != "manual" {
		t.Errorf("start type = %q, want manual", s.StartType)
	}
	if s.Description != "" {
		t.Errorf("description = %q, want empty", s.Description)
	}
	if s.State != "stopped" || s.DisplayName != "WaaSMedicSvc" {
		t.Errorf("unrelated fields disturbed: %+v", s)
	}

	// Everything readable: delayed auto-start and a real description.
	s = protocol.Service{Name: "Spooler", State: "running", StartType: "unknown"}
	winApplyServiceConfig(&s, winServiceConfig{
		HaveStartType: true, StartType: 2, Delayed: true,
		Description: "  Prints things  ", DisplayName: "Print Spooler",
	})
	if s.StartType != "auto_delayed" || s.Description != "Prints things" || s.DisplayName != "Print Spooler" {
		t.Errorf("full config = %+v", s)
	}

	// An unresolved MUI description is still blanked, and does not overwrite
	// the display name the enumeration already supplied.
	s = protocol.Service{Name: "workfolderssvc", DisplayName: "Work Folders", State: "stopped", StartType: "unknown"}
	winApplyServiceConfig(&s, winServiceConfig{
		HaveStartType: true, StartType: 4,
		Description: `@%SystemRoot%\system32\workfolderssvc.dll,-101`, DisplayName: "ignored",
	})
	if s.StartType != "disabled" || s.Description != "" || s.DisplayName != "Work Folders" {
		t.Errorf("MUI config = %+v", s)
	}

	// QueryServiceConfig itself failed: that, and only that, leaves the start
	// type unknown.
	s = protocol.Service{Name: "Protected", DisplayName: "Protected", State: "running", StartType: "unknown"}
	winApplyServiceConfig(&s, winServiceConfig{})
	if s.StartType != "unknown" || s.DisplayName != "Protected" {
		t.Errorf("empty config = %+v", s)
	}
}
