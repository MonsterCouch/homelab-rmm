//go:build !windows

package agent

import (
	"context"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

func TestServicingRepairIsRefusedOffWindows(t *testing.T) {
	_, err := servicingRepair(context.Background(), &Config{}, protocol.ServicingRepair{}, nil)
	if err == nil || err.Error() != "servicing repair is a Windows operation" {
		t.Errorf("err = %v", err)
	}
}
