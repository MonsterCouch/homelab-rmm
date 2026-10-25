//go:build !windows

package agent

import (
	"context"
	"errors"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// servicingRepair exists so the dispatcher compiles everywhere; DISM, SFC and
// the Windows Update component store are Windows concepts.
func servicingRepair(ctx context.Context, cfg *Config, req protocol.ServicingRepair, progress func(string)) (*protocol.ServicingRepairResult, error) {
	return nil, errors.New("servicing repair is a Windows operation")
}
