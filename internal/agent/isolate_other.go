//go:build !windows && !linux

package agent

import (
	"errors"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

func (a *Agent) handleIsolate(in protocol.DeviceIsolate) (any, error) {
	return nil, errors.New("network isolation is only supported on Windows and Linux endpoints")
}
