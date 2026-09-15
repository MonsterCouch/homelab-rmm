package agent

import (
	"os"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

func (a *Agent) startDesktop(req protocol.DesktopStart) (*protocol.DesktopStartResult, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	note, err := desktop.Launch(exe, a.cfg.ServerURL, req.Token, a.cfg.Fingerprint, req.Quality)
	if err != nil {
		return nil, err
	}
	return &protocol.DesktopStartResult{Started: true, Note: note}, nil
}
