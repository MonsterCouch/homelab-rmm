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
	note, err := desktop.Launch(exe, desktop.Config{
		ServerURL:   a.cfg.ServerURL,
		Token:       req.Token,
		Fingerprint: a.cfg.Fingerprint,
		Quality:     req.Quality,
		Mode:        string(req.Mode),
		WebRTC:      req.EnableWebRTC,
	})
	if err != nil {
		return nil, err
	}
	mode := req.Mode
	if mode == "" {
		mode = protocol.DesktopModeConsole
	}
	// WebRTCAvail reports whether this build can negotiate WebRTC at all. The
	// Pion stack is pure Go and compiled into every platform, so availability
	// tracks what the viewer asked for; the helper still falls back to tiles
	// if ICE cannot connect.
	return &protocol.DesktopStartResult{Started: true, Note: note, Mode: mode, WebRTCAvail: req.EnableWebRTC}, nil
}
