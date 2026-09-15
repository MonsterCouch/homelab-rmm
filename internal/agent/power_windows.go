//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// powerAction performs reboot|shutdown (through shutdown.exe, which shows
// the countdown and message to logged-in users) and lock|logoff (through
// the terminal-services API on the interactive session). Delay applies to
// reboot and shutdown only.
func powerAction(p protocol.Power) error {
	action := strings.ToLower(strings.TrimSpace(p.Action))
	switch action {
	case "reboot", "shutdown":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return runShutdown(ctx, winShutdownArgs(action, p.Delay, p.Message))
	case "lock":
		sid, err := interactiveSessionID()
		if err != nil {
			return err
		}
		// Disconnecting the console session is what tsdiscon does: the
		// session survives and the lock screen appears. LockWorkStation
		// only works from inside the session, which a service is not.
		if r, _, e := procWTSDisconnectSession.Call(wtsCurrentServerHandle, uintptr(sid), 0); r == 0 {
			return fmt.Errorf("lock session %d: %w", sid, e)
		}
		return nil
	case "logoff":
		sid, err := interactiveSessionID()
		if err != nil {
			return err
		}
		// bWait = FALSE: the reply goes back now; the logoff completes on
		// its own and a stuck application cannot hold the request open.
		if r, _, e := procWTSLogoffSession.Call(wtsCurrentServerHandle, uintptr(sid), 0); r == 0 {
			return fmt.Errorf("log off session %d: %w", sid, e)
		}
		return nil
	}
	return fmt.Errorf("unknown power action %q", p.Action)
}

// runShutdown runs shutdown.exe with args. When a shutdown is already
// scheduled it fails with error 1190; the pending one is cancelled and the
// new request applied so an operator can always shorten or extend a
// countdown instead of being told no.
func runShutdown(ctx context.Context, args []string) error {
	_, stderr, err := runHidden(ctx, "shutdown.exe", args...)
	if err == nil {
		return nil
	}
	if strings.Contains(stderr, "1190") || strings.Contains(err.Error(), "1190") {
		if _, _, aerr := runHidden(ctx, "shutdown.exe", "/a"); aerr == nil {
			if _, stderr, err = runHidden(ctx, "shutdown.exe", args...); err == nil {
				return nil
			}
		}
	}
	return fmt.Errorf("shutdown.exe: %s", winFirstLine(stderr, err.Error()))
}

// interactiveSessionID picks the session lock/logoff should act on: the
// console session when a user owns it, otherwise the first Active session
// with a user (an RDP-only server), otherwise the bare console id.
func interactiveSessionID() (uint32, error) {
	console := windows.WTSGetActiveConsoleSessionId()
	if sessions, err := wtsSessions(); err == nil {
		for _, s := range sessions {
			if s.id == console && s.user != "" {
				return s.id, nil
			}
		}
		for _, s := range sessions {
			if s.state == windows.WTSActive && s.user != "" {
				return s.id, nil
			}
		}
	}
	if console != wtsNoSession {
		return console, nil
	}
	return 0, errors.New("no interactive user session on this device")
}
