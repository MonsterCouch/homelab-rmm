//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// powerAction performs reboot|shutdown (through shutdown.exe, which shows
// the countdown and message to logged-in users) and lock|logoff (through
// the terminal-services API on the interactive session). The poweroff/halt
// and logout aliases are accepted here exactly as the server and the Linux
// agent accept them. Delay applies to reboot, shutdown and logoff; lock is
// immediate, as it is on Linux.
func powerAction(p protocol.Power) error {
	switch action := winPowerAction(p.Action); action {
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
		// Resolve the session now so "no interactive user on this device" is
		// answered as an error instead of arriving as a silent no-op minutes
		// later; the delayed run resolves it again, because the session that
		// is current when the grace period ends is the one to log off.
		if _, err := interactiveSessionID(); err != nil {
			return err
		}
		// delay_sec is the same "warn the user first" grace period the Linux
		// agent honours (power_linux.go logoffGraphicalSessions): answer the
		// server now and log off when it expires.
		if delay := winClampPowerDelay(p.Delay); delay > 0 {
			time.AfterFunc(time.Duration(delay)*time.Second, func() {
				if err := logoffInteractiveSession(); err != nil {
					slog.Error("scheduled logoff failed", "err", err)
				}
			})
			return nil
		}
		return logoffInteractiveSession()
	}
	return fmt.Errorf("unknown power action %q", p.Action)
}

// logoffInteractiveSession logs off whichever session is interactive now.
func logoffInteractiveSession() error {
	sid, err := interactiveSessionID()
	if err != nil {
		return err
	}
	// bWait = FALSE: the reply goes back now; the logoff completes on its own
	// and a stuck application cannot hold the request open.
	if r, _, e := procWTSLogoffSession.Call(wtsCurrentServerHandle, uintptr(sid), 0); r == 0 {
		return fmt.Errorf("log off session %d: %w", sid, e)
	}
	return nil
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
