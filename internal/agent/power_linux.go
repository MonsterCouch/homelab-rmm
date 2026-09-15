//go:build linux

package agent

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

const powerTimeout = 30 * time.Second

// maxPowerDelay bounds Delay (seconds). A huge value would overflow the
// Duration arithmetic (a wrapped negative timer fires at once, the opposite
// of what was asked) or park a reboot years out; a week is already absurd.
const maxPowerDelay = 7 * 24 * 60 * 60

// clampDelay normalises a requested delay in seconds.
func clampDelay(d int) int {
	if d < 0 {
		return 0
	}
	if d > maxPowerDelay {
		return maxPowerDelay
	}
	return d
}

// powerAction: reboot and shutdown go through shutdown(8) so logged-in
// users get the wall message and the delay is honoured by the OS itself;
// lock and logoff go through logind.
func powerAction(p protocol.Power) error {
	delay := clampDelay(p.Delay)
	msg := strings.TrimSpace(p.Message)
	if msg == "" {
		msg = "Requested by the RMM"
	}
	switch strings.ToLower(strings.TrimSpace(p.Action)) {
	case "reboot":
		return scheduleShutdown("-r", delay, msg)
	case "shutdown", "poweroff", "halt":
		return scheduleShutdown("-h", delay, msg)
	case "lock":
		if !hasCmd("loginctl") {
			return errors.New("loginctl is not available; cannot lock sessions")
		}
		_, stderr, _, err := runCmdTimeout(powerTimeout, "loginctl", "lock-sessions")
		if err != nil {
			return fmt.Errorf("loginctl lock-sessions: %s", orFirst(firstLine(stderr), err.Error()))
		}
		return nil
	case "logoff", "logout":
		return logoffGraphicalSessions(delay)
	}
	return fmt.Errorf("unknown power action %q", p.Action)
}

// scheduleShutdown runs "shutdown <flag> +M <msg>" for delays of a minute or
// more (shutdown only counts minutes) and "now" otherwise. A short non-zero
// delay is waited out here first so the reply still reaches the server and
// the operator's countdown means something.
func scheduleShutdown(flag string, delay int, msg string) error {
	if delay >= 60 {
		mins := (delay + 59) / 60
		if hasCmd("shutdown") {
			_, stderr, _, err := runCmdTimeout(powerTimeout, "shutdown", flag, "+"+strconv.Itoa(mins), msg)
			if err == nil {
				return nil
			}
			slog.Warn("shutdown +m failed, falling back to a timer", "err", err, "stderr", firstLine(stderr))
		}
	}
	run := func() error {
		if hasCmd("shutdown") {
			_, stderr, _, err := runCmdTimeout(powerTimeout, "shutdown", flag, "now", msg)
			if err == nil {
				return nil
			}
			slog.Warn("shutdown now failed, trying systemctl", "err", err, "stderr", firstLine(stderr))
		}
		verb := "reboot"
		if flag == "-h" {
			verb = "poweroff"
		}
		if hasCmd("systemctl") {
			// --no-ask-password: a non-root agent must fail fast, not sit on
			// a polkit prompt nobody can answer.
			_, stderr, _, err := runCmdTimeout(powerTimeout, "systemctl", "--no-ask-password", verb)
			if err != nil {
				return fmt.Errorf("systemctl %s: %s", verb, orFirst(firstLine(stderr), err.Error()))
			}
			return nil
		}
		return fmt.Errorf("neither shutdown nor systemctl is available to %s", verb)
	}
	if delay > 0 {
		time.AfterFunc(time.Duration(delay)*time.Second, func() {
			if err := run(); err != nil {
				slog.Error("scheduled power action failed", "err", err)
			}
		})
		return nil
	}
	return run()
}

// logoffGraphicalSessions terminates every active x11/wayland/mir session
// known to logind. SSH and tty sessions are left alone: "log off" on the
// RMM means the desktop user, and killing an admin's SSH session by
// accident is worse than doing nothing.
func logoffGraphicalSessions(delay int) error {
	if !hasCmd("loginctl") {
		return errors.New("loginctl is not available; cannot log off sessions")
	}
	out, stderr, _, err := runCmdTimeout(powerTimeout, "loginctl", "list-sessions", "--no-legend")
	if err != nil {
		return fmt.Errorf("loginctl list-sessions: %s", orFirst(firstLine(stderr), err.Error()))
	}
	ids := parseLoginctlSessions(out)
	if len(ids) == 0 {
		return errors.New("no login sessions found")
	}
	args := append([]string{"show-session", "--property=Id,Type,State,Class", "--"}, ids...)
	shown, stderr, _, err := runCmdTimeout(powerTimeout, "loginctl", args...)
	if err != nil && shown == "" {
		return fmt.Errorf("loginctl show-session: %s", orFirst(firstLine(stderr), err.Error()))
	}
	var targets []string
	for _, b := range parseShowBlocks(shown) {
		switch b["Type"] {
		case "x11", "wayland", "mir":
		default:
			continue
		}
		if b["Class"] != "" && b["Class"] != "user" {
			continue
		}
		if b["State"] == "closing" {
			continue
		}
		if id := b["Id"]; id != "" {
			targets = append(targets, id)
		}
	}
	if len(targets) == 0 {
		return errors.New("no graphical sessions to log off")
	}
	terminate := func() error {
		var errs []string
		for _, id := range targets {
			if _, stderr, _, err := runCmdTimeout(powerTimeout, "loginctl", "terminate-session", "--", id); err != nil {
				errs = append(errs, id+": "+orFirst(firstLine(stderr), err.Error()))
			}
		}
		if len(errs) > 0 {
			return errors.New("terminate-session: " + strings.Join(errs, "; "))
		}
		return nil
	}
	if delay > 0 {
		time.AfterFunc(time.Duration(delay)*time.Second, func() {
			if err := terminate(); err != nil {
				slog.Error("scheduled logoff failed", "err", err)
			}
		})
		return nil
	}
	return terminate()
}
