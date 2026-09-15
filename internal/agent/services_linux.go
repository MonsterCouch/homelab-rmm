//go:build linux

package agent

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

const systemctlTimeout = 30 * time.Second

var errNoSystemd = errors.New("systemd is not available on this device")

// listServices merges "list-unit-files" (every installed unit and its start
// type) with "list-units --all" (state and description of the loaded ones)
// and fetches MainPID for the running units in a single "show" call.
func listServices() ([]protocol.Service, error) {
	if !hasCmd("systemctl") {
		return nil, errNoSystemd
	}
	filesOut, filesErr, _, err := runCmdTimeout(systemctlTimeout, "systemctl", "list-unit-files", "--type=service", "--no-pager", "--plain", "--no-legend")
	if err != nil {
		return nil, fmt.Errorf("systemctl list-unit-files: %w (%s)", err, firstLine(filesErr))
	}
	unitsOut, unitsErr, _, err := runCmdTimeout(systemctlTimeout, "systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend")
	if err != nil {
		// No bus means no running systemd (a container, or a chroot): the
		// unit files alone say nothing about state, so this is an error.
		return nil, fmt.Errorf("systemctl list-units: %w (%s)", err, firstLine(unitsErr))
	}
	fileStates := parseListUnitFiles(filesOut)
	byName := map[string]*protocol.Service{}
	var order []string
	for _, r := range parseListUnits(unitsOut) {
		if r.Load == "not-found" {
			continue
		}
		s := &protocol.Service{
			Name:        r.Unit,
			DisplayName: r.Description,
			State:       unitState(r.Active, r.Sub),
			StartType:   unitStartType(fileStates[r.Unit]),
			Description: r.Description,
		}
		if r.Load == "masked" {
			s.StartType = "disabled"
		}
		if s.DisplayName == "" {
			s.DisplayName = r.Unit
		}
		byName[r.Unit] = s
		order = append(order, r.Unit)
	}
	// Units that are installed but not loaded (never started since boot and
	// nothing depends on them) are stopped; templates and aliases are not
	// startable by themselves and are left out.
	for unit, state := range fileStates {
		if _, ok := byName[unit]; ok || state == "alias" || strings.HasSuffix(unit, "@.service") {
			continue
		}
		s := &protocol.Service{Name: unit, DisplayName: unit, State: "stopped", StartType: unitStartType(state)}
		byName[unit] = s
		order = append(order, unit)
	}
	var running []string
	for _, n := range order {
		if byName[n].State == "running" {
			running = append(running, n)
		}
	}
	for _, blk := range showUnits(running, "Id", "MainPID", "Description") {
		if s := byName[blk["Id"]]; s != nil {
			if pid, err := parseInt(blk["MainPID"]); err == nil && pid > 0 {
				s.PID = pid
			}
			if d := blk["Description"]; d != "" {
				s.DisplayName, s.Description = d, d
			}
		}
	}
	out := make([]protocol.Service, 0, len(order))
	for _, n := range order {
		out = append(out, *byName[n])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// showUnits runs "systemctl show" for the given units in batches and returns
// one property map per unit. Batching keeps the argument list well under
// ARG_MAX on hosts with thousands of units.
func showUnits(units []string, props ...string) []map[string]string {
	var out []map[string]string
	const batch = 200
	for i := 0; i < len(units); i += batch {
		end := i + batch
		if end > len(units) {
			end = len(units)
		}
		args := []string{"show", "--no-pager", "--property=" + strings.Join(props, ","), "--"}
		args = append(args, units[i:end]...)
		text, _, _, err := runCmdTimeout(systemctlTimeout, "systemctl", args...)
		if err != nil && text == "" {
			continue
		}
		out = append(out, parseShowBlocks(text)...)
	}
	return out
}

// serviceAction runs one systemctl verb and returns the unit's state after
// it. "manual" maps to disable: a disabled unit is still startable by hand
// or by a dependency, which is what Windows means by manual start.
func serviceAction(name, action string) (*protocol.Service, error) {
	if !validUnitName(name) {
		return nil, fmt.Errorf("invalid service name %q", name)
	}
	if !hasCmd("systemctl") {
		return nil, errNoSystemd
	}
	var verb string
	switch action {
	case "start", "stop", "restart", "enable", "disable":
		verb = action
	case "manual":
		verb = "disable"
	default:
		return nil, fmt.Errorf("unknown service action %q", action)
	}
	// Without --no-block systemctl waits for the job, so a unit that dies on
	// start is reported here as an error rather than silently "stopped".
	// --no-ask-password: an agent running unprivileged gets a clean polkit
	// refusal instead of hanging on a prompt nobody can answer.
	_, stderr, _, err := runCmdTimeout(2*time.Minute, "systemctl", "--no-ask-password", verb, "--", name)
	if err != nil {
		return nil, fmt.Errorf("systemctl %s %s: %s", verb, name, orFirst(firstLine(stderr), err.Error()))
	}
	return serviceInfo(name)
}

// serviceInfo builds a Service from a single "systemctl show".
func serviceInfo(name string) (*protocol.Service, error) {
	blocks := showUnits([]string{name}, "Id", "MainPID", "Description", "ActiveState", "SubState", "UnitFileState", "LoadState")
	if len(blocks) == 0 {
		return nil, fmt.Errorf("systemctl show %s: no output", name)
	}
	s := serviceFromShow(blocks[0])
	if s.Name == "" {
		s.Name = name
	}
	if blocks[0]["LoadState"] == "not-found" {
		return nil, fmt.Errorf("no such service %q", name)
	}
	return &s, nil
}

// serviceState answers the monitored-services probe on every metrics tick,
// so it is a single cheap "is-active" whose exit code is not an error.
func serviceState(name string) string {
	if !validUnitName(name) || !hasCmd("systemctl") {
		return "unknown"
	}
	out, _, _, err := runCmdTimeout(10*time.Second, "systemctl", "is-active", "--", name)
	if err != nil && strings.TrimSpace(out) == "" {
		return "unknown"
	}
	return isActiveState(out)
}

func orFirst(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func parseInt(s string) (int, error) {
	n := 0
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a number: %q", s)
		}
		n = n*10 + int(r-'0')
		if n > 1<<30 {
			return 0, errors.New("out of range")
		}
	}
	return n, nil
}
