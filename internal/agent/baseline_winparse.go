package agent

// Pure parsers for the Windows tools the baseline kinds call. They carry no
// build constraint on purpose, for the same reason winparse.go does not: the
// Linux box that cross-compiles the Windows agent then tests these shapes
// instead of only type-checking them.

import (
	"encoding/json"
	"strings"
)

// winValidServiceName is the same rule serviceAction enforces: a Win32
// service name, non-empty, at most 256 characters and with no path separator
// in it.
func winValidServiceName(name string) bool {
	name = strings.TrimSpace(name)
	return name != "" && len(name) <= 256 && !strings.ContainsAny(name, `/\`)
}

// winStartTypeOK compares the wanted start type with the observed one, and is
// where A37 lives.
//
// "auto" matches auto_delayed as well: a delayed-start service IS automatic,
// and a check that called it drift would have the agent clear a deliberate
// delayed-start flag on every pass.
//
// "boot", "system" and an unreadable start type satisfy NOTHING - not even
// the "any" a check defaults to. They are how a driver starts, the SCM is the
// only thing that should be choosing them, and the agent reports the real
// observed string rather than quietly calling a boot-start driver compliant.
// The fix refuses to change them.
func winStartTypeOK(want, got string) bool {
	switch got {
	case "boot", "system", "unknown", "":
		return false
	}
	switch want {
	case "", "any":
		return true
	case "auto":
		return got == "auto" || got == "auto_delayed"
	}
	return want == got
}

// blWinFirewallProfiles reads "netsh advfirewall show allprofiles". The
// output is a block per profile, each with a "State ON|OFF" line; the words
// are localised on a non-English install, the block order is not, so the
// parser keys on the profile heading and the State label together and
// reports what it could not read rather than guessing.
func blWinFirewallProfiles(out string) (map[string]bool, bool) {
	profiles := map[string]bool{}
	current := ""
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "domain profile"):
			current = "domain"
			continue
		case strings.HasPrefix(lower, "private profile"):
			current = "private"
			continue
		case strings.HasPrefix(lower, "public profile"):
			current = "public"
			continue
		}
		if current == "" || !strings.HasPrefix(lower, "state") {
			continue
		}
		v := strings.TrimSpace(strings.ToUpper(strings.TrimPrefix(line, line[:len("State")])))
		switch {
		case strings.HasPrefix(v, "ON"):
			profiles[current] = true
		case strings.HasPrefix(v, "OFF"):
			profiles[current] = false
		default:
			continue
		}
		current = ""
	}
	_, d := profiles["domain"]
	_, p := profiles["private"]
	_, u := profiles["public"]
	return profiles, d && p && u
}

// blWinFirewallLabel renders the three profiles in a fixed order, which is
// what the observed column shows: "domain/private/public: on/on/off".
func blWinFirewallLabel(p map[string]bool) string {
	states := make([]string, 0, 3)
	for _, k := range []string{"domain", "private", "public"} {
		if v, ok := p[k]; ok {
			states = append(states, onOff(v))
		} else {
			states = append(states, "unknown")
		}
	}
	return "domain/private/public: " + strings.Join(states, "/")
}

// blWinTimeSource reads the "Source:" line of "w32tm /query /status". The
// two pseudo-sources mean the clock is free-running, which is the opposite of
// synchronised however healthy the service looks.
func blWinTimeSource(out string) (source string, synced bool) {
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		k, v, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "source") {
			continue
		}
		source = strings.TrimSpace(v)
		lower := strings.ToLower(source)
		if source == "" || strings.Contains(lower, "local cmos clock") || strings.Contains(lower, "free-running") {
			return source, false
		}
		return source, true
	}
	return "", false
}

// blWinFeatureState reads the JSON one-liner the feature script prints.
func blWinFeatureState(out string) (string, bool) {
	start := strings.Index(out, "{")
	end := strings.LastIndex(out, "}")
	if start < 0 || end <= start {
		return "", false
	}
	var v struct {
		Name  string `json:"name"`
		State string `json:"state"`
	}
	if err := json.Unmarshal([]byte(out[start:end+1]), &v); err != nil {
		return "", false
	}
	if v.State == "" {
		return "", false
	}
	return v.State, true
}

// blWinFeatureEnabled maps a DISM feature state onto the two states a check
// can ask for. EnablePending and DisablePending are the post-fix,
// pre-restart states and are deliberately reported as not yet there.
func blWinFeatureEnabled(state string) bool {
	return strings.EqualFold(strings.TrimSpace(state), "Enabled")
}

// blWinWingetList reads "winget list --id <id> --exact". The table is a
// header, a dashed rule and one row per match; "No installed package found"
// is the empty answer and is not an error.
func blWinWingetList(out, id string) (found bool, version string) {
	started := false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !started {
			if strings.HasPrefix(trimmed, "----") || strings.HasPrefix(trimmed, "——") {
				started = true
			}
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		for i, f := range fields {
			if !strings.EqualFold(f, id) {
				continue
			}
			if i+1 < len(fields) {
				return true, fields[i+1]
			}
			return true, ""
		}
	}
	return false, ""
}
