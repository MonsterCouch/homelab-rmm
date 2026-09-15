package agent

// The decision half of the `group_members` kind, kept free of any OS call so
// it is unit-tested on every platform. This is the single most dangerous
// check in the product - it removes accounts from administrative groups - so
// the rules that say "no" live in one pure function that a test can drive
// with a group it must refuse to empty.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MonsterCouch/homelab-rmm/internal/baselines"
)

// criticalGroups may never be emptied by a remediation. Removing the last
// member of one of these is indistinguishable from locking every
// administrator out of the device.
var criticalGroups = map[string]bool{
	"administrators": true,
	"sudo":           true,
	"wheel":          true,
	"adm":            true,
	"root":           true,
}

// groupGuard is what the device knows that the planner must not guess: which
// names are the built-in administrator or root, which account the agent
// itself runs as, and which members hold the group as their primary group and
// therefore cannot be removed from it at all.
type groupGuard struct {
	Builtin []string // well-known administrator (RID 500) or root / uid 0
	Self    []string // the account the agent service runs as
	Primary []string // members whose primary group this is (unix)
}

// groupPlan is the outcome: what drifted, what will actually be removed and
// what was deliberately left alone.
type groupPlan struct {
	Extra   []string          // observed members that are not allowed
	Remove  []string          // the subset of Extra that may be removed
	Kept    []string          // extras that must not be removed
	Reasons map[string]string // Kept -> why
	Missing []string          // allowed members that are absent (exact mode)
	Refusal string            // non-empty: apply nothing, report an error
}

// Drifted reports whether the observed membership violates the check.
func (p groupPlan) Drifted(mode string) bool {
	if len(p.Extra) > 0 {
		return true
	}
	return mode == "exact" && len(p.Missing) > 0
}

// planGroupMembers works out what a `group_members` check means for one
// observed membership list.
//
// mode `subset` (the default) says the observed members must all be allowed;
// extras are drift and may be removed. mode `exact` says membership must
// equal the allowed list: extras are still removed but a MISSING member is
// never added, so an exact check with a missing member stays failing - the
// console has to say so beside the mode selector.
func planGroupMembers(group string, observed []string, p baselines.GroupMembersParams, g groupGuard) groupPlan {
	plan := groupPlan{Reasons: map[string]string{}}
	allowed := lowerSet(p.Allowed)
	seen := map[string]bool{}
	for _, m := range observed {
		key := strings.ToLower(strings.TrimSpace(m))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		if allowed[key] {
			continue
		}
		plan.Extra = append(plan.Extra, m)
		switch {
		case isDomainPrincipal(m) && !p.AllowDomain:
			plan.Kept = append(plan.Kept, m)
			plan.Reasons[m] = "a domain principal is reported as drift, never removed, unless allow_domain is set"
		case inFold(g.Builtin, m):
			plan.Kept = append(plan.Kept, m)
			plan.Reasons[m] = "the built-in administrator account is never removed"
		case inFold(g.Self, m):
			plan.Kept = append(plan.Kept, m)
			plan.Reasons[m] = "this is the account the agent runs as"
		case inFold(g.Primary, m):
			plan.Kept = append(plan.Kept, m)
			plan.Reasons[m] = "this group is the account's primary group and cannot be removed here"
		case !removableName(m):
			plan.Kept = append(plan.Kept, m)
			plan.Reasons[m] = "this account name cannot be passed safely to a removal command and was left alone"
		default:
			plan.Remove = append(plan.Remove, m)
		}
	}
	if p.EffectiveMode() == "exact" {
		for _, a := range p.Allowed {
			if !seen[strings.ToLower(strings.TrimSpace(a))] {
				plan.Missing = append(plan.Missing, a)
			}
		}
	}
	if criticalGroups[strings.ToLower(group)] && len(plan.Remove) > 0 && len(seen) == len(plan.Remove) {
		plan.Refusal = fmt.Sprintf("refusing to empty %s", group)
		plan.Remove = nil
	}
	sort.Strings(plan.Remove)
	return plan
}

// groupObservedLabel renders the membership for the observed column. An
// account can reach the list twice - named in /etc/group AND holding the
// group as its primary - and "alice, alice" reads like a bug to whoever is
// looking at the drift.
func groupObservedLabel(members []string) string {
	seen := map[string]bool{}
	out := make([]string, 0, len(members))
	for _, m := range members {
		key := strings.ToLower(strings.TrimSpace(m))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, strings.TrimSpace(m))
	}
	if len(out) == 0 {
		return "no members"
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// groupExpectedLabel renders the check for the expected column.
func groupExpectedLabel(p baselines.GroupMembersParams) string {
	if len(p.Allowed) == 0 {
		if p.EffectiveMode() == "exact" {
			return "no members"
		}
		return "no members beyond the allowed list (which is empty)"
	}
	out := append([]string(nil), p.Allowed...)
	sort.Strings(out)
	return p.EffectiveMode() + ": " + strings.Join(out, ", ")
}

// groupDriftDetail says exactly what is wrong and what will not be touched.
func groupDriftDetail(plan groupPlan, p baselines.GroupMembersParams) string {
	var parts []string
	if len(plan.Extra) > 0 {
		parts = append(parts, "not allowed: "+strings.Join(plan.Extra, ", "))
	}
	if len(plan.Missing) > 0 {
		parts = append(parts, "missing (a group_members check never adds members): "+strings.Join(plan.Missing, ", "))
	}
	for _, k := range plan.Kept {
		parts = append(parts, k+": "+plan.Reasons[k])
	}
	if plan.Refusal != "" {
		parts = append(parts, plan.Refusal)
	}
	return strings.Join(parts, "; ")
}

// isDomainPrincipal reports whether a name belongs to a domain rather than to
// this machine. DOMAIN\user and user@domain are the two spellings Windows
// hands back; a local account never contains either character.
func isDomainPrincipal(name string) bool {
	return strings.ContainsAny(name, `\@`)
}

// removableName reports whether an observed member name can be handed to a
// removal command as an argument. The name comes from the DEVICE (getent, net
// localgroup), not from the check, so it has never been through the server's
// validator: "gpasswd -d -x sudo" and "net localgroup Users /x /delete" are
// what a name beginning with a dash or a slash would turn into, and neither
// tool has a separator the agent can rely on to stop it. Such a name is
// reported as drift and left alone rather than removed by guesswork.
func removableName(name string) bool {
	n := strings.TrimSpace(name)
	if n == "" || len(n) > 256 {
		return false
	}
	if strings.HasPrefix(n, "-") || strings.HasPrefix(n, "/") {
		return false
	}
	for _, r := range n {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func lowerSet(in []string) map[string]bool {
	out := map[string]bool{}
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out[strings.ToLower(s)] = true
		}
	}
	return out
}

func inFold(list []string, name string) bool {
	for _, s := range list {
		if strings.EqualFold(strings.TrimSpace(s), strings.TrimSpace(name)) {
			return true
		}
	}
	return false
}

// ---- pure parsers the platform files feed ----

// parseGroupLine reads one "group:x:gid:member,member" line, as /etc/group
// and "getent group" both produce it.
func parseGroupLine(line string) (name, gid string, members []string, ok bool) {
	line = strings.TrimSpace(strings.TrimRight(line, "\r"))
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", nil, false
	}
	f := strings.Split(line, ":")
	if len(f) < 3 {
		return "", "", nil, false
	}
	name, gid = f[0], f[2]
	if len(f) >= 4 {
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				members = append(members, m)
			}
		}
	}
	return name, gid, members, name != ""
}

// parsePasswdPrimary lists the accounts in /etc/passwd whose primary group is
// gid. They appear in no /etc/group member list but are members all the same,
// and no tool can remove them from it.
func parsePasswdPrimary(passwd, gid string) []string {
	var out []string
	if gid == "" {
		return nil
	}
	for _, line := range strings.Split(passwd, "\n") {
		f := strings.Split(strings.TrimSpace(strings.TrimRight(line, "\r")), ":")
		if len(f) < 4 || f[0] == "" {
			continue
		}
		if f[3] == gid {
			out = append(out, f[0])
		}
	}
	return out
}

// parseNetLocalGroup pulls the member names out of "net localgroup <name>".
// The output is a banner, a dashed rule, one member per line and a trailing
// "The command completed successfully." - the words are localised, the dashed
// rule is not, so the rule is what the parser keys on.
func parseNetLocalGroup(out string) []string {
	var (
		members []string
		started bool
	)
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if !started {
			if strings.HasPrefix(trimmed, "----") {
				started = true
			}
			continue
		}
		if trimmed == "" {
			continue
		}
		// The closing line is the only one that ends with a full stop and
		// carries no account characters worth keeping.
		if strings.HasSuffix(trimmed, ".") && strings.Contains(trimmed, " ") {
			continue
		}
		members = append(members, trimmed)
	}
	return members
}
