package agent

import (
	"log/slog"
	"strconv"
)

const meshRuleName = "HomelabRMM Subnet Cache"

// meshFirewall adds or removes the inbound rules that let the subnet reach the
// leader: TCP for HTTPS and UDP for HTTP/3, from the local subnet only. It is
// best effort and logged, because a device behind a managed firewall policy
// can still lead for itself and the members fall back to the origin when they
// cannot reach it. netsh is started hidden like every other child process.
func meshFirewall(add bool, port int) {
	ctx, cancel := meshFirewallCtx()
	defer cancel()
	// Always clear first: an add after a crash must not stack duplicates, and
	// a remove must find whatever an earlier run left.
	for _, proto := range []string{"TCP", "UDP"} {
		_, _, _ = runHidden(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+meshRuleName+" "+proto)
	}
	if !add {
		slog.Info("the subnet cache firewall rules were removed")
		return
	}
	for _, proto := range []string{"TCP", "UDP"} {
		_, stderr, err := runHidden(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
			"name="+meshRuleName+" "+proto, "dir=in", "action=allow", "protocol="+proto,
			"localport="+strconv.Itoa(port), "remoteip=LocalSubnet", "profile=any")
		if err != nil {
			slog.Warn("could not add the subnet cache firewall rule; members on other hosts may not reach this leader", "protocol", proto, "port", port, "err", err, "output", stderr)
			continue
		}
		slog.Info("the subnet cache firewall rule was added", "protocol", proto, "port", port)
	}
}
