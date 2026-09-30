//go:build windows

package agent

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

const isolationRulePrefix = "HomelabRMM-Isolate-"

func (a *Agent) handleIsolate(in protocol.DeviceIsolate) (any, error) {
	if !in.Isolate {
		if err := releaseWindowsIsolation(); err != nil {
			return nil, err
		}
		slog.Info("device released from network isolation")
		return protocol.DeviceIsolateResult{
			Isolated: false,
			Message:  "Device released from network isolation",
		}, nil
	}

	if err := applyWindowsIsolation(in.ServerHost, in.ServerPort); err != nil {
		return nil, err
	}

	slog.Warn("device isolated from network; RMM communication preserved", "server", in.ServerHost, "port", in.ServerPort)
	return protocol.DeviceIsolateResult{
		Isolated: true,
		Message:  "Device isolated from network (RMM channel preserved)",
	}, nil
}

func removeRuleByName(name string) {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s", name))
	_ = cmd.Run()
}

func releaseWindowsIsolation() error {
	// 1. Remove all isolation allow rules
	rules := []string{
		isolationRulePrefix + "RMM-Out",
		isolationRulePrefix + "RMM-In",
		isolationRulePrefix + "Loopback-Out",
		isolationRulePrefix + "Loopback-In",
		isolationRulePrefix + "DNS-Out",
	}
	for _, r := range rules {
		removeRuleByName(r)
	}

	// 2. Restore default firewall policy: block inbound, allow outbound
	cmd := exec.Command("netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("restore firewall policy failed: %v: %s", err, string(out))
	}
	return nil
}

func applyWindowsIsolation(serverHost string, serverPort int) error {
	// First clean up any pre-existing rules
	_ = releaseWindowsIsolation()

	if serverPort <= 0 {
		serverPort = 443
	}

	// Resolve server IP addresses
	var remoteIPs []string
	if serverHost != "" {
		if ips, err := net.LookupIP(serverHost); err == nil && len(ips) > 0 {
			for _, ip := range ips {
				remoteIPs = append(remoteIPs, ip.String())
			}
		} else {
			// Fallback to verbatim host if it's already an IP
			remoteIPs = append(remoteIPs, serverHost)
		}
	}

	remoteIPStr := strings.Join(remoteIPs, ",")
	if remoteIPStr == "" {
		remoteIPStr = "any"
	}

	portStr := strconv.Itoa(serverPort)

	// 1. Allow Outbound to RMM Server
	cmdRmmOut := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%sRMM-Out", isolationRulePrefix),
		"dir=out", "action=allow", "protocol=TCP",
		fmt.Sprintf("remoteip=%s", remoteIPStr),
		fmt.Sprintf("remoteport=%s", portStr),
	)
	if out, err := cmdRmmOut.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add RMM allow rule: %v: %s", err, string(out))
	}

	// 2. Allow Inbound from RMM Server
	cmdRmmIn := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%sRMM-In", isolationRulePrefix),
		"dir=in", "action=allow", "protocol=TCP",
		fmt.Sprintf("remoteip=%s", remoteIPStr),
	)
	_ = cmdRmmIn.Run()

	// 3. Allow Loopback
	cmdLoopOut := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%sLoopback-Out", isolationRulePrefix),
		"dir=out", "action=allow", "remoteip=127.0.0.1,::1",
	)
	_ = cmdLoopOut.Run()

	cmdLoopIn := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%sLoopback-In", isolationRulePrefix),
		"dir=in", "action=allow", "remoteip=127.0.0.1,::1",
	)
	_ = cmdLoopIn.Run()

	// 4. Allow DNS so host can re-resolve RMM hostname if needed
	cmdDNS := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%sDNS-Out", isolationRulePrefix),
		"dir=out", "action=allow", "protocol=UDP", "remoteport=53",
	)
	_ = cmdDNS.Run()

	// 5. Enforce default drop: block all inbound and outbound traffic
	cmdPolicy := exec.Command("netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound")
	if out, err := cmdPolicy.CombinedOutput(); err != nil {
		// Roll back on failure
		_ = releaseWindowsIsolation()
		return fmt.Errorf("failed to enforce block policy: %v: %s", err, string(out))
	}

	return nil
}
