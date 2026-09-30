//go:build linux

package agent

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strconv"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

func (a *Agent) handleIsolate(in protocol.DeviceIsolate) (any, error) {
	if !in.Isolate {
		if err := releaseLinuxIsolation(); err != nil {
			return nil, err
		}
		slog.Info("device released from network isolation")
		return protocol.DeviceIsolateResult{
			Isolated: false,
			Message:  "Device released from network isolation",
		}, nil
	}

	if err := applyLinuxIsolation(in.ServerHost, in.ServerPort); err != nil {
		return nil, err
	}

	slog.Warn("device isolated from network; RMM communication preserved", "server", in.ServerHost, "port", in.ServerPort)
	return protocol.DeviceIsolateResult{
		Isolated: true,
		Message:  "Device isolated from network (RMM channel preserved)",
	}, nil
}

func releaseLinuxIsolation() error {
	_ = exec.Command("iptables", "-D", "INPUT", "-j", "RMM_ISOLATE").Run()
	_ = exec.Command("iptables", "-D", "OUTPUT", "-j", "RMM_ISOLATE").Run()
	_ = exec.Command("iptables", "-F", "RMM_ISOLATE").Run()
	_ = exec.Command("iptables", "-X", "RMM_ISOLATE").Run()
	return nil
}

func applyLinuxIsolation(serverHost string, serverPort int) error {
	_ = releaseLinuxIsolation()

	if serverPort <= 0 {
		serverPort = 443
	}

	var remoteIP string
	if serverHost != "" {
		if ips, err := net.LookupIP(serverHost); err == nil && len(ips) > 0 {
			remoteIP = ips[0].String()
		} else {
			remoteIP = serverHost
		}
	}

	// Create custom chain
	if err := exec.Command("iptables", "-N", "RMM_ISOLATE").Run(); err != nil {
		return fmt.Errorf("failed to create iptables chain: %w", err)
	}

	// Rules in chain
	_ = exec.Command("iptables", "-A", "RMM_ISOLATE", "-i", "lo", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-A", "RMM_ISOLATE", "-o", "lo", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-A", "RMM_ISOLATE", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-A", "RMM_ISOLATE", "-p", "udp", "--dport", "53", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-A", "RMM_ISOLATE", "-p", "udp", "--dport", "67:68", "--sport", "67:68", "-j", "ACCEPT").Run()

	if remoteIP != "" {
		portStr := strconv.Itoa(serverPort)
		_ = exec.Command("iptables", "-A", "RMM_ISOLATE", "-p", "tcp", "-d", remoteIP, "--dport", portStr, "-j", "ACCEPT").Run()
	}

	_ = exec.Command("iptables", "-A", "RMM_ISOLATE", "-j", "DROP").Run()

	// Insert jump to chain at top of INPUT and OUTPUT
	if err := exec.Command("iptables", "-I", "INPUT", "1", "-j", "RMM_ISOLATE").Run(); err != nil {
		_ = releaseLinuxIsolation()
		return fmt.Errorf("failed to insert input rule: %w", err)
	}
	if err := exec.Command("iptables", "-I", "OUTPUT", "1", "-j", "RMM_ISOLATE").Run(); err != nil {
		_ = releaseLinuxIsolation()
		return fmt.Errorf("failed to insert output rule: %w", err)
	}

	return nil
}
