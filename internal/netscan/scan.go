package netscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type HostResult struct {
	IP            string `json:"ip"`
	MAC           string `json:"mac"`
	Hostname      string `json:"hostname"`
	Vendor        string `json:"vendor"`
	OS            string `json:"os"`
	DeviceType    string `json:"device_type"`
	OpenPorts     []int  `json:"open_ports"`
	SNMPEnabled   bool   `json:"snmp_enabled"`
	SNMPSysName   string `json:"snmp_sys_name"`
	SNMPSysDescr  string `json:"snmp_sys_descr"`
	SNMPSysUpTime int64  `json:"snmp_sys_uptime"`
}

// GenerateSubnetIPs expands a CIDR notation into a slice of target IP strings.
// Limits IPv4 ranges to /22 (1024 addresses max) to prevent denial of service.
func GenerateSubnetIPs(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	if (!ip.IsPrivate() && !ip.IsLoopback()) || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return nil, errors.New("subnet must be a private or loopback IP range; public and link-local ranges are rejected")
	}

	ones, bits := ipnet.Mask.Size()
	if bits == 32 && ones < 22 {
		return nil, fmt.Errorf("subnet too large: /%d exceeds maximum allowed range of /22 (1024 addresses)", ones)
	}
	if bits == 128 && ones < 120 {
		return nil, fmt.Errorf("subnet too large: /%d exceeds maximum allowed range of /120", ones)
	}

	var ips []string
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); incIP(cur) {
		ips = append(ips, cur.String())
		if len(ips) > 1024 {
			break
		}
	}
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ProbeHost tests common TCP ports and SNMP on a target IP.
func ProbeHost(ip string) *HostResult {
	portsToTest := []int{22, 80, 443, 445, 3389, 9100, 8080}
	var open []int

	for _, p := range portsToTest {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, p), 150*time.Millisecond)
		if err == nil {
			conn.Close()
			open = append(open, p)
		}
	}

	// Try SNMP
	snmpRes, snmpErr := QuerySNMP(ip, "public", 400*time.Millisecond)
	snmpActive := snmpErr == nil && snmpRes != nil

	if len(open) == 0 && !snmpActive {
		return nil
	}

	res := &HostResult{
		IP:          ip,
		OpenPorts:   open,
		DeviceType:  "unknown",
		SNMPEnabled: snmpActive,
		MAC:         resolveMAC(ip),
	}

	// Reverse DNS
	if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
		res.Hostname = strings.TrimSuffix(names[0], ".")
	}

	// Heuristic device classification
	hasPort := func(p int) bool {
		for _, op := range open {
			if op == p {
				return true
			}
		}
		return false
	}

	if hasPort(9100) {
		res.DeviceType = "printer"
	} else if hasPort(445) || hasPort(3389) {
		res.DeviceType = "workstation"
		res.OS = "Windows"
	} else if hasPort(22) {
		res.DeviceType = "server"
		res.OS = "Linux"
	} else if hasPort(80) || hasPort(443) {
		res.DeviceType = "network"
	}

	if snmpActive {
		res.SNMPSysDescr = snmpRes.SysDescr
		res.SNMPSysName = snmpRes.SysName
		res.SNMPSysUpTime = snmpRes.SysUpTime
		if res.Hostname == "" && snmpRes.SysName != "" {
			res.Hostname = snmpRes.SysName
		}
		descrLower := strings.ToLower(snmpRes.SysDescr)
		if strings.Contains(descrLower, "switch") {
			res.DeviceType = "switch"
		} else if strings.Contains(descrLower, "router") {
			res.DeviceType = "router"
		} else if strings.Contains(descrLower, "printer") || strings.Contains(descrLower, "laserjet") {
			res.DeviceType = "printer"
		} else if strings.Contains(descrLower, "linux") {
			res.DeviceType = "server"
			res.OS = "Linux"
		}
	}

	return res
}

// ScanSubnet concurrently probes all valid host addresses in the CIDR.
func ScanSubnet(ctx context.Context, cidr string, maxConcurrency int) ([]HostResult, error) {
	ips, err := GenerateSubnetIPs(cidr)
	if err != nil {
		return nil, err
	}

	if maxConcurrency <= 0 || maxConcurrency > 64 {
		maxConcurrency = 32
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrency)
	var mu sync.Mutex
	var results []HostResult

	for _, target := range ips {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() { _ = recover() }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			dev := ProbeHost(ip)
			if dev != nil {
				mu.Lock()
				results = append(results, *dev)
				mu.Unlock()
			}
		}(target)
	}

	wg.Wait()
	return results, nil
}

// GetLocalSubnets returns a list of IPv4 CIDR subnets active on local network interfaces.
func GetLocalSubnets() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var subnets []string
	seen := make(map[string]bool)

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			// Normalize to network base IP
			networkIP := ipnet.IP.Mask(ipnet.Mask)
			ones, _ := ipnet.Mask.Size()
			canonical := fmt.Sprintf("%s/%d", networkIP.String(), ones)
			if !seen[canonical] && ones <= 24 && ones >= 16 {
				seen[canonical] = true
				subnets = append(subnets, canonical)
			}
		}
	}
	return subnets, nil
}
