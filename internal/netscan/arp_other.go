//go:build !windows

package netscan

import (
	"bufio"
	"os"
	"strings"
)

func resolveMAC(ipStr string) string {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[0] == ipStr {
			mac := strings.ToUpper(fields[3])
			if mac != "00:00:00:00:00:00" {
				return mac
			}
		}
	}
	return ""
}
