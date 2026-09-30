package server

import (
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/netscan"
)

type SNMPResult = netscan.SNMPResult

// QuerySNMP probes a host via SNMPv2c on port 161.
func QuerySNMP(targetIP, community string, timeout time.Duration) (*SNMPResult, error) {
	return netscan.QuerySNMP(targetIP, community, timeout)
}

func parseSNMPStrings(data []byte) ([]string, int64) {
	return netscan.ParseSNMPStrings(data)
}
