package agent

import (
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

var netPrev struct {
	sync.Mutex
	rx, tx uint64
	at     time.Time
}

// collectMetrics is called on the metrics interval. CPU percent is the
// average since the previous call, which is exactly the interval window.
func collectMetrics(monitored []string) *protocol.Metrics {
	m := &protocol.Metrics{TS: time.Now().Unix()}
	if pct, err := cpu.Percent(0, false); err == nil && len(pct) > 0 {
		m.CPUPct = round1(pct[0])
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		m.MemUsed, m.MemTotal = vm.Used, vm.Total
	}
	if sw, err := mem.SwapMemory(); err == nil {
		m.SwapUsed = sw.Used
	}
	for _, p := range physicalPartitions() {
		if u, err := disk.Usage(p.Mountpoint); err == nil && u.Total > 0 {
			m.Disks = append(m.Disks, protocol.DiskUsage{Mount: p.Mountpoint, Total: u.Total, Used: u.Used, UsedPct: round1(u.UsedPercent)})
		}
	}
	if io, err := net.IOCounters(false); err == nil && len(io) > 0 {
		netPrev.Lock()
		nowT := time.Now()
		if !netPrev.at.IsZero() {
			secs := nowT.Sub(netPrev.at).Seconds()
			if secs > 0 && io[0].BytesRecv >= netPrev.rx && io[0].BytesSent >= netPrev.tx {
				m.NetRxBps = uint64(float64(io[0].BytesRecv-netPrev.rx) / secs)
				m.NetTxBps = uint64(float64(io[0].BytesSent-netPrev.tx) / secs)
			}
		}
		netPrev.rx, netPrev.tx, netPrev.at = io[0].BytesRecv, io[0].BytesSent, nowT
		netPrev.Unlock()
	}
	if up, err := host.Uptime(); err == nil {
		m.Uptime = up
	}
	if runtime.GOOS != "windows" {
		if l, err := load.Avg(); err == nil {
			m.Load1 = round1(l.Load1)
		}
	}
	if pids, err := process.Pids(); err == nil {
		m.ProcCount = len(pids)
	}
	if len(monitored) > 0 {
		m.Services = map[string]string{}
		for _, name := range monitored {
			name = strings.TrimSpace(name)
			if name != "" {
				m.Services[name] = serviceState(name)
			}
		}
	}
	m.PendingReboot = pendingReboot()
	m.LoggedIn = loggedInUsers()
	return m
}

// physicalPartitions filters out pseudo filesystems so the disk list is the
// set of volumes an operator cares about.
func physicalPartitions() []disk.PartitionStat {
	parts, err := disk.Partitions(false)
	if err != nil {
		return nil
	}
	var out []disk.PartitionStat
	for _, p := range parts {
		fs := strings.ToLower(p.Fstype)
		switch {
		case fs == "" || fs == "squashfs" || fs == "tmpfs" || fs == "devtmpfs" || fs == "overlay" || fs == "cdfs" || fs == "udf" || fs == "iso9660":
			continue
		case strings.HasPrefix(p.Mountpoint, "/snap/") || strings.HasPrefix(p.Mountpoint, "/boot/efi") || strings.HasPrefix(p.Mountpoint, "/var/lib/docker"):
			continue
		}
		for _, o := range p.Opts {
			if o == "cdrom" {
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }
