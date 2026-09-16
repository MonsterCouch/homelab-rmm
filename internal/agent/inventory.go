package agent

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// collectInventory gathers the cross-platform facts with gopsutil and then
// lets the platform file fill in the rest (platformInventory).
func collectInventory() (*protocol.Inventory, error) {
	inv := &protocol.Inventory{OS: runtime.GOOS, Arch: runtime.GOARCH, AgentVersion: Version, CollectedAt: time.Now().Unix(), Extra: protocol.Extra{}}
	inv.Hostname, _ = os.Hostname()
	if exe, err := os.Executable(); err == nil {
		inv.AgentPath = exe
	}
	if hi, err := host.Info(); err == nil {
		inv.Platform = platformName()
		inv.PlatformVer = hi.PlatformVersion
		inv.KernelVer = hi.KernelVersion
		inv.BootTime = int64(hi.BootTime)
	}
	if infos, err := cpu.Info(); err == nil && len(infos) > 0 {
		inv.CPUModel = infos[0].ModelName
		cores := 0
		for _, ci := range infos {
			cores += int(ci.Cores)
		}
		inv.CPUCores = cores
	}
	if n, err := cpu.Counts(true); err == nil {
		inv.CPUThreads = n
	}
	if inv.CPUCores == 0 {
		inv.CPUCores, _ = cpu.Counts(false)
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		inv.MemTotal = vm.Total
	}
	for _, p := range physicalPartitions() {
		if u, err := disk.Usage(p.Mountpoint); err == nil && u.Total > 0 {
			inv.Disks = append(inv.Disks, protocol.Disk{Device: p.Device, Mount: p.Mountpoint, FS: p.Fstype, Total: u.Total, Used: u.Used, Free: u.Free, UsedPct: round1(u.UsedPercent)})
		}
	}
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			up := false
			for _, f := range i.Flags {
				if f == "up" {
					up = true
				}
			}
			isLoop := false
			for _, f := range i.Flags {
				if f == "loopback" {
					isLoop = true
				}
			}
			if isLoop || (i.HardwareAddr == "" && len(i.Addrs) == 0) {
				continue
			}
			ni := protocol.NetIface{Name: i.Name, MAC: i.HardwareAddr, Up: up}
			for _, a := range i.Addrs {
				ni.IPs = append(ni.IPs, a.Addr)
			}
			inv.Network = append(inv.Network, ni)
		}
	}
	inv.Timezone = timezoneLabel(time.Now().Zone())
	inv.LoggedInUsers = loggedInUsers()
	inv.PendingReboot = pendingReboot()
	platformInventory(inv)
	sort.Slice(inv.Software, func(i, j int) bool { return inv.Software[i].Name < inv.Software[j].Name })
	if inv.Disks == nil {
		inv.Disks = []protocol.Disk{}
	}
	if inv.Network == nil {
		inv.Network = []protocol.NetIface{}
	}
	if inv.Software == nil {
		inv.Software = []protocol.Software{}
	}
	return inv, nil
}

// timezoneLabel pairs the seasonal abbreviation with the current UTC offset,
// "EDT (UTC-04:00)". The abbreviation alone is not enough to place a device:
// CST is US Central, China Standard and Cuba Standard, IST is India, Ireland
// and Israel, and the same machine reports two different ones over a year.
// A zone Go has no name for reports itself numerically ("+0545"), and then
// the offset alone says everything the name would. The platform files add
// the stable zone id (Windows: TimeZoneKeyName) to Extra.
func timezoneLabel(name string, offsetSec int) string {
	sign := "+"
	if offsetSec < 0 {
		sign, offsetSec = "-", -offsetSec
	}
	offset := fmt.Sprintf("UTC%s%02d:%02d", sign, offsetSec/3600, offsetSec%3600/60)
	name = strings.TrimSpace(name)
	if name == "" || name == "UTC" || strings.HasPrefix(name, "+") || strings.HasPrefix(name, "-") {
		return offset
	}
	return name + " (" + offset + ")"
}

// platformName is a human label such as "Windows 11 Pro" or "Ubuntu 24.04".
func platformName() string {
	hi, err := host.Info()
	if err != nil {
		return runtime.GOOS
	}
	return platformLabel(hi)
}
