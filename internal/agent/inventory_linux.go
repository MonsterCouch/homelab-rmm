//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/host"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// maxSoftware caps the installed-software list: a full desktop has 2-4k
// packages and the inventory travels over the WebSocket on every refresh.
const maxSoftware = 5000

// osRelease reads /etc/os-release (or its /usr/lib fallback) once; the
// distro does not change while the agent runs.
var osRelease = sync.OnceValue(func() map[string]string {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if b, err := os.ReadFile(p); err == nil {
			return parseOSRelease(string(b))
		}
	}
	return map[string]string{}
})

// platformLabel prefers the distro's own PRETTY_NAME ("Ubuntu 24.04.1 LTS")
// over gopsutil's lowercase platform id.
func platformLabel(hi *host.InfoStat) string {
	if pn := osRelease()["PRETTY_NAME"]; pn != "" {
		return pn
	}
	if hi == nil {
		return "linux"
	}
	name := hi.Platform
	if name == "" {
		name = "linux"
	}
	if len(name) > 0 {
		name = strings.ToUpper(name[:1]) + name[1:]
	}
	return strings.TrimSpace(name + " " + hi.PlatformVersion)
}

// platformInventory fills in DMI, domain, GPUs, installed software and the
// Linux-specific extras. Every source is optional: a container has no DMI,
// a server has no GPU, a minimal image has no package manager.
func platformInventory(inv *protocol.Inventory) {
	if inv.Extra == nil {
		inv.Extra = protocol.Extra{}
	}
	const dmi = "/sys/class/dmi/id/"
	inv.Manufacturer = dmiClean(readSysFile(dmi + "sys_vendor"))
	inv.Model = dmiClean(readSysFile(dmi + "product_name"))
	inv.Serial = dmiClean(readSysFile(dmi + "product_serial")) // root only; "" otherwise
	inv.BIOSVersion = dmiClean(readSysFile(dmi + "bios_version"))
	if v := dmiClean(readSysFile(dmi + "bios_vendor")); v != "" && inv.BIOSVersion != "" {
		inv.BIOSVersion = v + " " + inv.BIOSVersion
	}
	if d := dmiClean(readSysFile(dmi + "bios_date")); d != "" {
		inv.Extra["bios_date"] = d
	}
	if pv := dmiClean(readSysFile(dmi + "product_version")); pv != "" {
		inv.Extra["product_version"] = pv
	}
	if bv, bn := dmiClean(readSysFile(dmi+"board_vendor")), dmiClean(readSysFile(dmi+"board_name")); bn != "" {
		inv.Extra["board"] = strings.TrimSpace(bv + " " + bn)
	}
	if ct := readSysFile(dmi + "chassis_type"); ct != "" {
		inv.Extra["chassis_type"] = chassisTypeName(ct)
	}

	inv.Domain = linuxDomain(inv.Hostname)
	inv.GPUs = linuxGPUs()
	inv.Software = linuxSoftware()
	inv.AntivirusName = linuxAntivirus()
	if len(inv.LoggedInUsers) > 0 {
		inv.LastUser = inv.LoggedInUsers[0]
	} else if out, _, _, err := runCmdTimeout(5*time.Second, "last", "-w", "-n", "10"); err == nil {
		inv.LastUser = parseLastUser(out)
	}

	osr := osRelease()
	if osr["ID"] != "" {
		inv.Extra["distro_id"] = osr["ID"]
	}
	if osr["VERSION_CODENAME"] != "" {
		inv.Extra["codename"] = osr["VERSION_CODENAME"]
	}
	if pm := packageManager(); pm != "" {
		inv.Extra["package_manager"] = pm
	}
	if v := linuxVirtualization(); v != "" {
		inv.Extra["virtualization"] = v
	}
	if c := linuxContainer(); c != "" {
		inv.Extra["container"] = c
	}
	if s := linuxSELinux(); s != "" {
		inv.Extra["selinux"] = s
	}
	if a := linuxAppArmor(); a != "" {
		inv.Extra["apparmor"] = a
	}
	if fileExists("/run/systemd/system") {
		inv.Extra["init"] = "systemd"
	}
	if fs := linuxSecureBoot(); fs != "" {
		inv.Extra["secure_boot"] = fs
	}
}

// linuxDomain reads the DNS domain from resolv.conf, the FQDN, or hostname
// -d, in that order; each is cheap and the first hit wins.
func linuxDomain(hostname string) string {
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		if d := parseResolvConfDomain(string(b)); d != "" {
			return d
		}
	}
	if i := strings.Index(hostname, "."); i > 0 && i < len(hostname)-1 {
		return hostname[i+1:]
	}
	if out, _, _, err := runCmdTimeout(5*time.Second, "hostname", "-d"); err == nil {
		return strings.TrimSpace(out)
	}
	return ""
}

var drmCardRE = regexp.MustCompile(`^card[0-9]+$`)

// linuxGPUs asks lspci for display adapters and falls back to the PCI ids
// under /sys/class/drm, which exist wherever a DRM driver is bound.
func linuxGPUs() []string {
	if out, _, _, err := runCmdTimeout(10*time.Second, "lspci"); err == nil {
		if gpus := parseLspci(out); len(gpus) > 0 {
			return gpus
		}
	}
	cards, _ := filepath.Glob("/sys/class/drm/card*")
	var out []string
	for _, c := range cards {
		if !drmCardRE.MatchString(filepath.Base(c)) {
			continue
		}
		vendor := readSysFile(filepath.Join(c, "device", "vendor"))
		device := readSysFile(filepath.Join(c, "device", "device"))
		if vendor == "" {
			continue
		}
		name := pciVendorName(vendor)
		if name == "" {
			name = "PCI vendor " + vendor
		}
		if device != "" {
			name += " device " + strings.TrimPrefix(device, "0x")
		}
		out = append(out, name)
	}
	return uniqNonEmpty(out)
}

// linuxSoftware lists installed packages from the native package manager
// plus snaps and flatpaks, capped at maxSoftware entries.
func linuxSoftware() []protocol.Software {
	var all []protocol.Software
	switch {
	case hasCmd("dpkg-query"):
		// dpkg's database keeps removed packages whose conffiles remain
		// ("rc" state); the status column lets the parser drop those so the
		// list is what is installed, not what dpkg has ever heard of.
		if out, _, _, err := runCmdTimeout(60*time.Second, "dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Maintainer}\t${db:Status-Status}\n"); err == nil {
			all = append(all, parseTabbedSoftware(out)...)
		}
	case hasCmd("rpm"):
		if out, _, _, err := runCmdTimeout(60*time.Second, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"); err == nil {
			all = append(all, parseTabbedSoftware(out)...)
		}
	case hasCmd("pacman"):
		if out, _, _, err := runCmdTimeout(60*time.Second, "pacman", "-Q"); err == nil {
			all = append(all, parsePacmanQ(out)...)
		}
	}
	if hasCmd("snap") {
		if out, _, _, err := runCmdTimeout(30*time.Second, "snap", "list"); err == nil {
			all = append(all, parseSnapList(out)...)
		}
	}
	if hasCmd("flatpak") {
		if out, _, _, err := runCmdTimeout(30*time.Second, "flatpak", "list", "--columns=application,version"); err == nil {
			all = append(all, parseFlatpakList(out)...)
		}
	}
	if len(all) > maxSoftware {
		sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })
		all = all[:maxSoftware]
	}
	return all
}

// linuxAntivirus reports the endpoint protection product whose install
// footprint is present. These are stat calls, so the check is free.
func linuxAntivirus() string {
	checks := []struct{ path, name string }{
		{"/opt/microsoft/mdatp", "Microsoft Defender for Endpoint"},
		{"/opt/CrowdStrike", "CrowdStrike Falcon"},
		{"/opt/sentinelone", "SentinelOne"},
		{"/opt/sophos-spl", "Sophos Protection"},
		{"/opt/eset", "ESET"},
		{"/opt/bitdefender-security-tools", "Bitdefender GravityZone"},
		{"/opt/kaspersky", "Kaspersky"},
		{"/etc/clamav", "ClamAV"},
	}
	for _, c := range checks {
		if fileExists(c.path) {
			return c.name
		}
	}
	if hasCmd("clamd") || hasCmd("clamscan") {
		return "ClamAV"
	}
	return ""
}

// linuxVirtualization reports the hypervisor or container runtime, e.g.
// "kvm", "vmware", "docker"; "" on bare metal.
func linuxVirtualization() string {
	out, _, code, err := runCmdTimeout(5*time.Second, "systemd-detect-virt")
	v := strings.TrimSpace(out)
	if (err == nil || code == 1) && v != "" && v != "none" {
		return v
	}
	if v := readSysFile("/sys/class/dmi/id/product_name"); v != "" {
		switch {
		case strings.Contains(v, "VMware"):
			return "vmware"
		case strings.Contains(v, "VirtualBox"):
			return "oracle"
		case strings.Contains(v, "KVM") || strings.Contains(v, "QEMU"):
			return "kvm"
		case strings.Contains(v, "Virtual Machine"):
			return "microsoft"
		}
	}
	return ""
}

// linuxContainer names the container runtime when the agent runs inside
// one (docker, podman, lxc, ...).
func linuxContainer() string {
	if c := readSysFile("/run/systemd/container"); c != "" {
		return c
	}
	if fileExists("/.dockerenv") {
		return "docker"
	}
	if fileExists("/run/.containerenv") {
		return "podman"
	}
	return ""
}

func linuxSELinux() string {
	switch readSysFile("/sys/fs/selinux/enforce") {
	case "1":
		return "enforcing"
	case "0":
		return "permissive"
	}
	if fileExists("/etc/selinux/config") && !fileExists("/sys/fs/selinux") {
		return "disabled"
	}
	return ""
}

func linuxAppArmor() string {
	switch readSysFile("/sys/module/apparmor/parameters/enabled") {
	case "Y":
		return "enabled"
	case "N":
		return "disabled"
	}
	return ""
}

// linuxSecureBoot reads the EFI variable when the system booted with UEFI.
func linuxSecureBoot() string {
	matches, _ := filepath.Glob("/sys/firmware/efi/efivars/SecureBoot-*")
	if len(matches) == 0 {
		return ""
	}
	b, err := os.ReadFile(matches[0])
	if err != nil || len(b) < 5 {
		return ""
	}
	// 4 bytes of attributes, then the value.
	if b[4] == 1 {
		return "enabled"
	}
	return "disabled"
}

// chassisTypeName decodes the SMBIOS chassis type number.
func chassisTypeName(code string) string {
	names := map[string]string{
		"1": "Other", "2": "Unknown", "3": "Desktop", "4": "Low Profile Desktop", "5": "Pizza Box", "6": "Mini Tower",
		"7": "Tower", "8": "Portable", "9": "Laptop", "10": "Notebook", "11": "Hand Held", "12": "Docking Station",
		"13": "All in One", "14": "Sub Notebook", "15": "Space-saving", "16": "Lunch Box", "17": "Main Server Chassis",
		"18": "Expansion Chassis", "19": "SubChassis", "20": "Bus Expansion Chassis", "21": "Peripheral Chassis",
		"22": "RAID Chassis", "23": "Rack Mount Chassis", "24": "Sealed-case PC", "25": "Multi-system chassis",
		"26": "Compact PCI", "27": "Advanced TCA", "28": "Blade", "29": "Blade Enclosure", "30": "Tablet",
		"31": "Convertible", "32": "Detachable", "33": "IoT Gateway", "34": "Embedded PC", "35": "Mini PC", "36": "Stick PC",
	}
	if n, ok := names[strings.TrimSpace(code)]; ok {
		return n
	}
	return code
}

// loggedInUsers reads utmp through gopsutil and, when that is empty (glibc
// 2.40+ systems are dropping utmp), asks logind.
func loggedInUsers() []string {
	var names []string
	if users, err := host.Users(); err == nil {
		for _, u := range users {
			names = append(names, u.User)
		}
	}
	if len(names) == 0 && hasCmd("loginctl") {
		if out, _, _, err := runCmdTimeout(5*time.Second, "loginctl", "list-sessions", "--no-legend"); err == nil {
			names = append(names, parseLoginctlUsers(out)...)
		}
	}
	names = uniqNonEmpty(names)
	sort.Strings(names)
	return names
}

// rebootCache memoises the expensive reboot checks (needs-restarting scans
// every process) because metrics ask every 30 seconds.
var rebootCache struct {
	sync.Mutex
	at  time.Time
	val bool
}

const rebootCacheTTL = 2 * time.Minute

// pendingReboot: Debian's marker file first (free), then the RHEL-family
// needs-restarting, then Arch's running-vs-installed kernel comparison.
func pendingReboot() bool {
	if fileExists("/var/run/reboot-required") || fileExists("/run/reboot-required") {
		return true
	}
	rebootCache.Lock()
	defer rebootCache.Unlock()
	if !rebootCache.at.IsZero() && time.Since(rebootCache.at) < rebootCacheTTL {
		return rebootCache.val
	}
	rebootCache.val = pendingRebootSlow()
	rebootCache.at = time.Now()
	return rebootCache.val
}

func pendingRebootSlow() bool {
	if hasCmd("needs-restarting") {
		// Exit 1 means "reboot needed", 0 means no; anything else is a tool
		// error we treat as "no" rather than nag on every metrics tick.
		_, _, code, _ := runCmdTimeout(60*time.Second, "needs-restarting", "-r")
		if code == 1 {
			return true
		}
	}
	if hasCmd("pacman") && !fileExists("/.dockerenv") {
		if kr, _, _, err := runCmdTimeout(5*time.Second, "uname", "-r"); err == nil {
			pkg := archKernelPackage(strings.TrimSpace(kr))
			if q, _, _, err := runCmdTimeout(10*time.Second, "pacman", "-Q", "--", pkg); err == nil {
				if upToDate, ok := archKernelUpToDate(kr, q); ok && !upToDate {
					return true
				}
			}
		}
	}
	return false
}
