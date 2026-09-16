//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

const (
	regCurrentVersion = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	regLogonUI        = `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI`
	regUninstall      = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	regUninstall32    = `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
	regTimeZone       = `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`
)

// ---- registry helpers ----
//
// Every reader opens with WOW64_64KEY so the view is the real 64-bit one
// whatever the build; the WOW6432Node paths are spelled out explicitly.

func regString(root registry.Key, path, name string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

func regUint(root registry.Key, path, name string) (uint64, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return 0, false
	}
	return v, true
}

func regStrings(root registry.Key, path, name string) []string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil
	}
	defer k.Close()
	v, _, err := k.GetStringsValue(name)
	if err != nil {
		return nil
	}
	return v
}

func regKeyExists(root registry.Key, path string) bool {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

// ---- WMI ----

// wmiTimeout bounds every WMI query. WMI can hang for minutes when the
// repository is corrupt or a provider is wedged, and an inventory that never
// arrives is worse than one with a few blank fields.
const wmiTimeout = 20 * time.Second

// wmiClient tolerates properties that older Windows builds lack
// (SystemFamily appeared in Windows 8) instead of failing the whole query.
var wmiClient = &wmi.Client{AllowMissingFields: true, NonePtrZero: true}

// wmiHung is set while a query that outlived its deadline is still running.
// The wmi package serialises every query behind one package-level mutex, so
// as long as that goroutine holds it every later query could only burn its
// own timeout and leak another goroutine; they are refused up front instead,
// and the flag clears the moment the stuck query finally returns.
var wmiHung atomic.Bool

// wmiQuery runs one WQL query with a deadline. The goroutine owns the result
// slice and hands it over on the channel, so a query that finishes after the
// deadline can never write into memory the caller is already reading.
func wmiQuery[T any](namespace, query string, timeout time.Duration) ([]T, error) {
	if wmiHung.Load() {
		return nil, errors.New("wmi: skipped, an earlier query is still hung")
	}
	type result struct {
		rows []T
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var rows []T
		var err error
		if namespace == "" {
			err = wmiClient.Query(query, &rows)
		} else {
			err = wmiClient.Query(query, &rows, nil, namespace)
		}
		ch <- result{rows, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.rows, r.err
	case <-timer.C:
		wmiHung.Store(true)
		go func() {
			<-ch
			wmiHung.Store(false)
		}()
		return nil, fmt.Errorf("wmi: %q timed out after %s", query, timeout)
	}
}

// Field names must match the WMI property names (matched case-insensitively
// through IDispatch), which is why they do not follow Go's initialisms.

type win32ComputerSystem struct {
	Manufacturer    string
	Model           string
	Domain          string
	UserName        string
	PartOfDomain    bool
	DomainRole      uint16
	SystemFamily    string
	SystemSKUNumber string
}

type win32BIOS struct {
	SerialNumber      string
	SMBIOSBIOSVersion string
	Manufacturer      string
	ReleaseDate       string
}

type win32VideoController struct {
	Name          string
	DriverVersion string
}

type antiVirusProduct struct {
	DisplayName  string
	ProductState uint32
}

type softwareLicensingProduct struct {
	Name          string
	LicenseStatus uint32
}

// ---- contract ----

// platformLabel builds "Windows 11 Pro 23H2 (build 22631.4037)" from the
// CurrentVersion key, which is the authoritative source; gopsutil's platform
// string is only the fallback when the registry cannot be read.
func platformLabel(hi *host.InfoStat) string {
	fallback := ""
	if hi != nil {
		fallback = hi.Platform
	}
	product := regString(registry.LOCAL_MACHINE, regCurrentVersion, "ProductName")
	display := regString(registry.LOCAL_MACHINE, regCurrentVersion, "DisplayVersion")
	if display == "" {
		display = regString(registry.LOCAL_MACHINE, regCurrentVersion, "ReleaseId") // pre-20H2
	}
	build := regString(registry.LOCAL_MACHINE, regCurrentVersion, "CurrentBuild")
	if build == "" {
		build = regString(registry.LOCAL_MACHINE, regCurrentVersion, "CurrentBuildNumber")
	}
	ubr := ""
	if v, ok := regUint(registry.LOCAL_MACHINE, regCurrentVersion, "UBR"); ok {
		ubr = strconv.FormatUint(v, 10)
	}
	return winLabel(product, display, build, ubr, fallback)
}

// platformInventory fills what gopsutil cannot: hardware identity from WMI,
// installed software from the Uninstall hives, the antivirus product, the
// last interactive user and a handful of Windows specifics in Extra. Every
// source is optional; a failure is logged and the field stays blank.
func platformInventory(inv *protocol.Inventory) {
	if inv.Extra == nil {
		inv.Extra = protocol.Extra{}
	}
	consoleUser := ""

	if rows, err := wmiQuery[win32ComputerSystem]("", "SELECT Manufacturer, Model, Domain, UserName, PartOfDomain, DomainRole, SystemFamily, SystemSKUNumber FROM Win32_ComputerSystem", wmiTimeout); err != nil {
		slog.Warn("inventory: Win32_ComputerSystem", "err", err)
	} else if len(rows) > 0 {
		c := rows[0]
		inv.Manufacturer = strings.TrimSpace(c.Manufacturer)
		inv.Model = strings.TrimSpace(c.Model)
		inv.Domain = strings.TrimSpace(c.Domain)
		inv.Extra["domain_joined"] = strconv.FormatBool(c.PartOfDomain)
		if r := winDomainRole(c.DomainRole); r != "" {
			inv.Extra["domain_role"] = r
		}
		if f := strings.TrimSpace(c.SystemFamily); f != "" {
			inv.Extra["system_family"] = f
		}
		if s := strings.TrimSpace(c.SystemSKUNumber); s != "" {
			inv.Extra["system_sku"] = s
		}
		consoleUser = winCleanUser(c.UserName)
	}

	// Win32_Processor is the only source of the physical core count: gopsutil
	// fills cpu.Info().Cores from the package affinity mask on Windows, which
	// is the logical count, so the shared collector had cpu_cores == cpu_threads
	// on every device. The rows are per socket and both counts are summed.
	cores, threads := 0, 0
	if rows, err := wmiQuery[winProcessor]("", "SELECT NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor", wmiTimeout); err != nil {
		slog.Warn("inventory: Win32_Processor", "err", err)
	} else {
		cores, threads = winCPUCounts(rows)
	}
	if cores == 0 {
		// WMI is unavailable, but GetLogicalProcessorInformationEx still
		// knows how many cores the packages hold.
		cores, _ = cpu.Counts(false)
	}
	if cores > 0 {
		inv.CPUCores = cores
	}
	if threads > 0 {
		inv.CPUThreads = threads
	}

	if rows, err := wmiQuery[win32BIOS]("", "SELECT SerialNumber, SMBIOSBIOSVersion, Manufacturer, ReleaseDate FROM Win32_BIOS", wmiTimeout); err != nil {
		slog.Warn("inventory: Win32_BIOS", "err", err)
	} else if len(rows) > 0 {
		b := rows[0]
		inv.Serial = strings.TrimSpace(b.SerialNumber)
		inv.BIOSVersion = strings.TrimSpace(b.SMBIOSBIOSVersion)
		if v := strings.TrimSpace(b.Manufacturer); v != "" {
			inv.Extra["bios_vendor"] = v
		}
		if d := winCIMDate(b.ReleaseDate); d != "" {
			inv.Extra["bios_date"] = d
		}
	}

	if rows, err := wmiQuery[win32VideoController]("", "SELECT Name, DriverVersion FROM Win32_VideoController", wmiTimeout); err != nil {
		slog.Warn("inventory: Win32_VideoController", "err", err)
	} else {
		seen := map[string]bool{}
		var drivers []string
		for _, g := range rows {
			name := strings.TrimSpace(g.Name)
			if name == "" || seen[strings.ToLower(name)] {
				continue
			}
			seen[strings.ToLower(name)] = true
			inv.GPUs = append(inv.GPUs, name)
			if v := strings.TrimSpace(g.DriverVersion); v != "" {
				drivers = append(drivers, name+" "+v)
			}
		}
		if len(drivers) > 0 {
			inv.Extra["gpu_drivers"] = strings.Join(drivers, "; ")
		}
	}

	// SecurityCenter2 only exists on client SKUs; a Server's failure here is
	// expected and not worth a warning.
	if rows, err := wmiQuery[antiVirusProduct](`root\SecurityCenter2`, "SELECT displayName, productState FROM AntiVirusProduct", wmiTimeout); err != nil {
		slog.Debug("inventory: AntiVirusProduct", "err", err)
	} else {
		var products []winAVProduct
		var states []string
		for _, av := range rows {
			name := strings.TrimSpace(av.DisplayName)
			if name == "" {
				continue
			}
			products = append(products, winAVProduct{Name: name, State: av.ProductState})
			states = append(states, name+": "+winAVState(av.ProductState))
		}
		inv.AntivirusName = winAntivirusSummary(products)
		if len(states) > 0 {
			inv.Extra["antivirus_state"] = strings.Join(states, "; ")
		}
	}

	inv.Software = installedSoftware()

	lastUser := winCleanUser(regString(registry.LOCAL_MACHINE, regLogonUI, "LastLoggedOnUser"))
	if lastUser == "" {
		lastUser = winCleanUser(regString(registry.LOCAL_MACHINE, regLogonUI, "LastLoggedOnSAMUser"))
	}
	if lastUser == "" {
		lastUser = consoleUser
	}
	inv.LastUser = lastUser

	if v := regString(registry.LOCAL_MACHINE, regCurrentVersion, "ProductName"); v != "" {
		inv.Extra["windows_product"] = v
	}
	if v := regString(registry.LOCAL_MACHINE, regCurrentVersion, "DisplayVersion"); v != "" {
		inv.Extra["windows_display_version"] = v
	}
	if v := regString(registry.LOCAL_MACHINE, regCurrentVersion, "EditionID"); v != "" {
		inv.Extra["windows_edition"] = v
	}
	if v := regString(registry.LOCAL_MACHINE, regCurrentVersion, "InstallationType"); v != "" {
		inv.Extra["windows_installation_type"] = v
	}
	if build := regString(registry.LOCAL_MACHINE, regCurrentVersion, "CurrentBuild"); build != "" {
		if ubr, ok := regUint(registry.LOCAL_MACHINE, regCurrentVersion, "UBR"); ok {
			build += "." + strconv.FormatUint(ubr, 10)
		}
		inv.Extra["windows_build"] = build
	}
	if ts, ok := regUint(registry.LOCAL_MACHINE, regCurrentVersion, "InstallDate"); ok && ts > 0 {
		inv.Extra["windows_install_date"] = time.Unix(int64(ts), 0).UTC().Format("2006-01-02")
	}
	// inv.Timezone carries the abbreviation and the current offset; the zone
	// id ("Eastern Standard Time") is what survives a DST change, so a fleet
	// can be grouped or scheduled by it.
	if v := regString(registry.LOCAL_MACHINE, regTimeZone, "TimeZoneKeyName"); v != "" {
		inv.Extra["timezone_id"] = v
	}

	// Activation is one WQL query with a WHERE clause; it costs a second or
	// two, which an hourly inventory can afford.
	if rows, err := wmiQuery[softwareLicensingProduct]("", "SELECT Name, LicenseStatus FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL AND ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f'", 10*time.Second); err != nil {
		slog.Debug("inventory: SoftwareLicensingProduct", "err", err)
	} else if len(rows) > 0 {
		inv.Extra["activation"] = winLicenseStatus(rows[0].LicenseStatus)
	}
}

// installedSoftware enumerates the Uninstall hives: the 64-bit and
// WOW6432Node machine views, the service's own HKCU (nearly empty for
// SYSTEM, but the contract asks for it) and every loaded user hive under
// HKEY_USERS, which is where per-user installers such as VS Code and Teams
// register themselves. Those user hives are writable by their owner without
// any elevation, so the result is capped (winCapSoftware) and every field is
// clipped: what a standard user writes must not decide how big the frame the
// agent sends is.
func installedSoftware() []protocol.Software {
	type hive struct {
		root registry.Key
		path string
	}
	hives := []hive{
		{registry.LOCAL_MACHINE, regUninstall},
		{registry.LOCAL_MACHINE, regUninstall32},
		{registry.CURRENT_USER, regUninstall},
	}
	if users, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS); err == nil {
		names, _ := users.ReadSubKeyNames(-1)
		users.Close()
		for _, n := range names {
			if winIsUserHive(n) {
				hives = append(hives, hive{registry.USERS, n + `\` + regUninstall}, hive{registry.USERS, n + `\` + regUninstall32})
			}
		}
	}
	var all []protocol.Software
	for _, h := range hives {
		all = append(all, readUninstallHive(h.root, h.path)...)
	}
	return winCapSoftware(winDedupeSoftware(all))
}

func readUninstallHive(root registry.Key, path string) []protocol.Software {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	var out []protocol.Software
	for _, n := range names {
		// One hive alone cannot fill the list: everything past the cap would
		// be thrown away anyway, and reading it is work an unprivileged user
		// could ask for at will.
		if len(out) >= winMaxSoftware {
			break
		}
		sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		var e winUninstallEntry
		e.Name, _, _ = sk.GetStringValue("DisplayName")
		e.Version, _, _ = sk.GetStringValue("DisplayVersion")
		e.Publisher, _, _ = sk.GetStringValue("Publisher")
		e.InstallDate, _, _ = sk.GetStringValue("InstallDate")
		e.ReleaseType, _, _ = sk.GetStringValue("ReleaseType")
		e.ParentKeyName, _, _ = sk.GetStringValue("ParentKeyName")
		e.SystemComponent, _, _ = sk.GetIntegerValue("SystemComponent")
		sk.Close()
		if s, ok := winSoftwareFromUninstall(e); ok {
			out = append(out, s)
		}
	}
	return out
}

// ---- sessions ----

// x/sys/windows binds WTSEnumerateSessions and WTSFreeMemory but not the
// per-session query or the disconnect/logoff calls; those come straight
// from wtsapi32.
var (
	modWtsapi32                     = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformationW = modWtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSDisconnectSession        = modWtsapi32.NewProc("WTSDisconnectSession")
	procWTSLogoffSession            = modWtsapi32.NewProc("WTSLogoffSession")
)

const (
	wtsCurrentServerHandle = 0
	wtsInfoUserName        = 5 // WTS_INFO_CLASS.WTSUserName
	wtsInfoDomainName      = 7 // WTS_INFO_CLASS.WTSDomainName
	wtsNoSession           = 0xFFFFFFFF
)

type wtsSession struct {
	id, state    uint32
	user, domain string
}

// wtsSessions lists every terminal-services session with its user. A
// session with no user (services, the logon screen) has an empty user.
func wtsSessions() ([]wtsSession, error) {
	var (
		info  *windows.WTS_SESSION_INFO
		count uint32
	)
	if err := windows.WTSEnumerateSessions(wtsCurrentServerHandle, 0, 1, &info, &count); err != nil {
		return nil, fmt.Errorf("WTSEnumerateSessions: %w", err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	raw := unsafe.Slice(info, count)
	out := make([]wtsSession, 0, count)
	for _, s := range raw {
		sess := wtsSession{id: s.SessionID, state: s.State}
		sess.user, _ = wtsQueryString(s.SessionID, wtsInfoUserName)
		sess.domain, _ = wtsQueryString(s.SessionID, wtsInfoDomainName)
		out = append(out, sess)
	}
	return out, nil
}

func wtsQueryString(session, class uint32) (string, error) {
	var (
		buf *uint16
		n   uint32
	)
	r, _, e := procWTSQuerySessionInformationW.Call(wtsCurrentServerHandle, uintptr(session), uintptr(class), uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return "", fmt.Errorf("WTSQuerySessionInformation(%d, class %d): %w", session, class, e)
	}
	if buf == nil {
		return "", nil
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
	return windows.UTF16PtrToString(buf), nil
}

// loggedInUsers lists the users of Active sessions (console and RDP). The
// WTS API is the primary path; "query user" is the fallback when the API
// itself fails, which happens on stripped-down builds without the Terminal
// Services stack.
func loggedInUsers() []string {
	hostname, _ := os.Hostname()
	sessions, err := wtsSessions()
	if err != nil {
		return queryUserFallback(err)
	}
	var users []string
	seen := map[string]bool{}
	for _, s := range sessions {
		if s.state != windows.WTSActive {
			continue
		}
		u := winSessionUser(s.domain, s.user, hostname)
		if u == "" {
			continue
		}
		if k := strings.ToLower(u); !seen[k] {
			seen[k] = true
			users = append(users, u)
		}
	}
	return users
}

// queryUserFallback runs "query user" after the WTS API itself failed.
// query.exe belongs to the same Terminal Services stack, so on the SKUs this
// fallback exists for it is often not installed at all - Windows 11 Home has
// no query.exe, quser.exe or qwinsta.exe - and running it by name would only
// produce a confusing "is not recognized" error. It is therefore only
// launched when it is really there, and either way wtsErr is logged: an empty
// user list is otherwise indistinguishable from "nobody is logged in".
func queryUserFallback(wtsErr error) []string {
	exe := queryUserExe()
	if exe == "" {
		warnSessions("logged-in users: WTS enumeration failed and query.exe is not installed on this Windows edition", "err", wtsErr)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// "query user" exits 1 with "No User exists for *" when nobody is logged
	// in, so the exit status is not an error signal here.
	out, _, err := runHidden(ctx, exe, "user")
	users := winParseQueryUser(out)
	if len(users) == 0 {
		warnSessions("logged-in users: WTS enumeration failed and query user listed nobody", "wts_err", wtsErr, "query_err", err)
	}
	return users
}

// loggedInUsers runs with every metrics sample and a machine whose WTS stack
// is broken stays broken, so the fallback's warning is rate-limited to one an
// hour and the repeats go to Debug.
const sessionWarnEvery = time.Hour

var lastSessionWarn atomic.Int64

func warnSessions(msg string, args ...any) {
	now := time.Now().Unix()
	if last := lastSessionWarn.Load(); last != 0 && now-last < int64(sessionWarnEvery/time.Second) {
		slog.Debug(msg, args...)
		return
	}
	lastSessionWarn.Store(now)
	slog.Warn(msg, args...)
}

// queryUserExe is the full path of query.exe, or "" when this Windows
// edition does not ship it. Only System32 counts: the agent runs as SYSTEM
// and must not pick up a query.exe someone dropped on PATH.
func queryUserExe() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	p := filepath.Join(root, "System32", "query.exe")
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// ---- pending reboot ----

// pendingReboot checks the registry markers Windows itself uses: component
// servicing, Windows Update, pending file renames and a pending computer
// rename. The COM Microsoft.Update.SystemInfo flag is deliberately not
// consulted; this runs with every metrics sample and must stay cheap.
func pendingReboot() bool {
	const cbs = `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\`
	const wu = `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\`
	for _, p := range []string{
		cbs + "RebootPending",
		cbs + "RebootInProgress",
		cbs + "PackagesPending",
		wu + "RebootRequired",
		wu + "PostRebootReporting",
	} {
		if regKeyExists(registry.LOCAL_MACHINE, p) {
			return true
		}
	}
	if winPendingRenames(regStrings(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, "PendingFileRenameOperations")) {
		return true
	}
	active := regString(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName`, "ComputerName")
	wanted := regString(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`, "ComputerName")
	if active != "" && wanted != "" && !strings.EqualFold(active, wanted) {
		return true
	}
	return false
}
