package baselines

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
)

// ---- registry values ----

// RegistryValue is a registry value decoded according to its declared type.
// Exactly one field is meaningful, chosen by Kind.
type RegistryValue struct {
	Kind   string   // dword, qword, string, expand_string, multi_string
	DWord  uint32   //
	QWord  uint64   //
	String string   //
	Multi  []string //
}

// Typed decodes Value against Type and fails with the message the server puts
// in its 400 and the agent puts in a result detail. The JSON type is fixed by
// Type: a number for dword/qword, a string for string/expand_string, an array
// of strings for multi_string (A36).
func (p RegistryParams) Typed() (RegistryValue, error) {
	v := RegistryValue{Kind: p.Type}
	raw := strings.TrimSpace(string(p.Value))
	if raw == "" || raw == "null" {
		return v, errors.New("value: a value is required")
	}
	switch p.Type {
	case "dword", "qword":
		// encoding/json accepts a QUOTED number into a json.Number, so "0"
		// would pass for a dword; the JSON type is part of the contract.
		if raw[0] == '"' {
			return v, fmt.Errorf("value: %s needs a whole number, not a string", p.Type)
		}
		var n json.Number
		if err := json.Unmarshal(p.Value, &n); err != nil {
			return v, fmt.Errorf("value: %s needs a whole number", p.Type)
		}
		if strings.ContainsAny(n.String(), ".eE") {
			return v, fmt.Errorf("value: %s needs a whole number", p.Type)
		}
		u, err := strconv.ParseUint(n.String(), 10, 64)
		if err != nil {
			return v, fmt.Errorf("value: %s must be between 0 and %s", p.Type, regMax(p.Type))
		}
		if p.Type == "dword" {
			if u > 0xFFFFFFFF {
				return v, errors.New("value: dword must be between 0 and 4294967295")
			}
			v.DWord = uint32(u)
			return v, nil
		}
		v.QWord = u
		return v, nil
	case "string", "expand_string":
		var s string
		if err := json.Unmarshal(p.Value, &s); err != nil {
			return v, fmt.Errorf("value: %s needs a string", p.Type)
		}
		if len(s) > 8192 {
			return v, errors.New("value: at most 8192 characters")
		}
		v.String = s
		return v, nil
	case "multi_string":
		var ss []string
		if err := json.Unmarshal(p.Value, &ss); err != nil {
			return v, errors.New("value: multi_string needs an array of strings")
		}
		if len(ss) > 256 {
			return v, errors.New("value: at most 256 strings")
		}
		for _, s := range ss {
			if len(s) > 8192 {
				return v, errors.New("value: each string is at most 8192 characters")
			}
		}
		v.Multi = ss
		return v, nil
	}
	return v, fmt.Errorf("type: unknown registry type %q", p.Type)
}

func regMax(t string) string {
	if t == "dword" {
		return "4294967295"
	}
	return "18446744073709551615"
}

// String renders a registry value for the expected/observed columns.
func (v RegistryValue) Display() string {
	switch v.Kind {
	case "dword":
		return strconv.FormatUint(uint64(v.DWord), 10)
	case "qword":
		return strconv.FormatUint(v.QWord, 10)
	case "multi_string":
		return strings.Join(v.Multi, "|")
	}
	return v.String
}

// ---- registry paths ----

// regDenied are the hives a baseline may never touch: the account database,
// the security hive and the agent's own service configuration (A36). Matching
// is case-insensitive and prefix-based on whole components.
var regDenied = []string{
	`HKLM\SAM`,
	`HKLM\SECURITY`,
	`HKLM\SYSTEM\CurrentControlSet\Services\HomelabRMMAgent`,
}

// CheckRegistryPath validates a registry path syntactically and against the
// deny list. Only HKLM and HKCU are accepted; HKCU under a service account is
// the service's own hive, which the console has to say out loud.
func CheckRegistryPath(p string) error {
	if p == "" {
		return errors.New("a registry path is required")
	}
	if len(p) > 1024 {
		return errors.New("too long")
	}
	if !regPathRE.MatchString(p) {
		return errors.New(`must look like HKLM\SOFTWARE\... or HKCU\SOFTWARE\... with no wildcards`)
	}
	for _, c := range strings.Split(p, `\`)[1:] {
		if len(c) > 256 {
			return errors.New("each key name is at most 256 characters")
		}
	}
	lower := strings.ToLower(p)
	for _, d := range regDenied {
		dl := strings.ToLower(d)
		if lower == dl || strings.HasPrefix(lower, dl+`\`) {
			return fmt.Errorf("%s is not writable by a baseline", d)
		}
	}
	return nil
}

// ---- file paths ----

// PathStyle reports whether p is a unix or a windows absolute path, or "" if
// it is neither. The server validates Windows paths while running on Linux,
// so this cannot read runtime.GOOS.
func PathStyle(p string) string {
	switch {
	case strings.HasPrefix(p, "/"):
		return "unix"
	case len(p) >= 3 && isDriveLetter(p[0]) && p[1] == ':' && (p[2] == '\\' || p[2] == '/'):
		return "windows"
	}
	return ""
}

func isDriveLetter(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// CleanPath normalises a path of either style for comparison: forward slashes,
// no duplicate separators, no trailing separator, a lower-cased drive letter.
// It never resolves symlinks - that is the agent's job, at evaluation time.
func CleanPath(p string) string {
	style := PathStyle(p)
	q := strings.ReplaceAll(p, `\`, "/")
	if style == "windows" {
		// Windows paths are compared case-insensitively, so the whole path
		// is folded, not just the drive letter: a deny list that only
		// matched the exact spelling would be bypassed by "C:\WINDOWS\...".
		q = strings.ToLower(q)
	}
	q = path.Clean(q)
	return q
}

// HasDotDot reports whether any component of p is "..".
func HasDotDot(p string) bool {
	for _, c := range strings.Split(strings.ReplaceAll(p, `\`, "/"), "/") {
		if c == ".." {
			return true
		}
	}
	return false
}

// deniedAgentDirs are the agent's own default configuration directories, in
// CleanPath form. A file check that managed one would rewrite the device's
// identity, its server URL or its baseline cache on every matched device -
// and could switch the fleet to another server. The agent refuses its REAL
// ConfigDir() at evaluation time (an operator may have moved it with
// RMM_AGENT_DIR, which only the device knows); this is the half a writer can
// be refused for, which is the default location on each platform.
var deniedAgentDirs = []string{"/etc/homelab-rmm", "c:/programdata/homelabrmm"}

// unixDeniedPrefixes are the trees a file check may never write into.
var unixDeniedPrefixes = []string{"/proc", "/sys", "/dev"}

// unixDeniedFiles are the individual files that decide who is root.
var unixDeniedFiles = []string{"/etc/shadow", "/etc/gshadow", "/etc/sudoers"}

// winDeniedPrefixes are matched after CleanPath, so they are lower case with
// forward slashes and no drive letter assumptions beyond the one spelled out.
var winDeniedPrefixes = []string{
	"c:/windows/system32/config",
	"c:/programdata/homelabrmm",
}

// WinAuditedPaths are allowed but worth an audit entry; the hosts file is the
// one operators legitimately manage and attackers legitimately abuse.
var WinAuditedPaths = []string{"c:/windows/system32/drivers/etc/hosts"}

// CheckFilePath enforces the path half of the `file` kind on both sides: the
// path must be absolute, must not climb with "..", and must not be one of the
// files that decide who is root on the device. /etc/sudoers.d is allowed only
// for an explicit "present with content" check, because a baseline that can
// delete a sudoers drop-in is a privilege change with no audit trail.
func CheckFilePath(p, state, content string) error {
	if strings.TrimSpace(p) == "" {
		return errors.New("a path is required")
	}
	if len(p) > 4096 {
		return errors.New("too long")
	}
	if strings.ContainsAny(p, "\x00\n\r") {
		return errors.New("must not contain control characters")
	}
	style := PathStyle(p)
	if style == "" {
		return errors.New("must be an absolute path (/etc/... or C:\\...)")
	}
	if HasDotDot(p) {
		return errors.New(`must not contain ".."`)
	}
	clean := CleanPath(p)
	for _, d := range deniedAgentDirs {
		if clean == d || strings.HasPrefix(clean, d+"/") {
			return errors.New("the RMM agent's own configuration directory is not manageable by a baseline")
		}
	}
	if style == "unix" {
		for _, d := range unixDeniedPrefixes {
			if clean == d || strings.HasPrefix(clean, d+"/") {
				return fmt.Errorf("%s is not a real file tree a baseline may manage", d)
			}
		}
		for _, d := range unixDeniedFiles {
			if clean == d {
				return fmt.Errorf("%s decides who is root on this device and is not manageable by a baseline", d)
			}
		}
		if clean == "/etc/sudoers.d" || strings.HasPrefix(clean, "/etc/sudoers.d/") {
			if state != "present" || content == "" {
				return errors.New("/etc/sudoers.d is only manageable as state present with explicit content")
			}
		}
		if clean == "/" {
			return errors.New("the root directory is not a file")
		}
		return nil
	}
	for _, d := range winDeniedPrefixes {
		if clean == d || strings.HasPrefix(clean, d+"/") {
			return fmt.Errorf("%s is not manageable by a baseline", strings.ReplaceAll(d, "/", `\`))
		}
	}
	if len(clean) <= 3 {
		return errors.New("a drive root is not a file")
	}
	return nil
}

// FileIsAudited reports whether writing p deserves its own audit entry even
// though it is allowed.
func FileIsAudited(p string) bool {
	clean := CleanPath(p)
	for _, a := range WinAuditedPaths {
		if clean == a {
			return true
		}
	}
	return false
}

// FileNeedsAdmin reports whether a file check at p may only be created by an
// admin: anything outside /etc on unix and outside ProgramData on Windows
// (A43). A write into a program directory or a user profile is a code-change
// on every matched device.
func FileNeedsAdmin(p string) bool {
	clean := CleanPath(p)
	switch PathStyle(p) {
	case "unix":
		return !(clean == "/etc" || strings.HasPrefix(clean, "/etc/"))
	case "windows":
		i := strings.Index(clean, "/programdata/")
		return !(i == 2 && len(clean) > len("c:/programdata/"))
	}
	return true
}

// RequiresAdmin reports whether a check may only be created or edited by an
// admin, and why. The server puts the reason in its 403 and its audit entry.
func RequiresAdmin(kind string, params json.RawMessage) (bool, string) {
	switch kind {
	case "command":
		return true, "a command check runs as SYSTEM or root on every matched device"
	case "file":
		var p FileParams
		if DecodeLenient(params, &p) == nil && FileNeedsAdmin(p.Path) {
			return true, "a file check outside /etc or ProgramData changes system files on every matched device"
		}
	case "reboot_pending":
		if AllowsReboot(kind, params) {
			return true, "a reboot_pending check with allow_reboot restarts every matched device"
		}
	}
	return false, ""
}

// AllowsReboot reports whether a check would let the agent restart a device.
func AllowsReboot(kind string, params json.RawMessage) bool {
	if kind != "reboot_pending" {
		return false
	}
	var p RebootPendingParams
	return DecodeLenient(params, &p) == nil && p.AllowReboot
}

// ---- version comparison (A39) ----

// CompareVersions orders two package versions. An epoch ("1:") and everything
// from the first "-", "~" or "+" (a Debian revision or an RPM release) are
// stripped, then the dot-separated fields are compared left to right,
// numerically where both sides are numbers and as strings otherwise, missing
// fields counting as 0.
//
// It returns an error rather than a guess when neither side has a numeric
// field: a false drift alert that "self-heals" by installing a package is
// worse than an honest error.
func CompareVersions(a, b string) (int, error) {
	fa, fb := versionFields(a), versionFields(b)
	if !anyNumeric(fa) || !anyNumeric(fb) {
		return 0, fmt.Errorf("cannot compare versions %q and %q", a, b)
	}
	n := len(fa)
	if len(fb) > n {
		n = len(fb)
	}
	for i := 0; i < n; i++ {
		x, y := versionField(fa, i), versionField(fb, i)
		nx, ex := strconv.ParseUint(x, 10, 64)
		ny, ey := strconv.ParseUint(y, 10, 64)
		if ex == nil && ey == nil {
			switch {
			case nx < ny:
				return -1, nil
			case nx > ny:
				return 1, nil
			}
			continue
		}
		if c := strings.Compare(x, y); c != 0 {
			return c, nil
		}
	}
	return 0, nil
}

func versionFields(v string) []string {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, ":"); i >= 0 {
		v = v[i+1:]
	}
	if i := strings.IndexAny(v, "-~+"); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return strings.Split(v, ".")
}

func versionField(f []string, i int) string {
	if i < len(f) {
		return strings.TrimSpace(f[i])
	}
	return "0"
}

func anyNumeric(f []string) bool {
	for _, s := range f {
		if s == "" {
			continue
		}
		if _, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64); err == nil {
			return true
		}
	}
	return false
}
