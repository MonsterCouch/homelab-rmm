// Package baselines is the one definition of what a baseline check is: the
// parameter schema of every kind, the validator, the size limits and the
// small comparisons (version ordering, path safety) that both the server and
// the agent have to agree on.
//
// It exists because the alternative - a hand-written validator on the server
// and another one in the agent - drifts. The server rejects a bad check with
// a 400 that names the field; the agent re-validates the same params at
// evaluation time and reports the check as `error` rather than handing an
// unvalidated string to exec.
//
// Nothing here touches the OS or imports the agent or server packages.
package baselines

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Limits. Every one of them is enforced by the server when a baseline is
// written and defensively by the agent when it evaluates or reports.
const (
	MaxNameLen           = 120      // baseline and check names
	MaxDescriptionLen    = 2000     // baseline description
	MaxParamsBytes       = 16 << 10 // one check's params JSON, for every kind but the two that carry a body
	MaxChecksPerBaseline = 64
	MaxBaselines         = 100 // per server
	MaxBaselinesPerAgent = 16  // matching one device
	MaxCommandBodyBytes  = 64 << 10
	MaxFileContentBytes  = 256 << 10
	// A `command` check carries two script bodies and a `file` check carries
	// a whole file, so their params cannot fit the 16 KiB ceiling the other
	// kinds live under. The per-field limits above are the real contract;
	// these are the envelopes that make them reachable.
	MaxCommandParamsBytes = 2*MaxCommandBodyBytes + 4<<10
	MaxFileParamsBytes    = MaxFileContentBytes + 8<<10
	MaxObservedBytes      = 256 // expected and observed each
	MaxDetailBytes        = 4096
	MaxReportBytes        = 1 << 20

	MinIntervalSec     = 60
	MaxIntervalSec     = 86400
	DefaultIntervalSec = 3600
	MinTimeoutSec      = 5
	MaxTimeoutSec      = 600
	DefaultTimeoutSec  = 60
)

// States a check can end a pass in.
const (
	StatePass    = "pass"
	StateFail    = "fail"
	StateFixed   = "fixed"
	StateError   = "error"
	StateSkipped = "skipped"
)

// Triggers a report can carry (A51).
const (
	TriggerSchedule  = "schedule"
	TriggerStartup   = "startup"
	TriggerConfig    = "config"
	TriggerManual    = "manual"
	TriggerRemediate = "remediate"
	TriggerPreview   = "preview"
)

// ValidState reports whether s is one of the five result states.
func ValidState(s string) bool {
	switch s {
	case StatePass, StateFail, StateFixed, StateError, StateSkipped:
		return true
	}
	return false
}

// ValidTrigger reports whether t is one of the six triggers. A report with
// anything else is stored as "schedule" by the server.
func ValidTrigger(t string) bool {
	switch t {
	case TriggerSchedule, TriggerStartup, TriggerConfig, TriggerManual, TriggerRemediate, TriggerPreview:
		return true
	}
	return false
}

// ValidSeverity gates the drift-alert severity of a check. `info` is a real
// severity that deliberately opens no alert (A20).
func ValidSeverity(s string) bool {
	switch s {
	case "info", "warning", "critical":
		return true
	}
	return false
}

// ValidOSFilter gates BaselineCheck.OSFilter: empty means "every platform".
func ValidOSFilter(s string) bool {
	switch s {
	case "", "windows", "linux":
		return true
	}
	return false
}

// ClampInterval brings a baseline interval into [MinIntervalSec,
// MaxIntervalSec]; anything at or below zero becomes the default.
func ClampInterval(sec int) int {
	if sec <= 0 {
		return DefaultIntervalSec
	}
	if sec < MinIntervalSec {
		return MinIntervalSec
	}
	if sec > MaxIntervalSec {
		return MaxIntervalSec
	}
	return sec
}

// ClampTimeout brings a per-check timeout into [MinTimeoutSec,
// MaxTimeoutSec]. It applies to every kind, not only `command`.
func ClampTimeout(sec int) int {
	if sec <= 0 {
		return DefaultTimeoutSec
	}
	if sec < MinTimeoutSec {
		return MinTimeoutSec
	}
	if sec > MaxTimeoutSec {
		return MaxTimeoutSec
	}
	return sec
}

// Truncate cuts s to at most max bytes, appending a one-character ellipsis
// when it had to cut. The cut lands on a UTF-8 boundary so the result is
// always valid JSON text.
func Truncate(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	const ell = "…"
	room := max - len(ell)
	if room < 0 {
		room = 0
	}
	for room > 0 && !utf8Boundary(s, room) {
		room--
	}
	return s[:room] + ell
}

// utf8Boundary reports whether i is the start of a rune in s.
func utf8Boundary(s string, i int) bool {
	if i <= 0 || i >= len(s) {
		return true
	}
	return s[i]&0xC0 != 0x80
}

// ---- the kind table ----

type kindSpec struct {
	os       []string
	validate func(raw json.RawMessage, dec decodeFunc) error
}

// decodeFunc is how a validator reads params. The server passes the strict
// reader (unknown keys are a 400, so a console typo is caught before it
// becomes a check that silently does nothing); the agent passes the lenient
// one, because an agent older than the server meets keys it has never heard
// of and must keep evaluating the fields it does understand instead of
// reporting `error` on every device in the fleet (A28, A42).
type decodeFunc func(raw json.RawMessage, v any) error

var kindTable = map[string]kindSpec{
	"service":         {os: []string{"windows", "linux"}, validate: validateService},
	"package":         {os: []string{"windows", "linux"}, validate: validatePackage},
	"registry":        {os: []string{"windows"}, validate: validateRegistry},
	"file":            {os: []string{"windows", "linux"}, validate: validateFile},
	"command":         {os: []string{"windows", "linux"}, validate: validateCommand},
	"group_members":   {os: []string{"windows", "linux"}, validate: validateGroupMembers},
	"firewall":        {os: []string{"windows", "linux"}, validate: validateToggle},
	"time_sync":       {os: []string{"windows", "linux"}, validate: validateToggle},
	"sysctl":          {os: []string{"linux"}, validate: validateSysctl},
	"windows_feature": {os: []string{"windows"}, validate: validateWindowsFeature},
	"reboot_pending":  {os: []string{"windows", "linux"}, validate: validateRebootPending},
	"disk_free":       {os: []string{"windows", "linux"}, validate: validateDiskFree},
}

// Kinds lists every check kind this build knows, sorted.
func Kinds() []string {
	out := make([]string, 0, len(kindTable))
	for k := range kindTable {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// MaxParamsBytesFor is the params ceiling for one kind. It is 16 KiB for
// everything except the two kinds that legitimately carry a payload: a
// `command` check holds two script bodies and a `file` check holds a file.
func MaxParamsBytesFor(kind string) int {
	switch kind {
	case "command":
		return MaxCommandParamsBytes
	case "file":
		return MaxFileParamsBytes
	}
	return MaxParamsBytes
}

// KindKnown reports whether kind is in the table. An agent older than the
// server meets kinds it does not know and reports them `skipped`, never
// `error` (A42).
func KindKnown(kind string) bool { _, ok := kindTable[kind]; return ok }

// KindOS lists the platforms a kind is implemented on. A check whose kind is
// not implemented on the device's OS is `skipped`.
func KindOS(kind string) []string {
	k, ok := kindTable[kind]
	if !ok {
		return nil
	}
	out := make([]string, len(k.os))
	copy(out, k.os)
	return out
}

// KindRunsOn reports whether kind is implemented on goos.
func KindRunsOn(kind, goos string) bool {
	for _, o := range KindOS(kind) {
		if o == goos {
			return true
		}
	}
	return false
}

// ValidateCheck is the whole parameter contract for one check, read strictly:
// an unknown key is an error. It returns an error naming the offending field,
// which the server puts straight into its 400. Writers use this one.
func ValidateCheck(kind string, params json.RawMessage) error {
	return validateCheck(kind, params, decode)
}

// ValidateCheckLenient is ValidateCheck for a READER: every rule is enforced
// except "no unknown keys". The agent uses it at evaluation time, because a
// device running an older build than the server would otherwise report
// `error` for a params field a newer console added - a drift alert on every
// matched device the moment a new field ships, which is exactly what A42
// forbids for a new KIND and makes no more sense for a new field.
func ValidateCheckLenient(kind string, params json.RawMessage) error {
	return validateCheck(kind, params, DecodeLenient)
}

func validateCheck(kind string, params json.RawMessage, dec decodeFunc) error {
	spec, ok := kindTable[kind]
	if !ok {
		return fmt.Errorf("unknown check kind %q", kind)
	}
	if limit := MaxParamsBytesFor(kind); len(params) > limit {
		return fmt.Errorf("params: %d bytes exceeds the %d byte limit", len(params), limit)
	}
	raw := normaliseParams(params)
	if !json.Valid(raw) {
		return errors.New("params: not valid JSON")
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("params: must be a JSON object")
	}
	return spec.validate(raw, dec)
}

// normaliseParams turns an absent or null params into an empty object so
// every kind validator sees the same shape.
func normaliseParams(raw json.RawMessage) json.RawMessage {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || bytes.Equal(t, []byte("null")) {
		return json.RawMessage("{}")
	}
	return t
}

// decode unmarshals params into v, refusing unknown keys so a console typo
// ("enable" for "enabled") is a 400 rather than a check that silently does
// nothing. The agent is deliberately more forgiving: it calls DecodeLenient.
func decode(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(normaliseParams(raw)))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("params: %w", err)
	}
	return nil
}

// DecodeLenient is the agent's reader: unknown keys are ignored so a device
// running an older agent than the server still evaluates the fields it does
// understand (forward compatibility).
func DecodeLenient(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(normaliseParams(raw)))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("params: %w", err)
	}
	return nil
}

// ---- per-kind parameter structs ----

// ServiceParams is the `service` kind. StartType "" means "any" (A37).
type ServiceParams struct {
	Name      string `json:"name"`
	State     string `json:"state"`      // running, stopped
	StartType string `json:"start_type"` // auto, manual, disabled, any (default)
}

// PackageParams is the `package` kind. AllowWinget opts a Windows device in
// to a winget remediation that is refused by default (A38).
type PackageParams struct {
	Name        string `json:"name"`
	State       string `json:"state"` // present, absent
	MinVersion  string `json:"min_version"`
	AllowWinget bool   `json:"allow_winget"`
}

// RegistryParams is the `registry` kind. Value's JSON type is fixed by Type.
type RegistryParams struct {
	Path  string          `json:"path"`
	Name  string          `json:"name"`
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

// FileParams is the `file` kind. Only Content is fixable; SHA256 and
// Contains without Content are check-only even when remediate is set.
type FileParams struct {
	Path     string `json:"path"`
	State    string `json:"state"` // present, absent
	Content  string `json:"content"`
	SHA256   string `json:"sha256"`
	Contains string `json:"contains"`
	Mode     string `json:"mode"`  // 3- or 4-digit octal, linux
	Owner    string `json:"owner"` // user:group, linux
}

// CommandParams is the `command` kind: arbitrary SYSTEM/root code, which is
// why creating one needs the admin role (A33).
type CommandParams struct {
	Language string `json:"language"`
	Check    string `json:"check"`
	Fix      string `json:"fix"`
	Expected string `json:"expected"` // a label only, never compared
}

// GroupMembersParams is the `group_members` kind. Mode "" means "subset".
type GroupMembersParams struct {
	Group       string   `json:"group"`
	Allowed     []string `json:"allowed"`
	Mode        string   `json:"mode"` // exact, subset (default)
	AllowDomain bool     `json:"allow_domain"`
}

// Mode returns the effective membership mode.
func (p GroupMembersParams) EffectiveMode() string {
	if p.Mode == "exact" {
		return "exact"
	}
	return "subset"
}

// ToggleParams is the `firewall` and `time_sync` kinds. Enabled is a pointer
// so an absent field is distinguishable; it defaults to true, because a
// baseline check for a firewall that means "off" is not what anyone types by
// accident.
type ToggleParams struct {
	Enabled *bool `json:"enabled"`
}

// Want reports the desired state, defaulting to enabled.
func (p ToggleParams) Want() bool { return p.Enabled == nil || *p.Enabled }

// SysctlParams is the `sysctl` kind. Value is always a string on the wire and
// is compared after trimming.
type SysctlParams struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// WindowsFeatureParams is the `windows_feature` kind.
type WindowsFeatureParams struct {
	Name  string `json:"name"`
	State string `json:"state"` // enabled, disabled
}

// RebootPendingParams is the `reboot_pending` kind. AllowReboot turns the
// check into the most dangerous remediation in the product (A41).
type RebootPendingParams struct {
	MaxHours    int  `json:"max_hours"`
	AllowReboot bool `json:"allow_reboot"`
}

// DiskFreeParams is the `disk_free` kind; check only.
type DiskFreeParams struct {
	Mount      string  `json:"mount"`
	MinFreePct float64 `json:"min_free_pct"`
}

// ---- validators ----

var (
	// A service name has to survive both vocabularies: a systemd unit and a
	// Win32 service name. The device-side code re-validates with its own
	// platform pattern before the name reaches a command line.
	serviceNameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9@._\-\\:]{0,255}$`)
	pkgNameRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._:@-]{0,255}$`)
	groupNameRE   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9 ._\-]{0,63}$`)
	memberNameRE  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9 ._\-\\@$]{0,255}$`)
	sysctlKeyRE   = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_\-]+)*$`)
	winFeatureRE  = regexp.MustCompile(`^[A-Za-z0-9\-\.]{1,128}$`)
	regPathRE     = regexp.MustCompile(`^(HKLM|HKCU)\\[A-Za-z0-9 ._\-]+(\\[A-Za-z0-9 ._\-]+)*$`)
	modeRE        = regexp.MustCompile(`^[0-7]{3,4}$`)
	sha256RE      = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	ownerRE       = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._\-]{0,63}(:[A-Za-z0-9_][A-Za-z0-9._\-]{0,63})?$`)
)

func oneOf(field, v string, allowed ...string) error {
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return fmt.Errorf("%s: must be one of %s", field, strings.Join(allowed, ", "))
}

func validateService(raw json.RawMessage, dec decodeFunc) error {
	var p ServiceParams
	if err := dec(raw, &p); err != nil {
		return err
	}
	if !serviceNameRE.MatchString(p.Name) {
		return errors.New("name: a service or unit name is required")
	}
	if strings.ContainsAny(p.Name, `/`) {
		return errors.New("name: a service name cannot contain a slash")
	}
	if err := oneOf("state", p.State, "running", "stopped"); err != nil {
		return err
	}
	if p.StartType != "" {
		if err := oneOf("start_type", p.StartType, "auto", "manual", "disabled", "any"); err != nil {
			return err
		}
	}
	return nil
}

func validatePackage(raw json.RawMessage, dec decodeFunc) error {
	var p PackageParams
	if err := dec(raw, &p); err != nil {
		return err
	}
	if !pkgNameRE.MatchString(p.Name) {
		return errors.New("name: a package name or winget id is required")
	}
	switch p.Name[len(p.Name)-1] {
	case '-', ':':
		return errors.New("name: a package name cannot end with '-' or ':'")
	}
	if err := oneOf("state", p.State, "present", "absent"); err != nil {
		return err
	}
	if p.MinVersion != "" {
		if p.State != "present" {
			return errors.New("min_version: only applies when state is present")
		}
		if len(p.MinVersion) > 64 {
			return errors.New("min_version: too long")
		}
		if _, err := CompareVersions(p.MinVersion, p.MinVersion); err != nil {
			return fmt.Errorf("min_version: %q has no numeric field to compare", p.MinVersion)
		}
	}
	return nil
}

func validateRegistry(raw json.RawMessage, dec decodeFunc) error {
	var p RegistryParams
	if err := dec(raw, &p); err != nil {
		return err
	}
	if err := CheckRegistryPath(p.Path); err != nil {
		return fmt.Errorf("path: %w", err)
	}
	if len(p.Name) > 255 {
		return errors.New("name: a value name is at most 255 characters")
	}
	if err := oneOf("type", p.Type, "dword", "qword", "string", "expand_string", "multi_string"); err != nil {
		return err
	}
	_, err := p.Typed()
	return err
}

func validateFile(raw json.RawMessage, dec decodeFunc) error {
	var p FileParams
	if err := dec(raw, &p); err != nil {
		return err
	}
	if err := oneOf("state", p.State, "present", "absent"); err != nil {
		return err
	}
	if err := CheckFilePath(p.Path, p.State, p.Content); err != nil {
		return fmt.Errorf("path: %w", err)
	}
	if len(p.Content) > MaxFileContentBytes {
		return fmt.Errorf("content: %d bytes exceeds the %d byte limit", len(p.Content), MaxFileContentBytes)
	}
	if p.SHA256 != "" && !sha256RE.MatchString(p.SHA256) {
		return errors.New("sha256: must be 64 hex characters")
	}
	if len(p.Contains) > 4096 {
		return errors.New("contains: at most 4096 characters")
	}
	if p.Mode != "" {
		if !modeRE.MatchString(p.Mode) {
			return errors.New("mode: must be a 3- or 4-digit octal number")
		}
		m, err := strconv.ParseUint(p.Mode, 8, 32)
		if err != nil || m > 0o777 {
			return errors.New("mode: must be 0777 or lower with no setuid, setgid or sticky bit")
		}
	}
	if p.Owner != "" && !ownerRE.MatchString(p.Owner) {
		return errors.New("owner: must be user or user:group")
	}
	if p.State == "absent" && (p.Content != "" || p.SHA256 != "" || p.Contains != "" || p.Mode != "" || p.Owner != "") {
		return errors.New("state absent: content, sha256, contains, mode and owner do not apply")
	}
	return nil
}

func validateCommand(raw json.RawMessage, dec decodeFunc) error {
	var p CommandParams
	if err := dec(raw, &p); err != nil {
		return err
	}
	if err := oneOf("language", p.Language, "bash", "sh", "powershell", "cmd", "python"); err != nil {
		return err
	}
	if strings.TrimSpace(p.Check) == "" {
		return errors.New("check: a check script is required (a fix with no check is not a check)")
	}
	if len(p.Check) > MaxCommandBodyBytes {
		return fmt.Errorf("check: %d bytes exceeds the %d byte limit", len(p.Check), MaxCommandBodyBytes)
	}
	if len(p.Fix) > MaxCommandBodyBytes {
		return fmt.Errorf("fix: %d bytes exceeds the %d byte limit", len(p.Fix), MaxCommandBodyBytes)
	}
	if len(p.Expected) > MaxObservedBytes {
		return fmt.Errorf("expected: at most %d characters", MaxObservedBytes)
	}
	return nil
}

func validateGroupMembers(raw json.RawMessage, dec decodeFunc) error {
	var p GroupMembersParams
	if err := dec(raw, &p); err != nil {
		return err
	}
	if !groupNameRE.MatchString(p.Group) {
		return errors.New("group: a local group name is required")
	}
	if len(p.Allowed) > 256 {
		return errors.New("allowed: at most 256 names")
	}
	for i, m := range p.Allowed {
		if !memberNameRE.MatchString(m) {
			return fmt.Errorf("allowed[%d]: %q is not a valid account name", i, m)
		}
	}
	if p.Mode != "" {
		if err := oneOf("mode", p.Mode, "exact", "subset"); err != nil {
			return err
		}
	}
	return nil
}

func validateToggle(raw json.RawMessage, dec decodeFunc) error {
	var p ToggleParams
	return dec(raw, &p)
}

func validateSysctl(raw json.RawMessage, dec decodeFunc) error {
	var p SysctlParams
	if err := dec(raw, &p); err != nil {
		return err
	}
	if !sysctlKeyRE.MatchString(p.Key) {
		return errors.New("key: must look like net.ipv4.ip_forward")
	}
	if len(p.Key) > 256 {
		return errors.New("key: too long")
	}
	v := strings.TrimSpace(p.Value)
	if v == "" {
		return errors.New("value: a value is required (always a string)")
	}
	if len(v) > 256 || strings.ContainsAny(v, "\n\r") {
		return errors.New("value: must be a single short line")
	}
	return nil
}

func validateWindowsFeature(raw json.RawMessage, dec decodeFunc) error {
	var p WindowsFeatureParams
	if err := dec(raw, &p); err != nil {
		return err
	}
	if !winFeatureRE.MatchString(p.Name) {
		return errors.New("name: a Windows optional feature name is required")
	}
	return oneOf("state", p.State, "enabled", "disabled")
}

func validateRebootPending(raw json.RawMessage, dec decodeFunc) error {
	var p RebootPendingParams
	if err := dec(raw, &p); err != nil {
		return err
	}
	if p.MaxHours < 1 {
		return errors.New("max_hours: must be 1 or more")
	}
	if p.MaxHours > 24*365 {
		return errors.New("max_hours: must be a year or less")
	}
	return nil
}

func validateDiskFree(raw json.RawMessage, dec decodeFunc) error {
	var p DiskFreeParams
	if err := dec(raw, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Mount) == "" {
		return errors.New("mount: a mount point or drive is required")
	}
	if len(p.Mount) > 256 {
		return errors.New("mount: too long")
	}
	if !(p.MinFreePct > 0 && p.MinFreePct < 100) {
		return errors.New("min_free_pct: must be greater than 0 and less than 100")
	}
	return nil
}
