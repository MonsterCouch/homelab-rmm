// Package protocol defines the messages exchanged between the RMM server and
// its agents. Both sides speak JSON envelopes over a WebSocket; every
// server-initiated request carries an ID that the agent echoes back in its
// reply, so the server can run many requests concurrently over one socket.
package protocol

import "encoding/json"

// Version is bumped when an incompatible change is made to the envelope or to
// a message the server relies on. Agents with an older version are still
// accepted, but the server reports them as outdated.
const Version = 1

// Envelope is the wire frame. T is the message type, ID correlates a reply
// with its request, D is the type-specific payload and Err carries an error
// string in a reply instead of D.
type Envelope struct {
	T   string          `json:"t"`
	ID  string          `json:"id,omitempty"`
	D   json.RawMessage `json:"d,omitempty"`
	Err string          `json:"err,omitempty"`
	// A carries the operator signatures that authorize a protected request
	// (docs/plans/2026-10-06-phase3-signed-actions.md). Agents without a
	// trust bundle ignore it; old agents never see it as anything but an
	// unknown field.
	A *ActionAuth `json:"a,omitempty"`
	// Log is set on an agent's reply to a protected request: the size of the
	// transparency log head the device holds now, so the server can send the
	// next consistency proof from the right place.
	Log int64 `json:"log,omitempty"`
}

// Message types sent by the agent.
const (
	TypeHello     = "hello"     // first frame after connecting
	TypeInventory = "inventory" // full inventory snapshot
	TypeMetrics   = "metrics"   // periodic sample
	TypeReply     = "reply"     // response to a server request
	TypeStream    = "stream"    // chunk of a long-running request (shell, script)
	TypeEvent     = "event"     // unsolicited notification (service change, reboot required)
	TypePong      = "pong"
)

// Message types sent by the server. Each is a request the agent answers with a
// TypeReply carrying the same ID (or a sequence of TypeStream then TypeReply).
const (
	ReqPing              = "ping"
	ReqInventoryRefresh  = "inventory.refresh"
	ReqShellOpen         = "shell.open"
	ReqShellInput        = "shell.input"
	ReqShellResize       = "shell.resize"
	ReqShellClose        = "shell.close"
	ReqScriptRun         = "script.run"
	ReqScriptCancel      = "script.cancel"
	ReqProcList          = "proc.list"
	ReqProcKill          = "proc.kill"
	ReqSvcList           = "svc.list"
	ReqSvcAction         = "svc.action"
	ReqUpdatesScan       = "updates.scan"
	ReqUpdatesInstall    = "updates.install"
	ReqEventLogQuery     = "eventlog.query"
	ReqFsList            = "fs.list"
	ReqFsRead            = "fs.read"
	ReqFsWrite           = "fs.write"
	ReqFsDelete          = "fs.delete"
	ReqFsMkdir           = "fs.mkdir"
	ReqFsRename          = "fs.rename"
	ReqPower             = "power"
	ReqDesktopStart      = "desktop.start"
	ReqWakeOnLan         = "wol"
	ReqAgentUpdate       = "agent.update"
	ReqAgentConfig       = "agent.config"
	ReqBaselineEvaluate  = "baseline.evaluate"  // evaluate assigned baselines now; reply is an ACK, results arrive as TypeBaseline frames
	ReqBaselineRemediate = "baseline.remediate" // run the fixes for listed checks now; reply is an ACK, the result arrives as a TypeBaseline frame
	ReqBaselinePreview   = "baseline.preview"   // evaluate an unsaved spec, never storing or fixing; reply BaselineReport
	ReqDeviceIsolate     = "device.isolate"     // firewall isolate or release endpoint
	ReqNetworkScan       = "network.scan"       // agent-driven subnet probe
	ReqSNMPPoll          = "snmp.poll"          // agent-driven SNMP query
	ReqTrustUpdate       = "trust.update"       // replace the agent's trust bundle (signed by the current bundle's signers or a recovery key)
	ReqFsStage           = "fs.stage"           // append a chunk of an upload to an agent-private staging file; nothing reads it until fs.commit
	ReqFsCommit          = "fs.commit"          // move a staged upload into place once its size and SHA-256 match
)

// TypeBaseline is sent by the agent after every evaluation pass (scheduled,
// startup, manual or remediation) with one BaselineReport.
const TypeBaseline = "baseline"

// Hello is the agent's first frame.
type Hello struct {
	AgentID         string `json:"agent_id"`
	Hostname        string `json:"hostname"`
	OS              string `json:"os"`       // windows, linux, darwin
	Platform        string `json:"platform"` // "Windows 11 Pro 23H2", "Ubuntu 24.04"
	Arch            string `json:"arch"`
	Version         string `json:"version"`
	ProtocolVersion int    `json:"protocol_version"`
	// TrustEpoch and TrustHash identify the trust bundle the agent holds
	// (zero / empty: none yet). The server replays the bundles the agent
	// is missing as trust.update requests after the welcome.
	TrustEpoch int64  `json:"trust_epoch,omitempty"`
	TrustHash  string `json:"trust_hash,omitempty"`
	// LogSize is the size of the last transparency log head the device
	// accepted (0: none yet). ExecutedHead is the head of the device's
	// hash-chained executed.log.
	LogSize      int64  `json:"log_size,omitempty"`
	ExecutedHead string `json:"executed_head,omitempty"`
}

// AgentConfig is pushed by the server after hello and whenever settings change.
type AgentConfig struct {
	MetricsIntervalSec   int      `json:"metrics_interval_sec"`
	InventoryIntervalSec int      `json:"inventory_interval_sec"`
	PatchScanIntervalSec int      `json:"patch_scan_interval_sec"`
	MonitoredServices    []string `json:"monitored_services"`
	// Baselines are the desired-state specs assigned to this device. The
	// agent evaluates them on their own interval, offline too, and reports
	// with TypeBaseline. An empty list clears every assignment.
	Baselines []BaselineSpec `json:"baselines,omitempty"`
	// BaselineAuth holds each spec's standing approval, keyed by the spec's
	// ID in decimal. An agent holding a trust bundle keeps only the specs
	// whose approval verifies (in enforce mode; audit keeps and reports).
	BaselineAuth map[string]*ActionAuth `json:"baseline_auth,omitempty"`
}

// Inventory is the full description of a device.
type Inventory struct {
	Hostname      string     `json:"hostname"`
	OS            string     `json:"os"`
	Platform      string     `json:"platform"`
	PlatformVer   string     `json:"platform_version"`
	KernelVer     string     `json:"kernel_version"`
	Arch          string     `json:"arch"`
	BootTime      int64      `json:"boot_time"`
	CPUModel      string     `json:"cpu_model"`
	CPUCores      int        `json:"cpu_cores"`
	CPUThreads    int        `json:"cpu_threads"`
	MemTotal      uint64     `json:"mem_total"`
	Manufacturer  string     `json:"manufacturer"`
	Model         string     `json:"model"`
	Serial        string     `json:"serial"`
	BIOSVersion   string     `json:"bios_version"`
	Domain        string     `json:"domain"`
	LoggedInUsers []string   `json:"logged_in_users"`
	Timezone      string     `json:"timezone"`
	Disks         []Disk     `json:"disks"`
	Network       []NetIface `json:"network"`
	Software      []Software `json:"software"`
	GPUs          []string   `json:"gpus"`
	PublicIP      string     `json:"public_ip,omitempty"`
	// ExecutedHead is the head of the device's hash-chained executed.log,
	// reported so the server cannot quietly drop an executed manifest.
	ExecutedHead  string `json:"executed_head,omitempty"`
	PendingReboot bool   `json:"pending_reboot"`
	AntivirusName string `json:"antivirus,omitempty"`
	LastUser      string `json:"last_user,omitempty"`
	AgentVersion  string `json:"agent_version"`
	AgentPath     string `json:"agent_path"`
	CollectedAt   int64  `json:"collected_at"`
	Extra         Extra  `json:"extra,omitempty"`
}

// Extra holds free-form platform specifics.
type Extra map[string]string

type Disk struct {
	Device  string  `json:"device"`
	Mount   string  `json:"mount"`
	FS      string  `json:"fs"`
	Total   uint64  `json:"total"`
	Used    uint64  `json:"used"`
	Free    uint64  `json:"free"`
	UsedPct float64 `json:"used_pct"`
}

type NetIface struct {
	Name  string   `json:"name"`
	MAC   string   `json:"mac"`
	IPs   []string `json:"ips"`
	Up    bool     `json:"up"`
	Speed int64    `json:"speed_mbps,omitempty"`
}

type Software struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Publisher string `json:"publisher,omitempty"`
	Installed string `json:"installed,omitempty"`
}

// Metrics is a periodic sample.
type Metrics struct {
	TS            int64             `json:"ts"`
	CPUPct        float64           `json:"cpu"`
	MemUsed       uint64            `json:"mem_used"`
	MemTotal      uint64            `json:"mem_total"`
	SwapUsed      uint64            `json:"swap_used"`
	Disks         []DiskUsage       `json:"disks"`
	NetRxBps      uint64            `json:"net_rx"`
	NetTxBps      uint64            `json:"net_tx"`
	Uptime        uint64            `json:"uptime"`
	Load1         float64           `json:"load1"`
	ProcCount     int               `json:"procs"`
	Services      map[string]string `json:"services,omitempty"` // monitored service -> state
	PendingReboot bool              `json:"pending_reboot"`
	LoggedIn      []string          `json:"logged_in,omitempty"`
}

type DiskUsage struct {
	Mount   string  `json:"mount"`
	Total   uint64  `json:"total"`
	Used    uint64  `json:"used"`
	UsedPct float64 `json:"used_pct"`
}

// Event is an unsolicited notification from the agent.
type Event struct {
	Kind    string            `json:"kind"` // "service", "reboot_required", "log", "patch"
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
	TS      int64             `json:"ts"`
}

// ---- Shell ----

type ShellOpen struct {
	Shell string `json:"shell"` // "powershell", "cmd", "bash", "sh", "" = default
	Cols  int    `json:"cols"`
	Rows  int    `json:"rows"`
}

type ShellInput struct {
	Session string `json:"session"`
	Data    string `json:"data"` // raw bytes as string
}

type ShellResize struct {
	Session string `json:"session"`
	Cols    int    `json:"cols"`
	Rows    int    `json:"rows"`
}

type ShellClose struct {
	Session string `json:"session"`
}

// ShellChunk is streamed back for the shell.open request ID. EOF marks the end.
type ShellChunk struct {
	Session string `json:"session"`
	Data    string `json:"data,omitempty"`
	EOF     bool   `json:"eof,omitempty"`
}

// Default script execution resource quotas.
const (
	DefaultScriptMaxMemoryMB     uint64 = 1024 // Default memory ceiling: 1024 MB (1 GB)
	DefaultScriptCPULimitPercent uint32 = 80   // Default CPU rate hard cap: 80%
)

// ---- Scripts ----

type ScriptRun struct {
	RunID           string            `json:"run_id"`
	Language        string            `json:"language"` // powershell, cmd, bash, sh, python
	Body            string            `json:"body"`
	Args            []string          `json:"args,omitempty"`
	Env             map[string]string `json:"env,omitempty"`
	Timeout         int               `json:"timeout_sec"`
	RunAs           string            `json:"run_as,omitempty"`            // "" (system) or "user"
	MaxMemoryMB     uint64            `json:"max_memory_mb,omitempty"`     // 0 = default (1024 MB)
	CPULimitPercent uint32            `json:"cpu_limit_percent,omitempty"` // 0 = default (80%)
}

type ScriptChunk struct {
	RunID  string `json:"run_id"`
	Stream string `json:"stream"` // "stdout" or "stderr"
	Data   string `json:"data"`
}

type ScriptResult struct {
	RunID    string `json:"run_id"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	TimedOut bool   `json:"timed_out"`
	Error    string `json:"error,omitempty"`
	Duration int64  `json:"duration_ms"`
}

// ---- Processes ----

type Process struct {
	PID     int32   `json:"pid"`
	PPID    int32   `json:"ppid"`
	Name    string  `json:"name"`
	User    string  `json:"user"`
	CPUPct  float64 `json:"cpu"`
	MemRSS  uint64  `json:"mem"`
	Cmdline string  `json:"cmdline"`
	Started int64   `json:"started"`
}

type ProcKill struct {
	PID int32 `json:"pid"`
}

// ---- Services ----

type Service struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	State       string `json:"state"`      // running, stopped, ...
	StartType   string `json:"start_type"` // auto, manual, disabled
	PID         int    `json:"pid,omitempty"`
	Description string `json:"description,omitempty"`
}

type SvcAction struct {
	Name   string `json:"name"`
	Action string `json:"action"` // start, stop, restart, enable, disable, manual
}

// ---- Updates ----

type Update struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	KB          string   `json:"kb,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Categories  []string `json:"categories,omitempty"`
	SizeBytes   int64    `json:"size,omitempty"`
	Installed   bool     `json:"installed"`
	Downloaded  bool     `json:"downloaded"`
	RebootReq   bool     `json:"reboot_required"`
	Description string   `json:"description,omitempty"`
	Version     string   `json:"version,omitempty"` // linux: candidate version
	Source      string   `json:"source,omitempty"`  // "wua", "apt", "dnf", "pacman", "winget"
}

type UpdatesScanResult struct {
	Updates       []Update `json:"updates"`
	RebootPending bool     `json:"reboot_pending"`
	LastScan      int64    `json:"last_scan"`
	Error         string   `json:"error,omitempty"`
}

type UpdatesInstall struct {
	IDs    []string `json:"ids"` // empty = all available
	Reboot bool     `json:"reboot_if_required"`
}

type UpdatesInstallResult struct {
	Installed []string          `json:"installed"`
	Failed    map[string]string `json:"failed"`
	RebootReq bool              `json:"reboot_required"`
	Log       string            `json:"log"`
}

// ---- Event log ----

type EventLogQuery struct {
	Log     string `json:"log"`   // windows: System/Application/Security; linux: "" for journal
	Level   string `json:"level"` // error, warning, info, all
	Limit   int    `json:"limit"`
	Search  string `json:"search,omitempty"`
	SinceTS int64  `json:"since,omitempty"`
}

type EventLogEntry struct {
	TS      int64  `json:"ts"`
	Level   string `json:"level"`
	Source  string `json:"source"`
	EventID int    `json:"event_id"`
	Message string `json:"message"`
}

// ---- Files ----

type FsList struct {
	Path string `json:"path"` // "" = roots (drives on Windows, / on linux)
}

type FsEntry struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	IsDir   bool   `json:"is_dir"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"mtime"`
	Mode    string `json:"mode"`
}

type FsListResult struct {
	Path    string    `json:"path"`
	Entries []FsEntry `json:"entries"`
	// Truncated is set when the directory held more entries than the agent
	// will put in one frame. Optional and omitted when false, so an older
	// server simply ignores it; an older agent never sets it, which is the
	// behaviour the server already assumes.
	Truncated bool `json:"truncated,omitempty"`
}

type FsRead struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset"`
	Length int64  `json:"length"` // 0 = whole file (capped by agent)
}

type FsReadResult struct {
	Data []byte `json:"data"` // base64 by encoding/json
	Size int64  `json:"size"`
	EOF  bool   `json:"eof"`
}

type FsWrite struct {
	Path   string `json:"path"`
	Data   []byte `json:"data"`
	Append bool   `json:"append"`
}

// FsStage appends Data at Offset of the staging file for UploadID. Offset
// must equal the bytes staged so far (0 starts the upload over), so a chunk
// that arrives twice or out of order is refused rather than corrupting it.
type FsStage struct {
	UploadID string `json:"upload_id"`
	Offset   int64  `json:"offset"`
	Data     []byte `json:"data"`
}

// FsCommit moves the staged upload UploadID to Path, but only when the
// staged bytes are exactly Size long and hash to SHA256 (lowercase hex). It
// is what an operator signs for an upload: a destination and a digest,
// rather than the file itself, so a signed upload is not limited by the size
// of a manifest.
type FsCommit struct {
	UploadID string `json:"upload_id"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}

type FsPath struct {
	Path string `json:"path"`
}

type FsRename struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// ---- Power ----

type Power struct {
	Action  string `json:"action"` // reboot, shutdown, lock, logoff
	Delay   int    `json:"delay_sec"`
	Message string `json:"message,omitempty"`
}

// ---- Desktop ----

// DesktopMode defines the operational target desktop.
type DesktopMode string

const (
	DesktopModeConsole   DesktopMode = "console"   // Interactive user screen (winsta0\default)
	DesktopModeBackstage DesktopMode = "backstage" // Isolated administrative desktop (winsta0\HomelabRMM_Backstage)
)

// DesktopStart asks the agent to spawn its desktop helper in the interactive
// session. The helper connects back to the server on its own WebSocket using
// Token, and the server bridges it to the operator's browser.
type DesktopStart struct {
	Token        string      `json:"token"`
	Quality      int         `json:"quality"`                 // JPEG quality 1-100
	Mode         DesktopMode `json:"mode,omitempty"`          // console (default) or backstage
	EnableWebRTC bool        `json:"enable_webrtc,omitempty"` // true if viewer supports WebRTC
}

type DesktopStartResult struct {
	Started     bool        `json:"started"`
	Note        string      `json:"note,omitempty"`
	Mode        DesktopMode `json:"mode,omitempty"`
	WebRTCAvail bool        `json:"webrtc_avail,omitempty"`
}

// WebRTCSignalingMessage encapsulates JSON signaling messages exchanged between
// the browser viewer and the agent desktop helper via the server WebSocket bridge.
type WebRTCSignalingMessage struct {
	Type       string          `json:"t"`                     // "webrtc_offer", "webrtc_answer", "webrtc_candidate", "webrtc_config", "webrtc_active", "fallback_tiles"
	SDP        string          `json:"sdp,omitempty"`         // For offer and answer
	Candidate  json.RawMessage `json:"candidate,omitempty"`   // For trickle ICE candidate
	Reason     string          `json:"reason,omitempty"`      // For fallback notification
	ICEServers json.RawMessage `json:"ice_servers,omitempty"` // For webrtc_config
}

// ---- Device Isolation ----

type DeviceIsolate struct {
	Isolate    bool   `json:"isolate"`
	ServerHost string `json:"server_host,omitempty"`
	ServerPort int    `json:"server_port,omitempty"`
}

type DeviceIsolateResult struct {
	Isolated bool   `json:"isolated"`
	Message  string `json:"message,omitempty"`
}

// ---- Baselines (desired state) ----
//
// A baseline is a set of checks that describe how a device should look. The
// agent evaluates it on IntervalSec (offline too), fixes drift when the
// baseline is enforced and the check allows remediation, and reports every
// pass. Check kinds and their params are documented in docs/BASELINES.md.

type BaselineSpec struct {
	ID          int64           `json:"id"`
	Name        string          `json:"name"`
	Version     int             `json:"version"` // bumped on every edit; reports echo it
	Enforce     bool            `json:"enforce"` // auto-remediate checks that allow it
	IntervalSec int             `json:"interval_sec"`
	Checks      []BaselineCheck `json:"checks"`
}

type BaselineCheck struct {
	ID         int64           `json:"id"`
	Name       string          `json:"name"`
	Kind       string          `json:"kind"`   // service, package, registry, file, command, group_members, firewall, time_sync, sysctl, windows_feature, reboot_pending, disk_free
	Params     json.RawMessage `json:"params"` // kind-specific, see docs/BASELINES.md
	Remediate  bool            `json:"remediate"`
	Severity   string          `json:"severity"`  // info, warning, critical (drift alert severity)
	OSFilter   string          `json:"os_filter"` // "", windows, linux
	TimeoutSec int             `json:"timeout_sec"`
}

// BaselineReport is one evaluation pass of one baseline on one device.
type BaselineReport struct {
	BaselineID int64            `json:"baseline_id"`
	Version    int              `json:"version"`
	TS         int64            `json:"ts"`
	Trigger    string           `json:"trigger"` // schedule, startup, config, manual, remediate, preview
	Results    []BaselineResult `json:"results"`
}

type BaselineResult struct {
	CheckID    int64  `json:"check_id"`
	State      string `json:"state"` // pass, fail, fixed, error, skipped
	Expected   string `json:"expected"`
	Observed   string `json:"observed"`
	Detail     string `json:"detail,omitempty"` // explanation, error text or fix output (bounded)
	Fixed      bool   `json:"fixed"`            // a remediation ran in this pass
	DurationMs int64  `json:"duration_ms"`
}

type BaselineEvaluate struct {
	BaselineIDs []int64 `json:"baseline_ids,omitempty"` // empty = every assigned baseline
}

type BaselineRemediate struct {
	BaselineID int64   `json:"baseline_id"`
	CheckIDs   []int64 `json:"check_ids,omitempty"` // empty = every failing check that allows remediation
}

type BaselinePreview struct {
	Spec BaselineSpec `json:"spec"`
}

// ---- Wake-on-LAN ----

type WakeOnLan struct {
	MAC       string `json:"mac"`
	Broadcast string `json:"broadcast,omitempty"`
}

// ---- Agent self-update ----

type AgentUpdate struct {
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Version string `json:"version"`
}

// ---- Network Discovery & SNMP ----

type NetworkScanReq struct {
	Subnet string `json:"subnet"`
}

type DiscoveredHost struct {
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

type NetworkScanResp struct {
	Hosts []DiscoveredHost `json:"hosts"`
}

type SNMPPollReq struct {
	IP        string `json:"ip"`
	Community string `json:"community,omitempty"`
}

type SNMPPollResp struct {
	SysName   string `json:"sys_name"`
	SysDescr  string `json:"sys_descr"`
	SysUpTime int64  `json:"sys_uptime"`
}

// Must marshals v, panicking on failure; every payload here is a plain struct
// so a failure is a programming error.
func Must(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// ---- Action authorization (Phase 3) ----
//
// See internal/actionauth for the verification rules and
// docs/plans/2026-10-06-phase3-signed-actions.md for the design. Every
// binary field is unpadded base64url.

// Assertion is one WebAuthn assertion used as a signature: the authenticator
// signed authenticatorData || SHA-256(clientDataJSON), and clientDataJSON's
// challenge is SHA-256 of the signed document.
type Assertion struct {
	Cred string `json:"cred"` // credential ID
	AD   string `json:"ad"`   // authenticatorData
	CD   string `json:"cd"`   // clientDataJSON
	Sig  string `json:"sig"`  // signature
}

// ActionAuth is a signed manifest and its detached signatures. M is the
// exact manifest bytes; nobody re-serializes them.
type ActionAuth struct {
	M string      `json:"m"`
	S []Assertion `json:"s"`
	// L proves the manifest is in the server's transparency log. The
	// handler sets only Index; the hub completes the proof per send.
	L *LogProof `json:"l,omitempty"`
}

// LogProof is an inclusion proof for a manifest leaf against a signed tree
// head, optionally with a consistency proof from the head the device last
// accepted.
type LogProof struct {
	Head        string   `json:"head"`                  // base64 of the signed tree head note
	Index       int64    `json:"index"`                 // the manifest's leaf
	Proof       []string `json:"proof"`                 // inclusion proof, base64 hashes
	From        int64    `json:"from,omitempty"`        // size of the head the consistency proof starts from, 0 = none
	Consistency []string `json:"consistency,omitempty"` // consistency proof, base64 hashes
}

// RecoverySig is an Ed25519 signature by an offline recovery key over the
// exact bundle bytes.
type RecoverySig struct {
	ID  string `json:"id"`
	Sig string `json:"sig"`
}

// TrustUpdate replaces the agent's trust bundle. Bundle is the exact bundle
// bytes; S are WebAuthn assertions by signers of the agent's CURRENT bundle,
// R are recovery-key signatures.
type TrustUpdate struct {
	Bundle string        `json:"bundle"`
	S      []Assertion   `json:"s,omitempty"`
	R      []RecoverySig `json:"r,omitempty"`
}

// Security events are TypeEvent frames with Event.Kind "security". Fields:
// "op" (the request type), "mode" (audit | enforce), "executed" ("true" or
// "false"), "reason" (why verification failed, or what changed) and
// "manifest" (the manifest ID, when one was presented).
const EventKindSecurity = "security"
