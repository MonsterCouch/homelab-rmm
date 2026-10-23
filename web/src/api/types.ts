// Wire types. Every interface mirrors a Go struct in internal/server/*.go or
// internal/protocol/protocol.go; field names are the JSON tags (snake_case).
// Keep them in sync by hand: the Go side is the source of truth.

// 'poc' is a client contact: support tickets for one organization, no console.
export type Role = 'admin' | 'tech' | 'viewer' | 'poc';

export interface User {
  id: number;
  username: string;
  role: Role;
  email: string;
  totp_enabled: boolean;
  created_at: number;
  last_login: number;
  org_scope?: string[];
}

export interface AuthState {
  needs_setup: boolean;
  /** first-run setup from another machine needs the code printed in the server log */
  setup_code_required?: boolean;
  user: User | null;
  version: string;
}

export interface LoginResponse {
  ok?: boolean;
  user?: User;
  needs_totp?: boolean;
}

export type OS = 'windows' | 'linux' | 'darwin' | string;

// ---- protocol ----

export interface Disk {
  device: string;
  mount: string;
  fs: string;
  total: number;
  used: number;
  free: number;
  used_pct: number;
}

export interface NetIface {
  name: string;
  mac: string;
  ips: string[] | null;
  up: boolean;
  speed_mbps?: number;
}

export interface Software {
  name: string;
  version: string;
  publisher?: string;
  installed?: string;
}

export interface Inventory {
  hostname: string;
  os: OS;
  platform: string;
  platform_version: string;
  kernel_version: string;
  arch: string;
  boot_time: number;
  cpu_model: string;
  cpu_cores: number;
  cpu_threads: number;
  mem_total: number;
  manufacturer: string;
  model: string;
  serial: string;
  bios_version: string;
  domain: string;
  logged_in_users: string[] | null;
  timezone: string;
  disks: Disk[] | null;
  network: NetIface[] | null;
  software: Software[] | null;
  gpus: string[] | null;
  public_ip?: string;
  pending_reboot: boolean;
  antivirus?: string;
  last_user?: string;
  agent_version: string;
  agent_path: string;
  collected_at: number;
  extra?: Record<string, string>;
}

export interface DiskUsage {
  mount: string;
  total: number;
  used: number;
  used_pct: number;
}

export interface Metrics {
  ts: number;
  cpu: number;
  mem_used: number;
  mem_total: number;
  swap_used: number;
  disks: DiskUsage[] | null;
  net_rx: number;
  net_tx: number;
  uptime: number;
  load1: number;
  procs: number;
  services?: Record<string, string>;
  pending_reboot: boolean;
  logged_in?: string[];
}

export interface MetricRow {
  ts: number;
  cpu: number;
  mem_used: number;
  mem_total: number;
  disks: DiskUsage[] | null;
  net_rx: number;
  net_tx: number;
  uptime: number;
  load1: number;
  procs: number;
}

export interface Process {
  pid: number;
  ppid: number;
  name: string;
  user: string;
  cpu: number;
  mem: number;
  cmdline: string;
  started: number;
}

export interface Service {
  name: string;
  display_name: string;
  state: string;
  start_type: string;
  pid?: number;
  description?: string;
}

export type ServiceAction = 'start' | 'stop' | 'restart' | 'enable' | 'disable' | 'manual';

export interface EventLogEntry {
  ts: number;
  level: string;
  source: string;
  event_id: number;
  message: string;
}

export interface FsEntry {
  name: string;
  path: string;
  is_dir: boolean;
  size: number;
  mtime: number;
  mode: string;
}

export interface FsListResult {
  path: string;
  entries: FsEntry[];
}

export type PowerAction = 'reboot' | 'shutdown' | 'lock' | 'logoff';

export interface Organization {
  id: string;
  name: string;
  device_count: number;
  site_count: number;
  created_at: number;
}

export interface Site {
  id: string;
  org_id: string;
  name: string;
  device_count: number;
  created_at: number;
}

// ---- server ----

export interface Agent {
  id: string;
  hostname: string;
  display_name: string;
  os: OS;
  platform: string;
  arch: string;
  version: string;
  org_id?: string;
  org_name?: string;
  site_id?: string;
  site_name?: string;
  group_id: number | null;
  group_name?: string;
  tags: string[];
  custom_fields: Record<string, string>;
  notes: string;
  last_ip: string;
  last_seen: number;
  online: boolean;
  monitored_services: string[];
  maintenance_until: number;
  enrolled_at: number;
  pending_reboot: boolean;
  last_metrics?: Metrics;
  inventory?: Inventory;
  open_alerts: number;
  patches_available: number;
  isolated?: boolean;
  isolated_at?: number;
  isolated_by?: string;
}

export interface AgentUpdate {
  display_name?: string;
  org_id?: string;
  site_id?: string;
  group_id?: number | null;
  clear_group?: boolean;
  tags?: string[];
  custom_fields?: Record<string, string>;
  notes?: string;
  monitored_services?: string[];
  maintenance_until?: number;
}

export interface AgentEvent {
  id: number;
  ts: number;
  kind: string;
  message: string;
  fields: Record<string, string> | null;
}

export interface Targets {
  all: boolean;
  agents?: string[];
  groups?: number[];
  tags?: string[];
  os?: string;
  organizations?: string[];
  sites?: string[];
}

export interface Group {
  id: number;
  name: string;
  description: string;
  agent_count: number;
  created_at: number;
}

export interface EnrollToken {
  id: number;
  token: string;
  name: string;
  org_id?: string;
  site_id?: string;
  group_id: number | null;
  uses_left: number;
  expires_at: number;
  created_by: string;
  created_at: number;
}

export interface EnrollList {
  tokens: EnrollToken[];
  public_url: string;
  fingerprint: string;
}

export interface EnrollCreate {
  name: string;
  org_id?: string;
  site_id?: string;
  group_id?: number | null;
  uses: number;
  ttl_hours: number;
}

export interface EnrollCreated {
  id: number;
  token: string;
  windows: string;
  linux: string;
}

export type Language = 'powershell' | 'cmd' | 'bash' | 'sh' | 'python';

export interface ScriptParam {
  name: string;
  description: string;
  default: string;
  required: boolean;
}

export interface Script {
  id: number;
  name: string;
  description: string;
  category: string;
  language: Language;
  body: string;
  params: ScriptParam[];
  timeout_sec: number;
  os_filter: string;
  created_at: number;
  updated_at: number;
}

export type RunStatus = 'pending' | 'queued' | 'running' | 'done' | 'failed' | 'timeout' | 'cancelled';

export interface Run {
  id: string;
  script_id: number | null;
  script_name: string;
  agent_id: string;
  agent_name: string;
  task_id: number | null;
  trigger: string;
  run_by: string;
  args: string[];
  status: RunStatus;
  exit_code: number;
  stdout?: string;
  stderr?: string;
  started_at: number;
  finished_at: number;
}

export interface RunScriptInput {
  script_id?: number | null;
  language?: Language;
  body?: string;
  args?: string[];
  env?: Record<string, string>;
  timeout_sec?: number;
  targets?: Targets;
  agent_ids?: string[];
}

/** POST /api/scripts/run: agent id -> run id, or "error: ..." / "skipped: ..." */
export interface RunScriptResult {
  runs: Record<string, string>;
}

export type TaskKind = 'script' | 'patch_scan' | 'patch_install' | 'reboot' | 'inventory';

export interface TaskOptions {
  reboot_if_required?: boolean;
  delay_sec?: number;
  online_only?: boolean;
}

export interface Task {
  id: number;
  name: string;
  description: string;
  kind: TaskKind;
  script_id: number | null;
  args: string[];
  targets: Targets;
  schedule: string;
  enabled: boolean;
  timeout_sec: number;
  options: TaskOptions;
  last_run: number;
  next_run: number;
  created_at: number;
  updated_at: number;
}

export type AutomationTrigger =
  | 'agent_online'
  | 'agent_offline'
  | 'alert_opened'
  | 'alert_resolved'
  | 'enrolled'
  | 'reboot_required'
  | 'patch_installed'
  | 'drift_detected'
  | 'drift_fixed';

export type AutomationAction = 'run_script' | 'email' | 'webhook';

export interface AutomationFilter {
  targets?: Targets;
  rule_ids?: number[];
  severity?: string;
}

export interface AutomationParams {
  script_id?: number;
  args?: string[];
  subject?: string;
  url?: string;
}

export interface Automation {
  id: number;
  name: string;
  trigger: AutomationTrigger;
  filter: AutomationFilter;
  action: AutomationAction;
  action_params: AutomationParams;
  enabled: boolean;
  created_at: number;
}

export type RuleKind =
  | 'cpu'
  | 'memory'
  | 'disk'
  | 'offline'
  | 'service'
  | 'reboot_required'
  | 'script_failed'
  | 'patch_failed'
  | 'event';

export type Severity = 'info' | 'warning' | 'critical';

export interface RuleParams {
  threshold: number;
  minutes: number;
  mount: string;
  service: string;
  pattern: string;
}

export interface AlertRule {
  id: number;
  name: string;
  kind: RuleKind;
  params: RuleParams;
  targets: Targets;
  severity: Severity;
  notify_email: boolean;
  auto_resolve: boolean;
  enabled: boolean;
  created_at: number;
}

export type AlertStatus = 'open' | 'acked' | 'resolved';

export interface Alert {
  id: number;
  rule_id: number | null;
  rule_kind: string;
  agent_id: string;
  agent_name: string;
  severity: Severity | string;
  title: string;
  message: string;
  status: AlertStatus;
  opened_at: number;
  acked_at: number;
  acked_by: string;
  resolved_at: number;
}

export type PatchStatus = 'available' | 'approved' | 'installing' | 'installed' | 'failed' | 'ignored';

export interface Patch {
  agent_id: string;
  agent_name?: string;
  patch_id: string;
  title: string;
  kb: string;
  severity: string;
  categories: string[];
  size: number;
  source: string;
  version: string;
  status: PatchStatus | string;
  reboot_required: boolean;
  /** Windows Update has already staged the payload: `size` is not a download still to come. */
  downloaded?: boolean;
  description?: string;
  first_seen: number;
  last_seen: number;
  installed_at: number;
  error: string;
}

export interface AgentPatches {
  patches: Patch[];
  last_scan: number;
  /**
   * What the agent said went wrong during the last scan, '' when it was clean.
   * A failed scan still refreshes last_scan and still answers 200, so this is
   * the only thing that says the list beside it may be stale.
   */
  scan_error?: string;
}

export interface PatchPolicy {
  id: number;
  name: string;
  targets: Targets;
  scan_schedule: string;
  install_schedule: string;
  mode: 'approved' | 'all' | 'security' | string;
  reboot: 'never' | 'if_required' | 'always' | string;
  enabled: boolean;
  created_at: number;
}

export interface MailSettings {
  host: string;
  port: number;
  username: string;
  password: string;
  from: string;
  to: string[] | null;
  tls: 'starttls' | 'tls' | 'none' | string;
  enabled: boolean;
}

export interface AgentConfig {
  metrics_interval_sec: number;
  inventory_interval_sec: number;
  patch_scan_interval_sec: number;
  monitored_services?: string[] | null;
}

export interface Retention {
  metrics_days: number;
  runs_days: number;
  audit_days: number;
  events_days: number;
}

export interface Settings {
  public_url: string;
  smtp: MailSettings;
  agent_defaults: AgentConfig;
  retention: Retention;
}

export interface SystemInfo {
  version: string;
  public_url: string;
  fingerprint: string;
  data_dir: string;
  db_bytes: number;
  uptime: number;
  agents_connected: number;
}

export interface AuditRow {
  id: number;
  ts: number;
  user: string;
  ip: string;
  action: string;
  target: string;
  details: string;
}

export interface Dashboard {
  agents_online: number;
  agents_offline: number;
  pending_reboot: number;
  windows: number;
  linux: number;
  open_alerts: number;
  critical_alerts: number;
  devices_need_patches: number;
  runs_24h: number;
  runs_failed_24h: number;
  recent_alerts: Alert[];
  recent_runs: Run[];
  server_version: string;
  uptime: number;
}

export interface TOTPBegin {
  secret: string;
  url: string;
}

export interface WolResult {
  ok: boolean;
  via: string;
  macs: string[];
}

// ---- baselines (desired state, drift detection, self-healing) ----
// Mirrors internal/server/api_baselines.go and internal/baselines. `params`
// is a JSON object on the wire; the shapes per kind live in
// components/baselines/kinds.ts, which is the console half of the one
// validator both the server and the agent use.

export type BaselineKind =
  | 'service'
  | 'package'
  | 'registry'
  | 'file'
  | 'command'
  | 'group_members'
  | 'firewall'
  | 'time_sync'
  | 'sysctl'
  | 'windows_feature'
  | 'reboot_pending'
  | 'disk_free';

/** A check's state after one evaluation pass. A check with no row yet is "unknown" in the UI only. */
export type BaselineState = 'pass' | 'fail' | 'fixed' | 'error' | 'skipped';

export type BaselineTrigger = 'schedule' | 'startup' | 'config' | 'manual' | 'remediate' | 'preview';

export type BaselineParams = Record<string, unknown>;

export interface BaselineCheck {
  /** 0 on a check that has not been saved yet; permanent once assigned (A1). */
  id: number;
  baseline_id?: number;
  /** presentation order only — never an identity */
  position?: number;
  name: string;
  kind: BaselineKind;
  params: BaselineParams;
  remediate: boolean;
  severity: Severity;
  os_filter: string;
  timeout_sec: number;
}

export interface Baseline {
  id: number;
  name: string;
  description: string;
  targets: Targets;
  enforce: boolean;
  interval_sec: number;
  notify_email: boolean;
  enabled: boolean;
  version: number;
  checks_count: number;
  devices: number;
  devices_reported: number;
  devices_drifted: number;
  devices_unknown: number;
  /** 0..100, or null when no check applies (A25) */
  compliance: number | null;
  last_change: number;
  created_at: number;
  updated_at: number;
}

export interface BaselineDetail extends Baseline {
  checks: BaselineCheck[];
}

/** POST /api/baselines and PUT /api/baselines/{id}. */
export interface BaselineInput {
  name: string;
  description: string;
  targets: Targets;
  enforce: boolean;
  interval_sec: number;
  notify_email: boolean;
  enabled: boolean;
  checks: BaselineCheckInput[];
  /** save a baseline whose targets match nothing (A50) */
  allow_empty_targets?: boolean;
  /** an allow_reboot check on {all:true} targets needs this (A41) */
  confirm_fleet_reboot?: boolean;
}

export interface BaselineCheckInput {
  /** omitted or 0 inserts; an existing id updates in place (A2) */
  id?: number;
  name: string;
  kind: BaselineKind;
  params: BaselineParams;
  remediate: boolean;
  severity: Severity;
  os_filter: string;
  timeout_sec: number;
}

export interface BaselineResult {
  check_id: number;
  state: BaselineState;
  expected: string;
  observed: string;
  detail: string;
  fixed: boolean;
  duration_ms: number;
  version: number;
  /** the baseline changed after this result: the console greys it as "awaiting re-evaluation" (A12) */
  stale: boolean;
  /** the device clock at evaluation */
  checked_at: number;
  /** server time the report landed */
  received_at: number;
  /** server time the current state began (A24) */
  since: number;
}

export interface BaselineCounts {
  pass: number;
  fail: number;
  fixed: number;
  error: number;
  skipped: number;
  unknown: number;
}

export interface BaselineDeviceStatus {
  agent_id: string;
  agent_name: string;
  os: OS;
  online: boolean;
  maintenance_until: number;
  compliance: number | null;
  stale: boolean;
  version: number;
  last_report: number;
  last_trigger: string;
  counts: BaselineCounts;
  results: BaselineResult[];
}

export interface BaselineSummary {
  devices: number;
  devices_reported: number;
  devices_drifted: number;
  devices_unknown: number;
  compliance: number | null;
}

export interface BaselineStatus {
  baseline: Baseline;
  checks: BaselineCheck[];
  devices: BaselineDeviceStatus[];
  summary: BaselineSummary;
  truncated: boolean;
}

export interface BaselineEvaluateAgent {
  agent_id: string;
  status: 'queued' | 'offline' | 'error' | string;
  error?: string;
}

export interface BaselineEvaluateResult {
  baseline_id: number;
  requested: number;
  queued: number;
  offline: number;
  agents: BaselineEvaluateAgent[];
}

export interface BaselineRefusal {
  check_id: number;
  reason: string;
}

export interface BaselineRemediateResult {
  baseline_id: number;
  agent_id: string;
  accepted: number[];
  refused: BaselineRefusal[];
  /** always null: the pass arrives as a `baseline` SSE event (A6) */
  report: null;
}

/** The unsaved spec a preview evaluates. Check ids are assigned by the server as -(index+1) (A7). */
export interface BaselinePreviewSpec {
  name: string;
  enforce: boolean;
  interval_sec: number;
  checks: BaselineCheckInput[];
}

export interface BaselinePreviewSpecCheck {
  index: number;
  id: number;
  name: string;
  kind: string;
  os_filter: string;
}

export interface BaselinePreviewResult {
  check_id: number;
  state: BaselineState;
  expected: string;
  observed: string;
  detail: string;
  fixed: boolean;
  duration_ms: number;
}

export interface BaselinePreviewDevice {
  agent_id: string;
  agent_name: string;
  os: OS;
  status: 'ok' | 'offline' | 'timeout' | 'error' | string;
  error: string;
  results: BaselinePreviewResult[];
  duration_ms: number;
}

export interface BaselinePreview {
  spec_checks: BaselinePreviewSpecCheck[];
  devices: BaselinePreviewDevice[];
}

export interface AgentBaselineCheck extends BaselineCheck {
  result: BaselineResult | null;
}

export interface AgentBaseline {
  id: number;
  name: string;
  enforce: boolean;
  enabled: boolean;
  interval_sec: number;
  version: number;
  last_report: number;
  last_trigger: string;
  stale: boolean;
  compliance: number | null;
  counts: BaselineCounts;
  checks: AgentBaselineCheck[];
}

export interface AgentBaselines {
  agent_id: string;
  online: boolean;
  compliance: number | null;
  baselines: AgentBaseline[];
}

export interface BaselineHistoryRow {
  id: number;
  ts: number;
  baseline_id: number;
  baseline_name: string;
  check_id: number;
  check_name: string;
  from_state: string;
  to_state: string;
  detail: string;
}

export interface AgentBaselineHistory {
  agent_id: string;
  history: BaselineHistoryRow[];
}

export interface ComplianceWorstCheck {
  baseline_id: number;
  baseline_name: string;
  check_id: number;
  check_name: string;
  kind: string;
  severity: string;
  failing: number;
  applicable: number;
}

export interface ComplianceBaseline {
  id: number;
  name: string;
  enabled: boolean;
  enforce: boolean;
  score: number | null;
  devices: number;
  devices_drifted: number;
}

export interface ComplianceSummary {
  score: number | null;
  devices_total: number;
  devices_with_baselines: number;
  devices_compliant: number;
  devices_drifted: number;
  devices_unknown: number;
  checks_total: number;
  checks_failing: number;
  checks_error: number;
  open_drift_alerts: number;
  baselines_enabled: number;
  baselines_enforcing: number;
  worst_checks: ComplianceWorstCheck[];
  by_baseline: ComplianceBaseline[];
  updated_at: number;
}

// ---- SSE ----

export type EventKind =
  | 'hello'
  | 'agent_online'
  | 'agent_offline'
  | 'metrics'
  | 'inventory'
  | 'event'
  | 'alert'
  | 'run'
  | 'patches'
  | 'baseline';

export interface RunEventData {
  run_id: string;
  status?: RunStatus;
  stream?: 'stdout' | 'stderr';
  data?: string;
  exit_code?: number;
}

export interface AlertEventData {
  id?: number;
  status?: string;
  severity?: string;
  title?: string;
}

/**
 * One ingested baseline report. It is a notification, not data: `changed`
 * carries only real transitions (capped at 20) and the console refetches.
 */
export interface BaselineEventData {
  baseline_id: number;
  version: number;
  trigger: string;
  ts: number;
  counts: { pass: number; fail: number; fixed: number; error: number; skipped: number };
  compliance: number | null;
  changed: { check_id: number; from: string; to: string }[];
  changed_truncated?: boolean;
}

export interface HubEvent<T = unknown> {
  kind: EventKind;
  agent_id?: string;
  data?: T;
}

export interface SoftwareCatalogItem {
  id: string;
  name: string;
  description: string;
  publisher: string;
  version: string;
  category: string;
  icon: string;
  install_cmd: string;
  uninstall_cmd: string;
  os: string;
  created_at: number;
  updated_at: number;
}

export interface DiscoveredDevice {
  id: string;
  ip: string;
  mac: string;
  hostname: string;
  vendor: string;
  os: string;
  device_type: string;
  open_ports: number[];
  snmp_enabled: boolean;
  snmp_sys_name: string;
  snmp_sys_descr: string;
  snmp_sys_uptime: number;
  snmp_interfaces: any[];
  discovered_by: string;
  org_id: string;
  site_id: string;
  status: string;
  first_seen: number;
  last_seen: number;
}

export interface NetworkScan {
  id: number;
  subnet: string;
  agent_id: string;
  status: string;
  devices_found: number;
  started_at: number;
  completed_at: number;
  error: string;
}

export interface Ticket {
  id: number;
  agent_id: string;
  org_id: string;
  site_id: string;
  subject: string;
  description: string;
  requester_name: string;
  requester_email: string;
  requester_phone: string;
  status: 'open' | 'in_progress' | 'waiting' | 'resolved' | 'closed';
  priority: 'low' | 'normal' | 'high' | 'urgent';
  assigned_to: string;
  agent_name?: string;
  is_internal?: boolean;
  source?: string;
  requester_domain_user?: string;
  comments_count?: number;
  created_at: number;
  updated_at: number;
  resolved_at: number;
}

export interface TicketComment {
  id: number;
  ticket_id: number;
  author: string;
  is_internal: boolean;
  body: string;
  created_at: number;
}

export interface TicketWithComments extends Ticket {
  comments: TicketComment[];
}

export interface PortalConfig {
  agent_id: string;
  agent_name: string;
  computer_name: string;
  domain_user: string;
  is_workgroup: boolean;
  org_id: string;
  org_name: string;
  site_id: string;
  site_name: string;
  os: string;
  is_poc: boolean;
  user?: User;
}

export interface PortalSoftwareItem {
  id: string;
  name: string;
  description: string;
  publisher: string;
  version: string;
  category: string;
  icon: string;
  installed: boolean;
  installed_version: string;
  has_update: boolean;
}

export interface PortalSoftwareActionReq {
  agent_id?: string;
  software_id: string;
  action: 'install' | 'uninstall' | 'update';
}

export interface StagedUpdate {
  available: boolean;
  path: string;
  size: number;
  mod_time: number;
  sha256: string;
  differs: boolean;
}

export interface ServerVersionInfo {
  version: string;
  os: string;
  arch: string;
  pid: number;
  exe_path: string;
  staged_update?: StagedUpdate;
}

// ---- Phase 3: operator-signed actions ----
// docs/plans/2026-10-06-phase3-signed-actions.md §4.1. Binary values are
// unpadded base64url strings.

/** 202 from a protected request that still needs more signers. */
export interface ApprovalPending {
  pending: true;
  manifest_id: string;
  have: number;
  need: number;
}

export interface WebAuthnCredential {
  id: string;
  name: string;
  /** COSE algorithm: -7 ES256, -8 EdDSA, -257 RS256 */
  alg: number;
  owner: string;
  created_at: number;
  last_used_at: number;
  in_bundle: boolean;
}

export type TrustMode = 'off' | 'audit' | 'enforce';

export interface TrustPolicy {
  mode?: TrustMode;
  require_uv?: boolean;
  high_threshold?: number;
  bundle_threshold?: number;
  bulk_limit?: number;
}

export interface TrustSigner {
  owner: string;
  /** bundle shape */
  creds?: { id: string; alg?: number; pub?: string }[];
  /** proposal-request shape */
  credential_ids?: string[];
}

export interface TrustCurrent {
  epoch: number;
  hash: string;
  mode?: TrustMode;
  policy?: TrustPolicy;
  signers?: TrustSigner[] | null;
  recovery_ids?: string[] | null;
  rp_id?: string;
  origins?: string[] | null;
}

export interface TrustProposal {
  id: string;
  epoch: number;
  /** exact bundle bytes; absent from list rows on some servers (GET /api/trust/proposals/{pid} has it) */
  bundle?: string;
  need: number;
  have: number;
  created_by?: string;
  created_at?: number;
}

export interface TrustAgentCounts {
  at_current: number;
  behind: number;
  mismatched: number;
  none: number;
}

export interface TrustInfo {
  current: TrustCurrent | null;
  proposals: TrustProposal[] | null;
  agents: TrustAgentCounts;
}

export interface TrustProposalInput {
  mode: TrustMode;
  require_uv: boolean;
  high_threshold: number;
  bundle_threshold: number;
  bulk_limit: number;
  signers: { owner: string; credential_ids: string[] }[];
  /** only the public half ever leaves the browser */
  recovery: { id: string; pub: string }[];
}

export interface ProposalSignResult {
  have: number;
  need: number;
  active: boolean;
}

export interface PendingApproval {
  manifest_id: string;
  /** exact manifest bytes; the console will not sign what it cannot show */
  manifest?: string;
  summary?: string;
  issuer?: string;
  org?: string;
  have: number;
  need: number;
  created_at?: number;
  expires_at?: number;
}

export type UnsignedType = 'task' | 'automation' | 'patch_policy' | 'catalog_item' | 'baseline';

export interface UnsignedObject {
  type: UnsignedType;
  id: string | number;
  name: string;
  reason: 'missing' | 'expired' | 'content changed';
}

/** POST /api/agents/{id}/grant */
export interface GrantResult {
  required?: boolean;
  expires_at?: number;
}
