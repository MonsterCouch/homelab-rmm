// Wire types. Every interface mirrors a Go struct in internal/server/*.go or
// internal/protocol/protocol.go; field names are the JSON tags (snake_case).
// Keep them in sync by hand: the Go side is the source of truth.

export type Role = 'admin' | 'tech' | 'viewer';

export interface User {
  id: number;
  username: string;
  role: Role;
  email: string;
  totp_enabled: boolean;
  created_at: number;
  last_login: number;
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

// ---- server ----

export interface Agent {
  id: string;
  hostname: string;
  display_name: string;
  os: OS;
  platform: string;
  arch: string;
  version: string;
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
}

export interface AgentUpdate {
  display_name?: string;
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
  | 'patch_installed';

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
  first_seen: number;
  last_seen: number;
  installed_at: number;
  error: string;
}

export interface AgentPatches {
  patches: Patch[];
  last_scan: number;
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
  | 'patches';

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

export interface HubEvent<T = unknown> {
  kind: EventKind;
  agent_id?: string;
  data?: T;
}
