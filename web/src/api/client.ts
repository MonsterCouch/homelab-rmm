import type {
  Agent,
  AgentBaselineHistory,
  AgentBaselines,
  AgentEvent,
  AgentPatches,
  AgentUpdate,
  Alert,
  AlertRule,
  AuditRow,
  AuthState,
  Automation,
  Baseline,
  BaselineDetail,
  BaselineEvaluateResult,
  BaselineInput,
  BaselinePreview,
  BaselinePreviewSpec,
  BaselineRemediateResult,
  BaselineStatus,
  ComplianceSummary,
  Dashboard,
  EnrollCreate,
  EnrollCreated,
  EnrollList,
  EventLogEntry,
  FsListResult,
  Group,
  LoginResponse,
  MailSettings,
  MetricRow,
  Patch,
  PatchPolicy,
  PowerAction,
  Process,
  Run,
  RunScriptInput,
  RunScriptResult,
  Script,
  Service,
  ServiceAction,
  Settings,
  SystemInfo,
  Task,
  TOTPBegin,
  User,
  WolResult,
} from './types';

/** ApiError carries the HTTP status so callers can branch on 401/403/409. */
export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

interface RequestOptions {
  body?: unknown;
  /** raw body (file upload) — sent as-is with application/octet-stream */
  raw?: BodyInit;
  signal?: AbortSignal;
  /** do not redirect to /login on 401 (used by the auth endpoints themselves) */
  noRedirect?: boolean;
}

let onUnauthorized: (() => void) | null = null;

/** The auth provider installs a handler that clears the session and routes to /login. */
export function setUnauthorizedHandler(fn: (() => void) | null): void {
  onUnauthorized = fn;
}

async function request<T>(method: Method, url: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = {
    // CSRF guard: the server rejects state-changing requests without this header.
    'X-Requested-With': 'fetch',
    Accept: 'application/json',
  };
  let body: BodyInit | undefined;
  if (opts.raw !== undefined) {
    body = opts.raw;
    headers['Content-Type'] = 'application/octet-stream';
  } else if (opts.body !== undefined) {
    body = JSON.stringify(opts.body);
    headers['Content-Type'] = 'application/json';
  }
  let res: Response;
  try {
    res = await fetch(url, { method, headers, body, credentials: 'same-origin', signal: opts.signal });
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') throw err;
    throw new ApiError(0, 'network error: the server could not be reached');
  }
  if (res.status === 401 && !opts.noRedirect) {
    onUnauthorized?.();
  }
  const text = await res.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!res.ok) {
    const msg =
      data && typeof data === 'object' && 'error' in data && typeof (data as { error: unknown }).error === 'string'
        ? (data as { error: string }).error
        : typeof data === 'string' && data
          ? data
          : `${res.status} ${res.statusText}`;
    throw new ApiError(res.status, msg);
  }
  return data as T;
}

const get = <T>(url: string, opts?: RequestOptions) => request<T>('GET', url, opts);
const post = <T>(url: string, body?: unknown, opts?: RequestOptions) => request<T>('POST', url, { ...opts, body });
const put = <T>(url: string, body?: unknown) => request<T>('PUT', url, { body });
const patch = <T>(url: string, body?: unknown) => request<T>('PATCH', url, { body });
const del = <T>(url: string) => request<T>('DELETE', url);

function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : '';
}

const enc = encodeURIComponent;

interface Ok {
  ok: boolean;
}

// Go encodes a nil slice as null. Every list column on the server is
// initialised to an empty slice, but a failed query or a hand-edited row can
// still produce null, and `...a.tags` on null would take the whole page down.
const arr = <T>(v: T[] | null | undefined): T[] => (Array.isArray(v) ? v : []);
const list = <T>(p: Promise<T[] | null>): Promise<T[]> => p.then(arr);

function normAgent(a: Agent): Agent {
  return {
    ...a,
    tags: arr(a.tags),
    monitored_services: arr(a.monitored_services),
    custom_fields: a.custom_fields && typeof a.custom_fields === 'object' ? a.custom_fields : {},
  };
}

// params is a JSON object on the wire; a hand-edited row or an older server
// can still produce null, and every kind form reads params.<field>.
function normCheck<T extends { params?: unknown }>(c: T): T {
  return { ...c, params: c.params && typeof c.params === 'object' ? (c.params as Record<string, unknown>) : {} };
}

function normBaselineDetail(b: BaselineDetail): BaselineDetail {
  return { ...b, checks: arr(b.checks).map(normCheck) };
}

export const api = {
  // ---- auth ----
  authState: () => get<AuthState>('/api/auth/state', { noRedirect: true }),
  setup: (username: string, password: string, email: string, code: string) =>
    post<Ok>('/api/auth/setup', { username, password, email, code }, { noRedirect: true }),
  login: (username: string, password: string, code: string) =>
    post<LoginResponse>('/api/auth/login', { username, password, code }, { noRedirect: true }),
  logout: () => post<Ok>('/api/auth/logout', undefined, { noRedirect: true }),
  me: () => get<User>('/api/me'),
  changePassword: (current: string, next: string) => post<Ok>('/api/me/password', { current, new: next }),
  totpBegin: () => post<TOTPBegin>('/api/me/totp/begin'),
  totpConfirm: (code: string) => post<Ok>('/api/me/totp/confirm', { code }),
  totpDisable: (password: string) => post<Ok>('/api/me/totp/disable', { password }),

  // ---- dashboard / system ----
  dashboard: () => get<Dashboard>('/api/dashboard'),
  system: () => get<SystemInfo>('/api/system'),
  audit: (limit = 500) => list(get<AuditRow[] | null>(`/api/audit${qs({ limit })}`)),

  // ---- devices ----
  agents: () => list(get<Agent[] | null>('/api/agents')).then((l) => l.map(normAgent)),
  agent: (id: string) => get<Agent>(`/api/agents/${enc(id)}`).then(normAgent),
  updateAgent: (id: string, u: AgentUpdate) => patch<Agent>(`/api/agents/${enc(id)}`, u).then(normAgent),
  deleteAgent: (id: string) => del<Ok>(`/api/agents/${enc(id)}`),
  agentMetrics: (id: string, from: number, to: number, points = 400) =>
    list(get<MetricRow[] | null>(`/api/agents/${enc(id)}/metrics${qs({ from, to, points })}`)),
  agentEvents: (id: string, limit = 200) => list(get<AgentEvent[] | null>(`/api/agents/${enc(id)}/events${qs({ limit })}`)),
  refreshAgent: (id: string) => post<Ok>(`/api/agents/${enc(id)}/refresh`),
  processes: (id: string, signal?: AbortSignal) => list(get<Process[] | null>(`/api/agents/${enc(id)}/processes`, { signal })),
  killProcess: (id: string, pid: number) => post<Ok>(`/api/agents/${enc(id)}/processes/kill`, { pid }),
  services: (id: string, signal?: AbortSignal) => list(get<Service[] | null>(`/api/agents/${enc(id)}/services`, { signal })),
  serviceAction: (id: string, name: string, action: ServiceAction) =>
    post<Service>(`/api/agents/${enc(id)}/services/action`, { name, action }),
  eventLog: (id: string, q: { log: string; level: string; limit: number; search: string }, signal?: AbortSignal) =>
    list(get<EventLogEntry[] | null>(`/api/agents/${enc(id)}/eventlog${qs(q)}`, { signal })),
  fsList: (id: string, path: string, signal?: AbortSignal) =>
    get<FsListResult>(`/api/agents/${enc(id)}/fs${qs({ path })}`, { signal }),
  fsDownloadURL: (id: string, path: string) => `/api/agents/${enc(id)}/fs/download${qs({ path })}`,
  fsUpload: (id: string, path: string, file: File) =>
    request<Ok>('POST', `/api/agents/${enc(id)}/fs/upload${qs({ path })}`, { raw: file }),
  fsDelete: (id: string, path: string) => post<Ok>(`/api/agents/${enc(id)}/fs/delete`, { path }),
  fsMkdir: (id: string, path: string) => post<Ok>(`/api/agents/${enc(id)}/fs/mkdir`, { path }),
  fsRename: (id: string, from: string, to: string) => post<Ok>(`/api/agents/${enc(id)}/fs/rename`, { from, to }),
  power: (id: string, action: PowerAction, delay_sec: number, message: string) =>
    post<Ok>(`/api/agents/${enc(id)}/power`, { action, delay_sec, message }),
  wol: (id: string) => post<WolResult>(`/api/agents/${enc(id)}/wol`),
  runOnAgent: (id: string, input: RunScriptInput) => post<{ run_id: string }>(`/api/agents/${enc(id)}/run`, input),
  agentPatches: (id: string) => get<AgentPatches>(`/api/agents/${enc(id)}/patches`).then((r) => ({ ...r, patches: arr(r.patches).map((p) => ({ ...p, categories: arr(p.categories) })) })),
  patchScan: (id: string) => post<AgentPatches>(`/api/agents/${enc(id)}/patches/scan`).then((r) => ({ ...r, patches: arr(r.patches).map((p) => ({ ...p, categories: arr(p.categories) })) })),
  patchInstall: (id: string, body: { ids?: string[]; all?: boolean; reboot_if_required: boolean }) =>
    post<Ok>(`/api/agents/${enc(id)}/patches/install`, body),

  // ---- groups / enrolment ----
  groups: () => list(get<Group[] | null>('/api/groups')),
  createGroup: (name: string, description = '') => post<Group>('/api/groups', { name, description }),
  updateGroup: (id: number, name: string, description = '') => put<Ok>(`/api/groups/${id}`, { name, description }),
  deleteGroup: (id: number) => del<Ok>(`/api/groups/${id}`),
  enrollTokens: () => get<EnrollList>('/api/enroll').then((r) => ({ ...r, tokens: arr(r.tokens) })),
  createEnroll: (input: EnrollCreate) => post<EnrollCreated>('/api/enroll', input),
  deleteEnroll: (id: number) => del<Ok>(`/api/enroll/${id}`),

  // ---- scripts / runs ----
  scripts: () => list(get<Script[] | null>('/api/scripts')).then((l) => l.map((s) => ({ ...s, params: arr(s.params) }))),
  script: (id: number) => get<Script>(`/api/scripts/${id}`).then((s) => ({ ...s, params: arr(s.params) })),
  createScript: (s: Partial<Script>) => post<Script>('/api/scripts', s),
  updateScript: (id: number, s: Partial<Script>) => put<Script>(`/api/scripts/${id}`, s),
  deleteScript: (id: number) => del<Ok>(`/api/scripts/${id}`),
  runScript: (input: RunScriptInput) => post<RunScriptResult>('/api/scripts/run', input),
  runs: (agent = '', limit = 200) => list(get<Run[] | null>(`/api/runs${qs({ agent, limit })}`)),
  run: (id: string) => get<Run>(`/api/runs/${enc(id)}`).then((r) => ({ ...r, args: arr(r.args) })),
  cancelRun: (id: string) => post<Ok>(`/api/runs/${enc(id)}/cancel`),

  // ---- tasks ----
  tasks: () => list(get<Task[] | null>('/api/tasks')).then((l) => l.map((t) => ({ ...t, args: arr(t.args), targets: t.targets ?? { all: false }, options: t.options ?? {} }))),
  createTask: (t: Partial<Task>) => post<Task>('/api/tasks', t),
  updateTask: (id: number, t: Partial<Task>) => put<Task>(`/api/tasks/${id}`, t),
  deleteTask: (id: number) => del<Ok>(`/api/tasks/${id}`),
  runTask: (id: number) => post<{ ok: boolean; devices: number }>(`/api/tasks/${id}/run`),

  // ---- automations ----
  automations: () => list(get<Automation[] | null>('/api/automations')).then((l) => l.map((a) => ({ ...a, filter: a.filter ?? {}, action_params: a.action_params ?? {} }))),
  createAutomation: (a: Partial<Automation>) => post<Automation>('/api/automations', a),
  updateAutomation: (id: number, a: Partial<Automation>) => put<Automation>(`/api/automations/${id}`, a),
  deleteAutomation: (id: number) => del<Ok>(`/api/automations/${id}`),

  // ---- alerts ----
  alertRules: () => list(get<AlertRule[] | null>('/api/alert-rules')),
  createAlertRule: (r: Partial<AlertRule>) => post<AlertRule>('/api/alert-rules', r),
  updateAlertRule: (id: number, r: Partial<AlertRule>) => put<AlertRule>(`/api/alert-rules/${id}`, r),
  deleteAlertRule: (id: number) => del<Ok>(`/api/alert-rules/${id}`),
  alerts: (status: 'open' | 'acked' | 'resolved' | 'all' = 'open', agent = '', limit = 500) =>
    list(get<Alert[] | null>(`/api/alerts${qs({ status, agent, limit })}`)),
  ackAlert: (id: number) => post<Ok>(`/api/alerts/${id}/ack`),
  resolveAlert: (id: number) => post<Ok>(`/api/alerts/${id}/resolve`),
  resolveAllAlerts: () => post<{ ok: boolean; resolved: number }>('/api/alerts/resolve-all'),

  // ---- patches ----
  patches: (agent = '', status = '') => list(get<Patch[] | null>(`/api/patches${qs({ agent, status })}`)).then((l) => l.map((p) => ({ ...p, categories: arr(p.categories) }))),
  patchStatus: (items: { AgentID: string; PatchID: string }[], status: 'approved' | 'ignored' | 'available') =>
    post<Ok>('/api/patches/status', { items, status }),
  patchPolicies: () => list(get<PatchPolicy[] | null>('/api/patch-policies')),
  createPatchPolicy: (p: Partial<PatchPolicy>) => post<PatchPolicy>('/api/patch-policies', p),
  updatePatchPolicy: (id: number, p: Partial<PatchPolicy>) => put<PatchPolicy>(`/api/patch-policies/${id}`, p),
  deletePatchPolicy: (id: number) => del<Ok>(`/api/patch-policies/${id}`),

  // ---- baselines ----
  baselines: () => list(get<Baseline[] | null>('/api/baselines')),
  baseline: (id: number) => get<BaselineDetail>(`/api/baselines/${id}`).then(normBaselineDetail),
  createBaseline: (b: BaselineInput) => post<BaselineDetail>('/api/baselines', b).then(normBaselineDetail),
  updateBaseline: (id: number, b: BaselineInput) => put<BaselineDetail>(`/api/baselines/${id}`, b).then(normBaselineDetail),
  deleteBaseline: (id: number) => del<Ok>(`/api/baselines/${id}`),
  baselineStatus: (id: number, limit = 200) =>
    get<BaselineStatus>(`/api/baselines/${id}/status${qs({ limit })}`).then((r) => ({
      ...r,
      checks: arr(r.checks).map(normCheck),
      devices: arr(r.devices).map((d) => ({ ...d, results: arr(d.results) })),
    })),
  // A fan-out: always 200, with a per-agent queued/offline/error status.
  evaluateBaseline: (id: number, agent_ids?: string[]) =>
    post<BaselineEvaluateResult>(`/api/baselines/${id}/evaluate`, { agent_ids: agent_ids ?? [] }).then((r) => ({ ...r, agents: arr(r.agents) })),
  // 409 when the device is offline: a fix cannot be queued.
  remediateBaseline: (id: number, agent_id: string, check_ids?: number[]) =>
    post<BaselineRemediateResult>(`/api/baselines/${id}/remediate`, { agent_id, check_ids: check_ids ?? [] }).then((r) => ({
      ...r,
      accepted: arr(r.accepted),
      refused: arr(r.refused),
    })),
  previewBaseline: (spec: BaselinePreviewSpec, agent_ids: string[]) =>
    post<BaselinePreview>('/api/baselines/preview', { spec, agent_ids }).then((r) => ({
      spec_checks: arr(r.spec_checks),
      devices: arr(r.devices).map((d) => ({ ...d, results: arr(d.results) })),
    })),
  agentBaselines: (id: string) =>
    get<AgentBaselines>(`/api/agents/${enc(id)}/baselines`).then((r) => ({
      ...r,
      baselines: arr(r.baselines).map((b) => ({ ...b, checks: arr(b.checks).map((c) => ({ ...normCheck(c), result: c.result ?? null })) })),
    })),
  // baselineId narrows the rows server-side. Filtering here instead would
  // show an empty drawer whenever another baseline owns the newest `limit`
  // transitions.
  agentBaselineHistory: (id: string, limit = 100, baselineId?: number) =>
    get<AgentBaselineHistory>(`/api/agents/${enc(id)}/baselines/history${qs({ limit, baseline_id: baselineId })}`).then((r) => ({ ...r, history: arr(r.history) })),
  compliance: () =>
    get<ComplianceSummary>('/api/compliance').then((r) => ({ ...r, worst_checks: arr(r.worst_checks), by_baseline: arr(r.by_baseline) })),

  // ---- admin ----
  settings: () => get<Settings>('/api/settings'),
  saveSettings: (s: Settings) => put<Settings>('/api/settings', s),
  testMail: (smtp: MailSettings) => post<Ok>('/api/settings/test-mail', smtp),
  users: () => list(get<User[] | null>('/api/users')),
  createUser: (u: { username: string; password: string; role: string; email: string }) =>
    post<{ id: number }>('/api/users', u),
  updateUser: (id: number, u: { role?: string; email?: string; password?: string; reset_totp?: boolean }) =>
    put<Ok>(`/api/users/${id}`, u),
  deleteUser: (id: number) => del<Ok>(`/api/users/${id}`),
};

export type Api = typeof api;
