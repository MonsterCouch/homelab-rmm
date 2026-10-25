import { b64urlEncode, utf8 } from '../lib/webauthn';
import { requestSigning, SigningCancelled, signerCommand } from '../lib/signing';
import { PARKED_MESSAGE, toast } from '../state/toast';
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
  LogHead,
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
  ApprovalPending,
  SignObjectResult,
  ComplianceSummary,
  Dashboard,
  DiscoveredDevice,
  EnrollCreate,
  EnrollCreated,
  EnrollList,
  EventLogEntry,
  FsListResult,
  GrantResult,
  Group,
  LoginResponse,
  MailSettings,
  MetricRow,
  NetworkScan,
  Organization,
  Patch,
  PatchPolicy,
  ServicingRecord,
  ServicingRepairRequest,
  PendingApproval,
  PortalConfig,
  PortalSoftwareActionReq,
  PortalSoftwareItem,
  ProposalSignResult,
  PowerAction,
  Process,
  Run,
  RunScriptInput,
  RunScriptResult,
  Script,
  Service,
  ServiceAction,
  ServerVersionInfo,
  Settings,
  Site,
  SoftwareCatalogItem,
  SystemInfo,
  Task,
  Ticket,
  TicketComment,
  TicketWithComments,
  TOTPBegin,
  TrustInfo,
  TrustProposal,
  TrustProposalInput,
  UnsignedObject,
  UnsignedType,
  UpdateAllResult,
  UpdateBatchResult,
  User,
  WebAuthnCredential,
  WolResult,
} from './types';
import type { Assertion, CreationOptionsJSON, RegistrationResult } from '../lib/webauthn';

/** ApiError carries the HTTP status so callers can branch on 401/403/409. */
export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

/** A 428 the operator parked for rmm-signer: a cancel as far as loops are concerned, so it is a 428 too. */
export class SigningParkedError extends ApiError {
  readonly manifestId: string;
  constructor(manifestId: string) {
    super(428, PARKED_MESSAGE);
    this.name = 'SigningParkedError';
    this.manifestId = manifestId;
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

/** What a 428 carries: the stored manifest the operator must sign (§4.1). */
interface Challenge428 {
  manifest_id: string;
  manifest: string;
  summary?: string;
  required?: boolean;
  rp_id?: string;
  allow_credentials?: string[];
  user_verification?: UserVerificationRequirement;
}

function asChallenge(data: unknown): Challenge428 | null {
  if (!data || typeof data !== 'object') return null;
  const d = data as Record<string, unknown>;
  if (typeof d.manifest_id !== 'string' || !d.manifest_id || typeof d.manifest !== 'string' || !d.manifest) return null;
  return {
    manifest_id: d.manifest_id,
    manifest: d.manifest,
    summary: typeof d.summary === 'string' ? d.summary : undefined,
    // Unknown means required: never offer to skip a signature the server did not say is optional.
    required: d.required !== false,
    rp_id: typeof d.rp_id === 'string' ? d.rp_id : undefined,
    allow_credentials: Array.isArray(d.allow_credentials) ? d.allow_credentials.filter((x): x is string => typeof x === 'string') : undefined,
    user_verification: d.user_verification === 'required' || d.user_verification === 'discouraged' || d.user_verification === 'preferred' ? d.user_verification : undefined,
  };
}

/** True for the 202 body of a request that still needs other operators' signatures. */
export function isPending(v: unknown): v is ApprovalPending {
  return !!v && typeof v === 'object' && (v as { pending?: unknown }).pending === true;
}

interface Sent {
  res: Response;
  data: unknown;
}

async function send(method: Method, url: string, opts: RequestOptions, raw: BodyInit | undefined, extra?: Record<string, string>): Promise<Sent> {
  const headers: Record<string, string> = {
    // CSRF guard: the server rejects state-changing requests without this header.
    'X-Requested-With': 'fetch',
    Accept: 'application/json',
    ...extra,
  };
  let body: BodyInit | undefined;
  if (raw !== undefined) {
    body = raw;
    headers['Content-Type'] = 'application/octet-stream';
  } else if (opts.body !== undefined) {
    // serialized afresh each time from the same value, so a signed retry
    // carries the identical bytes
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
  return { res, data };
}

/**
 * Ask the operator to sign a 428 challenge and return the headers for the
 * retry. Cancelling becomes an ApiError so callers' existing catch blocks see
 * an ordinary failed request.
 */
async function signHeaders(ch: Challenge428, signal?: AbortSignal): Promise<Record<string, string>> {
  let decision;
  try {
    decision = await requestSigning(
      {
        docKind: 'manifest',
        doc: ch.manifest,
        manifestId: ch.manifest_id,
        summary: ch.summary,
        required: ch.required !== false,
        rpId: ch.rp_id,
        allowCredentials: ch.allow_credentials,
        userVerification: ch.user_verification,
      },
      signal,
    );
  } catch (err) {
    if (err instanceof SigningCancelled) {
      if (signal?.aborted) throw new DOMException('aborted', 'AbortError');
      throw new ApiError(428, 'Signature required: nothing was sent because the action was not signed.');
    }
    throw err;
  }
  if (decision.kind === 'park') {
    announceParked(ch.manifest_id);
    throw new SigningParkedError(ch.manifest_id);
  }
  if (decision.kind === 'skip') return { 'X-Action-Auth': 'skip' };
  return { 'X-Action-Auth': b64urlEncode(utf8(JSON.stringify({ manifest_id: ch.manifest_id, assertion: decision.assertion }))) };
}

/** Tell the operator how to finish a parked manifest; it stays until dismissed because the id is needed later. */
export function announceParked(manifestId: string): void {
  try {
    toast().push('info', 'Waiting for rmm-signer', 'Nothing was sent. The request waits until it expires; sign it with rmm-signer or from the Approvals page.', {
      sticky: true,
      copy: signerCommand(manifestId),
    });
  } catch {
    /* no toast host (tests) */
  }
}

async function request<T>(method: Method, url: string, opts: RequestOptions = {}): Promise<T> {
  // A stream body is single-use; the signed retry has to resend it.
  const raw = typeof ReadableStream !== 'undefined' && opts.raw instanceof ReadableStream ? await new Response(opts.raw).blob() : opts.raw;
  let { res, data } = await send(method, url, opts, raw);

  // Phase 3: a protected action in an organisation with a trust bundle answers
  // 428 with the manifest it will dispatch. Show it, have the operator sign
  // it, then repeat the identical request carrying the assertion. The server
  // dispatches the stored manifest, not this request's body.
  // (The auth and portal endpoints, which pass noRedirect, are never signed.)
  if (res.status === 428 && !opts.noRedirect) {
    const ch = asChallenge(data);
    if (ch) {
      const extra = await signHeaders(ch, opts.signal);
      ({ res, data } = await send(method, url, opts, raw, extra));
    }
  }

  // 202: signed, but the policy wants more operators. Not an error; the
  // caller gets the body (see isPending) and the operator is told once.
  if (res.status === 202 && isPending(data)) {
    const more = Math.max(1, data.need - data.have);
    try {
      toast().info(`Waiting for ${more} more approver${more === 1 ? '' : 's'}`, 'Other operators can add their signature under Approvals.');
    } catch {
      /* no toast host (tests) */
    }
    return data as T;
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

/** The upload reply from a device that checks signatures: the bytes are staged
 *  on the device, and moving them into place needs a signed commit. */
interface StagedUpload {
  staged: true;
  commit_required: boolean;
  upload_id: string;
  bytes: number;
  sha256: string;
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
  setup: (username: string, password: string, email: string, code = '') =>
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
  agents: (params?: { org_id?: string; site_id?: string }) => list(get<Agent[] | null>(`/api/agents${qs(params ?? {})}`)).then((l) => l.map(normAgent)),
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
  /** Uploads a file. To a device that checks signatures the bytes are staged
   *  first, then a small commit naming their size and SHA-256 is sent through
   *  the signing flow, so the file itself is never re-sent for a signature.
   *  Resolves to ApprovalPending when more approvers are needed. */
  fsUpload: async (id: string, path: string, file: File): Promise<Ok | ApprovalPending> => {
    const r = await request<Ok | StagedUpload>('POST', `/api/agents/${enc(id)}/fs/upload${qs({ path })}`, { raw: file });
    if ('commit_required' in r && r.commit_required) {
      return post<Ok | ApprovalPending>(`/api/agents/${enc(id)}/fs/commit`, { upload_id: r.upload_id });
    }
    return r as Ok;
  },
  fsDelete: (id: string, path: string) => post<Ok>(`/api/agents/${enc(id)}/fs/delete`, { path }),
  fsMkdir: (id: string, path: string) => post<Ok>(`/api/agents/${enc(id)}/fs/mkdir`, { path }),
  fsRename: (id: string, from: string, to: string) => post<Ok>(`/api/agents/${enc(id)}/fs/rename`, { from, to }),
  power: (id: string, action: PowerAction, delay_sec: number, message: string) =>
    post<Ok>(`/api/agents/${enc(id)}/power`, { action, delay_sec, message }),
  wol: (id: string) => post<WolResult>(`/api/agents/${enc(id)}/wol`),
  isolateAgent: (id: string, isolate: boolean) =>
    post<{ ok: boolean; isolated: boolean }>(`/api/agents/${enc(id)}/isolate`, { isolate }),
  runOnAgent: (id: string, input: RunScriptInput) => post<{ run_id: string }>(`/api/agents/${enc(id)}/run`, input),
  agentPatches: (id: string) => get<AgentPatches>(`/api/agents/${enc(id)}/patches`).then((r) => ({ ...r, patches: arr(r.patches).map((p) => ({ ...p, categories: arr(p.categories) })) })),
  patchScan: (id: string) => post<AgentPatches>(`/api/agents/${enc(id)}/patches/scan`).then((r) => ({ ...r, patches: arr(r.patches).map((p) => ({ ...p, categories: arr(p.categories) })) })),
  patchInstall: (id: string, body: { ids?: string[]; all?: boolean; reboot_if_required: boolean }) =>
    post<Ok>(`/api/agents/${enc(id)}/patches/install`, body),
  servicingRecords: (id: string, limit = 20) => list(get<ServicingRecord[] | null>(`/api/agents/${enc(id)}/servicing?limit=${limit}`)),
  servicingRepair: (id: string, body: ServicingRepairRequest) => post<Ok & { id: number }>(`/api/agents/${enc(id)}/servicing/repair`, body),

  // ---- organizations & sites ----
  organizations: () => list(get<Organization[] | null>('/api/organizations')),
  createOrganization: (o: { name: string }) => post<Organization>('/api/organizations', o),
  updateOrganization: (id: string, o: { name: string }) => put<Organization>(`/api/organizations/${enc(id)}`, o),
  deleteOrganization: (id: string) => del<Ok>(`/api/organizations/${enc(id)}`),
  sites: (orgId: string) => list(get<Site[] | null>(`/api/organizations/${enc(orgId)}/sites`)),
  allSites: () => list(get<Site[] | null>('/api/sites')),
  createSite: (orgId: string, s: { name: string }) => post<Site>(`/api/organizations/${enc(orgId)}/sites`, s),
  updateSite: (id: string, s: { name: string }) => put<Site>(`/api/sites/${enc(id)}`, s),
  deleteSite: (id: string) => del<Ok>(`/api/sites/${enc(id)}`),

  // ---- groups / enrollment ----
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
  createUser: (u: { username: string; password: string; role: string; email: string; org_scope?: string[] }) =>
    post<{ id: number }>('/api/users', u),
  updateUser: (id: number, u: { role?: string; email?: string; password?: string; reset_totp?: boolean; org_scope?: string[] }) =>
    put<Ok>(`/api/users/${id}`, u),
  deleteUser: (id: number) => del<Ok>(`/api/users/${id}`),

  // ---- software catalog & privileged execution ----
  softwareCatalog: (os?: string) => list(get<SoftwareCatalogItem[] | null>(`/api/software-catalog${os ? `?os=${encodeURIComponent(os)}` : ''}`)),
  softwareCatalogItem: (id: string) => get<SoftwareCatalogItem>(`/api/software-catalog/${encodeURIComponent(id)}`),
  createSoftwareCatalogItem: (it: Partial<SoftwareCatalogItem>) => post<SoftwareCatalogItem>('/api/software-catalog', it),
  updateSoftwareCatalogItem: (id: string, it: Partial<SoftwareCatalogItem>) => put<SoftwareCatalogItem>(`/api/software-catalog/${encodeURIComponent(id)}`, it),
  deleteSoftwareCatalogItem: (id: string) => del<Ok>(`/api/software-catalog/${encodeURIComponent(id)}`),
  installSoftware: (agentId: string, req: { catalog_id?: string; custom_cmd?: string }) =>
    post<{ run_id: string; status: string; app_name: string }>(`/api/agents/${enc(agentId)}/software/install`, req),
  uninstallSoftware: (agentId: string, req: { catalog_id?: string; custom_cmd?: string }) =>
    post<{ run_id: string; status: string; app_name: string }>(`/api/agents/${enc(agentId)}/software/uninstall`, req),

  // ---- network discovery & SNMP ----
  discoveredDevices: (org_id = '', site_id = '', status = '') =>
    list(get<DiscoveredDevice[] | null>(`/api/discovered-devices${qs({ org_id, site_id, status })}`)),
  discoveredDevice: (id: string) => get<DiscoveredDevice>(`/api/discovered-devices/${enc(id)}`),
  updateDiscoveredDevice: (id: string, dev: Partial<DiscoveredDevice>) =>
    put<DiscoveredDevice>(`/api/discovered-devices/${enc(id)}`, dev),
  deleteDiscoveredDevice: (id: string) => del<Ok>(`/api/discovered-devices/${enc(id)}`),
  pollSNMP: (id: string) => post<DiscoveredDevice>(`/api/discovered-devices/${enc(id)}/poll`),
  networkScans: () => list(get<NetworkScan[] | null>('/api/network-scans')),
  startNetworkScan: (subnet: string, agent_id = '') =>
    post<NetworkScan>('/api/network-scans', { subnet, agent_id }),

  // ---- helpdesk tickets ----
  tickets: (params: { status?: string; priority?: string; agent_id?: string; org_id?: string; assigned_to?: string; q?: string } = {}) =>
    list(get<Ticket[] | null>(`/api/tickets${qs(params)}`)),
  ticket: (id: number) => get<Ticket & { comments: TicketComment[] }>(`/api/tickets/${id}`),
  createTicket: (t: Partial<Ticket>) => post<Ticket>('/api/tickets', t),
  updateTicket: (id: number, t: Partial<Ticket>) => put<Ticket>(`/api/tickets/${id}`, t),
  deleteTicket: (id: number) => del<Ok>(`/api/tickets/${id}`),
  addTicketComment: (ticketId: number, c: { body: string; is_internal?: boolean }) =>
    post<TicketComment>(`/api/tickets/${ticketId}/comments`, c),
  agentTickets: (agentId: string) => list(get<Ticket[] | null>(`/api/agents/${enc(agentId)}/tickets`)),

  // ---- client portal ----
  // Who the caller is (device and signed-in user) comes from the portal
  // sign-in the tray app's pass set up, never from these parameters.
  // agent_id only picks a device for a console user viewing the portal.
  // A 401 here means "reopen from the tray", not "go to the console login".
  portalConfig: (params: { agent_id?: string } = {}) =>
    get<PortalConfig>(`/api/portal/config${qs(params)}`, { noRedirect: true }),
  portalSoftware: (params: { agent_id?: string } = {}) =>
    list(get<PortalSoftwareItem[] | null>(`/api/portal/software${qs(params)}`, { noRedirect: true })),
  portalSoftwareAction: (req: PortalSoftwareActionReq) =>
    post<{ ok: boolean; run_id: string; message: string; status: string; app_name: string }>('/api/portal/software/action', req, { noRedirect: true }),
  portalRun: (id: string) =>
    get<{ id: string; status: string; exit_code: number; stdout: string; stderr: string; started_at: number; finished_at: number }>(`/api/portal/runs/${enc(id)}`, { noRedirect: true }),
  portalTickets: (params: { agent_id?: string; status?: string; q?: string } = {}) =>
    list(get<Ticket[] | null>(`/api/portal/tickets${qs(params)}`, { noRedirect: true })),
  portalTicket: (id: number) =>
    get<TicketWithComments>(`/api/portal/tickets/${id}`, { noRedirect: true }),
  portalCreateTicket: (req: { agent_id?: string; subject: string; description: string; requester_name: string; requester_email?: string; requester_phone?: string; priority?: string }) =>
    post<{ ok: boolean; id: number }>('/api/portal/tickets', req, { noRedirect: true }),
  portalAddComment: (id: number, req: { body: string }) =>
    post<TicketComment>(`/api/portal/tickets/${id}/comments`, req, { noRedirect: true }),

  // ---- Phase 3: security keys, trust bundles, approvals, grants ----
  // See docs/plans/2026-10-06-phase3-signed-actions.md §4.1. Calls that the
  // server protects with a signature (grant, signObject, any destructive
  // action) answer 428 and request() runs the signing dialog; none of these
  // wrappers needs to know.
  webauthnCredentials: () => list(get<WebAuthnCredential[] | null>('/api/webauthn/credentials')),
  webauthnRegisterBegin: () => post<CreationOptionsJSON | { publicKey: CreationOptionsJSON }>('/api/webauthn/register/begin'),
  webauthnRegisterFinish: (name: string, r: RegistrationResult) => post<WebAuthnCredential>('/api/webauthn/register/finish', { name, ...r }),
  deleteWebauthnCredential: (id: string) => del<Ok>(`/api/webauthn/credentials/${enc(id)}`),
  trust: (orgId: string) =>
    get<TrustInfo>(`/api/organizations/${enc(orgId)}/trust`).then((r) => ({ ...r, current: r.current ?? null, proposals: arr(r.proposals) })),
  createTrustProposal: (orgId: string, p: TrustProposalInput) =>
    post<TrustProposal>(`/api/organizations/${enc(orgId)}/trust/proposals`, p),
  logHead: () => get<LogHead>('/api/log/head'),
  trustProposal: (pid: string) => get<TrustProposal>(`/api/trust/proposals/${enc(pid)}`),
  signTrustProposal: (pid: string, assertion: Assertion) =>
    post<ProposalSignResult>(`/api/trust/proposals/${enc(pid)}/sign`, { assertion }),
  recoverTrustProposal: (pid: string, r: { id: string; sig: string }) =>
    post<{ active: boolean }>(`/api/trust/proposals/${enc(pid)}/recovery`, r),
  approvals: () => list(get<PendingApproval[] | null>('/api/approvals')),
  signApproval: (manifestId: string, assertion: Assertion) =>
    post<ProposalSignResult | ApprovalPending>(`/api/approvals/${enc(manifestId)}/sign`, { assertion }),
  unsignedApprovals: (org: string) => list(get<UnsignedObject[] | null>(`/api/approvals/unsigned${qs({ org })}`)),
  // goes through the 428 flow itself: the standing manifest is built from the object's current content
  // org and purpose name one unit of the object; without them the server signs the first one that needs it
  signObject: (type: UnsignedType, id: string | number, opts?: { org?: string; purpose?: string }) =>
    post<SignObjectResult>(`/api/approvals/objects/${enc(type)}/${enc(String(id))}/sign${qs({ org: opts?.org, purpose: opts?.purpose })}`),
  grant: (agentId: string, ops: string[]) => post<GrantResult | ApprovalPending>(`/api/agents/${enc(agentId)}/grant`, { ops }),

  // ---- system & agent updates ----
  serverVersion: () => get<ServerVersionInfo>('/api/server/version'),
  updateServer: () => post<{ ok: boolean; message: string }>('/api/server/update'),
  dispatchAgentUpdate: (agentId: string) => post<{ ok: boolean; message: string; installing?: boolean; up_to_date?: boolean }>(`/api/agents/${enc(agentId)}/update`),
  /** Updates the devices of organizations that do not sign actions at once and
   *  returns the rest as groups; lib/fleetUpdate.ts asks for one signature per
   *  group through updateAgentBatch. */
  updateAllAgents: () => post<UpdateAllResult>('/api/agents/update-all'),
  /** One signed update for the devices of one group, through the signing flow.
   *  Resolves to ApprovalPending when more approvers are needed. */
  updateAgentBatch: (agentIds: string[]) => post<UpdateBatchResult | ApprovalPending>('/api/agents/update-batch', { agent_ids: agentIds }),
};

export type Api = typeof api;
