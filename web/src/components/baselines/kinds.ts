// The console half of the one check definition. internal/baselines/kinds.go
// is the source of truth: the server rejects a bad check with a 400 naming
// the field and the agent reports `error` rather than running it, so every
// rule here has a twin there. Keeping them in step is the point — a form that
// can produce params the server refuses is a dead end for the operator, and a
// form that produces a key the server does not know is a silent 400.
//
// Unknown keys in params are REJECTED by the server, so each kind lists the
// exact keys it may emit and the raw-JSON editor is checked against them.

import type { BaselineCheck, BaselineCheckInput, BaselineKind, BaselineParams } from '../../api/types';

// Limits, mirrored from internal/baselines (MaxNameLen, MaxChecksPerBaseline…).
export const LIMITS = {
  name: 120,
  description: 2000,
  params: 16 << 10,
  commandParams: 2 * (64 << 10) + (4 << 10),
  fileParams: (256 << 10) + (8 << 10),
  checksPerBaseline: 64,
  commandBody: 64 << 10,
  fileContent: 256 << 10,
  minInterval: 60,
  maxInterval: 86400,
  defaultInterval: 3600,
  minTimeout: 5,
  maxTimeout: 600,
  defaultTimeout: 60,
  previewAgents: 10,
} as const;

export interface KindDef {
  id: BaselineKind;
  label: string;
  /** platforms the kind is implemented on; elsewhere the result is `skipped` */
  os: ('windows' | 'linux')[];
  help: string;
  /** false when the kind never fixes anything, whatever `remediate` says */
  fixable: boolean;
  /** shown beside the remediate toggle when the fix has conditions */
  fixNote?: string;
  /** every key the server accepts for this kind */
  keys: string[];
  defaults: () => BaselineParams;
  /** one line for the checks table */
  summary: (p: BaselineParams) => string;
}

// ---- small typed readers (params is Record<string, unknown> on the wire) ----

export const str = (p: BaselineParams, k: string): string => (typeof p[k] === 'string' ? (p[k] as string) : '');
export const bool = (p: BaselineParams, k: string): boolean => p[k] === true;
export const numOr = (p: BaselineParams, k: string, fallback: number): number => (typeof p[k] === 'number' && Number.isFinite(p[k] as number) ? (p[k] as number) : fallback);
export const strList = (p: BaselineParams, k: string): string[] => (Array.isArray(p[k]) ? (p[k] as unknown[]).filter((x): x is string => typeof x === 'string') : []);

/**
 * A boolean param, judged the way encoding/json judges it on the server.
 * Absent and JSON `null` both leave the Go field at its default (nil for the
 * *bool behind firewall/time_sync `enabled`, false for a plain bool) and are
 * accepted; anything else fails to unmarshal and comes back as a 400 carrying
 * a raw Go message ("json: cannot unmarshal string into Go struct field
 * PackageParams.allow_winget of type bool"), so it is refused here with a
 * readable one instead.
 */
export function flagErr(p: BaselineParams, k: string): string | null {
  const v = p[k];
  if (v === undefined || v === null || typeof v === 'boolean') return null;
  return `${k}: must be true or false`;
}

/**
 * Byte length, which is what every `len(...)` limit in internal/baselines
 * counts. A limit measured in UTF-16 units here would accept params the
 * server refuses (and refuse params it accepts) the moment a value is not
 * plain ASCII.
 */
export const blen = (s: string): number => new TextEncoder().encode(s).length;

/**
 * Character (code point) length. The two NAME limits are deliberately counted
 * in characters on the server (utf8.RuneCountInString), so `.length`, which
 * counts UTF-16 units, would refuse a 61-emoji name at its apparent half.
 */
export const clen = (s: string): number => [...s].length;

/** The first line of a script worth showing: not the shebang, not a comment. */
function firstLine(body: string): string {
  for (const raw of body.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#!') || line.startsWith('#') || line.startsWith('//')) continue;
    return line.slice(0, 60);
  }
  return body.trim().split('\n')[0]?.slice(0, 60) ?? '';
}

export const KINDS: KindDef[] = [
  {
    id: 'service',
    label: 'Service / unit',
    os: ['windows', 'linux'],
    help: 'A service must be running or stopped, optionally with a start type.',
    fixable: true,
    fixNote: 'Starts or stops the service and sets the start type. A Windows boot/system driver start type is never changed; systemd has no "manual" to set.',
    keys: ['name', 'state', 'start_type'],
    defaults: () => ({ name: '', state: 'running', start_type: 'any' }),
    summary: (p) => `${str(p, 'name') || '(no name)'} ${str(p, 'state')}${str(p, 'start_type') && str(p, 'start_type') !== 'any' ? ` / ${str(p, 'start_type')}` : ''}`,
  },
  {
    id: 'package',
    label: 'Package',
    os: ['windows', 'linux'],
    help: 'A package is installed (optionally at a minimum version) or absent.',
    fixable: true,
    fixNote: 'Linux installs or removes with the system package manager. On Windows this is check-only unless "allow winget" is set, because winget is not usable from the agent service account.',
    keys: ['name', 'state', 'min_version', 'allow_winget'],
    defaults: () => ({ name: '', state: 'present' }),
    summary: (p) => `${str(p, 'name') || '(no name)'} ${str(p, 'state')}${str(p, 'min_version') ? ` ≥ ${str(p, 'min_version')}` : ''}`,
  },
  {
    id: 'registry',
    label: 'Registry value',
    os: ['windows'],
    help: 'A registry value under HKLM or HKCU has an exact value.',
    fixable: true,
    fixNote: 'Creates the key when needed and writes the value.',
    keys: ['path', 'name', 'type', 'value'],
    defaults: () => ({ path: 'HKLM\\SOFTWARE\\', name: '', type: 'dword', value: 0 }),
    summary: (p) => `${str(p, 'path')}\\${str(p, 'name') || '(default)'} = ${JSON.stringify(p.value ?? null)}`,
  },
  {
    id: 'file',
    label: 'File',
    os: ['windows', 'linux'],
    help: 'A file exists with given content, hash, substring, mode or owner — or is absent.',
    fixable: true,
    fixNote: 'Only `content` is fixable: a sha256 or contains check without content stays check-only. `absent` removes a regular file, never a directory.',
    keys: ['path', 'state', 'content', 'sha256', 'contains', 'mode', 'owner'],
    defaults: () => ({ path: '', state: 'present' }),
    summary: (p) => `${str(p, 'path') || '(no path)'} ${str(p, 'state')}${str(p, 'sha256') ? ' sha256' : ''}${str(p, 'contains') ? ' contains' : ''}${str(p, 'mode') ? ` mode ${str(p, 'mode')}` : ''}`,
  },
  {
    id: 'command',
    label: 'Command (script)',
    os: ['windows', 'linux'],
    help: 'Your own script decides: exit 0 is compliant, anything else is drift. An optional fix script runs before the re-check.',
    fixable: true,
    fixNote: 'Runs the fix script, then re-runs the check script.',
    keys: ['language', 'check', 'fix', 'expected'],
    defaults: () => ({ language: 'bash', check: '', fix: '', expected: '' }),
    summary: (p) => `${str(p, 'language')} · ${firstLine(str(p, 'check')) || '(no script)'}`,
  },
  {
    id: 'group_members',
    label: 'Local group members',
    os: ['windows', 'linux'],
    help: 'Members of a local group must be within the allowed list. Members are never added.',
    fixable: true,
    fixNote: 'Removes members that are not allowed. Never removes the built-in Administrator or root, never the last member of an admin group, and never a domain principal unless you allow it.',
    keys: ['group', 'allowed', 'mode', 'allow_domain'],
    defaults: () => ({ group: '', allowed: [], mode: 'subset', allow_domain: false }),
    summary: (p) => `${str(p, 'group') || '(no group)'} ${str(p, 'mode') || 'subset'} · ${strList(p, 'allowed').length} allowed`,
  },
  {
    id: 'firewall',
    label: 'Firewall',
    os: ['windows', 'linux'],
    help: 'The host firewall is on (all three profiles on Windows; ufw or firewalld on Linux).',
    fixable: true,
    keys: ['enabled'],
    defaults: () => ({ enabled: true }),
    summary: (p) => (p.enabled === false ? 'disabled' : 'enabled'),
  },
  {
    id: 'time_sync',
    label: 'Time sync',
    os: ['windows', 'linux'],
    help: 'Time synchronisation is on and has a source.',
    fixable: true,
    keys: ['enabled'],
    defaults: () => ({ enabled: true }),
    summary: (p) => (p.enabled === false ? 'disabled' : 'enabled'),
  },
  {
    id: 'sysctl',
    label: 'sysctl',
    os: ['linux'],
    help: 'A kernel parameter has a value.',
    fixable: true,
    fixNote: 'Applies with sysctl -w and writes /etc/sysctl.d/90-homelab-rmm.conf, a file the agent owns.',
    keys: ['key', 'value'],
    defaults: () => ({ key: '', value: '' }),
    summary: (p) => `${str(p, 'key') || '(no key)'} = ${str(p, 'value')}`,
  },
  {
    id: 'windows_feature',
    label: 'Windows optional feature',
    os: ['windows'],
    help: 'A Windows optional feature is enabled or disabled.',
    fixable: true,
    fixNote: 'Enable-/Disable-WindowsOptionalFeature, always with -NoRestart.',
    keys: ['name', 'state'],
    defaults: () => ({ name: '', state: 'disabled' }),
    summary: (p) => `${str(p, 'name') || '(no name)'} ${str(p, 'state')}`,
  },
  {
    id: 'reboot_pending',
    label: 'Pending reboot',
    os: ['windows', 'linux'],
    help: 'The device has not been waiting for a reboot longer than max_hours.',
    fixable: true,
    fixNote: 'Only reboots when "allow reboot" is set, at most once a day per device, with a 60 s notice, and never while a script run or a shell session is live.',
    keys: ['max_hours', 'allow_reboot'],
    defaults: () => ({ max_hours: 72, allow_reboot: false }),
    summary: (p) => `≤ ${numOr(p, 'max_hours', 72)} h${bool(p, 'allow_reboot') ? ' · may reboot' : ''}`,
  },
  {
    id: 'disk_free',
    label: 'Disk free space',
    os: ['windows', 'linux'],
    help: 'A mount point or drive keeps a minimum percentage free. Check only.',
    fixable: false,
    fixNote: 'Nothing can be fixed automatically: free space is not something an agent should delete its way to.',
    keys: ['mount', 'min_free_pct'],
    defaults: () => ({ mount: '/', min_free_pct: 10 }),
    summary: (p) => `${str(p, 'mount') || '(no mount)'} ≥ ${numOr(p, 'min_free_pct', 10)}% free`,
  },
];

export function kindDef(kind: string): KindDef | undefined {
  return KINDS.find((k) => k.id === kind);
}

export function kindLabel(kind: string): string {
  return kindDef(kind)?.label ?? kind;
}

/** Kinds that need the admin role to create or edit (A33, A41). */
export function needsAdmin(check: { kind: string; params: BaselineParams }): boolean {
  if (check.kind === 'command') return true;
  if (check.kind === 'reboot_pending' && bool(check.params, 'allow_reboot')) return true;
  if (check.kind === 'file') return fileNeedsAdmin(str(check.params, 'path'));
  return false;
}

/**
 * baselines.FileNeedsAdmin, rule for rule. A path outside /etc (unix) or
 * <drive>:\ProgramData\<something> (windows) is a code change on every
 * matched device, so only an admin may write it.
 *
 * The drive letter is not fixed to C: and "c:/programdata" with nothing under
 * it is NOT the ProgramData tree - matching either of those loosely is how
 * the console ends up letting a non-admin submit a check the server answers
 * with a 403.
 */
export function fileNeedsAdmin(path: string): boolean {
  const clean = cleanPath(path);
  switch (pathStyle(path)) {
    case 'unix':
      return !(clean === '/etc' || clean.startsWith('/etc/'));
    case 'windows': {
      const i = clean.indexOf('/programdata/');
      return !(i === 2 && clean.length > 'c:/programdata/'.length);
    }
    default:
      return true;
  }
}

/** True when the check runs code the operator wrote, or can restart the device. */
export function isDangerous(check: { kind: string; params: BaselineParams }): boolean {
  return check.kind === 'command' || check.kind === 'group_members' || (check.kind === 'reboot_pending' && bool(check.params, 'allow_reboot'));
}

/**
 * Whether a remediate toggle can do anything for these params. `file` with a
 * hash or a substring but no content is check-only even when remediate is on,
 * which the agent decides too — saying so in the form avoids an operator
 * believing a fix is armed when it is not.
 */
export function fixableWith(kind: string, p: BaselineParams): boolean {
  const def = kindDef(kind);
  if (!def?.fixable) return false;
  // internal/agent/baseline_kinds.go fileFixable, in the same order: a hash or
  // a substring with no content is check-only WHATEVER else is set, because
  // neither says what the file should hold.
  if (kind === 'file') {
    if (str(p, 'state') === 'absent') return true;
    if (str(p, 'content') === '' && (str(p, 'sha256') !== '' || str(p, 'contains') !== '')) return false;
    return str(p, 'content') !== '' || str(p, 'mode') !== '' || str(p, 'owner') !== '';
  }
  if (kind === 'command') return str(p, 'fix').trim() !== '';
  return true;
}

// ---- path helpers, mirrored from internal/baselines/values.go ----

export function pathStyle(p: string): 'unix' | 'windows' | '' {
  if (p.startsWith('/')) return 'unix';
  if (p.length >= 3 && /[A-Za-z]/.test(p[0]) && p[1] === ':' && (p[2] === '\\' || p[2] === '/')) return 'windows';
  return '';
}

export function hasDotDot(p: string): boolean {
  return p.replace(/\\/g, '/').split('/').includes('..');
}

/** Forward slashes, no duplicate or trailing separator; windows paths folded. */
export function cleanPath(p: string): string {
  const style = pathStyle(p);
  let q = p.replace(/\\/g, '/');
  if (style === 'windows') q = q.toLowerCase();
  const abs = q.startsWith('/');
  const out: string[] = [];
  for (const part of q.split('/')) {
    if (!part || part === '.') continue;
    if (part === '..') out.pop();
    else out.push(part);
  }
  const joined = out.join('/');
  return abs ? '/' + joined : joined || '.';
}

// The agent's own configuration directory, in cleanPath form, on both path
// styles. internal/baselines refuses it on the writer side and the agent
// refuses its REAL directory at evaluation time; without it here the form
// accepts a path the server then rejects on save.
const DENIED_AGENT_DIRS = ['/etc/homelab-rmm', 'c:/programdata/homelabrmm'];
const UNIX_DENIED_PREFIXES = ['/proc', '/sys', '/dev'];
const UNIX_DENIED_FILES = ['/etc/shadow', '/etc/gshadow', '/etc/sudoers'];
const WIN_DENIED_PREFIXES = ['c:/windows/system32/config', 'c:/programdata/homelabrmm'];
// The canonical spelling, as internal/baselines/values.go writes it: the
// message an operator reads is the registry path they typed, not a shouted
// lower-cased copy of it.
const REG_DENIED = ['HKLM\\SAM', 'HKLM\\SECURITY', 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\HomelabRMMAgent'];

export function checkFilePath(p: string, state: string, content: string): string | null {
  if (!p.trim()) return 'a path is required';
  if (blen(p) > 4096) return 'too long';
  if (/[\u0000\n\r]/.test(p)) return 'must not contain control characters';
  const style = pathStyle(p);
  if (!style) return 'must be an absolute path (/etc/… or C:\\…)';
  if (hasDotDot(p)) return 'must not contain ".."';
  const clean = cleanPath(p);
  for (const d of DENIED_AGENT_DIRS) {
    if (clean === d || clean.startsWith(d + '/')) return "the RMM agent's own configuration directory is not manageable by a baseline";
  }
  if (style === 'unix') {
    for (const d of UNIX_DENIED_PREFIXES) if (clean === d || clean.startsWith(d + '/')) return `${d} is not a real file tree a baseline may manage`;
    for (const d of UNIX_DENIED_FILES) if (clean === d) return `${d} decides who is root on this device and is not manageable by a baseline`;
    if (clean === '/etc/sudoers.d' || clean.startsWith('/etc/sudoers.d/')) {
      if (state !== 'present' || !content) return '/etc/sudoers.d is only manageable as state present with explicit content';
    }
    if (clean === '/') return 'the root directory is not a file';
    return null;
  }
  for (const d of WIN_DENIED_PREFIXES) if (clean === d || clean.startsWith(d + '/')) return `${d.replace(/\//g, '\\')} is not manageable by a baseline`;
  if (clean.length <= 3) return 'a drive root is not a file';
  return null;
}

const REG_PATH_RE = /^(HKLM|HKCU)\\[A-Za-z0-9 ._-]+(\\[A-Za-z0-9 ._-]+)*$/;

export function checkRegistryPath(p: string): string | null {
  if (!p) return 'a registry path is required';
  if (blen(p) > 1024) return 'too long';
  if (!REG_PATH_RE.test(p)) return 'must look like HKLM\\SOFTWARE\\… or HKCU\\SOFTWARE\\… with no wildcards';
  for (const c of p.split('\\').slice(1)) if (blen(c) > 256) return 'each key name is at most 256 characters';
  const lower = p.toLowerCase();
  for (const d of REG_DENIED) {
    const dl = d.toLowerCase();
    if (lower === dl || lower.startsWith(dl + '\\')) return `${d} is not writable by a baseline`;
  }
  return null;
}

// ---- validation, mirrored from internal/baselines/kinds.go ----

const SERVICE_NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9@._\-\\:]{0,255}$/;
const PKG_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9+._:@-]{0,255}$/;
const GROUP_NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9 ._-]{0,63}$/;
const MEMBER_NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9 ._\-\\@$]{0,255}$/;
const SYSCTL_KEY_RE = /^[a-z0-9_]+(\.[a-z0-9_-]+)*$/;
const WIN_FEATURE_RE = /^[A-Za-z0-9\-.]{1,128}$/;
const MODE_RE = /^[0-7]{3,4}$/;
const SHA256_RE = /^[0-9a-fA-F]{64}$/;
const OWNER_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}(:[A-Za-z0-9_][A-Za-z0-9._-]{0,63})?$/;

function oneOf(field: string, v: string, ...allowed: string[]): string | null {
  return allowed.includes(v) ? null : `${field}: must be one of ${allowed.join(', ')}`;
}

/** The numeric field of a version, epoch and release stripped (A39). */
function comparableVersion(v: string): boolean {
  let s = v.trim();
  const colon = s.indexOf(':');
  if (colon >= 0) s = s.slice(colon + 1);
  const cut = s.search(/[-~+]/);
  if (cut >= 0) s = s.slice(0, cut);
  return s.split('.').some((f) => /^\d+$/.test(f));
}

function maxParamsBytes(kind: string): number {
  if (kind === 'command') return LIMITS.commandParams;
  if (kind === 'file') return LIMITS.fileParams;
  return LIMITS.params;
}

/**
 * Validate one kind's params exactly as the server will. Returns a message
 * naming the field, or null. The message is the one the operator sees before
 * the request is made, so it reads like the server's 400.
 */
export function validateParams(kind: string, p: BaselineParams): string | null {
  const def = kindDef(kind);
  if (!def) return `unknown check kind "${kind}"`;
  if (!p || typeof p !== 'object' || Array.isArray(p)) return 'params: must be a JSON object';
  const unknown = Object.keys(p).filter((k) => !def.keys.includes(k));
  if (unknown.length) return `params: ${kind} does not take ${unknown.join(', ')} (allowed: ${def.keys.join(', ')})`;
  const size = new TextEncoder().encode(JSON.stringify(p)).length;
  if (size > maxParamsBytes(kind)) return `params: ${size} bytes exceeds the ${maxParamsBytes(kind)} byte limit`;

  switch (kind) {
    case 'service': {
      const name = str(p, 'name');
      if (!SERVICE_NAME_RE.test(name)) return 'name: a service or unit name is required';
      if (name.includes('/')) return 'name: a service name cannot contain a slash';
      const st = oneOf('state', str(p, 'state'), 'running', 'stopped');
      if (st) return st;
      const start = str(p, 'start_type');
      if (start) return oneOf('start_type', start, 'auto', 'manual', 'disabled', 'any');
      return null;
    }
    case 'package': {
      const name = str(p, 'name');
      if (!PKG_NAME_RE.test(name)) return 'name: a package name or winget id is required';
      if (name.endsWith('-') || name.endsWith(':')) return "name: a package name cannot end with '-' or ':'";
      const st = oneOf('state', str(p, 'state'), 'present', 'absent');
      if (st) return st;
      const mv = str(p, 'min_version');
      if (mv) {
        if (str(p, 'state') !== 'present') return 'min_version: only applies when state is present';
        if (blen(mv) > 64) return 'min_version: too long';
        if (!comparableVersion(mv)) return `min_version: "${mv}" has no numeric field to compare`;
      }
      return flagErr(p, 'allow_winget');
    }
    case 'registry': {
      const path = checkRegistryPath(str(p, 'path'));
      if (path) return `path: ${path}`;
      if (blen(str(p, 'name')) > 255) return 'name: a value name is at most 255 characters';
      const type = str(p, 'type');
      const t = oneOf('type', type, 'dword', 'qword', 'string', 'expand_string', 'multi_string');
      if (t) return t;
      const v = p.value;
      if (v === undefined || v === null) return 'value: a value is required';
      if (type === 'dword' || type === 'qword') {
        if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) return `value: ${type} needs a whole number, not a string`;
        if (type === 'dword' && v > 0xffffffff) return 'value: dword must be between 0 and 4294967295';
        // Above 2^53 a JSON number stops being an exact integer and
        // JSON.stringify starts writing exponents (1e+21), which the server
        // reads as "not a whole number". Refuse it here with the reason.
        if (type === 'qword' && v > Number.MAX_SAFE_INTEGER) return `value: qword must be a whole number up to ${Number.MAX_SAFE_INTEGER} here (larger values cannot be sent exactly)`;
      } else if (type === 'multi_string') {
        if (!Array.isArray(v) || v.some((x) => typeof x !== 'string')) return 'value: multi_string needs an array of strings';
        if (v.length > 256) return 'value: at most 256 strings';
        if ((v as string[]).some((x) => blen(x) > 8192)) return 'value: each string is at most 8192 characters';
      } else if (typeof v !== 'string') {
        return `value: ${type} needs a string`;
      } else if (blen(v) > 8192) {
        return 'value: at most 8192 characters';
      }
      return null;
    }
    case 'file': {
      const state = str(p, 'state');
      const st = oneOf('state', state, 'present', 'absent');
      if (st) return st;
      const content = str(p, 'content');
      const bad = checkFilePath(str(p, 'path'), state, content);
      if (bad) return `path: ${bad}`;
      if (new TextEncoder().encode(content).length > LIMITS.fileContent) return `content: exceeds the ${LIMITS.fileContent} byte limit`;
      if (str(p, 'sha256') && !SHA256_RE.test(str(p, 'sha256'))) return 'sha256: must be 64 hex characters';
      if (blen(str(p, 'contains')) > 4096) return 'contains: at most 4096 characters';
      const mode = str(p, 'mode');
      if (mode) {
        if (!MODE_RE.test(mode)) return 'mode: must be a 3- or 4-digit octal number';
        if (parseInt(mode, 8) > 0o777) return 'mode: must be 0777 or lower with no setuid, setgid or sticky bit';
      }
      if (str(p, 'owner') && !OWNER_RE.test(str(p, 'owner'))) return 'owner: must be user or user:group';
      if (state === 'absent' && (content || str(p, 'sha256') || str(p, 'contains') || mode || str(p, 'owner'))) {
        return 'state absent: content, sha256, contains, mode and owner do not apply';
      }
      return null;
    }
    case 'command': {
      const lang = oneOf('language', str(p, 'language'), 'bash', 'sh', 'powershell', 'cmd', 'python');
      if (lang) return lang;
      if (!str(p, 'check').trim()) return 'check: a check script is required (a fix with no check is not a check)';
      if (new TextEncoder().encode(str(p, 'check')).length > LIMITS.commandBody) return `check: exceeds the ${LIMITS.commandBody} byte limit`;
      if (new TextEncoder().encode(str(p, 'fix')).length > LIMITS.commandBody) return `fix: exceeds the ${LIMITS.commandBody} byte limit`;
      if (blen(str(p, 'expected')) > 256) return 'expected: at most 256 characters';
      return null;
    }
    case 'group_members': {
      if (!GROUP_NAME_RE.test(str(p, 'group'))) return 'group: a local group name is required';
      const allowed = p.allowed;
      if (allowed !== undefined && (!Array.isArray(allowed) || allowed.some((x) => typeof x !== 'string'))) return 'allowed: must be a list of account names';
      const names = strList(p, 'allowed');
      if (names.length > 256) return 'allowed: at most 256 names';
      for (let i = 0; i < names.length; i++) if (!MEMBER_NAME_RE.test(names[i])) return `allowed[${i}]: "${names[i]}" is not a valid account name`;
      const mode = str(p, 'mode');
      if (mode) {
        const m = oneOf('mode', mode, 'exact', 'subset');
        if (m) return m;
      }
      return flagErr(p, 'allow_domain');
    }
    case 'firewall':
    case 'time_sync':
      return flagErr(p, 'enabled');
    case 'sysctl': {
      const key = str(p, 'key');
      if (!SYSCTL_KEY_RE.test(key)) return 'key: must look like net.ipv4.ip_forward';
      if (blen(key) > 256) return 'key: too long';
      if (typeof p.value !== 'string') return 'value: a value is required (always a string)';
      const v = str(p, 'value').trim();
      if (!v) return 'value: a value is required (always a string)';
      if (blen(v) > 256 || /[\n\r]/.test(v)) return 'value: must be a single short line';
      return null;
    }
    case 'windows_feature': {
      if (!WIN_FEATURE_RE.test(str(p, 'name'))) return 'name: a Windows optional feature name is required';
      return oneOf('state', str(p, 'state'), 'enabled', 'disabled');
    }
    case 'reboot_pending': {
      const h = numOr(p, 'max_hours', 0);
      if (!Number.isInteger(h) || h < 1) return 'max_hours: must be 1 or more';
      if (h > 24 * 365) return 'max_hours: must be a year or less';
      return flagErr(p, 'allow_reboot');
    }
    case 'disk_free': {
      const mount = str(p, 'mount');
      if (!mount.trim()) return 'mount: a mount point or drive is required';
      if (blen(mount) > 256) return 'mount: too long';
      const pctv = p.min_free_pct;
      if (typeof pctv !== 'number' || !(pctv > 0 && pctv < 100)) return 'min_free_pct: must be greater than 0 and less than 100';
      return null;
    }
    default:
      return `unknown check kind "${kind}"`;
  }
}

/** Validate a whole check (the common fields plus its params). */
export function validateCheck(c: BaselineCheck | BaselineCheckInput): string | null {
  if (!c.name.trim()) return 'name: a check name is required';
  // The server trims the name and counts CHARACTERS (utf8.RuneCountInString).
  if (clen(c.name.trim()) > LIMITS.name) return `name: at most ${LIMITS.name} characters`;
  const def = kindDef(c.kind);
  if (!def) return `kind: unknown check kind "${c.kind}"`;
  const sev = oneOf('severity', c.severity, 'info', 'warning', 'critical');
  if (sev) return sev;
  if (c.os_filter && c.os_filter !== 'windows' && c.os_filter !== 'linux') return 'os_filter: must be empty, windows or linux';
  // validateBaselineInput refuses a kind filtered to an OS it is not
  // implemented on (400 "kind sysctl is not implemented on windows"). Saying
  // so only as a soft warning left the editor happily building a check that
  // the Save button then bounced off the server.
  if (c.os_filter && !def.os.includes(c.os_filter as 'windows' | 'linux')) {
    return `os_filter: ${c.kind} is not implemented on ${c.os_filter}`;
  }
  if (c.timeout_sec < LIMITS.minTimeout || c.timeout_sec > LIMITS.maxTimeout) return `timeout_sec: must be between ${LIMITS.minTimeout} and ${LIMITS.maxTimeout}`;
  return validateParams(c.kind, c.params);
}

/**
 * A check whose kind never runs on the OS it is filtered to would be
 * `skipped` on every device forever. It is not an error — the server accepts
 * it — but the editor says so.
 */
export function osWarning(c: { kind: string; os_filter: string }): string | null {
  const def = kindDef(c.kind);
  if (!def) return null;
  // A kind filtered to an OS it is not implemented on is an ERROR, not a
  // warning (validateCheck), because the server refuses it with a 400.
  if (c.os_filter && !def.os.includes(c.os_filter as 'windows' | 'linux')) return null;
  if (!c.os_filter && def.os.length === 1) return `${def.label} only runs on ${def.os[0]}; elsewhere it is skipped.`;
  return null;
}

/** Drop the keys a kind does not take, and the optional ones left empty. */
export function cleanParams(kind: string, p: BaselineParams): BaselineParams {
  const def = kindDef(kind);
  if (!def) return p;
  const out: BaselineParams = {};
  for (const k of def.keys) {
    const v = p[k];
    if (v === undefined || v === null) continue;
    if (typeof v === 'string' && v === '' && !required(kind, k)) continue;
    if (Array.isArray(v) && v.length === 0 && !required(kind, k)) continue;
    if (v === false && optionalFlag(kind, k)) continue;
    out[k] = v;
  }
  return out;
}

function required(kind: string, key: string): boolean {
  switch (kind) {
    case 'service':
      return key === 'name' || key === 'state';
    case 'package':
      return key === 'name' || key === 'state';
    case 'registry':
      return key === 'path' || key === 'type' || key === 'value';
    case 'file':
      return key === 'path' || key === 'state';
    case 'command':
      return key === 'language' || key === 'check';
    case 'group_members':
      return key === 'group';
    case 'sysctl':
      return key === 'key' || key === 'value';
    case 'windows_feature':
      return key === 'name' || key === 'state';
    case 'reboot_pending':
      return key === 'max_hours';
    case 'disk_free':
      return key === 'mount' || key === 'min_free_pct';
    default:
      return false;
  }
}

function optionalFlag(kind: string, key: string): boolean {
  return (kind === 'package' && key === 'allow_winget') || (kind === 'group_members' && key === 'allow_domain') || (kind === 'reboot_pending' && key === 'allow_reboot');
}

/** The body the API takes: position is the array index, so it is never sent. */
export function toInput(c: BaselineCheck): BaselineCheckInput {
  return {
    id: c.id > 0 ? c.id : 0,
    name: c.name.trim(),
    kind: c.kind,
    params: cleanParams(c.kind, c.params),
    remediate: c.remediate,
    severity: c.severity,
    os_filter: c.os_filter,
    timeout_sec: c.timeout_sec,
  };
}

export function blankCheck(kind: BaselineKind = 'service'): BaselineCheck {
  const def = kindDef(kind);
  return {
    id: 0,
    name: '',
    kind,
    params: def ? def.defaults() : {},
    remediate: false,
    severity: 'warning',
    os_filter: def && def.os.length === 1 ? def.os[0] : '',
    timeout_sec: LIMITS.defaultTimeout,
  };
}

export const INTERVALS: { sec: number; label: string }[] = [
  { sec: 300, label: 'Every 5 minutes' },
  { sec: 900, label: 'Every 15 minutes' },
  { sec: 1800, label: 'Every 30 minutes' },
  { sec: 3600, label: 'Hourly' },
  { sec: 14400, label: 'Every 4 hours' },
  { sec: 43200, label: 'Every 12 hours' },
  { sec: 86400, label: 'Daily' },
];
