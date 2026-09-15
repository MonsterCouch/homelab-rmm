// Formatting helpers shared by every page. All timestamps from the API are
// Unix seconds; 0 means "never".

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];

export function bytes(n: number | undefined | null, digits = 1): string {
  if (n === undefined || n === null || !Number.isFinite(n)) return '—';
  if (n < 0) return '—';
  let v = n;
  let i = 0;
  while (v >= 1024 && i < UNITS.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i === 0 ? v.toFixed(0) : v.toFixed(digits)} ${UNITS[i]}`;
}

export function bps(n: number | undefined | null): string {
  if (n === undefined || n === null || !Number.isFinite(n)) return '—';
  const bits = n * 8;
  if (bits < 1000) return `${bits.toFixed(0)} b/s`;
  if (bits < 1e6) return `${(bits / 1e3).toFixed(1)} kb/s`;
  if (bits < 1e9) return `${(bits / 1e6).toFixed(1)} Mb/s`;
  return `${(bits / 1e9).toFixed(2)} Gb/s`;
}

export function pct(n: number | undefined | null, digits = 0): string {
  if (n === undefined || n === null || !Number.isFinite(n)) return '—';
  return `${n.toFixed(digits)}%`;
}

export function num(n: number | undefined | null): string {
  if (n === undefined || n === null || !Number.isFinite(n)) return '—';
  return n.toLocaleString();
}

/** "3m ago", "2h ago", "in 5m" — relative to now. 0/undefined => "never". */
export function relTime(ts: number | undefined | null, nowMs = Date.now()): string {
  if (!ts) return 'never';
  const diff = Math.round(nowMs / 1000 - ts);
  const abs = Math.abs(diff);
  const fmt = (v: number, u: string) => `${v}${u}`;
  let s: string;
  if (abs < 5) s = 'just now';
  else if (abs < 60) s = fmt(abs, 's');
  else if (abs < 3600) s = fmt(Math.floor(abs / 60), 'm');
  else if (abs < 86400) s = fmt(Math.floor(abs / 3600), 'h');
  else if (abs < 86400 * 30) s = fmt(Math.floor(abs / 86400), 'd');
  else if (abs < 86400 * 365) s = fmt(Math.floor(abs / (86400 * 30)), 'mo');
  else s = fmt(Math.floor(abs / (86400 * 365)), 'y');
  if (s === 'just now') return s;
  return diff >= 0 ? `${s} ago` : `in ${s}`;
}

export function dateTime(ts: number | undefined | null): string {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function shortDateTime(ts: number | undefined | null): string {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleString(undefined, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

export function timeOnly(ts: number | undefined | null): string {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

/** Seconds -> "3d 4h 12m" (uptime-style). */
export function duration(secs: number | undefined | null): string {
  if (secs === undefined || secs === null || !Number.isFinite(secs) || secs < 0) return '—';
  const s = Math.floor(secs);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const parts: string[] = [];
  if (d) parts.push(`${d}d`);
  if (h || d) parts.push(`${h}h`);
  if (m || h || d) parts.push(`${m}m`);
  if (!d && !h) parts.push(`${sec}s`);
  return parts.slice(0, 3).join(' ');
}

/** Human-readable duration between two Unix seconds ("12s", "1m 03s"). */
export function elapsed(start: number, end: number): string {
  if (!start) return '—';
  const s = Math.max(0, (end || Math.floor(Date.now() / 1000)) - start);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const r = s % 60;
  if (m < 60) return `${m}m ${String(r).padStart(2, '0')}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

export function osLabel(os: string): string {
  switch (os) {
    case 'windows':
      return 'Windows';
    case 'linux':
      return 'Linux';
    case 'darwin':
      return 'macOS';
    default:
      return os || 'Unknown';
  }
}

export function capitalize(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

export function titleCase(s: string): string {
  return s.replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

export function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}

export function memPct(used: number | undefined, total: number | undefined): number | undefined {
  if (!used || !total) return undefined;
  return (used / total) * 100;
}

/** ISO local datetime string for <input type="datetime-local"> from Unix seconds. */
export function toLocalInput(ts: number): string {
  const d = new Date(ts * 1000);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function fromLocalInput(s: string): number {
  const ms = Date.parse(s);
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : 0;
}

export function pluralize(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** Stable string compare for table sorting; numbers compare numerically. */
export function compare(a: unknown, b: unknown): number {
  if (a === b) return 0;
  if (a === undefined || a === null) return 1;
  if (b === undefined || b === null) return -1;
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  if (typeof a === 'boolean' && typeof b === 'boolean') return Number(a) - Number(b);
  return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
}
