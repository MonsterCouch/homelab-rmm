import { useMemo, useState } from 'react';
import { api } from '../api/client';
import type { AuditRow } from '../api/types';
import { DataTable, textMatch, type Column } from '../components/DataTable';
import { IconRefresh } from '../components/Icons';
import { Button, ErrorBox } from '../components/ui';
import { useAsync, useDebounced } from '../hooks/useAsync';
import { dateTime } from '../lib/format';

function prettyDetails(d: string): string {
  if (!d) return '';
  try {
    const v = JSON.parse(d) as unknown;
    if (v && typeof v === 'object') {
      return Object.entries(v as Record<string, unknown>)
        .filter(([, val]) => val !== null && val !== undefined && val !== '' && val !== false)
        .map(([k, val]) => `${k}=${typeof val === 'object' ? JSON.stringify(val) : String(val)}`)
        .join('  ');
    }
    return String(v);
  } catch {
    return d;
  }
}

export function Audit() {
  const [limit, setLimit] = useState(500);
  const rows = useAsync(() => api.audit(limit), [limit]);
  const [q, setQ] = useState('');
  const dq = useDebounced(q);
  const [user, setUser] = useState('');
  const users = useMemo(() => Array.from(new Set((rows.data ?? []).map((r) => r.user))).sort(), [rows.data]);
  const filtered = useMemo(() => (rows.data ?? []).filter((r) => (!user || r.user === user) && textMatch(dq, r.action, r.target, r.details, r.ip, r.user)), [rows.data, dq, user]);

  const columns: Column<AuditRow>[] = [
    { key: 'ts', header: 'Time', sort: (r) => r.ts, render: (r) => <span className="muted nowrap">{dateTime(r.ts)}</span>, width: 170 },
    { key: 'user', header: 'User', sort: (r) => r.user, render: (r) => <b>{r.user}</b> },
    { key: 'ip', header: 'IP', sort: (r) => r.ip, render: (r) => <span className="mono muted">{r.ip}</span> },
    { key: 'action', header: 'Action', sort: (r) => r.action, render: (r) => <span className="chip outline mono" style={{ fontWeight: 400 }}>{r.action}</span> },
    { key: 'target', header: 'Target', sort: (r) => r.target, render: (r) => <span className="mono small truncate" style={{ maxWidth: 240, display: 'inline-block' }} title={r.target}>{r.target}</span> },
    { key: 'details', header: 'Details', render: (r) => <span className="muted small mono truncate" style={{ maxWidth: 420, display: 'inline-block' }} title={r.details}>{prettyDetails(r.details)}</span> },
  ];

  return (
    <>
      <div className="page-head">
        <h1>Audit log</h1>
        <Button onClick={() => rows.reload()} icon aria-label="Refresh">
          <IconRefresh />
        </Button>
      </div>
      <div className="toolbar">
        <input type="search" placeholder="Filter action, target, details…" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 320 }} aria-label="Filter audit" />
        <select value={user} onChange={(e) => setUser(e.target.value)} style={{ width: 160 }} aria-label="User">
          <option value="">Any user</option>
          {users.map((u) => (
            <option key={u} value={u}>
              {u}
            </option>
          ))}
        </select>
        <select value={limit} onChange={(e) => setLimit(+e.target.value)} style={{ width: 130 }} aria-label="Limit">
          {[200, 500, 1000, 5000].map((n) => (
            <option key={n} value={n}>
              last {n}
            </option>
          ))}
        </select>
        <span className="grow" />
        {rows.data && <span className="muted small">{filtered.length} entries</span>}
      </div>
      {rows.error && <ErrorBox error={rows.error} onRetry={rows.reload} />}
      <DataTable columns={columns} rows={rows.data ? filtered : undefined} loading={rows.loading} rowKey={(r) => String(r.id)} defaultSort={{ key: 'ts', dir: 'desc' }} compact emptyTitle="No audit entries" />
    </>
  );
}
