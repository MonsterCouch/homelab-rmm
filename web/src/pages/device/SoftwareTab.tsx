import { useMemo, useState } from 'react';
import type { Software } from '../../api/types';
import { DataTable, textMatch, type Column } from '../../components/DataTable';
import { useDebounced } from '../../hooks/useAsync';
import { relTime } from '../../lib/format';
import type { TabProps } from './DeviceDetail';

export function SoftwareTab({ agent }: TabProps) {
  const [q, setQ] = useState('');
  const dq = useDebounced(q);
  const all = agent.inventory?.software ?? [];
  const rows = useMemo(() => all.filter((s) => textMatch(dq, s.name, s.version, s.publisher)), [all, dq]);
  const columns: Column<Software>[] = [
    { key: 'name', header: 'Name', sort: (s) => s.name, render: (s) => s.name },
    { key: 'version', header: 'Version', sort: (s) => s.version, render: (s) => <span className="mono small">{s.version || '—'}</span> },
    { key: 'publisher', header: 'Publisher', sort: (s) => s.publisher ?? '', render: (s) => <span className="muted">{s.publisher || '—'}</span> },
    { key: 'installed', header: 'Installed', sort: (s) => s.installed ?? '', render: (s) => <span className="muted">{s.installed || '—'}</span> },
  ];
  return (
    <>
      <div className="toolbar">
        <input type="search" placeholder="Filter software…" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 320 }} aria-label="Filter software" />
        <span className="grow" />
        <span className="muted small">
          {rows.length} of {all.length} packages · inventory {relTime(agent.inventory?.collected_at)}
        </span>
      </div>
      <DataTable columns={columns} rows={rows} rowKey={(s, ) => `${s.name}|${s.version}|${s.publisher ?? ''}`} defaultSort={{ key: 'name', dir: 'asc' }} compact emptyTitle="No software inventory" emptyBody="Refresh the inventory while the device is online." />
    </>
  );
}
