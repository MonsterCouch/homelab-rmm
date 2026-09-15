import { useMemo, useState } from 'react';
import { api } from '../../api/client';
import type { AgentEvent } from '../../api/types';
import { DataTable, textMatch, type Column } from '../../components/DataTable';
import { Chip, ErrorBox } from '../../components/ui';
import { useAsync, useDebounced } from '../../hooks/useAsync';
import { useLiveReload } from '../../hooks/useEvents';
import { dateTime } from '../../lib/format';
import type { TabProps } from './DeviceDetail';

function kindTone(k: string): 'danger' | 'warn' | 'info' | 'ok' | '' {
  switch (k) {
    case 'reboot_required':
      return 'warn';
    case 'service':
      return 'info';
    case 'patch':
      return 'ok';
    case 'log':
      return '';
    default:
      return '';
  }
}

export function DeviceEvents({ agent }: TabProps) {
  const events = useAsync(() => api.agentEvents(agent.id, 500), [agent.id]);
  useLiveReload(['event', 'inventory'], events.reload, { agentId: agent.id });
  const [q, setQ] = useState('');
  const dq = useDebounced(q);
  const rows = useMemo(() => (events.data ?? []).filter((e) => textMatch(dq, e.kind, e.message, ...Object.values(e.fields ?? {}))), [events.data, dq]);
  const columns: Column<AgentEvent>[] = [
    { key: 'ts', header: 'Time', sort: (e) => e.ts, render: (e) => <span className="muted nowrap">{dateTime(e.ts)}</span>, width: 170 },
    { key: 'kind', header: 'Kind', sort: (e) => e.kind, render: (e) => <Chip tone={kindTone(e.kind)}>{e.kind}</Chip>, width: 130 },
    { key: 'msg', header: 'Message', sort: (e) => e.message, render: (e) => <span className="wrap">{e.message}</span>, className: 'wrap' },
    {
      key: 'fields',
      header: 'Details',
      render: (e) =>
        e.fields && Object.keys(e.fields).length ? (
          <span className="tags">
            {Object.entries(e.fields).map(([k, v]) => (
              <span key={k} className="chip outline mono" style={{ fontWeight: 400 }}>
                {k}={v}
              </span>
            ))}
          </span>
        ) : null,
      className: 'wrap',
    },
  ];
  return (
    <>
      <div className="toolbar">
        <input type="search" placeholder="Filter events…" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 300 }} aria-label="Filter events" />
        <span className="grow" />
        {events.data && <span className="muted small">{rows.length} events</span>}
      </div>
      {events.error && <ErrorBox error={events.error} onRetry={events.reload} />}
      <DataTable columns={columns} rows={events.data ? rows : undefined} loading={events.loading} rowKey={(e) => String(e.id)} defaultSort={{ key: 'ts', dir: 'desc' }} compact emptyTitle="No events recorded" emptyBody="Service changes, reboot flags and agent notices appear here." />
    </>
  );
}
