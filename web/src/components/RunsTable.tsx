import { Link } from 'react-router-dom';
import type { Run } from '../api/types';
import { elapsed, relTime } from '../lib/format';
import { DataTable, type Column } from './DataTable';
import { RunStatusChip } from './ui';

export function RunsTable({
  rows,
  loading,
  onOpen,
  showDevice = true,
  emptyTitle = 'No runs',
  csvName = 'runs',
}: {
  rows: Run[] | undefined;
  loading?: boolean;
  onOpen: (r: Run) => void;
  showDevice?: boolean;
  emptyTitle?: string;
  csvName?: string;
}) {
  const columns: Column<Run>[] = [
    { key: 'status', header: 'Status', sort: (r) => r.status, render: (r) => <RunStatusChip status={r.status} /> },
    { key: 'script', header: 'Script', sort: (r) => r.script_name, render: (r) => <b>{r.script_name}</b> },
    ...(showDevice
      ? [
          {
            key: 'device',
            header: 'Device',
            sort: (r: Run) => r.agent_name,
            render: (r: Run) => (
              <Link to={`/devices/${r.agent_id}`} onClick={(e) => e.stopPropagation()}>
                {r.agent_name || r.agent_id}
              </Link>
            ),
          } as Column<Run>,
        ]
      : []),
    { key: 'trigger', header: 'Trigger', sort: (r) => `${r.trigger} ${r.run_by}`, render: (r) => <span className="muted">{r.trigger}{r.run_by ? ` · ${r.run_by}` : ''}</span> },
    {
      key: 'exit',
      header: 'Exit',
      align: 'right',
      sort: (r) => r.exit_code,
      csv: (r) => (r.status === 'running' || r.status === 'queued' ? '' : r.exit_code),
      render: (r) => <span className="mono">{r.status === 'running' || r.status === 'queued' ? '' : r.exit_code}</span>,
    },
    {
      key: 'dur',
      header: 'Duration',
      sort: (r) => (r.finished_at || Date.now() / 1000) - r.started_at,
      csv: (r) => elapsed(r.started_at, r.finished_at),
      render: (r) => <span className="muted">{elapsed(r.started_at, r.finished_at)}</span>,
    },
    {
      key: 'started',
      header: 'Started',
      sort: (r) => r.started_at,
      csv: (r) => (r.started_at ? new Date(r.started_at * 1000).toISOString() : ''),
      render: (r) => <span className="muted">{relTime(r.started_at)}</span>,
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={rows}
      loading={loading}
      rowKey={(r) => r.id}
      onRowClick={onOpen}
      defaultSort={{ key: 'started', dir: 'desc' }}
      compact
      emptyTitle={emptyTitle}
      csvName={csvName}
    />
  );
}
