import { useMemo, useState } from 'react';
import { api } from '../../api/client';
import type { AgentEvent } from '../../api/types';
import { DataTable, textMatch, type Column } from '../../components/DataTable';
import { RunDrawer } from '../../components/RunDrawer';
import { Button, Chip, ErrorBox } from '../../components/ui';
import { useAsync, useDebounced } from '../../hooks/useAsync';
import { useLiveReload } from '../../hooks/useEvents';
import { dateTime, relTime } from '../../lib/format';
import { describeUpdateSource } from '../../lib/fleetUpdate';
import type { TabProps } from './DeviceDetail';

type CategoryFilter = 'all' | 'run' | 'patch' | 'drift' | 'remote' | 'software' | 'system';

function categoryOf(kind: string): CategoryFilter {
  switch (kind) {
    case 'run':
      return 'run';
    case 'patch':
      return 'patch';
    case 'drift':
      return 'drift';
    case 'remote':
      return 'remote';
    case 'software':
      return 'software';
    default:
      return 'system';
  }
}

function kindMeta(k: string): { label: string; tone: 'danger' | 'warn' | 'info' | 'ok' | 'purple' | '' } {
  switch (k) {
    case 'run':
      return { label: 'Script Run', tone: 'info' };
    case 'patch':
      return { label: 'Patching', tone: 'ok' };
    case 'drift':
      return { label: 'Baseline Drift', tone: 'warn' };
    case 'remote':
      return { label: 'Remote Access', tone: 'purple' };
    case 'software':
      return { label: 'Software', tone: 'info' };
    case 'enroll':
      return { label: 'Enrolled', tone: 'ok' };
    case 'reboot_required':
      return { label: 'Reboot Required', tone: 'warn' };
    case 'isolate':
      return { label: 'Isolation', tone: 'danger' };
    case 'service':
      return { label: 'Service', tone: 'info' };
    case 'update':
      return { label: 'Agent Update', tone: 'info' };
    default:
      return { label: k, tone: '' };
  }
}

export function DeviceEvents({ agent }: TabProps) {
  const events = useAsync(() => api.agentEvents(agent.id, 500), [agent.id]);
  useLiveReload(['event', 'inventory', 'run'], events.reload, { agentId: agent.id });
  const [q, setQ] = useState('');
  const [category, setCategory] = useState<CategoryFilter>('all');
  const [activeRunId, setActiveRunId] = useState<string | null>(null);

  const dq = useDebounced(q);

  const filtered = useMemo(() => {
    let list = events.data ?? [];
    if (category !== 'all') {
      list = list.filter((e) => categoryOf(e.kind) === category);
    }
    if (dq.trim()) {
      list = list.filter((e) => textMatch(dq, e.kind, e.message, ...Object.values(e.fields ?? {})));
    }
    return list;
  }, [events.data, category, dq]);

  const columns: Column<AgentEvent>[] = [
    {
      key: 'ts',
      header: 'Time',
      sort: (e) => e.ts,
      render: (e) => (
        <span className="nowrap" title={dateTime(e.ts)}>
          <span className="mono small">{dateTime(e.ts)}</span>
          <span className="muted small" style={{ display: 'block', fontSize: '0.78rem' }}>
            {relTime(e.ts)}
          </span>
        </span>
      ),
      width: 170,
    },
    {
      key: 'kind',
      header: 'Category',
      sort: (e) => e.kind,
      render: (e) => {
        const meta = kindMeta(e.kind);
        return <Chip tone={meta.tone}>{meta.label}</Chip>;
      },
      width: 140,
    },
    {
      key: 'msg',
      header: 'Activity Details',
      sort: (e) => e.message,
      render: (e) => {
        const runId = e.fields?.run_id ? String(e.fields.run_id) : null;
        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <span className="wrap" style={{ fontWeight: 500 }}>
              {e.message}
            </span>
            {e.kind === 'update' && (
              <span className="muted small wrap">{describeUpdateSource(e.fields?.source)}</span>
            )}
            {runId && (
              <div>
                <Button size="xs" variant="ghost" onClick={() => setActiveRunId(runId)}>
                  View Run Output ({runId.slice(0, 8)}…)
                </Button>
              </div>
            )}
          </div>
        );
      },
      className: 'wrap',
    },
    {
      key: 'fields',
      header: 'Metadata',
      render: (e) =>
        e.fields && Object.keys(e.fields).length ? (
          <span className="tags">
            {Object.entries(e.fields).map(([k, v]) => (
              <span key={k} className="chip outline mono" style={{ fontWeight: 400, fontSize: '0.75rem' }}>
                {k}: {String(v)}
              </span>
            ))}
          </span>
        ) : null,
      className: 'wrap',
      width: 250,
    },
  ];

  const categories: { id: CategoryFilter; label: string }[] = [
    { id: 'all', label: 'All Activity' },
    { id: 'run', label: 'Runs & Tasks' },
    { id: 'patch', label: 'Patching' },
    { id: 'drift', label: 'Baselines & Drift' },
    { id: 'remote', label: 'Remote Access' },
    { id: 'software', label: 'Software' },
    { id: 'system', label: 'System & Lifecycle' },
  ];

  return (
    <>
      <div className="toolbar" style={{ gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
        <div className="seg" role="radiogroup" aria-label="Activity Category">
          {categories.map((c) => (
            <button
              key={c.id}
              role="radio"
              aria-checked={category === c.id}
              className={category === c.id ? 'active' : ''}
              onClick={() => setCategory(c.id)}
            >
              {c.label}
            </button>
          ))}
        </div>
        <span className="grow" />
        <input
          type="search"
          placeholder="Filter activity feed…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          style={{ maxWidth: 280 }}
          aria-label="Filter activity feed"
        />
        {events.data && <span className="muted small">{filtered.length} entries</span>}
      </div>

      {events.error && <ErrorBox error={events.error} onRetry={events.reload} />}

      <DataTable
        columns={columns}
        rows={events.data ? filtered : undefined}
        loading={events.loading}
        rowKey={(e) => String(e.id)}
        defaultSort={{ key: 'ts', dir: 'desc' }}
        compact
        emptyTitle="No activity recorded"
        emptyBody="Endpoint tasks, patch installations, baseline drifts, software deployments, and remote sessions will appear here in real-time."
      />

      {activeRunId && (
        <RunDrawer
          runId={activeRunId}
          onClose={() => setActiveRunId(null)}
          onChanged={events.reload}
        />
      )}
    </>
  );
}
