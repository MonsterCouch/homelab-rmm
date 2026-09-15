import { useMemo, useState } from 'react';
import { api } from '../../api/client';
import type { Service, ServiceAction } from '../../api/types';
import { DataTable, textMatch, type Column } from '../../components/DataTable';
import { IconRefresh } from '../../components/Icons';
import { Button, Chip, ErrorBox } from '../../components/ui';
import { useAsync, useDebounced } from '../../hooks/useAsync';
import { errMsg, useToast } from '../../state/toast';
import type { TabProps } from './DeviceDetail';

function stateTone(s: string): 'ok' | 'warn' | 'danger' | '' {
  const v = s.toLowerCase();
  if (v === 'running' || v === 'active') return 'ok';
  if (v.includes('start') || v.includes('stop') || v.includes('activating')) return 'warn';
  if (v === 'failed') return 'danger';
  return '';
}

export function Services({ agent, reload, canWrite }: TabProps) {
  const toast = useToast();
  const svcs = useAsync((signal) => api.services(agent.id, signal), [agent.id]);
  const [q, setQ] = useState('');
  const dq = useDebounced(q);
  const [busy, setBusy] = useState<string | null>(null);
  const [onlyMonitored, setOnlyMonitored] = useState(false);
  const monitored = useMemo(() => new Set(agent.monitored_services.map((s) => s.toLowerCase())), [agent.monitored_services]);

  const rows = useMemo(
    () => (svcs.data ?? []).filter((s) => (!onlyMonitored || monitored.has(s.name.toLowerCase())) && textMatch(dq, s.name, s.display_name, s.state, s.description)),
    [svcs.data, dq, onlyMonitored, monitored],
  );

  const act = async (s: Service, action: ServiceAction) => {
    setBusy(`${s.name}:${action}`);
    try {
      const updated = await api.serviceAction(agent.id, s.name, action);
      toast.success(`${action} ${s.name}`, updated?.state ? `now ${updated.state}` : undefined);
      // patch the row in place; the list call is slow on Windows
      svcs.setData((list) => list?.map((x) => (x.name === s.name && updated?.name ? { ...x, ...updated } : x)));
      if (!updated?.name) void svcs.reload();
    } catch (err) {
      toast.error(`${action} failed`, errMsg(err));
    } finally {
      setBusy(null);
    }
  };

  const toggleMonitor = async (s: Service) => {
    const has = monitored.has(s.name.toLowerCase());
    const next = has ? agent.monitored_services.filter((x) => x.toLowerCase() !== s.name.toLowerCase()) : [...agent.monitored_services, s.name];
    try {
      await api.updateAgent(agent.id, { monitored_services: next });
      toast.success(has ? `Stopped monitoring ${s.name}` : `Monitoring ${s.name}`);
      await reload();
    } catch (err) {
      toast.error('Update failed', errMsg(err));
    }
  };

  const columns: Column<Service>[] = [
    {
      key: 'name',
      header: 'Service',
      sort: (s) => s.display_name || s.name,
      render: (s) => (
        <div>
          <div style={{ fontWeight: 500 }}>{s.display_name || s.name}</div>
          {s.display_name && s.display_name !== s.name && <div className="muted small mono">{s.name}</div>}
        </div>
      ),
    },
    { key: 'state', header: 'State', sort: (s) => s.state, render: (s) => <Chip tone={stateTone(s.state)}>{s.state}</Chip> },
    { key: 'start', header: 'Start type', sort: (s) => s.start_type, render: (s) => <span className="muted">{s.start_type || '—'}</span> },
    { key: 'pid', header: 'PID', align: 'right', sort: (s) => s.pid ?? 0, render: (s) => <span className="mono">{s.pid || ''}</span> },
    {
      key: 'mon',
      header: 'Monitored',
      sort: (s) => (monitored.has(s.name.toLowerCase()) ? 0 : 1),
      render: (s) => (
        <button
          type="button"
          role="switch"
          aria-checked={monitored.has(s.name.toLowerCase())}
          aria-label={`Monitor ${s.name}`}
          className="switch"
          disabled={!canWrite}
          title="Report this service's state with every metrics sample"
          onClick={() => toggleMonitor(s)}
        />
      ),
    },
    {
      key: 'actions',
      header: '',
      render: (s) =>
        canWrite ? (
          <div className="cell-actions">
            {(['start', 'stop', 'restart'] as ServiceAction[]).map((a) => (
              <Button key={a} size="xs" busy={busy === `${s.name}:${a}`} disabled={!!busy} onClick={() => act(s, a)}>
                {a}
              </Button>
            ))}
            <span style={{ width: 8 }} />
            {(['enable', 'manual', 'disable'] as ServiceAction[]).map((a) => (
              <Button key={a} size="xs" variant="ghost" busy={busy === `${s.name}:${a}`} disabled={!!busy} onClick={() => act(s, a)} title={`Set start type: ${a}`}>
                {a}
              </Button>
            ))}
          </div>
        ) : null,
    },
  ];

  return (
    <>
      <div className="toolbar">
        <input type="search" placeholder="Filter services…" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 300 }} aria-label="Filter services" />
        <label className="row" style={{ gap: 6 }}>
          <input type="checkbox" checked={onlyMonitored} onChange={(e) => setOnlyMonitored(e.target.checked)} /> Monitored only
        </label>
        <Button onClick={() => svcs.reload()} busy={svcs.loading && !!svcs.data}>
          <IconRefresh /> Refresh
        </Button>
        <span className="grow" />
        {svcs.data && (
          <span className="muted small">
            {rows.length} of {svcs.data.length} services · {svcs.data.filter((s) => stateTone(s.state) === 'ok').length} running
          </span>
        )}
      </div>
      {svcs.error && <ErrorBox error={svcs.error} onRetry={svcs.reload} />}
      <DataTable columns={columns} rows={svcs.data ? rows : undefined} loading={svcs.loading} rowKey={(s) => s.name} defaultSort={{ key: 'name', dir: 'asc' }} compact emptyTitle="No services reported" />
    </>
  );
}
