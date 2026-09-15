import { useMemo, useState } from 'react';
import { api } from '../../api/client';
import type { Process } from '../../api/types';
import { DataTable, textMatch, type Column } from '../../components/DataTable';
import { IconRefresh } from '../../components/Icons';
import { useConfirm } from '../../components/Modal';
import { Button, ErrorBox, Switch } from '../../components/ui';
import { useAsync, useDebounced, useInterval } from '../../hooks/useAsync';
import { bytes, relTime } from '../../lib/format';
import { errMsg, useToast } from '../../state/toast';
import type { TabProps } from './DeviceDetail';

export function Processes({ agent, canWrite }: TabProps) {
  const toast = useToast();
  const confirm = useConfirm();
  const procs = useAsync((signal) => api.processes(agent.id, signal), [agent.id]);
  const [q, setQ] = useState('');
  const dq = useDebounced(q);
  const [auto, setAuto] = useState(false);
  useInterval(procs.reload, 5000, auto);

  const rows = useMemo(() => (procs.data ?? []).filter((p) => textMatch(dq, p.name, p.user, p.cmdline, p.pid)), [procs.data, dq]);

  const kill = async (p: Process) => {
    if (!(await confirm({ title: 'Kill process', message: `Terminate "${p.name}" (PID ${p.pid})? Unsaved work in that program is lost.`, danger: true, confirmLabel: 'Kill' }))) return;
    try {
      await api.killProcess(agent.id, p.pid);
      toast.success(`Killed ${p.name}`);
      void procs.reload();
    } catch (err) {
      toast.error('Kill failed', errMsg(err));
    }
  };

  const columns: Column<Process>[] = [
    { key: 'pid', header: 'PID', align: 'right', sort: (p) => p.pid, render: (p) => <span className="mono">{p.pid}</span> },
    { key: 'name', header: 'Name', sort: (p) => p.name, render: (p) => <b>{p.name}</b> },
    { key: 'user', header: 'User', sort: (p) => p.user, render: (p) => <span className="muted">{p.user || '—'}</span> },
    { key: 'cpu', header: 'CPU %', align: 'right', sort: (p) => p.cpu, render: (p) => p.cpu.toFixed(1) },
    { key: 'mem', header: 'Memory', align: 'right', sort: (p) => p.mem, render: (p) => bytes(p.mem) },
    { key: 'started', header: 'Started', sort: (p) => p.started, render: (p) => <span className="muted">{p.started ? relTime(p.started) : '—'}</span> },
    {
      key: 'cmd',
      header: 'Command line',
      sort: (p) => p.cmdline,
      render: (p) => (
        <span className="ellipsis mono small muted" style={{ display: 'inline-block', maxWidth: 420 }} title={p.cmdline}>
          {p.cmdline}
        </span>
      ),
    },
    {
      key: 'actions',
      header: '',
      render: (p) =>
        canWrite ? (
          <div className="cell-actions">
            <Button size="xs" variant="danger" onClick={() => kill(p)}>
              Kill
            </Button>
          </div>
        ) : null,
    },
  ];

  return (
    <>
      <div className="toolbar">
        <input type="search" placeholder="Filter by name, user, command…" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 320 }} aria-label="Filter processes" />
        <Button onClick={() => procs.reload()} busy={procs.loading && !!procs.data}>
          <IconRefresh /> Refresh
        </Button>
        <Switch checked={auto} onChange={setAuto} label="Auto-refresh (5s)" />
        <span className="grow" />
        {procs.data && (
          <span className="muted small">
            {rows.length} of {procs.data.length} processes
          </span>
        )}
      </div>
      {procs.error && <ErrorBox error={procs.error} onRetry={procs.reload} />}
      <DataTable columns={columns} rows={procs.data ? rows : undefined} loading={procs.loading} rowKey={(p) => String(p.pid)} defaultSort={{ key: 'cpu', dir: 'desc' }} compact emptyTitle="No processes reported" />
    </>
  );
}
