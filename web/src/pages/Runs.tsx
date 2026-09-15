import { useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { IconRefresh } from '../components/Icons';
import { RunDrawer } from '../components/RunDrawer';
import { RunsTable } from '../components/RunsTable';
import { Button, ErrorBox } from '../components/ui';
import { useAsync, useDebounced } from '../hooks/useAsync';
import { useLiveReload } from '../hooks/useEvents';
import { textMatch } from '../components/DataTable';

const STATUSES = ['all', 'running', 'queued', 'done', 'failed', 'timeout', 'cancelled'];

export function Runs() {
  const [params, setParams] = useSearchParams();
  const agentFilter = params.get('agent') ?? '';
  const openId = params.get('id');
  const runs = useAsync(() => api.runs(agentFilter, 500), [agentFilter]);
  useLiveReload(['run'], runs.reload, { debounceMs: 800 });
  const agents = useAsync(() => api.agents(), []);
  const [status, setStatus] = useState('all');
  const [q, setQ] = useState('');
  const dq = useDebounced(q);

  const rows = useMemo(() => (runs.data ?? []).filter((r) => (status === 'all' || r.status === status) && textMatch(dq, r.script_name, r.agent_name, r.run_by, r.trigger, r.id)), [runs.data, status, dq]);

  const setParam = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setParams(next, { replace: true });
  };

  return (
    <>
      <div className="page-head">
        <h1>Runs</h1>
        <Button onClick={() => runs.reload()} icon aria-label="Refresh">
          <IconRefresh />
        </Button>
      </div>
      <div className="toolbar">
        <input type="search" placeholder="Search script, device, user…" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 280 }} aria-label="Search runs" />
        <select value={status} onChange={(e) => setStatus(e.target.value)} style={{ width: 140 }} aria-label="Status">
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s === 'all' ? 'Any status' : s}
            </option>
          ))}
        </select>
        <select value={agentFilter} onChange={(e) => setParam('agent', e.target.value)} style={{ width: 200 }} aria-label="Device">
          <option value="">Any device</option>
          {(agents.data ?? []).map((a) => (
            <option key={a.id} value={a.id}>
              {a.display_name}
            </option>
          ))}
        </select>
        <span className="grow" />
        {runs.data && (
          <span className="muted small">
            {rows.length} of {runs.data.length} runs · {runs.data.filter((r) => r.status === 'running').length} running
          </span>
        )}
      </div>
      {runs.error && <ErrorBox error={runs.error} onRetry={runs.reload} />}
      <RunsTable rows={runs.data ? rows : undefined} loading={runs.loading} onOpen={(r) => setParam('id', r.id)} emptyTitle={runs.data?.length ? 'No runs match' : 'No runs yet'} />
      {openId && <RunDrawer runId={openId} onClose={() => setParam('id', '')} onChanged={runs.reload} />}
    </>
  );
}
