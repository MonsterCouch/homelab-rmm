import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import type { Run, RunEventData } from '../api/types';
import { useAsync } from '../hooks/useAsync';
import { useEvents } from '../hooks/useEvents';
import { dateTime, elapsed } from '../lib/format';
import { useAuth } from '../state/auth';
import { errMsg, useToast } from '../state/toast';
import { Drawer } from './Modal';
import { OutputPane } from './RunDialog';
import { Button, ErrorBox, Loading, RunStatusChip, Tabs } from './ui';

const ACTIVE = new Set(['running', 'queued', 'pending']);

/** Run detail with live-streamed output; used from the Runs page and the device Runs tab. */
export function RunDrawer({
  runId,
  onClose,
  onChanged,
  onOpenRun,
}: {
  runId: string;
  onClose: () => void;
  onChanged?: () => void;
  /** follow a re-run into its own drawer when the caller owns which run is open */
  onOpenRun?: (id: string) => void;
}) {
  const toast = useToast();
  const { canWrite } = useAuth();
  const run = useAsync(() => api.run(runId), [runId]);
  const [tab, setTab] = useState<'stdout' | 'stderr'>('stdout');
  const [tick, setTick] = useState(0);

  // elapsed-time ticker while running
  useEffect(() => {
    if (!run.data || !ACTIVE.has(run.data.status)) return;
    const id = window.setInterval(() => setTick((t) => t + 1), 1000);
    return () => window.clearInterval(id);
  }, [run.data]);

  useEvents(['run'], (ev) => {
    const d = ev.data as RunEventData | undefined;
    if (!d || d.run_id !== runId) return;
    if (d.stream && d.data !== undefined) {
      run.setData((r) => (r ? { ...r, [d.stream!]: (r[d.stream!] ?? '') + d.data } : r));
    }
    if (d.status) {
      const finished = !ACTIVE.has(d.status);
      run.setData((r) => (r ? { ...r, status: d.status!, exit_code: d.exit_code ?? r.exit_code, finished_at: finished && !r.finished_at ? Math.floor(Date.now() / 1000) : r.finished_at } : r));
      if (finished) {
        void run.reload();
        onChanged?.();
      }
    }
  });

  const r: Run | undefined = run.data;
  const active = !!r && ACTIVE.has(r.status);

  const cancel = async () => {
    try {
      await api.cancelRun(runId);
      toast.info('Cancel requested');
    } catch (err) {
      toast.error('Cancel failed', errMsg(err));
    }
  };

  const [rerunning, setRerunning] = useState(false);
  /**
   * Repeat this run: same script, same arguments, same device. An ad hoc run
   * cannot be repeated — the body was never stored — so the button says so
   * instead of failing.
   */
  const rerun = async () => {
    if (!r?.script_id) return;
    setRerunning(true);
    try {
      const res = await api.runScript({ script_id: r.script_id, args: r.args, targets: { all: false, agents: [r.agent_id] } });
      const next = Object.values(res.runs).find((v) => !v.startsWith('error: ') && !v.startsWith('skipped: '));
      const problem = Object.values(res.runs).find((v) => v.startsWith('error: ') || v.startsWith('skipped: '));
      if (!next) {
        toast.error('Could not start', problem ?? 'the device did not accept the run');
        return;
      }
      toast.success('Re-run started', r.script_name);
      onChanged?.();
      onOpenRun?.(next);
    } catch (err) {
      toast.error('Re-run failed', errMsg(err));
    } finally {
      setRerunning(false);
    }
  };

  return (
    <Drawer
      title={
        <span className="row">
          {r ? r.script_name : 'Run'} {r && <RunStatusChip status={r.status} />}
        </span>
      }
      onClose={onClose}
      wide
      actions={
        canWrite ? (
          active ? (
            <Button size="sm" variant="danger" onClick={cancel}>
              Cancel run
            </Button>
          ) : r ? (
            <Button size="sm" busy={rerunning} disabled={!r.script_id} onClick={rerun} title={r.script_id ? 'Run this script again on this device' : 'Ad hoc runs are not stored and cannot be repeated'}>
              Re-run
            </Button>
          ) : undefined
        ) : undefined
      }
    >
      {run.error && !r && <ErrorBox error={run.error} onRetry={run.reload} />}
      {!r && !run.error && <Loading />}
      {r && (
        <div className="stack" style={{ gap: 12 }}>
          <dl className="kv small">
            <dt>Device</dt>
            <dd>
              <Link to={`/devices/${r.agent_id}`}>{r.agent_name || r.agent_id}</Link>
            </dd>
            <dt>Started</dt>
            <dd>
              {dateTime(r.started_at)} · {r.trigger}
              {r.run_by && ` by ${r.run_by}`}
            </dd>
            <dt>Duration</dt>
            <dd>
              {elapsed(r.started_at, r.finished_at)}
              {active && <span className="muted"> (running{tick % 2 ? '' : ''})</span>}
            </dd>
            <dt>Exit code</dt>
            <dd className="mono">{active ? '—' : r.exit_code}</dd>
            {r.args.length > 0 && (
              <>
                <dt>Arguments</dt>
                <dd className="mono">{r.args.map((a) => JSON.stringify(a)).join(' ')}</dd>
              </>
            )}
            <dt>Run ID</dt>
            <dd className="mono muted">{r.id}</dd>
          </dl>
          <Tabs
            tabs={[
              { id: 'stdout', label: 'stdout' },
              { id: 'stderr', label: 'stderr', count: r.stderr ? r.stderr.split('\n').filter(Boolean).length : undefined },
            ]}
            value={tab}
            onChange={setTab}
          />
          <OutputPane text={(tab === 'stdout' ? r.stdout : r.stderr) ?? ''} live={active} stderr={tab === 'stderr'} height={480} />
        </div>
      )}
    </Drawer>
  );
}
