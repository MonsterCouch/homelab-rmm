// The device's side of baselines: every assigned baseline, every check, what
// was expected against what was observed, since when, and the buttons that
// change it. Deliberately available while the device is offline — the last
// known state of a machine that is not answering is exactly what an operator
// comes here to read.

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api, ApiError } from '../../api/client';
import type { AgentBaseline, AgentBaselineCheck } from '../../api/types';
import { kindDef, kindLabel } from '../../components/baselines/kinds';
import { ComplianceChip, CountsRow, StateChip, type CellState } from '../../components/baselines/state';
import { IconRefresh } from '../../components/Icons';
import { Drawer, useConfirm } from '../../components/Modal';
import { Button, Chip, Empty, ErrorBox, SeverityChip, Skeleton } from '../../components/ui';
import { useAsync } from '../../hooks/useAsync';
import { useLiveReload } from '../../hooks/useEvents';
import { dateTime, duration, relTime } from '../../lib/format';
import { errMsg, useToast } from '../../state/toast';
import type { TabProps } from './DeviceDetail';

export function Compliance({ agent, canWrite }: TabProps) {
  const toast = useToast();
  const confirm = useConfirm();
  const data = useAsync(() => api.agentBaselines(agent.id), [agent.id]);
  useLiveReload(['baseline', 'hello'], data.reload, { agentId: agent.id, debounceMs: 700 });
  const [historyOpen, setHistoryOpen] = useState(false);
  const [busy, setBusy] = useState('');

  const act = async (key: string, fn: () => Promise<string | undefined>, label: string) => {
    setBusy(key);
    try {
      const detail = await fn();
      toast.success(label, detail);
      window.setTimeout(() => void data.reload(), 1200);
    } catch (err) {
      const offline = err instanceof ApiError && err.status === 409;
      toast.error(offline ? 'The device is offline' : 'Failed', offline ? 'A fix cannot be queued; it runs on the next pass after it reconnects.' : errMsg(err));
    } finally {
      setBusy('');
    }
  };

  const evaluate = (b: AgentBaseline) =>
    act(`eval:${b.id}`, async () => {
      const r = await api.evaluateBaseline(b.id, [agent.id]);
      return r.agents[0]?.status === 'offline' ? 'the device is offline; it will report when it reconnects' : undefined;
    }, `Evaluation requested: ${b.name}`);

  const remediateAll = async (b: AgentBaseline) => {
    if (!(await confirm({ title: 'Remediate failing checks', danger: true, confirmLabel: 'Remediate', message: `Run the fixes for every failing check of "${b.name}" on ${agent.display_name} now. This changes the device.` }))) return;
    await act(`fix:${b.id}`, async () => {
      const r = await api.remediateBaseline(b.id, agent.id);
      const refused = r.refused.length ? `${r.refused.length} refused: ${r.refused.map((x) => x.reason).join('; ')}` : undefined;
      return `${r.accepted.length} accepted${refused ? ` · ${refused}` : ''}`;
    }, 'Remediation requested');
  };

  const remediateOne = async (b: AgentBaseline, c: AgentBaselineCheck) => {
    if (!(await confirm({ title: `Fix "${c.name}"?`, danger: true, confirmLabel: 'Run the fix', message: `The agent runs this check's fix on ${agent.display_name} now, whether or not the baseline is enforced.` }))) return;
    await act(`fix:${b.id}:${c.id}`, async () => {
      const r = await api.remediateBaseline(b.id, agent.id, [c.id]);
      if (r.refused.length) return `refused: ${r.refused[0].reason}`;
      return 'the pass will arrive in a moment';
    }, `Fix requested for ${c.name}`);
  };

  if (data.error && !data.data) return <ErrorBox error={data.error} onRetry={data.reload} />;
  if (!data.data) return <Skeleton rows={4} />;
  const list = data.data.baselines;

  return (
    <>
      <div className="toolbar">
        <span className="row" style={{ gap: 8 }}>
          <span className="muted small">Overall compliance</span>
          <ComplianceChip value={data.data.compliance} />
        </span>
        <span className="grow" />
        <Button size="sm" onClick={() => setHistoryOpen(true)}>
          History
        </Button>
        <Button size="sm" onClick={data.reload} aria-label="Refresh" title="Refresh">
          <IconRefresh />
        </Button>
      </div>

      {!list.length && (
        <Empty title="No baselines assigned">
          This device matches no enabled baseline. <Link to="/baselines">Baselines</Link> is where desired state is defined.
        </Empty>
      )}

      <div className="stack" style={{ gap: 14 }}>
        {list.map((b) => (
          <div key={b.id} className="card" data-testid={`compliance-baseline-${b.id}`}>
            <div className="card-head">
              <Link to={`/baselines/${b.id}`}>{b.name}</Link>
              {b.enforce ? <Chip tone="purple" title="The agent fixes drift on this device without asking">enforcing</Chip> : <Chip outline>report only</Chip>}
              <ComplianceChip value={b.compliance} stale={b.stale} />
              <span className="muted small">
                every {duration(b.interval_sec)} · {b.last_report ? `last report ${relTime(b.last_report)}${b.last_trigger ? ` (${b.last_trigger})` : ''}` : 'no report yet'}
              </span>
              <div className="actions">
                {canWrite && (
                  <>
                    <Button size="xs" onClick={() => evaluate(b)} busy={busy === `eval:${b.id}`} disabled={!agent.online} title={agent.online ? undefined : 'The device is offline'}>
                      Evaluate now
                    </Button>
                    <Button
                      size="xs"
                      variant="danger"
                      onClick={() => remediateAll(b)}
                      busy={busy === `fix:${b.id}`}
                      disabled={!agent.online || !b.checks.some((c) => c.remediate && ['fail', 'error'].includes(c.result?.state ?? ''))}
                      title={agent.online ? 'Run the fixes for every failing check that allows it' : 'The device is offline'}
                    >
                      Remediate failing
                    </Button>
                  </>
                )}
              </div>
            </div>
            <div className="card-body tight">
              <CountsRow counts={b.counts} />
            </div>
            <div className="table-wrap">
              <table className="tbl compact">
                <thead>
                  <tr>
                    <th>Check</th>
                    <th>State</th>
                    <th>Expected</th>
                    <th>Observed</th>
                    <th>Since</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {b.checks.map((c) => (
                    <tr key={c.id}>
                      <td>
                        <div>
                          <b>{c.name}</b>
                          <div className="muted small">
                            <Chip outline>{kindLabel(c.kind)}</Chip> <SeverityChip severity={c.severity} />
                            {c.remediate ? <Chip tone="purple">fix</Chip> : null}
                          </div>
                          <div className="faint small mono truncate" style={{ maxWidth: 360 }}>
                            {kindDef(c.kind)?.summary(c.params) ?? ''}
                          </div>
                        </div>
                      </td>
                      <td title={c.result?.detail || undefined}>
                        <StateChip state={c.result?.state ?? 'unknown'} stale={c.result?.stale} />
                      </td>
                      <td className="mono small">{c.result?.expected || '—'}</td>
                      <td className="mono small" title={c.result?.detail || undefined}>
                        {c.result?.observed || '—'}
                      </td>
                      <td className="muted small nowrap" title={c.result?.since ? dateTime(c.result.since) : undefined}>
                        {c.result?.since ? relTime(c.result.since) : '—'}
                      </td>
                      <td>
                        {canWrite && c.remediate && ['fail', 'error'].includes(c.result?.state ?? '') && (
                          <Button size="xs" variant="danger" busy={busy === `fix:${b.id}:${c.id}`} disabled={!agent.online} onClick={() => remediateOne(b, c)}>
                            Fix
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {b.checks.some((c) => c.result?.detail) && (
              <div className="tbl-foot">
                <span className="muted small">Hover a state or an observed value to read the detail the agent reported.</span>
              </div>
            )}
          </div>
        ))}
      </div>

      {historyOpen && <DeviceHistory agentId={agent.id} onClose={() => setHistoryOpen(false)} />}
    </>
  );
}

function DeviceHistory({ agentId, onClose }: { agentId: string; onClose: () => void }) {
  const hist = useAsync(() => api.agentBaselineHistory(agentId, 200), [agentId]);
  const rows = hist.data?.history ?? [];
  return (
    <Drawer title="Baseline history" onClose={onClose} wide footer={<Button onClick={onClose}>Close</Button>}>
      {hist.error && <ErrorBox error={hist.error} onRetry={hist.reload} />}
      {hist.loading && !hist.data && <Skeleton rows={4} cols={3} />}
      {hist.data && !rows.length && <Empty title="No transitions yet">A row is written whenever a check changes state.</Empty>}
      {rows.length > 0 && (
        <div className="table-wrap">
          <table className="tbl compact">
            <thead>
              <tr>
                <th>When</th>
                <th>Baseline</th>
                <th>Check</th>
                <th>Change</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((h) => (
                <tr key={h.id}>
                  <td className="muted small nowrap" title={dateTime(h.ts)}>
                    {relTime(h.ts)}
                  </td>
                  <td className="muted small">{h.baseline_name || `#${h.baseline_id}`}</td>
                  <td>{h.check_name || `#${h.check_id}`}</td>
                  <td className="nowrap">
                    <StateChip state={(h.from_state || 'unknown') as CellState} /> → <StateChip state={h.to_state as CellState} />
                  </td>
                  <td className="muted small truncate" style={{ maxWidth: 360 }} title={h.detail}>
                    {h.detail}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Drawer>
  );
}
