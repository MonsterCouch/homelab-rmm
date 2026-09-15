// One baseline, every matched device, every check: the device × check matrix
// with the state of each pair, what was expected, what was observed and since
// when. Actions live where the trouble is — evaluate a device, remediate its
// failing checks, or fix one cell.

import { useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api, ApiError } from '../api/client';
import type { BaselineCheck, BaselineDeviceStatus, BaselineEventData, BaselineResult } from '../api/types';
import { kindDef, kindLabel } from '../components/baselines/kinds';
import { ComplianceChip, STATES, StateChip, resultTooltip, type CellState } from '../components/baselines/state';
import { textMatch } from '../components/DataTable';
import { IconRefresh } from '../components/Icons';
import { Drawer, useConfirm } from '../components/Modal';
import { targetsSummary } from '../components/TargetPicker';
import { Button, Chip, Empty, ErrorBox, Loading, OnlineDot, SeverityChip, Skeleton } from '../components/ui';
import { useAsync, useDebounced } from '../hooks/useAsync';
import { useLiveReload } from '../hooks/useEvents';
import { dateTime, duration, osLabel, relTime } from '../lib/format';
import { useAuth } from '../state/auth';
import { errMsg, useToast } from '../state/toast';

export function BaselineStatus() {
  const { id = '' } = useParams();
  const baselineId = Number(id);
  const navigate = useNavigate();
  const toast = useToast();
  const confirm = useConfirm();
  const { canWrite } = useAuth();
  const status = useAsync(() => api.baselineStatus(baselineId, 500), [baselineId]);
  const agentsList = useAsync(() => api.agents(), []);
  const groups = useAsync(() => api.groups(), []);
  // Every ingested report broadcasts a `baseline` event; it is a notification,
  // so the page refetches rather than trying to patch the matrix in place.
  // A `baseline` event for ANOTHER baseline says nothing about this matrix,
  // and on a fleet evaluating several baselines on their own schedules that
  // is a refetch of every device × check every few seconds for nothing.
  useLiveReload(['baseline', 'alert', 'agent_online', 'agent_offline', 'hello'], status.reload, {
    debounceMs: 700,
    filter: (ev) => ev.kind !== 'baseline' || (ev.data as BaselineEventData | undefined)?.baseline_id === baselineId,
  });

  const [q, setQ] = useState('');
  const dq = useDebounced(q);
  const [os, setOs] = useState('');
  const [stateFilter, setStateFilter] = useState<CellState | ''>('');
  const [cell, setCell] = useState<{ device: BaselineDeviceStatus; check: BaselineCheck } | null>(null);
  const [historyFor, setHistoryFor] = useState<BaselineDeviceStatus | null>(null);
  const [busy, setBusy] = useState('');

  const data = status.data;
  const byCheck = useMemo(() => {
    const m = new Map<string, BaselineResult>();
    for (const d of data?.devices ?? []) for (const r of d.results) m.set(`${d.agent_id}|${r.check_id}`, r);
    return m;
  }, [data]);
  const result = (agentId: string, checkId: number) => byCheck.get(`${agentId}|${checkId}`);
  const cellState = (d: BaselineDeviceStatus, c: BaselineCheck): CellState => result(d.agent_id, c.id)?.state ?? 'unknown';

  const devices = useMemo(() => {
    const list = data?.devices ?? [];
    return list.filter((d) => {
      if (os && d.os !== os) return false;
      if (!textMatch(dq, d.agent_name, d.agent_id, d.os, d.last_trigger)) return false;
      if (stateFilter) return (data?.checks ?? []).some((c) => cellState(d, c) === stateFilter);
      return true;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, dq, os, stateFilter, byCheck]);

  if (status.error && !data) {
    const notFound = status.error.toLowerCase().includes('not found');
    return (
      <>
        <div className="page-head">
          <Link to="/baselines">← Baselines</Link>
        </div>
        <ErrorBox error={notFound ? 'This baseline no longer exists.' : status.error} onRetry={notFound ? undefined : status.reload} />
      </>
    );
  }
  if (!data) return <Loading />;
  const b = data.baseline;

  const act = async (key: string, fn: () => Promise<string | undefined>, label: string) => {
    setBusy(key);
    try {
      const detail = await fn();
      toast.success(label, detail);
      window.setTimeout(() => void status.reload(), 1200);
    } catch (err) {
      const offline = err instanceof ApiError && err.status === 409;
      toast.error(offline ? 'The device is offline' : 'Failed', offline ? 'A fix cannot be queued; it runs on the next pass after it reconnects.' : errMsg(err));
    } finally {
      setBusy('');
    }
  };

  const evaluateAll = () =>
    act('all', async () => {
      const r = await api.evaluateBaseline(b.id);
      return `${r.queued} queued, ${r.offline} offline`;
    }, 'Evaluation requested');

  const evaluateOne = (d: BaselineDeviceStatus) =>
    act(`eval:${d.agent_id}`, async () => {
      const r = await api.evaluateBaseline(b.id, [d.agent_id]);
      return r.agents[0]?.status === 'offline' ? 'the device is offline; it will report when it reconnects' : undefined;
    }, `Evaluation requested on ${d.agent_name}`);

  const remediateDevice = async (d: BaselineDeviceStatus) => {
    const failing = (data.checks ?? []).filter((c) => ['fail', 'error'].includes(cellState(d, c)) && c.remediate);
    if (
      !(await confirm({
        title: 'Remediate failing checks',
        danger: true,
        confirmLabel: 'Remediate',
        message: `Run the fixes for ${failing.length || 'every failing'} check(s) on ${d.agent_name} now. This changes the device.`,
      }))
    )
      return;
    await act(`fix:${d.agent_id}`, async () => {
      const r = await api.remediateBaseline(b.id, d.agent_id);
      const refused = r.refused.length ? `${r.refused.length} refused: ${r.refused.map((x) => x.reason).join('; ')}` : undefined;
      return `${r.accepted.length} accepted${refused ? ` · ${refused}` : ''}`;
    }, `Remediation requested on ${d.agent_name}`);
  };

  const remediateCheck = async (d: BaselineDeviceStatus, c: BaselineCheck) => {
    if (!(await confirm({ title: `Fix "${c.name}"?`, danger: true, confirmLabel: 'Run the fix', message: `The agent runs this check's fix on ${d.agent_name} now, whether or not the baseline is enforced.` }))) return;
    await act(`fix:${d.agent_id}:${c.id}`, async () => {
      const r = await api.remediateBaseline(b.id, d.agent_id, [c.id]);
      if (r.refused.length) return `refused: ${r.refused[0].reason}`;
      return 'the pass will arrive in a moment';
    }, `Fix requested for ${c.name}`);
  };

  const sum = data.summary;

  return (
    <>
      <div className="page-head" style={{ marginBottom: 10 }}>
        <div className="row" style={{ marginRight: 'auto', gap: 10 }}>
          <Link to="/baselines" className="muted small">
            Baselines
          </Link>
          <span className="faint">/</span>
          <h1>{b.name}</h1>
          <Chip outline>v{b.version}</Chip>
          {b.enabled ? <Chip tone="ok">enabled</Chip> : <Chip tone="warn">disabled</Chip>}
          {b.enforce ? <Chip tone="purple" title="The agent fixes drift on these devices without asking">enforcing</Chip> : <Chip outline>report only</Chip>}
          <span className="muted small">every {duration(b.interval_sec)}</span>
        </div>
        <Button size="sm" onClick={status.reload} aria-label="Refresh" title="Refresh">
          <IconRefresh />
        </Button>
        {canWrite && (
          <>
            <Button
              size="sm"
              onClick={evaluateAll}
              busy={busy === 'all'}
              disabled={!b.enabled}
              title={b.enabled ? 'Ask every matched online device to evaluate now' : 'No device is holding this baseline: enable it first'}
            >
              Evaluate now
            </Button>
            <Button size="sm" onClick={() => navigate(`/baselines/${b.id}/edit`)}>
              Edit
            </Button>
          </>
        )}
      </div>

      {b.description && <p className="muted">{b.description}</p>}
      <div className="grid cols-4 mb">
        <div className="card stat">
          <span className="label">Compliance</span>
          <span className="value">
            <ComplianceChip value={sum.compliance} />
          </span>
          <span className="foot">mean over the devices that reported</span>
        </div>
        <div className="card stat">
          <span className="label">Devices</span>
          <span className="value">{sum.devices}</span>
          <span className="foot">{targetsSummary(b.targets, agentsList.data, groups.data)}</span>
        </div>
        <div className="card stat">
          <span className="label">Drifted</span>
          <span className={`value ${sum.devices_drifted ? 'danger' : ''}`}>{sum.devices_drifted}</span>
          <span className="foot">{sum.devices_reported} reported</span>
        </div>
        <div className="card stat">
          <span className="label">Not reported</span>
          <span className={`value ${sum.devices_unknown ? 'warn' : ''}`}>{sum.devices_unknown}</span>
          <span className="foot">no report for the current version yet</span>
        </div>
      </div>

      <div className="toolbar">
        <input type="search" placeholder="Filter devices…" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 220 }} aria-label="Filter devices" />
        <select value={os} onChange={(e) => setOs(e.target.value)} style={{ width: 130 }} aria-label="OS">
          <option value="">Any OS</option>
          <option value="windows">Windows</option>
          <option value="linux">Linux</option>
        </select>
        <select value={stateFilter} onChange={(e) => setStateFilter(e.target.value as CellState | '')} style={{ width: 170 }} aria-label="State">
          <option value="">Any state</option>
          {STATES.map((s) => (
            <option key={s} value={s}>
              has a {s} check
            </option>
          ))}
        </select>
        <span className="grow" />
        <span className="muted small">
          {devices.length} of {data.devices.length} devices · {data.checks.length} checks
        </span>
      </div>

      {data.truncated && (
        <div className="banner warn" role="status">
          <span>
            Showing the first {data.devices.length} of {sum.devices} matched devices. Filter to narrow the list; the compliance figures above cover every matched device.
          </span>
        </div>
      )}

      {status.loading && !data.devices.length ? (
        <div className="card">
          <Skeleton rows={4} />
        </div>
      ) : !data.checks.length ? (
        <Empty title="This baseline has no checks">
          <Link to={`/baselines/${b.id}/edit`}>Add one</Link> and the matrix fills in on the next pass.
        </Empty>
      ) : !devices.length ? (
        <Empty title="No devices match">
          {data.devices.length ? 'Clear the filters to see the rest.' : 'No device matches this baseline’s targets yet.'}
        </Empty>
      ) : (
        <div className="table-wrap">
          <table className="tbl compact baseline-matrix">
            <caption className="sr-only">
              {b.name}: every matched device against every check. Each cell is a button that opens what was expected and what was observed.
            </caption>
            <thead>
              <tr>
                <th scope="col" className="sticky-col">
                  Device
                </th>
                <th scope="col">Compliance</th>
                <th scope="col">Last report</th>
                {data.checks.map((c) => (
                  <th scope="col" key={c.id} title={`${kindLabel(c.kind)} — ${kindDef(c.kind)?.summary(c.params) ?? ''}`}>
                    <span className="truncate" style={{ display: 'inline-block', maxWidth: 140 }}>
                      {c.name}
                    </span>
                  </th>
                ))}
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.agent_id}>
                  <th scope="row" className="sticky-col">
                    <div className="row" style={{ gap: 6, flexWrap: 'nowrap' }}>
                      <OnlineDot online={d.online} />
                      <Link to={`/devices/${d.agent_id}/compliance`} onClick={(e) => e.stopPropagation()}>
                        {d.agent_name || d.agent_id}
                      </Link>
                      <span className="muted small">{osLabel(d.os)}</span>
                      <span className="sr-only">{d.online ? '(online)' : '(offline)'}</span>
                    </div>
                  </th>
                  <td>
                    <ComplianceChip value={d.compliance} stale={d.stale} />
                  </td>
                  <td className="muted small" title={d.last_report ? `${dateTime(d.last_report)} · trigger ${d.last_trigger || 'unknown'} · version ${d.version}` : undefined}>
                    {d.last_report ? `${relTime(d.last_report)}${d.last_trigger ? ` (${d.last_trigger})` : ''}` : 'never'}
                  </td>
                  {data.checks.map((c) => {
                    const r = result(d.agent_id, c.id);
                    return (
                      <td key={c.id}>
                        <button
                          type="button"
                          className="cell-btn"
                          title={resultTooltip(r, c.name)}
                          aria-label={`${c.name} on ${d.agent_name || d.agent_id}: ${r?.state ?? 'unknown'}${r?.stale ? ', stale' : ''}. Open the detail.`}
                          onClick={() => setCell({ device: d, check: c })}
                        >
                          <StateChip state={r?.state ?? 'unknown'} stale={r?.stale} />
                        </button>
                      </td>
                    );
                  })}
                  <td>
                    <div className="cell-actions">
                      <Button size="xs" onClick={() => setHistoryFor(d)} aria-label={`History for ${d.agent_name || d.agent_id}`}>
                        History
                      </Button>
                      {canWrite && (
                        <>
                          <Button
                            size="xs"
                            onClick={() => evaluateOne(d)}
                            busy={busy === `eval:${d.agent_id}`}
                            disabled={!b.enabled || !d.online}
                            aria-label={`Evaluate ${d.agent_name || d.agent_id} now`}
                            title={!b.enabled ? 'No device is holding this baseline: enable it first' : d.online ? 'Evaluate now' : 'The device is offline'}
                          >
                            Evaluate
                          </Button>
                          <Button
                            size="xs"
                            variant="danger"
                            onClick={() => remediateDevice(d)}
                            busy={busy === `fix:${d.agent_id}`}
                            disabled={!b.enabled || !d.online || !data.checks.some((c) => ['fail', 'error'].includes(cellState(d, c)) && c.remediate)}
                            aria-label={`Remediate the failing checks on ${d.agent_name || d.agent_id}`}
                            title={
                              !b.enabled
                                ? 'The device is not holding this baseline: enable it first'
                                : d.online
                                  ? 'Run the fixes for every failing check that allows it'
                                  : 'The device is offline'
                            }
                          >
                            Remediate
                          </Button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {cell && (
        <CellDrawer
          device={cell.device}
          check={cell.check}
          result={result(cell.device.agent_id, cell.check.id)}
          canWrite={canWrite}
          baselineEnabled={b.enabled}
          busy={busy === `fix:${cell.device.agent_id}:${cell.check.id}`}
          onRemediate={() => remediateCheck(cell.device, cell.check)}
          onClose={() => setCell(null)}
        />
      )}
      {historyFor && <HistoryDrawer device={historyFor} baselineId={b.id} onClose={() => setHistoryFor(null)} />}
    </>
  );
}

function CellDrawer({
  device,
  check,
  result,
  canWrite,
  baselineEnabled,
  busy,
  onRemediate,
  onClose,
}: {
  device: BaselineDeviceStatus;
  check: BaselineCheck;
  result: BaselineResult | undefined;
  canWrite: boolean;
  baselineEnabled: boolean;
  busy: boolean;
  onRemediate: () => void;
  onClose: () => void;
}) {
  return (
    <Drawer
      title={`${check.name} on ${device.agent_name || device.agent_id}`}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Close</Button>
          {canWrite && check.remediate && (
            <Button
              variant="danger"
              solid
              onClick={onRemediate}
              busy={busy}
              disabled={!baselineEnabled || !device.online}
              title={
                !baselineEnabled
                  ? 'The baseline is disabled, so the device is not holding this check: enable it first'
                  : device.online
                    ? 'Runs this check\u2019s fix now, whether or not the baseline is enforced'
                    : 'The device is offline, so a fix cannot be queued'
              }
            >
              Run the fix now
            </Button>
          )}
        </>
      }
    >
      <div className="row" style={{ gap: 8 }}>
        <StateChip state={result?.state ?? 'unknown'} stale={result?.stale} />
        <SeverityChip severity={check.severity} />
        <Chip outline>{kindLabel(check.kind)}</Chip>
        {check.remediate ? <Chip tone="purple">fix allowed</Chip> : <Chip outline>report only</Chip>}
      </div>
      <dl className="kv" style={{ marginTop: 10 }}>
        <dt>Expected</dt>
        <dd className="mono">{result?.expected || '—'}</dd>
        <dt>Observed</dt>
        <dd className="mono">{result?.observed || '—'}</dd>
        <dt>Since</dt>
        <dd>{result?.since ? `${dateTime(result.since)} (${relTime(result.since)})` : '—'}</dd>
        <dt>Checked</dt>
        <dd>{result?.checked_at ? `${dateTime(result.checked_at)} on the device` : '—'}</dd>
        <dt>Received</dt>
        <dd>{result?.received_at ? relTime(result.received_at) : '—'}</dd>
        <dt>Duration</dt>
        <dd>{result ? `${result.duration_ms} ms` : '—'}</dd>
        <dt>Baseline version</dt>
        <dd>
          {result?.version ?? '—'}
          {result?.stale ? ' (awaiting re-evaluation after an edit)' : ''}
        </dd>
        <dt>Parameters</dt>
        <dd className="mono small">{kindDef(check.kind)?.summary(check.params)}</dd>
      </dl>
      {result?.detail && (
        <>
          <h3>Detail</h3>
          <pre className="output">{result.detail}</pre>
        </>
      )}
      {!result && <p className="muted small">This device has not reported this check yet.</p>}
    </Drawer>
  );
}

function HistoryDrawer({ device, baselineId, onClose }: { device: BaselineDeviceStatus; baselineId: number; onClose: () => void }) {
  // Filtered by the server: this device may hold several baselines, and the
  // newest 200 rows over all of them can be none of this one's.
  const hist = useAsync(() => api.agentBaselineHistory(device.agent_id, 200, baselineId), [device.agent_id, baselineId]);
  const rows = hist.data?.history ?? [];
  return (
    <Drawer title={`History — ${device.agent_name || device.agent_id}`} onClose={onClose} wide footer={<Button onClick={onClose}>Close</Button>}>
      {hist.error && <ErrorBox error={hist.error} onRetry={hist.reload} />}
      {hist.loading && !hist.data && <Skeleton rows={4} cols={3} />}
      {hist.data && !rows.length && <Empty title="No transitions yet">A row is written whenever a check changes state.</Empty>}
      {rows.length > 0 && (
        <div className="table-wrap">
          <table className="tbl compact">
            <thead>
              <tr>
                <th scope="col">When</th>
                <th scope="col">Check</th>
                <th scope="col">Change</th>
                <th scope="col">Detail</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((h) => (
                <tr key={h.id}>
                  <td className="muted small nowrap" title={dateTime(h.ts)}>
                    {relTime(h.ts)}
                  </td>
                  <td>{h.check_name || `#${h.check_id}`}</td>
                  <td className="nowrap">
                    <StateChip state={(h.from_state || 'unknown') as CellState} /> <span aria-hidden="true">→</span>
                    <span className="sr-only">changed to</span> <StateChip state={h.to_state as CellState} />
                  </td>
                  <td className="muted small truncate" style={{ maxWidth: 380 }} title={h.detail}>
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
