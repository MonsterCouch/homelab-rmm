import { useMemo, useState } from 'react';
import { api } from '../../api/client';
import type { Patch, ServicingRecord } from '../../api/types';
import { DataTable, textMatch, type Column } from '../../components/DataTable';
import { IconRefresh } from '../../components/Icons';
import { Modal, useConfirm } from '../../components/Modal';
import { Button, Chip, ErrorBox, Field, PatchStatusChip, Switch } from '../../components/ui';
import { useAsync, useDebounced } from '../../hooks/useAsync';
import { useLiveReload } from '../../hooks/useEvents';
import { bytes, dateTime, relTime } from '../../lib/format';
import { errMsg, useToast } from '../../state/toast';
import type { TabProps } from './DeviceDetail';
import '../../styles/mobile-pages.css';

export function sevTone(s: string): 'danger' | 'warn' | 'info' | '' {
  const v = s.toLowerCase();
  if (v === 'critical') return 'danger';
  if (v === 'important' || v === 'high') return 'warn';
  if (v === 'moderate' || v === 'medium' || v === 'low') return 'info';
  return '';
}

export const patchKey = (p: Patch) => `${p.agent_id}|${p.patch_id}`;

const REPAIR_STEPS: { id: string; label: string; hint: string }[] = [
  { id: 'dism_restore', label: 'DISM RestoreHealth', hint: 'Repairs the component store from Windows Update.' },
  { id: 'sfc', label: 'System File Checker', hint: 'Advisory: a failure here does not stop the repair.' },
  { id: 'reset_components', label: 'Reset Windows Update components', hint: 'Renames the update catalog and download caches so Windows rebuilds them.' },
  { id: 'rescan', label: 'Scan for updates afterwards', hint: 'Takes a fresh update scan when the repair is done.' },
];

const stepTone = (s: string): 'ok' | 'danger' | '' => (s === 'ok' ? 'ok' : s === 'failed' ? 'danger' : '');

function RepairDialog({ agentId, onClose, onStarted }: { agentId: string; onClose: () => void; onStarted: () => void }) {
  const toast = useToast();
  const [steps, setSteps] = useState<Set<string>>(new Set(['dism_restore', 'reset_components', 'rescan']));
  const [reboot, setReboot] = useState<'never' | 'if_required'>('never');
  const [busy, setBusy] = useState(false);
  const start = async () => {
    setBusy(true);
    try {
      // Sent in canonical order whatever order they were ticked in, so what
      // is signed reads the same as what the device runs.
      await api.servicingRepair(agentId, { steps: REPAIR_STEPS.filter((s) => steps.has(s.id)).map((s) => s.id), reboot });
      toast.info('Repair started', 'It can take several minutes. The result appears under the patch list.');
      onStarted();
      onClose();
    } catch (err) {
      toast.error('Repair failed to start', errMsg(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title="Repair Windows servicing"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" busy={busy} disabled={!steps.size} onClick={start}>
            Start repair
          </Button>
        </>
      }
    >
      <p className="muted small" style={{ marginTop: 0 }}>
        Use this when updates fail with a servicing error such as 0x80073712 or 0x800F081F. The repair holds the device's patch jobs while it runs.
      </p>
      {REPAIR_STEPS.map((s) => (
        <label key={s.id} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginBottom: 8 }}>
          <input
            type="checkbox"
            checked={steps.has(s.id)}
            onChange={(e) =>
              setSteps((cur) => {
                const n = new Set(cur);
                if (e.target.checked) n.add(s.id);
                else n.delete(s.id);
                return n;
              })
            }
          />
          <span>
            {s.label}
            <br />
            <span className="muted small">{s.hint}</span>
          </span>
        </label>
      ))}
      <Field label="Reboot">
        <select value={reboot} onChange={(e) => setReboot(e.target.value as 'never' | 'if_required')}>
          <option value="never">Never, only report that one is needed</option>
          <option value="if_required">If required</option>
        </select>
      </Field>
    </Modal>
  );
}

function LastRepair({ rec }: { rec: ServicingRecord }) {
  const steps = rec.result?.steps ?? [];
  return (
    <div className="card" style={{ marginTop: 12 }}>
      <div className="card-head">
        Last servicing repair <Chip tone={rec.status === 'ok' ? 'ok' : rec.status === 'failed' ? 'danger' : 'info'}>{rec.status}</Chip>
      </div>
      <div className="card-body">
        <div className="muted small">
          {rec.trigger === 'auto' ? 'Started automatically' : 'Started by ' + (rec.by || 'an operator')} {dateTime(rec.started_at)}
          {rec.code && ` after ${rec.code}`}
          {rec.why && `: ${rec.why}`}
        </div>
        {rec.result?.error && <div style={{ color: 'var(--danger)', marginTop: 6 }}>{rec.result.error}</div>}
        {steps.length > 0 && (
          <table className="table compact" style={{ marginTop: 8 }}>
            <tbody>
              {steps.map((s) => (
                <tr key={s.name}>
                  <td className="mono">{s.name}</td>
                  <td>
                    <Chip tone={stepTone(s.status)}>{s.status}</Chip>
                  </td>
                  <td className="muted small">{s.status === 'skipped' ? '' : `exit ${s.exit_code}, ${Math.round(s.duration_ms / 1000)} s`}</td>
                  <td className="muted small mono truncate" style={{ maxWidth: 420 }} title={s.tail}>
                    {s.tail?.split('\n').filter(Boolean).slice(-1)[0] ?? ''}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {rec.result?.reboot_required && <div className="banner warn" style={{ marginTop: 8 }}>The repair finished and the device needs a reboot.</div>}
      </div>
    </div>
  );
}

export function DevicePatches({ agent, canWrite }: TabProps) {
  const toast = useToast();
  const confirm = useConfirm();
  const data = useAsync(() => api.agentPatches(agent.id), [agent.id]);
  useLiveReload(['patches'], data.reload, { agentId: agent.id });
  const [q, setQ] = useState('');
  const dq = useDebounced(q);
  const [status, setStatus] = useState('pending');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [scanning, setScanning] = useState(false);
  const [reboot, setReboot] = useState(false);
  const [repairing, setRepairing] = useState(false);
  const isWindows = agent.os === 'windows';
  const servicing = useAsync(() => (isWindows ? api.servicingRecords(agent.id, 1) : Promise.resolve([] as ServicingRecord[])), [agent.id, isWindows]);
  useLiveReload(['patches'], servicing.reload, { agentId: agent.id });
  const lastRepair = servicing.data?.[0];

  const patches = data.data?.patches ?? [];
  const rows = useMemo(
    () =>
      patches.filter((p) => {
        if (status === 'pending' && !['available', 'approved', 'installing', 'failed'].includes(p.status)) return false;
        if (status !== 'pending' && status !== 'all' && p.status !== status) return false;
        return textMatch(dq, p.title, p.kb, p.severity, p.source, p.version, ...p.categories);
      }),
    [patches, status, dq],
  );
  const sel = patches.filter((p) => selected.has(patchKey(p)));
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const p of patches) c[p.status] = (c[p.status] ?? 0) + 1;
    return c;
  }, [patches]);

  const scan = async () => {
    setScanning(true);
    try {
      const res = await api.patchScan(agent.id);
      data.setData(res);
      // A scan whose update source failed still answers 200 with a fresh
      // timestamp and the previous list, so say so instead of "complete".
      if (res.scan_error) toast.warning('Patch scan reported a problem', res.scan_error);
      else toast.success('Patch scan complete', `${res.patches.filter((p) => p.status === 'available').length} available`);
    } catch (err) {
      toast.error('Scan failed', errMsg(err));
    } finally {
      setScanning(false);
    }
  };
  const setSel = async (st: 'approved' | 'ignored' | 'available') => {
    if (!sel.length) return;
    try {
      await api.patchStatus(
        sel.map((p) => ({ AgentID: p.agent_id, PatchID: p.patch_id })),
        st,
      );
      toast.success(`${sel.length} patch(es) marked ${st}`);
      setSelected(new Set());
      void data.reload();
    } catch (err) {
      toast.error('Update failed', errMsg(err));
    }
  };
  const install = async (all: boolean) => {
    const n = all ? patches.filter((p) => p.status === 'available' || p.status === 'approved').length : sel.length;
    if (!n) return;
    if (!(await confirm({ title: all ? 'Install all patches' : `Install ${n} patch(es)`, message: `The device will download and install ${n} update(s) now.${reboot ? ' It will reboot afterwards if required.' : ''} Follow progress on this page.`, confirmLabel: 'Install' }))) return;
    try {
      await api.patchInstall(agent.id, all ? { all: true, reboot_if_required: reboot } : { ids: sel.map((p) => p.patch_id), reboot_if_required: reboot });
      toast.info('Installation started', 'Status updates arrive live.');
      setSelected(new Set());
      void data.reload();
    } catch (err) {
      toast.error('Install failed', errMsg(err));
    }
  };

  const columns: Column<Patch>[] = [
    { key: 'status', header: 'Status', sort: (p) => p.status, render: (p) => <PatchStatusChip status={p.status} /> },
    {
      key: 'title',
      header: 'Update',
      sort: (p) => p.title,
      render: (p) => (
        <div style={{ maxWidth: 560 }}>
          <div className="truncate" title={p.title} style={{ fontWeight: 500 }}>
            {p.title}
          </div>
          <div className="muted small">
            {p.categories.join(', ')}
            {p.version && ` · ${p.version}`}
            {p.error && <span style={{ color: 'var(--danger)' }}> · {p.error}</span>}
          </div>
        </div>
      ),
    },
    { key: 'kb', header: 'KB', sort: (p) => p.kb, render: (p) => <span className="mono small">{p.kb || '—'}</span> },
    { key: 'sev', header: 'Severity', sort: (p) => p.severity, render: (p) => (p.severity ? <Chip tone={sevTone(p.severity)}>{p.severity}</Chip> : <span className="faint">—</span>) },
    {
      key: 'size',
      header: 'Size',
      align: 'right',
      sort: (p) => p.size,
      csv: (p) => (p.downloaded ? `${p.size} (downloaded)` : p.size),
      // "downloaded" is the difference between a 96 GB cumulative update the
      // device still has to fetch and one Windows has already staged.
      render: (p) => (
        <span>
          {p.size ? bytes(p.size) : <span className="faint">—</span>}
          {p.downloaded && (
            <>
              {' '}
              <Chip tone="info">downloaded</Chip>
            </>
          )}
        </span>
      ),
    },
    {
      key: 'src',
      header: 'Source',
      sort: (p) => p.source,
      render: (p) => (
        <span className="muted" title={p.source === 'winget' ? 'Application upgrade reported by winget — informational: the agent service account cannot install it' : undefined}>
          {p.source}
        </span>
      ),
    },
    { key: 'reboot', header: 'Reboot', sort: (p) => (p.reboot_required ? 0 : 1), csv: (p) => (p.reboot_required ? 'yes' : 'no'), render: (p) => (p.reboot_required ? <Chip tone="warn">yes</Chip> : <span className="faint">no</span>) },
    {
      key: 'seen',
      header: 'First seen',
      sort: (p) => p.first_seen,
      csv: (p) => (p.first_seen ? new Date(p.first_seen * 1000).toISOString() : ''),
      render: (p) => <span className="muted">{relTime(p.first_seen)}</span>,
    },
  ];

  return (
    <>
      {agent.pending_reboot && (
        <div className="banner warn">
          <span>This device requires a reboot to finish installing updates.</span>
        </div>
      )}
      {data.data?.scan_error && (
        <div className="banner warn">
          <span>
            The last patch scan reported a problem: {data.data.scan_error}. The list below is what the previous scan found and may be out of date.
          </span>
        </div>
      )}
      <div className="toolbar">
        <div className="btn-group">
          {[
            ['pending', `Pending (${(counts.available ?? 0) + (counts.approved ?? 0) + (counts.installing ?? 0) + (counts.failed ?? 0)})`],
            ['installed', `Installed (${counts.installed ?? 0})`],
            ['ignored', `Ignored (${counts.ignored ?? 0})`],
            ['all', `All (${patches.length})`],
          ].map(([id, label]) => (
            <button key={id} className={`btn sm ${status === id ? 'active' : ''}`} onClick={() => setStatus(id)}>
              {label}
            </button>
          ))}
        </div>
        <input type="search" placeholder="Filter…" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 200 }} aria-label="Filter patches" />
        <span className="grow" />
        <span className="muted small">Last scan: {data.data?.last_scan ? relTime(data.data.last_scan) : 'never'}</span>
        {canWrite && (
          <Button onClick={scan} busy={scanning} disabled={!agent.online}>
            <IconRefresh /> Scan now
          </Button>
        )}
        {canWrite && isWindows && (
          <Button onClick={() => setRepairing(true)} disabled={!agent.online || lastRepair?.status === 'running'} title="Repair the Windows Update servicing stack on this device">
            Repair Windows servicing
          </Button>
        )}
      </div>
      {canWrite && (
        <div className="toolbar">
          <span className="muted small">{sel.length} selected</span>
          <Button size="sm" disabled={!sel.length} onClick={() => setSel('approved')}>
            Approve
          </Button>
          <Button size="sm" disabled={!sel.length} onClick={() => setSel('ignored')}>
            Ignore
          </Button>
          <Button size="sm" disabled={!sel.length} onClick={() => setSel('available')}>
            Reset to available
          </Button>
          <Button size="sm" variant="primary" disabled={!sel.length || !agent.online} onClick={() => install(false)}>
            Install selected
          </Button>
          <Button size="sm" disabled={!agent.online || !patches.some((p) => p.status === 'available' || p.status === 'approved')} onClick={() => install(true)}>
            Install all
          </Button>
          <Switch checked={reboot} onChange={setReboot} label="Reboot if required" />
        </div>
      )}
      {data.error && <ErrorBox error={data.error} onRetry={data.reload} />}
      <DataTable
        columns={columns}
        rows={data.data ? rows : undefined}
        loading={data.loading}
        rowKey={patchKey}
        selectable={canWrite}
        selected={selected}
        onSelect={setSelected}
        defaultSort={{ key: 'sev', dir: 'asc' }}
        compact
        csvName="device-patches"
        emptyTitle={patches.length ? 'No patches in this view' : 'No patch data yet'}
        emptyBody={!patches.length ? 'Run a scan to see available updates.' : undefined}
      />
      {lastRepair && <LastRepair rec={lastRepair} />}
      {repairing && <RepairDialog agentId={agent.id} onClose={() => setRepairing(false)} onStarted={() => void servicing.reload()} />}
    </>
  );
}
