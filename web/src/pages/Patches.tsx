import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api, ApiError } from '../api/client';
import type { Patch, PatchPolicy } from '../api/types';
import { CronEditor } from '../components/CronEditor';
import { DataTable, textMatch, type Column } from '../components/DataTable';
import { IconPlus, IconRefresh } from '../components/Icons';
import { Modal, useConfirm } from '../components/Modal';
import { EMPTY_TARGETS, TargetPicker, targetsSummary } from '../components/TargetPicker';
import { Button, Chip, ErrorBox, Field, PatchStatusChip, Switch, Tabs } from '../components/ui';
import { useAsync, useDebounced } from '../hooks/useAsync';
import { useLiveReload } from '../hooks/useEvents';
import { describeCron } from '../lib/cron';
import { bytes, relTime } from '../lib/format';
import { useAuth } from '../state/auth';
import { errMsg, useToast } from '../state/toast';
import { patchKey, sevTone } from './device/DevicePatches';
import { normTargets } from './Tasks';

export function Patches() {
  const [params, setParams] = useSearchParams();
  const tab = params.get('tab') === 'policies' ? 'policies' : 'patches';
  return (
    <>
      <div className="page-head">
        <h1>Patches</h1>
      </div>
      <Tabs
        tabs={[
          { id: 'patches', label: 'Patches' },
          { id: 'policies', label: 'Policies' },
        ]}
        value={tab}
        onChange={(t) => setParams(t === 'policies' ? { tab: 'policies' } : {}, { replace: true })}
      />
      {tab === 'patches' ? <PatchList /> : <PolicyList />}
    </>
  );
}

function PatchList() {
  const { canWrite } = useAuth();
  const toast = useToast();
  const confirm = useConfirm();
  const [device, setDevice] = useState('');
  const [status, setStatus] = useState('pending');
  const [sev, setSev] = useState('');
  const [source, setSource] = useState('');
  const [q, setQ] = useState('');
  const dq = useDebounced(q);
  const patches = useAsync(() => api.patches(device, ''), [device]);
  const agents = useAsync(() => api.agents(), []);
  useLiveReload(['patches', 'hello'], patches.reload, { debounceMs: 800 });
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const all = patches.data ?? [];
  const sources = useMemo(() => Array.from(new Set(all.map((p) => p.source).filter(Boolean))).sort(), [all]);
  const sevs = useMemo(() => Array.from(new Set(all.map((p) => p.severity).filter(Boolean))).sort(), [all]);
  const rows = useMemo(
    () =>
      all.filter((p) => {
        if (status === 'pending' && !['available', 'approved', 'installing', 'failed'].includes(p.status)) return false;
        if (status !== 'pending' && status !== 'all' && p.status !== status) return false;
        if (sev && p.severity !== sev) return false;
        if (source && p.source !== source) return false;
        return textMatch(dq, p.title, p.kb, p.agent_name, p.version, ...p.categories);
      }),
    [all, status, sev, source, dq],
  );
  const sel = all.filter((p) => selected.has(patchKey(p)));

  const setSel = async (st: 'approved' | 'ignored' | 'available') => {
    if (!sel.length) return;
    try {
      await api.patchStatus(
        sel.map((p) => ({ AgentID: p.agent_id, PatchID: p.patch_id })),
        st,
      );
      toast.success(`${sel.length} patch(es) marked ${st}`);
      setSelected(new Set());
      void patches.reload();
    } catch (err) {
      toast.error('Update failed', errMsg(err));
    }
  };

  const installApproved = async () => {
    const byAgent = new Map<string, Patch[]>();
    for (const p of all) if (p.status === 'approved' && (!device || p.agent_id === device)) byAgent.set(p.agent_id, [...(byAgent.get(p.agent_id) ?? []), p]);
    if (!byAgent.size) return toast.warning('No approved patches', 'Approve some patches first.');
    const agentNames = [...byAgent.keys()].map((id) => agents.data?.find((a) => a.id === id)?.display_name ?? id);
    if (!(await confirm({ title: 'Install approved patches', message: `Install ${[...byAgent.values()].reduce((n, l) => n + l.length, 0)} approved patch(es) on ${agentNames.join(', ')}?`, confirmLabel: 'Install' }))) return;
    const res = await Promise.allSettled([...byAgent.entries()].map(([id, list]) => api.patchInstall(id, { ids: list.map((p) => p.patch_id), reboot_if_required: false })));
    const failed = res.filter((r): r is PromiseRejectedResult => r.status === 'rejected');
    if (failed.length) toast.warning(`${res.length - failed.length} started, ${failed.length} failed`, failed.map((f) => (f.reason instanceof ApiError ? f.reason.message : String(f.reason))).join('; '));
    else toast.success(`Installation started on ${res.length} device(s)`);
  };

  const columns: Column<Patch>[] = [
    { key: 'status', header: 'Status', sort: (p) => p.status, render: (p) => <PatchStatusChip status={p.status} /> },
    {
      key: 'device',
      header: 'Device',
      sort: (p) => p.agent_name ?? '',
      render: (p) => (
        <Link to={`/devices/${p.agent_id}/patches`} onClick={(e) => e.stopPropagation()}>
          {p.agent_name || p.agent_id}
        </Link>
      ),
    },
    {
      key: 'title',
      header: 'Update',
      sort: (p) => p.title,
      render: (p) => (
        <div style={{ maxWidth: 480 }}>
          <div className="truncate" title={p.title} style={{ fontWeight: 500 }}>
            {p.title}
          </div>
          <div className="muted small truncate">
            {p.categories.join(', ')}
            {p.version && ` · ${p.version}`}
            {p.error && <span style={{ color: 'var(--danger)' }}> · {p.error}</span>}
          </div>
        </div>
      ),
    },
    { key: 'kb', header: 'KB', sort: (p) => p.kb, render: (p) => <span className="mono small">{p.kb || '—'}</span> },
    { key: 'sev', header: 'Severity', sort: (p) => p.severity, render: (p) => (p.severity ? <Chip tone={sevTone(p.severity)}>{p.severity}</Chip> : <span className="faint">—</span>) },
    { key: 'size', header: 'Size', align: 'right', sort: (p) => p.size, render: (p) => (p.size ? bytes(p.size) : <span className="faint">—</span>) },
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
      <div className="toolbar">
        <select value={device} onChange={(e) => { setDevice(e.target.value); setSelected(new Set()); }} style={{ width: 200 }} aria-label="Device">
          <option value="">All devices</option>
          {(agents.data ?? []).map((a) => (
            <option key={a.id} value={a.id}>
              {a.display_name}
            </option>
          ))}
        </select>
        <select value={status} onChange={(e) => setStatus(e.target.value)} style={{ width: 130 }} aria-label="Status">
          <option value="pending">Pending</option>
          <option value="available">Available</option>
          <option value="approved">Approved</option>
          <option value="installing">Installing</option>
          <option value="failed">Failed</option>
          <option value="installed">Installed</option>
          <option value="ignored">Ignored</option>
          <option value="all">All</option>
        </select>
        <select value={sev} onChange={(e) => setSev(e.target.value)} style={{ width: 130 }} aria-label="Severity">
          <option value="">Any severity</option>
          {sevs.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select value={source} onChange={(e) => setSource(e.target.value)} style={{ width: 120 }} aria-label="Source">
          <option value="">Any source</option>
          {sources.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <input type="search" placeholder="Search…" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 200 }} aria-label="Search patches" />
        <Button onClick={() => patches.reload()} icon aria-label="Refresh">
          <IconRefresh />
        </Button>
        <span className="grow" />
        <span className="muted small">{rows.length} of {all.length}</span>
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
          <span style={{ width: 12 }} />
          <Button size="sm" variant="primary" onClick={installApproved} disabled={!all.some((p) => p.status === 'approved')}>
            Install approved{device ? ' on this device' : ' (per device)'}
          </Button>
        </div>
      )}
      {patches.error && <ErrorBox error={patches.error} onRetry={patches.reload} />}
      <DataTable columns={columns} rows={patches.data ? rows : undefined} loading={patches.loading} rowKey={patchKey} selectable={canWrite} selected={selected} onSelect={setSelected} defaultSort={{ key: 'device', dir: 'asc' }} compact csvName="patches" emptyTitle={all.length ? 'No patches in this view' : 'No patch data'} emptyBody={!all.length ? 'Run a patch scan on a device, or create a policy with a scan schedule.' : undefined} />
    </>
  );
}

const blankPolicy = (): PatchPolicy => ({ id: 0, name: '', targets: EMPTY_TARGETS, scan_schedule: '0 */6 * * *', install_schedule: '', mode: 'approved', reboot: 'never', enabled: true, repair: 'off', created_at: 0 });

function PolicyList() {
  const { can } = useAuth();
  const canEdit = can('patch_policies.edit');
  const toast = useToast();
  const confirm = useConfirm();
  const policies = useAsync(() => api.patchPolicies(), []);
  const agents = useAsync(() => api.agents(), []);
  const groups = useAsync(() => api.groups(), []);
  const [editing, setEditing] = useState<PatchPolicy | null>(null);

  const toggle = async (p: PatchPolicy, enabled: boolean) => {
    try {
      await api.updatePatchPolicy(p.id, { ...p, enabled });
      void policies.reload();
    } catch (err) {
      toast.error('Update failed', errMsg(err));
    }
  };
  const remove = async (p: PatchPolicy) => {
    if (!(await confirm({ title: 'Delete policy', message: `Delete "${p.name}"?`, danger: true, confirmLabel: 'Delete' }))) return;
    try {
      await api.deletePatchPolicy(p.id);
      void policies.reload();
    } catch (err) {
      toast.error('Delete failed', errMsg(err));
    }
  };

  const columns: Column<PatchPolicy>[] = [
    { key: 'name', header: 'Name', sort: (p) => p.name, render: (p) => <b>{p.name}</b> },
    { key: 'targets', header: 'Targets', render: (p) => <span className="muted">{targetsSummary(p.targets, agents.data, groups.data)}</span> },
    { key: 'scan', header: 'Scan', render: (p) => describeCron(p.scan_schedule) },
    { key: 'install', header: 'Install', render: (p) => (p.install_schedule ? describeCron(p.install_schedule) : <span className="muted">manual approval only</span>) },
    { key: 'mode', header: 'Mode', sort: (p) => p.mode, render: (p) => <Chip outline>{p.mode}</Chip> },
    { key: 'reboot', header: 'Reboot', sort: (p) => p.reboot, render: (p) => <span className="muted">{p.reboot.replace('_', ' ')}</span> },
    { key: 'enabled', header: 'Enabled', sort: (p) => (p.enabled ? 0 : 1), render: (p) => <Switch checked={p.enabled} disabled={!canEdit} ariaLabel={`Enable policy ${p.name}`} onChange={(v) => toggle(p, v)} /> },
    {
      key: 'actions',
      header: '',
      render: (p) =>
        canEdit ? (
          <div className="cell-actions">
            <Button size="xs" onClick={() => setEditing(p)}>
              Edit
            </Button>
            <Button size="xs" variant="danger" onClick={() => remove(p)}>
              Delete
            </Button>
          </div>
        ) : null,
    },
  ];

  return (
    <>
      <div className="toolbar">
        <span className="muted small">A policy scans its targets on a schedule and, optionally, installs on another schedule according to its mode.</span>
        <span className="grow" />
        {canEdit && (
          <Button variant="primary" onClick={() => setEditing(blankPolicy())}>
            <IconPlus /> New policy
          </Button>
        )}
      </div>
      {policies.error && <ErrorBox error={policies.error} onRetry={policies.reload} />}
      <DataTable columns={columns} rows={policies.data} loading={policies.loading} rowKey={(p) => String(p.id)} onRowClick={canEdit ? (p) => setEditing(p) : undefined} defaultSort={{ key: 'name', dir: 'asc' }} emptyTitle="No patch policies" />
      {editing && (
        <PolicyEditor
          policy={editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            void policies.reload();
          }}
        />
      )}
    </>
  );
}

function PolicyEditor({ policy, onClose, onSaved }: { policy: PatchPolicy; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const agents = useAsync(() => api.agents(), []);
  const groups = useAsync(() => api.groups(), []);
  const [form, setForm] = useState<PatchPolicy>(policy);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cronError, setCronError] = useState<string | null>(null);
  const isNew = policy.id === 0;
  const upd = (patch: Partial<PatchPolicy>) => setForm((f) => ({ ...f, ...patch }));

  const save = async () => {
    setError(null);
    setCronError(null);
    if (!form.name.trim()) return setError('Name is required.');
    if (!form.scan_schedule.trim()) return setError('A scan schedule is required.');
    setBusy(true);
    try {
      const payload = { ...form, name: form.name.trim(), targets: normTargets(form.targets) };
      if (isNew) await api.createPatchPolicy(payload);
      else await api.updatePatchPolicy(form.id, payload);
      toast.success(isNew ? 'Policy created' : 'Policy saved');
      onSaved();
    } catch (err) {
      const msg = errMsg(err);
      if (msg.startsWith('schedule:')) setCronError(msg.slice(9).trim());
      else setError(msg);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title={isNew ? 'New patch policy' : `Edit policy: ${policy.name}`}
      onClose={onClose}
      size="lg"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={save} busy={busy}>
            {isNew ? 'Create' : 'Save'}
          </Button>
        </>
      }
    >
      {error && <div className="form-error" role="alert">{error}</div>}
      <Field label="Name">
        <input value={form.name} autoFocus onChange={(e) => upd({ name: e.target.value })} />
      </Field>
      <Field label="Targets">
        <TargetPicker value={form.targets} onChange={(targets) => upd({ targets })} agents={agents.data ?? []} groups={groups.data ?? []} />
      </Field>
      <Field label="Scan schedule" error={cronError}>
        <CronEditor value={form.scan_schedule} onChange={(scan_schedule) => upd({ scan_schedule })} allowManual={false} serverError={cronError} />
      </Field>
      <Field label="Install schedule" hint="Leave on manual to only install what you approve by hand.">
        <CronEditor value={form.install_schedule} onChange={(install_schedule) => upd({ install_schedule })} />
      </Field>
      <div className="form-row">
        <Field label="Install mode" hint={form.mode === 'approved' ? 'Only patches you approved.' : form.mode === 'security' ? 'Approve and install security/critical updates automatically.' : 'Approve and install everything available.'}>
          <select value={form.mode} onChange={(e) => upd({ mode: e.target.value })}>
            <option value="approved">Approved only</option>
            <option value="security">Security updates</option>
            <option value="all">All updates</option>
          </select>
        </Field>
        <Field label="Reboot after install">
          <select value={form.reboot} onChange={(e) => upd({ reboot: e.target.value })}>
            <option value="never">Never</option>
            <option value="if_required">If required</option>
            <option value="always">Always (60s delay)</option>
          </select>
        </Field>
      </div>
      <Field label="Repair Windows servicing" hint="With Automatic, a scan or install that fails with a known Windows Update servicing error starts one repair on that device (DISM restore, component reset, rescan), at most once a day. Repairs run under this policy's standing approval.">
        <select value={form.repair ?? 'off'} onChange={(e) => upd({ repair: e.target.value })}>
          <option value="off">Off</option>
          <option value="auto">Automatic</option>
        </select>
      </Field>
      <Switch checked={form.enabled} onChange={(enabled) => upd({ enabled })} label="Enabled" />
    </Modal>
  );
}
