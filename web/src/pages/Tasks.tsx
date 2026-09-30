import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, ApiError } from '../api/client';
import type { Run, Script, Task, TaskKind, Targets } from '../api/types';
import { CronEditor } from '../components/CronEditor';
import { DataTable, type Column } from '../components/DataTable';
import { IconPlus, IconRuns } from '../components/Icons';
import { Modal, useConfirm } from '../components/Modal';
import { EMPTY_TARGETS, TargetPicker, targetsSummary } from '../components/TargetPicker';
import { Button, Chip, ErrorBox, Field, RunStatusChip, Switch, TagInput } from '../components/ui';
import { useAsync } from '../hooks/useAsync';
import { useLiveReload } from '../hooks/useEvents';
import { describeCron } from '../lib/cron';
import { relTime } from '../lib/format';
import { useAuth } from '../state/auth';
import { errMsg, useToast } from '../state/toast';

const KINDS: { id: TaskKind; label: string; help: string }[] = [
  { id: 'script', label: 'Run script', help: 'Runs a library script on every target.' },
  { id: 'patch_scan', label: 'Patch scan', help: 'Refreshes the available-updates list.' },
  { id: 'patch_install', label: 'Install approved patches', help: 'Installs every patch you have approved on each target.' },
  { id: 'reboot', label: 'Reboot', help: 'Reboots the targets after the delay.' },
  { id: 'inventory', label: 'Refresh inventory', help: 'Asks each target for a fresh hardware/software inventory.' },
];

const blank = (): Task => ({
  id: 0,
  name: '',
  description: '',
  kind: 'script',
  script_id: null,
  args: [],
  targets: EMPTY_TARGETS,
  schedule: '',
  enabled: true,
  timeout_sec: 300,
  options: {},
  last_run: 0,
  next_run: 0,
  created_at: 0,
  updated_at: 0,
});

export function Tasks() {
  const { canWrite } = useAuth();
  const toast = useToast();
  const confirm = useConfirm();
  const tasks = useAsync(() => api.tasks(), []);
  const scripts = useAsync(() => api.scripts(), []);
  const agents = useAsync(() => api.agents(), []);
  const groups = useAsync(() => api.groups(), []);
  // A schedule that has been failing for a week looked exactly like a healthy
  // one: the table showed when it last ran, never how it went. Runs carry the
  // task they came from, so the outcome of the last batch is derived here.
  const runs = useAsync(() => api.runs('', 500), []);
  useLiveReload(['run'], runs.reload, { debounceMs: 1500 });
  const [editing, setEditing] = useState<Task | null>(null);

  const results = useMemo(() => byTask(runs.data ?? []), [runs.data]);

  const runNow = async (t: Task) => {
    try {
      const r = await api.runTask(t.id);
      toast.success(`Task started on ${r.devices} device(s)`);
      void tasks.reload();
    } catch (err) {
      toast.error('Run failed', errMsg(err));
    }
  };
  const toggle = async (t: Task, enabled: boolean) => {
    try {
      await api.updateTask(t.id, { ...t, enabled });
      void tasks.reload();
    } catch (err) {
      toast.error('Update failed', errMsg(err));
    }
  };
  const remove = async (t: Task) => {
    if (!(await confirm({ title: 'Delete task', message: `Delete "${t.name}"?`, danger: true, confirmLabel: 'Delete' }))) return;
    try {
      await api.deleteTask(t.id);
      void tasks.reload();
    } catch (err) {
      toast.error('Delete failed', errMsg(err));
    }
  };

  const columns: Column<Task>[] = [
    {
      key: 'name',
      header: 'Name',
      sort: (t) => t.name,
      render: (t) => (
        <div>
          <b>{t.name}</b>
          {t.description && <div className="muted small">{t.description}</div>}
        </div>
      ),
    },
    {
      key: 'kind',
      header: 'Kind',
      sort: (t) => t.kind,
      render: (t) => (
        <span>
          <Chip outline>{KINDS.find((k) => k.id === t.kind)?.label ?? t.kind}</Chip>
          {t.kind === 'script' && <span className="muted small"> {scripts.data?.find((s) => s.id === t.script_id)?.name ?? (t.script_id ? `#${t.script_id}` : 'missing script')}</span>}
        </span>
      ),
    },
    {
      key: 'schedule',
      header: 'Schedule',
      sort: (t) => t.next_run || Number.MAX_SAFE_INTEGER,
      render: (t) => (
        <div>
          <div>{describeCron(t.schedule)}</div>
          {t.enabled && t.schedule && <div className="muted small">next {t.next_run ? relTime(t.next_run) : 'pending'}</div>}
        </div>
      ),
    },
    { key: 'targets', header: 'Targets', render: (t) => <span className="muted">{targetsSummary(t.targets, agents.data, groups.data)}</span> },
    { key: 'enabled', header: 'Enabled', sort: (t) => (t.enabled ? 0 : 1), render: (t) => <Switch checked={t.enabled} disabled={!canWrite} ariaLabel={`Enable task ${t.name}`} onChange={(v) => toggle(t, v)} /> },
    { key: 'last', header: 'Last run', sort: (t) => t.last_run, render: (t) => <span className="muted">{relTime(t.last_run)}</span> },
    {
      key: 'result',
      header: 'Last result',
      sort: (t) => results.get(t.id)?.last?.status ?? '',
      render: (t) => {
        const r = results.get(t.id);
        if (!r?.last) return <span className="faint">{runs.loading ? '' : '—'}</span>;
        return (
          <span className="row" style={{ gap: 6, flexWrap: 'nowrap' }}>
            <RunStatusChip status={r.last.status} />
            {r.failed > 0 && (
              <Link to={`/runs?task=${t.id}&status=failed`} className="small" style={{ color: 'var(--danger)' }} onClick={(e) => e.stopPropagation()} title="Runs of this task that failed">
                {r.failed} failed
              </Link>
            )}
            {r.failed === 0 && r.batch > 1 && <span className="muted small">{r.batch} devices</span>}
          </span>
        );
      },
    },
    {
      key: 'actions',
      header: '',
      render: (t) =>
        canWrite ? (
          <div className="cell-actions">
            <Button size="xs" onClick={() => runNow(t)}>
              <IconRuns /> Run now
            </Button>
            <Button size="xs" onClick={() => setEditing(t)}>
              Edit
            </Button>
            <Button size="xs" variant="danger" onClick={() => remove(t)}>
              Delete
            </Button>
          </div>
        ) : null,
    },
  ];

  return (
    <>
      <div className="page-head">
        <h1>Scheduled tasks</h1>
        {canWrite && (
          <Button variant="primary" onClick={() => setEditing(blank())}>
            <IconPlus /> New task
          </Button>
        )}
      </div>
      {tasks.error && <ErrorBox error={tasks.error} onRetry={tasks.reload} />}
      <DataTable columns={columns} rows={tasks.data} loading={tasks.loading} rowKey={(t) => String(t.id)} onRowClick={canWrite ? (t) => setEditing(t) : undefined} defaultSort={{ key: 'name', dir: 'asc' }} emptyTitle="No tasks" emptyBody="Schedule scripts, patch scans, installs, reboots or inventory refreshes." />
      {editing && (
        <TaskEditor
          task={editing}
          scripts={scripts.data ?? []}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            void tasks.reload();
          }}
        />
      )}
    </>
  );
}

function TaskEditor({ task, scripts, onClose, onSaved }: { task: Task; scripts: Script[]; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const agents = useAsync(() => api.agents(), []);
  const groups = useAsync(() => api.groups(), []);
  const [form, setForm] = useState<Task>(task);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cronError, setCronError] = useState<string | null>(null);
  const isNew = task.id === 0;
  const script = scripts.find((s) => s.id === form.script_id);
  const upd = (patch: Partial<Task>) => setForm((f) => ({ ...f, ...patch }));
  const setOpt = (patch: Partial<Task['options']>) => upd({ options: { ...form.options, ...patch } });

  useEffect(() => {
    // args line up with the script's params; resize when the script changes
    if (form.kind === 'script' && script) {
      const args = script.params.map((p, i) => form.args[i] ?? p.default ?? '');
      if (args.length !== form.args.length) upd({ args });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [script?.id, form.kind]);

  const save = async () => {
    setError(null);
    setCronError(null);
    if (!form.name.trim()) return setError('Name is required.');
    if (form.kind === 'script' && !form.script_id) return setError('Choose a script.');
    setBusy(true);
    try {
      const payload: Partial<Task> = { ...form, name: form.name.trim(), targets: normTargets(form.targets) };
      if (isNew) await api.createTask(payload);
      else await api.updateTask(form.id, payload);
      toast.success(isNew ? 'Task created' : 'Task saved');
      onSaved();
    } catch (err) {
      const msg = errMsg(err);
      if (err instanceof ApiError && msg.startsWith('schedule:')) setCronError(msg.slice(9).trim());
      else setError(msg);
    } finally {
      setBusy(false);
    }
  };

  const handleTargetsChange = (newTargets: Targets) => {
    let scriptId = form.script_id;
    let args = form.args;
    if (newTargets.os !== form.targets.os && scriptId) {
      const cur = scripts.find((s) => s.id === scriptId);
      if (cur && newTargets.os && cur.os_filter && cur.os_filter !== newTargets.os) {
        scriptId = null;
        args = [];
      }
    }
    upd({
      targets: newTargets,
      script_id: scriptId,
      args,
    });
  };

  const handleOSChange = (newOS?: string) => {
    handleTargetsChange({ ...form.targets, os: newOS });
  };

  return (
    <Modal
      title={isNew ? 'New task' : `Edit task: ${task.name}`}
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
      <Field label="Target Operating System" hint="Filter scripts and endpoints to this operating system.">
        <div className="row" style={{ gap: 16 }}>
          <label className="row" style={{ gap: 6, cursor: 'pointer', fontWeight: !form.targets.os ? 600 : 400 }}>
            <input type="radio" name="task-os" checked={!form.targets.os} onChange={() => handleOSChange(undefined)} /> Cross-Platform / Any
          </label>
          <label className="row" style={{ gap: 6, cursor: 'pointer', fontWeight: form.targets.os === 'windows' ? 600 : 400 }}>
            <input type="radio" name="task-os" checked={form.targets.os === 'windows'} onChange={() => handleOSChange('windows')} /> Windows
          </label>
          <label className="row" style={{ gap: 6, cursor: 'pointer', fontWeight: form.targets.os === 'linux' ? 600 : 400 }}>
            <input type="radio" name="task-os" checked={form.targets.os === 'linux'} onChange={() => handleOSChange('linux')} /> Linux
          </label>
        </div>
      </Field>
      <div className="form-row">
        <Field label="Name">
          <input value={form.name} autoFocus onChange={(e) => upd({ name: e.target.value })} />
        </Field>
        <Field label="Kind">
          <select value={form.kind} onChange={(e) => upd({ kind: e.target.value as TaskKind })}>
            {KINDS.map((k) => (
              <option key={k.id} value={k.id}>
                {k.label}
              </option>
            ))}
          </select>
        </Field>
      </div>
      <Field label="Description">
        <input value={form.description} onChange={(e) => upd({ description: e.target.value })} />
      </Field>
      <p className="muted small">{KINDS.find((k) => k.id === form.kind)?.help}</p>

      {form.kind === 'script' && (
        <>
          <Field label="Script" hint={form.targets.os ? `Filtered to ${form.targets.os}-compatible scripts` : undefined}>
            <select value={form.script_id ?? ''} onChange={(e) => upd({ script_id: e.target.value ? +e.target.value : null })}>
              <option value="">— choose —</option>
              {scripts
                .filter((s) => !form.targets.os || !s.os_filter || s.os_filter === form.targets.os)
                .map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name} ({s.language}
                    {s.os_filter ? `, ${s.os_filter}` : ''})
                  </option>
                ))}
            </select>
          </Field>
          {script && script.params.length > 0 && (
            <div className="form-row">
              {script.params.map((p, i) => (
                <Field key={p.name} label={`${p.name}${p.required ? ' *' : ''}`} hint={p.description}>
                  <input value={form.args[i] ?? ''} placeholder={p.default} onChange={(e) => upd({ args: form.args.map((a, j) => (j === i ? e.target.value : a)) })} />
                </Field>
              ))}
            </div>
          )}
          {script && script.params.length === 0 && (
            <Field label="Arguments" hint="Positional arguments passed to the script.">
              <TagInput value={form.args} onChange={(args) => upd({ args })} placeholder="add argument…" />
            </Field>
          )}
          <Field label="Timeout (seconds)" hint="Per device; 0 means the server default of 300 s.">
            <input type="number" min={0} value={form.timeout_sec} onChange={(e) => upd({ timeout_sec: +e.target.value || 0 })} style={{ maxWidth: 160 }} />
          </Field>
        </>
      )}
      {form.kind === 'patch_install' && (
        <Field label="Options">
          <Switch checked={!!form.options.reboot_if_required} onChange={(v) => setOpt({ reboot_if_required: v })} label="Reboot if required after installing" />
        </Field>
      )}
      {form.kind === 'reboot' && (
        <Field label="Reboot delay (seconds)" hint="Logged-in users get this long to save their work.">
          <input type="number" min={0} max={86400} value={form.options.delay_sec ?? 60} onChange={(e) => setOpt({ delay_sec: +e.target.value || 0 })} style={{ maxWidth: 160 }} />
        </Field>
      )}

      <Field label="Targets">
        <TargetPicker value={form.targets} onChange={handleTargetsChange} agents={agents.data ?? []} groups={groups.data ?? []} />
      </Field>
      <Field label="Schedule">
        <CronEditor value={form.schedule} onChange={(schedule) => upd({ schedule })} serverError={cronError} />
      </Field>
      <Field label="">
        <Switch checked={form.enabled} onChange={(enabled) => upd({ enabled })} label="Enabled" />
      </Field>
    </Modal>
  );
}

interface TaskResult {
  /** most recent run of the task */
  last?: Run;
  /** failed/timed-out runs in the most recent batch */
  failed: number;
  /** runs in the most recent batch (one per device) */
  batch: number;
}

/**
 * Outcome per task from the recent-runs window. A scheduled task fans out to
 * one run per device within a second or two, so "the last batch" is every run
 * of that task started within a minute of its newest one.
 */
function byTask(runs: Run[]): Map<number, TaskResult> {
  const newest = new Map<number, number>();
  for (const r of runs) {
    if (!r.task_id) continue;
    newest.set(r.task_id, Math.max(newest.get(r.task_id) ?? 0, r.started_at));
  }
  const out = new Map<number, TaskResult>();
  for (const r of runs) {
    if (!r.task_id) continue;
    if (r.started_at < (newest.get(r.task_id) ?? 0) - 60) continue;
    const e = out.get(r.task_id) ?? { failed: 0, batch: 0 };
    if (!e.last || r.started_at > e.last.started_at) e.last = r;
    if (r.status === 'failed' || r.status === 'timeout') e.failed++;
    e.batch++;
    out.set(r.task_id, e);
  }
  return out;
}

/** Drop empty arrays so the stored JSON stays tidy. */
export function normTargets(t: Targets): Targets {
  const out: Targets = { all: t.all };
  if (!t.all) {
    if (t.agents?.length) out.agents = t.agents;
    if (t.groups?.length) out.groups = t.groups;
    if (t.tags?.length) out.tags = t.tags;
    if (t.organizations?.length) out.organizations = t.organizations;
    if (t.sites?.length) out.sites = t.sites;
  }
  if (t.os) out.os = t.os;
  return out;
}
