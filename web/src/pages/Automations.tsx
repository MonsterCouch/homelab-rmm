import { useState } from 'react';
import { api } from '../api/client';
import type { Automation, AutomationAction, AutomationTrigger } from '../api/types';
import { DataTable, type Column } from '../components/DataTable';
import { IconPlus } from '../components/Icons';
import { Modal, useConfirm } from '../components/Modal';
import { EMPTY_TARGETS, TargetPicker, targetsSummary } from '../components/TargetPicker';
import { Button, Chip, ErrorBox, Field, Switch, TagInput } from '../components/ui';
import { useAsync } from '../hooks/useAsync';
import { titleCase } from '../lib/format';
import { useAuth } from '../state/auth';
import { errMsg, useToast } from '../state/toast';
import { normTargets } from './Tasks';

const TRIGGERS: { id: AutomationTrigger; label: string }[] = [
  { id: 'agent_online', label: 'Device comes online' },
  { id: 'agent_offline', label: 'Device goes offline' },
  { id: 'alert_opened', label: 'Alert opened' },
  { id: 'alert_resolved', label: 'Alert resolved' },
  { id: 'enrolled', label: 'Device enrolled' },
  { id: 'reboot_required', label: 'Reboot required' },
  { id: 'patch_installed', label: 'Patch installed' },
];
const ACTIONS: { id: AutomationAction; label: string }[] = [
  { id: 'run_script', label: 'Run a script' },
  { id: 'email', label: 'Send email' },
  { id: 'webhook', label: 'Call a webhook' },
];

const blank = (): Automation => ({ id: 0, name: '', trigger: 'alert_opened', filter: { targets: EMPTY_TARGETS }, action: 'email', action_params: {}, enabled: true, created_at: 0 });

export function Automations() {
  const { canWrite } = useAuth();
  const toast = useToast();
  const confirm = useConfirm();
  const autos = useAsync(() => api.automations(), []);
  const scripts = useAsync(() => api.scripts(), []);
  const rules = useAsync(() => api.alertRules(), []);
  const agents = useAsync(() => api.agents(), []);
  const groups = useAsync(() => api.groups(), []);
  const [editing, setEditing] = useState<Automation | null>(null);

  const toggle = async (a: Automation, enabled: boolean) => {
    try {
      await api.updateAutomation(a.id, { ...a, enabled });
      void autos.reload();
    } catch (err) {
      toast.error('Update failed', errMsg(err));
    }
  };
  const remove = async (a: Automation) => {
    if (!(await confirm({ title: 'Delete automation', message: `Delete "${a.name}"?`, danger: true, confirmLabel: 'Delete' }))) return;
    try {
      await api.deleteAutomation(a.id);
      void autos.reload();
    } catch (err) {
      toast.error('Delete failed', errMsg(err));
    }
  };

  const describeAction = (a: Automation) => {
    const p = a.action_params ?? {};
    switch (a.action) {
      case 'run_script':
        return `Run ${scripts.data?.find((s) => s.id === p.script_id)?.name ?? (p.script_id ? `script #${p.script_id}` : '(no script)')}`;
      case 'email':
        return `Email${p.subject ? `: ${p.subject}` : ''}`;
      case 'webhook':
        return `POST ${p.url ?? '(no url)'}`;
    }
  };
  const describeFilter = (a: Automation) => {
    const f = a.filter ?? {};
    const parts: string[] = [];
    if (f.targets && !f.targets.all) parts.push(targetsSummary(f.targets, agents.data, groups.data));
    if (f.severity) parts.push(`severity ${f.severity}`);
    if (f.rule_ids?.length) parts.push(`rules: ${f.rule_ids.map((id) => rules.data?.find((r) => r.id === id)?.name ?? `#${id}`).join(', ')}`);
    return parts.length ? parts.join(' · ') : 'any';
  };

  const columns: Column<Automation>[] = [
    { key: 'name', header: 'Name', sort: (a) => a.name, render: (a) => <b>{a.name}</b> },
    { key: 'trigger', header: 'Trigger', sort: (a) => a.trigger, render: (a) => <Chip outline>{TRIGGERS.find((t) => t.id === a.trigger)?.label ?? titleCase(a.trigger)}</Chip> },
    { key: 'filter', header: 'Filter', render: (a) => <span className="muted">{describeFilter(a)}</span> },
    { key: 'action', header: 'Action', sort: (a) => a.action, render: (a) => <span className="truncate" style={{ maxWidth: 320, display: 'inline-block' }}>{describeAction(a)}</span> },
    { key: 'enabled', header: 'Enabled', sort: (a) => (a.enabled ? 0 : 1), render: (a) => <Switch checked={a.enabled} disabled={!canWrite} ariaLabel={`Enable automation ${a.name}`} onChange={(v) => toggle(a, v)} /> },
    {
      key: 'actions',
      header: '',
      render: (a) =>
        canWrite ? (
          <div className="cell-actions">
            <Button size="xs" onClick={() => setEditing(a)}>
              Edit
            </Button>
            <Button size="xs" variant="danger" onClick={() => remove(a)}>
              Delete
            </Button>
          </div>
        ) : null,
    },
  ];

  return (
    <>
      <div className="page-head">
        <h1>Automations</h1>
        {canWrite && (
          <Button variant="primary" onClick={() => setEditing(blank())}>
            <IconPlus /> New automation
          </Button>
        )}
      </div>
      {autos.error && <ErrorBox error={autos.error} onRetry={autos.reload} />}
      <DataTable columns={columns} rows={autos.data} loading={autos.loading} rowKey={(a) => String(a.id)} onRowClick={canWrite ? (a) => setEditing(a) : undefined} defaultSort={{ key: 'name', dir: 'asc' }} emptyTitle="No automations" emptyBody="React to events: run a script when a device comes online, email on critical alerts, or call a webhook." />
      {editing && (
        <AutomationEditor
          automation={editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            void autos.reload();
          }}
        />
      )}
    </>
  );
}

function AutomationEditor({ automation, onClose, onSaved }: { automation: Automation; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const scripts = useAsync(() => api.scripts(), []);
  const rules = useAsync(() => api.alertRules(), []);
  const agents = useAsync(() => api.agents(), []);
  const groups = useAsync(() => api.groups(), []);
  const [form, setForm] = useState<Automation>({ ...automation, filter: { targets: EMPTY_TARGETS, ...(automation.filter ?? {}) }, action_params: automation.action_params ?? {} });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isNew = automation.id === 0;
  const upd = (patch: Partial<Automation>) => setForm((f) => ({ ...f, ...patch }));
  const setFilter = (patch: Partial<Automation['filter']>) => upd({ filter: { ...form.filter, ...patch } });
  const setParams = (patch: Partial<Automation['action_params']>) => upd({ action_params: { ...form.action_params, ...patch } });
  const alertTrigger = form.trigger === 'alert_opened' || form.trigger === 'alert_resolved';
  const script = scripts.data?.find((s) => s.id === form.action_params.script_id);

  const save = async () => {
    setError(null);
    if (!form.name.trim()) return setError('Name is required.');
    if (form.action === 'run_script' && !form.action_params.script_id) return setError('Choose a script to run.');
    if (form.action === 'webhook' && !/^https?:\/\//.test(form.action_params.url ?? '')) return setError('Webhook URL must start with http:// or https://');
    setBusy(true);
    try {
      const filter = { ...form.filter, targets: form.filter.targets ? normTargets(form.filter.targets) : undefined };
      if (!alertTrigger) {
        delete filter.rule_ids;
        delete filter.severity;
      }
      const params: Automation['action_params'] =
        form.action === 'run_script'
          ? { script_id: form.action_params.script_id, args: form.action_params.args ?? [] }
          : form.action === 'email'
            ? { subject: form.action_params.subject ?? '' }
            : { url: form.action_params.url ?? '' };
      const payload = { ...form, name: form.name.trim(), filter, action_params: params };
      if (isNew) await api.createAutomation(payload);
      else await api.updateAutomation(form.id, payload);
      toast.success(isNew ? 'Automation created' : 'Automation saved');
      onSaved();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title={isNew ? 'New automation' : `Edit: ${automation.name}`}
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
      <div className="form-row">
        <Field label="When">
          <select value={form.trigger} onChange={(e) => upd({ trigger: e.target.value as AutomationTrigger })}>
            {TRIGGERS.map((t) => (
              <option key={t.id} value={t.id}>
                {t.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Then">
          <select value={form.action} onChange={(e) => upd({ action: e.target.value as AutomationAction })}>
            {ACTIONS.map((a) => (
              <option key={a.id} value={a.id}>
                {a.label}
              </option>
            ))}
          </select>
        </Field>
      </div>

      {form.action === 'run_script' && (
        <>
          <Field label="Script" hint="Runs on the device the event is about.">
            <select value={form.action_params.script_id ?? ''} onChange={(e) => setParams({ script_id: e.target.value ? +e.target.value : undefined })}>
              <option value="">— choose —</option>
              {(scripts.data ?? []).map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({s.language})
                </option>
              ))}
            </select>
          </Field>
          <Field label="Arguments" hint={script?.params.length ? `Expected: ${script.params.map((p) => p.name).join(', ')}` : 'Positional arguments.'}>
            <TagInput value={form.action_params.args ?? []} onChange={(args) => setParams({ args })} placeholder="add argument…" />
          </Field>
        </>
      )}
      {form.action === 'email' && (
        <Field label="Subject" hint="Sent to the SMTP recipients configured in Settings. Leave empty for the default.">
          <input value={form.action_params.subject ?? ''} placeholder="[RMM] {trigger}: {device}" onChange={(e) => setParams({ subject: e.target.value })} />
        </Field>
      )}
      {form.action === 'webhook' && (
        <Field label="URL" hint="Receives a JSON POST with automation, trigger, agent_id, agent_name, data and ts.">
          <input type="url" value={form.action_params.url ?? ''} placeholder="https://hooks.example.com/…" onChange={(e) => setParams({ url: e.target.value })} />
        </Field>
      )}

      <h3 className="mb mt">Only when…</h3>
      {alertTrigger && (
        <div className="form-row">
          <Field label="Severity">
            <select value={form.filter.severity ?? ''} onChange={(e) => setFilter({ severity: e.target.value || undefined })}>
              <option value="">Any severity</option>
              <option value="info">info</option>
              <option value="warning">warning</option>
              <option value="critical">critical</option>
            </select>
          </Field>
          <Field label="Alert rules" hint="Leave all unchecked for any rule.">
            <div className="checks card" style={{ padding: 8, maxHeight: 120, overflow: 'auto' }}>
              {(rules.data ?? []).map((r) => (
                <label key={r.id}>
                  <input
                    type="checkbox"
                    checked={form.filter.rule_ids?.includes(r.id) ?? false}
                    onChange={(e) => {
                      const cur = form.filter.rule_ids ?? [];
                      setFilter({ rule_ids: e.target.checked ? [...cur, r.id] : cur.filter((x) => x !== r.id) });
                    }}
                  />
                  {r.name}
                </label>
              ))}
              {!rules.data?.length && <span className="muted small">No alert rules defined.</span>}
            </div>
          </Field>
        </div>
      )}
      <Field label="Devices">
        <TargetPicker value={form.filter.targets ?? EMPTY_TARGETS} onChange={(targets) => setFilter({ targets })} agents={agents.data ?? []} groups={groups.data ?? []} />
      </Field>
      <Switch checked={form.enabled} onChange={(enabled) => upd({ enabled })} label="Enabled" />
    </Modal>
  );
}
