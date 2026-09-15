import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import type { Alert, AlertRule, RuleKind, Severity } from '../api/types';
import { DataTable, textMatch, type Column } from '../components/DataTable';
import { IconPlus } from '../components/Icons';
import { Modal, useConfirm } from '../components/Modal';
import { EMPTY_TARGETS, TargetPicker, targetsSummary } from '../components/TargetPicker';
import { AlertStatusChip, Button, Chip, ErrorBox, Field, SeverityChip, Switch, Tabs } from '../components/ui';
import { useAsync, useDebounced } from '../hooks/useAsync';
import { useLiveReload } from '../hooks/useEvents';
import { relTime, titleCase } from '../lib/format';
import { useAuth } from '../state/auth';
import { errMsg, useToast } from '../state/toast';
import { normTargets } from './Tasks';

type Status = 'open' | 'acked' | 'resolved' | 'all';

export function Alerts() {
  const [params, setParams] = useSearchParams();
  const tab = params.get('tab') === 'rules' ? 'rules' : 'alerts';
  return (
    <>
      <div className="page-head">
        <h1>Alerts</h1>
      </div>
      <Tabs
        tabs={[
          { id: 'alerts', label: 'Alerts' },
          { id: 'rules', label: 'Alert rules' },
        ]}
        value={tab}
        onChange={(t) => setParams(t === 'rules' ? { tab: 'rules' } : {}, { replace: true })}
      />
      {tab === 'alerts' ? <AlertList /> : <RuleList />}
    </>
  );
}

function AlertList() {
  const { canWrite } = useAuth();
  const toast = useToast();
  const confirm = useConfirm();
  const [status, setStatus] = useState<Status>('open');
  const alerts = useAsync(() => api.alerts(status, '', 500), [status]);
  useLiveReload(['alert', 'hello'], alerts.reload, { debounceMs: 600 });
  // "Disk" and "Cpu" are kinds, not names: with two CPU rules at different
  // thresholds the list could not say which one tripped. Rule names come from
  // the rules endpoint and are joined here (the alert keeps its rule_id).
  const rules = useAsync(() => api.alertRules(), []);
  const ruleName = useMemo(() => new Map((rules.data ?? []).map((r) => [r.id, r.name])), [rules.data]);
  const [q, setQ] = useState('');
  const dq = useDebounced(q);
  const [sev, setSev] = useState('');
  const rows = useMemo(
    () => (alerts.data ?? []).filter((a) => (!sev || a.severity === sev) && textMatch(dq, a.title, a.message, a.agent_name, a.rule_kind, a.rule_id ? ruleName.get(a.rule_id) : '')),
    [alerts.data, dq, sev, ruleName],
  );

  const act = async (fn: () => Promise<unknown>, label: string) => {
    try {
      await fn();
      toast.success(label);
      void alerts.reload();
    } catch (err) {
      toast.error('Failed', errMsg(err));
    }
  };
  const resolveAll = async () => {
    if (!(await confirm({ title: 'Resolve all alerts', message: 'Mark every open and acknowledged alert as resolved?', confirmLabel: 'Resolve all' }))) return;
    await act(() => api.resolveAllAlerts(), 'All alerts resolved');
  };

  const columns: Column<Alert>[] = [
    {
      key: 'sev',
      header: 'Severity',
      sort: (a) => ({ critical: 0, warning: 1, info: 2 } as Record<string, number>)[a.severity] ?? 3,
      csv: (a) => a.severity,
      render: (a) => <SeverityChip severity={a.severity} />,
    },
    { key: 'status', header: 'Status', sort: (a) => a.status, render: (a) => <AlertStatusChip status={a.status} /> },
    {
      key: 'title',
      header: 'Alert',
      sort: (a) => a.title,
      render: (a) => (
        <div style={{ maxWidth: 520 }}>
          <div style={{ fontWeight: 500 }}>{a.title}</div>
          <div className="muted small truncate" title={a.message}>
            {a.message}
          </div>
        </div>
      ),
    },
    {
      key: 'device',
      header: 'Device',
      sort: (a) => a.agent_name,
      render: (a) => (a.agent_id ? <Link to={`/devices/${a.agent_id}`} onClick={(e) => e.stopPropagation()}>{a.agent_name || a.agent_id}</Link> : <span className="muted">server</span>),
    },
    {
      key: 'kind',
      header: 'Rule',
      sort: (a) => (a.rule_id ? ruleName.get(a.rule_id) : undefined) ?? a.rule_kind,
      csv: (a) => {
        const n = a.rule_id ? ruleName.get(a.rule_id) : undefined;
        return n ? `${n} (${a.rule_kind})` : titleCase(a.rule_kind || '');
      },
      render: (a) => {
        // A rule that has since been deleted leaves the kind as the only label.
        const n = a.rule_id ? ruleName.get(a.rule_id) : undefined;
        return n ? (
          <span>
            {n} <span className="muted small">{titleCase(a.rule_kind)}</span>
          </span>
        ) : (
          <span className="muted">{titleCase(a.rule_kind || '—')}</span>
        );
      },
    },
    {
      key: 'opened',
      header: 'Opened',
      sort: (a) => a.opened_at,
      csv: (a) => (a.opened_at ? new Date(a.opened_at * 1000).toISOString() : ''),
      render: (a) => <span className="muted">{relTime(a.opened_at)}</span>,
    },
    {
      key: 'ack',
      header: 'Acked / resolved',
      sort: (a) => a.resolved_at || a.acked_at,
      csv: (a) => (a.status === 'resolved' ? `resolved ${new Date(a.resolved_at * 1000).toISOString()}` : a.status === 'acked' ? `${a.acked_by} ${new Date(a.acked_at * 1000).toISOString()}` : ''),
      render: (a) => <span className="muted small">{a.status === 'resolved' ? `resolved ${relTime(a.resolved_at)}` : a.status === 'acked' ? `${a.acked_by} · ${relTime(a.acked_at)}` : ''}</span>,
    },
    {
      key: 'actions',
      header: '',
      render: (a) =>
        canWrite && a.status !== 'resolved' ? (
          <div className="cell-actions">
            {a.status === 'open' && (
              <Button size="xs" onClick={() => act(() => api.ackAlert(a.id), 'Acknowledged')}>
                Ack
              </Button>
            )}
            <Button size="xs" onClick={() => act(() => api.resolveAlert(a.id), 'Resolved')}>
              Resolve
            </Button>
          </div>
        ) : null,
    },
  ];

  return (
    <>
      <div className="toolbar">
        <div className="btn-group">
          {(['open', 'acked', 'resolved', 'all'] as Status[]).map((s) => (
            <button key={s} className={`btn sm ${status === s ? 'active' : ''}`} onClick={() => setStatus(s)}>
              {s === 'open' ? 'Open' : s === 'acked' ? 'Acknowledged' : s === 'resolved' ? 'Resolved' : 'All'}
            </button>
          ))}
        </div>
        <select value={sev} onChange={(e) => setSev(e.target.value)} style={{ width: 130 }} aria-label="Severity">
          <option value="">Any severity</option>
          <option value="critical">critical</option>
          <option value="warning">warning</option>
          <option value="info">info</option>
        </select>
        <input type="search" placeholder="Search…" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 220 }} aria-label="Search alerts" />
        <span className="grow" />
        {alerts.data && <span className="muted small">{rows.length} alerts</span>}
        {canWrite && status !== 'resolved' && (
          <Button size="sm" onClick={resolveAll} disabled={!alerts.data?.some((a) => a.status !== 'resolved')}>
            Resolve all
          </Button>
        )}
      </div>
      {alerts.error && <ErrorBox error={alerts.error} onRetry={alerts.reload} />}
      <DataTable columns={columns} rows={alerts.data ? rows : undefined} loading={alerts.loading} rowKey={(a) => String(a.id)} defaultSort={{ key: 'opened', dir: 'desc' }} csvName="alerts" emptyTitle={status === 'open' ? 'No open alerts' : 'No alerts'} emptyBody={status === 'open' ? 'Alert rules fire here when a condition holds.' : undefined} />
    </>
  );
}

const KINDS: { id: RuleKind; label: string; help: string }[] = [
  { id: 'cpu', label: 'CPU usage', help: 'CPU at or above the threshold for N minutes.' },
  { id: 'memory', label: 'Memory usage', help: 'Memory at or above the threshold for N minutes.' },
  { id: 'disk', label: 'Disk usage', help: 'A volume at or above the threshold (optionally one mount).' },
  { id: 'offline', label: 'Device offline', help: 'No check-in for N minutes (default 5).' },
  { id: 'service', label: 'Monitored service stopped', help: 'A monitored service is not running (optionally one service name).' },
  { id: 'reboot_required', label: 'Reboot required', help: 'The device reports a pending reboot.' },
  { id: 'script_failed', label: 'Script failed', help: 'A script run ended failed or timed out.' },
  { id: 'patch_failed', label: 'Patch failed', help: 'A patch install reported an error.' },
  { id: 'event', label: 'Agent event matches', help: 'An agent event message contains the pattern.' },
];

const blankRule = (): AlertRule => ({
  id: 0,
  name: '',
  kind: 'cpu',
  params: { threshold: 90, minutes: 5, mount: '', service: '', pattern: '' },
  targets: EMPTY_TARGETS,
  severity: 'warning',
  notify_email: true,
  auto_resolve: true,
  enabled: true,
  created_at: 0,
});

function ruleSummary(r: AlertRule): string {
  const p = r.params;
  switch (r.kind) {
    case 'cpu':
    case 'memory':
      return `≥ ${p.threshold}% for ${p.minutes} min`;
    case 'disk':
      return `≥ ${p.threshold}%${p.mount ? ` on ${p.mount}` : ' on any volume'}`;
    case 'offline':
      return `> ${p.minutes || 5} min`;
    case 'service':
      return p.service ? `service ${p.service}` : 'any monitored service';
    case 'event':
      return p.pattern ? `message contains "${p.pattern}"` : 'any event';
    default:
      return '';
  }
}

function RuleList() {
  const { canWrite } = useAuth();
  const toast = useToast();
  const confirm = useConfirm();
  const rules = useAsync(() => api.alertRules(), []);
  const agents = useAsync(() => api.agents(), []);
  const groups = useAsync(() => api.groups(), []);
  const [editing, setEditing] = useState<AlertRule | null>(null);

  const toggle = async (r: AlertRule, enabled: boolean) => {
    try {
      await api.updateAlertRule(r.id, { ...r, enabled });
      void rules.reload();
    } catch (err) {
      toast.error('Update failed', errMsg(err));
    }
  };
  const remove = async (r: AlertRule) => {
    if (!(await confirm({ title: 'Delete rule', message: `Delete "${r.name}"? Existing alerts stay.`, danger: true, confirmLabel: 'Delete' }))) return;
    try {
      await api.deleteAlertRule(r.id);
      void rules.reload();
    } catch (err) {
      toast.error('Delete failed', errMsg(err));
    }
  };

  const columns: Column<AlertRule>[] = [
    { key: 'name', header: 'Name', sort: (r) => r.name, render: (r) => <b>{r.name}</b> },
    { key: 'kind', header: 'Condition', sort: (r) => r.kind, render: (r) => <span><Chip outline>{KINDS.find((k) => k.id === r.kind)?.label ?? r.kind}</Chip> <span className="muted small">{ruleSummary(r)}</span></span> },
    { key: 'sev', header: 'Severity', sort: (r) => r.severity, render: (r) => <SeverityChip severity={r.severity} /> },
    { key: 'targets', header: 'Targets', render: (r) => <span className="muted">{targetsSummary(r.targets, agents.data, groups.data)}</span> },
    { key: 'email', header: 'Email', sort: (r) => (r.notify_email ? 0 : 1), render: (r) => (r.notify_email ? 'yes' : <span className="faint">no</span>) },
    { key: 'auto', header: 'Auto-resolve', sort: (r) => (r.auto_resolve ? 0 : 1), render: (r) => (r.auto_resolve ? 'yes' : <span className="faint">no</span>) },
    { key: 'enabled', header: 'Enabled', sort: (r) => (r.enabled ? 0 : 1), render: (r) => <Switch checked={r.enabled} disabled={!canWrite} ariaLabel={`Enable rule ${r.name}`} onChange={(v) => toggle(r, v)} /> },
    {
      key: 'actions',
      header: '',
      render: (r) =>
        canWrite ? (
          <div className="cell-actions">
            <Button size="xs" onClick={() => setEditing(r)}>
              Edit
            </Button>
            <Button size="xs" variant="danger" onClick={() => remove(r)}>
              Delete
            </Button>
          </div>
        ) : null,
    },
  ];

  return (
    <>
      <div className="toolbar">
        <span className="muted small">Rules are evaluated on every metrics sample and every 30 seconds for offline detection.</span>
        <span className="grow" />
        {canWrite && (
          <Button variant="primary" onClick={() => setEditing(blankRule())}>
            <IconPlus /> New rule
          </Button>
        )}
      </div>
      {rules.error && <ErrorBox error={rules.error} onRetry={rules.reload} />}
      <DataTable columns={columns} rows={rules.data} loading={rules.loading} rowKey={(r) => String(r.id)} onRowClick={canWrite ? (r) => setEditing(r) : undefined} defaultSort={{ key: 'name', dir: 'asc' }} csvName="alert-rules" emptyTitle="No alert rules" emptyBody="Add rules for CPU, memory, disk, offline devices, services and more." />
      {editing && (
        <RuleEditor
          rule={editing}
          existing={rules.data ?? []}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            void rules.reload();
          }}
        />
      )}
    </>
  );
}

function RuleEditor({ rule, existing, onClose, onSaved }: { rule: AlertRule; existing: AlertRule[]; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const agents = useAsync(() => api.agents(), []);
  const groups = useAsync(() => api.groups(), []);
  const [form, setForm] = useState<AlertRule>({ ...rule, params: { ...rule.params } });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isNew = rule.id === 0;
  const upd = (patch: Partial<AlertRule>) => setForm((f) => ({ ...f, ...patch }));
  const setP = (patch: Partial<AlertRule['params']>) => upd({ params: { ...form.params, ...patch } });
  const k = form.kind;
  // Alerts are labelled with their rule's name, so two rules called "High CPU"
  // make the alert list unreadable. The server still accepts it; this is the
  // nudge at the point where the name is chosen.
  const duplicateName = existing.some((r) => r.id !== form.id && r.name.trim().toLowerCase() === form.name.trim().toLowerCase() && form.name.trim() !== '');
  const hasThreshold = k === 'cpu' || k === 'memory' || k === 'disk';
  const hasMinutes = k === 'cpu' || k === 'memory' || k === 'offline';

  const save = async () => {
    setError(null);
    if (!form.name.trim()) return setError('Name is required.');
    if (hasThreshold && (form.params.threshold <= 0 || form.params.threshold > 100)) return setError('Threshold must be between 1 and 100.');
    setBusy(true);
    try {
      const payload = { ...form, name: form.name.trim(), targets: normTargets(form.targets) };
      if (isNew) await api.createAlertRule(payload);
      else await api.updateAlertRule(form.id, payload);
      toast.success(isNew ? 'Rule created' : 'Rule saved');
      onSaved();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title={isNew ? 'New alert rule' : `Edit rule: ${rule.name}`}
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
      <div className="form-row">
        <Field label="Name" hint={duplicateName ? 'Another rule already has this name — alerts from both will look the same in the list.' : undefined}>
          <input value={form.name} autoFocus onChange={(e) => upd({ name: e.target.value })} />
        </Field>
        <Field label="Condition">
          <select
            value={form.kind}
            onChange={(e) => {
              const kind = e.target.value as RuleKind;
              const defaults: Partial<AlertRule['params']> = kind === 'disk' ? { threshold: 90 } : kind === 'cpu' || kind === 'memory' ? { threshold: 90, minutes: 5 } : kind === 'offline' ? { minutes: 5 } : {};
              upd({ kind, params: { ...form.params, ...defaults } });
            }}
          >
            {KINDS.map((x) => (
              <option key={x.id} value={x.id}>
                {x.label}
              </option>
            ))}
          </select>
        </Field>
      </div>
      <p className="muted small">{KINDS.find((x) => x.id === k)?.help}</p>
      <div className="form-row">
        {hasThreshold && (
          <Field label="Threshold (%)">
            <input type="number" min={1} max={100} value={form.params.threshold} onChange={(e) => setP({ threshold: +e.target.value })} />
          </Field>
        )}
        {hasMinutes && (
          <Field label={k === 'offline' ? 'Grace period (minutes)' : 'Sustained for (minutes)'} hint={k === 'offline' ? '0 uses the default of 5.' : '0 fires on the first sample.'}>
            <input type="number" min={0} max={10080} value={form.params.minutes} onChange={(e) => setP({ minutes: +e.target.value })} />
          </Field>
        )}
        {k === 'disk' && (
          <Field label="Mount / drive" hint="Leave empty for every volume.">
            <input value={form.params.mount} placeholder="C: or /" onChange={(e) => setP({ mount: e.target.value })} />
          </Field>
        )}
        {k === 'service' && (
          <Field label="Service name" hint="Must be in the device's monitored services. Empty = all monitored.">
            <input value={form.params.service} placeholder="Spooler" onChange={(e) => setP({ service: e.target.value })} />
          </Field>
        )}
        {k === 'event' && (
          <Field label="Message contains" hint="Case-insensitive substring. Empty matches every event.">
            <input value={form.params.pattern} placeholder="disk error" onChange={(e) => setP({ pattern: e.target.value })} />
          </Field>
        )}
      </div>
      <div className="form-row">
        <Field label="Severity">
          <select value={form.severity} onChange={(e) => upd({ severity: e.target.value as Severity })}>
            <option value="info">info</option>
            <option value="warning">warning</option>
            <option value="critical">critical</option>
          </select>
        </Field>
        <Field label="Options">
          <div className="stack" style={{ gap: 6 }}>
            <Switch checked={form.notify_email} onChange={(notify_email) => upd({ notify_email })} label="Email when opened" />
            <Switch checked={form.auto_resolve} onChange={(auto_resolve) => upd({ auto_resolve })} label="Auto-resolve when the condition clears" />
            <Switch checked={form.enabled} onChange={(enabled) => upd({ enabled })} label="Enabled" />
          </div>
        </Field>
      </div>
      <Field label="Targets">
        <TargetPicker value={form.targets} onChange={(targets) => upd({ targets })} agents={agents.data ?? []} groups={groups.data ?? []} />
      </Field>
    </Modal>
  );
}
