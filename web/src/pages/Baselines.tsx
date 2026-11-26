// The baselines list: what desired state exists, where it applies, and how
// far the fleet is from it.

import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import type { Baseline } from '../api/types';
import { ComplianceChip } from '../components/baselines/state';
import { DataTable, textMatch, type Column } from '../components/DataTable';
import { IconPlus } from '../components/Icons';
import { useConfirm } from '../components/Modal';
import { targetsSummary } from '../components/TargetPicker';
import { Button, Chip, ErrorBox, Switch } from '../components/ui';
import { useAsync, useDebounced } from '../hooks/useAsync';
import { useLiveReload } from '../hooks/useEvents';
import { pluralize, relTime } from '../lib/format';
import { useAuth } from '../state/auth';
import { errMsg, useToast } from '../state/toast';

export function Baselines() {
  const { canWrite, can } = useAuth();
  const canEdit = can('baselines.edit');
  const navigate = useNavigate();
  const toast = useToast();
  const confirm = useConfirm();
  const baselines = useAsync(() => api.baselines(), []);
  const agents = useAsync(() => api.agents(), []);
  const groups = useAsync(() => api.groups(), []);
  useLiveReload(['baseline', 'hello'], baselines.reload, { debounceMs: 800 });
  const [q, setQ] = useState('');
  const dq = useDebounced(q);

  const rows = useMemo(() => (baselines.data ?? []).filter((b) => textMatch(dq, b.name, b.description)), [baselines.data, dq]);

  const toggle = async (b: Baseline, enabled: boolean) => {
    try {
      // Enabling is a save of the whole baseline, so the checks have to come
      // with it: PUT is a merge and an absent check is a deleted check (A2).
      const full = await api.baseline(b.id);
      // The server refuses an enforced {all: true} baseline holding a check
      // that may reboot unless the request confirms it. Without asking here
      // the switch just fails with that message and there is no way to say
      // yes from this page, so the editor's confirmation is asked here too.
      let confirmFleetReboot = false;
      if (enabled && full.targets.all && full.enforce && full.checks.some((c) => c.kind === 'reboot_pending' && c.params.allow_reboot === true)) {
        const okToReboot = await confirm({
          title: 'Reboot every device?',
          danger: true,
          confirmLabel: 'I understand',
          message: `"${full.name}" targets ALL devices, is enforced and contains a check that may reboot. Enabling it lets every device that has been pending a reboot for too long restart itself with a 60 second notice.`,
        });
        if (!okToReboot) {
          void baselines.reload();
          return;
        }
        confirmFleetReboot = true;
      }
      await api.updateBaseline(b.id, {
        name: full.name,
        description: full.description,
        targets: full.targets,
        enforce: full.enforce,
        interval_sec: full.interval_sec,
        notify_email: full.notify_email,
        enabled,
        checks: full.checks.map((c) => ({ ...c, id: c.id })),
        allow_empty_targets: true,
        confirm_fleet_reboot: confirmFleetReboot || undefined,
      });
      toast.success(enabled ? 'Baseline enabled' : 'Baseline disabled');
      void baselines.reload();
    } catch (err) {
      toast.error('Update failed', errMsg(err));
    }
  };

  const remove = async (b: Baseline) => {
    if (
      !(await confirm({
        title: 'Delete baseline',
        message: `Delete "${b.name}"? Its results on every device go with it and every open drift alert it raised is resolved. Its history rows stay for the audit trail.`,
        danger: true,
        confirmLabel: 'Delete',
      }))
    )
      return;
    try {
      await api.deleteBaseline(b.id);
      toast.success('Baseline deleted');
      void baselines.reload();
    } catch (err) {
      toast.error('Delete failed', errMsg(err));
    }
  };

  const evaluate = async (b: Baseline) => {
    try {
      const r = await api.evaluateBaseline(b.id);
      toast.success(`Evaluation requested on ${r.queued} of ${r.requested} device(s)`, r.offline ? `${r.offline} offline — they report on their own schedule` : undefined);
    } catch (err) {
      toast.error('Evaluate failed', errMsg(err));
    }
  };

  const columns: Column<Baseline>[] = [
    {
      key: 'name',
      header: 'Name',
      sort: (b) => b.name,
      render: (b) => (
        <div>
          <b>{b.name}</b>
          {b.description && <div className="muted small truncate" style={{ maxWidth: 380 }}>{b.description}</div>}
        </div>
      ),
    },
    {
      key: 'mode',
      header: 'Mode',
      sort: (b) => (b.enforce ? 0 : 1),
      csv: (b) => (b.enforce ? 'enforcing' : 'reporting'),
      render: (b) => (b.enforce ? <Chip tone="purple" title="The agent fixes drift on these devices without asking">enforcing</Chip> : <Chip outline>report only</Chip>),
    },
    { key: 'checks', header: 'Checks', sort: (b) => b.checks_count, render: (b) => <span className="mono">{b.checks_count}</span> },
    { key: 'targets', header: 'Targets', render: (b) => <span className="muted">{targetsSummary(b.targets, agents.data, groups.data)}</span> },
    {
      key: 'devices',
      header: 'Devices',
      sort: (b) => b.devices,
      csv: (b) => b.devices,
      render: (b) => (
        <span className="muted small">
          {b.devices} matched · {b.devices_reported} reported
          {b.devices_drifted > 0 && <span style={{ color: 'var(--danger)' }}> · {b.devices_drifted} drifted</span>}
          {b.devices_unknown > 0 && <span> · {b.devices_unknown} unknown</span>}
        </span>
      ),
    },
    {
      key: 'compliance',
      header: 'Compliance',
      sort: (b) => (b.compliance === null ? -1 : b.compliance),
      csv: (b) => (b.compliance === null ? '' : b.compliance),
      render: (b) => <ComplianceChip value={b.compliance} />,
    },
    { key: 'change', header: 'Last change', sort: (b) => b.last_change, render: (b) => <span className="muted">{b.last_change ? relTime(b.last_change) : '—'}</span> },
    {
      key: 'enabled',
      header: 'Enabled',
      sort: (b) => (b.enabled ? 0 : 1),
      // The row opens the status view, so every control in it has to keep its
      // click to itself: the row handler runs after the button's and would
      // navigate away from the list mid-action (Edit landed on the status
      // view, Delete on the baseline it had just deleted).
      render: (b) => (
        <span onClick={(e) => e.stopPropagation()}>
          <Switch checked={b.enabled} disabled={!canEdit} ariaLabel={`Enable baseline ${b.name}`} onChange={(v) => toggle(b, v)} />
        </span>
      ),
    },
    {
      key: 'actions',
      header: '',
      render: (b) =>
        canWrite || canEdit ? (
          <div className="cell-actions" onClick={(e) => e.stopPropagation()}>
            {canWrite && (
              <Button
                size="xs"
                onClick={() => evaluate(b)}
                disabled={!b.enabled}
                title={b.enabled ? 'Ask every matched online device to evaluate now' : 'No device is holding this baseline: enable it first'}
              >
                Evaluate
              </Button>
            )}
            {canEdit && (
              <>
                <Button size="xs" onClick={() => navigate(`/baselines/${b.id}/edit`)}>
                  Edit
                </Button>
                <Button size="xs" variant="danger" onClick={() => remove(b)}>
                  Delete
                </Button>
              </>
            )}
          </div>
        ) : null,
    },
  ];

  return (
    <>
      <div className="page-head">
        <h1>Baselines</h1>
        {canEdit && (
          <Button variant="primary" onClick={() => navigate('/baselines/new')}>
            <IconPlus /> New baseline
          </Button>
        )}
      </div>
      <div className="toolbar">
        <span className="muted small">
          A baseline is a list of checks a device must satisfy. Enforced baselines let the agent fix drift itself; the rest only report it.
        </span>
        <span className="grow" />
        <input type="search" placeholder="Search…" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 220 }} aria-label="Search baselines" />
        {baselines.data && <span className="muted small">{pluralize(rows.length, 'baseline')}</span>}
      </div>
      {baselines.error && <ErrorBox error={baselines.error} onRetry={baselines.reload} />}
      <DataTable
        columns={columns}
        rows={baselines.data ? rows : undefined}
        loading={baselines.loading}
        rowKey={(b) => String(b.id)}
        onRowClick={(b) => navigate(`/baselines/${b.id}`)}
        defaultSort={{ key: 'name', dir: 'asc' }}
        csvName="baselines"
        emptyTitle="No baselines"
        emptyBody="Describe how a device should look — services, files, registry values, packages, firewall — and the agent reports (or fixes) every difference."
      />
    </>
  );
}
