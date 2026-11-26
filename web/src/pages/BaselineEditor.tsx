// Create or edit a baseline: what it checks, where it applies, and whether
// the agent is allowed to change devices to satisfy it.
//
// Saving is a MERGE on the server: a check keeps its id (and therefore its
// results, its history and its open alert) when it is edited, and is deleted
// when it is not in the body. The editor keeps ids on the rows it loaded and
// sends 0 for new ones.

import { useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api } from '../api/client';
import type { Agent, Baseline, BaselineCheck, BaselineInput, BaselinePreview, BaselinePreviewSpec, Targets } from '../api/types';
import { CheckDialog } from '../components/baselines/CheckDialog';
import { LIMITS, INTERVALS, blankCheck, isDangerous, kindDef, kindLabel, needsAdmin, osWarning, toInput, validateCheck } from '../components/baselines/kinds';
import { StateChip } from '../components/baselines/state';
import { IconPlus } from '../components/Icons';
import { Modal, useConfirm } from '../components/Modal';
import { DeviceMultiSelect, EMPTY_TARGETS, TargetPicker, targetsMatch } from '../components/TargetPicker';
import { Button, Chip, Empty, ErrorBox, Field, Loading, SeverityChip, Switch } from '../components/ui';
import { useAsync } from '../hooks/useAsync';
import { duration, osLabel } from '../lib/format';
import { useAuth } from '../state/auth';
import { errMsg, useToast } from '../state/toast';
import { normTargets } from './Tasks';

interface Form {
  name: string;
  description: string;
  targets: Targets;
  enforce: boolean;
  interval_sec: number;
  notify_email: boolean;
  enabled: boolean;
  checks: BaselineCheck[];
}

const blankForm = (): Form => ({
  name: '',
  description: '',
  targets: EMPTY_TARGETS,
  enforce: false,
  interval_sec: LIMITS.defaultInterval,
  notify_email: false,
  enabled: false,
  checks: [],
});

function renderRemediationAction(c: BaselineCheck, enforceBaseline: boolean) {
  if (!c.remediate) {
    return <Chip outline>Audit Only</Chip>;
  }

  let label = 'Auto-Fix';
  let tone: 'purple' | 'warn' | 'danger' | 'info' = 'purple';
  let title = 'Remediates drift automatically';

  if (c.kind === 'package') {
    if (c.params.fix_script) {
      label = `Script (${c.params.fix_lang || 'ps1'})`;
      title = 'Custom script remediation';
    } else if (c.params.allow_winget) {
      label = 'Winget';
      title = 'Winget silent package manager';
    } else if (c.os_filter === 'linux') {
      label = 'apt / dnf';
      title = 'Linux package manager';
    } else {
      label = 'Pkg Mgr';
      title = 'System package manager';
    }
  } else if (c.kind === 'service') {
    if (c.params.fix_script) {
      label = `Script (${c.params.fix_lang || 'ps1'})`;
      title = 'Custom script remediation';
    } else {
      label = 'Service Mgr';
      title = 'Built-in sc.exe / systemctl service control';
    }
  } else if (c.kind === 'command') {
    label = `Fix Script (${c.params.language || 'bash'})`;
    title = 'Executes custom fix script';
  } else if (c.kind === 'registry') {
    label = 'Reg Write';
    title = 'Atomic Win32 registry set';
  } else if (c.kind === 'file') {
    label = c.params.state === 'absent' ? 'File Remove' : 'File Sync';
    title = 'Atomic file update or deletion';
  } else if (c.kind === 'reboot_pending') {
    if (c.params.warn_user !== false) {
      label = `Prompt User (${c.params.max_postpones ?? 3}x)`;
      tone = 'warn';
      title = `Interactive prompt with up to ${c.params.max_postpones ?? 3} postpones, enforcing at ${c.params.enforce_time || '23:00'}`;
    } else {
      label = 'Auto Reboot';
      tone = 'danger';
      title = 'Unattended restart with 60-second system warning';
    }
  } else if (c.kind === 'firewall') {
    label = 'Firewall Policy';
    title = 'Enforces firewall state';
  } else if (c.kind === 'time_sync') {
    label = 'Time Sync';
    title = 'Enables & resyncs time service';
  } else if (c.kind === 'windows_feature') {
    label = 'Win Feature';
    title = 'Enables or disables optional feature';
  } else if (c.kind === 'sysctl') {
    label = 'sysctl Write';
    title = 'Enforces Linux kernel parameters';
  } else if (c.kind === 'group_members') {
    label = 'Group Prune';
    title = 'Removes unauthorized accounts from local group';
  }

  return (
    <div className="row" style={{ gap: 4, alignItems: 'center', flexWrap: 'nowrap' }}>
      <Chip tone={tone} title={title}>
        {label}
      </Chip>
      {!enforceBaseline && (
        <span className="muted small" title="Check has remediation configured, but baseline-level enforcement is currently off">
          (audit)
        </span>
      )}
    </div>
  );
}

export function BaselineEditor() {
  const { id } = useParams();
  const baselineId = id ? Number(id) : 0;
  const navigate = useNavigate();
  const toast = useToast();
  const confirm = useConfirm();
  const { canWrite, can, isAdmin } = useAuth();
  const canEdit = can('baselines.edit');
  const agents = useAsync(() => api.agents(), []);
  const groups = useAsync(() => api.groups(), []);
  const loaded = useAsync(async () => (baselineId ? api.baseline(baselineId) : null), [baselineId]);

  const [form, setForm] = useState<Form | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [allowEmpty, setAllowEmpty] = useState(false);
  // "Custom…" in the interval select is a mode, not a value: without it the
  // select falls straight back to whichever preset the interval still is.
  const [custom, setCustom] = useState(false);
  const [editing, setEditing] = useState<{ index: number; check: BaselineCheck } | null>(null);
  const [previewOpen, setPreviewOpen] = useState(false);

  // Seed the form once the baseline is in (or immediately for a new one).
  const current = form ?? (loaded.loaded ? seed(loaded.data) : null);
  if (loaded.error && !form) return <ErrorBox error={loaded.error} onRetry={loaded.reload} />;
  if (!current) return <Loading />;
  const f = current;
  const upd = (patch: Partial<Form>) => setForm({ ...f, ...patch });
  const isNew = baselineId === 0;

  const matched = (agents.data ?? []).filter((a) => targetsMatch(f.targets, a));
  const checkErrors = f.checks.map((c) => validateCheck(c));
  const firstError = checkErrors.findIndex((e) => e !== null);
  const wantsFleetReboot = f.targets.all && f.enforce && f.checks.some((c) => c.kind === 'reboot_pending' && c.params.allow_reboot === true);
  const adminBlocked = !isAdmin && f.checks.some((c) => needsAdmin(c));

  const setCheck = (index: number, check: BaselineCheck) => {
    const next = [...f.checks];
    if (index < 0) next.push(check);
    else next[index] = check;
    upd({ checks: next });
  };
  const move = (index: number, delta: number) => {
    const to = index + delta;
    if (to < 0 || to >= f.checks.length) return;
    const next = [...f.checks];
    const [row] = next.splice(index, 1);
    next.splice(to, 0, row);
    upd({ checks: next });
  };
  const removeCheck = async (index: number) => {
    const c = f.checks[index];
    if (c.id > 0 && !(await confirm({ title: 'Remove check', message: `Remove "${c.name}"? Saving then deletes its results on every device and resolves its open drift alerts. Its history rows stay.`, danger: true, confirmLabel: 'Remove' }))) return;
    upd({ checks: f.checks.filter((_, i) => i !== index) });
  };

  const body = (extra?: Partial<BaselineInput>): BaselineInput => ({
    name: f.name.trim(),
    description: f.description,
    targets: normTargets(f.targets),
    enforce: f.enforce,
    interval_sec: f.interval_sec,
    notify_email: f.notify_email,
    enabled: f.enabled,
    checks: f.checks.map(toInput),
    ...extra,
  });

  const save = async () => {
    setError(null);
    if (!f.name.trim()) return setError('A name is required.');
    if (f.name.length > LIMITS.name) return setError(`The name is at most ${LIMITS.name} characters.`);
    if (f.description.length > LIMITS.description) return setError(`The description is at most ${LIMITS.description} characters.`);
    if (!f.checks.length) return setError('Add at least one check — a baseline with no checks measures nothing.');
    if (f.checks.length > LIMITS.checksPerBaseline) return setError(`At most ${LIMITS.checksPerBaseline} checks per baseline.`);
    if (firstError >= 0) return setError(`${f.checks[firstError].name || `Check ${firstError + 1}`}: ${checkErrors[firstError]}`);
    if (f.interval_sec < LIMITS.minInterval || f.interval_sec > LIMITS.maxInterval) return setError(`The interval must be between ${LIMITS.minInterval} s and ${LIMITS.maxInterval} s.`);
    if (!matched.length && !allowEmpty) return setError('These targets match no devices. Tick "save anyway" below if that is deliberate.');

    let confirmFleetReboot = false;
    if (wantsFleetReboot) {
      const ok = await confirm({
        title: 'Reboot every device?',
        danger: true,
        confirmLabel: 'I understand',
        message: 'This baseline targets ALL devices, is enforced, and contains a check that may reboot. Every device that has been pending a reboot for too long will be restarted with a 60 second notice.',
      });
      if (!ok) return;
      confirmFleetReboot = true;
    }
    if (f.enforce) {
      const fixes = f.checks.filter((c) => c.remediate);
      if (fixes.length) {
        const ok = await confirm({
          title: 'Enforce this baseline?',
          danger: true,
          confirmLabel: 'Enforce',
          message: `The agent will change ${matched.length} device(s) without asking: ${fixes.map((c) => c.name).join(', ')}.`,
        });
        if (!ok) return;
      }
    }

    setBusy(true);
    try {
      const payload = body({ allow_empty_targets: allowEmpty || undefined, confirm_fleet_reboot: confirmFleetReboot || undefined });
      const saved = isNew ? await api.createBaseline(payload) : await api.updateBaseline(baselineId, payload);
      toast.success(isNew ? 'Baseline created' : 'Baseline saved', saved.version ? `version ${saved.version}` : undefined);
      navigate(`/baselines/${saved.id}`);
    } catch (err) {
      const msg = errMsg(err);
      setError(msg);
      if (/match no devices/i.test(msg)) setAllowEmpty(false);
    } finally {
      setBusy(false);
    }
  };

  const previewSpec: BaselinePreviewSpec = { name: f.name.trim() || 'draft', enforce: false, interval_sec: f.interval_sec, checks: f.checks.map(toInput) };

  return (
    <>
      <div className="page-head">
        <div className="row" style={{ marginRight: 'auto', gap: 10 }}>
          <Link to="/baselines" className="muted small">
            Baselines
          </Link>
          <span className="faint">/</span>
          <h1>{isNew ? 'New baseline' : f.name || `Baseline #${baselineId}`}</h1>
          {!isNew && <Chip outline>v{loaded.data?.version ?? 1}</Chip>}
        </div>
        <Button onClick={() => navigate(isNew ? '/baselines' : `/baselines/${baselineId}`)}>Cancel</Button>
        <Button
          onClick={() => setPreviewOpen(true)}
          disabled={!canWrite || !f.checks.length || firstError >= 0}
          title={firstError >= 0 ? 'Fix the checks first' : 'Evaluate this draft on devices without saving or fixing anything'}
        >
          Preview on devices
        </Button>
        <Button variant="primary" onClick={save} busy={busy} disabled={!canEdit || adminBlocked}>
          {isNew ? 'Create baseline' : 'Save baseline'}
        </Button>
      </div>

      {!canEdit && (
        <div className="banner info">
          <span>You have read-only access: this baseline cannot be changed.</span>
        </div>
      )}
      {adminBlocked && (
        <div className="banner danger" role="alert">
          <span>This baseline contains a check only an administrator may save (a command script, a reboot, or a file outside /etc and ProgramData).</span>
        </div>
      )}
      {error && (
        <div className="form-error" role="alert">
          {error}
        </div>
      )}

      <div className="grid cols-2" style={{ alignItems: 'start' }}>
        <div className="card">
          <div className="card-head">Basics</div>
          <div className="card-body">
            <Field label="Target Operating System" hint="Select the OS first to filter available checks and endpoints.">
              <div className="row" style={{ gap: 16 }}>
                <label className="row" style={{ gap: 6, cursor: 'pointer', fontWeight: !f.targets.os ? 600 : 400 }}>
                  <input type="radio" name="bl-os" checked={!f.targets.os} disabled={!canEdit} onChange={() => upd({ targets: { ...f.targets, os: undefined } })} /> Cross-Platform / Any
                </label>
                <label className="row" style={{ gap: 6, cursor: 'pointer', fontWeight: f.targets.os === 'windows' ? 600 : 400 }}>
                  <input type="radio" name="bl-os" checked={f.targets.os === 'windows'} disabled={!canEdit} onChange={() => upd({ targets: { ...f.targets, os: 'windows' } })} /> Windows
                </label>
                <label className="row" style={{ gap: 6, cursor: 'pointer', fontWeight: f.targets.os === 'linux' ? 600 : 400 }}>
                  <input type="radio" name="bl-os" checked={f.targets.os === 'linux'} disabled={!canEdit} onChange={() => upd({ targets: { ...f.targets, os: 'linux' } })} /> Linux
                </label>
              </div>
            </Field>
            <Field label="Name" htmlFor="bl-name">
              <input id="bl-name" value={f.name} maxLength={LIMITS.name} disabled={!canEdit} onChange={(e) => upd({ name: e.target.value })} />
            </Field>
            <Field label="Description" htmlFor="bl-desc" hint="Why this baseline exists. Not sent to devices.">
              <input id="bl-desc" value={f.description} maxLength={LIMITS.description} disabled={!canEdit} onChange={(e) => upd({ description: e.target.value })} />
            </Field>
            <div className="form-row">
              <Field label="Evaluate every" htmlFor="bl-interval" hint={`Between ${duration(LIMITS.minInterval)} and ${duration(LIMITS.maxInterval)}. Devices evaluate offline too and report when they reconnect.`}>
                <select
                  id="bl-interval"
                  value={custom || !INTERVALS.some((i) => i.sec === f.interval_sec) ? 'custom' : String(f.interval_sec)}
                  disabled={!canEdit}
                  // "Custom…" has to be a state of its own: keeping the
                  // current interval (a preset) made the select snap back and
                  // the seconds field never appeared, so a custom interval
                  // could not be typed at all.
                  onChange={(e) => {
                    if (e.target.value === 'custom') setCustom(true);
                    else {
                      setCustom(false);
                      upd({ interval_sec: Number(e.target.value) });
                    }
                  }}
                >
                  {INTERVALS.map((i) => (
                    <option key={i.sec} value={i.sec}>
                      {i.label}
                    </option>
                  ))}
                  <option value="custom">Custom…</option>
                </select>
              </Field>
              {(custom || !INTERVALS.some((i) => i.sec === f.interval_sec)) && (
                <Field label="Seconds" htmlFor="bl-interval-sec">
                  <input
                    id="bl-interval-sec"
                    type="number"
                    min={LIMITS.minInterval}
                    max={LIMITS.maxInterval}
                    value={f.interval_sec}
                    disabled={!canEdit}
                    onChange={(e) => upd({ interval_sec: +e.target.value || LIMITS.defaultInterval })}
                  />
                </Field>
              )}
            </div>
            <Field label="Options" hint="A digest is sent at most once an hour per device and baseline, and only for checks that newly drift at critical severity.">
              <div className="stack" style={{ gap: 8 }}>
                <span data-testid="bl-enabled">
                  <Switch checked={f.enabled} disabled={!canEdit} onChange={(enabled) => upd({ enabled })} label="Enabled (assigned to matching devices)" />
                </span>
                <span data-testid="bl-notify">
                  <Switch
                    checked={f.notify_email}
                    disabled={!canEdit}
                    onChange={(notify_email) => upd({ notify_email })}
                    label="Email a digest of new critical drift"
                  />
                </span>
              </div>
            </Field>
          </div>
        </div>

        <div className="card">
          <div className="card-head">Targets</div>
          <div className="card-body">
            <TargetPicker value={f.targets} onChange={(targets) => upd({ targets })} agents={agents.data ?? []} groups={groups.data ?? []} disabled={!canEdit} />
            {!matched.length && (
              <div className="banner warn" style={{ marginTop: 8 }}>
                <div className="stack" style={{ gap: 6, width: '100%' }}>
                  <span>These targets match no devices, so nothing will ever evaluate this baseline.</span>
                  <label className="row" style={{ gap: 6 }}>
                    <input type="checkbox" checked={allowEmpty} disabled={!canEdit} onChange={(e) => setAllowEmpty(e.target.checked)} /> Save anyway
                  </label>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="card" style={{ marginTop: 14, border: f.enforce ? '1px solid var(--accent)' : undefined }}>
        <div className="card-head" style={{ justifyContent: 'space-between' }}>
          <span>Compliance & Enforcement Policy</span>
          <Chip tone={f.enforce ? 'purple' : 'info'}>
            {f.enforce ? 'Auto-Enforce & Remediate' : 'Audit & Alert Only'}
          </Chip>
        </div>
        <div className="card-body stack" style={{ gap: 12 }}>
          <p className="small muted" style={{ margin: 0 }}>
            Choose whether this baseline only measures compliance and opens drift alerts, or actively enforces settings on endpoints.
          </p>
          <div className="grid cols-2" style={{ gap: 14 }}>
            <label
              className="card"
              style={{
                padding: '12px 14px',
                margin: 0,
                cursor: canEdit ? 'pointer' : 'default',
                border: !f.enforce ? '2px solid var(--primary)' : '1px solid var(--border)',
                background: !f.enforce ? 'rgba(59, 130, 246, 0.08)' : 'var(--bg-card)',
              }}
            >
              <div className="row" style={{ gap: 8, alignItems: 'center', marginBottom: 4 }}>
                <input
                  type="radio"
                  name="bl-enforce-mode"
                  checked={!f.enforce}
                  disabled={!canEdit}
                  onChange={() => upd({ enforce: false })}
                />
                <b>Audit & Alert Only</b>
              </div>
              <div className="small muted">
                Monitors checks on schedule, flags drift in the Activity log, and opens alerts. Never alters system state.
              </div>
            </label>

            <label
              className="card"
              style={{
                padding: '12px 14px',
                margin: 0,
                cursor: canEdit ? 'pointer' : 'default',
                border: f.enforce ? '2px solid var(--accent)' : '1px solid var(--border)',
                background: f.enforce ? 'rgba(168, 85, 247, 0.08)' : 'var(--bg-card)',
              }}
            >
              <div className="row" style={{ gap: 8, alignItems: 'center', marginBottom: 4 }}>
                <input
                  type="radio"
                  name="bl-enforce-mode"
                  checked={f.enforce}
                  disabled={!canEdit}
                  onChange={() => upd({ enforce: true })}
                />
                <b>Auto-Enforce & Remediate</b>
              </div>
              <div className="small muted">
                The agent actively fixes drifted settings using built-in actions, custom scripts, or interactive prompts.
              </div>
            </label>
          </div>

          {f.enforce && (
            <div className="banner warn" role="note" style={{ margin: 0 }}>
              <span>
                ⚡ <b>Active Enforcement Mode:</b> Every check below with remediation enabled will be automatically fixed by the agent on matched devices. Review each check's <b>Remediation Action Preview</b> before saving.
              </span>
            </div>
          )}
        </div>
      </div>

      <div className="card" style={{ marginTop: 14 }}>
        <div className="card-head">
          Checks
          <span className="muted small">
            {f.checks.length} / {LIMITS.checksPerBaseline}
          </span>
          <div className="actions">
            {canEdit && (
              <Button size="sm" variant="primary" onClick={() => setEditing({ index: -1, check: blankCheck() })} disabled={f.checks.length >= LIMITS.checksPerBaseline}>
                <IconPlus /> Add check
              </Button>
            )}
          </div>
        </div>
        {f.checks.length ? (
          <div className="table-wrap">
            <table className="tbl compact">
              <thead>
                <tr>
                  <th style={{ width: 70 }}>Order</th>
                  <th>Check</th>
                  <th>Kind</th>
                  <th>Severity</th>
                  <th>Remediation Action</th>
                  <th>OS</th>
                  <th>Timeout</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {f.checks.map((c, i) => {
                  const err = checkErrors[i];
                  const warn = osWarning(c);
                  return (
                    <tr key={`${c.id}-${i}`}>
                      <td>
                        <div className="row" style={{ gap: 2, flexWrap: 'nowrap' }}>
                          <Button size="xs" variant="ghost" icon aria-label={`Move ${c.name} up`} disabled={!canEdit || i === 0} onClick={() => move(i, -1)}>
                            ↑
                          </Button>
                          <Button size="xs" variant="ghost" icon aria-label={`Move ${c.name} down`} disabled={!canEdit || i === f.checks.length - 1} onClick={() => move(i, 1)}>
                            ↓
                          </Button>
                        </div>
                      </td>
                      <td>
                        <div>
                          <b>{c.name || <span className="muted">(unnamed)</span>}</b>
                          {c.id > 0 && <span className="faint small mono"> #{c.id}</span>}
                          <div className="muted small mono truncate" style={{ maxWidth: 420 }}>
                            {kindDef(c.kind)?.summary(c.params) ?? ''}
                          </div>
                          {err && <div className="small" style={{ color: 'var(--danger)' }}>{err}</div>}
                          {!err && warn && <div className="small" style={{ color: 'var(--warn)' }}>{warn}</div>}
                        </div>
                      </td>
                      <td>
                        <Chip outline>{kindLabel(c.kind)}</Chip>
                        {isDangerous(c) && <Chip tone="danger" title="Runs operator code, removes group members or reboots">care</Chip>}
                      </td>
                      <td>
                        <SeverityChip severity={c.severity} />
                      </td>
                      <td>{renderRemediationAction(c, f.enforce)}</td>
                      <td className="muted small">{c.os_filter ? osLabel(c.os_filter) : 'any'}</td>
                      <td className="muted small">{c.timeout_sec}s</td>
                      <td>
                        {canEdit && (
                          <div className="cell-actions">
                            <Button size="xs" onClick={() => setEditing({ index: i, check: c })}>
                              Edit
                            </Button>
                            <Button size="xs" variant="danger" onClick={() => removeCheck(i)}>
                              Remove
                            </Button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No checks yet">Add the first check: a service that must run, a file that must exist, a firewall that must be on.</Empty>
        )}
      </div>

      {editing && (
        <CheckDialog
          check={editing.check}
          isAdmin={isAdmin}
          osFilter={f.targets.os}
          onClose={() => setEditing(null)}
          onSave={(c) => {
            setCheck(editing.index, c);
            setEditing(null);
          }}
        />
      )}
      {previewOpen && <PreviewDialog spec={previewSpec} agents={agents.data ?? []} onClose={() => setPreviewOpen(false)} />}
    </>
  );
}

function seed(b: (Baseline & { checks?: BaselineCheck[] }) | null | undefined): Form {
  if (!b) return blankForm();
  return {
    name: b.name,
    description: b.description,
    targets: b.targets ?? EMPTY_TARGETS,
    enforce: b.enforce,
    interval_sec: b.interval_sec,
    notify_email: b.notify_email,
    enabled: b.enabled,
    checks: (b.checks ?? []).map((c) => ({ ...c, params: { ...c.params } })),
  };
}

// ---------- preview ----------

/**
 * A dry run of the draft on real devices: the agent evaluates it, never fixes
 * anything and never stores it. Check ids are the synthetic negatives the
 * server assigned, so results map back to rows by index.
 */
function PreviewDialog({ spec, agents, onClose }: { spec: BaselinePreviewSpec; agents: Agent[]; onClose: () => void }) {
  const online = useMemo(() => agents.filter((a) => a.online), [agents]);
  const [sel, setSel] = useState<Set<string>>(() => new Set(online.slice(0, 1).map((a) => a.id)));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [out, setOut] = useState<BaselinePreview | null>(null);

  // The server takes at most LIMITS.previewAgents ids. Slicing the selection
  // silently would run the draft on the first ten and quietly ignore the rest,
  // which reads as "these devices are all fine".
  const tooMany = sel.size > LIMITS.previewAgents;

  const run = async () => {
    setError(null);
    if (tooMany) return setError(`Pick at most ${LIMITS.previewAgents} devices: a preview runs the draft on each of them.`);
    setBusy(true);
    try {
      setOut(await api.previewBaseline(spec, [...sel]));
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  const nameFor = (checkId: number) => out?.spec_checks.find((c) => c.id === checkId)?.name ?? `check ${checkId}`;

  return (
    <Modal
      title="Preview on devices"
      onClose={onClose}
      size="xl"
      footer={
        <>
          <Button onClick={onClose}>Close</Button>
          <Button variant="primary" onClick={run} busy={busy} disabled={!sel.size || tooMany} title={tooMany ? `At most ${LIMITS.previewAgents} devices` : undefined}>
            Run preview on {sel.size} device{sel.size === 1 ? '' : 's'}
          </Button>
        </>
      }
    >
      <p className="muted small">
        The draft is evaluated on the devices you pick. Nothing is saved, nothing is fixed and no alert is raised — a drifted check simply reports <code>fail</code>. Offline
        devices answer <code>offline</code> rather than failing the whole run. At most {LIMITS.previewAgents} devices.
      </p>
      {error && (
        <div className="form-error" role="alert">
          {error}
        </div>
      )}
      <DeviceMultiSelect agents={online} value={sel} onChange={setSel} />
      {!online.length && <p className="muted small">No device is online right now.</p>}
      {out && (
        <div className="stack" style={{ gap: 10, marginTop: 12 }}>
          {out.devices.map((d) => (
            <div key={d.agent_id} className="card" data-testid={`preview-${d.agent_id}`}>
              <div className="card-head">
                {d.agent_name || d.agent_id}
                <Chip tone={d.status === 'ok' ? 'ok' : d.status === 'offline' ? '' : 'danger'}>{d.status}</Chip>
                <span className="muted small">{osLabel(d.os)}</span>
                <span className="muted small ml-auto">{d.duration_ms} ms</span>
              </div>
              {d.error && <div className="card-body muted small">{d.error}</div>}
              {d.results.length > 0 && (
                <div className="table-wrap">
                  <table className="tbl compact">
                    <thead>
                      <tr>
                        <th>Check</th>
                        <th>State</th>
                        <th>Expected</th>
                        <th>Observed</th>
                        <th>Detail</th>
                      </tr>
                    </thead>
                    <tbody>
                      {d.results.map((r) => (
                        <tr key={r.check_id}>
                          <td>{nameFor(r.check_id)}</td>
                          <td>
                            <StateChip state={r.state} />
                          </td>
                          <td className="mono small">{r.expected || '—'}</td>
                          <td className="mono small">{r.observed || '—'}</td>
                          <td className="muted small truncate" style={{ maxWidth: 320 }} title={r.detail}>
                            {r.detail}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </Modal>
  );
}
