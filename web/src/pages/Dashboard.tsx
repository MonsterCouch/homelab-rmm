import { useMemo } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import type { Agent, ComplianceSummary, Task } from '../api/types';
import { useAsync, useInterval, useLocalState } from '../hooks/useAsync';
import { useLiveReload } from '../hooks/useEvents';
import { describeCron } from '../lib/cron';
import { duration, relTime } from '../lib/format';
import { useAuth } from '../state/auth';
import { ComplianceChip } from '../components/baselines/state';
import { Bar, Button, Chip, Empty, ErrorBox, RunStatusChip, SeverityChip, Skeleton } from '../components/ui';
import '../styles/mobile-pages.css';

export function Dashboard() {
  const navigate = useNavigate();
  const d = useAsync(() => api.dashboard(), []);
  // The fleet list answers most of "what needs me now?" without a new endpoint:
  // who is offline, which disks are filling, who is behind on patches or agent
  // version. It is the same call the devices page makes.
  const agents = useAsync(() => api.agents(), []);
  const tasks = useAsync(() => api.tasks(), []);
  // Baselines are optional: a server that does not serve /api/compliance (an
  // older one, or a failed query) simply hides the tile rather than painting
  // an error across the dashboard.
  const compliance = useAsync(() => api.compliance().catch(() => undefined), []);
  useLiveReload(['agent_online', 'agent_offline', 'alert', 'run', 'patches', 'inventory', 'hello'], d.reload, { debounceMs: 600 });
  // Not on 'metrics': that is one event per device every 30 s, and refetching
  // the whole fleet list that often is a lot of work for a disk gauge.
  useLiveReload(['agent_online', 'agent_offline', 'inventory', 'patches'], agents.reload, { debounceMs: 5000 });
  useLiveReload(['baseline', 'hello'], compliance.reload, { debounceMs: 2000 });
  useInterval(d.reload, 60_000);
  useInterval(agents.reload, 120_000);

  const data = d.data;
  if (d.error && !data) return <ErrorBox error={d.error} onRetry={d.reload} />;
  // The server emits null for a list whose query failed; never let that crash the page.
  const recentAlerts = data?.recent_alerts ?? [];
  const recentRuns = data?.recent_runs ?? [];

  const total = data ? data.agents_online + data.agents_offline : 0;
  const other = data ? total - data.windows - data.linux : 0;

  return (
    <>
      <div className="page-head">
        <h1>Dashboard</h1>
        {data && <span className="muted small">Server up {duration(data.uptime)} · v{data.server_version}</span>}
      </div>
      {!data ? (
        <div className="card">
          <Skeleton rows={4} />
        </div>
      ) : (
        <>
          {/* The stat row comes first: on a phone it is the whole reason the
              app was opened, and the onboarding checklist below used to push
              the open-alert count more than a screen down. Each tile is a
              real <Link>, so it has middle-click, long-press and a real focus
              ring instead of a role="link" div. */}
          <div className="grid cols-4 mb">
            <Link className="card stat link" to="/devices?online=1">
              <span className="label">Devices online</span>
              <span className={`value ${data.agents_online > 0 ? 'ok' : ''}`}>{data.agents_online}</span>
              <span className="foot">{data.agents_offline} offline · {total} total</span>
            </Link>
            <Link className="card stat link" to="/alerts">
              <span className="label">Open alerts</span>
              <span className={`value ${data.critical_alerts > 0 ? 'danger' : data.open_alerts > 0 ? 'warn' : ''}`}>{data.open_alerts}</span>
              <span className="foot">{data.critical_alerts} critical · {data.open_alerts - data.critical_alerts} warning/info</span>
            </Link>
            <Link className="card stat link" to="/patches">
              <span className="label">Need patches</span>
              <span className={`value ${data.devices_need_patches > 0 ? 'warn' : ''}`}>{data.devices_need_patches}</span>
              <span className="foot">{data.pending_reboot} pending reboot</span>
            </Link>
            {/* The failed count is the reason to open this tile, so it carries the
                filter with it instead of dropping the reader in an unfiltered list. */}
            <Link className="card stat link" to={data.runs_failed_24h > 0 ? '/runs?status=failed' : '/runs'}>
              <span className="label">Runs (24h)</span>
              <span className="value">{data.runs_24h}</span>
              <span className="foot" style={data.runs_failed_24h > 0 ? { color: 'var(--danger)' } : undefined}>
                {data.runs_failed_24h} failed
              </span>
            </Link>
          </div>
          <GettingStarted devices={total} />
          <div className="grid cols-3">
            <div className="card" style={{ gridColumn: 'span 1' }}>
              <div className="card-head">
                Recent alerts
                <div className="actions">
                  <Link to="/alerts" className="small">
                    View all
                  </Link>
                </div>
              </div>
              <div className="list">
                {recentAlerts.map((a) => (
                  <div key={a.id} className="list-item">
                    <SeverityChip severity={a.severity} />
                    <div className="grow">
                      <div className="title truncate">{a.title}</div>
                      <div className="sub">
                        {a.agent_id ? <Link to={`/devices/${a.agent_id}`}>{a.agent_name || a.agent_id}</Link> : 'server'} · {relTime(a.opened_at)}
                      </div>
                    </div>
                  </div>
                ))}
                {!recentAlerts.length && <Empty title="No open alerts">Everything is quiet.</Empty>}
              </div>
            </div>
            <div className="card">
              <div className="card-head">
                Recent runs
                <div className="actions">
                  {data.runs_failed_24h > 0 && (
                    <Link to="/runs?status=failed" className="small" style={{ color: 'var(--danger)' }}>
                      {data.runs_failed_24h} failed
                    </Link>
                  )}
                  <Link to="/runs" className="small">
                    View all
                  </Link>
                </div>
              </div>
              <div className="list">
                {recentRuns.map((r) => (
                  <Link key={r.id} className="list-item" to={`/runs?id=${r.id}`}>
                    <RunStatusChip status={r.status} />
                    <div className="grow">
                      <div className="title truncate">{r.script_name}</div>
                      <div className="sub">
                        {r.agent_name || r.agent_id} · {r.trigger} · {relTime(r.started_at)}
                      </div>
                    </div>
                  </Link>
                ))}
                {!recentRuns.length && <Empty title="No runs yet">Run a script from the library to see it here.</Empty>}
              </div>
            </div>
            <div className="card">
              <div className="card-head">Fleet</div>
              <div className="card-body stack">
                <OSRow label="Windows" n={data.windows} total={total} color="var(--accent)" onClick={() => navigate('/devices?os=windows')} />
                <OSRow label="Linux" n={data.linux} total={total} color="var(--warn)" onClick={() => navigate('/devices?os=linux')} />
                {other > 0 && <OSRow label="Other" n={other} total={total} color="var(--text-faint)" />}
                <hr />
                <dl className="kv">
                  <dt>Online</dt>
                  <dd>
                    {data.agents_online} / {total}
                  </dd>
                  <dt>Pending reboot</dt>
                  <dd>{data.pending_reboot}</dd>
                  <dt>Devices needing patches</dt>
                  <dd>{data.devices_need_patches}</dd>
                </dl>
                {total === 0 && (
                  <div className="banner info" style={{ marginBottom: 0 }}>
                    <span>
                      No devices yet. <Link to="/devices?enroll=1">Enroll your first device</Link>.
                    </span>
                  </div>
                )}
              </div>
            </div>
          </div>
          <FleetWidgets agents={agents.data} tasks={tasks.data} compliance={compliance.data} />
        </>
      )}
    </>
  );
}

function OSRow({ label, n, total, color, onClick }: { label: string; n: number; total: number; color: string; onClick?: () => void }) {
  const pct = total ? (n / total) * 100 : 0;
  return (
    <div className="stack" style={{ gap: 4, cursor: onClick ? 'pointer' : undefined }} onClick={onClick}>
      <div className="row between">
        <span>{label}</span>
        <span className="muted small">
          {n} · {Math.round(pct)}%
        </span>
      </div>
      <span className="bar">
        <i style={{ width: `${pct}%`, background: color }} />
      </span>
    </div>
  );
}

// ---------- second row: what needs attention ----------

interface DiskRow {
  agent: Agent;
  mount: string;
  pct: number;
}

/**
 * Widgets derived from the fleet list and the task list. Each one is a
 * question the dashboard could not answer before (who is offline right now,
 * which disks are nearly full, how far the fleet is from patched, what runs
 * next, which agents are behind) and each hides itself when it has nothing to
 * say, rather than showing an empty box.
 */
function FleetWidgets({ agents, tasks, compliance: comp }: { agents: Agent[] | undefined; tasks: Task[] | undefined; compliance: ComplianceSummary | undefined }) {
  const offline = useMemo(() => (agents ?? []).filter((a) => !a.online).sort((x, y) => y.last_seen - x.last_seen).slice(0, 6), [agents]);
  const disks = useMemo(() => {
    const out: DiskRow[] = [];
    for (const a of agents ?? []) {
      for (const dk of a.last_metrics?.disks ?? []) out.push({ agent: a, mount: dk.mount, pct: dk.used_pct });
    }
    return out.sort((x, y) => y.pct - x.pct).filter((r) => r.pct >= 70).slice(0, 6);
  }, [agents]);
  const compliance = useMemo(() => {
    const list = agents ?? [];
    const pending = list.reduce((n, a) => n + a.patches_available, 0);
    return { total: list.length, ok: list.filter((a) => a.patches_available === 0).length, pending };
  }, [agents]);
  const next = useMemo(
    () => (tasks ?? []).filter((t) => t.enabled && t.next_run > 0).sort((x, y) => x.next_run - y.next_run).slice(0, 5),
    [tasks],
  );
  const versions = useMemo(() => {
    const m = new Map<string, number>();
    for (const a of agents ?? []) m.set(a.version || 'unknown', (m.get(a.version || 'unknown') ?? 0) + 1);
    return [...m.entries()].sort((x, y) => y[1] - x[1]);
  }, [agents]);

  const cards = [
    comp && (comp.by_baseline.length > 0 || comp.devices_with_baselines > 0) && (
      <div className="card" key="baselines" data-testid="tile-compliance">
        <div className="card-head">
          Baseline compliance
          <div className="actions">
            <Link to="/baselines" className="small">
              Baselines
            </Link>
          </div>
        </div>
        <div className="card-body stack">
          <div className="row between">
            <span className="row" style={{ gap: 8 }}>
              <ComplianceChip value={comp.score} />
              {/* The fleet score is the mean over the devices that HAVE
                  reported: a device with baselines and no report is in
                  devices_with_baselines and in devices_unknown, and counting
                  it here would read as "92% of all ten", which is the "no
                  data is not data" mistake A25 exists to prevent. */}
              <span className="muted small">
                mean over {comp.devices_with_baselines - comp.devices_unknown} of {comp.devices_with_baselines} device{comp.devices_with_baselines === 1 ? '' : 's'} with baselines
              </span>
            </span>
            <Link
              to="/alerts"
              className="small"
              style={comp.open_drift_alerts > 0 ? { color: 'var(--chip-danger)', fontWeight: 600 } : undefined}
              title="Open alerts raised by a baseline check"
            >
              {comp.open_drift_alerts} open drift alert{comp.open_drift_alerts === 1 ? '' : 's'}
            </Link>
          </div>
          {/* A null score is "nothing applicable has reported", which is NOT
              0% (A25): a zero-width bar under a "—" chip reads as a fleet
              that is 0% compliant. Say what is actually missing instead. */}
          {comp.score === null ? (
            <span className="muted small">No applicable check has reported yet, so there is no fleet score.</span>
          ) : (
            <Bar value={comp.score} warn={101} danger={101} title={`Fleet compliance ${comp.score}%`} />
          )}
          <dl className="kv">
            <dt>Devices drifted</dt>
            <dd style={comp.devices_drifted > 0 ? { color: 'var(--chip-danger)', fontWeight: 600 } : undefined}>
              {comp.devices_drifted} of {comp.devices_with_baselines}
            </dd>
            <dt>Not reported yet</dt>
            <dd>{comp.devices_unknown}</dd>
            <dt>Checks failing</dt>
            <dd>
              {comp.checks_failing} of {comp.checks_total}
              {comp.checks_error > 0 ? ` · ${comp.checks_error} errored` : ''}
            </dd>
            <dt>Baselines</dt>
            <dd>
              {comp.baselines_enabled} enabled · {comp.baselines_enforcing} enforcing
            </dd>
          </dl>
          {comp.worst_checks.length > 0 && (
            <div className="stack" style={{ gap: 4 }}>
              <span className="muted small">Worst checks</span>
              {comp.worst_checks.slice(0, 3).map((w) => (
                <div key={`${w.baseline_id}-${w.check_id}`} className="row between">
                  <Link to={`/baselines/${w.baseline_id}`} className="truncate small">
                    {w.check_name}
                  </Link>
                  <span className="muted small nowrap">
                    {w.failing}/{w.applicable} failing
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    ),
    offline.length > 0 && (
      <div className="card" key="offline">
        <div className="card-head">
          Offline devices
          <div className="actions">
            <Link to="/devices?online=0" className="small">
              View all
            </Link>
          </div>
        </div>
        <div className="list">
          {offline.map((a) => (
            <div key={a.id} className="list-item">
              <span className="dot off" />
              <div className="grow">
                <div className="title truncate">
                  <Link to={`/devices/${a.id}`}>{a.display_name}</Link>
                </div>
                <div className="sub">last seen {relTime(a.last_seen)}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    ),
    disks.length > 0 && (
      <div className="card" key="disks">
        <div className="card-head">Disks filling up</div>
        <div className="list">
          {disks.map((r) => (
            <div key={`${r.agent.id}|${r.mount}`} className="list-item">
              <div className="grow">
                <div className="title truncate">
                  <Link to={`/devices/${r.agent.id}`}>{r.agent.display_name}</Link> <span className="muted small mono">{r.mount}</span>
                </div>
                <Bar value={r.pct} />
              </div>
              <span className="mono small">{Math.round(r.pct)}%</span>
            </div>
          ))}
        </div>
      </div>
    ),
    compliance.total > 0 && (
      <div className="card" key="compliance">
        <div className="card-head">
          Patch compliance
          <div className="actions">
            <Link to="/patches" className="small">
              Patches
            </Link>
          </div>
        </div>
        <div className="card-body stack">
          <div className="row between">
            <span>Fully patched</span>
            <span className="muted small">
              {compliance.ok} / {compliance.total}
            </span>
          </div>
          <Bar value={(compliance.ok / compliance.total) * 100} warn={101} danger={101} />
          <dl className="kv">
            <dt>Updates pending</dt>
            <dd>{compliance.pending}</dd>
            <dt>Devices with updates</dt>
            <dd>{compliance.total - compliance.ok}</dd>
          </dl>
        </div>
      </div>
    ),
    next.length > 0 && (
      <div className="card" key="next">
        <div className="card-head">
          Next scheduled
          <div className="actions">
            <Link to="/tasks" className="small">
              Tasks
            </Link>
          </div>
        </div>
        <div className="list">
          {next.map((t) => (
            <div key={t.id} className="list-item">
              <div className="grow">
                <div className="title truncate">{t.name}</div>
                <div className="sub">{describeCron(t.schedule)}</div>
              </div>
              <span className="muted small nowrap">{relTime(t.next_run)}</span>
            </div>
          ))}
        </div>
      </div>
    ),
    versions.length > 1 && (
      <div className="card" key="versions">
        <div className="card-head">Agent versions</div>
        <div className="list">
          {versions.map(([v, n]) => (
            <div key={v} className="list-item">
              <Chip outline>{v}</Chip>
              <span className="grow" />
              <span className="muted small">{n} device{n === 1 ? '' : 's'}</span>
            </div>
          ))}
        </div>
      </div>
    ),
  ].filter(Boolean);

  if (!cards.length) return null;
  return (
    <div className="grid cols-3" style={{ marginTop: 14 }}>
      {cards}
    </div>
  );
}

// ---------- first-run checklist ----------

interface Step {
  id: string;
  label: string;
  done: boolean;
  to: string;
  hint: string;
}

/**
 * What decides whether this install is actually useful, in order: a device, a
 * public URL that is not loopback (every install one-liner embeds it), mail so
 * alerts leave the box, 2FA on the account that can do anything, and a patch
 * policy. Each item is driven by real state, so it ticks itself.
 */
function GettingStarted({ devices }: { devices: number }) {
  const { user, isAdmin, canWrite } = useAuth();
  const [dismissed, setDismissed] = useLocalState(`rmm.gettingStarted.${user?.id ?? 0}`, false);
  const system = useAsync(() => api.system(), [], { enabled: canWrite && !dismissed });
  const policies = useAsync(() => api.patchPolicies(), [], { enabled: canWrite && !dismissed });
  // Mail settings are admin-only; a tech gets the rest of the list.
  const settings = useAsync(() => api.settings(), [], { enabled: isAdmin && !dismissed });

  if (!canWrite || dismissed) return null;

  const url = system.data?.public_url ?? '';
  const loopback = /\/\/(127\.0\.0\.1|localhost|\[::1\])(:|\/|$)/i.test(url);
  const steps: Step[] = [
    { id: 'device', label: 'Enroll a device', done: devices > 0, to: '/devices?enroll=1', hint: 'The install one-liner is in the enroll drawer.' },
    {
      id: 'url',
      label: 'Set the public URL agents dial',
      done: !!url && !loopback,
      to: '/settings',
      hint: loopback ? `Currently ${url} — only this machine can reach that.` : 'Agents connect to this address, and it is baked into every install command.',
    },
    ...(isAdmin ? [{ id: 'smtp', label: 'Send alert email', done: !!settings.data?.smtp.enabled, to: '/settings', hint: 'Without SMTP an alert only exists in this console.' }] : []),
    { id: 'totp', label: 'Turn on two-factor for your account', done: !!user?.totp_enabled, to: '/account', hint: 'This console can run code as SYSTEM on every device.' },
    { id: 'patch', label: 'Schedule patch scans', done: (policies.data ?? []).some((p) => p.enabled), to: '/patches?tab=policies', hint: 'A policy scans its targets on a schedule.' },
  ];
  const left = steps.filter((s) => !s.done);
  if (!left.length) return null;

  return (
    <div className="card mb checklist">
      <div className="card-head">
        Getting started
        <span className="muted small">
          {steps.length - left.length} of {steps.length} done
        </span>
        <div className="actions">
          <Button size="xs" variant="ghost" onClick={() => setDismissed(true)}>
            Dismiss
          </Button>
        </div>
      </div>
      <div className="list">
        {steps.map((s) => (
          <div key={s.id} className="list-item">
            <span className={`tick ${s.done ? 'done' : ''}`}>{s.done ? '✓' : ''}</span>
            <div className="grow">
              <div className="title">
                {s.done ? s.label : <Link to={s.to}>{s.label}</Link>}
              </div>
              {!s.done && <div className="sub">{s.hint}</div>}
            </div>
          </div>
        ))}
      </div>
      <div className="tbl-foot">
        <span>
          A starter library is already here: seeded scripts on <Link to="/scripts">Scripts</Link>, alert rules on <Link to="/alerts?tab=rules">Alerts</Link>.
        </span>
      </div>
    </div>
  );
}
