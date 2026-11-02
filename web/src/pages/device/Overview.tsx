import { Fragment, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../../api/client';
import type { Agent, AgentUpdate, MetricRow, Metrics } from '../../api/types';
import { TimeSeriesChart } from '../../components/Charts';
import { Bar, Button, Chip, ErrorBox, Field, KeyValueEditor, SeverityChip, Switch, TagInput } from '../../components/ui';
import { useAsync, useLocalState } from '../../hooks/useAsync';
import { useEvents, useLiveReload } from '../../hooks/useEvents';
import { bps, bytes, dateTime, duration, fromLocalInput, num, pct, relTime, toLocalInput } from '../../lib/format';
import { errMsg, useToast } from '../../state/toast';
import type { TabProps } from './DeviceDetail';

const RANGES: { id: string; label: string; secs: number }[] = [
  { id: '1h', label: '1h', secs: 3600 },
  { id: '6h', label: '6h', secs: 6 * 3600 },
  { id: '24h', label: '24h', secs: 86400 },
  { id: '7d', label: '7d', secs: 7 * 86400 },
  { id: '30d', label: '30d', secs: 30 * 86400 },
];

export function Overview({ agent, reload, canWrite }: TabProps) {
  const inv = agent.inventory;
  const m = agent.last_metrics;
  // .grid.aside, not an inline gridTemplateColumns: an inline style cannot be
  // reached by the phone media query, and at 390px this one computed to
  // "352px 0px" - every live stat tile, chart, disk and interface was laid out
  // off-screen. The class also collapses to one column below 700px and moves
  // this first column (the identity form) after the stats and charts.
  return (
    <div className="grid aside">
      <div className="stack" style={{ gap: 14 }}>
        <IdentityCard agent={agent} reload={reload} canWrite={canWrite} />
        <div className="card">
          <div className="card-head">Hardware</div>
          <div className="card-body">
            {inv ? (
              <dl className="kv">
                <dt>Manufacturer</dt>
                <dd>{inv.manufacturer || '—'}</dd>
                <dt>Model</dt>
                <dd>{inv.model || '—'}</dd>
                <dt>Serial</dt>
                <dd className="mono">{inv.serial || '—'}</dd>
                <dt>BIOS</dt>
                <dd>{inv.bios_version || '—'}</dd>
                <dt>CPU</dt>
                <dd>
                  {inv.cpu_model || '—'}
                  {inv.cpu_cores ? (
                    <span className="muted">
                      {' '}
                      · {inv.cpu_cores}c/{inv.cpu_threads}t
                    </span>
                  ) : null}
                </dd>
                <dt>Memory</dt>
                <dd>{bytes(inv.mem_total)}</dd>
                {inv.gpus?.length ? (
                  <>
                    <dt>GPU</dt>
                    <dd>{inv.gpus.join(', ')}</dd>
                  </>
                ) : null}
              </dl>
            ) : (
              <span className="muted">No inventory yet.</span>
            )}
          </div>
        </div>
        <div className="card">
          <div className="card-head">Operating system</div>
          <div className="card-body">
            {inv ? (
              <dl className="kv">
                <dt>Platform</dt>
                <dd>
                  {inv.platform} {inv.platform_version}
                </dd>
                <dt>Kernel</dt>
                <dd>{inv.kernel_version || '—'}</dd>
                <dt>Arch</dt>
                <dd>{inv.arch}</dd>
                <dt>Booted</dt>
                <dd>
                  {inv.boot_time ? `${dateTime(inv.boot_time)} (${duration(Date.now() / 1000 - inv.boot_time)})` : '—'}
                </dd>
                <dt>Timezone</dt>
                <dd>{inv.timezone || '—'}</dd>
                <dt>Domain</dt>
                <dd>{inv.domain || '—'}</dd>
                {inv.antivirus && (
                  <>
                    <dt>Antivirus</dt>
                    <dd>{inv.antivirus}</dd>
                  </>
                )}
                {inv.public_ip && (
                  <>
                    <dt>Public IP</dt>
                    <dd className="mono">{inv.public_ip}</dd>
                  </>
                )}
                <dt>Logged in</dt>
                <dd>{(m?.logged_in ?? inv.logged_in_users)?.join(', ') || <span className="muted">nobody</span>}</dd>
                {inv.last_user && (
                  <>
                    <dt>Last user</dt>
                    <dd>{inv.last_user}</dd>
                  </>
                )}
                {inv.cache && inv.cache.role && (
                  <>
                    <dt>Update cache</dt>
                    <dd title="Hits and misses count requests this device answered (leader) or fetches it made (member)">
                      <Chip tone={inv.cache.role === 'leader' ? 'info' : ''}>{inv.cache.role}</Chip>{' '}
                      <span className="muted">
                        {num(inv.cache.hits)} hits, {num(inv.cache.misses)} misses
                        {inv.cache.role === 'leader' ? `, ${bytes(inv.cache.bytes_served)} served, ${bytes(inv.cache.bytes_stored)} stored` : ''}
                      </span>
                    </dd>
                  </>
                )}
                <dt>Reboot</dt>
                <dd>{agent.pending_reboot ? <Chip tone="warn">pending</Chip> : <span className="muted">not required</span>}</dd>
                <dt>Collected</dt>
                <dd>{relTime(inv.collected_at)}</dd>
                {inv.extra &&
                  Object.entries(inv.extra).map(([k, v]) => (
                    <Fragment key={k}>
                      <dt>{k}</dt>
                      <dd>{v}</dd>
                    </Fragment>
                  ))}
              </dl>
            ) : (
              <span className="muted">No inventory yet.</span>
            )}
          </div>
        </div>
      </div>
      <div className="stack" style={{ gap: 14, minWidth: 0 }}>
        <LiveStats agent={agent} />
        <MetricsPanel agent={agent} />
        <DeviceAlerts agent={agent} />
        <div className="grid cols-2">
          <div className="card">
            <div className="card-head">Disks</div>
            <div className="card-body stack">
              {inv?.disks?.length ? (
                inv.disks.map((d) => {
                  const live = m?.disks?.find((x) => x.mount === d.mount);
                  const used = live?.used ?? d.used;
                  const p = live?.used_pct ?? d.used_pct;
                  return (
                    <div key={d.mount + d.device} className="stack" style={{ gap: 3 }}>
                      <div className="row between">
                        <span>
                          <b>{d.mount}</b> <span className="muted small">{d.device !== d.mount ? d.device : ''} {d.fs}</span>
                        </span>
                        <span className="muted small">
                          {bytes(used)} / {bytes(d.total)} · {pct(p)}
                        </span>
                      </div>
                      <Bar value={p} />
                    </div>
                  );
                })
              ) : (
                <span className="muted">No disks reported.</span>
              )}
            </div>
          </div>
          <div className="card">
            <div className="card-head">Network interfaces</div>
            <div className="card-body tight">
              {inv?.network?.length ? (
                <table className="tbl compact">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Addresses</th>
                      <th>MAC</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {inv.network.map((n) => (
                      <tr key={n.name + n.mac}>
                        <td>{n.name}</td>
                        <td className="mono wrap small">{n.ips?.join(', ') || '—'}</td>
                        <td className="mono small">{n.mac || '—'}</td>
                        <td>
                          <span className={`dot ${n.up ? 'on' : 'off'}`} title={n.up ? 'up' : 'down'} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="card-body muted">No interfaces reported.</div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function LiveStats({ agent }: { agent: Agent }) {
  const m = agent.last_metrics;
  const memP = m && m.mem_total ? (m.mem_used / m.mem_total) * 100 : undefined;
  return (
    <div className="grid cols-4">
      <div className="card stat">
        <span className="label">CPU</span>
        <span className="value">{agent.online && m ? pct(m.cpu) : '—'}</span>
        {/* Windows has no load average and the agent never collects one, so
            showing it there printed a hard-coded "load 0.00" that looked like
            a real measurement of a perpetually idle machine. */}
        <span className="foot">
          {agent.os === 'windows' ? '' : `load ${m?.load1?.toFixed(2) ?? '—'} · `}
          {num(m?.procs)} procs
        </span>
      </div>
      <div className="card stat">
        <span className="label">Memory</span>
        <span className="value">{agent.online && memP !== undefined ? pct(memP) : '—'}</span>
        <span className="foot">
          {bytes(m?.mem_used)} of {bytes(m?.mem_total)}
        </span>
      </div>
      <div className="card stat">
        <span className="label">Network</span>
        <span className="value" style={{ fontSize: 18 }}>
          {agent.online && m ? `↓ ${bps(m.net_rx)}` : '—'}
        </span>
        <span className="foot">{agent.online && m ? `↑ ${bps(m.net_tx)}` : ''}</span>
      </div>
      <div className="card stat">
        <span className="label">Uptime</span>
        <span className="value" style={{ fontSize: 20 }}>
          {agent.online && m ? duration(m.uptime) : '—'}
        </span>
        <span className="foot">{agent.online ? `sample ${relTime(m?.ts)}` : `offline since ${relTime(agent.last_seen)}`}</span>
      </div>
    </div>
  );
}

function MetricsPanel({ agent }: { agent: Agent }) {
  const [range, setRange] = useLocalState('rmm.metrics.range', '1h');
  const r = RANGES.find((x) => x.id === range) ?? RANGES[0];
  const [rows, setRows] = useState<MetricRow[]>([]);
  const hist = useAsync(
    async () => {
      const to = Math.floor(Date.now() / 1000);
      return api.agentMetrics(agent.id, to - r.secs, to, 400);
    },
    [agent.id, r.secs],
  );
  useEffect(() => {
    if (hist.data) setRows(hist.data);
  }, [hist.data]);

  // Append live samples for short ranges; long ranges are bucketed server-side, so refetch instead.
  useEvents(['metrics'], (ev) => {
    if (ev.agent_id !== agent.id) return;
    const mm = ev.data as Metrics | undefined;
    if (!mm) return;
    if (r.secs > 6 * 3600) return;
    setRows((prev) => {
      const cutoff = Math.floor(Date.now() / 1000) - r.secs;
      const next = prev.filter((x) => x.ts >= cutoff && x.ts < mm.ts);
      next.push({ ts: mm.ts, cpu: mm.cpu, mem_used: mm.mem_used, mem_total: mm.mem_total, disks: mm.disks, net_rx: mm.net_rx, net_tx: mm.net_tx, uptime: mm.uptime, load1: mm.load1, procs: mm.procs });
      return next;
    });
  });
  // Long ranges are bucketed server-side, so they are refetched instead of
  // appended to. A debounce would never fire while samples keep arriving
  // every 30 s, hence a throttle: at most one refetch per minute.
  const lastHist = useRef(0);
  useEvents(['metrics'], (ev) => {
    if (ev.agent_id !== agent.id || r.secs <= 6 * 3600) return;
    const now = Date.now();
    if (now - lastHist.current < 60_000) return;
    lastHist.current = now;
    void hist.reload();
  });

  const xs = useMemo(() => rows.map((x) => x.ts), [rows]);
  // Window pinned to the selected range; recomputed only when data arrives so
  // the chart is not redrawn on unrelated renders.
  const xRange = useMemo<[number, number]>(() => {
    const now = Math.floor(Date.now() / 1000);
    return [now - r.secs, now];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, r.secs]);
  const cpu = useMemo(() => [{ label: 'CPU %', values: rows.map((x) => x.cpu), color: cssColor('--chart-cpu'), fill: true }], [rows]);
  const mem = useMemo(() => [{ label: 'Memory %', values: rows.map((x) => (x.mem_total ? (x.mem_used / x.mem_total) * 100 : null)), color: cssColor('--chart-mem'), fill: true }], [rows]);
  const mounts = useMemo(() => Array.from(new Set(rows.flatMap((x) => (x.disks ?? []).map((d) => d.mount)))).slice(0, 6), [rows]);
  const disk = useMemo(
    () =>
      mounts.map((mnt, i) => ({
        label: mnt,
        values: rows.map((x) => x.disks?.find((d) => d.mount === mnt)?.used_pct ?? null),
        color: [cssColor('--chart-disk'), cssColor('--chart-cpu'), cssColor('--chart-mem'), cssColor('--chart-rx'), cssColor('--chart-tx'), '#e879f9'][i % 6],
      })),
    [rows, mounts],
  );
  const net = useMemo(
    () => [
      { label: 'Down', values: rows.map((x) => x.net_rx), color: cssColor('--chart-rx'), fill: true },
      { label: 'Up', values: rows.map((x) => x.net_tx), color: cssColor('--chart-tx') },
    ],
    [rows],
  );

  return (
    <div className="card">
      <div className="card-head">
        Metrics
        <div className="actions">
          <div className="btn-group">
            {RANGES.map((x) => (
              <button key={x.id} className={`btn sm ${x.id === r.id ? 'active' : ''}`} onClick={() => setRange(x.id)}>
                {x.label}
              </button>
            ))}
          </div>
        </div>
      </div>
      <div className="card-body">
        {hist.error && <ErrorBox error={hist.error} onRetry={hist.reload} />}
        {rows.length === 0 && !hist.loading ? (
          <div className="empty">No samples in this range.</div>
        ) : (
          <div className="grid cols-2">
            <TimeSeriesChart xs={xs} series={cpu} range={[0, 100]} format={(v) => `${v.toFixed(0)}%`} title="CPU" height={140} xRange={xRange} />
            <TimeSeriesChart xs={xs} series={mem} range={[0, 100]} format={(v) => `${v.toFixed(0)}%`} title="Memory" height={140} xRange={xRange} />
            <TimeSeriesChart xs={xs} series={disk} range={[0, 100]} format={(v) => `${v.toFixed(0)}%`} title="Disk used" height={140} xRange={xRange} />
            <TimeSeriesChart xs={xs} series={net} format={(v) => bps(v)} title="Network" height={140} xRange={xRange} />
          </div>
        )}
      </div>
    </div>
  );
}

function cssColor(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || '#3b82f6';
}

function DeviceAlerts({ agent }: { agent: Agent }) {
  const toast = useToast();
  const alerts = useAsync(() => api.alerts('open', agent.id), [agent.id]);
  useLiveReload(['alert'], alerts.reload, { agentId: agent.id });
  if (!alerts.data?.length) return null;
  const act = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      void alerts.reload();
    } catch (err) {
      toast.error('Failed', errMsg(err));
    }
  };
  return (
    <div className="card">
      <div className="card-head">
        Open alerts <span className="badge">{alerts.data.length}</span>
        <div className="actions">
          <Link to="/alerts" className="small">
            All alerts
          </Link>
        </div>
      </div>
      <div className="list">
        {alerts.data.map((a) => (
          <div key={a.id} className="list-item">
            <SeverityChip severity={a.severity} />
            <div className="grow">
              <div className="title">{a.title}</div>
              <div className="sub">
                {a.message} · {relTime(a.opened_at)}
                {a.status === 'acked' && ` · acked by ${a.acked_by}`}
              </div>
            </div>
            {a.status === 'open' && (
              <Button size="sm" onClick={() => act(() => api.ackAlert(a.id))}>
                Ack
              </Button>
            )}
            <Button size="sm" onClick={() => act(() => api.resolveAlert(a.id))}>
              Resolve
            </Button>
          </div>
        ))}
      </div>
    </div>
  );
}

function IdentityCard({ agent, reload, canWrite }: TabProps) {
  const toast = useToast();
  const groups = useAsync(() => api.groups(), []);
  const [form, setForm] = useState(() => initial(agent));
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!dirty) setForm(initial(agent));
  }, [agent, dirty]);

  const upd = (patch: Partial<typeof form>) => {
    setForm((f) => ({ ...f, ...patch }));
    setDirty(true);
  };
  const save = async () => {
    setBusy(true);
    try {
      const u: AgentUpdate = {
        display_name: form.display_name,
        tags: form.tags,
        notes: form.notes,
        custom_fields: form.custom_fields,
        monitored_services: form.monitored_services,
        maintenance_until: form.maintenance ? form.maintenance_until || Math.floor(Date.now() / 1000) + 3600 : 0,
      };
      if (form.group === '') u.clear_group = true;
      else u.group_id = +form.group;
      await api.updateAgent(agent.id, u);
      setDirty(false);
      toast.success('Device saved');
      await reload();
    } catch (err) {
      toast.error('Save failed', errMsg(err));
    } finally {
      setBusy(false);
    }
  };
  const ro = !canWrite;
  return (
    <div className="card">
      <div className="card-head">
        Identity
        {dirty && (
          <div className="actions">
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setForm(initial(agent));
                setDirty(false);
              }}
            >
              Discard
            </Button>
            <Button size="sm" variant="primary" onClick={save} busy={busy}>
              Save
            </Button>
          </div>
        )}
      </div>
      <div className="card-body">
        <Field label="Display name">
          <input value={form.display_name} placeholder={agent.hostname} disabled={ro} onChange={(e) => upd({ display_name: e.target.value })} />
        </Field>
        <Field label="Group">
          <select value={form.group} disabled={ro} onChange={(e) => upd({ group: e.target.value })}>
            <option value="">No group</option>
            {(groups.data ?? []).map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Tags">
          <TagInput value={form.tags} disabled={ro} onChange={(tags) => upd({ tags })} placeholder="add tag…" />
        </Field>
        <Field label="Monitored services" hint="Service names whose state the agent reports every sample; the 'service' alert rule watches them.">
          <TagInput value={form.monitored_services} disabled={ro} onChange={(monitored_services) => upd({ monitored_services })} placeholder="e.g. sshd, Spooler" />
        </Field>
        <Field label="Notes">
          <textarea value={form.notes} disabled={ro} rows={3} onChange={(e) => upd({ notes: e.target.value })} />
        </Field>
        <Field label="Custom fields">
          <KeyValueEditor value={form.custom_fields} disabled={ro} onChange={(custom_fields) => upd({ custom_fields })} />
        </Field>
        <Field label="Maintenance mode" hint="Suppresses new alerts for this device until the time below.">
          <Switch checked={form.maintenance} disabled={ro} onChange={(v) => upd({ maintenance: v, maintenance_until: v && !form.maintenance_until ? Math.floor(Date.now() / 1000) + 3600 : form.maintenance_until })} label={form.maintenance ? 'On' : 'Off'} />
          {form.maintenance && (
            <input type="datetime-local" value={toLocalInput(form.maintenance_until || Math.floor(Date.now() / 1000) + 3600)} disabled={ro} onChange={(e) => upd({ maintenance_until: fromLocalInput(e.target.value) })} style={{ marginTop: 6 }} />
          )}
        </Field>
        <dl className="kv small muted">
          <dt>Agent ID</dt>
          <dd className="mono">{agent.id}</dd>
          <dt>Enrolled</dt>
          <dd>{dateTime(agent.enrolled_at)}</dd>
          <dt>Agent version</dt>
          <dd>
            {agent.version || '—'}
            {agent.inventory?.agent_path && <span className="muted mono small" style={{ marginLeft: 6 }}>({agent.inventory.agent_path})</span>}
          </dd>
        </dl>
      </div>
    </div>
  );
}

function initial(a: Agent) {
  return {
    display_name: a.display_name === a.hostname ? '' : a.display_name,
    group: a.group_id === null ? '' : String(a.group_id),
    tags: a.tags,
    notes: a.notes,
    custom_fields: a.custom_fields,
    monitored_services: a.monitored_services,
    maintenance: a.maintenance_until > Date.now() / 1000,
    maintenance_until: a.maintenance_until > Date.now() / 1000 ? a.maintenance_until : 0,
  };
}
