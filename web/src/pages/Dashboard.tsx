import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { useAsync, useInterval } from '../hooks/useAsync';
import { useLiveReload } from '../hooks/useEvents';
import { duration, relTime } from '../lib/format';
import { Empty, ErrorBox, RunStatusChip, SeverityChip, Skeleton } from '../components/ui';

export function Dashboard() {
  const navigate = useNavigate();
  const d = useAsync(() => api.dashboard(), []);
  useLiveReload(['agent_online', 'agent_offline', 'alert', 'run', 'patches', 'inventory', 'hello'], d.reload, { debounceMs: 600 });
  useInterval(d.reload, 60_000);

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
          <div className="grid cols-4 mb">
            <div className="card stat link" role="link" tabIndex={0} onClick={() => navigate('/devices?online=1')} onKeyDown={(e) => e.key === 'Enter' && navigate('/devices?online=1')}>
              <span className="label">Devices online</span>
              <span className={`value ${data.agents_online > 0 ? 'ok' : ''}`}>{data.agents_online}</span>
              <span className="foot">{data.agents_offline} offline · {total} total</span>
            </div>
            <div className="card stat link" role="link" tabIndex={0} onClick={() => navigate('/alerts')} onKeyDown={(e) => e.key === 'Enter' && navigate('/alerts')}>
              <span className="label">Open alerts</span>
              <span className={`value ${data.critical_alerts > 0 ? 'danger' : data.open_alerts > 0 ? 'warn' : ''}`}>{data.open_alerts}</span>
              <span className="foot">{data.critical_alerts} critical · {data.open_alerts - data.critical_alerts} warning/info</span>
            </div>
            <div className="card stat link" role="link" tabIndex={0} onClick={() => navigate('/patches')} onKeyDown={(e) => e.key === 'Enter' && navigate('/patches')}>
              <span className="label">Need patches</span>
              <span className={`value ${data.devices_need_patches > 0 ? 'warn' : ''}`}>{data.devices_need_patches}</span>
              <span className="foot">{data.pending_reboot} pending reboot</span>
            </div>
            <div className="card stat link" role="link" tabIndex={0} onClick={() => navigate('/runs')} onKeyDown={(e) => e.key === 'Enter' && navigate('/runs')}>
              <span className="label">Runs (24h)</span>
              <span className="value">{data.runs_24h}</span>
              <span className="foot" style={data.runs_failed_24h > 0 ? { color: 'var(--danger)' } : undefined}>
                {data.runs_failed_24h} failed
              </span>
            </div>
          </div>
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
                  <Link to="/runs" className="small">
                    View all
                  </Link>
                </div>
              </div>
              <div className="list">
                {recentRuns.map((r) => (
                  <div key={r.id} className="list-item" style={{ cursor: 'pointer' }} role="link" tabIndex={0} onClick={() => navigate(`/runs?id=${r.id}`)} onKeyDown={(e) => e.key === 'Enter' && navigate(`/runs?id=${r.id}`)}>
                    <RunStatusChip status={r.status} />
                    <div className="grow">
                      <div className="title truncate">{r.script_name}</div>
                      <div className="sub">
                        {r.agent_name || r.agent_id} · {r.trigger} · {relTime(r.started_at)}
                      </div>
                    </div>
                  </div>
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
                      No devices yet. <Link to="/devices?enroll=1">Enrol your first device</Link>.
                    </span>
                  </div>
                )}
              </div>
            </div>
          </div>
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
