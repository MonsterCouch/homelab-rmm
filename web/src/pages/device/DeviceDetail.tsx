import { useState } from 'react';
import { Link, NavLink, useNavigate, useParams } from 'react-router-dom';
import { api, ApiError } from '../../api/client';
import type { Agent, Metrics, PowerAction } from '../../api/types';
import { IconMore, IconPower, IconRefresh, IconWifi } from '../../components/Icons';
import { useConfirm } from '../../components/Modal';
import { PowerDialog } from '../../components/PowerDialog';
import { RunDialog } from '../../components/RunDialog';
import { Button, Chip, Dropdown, ErrorBox, Loading, OnlineDot } from '../../components/ui';
import { useAsync } from '../../hooks/useAsync';
import { useEvents, useLiveReload } from '../../hooks/useEvents';
import { osLabel, relTime } from '../../lib/format';
import { useAuth } from '../../state/auth';
import { errMsg, useToast } from '../../state/toast';
import { OSIcon } from '../Devices';
import { Overview } from './Overview';
import { Terminal } from './Terminal';
import { Desktop } from './Desktop';
import { Processes } from './Processes';
import { Services } from './Services';
import { SoftwareTab } from './SoftwareTab';
import { Files } from './Files';
import { EventLog } from './EventLog';
import { DevicePatches } from './DevicePatches';
import { DeviceRuns } from './DeviceRuns';
import { DeviceEvents } from './DeviceEvents';

export interface TabProps {
  agent: Agent;
  reload: () => Promise<void>;
  canWrite: boolean;
}

const TABS: readonly { id: string; label: string; needsOnline?: boolean }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'terminal', label: 'Terminal', needsOnline: true },
  { id: 'desktop', label: 'Remote Desktop', needsOnline: true },
  { id: 'processes', label: 'Processes', needsOnline: true },
  { id: 'services', label: 'Services', needsOnline: true },
  { id: 'software', label: 'Software' },
  { id: 'files', label: 'Files', needsOnline: true },
  { id: 'eventlog', label: 'Event log', needsOnline: true },
  { id: 'patches', label: 'Patches' },
  { id: 'runs', label: 'Runs' },
  { id: 'events', label: 'Events' },
];

type TabId = 'overview' | 'terminal' | 'desktop' | 'processes' | 'services' | 'software' | 'files' | 'eventlog' | 'patches' | 'runs' | 'events';

export function DeviceDetail() {
  const { id = '', tab = 'overview' } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const confirm = useConfirm();
  const { canWrite } = useAuth();
  const agent = useAsync(() => api.agent(id), [id]);
  useLiveReload(['agent_online', 'agent_offline', 'inventory', 'alert', 'patches', 'hello'], agent.reload, { agentId: id, debounceMs: 500 });
  useEvents(['metrics'], (ev) => {
    if (ev.agent_id !== id) return;
    const m = ev.data as Metrics | undefined;
    if (m) agent.setData((a) => (a ? { ...a, last_metrics: m, online: true, pending_reboot: m.pending_reboot } : a));
  });
  const [power, setPower] = useState<PowerAction | null>(null);
  const [runOpen, setRunOpen] = useState(false);

  const a = agent.data;
  if (agent.error && !a) {
    const notFound = agent.error.toLowerCase().includes('not found');
    return (
      <>
        <div className="page-head">
          <Link to="/devices">← Devices</Link>
        </div>
        <ErrorBox error={notFound ? 'This device no longer exists.' : agent.error} onRetry={notFound ? undefined : agent.reload} />
      </>
    );
  }
  if (!a) return <Loading />;

  const activeTab: TabId = (TABS.find((t) => t.id === tab)?.id ?? 'overview') as TabId;
  const needsOnline = TABS.find((t) => t.id === activeTab)?.needsOnline;

  const doRefresh = async () => {
    try {
      await api.refreshAgent(a.id);
      toast.success('Inventory refresh requested');
    } catch (err) {
      toast.error('Refresh failed', errMsg(err));
    }
  };
  const doWol = async () => {
    try {
      const r = await api.wol(a.id);
      toast.success('Magic packet sent', `via ${r.via} to ${r.macs.join(', ')}`);
    } catch (err) {
      toast.error('Wake-on-LAN failed', errMsg(err));
    }
  };
  const doDelete = async () => {
    if (
      !(await confirm({
        title: 'Delete device',
        message: `Remove "${a.display_name}" and all of its history? The agent on the device keeps running until uninstalled and will be rejected.`,
        danger: true,
        confirmLabel: 'Delete device',
      }))
    )
      return;
    try {
      await api.deleteAgent(a.id);
      toast.success('Device deleted');
      navigate('/devices');
    } catch (err) {
      toast.error('Delete failed', errMsg(err));
    }
  };
  const doPower = async (delay: number, message: string) => {
    if (!power) return;
    try {
      await api.power(a.id, power, delay, message);
      toast.success(`${power} sent`, delay ? `in ${delay}s` : undefined);
    } catch (err) {
      toast.error(`${power} failed`, err instanceof ApiError && err.status === 409 ? 'The device is offline.' : errMsg(err));
      throw err;
    }
  };

  const tabProps: TabProps = { agent: a, reload: agent.reload, canWrite };

  return (
    <>
      <div className="page-head" style={{ marginBottom: 10 }}>
        <div className="row" style={{ marginRight: 'auto', gap: 10 }}>
          <Link to="/devices" className="muted small">
            Devices
          </Link>
          <span className="faint">/</span>
          <OnlineDot online={a.online} />
          <h1>{a.display_name}</h1>
          <span className="row" style={{ gap: 6 }}>
            <OSIcon os={a.os} />
            <span className="muted">{a.platform || osLabel(a.os)}</span>
          </span>
          <span className="muted mono small">{a.last_ip}</span>
          {a.group_name && <Chip outline>{a.group_name}</Chip>}
          {a.pending_reboot && <Chip tone="warn">reboot required</Chip>}
          {a.maintenance_until > Date.now() / 1000 && <Chip tone="purple">maintenance until {relTime(a.maintenance_until)}</Chip>}
          {!a.online && <span className="muted small">last seen {relTime(a.last_seen)}</span>}
        </div>
        {canWrite && (
          <>
            <Button size="sm" onClick={() => setRunOpen(true)} disabled={!a.online}>
              Run script
            </Button>
            <Button size="sm" onClick={doRefresh} disabled={!a.online} title="Refresh inventory">
              <IconRefresh /> Inventory
            </Button>
            {!a.online && (
              <Button size="sm" onClick={doWol} title="Wake-on-LAN via another agent on the subnet">
                <IconWifi /> Wake
              </Button>
            )}
            <Dropdown
              trigger={
                <button className="btn sm" disabled={!a.online}>
                  <IconPower /> Power
                </button>
              }
            >
              <button onClick={() => setPower('reboot')}>Reboot…</button>
              <button onClick={() => setPower('shutdown')}>Shut down…</button>
              <button onClick={() => setPower('lock')}>Lock session…</button>
              <button onClick={() => setPower('logoff')}>Log off…</button>
            </Dropdown>
            <Dropdown
              trigger={
                <button className="btn sm icon" aria-label="More">
                  <IconMore />
                </button>
              }
            >
              <button onClick={doWol}>Wake-on-LAN</button>
              <hr />
              <button className="danger" onClick={doDelete}>
                Delete device
              </button>
            </Dropdown>
          </>
        )}
      </div>
      <div className="tabs">
        {TABS.map((t) => (
          <NavLink key={t.id} to={`/devices/${a.id}${t.id === 'overview' ? '' : `/${t.id}`}`} end className={({ isActive }) => (isActive ? 'active' : '')}>
            {t.label}
            {t.id === 'patches' && a.patches_available > 0 && <span className="count">{a.patches_available}</span>}
          </NavLink>
        ))}
      </div>
      {needsOnline && !a.online ? (
        <div className="banner warn">
          <span>This device is offline; {TABS.find((t) => t.id === activeTab)?.label.toLowerCase()} needs a live connection.</span>
        </div>
      ) : (
        <>
          {activeTab === 'overview' && <Overview {...tabProps} />}
          {activeTab === 'terminal' && <Terminal {...tabProps} />}
          {activeTab === 'desktop' && <Desktop {...tabProps} />}
          {activeTab === 'processes' && <Processes {...tabProps} />}
          {activeTab === 'services' && <Services {...tabProps} />}
          {activeTab === 'software' && <SoftwareTab {...tabProps} />}
          {activeTab === 'files' && <Files {...tabProps} />}
          {activeTab === 'eventlog' && <EventLog {...tabProps} />}
          {activeTab === 'patches' && <DevicePatches {...tabProps} />}
          {activeTab === 'runs' && <DeviceRuns {...tabProps} />}
          {activeTab === 'events' && <DeviceEvents {...tabProps} />}
        </>
      )}
      {power && <PowerDialog action={power} targetLabel={a.display_name} onClose={() => setPower(null)} onConfirm={doPower} />}
      {runOpen && <RunDialog onClose={() => setRunOpen(false)} agentId={a.id} />}
    </>
  );
}
