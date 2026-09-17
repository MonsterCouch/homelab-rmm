import { useEffect, useRef, useState } from 'react';
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
import { Compliance } from './Compliance';
import '../../styles/mobile-pages.css';

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
  // No needsOnline: the last known compliance of a device that is not
  // answering is exactly what this tab is for.
  { id: 'compliance', label: 'Compliance' },
  { id: 'runs', label: 'Runs' },
  { id: 'events', label: 'Events' },
];

type TabId = 'overview' | 'terminal' | 'desktop' | 'processes' | 'services' | 'software' | 'files' | 'eventlog' | 'patches' | 'compliance' | 'runs' | 'events';

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

  const activeTab: TabId = (TABS.find((t) => t.id === tab)?.id ?? 'overview') as TabId;
  // Twelve tabs are 985px of strip in a 366px box, so opening
  // /devices/<id>/events directly would otherwise leave the active tab at
  // left 933 with scrollLeft 0 — off-screen and unsignalled. The strip only
  // exists once the agent has loaded, hence the id in the dependencies.
  const tabsRef = useRef<HTMLDivElement>(null);
  const agentId = agent.data?.id;
  useEffect(() => {
    const el = tabsRef.current?.querySelector<HTMLElement>('a.active');
    if (!el) return;
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    el.scrollIntoView({ inline: 'center', block: 'nearest', behavior: reduce ? 'auto' : 'smooth' });
  }, [activeTab, agentId]);

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
          {/* Both the OS label and the last IP are on the Overview tab; on a
              phone they cost a row of a head that repeats on all twelve
              tabs, so mobile-pages.css hides them below 700px. */}
          <span className="row dev-os" style={{ gap: 6 }}>
            <OSIcon os={a.os} />
            <span className="muted">{a.platform || osLabel(a.os)}</span>
          </span>
          <span className="muted mono small dev-ip">{a.last_ip}</span>
          {a.group_name && <Chip outline>{a.group_name}</Chip>}
          {a.pending_reboot && <Chip tone="warn">reboot required</Chip>}
          {a.maintenance_until > Date.now() / 1000 && <Chip tone="purple">maintenance until {relTime(a.maintenance_until)}</Chip>}
          {!a.online && <span className="muted small">last seen {relTime(a.last_seen)}</span>}
        </div>
        {canWrite && (
          <>
            {/* Below 700px these three fold into the More menu, so the head
                is one row: breadcrumb + dot + name, Power, More. */}
            <Button size="sm" className="dev-head-btn" onClick={() => setRunOpen(true)} disabled={!a.online}>
              Run script
            </Button>
            <Button size="sm" className="dev-head-btn" onClick={doRefresh} disabled={!a.online} title="Refresh inventory">
              <IconRefresh /> Inventory
            </Button>
            {!a.online && (
              <Button size="sm" className="dev-head-btn" onClick={doWol} title="Wake-on-LAN via another agent on the subnet">
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
              {/* The phone home for the buttons hidden above. Rendered
                  always, displayed only below 700px, so the menu needs no
                  media-query state in JS. */}
              <button className="phone-only" disabled={!a.online} onClick={() => setRunOpen(true)}>
                Run script
              </button>
              <button className="phone-only" disabled={!a.online} onClick={doRefresh}>
                Refresh inventory
              </button>
              <hr className="phone-only" />
              <button onClick={doWol}>Wake-on-LAN</button>
              <hr />
              <button className="danger" onClick={doDelete}>
                Delete device
              </button>
            </Dropdown>
          </>
        )}
      </div>
      <div className="tabs" ref={tabsRef}>
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
          {activeTab === 'compliance' && <Compliance {...tabProps} />}
          {activeTab === 'runs' && <DeviceRuns {...tabProps} />}
          {activeTab === 'events' && <DeviceEvents {...tabProps} />}
        </>
      )}
      {power && <PowerDialog action={power} targetLabel={a.display_name} onClose={() => setPower(null)} onConfirm={doPower} />}
      {runOpen && <RunDialog onClose={() => setRunOpen(false)} agentId={a.id} />}
    </>
  );
}
