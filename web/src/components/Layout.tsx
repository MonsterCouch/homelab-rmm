import { useEffect, useMemo, useRef, useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import type { Agent } from '../api/types';
import { useAsync } from '../hooks/useAsync';
import { useEventBus, useLiveReload } from '../hooks/useEvents';
import { useTheme } from '../hooks/useTheme';
import { osLabel } from '../lib/format';
import { useAuth } from '../state/auth';
import { textMatch } from './DataTable';
import {
  IconAlert,
  IconAudit,
  IconAutomation,
  IconDashboard,
  IconDevices,
  IconLogout,
  IconMoon,
  IconPatch,
  IconRuns,
  IconScript,
  IconSearch,
  IconSettings,
  IconSun,
  IconTasks,
  IconUser,
  IconUsers,
} from './Icons';
import { Button, Dropdown, ErrorBoundary, OnlineDot } from './ui';

const NAV = [
  { to: '/', label: 'Dashboard', icon: IconDashboard, end: true },
  { to: '/devices', label: 'Devices', icon: IconDevices },
  { to: '/scripts', label: 'Scripts', icon: IconScript },
  { to: '/runs', label: 'Runs', icon: IconRuns },
  { to: '/tasks', label: 'Tasks', icon: IconTasks },
  { to: '/automations', label: 'Automations', icon: IconAutomation },
  { to: '/alerts', label: 'Alerts', icon: IconAlert, badge: true },
  { to: '/patches', label: 'Patches', icon: IconPatch },
];
const ADMIN_NAV = [
  { to: '/settings', label: 'Settings', icon: IconSettings },
  { to: '/users', label: 'Users', icon: IconUsers },
];
const TAIL_NAV = [
  { to: '/audit', label: 'Audit', icon: IconAudit },
  { to: '/account', label: 'Account', icon: IconUser },
];

export function Layout() {
  const { user, isAdmin, logout, version } = useAuth();
  const [theme, toggleTheme] = useTheme();
  const navigate = useNavigate();

  // Open-alert badge: cheap dashboard call, refreshed on alert events.
  const dash = useAsync(() => api.dashboard(), []);
  useLiveReload(['alert', 'hello'], dash.reload, { debounceMs: 800 });
  const openAlerts = dash.data?.open_alerts ?? 0;

  return (
    <div className="app">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <nav className="nav" aria-label="Main">
        <div className="nav-brand">
          <span className="logo">R</span>
          <span>Homelab RMM</span>
        </div>
        <div className="nav-section">Manage</div>
        {NAV.map((n) => (
          <NavLink key={n.to} to={n.to} end={n.end} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`} title={n.label} aria-label={n.label}>
            <n.icon />
            <span>{n.label}</span>
            {n.badge && openAlerts > 0 && <span className="badge">{openAlerts}</span>}
          </NavLink>
        ))}
        {isAdmin && (
          <>
            <div className="nav-section">Admin</div>
            {ADMIN_NAV.map((n) => (
              <NavLink key={n.to} to={n.to} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`} title={n.label} aria-label={n.label}>
                <n.icon />
                <span>{n.label}</span>
              </NavLink>
            ))}
          </>
        )}
        <div className="nav-section">You</div>
        {TAIL_NAV.map((n) => (
          <NavLink key={n.to} to={n.to} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`} title={n.label} aria-label={n.label}>
            <n.icon />
            <span>{n.label}</span>
          </NavLink>
        ))}
        <div className="nav-foot">
          <ConnState />
          <div>v{version || 'dev'}</div>
        </div>
      </nav>
      <header className="topbar">
        <GlobalSearch />
        <span className="spacer" />
        <Button variant="ghost" icon onClick={toggleTheme} title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'} aria-label="Toggle theme">
          {theme === 'dark' ? <IconSun /> : <IconMoon />}
        </Button>
        <Dropdown
          trigger={
            <button className="btn ghost" style={{ gap: 8 }} aria-label="User menu">
              <span className="avatar">{(user?.username ?? '?').slice(0, 2).toUpperCase()}</span>
              <span>{user?.username}</span>
              <span className="chip outline">{user?.role}</span>
            </button>
          }
        >
          <button onClick={() => navigate('/account')}>
            <IconUser /> Account
          </button>
          <hr />
          <button
            onClick={async () => {
              await logout();
              navigate('/login');
            }}
          >
            <IconLogout /> Sign out
          </button>
        </Dropdown>
      </header>
      <main className="main" id="main" tabIndex={-1}>
        <ErrorBoundary>
          <Outlet />
        </ErrorBoundary>
      </main>
    </div>
  );
}

function ConnState() {
  const bus = useEventBus();
  const [ok, setOk] = useState(false);
  const [ever, setEver] = useState(false);
  useEffect(() => {
    const tick = () => {
      const c = bus?.connected() ?? false;
      setOk(c);
      if (c) setEver(true);
    };
    tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, [bus]);
  return (
    <div className="row" style={{ gap: 6 }}>
      <span className={`dot ${ok ? 'on' : 'warn'}`} /> {ok ? 'Live updates on' : ever ? 'Reconnecting…' : 'Connecting…'}
    </div>
  );
}

function GlobalSearch() {
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const navigate = useNavigate();
  const agents = useAsync(() => api.agents(), [], { enabled: open || q.length > 0 });
  useLiveReload(['agent_online', 'agent_offline', 'inventory'], agents.reload, { debounceMs: 2000 });
  const ref = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const results = useMemo(() => {
    if (!q.trim() || !agents.data) return [];
    return agents.data.filter((a: Agent) => textMatch(q, a.display_name, a.hostname, a.last_ip, a.group_name, a.platform, ...a.tags)).slice(0, 8);
  }, [q, agents.data]);

  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      // "/" focuses the search unless typing in a field (or driving the remote desktop)
      const t = e.target as HTMLElement | null;
      const editing = t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement || t instanceof HTMLSelectElement || !!t?.isContentEditable;
      if (e.key === '/' && !editing && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, []);

  const go = (a: Agent) => {
    navigate(`/devices/${a.id}`);
    setQ('');
    setOpen(false);
  };

  return (
    <div className="search" ref={ref}>
      <IconSearch />
      <input
        ref={inputRef}
        type="search"
        placeholder="Search devices by name, IP or tag…  ( / )"
        value={q}
        aria-label="Search devices"
        onChange={(e) => {
          setQ(e.target.value);
          setOpen(true);
          setActive(0);
        }}
        onFocus={() => setOpen(true)}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown') {
            e.preventDefault();
            setActive((i) => Math.min(results.length - 1, i + 1));
          } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            setActive((i) => Math.max(0, i - 1));
          } else if (e.key === 'Enter' && results[active]) {
            go(results[active]);
          } else if (e.key === 'Escape') {
            setOpen(false);
            inputRef.current?.blur();
          }
        }}
      />
      {open && q.trim() && (
        <div className="search-results" role="listbox">
          {results.map((a, i) => (
            <div key={a.id} className={`item ${i === active ? 'active' : ''}`} role="option" aria-selected={i === active} onMouseDown={() => go(a)}>
              <OnlineDot online={a.online} />
              <span>{a.display_name}</span>
              <span className="meta">
                {a.last_ip} · {osLabel(a.os)}
                {a.group_name ? ` · ${a.group_name}` : ''}
              </span>
            </div>
          ))}
          {!results.length && <div className="item muted">{agents.loading ? 'Searching…' : 'No matching devices'}</div>}
        </div>
      )}
    </div>
  );
}
