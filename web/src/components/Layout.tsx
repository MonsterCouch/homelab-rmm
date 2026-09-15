import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import type { Agent } from '../api/types';
import { useAsync } from '../hooks/useAsync';
import { useEventBus, useLiveReload } from '../hooks/useEvents';
import { useTheme } from '../hooks/useTheme';
import { osLabel, relTime } from '../lib/format';
import { useActivity } from '../state/toast';
import { useAuth } from '../state/auth';
import { textMatch } from './DataTable';
import { Modal } from './Modal';
import {
  IconAlert,
  IconAudit,
  IconAutomation,
  IconBaseline,
  IconBell,
  IconDashboard,
  IconDevices,
  IconKeyboard,
  IconLogout,
  IconMenu,
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
  { to: '/baselines', label: 'Baselines', icon: IconBaseline },
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
  const loc = useLocation();
  // Below 700px the rail is an off-canvas drawer; above it the class does nothing.
  const [navOpen, setNavOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  useShortcuts(() => setHelpOpen((o) => !o));

  // A tap that navigates must also put the drawer away.
  useEffect(() => setNavOpen(false), [loc.pathname]);

  // Open-alert badge: cheap dashboard call, refreshed on alert events.
  const dash = useAsync(() => api.dashboard(), []);
  useLiveReload(['alert', 'hello'], dash.reload, { debounceMs: 800 });
  const openAlerts = dash.data?.open_alerts ?? 0;

  return (
    <div className="app">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      {navOpen && <div className="nav-scrim" onClick={() => setNavOpen(false)} />}
      <nav className={`nav ${navOpen ? 'open' : ''}`} aria-label="Main">
        <div className="nav-brand">
          <span className="logo">R</span>
          <span>Homelab RMM</span>
        </div>
        <div className="nav-section">Manage</div>
        {NAV.map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            end={n.end}
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            title={n.label}
            // aria-label REPLACES the link's text for a screen reader, so the
            // open-alert badge beside it was announced as nothing at all.
            aria-label={n.badge && openAlerts > 0 ? `${n.label} (${openAlerts} open)` : n.label}
          >
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
        <Button variant="ghost" icon className="nav-toggle" onClick={() => setNavOpen((o) => !o)} aria-label="Menu" aria-expanded={navOpen}>
          <IconMenu />
        </Button>
        <GlobalSearch />
        <span className="spacer" />
        <ActivityMenu />
        <Button variant="ghost" icon onClick={() => setHelpOpen(true)} title="Keyboard shortcuts (?)" aria-label="Keyboard shortcuts">
          <IconKeyboard />
        </Button>
        <Button variant="ghost" icon onClick={toggleTheme} title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'} aria-label="Toggle theme">
          {theme === 'dark' ? <IconSun /> : <IconMoon />}
        </Button>
        <Dropdown
          trigger={
            <button className="btn ghost user-btn" style={{ gap: 8 }} aria-label="User menu">
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
      {helpOpen && <ShortcutHelp onClose={() => setHelpOpen(false)} />}
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

// ---------- keyboard shortcuts ----------

/** "g" then one of these goes to that page. */
const GOTO: Record<string, string> = {
  h: '/',
  d: '/devices',
  s: '/scripts',
  r: '/runs',
  t: '/tasks',
  a: '/alerts',
  p: '/patches',
  m: '/automations',
  b: '/baselines',
};

const SHORTCUTS: { keys: string[]; what: string }[] = [
  { keys: ['/'], what: 'Focus the device search' },
  { keys: ['g', 'h'], what: 'Go to the dashboard' },
  { keys: ['g', 'd'], what: 'Go to devices' },
  { keys: ['g', 's'], what: 'Go to scripts' },
  { keys: ['g', 'r'], what: 'Go to runs' },
  { keys: ['g', 't'], what: 'Go to tasks' },
  { keys: ['g', 'm'], what: 'Go to automations' },
  { keys: ['g', 'b'], what: 'Go to baselines' },
  { keys: ['g', 'a'], what: 'Go to alerts' },
  { keys: ['g', 'p'], what: 'Go to patches' },
  { keys: ['n'], what: 'New — the primary action on this page' },
  { keys: ['r'], what: 'Refresh this page' },
  { keys: ['?'], what: 'This list' },
  { keys: ['Esc'], what: 'Close the dialog on top' },
];

/** True while a text field, a select, the terminal or the remote desktop has the keyboard. */
function isEditing(t: EventTarget | null): boolean {
  const el = t as HTMLElement | null;
  if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement) return true;
  // The desktop viewer forwards every key to the remote session; it stops
  // propagation while connected, and this covers the rest of the time.
  return !!el?.isContentEditable || !!el?.closest?.('[role="application"]');
}

/**
 * Document-level bindings. A dialog owns the keyboard while it is open (its
 * own Escape handling would otherwise fight these), and anything typed into a
 * field is left alone — including the terminal, whose xterm helper is a
 * textarea.
 */
function useShortcuts(toggleHelp: () => void): void {
  const navigate = useNavigate();
  const help = useRef(toggleHelp);
  help.current = toggleHelp;
  useEffect(() => {
    let prefixAt = 0;
    const click = (sel: string) => (document.querySelector(sel) as HTMLElement | null)?.click();
    const onKey = (e: KeyboardEvent) => {
      if (isEditing(e.target) || e.ctrlKey || e.metaKey || e.altKey || e.defaultPrevented) return;
      if (document.querySelector('.overlay, .drawer-host')) return;
      const now = Date.now();
      const chord = prefixAt && now - prefixAt < 1500;
      prefixAt = 0;
      if (chord) {
        const to = GOTO[e.key.toLowerCase()];
        if (to) {
          e.preventDefault();
          navigate(to);
        }
        return;
      }
      switch (e.key) {
        case 'g':
          prefixAt = now;
          return;
        case '?':
          e.preventDefault();
          help.current();
          return;
        case 'n':
          // Every page puts its create action first in the header.
          e.preventDefault();
          click('.page-head .btn.primary');
          return;
        case 'r':
          e.preventDefault();
          click('button[aria-label="Refresh"]');
          return;
        default:
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [navigate]);
}

function ShortcutHelp({ onClose }: { onClose: () => void }) {
  return (
    <Modal title="Keyboard shortcuts" onClose={onClose} size="sm" center footer={<Button onClick={onClose}>Close</Button>}>
      <div className="shortcuts">
        {SHORTCUTS.map((s) => (
          <Fragment key={s.keys.join('+')}>
            <span className="keys">
              {s.keys.map((k) => (
                <kbd className="kbd" key={k}>
                  {k}
                </kbd>
              ))}
            </span>
            <span>{s.what}</span>
          </Fragment>
        ))}
      </div>
      <p className="muted small" style={{ marginTop: 12 }}>
        Shortcuts are off while you are typing in a field or a dialog is open.
      </p>
    </Modal>
  );
}

// ---------- activity log ----------

/**
 * The last messages the console raised. Toasts are capped at three on screen
 * and expire in seconds, so a burst (one line per device in a bulk action)
 * would otherwise be unreadable a minute later; this keeps them.
 */
function ActivityMenu() {
  const { items, unread, markRead, clear } = useActivity();
  const onOpen = useCallback(() => markRead(), [markRead]);
  return (
    <Dropdown
      menuClassName="notif-menu"
      closeOnClick={false}
      onOpen={onOpen}
      trigger={
        <button className="btn ghost icon notif-btn" aria-label={unread ? `Activity (${unread} new)` : 'Activity'} title="Activity">
          <IconBell />
          {unread > 0 && <span className="unread" />}
        </button>
      }
    >
      <div className="notif-head">
        <span>Activity</span>
        <span className="muted small">{items.length ? `last ${items.length}` : ''}</span>
        <span style={{ marginLeft: 'auto' }}>
          <Button size="xs" variant="ghost" onClick={clear} disabled={!items.length}>
            Clear
          </Button>
        </span>
      </div>
      <div className="notif-list">
        {items.map((a) => (
          <div key={a.id} className={`notif-item kind-${a.kind}`}>
            <div className="grow" style={{ minWidth: 0 }}>
              <div className="title">{a.title}</div>
              {a.detail && <div className="sub">{a.detail}</div>}
            </div>
            <span className="when">{relTime(Math.floor(a.at / 1000))}</span>
          </div>
        ))}
        {!items.length && <div className="muted small" style={{ padding: '14px 12px' }}>Nothing yet. Messages the console raises are kept here.</div>}
      </div>
    </Dropdown>
  );
}
