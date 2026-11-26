import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import type { Agent } from '../api/types';
import { useAsync } from '../hooks/useAsync';
import { useEventBus, useEvents, useLiveReload } from '../hooks/useEvents';
import { useTheme } from '../hooks/useTheme';
import { osLabel, relTime } from '../lib/format';
import { host } from '../lib/host';
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
  IconBuilding,
  IconDashboard,
  IconDevices,
  IconGrid,
  IconKey,
  IconKeyboard,
  IconLock,
  IconLogout,
  IconMenu,
  IconMoon,
  IconNetwork,
  IconPackage,
  IconPatch,
  IconRuns,
  IconScript,
  IconSearch,
  IconSettings,
  IconSun,
  IconTasks,
  IconTicket,
  IconUpload,
  IconUser,
  IconUsers,
  LogoMark,
} from './Icons';
import { Button, Dropdown, ErrorBoundary, OnlineDot } from './ui';
import { ServerUpdateModal } from './ServerUpdateModal';
import '../styles/shell.css';

const NAV_FLEET = [
  { to: '/', label: 'Dashboard', icon: IconDashboard, end: true },
  { to: '/devices', label: 'Devices', icon: IconDevices },
  { to: '/discovery', label: 'Discovery & SNMP', icon: IconNetwork },
];
const NAV_OPS = [
  { to: '/scripts', label: 'Scripts', icon: IconScript },
  { to: '/runs', label: 'Runs', icon: IconRuns },
  { to: '/tasks', label: 'Tasks', icon: IconTasks },
  { to: '/automations', label: 'Automations', icon: IconAutomation },
  { to: '/baselines', label: 'Baselines', icon: IconBaseline },
  { to: '/patches', label: 'Patches', icon: IconPatch },
  { to: '/software-catalog', label: 'Software Drawer', icon: IconPackage },
  { to: '/approvals', label: 'Approvals', icon: IconLock },
];
const NAV_MONITOR = [
  { to: '/alerts', label: 'Alerts', icon: IconAlert, badge: true },
  { to: '/tickets', label: 'Tickets', icon: IconTicket },
];
const ADMIN_NAV = [
  { to: '/organizations', label: 'Organizations', icon: IconBuilding },
  { to: '/trust', label: 'Trust & signing', icon: IconKey },
  { to: '/settings', label: 'Settings', icon: IconSettings },
  { to: '/users', label: 'Users', icon: IconUsers },
  { to: '/roles', label: 'Roles', icon: IconGrid },
  { to: '/audit', label: 'Audit', icon: IconAudit },
];
const TAIL_NAV = [
  { to: '/account', label: 'Account', icon: IconUser },
];

export function Layout() {
  const { user, isAdmin, canAutomations, logout, version } = useAuth();
  const [theme, toggleTheme] = useTheme();
  const navigate = useNavigate();
  const loc = useLocation();
  // Below 700px the rail is an off-canvas drawer; above it the class does nothing.
  const [navOpen, setNavOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [updateOpen, setUpdateOpen] = useState(false);
  // C16: while the phone search has the keyboard it takes the whole topbar row.
  const [searchOpen, setSearchOpen] = useState(false);
  useShortcuts(() => setHelpOpen((o) => !o));

  // A tap that navigates must also put the drawer away.
  useEffect(() => setNavOpen(false), [loc.pathname]);

  // ---- the Android shell contract (C12, docs/ANDROID.md §3.4/§3.6) ----------
  // Every line of this is inert in a browser: the bridge answers nothing, the
  // subscriptions never fire and host.* resolves false, so a plain browser
  // renders exactly what it rendered before. Only a shell that has said hello
  // sets data-rmm-shell, which is what hides the drawer (styles/shell.css); if
  // it never does, the drawer stays and the native bar falls back to loadUrl.
  const inShell = useShell();

  // A bottom-tab tap arrives as {t:'navigate'} and becomes a client-side
  // transition, so the SSE stream and any live socket survive it.
  useEffect(() => host.onNavigate((path) => navigate(path)), [navigate]);

  // System back: the drawer is the only thing this component can swallow it
  // with. Returning true tells the shell the press was consumed.
  useEffect(
    () =>
      host.onBack(() => {
        if (!navOpen) return false;
        setNavOpen(false);
        return true;
      }),
    [navOpen],
  );

  // The shell mirrors its own theme preference into the page.
  useEffect(
    () =>
      host.onTheme((value) => {
        if (value !== theme) toggleTheme();
      }),
    [theme, toggleTheme],
  );

  // Connection test row 3 (§6): the console reports its own SSE hello. The
  // provider dispatches a synthetic hello on every (re)connect, so this is the
  // existing stream, not a new one.
  useEvents(['hello'], () => {
    void host.sse(true);
  });

  // Open-alert badge: cheap dashboard call, refreshed on alert events.
  const dash = useAsync(() => api.dashboard(), []);
  useLiveReload(['alert', 'hello'], dash.reload, { debounceMs: 800 });
  const openAlerts = dash.data?.open_alerts ?? 0;
  const criticalAlerts = dash.data?.critical_alerts ?? 0;

  // The native bottom-bar badge rides the counts the drawer badge already has:
  // no second poller, no second endpoint. inShell is a dependency so a late
  // handshake still gets the current counts.
  useEffect(() => {
    if (!inShell) return;
    void host.badge(openAlerts, criticalAlerts);
  }, [inShell, openAlerts, criticalAlerts]);

  return (
    <div className="app">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      {navOpen && <div className="nav-scrim" onClick={() => setNavOpen(false)} />}
      <nav className={`nav ${navOpen ? 'open' : ''}`} aria-label="Main">
        <div className="nav-brand">
          <LogoMark size={22} className="brand-logo" />
          <span className="brand-name">Homelab RMM</span>
        </div>

        <div className="nav-section">Fleet</div>
        {NAV_FLEET.map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            end={n.end}
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            title={n.label}
            aria-label={n.label}
          >
            <n.icon />
            <span>{n.label}</span>
          </NavLink>
        ))}

        <div className="nav-section">Operations</div>
        {NAV_OPS.filter((n) => n.to !== '/automations' || canAutomations).map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            title={n.label}
            aria-label={n.label}
          >
            <n.icon />
            <span>{n.label}</span>
          </NavLink>
        ))}

        <div className="nav-section">Monitoring</div>
        {NAV_MONITOR.map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            title={n.label}
            aria-label={n.badge && openAlerts > 0 ? `${n.label} (${openAlerts} open)` : n.label}
          >
            <n.icon />
            <span>{n.label}</span>
            {/* the open-alert count belongs to Alerts alone */}
            {n.badge && openAlerts > 0 && <span className="badge">{openAlerts}</span>}
          </NavLink>
        ))}

        {isAdmin && (
          <>
            <div className="nav-section">Administration</div>
            {ADMIN_NAV.map((n) => (
              <NavLink key={n.to} to={n.to} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`} title={n.label} aria-label={n.label}>
                <n.icon />
                <span>{n.label}</span>
              </NavLink>
            ))}
          </>
        )}
        <div className="nav-section">Preferences</div>
        {TAIL_NAV.map((n) => (
          <NavLink key={n.to} to={n.to} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`} title={n.label} aria-label={n.label}>
            <n.icon />
            <span>{n.label}</span>
          </NavLink>
        ))}
        <div className="nav-foot">
          <ConnState />
          {isAdmin ? (
            <button
              type="button"
              onClick={() => setUpdateOpen(true)}
              style={{ background: 'none', border: 'none', padding: 0, color: 'inherit', cursor: 'pointer', font: 'inherit', textDecoration: 'underline' }}
              title="Check updates"
            >
              v{version || 'dev'}
            </button>
          ) : (
            <div>v{version || 'dev'}</div>
          )}
        </div>
      </nav>
      <header className={`topbar ${searchOpen ? 'search-open' : ''}`}>
        <Button variant="ghost" icon className="nav-toggle" onClick={() => setNavOpen((o) => !o)} aria-label="Menu" aria-expanded={navOpen}>
          <IconMenu />
        </Button>
        <GlobalSearch onFocusChange={setSearchOpen} />
        <span className="spacer" />
        <ActivityMenu />
        {isAdmin && (
          <Button variant="ghost" icon onClick={() => setUpdateOpen(true)} title="Server & Fleet Updates" aria-label="Server & Fleet Updates">
            <IconUpload />
          </Button>
        )}
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
              <span className="chip outline">{user?.role_name || user?.role}</span>
            </button>
          }
        >
          <button onClick={() => navigate('/account')}>
            <IconUser /> Account
          </button>
          {isAdmin && (
            <button onClick={() => setUpdateOpen(true)}>
              <IconUpload /> System Updates…
            </button>
          )}
          {/* The topbar toggle is hidden below 700px (C16), so the theme has to
              stay reachable from somewhere a thumb can find. */}
          <button onClick={toggleTheme}>
            {theme === 'dark' ? <IconSun /> : <IconMoon />} {theme === 'dark' ? 'Light theme' : 'Dark theme'}
          </button>
          <hr />
          <button
            onClick={async () => {
              await logout();
              // The shell clears its own session state on this signal (§3.6);
              // in a browser it is a no-op.
              void host.signedOut();
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
      {updateOpen && <ServerUpdateModal onClose={() => setUpdateOpen(false)} />}
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

/**
 * True once the Android shell's bridge has completed its handshake
 * (web/src/lib/host.ts). False in every browser, and false in the shell until
 * the shell actually answers — the drawer stays until then, by design.
 */
function useShell(): boolean {
  const [on, setOn] = useState(host.available);
  useEffect(() => host.onAvailable(setOn), []);
  return on;
}

/** A media query as state, for the bits of the phone layout JS has to own. */
function useMedia(query: string): boolean {
  const [on, setOn] = useState(() => window.matchMedia?.(query).matches ?? false);
  useEffect(() => {
    const mq = window.matchMedia?.(query);
    if (!mq) return;
    const onChange = () => setOn(mq.matches);
    onChange();
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, [query]);
  return on;
}

function GlobalSearch({ onFocusChange }: { onFocusChange: (focused: boolean) => void }) {
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const phone = useMedia('(max-width: 700px)');
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
      // "/" or Ctrl+K / Cmd+K focuses the search unless typing in a field
      const t = e.target as HTMLElement | null;
      const editing = t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement || t instanceof HTMLSelectElement || !!t?.isContentEditable;
      if (((e.key === '/' && !editing) || ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k')) && !e.altKey) {
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

  // System back closes the results list before it reaches the shell's history.
  useEffect(
    () =>
      host.onBack(() => {
        if (!open) return false;
        setOpen(false);
        inputRef.current?.blur();
        return true;
      }),
    [open],
  );

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
        placeholder={phone ? 'Search devices…' : 'Search devices by name, IP, group or tag…'}
        value={q}
        aria-label="Search devices"
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
        enterKeyHint="search"
        onChange={(e) => {
          setQ(e.target.value);
          setOpen(true);
          setActive(0);
        }}
        onFocus={() => {
          setOpen(true);
          onFocusChange(true);
        }}
        onBlur={() => onFocusChange(false)}
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
      {!phone && (
        <span className="search-shortcut" onClick={() => inputRef.current?.focus()}>
          <kbd>/</kbd>
        </span>
      )}
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
