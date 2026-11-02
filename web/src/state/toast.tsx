import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react';

export type ToastKind = 'info' | 'success' | 'error' | 'warning';

export interface Toast {
  id: number;
  kind: ToastKind;
  title: string;
  detail?: string;
  /** stays until dismissed instead of expiring */
  sticky?: boolean;
  /** shown in a box with a copy button */
  copy?: string;
}

/** A toast that has been raised, kept in the activity log after it expires. */
export interface Activity extends Toast {
  /** wall-clock ms when it was raised */
  at: number;
}

interface ToastApi {
  push: (kind: ToastKind, title: string, detail?: string, extra?: { sticky?: boolean; copy?: string }) => void;
  info: (title: string, detail?: string) => void;
  success: (title: string, detail?: string) => void;
  error: (title: string, detail?: string) => void;
  warning: (title: string, detail?: string) => void;
  dismiss: (id: number) => void;
}

interface ActivityApi {
  /** newest first */
  items: Activity[];
  unread: number;
  markRead: () => void;
  clear: () => void;
}

const Ctx = createContext<ToastApi | null>(null);
const ActivityCtx = createContext<ActivityApi | null>(null);

/**
 * At most this many toasts are on screen at once: a burst (one failing bulk
 * action raises one per device) otherwise stacks up the whole right-hand edge
 * and hides the page behind it. The newest win; older ones are dropped from
 * the screen — but not from the activity log, which is what makes a dropped
 * "3 of 5 devices failed" readable a minute later.
 */
const MAX_VISIBLE = 3;

/** How many past messages the activity log keeps. */
const MAX_HISTORY = 50;

/**
 * How long a toast stays up, by kind. Something that went wrong is worth
 * reading twice as long as a confirmation nobody needed to read at all.
 */
const TTL_MS: Record<ToastKind, number> = { success: 4000, info: 4000, warning: 6000, error: 8000 };

// Module-level bridge so non-React code (the fetch wrapper, SSE hook) can
// raise a toast without threading the context through.
let bridge: ToastApi | null = null;
export function toast(): ToastApi {
  if (!bridge) throw new Error('ToastProvider is not mounted');
  return bridge;
}

interface Timer {
  handle: number;
  /** ms still to run when the countdown was last started */
  remaining: number;
  startedAt: number;
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);
  const [log, setLog] = useState<Activity[]>([]);
  const [unread, setUnread] = useState(0);
  const seq = useRef(0);
  const timers = useRef(new Map<number, Timer>());
  const paused = useRef(false);

  const dismiss = useCallback((id: number) => {
    setItems((list) => list.filter((t) => t.id !== id));
    const t = timers.current.get(id);
    if (t) {
      window.clearTimeout(t.handle);
      timers.current.delete(id);
    }
  }, []);

  const arm = useCallback(
    (id: number, ms: number) => {
      const handle = window.setTimeout(() => dismiss(id), ms);
      timers.current.set(id, { handle, remaining: ms, startedAt: Date.now() });
    },
    [dismiss],
  );

  const push = useCallback(
    (kind: ToastKind, title: string, detail?: string, extra?: { sticky?: boolean; copy?: string }) => {
      if (kind === 'error' && (title === PARKED_MESSAGE || detail === PARKED_MESSAGE)) return;
      const id = ++seq.current;
      setItems((list) => [...list, { id, kind, title, detail, ...extra }].slice(-MAX_VISIBLE));
      setLog((list) => [{ id, kind, title, detail, at: Date.now() }, ...list].slice(0, MAX_HISTORY));
      setUnread((n) => Math.min(n + 1, 99));
      if (extra?.sticky) return;
      arm(id, TTL_MS[kind]);
      // A toast raised while the pointer rests on the stack must not start
      // counting down either, or it disappears from under the reader.
      if (paused.current) {
        const t = timers.current.get(id);
        if (t) {
          window.clearTimeout(t.handle);
          t.handle = 0;
        }
      }
    },
    [arm],
  );

  // Hovering (or tabbing into) the stack holds every countdown: a toast must
  // not vanish while it is being read or its detail copied.
  const pause = useCallback(() => {
    if (paused.current) return;
    paused.current = true;
    const now = Date.now();
    for (const t of timers.current.values()) {
      if (!t.handle) continue;
      window.clearTimeout(t.handle);
      t.remaining = Math.max(600, t.remaining - (now - t.startedAt));
      t.handle = 0;
    }
  }, []);
  const resume = useCallback(() => {
    if (!paused.current) return;
    paused.current = false;
    for (const [id, t] of timers.current) {
      if (t.handle) continue;
      t.startedAt = Date.now();
      t.handle = window.setTimeout(() => dismiss(id), t.remaining);
    }
  }, [dismiss]);

  // Toasts pushed off the end by MAX_VISIBLE never reach dismiss(), so drop
  // their timers here rather than inside the state updater (which React may
  // call twice). Anything no longer rendered has nothing left to expire.
  useEffect(() => {
    const live = new Set(items.map((t) => t.id));
    for (const [id, t] of timers.current) {
      if (live.has(id)) continue;
      window.clearTimeout(t.handle);
      timers.current.delete(id);
    }
  }, [items]);

  // A page that fills the viewport keeps its own read-out along the bottom (the
  // terminal and the remote desktop status lines carry "fps · B/s", the number
  // you watch while judging a connection). Measure it and start the stack above
  // it rather than painting over it. Layout effect: before the toast is painted.
  useLayoutEffect(() => {
    const root = document.documentElement;
    if (!items.length) {
      root.style.removeProperty('--statusline-h');
      return;
    }
    const line = document.querySelector('.fill-page .statusline');
    const clear = line ? Math.max(0, window.innerHeight - line.getBoundingClientRect().top + 8) : 0;
    root.style.setProperty('--statusline-h', `${Math.round(clear)}px`);
  }, [items.length]);

  // Unmount (a full remount in dev, a logout-driven teardown in the app) must
  // not leave timers firing into a dead component.
  useEffect(() => {
    const pending = timers.current;
    return () => {
      for (const t of pending.values()) window.clearTimeout(t.handle);
      pending.clear();
    };
  }, []);

  const value = useMemo<ToastApi>(
    () => ({
      push,
      dismiss,
      info: (t, d) => push('info', t, d),
      success: (t, d) => push('success', t, d),
      error: (t, d) => push('error', t, d),
      warning: (t, d) => push('warning', t, d),
    }),
    [push, dismiss],
  );
  bridge = value;

  const activity = useMemo<ActivityApi>(
    () => ({
      items: log,
      unread,
      markRead: () => setUnread(0),
      clear: () => {
        setLog([]);
        setUnread(0);
      },
    }),
    [log, unread],
  );

  return (
    <Ctx.Provider value={value}>
      <ActivityCtx.Provider value={activity}>
        {children}
        <div className="toast-host" role="status" aria-live="polite" onMouseEnter={pause} onMouseLeave={resume} onFocusCapture={pause} onBlurCapture={resume}>
          {items.map((t) => (
            <div key={t.id} className={`toast toast-${t.kind}`}>
              <div className="toast-body">
                <div className="toast-title">{t.title}</div>
                {t.detail && <div className="toast-detail">{t.detail}</div>}
                {t.copy && <ToastCopy text={t.copy} />}
              </div>
              <button className="toast-close" aria-label="Dismiss" onClick={() => dismiss(t.id)}>
                ×
              </button>
            </div>
          ))}
        </div>
      </ActivityCtx.Provider>
    </Ctx.Provider>
  );
}

function ToastCopy({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  const copy = () => {
    void navigator.clipboard?.writeText(text).then(
      () => setDone(true),
      () => setDone(false),
    );
  };
  return (
    <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 6 }}>
      <code className="mono small" style={{ flex: 1, minWidth: 0, wordBreak: 'break-all', userSelect: 'all' }}>
        {text}
      </code>
      <button type="button" className="btn sm" onClick={copy}>
        {done ? 'Copied' : 'Copy'}
      </button>
    </div>
  );
}

export function useToast(): ToastApi {
  const v = useContext(Ctx);
  if (!v) throw new Error('useToast outside ToastProvider');
  return v;
}

/** The last messages raised, for the topbar activity log. */
export function useActivity(): ActivityApi {
  const v = useContext(ActivityCtx);
  if (!v) throw new Error('useActivity outside ToastProvider');
  return v;
}

/** Message for an unknown thrown value. */
/**
 * The message of the error request() throws when an action was parked for
 * rmm-signer. The "Waiting for rmm-signer" info toast already says so, so an
 * error toast carrying this text is dropped instead of showing a red failure.
 */
export const PARKED_MESSAGE = 'The request is waiting for rmm-signer.';

export function errMsg(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === 'string') return err;
  return 'unexpected error';
}
