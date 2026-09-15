import { createContext, useContext, useEffect, useRef, type ReactNode } from 'react';
import { api } from '../api/client';
import type { EventKind, HubEvent } from '../api/types';
import { useAuth } from '../state/auth';

type Handler = (ev: HubEvent) => void;

interface EventBus {
  subscribe: (fn: Handler) => () => void;
  /** connection state for the status indicator */
  connected: () => boolean;
}

const Ctx = createContext<EventBus | null>(null);

const KINDS: EventKind[] = ['hello', 'agent_online', 'agent_offline', 'metrics', 'inventory', 'event', 'alert', 'run', 'patches'];

/**
 * One EventSource for the whole app. Components subscribe through useEvents;
 * the provider reconnects with backoff when the stream drops and tears it
 * down when the user signs out (an EventSource on a 401 would otherwise loop).
 */
export function EventsProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const handlers = useRef(new Set<Handler>());
  const connectedRef = useRef(false);
  const busRef = useRef<EventBus>({
    subscribe: (fn) => {
      handlers.current.add(fn);
      return () => {
        handlers.current.delete(fn);
      };
    },
    connected: () => connectedRef.current,
  });

  useEffect(() => {
    if (!user) return;
    let es: EventSource | null = null;
    let retry = 1000;
    let timer = 0;
    let closed = false;

    const dispatch = (ev: HubEvent) => {
      for (const h of handlers.current) {
        try {
          h(ev);
        } catch (err) {
          console.error('event handler failed', err);
        }
      }
    };

    const open = () => {
      if (closed) return;
      es = new EventSource('/api/events', { withCredentials: true });
      for (const kind of KINDS) {
        es.addEventListener(kind, (e: MessageEvent<string>) => {
          let parsed: HubEvent;
          try {
            parsed = JSON.parse(e.data) as HubEvent;
          } catch {
            parsed = { kind };
          }
          if (!parsed || typeof parsed !== 'object') parsed = { kind };
          parsed.kind = kind;
          dispatch(parsed);
        });
      }
      es.onopen = () => {
        retry = 1000;
        const was = connectedRef.current;
        connectedRef.current = true;
        if (!was) dispatch({ kind: 'hello' });
      };
      es.onerror = () => {
        // CLOSED means the server refused the stream (401 after the session
        // expired or was revoked, or a 5xx) rather than a dropped connection.
        // EventSource cannot see the status, so ask an endpoint that can: a
        // 401 from /api/me runs the unauthorized handler, which clears the
        // user and tears this loop down instead of retrying forever.
        const refused = es?.readyState === EventSource.CLOSED;
        connectedRef.current = false;
        es?.close();
        es = null;
        if (closed) return;
        if (refused) void api.me().catch(() => undefined);
        timer = window.setTimeout(open, retry);
        retry = Math.min(retry * 2, 30000);
      };
    };
    open();
    return () => {
      closed = true;
      window.clearTimeout(timer);
      es?.close();
      connectedRef.current = false;
    };
  }, [user]);

  return <Ctx.Provider value={busRef.current}>{children}</Ctx.Provider>;
}

/**
 * Subscribe to live events. The handler always sees the latest closure, so
 * callers do not need to memoise it.
 */
export function useEvents(kinds: EventKind[] | 'all', handler: Handler): void {
  const bus = useContext(Ctx);
  const ref = useRef(handler);
  ref.current = handler;
  const key = kinds === 'all' ? 'all' : kinds.join(',');
  useEffect(() => {
    if (!bus) return;
    const want = key === 'all' ? null : new Set(key.split(','));
    return bus.subscribe((ev) => {
      if (want && !want.has(ev.kind)) return;
      ref.current(ev);
    });
  }, [bus, key]);
}

interface LiveReloadOpts {
  /** only react to events for this agent (events without agent_id always pass) */
  agentId?: string;
  debounceMs?: number;
}

/** Debounced "refetch when these kinds arrive". */
export function useLiveReload(kinds: EventKind[], reload: () => void, opts: LiveReloadOpts = {}): void {
  const timer = useRef(0);
  const reloadRef = useRef(reload);
  reloadRef.current = reload;
  const { agentId, debounceMs = 400 } = opts;
  useEvents(kinds, (ev) => {
    if (agentId && ev.agent_id && ev.agent_id !== agentId) return;
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => reloadRef.current(), debounceMs);
  });
  useEffect(() => () => window.clearTimeout(timer.current), []);
}

export function useEventBus(): EventBus | null {
  return useContext(Ctx);
}
