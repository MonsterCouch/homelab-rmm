import { useCallback, useEffect, useRef, useState, type DependencyList } from 'react';
import { errMsg } from '../state/toast';

export interface AsyncState<T> {
  data: T | undefined;
  error: string | null;
  loading: boolean;
  /** true after the first load has settled (used for skeleton vs. spinner) */
  loaded: boolean;
  reload: () => Promise<void>;
  /** update the cached value locally (optimistic edits) */
  setData: (updater: T | ((prev: T | undefined) => T | undefined)) => void;
}

/**
 * Load data with an async function; re-runs when deps change. Late results
 * from a superseded call are dropped, and the in-flight request is aborted
 * on unmount when the loader honours the signal.
 */
export function useAsync<T>(
  fn: (signal: AbortSignal) => Promise<T>,
  deps: DependencyList,
  opts: { enabled?: boolean; keepData?: boolean } = {},
): AsyncState<T> {
  const { enabled = true, keepData = true } = opts;
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(enabled);
  const [loaded, setLoaded] = useState(false);
  const seq = useRef(0);
  const ctrl = useRef<AbortController | null>(null);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const run = useCallback(async () => {
    ctrl.current?.abort();
    const c = new AbortController();
    ctrl.current = c;
    const id = ++seq.current;
    setLoading(true);
    if (!keepData) setData(undefined);
    try {
      const v = await fnRef.current(c.signal);
      if (id !== seq.current) return;
      setData(v);
      setError(null);
    } catch (err) {
      if (id !== seq.current) return;
      if (err instanceof DOMException && err.name === 'AbortError') return;
      setError(errMsg(err));
    } finally {
      if (id === seq.current) {
        setLoading(false);
        setLoaded(true);
      }
    }
  }, [keepData]);

  useEffect(() => {
    if (!enabled) {
      setLoading(false);
      return;
    }
    void run();
    return () => ctrl.current?.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, run, ...deps]);

  const set = useCallback((u: T | ((prev: T | undefined) => T | undefined)) => {
    setData((prev) => (typeof u === 'function' ? (u as (p: T | undefined) => T | undefined)(prev) : u));
  }, []);

  return { data, error, loading, loaded, reload: run, setData: set };
}

/** Poll while the tab is visible. Interval 0 disables. */
export function useInterval(fn: () => void, ms: number, enabled = true): void {
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => {
    if (!enabled || ms <= 0) return;
    const tick = () => {
      if (document.visibilityState === 'visible') ref.current();
    };
    const id = window.setInterval(tick, ms);
    return () => window.clearInterval(id);
  }, [ms, enabled]);
}

/** Debounced value for search boxes. */
export function useDebounced<T>(value: T, ms = 250): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const id = window.setTimeout(() => setV(value), ms);
    return () => window.clearTimeout(id);
  }, [value, ms]);
  return v;
}

/** localStorage-backed state for per-user UI preferences (column sort, ranges). */
export function useLocalState<T>(key: string, initial: T): [T, (v: T | ((p: T) => T)) => void] {
  const [v, setV] = useState<T>(() => {
    try {
      const raw = localStorage.getItem(key);
      return raw ? (JSON.parse(raw) as T) : initial;
    } catch {
      return initial;
    }
  });
  const set = useCallback(
    (u: T | ((p: T) => T)) => {
      setV((prev) => {
        const next = typeof u === 'function' ? (u as (p: T) => T)(prev) : u;
        try {
          localStorage.setItem(key, JSON.stringify(next));
        } catch {
          /* ignore */
        }
        return next;
      });
    },
    [key],
  );
  return [v, set];
}
