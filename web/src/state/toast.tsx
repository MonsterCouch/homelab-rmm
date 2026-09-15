import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react';

export type ToastKind = 'info' | 'success' | 'error' | 'warning';

export interface Toast {
  id: number;
  kind: ToastKind;
  title: string;
  detail?: string;
}

interface ToastApi {
  push: (kind: ToastKind, title: string, detail?: string) => void;
  info: (title: string, detail?: string) => void;
  success: (title: string, detail?: string) => void;
  error: (title: string, detail?: string) => void;
  warning: (title: string, detail?: string) => void;
  dismiss: (id: number) => void;
}

const Ctx = createContext<ToastApi | null>(null);

// Module-level bridge so non-React code (the fetch wrapper, SSE hook) can
// raise a toast without threading the context through.
let bridge: ToastApi | null = null;
export function toast(): ToastApi {
  if (!bridge) throw new Error('ToastProvider is not mounted');
  return bridge;
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);
  const seq = useRef(0);
  const timers = useRef(new Map<number, number>());

  const dismiss = useCallback((id: number) => {
    setItems((list) => list.filter((t) => t.id !== id));
    const t = timers.current.get(id);
    if (t) {
      window.clearTimeout(t);
      timers.current.delete(id);
    }
  }, []);

  const push = useCallback(
    (kind: ToastKind, title: string, detail?: string) => {
      const id = ++seq.current;
      setItems((list) => [...list.slice(-5), { id, kind, title, detail }]);
      const ttl = kind === 'error' ? 9000 : 4500;
      timers.current.set(id, window.setTimeout(() => dismiss(id), ttl));
    },
    [dismiss],
  );

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

  return (
    <Ctx.Provider value={value}>
      {children}
      <div className="toast-host" role="status" aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className={`toast toast-${t.kind}`}>
            <div className="toast-body">
              <div className="toast-title">{t.title}</div>
              {t.detail && <div className="toast-detail">{t.detail}</div>}
            </div>
            <button className="toast-close" aria-label="Dismiss" onClick={() => dismiss(t.id)}>
              ×
            </button>
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}

export function useToast(): ToastApi {
  const v = useContext(Ctx);
  if (!v) throw new Error('useToast outside ToastProvider');
  return v;
}

/** Message for an unknown thrown value. */
export function errMsg(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === 'string') return err;
  return 'unexpected error';
}
