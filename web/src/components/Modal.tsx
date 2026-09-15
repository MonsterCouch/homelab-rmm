import { createContext, useCallback, useContext, useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { Button } from './ui';
import { IconX } from './Icons';

// Dialogs stack (a confirm on top of a drawer, a prompt on top of a modal).
// Escape must close only the topmost one, so every open dialog registers here
// and useEscape checks that it is the one on top before acting.
const openDialogs: symbol[] = [];

function useDialogStack(): symbol {
  const id = useRef(Symbol('dialog')).current;
  useEffect(() => {
    openDialogs.push(id);
    return () => {
      const i = openDialogs.indexOf(id);
      if (i >= 0) openDialogs.splice(i, 1);
    };
  }, [id]);
  return id;
}

function useEscape(id: symbol, onClose: () => void) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape' || e.defaultPrevented) return;
      if (openDialogs[openDialogs.length - 1] !== id) return;
      e.stopPropagation();
      onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [id, onClose]);
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([type=hidden]):not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Focus the first field when opened, keep Tab cycling inside the dialog
 * (aria-modal alone does not stop keyboard focus from leaving) and restore
 * focus to the opener on close.
 */
function useDialogFocus(ref: React.RefObject<HTMLElement>) {
  useEffect(() => {
    // React applies autoFocus during commit, before this effect, which
    // would make the dialog's own button look like the opener; dialogs
    // therefore mark their preferred control with data-autofocus instead.
    let prev = document.activeElement as HTMLElement | null;
    const el = ref.current;
    if (!el) return;
    if (prev && el.contains(prev)) prev = null;
    const first =
      el.querySelector<HTMLElement>('[data-autofocus]') ??
      el.querySelector<HTMLElement>('input:not([type=hidden]):not([disabled]), select:not([disabled]), textarea:not([disabled]), button:not(.modal-close):not([disabled])');
    (first ?? el).focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return;
      const items = Array.from(el.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((x) => x.offsetParent !== null || x === document.activeElement);
      if (!items.length) {
        e.preventDefault();
        el.focus();
        return;
      }
      const firstItem = items[0];
      const lastItem = items[items.length - 1];
      const active = document.activeElement as HTMLElement | null;
      if (e.shiftKey && (active === firstItem || !el.contains(active))) {
        e.preventDefault();
        lastItem.focus();
      } else if (!e.shiftKey && (active === lastItem || !el.contains(active))) {
        e.preventDefault();
        firstItem.focus();
      }
    };
    el.addEventListener('keydown', onKey);
    return () => {
      el.removeEventListener('keydown', onKey);
      prev?.focus?.();
    };
  }, [ref]);
}

interface ModalProps {
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl';
  center?: boolean;
}

export function Modal({ title, onClose, children, footer, size = 'md', center }: ModalProps) {
  const id = useDialogStack();
  useEscape(id, onClose);
  const ref = useRef<HTMLDivElement>(null);
  useDialogFocus(ref);
  const titleId = useId();
  return createPortal(
    <div className={`overlay ${center ? 'center' : ''}`} onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal ${size !== 'md' ? size : ''}`} role="dialog" aria-modal="true" aria-labelledby={titleId} ref={ref} tabIndex={-1}>
        <div className="modal-head">
          <h2 id={titleId}>{title}</h2>
          <Button variant="ghost" icon size="sm" className="modal-close" onClick={onClose} aria-label="Close">
            <IconX />
          </Button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>,
    document.body,
  );
}

interface DrawerProps {
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
  actions?: ReactNode;
}

export function Drawer({ title, onClose, children, footer, wide, actions }: DrawerProps) {
  const id = useDialogStack();
  useEscape(id, onClose);
  const ref = useRef<HTMLDivElement>(null);
  useDialogFocus(ref);
  const titleId = useId();
  return createPortal(
    <div className="drawer-host" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`drawer ${wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-labelledby={titleId} ref={ref} tabIndex={-1}>
        <div className="modal-head">
          <h2 id={titleId}>{title}</h2>
          {actions}
          <Button variant="ghost" icon size="sm" className="modal-close" onClick={onClose} aria-label="Close">
            <IconX />
          </Button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>,
    document.body,
  );
}

// ---------- confirm ----------

export interface ConfirmOptions {
  title: string;
  message?: ReactNode;
  confirmLabel?: string;
  danger?: boolean;
  /** extra form fields rendered inside the dialog; their state lives with the caller */
  body?: ReactNode;
}

type Confirm = (opts: ConfirmOptions) => Promise<boolean>;

const ConfirmCtx = createContext<Confirm | null>(null);

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<(ConfirmOptions & { resolve: (v: boolean) => void }) | null>(null);
  const confirm = useCallback<Confirm>((opts) => new Promise((resolve) => setState({ ...opts, resolve })), []);
  const close = (v: boolean) => {
    state?.resolve(v);
    setState(null);
  };
  return (
    <ConfirmCtx.Provider value={confirm}>
      {children}
      {state && (
        <Modal
          title={state.title}
          onClose={() => close(false)}
          size="sm"
          center
          footer={
            <>
              <Button onClick={() => close(false)}>Cancel</Button>
              {/* Enter confirms a routine action; a destructive one starts on Cancel so a stray Enter cannot delete. */}
              <Button variant={state.danger ? 'danger' : 'primary'} solid={state.danger} onClick={() => close(true)} data-autofocus={state.danger ? undefined : ''}>
                {state.confirmLabel ?? 'Confirm'}
              </Button>
            </>
          }
        >
          {state.message && <p>{state.message}</p>}
          {state.body}
        </Modal>
      )}
    </ConfirmCtx.Provider>
  );
}

export function useConfirm(): Confirm {
  const c = useContext(ConfirmCtx);
  if (!c) throw new Error('useConfirm outside ConfirmProvider');
  return c;
}

/** Small inline prompt dialog for a single text value (rename, new folder…). */
export function PromptDialog({
  title,
  label,
  initial = '',
  onClose,
  onSubmit,
  confirmLabel = 'OK',
  placeholder,
}: {
  title: string;
  label?: string;
  initial?: string;
  onClose: () => void;
  onSubmit: (value: string) => void | Promise<void>;
  confirmLabel?: string;
  placeholder?: string;
}) {
  const [v, setV] = useState(initial);
  const [busy, setBusy] = useState(false);
  const inputId = useId();
  const submit = async () => {
    if (!v.trim()) return;
    setBusy(true);
    try {
      await onSubmit(v.trim());
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title={title}
      onClose={onClose}
      size="sm"
      center
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} busy={busy} disabled={!v.trim()}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="field">
        {label && <label htmlFor={inputId}>{label}</label>}
        <input id={inputId} value={v} placeholder={placeholder} onChange={(e) => setV(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && submit()} />
      </div>
    </Modal>
  );
}
