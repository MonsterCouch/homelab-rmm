import {
  Component,
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type ErrorInfo,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from 'react';
import { IconCheck, IconCopy } from './Icons';
import { toast } from '../state/toast';

// ---------- buttons ----------

interface BtnProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'primary' | 'danger' | 'ghost';
  size?: 'md' | 'sm' | 'xs';
  busy?: boolean;
  icon?: boolean;
  solid?: boolean;
}

export function Button({ variant = 'default', size = 'md', busy, icon, solid, className = '', children, disabled, ...rest }: BtnProps) {
  const cls = ['btn', variant !== 'default' ? variant : '', size !== 'md' ? size : '', icon ? 'icon' : '', solid ? 'solid' : '', className]
    .filter(Boolean)
    .join(' ');
  return (
    <button type="button" className={cls} disabled={disabled || busy} {...rest}>
      {busy ? <span className="spinner" /> : null}
      {children}
    </button>
  );
}

export function CopyButton({ text, label, size = 'sm' }: { text: string; label?: string; size?: 'md' | 'sm' | 'xs' }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setDone(true);
      window.setTimeout(() => setDone(false), 1500);
    } catch {
      // Clipboard API needs a secure context; fall back to a selection copy.
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      if (ok) {
        setDone(true);
        window.setTimeout(() => setDone(false), 1500);
      } else toast().error('Copy failed', 'Select the text and copy it manually.');
    }
  };
  return (
    <Button size={size} onClick={copy} title="Copy to clipboard" aria-label={label ? undefined : 'Copy'}>
      {done ? <IconCheck /> : <IconCopy />}
      {label ? (done ? 'Copied' : label) : null}
    </Button>
  );
}

// ---------- form controls ----------

interface FieldProps {
  label?: ReactNode;
  hint?: ReactNode;
  error?: string | null;
  children: ReactNode;
  className?: string;
  htmlFor?: string;
}

export function Field({ label, hint, error, children, className = '', htmlFor }: FieldProps) {
  return (
    <div className={`field ${className}`}>
      {label && <label htmlFor={htmlFor}>{label}</label>}
      {children}
      {error ? <span className="err">{error}</span> : hint ? <span className="hint">{hint}</span> : null}
    </div>
  );
}

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} />;
}

export function TextArea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} />;
}

export function Select(props: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} />;
}

export function Switch({
  checked,
  onChange,
  disabled,
  label,
  ariaLabel,
  title,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  label?: ReactNode;
  /** accessible name when there is no visible label (table cells) */
  ariaLabel?: string;
  title?: string;
}) {
  const id = useId();
  return (
    <span className="row" style={{ gap: 8 }}>
      <button
        id={id}
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label ? undefined : ariaLabel}
        title={title}
        className="switch"
        disabled={disabled}
        onClick={(e) => {
          e.stopPropagation(); // a switch inside a clickable row must not also open the row
          onChange(!checked);
        }}
      />
      {label && (
        <label htmlFor={id} style={{ cursor: disabled ? 'default' : 'pointer' }}>
          {label}
        </label>
      )}
    </span>
  );
}

export function Checkbox({
  checked,
  onChange,
  label,
  disabled,
  indeterminate,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label?: ReactNode;
  disabled?: boolean;
  indeterminate?: boolean;
}) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = !!indeterminate && !checked;
  }, [indeterminate, checked]);
  return (
    <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, cursor: disabled ? 'default' : 'pointer' }}>
      <input ref={ref} type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      {label}
    </label>
  );
}

/** Comma/Enter-separated chips input for tags, recipients, monitored services. */
export function TagInput({
  value,
  onChange,
  placeholder,
  disabled,
  suggestions,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
  disabled?: boolean;
  suggestions?: string[];
}) {
  const [text, setText] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  const listId = useId();
  const commit = (raw: string) => {
    const parts = raw
      .split(/[,\n]/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (!parts.length) return;
    const next = [...value];
    for (const p of parts) if (!next.some((v) => v.toLowerCase() === p.toLowerCase())) next.push(p);
    onChange(next);
    setText('');
  };
  return (
    <div className={`input tag-input ${disabled ? 'disabled' : ''}`} onClick={() => inputRef.current?.focus()}>
      {value.map((t) => (
        <span key={t} className="chip outline">
          {t}
          {!disabled && (
            <span
              className="x"
              role="button"
              aria-label={`Remove ${t}`}
              onClick={(e) => {
                e.stopPropagation();
                onChange(value.filter((v) => v !== t));
              }}
            >
              ×
            </span>
          )}
        </span>
      ))}
      <input
        ref={inputRef}
        value={text}
        disabled={disabled}
        placeholder={value.length ? '' : placeholder}
        aria-label={placeholder ?? 'Add item'}
        list={suggestions ? listId : undefined}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ',' || e.key === 'Tab') {
            if (text.trim()) {
              e.preventDefault();
              commit(text);
            }
          } else if (e.key === 'Backspace' && !text && value.length) {
            onChange(value.slice(0, -1));
          }
        }}
        onBlur={() => commit(text)}
      />
      {suggestions && (
        <datalist id={listId}>
          {suggestions.map((s) => (
            <option key={s} value={s} />
          ))}
        </datalist>
      )}
    </div>
  );
}

/** Key/value editor for custom fields. */
export function KeyValueEditor({
  value,
  onChange,
  disabled,
}: {
  value: Record<string, string>;
  onChange: (v: Record<string, string>) => void;
  disabled?: boolean;
}) {
  const rows = Object.entries(value);
  const [nk, setNk] = useState('');
  const [nv, setNv] = useState('');
  const add = () => {
    const k = nk.trim();
    if (!k) return;
    onChange({ ...value, [k]: nv });
    setNk('');
    setNv('');
  };
  return (
    <div className="stack" style={{ gap: 6 }}>
      {rows.map(([k, v]) => (
        <div key={k} className="row" style={{ flexWrap: 'nowrap' }}>
          <input value={k} readOnly style={{ flex: '1 1 40%', minWidth: 0 }} aria-label="Key" />
          <input
            value={v}
            disabled={disabled}
            aria-label={`Value for ${k}`}
            style={{ flex: '1 1 60%', minWidth: 0 }}
            onChange={(e) => onChange({ ...value, [k]: e.target.value })}
          />
          {!disabled && (
            <Button size="sm" variant="ghost" aria-label={`Remove ${k}`} onClick={() => {
              const next = { ...value };
              delete next[k];
              onChange(next);
            }}>
              ×
            </Button>
          )}
        </div>
      ))}
      {!disabled && (
        <div className="row" style={{ flexWrap: 'nowrap' }}>
          <input placeholder="key" value={nk} style={{ flex: '1 1 40%', minWidth: 0 }} onChange={(e) => setNk(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && add()} />
          <input placeholder="value" value={nv} style={{ flex: '1 1 60%', minWidth: 0 }} onChange={(e) => setNv(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && add()} />
          <Button size="sm" onClick={add} disabled={!nk.trim()}>
            Add
          </Button>
        </div>
      )}
      {!rows.length && disabled && <span className="muted small">None</span>}
    </div>
  );
}

// ---------- chips ----------

type Tone = 'ok' | 'warn' | 'danger' | 'info' | 'accent' | 'purple' | '';

export function Chip({ tone = '', children, title, outline }: { tone?: Tone; children: ReactNode; title?: string; outline?: boolean }) {
  return (
    <span className={`chip ${tone} ${outline ? 'outline' : ''}`} title={title}>
      {children}
    </span>
  );
}

export function severityTone(s: string): Tone {
  switch (s) {
    case 'critical':
      return 'danger';
    case 'warning':
      return 'warn';
    case 'info':
      return 'info';
    default:
      return '';
  }
}

export function SeverityChip({ severity }: { severity: string }) {
  return <Chip tone={severityTone(severity)}>{severity || 'unknown'}</Chip>;
}

export function runTone(status: string): Tone {
  switch (status) {
    case 'done':
      return 'ok';
    case 'running':
      return 'accent';
    case 'queued':
    case 'pending':
      return 'info';
    case 'failed':
    case 'timeout':
      return 'danger';
    case 'cancelled':
      return 'warn';
    default:
      return '';
  }
}

export function RunStatusChip({ status }: { status: string }) {
  return (
    <Chip tone={runTone(status)}>
      {status === 'running' && <span className="spinner" style={{ width: 10, height: 10, borderWidth: 1.5 }} />}
      {status}
    </Chip>
  );
}

export function patchTone(status: string): Tone {
  switch (status) {
    case 'available':
      return 'info';
    case 'approved':
      return 'accent';
    case 'installing':
      return 'purple';
    case 'installed':
      return 'ok';
    case 'failed':
      return 'danger';
    case 'ignored':
      return '';
    default:
      return '';
  }
}

export function PatchStatusChip({ status }: { status: string }) {
  return (
    <Chip tone={patchTone(status)}>
      {status === 'installing' && <span className="spinner" style={{ width: 10, height: 10, borderWidth: 1.5 }} />}
      {status}
    </Chip>
  );
}

export function AlertStatusChip({ status }: { status: string }) {
  const tone: Tone = status === 'open' ? 'danger' : status === 'acked' ? 'warn' : 'ok';
  return <Chip tone={tone}>{status}</Chip>;
}

export function OnlineDot({ online, title }: { online: boolean; title?: string }) {
  return <span className={`dot ${online ? 'on' : 'off'}`} title={title ?? (online ? 'Online' : 'Offline')} />;
}

// ---------- bars ----------

export function Bar({ value, warn = 80, danger = 90, title }: { value: number | undefined; warn?: number; danger?: number; title?: string }) {
  const v = value === undefined || !Number.isFinite(value) ? 0 : Math.min(100, Math.max(0, value));
  const cls = v >= danger ? 'danger' : v >= warn ? 'warn' : '';
  return (
    <span className={`bar ${cls}`} title={title} role="progressbar" aria-valuenow={Math.round(v)} aria-valuemin={0} aria-valuemax={100}>
      <i style={{ width: `${v}%` }} />
    </span>
  );
}

export function MiniBar({ value, title }: { value: number | undefined; title?: string }) {
  if (value === undefined || !Number.isFinite(value)) return <span className="muted">—</span>;
  return (
    <span className="mini-bar" title={title}>
      <Bar value={value} />
      <span>{Math.round(value)}%</span>
    </span>
  );
}

// ---------- states ----------

export function Empty({ title, children, icon }: { title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="empty">
      {icon && <div className="icon">{icon}</div>}
      <h3>{title}</h3>
      {children && <div className="small">{children}</div>}
    </div>
  );
}

export function Skeleton({ rows = 5, cols = 4 }: { rows?: number; cols?: number }) {
  return (
    <div className="stack" style={{ padding: 12 }} aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="row" style={{ flexWrap: 'nowrap' }}>
          {Array.from({ length: cols }).map((__, c) => (
            <span key={c} className="skeleton" style={{ flex: c === 0 ? 2 : 1 }} />
          ))}
        </div>
      ))}
    </div>
  );
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="empty row" style={{ justifyContent: 'center' }}>
      <span className="spinner" /> {label}
    </div>
  );
}

export function ErrorBox({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <div className="banner danger">
      <span style={{ flex: 1 }}>{error}</span>
      {onRetry && (
        <Button size="sm" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

interface EBState {
  error: Error | null;
}

export class ErrorBoundary extends Component<{ children: ReactNode; fallback?: ReactNode }, EBState> {
  state: EBState = { error: null };
  static getDerivedStateFromError(error: Error): EBState {
    return { error };
  }
  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('render error', error, info.componentStack);
  }
  render() {
    if (this.state.error) {
      return (
        this.props.fallback ?? (
          <div className="card" style={{ margin: 20 }}>
            <div className="card-body">
              <h3>Something went wrong</h3>
              <p className="muted small mono">{this.state.error.message}</p>
              <Button onClick={() => this.setState({ error: null })}>Try again</Button>
            </div>
          </div>
        )
      );
    }
    return this.props.children;
  }
}

// ---------- tabs ----------

export function Tabs<T extends string>({
  tabs,
  value,
  onChange,
}: {
  tabs: { id: T; label: ReactNode; count?: number }[];
  value: T;
  onChange: (t: T) => void;
}) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={t.id === value} className={t.id === value ? 'active' : ''} onClick={() => onChange(t.id)}>
          {t.label}
          {t.count !== undefined && <span className="count">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

// ---------- dropdown menu ----------

export function Dropdown({
  trigger,
  children,
  align = 'right',
  menuClassName = '',
  closeOnClick = true,
  onOpen,
}: {
  trigger: ReactNode;
  children: ReactNode;
  align?: 'left' | 'right';
  /** extra classes on the menu panel (width, padding) */
  menuClassName?: string;
  /** false for a panel you interact with (a list, a filter) rather than a menu of verbs */
  closeOnClick?: boolean;
  onOpen?: () => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);
  return (
    <div className="dropdown" ref={ref}>
      <span
        onClick={() =>
          setOpen((o) => {
            if (!o) onOpen?.();
            return !o;
          })
        }
      >
        {trigger}
      </span>
      {open && (
        <div
          className={`menu ${menuClassName}`.trim()}
          style={align === 'left' ? { left: 0, right: 'auto' } : undefined}
          onClick={closeOnClick ? () => setOpen(false) : undefined}
        >
          {children}
        </div>
      )}
    </div>
  );
}

/** Convenience hook: a boolean toggle plus setters. */
export function useToggle(initial = false): [boolean, () => void, (v: boolean) => void] {
  const [v, setV] = useState(initial);
  const toggle = useCallback(() => setV((x) => !x), []);
  return [v, toggle, setV];
}
