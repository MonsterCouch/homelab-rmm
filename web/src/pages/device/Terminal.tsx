import { useCallback, useEffect, useRef, useState } from 'react';
import { Terminal as XTerm } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { Button } from '../../components/ui';
import { IconClipboard, IconCopy, IconRefresh, IconStop } from '../../components/Icons';
import { useToast } from '../../state/toast';
import type { TabProps } from './DeviceDetail';

type Status = 'idle' | 'connecting' | 'connected' | 'closed' | 'error';

interface ShellMsg {
  t: 'opened' | 'out' | 'closed' | 'error';
  data?: string;
  message?: string;
  session?: string;
}

function wsURL(path: string): string {
  return `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}${path}`;
}

export function Terminal({ agent }: TabProps) {
  const toast = useToast();
  const host = useRef<HTMLDivElement>(null);
  const term = useRef<XTerm | null>(null);
  const fit = useRef<FitAddon | null>(null);
  const ws = useRef<WebSocket | null>(null);
  const shells = agent.os === 'windows' ? ['powershell', 'cmd'] : ['bash', 'sh'];
  const [shell, setShell] = useState(shells[0]);
  const [status, setStatus] = useState<Status>('idle');
  const [detail, setDetail] = useState('');
  const [size, setSize] = useState({ cols: 0, rows: 0 });

  const send = useCallback((msg: Record<string, unknown>) => {
    const s = ws.current;
    if (s && s.readyState === WebSocket.OPEN) s.send(JSON.stringify(msg));
  }, []);

  const connect = useCallback(() => {
    const t = term.current;
    if (!t) return;
    ws.current?.close();
    setStatus('connecting');
    setDetail('');
    t.reset();
    const s = new WebSocket(wsURL(`/ws/shell/${encodeURIComponent(agent.id)}`));
    ws.current = s;
    s.onopen = () => {
      fit.current?.fit();
      send({ t: 'open', shell, cols: t.cols, rows: t.rows });
    };
    s.onmessage = (e: MessageEvent<string>) => {
      let m: ShellMsg;
      try {
        m = JSON.parse(e.data) as ShellMsg;
      } catch {
        return;
      }
      switch (m.t) {
        case 'opened':
          setStatus('connected');
          t.focus();
          break;
        case 'out':
          if (m.data) t.write(m.data);
          break;
        case 'closed':
          setStatus((st) => (st === 'error' ? st : 'closed'));
          t.write('\r\n\x1b[90m[session closed]\x1b[0m\r\n');
          break;
        case 'error':
          setStatus('error');
          setDetail(m.message ?? 'unknown error');
          t.write(`\r\n\x1b[31m[error] ${m.message ?? ''}\x1b[0m\r\n`);
          break;
      }
    };
    s.onerror = () => {
      setStatus((st) => (st === 'connected' ? 'closed' : 'error'));
      setDetail((d) => d || 'connection failed (is the device online?)');
    };
    s.onclose = (ev) => {
      if (ws.current === s) ws.current = null;
      setStatus((st) => (st === 'error' ? st : 'closed'));
      if (ev.code !== 1000 && ev.code !== 1005 && !ev.wasClean) setDetail((d) => d || `socket closed (${ev.code})`);
    };
  }, [agent.id, shell, send]);

  // create the terminal once
  useEffect(() => {
    const el = host.current;
    if (!el) return;
    // The terminal stays dark in both themes (matches .term-wrap); a light
    // terminal on a light page reads worse than a dark island.
    const t = new XTerm({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: 'ui-monospace, "Cascadia Code", "JetBrains Mono", Menlo, Consolas, monospace',
      scrollback: 5000,
      theme: { background: '#0b0d11', foreground: '#d7dde6', cursor: '#d7dde6' },
    });
    const f = new FitAddon();
    t.loadAddon(f);
    t.open(el);
    f.fit();
    term.current = t;
    fit.current = f;
    setSize({ cols: t.cols, rows: t.rows });

    t.onData((d) => send({ t: 'in', data: d }));
    t.onResize(({ cols, rows }) => {
      setSize({ cols, rows });
      send({ t: 'resize', cols, rows });
    });
    // Ctrl+Shift+C copies, Ctrl+C with a selection copies (Windows habit),
    // Ctrl+Shift+V pastes; plain Ctrl+V is a browser paste that xterm handles.
    t.attachCustomKeyEventHandler((e) => {
      if (e.type !== 'keydown') return true;
      if (e.ctrlKey && (e.key === 'C' || e.key === 'c') && (e.shiftKey || t.hasSelection())) {
        const sel = t.getSelection();
        if (sel) {
          void navigator.clipboard.writeText(sel).catch(() => undefined);
          t.clearSelection();
          return false;
        }
      }
      if (e.ctrlKey && e.shiftKey && (e.key === 'V' || e.key === 'v')) {
        void navigator.clipboard.readText().then((txt) => txt && t.paste(txt)).catch(() => undefined);
        return false;
      }
      return true;
    });
    const ro = new ResizeObserver(() => {
      try {
        f.fit();
      } catch {
        /* container hidden */
      }
    });
    ro.observe(el);
    t.writeln('\x1b[90mPress Connect to open a shell.\x1b[0m');
    return () => {
      ro.disconnect();
      ws.current?.close();
      ws.current = null;
      t.dispose();
      term.current = null;
    };
  }, [send]);

  // auto-connect on mount
  useEffect(() => {
    const id = window.setTimeout(connect, 50);
    return () => window.clearTimeout(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const disconnect = () => {
    send({ t: 'close' });
    ws.current?.close();
  };

  const copySel = async () => {
    const sel = term.current?.getSelection();
    if (!sel) return toast.info('Nothing selected');
    await navigator.clipboard.writeText(sel);
    toast.success('Copied');
  };
  const paste = async () => {
    try {
      const txt = await navigator.clipboard.readText();
      if (txt) term.current?.paste(txt);
      term.current?.focus();
    } catch {
      toast.error('Clipboard read blocked', 'Use Ctrl+V or Ctrl+Shift+V inside the terminal instead.');
    }
  };

  return (
    <div className="fill-page">
      <div className="toolbar">
        <select value={shell} onChange={(e) => setShell(e.target.value)} style={{ width: 130 }} aria-label="Shell">
          {shells.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        {status === 'connected' || status === 'connecting' ? (
          <Button onClick={disconnect}>
            <IconStop /> Disconnect
          </Button>
        ) : (
          <Button variant="primary" onClick={connect}>
            <IconRefresh /> {status === 'idle' ? 'Connect' : 'Reconnect'}
          </Button>
        )}
        <Button onClick={copySel} title="Copy selection (Ctrl+Shift+C)">
          <IconCopy /> Copy
        </Button>
        <Button onClick={paste} title="Paste clipboard (Ctrl+Shift+V)">
          <IconClipboard /> Paste
        </Button>
        <span className="grow" />
        <span className="muted small">Tip: select text to copy; Ctrl+C with a selection copies instead of interrupting.</span>
      </div>
      <div className="term-wrap" ref={host} role="application" aria-label={`Terminal on ${agent.display_name}`} />
      <div className="statusline">
        <span className={`dot ${status === 'connected' ? 'on' : status === 'connecting' ? 'warn' : 'off'}`} />
        <span>
          {status === 'idle' && 'Not connected'}
          {status === 'connecting' && 'Connecting…'}
          {status === 'connected' && `Connected · ${shell}`}
          {status === 'closed' && 'Session closed'}
          {status === 'error' && 'Error'}
        </span>
        {detail && <span style={{ color: 'var(--danger)' }}>{detail}</span>}
        <span className="ml-auto mono">
          {size.cols}×{size.rows}
        </span>
      </div>
    </div>
  );
}
