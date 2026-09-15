import { useCallback, useEffect, useRef, useState } from 'react';
import { Button } from '../../components/ui';
import { IconClipboard, IconExpand, IconRefresh, IconStop } from '../../components/Icons';
import { bytes } from '../../lib/format';
import { useToast } from '../../state/toast';
import type { TabProps } from './DeviceDetail';

// Implements docs/DESKTOP-PROTOCOL.md. The server bridges frames verbatim, so
// everything here talks to the helper directly: JSON text frames for control
// and input, little-endian binary frames for tiles.

type Status = 'idle' | 'connecting' | 'connected' | 'closed' | 'error';

interface MonitorInfo {
  index: number;
  x: number;
  y: number;
  w: number;
  h: number;
  primary?: boolean;
}

interface ScreenMsg {
  t: 'screen';
  w: number;
  h: number;
  monitor: number;
  monitors?: MonitorInfo[];
}

interface TextMsg {
  t: string;
  message?: string;
  text?: string;
  x?: number;
  y?: number;
}

function wsURL(path: string): string {
  return `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}${path}`;
}

const TILE = 0x01;
const FRAME_END = 0x02;

/** createImageBitmap is fastest; older Safari decodes through an <img>. */
function decodeImage(blob: Blob): Promise<ImageBitmap | HTMLImageElement> {
  if (typeof createImageBitmap === 'function') return createImageBitmap(blob);
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(blob);
    const img = new Image();
    img.onload = () => {
      URL.revokeObjectURL(url);
      resolve(img);
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error('image decode failed'));
    };
    img.src = url;
  });
}

export function Desktop({ agent, canWrite }: TabProps) {
  const toast = useToast();
  const wrap = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const ws = useRef<WebSocket | null>(null);
  const screen = useRef({ w: 0, h: 0 });
  const drawQueue = useRef<Promise<void>>(Promise.resolve());
  const pressed = useRef(new Set<string>());
  const mouseDown = useRef(new Set<number>());
  const lastPoint = useRef({ x: 0, y: 0 });
  const moveRaf = useRef(0);
  const pendingMove = useRef<{ x: number; y: number } | null>(null);
  const stats = useRef({ frames: 0, bytes: 0 });

  const [status, setStatus] = useState<Status>('idle');
  const [note, setNote] = useState('');
  const [detail, setDetail] = useState('');
  const [monitors, setMonitors] = useState<MonitorInfo[]>([]);
  const [monitor, setMonitor] = useState(0);
  const [quality, setQuality] = useState(60);
  const [dims, setDims] = useState({ w: 0, h: 0 });
  const [fps, setFps] = useState(0);
  const [kbps, setKbps] = useState(0);
  const [remoteClip, setRemoteClip] = useState('');
  const [fullscreen, setFullscreen] = useState(false);
  const viewOnly = !canWrite;

  const send = useCallback((msg: Record<string, unknown>) => {
    const s = ws.current;
    if (s && s.readyState === WebSocket.OPEN) s.send(JSON.stringify(msg));
  }, []);

  /** Scale the canvas CSS box to fit the wrapper while keeping the aspect ratio. */
  const layout = useCallback(() => {
    const c = canvas.current;
    const w = wrap.current;
    if (!c || !w || !screen.current.w) return;
    const bw = w.clientWidth;
    const bh = w.clientHeight;
    const scale = Math.min(bw / screen.current.w, bh / screen.current.h);
    c.style.width = `${Math.floor(screen.current.w * scale)}px`;
    c.style.height = `${Math.floor(screen.current.h * scale)}px`;
  }, []);

  const drawTile = useCallback((buf: ArrayBuffer) => {
    const dv = new DataView(buf);
    const x = dv.getUint16(1, true);
    const y = dv.getUint16(3, true);
    const w = dv.getUint16(5, true);
    const h = dv.getUint16(7, true);
    const codec = dv.getUint8(9);
    if (!w || !h) return; // an empty rectangle has nothing to paint
    const blob = new Blob([buf.slice(10)], { type: codec === 1 ? 'image/png' : 'image/jpeg' });
    // Decoding is async; chain it so tiles land in wire order and the frame
    // ack goes out only after the last tile of the frame is painted.
    drawQueue.current = drawQueue.current.then(async () => {
      try {
        const img = await decodeImage(blob);
        const ctx = canvas.current?.getContext('2d');
        if (ctx) ctx.drawImage(img, x, y, w, h);
        if ('close' in img) img.close();
      } catch (err) {
        console.warn('tile decode failed', err);
      }
    });
  }, []);

  const connect = useCallback(() => {
    ws.current?.close();
    setStatus('connecting');
    setDetail('');
    setNote('');
    drawQueue.current = Promise.resolve();
    const s = new WebSocket(wsURL(`/ws/desktop/${encodeURIComponent(agent.id)}?quality=${quality}`));
    s.binaryType = 'arraybuffer';
    ws.current = s;
    s.onmessage = (e: MessageEvent<ArrayBuffer | string>) => {
      if (typeof e.data === 'string') {
        let m: TextMsg;
        try {
          m = JSON.parse(e.data) as TextMsg;
        } catch {
          return;
        }
        switch (m.t) {
          case 'connected':
            setStatus('connected');
            break;
          case 'screen': {
            const sm = m as unknown as ScreenMsg;
            screen.current = { w: sm.w, h: sm.h };
            const c = canvas.current;
            if (c && (c.width !== sm.w || c.height !== sm.h)) {
              c.width = sm.w;
              c.height = sm.h;
            }
            setDims({ w: sm.w, h: sm.h });
            setMonitor(sm.monitor);
            if (sm.monitors) setMonitors(sm.monitors);
            layout();
            break;
          }
          case 'note':
            setNote(m.message ?? '');
            break;
          case 'clipboard':
            setRemoteClip(m.text ?? '');
            break;
          case 'error':
            setStatus('error');
            setDetail(m.message ?? 'unknown error');
            break;
          case 'cursor':
            // The viewer shows the local cursor; position hints are not needed.
            break;
        }
        return;
      }
      const buf = e.data;
      stats.current.bytes += buf.byteLength;
      if (buf.byteLength < 1) return;
      const kind = new DataView(buf).getUint8(0);
      if (kind === TILE && buf.byteLength >= 10) {
        drawTile(buf);
      } else if (kind === FRAME_END && buf.byteLength >= 5) {
        const frameId = new DataView(buf).getUint32(1, true);
        stats.current.frames++;
        // Ack on the socket that delivered the frame, not ws.current: after a
        // reconnect the old queue would otherwise feed the new helper frame
        // ids from the previous session and defeat its flow control.
        drawQueue.current = drawQueue.current.then(() => {
          if (s.readyState === WebSocket.OPEN) s.send(JSON.stringify({ t: 'ack', frame: frameId }));
        });
      }
    };
    s.onerror = () => {
      setStatus((st) => (st === 'connected' ? 'closed' : 'error'));
      setDetail((d) => d || 'connection failed (is the device online?)');
    };
    s.onclose = (ev) => {
      if (ws.current === s) ws.current = null;
      setStatus((st) => (st === 'error' ? st : 'closed'));
      if (!ev.wasClean && ev.code !== 1000) setDetail((d) => d || `socket closed (${ev.code})`);
      pressed.current.clear();
      mouseDown.current.clear();
    };
  }, [agent.id, quality, drawTile, layout]);

  const disconnect = useCallback(() => {
    ws.current?.close();
    ws.current = null;
    pressed.current.clear();
    mouseDown.current.clear();
    setStatus('closed');
  }, []);

  useEffect(() => {
    const id = window.setTimeout(connect, 50);
    return () => {
      window.clearTimeout(id);
      ws.current?.close();
      ws.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // fit on resize + fullscreen changes
  useEffect(() => {
    const w = wrap.current;
    if (!w) return;
    const ro = new ResizeObserver(layout);
    ro.observe(w);
    const onFs = () => {
      setFullscreen(document.fullscreenElement === w);
      window.setTimeout(layout, 50);
    };
    document.addEventListener('fullscreenchange', onFs);
    return () => {
      ro.disconnect();
      document.removeEventListener('fullscreenchange', onFs);
    };
  }, [layout]);

  // fps / bandwidth counters
  useEffect(() => {
    const id = window.setInterval(() => {
      setFps(stats.current.frames);
      setKbps(stats.current.bytes);
      stats.current = { frames: 0, bytes: 0 };
    }, 1000);
    return () => window.clearInterval(id);
  }, []);

  // ---- input ----

  const toRemote = (e: { clientX: number; clientY: number }) => {
    const c = canvas.current;
    if (!c || !screen.current.w) return null;
    const r = c.getBoundingClientRect();
    if (!r.width || !r.height) return null;
    const x = Math.round(((e.clientX - r.left) / r.width) * screen.current.w);
    const y = Math.round(((e.clientY - r.top) / r.height) * screen.current.h);
    return { x: Math.max(0, Math.min(screen.current.w - 1, x)), y: Math.max(0, Math.min(screen.current.h - 1, y)) };
  };

  const onMouseMove = (e: React.MouseEvent) => {
    if (viewOnly) return;
    const p = toRemote(e);
    if (!p) return;
    lastPoint.current = p;
    pendingMove.current = p;
    if (!moveRaf.current) {
      // coalesce moves to one per animation frame; the helper does not need 1 kHz
      moveRaf.current = requestAnimationFrame(() => {
        moveRaf.current = 0;
        if (pendingMove.current) send({ t: 'mousemove', ...pendingMove.current });
        pendingMove.current = null;
      });
    }
  };
  const onMouseButton = (kind: 'mousedown' | 'mouseup') => (e: React.MouseEvent) => {
    wrap.current?.focus();
    e.preventDefault();
    if (viewOnly) return;
    const p = toRemote(e);
    if (!p) return;
    lastPoint.current = p;
    if (kind === 'mousedown') mouseDown.current.add(e.button);
    else mouseDown.current.delete(e.button);
    send({ t: kind, button: e.button, ...p });
  };

  // A drag that ends outside the canvas never delivers mouseup to it; without
  // this the remote keeps the button held ("sticky click"). Listen on the
  // window and release whatever is still pressed at the last known point.
  useEffect(() => {
    const release = (e?: MouseEvent) => {
      if (!mouseDown.current.size) return;
      const p = (e && toRemote(e)) ?? lastPoint.current;
      for (const b of mouseDown.current) send({ t: 'mouseup', button: b, ...p });
      mouseDown.current.clear();
    };
    const onUp = (e: MouseEvent) => {
      if (mouseDown.current.has(e.button)) {
        const p = toRemote(e) ?? lastPoint.current;
        mouseDown.current.delete(e.button);
        send({ t: 'mouseup', button: e.button, ...p });
      }
    };
    const onBlur = () => release();
    window.addEventListener('mouseup', onUp);
    window.addEventListener('blur', onBlur);
    return () => {
      window.removeEventListener('mouseup', onUp);
      window.removeEventListener('blur', onBlur);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [send]);
  const onWheel = (e: React.WheelEvent) => {
    if (viewOnly) return;
    const p = toRemote(e);
    if (!p) return;
    // normalise line/page scrolling to pixels (~100 per notch)
    const k = e.deltaMode === 1 ? 33 : e.deltaMode === 2 ? 100 : 1;
    send({ t: 'wheel', dx: Math.round(e.deltaX * k), dy: Math.round(e.deltaY * k), ...p });
  };

  useEffect(() => {
    const w = wrap.current;
    if (!w) return;
    const key = (kind: 'keydown' | 'keyup') => (e: KeyboardEvent) => {
      if (viewOnly || status !== 'connected') return;
      // Everything goes to the remote while the viewer is focused, including
      // Tab, F-keys and Ctrl+W. Escape leaves fullscreen only when held with
      // Shift so a bare Escape still reaches remote apps.
      e.preventDefault();
      e.stopPropagation();
      // Auto-repeat arrives as repeated keydowns; they are forwarded as-is so
      // held keys repeat remotely exactly as the browser reports them.
      if (kind === 'keydown') pressed.current.add(e.code);
      else pressed.current.delete(e.code);
      send({ t: kind, code: e.code, key: e.key, ctrl: e.ctrlKey, alt: e.altKey, shift: e.shiftKey, meta: e.metaKey });
    };
    const kd = key('keydown');
    const ku = key('keyup');
    const onBlur = () => {
      // release anything still held so the remote never sees a stuck modifier
      for (const code of pressed.current) send({ t: 'keyup', code, key: '', ctrl: false, alt: false, shift: false, meta: false });
      pressed.current.clear();
    };
    // wheel must be non-passive to preventDefault page scroll
    const wheelBlock = (e: WheelEvent) => e.preventDefault();
    w.addEventListener('keydown', kd);
    w.addEventListener('keyup', ku);
    w.addEventListener('blur', onBlur);
    w.addEventListener('wheel', wheelBlock, { passive: false });
    return () => {
      w.removeEventListener('keydown', kd);
      w.removeEventListener('keyup', ku);
      w.removeEventListener('blur', onBlur);
      w.removeEventListener('wheel', wheelBlock);
    };
  }, [send, status, viewOnly]);

  const pasteClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (!text) return toast.info('Clipboard is empty');
      send({ t: 'paste', text });
      toast.success('Pasted', `${text.length} characters`);
    } catch {
      toast.error('Clipboard read blocked', 'Allow clipboard access for this site, or use a secure (HTTPS) context.');
    }
    wrap.current?.focus();
  };
  const copyRemote = async () => {
    if (!remoteClip) return;
    await navigator.clipboard.writeText(remoteClip);
    toast.success('Remote clipboard copied');
  };
  const toggleFullscreen = () => {
    const w = wrap.current;
    if (!w) return;
    if (document.fullscreenElement) void document.exitFullscreen();
    else void w.requestFullscreen?.();
  };

  const live = status === 'connected';

  return (
    <div className="fill-page">
      <div className="toolbar">
        {live || status === 'connecting' ? (
          <Button onClick={disconnect}>
            <IconStop /> Disconnect
          </Button>
        ) : (
          <Button variant="primary" onClick={connect}>
            <IconRefresh /> {status === 'idle' ? 'Connect' : 'Reconnect'}
          </Button>
        )}
        {monitors.length > 1 && (
          <select
            value={monitor}
            disabled={!live}
            onChange={(e) => {
              const idx = +e.target.value;
              setMonitor(idx);
              send({ t: 'monitor', index: idx });
            }}
            style={{ width: 200 }}
            aria-label="Monitor"
          >
            {monitors.map((mo) => (
              <option key={mo.index} value={mo.index}>
                Monitor {mo.index + 1} · {mo.w}×{mo.h}
                {mo.primary ? ' (primary)' : ''}
              </option>
            ))}
          </select>
        )}
        <label className="row small muted" style={{ gap: 6 }}>
          Quality
          <input
            type="range"
            min={10}
            max={100}
            step={5}
            value={quality}
            onChange={(e) => {
              const q = +e.target.value;
              setQuality(q);
              send({ t: 'quality', q });
            }}
            style={{ width: 110 }}
            aria-label="JPEG quality"
          />
          {quality}
        </label>
        <Button onClick={() => send({ t: 'refresh' })} disabled={!live} title="Request a full frame">
          <IconRefresh /> Refresh
        </Button>
        {!viewOnly && (
          <>
            <Button onClick={() => send({ t: 'ctrlaltdel' })} disabled={!live} title="Send Ctrl+Alt+Del (Windows: needs SoftwareSASGeneration policy)">
              Ctrl+Alt+Del
            </Button>
            <Button onClick={pasteClipboard} disabled={!live} title="Type your clipboard into the remote session">
              <IconClipboard /> Paste
            </Button>
          </>
        )}
        {remoteClip && (
          <Button onClick={copyRemote} title="Copy the remote clipboard locally">
            Remote clipboard
          </Button>
        )}
        <span className="grow" />
        <Button onClick={toggleFullscreen} title="Fullscreen (Shift+Esc leaves)">
          <IconExpand /> {fullscreen ? 'Exit fullscreen' : 'Fullscreen'}
        </Button>
      </div>
      <div
        className="desktop-wrap"
        ref={wrap}
        tabIndex={0}
        role="application"
        aria-label={`Remote desktop of ${agent.display_name}; keyboard input goes to the remote session while focused`}
        onContextMenu={(e) => e.preventDefault()}
        onKeyDownCapture={(e) => {
          if (e.key === 'Escape' && e.shiftKey && document.fullscreenElement) void document.exitFullscreen();
        }}
      >
        <canvas
          ref={canvas}
          className="show-cursor"
          onMouseMove={onMouseMove}
          onMouseDown={onMouseButton('mousedown')}
          onMouseUp={onMouseButton('mouseup')}
          onWheel={onWheel}
          onDoubleClick={(e) => e.preventDefault()}
          style={{ display: dims.w ? 'block' : 'none' }}
        />
        {(status !== 'connected' || !dims.w) && (
          <div className="desktop-status">
            {status === 'connecting' && (
              <>
                <span className="spinner" /> Starting desktop helper on {agent.display_name}…
              </>
            )}
            {status === 'connected' && !dims.w && (
              <>
                <span className="spinner" /> Waiting for the first frame…
              </>
            )}
            {status === 'closed' && 'Disconnected'}
            {status === 'error' && <span style={{ color: 'var(--danger)' }}>{detail || 'Error'}</span>}
            {status === 'idle' && 'Not connected'}
          </div>
        )}
        {fullscreen && (
          <div className="desktop-status" style={{ top: 12, transform: 'translateX(-50%)', padding: '4px 10px', fontSize: 12, opacity: 0.8 }}>
            {agent.display_name} · Shift+Esc to leave fullscreen
          </div>
        )}
      </div>
      <div className="statusline">
        <span className={`dot ${live ? 'on' : status === 'connecting' ? 'warn' : 'off'}`} />
        <span>
          {status === 'idle' && 'Not connected'}
          {status === 'connecting' && 'Connecting…'}
          {status === 'connected' && `Connected${dims.w ? ` · ${dims.w}×${dims.h}` : ''}`}
          {status === 'closed' && 'Disconnected'}
          {status === 'error' && 'Error'}
        </span>
        {note && <span style={{ color: 'var(--warn)' }}>{note}</span>}
        {detail && status === 'error' && <span style={{ color: 'var(--danger)' }}>{detail}</span>}
        {viewOnly && <span className="chip warn">view only</span>}
        <span className="ml-auto mono">
          {fps} fps · {bytes(kbps)}/s
        </span>
      </div>
    </div>
  );
}
