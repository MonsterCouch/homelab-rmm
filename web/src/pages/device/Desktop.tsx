import { useCallback, useEffect, useRef, useState } from 'react';
import { Button, Dropdown } from '../../components/ui';
import { IconClipboard, IconExpand, IconKeyboard, IconMore, IconRefresh, IconStop } from '../../components/Icons';
import { bytes } from '../../lib/format';
import { host } from '../../lib/host';
import { useToast } from '../../state/toast';
import type { TabProps } from './DeviceDetail';
import { copyText, readClipboard } from './clipboard';
import { KeyBar, KeyButton } from './KeyBar';
import { coarsePointer, useCoarsePointer, useFillHeight } from './touch';
import { createTrackpad } from './trackpad';
import '../../styles/device-touch.css';

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

// ---- wheel normalisation (docs/DESKTOP-PROTOCOL.md) ----
//
// One wheel notch is 100 units on the wire. Browsers disagree wildly about
// what a notch is worth — Chrome on Windows reports 120 px, on Linux 100 or
// 53, Firefox reports 3 *lines*, and page mode reports 1 *page* — so a raw
// delta forwarded as pixels makes the helper scroll twice every fifth notch
// (its carried remainder reaches 100) or swallow every other one. Whole
// notches are sent instead: a mouse-wheel event is one deliberate click
// whatever the browser calls it. Sub-notch deltas are trackpad scrolling and
// go through untouched so the helper can accumulate them into a notch.
const WHEEL_NOTCH = 100;
/** Lines per notch in deltaMode 1 (Firefox's default wheel step). */
const WHEEL_LINES_PER_NOTCH = 3;
/** Below this many pixels a deltaMode-0 event is trackpad scrolling. */
const WHEEL_TRACKPAD_MAX = 40;

/** Round to a whole count away from zero, never below one. */
function notchCount(v: number): number {
  const n = Math.max(1, Math.round(Math.abs(v)));
  return v < 0 ? -n : n;
}

/**
 * wheelWire converts one axis of a WheelEvent into the wire delta: whole
 * notches of 100 for anything the user meant as a wheel click, the raw delta
 * for trackpad-sized pixel scrolling, 0 for nothing.
 */
function wheelWire(delta: number, deltaMode: number): number {
  if (!Number.isFinite(delta) || delta === 0) return 0;
  if (deltaMode === 1) return notchCount(delta / WHEEL_LINES_PER_NOTCH) * WHEEL_NOTCH; // lines
  if (deltaMode === 2) return notchCount(delta) * WHEEL_NOTCH; // pages
  // Pixels: a trackpad flick is left alone, a wheel click is rounded to notches.
  if (Math.abs(delta) < WHEEL_TRACKPAD_MAX) return delta;
  return notchCount(delta / WHEEL_NOTCH) * WHEEL_NOTCH;
}

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

// ---- touch (task C14) ----

/** JPEG quality: 60 on a desk, 35 on a phone, where the link is the bottleneck. */
const QUALITY_DESK = 60;
const QUALITY_TOUCH = 35;
/** Hard ceiling for pinch zoom. Past 4x a tile is mush anyway. */
const MAX_ZOOM = 4;
/** A mouse event this soon after a touch is a compatibility event; ignore it. */
const TOUCH_GUARD_MS = 700;

/** Named keys an Android IME reports with `code: ""` and `key: "Unidentified"`. */
const NAMED_KEYS: Readonly<Record<string, string>> = {
  Enter: 'Enter',
  Backspace: 'Backspace',
  Tab: 'Tab',
  Escape: 'Escape',
  Delete: 'Delete',
  Insert: 'Insert',
  ArrowUp: 'ArrowUp',
  ArrowDown: 'ArrowDown',
  ArrowLeft: 'ArrowLeft',
  ArrowRight: 'ArrowRight',
  Home: 'Home',
  End: 'End',
  PageUp: 'PageUp',
  PageDown: 'PageDown',
};

/**
 * The W3C `code` to put on the wire, or '' for a printable rune (which goes
 * through `{t:'paste'}` instead — `keymap.go` only falls back to `key` for
 * single printable runes, and Android IMEs report `code:""`).
 */
function w3cCode(key: string, code: string): string {
  if ([...key].length === 1) return '';
  if (code && code !== 'Unidentified') return code;
  return NAMED_KEYS[key] ?? '';
}

interface Mods {
  ctrl: boolean;
  alt: boolean;
  shift: boolean;
  meta: boolean;
}
const NO_MODS: Mods = { ctrl: false, alt: false, shift: false, meta: false };
const MOD_KEYS: readonly { id: keyof Mods; label: string; code: string; key: string }[] = [
  { id: 'ctrl', label: 'Ctrl', code: 'ControlLeft', key: 'Control' },
  { id: 'alt', label: 'Alt', code: 'AltLeft', key: 'Alt' },
  { id: 'shift', label: 'Shift', code: 'ShiftLeft', key: 'Shift' },
  { id: 'meta', label: 'Win', code: 'MetaLeft', key: 'Meta' },
];

const DESKTOP_KEYS: readonly { label: string; title: string; code: string; key: string; wide?: boolean }[] = [
  { label: 'Esc', title: 'Escape', code: 'Escape', key: 'Escape', wide: true },
  { label: 'Tab', title: 'Tab', code: 'Tab', key: 'Tab', wide: true },
  { label: '↵', title: 'Enter', code: 'Enter', key: 'Enter' },
  { label: '⌫', title: 'Backspace', code: 'Backspace', key: 'Backspace' },
  { label: 'Del', title: 'Delete', code: 'Delete', key: 'Delete', wide: true },
  { label: '↑', title: 'Up arrow', code: 'ArrowUp', key: 'ArrowUp' },
  { label: '↓', title: 'Down arrow', code: 'ArrowDown', key: 'ArrowDown' },
  { label: '←', title: 'Left arrow', code: 'ArrowLeft', key: 'ArrowLeft' },
  { label: '→', title: 'Right arrow', code: 'ArrowRight', key: 'ArrowRight' },
  { label: 'Home', title: 'Home', code: 'Home', key: 'Home', wide: true },
  { label: 'End', title: 'End', code: 'End', key: 'End', wide: true },
  { label: 'PgUp', title: 'Page up', code: 'PageUp', key: 'PageUp', wide: true },
  { label: 'PgDn', title: 'Page down', code: 'PageDown', key: 'PageDown', wide: true },
  { label: 'F2', title: 'F2', code: 'F2', key: 'F2' },
  { label: 'F5', title: 'F5', code: 'F5', key: 'F5' },
  { label: 'F11', title: 'F11', code: 'F11', key: 'F11', wide: true },
];

const clamp = (v: number, lo: number, hi: number) => (v < lo ? lo : v > hi ? hi : v);

export function Desktop({ agent, canWrite }: TabProps) {
  const toast = useToast();
  const page = useRef<HTMLDivElement>(null);
  const wrap = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const cursorEl = useRef<HTMLDivElement>(null);
  const kbd = useRef<HTMLInputElement>(null);
  const ws = useRef<WebSocket | null>(null);
  const screen = useRef({ w: 0, h: 0 });
  const drawQueue = useRef<Promise<void>>(Promise.resolve());
  const pressed = useRef(new Set<string>());
  const mouseDown = useRef(new Set<number>());
  const lastPoint = useRef({ x: 0, y: 0 });
  const moveRaf = useRef(0);
  const pendingMove = useRef<{ x: number; y: number } | null>(null);
  const stats = useRef({ frames: 0, bytes: 0 });

  // touch state
  /** Where the trackpad cursor is, in remote pixels (fractional while zoomed). */
  const cursor = useRef({ x: 0, y: 0 });
  /** CSS pixels per remote pixel, i.e. the canvas's current display scale. */
  const scaleRef = useRef(0);
  const zoomRef = useRef<'fit' | number>('fit');
  const lastTouchAt = useRef(0);
  const touchModeRef = useRef(false);
  const composing = useRef(false);

  const [status, setStatus] = useState<Status>('idle');
  const [note, setNote] = useState('');
  const [detail, setDetail] = useState('');
  const [monitors, setMonitors] = useState<MonitorInfo[]>([]);
  const [monitor, setMonitor] = useState(0);
  const [quality, setQuality] = useState(() => (coarsePointer() ? QUALITY_TOUCH : QUALITY_DESK));
  const [dims, setDims] = useState({ w: 0, h: 0 });
  const [fps, setFps] = useState(0);
  const [kbps, setKbps] = useState(0);
  const [remoteClip, setRemoteClip] = useState('');
  const [fullscreen, setFullscreen] = useState(false);
  const [zoom, setZoom] = useState<'fit' | number>('fit');
  const [touchMode, setTouchMode] = useState(false);
  const [mods, setMods] = useState<Mods>(NO_MODS);
  const touchUI = useCoarsePointer();
  const viewOnly = !canWrite;
  const viewOnlyRef = useRef(viewOnly);
  viewOnlyRef.current = viewOnly;

  const send = useCallback((msg: Record<string, unknown>) => {
    const s = ws.current;
    if (s && s.readyState === WebSocket.OPEN) s.send(JSON.stringify(msg));
  }, []);

  /** A mouse event that Chromium synthesised from a touch we already handled. */
  const fromTouch = () => performance.now() - lastTouchAt.current < TOUCH_GUARD_MS;

  /** The scale at which the whole remote screen fits the wrapper. */
  const fitScale = useCallback(() => {
    const w = wrap.current;
    if (!w || !screen.current.w || !screen.current.h) return 0;
    return Math.min(w.clientWidth / screen.current.w, w.clientHeight / screen.current.h);
  }, []);

  /** Put the cursor marker where the trackpad cursor is. */
  const drawCursor = useCallback(() => {
    const c = canvas.current;
    const m = cursorEl.current;
    if (!c || !m || !scaleRef.current) return;
    // offsetLeft/Top, not a client rect: the marker is a child of the wrapper
    // and scrolls with it, so a rect would count the scroll offset twice.
    const x = c.offsetLeft + cursor.current.x * scaleRef.current;
    const y = c.offsetTop + cursor.current.y * scaleRef.current;
    m.style.transform = `translate(${x}px, ${y}px)`;
  }, []);

  /**
   * Size the canvas's CSS box. `zoomRef` is 'fit' (the old behaviour, and
   * still the default) or an explicit scale set by pinch or the Fit/1:1
   * toggle. `toRemote()` derives from a client rect, so it stays correct at
   * any zoom.
   */
  const layout = useCallback(() => {
    const c = canvas.current;
    const w = wrap.current;
    if (!c || !w || !screen.current.w) return;
    const fitS = fitScale();
    const z = zoomRef.current;
    const scale = z === 'fit' ? fitS : z;
    if (!scale) return;
    scaleRef.current = scale;
    c.style.width = `${Math.floor(screen.current.w * scale)}px`;
    c.style.height = `${Math.floor(screen.current.h * scale)}px`;
    drawCursor();
  }, [fitScale, drawCursor]);

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
            // Park the trackpad cursor in the middle of the new screen.
            cursor.current = { x: Math.floor(sm.w / 2), y: Math.floor(sm.h / 2) };
            lastPoint.current = { x: cursor.current.x, y: cursor.current.y };
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

  // Fill what the visual viewport actually leaves (C14, shared with C8).
  useFillHeight(page, layout);

  useEffect(() => {
    zoomRef.current = zoom;
    layout();
  }, [zoom, layout]);

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
    if (viewOnly || fromTouch()) return;
    const p = toRemote(e);
    if (!p) return;
    lastPoint.current = p;
    cursor.current = { x: p.x, y: p.y };
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
    if (fromTouch()) return;
    wrap.current?.focus();
    e.preventDefault();
    if (viewOnly) return;
    const p = toRemote(e);
    if (!p) return;
    lastPoint.current = p;
    cursor.current = { x: p.x, y: p.y };
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
      if (fromTouch()) return;
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
    if (viewOnly || fromTouch()) return;
    const p = toRemote(e);
    if (!p) return;
    const dx = wheelWire(e.deltaX, e.deltaMode);
    const dy = wheelWire(e.deltaY, e.deltaMode);
    if (!dx && !dy) return; // nothing the helper could act on
    send({ t: 'wheel', dx, dy, ...p });
  };

  // ---- touch: the trackpad (C14) ----

  /** Queue a mousemove for the current cursor, one per animation frame. */
  const flushCursor = useCallback(() => {
    const p = { x: Math.round(cursor.current.x), y: Math.round(cursor.current.y) };
    lastPoint.current = p;
    pendingMove.current = p;
    if (!moveRaf.current) {
      moveRaf.current = requestAnimationFrame(() => {
        moveRaf.current = 0;
        if (pendingMove.current) send({ t: 'mousemove', ...pendingMove.current });
        pendingMove.current = null;
        drawCursor();
      });
    }
  }, [send, drawCursor]);

  const pinchZoom = useCallback(
    (factor: number, cx: number, cy: number) => {
      const w = wrap.current;
      const c = canvas.current;
      if (!w || !c || !screen.current.w) return;
      const old = scaleRef.current;
      const fitS = fitScale();
      if (!old || !fitS) return;
      const next = clamp(old * factor, fitS, MAX_ZOOM);
      if (Math.abs(next - old) < 0.0005) return;
      // Where the pinch centre sits on the remote screen, so it can be put
      // back under the fingers after the resize.
      const r = c.getBoundingClientRect();
      const rx = (cx - r.left) / old;
      const ry = (cy - r.top) / old;
      const z: 'fit' | number = next <= fitS * 1.02 ? 'fit' : next;
      zoomRef.current = z;
      layout();
      setZoom(z);
      w.scrollLeft += rx * (scaleRef.current - old);
      w.scrollTop += ry * (scaleRef.current - old);
      drawCursor();
    },
    [fitScale, layout, drawCursor],
  );

  useEffect(() => {
    const c = canvas.current;
    if (!c) return;
    const press = (button: number, down: boolean) => {
      if (viewOnlyRef.current) return;
      const p = { x: Math.round(cursor.current.x), y: Math.round(cursor.current.y) };
      lastPoint.current = p;
      if (down) mouseDown.current.add(button);
      else mouseDown.current.delete(button);
      send({ t: down ? 'mousedown' : 'mouseup', button, ...p });
    };
    const tp = createTrackpad({
      move: (dx, dy) => {
        if (viewOnlyRef.current) return;
        const s = scaleRef.current;
        if (!s || !screen.current.w) return;
        cursor.current = {
          x: clamp(cursor.current.x + dx / s, 0, screen.current.w - 1),
          y: clamp(cursor.current.y + dy / s, 0, screen.current.h - 1),
        };
        flushCursor();
      },
      down: (b) => press(b, true),
      up: (b) => press(b, false),
      click: (b) => {
        press(b, true);
        press(b, false);
      },
      wheel: (dx, dy) => {
        if (viewOnlyRef.current) return;
        const wx = Math.round(dx);
        const wy = Math.round(dy);
        if (!wx && !wy) return;
        // Sub-notch pixel deltas; the helper accumulates them into a notch.
        send({ t: 'wheel', dx: wx, dy: wy, x: Math.round(cursor.current.x), y: Math.round(cursor.current.y) });
      },
      zoom: (f, cx, cy) => pinchZoom(f, cx, cy),
    });
    const touch = (e: PointerEvent) => e.pointerType !== 'mouse';
    const onDown = (e: PointerEvent) => {
      if (!touch(e)) return;
      lastTouchAt.current = performance.now();
      if (!touchModeRef.current) {
        touchModeRef.current = true;
        setTouchMode(true);
      }
      // Suppresses the compatibility mouse events as well as page panning.
      e.preventDefault();
      try {
        c.setPointerCapture(e.pointerId);
      } catch {
        /* capture is an optimisation, not a requirement */
      }
      tp.onPointerDown(e);
    };
    const onMove = (e: PointerEvent) => {
      if (!touch(e)) return;
      lastTouchAt.current = performance.now();
      e.preventDefault();
      tp.onPointerMove(e);
    };
    const onUp = (e: PointerEvent) => {
      if (!touch(e)) return;
      lastTouchAt.current = performance.now();
      e.preventDefault();
      try {
        c.releasePointerCapture(e.pointerId);
      } catch {
        /* already released */
      }
      tp.onPointerUp(e);
    };
    const onCancel = (e: PointerEvent) => {
      if (!touch(e)) return;
      tp.reset();
    };
    c.addEventListener('pointerdown', onDown, { passive: false });
    c.addEventListener('pointermove', onMove, { passive: false });
    c.addEventListener('pointerup', onUp, { passive: false });
    c.addEventListener('pointercancel', onCancel);
    return () => {
      c.removeEventListener('pointerdown', onDown);
      c.removeEventListener('pointermove', onMove);
      c.removeEventListener('pointerup', onUp);
      c.removeEventListener('pointercancel', onCancel);
      tp.reset();
    };
  }, [send, flushCursor, pinchZoom]);

  // ---- keyboard ----

  useEffect(() => {
    const w = wrap.current;
    if (!w) return;
    const key = (kind: 'keydown' | 'keyup') => (e: KeyboardEvent) => {
      if (viewOnly || status !== 'connected') return;
      // The hidden input has its own handler (soft keyboards need an <input>
      // to raise at all); do not send its events twice.
      if (e.target === kbd.current) return;
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

  const live = status === 'connected';
  const modsRef = useRef(mods);
  modsRef.current = mods;

  /**
   * Send one key with the armed sticky modifiers wrapped around it. The
   * modifiers go on the wire as real ControlLeft/AltLeft/… presses as well as
   * flags, because the helper needs the modifier physically held for the
   * combination to reach the remote application.
   */
  const sendKey = useCallback(
    (code: string, keyName: string) => {
      if (viewOnlyRef.current || !code) return;
      const m = modsRef.current;
      const flags = { ctrl: m.ctrl, alt: m.alt, shift: m.shift, meta: m.meta };
      const held = MOD_KEYS.filter((k) => m[k.id]);
      for (const k of held) send({ t: 'keydown', code: k.code, key: k.key, ...flags });
      send({ t: 'keydown', code, key: keyName, ...flags });
      send({ t: 'keyup', code, key: keyName, ...flags });
      for (const k of [...held].reverse()) send({ t: 'keyup', code: k.code, key: k.key, ...flags });
      if (held.length) setMods(NO_MODS);
    },
    [send],
  );

  /** Typed text goes as `{t:'paste'}` — see w3cCode(). */
  const sendText = useCallback(
    (text: string) => {
      if (viewOnlyRef.current || !text) return;
      send({ t: 'paste', text });
    },
    [send],
  );

  // The native shell's Paste push (C7).
  useEffect(() => host.onPaste((text) => sendText(text)), [sendText]);

  const pasteClipboard = async () => {
    const text = await readClipboard();
    if (text === null) {
      toast.error('Clipboard read blocked', 'Allow clipboard access for this site, or use a secure (HTTPS) context.');
    } else if (!text) {
      toast.info('Clipboard is empty');
    } else {
      send({ t: 'paste', text });
      toast.success('Pasted', `${text.length} characters`);
    }
    if (!touchUI) wrap.current?.focus();
  };
  const copyRemote = async () => {
    if (!remoteClip) return;
    if (await copyText(remoteClip)) toast.success('Remote clipboard copied');
    else toast.error('Copy failed', 'Select the text and copy it with the browser menu.');
  };
  const toggleFullscreen = () => {
    const w = wrap.current;
    if (!w) return;
    if (document.fullscreenElement) void document.exitFullscreen();
    else void w.requestFullscreen?.();
  };
  const openKeyboard = () => {
    const el = kbd.current;
    if (!el) return;
    el.focus({ preventScroll: true });
    el.click();
  };
  const toggleZoom = () => {
    if (zoom === 'fit') setZoom(1);
    else setZoom('fit');
  };
  const toggleMod = (id: keyof Mods) => setMods((m) => ({ ...m, [id]: !m[id] }));

  const monitorSelect = monitors.length > 1 && (
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
  );
  const qualityControl = (
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
  );
  const refreshControl = (
    <Button onClick={() => send({ t: 'refresh' })} disabled={!live} title="Request a full frame">
      <IconRefresh /> Refresh
    </Button>
  );
  const casControl = !viewOnly && (
    <Button onClick={() => send({ t: 'ctrlaltdel' })} disabled={!live} title="Send Ctrl+Alt+Del (Windows: needs SoftwareSASGeneration policy)">
      Ctrl+Alt+Del
    </Button>
  );

  return (
    <div className="fill-page device-fill desktop-page" ref={page}>
      <div className="toolbar">
        {live || status === 'connecting' ? (
          <Button onClick={disconnect} icon={touchUI} aria-label={touchUI ? 'Disconnect' : undefined} title={touchUI ? 'Disconnect' : undefined}>
            <IconStop /> {touchUI ? null : 'Disconnect'}
          </Button>
        ) : (
          <Button variant="primary" onClick={connect}>
            <IconRefresh /> {status === 'idle' ? 'Connect' : 'Reconnect'}
          </Button>
        )}
        {touchUI && !viewOnly && (
          <Button onClick={openKeyboard} disabled={!live} icon aria-label="Keyboard" title="Show the keyboard">
            <IconKeyboard />
          </Button>
        )}
        {touchUI && (
          <Button onClick={toggleZoom} disabled={!dims.w} title={zoom === 'fit' ? 'Zoom to actual size' : 'Fit the screen'}>
            {zoom === 'fit' ? '1:1' : 'Fit'}
          </Button>
        )}
        {!touchUI && monitorSelect}
        {!touchUI && qualityControl}
        {!touchUI && refreshControl}
        {!viewOnly && (
          <>
            {!touchUI && casControl}
            <Button onClick={pasteClipboard} disabled={!live} icon={touchUI} aria-label={touchUI ? 'Paste' : undefined} title="Type your clipboard into the remote session">
              <IconClipboard /> {touchUI ? null : 'Paste'}
            </Button>
          </>
        )}
        {remoteClip && (
          <Button onClick={copyRemote} title="Copy the remote clipboard locally">
            {touchUI ? 'Remote clip' : 'Remote clipboard'}
          </Button>
        )}
        {touchUI && (
          <Dropdown
            closeOnClick={false}
            menuClassName="desktop-overflow"
            trigger={
              <button className="btn icon" aria-label="More viewer controls">
                <IconMore />
              </button>
            }
          >
            {monitorSelect}
            {qualityControl}
            {refreshControl}
            {casControl}
          </Dropdown>
        )}
        <span className="grow" />
        <Button onClick={toggleFullscreen} icon={touchUI} aria-label={touchUI ? 'Fullscreen' : undefined} title="Fullscreen (Shift+Esc leaves)">
          <IconExpand /> {touchUI ? null : fullscreen ? 'Exit fullscreen' : 'Fullscreen'}
        </Button>
      </div>
      <div
        className={`desktop-wrap${zoom === 'fit' ? '' : ' is-zoomed'}${touchMode ? ' touch-mode' : ''}`}
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
        {/* The trackpad cursor. A finger has no pointer of its own, so the
            viewer draws the one the taps act on. */}
        <div className="desktop-cursor" ref={cursorEl} aria-hidden="true" style={{ display: touchMode && dims.w ? 'block' : 'none' }} />
        {/* A focusable input is the only thing that raises an Android soft
            keyboard; a tabIndex div never does. */}
        <input
          ref={kbd}
          className="desktop-kbd"
          aria-label="Remote keyboard input"
          autoCapitalize="none"
          autoCorrect="off"
          autoComplete="off"
          spellCheck={false}
          inputMode="text"
          enterKeyHint="send"
          defaultValue=""
          disabled={viewOnly}
          onCompositionStart={() => (composing.current = true)}
          onCompositionEnd={(e) => {
            composing.current = false;
            const el = e.currentTarget;
            const text = el.value;
            el.value = '';
            sendText(text);
          }}
          onChange={(e) => {
            if (composing.current) return;
            const el = e.currentTarget;
            const text = el.value;
            el.value = '';
            sendText(text);
          }}
          onKeyDown={(e) => {
            const code = w3cCode(e.key, e.code);
            if (!code) return; // a printable rune; the change handler pastes it
            e.preventDefault();
            sendKey(code, e.key);
          }}
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
      {!viewOnly && (
        <KeyBar label="Remote desktop keys">
          {MOD_KEYS.map((k) => (
            <KeyButton key={k.id} title={`${k.label} — applies to the next key`} on={mods[k.id]} wide onPress={() => toggleMod(k.id)} disabled={!live}>
              {k.label}
            </KeyButton>
          ))}
          {DESKTOP_KEYS.map((k) => (
            <KeyButton key={k.title} title={k.title} wide={k.wide} disabled={!live} onPress={() => sendKey(k.code, k.key)}>
              {k.label}
            </KeyButton>
          ))}
        </KeyBar>
      )}
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
        {touchUI && dims.w > 0 && <span className="small muted">{zoom === 'fit' ? 'Fit' : `${Math.round(scaleRef.current * 100)}%`}</span>}
        <span className="ml-auto mono">
          {fps} fps · {bytes(kbps)}/s
        </span>
      </div>
    </div>
  );
}
