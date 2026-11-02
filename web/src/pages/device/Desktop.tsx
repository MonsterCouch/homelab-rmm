import { useCallback, useEffect, useRef, useState } from 'react';
import { Button, Dropdown } from '../../components/ui';
import { IconClipboard, IconExpand, IconKeyboard, IconMore, IconRefresh, IconStop } from '../../components/Icons';
import { bps, bytes } from '../../lib/format';
import { GRANT_OPS, ensureGrant } from '../../lib/grants';
import { host } from '../../lib/host';
import { errMsg, useToast } from '../../state/toast';
import type { TabProps } from './DeviceDetail';
import { copyText, readClipboard } from './clipboard';
import { KeyBar, KeyButton } from './KeyBar';
import { coarsePointer, useCoarsePointer, useFillHeight } from './touch';
import { createTrackpad } from './trackpad';
import { ViewerRTC } from './webrtc';
import '../../styles/device-touch.css';

// Implements docs/DESKTOP-PROTOCOL.md. The server bridges frames verbatim, so
// everything here talks to the helper directly: JSON text frames for control
// and input, little-endian binary frames for tiles.
//
// Two engines share the stage. JPEG tiles on the <canvas> start at once and
// are the fallback; WebRTC video (hardware-decoded, ./webrtc.ts) takes over
// when it connects, and hands back to the tiles if it never does or drops.

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
  /** On a note: a wait the helper is in (a screen-share prompt); shown until the first frame. */
  pending?: boolean;
  text?: string;
  x?: number;
  y?: number;
  sdp?: string;
  ice_servers?: RTCIceServer[];
  candidate?: RTCIceCandidateInit;
}

function wsURL(path: string): string {
  return `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}${path}`;
}

const TILE = 0x01;
const FRAME_END = 0x02;

/** WebRTC gets this long after the offer to connect before the tiles stay. */
const RTC_CONNECT_MS = 4000;
/** Grace period for ICE to recover from a transient `disconnected` before
 *  giving up and reverting to tiles; `failed`/`closed` fall back at once. */
const RTC_DISCONNECT_GRACE_MS = 4000;
/** The messages the helper also accepts over the WebRTC data channels. */
const INPUT_TYPES: ReadonlySet<string> = new Set(['mousemove', 'mousedown', 'mouseup', 'wheel', 'keydown', 'keyup', 'paste', 'ctrlaltdel']);

type Transport = 'ws' | 'rtc';
type Mode = 'console' | 'backstage';

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
  const video = useRef<HTMLVideoElement>(null);
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

  // WebRTC state. `rtc` is the live peer connection, if any; `rtcActive` is
  // true once its <video> is playing (and the helper has been told to stop
  // sending tiles); `rtcWatch` is the connect watchdog.
  const rtc = useRef<ViewerRTC | null>(null);
  const rtcActive = useRef(false);
  const rtcWatch = useRef(0);
  const rtcGrace = useRef(0);
  // The helper reads no socket frames until its first screen message (a first
  // Wayland session waits on a portal prompt), so the connect watchdog only
  // runs once a screen has arrived.
  const screenSeen = useRef(false);
  const rtcOnRef = useRef(true);
  const modeRef = useRef<Mode>('console');

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
  // What the helper is waiting for before it can stream, e.g. the person at
  // the machine accepting a screen-share prompt; empty once it is over.
  const [waitNote, setWaitNote] = useState('');
  const [detail, setDetail] = useState('');
  const [monitors, setMonitors] = useState<MonitorInfo[]>([]);
  const [monitor, setMonitor] = useState(0);
  const [quality, setQuality] = useState(() => (coarsePointer() ? QUALITY_TOUCH : QUALITY_DESK));
  const [dims, setDims] = useState({ w: 0, h: 0 });
  const [fps, setFps] = useState(0);
  const [kbps, setKbps] = useState(0);
  const [rttMs, setRttMs] = useState<number | null>(null);
  const [transport, setTransport] = useState<Transport>('ws');
  const [mode, setMode] = useState<Mode>('console');
  const [rtcOn, setRtcOn] = useState(true);
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
    // Input prefers the WebRTC data channels once connected; control messages
    // (ack, monitor, quality, refresh, ...) always ride the WebSocket.
    if (typeof msg.t === 'string' && INPUT_TYPES.has(msg.t) && rtc.current?.connected && rtc.current.sendInput(msg)) return;
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
    // The video sits exactly over the canvas, which keeps the input geometry.
    const v = video.current;
    if (v) {
      v.style.width = c.style.width;
      v.style.height = c.style.height;
      v.style.left = `${c.offsetLeft}px`;
      v.style.top = `${c.offsetTop}px`;
    }
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

  /** Drop the peer connection and its watchdog; back to the tiles' canvas. */
  const closeRTC = useCallback(() => {
    window.clearTimeout(rtcWatch.current);
    rtcWatch.current = 0;
    window.clearTimeout(rtcGrace.current);
    rtcGrace.current = 0;
    const r = rtc.current;
    rtc.current = null;
    rtcActive.current = false;
    r?.close();
    if (video.current) video.current.srcObject = null;
    setTransport('ws');
  }, []);

  /** WebRTC failed or dropped: tell the helper to resume tiles and show them. */
  const rtcFallback = useCallback(
    (r: ViewerRTC, s: WebSocket) => {
      if (rtc.current !== r) return; // already torn down or replaced
      closeRTC();
      if (s.readyState === WebSocket.OPEN) {
        s.send(JSON.stringify({ t: 'fallback_tiles' }));
        // The canvas went stale while the video ran; ask for a full frame.
        s.send(JSON.stringify({ t: 'refresh' }));
      }
    },
    [closeRTC],
  );

  const startRTC = useCallback(
    (s: WebSocket, iceServers: RTCIceServer[]) => {
      closeRTC();
      const signal = (o: Record<string, unknown>) => {
        if (s.readyState === WebSocket.OPEN) s.send(JSON.stringify(o));
      };
      let r: ViewerRTC;
      try {
        r = new ViewerRTC(iceServers, signal, {
          onStream: (stream) => {
            const v = video.current;
            if (rtc.current !== r || !v) return;
            v.srcObject = stream;
            void v.play().catch(() => undefined); // autoplay is muted, so this is a nudge only
          },
          onState: (st) => {
            if (rtc.current !== r) return;
            if (st === 'connected') {
              window.clearTimeout(rtcWatch.current);
              rtcWatch.current = 0;
              // Recovered from a blip: cancel any pending give-up.
              window.clearTimeout(rtcGrace.current);
              rtcGrace.current = 0;
            } else if (st === 'failed' || st === 'closed') {
              rtcFallback(r, s); // permanent: revert to tiles now
            } else if (st === 'disconnected') {
              // Often transient (a roaming Wi-Fi hop, a NAT rebind); give ICE a
              // moment to restore the connection before falling back.
              if (!rtcGrace.current) {
                rtcGrace.current = window.setTimeout(() => {
                  rtcGrace.current = 0;
                  if (rtc.current === r && !r.connected) rtcFallback(r, s);
                }, RTC_DISCONNECT_GRACE_MS);
              }
            }
          },
        });
      } catch (err) {
        console.warn('webrtc unavailable', err);
        signal({ t: 'fallback_tiles' });
        return;
      }
      rtc.current = r;
      if (screenSeen.current) {
        rtcWatch.current = window.setTimeout(() => {
          if (rtc.current === r && !r.connected) rtcFallback(r, s);
        }, RTC_CONNECT_MS);
      }
      r.start().catch((err) => {
        console.warn('webrtc offer failed', err);
        rtcFallback(r, s);
      });
    },
    [closeRTC, rtcFallback],
  );

  // Bumped by every connect and disconnect: a signing dialog the operator
  // answers late must not open a session they have since abandoned.
  const attempt = useRef(0);

  const openSocket = useCallback(() => {
    drawQueue.current = Promise.resolve();
    const wantRTC = rtcOnRef.current && typeof RTCPeerConnection !== 'undefined';
    const query = `quality=${quality}${wantRTC ? '&webrtc=1' : ''}${modeRef.current === 'backstage' ? '&mode=backstage' : ''}`;
    const s = new WebSocket(wsURL(`/ws/desktop/${encodeURIComponent(agent.id)}?${query}`));
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
            setWaitNote('');
            screenSeen.current = true;
            {
              const r = rtc.current;
              if (r && !r.connected && !rtcWatch.current && ws.current === s) {
                rtcWatch.current = window.setTimeout(() => {
                  if (rtc.current === r && !r.connected) rtcFallback(r, s);
                }, RTC_CONNECT_MS);
              }
            }
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
            if (m.pending) setWaitNote(m.message ?? '');
            else setNote(m.message ?? '');
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
          // WebRTC signalling. Ignore a socket that has been replaced.
          case 'webrtc_config':
            if (ws.current === s && rtcOnRef.current) startRTC(s, m.ice_servers ?? []);
            break;
          case 'webrtc_answer': {
            const r = rtc.current;
            if (ws.current === s && r && m.sdp) {
              r.applyAnswer(m.sdp).catch((err) => {
                console.warn('webrtc answer rejected', err);
                rtcFallback(r, s);
              });
            }
            break;
          }
          case 'webrtc_candidate':
            if (ws.current === s && m.candidate) void rtc.current?.addCandidate(m.candidate);
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
      if (ws.current === s) {
        ws.current = null;
        closeRTC();
      }
      setStatus((st) => (st === 'error' ? st : 'closed'));
      if (!ev.wasClean && ev.code !== 1000) setDetail((d) => d || `socket closed (${ev.code})`);
      pressed.current.clear();
      mouseDown.current.clear();
    };
  }, [agent.id, quality, drawTile, layout, closeRTC, startRTC, rtcFallback]);

  const connect = useCallback(() => {
    closeRTC();
    ws.current?.close();
    setStatus('connecting');
    setDetail('');
    setNote('');
    setWaitNote('');
    screenSeen.current = false;
    const n = ++attempt.current;
    // Phase 3: remote desktop needs a signed grant first (a no-op when the
    // organization has no trust bundle, or the grant is still live).
    ensureGrant(agent.id, GRANT_OPS.desktop).then(
      () => {
        if (n === attempt.current) openSocket();
      },
      (err: unknown) => {
        if (n !== attempt.current) return;
        setStatus('error');
        setDetail(errMsg(err));
      },
    );
  }, [agent.id, closeRTC, openSocket]);

  const disconnect = useCallback(() => {
    attempt.current++; // also cancels a connect that is still waiting for a signature
    closeRTC();
    ws.current?.close();
    ws.current = null;
    pressed.current.clear();
    mouseDown.current.clear();
    setStatus('closed');
  }, [closeRTC]);

  useEffect(() => {
    const id = window.setTimeout(connect, 50);
    return () => {
      attempt.current++;
      window.clearTimeout(id);
      closeRTC();
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

  // The canvas only gets its box (and so its offsets) once it is displayed;
  // place the video over it from there.
  useEffect(() => {
    layout();
  }, [dims.w, dims.h, layout]);

  // fps / bandwidth counters; the WebRTC numbers come from getStats()
  useEffect(() => {
    const id = window.setInterval(() => {
      const r = rtcActive.current ? rtc.current : null;
      if (r) {
        stats.current = { frames: 0, bytes: 0 };
        r.getStats()
          .then((st) => {
            if (rtc.current !== r) return;
            setFps(st.fps);
            setKbps(st.bytesPerSec);
            setRttMs(st.rttMs);
          })
          .catch(() => undefined);
        return;
      }
      setRttMs(null);
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

  const cycleMonitor = () => {
    if (monitors.length <= 1) return;
    const currentPos = monitors.findIndex((m) => m.index === monitor);
    const nextPos = (currentPos + 1) % monitors.length;
    const nextIdx = monitors[nextPos].index;
    setMonitor(nextIdx);
    send({ t: 'monitor', index: nextIdx });
    toast.info(`Switched to Display ${nextIdx + 1}`, `${monitors[nextPos].w}×${monitors[nextPos].h}`);
  };

  const monitorSelect = monitors.length > 1 && (
    <div className="row" style={{ gap: 4 }}>
      <Button
        size="sm"
        onClick={cycleMonitor}
        disabled={!live}
        title="Cycle to next display"
        aria-label="Cycle display"
      >
        🖥️ Display {monitor + 1}/{monitors.length}
      </Button>
      <select
        value={monitor}
        disabled={!live}
        onChange={(e) => {
          const idx = +e.target.value;
          setMonitor(idx);
          send({ t: 'monitor', index: idx });
        }}
        style={{ width: 170 }}
        aria-label="Monitor"
      >
        {monitors.map((mo) => (
          <option key={mo.index} value={mo.index}>
            Disp {mo.index + 1} ({mo.w}×{mo.h}){mo.primary ? ' ★' : ''}
          </option>
        ))}
      </select>
    </div>
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
  /** Playing is what flips the engine: tell the helper to stop sending tiles. */
  const onVideoPlaying = () => {
    const r = rtc.current;
    if (!r || rtcActive.current) return;
    rtcActive.current = true;
    window.clearTimeout(rtcWatch.current);
    rtcWatch.current = 0;
    send({ t: 'webrtc_active' });
    setTransport('rtc');
  };
  // Both of these reconnect: the engine and the mode are chosen by query
  // string when the socket opens.
  const toggleRtc = () => {
    const next = !rtcOnRef.current;
    rtcOnRef.current = next;
    setRtcOn(next);
    connect();
  };
  const toggleBackstage = () => {
    const next: Mode = modeRef.current === 'backstage' ? 'console' : 'backstage';
    modeRef.current = next;
    setMode(next);
    connect();
  };
  const engineControls = (
    <>
      <label className="row small muted" style={{ gap: 6 }} title="Hardware-decoded WebRTC video with automatic fallback to the WebSocket. Off forces WebSocket only.">
        <input type="checkbox" checked={rtcOn} onChange={toggleRtc} aria-label="Use WebRTC" />
        WebRTC
      </label>
      <Button
        size="sm"
        onClick={toggleBackstage}
        title={mode === 'backstage' ? 'Back to the console session (reconnects)' : 'Work in a Backstage session (reconnects)'}
        aria-pressed={mode === 'backstage'}
      >
        {mode === 'backstage' ? 'Backstage on' : 'Backstage'}
      </Button>
    </>
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
        {!touchUI && engineControls}
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
            {engineControls}
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
          style={{ display: dims.w ? 'block' : 'none', opacity: transport === 'rtc' ? 0 : 1 }}
        />
        {/* The WebRTC engine. Laid over the canvas by layout(); it never takes
            pointer events, so the canvas keeps receiving all input. */}
        <video
          ref={video}
          autoPlay
          playsInline
          muted
          onPlaying={onVideoPlaying}
          aria-hidden="true"
          style={{
            position: 'absolute',
            pointerEvents: 'none',
            objectFit: 'fill',
            background: '#000',
            opacity: transport === 'rtc' ? 1 : 0,
          }}
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
                <span className="spinner" /> {waitNote || 'Waiting for the first frame…'}
              </>
            )}
            {status === 'closed' && 'Disconnected'}
            {status === 'error' && <span style={{ color: 'var(--danger)' }}>{detail || 'Error'}</span>}
            {status === 'idle' && 'Not connected'}
          </div>
        )}
        {live && dims.w > 0 && (
          <div
            className="mono"
            aria-hidden="true"
            style={{
              position: 'absolute',
              top: 8,
              right: 8,
              zIndex: 2,
              pointerEvents: 'none',
              background: 'rgba(20, 24, 31, 0.7)',
              color: '#e6e9ef',
              padding: '4px 8px',
              borderRadius: 'var(--radius-sm)',
              fontSize: 11,
              lineHeight: 1.45,
              textAlign: 'right',
            }}
          >
            <div>{transport === 'rtc' ? 'WebRTC P2P (UDP)' : 'WebSocket Relay'}</div>
            <div>
              {fps} fps · {rttMs === null ? '— ms' : `${rttMs} ms`} · {bps(kbps)}
            </div>
            <div>{mode === 'backstage' ? 'Backstage' : 'Console'}</div>
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
        {waitNote && !dims.w && <span style={{ color: 'var(--warn)' }}>{waitNote}</span>}
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
