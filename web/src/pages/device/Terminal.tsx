import { useCallback, useEffect, useRef, useState } from 'react';
import { Terminal as XTerm } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { Button } from '../../components/ui';
import { IconClipboard, IconCopy, IconRefresh, IconStop } from '../../components/Icons';
import { GRANT_OPS, ensureGrant } from '../../lib/grants';
import { host } from '../../lib/host';
import { errMsg, useToast } from '../../state/toast';
import type { TabProps } from './DeviceDetail';
import { copyText, readClipboard } from './clipboard';
import { KeyBar, KeyButton } from './KeyBar';
import { TerminalRTC } from './termrtc';
import { coarsePointer, useFillHeight } from './touch';
import '../../styles/device-touch.css';

type Status = 'idle' | 'connecting' | 'connected' | 'closed' | 'error';

interface ShellMsg {
  t:
    | 'opened'
    | 'out'
    | 'closed'
    | 'error'
    | 'webrtc_config'
    | 'rtc_answer'
    | 'rtc_candidate'
    | 'rtc_switch'
    | 'rtc_unavailable';
  data?: string;
  message?: string;
  session?: string;
  ice_servers?: RTCIceServer[];
  sdp?: string;
  candidate?: RTCIceCandidateInit;
  reason?: string;
}

/** WebRTC gets this long after the offer to open its channel before the relay stays. */
const RTC_CONNECT_MS = 4000;
/** A connection that drops to "disconnected" gets this long to recover. */
const RTC_DISCONNECT_GRACE_MS = 4000;
/** Channel output held back until the relay's switch marker arrives; beyond this the transport is abandoned. */
const RTC_HOLD_MAX_BYTES = 4 << 20;
/** The WebRTC toggle, remembered per browser. */
const RTC_PREF_KEY = 'rmm.webrtc';

function loadRtcPref(): boolean {
  try {
    return localStorage.getItem(RTC_PREF_KEY) !== '0';
  } catch {
    return true;
  }
}

interface StickyMods {
  ctrl: boolean;
  alt: boolean;
}

/**
 * The on-screen key bar (task C8a). Everything here is a byte sequence the
 * shell already understands, fed into the same `{t:'in',data}` frame the
 * keyboard uses — no new server or agent surface.
 */
const TERM_KEYS: readonly { label: string; title: string; data: string; wide?: boolean }[] = [
  { label: 'Esc', title: 'Escape', data: '\x1b', wide: true },
  { label: 'Tab', title: 'Tab', data: '\t', wide: true },
  { label: '↑', title: 'Up arrow', data: '\x1b[A' },
  { label: '↓', title: 'Down arrow', data: '\x1b[B' },
  { label: '←', title: 'Left arrow', data: '\x1b[D' },
  { label: '→', title: 'Right arrow', data: '\x1b[C' },
  { label: '^C', title: 'Ctrl+C — interrupt', data: '\x03' },
  { label: '^D', title: 'Ctrl+D — end of input', data: '\x04' },
  { label: '^Z', title: 'Ctrl+Z — suspend', data: '\x1a' },
  { label: '^L', title: 'Ctrl+L — clear screen', data: '\x0c' },
  { label: '^R', title: 'Ctrl+R — reverse search', data: '\x12' },
  { label: 'Home', title: 'Home', data: '\x1b[H', wide: true },
  { label: 'End', title: 'End', data: '\x1b[F', wide: true },
  { label: 'PgUp', title: 'Page up', data: '\x1b[5~', wide: true },
  { label: 'PgDn', title: 'Page down', data: '\x1b[6~', wide: true },
  { label: '|', title: 'Pipe', data: '|' },
  { label: '~', title: 'Tilde', data: '~' },
  { label: '/', title: 'Slash', data: '/' },
  { label: '-', title: 'Hyphen', data: '-' },
];

/**
 * Apply the armed sticky modifiers to one typed character. Ctrl maps a letter
 * the way a real terminal does (`charCodeAt - 64`), Alt prefixes ESC, which is
 * what every shell reads as Meta. Sequences longer than one character (the key
 * bar's own escape codes) are left alone.
 */
function applyMods(data: string, mods: StickyMods): string {
  if (!mods.ctrl && !mods.alt) return data;
  let out = data;
  if (mods.ctrl && out.length === 1) {
    const c = out.toUpperCase().charCodeAt(0);
    if (c >= 64 && c <= 95) out = String.fromCharCode(c - 64); // @ A-Z [ \ ] ^ _
    else if (out === '?') out = '\x7f'; // Ctrl+? is DEL
    else if (out === ' ') out = '\x00'; // Ctrl+Space is NUL
  }
  if (mods.alt && out.length === 1) out = `\x1b${out}`;
  return out;
}

function wsURL(path: string): string {
  return `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}${path}`;
}

export function Terminal({ agent }: TabProps) {
  const toast = useToast();
  const page = useRef<HTMLDivElement>(null);
  const host_ = useRef<HTMLDivElement>(null);
  const term = useRef<XTerm | null>(null);
  const fit = useRef<FitAddon | null>(null);
  const ws = useRef<WebSocket | null>(null);
  const shells = agent.os === 'windows' ? ['powershell', 'cmd'] : ['bash', 'sh'];
  const [shell, setShell] = useState(shells[0]);
  const [status, setStatus] = useState<Status>('idle');
  const [detail, setDetail] = useState('');
  const [size, setSize] = useState({ cols: 0, rows: 0 });
  const [mods, setMods] = useState<StickyMods>({ ctrl: false, alt: false });
  const modsRef = useRef(mods);
  modsRef.current = mods;

  const [rtcOn, setRtcOn] = useState(loadRtcPref);
  const rtcOnRef = useRef(rtcOn);
  const [transport, setTransport] = useState<'relay' | 'rtc'>('relay');
  // WebRTC byte path. `rtc` is the live peer connection, if any. `switched`
  // is true once the relay announced rtc_switch: from then on the agent
  // sends output on the data channel, and until then channel output is
  // held in `held` so it can never overtake what the relay still carries.
  const rtc = useRef<TerminalRTC | null>(null);
  const switched = useRef(false);
  const held = useRef<Uint8Array[]>([]);
  const heldBytes = useRef(0);
  const iceServers = useRef<RTCIceServer[]>([]);
  const rtcTimer = useRef<number | null>(null); // connect watchdog, cleared only by the channel opening
  const rtcGrace = useRef<number | null>(null); // disconnect grace
  // Channel output held at fallback time. It is strictly after the switch
  // marker and before any post-revert relay output, so it is written when
  // the marker arrives rather than lost.
  const pendingHeld = useRef<Uint8Array[]>([]);

  const send = useCallback((msg: Record<string, unknown>) => {
    const s = ws.current;
    if (s && s.readyState === WebSocket.OPEN) s.send(JSON.stringify(msg));
  }, []);

  /** True when keystrokes and resizes should go over the data channel. */
  const viaRTC = useCallback(() => !!rtc.current && switched.current && rtc.current.open, []);

  const sendResize = useCallback(
    (cols: number, rows: number) => {
      if (viaRTC() && rtc.current?.sendControl({ t: 'resize', cols, rows })) return;
      send({ t: 'resize', cols, rows });
    },
    [send, viaRTC],
  );
  const sendResizeRef = useRef(sendResize);
  sendResizeRef.current = sendResize;

  /** Type raw bytes at the shell, consuming any armed sticky modifier. */
  const sendData = useCallback(
    (data: string) => {
      const m = modsRef.current;
      const out = applyMods(data, m);
      if (!(viaRTC() && rtc.current?.sendBytes(out))) send({ t: 'in', data: out });
      if (m.ctrl || m.alt) setMods({ ctrl: false, alt: false });
    },
    [send, viaRTC],
  );

  const clearRtcTimer = useCallback(() => {
    if (rtcTimer.current !== null) {
      window.clearTimeout(rtcTimer.current);
      rtcTimer.current = null;
    }
  }, []);

  const clearRtcGrace = useCallback(() => {
    if (rtcGrace.current !== null) {
      window.clearTimeout(rtcGrace.current);
      rtcGrace.current = null;
    }
  }, []);

  /** Tear the peer connection down and forget everything about it. */
  const closeRTC = useCallback(() => {
    clearRtcTimer();
    clearRtcGrace();
    rtc.current?.close();
    rtc.current = null;
    switched.current = false;
    held.current = [];
    heldBytes.current = 0;
    setTransport('relay');
  }, [clearRtcTimer, clearRtcGrace]);

  /** WebRTC failed or dropped: tell the agent to resume the relay and keep using it. */
  const rtcFallback = useCallback(
    (r: TerminalRTC) => {
      if (rtc.current !== r) return;
      send({ t: 'rtc_fallback' });
      // Output held for a switch marker that has not arrived yet is real
      // screen output (the agent sent it on the channel); keep it, in order,
      // for when the marker lands.
      if (!switched.current && held.current.length > 0) {
        pendingHeld.current.push(...held.current);
      }
      closeRTC();
    },
    [send, closeRTC],
  );

  const startRTC = useCallback(
    (t: XTerm) => {
      closeRTC();
      let r: TerminalRTC;
      try {
        r = new TerminalRTC(iceServers.current, send, {
          onOpen: () => {
            if (rtc.current !== r) return;
            clearRtcTimer();
            if (switched.current) setTransport('rtc');
          },
          onData: (data) => {
            if (rtc.current !== r) return;
            if (switched.current) {
              t.write(data);
              return;
            }
            held.current.push(data);
            heldBytes.current += data.length;
            if (heldBytes.current > RTC_HOLD_MAX_BYTES) rtcFallback(r);
          },
          onState: (state) => {
            if (rtc.current !== r) return;
            if (state === 'failed' || state === 'closed') {
              rtcFallback(r);
            } else if (state === 'disconnected') {
              clearRtcGrace();
              rtcGrace.current = window.setTimeout(() => rtcFallback(r), RTC_DISCONNECT_GRACE_MS);
            } else if (state === 'connected') {
              // Only the channel opening ends the connect watchdog.
              clearRtcGrace();
            }
          },
        });
      } catch (err) {
        console.warn('terminal webrtc unavailable', err);
        return;
      }
      rtc.current = r;
      r.start().catch((err: unknown) => {
        console.warn('terminal webrtc offer failed', err);
        rtcFallback(r);
      });
      rtcTimer.current = window.setTimeout(() => {
        if (!r.open) rtcFallback(r);
      }, RTC_CONNECT_MS);
    },
    [send, closeRTC, clearRtcTimer, clearRtcGrace, rtcFallback],
  );
  const startRTCRef = useRef(startRTC);
  startRTCRef.current = startRTC;

  // The terminal is created exactly once; anything the mount effect needs from
  // a later render is reached through a ref so the effect never re-runs and
  // tears a live session down.
  const sendDataRef = useRef(sendData);
  sendDataRef.current = sendData;
  const toastRef = useRef(toast);
  toastRef.current = toast;

  const refit = useCallback(() => {
    try {
      fit.current?.fit();
    } catch {
      /* container hidden */
    }
  }, []);

  // Bumped by every connect and disconnect: a signing dialog the operator
  // answers late must not open a socket they have since abandoned.
  const attempt = useRef(0);

  const open = useCallback(
    (t: XTerm) => {
      const wantRTC = rtcOnRef.current && typeof RTCPeerConnection !== 'undefined';
      const s = new WebSocket(wsURL(`/ws/shell/${encodeURIComponent(agent.id)}${wantRTC ? '?webrtc=1' : ''}`));
      ws.current = s;
      s.onopen = () => {
        fit.current?.fit();
        send({ t: 'open', shell, cols: t.cols, rows: t.rows });
      };
      s.onmessage = (e: MessageEvent<string>) => {
        // A superseded socket must not drive the new session's state.
        if (ws.current !== s) return;
        let m: ShellMsg;
        try {
          m = JSON.parse(e.data) as ShellMsg;
        } catch {
          return;
        }
        switch (m.t) {
          case 'webrtc_config':
            if (wantRTC) iceServers.current = m.ice_servers ?? [];
            break;
          case 'opened':
            setStatus('connected');
            t.focus();
            if (wantRTC && ws.current === s) startRTCRef.current(t);
            break;
          case 'rtc_answer':
            if (rtc.current && m.sdp) {
              const r = rtc.current;
              r.applyAnswer(m.sdp).catch((err: unknown) => {
                console.warn('terminal webrtc answer rejected', err);
                rtcFallback(r);
              });
            }
            break;
          case 'rtc_candidate':
            if (rtc.current && m.candidate) void rtc.current.addCandidate(m.candidate);
            break;
          case 'rtc_switch': {
            const r = rtc.current;
            if (!r) {
              // Already fell back: the held channel output follows the relay
              // output written so far and precedes anything sent after the revert.
              for (const chunk of pendingHeld.current) t.write(chunk);
              pendingHeld.current = [];
              break;
            }
            if (switched.current) break;
            // Everything the relay carried is already written; the channel
            // output held until now follows it, then the channel is the route.
            switched.current = true;
            for (const chunk of held.current) t.write(chunk);
            held.current = [];
            heldBytes.current = 0;
            // The size over the relay too, so the pty is right whichever path
            // the agent reads its next frame from.
            send({ t: 'resize', cols: t.cols, rows: t.rows });
            if (r.open) setTransport('rtc');
            break;
          }
          case 'rtc_unavailable':
            // The agent could not build a peer connection: stay on the relay.
            closeRTC();
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
        // A stale socket's late close must not tear down the new session.
        if (ws.current !== s) return;
        ws.current = null;
        closeRTC();
        setStatus((st) => (st === 'error' ? st : 'closed'));
        if (ev.code !== 1000 && ev.code !== 1005 && !ev.wasClean) setDetail((d) => d || `socket closed (${ev.code})`);
      };
    },
    [agent.id, shell, send, closeRTC, rtcFallback],
  );

  const connect = useCallback(() => {
    const t = term.current;
    if (!t) return;
    ws.current?.close();
    closeRTC();
    pendingHeld.current = [];
    setStatus('connecting');
    setDetail('');
    t.reset();
    const n = ++attempt.current;
    // Phase 3: a shell needs a signed grant first (a no-op when the
    // organization has no trust bundle, or the grant is still live).
    ensureGrant(agent.id, GRANT_OPS.shell).then(
      () => {
        if (n === attempt.current && term.current === t) open(t);
      },
      (err: unknown) => {
        if (n !== attempt.current) return;
        setStatus('error');
        setDetail(errMsg(err));
        t.write(`\r\n\x1b[31m[${errMsg(err)}]\x1b[0m\r\n`);
      },
    );
  }, [agent.id, open, closeRTC]);

  // create the terminal once
  useEffect(() => {
    const el = host_.current;
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

    // C8(c). Without these Gboard offers a URL-ish keyboard with a "Go" key
    // and autocorrects shell words; `inputmode=text` and `enterkeyhint=send`
    // are the two attributes xterm does not set for us.
    const ta = t.textarea;
    if (ta) {
      ta.setAttribute('inputmode', 'text');
      ta.setAttribute('enterkeyhint', 'send');
      ta.setAttribute('autocapitalize', 'none');
      ta.setAttribute('autocorrect', 'off');
      ta.setAttribute('spellcheck', 'false');
    }

    t.onData((d) => sendDataRef.current(d));
    t.onResize(({ cols, rows }) => {
      setSize({ cols, rows });
      sendResizeRef.current(cols, rows);
    });
    // Ctrl+Shift+C copies, Ctrl+C with a selection copies (Windows habit),
    // Ctrl+Shift+V pastes; plain Ctrl+V is a browser paste that xterm handles.
    t.attachCustomKeyEventHandler((e) => {
      if (e.type !== 'keydown') return true;
      if (e.ctrlKey && (e.key === 'C' || e.key === 'c') && (e.shiftKey || t.hasSelection())) {
        const sel = t.getSelection();
        if (sel) {
          // This handler is SYNCHRONOUS. copyText is async and swallows its
          // own failures, so nothing can throw back into xterm here — the old
          // `navigator.clipboard.writeText(...)` threw a TypeError on a
          // non-secure origin that its own .catch() could not see (C7).
          void copyText(sel).then((ok) => {
            if (!ok) toastRef.current.error('Copy failed', 'Select the text and copy it with the browser menu.');
          });
          t.clearSelection();
          return false;
        }
      }
      if (e.ctrlKey && e.shiftKey && (e.key === 'V' || e.key === 'v')) {
        void readClipboard().then((txt) => {
          if (txt) t.paste(txt);
        });
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
    t.writeln(
      coarsePointer()
        ? '\x1b[90mTap Connect to open a shell on this device.\x1b[0m'
        : '\x1b[90mPress Connect to open a shell.\x1b[0m',
    );
    return () => {
      ro.disconnect();
      closeRTC();
      ws.current?.close();
      ws.current = null;
      t.dispose();
      term.current = null;
    };
  }, [closeRTC]);

  // C8(d) SECURITY. Auto-connect spawns an audited shell session on a live
  // device. On a phone, merely opening the tab — a mis-tap in a pocket — is
  // not consent, so a coarse pointer has to ask for it explicitly.
  useEffect(() => {
    if (coarsePointer()) return;
    const id = window.setTimeout(connect, 50);
    return () => window.clearTimeout(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // C8(b). Fill what the visual viewport actually leaves, and re-fit when the
  // soft keyboard takes half of it.
  useFillHeight(page, refit);

  // The native shell's Paste push (C7): the only working paste path inside an
  // Android WebView.
  useEffect(() => host.onPaste((text) => text && term.current?.paste(text)), []);

  const disconnect = () => {
    attempt.current++; // also cancels a connect that is still waiting for a signature
    send({ t: 'close' });
    closeRTC();
    ws.current?.close();
    if (!ws.current) setStatus('closed');
  };

  const copySel = async () => {
    const sel = term.current?.getSelection();
    if (!sel) return toast.info('Nothing selected');
    if (await copyText(sel)) toast.success('Copied');
    else toast.error('Copy failed', 'Select the text and copy it with the browser menu.');
    term.current?.focus();
  };
  const paste = async () => {
    const txt = await readClipboard();
    if (txt === null) {
      toast.error('Clipboard read blocked', 'Use Ctrl+V or Ctrl+Shift+V inside the terminal instead.');
      return;
    }
    if (txt) term.current?.paste(txt);
    term.current?.focus();
  };

  // The engine is chosen by query string when the socket opens, so the toggle
  // reconnects, as the desktop viewer's does.
  const toggleRtc = () => {
    const next = !rtcOnRef.current;
    rtcOnRef.current = next;
    setRtcOn(next);
    try {
      localStorage.setItem(RTC_PREF_KEY, next ? '1' : '0');
    } catch {
      /* storage blocked: the choice lasts for this page only */
    }
    if (status === 'connected' || status === 'connecting') connect();
  };

  const toggleMod = (k: keyof StickyMods) => setMods((m) => ({ ...m, [k]: !m[k] }));

  return (
    <div className="fill-page device-fill term-page" ref={page}>
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
        <label className="row small muted" style={{ gap: 6 }} title="Send the terminal over a direct WebRTC data channel with automatic fallback to the relay. Off forces the WebSocket relay only. Changing it reconnects.">
          <input type="checkbox" checked={rtcOn} onChange={toggleRtc} aria-label="Use WebRTC" />
          WebRTC
        </label>
        <Button onClick={copySel} title="Copy selection (Ctrl+Shift+C)">
          <IconCopy /> Copy
        </Button>
        <Button onClick={paste} title="Paste clipboard (Ctrl+Shift+V)">
          <IconClipboard /> Paste
        </Button>
        <span className="grow" />
        <span className="muted small term-tip">Tip: select text to copy; Ctrl+C with a selection copies instead of interrupting.</span>
      </div>
      <div className="term-wrap" ref={host_} role="application" aria-label={`Terminal on ${agent.display_name}`} />
      <KeyBar label="Terminal keys">
        <KeyButton title="Ctrl — applies to the next key" on={mods.ctrl} onPress={() => toggleMod('ctrl')} wide>
          Ctrl
        </KeyButton>
        <KeyButton title="Alt — applies to the next key" on={mods.alt} onPress={() => toggleMod('alt')} wide>
          Alt
        </KeyButton>
        {TERM_KEYS.map((k) => (
          <KeyButton key={k.title} title={k.title} wide={k.wide} onPress={() => sendData(k.data)}>
            {k.label}
          </KeyButton>
        ))}
      </KeyBar>
      <div className="statusline">
        <span className={`dot ${status === 'connected' ? 'on' : status === 'connecting' ? 'warn' : 'off'}`} />
        <span>
          {status === 'idle' && 'Not connected'}
          {status === 'connecting' && 'Connecting…'}
          {status === 'connected' && `Connected · ${shell} · ${transport === 'rtc' ? 'WebRTC (direct)' : 'Relay'}`}
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
