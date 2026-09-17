/**
 * host.ts — the console half of the Android shell bridge (docs/ANDROID.md §3.6).
 *
 * The native app injects an object named `RmmHost` with
 * `WebViewCompat.addWebMessageListener(webView, "RmmHost", setOf(origin), …)`,
 * scoped by Chromium to the server's own origin. A native object injection is
 * not a script load, so `script-src 'self'` never applies and the shim itself
 * ships here, in the console, rather than being evaluated into the page.
 *
 * Wire format (every frame is JSON):
 *
 *   page → native   {id, t, …}      request
 *   native → page   {id, ok, …}     reply on the same channel
 *   native → page   {t, …}          push, no id
 *
 * Page → native frames, exactly the set in §3.6:
 *   hello · save · clip.read · clip.write · badge · busy · sse · signedOut
 * plus one echo, `{t:'back',consumed:true}`, which is how the page tells the
 * shell that it swallowed a system-back within the 120 ms window of §3.4.
 *
 * Native → page pushes, exactly the set in §3.6:
 *   navigate · visibility · paste · back · theme
 *
 * Degraded transport (§3.6: `WebViewFeature.WEB_MESSAGE_LISTENER` unsupported):
 * the app injects `RmmHostSync` with `addJavascriptInterface` and a per-call
 * host check, and delivers replies and pushes by evaluating
 * `window.__rmmHostReceive('<json>')`. That hook is installed only when the
 * degraded object is actually present, and the native side must call it
 * defensively (`window.__rmmHostReceive && …`) because it cannot assume the
 * page has loaded this module yet.
 *
 * Feature detection is total and runs in both directions:
 *   - no host object  ⇒ every call is a no-op resolving to `false`/`null`,
 *     `available` stays false and `data-rmm-shell` is never set, so a plain
 *     browser renders byte-identically to today;
 *   - no `hello` reply within 1.5 s ⇒ the console keeps its own drawer, the
 *     mirror image of the native bar's NORMATIVE `loadUrl` fallback (§3.4), so
 *     no configuration ends up with no navigation. A late reply is still
 *     honoured — the shell simply took longer than the first tab tap.
 *
 * Nothing that arrives over the channel is trusted as a capability: a
 * `navigate` path is validated to a same-origin absolute path before it ever
 * reaches react-router, because `history.push('//evil.example')` is an
 * off-origin navigation.
 */

/* ---------- transports ---------- */

/** The object `addWebMessageListener` injects. */
interface ChannelHost {
  postMessage(message: string): void;
  addEventListener(type: 'message', listener: (event: { data?: unknown }) => void): void;
  removeEventListener?(type: 'message', listener: (event: { data?: unknown }) => void): void;
}

/** The object the degraded `addJavascriptInterface` path injects. */
interface InjectedHost {
  postMessage(message: string): void;
}

declare global {
  interface Window {
    RmmHost?: ChannelHost;
    RmmHostSync?: InjectedHost;
    __rmmHostReceive?: (json: string) => void;
  }
}

/* ---------- wire frames (page → native) ---------- */

type OutFrame =
  | { t: 'hello'; version: string }
  | { t: 'save'; name: string; mime: string; text: string }
  | { t: 'clip.read' }
  | { t: 'clip.write'; text: string }
  | { t: 'badge'; open: number; critical: number }
  | { t: 'busy'; on: boolean }
  | { t: 'sse'; ok: boolean }
  | { t: 'signedOut' }
  | { t: 'back'; consumed: boolean };

export type TransportKind = 'channel' | 'injected';
export type Visibility = 'hidden' | 'visible';
export type ThemeName = 'dark' | 'light';

/** A back handler returns true when it consumed the press. */
export type BackHandler = () => boolean | void;

export interface Host {
  /** True once the shell has answered `hello`. */
  readonly available: boolean;
  /** The shell name from the hello reply ('android'), or null. */
  readonly shell: string | null;
  /** Which injection was found, or null in a plain browser. */
  readonly transport: TransportKind | null;
  /** Resolves true if `hello` is answered inside the handshake window. */
  whenReady(): Promise<boolean>;
  /** Fires when the handshake completes (never fires in a plain browser). */
  onAvailable(fn: (available: boolean) => void): () => void;

  /** Write a text file through the shell (CSV export — C6). False ⇒ caller falls back. */
  saveText(name: string, mime: string, text: string): Promise<boolean>;
  /** The only Paste path that works in a WebView (§3.6). Null ⇒ caller falls back. */
  clipboardRead(): Promise<string | null>;
  clipboardWrite(text: string): Promise<boolean>;
  /** Alert counts for the native bottom-bar badge, from the SSE stream (C12). */
  badge(open: number, critical: number): Promise<boolean>;
  /** A live terminal/desktop session: hold off the lock grace and keep awake. */
  busy(on: boolean): Promise<boolean>;
  /** The Connection-test row-3 signal: the console's SSE stream said hello. */
  sse(ok: boolean): Promise<boolean>;
  /** The console observed a sign-out. */
  signedOut(): Promise<boolean>;

  onNavigate(fn: (path: string) => void): () => void;
  onVisibility(fn: (state: Visibility) => void): () => void;
  onPaste(fn: (text: string) => void): () => void;
  /** Handlers run newest-first; the first to return true consumes the press. */
  onBack(fn: BackHandler): () => void;
  onTheme(fn: (theme: ThemeName) => void): () => void;
}

/* ---------- constants ---------- */

const PROTOCOL_VERSION = '1';
/** Mirrors the native bar's 1.5 s fallback (docs/ANDROID.md §3.4). */
const HELLO_TIMEOUT_MS = 1500;
const REPLY_TIMEOUT_MS = 6000;
/** A CSV of a large fleet plus a MediaStore write. */
const SAVE_TIMEOUT_MS = 20000;

/* ---------- state ---------- */

type Pending = { resolve: (v: Record<string, unknown> | null) => void; timer: number };

let transport: TransportKind | null = null;
let post: ((json: string) => void) | null = null;
let ready = false;
let shellName: string | null = null;
let seq = 0;
const pending = new Map<string, Pending>();
let helloId = '';
let resolveReady: (v: boolean) => void = () => undefined;
const readyPromise = new Promise<boolean>((r) => {
  resolveReady = r;
});

const availableSubs = new Set<(v: boolean) => void>();
const navigateSubs = new Set<(path: string) => void>();
const visibilitySubs = new Set<(state: Visibility) => void>();
const pasteSubs = new Set<(text: string) => void>();
const themeSubs = new Set<(theme: ThemeName) => void>();
const backSubs: BackHandler[] = [];

function sub<T>(set: Set<T>, fn: T): () => void {
  set.add(fn);
  return () => {
    set.delete(fn);
  };
}

/* ---------- validation ----------
   Everything below the wire is untrusted input, not a capability. */

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object';
}

/**
 * A same-origin absolute path. `//host` and `/\host` are protocol-relative to
 * the URL parser, i.e. a different origin, and control characters would be
 * stripped by that same parser into something else again.
 */
function safePath(v: unknown): string | null {
  if (typeof v !== 'string' || v.length === 0 || v.length > 2048) return null;
  if (v.charCodeAt(0) !== 47 /* '/' */) return null;
  if (v.startsWith('//') || v.startsWith('/\\')) return null;
  if (/[\x00-\x1f\x7f\s\\]/.test(v)) return null;
  return v;
}

function count(v: number): number {
  return Number.isFinite(v) ? Math.max(0, Math.min(9999, Math.trunc(v))) : 0;
}

/* ---------- send / receive ---------- */

function send(frame: OutFrame, timeoutMs: number): Promise<Record<string, unknown> | null> {
  if (!post) return Promise.resolve(null);
  const id = `c${++seq}`;
  const json = JSON.stringify({ id, ...frame });
  return new Promise((resolve) => {
    const timer = window.setTimeout(() => {
      // Keep the hello slot: a shell that answers late is still a shell.
      if (frame.t !== 'hello') pending.delete(id);
      resolve(null);
    }, timeoutMs);
    pending.set(id, { resolve, timer });
    if (frame.t === 'hello') helloId = id;
    try {
      post?.(json);
    } catch (err) {
      window.clearTimeout(timer);
      pending.delete(id);
      console.warn('rmm host bridge: post failed', err);
      resolve(null);
    }
  });
}

/** Fire-and-forget notification: true when the shell acknowledged it. */
async function notify(frame: OutFrame, timeoutMs = REPLY_TIMEOUT_MS): Promise<boolean> {
  const reply = await send(frame, timeoutMs);
  return !!reply && reply.ok !== false;
}

function adoptHello(reply: Record<string, unknown>): void {
  if (ready) return;
  const name = typeof reply.shell === 'string' && /^[a-z0-9-]{1,16}$/.test(reply.shell) ? reply.shell : 'android';
  ready = true;
  shellName = name;
  try {
    document.documentElement.dataset.rmmShell = name;
  } catch {
    /* no document (tests): the bridge still works, only the CSS hook is missing */
  }
  resolveReady(true);
  for (const fn of Array.from(availableSubs)) {
    try {
      fn(true);
    } catch (err) {
      console.error('rmm host bridge: availability handler failed', err);
    }
  }
}

function dispatchPush(msg: Record<string, unknown>): void {
  switch (msg.t) {
    case 'hello': {
      // Unsolicited greeting: the shell reattached after a renderer restart.
      adoptHello(msg);
      return;
    }
    case 'navigate': {
      const path = safePath(msg.path);
      if (!path) {
        console.warn('rmm host bridge: rejected navigate path', msg.path);
        return;
      }
      for (const fn of Array.from(navigateSubs)) fn(path);
      return;
    }
    case 'visibility': {
      const state = msg.state === 'hidden' ? 'hidden' : msg.state === 'visible' ? 'visible' : null;
      if (!state) return;
      for (const fn of Array.from(visibilitySubs)) fn(state);
      return;
    }
    case 'paste': {
      if (typeof msg.text !== 'string' || !msg.text) return;
      for (const fn of Array.from(pasteSubs)) fn(msg.text);
      return;
    }
    case 'theme': {
      const value = msg.value === 'light' ? 'light' : msg.value === 'dark' ? 'dark' : null;
      if (!value) return;
      for (const fn of Array.from(themeSubs)) fn(value);
      return;
    }
    case 'back': {
      // Newest handler first: the topmost thing on screen owns the press.
      let consumed = false;
      for (let i = backSubs.length - 1; i >= 0 && !consumed; i--) {
        try {
          consumed = backSubs[i]() === true;
        } catch (err) {
          console.error('rmm host bridge: back handler failed', err);
        }
      }
      if (consumed) void notify({ t: 'back', consumed: true }, REPLY_TIMEOUT_MS);
      return;
    }
    default:
      return; // an unknown push is a newer shell talking to an older console
  }
}

function receive(raw: unknown): void {
  if (typeof raw !== 'string' || raw.length === 0) return;
  let msg: unknown;
  try {
    msg = JSON.parse(raw);
  } catch {
    return;
  }
  if (!isRecord(msg)) return;
  if (typeof msg.id === 'string') {
    const slot = pending.get(msg.id);
    if (slot) {
      window.clearTimeout(slot.timer);
      pending.delete(msg.id);
      slot.resolve(msg);
    }
    if (msg.id === helloId && msg.ok !== false) adoptHello(msg);
    return;
  }
  if (typeof msg.t === 'string') dispatchPush(msg);
}

/* ---------- start-up ---------- */

function topLevel(): boolean {
  // addJavascriptInterface exposes its object to every frame of every page
  // (§3.6); the console is only ever the top-level document.
  try {
    return window.top === window.self;
  } catch {
    return false;
  }
}

function connect(): void {
  if (typeof window === 'undefined' || !topLevel()) return;
  const channel = window.RmmHost;
  if (channel && typeof channel.postMessage === 'function' && typeof channel.addEventListener === 'function') {
    transport = 'channel';
    post = (json) => channel.postMessage(json);
    channel.addEventListener('message', (event) => receive(event?.data));
  } else {
    const injected = window.RmmHostSync;
    if (!injected || typeof injected.postMessage !== 'function') return;
    transport = 'injected';
    post = (json) => injected.postMessage(json);
    window.__rmmHostReceive = (json: string) => receive(json);
  }
  void send({ t: 'hello', version: PROTOCOL_VERSION }, HELLO_TIMEOUT_MS).then((reply) => {
    // A reply also lands in receive(), which is what adopts it; this only has
    // to settle whenReady() for the no-answer case.
    if (!reply) resolveReady(false);
  });
}

connect();

/* ---------- the API ---------- */

export const host: Host = {
  get available() {
    return ready;
  },
  get shell() {
    return shellName;
  },
  get transport() {
    return transport;
  },
  whenReady: () => readyPromise,
  onAvailable: (fn) => sub(availableSubs, fn),

  saveText: (name, mime, text) => notify({ t: 'save', name, mime, text }, SAVE_TIMEOUT_MS),
  clipboardRead: async () => {
    const reply = await send({ t: 'clip.read' }, REPLY_TIMEOUT_MS);
    if (!reply || reply.ok === false) return null;
    return typeof reply.text === 'string' ? reply.text : null;
  },
  clipboardWrite: (text) => notify({ t: 'clip.write', text }),
  badge: (open, critical) => notify({ t: 'badge', open: count(open), critical: count(critical) }),
  busy: (on) => notify({ t: 'busy', on: !!on }),
  sse: (ok) => notify({ t: 'sse', ok: !!ok }),
  signedOut: () => notify({ t: 'signedOut' }),

  onNavigate: (fn) => sub(navigateSubs, fn),
  onVisibility: (fn) => sub(visibilitySubs, fn),
  onPaste: (fn) => sub(pasteSubs, fn),
  onTheme: (fn) => sub(themeSubs, fn),
  onBack: (fn) => {
    backSubs.push(fn);
    return () => {
      const i = backSubs.indexOf(fn);
      if (i >= 0) backSubs.splice(i, 1);
    };
  },
};

export default host;
