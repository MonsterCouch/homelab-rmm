// Task C14. The touch gesture model for the remote-desktop viewer.
//
// Absolute mapping is unusable on a phone: a 1920x1080 session fits at 0.19x
// in a 364x507 wrapper, where a fingertip covers ~130 remote pixels. So the
// finger drives a *trackpad*, not a touchscreen — it moves a cursor the viewer
// draws, and the cursor is what clicks.
//
//   one-finger drag                  relative cursor move
//   tap                              click at the cursor
//   tap, then press and drag < 300ms drag with button 0 held
//   long press > 500ms, < 10px       button 2 (right click)
//   two-finger drag                  wheel (sub-notch deltas, per the protocol)
//   pinch                            local canvas zoom
//
// This module is pure event bookkeeping: it never touches the DOM and never
// talks to the socket, so the gesture rules can be read (and reasoned about)
// in one place.

export interface TrackpadHandlers {
  /** Relative cursor move, in CSS pixels of the displayed image. */
  move(dxCss: number, dyCss: number): void;
  down(button: number): void;
  up(button: number): void;
  click(button: number): void;
  /** Two-finger scroll, in CSS pixels, already in wheel-wire orientation. */
  wheel(dx: number, dy: number): void;
  /** Multiply the local zoom by `factor` about the client point (cx, cy). */
  zoom(factor: number, cx: number, cy: number): void;
}

export interface Trackpad {
  onPointerDown(e: PointerEvent): void;
  onPointerMove(e: PointerEvent): void;
  onPointerUp(e: PointerEvent): void;
  /** Drop every gesture and release anything held. */
  reset(): void;
}

/** A press shorter than this, with no travel, is a tap. */
const TAP_MS = 300;
/** Press-and-drag this soon after a tap starts a held drag. */
const DOUBLE_MS = 300;
/** Travel below this is still a tap, not a move. */
const SLOP_PX = 10;
/** Hold this long without travelling for a right click. */
const LONG_PRESS_MS = 500;
/** Relative distance change that means "pinch" rather than "two-finger drag". */
const PINCH_RATIO = 0.08;

interface Pt {
  x: number;
  y: number;
  sx: number;
  sy: number;
  t: number;
}

type Mode =
  /** nothing in progress */
  | 'idle'
  /** one finger down, still inside the tap slop */
  | 'tap'
  /** one finger moving the cursor */
  | 'move'
  /** one finger moving the cursor with button 0 held */
  | 'drag'
  /** two fingers: wheel or pinch */
  | 'gesture'
  /** gesture already resolved (long press, 3+ fingers); ignore until all lift */
  | 'spent';

const now = () => performance.now();

export function createTrackpad(h: TrackpadHandlers): Trackpad {
  const pointers = new Map<number, Pt>();
  let mode: Mode = 'idle';
  let lastTapAt = 0;
  let longTimer = 0;
  /**
   * A live two-finger gesture. `s*` is where it started — the kind is decided
   * against the *cumulative* change, because a per-event delta is only a few
   * pixels and would never clear the slop.
   */
  let two: { dist: number; cx: number; cy: number; sdist: number; scx: number; scy: number; kind: 'none' | 'wheel' | 'zoom' } | null = null;

  const clearLong = () => {
    if (longTimer) {
      clearTimeout(longTimer);
      longTimer = 0;
    }
  };

  const pair = (): [Pt, Pt] | null => {
    const it = pointers.values();
    const a = it.next().value as Pt | undefined;
    const b = it.next().value as Pt | undefined;
    return a && b ? [a, b] : null;
  };

  const endAll = (release: boolean) => {
    clearLong();
    if (release && mode === 'drag') h.up(0);
    pointers.clear();
    two = null;
    mode = 'idle';
  };

  return {
    onPointerDown(e) {
      const t = now();
      pointers.set(e.pointerId, { x: e.clientX, y: e.clientY, sx: e.clientX, sy: e.clientY, t });
      clearLong();
      if (pointers.size === 1) {
        if (t - lastTapAt <= DOUBLE_MS) {
          // tap-then-press: the second press picks the button up and holds it
          mode = 'drag';
          h.down(0);
        } else {
          mode = 'tap';
          longTimer = window.setTimeout(() => {
            longTimer = 0;
            if (mode !== 'tap') return;
            mode = 'spent';
            h.click(2);
          }, LONG_PRESS_MS);
        }
        return;
      }
      if (mode === 'drag') h.up(0);
      if (pointers.size === 2) {
        const p = pair();
        if (p) {
          mode = 'gesture';
          const d = Math.hypot(p[0].x - p[1].x, p[0].y - p[1].y);
          const cx = (p[0].x + p[1].x) / 2;
          const cy = (p[0].y + p[1].y) / 2;
          two = { dist: d, cx, cy, sdist: d, scx: cx, scy: cy, kind: 'none' };
          return;
        }
      }
      mode = 'spent';
      two = null;
    },

    onPointerMove(e) {
      const p = pointers.get(e.pointerId);
      if (!p) return;
      const dx = e.clientX - p.x;
      const dy = e.clientY - p.y;
      p.x = e.clientX;
      p.y = e.clientY;

      if (pointers.size === 1) {
        if (mode === 'tap') {
          if (Math.hypot(e.clientX - p.sx, e.clientY - p.sy) <= SLOP_PX) return;
          clearLong();
          mode = 'move';
        }
        if (mode === 'move' || mode === 'drag') h.move(dx, dy);
        return;
      }

      if (mode !== 'gesture' || !two || pointers.size !== 2) return;
      const q = pair();
      if (!q) return;
      const dist = Math.hypot(q[0].x - q[1].x, q[0].y - q[1].y);
      const cx = (q[0].x + q[1].x) / 2;
      const cy = (q[0].y + q[1].y) / 2;
      const ddx = cx - two.cx;
      const ddy = cy - two.cy;
      if (two.kind === 'none') {
        const ratio = two.sdist > 0 ? Math.abs(dist / two.sdist - 1) : 0;
        if (ratio > PINCH_RATIO) two.kind = 'zoom';
        else if (Math.hypot(cx - two.scx, cy - two.scy) > SLOP_PX) two.kind = 'wheel';
      }
      if (two.kind === 'zoom' && two.dist > 0 && dist > 0) {
        h.zoom(dist / two.dist, cx, cy);
      } else if (two.kind === 'wheel' && (ddx || ddy)) {
        // Content follows the fingers: dragging up scrolls down.
        h.wheel(-ddx, -ddy);
      }
      two.dist = dist;
      two.cx = cx;
      two.cy = cy;
    },

    onPointerUp(e) {
      const p = pointers.get(e.pointerId);
      pointers.delete(e.pointerId);
      clearLong();
      if (pointers.size > 0) {
        // A finger left a multi-finger gesture. Do not fall back to
        // single-finger tracking mid-gesture; wait for a clean slate.
        if (mode === 'gesture') {
          mode = 'spent';
          two = null;
        }
        return;
      }
      const t = now();
      if (mode === 'tap' && p && t - p.t <= TAP_MS) {
        h.click(0);
        lastTapAt = t;
      } else {
        if (mode === 'drag') h.up(0);
        lastTapAt = 0;
      }
      two = null;
      mode = 'idle';
    },

    reset() {
      endAll(true);
      lastTapAt = 0;
    },
  };
}
