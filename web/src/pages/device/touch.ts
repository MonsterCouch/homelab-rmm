import { useEffect, useRef, useState, type RefObject } from 'react';

// Shared touch plumbing for the terminal and the remote-desktop viewer
// (tasks C8 and C14). Nothing here changes behaviour for a mouse: every hook
// either keys off `(pointer: coarse)` or is inert until a touch pointer
// actually arrives.

/** True when the primary pointer cannot hover — a finger or a stylus. */
export function coarsePointer(): boolean {
  try {
    return window.matchMedia('(pointer: coarse)').matches;
  } catch {
    return false;
  }
}

/** Reactive `matchMedia`, so rotating or docking a device is picked up. */
export function useMediaQuery(query: string): boolean {
  const [match, setMatch] = useState(() => {
    try {
      return window.matchMedia(query).matches;
    } catch {
      return false;
    }
  });
  useEffect(() => {
    let mq: MediaQueryList;
    try {
      mq = window.matchMedia(query);
    } catch {
      return;
    }
    const on = () => setMatch(mq.matches);
    on();
    mq.addEventListener('change', on);
    return () => mq.removeEventListener('change', on);
  }, [query]);
  return match;
}

/** `(pointer: coarse)` as reactive state. */
export function useCoarsePointer(): boolean {
  return useMediaQuery('(pointer: coarse)');
}

/** Never shrink a terminal or a viewer below this many CSS pixels. */
const MIN_FILL = 180;

/**
 * Task C8(b) / C14. `.fill-page` is a fixed `100vh`-derived box that starts
 * ~247 px down a phone page, so it already overflows the fold by ~75 px before
 * the soft keyboard opens — and `vh` does not shrink when Gboard appears.
 *
 * The stylesheet turns the page into a flex column on phones; this hook is the
 * guarantee on top of it: on coarse pointers it measures the *visual* viewport
 * (the part the keyboard leaves) and pins the element's height to what is
 * actually visible, then re-fits. On a mouse it removes anything it set and
 * does nothing else, so desktop layout is untouched.
 */
export function useFillHeight(ref: RefObject<HTMLElement>, refit?: () => void): void {
  const refitRef = useRef(refit);
  refitRef.current = refit;

  useEffect(() => {
    const vv = window.visualViewport ?? null;
    let raf = 0;

    const clear = (node: HTMLElement) => {
      node.style.removeProperty('height');
      node.style.removeProperty('flex');
    };

    const apply = () => {
      raf = 0;
      const node = ref.current;
      if (!node) return;
      if (!coarsePointer()) {
        clear(node);
        refitRef.current?.();
        return;
      }
      const availH = vv ? vv.height : window.innerHeight;
      const offsetTop = vv ? vv.offsetTop : 0;
      const rect = node.getBoundingClientRect();
      // Distance from the element's top edge to the bottom of what the user
      // can actually see, in layout-viewport coordinates.
      const room = availH + offsetTop - rect.top;
      // Leave the scroll container's own bottom padding free so the page does
      // not gain 30 px of pointless scroll.
      let pad = 12;
      const parent = node.parentElement;
      if (parent) {
        const pb = parseFloat(getComputedStyle(parent).paddingBottom);
        if (Number.isFinite(pb)) pad = Math.min(40, Math.max(8, pb));
      }
      const target = Math.max(MIN_FILL, Math.round(room - pad));
      if (Math.abs(rect.height - target) > 2) {
        node.style.height = `${target}px`;
        node.style.flex = '0 0 auto';
      }
      refitRef.current?.();
    };

    const schedule = () => {
      if (!raf) raf = requestAnimationFrame(apply);
    };

    schedule();
    window.addEventListener('resize', schedule);
    window.addEventListener('orientationchange', schedule);
    vv?.addEventListener('resize', schedule);
    vv?.addEventListener('scroll', schedule);
    return () => {
      if (raf) cancelAnimationFrame(raf);
      window.removeEventListener('resize', schedule);
      window.removeEventListener('orientationchange', schedule);
      vv?.removeEventListener('resize', schedule);
      vv?.removeEventListener('scroll', schedule);
      const node = ref.current;
      if (node) clear(node);
    };
  }, [ref]);
}
