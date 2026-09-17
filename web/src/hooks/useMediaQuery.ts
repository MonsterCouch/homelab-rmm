import { useEffect, useState } from 'react';

/**
 * Subscribe to a media query. Components that have to *render differently*
 * (the DataTable's phone cards, a dialog that must not raise the keyboard)
 * cannot express the decision in CSS alone, so they ask here — and they still
 * re-render when the query flips, which is what makes rotating a phone and
 * resizing a desktop window behave the same way.
 *
 * `matchMedia` is missing in a non-browser test environment, so the hook
 * degrades to `false` instead of throwing.
 */
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => window.matchMedia?.(query).matches ?? false);
  useEffect(() => {
    const mq = window.matchMedia?.(query);
    if (!mq) return;
    setMatches(mq.matches);
    const onChange = (e: MediaQueryListEvent) => setMatches(e.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, [query]);
  return matches;
}

/** The console's single phone breakpoint, the one global.css already uses. */
export function usePhone(): boolean {
  return useMediaQuery('(max-width: 700px)');
}

/**
 * A finger, not a mouse. Used for behaviour that is wrong on touch at any
 * width — a backdrop tap that discards a half-filled dialog, an auto-focus
 * that opens the keyboard over the dialog it just opened.
 */
export function useCoarsePointer(): boolean {
  return useMediaQuery('(pointer: coarse)');
}
