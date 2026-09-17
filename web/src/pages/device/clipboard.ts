import { host } from '../../lib/host';

// Task C7. Every clipboard touch in the terminal and the remote desktop goes
// through here.
//
// Two hazards this exists to remove:
//
//  1. `navigator.clipboard` is undefined on a non-secure origin, so
//     `navigator.clipboard.writeText(s)` throws a *synchronous* TypeError
//     while reading the property. A trailing `.catch()` cannot see it. One of
//     the old call sites was inside xterm's synchronous
//     `attachCustomKeyEventHandler`, where that throw ate a Ctrl+C.
//  2. `navigator.clipboard.readText()` needs the CLIPBOARD_READ_WRITE
//     permission, which an Android WebView has no API to grant. The native
//     bridge is the only working Paste path there (docs/ANDROID.md §3.6).
//
// Both helpers are `async`, so nothing they do can throw at the call site: a
// failure is a `false` / `null` return, never an exception.

/** The `document.execCommand('copy')` fallback CopyButton already uses. */
function execCommandCopy(text: string): boolean {
  try {
    const active = document.activeElement as HTMLElement | null;
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.top = '0';
    ta.style.left = '0';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    // The textarea stole focus; hand it straight back so a terminal keeps
    // receiving keystrokes after a copy.
    active?.focus?.();
    return ok;
  } catch {
    return false;
  }
}

/**
 * Copy `text`, preferring the native bridge, then the async Clipboard API,
 * then a selection copy. Returns whether anything took it.
 */
export async function copyText(text: string): Promise<boolean> {
  if (!text) return false;
  try {
    if (await host.clipboardWrite(text)) return true;
  } catch {
    /* bridge unusable; fall through */
  }
  try {
    const cb = navigator.clipboard;
    if (cb && typeof cb.writeText === 'function') {
      await cb.writeText(text);
      return true;
    }
  } catch {
    /* insecure origin, denied permission or no focus; fall through */
  }
  return execCommandCopy(text);
}

/**
 * Read the clipboard, preferring the native bridge. Returns null when the
 * clipboard cannot be read — which is the normal case in a WebView and on a
 * non-secure origin, so callers must have a keyboard-driven alternative.
 */
export async function readClipboard(): Promise<string | null> {
  try {
    const viaHost = await host.clipboardRead();
    if (viaHost !== null) return viaHost;
  } catch {
    /* bridge unusable; fall through */
  }
  try {
    const cb = navigator.clipboard;
    if (cb && typeof cb.readText === 'function') return await cb.readText();
  } catch {
    /* blocked */
  }
  return null;
}
