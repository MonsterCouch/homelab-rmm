import type { ReactNode } from 'react';

// The on-screen key bar shared by the terminal (C8) and the remote-desktop
// viewer (C14). Gboard emits no Ctrl, Esc, Tab, arrows or function keys, so
// without this a phone operator cannot break a hung command, tab-complete,
// recall history, leave vi or send Alt+F4.
//
// The bar is always rendered and hidden by `device-touch.css` unless
// `(pointer: coarse)` matches, so a mouse sees exactly what it saw before.

/**
 * A key button.
 *
 * It acts on `pointerdown` and calls `preventDefault()` there, which is the
 * whole point: the default action of a pointerdown on a button is to move
 * focus, and moving focus out of the terminal's textarea (or the viewer's
 * hidden input) closes the Android soft keyboard. Acting on `click` instead
 * would dismiss the keyboard on every keystroke. Enter/Space keep the button
 * usable from a hardware keyboard.
 */
export function KeyButton({
  onPress,
  children,
  title,
  on,
  wide,
  disabled,
}: {
  onPress: () => void;
  children: ReactNode;
  title: string;
  /** sticky modifier that is currently armed */
  on?: boolean;
  /** a word-width face ("PgUp") rather than a square one */
  wide?: boolean;
  disabled?: boolean;
}) {
  const cls = ['btn', 'keycap', on ? 'on' : '', wide ? 'wide' : ''].filter(Boolean).join(' ');
  return (
    <button
      type="button"
      className={cls}
      title={title}
      aria-label={title}
      aria-pressed={on === undefined ? undefined : on}
      disabled={disabled}
      onPointerDown={(e) => {
        e.preventDefault();
        if (!disabled) onPress();
      }}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          if (!disabled) onPress();
        }
      }}
    >
      {children}
    </button>
  );
}

/** The scrolling row the key buttons live in. */
export function KeyBar({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="touch-keybar" role="toolbar" aria-label={label}>
      {children}
    </div>
  );
}
