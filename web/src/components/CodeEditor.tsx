import { useCallback, useMemo, useRef, type KeyboardEvent } from 'react';

interface Props {
  value: string;
  onChange: (v: string) => void;
  language?: string;
  disabled?: boolean;
  minHeight?: number;
  placeholder?: string;
  id?: string;
}

/**
 * Textarea-based code editor: line-number gutter kept in scroll sync, Tab
 * inserts an indent (Shift+Tab outdents), Enter keeps the current indent.
 * Deliberately not a full editor — the scripts here are short and the bundle
 * stays small.
 */
export function CodeEditor({ value, onChange, disabled, minHeight = 320, placeholder, id }: Props) {
  const gutter = useRef<HTMLDivElement>(null);
  const ta = useRef<HTMLTextAreaElement>(null);
  const lines = useMemo(() => Math.max(1, value.split('\n').length), [value]);
  const numbers = useMemo(() => Array.from({ length: lines }, (_, i) => i + 1).join('\n'), [lines]);

  const onScroll = useCallback(() => {
    if (gutter.current && ta.current) gutter.current.scrollTop = ta.current.scrollTop;
  }, []);

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    const el = e.currentTarget;
    const { selectionStart: s, selectionEnd: en } = el;
    const indent = '    ';
    const apply = (next: string, selStart: number, selEnd = selStart) => {
      onChange(next);
      // React re-renders asynchronously; restore the caret afterwards.
      requestAnimationFrame(() => {
        el.selectionStart = selStart;
        el.selectionEnd = selEnd;
      });
    };
    if (e.key === 'Tab') {
      e.preventDefault();
      const lineStart = value.lastIndexOf('\n', s - 1) + 1;
      if (s !== en && value.slice(s, en).includes('\n')) {
        // block indent/outdent
        const blockEnd = value.indexOf('\n', en - 1) === -1 ? value.length : Math.max(en, value.indexOf('\n', en - 1));
        const block = value.slice(lineStart, blockEnd);
        const changed = block
          .split('\n')
          .map((l) => (e.shiftKey ? l.replace(/^( {1,4}|\t)/, '') : indent + l))
          .join('\n');
        apply(value.slice(0, lineStart) + changed + value.slice(blockEnd), lineStart, lineStart + changed.length);
      } else if (e.shiftKey) {
        const m = value.slice(lineStart).match(/^( {1,4}|\t)/);
        if (m) {
          const n = m[1].length;
          apply(value.slice(0, lineStart) + value.slice(lineStart + n), Math.max(lineStart, s - n), Math.max(lineStart, en - n));
        }
      } else {
        apply(value.slice(0, s) + indent + value.slice(en), s + indent.length);
      }
    } else if (e.key === 'Enter' && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      const lineStart = value.lastIndexOf('\n', s - 1) + 1;
      const m = value.slice(lineStart, s).match(/^[ \t]*/);
      const pad = m ? m[0] : '';
      apply(value.slice(0, s) + '\n' + pad + value.slice(en), s + 1 + pad.length);
    } else if (e.key === 'Escape') {
      // Escape only releases the keyboard trap (so Tab can leave the editor);
      // it must not bubble to a surrounding dialog and discard the ad hoc
      // script being typed. A second Escape, with focus outside, closes it.
      e.preventDefault();
      e.stopPropagation();
      el.blur();
    }
  };

  return (
    <div className="editor" style={{ minHeight }}>
      <div className="gutter" ref={gutter} aria-hidden="true">
        {numbers}
      </div>
      <textarea
        id={id}
        ref={ta}
        value={value}
        disabled={disabled}
        placeholder={placeholder}
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
        wrap="off"
        style={{ minHeight }}
        onChange={(e) => onChange(e.target.value)}
        onScroll={onScroll}
        onKeyDown={onKeyDown}
      />
    </div>
  );
}
