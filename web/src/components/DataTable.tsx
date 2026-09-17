import { Fragment, useMemo, useState, type ReactNode } from 'react';
import { usePhone } from '../hooks/useMediaQuery';
import { compare } from '../lib/format';
import { host } from '../lib/host';
import { IconDownload } from './Icons';
import { Button, Checkbox, Empty, Skeleton } from './ui';

export interface Column<T> {
  key: string;
  header: ReactNode;
  /** value used for sorting; defaults to render output when a string */
  sort?: (row: T) => unknown;
  render: (row: T) => ReactNode;
  className?: string;
  width?: number | string;
  align?: 'left' | 'right';
  /**
   * Value for the CSV export. Without it the export falls back to `sort()`
   * and then `render()` when either returns text; a column that renders only
   * markup (an action column, a bar) is left out of the file.
   */
  csv?: (row: T) => string | number | boolean | undefined | null;
  /**
   * Where this column lands in the phone card renderer (below 700px), which
   * replaces a table that would otherwise be three times the width of the
   * screen. Unset means "a labelled field row", so an un-annotated table
   * still shows everything — annotating a page only makes its cards shorter.
   *
   * - `primary`   the card's heading line (several are allowed, and they sit
   *               on one line together: an online dot plus a device name)
   * - `secondary` a subtitle under the heading, with no label
   * - `hide`      not on the card at all; still on the desktop table and
   *               still in the CSV export
   *
   * A column with no text header is an action column wherever it sits in the
   * table: the card lifts it to its own full-width row near the top, because
   * on Alerts those 33x19px Ack/Resolve buttons are the whole reason a phone
   * is out of a pocket and they are off the right edge of the table.
   */
  mobile?: 'primary' | 'secondary' | 'hide';
}

interface Props<T> {
  columns: Column<T>[];
  rows: T[] | undefined;
  rowKey: (row: T) => string;
  loading?: boolean;
  emptyTitle?: string;
  emptyBody?: ReactNode;
  onRowClick?: (row: T) => void;
  rowClass?: (row: T) => string;
  defaultSort?: { key: string; dir: 'asc' | 'desc' };
  selectable?: boolean;
  selected?: Set<string>;
  onSelect?: (s: Set<string>) => void;
  compact?: boolean;
  footer?: ReactNode;
  maxHeight?: number | string;
  /**
   * Base name for the "Export CSV" button in the table footer, e.g. "devices".
   * The file is named `<csvName>-<yyyy-mm-dd>.csv` and contains exactly the
   * rows on screen, in the order on screen: the caller filters, this sorts.
   */
  csvName?: string;
}

/**
 * Sortable table with optional multi-select. Sorting is client-side: every
 * list in this app is small enough (hundreds to a few thousand rows) that a
 * round trip per header click would be slower than a sort.
 */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  loading,
  emptyTitle = 'Nothing here',
  emptyBody,
  onRowClick,
  rowClass,
  defaultSort,
  selectable,
  selected,
  onSelect,
  compact,
  footer,
  maxHeight,
  csvName,
}: Props<T>) {
  const [sort, setSort] = useState<{ key: string; dir: 'asc' | 'desc' } | null>(defaultSort ?? null);
  const phone = usePhone();

  const sorted = useMemo(() => {
    if (!rows) return [];
    if (!sort) return rows;
    const col = columns.find((c) => c.key === sort.key);
    if (!col) return rows;
    const get = col.sort ?? ((r: T) => col.render(r));
    const dir = sort.dir === 'asc' ? 1 : -1;
    return rows
      .map((r, i) => ({ r, i, v: get(r) }))
      .sort((a, b) => compare(a.v, b.v) * dir || a.i - b.i)
      .map((x) => x.r);
  }, [rows, sort, columns]);

  const toggleSort = (key: string) => {
    setSort((s) => (s?.key === key ? (s.dir === 'asc' ? { key, dir: 'desc' } : null) : { key, dir: 'asc' }));
  };

  const allKeys = useMemo(() => sorted.map(rowKey), [sorted, rowKey]);
  const allSelected = selectable && selected && allKeys.length > 0 && allKeys.every((k) => selected.has(k));
  const someSelected = selectable && selected && allKeys.some((k) => selected.has(k));

  const toggleAll = () => {
    if (!onSelect || !selected) return;
    const next = new Set(selected);
    if (allSelected) allKeys.forEach((k) => next.delete(k));
    else allKeys.forEach((k) => next.add(k));
    onSelect(next);
  };
  const toggleOne = (k: string) => {
    if (!onSelect || !selected) return;
    const next = new Set(selected);
    if (next.has(k)) next.delete(k);
    else next.add(k);
    onSelect(next);
  };

  if (loading && !rows) {
    return (
      <div className="dt">
        <div className="table-wrap">
          <Skeleton cols={Math.min(columns.length, 6)} />
        </div>
      </div>
    );
  }

  const foot = (footer || csvName) && (
    <div className="tbl-foot">
      {footer}
      <span style={{ marginLeft: 'auto' }} />
      {csvName && (
        <Button
          size="xs"
          disabled={!sorted.length}
          title="Download these rows (current filters and sort) as CSV"
          onClick={() => void downloadCsv(`${csvName}-${new Date().toISOString().slice(0, 10)}.csv`, toCsv(columns, sorted))}
        >
          <IconDownload /> Export CSV
        </Button>
      )}
    </div>
  );

  // Below the phone breakpoint the table becomes a list of cards: Devices is
  // 13 columns and 1211px wide in a 364px box, with no sticky first column, so
  // scrolling right to the disk figure leaves the row anonymous.
  if (phone) {
    return (
      <div className="dt">
        {sorted.length ? (
          <ul className="card-list">
            {/* The table's select-all lives in the header checkbox, which the
                card list has no room for; without this row the whole bulk
                workflow would be per-row only on a phone. */}
            {selectable && (
              <li className="rc-all">
                <Checkbox
                  checked={!!allSelected}
                  indeterminate={!!someSelected && !allSelected}
                  onChange={toggleAll}
                  label={allSelected ? 'Clear selection' : `Select all ${sorted.length}`}
                />
              </li>
            )}
            {sorted.map((r) => (
              <RowCard
                key={rowKey(r)}
                row={r}
                columns={columns}
                selectable={selectable}
                selected={selected?.has(rowKey(r))}
                onToggle={() => toggleOne(rowKey(r))}
                onRowClick={onRowClick}
                rowClass={rowClass}
              />
            ))}
          </ul>
        ) : (
          <Empty title={emptyTitle}>{emptyBody}</Empty>
        )}
        {foot}
      </div>
    );
  }

  return (
    <div className="dt">
      <div className="table-wrap" style={maxHeight ? { maxHeight, overflow: 'auto' } : undefined}>
      <table className={`tbl ${compact ? 'compact' : ''}`}>
        <thead>
          <tr>
            {selectable && (
              <th className="check">
                <Checkbox checked={!!allSelected} indeterminate={!!someSelected && !allSelected} onChange={toggleAll} />
              </th>
            )}
            {columns.map((c) => {
              // Sortable when the column says how, or when it renders plain
              // text; action/button columns have nothing meaningful to sort by.
              const probe = sorted[0];
              const rendered = c.sort === undefined && probe !== undefined ? c.render(probe) : undefined;
              const sortable = c.sort !== undefined || typeof rendered === 'string' || typeof rendered === 'number';
              const active = sortable && sort?.key === c.key;
              return (
                <th
                  key={c.key}
                  className={`${sortable ? 'sortable' : ''} ${c.align === 'right' ? 'num' : ''} ${c.className ?? ''}`}
                  style={c.width ? { width: c.width } : undefined}
                  onClick={() => sortable && toggleSort(c.key)}
                  onKeyDown={(e) => {
                    if (sortable && (e.key === 'Enter' || e.key === ' ')) {
                      e.preventDefault();
                      toggleSort(c.key);
                    }
                  }}
                  tabIndex={sortable ? 0 : undefined}
                  aria-sort={sortable ? (active ? (sort!.dir === 'asc' ? 'ascending' : 'descending') : 'none') : undefined}
                >
                  {c.header}
                  {active && <span className="arrow">{sort!.dir === 'asc' ? '▲' : '▼'}</span>}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {sorted.map((r) => {
            const k = rowKey(r);
            const sel = selected?.has(k);
            return (
              <tr
                key={k}
                className={`${onRowClick ? 'clickable' : ''} ${sel ? 'selected' : ''} ${rowClass?.(r) ?? ''}`}
                onClick={onRowClick ? () => onRowClick(r) : undefined}
                // Row click is the only way to open some rows (runs), so the
                // row itself must be reachable and activatable from the keyboard.
                tabIndex={onRowClick ? 0 : undefined}
                onKeyDown={
                  onRowClick
                    ? (e) => {
                        if (e.target !== e.currentTarget) return; // a control inside the row handles its own keys
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          onRowClick(r);
                        }
                      }
                    : undefined
                }
              >
                {selectable && (
                  <td className="check" onClick={(e) => e.stopPropagation()}>
                    <Checkbox checked={!!sel} onChange={() => toggleOne(k)} />
                  </td>
                )}
                {columns.map((c) => (
                  <td key={c.key} data-label={headerText(c)} className={`${c.align === 'right' ? 'num' : ''} ${c.className ?? ''}`}>
                    {c.render(r)}
                  </td>
                ))}
              </tr>
            );
          })}
          {!sorted.length && (
            <tr>
              <td colSpan={columns.length + (selectable ? 1 : 0)} style={{ padding: 0 }}>
                <Empty title={emptyTitle}>{emptyBody}</Empty>
              </td>
            </tr>
          )}
        </tbody>
      </table>
      </div>
      {foot}
    </div>
  );
}

/**
 * One row as a card. Reading order is identity first, then the actions — the
 * actions have to be near the top and full size (they are `xs` buttons in the
 * table), but putting them above the name of the device they act on is how a
 * phone acknowledges the wrong alert.
 */
function RowCard<T>({
  row,
  columns,
  selectable,
  selected,
  onToggle,
  onRowClick,
  rowClass,
}: {
  row: T;
  columns: Column<T>[];
  selectable?: boolean;
  selected?: boolean;
  onToggle: () => void;
  onRowClick?: (row: T) => void;
  rowClass?: (row: T) => string;
}) {
  const actions: ReactNode[] = [];
  const heads: Column<T>[] = [];
  const subs: Column<T>[] = [];
  const fields: Column<T>[] = [];
  for (const c of columns) {
    if (isActionColumn(c)) {
      const node = c.render(row);
      if (node !== null && node !== undefined && node !== false && node !== '') actions.push(<Fragment key={c.key}>{node}</Fragment>);
    } else if (c.mobile === 'hide') continue;
    else if (c.mobile === 'primary') heads.push(c);
    else if (c.mobile === 'secondary') subs.push(c);
    else fields.push(c);
  }
  // Nothing annotated: the first text column is the card's identity.
  if (!heads.length && fields.length) heads.push(fields.shift()!);

  return (
    <li
      className={`${onRowClick ? 'clickable' : ''} ${selected ? 'selected' : ''} ${rowClass?.(row) ?? ''}`}
      onClick={onRowClick ? () => onRowClick(row) : undefined}
      tabIndex={onRowClick ? 0 : undefined}
      onKeyDown={
        onRowClick
          ? (e) => {
              if (e.target !== e.currentTarget) return;
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                onRowClick(row);
              }
            }
          : undefined
      }
    >
      <div className="rc-head">
        {selectable && (
          <span className="rc-check" onClick={(e) => e.stopPropagation()}>
            <Checkbox checked={!!selected} onChange={onToggle} />
          </span>
        )}
        <div className="rc-title">
          {heads.map((c) => (
            <Fragment key={c.key}>{c.render(row)}</Fragment>
          ))}
          {subs.map((c) => (
            <div className="rc-sub" key={c.key}>
              {c.render(row)}
            </div>
          ))}
        </div>
      </div>
      {actions.length > 0 && <div className="rc-actions">{actions}</div>}
      {fields.length > 0 && (
        <dl className="rc-fields">
          {fields.map((c) => (
            <Fragment key={c.key}>
              <dt>{headerText(c)}</dt>
              <dd className={c.className ?? ''}>{c.render(row)}</dd>
            </Fragment>
          ))}
        </dl>
      )}
    </li>
  );
}

/** A column with no text header renders buttons or an icon, never a value. */
function isActionColumn<T>(c: Column<T>): boolean {
  return !(typeof c.header === 'string' && c.header.trim());
}

// ---------- CSV export ----------

function headerText<T>(c: Column<T>): string {
  return typeof c.header === 'string' && c.header.trim() ? c.header : c.key;
}

/** Columns that can be written as text: everything else is markup (bars, buttons). */
function exportable<T>(columns: Column<T>[], rows: T[]): Column<T>[] {
  const probe = rows[0];
  return columns.filter((c) => {
    if (c.csv) return true;
    if (!(typeof c.header === 'string' && c.header.trim())) return false; // icon/action column
    if (probe === undefined) return true;
    const v = c.sort ? c.sort(probe) : c.render(probe);
    return typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean';
  });
}

function cell<T>(c: Column<T>, r: T): string {
  const v = c.csv ? c.csv(r) : c.sort ? c.sort(r) : c.render(r);
  if (v === undefined || v === null) return '';
  if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') return String(v);
  return '';
}

/** RFC 4180 quoting, plus a guard against a spreadsheet reading a value as a formula. */
export function csvField(value: string): string {
  // A leading =, +, - or @ makes Excel and Sheets evaluate the cell; a device
  // name or an audit detail is data, never a formula.
  const v = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return /[",\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

/** The rows as shown, as CSV text (header row first). */
export function toCsv<T>(columns: Column<T>[], rows: T[]): string {
  const cols = exportable(columns, rows);
  const lines = [cols.map((c) => csvField(headerText(c))).join(',')];
  for (const r of rows) lines.push(cols.map((c) => csvField(cell(c, r))).join(','));
  return lines.join('\r\n');
}

/**
 * Hand the file to whoever can take it: the native shell first, then the
 * browser. Same-origin blob: the CSP allows no other source.
 *
 * Inside the Android WebView the blob path is a dead end \u2014 `DownloadListener`
 * never fires for a `blob:` URL and no HTTP client can resolve one \u2014 so every
 * Export CSV button is a silent no-op there unless the text goes to the native
 * side before the Blob exists. `host.saveText` writes it to
 * MediaStore.Downloads and resolves true; in a browser there is no bridge, it
 * resolves false, and nothing below changes.
 */
export async function downloadCsv(filename: string, csv: string): Promise<void> {
  // The BOM is what makes Excel open a UTF-8 CSV as UTF-8 \u2014 it belongs in the
  // file whichever side writes it.
  if (await host.saveText(filename, 'text/csv;charset=utf-8', '\uFEFF' + csv)) return;
  const blob = new Blob(['\uFEFF', csv], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** Case-insensitive "every word matches somewhere" text filter. */
export function textMatch(q: string, ...fields: (string | number | undefined | null)[]): boolean {
  const words = q.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return true;
  const hay = fields
    .filter((f) => f !== undefined && f !== null)
    .map((f) => String(f).toLowerCase())
    .join(' ');
  return words.every((w) => hay.includes(w));
}
