// State chips and compliance formatting, shared by the baselines list, the
// status matrix, the device tab and the preview table.

import type { ReactNode } from 'react';
import type { BaselineCounts, BaselineResult, BaselineState } from '../../api/types';
import { Chip } from '../ui';
import { dateTime, relTime } from '../../lib/format';

type Tone = 'ok' | 'warn' | 'danger' | 'info' | 'accent' | 'purple' | '';

/** "unknown" is the console's word for a check with no result row yet. */
export type CellState = BaselineState | 'unknown';

export const STATES: CellState[] = ['pass', 'fail', 'fixed', 'error', 'skipped', 'unknown'];

export function stateTone(s: string): Tone {
  switch (s) {
    case 'pass':
      return 'ok';
    case 'fixed':
      return 'accent';
    case 'fail':
      return 'danger';
    case 'error':
      return 'warn';
    case 'skipped':
      return 'info';
    default:
      return '';
  }
}

export const STATE_HELP: Record<CellState, string> = {
  pass: 'Compliant.',
  fail: 'Drift observed and not fixed.',
  fixed: 'Drift was observed, the fix ran and the re-check passed.',
  error: 'The check could not run, or the fix failed and the re-check still fails.',
  skipped: 'Not applicable here (OS filter, or the kind is not implemented on this device).',
  unknown: 'No report for this check yet.',
};

/** What a stale row means, in the words the doc uses (A12). */
export const STALE_HELP = 'The baseline changed after this result: awaiting re-evaluation.';

/**
 * One state, as a chip. The word is always present — the colour repeats it,
 * it never carries it alone — and a STALE result keeps its own colour and
 * full contrast, marked by a dashed outline plus text a screen reader reads.
 * It used to be drawn at opacity 0.55, which pushed every chip under 3:1
 * against the card behind it and left "awaiting re-evaluation" as a
 * difference in paleness nobody can name.
 */
export function StateChip({ state, stale, title }: { state: CellState; stale?: boolean; title?: string }) {
  return (
    <span className={stale ? 'chip-stale' : undefined} title={title ?? (stale ? `${STATE_HELP[state]} ${STALE_HELP}` : STATE_HELP[state])}>
      <Chip tone={stateTone(state)}>{state}</Chip>
      {stale && <span className="sr-only"> (stale, awaiting re-evaluation)</span>}
    </span>
  );
}

/** 0..100 or null — null is "nothing applies here", never 0 (A25). */
export function complianceText(v: number | null | undefined): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return '—';
  return `${Math.round(v * 10) / 10}%`;
}

export function complianceTone(v: number | null | undefined): Tone {
  if (v === null || v === undefined || !Number.isFinite(v)) return '';
  if (v >= 99.999) return 'ok';
  if (v >= 90) return 'warn';
  return 'danger';
}

export function ComplianceChip({ value, stale }: { value: number | null | undefined; stale?: boolean }) {
  const none = value === null || value === undefined || !Number.isFinite(value);
  const title = none ? 'No applicable check has reported yet, so there is no score — this is not 0%.' : stale ? STALE_HELP : undefined;
  return (
    <span className={stale ? 'chip-stale' : undefined} title={title}>
      <Chip tone={complianceTone(value)}>
        {complianceText(value)}
        {stale ? ' (stale)' : ''}
      </Chip>
    </span>
  );
}

/** pass/fail/fixed/error/skipped/unknown as a compact row of counts. */
export function CountsRow({ counts }: { counts: BaselineCounts | undefined }) {
  if (!counts) return <span className="faint">—</span>;
  const parts: ReactNode[] = [];
  for (const s of STATES) {
    const n = counts[s as keyof BaselineCounts] ?? 0;
    if (!n) continue;
    parts.push(
      <span key={s} title={`${n} ${s}`}>
        <Chip tone={stateTone(s)}>
          {n} {s}
        </Chip>
      </span>,
    );
  }
  if (!parts.length) return <span className="faint">no results</span>;
  return (
    <span className="row" style={{ gap: 4 }}>
      {parts}
    </span>
  );
}

/** expected vs observed with since/duration — the hover text of a matrix cell. */
export function resultTooltip(r: BaselineResult | null | undefined, checkName: string): string {
  if (!r) return `${checkName}: no report yet`;
  const lines = [`${checkName} — ${r.state}${r.stale ? ' (awaiting re-evaluation)' : ''}`];
  if (r.expected) lines.push(`expected: ${r.expected}`);
  if (r.observed) lines.push(`observed: ${r.observed}`);
  if (r.detail) lines.push(`detail: ${r.detail.slice(0, 300)}`);
  if (r.since) lines.push(`since ${dateTime(r.since)} (${relTime(r.since)})`);
  if (r.checked_at) lines.push(`checked ${relTime(r.checked_at)} on the device`);
  return lines.join('\n');
}
