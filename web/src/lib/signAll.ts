// "Sign all" on the Review tab. Every row is one unit (one organization and one
// purpose of an object), and each needs its own signature, so signing the list
// is one dialog per row, one at a time. Cancelling a dialog stops the rest: the
// next one would only land in front of someone who just said no.

import { api, ApiError, isPending } from '../api/client';
import type { UnsignedObject } from '../api/types';
import { errMsg } from '../state/toast';
import { pluralize } from './format';

/** What one run of signAll did. */
export interface SignAllSummary {
  /** units signed here, including those found already approved */
  signed: number;
  /** units signed here that still wait for another approver */
  pending: number;
  /** units that could not be signed, with the reason */
  failed: { name: string; error: string }[];
  /** units left unsigned because the operator cancelled a signing dialog */
  cancelled: number;
  /** units that still need a signature after the run, counted from each object's last reply: they were not in the list */
  more: number;
}

/** "Patch policy" rows say what they cover: "Nightly (reboot)". */
export function unitLabel(o: Pick<UnsignedObject, 'name' | 'id' | 'purpose'>): string {
  const name = o.name || String(o.id);
  return o.purpose ? `${name} (${o.purpose})` : name;
}

/** Sign each row's own unit, one dialog at a time, and report what happened. */
export async function signAll(rows: UnsignedObject[], onProgress?: (done: number) => void): Promise<SignAllSummary> {
  const s: SignAllSummary = { signed: 0, pending: 0, failed: [], cancelled: 0, more: 0 };
  // Replies count the object's other unsigned units at that moment, so only
  // the last reply per object says what is still open once this run is done.
  const left = new Map<string, number>();
  for (const [i, o] of rows.entries()) {
    try {
      const r = await api.signObject(o.type, o.id, { org: o.org, purpose: o.purpose });
      if (isPending(r)) s.pending++;
      else {
        s.signed++;
        left.set(`${o.type}/${o.id}`, r.remaining ?? 0);
      }
    } catch (err) {
      // request() turns a cancelled signing dialog into a 428.
      if (err instanceof ApiError && err.status === 428) {
        s.cancelled = rows.length - i;
        break;
      }
      s.failed.push({ name: unitLabel(o), error: errMsg(err) });
    }
    onProgress?.(i + 1);
  }
  for (const n of left.values()) s.more += n;
  return s;
}

/** One sentence for a toast, built from the parts of the run that are not zero. */
export function summarizeSignAll(s: SignAllSummary): string {
  const parts: string[] = [];
  if (s.signed > 0) parts.push(`${pluralize(s.signed, 'approval')} signed`);
  if (s.pending > 0) parts.push(`${pluralize(s.pending, 'approval')} ${s.pending === 1 ? 'is' : 'are'} waiting for another approver`);
  if (s.failed.length > 0) {
    const why = s.failed.map((f) => `${f.name}: ${f.error.replace(/[.\s]+$/, '')}`);
    parts.push(`${pluralize(s.failed.length, 'approval')} failed - ${why.join('; ')}`);
  }
  if (s.cancelled > 0) parts.push(`${pluralize(s.cancelled, 'approval')} ${s.cancelled === 1 ? 'was' : 'were'} not signed`);
  if (s.more > 0) parts.push(`${pluralize(s.more, 'more unit')} of these objects still ${s.more === 1 ? 'needs' : 'need'} a signature`);
  return parts.length > 0 ? `${parts.join('; ')}.` : 'Nothing was signed.';
}

/** Warning when only part of it went through, error when nothing did, success otherwise. */
export function signAllTone(s: SignAllSummary): 'success' | 'warning' | 'error' {
  if (s.failed.length > 0) return s.signed + s.pending > 0 ? 'warning' : 'error';
  if (s.cancelled > 0 || s.more > 0) return 'warning';
  return 'success';
}
