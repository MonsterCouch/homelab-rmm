// Fleet agent updates. A signed manifest covers one organization, one build of
// the agent and no more devices than one update may carry, so updating every
// device in organizations that sign actions is several signatures, and no single
// request can carry them. The server updates the devices of unsigned
// organizations at once and hands back the rest as groups; the console drives
// the loop from here, one group at a time, so the operator signs one dialog at a
// time and cancelling one stops the rest. What the run did comes back as a
// summary, and as one sentence for a toast.

import { api, ApiError, isPending } from '../api/client';
import type { SignedUpdateGroup, UpdateBatchResult } from '../api/types';
import { errMsg } from '../state/toast';
import { pluralize } from './format';

/** What one run of updateFleet did. */
export interface FleetUpdateSummary {
  /**
   * devices sent the update without a signature: those of organizations that do
   * not sign actions, and those the operator let through with "Continue
   * without signing" in an organization that only audits
   */
  unsigned: number;
  /** devices a signed update was sent to */
  signed: number;
  /** devices that were offline when their group was sent, so the update did not reach them */
  offline: number;
  /** online devices the server has no agent build for, so it sent them nothing */
  noBuild: number;
  /** online devices that already run the pushed build, so nothing was sent to them */
  upToDate: number;
  /** groups signed here that still wait for another approver */
  pendingGroups: number;
  /** groups in which a device failed, or that could not be sent at all, with the reasons */
  failed: { group: SignedUpdateGroup; error: string }[];
  /** groups left unsigned because the operator cancelled a signing dialog */
  cancelledGroups: number;
}

/** "3 devices (linux/amd64) in Acme": which devices a group is, for a sentence. */
export function describeGroup(g: SignedUpdateGroup): string {
  return `${pluralize(g.agent_ids?.length ?? 0, 'device')} (${g.os}/${g.arch}) in ${g.org_name || g.org}`;
}

/** The most distinct reasons, and the most devices for each, that a sentence names. */
const MAX_REASONS = 3;
const MAX_DEVICES = 3;
/** A reason is text the device wrote, so it is clipped before it goes into a sentence. */
const MAX_REASON_LENGTH = 140;

/**
 * Why devices did not take an update, for a sentence: one entry per distinct
 * reason with the devices that gave it, most devices first, so 500 devices that
 * refused the same way read as one line instead of 500.
 */
export function explainFailures(failed: UpdateBatchResult['failed']): string {
  const byReason = new Map<string, string[]>();
  for (const f of failed) {
    let reason = f.error.replace(/\s+/g, ' ').trim().replace(/[.\s]+$/, '');
    if (reason.length > MAX_REASON_LENGTH) reason = `${reason.slice(0, MAX_REASON_LENGTH)}...`;
    reason = reason || 'no reason given';
    byReason.set(reason, [...(byReason.get(reason) ?? []), f.name || f.id]);
  }
  const entries = [...byReason].sort((a, b) => b[1].length - a[1].length).map(([reason, who]) => {
    const shown = who.slice(0, MAX_DEVICES).join(', ');
    return `${shown}${who.length > MAX_DEVICES ? ` and ${who.length - MAX_DEVICES} more` : ''}: ${reason}`;
  });
  const unshown = entries.length - MAX_REASONS;
  return entries.slice(0, MAX_REASONS).join('; ') + (unshown > 0 ? `; ${pluralize(unshown, 'other reason')} not shown` : '');
}

async function run(): Promise<FleetUpdateSummary> {
  const all = await api.updateAllAgents();
  // A Go server may encode an empty list as null (signed_groups here, failed below).
  const groups = all.signed_groups ?? [];
  const s: FleetUpdateSummary = {
    unsigned: all.dispatched_to,
    signed: 0,
    offline: 0,
    noBuild: all.skipped_no_build,
    upToDate: all.up_to_date ?? 0,
    pendingGroups: 0,
    failed: [],
    cancelledGroups: 0,
  };
  for (const [i, g] of groups.entries()) {
    try {
      const res = await api.updateAgentBatch(g.agent_ids);
      if (isPending(res)) {
        s.pendingGroups++;
        continue;
      }
      // Whether the reply was signed is the server's to say: in an organization
      // that only audits the operator can continue without signing, and then
      // nothing was signed whatever the group is.
      if (res.signed) s.signed += res.dispatched_to;
      else s.unsigned += res.dispatched_to;
      // A device that dropped offline since the listing is not a failure, and
      // not an error: it only needs the update again when it is back.
      s.offline += res.offline;
      s.upToDate += res.up_to_date ?? 0;
      const failed = res.failed ?? [];
      if (failed.length > 0) s.failed.push({ group: g, error: explainFailures(failed) });
    } catch (err) {
      // request() turns a cancelled signing dialog into a 428. Cancelling means
      // stop: the next dialog would only land in front of someone who just said no.
      if (err instanceof ApiError && err.status === 428) {
        s.cancelledGroups = groups.length - i;
        break;
      }
      s.failed.push({ group: g, error: errMsg(err) });
    }
  }
  return s;
}

let inflight: Promise<FleetUpdateSummary> | null = null;
const listeners = new Set<() => void>();

function setInflight(p: Promise<FleetUpdateSummary> | null): void {
  inflight = p;
  for (const l of listeners) l();
}

/** For useSyncExternalStore: told whenever a run starts or finishes. */
export function subscribeFleetUpdate(fn: () => void): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

/** True while a run is going, wherever in the console it was started. */
export function fleetUpdateRunning(): boolean {
  return inflight !== null;
}

/**
 * Update every online device. The server updates unsigned organizations at
 * once; for each group of a signing organization the operator is asked for one
 * signature, one dialog at a time. Cancelling a dialog stops the run, any
 * other failure is recorded against its group and the run goes on, so this
 * rejects only when the first request fails, before anything was sent.
 * Concurrent calls share the run already going (as ensureGrant does with its
 * dialog): it can sit on a dialog or wait out a slow device for a while, and a
 * second call in that time must not ask for the same signatures again. The
 * buttons that start it follow fleetUpdateRunning, so a click cannot even
 * join a run and report it twice.
 */
export function updateFleet(): Promise<FleetUpdateSummary> {
  if (inflight) return inflight;
  const p = run().finally(() => setInflight(null));
  setInflight(p);
  return p;
}

/** One sentence for a toast, built from the parts of the run that are not zero. */
export function summarizeFleetUpdate(s: FleetUpdateSummary): string {
  const parts: string[] = [];
  const sent = s.unsigned + s.signed;
  if (sent > 0) parts.push(`Update sent to ${pluralize(sent, 'device')}${s.signed > 0 ? ` (${s.signed} by signed update)` : ''}`);
  if (s.pendingGroups > 0) parts.push(`${pluralize(s.pendingGroups, 'group')} ${s.pendingGroups === 1 ? 'is' : 'are'} waiting for another approver`);
  if (s.offline > 0) parts.push(`${pluralize(s.offline, 'device')} ${s.offline === 1 ? 'was' : 'were'} offline; run Update Agents again when ${s.offline === 1 ? 'it is' : 'they are'} back`);
  if (s.noBuild > 0) parts.push(`${pluralize(s.noBuild, 'online device')} skipped: this server has no agent build for ${s.noBuild === 1 ? 'it' : 'them'}`);
  if (s.upToDate > 0) parts.push(`${pluralize(s.upToDate, 'device')} already ${s.upToDate === 1 ? 'runs' : 'run'} this build`);
  if (s.failed.length > 0) {
    // A message often ends in a full stop of its own; the sentence supplies the only one.
    const why = s.failed.map((f) => `${describeGroup(f.group)}: ${f.error.replace(/[.\s]+$/, '')}`);
    parts.push(`${pluralize(s.failed.length, 'group')} failed - ${why.join('; ')}`);
  }
  if (s.cancelledGroups > 0) parts.push(`${pluralize(s.cancelledGroups, 'group')} ${s.cancelledGroups === 1 ? 'was' : 'were'} not signed`);
  // Reached only when nothing was sent and nothing went wrong: nobody is online.
  // Whether a device needs the update is never decided here, so no reason is
  // given beyond what was done.
  return parts.length > 0 ? `${parts.join('; ')}.` : 'No online device was sent an update.';
}

/**
 * How loud a toast about the run should be, the same way the other bulk
 * actions pick it: a warning when only part of it went through or something is
 * left to do, an error only when a device failed and nothing was sent, and
 * plain information otherwise (a group waiting for another approver, or one the
 * operator chose not to sign, is the operator's business, not a fault).
 */
export function fleetUpdateTone(s: FleetUpdateSummary): 'info' | 'warning' | 'error' {
  if (s.failed.length > 0) return s.unsigned + s.signed > 0 ? 'warning' : 'error';
  if (s.offline > 0 || s.noBuild > 0) return 'warning';
  return 'info';
}
