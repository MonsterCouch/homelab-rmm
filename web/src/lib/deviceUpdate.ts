// What a single-device agent update did, as one toast. Pure, so the wording is
// decided here and the device page only shows it.

import type { ApprovalPending, DispatchUpdateResult } from '../api/types';
import { bytes, pluralize } from './format';
import { describeUpdateSource } from './fleetUpdate';

export interface DeviceUpdateSummary {
  tone: 'success' | 'info' | 'warning';
  title: string;
  detail: string;
}

/**
 * The toast for the answer to POST /api/agents/{id}/update. A pending answer
 * is toasted by the request layer already, so a caller shows this one only for
 * the other answers.
 */
export function summarizeDeviceUpdate(res: DispatchUpdateResult | ApprovalPending, agentName: string): DeviceUpdateSummary {
  if ('pending' in res && res.pending === true) {
    const more = Math.max(0, res.need - res.have);
    return {
      tone: 'info',
      title: `Waiting for ${pluralize(more, 'more approver')}`,
      detail: `The update of ${agentName} is sent once ${res.need} operators have signed it.`,
    };
  }
  const r = res as DispatchUpdateResult;
  if (r.up_to_date) return { tone: 'info', title: 'Already on this build', detail: r.message };
  if (r.installing) return { tone: 'info', title: `Update in progress on ${agentName}`, detail: r.message };
  const out = r.result;
  const parts: string[] = [];
  if (out) {
    parts.push(describeUpdateSource(out.source));
    if (out.bytes) parts.push(bytes(out.bytes));
    if (out.resumed_chunks && out.resumed_chunks > 0) parts.push(`resumed ${pluralize(out.resumed_chunks, 'chunk')}`);
    if (out.version) parts.push(`restarting on ${out.version}`);
  }
  return { tone: 'success', title: `Update staged on ${agentName}`, detail: parts.length ? parts.join(', ') : r.message };
}
