// Grants for the streaming features (§4.1 "Grants for streaming features").
// A shell or remote-desktop WebSocket cannot answer a 428 and the file browser
// issues many requests, so the console first obtains one signed grant per
// device and feature through request() (which runs the signing dialog), and
// the server attaches it to the matching requests until it expires.

import { api, isPending } from '../api/client';

/** Operations a grant covers, per feature. */
export const GRANT_OPS = {
  shell: ['shell.open'],
  desktop: ['desktop.start'],
  files: ['fs.list', 'fs.read'],
} as const;

/** Re-ask a little before the server would refuse, so a long session does not stall mid-request. */
const MARGIN_MS = 30_000;
/** "No bundle applies" is cheap to re-check and can change when a bundle goes live. */
const UNREQUIRED_TTL_MS = 30_000;

const granted = new Map<string, number>(); // device|ops -> usable until (ms epoch)
const inflight = new Map<string, Promise<void>>();

/** The server's timestamps are unix seconds; tolerate milliseconds too. */
function toMs(t: number): number {
  return t > 1e12 ? t : t * 1000;
}

/**
 * Make sure the signed-in operator holds a grant for these operations on this
 * device. Resolves when the feature may open; rejects with an Error whose
 * message is fit to show ("Signature required: ..." when the operator
 * cancelled). Concurrent calls for the same device and operations share one
 * signing dialog.
 */
export function ensureGrant(agentId: string, ops: readonly string[]): Promise<void> {
  const key = `${agentId}|${[...ops].sort().join(',')}`;
  const until = granted.get(key);
  if (until && until > Date.now()) return Promise.resolve();
  const running = inflight.get(key);
  if (running) return running;
  const p = (async () => {
    const r = await api.grant(agentId, [...ops]);
    if (isPending(r)) {
      const more = Math.max(1, r.need - r.have);
      throw new Error(`Waiting for ${more} more approver${more === 1 ? '' : 's'} before this can open. Other operators can sign it under Approvals.`);
    }
    if (typeof r?.expires_at === 'number' && r.expires_at > 0) {
      granted.set(key, toMs(r.expires_at) - MARGIN_MS);
    } else if (r?.required === false) {
      granted.set(key, Date.now() + UNREQUIRED_TTL_MS);
    }
  })().finally(() => inflight.delete(key));
  inflight.set(key, p);
  return p;
}

/** Forget cached grants (sign-out, or a grant the server turned out to have dropped). */
export function forgetGrants(agentId?: string): void {
  for (const k of [...granted.keys()]) if (!agentId || k.startsWith(`${agentId}|`)) granted.delete(k);
}
