// The signing request queue. request() in api/client.ts stays free of UI: when
// the server answers 428 it calls requestSigning(), which parks the request
// here; <SigningHost/> (components/SigningDialog.tsx) renders the head of the
// queue and settles it. The same queue serves the approvals and trust pages,
// so every touch of a security key goes through one dialog that shows what
// the key is about to sign.

import type { BundleView } from './manifest';
import type { Assertion } from './webauthn';

/** What the server sends with a 428 (and what the approvals queue sends per item). */
export interface SigningChallenge {
  /** manifest: bytes of an action/grant/standing manifest; bundle: a proposed trust bundle */
  docKind: 'manifest' | 'bundle';
  /** exact bytes to sign, unpadded base64url */
  doc: string;
  /** the server's own description: shown, but labelled as the server's claim */
  summary?: string;
  /** false in audit mode: the operator may proceed unsigned */
  required: boolean;
  /** shown in the dialog title/context, e.g. "Approve a pending request" */
  title?: string;
  /** RP ID for navigator.credentials.get (default: location.hostname) */
  rpId?: string;
  /** base64url credential IDs allowed to sign (default: any) */
  allowCredentials?: string[];
  userVerification?: UserVerificationRequirement;
  /** bundle signing only: the live bundle, to show what changes */
  currentBundle?: BundleView | null;
}

export type SigningDecision = { kind: 'sign'; assertion: Assertion } | { kind: 'skip' };

/** Rejection reason when the operator closes the dialog, or the caller goes away. */
export class SigningCancelled extends Error {
  constructor(message = 'signing was cancelled') {
    super(message);
    this.name = 'SigningCancelled';
  }
}

export interface QueuedSigning {
  id: number;
  challenge: SigningChallenge;
  resolve: (d: SigningDecision) => void;
  reject: (e: Error) => void;
}

let seq = 0;
let queue: QueuedSigning[] = [];
const listeners = new Set<() => void>();

function emit(): void {
  for (const l of listeners) l();
}

/** Ask the operator to sign. Resolves with the assertion (or a skip), rejects with SigningCancelled. */
export function requestSigning(challenge: SigningChallenge, signal?: AbortSignal): Promise<SigningDecision> {
  return new Promise<SigningDecision>((resolve, reject) => {
    if (signal?.aborted) {
      reject(new SigningCancelled('request was aborted'));
      return;
    }
    const id = ++seq;
    const item: QueuedSigning = {
      id,
      challenge,
      resolve: (d) => {
        signal?.removeEventListener('abort', onAbort);
        resolve(d);
      },
      reject: (e) => {
        signal?.removeEventListener('abort', onAbort);
        reject(e);
      },
    };
    const onAbort = () => settle(id, null, new SigningCancelled('request was aborted'));
    signal?.addEventListener('abort', onAbort, { once: true });
    queue = [...queue, item];
    emit();
  });
}

/** Resolve (decision) or reject (error) a queued request and drop it. */
export function settle(id: number, decision: SigningDecision | null, err?: Error): void {
  const item = queue.find((q) => q.id === id);
  if (!item) return;
  queue = queue.filter((q) => q.id !== id);
  emit();
  if (decision) item.resolve(decision);
  else item.reject(err ?? new SigningCancelled());
}

export function subscribeSigning(fn: () => void): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

export function signingSnapshot(): QueuedSigning[] {
  return queue;
}
