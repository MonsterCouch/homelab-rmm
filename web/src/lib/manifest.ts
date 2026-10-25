// The console's own reading of the documents an operator is asked to sign.
// The server sends a summary too, but a summary is the server's claim; what a
// security key signs is the byte string, so the signing dialog shows what
// this code decodes from those bytes.

import { b64urlDecode } from './webauthn';

export interface ManifestView {
  v: number;
  kind: string;
  id: string;
  org: string;
  targets: string[];
  op?: string;
  ops?: string[];
  payload?: Record<string, unknown>;
  constraints?: Record<string, unknown>;
  nonce: string;
  iat: number;
  exp: number;
  issuer?: string;
}

export interface DecodedManifest {
  bytes: Uint8Array<ArrayBuffer>;
  m: ManifestView;
}

function parseObject(bytes: Uint8Array): Record<string, unknown> {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const v: unknown = JSON.parse(text);
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('not a JSON object');
  return v as Record<string, unknown>;
}

/**
 * The server sends document bytes as unpadded base64url. A string that is
 * itself JSON text is accepted as its own UTF-8 bytes. An already-parsed JSON
 * object is refused: re-serializing would not reproduce the bytes the agent
 * will verify, and signing anything but those exact bytes is worthless.
 */
export function docBytes(doc: unknown): Uint8Array<ArrayBuffer> {
  if (typeof doc !== 'string' || !doc) throw new Error('the server did not send the document as exact bytes (base64url string)');
  if (doc.trimStart().startsWith('{')) {
    const e = new TextEncoder().encode(doc);
    const out = new Uint8Array(new ArrayBuffer(e.length));
    out.set(e);
    return out;
  }
  return b64urlDecode(doc);
}

const str = (v: unknown): string => (typeof v === 'string' ? v : '');
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
const int = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) ? v : 0);

export function decodeManifest(doc: unknown): DecodedManifest {
  const bytes = docBytes(doc);
  const o = parseObject(bytes);
  const obj = (v: unknown) => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined);
  return {
    bytes,
    m: {
      v: int(o.v),
      kind: str(o.kind),
      id: str(o.id),
      org: str(o.org),
      targets: strs(o.targets),
      op: str(o.op) || undefined,
      ops: o.ops === undefined ? undefined : strs(o.ops),
      payload: obj(o.payload),
      constraints: obj(o.constraints),
      nonce: str(o.nonce),
      iat: int(o.iat),
      exp: int(o.exp),
      issuer: str(o.issuer) || undefined,
    },
  };
}

// ---------- trust bundles ----------

export interface BundleCred {
  id: string;
  alg: number;
}

export interface BundleView {
  epoch: number;
  prev: string;
  org: string;
  rpId: string;
  origins: string[];
  signers: { owner: string; creds: BundleCred[] }[];
  recovery: string[];
  mode: string;
  requireUV: boolean;
  /** Devices refuse a protected request that carries no transparency log proof. */
  requireLogProof: boolean;
  /** The transparency log key devices pin, empty when the bundle pins none. */
  logKey: string;
  highThreshold: number;
  bundleThreshold: number;
  bulkLimit: number;
}

export function decodeBundle(doc: unknown): { bytes: Uint8Array<ArrayBuffer>; b: BundleView } {
  const bytes = docBytes(doc);
  const o = parseObject(bytes);
  const pol = (o.policy && typeof o.policy === 'object' ? o.policy : {}) as Record<string, unknown>;
  const signers = (Array.isArray(o.signers) ? o.signers : []).map((s) => {
    const r = (s ?? {}) as Record<string, unknown>;
    return {
      owner: str(r.owner),
      creds: (Array.isArray(r.creds) ? r.creds : []).map((c) => {
        const cr = (c ?? {}) as Record<string, unknown>;
        return { id: str(cr.id), alg: int(cr.alg) };
      }),
    };
  });
  const recovery = (Array.isArray(o.recovery) ? o.recovery : []).map((r) => str(((r ?? {}) as Record<string, unknown>).id));
  return {
    bytes,
    b: {
      epoch: int(o.epoch),
      prev: str(o.prev),
      org: str(o.org),
      rpId: str(o.rp_id),
      origins: strs(o.origins),
      signers,
      recovery,
      mode: str(pol.mode),
      requireUV: pol.require_uv === true,
      requireLogProof: pol.require_log_proof === true,
      logKey: str(o.log_key),
      highThreshold: int(pol.high_threshold),
      bundleThreshold: int(pol.bundle_threshold),
      bulkLimit: int(pol.bulk_limit),
    },
  };
}

/** Human-readable differences between the live bundle and a proposed one. */
export function diffBundle(cur: BundleView | null, next: BundleView): string[] {
  const out: string[] = [];
  if (!cur) {
    out.push(`First trust bundle for ${next.org || 'this organization'} (epoch ${next.epoch}).`);
    out.push(`Mode: ${next.mode || 'unset'}`);
    out.push(`Signers: ${next.signers.length ? next.signers.map((s) => `${s.owner} (${s.creds.length} key${s.creds.length === 1 ? '' : 's'})`).join(', ') : 'none'}`);
    out.push(`Recovery keys: ${next.recovery.length ? next.recovery.join(', ') : 'none'}`);
    out.push(`Require log proofs: ${next.requireLogProof ? 'yes' : 'no'}`);
    out.push(`Transparency log key: ${next.logKey || 'none'}`);
    return out;
  }
  out.push(`Epoch ${cur.epoch} → ${next.epoch}`);
  if (cur.mode !== next.mode) out.push(`Mode: ${cur.mode || 'unset'} → ${next.mode || 'unset'}`);
  if (cur.requireUV !== next.requireUV) out.push(`Require user verification: ${cur.requireUV ? 'yes' : 'no'} → ${next.requireUV ? 'yes' : 'no'}`);
  if (cur.requireLogProof !== next.requireLogProof) out.push(`Require log proofs: ${cur.requireLogProof ? 'yes' : 'no'} → ${next.requireLogProof ? 'yes' : 'no'}`);
  if (cur.logKey !== next.logKey) out.push(`Transparency log key: ${cur.logKey || 'none'} → ${next.logKey || 'none'}`);
  if (cur.highThreshold !== next.highThreshold) out.push(`High-risk threshold: ${cur.highThreshold} → ${next.highThreshold}`);
  if (cur.bundleThreshold !== next.bundleThreshold) out.push(`Bundle-change threshold: ${cur.bundleThreshold} → ${next.bundleThreshold}`);
  if (cur.bulkLimit !== next.bulkLimit) out.push(`Bulk limit: ${cur.bulkLimit} → ${next.bulkLimit}`);
  const curOwners = new Map(cur.signers.map((s) => [s.owner, new Set(s.creds.map((c) => c.id))]));
  const nextOwners = new Map(next.signers.map((s) => [s.owner, new Set(s.creds.map((c) => c.id))]));
  for (const [o, ids] of nextOwners) {
    const was = curOwners.get(o);
    if (!was) out.push(`Signer added: ${o} (${ids.size} key${ids.size === 1 ? '' : 's'})`);
    else {
      const added = [...ids].filter((i) => !was.has(i)).length;
      const removed = [...was].filter((i) => !ids.has(i)).length;
      if (added) out.push(`${o}: ${added} key${added === 1 ? '' : 's'} added`);
      if (removed) out.push(`${o}: ${removed} key${removed === 1 ? '' : 's'} removed`);
    }
  }
  for (const o of curOwners.keys()) if (!nextOwners.has(o)) out.push(`Signer removed: ${o}`);
  for (const r of next.recovery) if (!cur.recovery.includes(r)) out.push(`Recovery key added: ${r}`);
  for (const r of cur.recovery) if (!next.recovery.includes(r)) out.push(`Recovery key removed: ${r}`);
  if (cur.rpId !== next.rpId) out.push(`RP ID: ${cur.rpId} → ${next.rpId}`);
  if (cur.origins.join(',') !== next.origins.join(',')) out.push(`Origins: ${cur.origins.join(', ')} → ${next.origins.join(', ')}`);
  if (out.length === 1) out.push('No policy, signer or recovery changes.');
  return out;
}
