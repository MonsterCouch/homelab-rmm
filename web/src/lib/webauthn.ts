// WebAuthn and WebCrypto helpers for Phase 3 (operator-signed actions,
// docs/plans/2026-10-06-phase3-signed-actions.md §3.2 and §4.1).
//
// Native browser APIs only. Every binary value on the wire is unpadded
// base64url. A security key never signs a "message": it signs
// authenticatorData || SHA-256(clientDataJSON), and clientDataJSON carries
// the challenge. We make the challenge SHA-256 of the document being
// approved (a manifest or a trust bundle), so the assertion binds the exact
// bytes and nothing the server re-serializes can be swapped in afterwards.

/** A byte array the DOM accepts as a BufferSource. */
export type Bytes = Uint8Array<ArrayBuffer>;

/** One WebAuthn assertion used as a signature (protocol.Assertion on the Go side). */
export interface Assertion {
  /** credential ID */
  cred: string;
  /** authenticatorData */
  ad: string;
  /** clientDataJSON */
  cd: string;
  /** signature */
  sig: string;
}

// ---------- base64url ----------

export function b64urlEncode(data: ArrayBuffer | Uint8Array): string {
  const u = data instanceof Uint8Array ? data : new Uint8Array(data);
  let s = '';
  // chunked: String.fromCharCode(...bigArray) overflows the call stack
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decode base64url (padded or not, and tolerant of plain base64). Throws on garbage. */
export function b64urlDecode(s: string): Bytes {
  const t = s.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
  const bin = atob(t + '='.repeat((4 - (t.length % 4)) % 4));
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function utf8(s: string): Bytes {
  const e = new TextEncoder().encode(s);
  const out = new Uint8Array(new ArrayBuffer(e.length));
  out.set(e);
  return out;
}

export function hex(data: ArrayBuffer | Uint8Array): string {
  const u = data instanceof Uint8Array ? data : new Uint8Array(data);
  return Array.from(u, (b) => b.toString(16).padStart(2, '0')).join('');
}

export async function sha256(data: BufferSource): Promise<Bytes> {
  const d = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(d);
}

export async function sha256Hex(data: BufferSource): Promise<string> {
  return hex(await sha256(data));
}

// ---------- availability ----------

export type Usable = { ok: true } | { ok: false; reason: string };

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * Security keys only work when the console is reached by a DNS name over a
 * trusted HTTPS origin: the RP ID is a registrable domain, never an IP
 * address, and browsers expose navigator.credentials only to secure contexts.
 */
export function isWebAuthnUsable(): Usable {
  if (typeof window === 'undefined' || typeof PublicKeyCredential === 'undefined' || !navigator.credentials) {
    return { ok: false, reason: 'This browser does not support WebAuthn security keys.' };
  }
  if (!window.isSecureContext) {
    return {
      ok: false,
      reason: 'Security keys need a secure page. Open the console over HTTPS with a certificate your browser trusts (a self-signed certificate must be trusted on this machine first).',
    };
  }
  const h = location.hostname;
  if (IPV4.test(h) || h.includes(':') || h.startsWith('[')) {
    return { ok: false, reason: 'Security keys need the console to be reached by a DNS name, not an IP address.' };
  }
  return { ok: true };
}

/** A readable message for the DOMExceptions navigator.credentials throws. */
export function webauthnErrorMessage(err: unknown): string {
  if (err instanceof DOMException) {
    switch (err.name) {
      case 'NotAllowedError':
        return 'The request was cancelled, timed out, or no matching security key was presented.';
      case 'InvalidStateError':
        return 'This security key is already registered.';
      case 'SecurityError':
        return `The browser refused the request for this address (${location.hostname}). The console must be opened by the same DNS name the server was configured with.`;
      case 'NotSupportedError':
        return 'This security key does not support a signature algorithm the server accepts.';
      case 'AbortError':
        return 'The request was cancelled.';
      default:
        return err.message || err.name;
    }
  }
  return err instanceof Error ? err.message : 'security key request failed';
}

// ---------- registration ----------

/** PublicKeyCredentialCreationOptions as JSON (binary fields base64url). */
export interface CreationOptionsJSON {
  challenge: string;
  rp: { id?: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  attestation?: AttestationConveyancePreference;
  excludeCredentials?: { id: string; type?: PublicKeyCredentialType; transports?: AuthenticatorTransport[] }[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
}

/** Body of POST /api/webauthn/register/finish (minus the user-chosen name). */
export interface RegistrationResult {
  id: string;
  clientDataJSON: string;
  authenticatorData: string;
  /** SPKI DER from response.getPublicKey() */
  publicKey: string;
  publicKeyAlgorithm: number;
}

export async function register(options: CreationOptionsJSON | { publicKey: CreationOptionsJSON }): Promise<RegistrationResult> {
  const o = 'publicKey' in options ? options.publicKey : options;
  const publicKey: PublicKeyCredentialCreationOptions = {
    challenge: b64urlDecode(o.challenge),
    rp: o.rp,
    user: { id: b64urlDecode(o.user.id), name: o.user.name, displayName: o.user.displayName },
    pubKeyCredParams: o.pubKeyCredParams,
    timeout: o.timeout ?? 120_000,
    attestation: o.attestation ?? 'none',
    authenticatorSelection: o.authenticatorSelection,
    excludeCredentials: (o.excludeCredentials ?? []).map((c) => ({
      type: 'public-key' as const,
      id: b64urlDecode(c.id),
      transports: c.transports,
    })),
  };
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error('no credential was created');
  const r = cred.response as AuthenticatorAttestationResponse;
  const spki = r.getPublicKey?.();
  const alg = r.getPublicKeyAlgorithm?.();
  if (!spki || typeof alg !== 'number') {
    throw new Error('this browser does not expose the new key\'s public key (getPublicKey); update the browser and try again');
  }
  return {
    id: b64urlEncode(cred.rawId),
    clientDataJSON: b64urlEncode(r.clientDataJSON),
    authenticatorData: b64urlEncode(r.getAuthenticatorData()),
    publicKey: b64urlEncode(spki),
    publicKeyAlgorithm: alg,
  };
}

// ---------- signing ----------

export interface SignOptions {
  /** RP ID for get(); the server's trust data gives one, else the page's hostname. */
  rpId?: string;
  /** base64url credential IDs the user may sign with; omit for any (discoverable) credential */
  allowCredentials?: string[];
  userVerification?: UserVerificationRequirement;
  timeoutMs?: number;
}

/**
 * Sign the exact bytes of a document: challenge = SHA-256(doc). Returns the
 * assertion the agent and the server verify against the pinned trust bundle.
 */
export async function signDocument(doc: Uint8Array, opts: SignOptions = {}): Promise<Assertion> {
  const copy = new Uint8Array(new ArrayBuffer(doc.length));
  copy.set(doc);
  const challenge = await sha256(copy);
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge,
    rpId: opts.rpId || location.hostname,
    userVerification: opts.userVerification ?? 'preferred',
    timeout: opts.timeoutMs ?? 120_000,
  };
  if (opts.allowCredentials?.length) {
    publicKey.allowCredentials = opts.allowCredentials.map((id) => ({ type: 'public-key' as const, id: b64urlDecode(id) }));
  }
  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error('no assertion was produced');
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    cred: b64urlEncode(cred.rawId),
    ad: b64urlEncode(r.authenticatorData),
    cd: b64urlEncode(r.clientDataJSON),
    sig: b64urlEncode(r.signature),
  };
}

// ---------- recovery key (Ed25519 via WebCrypto) ----------

export const RECOVERY_PREFIX = 'rmm-recovery-v1:';

export interface RecoveryKey {
  /** "recovery-" + first 12 hex chars of SHA-256(public key) */
  id: string;
  /** base64url raw 32-byte public key: the only part that is ever sent to the server */
  pub: string;
  /** "rmm-recovery-v1:" + base64url(32-byte seed). Shown once, never sent anywhere. */
  secret: string;
}

/** True when this browser's WebCrypto can generate Ed25519 keys. */
export async function ed25519Supported(): Promise<boolean> {
  try {
    await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
    return true;
  } catch {
    return false;
  }
}

export async function generateRecoveryKey(): Promise<RecoveryKey> {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const pub = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  if (pub.length !== 32 || pkcs8.length < 32) throw new Error('unexpected Ed25519 key encoding');
  // PKCS#8 for Ed25519 ends with the 32-byte seed (RFC 8410 CurvePrivateKey).
  const seed = pkcs8.slice(pkcs8.length - 32);
  const id = `recovery-${(await sha256Hex(pub)).slice(0, 12)}`;
  const secret = RECOVERY_PREFIX + b64urlEncode(seed);
  seed.fill(0);
  pkcs8.fill(0);
  return { id, pub: b64urlEncode(pub), secret };
}
