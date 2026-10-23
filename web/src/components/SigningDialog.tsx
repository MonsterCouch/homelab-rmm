import { useEffect, useMemo, useState, useSyncExternalStore } from 'react';
import { api } from '../api/client';
import { useAsync } from '../hooks/useAsync';
import { dateTime, relTime } from '../lib/format';
import { decodeBundle, decodeManifest, diffBundle, type BundleView, type ManifestView } from '../lib/manifest';
import { settle, SigningCancelled, signingSnapshot, subscribeSigning, type QueuedSigning } from '../lib/signing';
import { isWebAuthnUsable, sha256Hex, signDocument, utf8, webauthnErrorMessage } from '../lib/webauthn';
import { Modal } from './Modal';
import { Button, Chip } from './ui';

/**
 * Renders the head of the signing queue (lib/signing.ts). Mounted once, next
 * to the other global dialogs, so request() can ask for a signature from any
 * page without importing UI.
 */
export function SigningHost() {
  const queue = useSyncExternalStore(subscribeSigning, signingSnapshot);
  const head = queue[0];
  if (!head) return null;
  // key: a second request must not inherit the first one's busy/error state
  return <SigningModal key={head.id} item={head} waiting={queue.length - 1} />;
}

type Decoded =
  | { kind: 'manifest'; bytes: Uint8Array<ArrayBuffer>; m: ManifestView }
  | { kind: 'bundle'; bytes: Uint8Array<ArrayBuffer>; b: BundleView; cur: BundleView | null };

function decode(item: QueuedSigning): Decoded {
  const c = item.challenge;
  if (c.docKind === 'bundle') {
    const { bytes, b } = decodeBundle(c.doc);
    const cur = c.currentBundle ?? null;
    return { kind: 'bundle', bytes, b, cur };
  }
  const { bytes, m } = decodeManifest(c.doc);
  return { kind: 'manifest', bytes, m };
}

function SigningModal({ item, waiting }: { item: QueuedSigning; waiting: number }) {
  const c = item.challenge;
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const usable = isWebAuthnUsable();

  const decoded = useMemo(() => {
    try {
      return { ok: true as const, d: decode(item) };
    } catch (e) {
      return { ok: false as const, error: e instanceof Error ? e.message : 'unreadable document' };
    }
  }, [item]);

  const cancel = () => settle(item.id, null, new SigningCancelled());

  const sign = async () => {
    if (!decoded.ok) return;
    setBusy(true);
    setErr(null);
    try {
      const assertion = await signDocument(decoded.d.bytes, {
        rpId: c.rpId,
        allowCredentials: c.allowCredentials,
        userVerification: c.userVerification,
      });
      settle(item.id, { kind: 'sign', assertion });
    } catch (e) {
      // stay open: a key tapped too late or a wrong key is retried here
      setErr(webauthnErrorMessage(e));
      setBusy(false);
    }
  };

  const title = c.title ?? (decoded.ok && decoded.d.kind === 'bundle' ? 'Sign a trust bundle change' : 'Sign this action');
  const canSkip = !c.required && c.docKind === 'manifest';

  return (
    <Modal
      title={title}
      onClose={busy ? () => undefined : cancel}
      size="lg"
      footer={
        <>
          <Button onClick={cancel} disabled={busy}>
            Cancel
          </Button>
          {canSkip && (
            <Button onClick={() => settle(item.id, { kind: 'skip' })} disabled={busy} title="Audit mode: the action runs unsigned and the agent reports it">
              Continue without signing
            </Button>
          )}
          <Button variant="primary" onClick={sign} busy={busy} disabled={!decoded.ok || !usable.ok} data-autofocus="">
            {busy ? 'Touch your security key…' : 'Sign with security key'}
          </Button>
        </>
      }
    >
      <div className="stack" style={{ gap: 12 }}>
        {!usable.ok && (
          <div className="banner danger" role="alert">
            {usable.reason}
          </div>
        )}
        {err && (
          <div className="banner danger" role="alert">
            {err}
          </div>
        )}
        {!decoded.ok && (
          <div className="banner danger" role="alert">
            This console could not read what the server wants signed ({decoded.error}). It will not sign something it cannot show you.
          </div>
        )}
        {c.summary && (
          <div>
            <div className="muted small">The server describes this as (its own words, not checked):</div>
            <div style={{ fontWeight: 600 }}>{c.summary}</div>
          </div>
        )}
        {decoded.ok && (
          <>
            <div className="muted small">What this console decoded from the exact bytes your key will sign:</div>
            {decoded.d.kind === 'manifest' ? <ManifestDetails m={decoded.d.m} bytes={decoded.d.bytes} /> : <BundleDetails b={decoded.d.b} cur={decoded.d.cur} bytes={decoded.d.bytes} />}
            <div className="banner info" role="note">
              <b>Your security key will sign exactly this.</b>
            </div>
          </>
        )}
        {!c.required && c.docKind === 'manifest' && (
          <p className="muted small" style={{ margin: 0 }}>
            This organization is in audit mode: you may continue without signing. The action will run, but the device reports it as unsigned.
          </p>
        )}
        <p className="muted small" style={{ margin: 0 }}>
          A security key does not display what it signs, so the text above is what you are trusting. If it does not match what you meant to do, cancel.
          {waiting > 0 ? ` ${waiting} more request${waiting === 1 ? ' is' : 's are'} waiting after this one.` : ''}
        </p>
      </div>
    </Modal>
  );
}

// ---------- manifest ----------

function expiryText(exp: number): string {
  return exp ? `${dateTime(exp)} (${relTime(exp)})` : '—';
}

function ManifestDetails({ m, bytes }: { m: ManifestView; bytes: Uint8Array<ArrayBuffer> }) {
  const [fp, setFp] = useState('');
  useEffect(() => {
    let live = true;
    void sha256Hex(bytes).then((h) => live && setFp(h));
    return () => {
      live = false;
    };
  }, [bytes]);

  const everyDevice = m.targets.length === 1 && m.targets[0] === '*';
  const agents = useAsync(() => api.agents(), [], { enabled: m.targets.length > 0 && !everyDevice });
  const names = useMemo(() => {
    const byId = new Map((agents.data ?? []).map((a) => [a.id, a.display_name || a.hostname]));
    return m.targets.map((t) => byId.get(t) ?? t);
  }, [agents.data, m.targets]);

  const ops = m.ops?.length ? m.ops : m.op ? [m.op] : [];
  const isScript = m.op === 'script.run' && !!m.payload;
  const body = isScript && typeof m.payload?.body === 'string' ? m.payload.body : '';
  const [bodyHash, setBodyHash] = useState('');
  useEffect(() => {
    if (!isScript) return;
    let live = true;
    void sha256Hex(utf8(body)).then((h) => live && setBodyHash(h));
    return () => {
      live = false;
    };
  }, [isScript, body]);

  const args = Array.isArray(m.payload?.args) ? (m.payload?.args as unknown[]).map(String) : [];
  const otherPayload = m.payload && !isScript ? JSON.stringify(m.payload, null, 2) : '';

  return (
    <div className="stack" style={{ gap: 10 }}>
      <dl className="kv">
        <dt>Kind</dt>
        <dd>
          <Chip tone={m.kind === 'standing' ? 'warn' : 'accent'}>{m.kind || 'unknown'}</Chip>
          {m.kind === 'grant' && <span className="muted small"> time-boxed access, reusable until it expires</span>}
          {m.kind === 'standing' && <span className="muted small"> reusable approval for unattended runs</span>}
        </dd>
        <dt>{ops.length > 1 ? 'Operations' : 'Operation'}</dt>
        <dd className="mono">{ops.length ? ops.join(', ') : '—'}</dd>
        <dt>Devices</dt>
        <dd>
          {everyDevice ? (
            <b>Every device in the organization, including ones enrolled later</b>
          ) : (
            <>
              <b>{m.targets.length}</b> {m.targets.length === 1 ? 'device' : 'devices'}
              {m.targets.length > 0 && m.targets.length <= 6 && <span> — {names.join(', ')}</span>}
            </>
          )}
        </dd>
        <dt>Organization</dt>
        <dd className="mono">{m.org || '—'}</dd>
        <dt>Expires</dt>
        <dd>{expiryText(m.exp)}</dd>
        {m.issuer && (
          <>
            <dt>Requested by</dt>
            <dd>{m.issuer}</dd>
          </>
        )}
      </dl>
      {isScript && (
        <>
          <dl className="kv">
            <dt>Language</dt>
            <dd className="mono">{String(m.payload?.language ?? '—')}</dd>
            {args.length > 0 && (
              <>
                <dt>Arguments</dt>
                <dd className="mono">{args.join(' ')}</dd>
              </>
            )}
            {typeof m.payload?.timeout_sec === 'number' && (
              <>
                <dt>Timeout</dt>
                <dd>{m.payload.timeout_sec} s</dd>
              </>
            )}
            <dt>Body SHA-256</dt>
            <dd className="mono small" style={{ wordBreak: 'break-all' }}>
              {bodyHash || '…'}
            </dd>
          </dl>
          <div className="code-block" style={{ maxHeight: 240, whiteSpace: 'pre', wordBreak: 'normal' }} tabIndex={0} aria-label="Script body">
            {body || '(empty script)'}
          </div>
        </>
      )}
      {otherPayload && (
        <div>
          <div className="muted small">Payload</div>
          <div className="code-block" style={{ maxHeight: 180, whiteSpace: 'pre', wordBreak: 'normal' }} tabIndex={0}>
            {otherPayload}
          </div>
        </div>
      )}
      {m.constraints && (
        <div>
          <div className="muted small">The approval allows only runs that match</div>
          <div className="code-block" style={{ maxHeight: 180, whiteSpace: 'pre', wordBreak: 'normal' }} tabIndex={0}>
            {JSON.stringify(m.constraints, null, 2)}
          </div>
        </div>
      )}
      <div className="muted small mono" style={{ wordBreak: 'break-all' }}>
        document SHA-256 {fp || '…'}
      </div>
    </div>
  );
}

// ---------- trust bundle ----------

function BundleDetails({ b, cur, bytes }: { b: BundleView; cur: BundleView | null; bytes: Uint8Array<ArrayBuffer> }) {
  const [fp, setFp] = useState('');
  useEffect(() => {
    let live = true;
    void sha256Hex(bytes).then((h) => live && setFp(h));
    return () => {
      live = false;
    };
  }, [bytes]);
  const changes = diffBundle(cur, b);
  return (
    <div className="stack" style={{ gap: 10 }}>
      <div>
        <div className="muted small">Changes</div>
        <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
          {changes.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
      </div>
      {b.mode === 'enforce' && (
        <div className="banner danger" role="note">
          Enforce mode: devices will refuse every protected action that is not signed by a key in this bundle.
        </div>
      )}
      <dl className="kv">
        <dt>Organization</dt>
        <dd className="mono">{b.org}</dd>
        <dt>Epoch</dt>
        <dd>{b.epoch}</dd>
        <dt>Mode</dt>
        <dd>
          <Chip tone={b.mode === 'enforce' ? 'danger' : b.mode === 'audit' ? 'warn' : ''}>{b.mode || 'unset'}</Chip>
        </dd>
        <dt>Policy</dt>
        <dd>
          user verification {b.requireUV ? 'required' : 'not required'} · high-risk needs {b.highThreshold} · bundle change needs {b.bundleThreshold} · bulk over {b.bulkLimit} devices
        </dd>
        <dt>RP ID</dt>
        <dd className="mono">{b.rpId}</dd>
        <dt>Origins</dt>
        <dd className="mono small">{b.origins.join(', ') || '—'}</dd>
        <dt>Signers</dt>
        <dd>
          {b.signers.length
            ? b.signers.map((s) => (
                <div key={s.owner}>
                  {s.owner} <span className="muted small">({s.creds.length} key{s.creds.length === 1 ? '' : 's'})</span>
                </div>
              ))
            : 'none'}
        </dd>
        <dt>Recovery keys</dt>
        <dd className="mono small">{b.recovery.join(', ') || 'none'}</dd>
      </dl>
      <div className="muted small mono" style={{ wordBreak: 'break-all' }}>
        document SHA-256 {fp || '…'}
      </div>
    </div>
  );
}
