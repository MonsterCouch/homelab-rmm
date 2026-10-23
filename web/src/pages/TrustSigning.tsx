import { useMemo, useState } from 'react';
import { api } from '../api/client';
import type { TrustCurrent, TrustMode, TrustProposal, TrustProposalInput, WebAuthnCredential } from '../api/types';
import { IconPlus } from '../components/Icons';
import { Modal } from '../components/Modal';
import { Button, Checkbox, Chip, CopyButton, ErrorBox, Field, Loading, Switch } from '../components/ui';
import { useAsync } from '../hooks/useAsync';
import { dateTime } from '../lib/format';
import type { BundleView } from '../lib/manifest';
import { requestSigning, SigningCancelled } from '../lib/signing';
import { b64urlDecode, ed25519Supported, generateRecoveryKey, isWebAuthnUsable, type RecoveryKey } from '../lib/webauthn';
import { useAuth } from '../state/auth';
import { errMsg, useToast } from '../state/toast';
import '../styles/mobile-pages.css';

const ALG: Record<number, string> = { [-7]: 'ES256', [-8]: 'EdDSA', [-257]: 'RS256' };

function modeOf(c: TrustCurrent): TrustMode {
  return c.mode ?? c.policy?.mode ?? 'off';
}

function modeTone(m: string): 'danger' | 'warn' | '' {
  return m === 'enforce' ? 'danger' : m === 'audit' ? 'warn' : '';
}

function credIds(s: { creds?: { id: string }[]; credential_ids?: string[] }): string[] {
  return s.credential_ids ?? (s.creds ?? []).map((c) => c.id);
}

/** The live bundle as the same shape the signing dialog decodes a proposal into, so it can show a diff. */
function currentView(c: TrustCurrent, org: string): BundleView {
  return {
    epoch: c.epoch,
    prev: '',
    org,
    rpId: c.rp_id ?? '',
    origins: c.origins ?? [],
    signers: (c.signers ?? []).map((s) => ({ owner: s.owner, creds: credIds(s).map((id) => ({ id, alg: 0 })) })),
    recovery: c.recovery_ids ?? [],
    mode: modeOf(c),
    requireUV: c.policy?.require_uv === true,
    highThreshold: c.policy?.high_threshold ?? 1,
    bundleThreshold: c.policy?.bundle_threshold ?? 1,
    bulkLimit: c.policy?.bulk_limit ?? 10,
  };
}

function download(name: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function TrustSigning() {
  const toast = useToast();
  const { user } = useAuth();
  const orgs = useAsync(() => api.organizations(), []);
  const [orgId, setOrgId] = useState('org_default');
  const trust = useAsync(() => api.trust(orgId), [orgId]);
  const creds = useAsync(() => api.webauthnCredentials(), []);
  const [editing, setEditing] = useState(false);
  const [recovering, setRecovering] = useState<TrustProposal | null>(null);
  const [signing, setSigning] = useState<string | null>(null);
  const usable = isWebAuthnUsable();

  const cur = trust.data?.current ?? null;
  const proposals = trust.data?.proposals ?? [];
  const orgName = (orgs.data ?? []).find((o) => o.id === orgId)?.name ?? orgId;

  const signProposal = async (p: TrustProposal) => {
    setSigning(p.id);
    try {
      const full = p.bundle ? p : await api.trustProposal(p.id);
      if (!full.bundle) throw new Error('the server did not return the bundle bytes for this proposal');
      // Your keys, narrowed to the ones the live bundle trusts (any of yours for the first bundle).
      const mine = (creds.data ?? []).filter((c) => c.owner === user?.username && (!cur || c.in_bundle)).map((c) => c.id);
      const d = await requestSigning({
        docKind: 'bundle',
        doc: full.bundle,
        required: true,
        title: `Sign trust bundle epoch ${full.epoch}`,
        rpId: cur?.rp_id,
        allowCredentials: mine.length ? mine : undefined,
        userVerification: cur?.policy?.require_uv ? 'required' : undefined,
        currentBundle: cur ? currentView(cur, orgId) : null,
      });
      if (d.kind !== 'sign') return;
      const r = await api.signTrustProposal(p.id, d.assertion);
      if (r.active) toast.success('Trust bundle active', `Epoch ${p.epoch} is live and is being pushed to online devices.`);
      else toast.success('Signature added', `${r.have} of ${r.need} signatures.`);
      void trust.reload();
    } catch (err) {
      if (err instanceof SigningCancelled) return;
      toast.error('Signing failed', errMsg(err));
    } finally {
      setSigning(null);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Trust &amp; signing</h1>
          <p className="muted small" style={{ margin: 0 }}>
            Which security keys may authorize actions on an organization&apos;s devices, and whether devices enforce it.
          </p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <select value={orgId} onChange={(e) => setOrgId(e.target.value)} aria-label="Organization">
            {(orgs.data ?? [{ id: 'org_default', name: 'Default', device_count: 0, site_count: 0, created_at: 0 }]).map((o) => (
              <option key={o.id} value={o.id}>
                {o.name}
              </option>
            ))}
          </select>
          <Button variant="primary" onClick={() => setEditing(true)} disabled={!trust.data}>
            <IconPlus /> New proposal
          </Button>
        </div>
      </div>

      {!usable.ok && (
        <div className="banner warn" role="alert" style={{ marginBottom: 12 }}>
          {usable.reason}
        </div>
      )}
      {trust.error && <ErrorBox error={trust.error} onRetry={trust.reload} />}
      {!trust.data && !trust.error && <Loading />}

      {trust.data && (
        <div className="grid cols-2" style={{ alignItems: 'start', gap: 16 }}>
          <div className="card">
            <div className="card-head">
              Current bundle — {orgName}
              <div className="actions">{cur ? <Chip tone={modeTone(modeOf(cur))}>{modeOf(cur)}</Chip> : <Chip>none</Chip>}</div>
            </div>
            <div className="card-body">
              {!cur ? (
                <p className="muted" style={{ margin: 0 }}>
                  No trust bundle yet, so nothing is checked and actions behave as before. Create the first bundle with a proposal: add your keys as signers, start in
                  <b> audit</b> mode to see which paths are still unsigned, and move to enforce later.
                </p>
              ) : (
                <dl className="kv">
                  <dt>Epoch</dt>
                  <dd>{cur.epoch}</dd>
                  <dt>Hash</dt>
                  <dd className="mono small" style={{ wordBreak: 'break-all' }}>
                    {cur.hash}
                  </dd>
                  <dt>RP ID</dt>
                  <dd className="mono">{cur.rp_id || '—'}</dd>
                  <dt>Origins</dt>
                  <dd className="mono small">{(cur.origins ?? []).join(', ') || '—'}</dd>
                  <dt>Policy</dt>
                  <dd>
                    user verification {cur.policy?.require_uv ? 'required' : 'not required'}
                    <br />
                    high-risk actions need {cur.policy?.high_threshold ?? 1} signer(s) · bundle changes need {cur.policy?.bundle_threshold ?? 1} · bulk over{' '}
                    {cur.policy?.bulk_limit ?? 10} devices
                  </dd>
                  <dt>Signers</dt>
                  <dd>
                    {(cur.signers ?? []).length
                      ? (cur.signers ?? []).map((s) => (
                          <div key={s.owner}>
                            {s.owner} <span className="muted small">({credIds(s).length} key{credIds(s).length === 1 ? '' : 's'})</span>
                          </div>
                        ))
                      : 'none'}
                  </dd>
                  <dt>Recovery keys</dt>
                  <dd className="mono small">{(cur.recovery_ids ?? []).join(', ') || <span className="muted">none</span>}</dd>
                </dl>
              )}
            </div>
          </div>

          <div className="stack" style={{ gap: 16 }}>
            <div className="card">
              <div className="card-head">Devices</div>
              <div className="card-body">
                <div className="row" style={{ gap: 8 }}>
                  <Chip tone="ok">{trust.data.agents.at_current} on current</Chip>
                  <Chip tone={trust.data.agents.behind ? 'warn' : ''}>{trust.data.agents.behind} behind</Chip>
                  <Chip tone={trust.data.agents.mismatched ? 'danger' : ''}>{trust.data.agents.mismatched} mismatched</Chip>
                  <Chip>{trust.data.agents.none} no bundle</Chip>
                </div>
                {trust.data.agents.mismatched > 0 && (
                  <div className="banner danger" role="alert" style={{ marginTop: 10 }}>
                    {trust.data.agents.mismatched} device(s) hold a bundle that does not match this organization&apos;s history. Investigate before trusting them.
                  </div>
                )}
                <p className="muted small" style={{ marginBottom: 0 }}>
                  &quot;Behind&quot; devices receive the missing epochs when they connect. &quot;No bundle&quot; devices accept the first bundle sent over their authenticated connection.
                </p>
              </div>
            </div>

            <div className="card">
              <div className="card-head">Open proposals</div>
              <div className="card-body">
                {!proposals.length && <p className="muted small" style={{ margin: 0 }}>No proposals are waiting for signatures.</p>}
                {proposals.map((p) => (
                  <div key={p.id} className="row" style={{ justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                    <div>
                      <b>Epoch {p.epoch}</b> <Chip tone={p.have >= p.need ? 'ok' : 'info'}>{p.have} / {p.need} signed</Chip>
                      <div className="muted small">
                        {p.created_by ? `by ${p.created_by} · ` : ''}
                        {p.created_at ? dateTime(p.created_at) : ''}
                      </div>
                    </div>
                    <div className="row" style={{ gap: 6 }}>
                      <Button size="sm" variant="primary" busy={signing === p.id} onClick={() => signProposal(p)} disabled={!usable.ok}>
                        Review &amp; sign
                      </Button>
                      <Button size="sm" onClick={() => setRecovering(p)}>
                        Recovery…
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {editing && trust.data && (
        <ProposalEditor
          orgId={orgId}
          cur={cur}
          creds={creds.data ?? []}
          onClose={() => setEditing(false)}
          onCreated={(p) => {
            setEditing(false);
            void trust.reload();
            void signProposal(p);
          }}
        />
      )}
      {recovering && (
        <RecoveryModal
          proposal={recovering}
          onClose={() => setRecovering(null)}
          onDone={() => {
            setRecovering(null);
            void trust.reload();
          }}
        />
      )}
    </>
  );
}

// ---------- proposal editor ----------

function ProposalEditor({
  orgId,
  cur,
  creds,
  onClose,
  onCreated,
}: {
  orgId: string;
  cur: TrustCurrent | null;
  creds: WebAuthnCredential[];
  onClose: () => void;
  onCreated: (p: TrustProposal) => void;
}) {
  const toast = useToast();
  const { user } = useAuth();
  const [mode, setMode] = useState<TrustMode>(cur ? modeOf(cur) : 'audit');
  const [requireUV, setRequireUV] = useState(cur?.policy?.require_uv === true);
  const [high, setHigh] = useState(cur?.policy?.high_threshold ?? 1);
  const [bundleT, setBundleT] = useState(cur?.policy?.bundle_threshold ?? 1);
  const [bulk, setBulk] = useState(cur?.policy?.bulk_limit ?? 10);
  // Start from who is trusted now; for the very first bundle, from your own keys.
  const [chosen, setChosen] = useState<Set<string>>(() => {
    if (cur) return new Set((cur.signers ?? []).flatMap(credIds));
    return new Set(creds.filter((c) => c.owner === user?.username).map((c) => c.id));
  });
  const [keys, setKeys] = useState<{ key: RecoveryKey; stored: boolean }[]>([]);
  const [understood, setUnderstood] = useState(false);
  const [busy, setBusy] = useState(false);
  const [edSupport, setEdSupport] = useState<boolean | null>(null);
  const [genBusy, setGenBusy] = useState(false);

  const byOwner = useMemo(() => {
    const m = new Map<string, WebAuthnCredential[]>();
    for (const c of creds) m.set(c.owner, [...(m.get(c.owner) ?? []), c]);
    return [...m.entries()];
  }, [creds]);

  const owners = useMemo(() => {
    const s = new Set<string>();
    for (const c of creds) if (chosen.has(c.id)) s.add(c.owner);
    return s;
  }, [creds, chosen]);

  const recoveryCount = (cur?.recovery_ids ?? []).length + keys.length;

  const toggle = (id: string, on: boolean) =>
    setChosen((prev) => {
      const n = new Set(prev);
      if (on) n.add(id);
      else n.delete(id);
      return n;
    });

  const generate = async () => {
    setGenBusy(true);
    try {
      if (edSupport === null) setEdSupport(await ed25519Supported());
      const key = await generateRecoveryKey();
      setKeys((k) => [...k, { key, stored: false }]);
      setEdSupport(true);
    } catch {
      setEdSupport(false);
    } finally {
      setGenBusy(false);
    }
  };

  const problem = (() => {
    if (mode !== 'off' && owners.size === 0) return 'Choose at least one signer key.';
    for (const [label, v] of [['High-risk threshold', high], ['Bundle-change threshold', bundleT]] as const) {
      if (!Number.isInteger(v) || v < 1) return `${label} must be at least 1.`;
      if (mode !== 'off' && v > owners.size) return `${label} (${v}) is more than the number of distinct signers chosen (${owners.size}); nobody could ever meet it.`;
    }
    if (!Number.isInteger(bulk) || bulk < 1) return 'Bulk limit must be at least 1.';
    if (mode === 'enforce' && recoveryCount === 0) return 'Enforce needs a recovery key in the bundle. Generate one below.';
    if (mode === 'enforce' && !understood) return 'Confirm that you understand what enforce mode does.';
    if (keys.some((k) => !k.stored)) return 'Confirm that you have stored each new recovery key offline.';
    return '';
  })();

  const submit = async () => {
    const byId = new Map(creds.map((c) => [c.id, c]));
    const signers: TrustProposalInput['signers'] = [];
    for (const [owner, list] of byOwner) {
      const ids = list.filter((c) => chosen.has(c.id) && byId.has(c.id)).map((c) => c.id);
      if (ids.length) signers.push({ owner, credential_ids: ids });
    }
    const body: TrustProposalInput = {
      mode,
      require_uv: requireUV,
      high_threshold: high,
      bundle_threshold: bundleT,
      bulk_limit: bulk,
      signers,
      // Only the public half leaves the browser.
      recovery: keys.map((k) => ({ id: k.key.id, pub: k.key.pub })),
    };
    setBusy(true);
    try {
      const p = await api.createTrustProposal(orgId, body);
      toast.success('Proposal created', 'Review the bundle and sign it with your security key.');
      onCreated(p);
    } catch (err) {
      toast.error('Proposal refused', errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title={cur ? `New proposal — epoch ${cur.epoch + 1}` : 'First trust bundle'}
      size="lg"
      onClose={busy ? () => undefined : onClose}
      footer={
        <>
          {problem && <span className="muted small" style={{ marginRight: 'auto', maxWidth: 420 }}>{problem}</span>}
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={submit} busy={busy} disabled={!!problem}>
            Create proposal
          </Button>
        </>
      }
    >
      <div className="stack" style={{ gap: 14 }}>
        <Field label="Mode" htmlFor="tp-mode">
          <select id="tp-mode" value={mode} onChange={(e) => setMode(e.target.value as TrustMode)}>
            <option value="off">off — bundle is kept but nothing is checked</option>
            <option value="audit">audit — devices verify and report, but still run unsigned actions</option>
            <option value="enforce">enforce — devices refuse anything not signed</option>
          </select>
        </Field>
        {mode === 'enforce' && (
          <div className="banner danger" role="alert" style={{ alignItems: 'flex-start', flexDirection: 'column' }}>
            <div>
              <b>Enforce mode.</b> Devices reject every protected action, shell, remote desktop and update that is not signed by a key in this bundle. Scheduled tasks,
              automations, patch policies and catalog items stop running until they carry a signed approval (Approvals → Review &amp; sign). Lose every key and the
              recovery key and you cannot change anything again. Run in audit first.
            </div>
            <Checkbox checked={understood} onChange={setUnderstood} label="I understand and have checked the Review & sign list" />
          </div>
        )}
        <div className="grid cols-2" style={{ gap: 12 }}>
          <Field label="High-risk signers needed" htmlFor="tp-high" hint="Agent updates and bulk actions.">
            <input id="tp-high" type="number" min={1} value={high} onChange={(e) => setHigh(Number(e.target.value))} />
          </Field>
          <Field label="Bundle-change signers needed" htmlFor="tp-bundle" hint="Distinct people who must sign a new bundle.">
            <input id="tp-bundle" type="number" min={1} value={bundleT} onChange={(e) => setBundleT(Number(e.target.value))} />
          </Field>
          <Field label="Bulk limit" htmlFor="tp-bulk" hint="Actions on more devices than this count as high-risk.">
            <input id="tp-bulk" type="number" min={1} value={bulk} onChange={(e) => setBulk(Number(e.target.value))} />
          </Field>
          <Field label="User verification">
            <Switch checked={requireUV} onChange={setRequireUV} label="Require PIN or biometric on every signature" />
          </Field>
        </div>

        <div>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>Signers</div>
          {!creds.length && <p className="muted small">No security keys are registered yet. Register one on the Account page first.</p>}
          {byOwner.map(([owner, list]) => (
            <div key={owner} style={{ marginBottom: 6 }}>
              <div className="muted small">{owner}</div>
              {list.map((c) => (
                <div key={c.id}>
                  <Checkbox checked={chosen.has(c.id)} onChange={(v) => toggle(c.id, v)} label={`${c.name} (${ALG[c.alg] ?? c.alg})${c.in_bundle ? ' · in bundle' : ''}`} />
                </div>
              ))}
            </div>
          ))}
          <p className="muted small" style={{ marginBottom: 0 }}>
            Thresholds count distinct people, not keys. Give each person two keys so losing one does not lock them out.
          </p>
        </div>

        <div>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>Recovery keys</div>
          <p className="muted small" style={{ marginTop: 0 }}>
            An offline Ed25519 key that can sign a bundle when every security key is lost. It is generated here, shown once, and never sent to the server — only its public half is.
            Existing: {(cur?.recovery_ids ?? []).join(', ') || 'none'}.
          </p>
          {edSupport === false && (
            <div className="banner warn" role="alert" style={{ marginBottom: 8 }}>
              This browser cannot generate Ed25519 keys with WebCrypto. A command-line way to generate a recovery key is not available yet, so use a current Chrome, Edge,
              Firefox or Safari for this step.
            </div>
          )}
          {keys.map((k, i) => (
            <RecoveryKeyCard
              key={k.key.id}
              k={k.key}
              stored={k.stored}
              onStored={(v) => setKeys((all) => all.map((x, j) => (j === i ? { ...x, stored: v } : x)))}
              onDiscard={() => setKeys((all) => all.filter((_, j) => j !== i))}
            />
          ))}
          <Button onClick={generate} busy={genBusy}>
            Generate recovery key
          </Button>
        </div>
      </div>
    </Modal>
  );
}

function RecoveryKeyCard({ k, stored, onStored, onDiscard }: { k: RecoveryKey; stored: boolean; onStored: (v: boolean) => void; onDiscard: () => void }) {
  return (
    <div className="banner warn" style={{ flexDirection: 'column', alignItems: 'stretch', marginBottom: 8 }} role="group" aria-label={`Recovery key ${k.id}`}>
      <div>
        <b>{k.id}</b> — this is the only time the secret is shown. Store it offline (printed, or on a drive that stays in a safe).
      </div>
      <div className="code-block" style={{ color: 'var(--text)' }}>
        {k.secret}
      </div>
      <div className="row" style={{ gap: 8 }}>
        <CopyButton text={k.secret} label="Copy" />
        <Button size="sm" onClick={() => download(`rmm-${k.id}.txt`, `${k.secret}\n`)}>
          Download
        </Button>
        <Button size="sm" variant="ghost" onClick={onDiscard} style={{ marginLeft: 'auto' }}>
          Discard
        </Button>
      </div>
      <Checkbox checked={stored} onChange={onStored} label="I have stored this offline" />
    </div>
  );
}

// ---------- offline recovery signing ----------

function RecoveryModal({ proposal, onClose, onDone }: { proposal: TrustProposal; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const full = useAsync(async () => (proposal.bundle ? proposal : api.trustProposal(proposal.id)), [proposal.id]);
  const [paste, setPaste] = useState('');
  const [busy, setBusy] = useState(false);
  const bundle = full.data?.bundle ?? '';

  const parsed = useMemo(() => {
    if (!paste.trim()) return { ok: false as const, error: '' };
    try {
      const v: unknown = JSON.parse(paste);
      const o = (v ?? {}) as { id?: unknown; sig?: unknown };
      if (typeof o.id !== 'string' || !o.id || typeof o.sig !== 'string' || !o.sig) return { ok: false as const, error: 'Expected JSON like {"id": "...", "sig": "..."}.' };
      return { ok: true as const, id: o.id, sig: o.sig };
    } catch {
      return { ok: false as const, error: 'That is not valid JSON.' };
    }
  }, [paste]);

  const submit = async () => {
    if (!parsed.ok) return;
    setBusy(true);
    try {
      const r = await api.recoverTrustProposal(proposal.id, { id: parsed.id, sig: parsed.sig });
      if (r.active) toast.success('Trust bundle active', 'Signed with the recovery key.');
      else toast.success('Recovery signature added');
      onDone();
    } catch (err) {
      toast.error('Recovery signature refused', errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title={`Offline recovery signing — epoch ${proposal.epoch}`}
      size="lg"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Close</Button>
          <Button variant="primary" onClick={submit} busy={busy} disabled={!parsed.ok}>
            Submit recovery signature
          </Button>
        </>
      }
    >
      <div className="stack" style={{ gap: 12 }}>
        <p className="muted" style={{ margin: 0 }}>
          Use this only when no security key in the current bundle can sign. On a machine that holds the recovery key, run
          <code> rmm-server trust sign-bundle --recovery-key FILE</code> (see its help for how to pass the bundle) on the bundle below, then paste the JSON it prints.
        </p>
        {full.error && <ErrorBox error={full.error} onRetry={full.reload} />}
        {full.loading && !bundle && <Loading />}
        {bundle && (
          <Field label="Bundle (base64url)">
            <textarea readOnly rows={5} value={bundle} className="mono small" onFocus={(e) => e.currentTarget.select()} />
            <div className="row" style={{ gap: 8, marginTop: 6 }}>
              <CopyButton text={bundle} label="Copy" />
              <Button size="sm" onClick={() => download(`trust-bundle-epoch-${proposal.epoch}.txt`, `${bundle}\n`)}>
                Download
              </Button>
              <Button
                size="sm"
                onClick={() => download(`trust-bundle-epoch-${proposal.epoch}.json`, new TextDecoder().decode(b64urlDecode(bundle)))}
                title="The decoded bundle bytes, exactly as they are signed"
              >
                Download decoded
              </Button>
            </div>
          </Field>
        )}
        <Field label="Signature from rmm-server" htmlFor="rec-paste" error={parsed.ok ? null : parsed.error || null}>
          <textarea id="rec-paste" rows={3} value={paste} className="mono small" placeholder='{"id":"recovery-…","sig":"…"}' onChange={(e) => setPaste(e.target.value)} />
        </Field>
      </div>
    </Modal>
  );
}
