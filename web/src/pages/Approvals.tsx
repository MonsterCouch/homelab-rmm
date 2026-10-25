import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { announceParked, api, isPending } from '../api/client';
import type { PendingApproval, UnsignedObject, UnsignedType } from '../api/types';
import { Button, Chip, Empty, ErrorBox, Loading, Tabs } from '../components/ui';
import { useAsync, useInterval } from '../hooks/useAsync';
import { dateTime, relTime } from '../lib/format';
import { decodeManifest } from '../lib/manifest';
import { requestSigning, signerCommand, SigningCancelled } from '../lib/signing';
import { signAll, signAllTone, summarizeSignAll, unitLabel } from '../lib/signAll';
import { isWebAuthnUsable } from '../lib/webauthn';
import { errMsg, useToast } from '../state/toast';
import '../styles/mobile-pages.css';

type Tab = 'pending' | 'review';

const TYPE_LABEL: Record<UnsignedType, string> = {
  task: 'Scheduled task',
  automation: 'Alert automation',
  patch_policy: 'Patch policy',
  catalog_item: 'Software catalog item',
  baseline: 'Baseline',
};

/** One row is one unit: an object in an organization, for one purpose. */
function unitKey(o: UnsignedObject): string {
  return `${o.type}:${o.id}:${o.org}:${o.purpose}`;
}

function objectLink(o: UnsignedObject): string {
  switch (o.type) {
    case 'task':
      return '/tasks';
    case 'automation':
      return '/automations';
    case 'patch_policy':
      return '/patches';
    case 'catalog_item':
      return '/software-catalog';
    case 'baseline':
      return `/baselines/${encodeURIComponent(String(o.id))}`;
  }
}

export function Approvals() {
  const [tab, setTab] = useState<Tab>('pending');
  const usable = isWebAuthnUsable();
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Approvals</h1>
          <p className="muted small" style={{ margin: 0 }}>
            Requests waiting for more signatures, and unattended work (tasks, automations, policies, catalog items) that still needs a signed approval.
          </p>
        </div>
      </div>
      {!usable.ok && (
        <div className="banner warn" role="alert" style={{ marginBottom: 12 }}>
          {usable.reason}
        </div>
      )}
      <Tabs
        tabs={[
          { id: 'pending' as const, label: 'Waiting for signatures' },
          { id: 'review' as const, label: 'Review & sign' },
        ]}
        value={tab}
        onChange={setTab}
      />
      <div style={{ marginTop: 12 }}>{tab === 'pending' ? <PendingTab canSign={usable.ok} /> : <ReviewTab canSign={usable.ok} />}</div>
    </>
  );
}

function PendingTab({ canSign }: { canSign: boolean }) {
  const toast = useToast();
  const list = useAsync(() => api.approvals(), []);
  const [busy, setBusy] = useState<string | null>(null);
  useInterval(() => void list.reload(), 15_000);

  const sign = async (a: PendingApproval) => {
    if (!a.manifest) {
      toast.error('Cannot review this request', 'The server did not include the manifest, and this console will not sign what it cannot show you.');
      return;
    }
    setBusy(a.manifest_id);
    try {
      const d = await requestSigning({ docKind: 'manifest', doc: a.manifest, summary: a.summary, required: true, title: 'Approve a pending request', manifestId: a.manifest_id, rpId: a.rp_id, allowCredentials: a.allow_credentials, userVerification: a.user_verification });
      if (d.kind === 'park') {
        announceParked(a.manifest_id);
        return;
      }
      if (d.kind !== 'sign') return;
      const r = await api.signApproval(a.manifest_id, d.assertion);
      if (isPending(r) || r.have < r.need) toast.success('Signature added', `${r.have} of ${r.need} signatures.`);
      else toast.success('Approved', 'The request had all its signatures and was dispatched.');
      void list.reload();
    } catch (err) {
      if (err instanceof SigningCancelled) return;
      toast.error('Approval failed', errMsg(err));
    } finally {
      setBusy(null);
    }
  };

  const rows = list.data ?? [];
  return (
    <div className="card">
      <div className="card-body" style={{ padding: 0 }}>
        {list.error && <ErrorBox error={list.error} onRetry={list.reload} />}
        {!list.loaded && <Loading />}
        {list.loaded && !rows.length && !list.error && (
          <Empty title="Nothing is waiting">Requests that need more than one signer appear here for the other operators.</Empty>
        )}
        {rows.length > 0 && (
          <div className="table-wrap">
            <table className="tbl compact">
              <thead>
                <tr>
                  <th>Request</th>
                  <th>Requested by</th>
                  <th>Signatures</th>
                  <th>Expires</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => (
                  <tr key={a.manifest_id}>
                    <td className="wrap">
                      <PendingTitle a={a} />
                    </td>
                    <td>{a.issuer || '—'}</td>
                    <td>
                      <Chip tone={a.have >= a.need ? 'ok' : 'info'}>
                        {a.have} / {a.need}
                      </Chip>
                      {a.have === 0 && <div className="muted small">Waiting for your signature, 0 of {a.need}</div>}
                      {a.signers && a.signers.length > 0 && <div className="muted small">signed by {a.signers.join(', ')}</div>}
                    </td>
                    <td className="muted" title={a.expires_at ? dateTime(a.expires_at) : undefined}>
                      {a.expires_at ? relTime(a.expires_at) : '—'}
                    </td>
                    <td>
                      <CopyCommand text={signerCommand(a.manifest_id)} />{' '}
                      <Button size="sm" variant="primary" busy={busy === a.manifest_id} disabled={!canSign} onClick={() => sign(a)}>
                        Review &amp; sign
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function CopyCommand({ text }: { text: string }) {
  const toast = useToast();
  const copy = () => {
    void navigator.clipboard?.writeText(text).then(
      () => toast.success('Command copied', text),
      () => toast.error('Could not copy', 'Select the command and copy it by hand.'),
    );
  };
  return (
    <Button size="sm" onClick={copy} title={text}>
      Copy rmm-signer command
    </Button>
  );
}

/** The server's summary if it sent one, else what this console reads from the manifest. */
function PendingTitle({ a }: { a: PendingApproval }) {
  const own = useMemo(() => {
    if (!a.manifest) return '';
    try {
      const { m } = decodeManifest(a.manifest);
      const what = m.ops?.length ? m.ops.join(', ') : m.op || m.kind;
      return `${what} on ${m.targets.length} device${m.targets.length === 1 ? '' : 's'}`;
    } catch {
      return '';
    }
  }, [a.manifest]);
  return (
    <>
      <b>{a.summary || own || a.manifest_id}</b>
      {a.summary && own && <div className="muted small">decoded: {own}</div>}
    </>
  );
}

function ReviewTab({ canSign }: { canSign: boolean }) {
  const toast = useToast();
  const orgs = useAsync(() => api.organizations(), []);
  const [org, setOrg] = useState('org_default');
  const list = useAsync(() => api.unsignedApprovals(org), [org]);
  const [busy, setBusy] = useState<string | null>(null);
  const [all, setAll] = useState(false);
  const rows = list.data ?? [];

  const sign = async (o: UnsignedObject) => {
    const key = unitKey(o);
    setBusy(key);
    try {
      // The server answers 428 with a standing manifest built from the
      // object's current content; request() shows it and retries.
      // Org and purpose name this row's unit, so the signature covers what the row says.
      const r = await api.signObject(o.type, o.id, { org: o.org, purpose: o.purpose });
      if (isPending(r)) toast.info('Signature added', `"${unitLabel(o)}" is waiting for another approver.`);
      else if (r.already_approved) toast.info('Already approved', `"${unitLabel(o)}" already has a valid approval.`);
      else toast.success('Approved', `"${unitLabel(o)}" may run unattended${r.expires_at ? ` until ${dateTime(r.expires_at)}` : ''}.`);
      void list.reload();
    } catch (err) {
      toast.error('Approval failed', errMsg(err));
    } finally {
      setBusy(null);
    }
  };

  const signEvery = async () => {
    setAll(true);
    try {
      const s = await signAll(rows);
      toast[signAllTone(s)](s.cancelled > 0 ? 'Signing stopped' : 'Approvals', summarizeSignAll(s));
    } finally {
      setAll(false);
      void list.reload();
    }
  };

  return (
    <div className="card">
      <div className="card-head">
        Unattended work without a valid approval
        <div className="actions">
          <Button size="sm" variant="primary" busy={all} disabled={!canSign || busy !== null || rows.length === 0} onClick={signEvery}>
            Sign all
          </Button>
          <select value={org} onChange={(e) => setOrg(e.target.value)} aria-label="Organization">
            {(orgs.data ?? [{ id: 'org_default', name: 'Default' }]).map((o) => (
              <option key={o.id} value={o.id}>
                {o.name}
              </option>
            ))}
          </select>
        </div>
      </div>
      <div className="card-body" style={{ padding: 0 }}>
        <p className="muted small" style={{ margin: 12 }}>
          These run on their own, with nobody present to touch a key. An approval binds the exact script or settings you reviewed; editing the item afterwards
          makes it &quot;content changed&quot; until you sign again. In audit mode they keep running, with warnings, until signed.
        </p>
        {list.error && <ErrorBox error={list.error} onRetry={list.reload} />}
        {!list.loaded && <Loading />}
        {list.loaded && !rows.length && !list.error && <Empty title="Everything is approved">No unattended work is missing a valid approval in this organization.</Empty>}
        {rows.length > 0 && (
          <div className="table-wrap">
            <table className="tbl compact">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Name</th>
                  <th>Status</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((o) => {
                  const key = unitKey(o);
                  return (
                    <tr key={key}>
                      <td>{TYPE_LABEL[o.type] ?? o.type}</td>
                      <td>
                        <Link to={objectLink(o)}>{o.name || String(o.id)}</Link>
                        {o.purpose && <span className="muted small"> ({o.purpose})</span>}
                      </td>
                      <td>
                        <Chip tone={o.reason === 'content changed' ? 'warn' : o.reason === 'expired' ? 'warn' : 'danger'}>{o.reason}</Chip>
                      </td>
                      <td>
                        <Button size="sm" variant="primary" busy={busy === key} disabled={!canSign || all || (busy !== null && busy !== key)} onClick={() => sign(o)}>
                          Review &amp; sign
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
