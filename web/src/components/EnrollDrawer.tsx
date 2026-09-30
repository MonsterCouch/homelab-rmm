import { useState } from 'react';
import { api } from '../api/client';
import type { EnrollCreated, Group } from '../api/types';
import { useAsync } from '../hooks/useAsync';
import { relTime } from '../lib/format';
import { errMsg, useToast } from '../state/toast';
import { useConfirm, Drawer } from './Modal';
import { PairCard } from './PairCard';
import { Button, CopyButton, Field, Skeleton } from './ui';
import { IconDownload, IconTrash } from './Icons';
import '../styles/mobile-pages.css';

export function EnrollDrawer({ onClose, groups }: { onClose: () => void; groups: Group[] }) {
  const toast = useToast();
  const confirm = useConfirm();
  const list = useAsync(() => api.enrollTokens(), []);
  const orgs = useAsync(() => api.organizations(), []);
  const [name, setName] = useState('');
  const [orgId, setOrgId] = useState<string>('org_default');
  const [siteId, setSiteId] = useState<string>('site_default');
  const sites = useAsync(async () => {
    if (!orgId) return [];
    return api.sites(orgId);
  }, [orgId]);

  const [groupId, setGroupId] = useState<string>('');
  const [uses, setUses] = useState(1);
  const [unlimited, setUnlimited] = useState(false);
  const [ttl, setTtl] = useState(24);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<EnrollCreated | null>(null);

  const handleOrgChange = (nextOrgId: string) => {
    setOrgId(nextOrgId);
    setSiteId('');
  };

  const create = async () => {
    setBusy(true);
    try {
      const res = await api.createEnroll({
        name: name.trim(),
        org_id: orgId || undefined,
        site_id: siteId || undefined,
        group_id: groupId ? +groupId : null,
        uses: unlimited ? -1 : Math.max(1, uses),
        ttl_hours: Math.max(1, ttl),
      });
      setCreated(res);
      toast.success('Enrollment token created');
      void list.reload();
    } catch (err) {
      toast.error('Could not create token', errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (id: number, label: string) => {
    if (!(await confirm({ title: 'Delete token', message: `Delete the enrollment token "${label}"? Installs already in progress keep working.`, danger: true, confirmLabel: 'Delete' }))) return;
    try {
      await api.deleteEnroll(id);
      if (created?.id === id) setCreated(null);
      void list.reload();
    } catch (err) {
      toast.error('Delete failed', errMsg(err));
    }
  };

  return (
    <Drawer title="Enroll a device" onClose={onClose} wide>
      <div className="stack" style={{ gap: 16 }}>
        <div className="card">
          <div className="card-head">New enrollment token</div>
          <div className="card-body">
            <div className="form-row">
              <Field label="Name" hint="A label for the audit log, e.g. the device or site.">
                <input value={name} placeholder="workshop-pc" onChange={(e) => setName(e.target.value)} autoFocus />
              </Field>
              <Field label="Group">
                <select value={groupId} onChange={(e) => setGroupId(e.target.value)}>
                  <option value="">No group</option>
                  {groups.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name}
                    </option>
                  ))}
                </select>
              </Field>
            </div>
            <div className="form-row">
              <Field label="Organization / Client" hint="Assign new devices directly into this organization.">
                <select value={orgId} onChange={(e) => handleOrgChange(e.target.value)}>
                  {(orgs.data ?? []).map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.name}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Site / Branch" hint="Branch office or physical location.">
                <select value={siteId} onChange={(e) => setSiteId(e.target.value)}>
                  {(sites.data ?? []).map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </select>
              </Field>
            </div>
            <div className="form-row">
              <Field label="Uses" hint="How many devices may enroll with this token.">
                <div className="row" style={{ flexWrap: 'nowrap' }}>
                  <input type="number" min={1} max={1000} value={uses} disabled={unlimited} onChange={(e) => setUses(+e.target.value || 1)} style={{ width: 100 }} />
                  <label className="row" style={{ gap: 6, whiteSpace: 'nowrap' }}>
                    <input type="checkbox" checked={unlimited} onChange={(e) => setUnlimited(e.target.checked)} /> unlimited
                  </label>
                </div>
              </Field>
              <Field label="Valid for (hours)">
                <input type="number" min={1} max={8760} value={ttl} onChange={(e) => setTtl(+e.target.value || 24)} />
              </Field>
            </div>
            <div className="form-actions">
              <Button variant="primary" onClick={create} busy={busy}>
                Create token
              </Button>
            </div>
          </div>
        </div>

        {created && (
          <div className="card">
            <div className="card-head">Installers & Commands</div>
            <div className="card-body stack">
              <p className="muted small">
                Choose a pre-configured standalone installer or run an elevated one-line command. Pre-configured packages automatically embed this server URL and enrollment token into the installer so no command-line parameters are required on the target endpoint.
              </p>

              <div>
                <div className="field-label mb">Pre-configured Installers (Zero-Touch)</div>
                <div className="row" style={{ gap: 10, flexWrap: 'wrap' }}>
                  <a
                    href={`/install/${created.token}/msi`}
                    download="HomelabRMM-Agent.msi"
                    className="btn"
                    style={{ textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 6 }}
                    data-testid="download-msi"
                  >
                    <IconDownload /> Download Windows Installer (.msi)
                  </a>
                  <a
                    href={`/install/${created.token}/deb`}
                    download="homelab-rmm-agent_amd64.deb"
                    className="btn"
                    style={{ textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 6 }}
                    data-testid="download-deb"
                  >
                    <IconDownload /> Download Linux Package (.deb)
                  </a>
                </div>
              </div>

              <div>
                <div className="field-label mb">Windows (PowerShell as Administrator)</div>
                <div className="code-block" data-testid="enroll-windows">
                  {created.windows}
                  <span className="copy">
                    <CopyButton text={created.windows} />
                  </span>
                </div>
              </div>
              <div>
                <div className="field-label mb">Linux (bash, needs sudo)</div>
                <div className="code-block" data-testid="enroll-linux">
                  {created.linux}
                  <span className="copy">
                    <CopyButton text={created.linux} />
                  </span>
                </div>
              </div>
              <div>
                <div className="field-label mb">Server certificate fingerprint (SHA-256)</div>
                {/* Never truncated: this is the value compared by hand
                    against the installer output and against the Android
                    app's Trust review screen. */}
                <div className="code-block">
                  {list.data?.fingerprint || '—'}
                  <span className="copy">
                    <CopyButton text={list.data?.fingerprint ?? ''} />
                  </span>
                </div>
              </div>
              <div className="muted small">
                Token: <code data-testid="enroll-token">{created.token}</code>
              </div>
            </div>
          </div>
        )}

        <div className="card">
          <div className="card-head">Pair a phone</div>
          <div className="card-body">
            {list.data ? <PairCard url={list.data.public_url} fingerprint={list.data.fingerprint} /> : <Skeleton rows={1} cols={2} />}
          </div>
        </div>

        <div className="card">
          <div className="card-head">
            Active tokens
            <div className="actions">
              <span className="muted small">Server URL: {list.data?.public_url || '—'}</span>
            </div>
          </div>
          {!list.data ? (
            <Skeleton rows={2} cols={3} />
          ) : list.data.tokens.length ? (
            <div className="list">
              {list.data.tokens.map((t) => (
                <div key={t.id} className="list-item">
                  <div className="grow">
                    <div className="title">
                      {t.name || <span className="muted">(unnamed)</span>}
                      {t.group_id !== null && <span className="chip outline" style={{ marginLeft: 6 }}>{groups.find((g) => g.id === t.group_id)?.name ?? `group #${t.group_id}`}</span>}
                    </div>
                    <div className="sub">
                      {t.uses_left < 0 ? 'unlimited uses' : `${t.uses_left} use${t.uses_left === 1 ? '' : 's'} left`} · expires {relTime(t.expires_at)} · by {t.created_by}
                    </div>
                  </div>
                  <Button size="sm" onClick={() => setCreated({ id: t.id, token: t.token, windows: windowsCmd(list.data!.public_url, t.token), linux: linuxCmd(list.data!.public_url, t.token) })}>
                    Show commands
                  </Button>
                  <Button size="sm" variant="ghost" icon aria-label="Delete token" onClick={() => remove(t.id, t.name || t.token.slice(0, 8))}>
                    <IconTrash />
                  </Button>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty">No active tokens.</div>
          )}
        </div>
      </div>
    </Drawer>
  );
}

// Mirrors installCommandWindows/Linux in api_agents.go so an existing token's
// commands can be shown again without a second POST.
function windowsCmd(url: string, token: string): string {
  return `[Net.ServicePointManager]::ServerCertificateValidationCallback={$true}; iex ((New-Object Net.WebClient).DownloadString('${url}/install/${token}?os=windows'))`;
}
function linuxCmd(url: string, token: string): string {
  return `curl -fsSk '${url}/install/${token}?os=linux' | sudo bash`;
}
