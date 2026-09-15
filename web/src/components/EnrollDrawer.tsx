import { useState } from 'react';
import { api } from '../api/client';
import type { EnrollCreated, Group } from '../api/types';
import { useAsync } from '../hooks/useAsync';
import { relTime } from '../lib/format';
import { errMsg, useToast } from '../state/toast';
import { useConfirm, Drawer } from './Modal';
import { Button, CopyButton, Field, Skeleton } from './ui';
import { IconTrash } from './Icons';

export function EnrollDrawer({ onClose, groups }: { onClose: () => void; groups: Group[] }) {
  const toast = useToast();
  const confirm = useConfirm();
  const list = useAsync(() => api.enrollTokens(), []);
  const [name, setName] = useState('');
  const [groupId, setGroupId] = useState<string>('');
  const [uses, setUses] = useState(1);
  const [unlimited, setUnlimited] = useState(false);
  const [ttl, setTtl] = useState(24);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<EnrollCreated | null>(null);

  const create = async () => {
    setBusy(true);
    try {
      const res = await api.createEnroll({ name: name.trim(), group_id: groupId ? +groupId : null, uses: unlimited ? -1 : Math.max(1, uses), ttl_hours: Math.max(1, ttl) });
      setCreated(res);
      toast.success('Enrolment token created');
      void list.reload();
    } catch (err) {
      toast.error('Could not create token', errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (id: number, label: string) => {
    if (!(await confirm({ title: 'Delete token', message: `Delete the enrolment token "${label}"? Installs already in progress keep working.`, danger: true, confirmLabel: 'Delete' }))) return;
    try {
      await api.deleteEnroll(id);
      if (created?.id === id) setCreated(null);
      void list.reload();
    } catch (err) {
      toast.error('Delete failed', errMsg(err));
    }
  };

  return (
    <Drawer title="Enrol a device" onClose={onClose} wide>
      <div className="stack" style={{ gap: 16 }}>
        <div className="card">
          <div className="card-head">New enrolment token</div>
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
              <Field label="Uses" hint="How many devices may enrol with this token.">
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
            <div className="card-head">Install commands</div>
            <div className="card-body stack">
              <p className="muted small">
                Run one of these on the device as an administrator / root. The agent downloads itself from this server, registers as a service and connects
                back. Verify the certificate fingerprint below matches what the installer prints.
              </p>
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
