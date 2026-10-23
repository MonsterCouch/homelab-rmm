import { useState } from 'react';
import { api } from '../api/client';
import type { WebAuthnCredential } from '../api/types';
import { useAsync } from '../hooks/useAsync';
import { dateTime } from '../lib/format';
import { isWebAuthnUsable, register, webauthnErrorMessage } from '../lib/webauthn';
import { errMsg, useToast } from '../state/toast';
import { useAuth } from '../state/auth';
import { IconTrash } from './Icons';
import { PromptDialog, useConfirm } from './Modal';
import { Button, Chip, ErrorBox } from './ui';

const ALG: Record<number, string> = { [-7]: 'ES256', [-8]: 'EdDSA', [-257]: 'RS256' };

/**
 * Security keys (WebAuthn credentials) for the signed-in operator. A key
 * registered here proves nothing to a device until an admin adds it to the
 * organization's trust bundle (Trust & signing).
 */
export function SecurityKeys() {
  const toast = useToast();
  const confirm = useConfirm();
  const { user, isAdmin } = useAuth();
  const creds = useAsync(() => api.webauthnCredentials(), []);
  const [naming, setNaming] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const usable = isWebAuthnUsable();

  const add = async (name: string) => {
    try {
      const options = await api.webauthnRegisterBegin();
      const result = await register(options);
      await api.webauthnRegisterFinish(name, result);
      toast.success('Security key registered', `"${name}" can sign once an admin adds it to the trust bundle.`);
      setNaming(false);
      void creds.reload();
    } catch (err) {
      const msg = err instanceof DOMException ? webauthnErrorMessage(err) : errMsg(err);
      toast.error('Could not register the security key', msg);
    }
  };

  const remove = async (c: WebAuthnCredential) => {
    const ok = await confirm({
      title: `Remove ${c.name}`,
      message: c.in_bundle
        ? `"${c.name}" is part of an organization's trust bundle. Removing it needs a bundle update first (Trust & signing); the server will refuse until then.`
        : `Remove the security key "${c.name}"? It will no longer be able to sign.`,
      danger: true,
      confirmLabel: 'Remove',
    });
    if (!ok) return;
    setRemoving(c.id);
    try {
      await api.deleteWebauthnCredential(c.id);
      toast.success('Security key removed');
      void creds.reload();
    } catch (err) {
      toast.error('Remove failed', errMsg(err));
    } finally {
      setRemoving(null);
    }
  };

  const rows = creds.data ?? [];
  return (
    <div className="card">
      <div className="card-head">
        Security keys
        <div className="actions">
          <Button size="sm" variant="primary" onClick={() => setNaming(true)} disabled={!usable.ok}>
            Add security key
          </Button>
        </div>
      </div>
      <div className="card-body stack">
        {!usable.ok && (
          <div className="banner warn" role="alert">
            {usable.reason}
          </div>
        )}
        <p className="muted" style={{ margin: 0 }}>
          A hardware key or passkey signs destructive actions, shells and remote desktops so a stolen session cannot run them. A newly registered key only
          authorizes actions after an admin adds it to the organization&apos;s trust bundle{isAdmin ? ' (Trust & signing).' : '.'}
        </p>
        {creds.error && <ErrorBox error={creds.error} onRetry={creds.reload} />}
        {creds.loaded && !rows.length && !creds.error && <p className="muted small">No security keys registered yet.</p>}
        {rows.length > 0 && (
          <div className="table-wrap">
          <table className="tbl compact">
            <thead>
              <tr>
                <th>Name</th>
                {isAdmin && <th>Owner</th>}
                <th>Type</th>
                <th>Added</th>
                <th>Last used</th>
                <th>Trust bundle</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.id}>
                  <td>
                    <b>{c.name}</b>
                  </td>
                  {isAdmin && <td>{c.owner}</td>}
                  <td className="mono small">{ALG[c.alg] ?? `alg ${c.alg}`}</td>
                  <td className="muted">{dateTime(c.created_at)}</td>
                  <td className="muted">{c.last_used_at ? dateTime(c.last_used_at) : 'never'}</td>
                  <td>{c.in_bundle ? <Chip tone="ok">in bundle</Chip> : <Chip title="Not trusted by any device until an admin adds it">not trusted yet</Chip>}</td>
                  <td>
                    {(isAdmin || c.owner === user?.username) && (
                      <Button size="xs" variant="danger" icon busy={removing === c.id} onClick={() => remove(c)} title="Remove" aria-label={`Remove ${c.name}`}>
                        <IconTrash />
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
        {rows.length === 1 && <p className="muted small">Register a second key and keep it somewhere safe: losing your only key locks you out of signing.</p>}
      </div>
      {naming && (
        <PromptDialog
          title="Add a security key"
          label="Name (so you can tell your keys apart)"
          initial=""
          placeholder="YubiKey 5 (desk)"
          confirmLabel="Continue"
          onClose={() => setNaming(false)}
          onSubmit={add}
        />
      )}
    </div>
  );
}
