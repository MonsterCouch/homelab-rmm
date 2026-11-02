import { useEffect, useState, type FormEvent } from 'react';
import QRCode from 'qrcode';
import { api } from '../api/client';
import { SecurityKeys } from '../components/SecurityKeys';
import { Button, Chip, CopyButton, Field } from '../components/ui';
import { dateTime } from '../lib/format';
import { useAuth } from '../state/auth';
import { errMsg, useToast } from '../state/toast';

export function Account() {
  const { user, refresh } = useAuth();
  if (!user) return null;
  return (
    <>
      <div className="page-head">
        <h1>Account</h1>
      </div>
      <div className="grid cols-2">
        <div className="stack" style={{ gap: 14 }}>
          <div className="card">
            <div className="card-head">Profile</div>
            <div className="card-body">
              <dl className="kv">
                <dt>Username</dt>
                <dd>{user.username}</dd>
                <dt>Role</dt>
                <dd>
                  <Chip tone={user.role === 'admin' ? 'accent' : user.role === 'tech' ? 'info' : ''}>{user.role}</Chip>
                </dd>
                <dt>Email</dt>
                <dd>{user.email || <span className="muted">not set</span>}</dd>
                <dt>Member since</dt>
                <dd>{dateTime(user.created_at)}</dd>
                <dt>Last login</dt>
                <dd>{dateTime(user.last_login)}</dd>
              </dl>
            </div>
          </div>
          <ChangePassword />
        </div>
        <div className="stack" style={{ gap: 14 }}>
          <TwoFactor enabled={user.totp_enabled} onChanged={refresh} />
          {user.role !== 'poc' && <SecurityKeys />}
        </div>
      </div>
    </>
  );
}

function ChangePassword() {
  const toast = useToast();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (next.length < 8) return setError('New password must be at least 8 characters.');
    if (next !== confirm) return setError('Passwords do not match.');
    setBusy(true);
    try {
      await api.changePassword(current, next);
      toast.success('Password changed');
      setCurrent('');
      setNext('');
      setConfirm('');
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="card" onSubmit={submit}>
      <div className="card-head">Change password</div>
      <div className="card-body">
        {error && <div className="form-error" role="alert">{error}</div>}
        <Field label="Current password" htmlFor="cp-cur">
          <input id="cp-cur" type="password" value={current} autoComplete="current-password" required onChange={(e) => setCurrent(e.target.value)} />
        </Field>
        <Field label="New password" htmlFor="cp-new" hint="At least 8 characters.">
          <input id="cp-new" type="password" value={next} autoComplete="new-password" required onChange={(e) => setNext(e.target.value)} />
        </Field>
        <Field label="Confirm new password" htmlFor="cp-conf">
          <input id="cp-conf" type="password" value={confirm} autoComplete="new-password" required onChange={(e) => setConfirm(e.target.value)} />
        </Field>
        <div className="form-actions">
          <Button type="submit" variant="primary" busy={busy}>
            Change password
          </Button>
        </div>
      </div>
    </form>
  );
}

function TwoFactor({ enabled, onChanged }: { enabled: boolean; onChanged: () => Promise<void> }) {
  const toast = useToast();
  const [setup, setSetup] = useState<{ secret: string; url: string; qr: string } | null>(null);
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // If the user navigates away mid-setup the secret is left pending on the
    // server but disabled; beginning again replaces it.
    return () => setSetup(null);
  }, []);

  const begin = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await api.totpBegin();
      const qr = await QRCode.toDataURL(r.url, { width: 200, margin: 1, color: { dark: '#000000', light: '#ffffff' } });
      setSetup({ ...r, qr });
      setCode('');
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };
  const confirm = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.totpConfirm(code.trim());
      toast.success('Two-factor authentication enabled');
      setSetup(null);
      await onChanged();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };
  const disable = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.totpDisable(password);
      toast.success('Two-factor authentication disabled');
      setPassword('');
      await onChanged();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card">
      <div className="card-head">
        Two-factor authentication
        <div className="actions">{enabled ? <Chip tone="ok">enabled</Chip> : <Chip>off</Chip>}</div>
      </div>
      <div className="card-body">
        {error && <div className="form-error" role="alert">{error}</div>}
        {enabled ? (
          <form onSubmit={disable}>
            <p className="muted">Signing in requires a code from your authenticator app. Enter your password to turn this off.</p>
            <Field label="Password" htmlFor="tf-pw">
              <input id="tf-pw" type="password" value={password} autoComplete="current-password" required onChange={(e) => setPassword(e.target.value)} />
            </Field>
            <div className="form-actions">
              <Button type="submit" variant="danger" busy={busy}>
                Disable two-factor
              </Button>
            </div>
          </form>
        ) : !setup ? (
          <>
            <p className="muted">Protect this account with a time-based one-time code (Google Authenticator, Aegis, 1Password, Bitwarden…).</p>
            <Button variant="primary" onClick={begin} busy={busy}>
              Set up authenticator
            </Button>
          </>
        ) : (
          <form onSubmit={confirm} className="stack">
            <p className="muted">1. Scan the QR code with your authenticator app, or enter the secret by hand.</p>
            <div className="row" style={{ alignItems: 'flex-start', gap: 16 }}>
              <img src={setup.qr} alt="TOTP QR code" width={200} height={200} style={{ borderRadius: 6, background: '#fff' }} />
              <div className="stack" style={{ flex: 1, minWidth: 0 }}>
                <Field label="Secret">
                  <div className="row" style={{ flexWrap: 'nowrap' }}>
                    <code className="input" style={{ wordBreak: 'break-all' }}>
                      {setup.secret}
                    </code>
                    <CopyButton text={setup.secret} />
                  </div>
                </Field>
                <details>
                  <summary className="muted small" style={{ cursor: 'pointer' }}>
                    otpauth URL
                  </summary>
                  <code className="small" style={{ wordBreak: 'break-all' }}>
                    {setup.url}
                  </code>
                </details>
              </div>
            </div>
            <p className="muted">2. Enter the 6-digit code the app shows to confirm.</p>
            <Field label="Code" htmlFor="tf-code">
              <input
                id="tf-code"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={8}
                value={code}
                autoComplete="one-time-code"
                required
                autoFocus
                className="mono"
                style={{ maxWidth: 200, fontSize: 18, letterSpacing: 4 }}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
              />
            </Field>
            <div className="form-actions">
              <Button onClick={() => setSetup(null)}>Cancel</Button>
              <Button type="submit" variant="primary" busy={busy} disabled={code.length < 6}>
                Confirm and enable
              </Button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
