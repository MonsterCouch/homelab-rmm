import { useState, type FormEvent } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { api, ApiError } from '../api/client';
import { Button, Field } from '../components/ui';
import { useAuth } from '../state/auth';
import { errMsg } from '../state/toast';

export function Login() {
  const { setUser } = useAuth();
  const navigate = useNavigate();
  const loc = useLocation();
  const from = (loc.state as { from?: string } | null)?.from ?? '/';
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [needsTotp, setNeedsTotp] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const res = await api.login(username.trim(), password, code.trim());
      if (res.needs_totp) {
        // Same response for "code missing" and "code wrong": tell the user
        // which one only when they actually typed something.
        if (needsTotp && code.trim()) setError('That code was not accepted. Codes rotate every 30 seconds.');
        setNeedsTotp(true);
        setCode('');
        return;
      }
      if (res.user) {
        setUser(res.user);
        navigate(from, { replace: true });
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setError('Invalid username or password.');
      else if (err instanceof ApiError && err.status === 429) setError('Too many attempts. Wait a minute and try again.');
      else setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth">
      <form className="card" onSubmit={submit}>
        <div className="brand">
          <span className="logo">R</span> Homelab RMM
        </div>
        <h1 style={{ marginBottom: 16 }}>{needsTotp ? 'Two-factor code' : 'Sign in'}</h1>
        {error && <div className="form-error" role="alert">{error}</div>}
        {!needsTotp ? (
          <>
            <Field label="Username" htmlFor="li-user">
              <input id="li-user" value={username} autoComplete="username" required autoFocus onChange={(e) => setUsername(e.target.value)} />
            </Field>
            <Field label="Password" htmlFor="li-pw">
              <input id="li-pw" type="password" value={password} autoComplete="current-password" required onChange={(e) => setPassword(e.target.value)} />
            </Field>
          </>
        ) : (
          <Field label="Authenticator code" htmlFor="li-code" hint={`Signing in as ${username}. Enter the 6-digit code from your authenticator app.`}>
            <input
              id="li-code"
              inputMode="numeric"
              pattern="[0-9]*"
              maxLength={8}
              value={code}
              autoComplete="one-time-code"
              required
              autoFocus
              className="mono"
              style={{ fontSize: 20, letterSpacing: 6, textAlign: 'center' }}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
            />
          </Field>
        )}
        <Button type="submit" variant="primary" busy={busy} style={{ width: '100%', marginTop: 6 }}>
          {needsTotp ? 'Verify' : 'Sign in'}
        </Button>
        {needsTotp && (
          <Button
            variant="ghost"
            style={{ width: '100%', marginTop: 6 }}
            onClick={() => {
              setNeedsTotp(false);
              setCode('');
              setError(null);
            }}
          >
            Back
          </Button>
        )}
      </form>
    </div>
  );
}
