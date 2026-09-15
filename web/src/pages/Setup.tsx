import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { Button, Field } from '../components/ui';
import { useAuth } from '../state/auth';
import { errMsg } from '../state/toast';

export function Setup() {
  const { refresh, setupCodeRequired: codeRequired } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState('admin');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (password.length < 8) return setError('Password must be at least 8 characters.');
    if (password !== confirm) return setError('Passwords do not match.');
    setBusy(true);
    try {
      await api.setup(username.trim(), password, email.trim(), code.trim());
      await refresh();
      navigate('/', { replace: true });
    } catch (err) {
      setError(errMsg(err));
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
        <h1 style={{ marginBottom: 4 }}>Welcome</h1>
        <p className="muted" style={{ marginBottom: 18 }}>
          Create the first administrator account. You can add more users and enable two-factor authentication afterwards.
        </p>
        {error && <div className="form-error" role="alert">{error}</div>}
        <Field label="Username" htmlFor="su-user">
          <input id="su-user" value={username} autoComplete="username" required autoFocus onChange={(e) => setUsername(e.target.value)} />
        </Field>
        <Field label="Email (optional)" htmlFor="su-email" hint="Used for alert notifications.">
          <input id="su-email" type="email" value={email} autoComplete="email" onChange={(e) => setEmail(e.target.value)} />
        </Field>
        <Field label="Password" htmlFor="su-pw" hint="At least 8 characters.">
          <input id="su-pw" type="password" value={password} autoComplete="new-password" required onChange={(e) => setPassword(e.target.value)} />
        </Field>
        <Field label="Confirm password" htmlFor="su-pw2">
          <input id="su-pw2" type="password" value={confirm} autoComplete="new-password" required onChange={(e) => setConfirm(e.target.value)} />
        </Field>
        {codeRequired && (
          <Field
            label="Setup code"
            htmlFor="su-code"
            hint="The one-time code the server printed at startup — on the console, and as a WARN line in server.log in the data directory. Lost it? Restart the server before anyone creates a user and it prints a new one."
          >
            <input id="su-code" value={code} autoComplete="off" required spellCheck={false} onChange={(e) => setCode(e.target.value)} />
          </Field>
        )}
        <Button type="submit" variant="primary" busy={busy} style={{ width: '100%', marginTop: 6 }}>
          Create administrator
        </Button>
      </form>
    </div>
  );
}
