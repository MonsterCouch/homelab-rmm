import { useState } from 'react';
import { api } from '../api/client';
import type { Role, User } from '../api/types';
import { DataTable, type Column } from '../components/DataTable';
import { IconPlus } from '../components/Icons';
import { Modal, useConfirm } from '../components/Modal';
import { Button, Chip, ErrorBox, Field } from '../components/ui';
import { useAsync } from '../hooks/useAsync';
import { dateTime, relTime } from '../lib/format';
import { useAuth } from '../state/auth';
import { errMsg, useToast } from '../state/toast';

const ROLES: { id: Role; label: string; help: string }[] = [
  { id: 'admin', label: 'Admin', help: 'Everything, including users and settings.' },
  { id: 'tech', label: 'Tech', help: 'Manage devices, scripts, alerts and patches; no users or settings.' },
  { id: 'viewer', label: 'Viewer', help: 'Read-only.' },
];

export function Users() {
  const { user: me } = useAuth();
  const toast = useToast();
  const confirm = useConfirm();
  const users = useAsync(() => api.users(), []);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<User | null>(null);

  const remove = async (u: User) => {
    if (!(await confirm({ title: 'Delete user', message: `Delete "${u.username}"? Their sessions end immediately.`, danger: true, confirmLabel: 'Delete' }))) return;
    try {
      await api.deleteUser(u.id);
      toast.success('User deleted');
      void users.reload();
    } catch (err) {
      toast.error('Delete failed', errMsg(err));
    }
  };

  const columns: Column<User>[] = [
    { key: 'username', header: 'Username', sort: (u) => u.username, render: (u) => <b>{u.username}{u.id === me?.id && <span className="muted small"> (you)</span>}</b> },
    { key: 'role', header: 'Role', sort: (u) => u.role, render: (u) => <Chip tone={u.role === 'admin' ? 'accent' : u.role === 'tech' ? 'info' : ''}>{u.role}</Chip> },
    { key: 'email', header: 'Email', sort: (u) => u.email, render: (u) => u.email || <span className="faint">—</span> },
    { key: 'totp', header: '2FA', sort: (u) => (u.totp_enabled ? 0 : 1), render: (u) => (u.totp_enabled ? <Chip tone="ok">enabled</Chip> : <span className="muted">off</span>) },
    { key: 'login', header: 'Last login', sort: (u) => u.last_login, render: (u) => <span className="muted">{relTime(u.last_login)}</span> },
    { key: 'created', header: 'Created', sort: (u) => u.created_at, render: (u) => <span className="muted">{dateTime(u.created_at)}</span> },
    {
      key: 'actions',
      header: '',
      render: (u) => (
        <div className="cell-actions">
          <Button size="xs" onClick={() => setEditing(u)}>
            Edit
          </Button>
          <Button size="xs" variant="danger" disabled={u.id === me?.id} onClick={() => remove(u)}>
            Delete
          </Button>
        </div>
      ),
    },
  ];

  return (
    <>
      <div className="page-head">
        <h1>Users</h1>
        <Button variant="primary" onClick={() => setCreating(true)}>
          <IconPlus /> New user
        </Button>
      </div>
      {users.error && <ErrorBox error={users.error} onRetry={users.reload} />}
      <DataTable columns={columns} rows={users.data ?? (users.loaded ? [] : undefined)} loading={users.loading} rowKey={(u) => String(u.id)} onRowClick={(u) => setEditing(u)} defaultSort={{ key: 'username', dir: 'asc' }} emptyTitle="No users" />
      {creating && (
        <CreateUser
          onClose={() => setCreating(false)}
          onSaved={() => {
            setCreating(false);
            void users.reload();
          }}
        />
      )}
      {editing && (
        <EditUser
          user={editing}
          isSelf={editing.id === me?.id}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            void users.reload();
          }}
        />
      )}
    </>
  );
}

function CreateUser({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<Role>('tech');
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const save = async () => {
    setError(null);
    if (!username.trim()) return setError('Username is required.');
    if (password.length < 8) return setError('Password must be at least 8 characters.');
    setBusy(true);
    try {
      await api.createUser({ username: username.trim(), password, role, email: email.trim() });
      toast.success(`User ${username.trim()} created`);
      onSaved();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title="New user"
      onClose={onClose}
      size="sm"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={save} busy={busy}>
            Create
          </Button>
        </>
      }
    >
      {error && <div className="form-error" role="alert">{error}</div>}
      <Field label="Username">
        <input value={username} autoFocus autoComplete="off" onChange={(e) => setUsername(e.target.value)} />
      </Field>
      <Field label="Password" hint="At least 8 characters. Share it out of band; the user can change it afterwards.">
        <input type="password" value={password} autoComplete="new-password" onChange={(e) => setPassword(e.target.value)} />
      </Field>
      <Field label="Role" hint={ROLES.find((r) => r.id === role)?.help}>
        <select value={role} onChange={(e) => setRole(e.target.value as Role)}>
          {ROLES.map((r) => (
            <option key={r.id} value={r.id}>
              {r.label}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Email (optional)">
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
      </Field>
    </Modal>
  );
}

function EditUser({ user, isSelf, onClose, onSaved }: { user: User; isSelf: boolean; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const confirm = useConfirm();
  const [role, setRole] = useState<Role>(user.role);
  const [email, setEmail] = useState(user.email);
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const save = async () => {
    setError(null);
    if (password && password.length < 8) return setError('Password must be at least 8 characters.');
    setBusy(true);
    try {
      await api.updateUser(user.id, { role: role !== user.role ? role : undefined, email: email !== user.email ? email.trim() : undefined, password: password || undefined });
      toast.success('User updated', password ? 'Their password was reset and sessions ended.' : undefined);
      onSaved();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };
  const resetTotp = async () => {
    if (!(await confirm({ title: 'Reset two-factor', message: `Remove the authenticator from "${user.username}"? They can enroll a new one from their Account page.`, danger: true, confirmLabel: 'Reset 2FA' }))) return;
    try {
      await api.updateUser(user.id, { reset_totp: true });
      toast.success('Two-factor reset');
      onSaved();
    } catch (err) {
      toast.error('Reset failed', errMsg(err));
    }
  };
  return (
    <Modal
      title={`Edit ${user.username}`}
      onClose={onClose}
      size="sm"
      footer={
        <>
          {user.totp_enabled && (
            <Button variant="danger" onClick={resetTotp} style={{ marginRight: 'auto' }}>
              Reset 2FA
            </Button>
          )}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={save} busy={busy}>
            Save
          </Button>
        </>
      }
    >
      {error && <div className="form-error" role="alert">{error}</div>}
      <Field label="Role" hint={isSelf ? 'You cannot change your own role.' : ROLES.find((r) => r.id === role)?.help}>
        <select value={role} disabled={isSelf} onChange={(e) => setRole(e.target.value as Role)}>
          {ROLES.map((r) => (
            <option key={r.id} value={r.id}>
              {r.label}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Email">
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
      </Field>
      <Field label="Reset password" hint="Leave empty to keep the current password. Setting one signs the user out everywhere.">
        <input type="password" value={password} autoComplete="new-password" placeholder="new password" onChange={(e) => setPassword(e.target.value)} />
      </Field>
    </Modal>
  );
}
