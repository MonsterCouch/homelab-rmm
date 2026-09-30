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
  { id: 'poc', label: 'Client contact', help: "Someone at a client business. Sees their organization's support tickets and nothing else; cannot use this console." },
];

const roleLabel = (r: Role) => ROLES.find((x) => x.id === r)?.label ?? r;

/** org_scope to save: a client contact has exactly their one organization. */
function scopeFor(role: Role, allOrgs: boolean, selectedOrgs: string[], contactOrg: string): string[] {
  if (role === 'poc') return contactOrg ? [contactOrg] : [];
  return role === 'admin' || allOrgs ? [] : selectedOrgs;
}

function ContactOrgField({ orgs, value, onChange }: { orgs: { id: string; name: string }[]; value: string; onChange: (id: string) => void }) {
  return (
    <Field label="Organization" hint="The client business this person works for. They will only see its tickets.">
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Choose an organization…</option>
        {orgs.map((o) => (
          <option key={o.id} value={o.id}>
            {o.name}
          </option>
        ))}
      </select>
    </Field>
  );
}

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
    { key: 'role', header: 'Role', sort: (u) => u.role, render: (u) => <Chip tone={u.role === 'admin' ? 'accent' : u.role === 'tech' ? 'info' : u.role === 'poc' ? 'purple' : ''}>{roleLabel(u.role)}</Chip> },
    {
      key: 'org_scope',
      header: 'Client Access',
      sort: (u) => (u.org_scope?.length ? u.org_scope.join(',') : ''),
      render: (u) =>
        u.role === 'admin' ? (
          <span className="muted small">Global (Admin)</span>
        ) : u.org_scope && u.org_scope.length > 0 ? (
          <Chip tone="purple">{u.org_scope.length} organization{u.org_scope.length === 1 ? '' : 's'}</Chip>
        ) : (
          <span className="muted small">Global (All clients)</span>
        ),
    },
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
  const orgs = useAsync(() => api.organizations(), []);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<Role>('tech');
  const [email, setEmail] = useState('');
  const [allOrgs, setAllOrgs] = useState(true);
  const [selectedOrgs, setSelectedOrgs] = useState<string[]>([]);
  const [contactOrg, setContactOrg] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toggleOrg = (id: string) => {
    setSelectedOrgs((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  };

  const save = async () => {
    setError(null);
    if (!username.trim()) return setError('Username is required.');
    if (password.length < 8) return setError('Password must be at least 8 characters.');
    if (role === 'poc' && !contactOrg) return setError('Choose the organization this contact works for.');
    setBusy(true);
    try {
      await api.createUser({
        username: username.trim(),
        password,
        role,
        email: email.trim(),
        org_scope: scopeFor(role, allOrgs, selectedOrgs, contactOrg),
      });
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
      {role === 'poc' && <ContactOrgField orgs={orgs.data ?? []} value={contactOrg} onChange={setContactOrg} />}
      {role !== 'admin' && role !== 'poc' && (
        <Field label="Organization Access" hint="Restrict this technician or viewer to specific customer organizations.">
          <div className="stack" style={{ gap: 6, marginTop: 4 }}>
            <label className="row" style={{ gap: 8, cursor: 'pointer' }}>
              <input type="checkbox" checked={allOrgs} onChange={(e) => setAllOrgs(e.target.checked)} />
              <span><b>Global</b> (Access to all organizations)</span>
            </label>
            {!allOrgs && (
              <div className="stack" style={{ gap: 4, marginLeft: 22, marginTop: 4 }}>
                {(orgs.data ?? []).map((o) => (
                  <label key={o.id} className="row" style={{ gap: 8, cursor: 'pointer' }}>
                    <input type="checkbox" checked={selectedOrgs.includes(o.id)} onChange={() => toggleOrg(o.id)} />
                    <span>{o.name}</span>
                  </label>
                ))}
              </div>
            )}
          </div>
        </Field>
      )}
      <Field label="Email (optional)">
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
      </Field>
    </Modal>
  );
}

function EditUser({ user, isSelf, onClose, onSaved }: { user: User; isSelf: boolean; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const confirm = useConfirm();
  const orgs = useAsync(() => api.organizations(), []);
  const [role, setRole] = useState<Role>(user.role);
  const [email, setEmail] = useState(user.email);
  const [password, setPassword] = useState('');
  const [allOrgs, setAllOrgs] = useState(!user.org_scope || user.org_scope.length === 0);
  const [selectedOrgs, setSelectedOrgs] = useState<string[]>(user.org_scope ?? []);
  const [contactOrg, setContactOrg] = useState(user.role === 'poc' ? (user.org_scope?.[0] ?? '') : '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toggleOrg = (id: string) => {
    setSelectedOrgs((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  };

  const save = async () => {
    setError(null);
    if (password && password.length < 8) return setError('Password must be at least 8 characters.');
    if (role === 'poc' && !contactOrg) return setError('Choose the organization this contact works for.');
    setBusy(true);
    try {
      await api.updateUser(user.id, {
        role: role !== user.role ? role : undefined,
        email: email !== user.email ? email.trim() : undefined,
        password: password || undefined,
        org_scope: scopeFor(role, allOrgs, selectedOrgs, contactOrg),
      });
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
      {role === 'poc' && <ContactOrgField orgs={orgs.data ?? []} value={contactOrg} onChange={setContactOrg} />}
      {role !== 'admin' && role !== 'poc' && (
        <Field label="Organization Access" hint="Restrict this technician or viewer to specific customer organizations.">
          <div className="stack" style={{ gap: 6, marginTop: 4 }}>
            <label className="row" style={{ gap: 8, cursor: 'pointer' }}>
              <input type="checkbox" checked={allOrgs} onChange={(e) => setAllOrgs(e.target.checked)} />
              <span><b>Global</b> (Access to all organizations)</span>
            </label>
            {!allOrgs && (
              <div className="stack" style={{ gap: 4, marginLeft: 22, marginTop: 4 }}>
                {(orgs.data ?? []).map((o) => (
                  <label key={o.id} className="row" style={{ gap: 8, cursor: 'pointer' }}>
                    <input type="checkbox" checked={selectedOrgs.includes(o.id)} onChange={() => toggleOrg(o.id)} />
                    <span>{o.name}</span>
                  </label>
                ))}
              </div>
            )}
          </div>
        </Field>
      )}
      <Field label="Email">
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
      </Field>
      <Field label="Reset password" hint="Leave empty to keep the current password. Setting one signs the user out everywhere.">
        <input type="password" value={password} autoComplete="new-password" placeholder="new password" onChange={(e) => setPassword(e.target.value)} />
      </Field>
    </Modal>
  );
}
