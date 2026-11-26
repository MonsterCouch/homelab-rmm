import { useMemo, useState } from 'react';
import { api } from '../api/client';
import type { AutomationScope, PermissionDef, RoleDef, RoleInput } from '../api/types';
import { DataTable, type Column } from '../components/DataTable';
import { IconPlus } from '../components/Icons';
import { Modal, useConfirm } from '../components/Modal';
import { Button, Chip, ErrorBox, Field } from '../components/ui';
import { useAsync } from '../hooks/useAsync';
import { errMsg, useToast } from '../state/toast';

type Grant = 'inherit' | 'allow' | 'deny';
type AutoMode = 'inherit' | 'all' | 'only';

const AUTOMATIONS_PERM = 'automations.edit';

const scopeText = (s: AutomationScope) => (s === 'all' ? 'all automations' : `${s.length} automation${s.length === 1 ? '' : 's'}`);

/** Ids of every role that inherits (directly or not) from `id`, so they cannot be picked as its parent. */
function descendantsOf(id: string, roles: RoleDef[]): Set<string> {
  const out = new Set<string>();
  let grew = true;
  while (grew) {
    grew = false;
    for (const r of roles) {
      if (!out.has(r.id) && (r.parent === id || out.has(r.parent))) {
        out.add(r.id);
        grew = true;
      }
    }
  }
  return out;
}

export function Roles() {
  const toast = useToast();
  const confirm = useConfirm();
  const data = useAsync(() => api.listRoles(), []);
  const [editing, setEditing] = useState<RoleDef | 'new' | null>(null);
  const perms = data.data?.permissions ?? [];
  const roles = data.data?.roles ?? [];

  const remove = async (r: RoleDef) => {
    if (!(await confirm({ title: 'Delete role', message: `Delete the role "${r.name}"?`, danger: true, confirmLabel: 'Delete' }))) return;
    try {
      await api.deleteRole(r.id);
      toast.success('Role deleted');
      void data.reload();
    } catch (err) {
      toast.error('Delete failed', errMsg(err));
    }
  };

  const parentName = (r: RoleDef) => roles.find((x) => x.id === r.parent)?.name ?? r.parent;

  const columns: Column<RoleDef>[] = [
    { key: 'name', header: 'Role', sort: (r) => r.name, render: (r) => <b>{r.name}</b> },
    {
      key: 'parent',
      header: 'Based on',
      sort: (r) => (r.builtin ? '' : parentName(r)),
      render: (r) => (r.builtin ? <Chip outline>Built-in</Chip> : <span>{parentName(r)}</span>),
    },
    {
      key: 'perms',
      header: 'Effective permissions',
      render: (r) => {
        if (r.effective.base === 'admin') return <span className="muted small">Everything</span>;
        const allowed = perms.filter((p) => r.effective.permissions[p.key] === true);
        const auto = r.effective.permissions[AUTOMATIONS_PERM] === true ? ` · automations: ${scopeText(r.effective.automation_scope)}` : '';
        return (
          <span className="muted small" title={allowed.map((p) => p.label).join(', ')}>
            {allowed.length} of {perms.length} allowed{auto}
          </span>
        );
      },
    },
    { key: 'users', header: 'Accounts', sort: (r) => r.users, render: (r) => r.users },
    {
      key: 'actions',
      header: '',
      render: (r) => (
        <div className="cell-actions">
          <Button size="xs" onClick={() => setEditing(r)}>
            {r.builtin ? 'View' : 'Edit'}
          </Button>
          {!r.builtin && (
            <Button size="xs" variant="danger" onClick={() => remove(r)}>
              Delete
            </Button>
          )}
        </div>
      ),
    },
  ];

  return (
    <>
      <div className="page-head">
        <h1>Roles</h1>
        <Button variant="primary" onClick={() => setEditing('new')} disabled={!data.data}>
          <IconPlus /> New role
        </Button>
      </div>
      {data.error && <ErrorBox error={data.error} onRetry={data.reload} />}
      <DataTable columns={columns} rows={data.data ? roles : undefined} loading={data.loading} rowKey={(r) => r.id} onRowClick={(r) => setEditing(r)} emptyTitle="No roles" />
      {editing && data.data && (
        <RoleDialog
          role={editing === 'new' ? null : editing}
          roles={roles}
          perms={perms}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            void data.reload();
          }}
        />
      )}
    </>
  );
}

function RoleDialog({ role, roles, perms, onClose, onSaved }: { role: RoleDef | null; roles: RoleDef[]; perms: PermissionDef[]; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const isNew = role === null;
  const readOnly = !!role?.builtin;
  const autos = useAsync(() => api.automations(), [], { enabled: !readOnly });

  const [name, setName] = useState(role?.name ?? '');
  const [parent, setParent] = useState(role?.parent || 'tech');
  const [grants, setGrants] = useState<Record<string, Grant>>(() => {
    const g: Record<string, Grant> = {};
    for (const p of perms) {
      const v = role?.grants?.[p.key];
      g[p.key] = v === true ? 'allow' : v === false ? 'deny' : 'inherit';
    }
    return g;
  });
  const [autoMode, setAutoMode] = useState<AutoMode>(role?.automations == null ? 'inherit' : role.automations === 'all' ? 'all' : 'only');
  const [autoIds, setAutoIds] = useState<number[]>(Array.isArray(role?.automations) ? role.automations : []);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const parentOptions = useMemo(() => {
    const banned = role ? descendantsOf(role.id, roles) : new Set<string>();
    return roles.filter((r) => !r.builtin && r.id !== role?.id && !banned.has(r.id));
  }, [roles, role]);
  const parentRole = roles.find((r) => r.id === parent);
  const inheritedPerm = (key: string) => parentRole?.effective.permissions[key] === true;
  const grantedNow = (key: string) => (grants[key] === 'allow' ? true : grants[key] === 'deny' ? false : inheritedPerm(key));
  const automationsAllowed = grantedNow(AUTOMATIONS_PERM);
  const inheritedScope = parentRole?.effective.automation_scope ?? 'all';

  const save = async () => {
    setError(null);
    if (!name.trim()) return setError('Name is required.');
    let automations: AutomationScope | null = null;
    if (automationsAllowed) {
      if (autoMode === 'all') automations = 'all';
      else if (autoMode === 'only') {
        if (!autoIds.length) return setError('Choose at least one automation, or pick "All automations".');
        automations = autoIds;
      }
    }
    const g: Record<string, boolean> = {};
    for (const p of perms) {
      if (grants[p.key] === 'allow') g[p.key] = true;
      else if (grants[p.key] === 'deny') g[p.key] = false;
    }
    const body: RoleInput = { name: name.trim(), parent, grants: g, automations };
    setBusy(true);
    try {
      if (role) await api.updateRole(role.id, body);
      else await api.createRole(body);
      toast.success(isNew ? 'Role created' : 'Role saved');
      onSaved();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title={isNew ? 'New role' : readOnly ? `${role.name} (built-in)` : `Edit ${role.name}`}
      onClose={onClose}
      size="lg"
      footer={
        readOnly ? (
          <Button onClick={onClose}>Close</Button>
        ) : (
          <>
            <Button onClick={onClose}>Cancel</Button>
            <Button variant="primary" onClick={save} busy={busy}>
              {isNew ? 'Create' : 'Save'}
            </Button>
          </>
        )
      }
    >
      {error && <div className="form-error" role="alert">{error}</div>}
      <div className="banner info">
        <span>
          {readOnly
            ? 'Built-in roles cannot be changed. '
            : 'A role is a technician or viewer at its core: it inherits everything from its parent, then allows or denies individual permissions. '}
          Administrators always have every permission.
        </span>
      </div>
      {!readOnly && (
        <div className="form-row">
          <Field label="Name">
            <input value={name} autoFocus maxLength={64} onChange={(e) => setName(e.target.value)} />
          </Field>
          <Field label="Inherits from" hint="Starts with everything this role has.">
            <select value={parent} onChange={(e) => setParent(e.target.value)}>
              <option value="tech">Technician</option>
              <option value="viewer">Viewer</option>
              {parentOptions.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </select>
          </Field>
        </div>
      )}

      <h3 className="mb mt">Permissions</h3>
      <div className="stack" style={{ gap: 10 }}>
        {perms.map((p) => {
          const isAuto = p.key === AUTOMATIONS_PERM;
          const effective = readOnly ? role.effective.permissions[p.key] === true || role.effective.base === 'admin' : grantedNow(p.key);
          return (
            <div key={p.key} className="stack" style={{ gap: 6 }}>
              <div className="row" style={{ justifyContent: 'space-between', gap: 12, alignItems: 'flex-start' }}>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <label htmlFor={`perm-${p.key}`}>
                    <b>{p.label}</b>
                  </label>
                  <div className="muted small">{p.help}</div>
                </div>
                {readOnly ? (
                  <Chip tone={effective ? 'ok' : ''}>{effective ? 'Allowed' : 'Denied'}</Chip>
                ) : (
                  <select id={`perm-${p.key}`} value={grants[p.key]} style={{ maxWidth: 240 }} onChange={(e) => setGrants((g) => ({ ...g, [p.key]: e.target.value as Grant }))}>
                    <option value="inherit">Inherit (currently {inheritedPerm(p.key) ? 'allowed' : 'denied'})</option>
                    <option value="allow">Allow</option>
                    <option value="deny">Deny</option>
                  </select>
                )}
              </div>
              {isAuto && readOnly && effective && <div className="muted small">Scope: {role.effective.base === 'admin' ? 'all automations' : scopeText(role.effective.automation_scope)}</div>}
              {isAuto && !readOnly && automationsAllowed && (
                <div className="card" style={{ padding: 10 }}>
                  <Field label="Which automations" hint="Scoped roles can edit their automations but not create or delete any.">
                    <select value={autoMode} onChange={(e) => setAutoMode(e.target.value as AutoMode)}>
                      <option value="inherit">Inherit from parent (currently {scopeText(inheritedScope)})</option>
                      <option value="all">All automations</option>
                      <option value="only">Only these</option>
                    </select>
                  </Field>
                  {autoMode === 'only' && (
                    <div className="checks" style={{ maxHeight: 160, overflow: 'auto' }}>
                      {(autos.data ?? []).map((a) => (
                        <label key={a.id}>
                          <input
                            type="checkbox"
                            checked={autoIds.includes(a.id)}
                            onChange={(e) => setAutoIds((cur) => (e.target.checked ? [...cur, a.id] : cur.filter((x) => x !== a.id)))}
                          />
                          {a.name}
                        </label>
                      ))}
                      {autos.loaded && !autos.data?.length && <span className="muted small">No automations defined yet.</span>}
                      {autos.error && <span className="muted small">{autos.error}</span>}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </Modal>
  );
}
