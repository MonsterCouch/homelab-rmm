import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import type { Organization, Site } from '../api/types';
import { DataTable, type Column } from '../components/DataTable';
import { IconBuilding, IconPlus, IconTrash } from '../components/Icons';
import { Modal, useConfirm } from '../components/Modal';
import { Button, Chip, ErrorBox, Field } from '../components/ui';
import { useAsync } from '../hooks/useAsync';
import { dateTime } from '../lib/format';
import { useAuth } from '../state/auth';
import { errMsg, useToast } from '../state/toast';

export function Organizations() {
  const { isAdmin } = useAuth();
  const toast = useToast();
  const confirm = useConfirm();
  const orgs = useAsync(() => api.organizations(), []);
  const [selectedOrgId, setSelectedOrgId] = useState<string>('org_default');
  const [creatingOrg, setCreatingOrg] = useState(false);
  const [creatingSite, setCreatingSite] = useState(false);

  const activeOrg = (orgs.data ?? []).find((o) => o.id === selectedOrgId) ?? orgs.data?.[0];
  const sites = useAsync(
    async () => {
      if (!activeOrg) return [];
      return api.sites(activeOrg.id);
    },
    [activeOrg?.id],
  );

  const deleteOrg = async (o: Organization) => {
    if (o.id === 'org_default') {
      toast.warning('Cannot delete default organization', 'The default organization is required as the fallback home for unassigned devices.');
      return;
    }
    const ok = await confirm({
      title: `Delete ${o.name}`,
      message: `Are you sure you want to delete "${o.name}"? Enrolled devices in this organization will be reassigned to the default organization.`,
      danger: true,
      confirmLabel: 'Delete Organization',
    });
    if (!ok) return;

    try {
      await api.deleteOrganization(o.id);
      toast.success('Organization deleted');
      if (selectedOrgId === o.id) setSelectedOrgId('org_default');
      void orgs.reload();
    } catch (err) {
      toast.error('Failed to delete organization', errMsg(err));
    }
  };

  const deleteSite = async (s: Site) => {
    if (s.id === 'site_default') {
      toast.warning('Cannot delete default site', 'The default site is required.');
      return;
    }
    const ok = await confirm({
      title: `Delete site ${s.name}`,
      message: `Delete site "${s.name}"? Enrolled devices will be reassigned to the main site.`,
      danger: true,
      confirmLabel: 'Delete Site',
    });
    if (!ok) return;

    try {
      await api.deleteSite(s.id);
      toast.success('Site deleted');
      void sites.reload();
      void orgs.reload();
    } catch (err) {
      toast.error('Failed to delete site', errMsg(err));
    }
  };

  const orgColumns: Column<Organization>[] = [
    {
      key: 'name',
      header: 'Organization / Client',
      sort: (o) => o.name,
      render: (o) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <IconBuilding style={{ color: 'var(--accent)', flexShrink: 0 }} />
          <div>
            <b>{o.name}</b>
            {o.id === 'org_default' && <span className="muted small"> (default)</span>}
          </div>
        </div>
      ),
    },
    {
      key: 'devices',
      header: 'Devices',
      sort: (o) => o.device_count,
      render: (o) => (
        <Link to={`/devices?org=${encodeURIComponent(o.id)}`} onClick={(e) => e.stopPropagation()}>
          <Chip tone={o.device_count > 0 ? 'accent' : ''}>{o.device_count} device{o.device_count === 1 ? '' : 's'}</Chip>
        </Link>
      ),
    },
    {
      key: 'sites',
      header: 'Sites',
      sort: (o) => o.site_count,
      render: (o) => <span>{o.site_count}</span>,
    },
    {
      key: 'created',
      header: 'Created',
      sort: (o) => o.created_at,
      render: (o) => <span className="muted">{dateTime(o.created_at)}</span>,
    },
    {
      key: 'actions',
      header: '',
      render: (o) => (
        <div className="cell-actions" onClick={(e) => e.stopPropagation()}>
          {isAdmin && o.id !== 'org_default' && (
            <Button size="xs" variant="danger" icon onClick={() => deleteOrg(o)} title="Delete Organization" aria-label="Delete Organization">
              <IconTrash />
            </Button>
          )}
        </div>
      ),
    },
  ];

  const siteColumns: Column<Site>[] = [
    {
      key: 'name',
      header: 'Site / Branch Location',
      sort: (s) => s.name,
      render: (s) => (
        <div>
          <b>{s.name}</b>
          {s.id === 'site_default' && <span className="muted small"> (default)</span>}
        </div>
      ),
    },
    {
      key: 'devices',
      header: 'Devices',
      sort: (s) => s.device_count,
      render: (s) => (
        <Link to={`/devices?org=${encodeURIComponent(s.org_id)}&site=${encodeURIComponent(s.id)}`} onClick={(e) => e.stopPropagation()}>
          <Chip tone={s.device_count > 0 ? 'accent' : ''}>{s.device_count} device{s.device_count === 1 ? '' : 's'}</Chip>
        </Link>
      ),
    },
    {
      key: 'created',
      header: 'Created',
      sort: (s) => s.created_at,
      render: (s) => <span className="muted">{dateTime(s.created_at)}</span>,
    },
    {
      key: 'actions',
      header: '',
      render: (s) => (
        <div className="cell-actions" onClick={(e) => e.stopPropagation()}>
          {isAdmin && s.id !== 'site_default' && (
            <Button size="xs" variant="danger" icon onClick={() => deleteSite(s)} title="Delete Site" aria-label="Delete Site">
              <IconTrash />
            </Button>
          )}
        </div>
      ),
    },
  ];

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Organizations & Sites</h1>
          <p className="muted small" style={{ margin: 0 }}>
            Manage the multi-tenant MSP hierarchy: Clients/Organizations and their physical or branch Sites.
          </p>
        </div>
        {isAdmin && (
          <Button variant="primary" onClick={() => setCreatingOrg(true)}>
            <IconPlus /> New Organization
          </Button>
        )}
      </div>

      {orgs.error && <ErrorBox error={orgs.error} onRetry={orgs.reload} />}

      <div className="grid cols-2" style={{ alignItems: 'start', gap: 16 }}>
        {/* Organizations Card */}
        <div className="card">
          <div className="card-head" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>Organizations / Clients</span>
            <span className="muted small">Click row to inspect sites</span>
          </div>
          <div className="card-body" style={{ padding: 0 }}>
            <DataTable
              columns={orgColumns}
              rows={orgs.data ?? (orgs.loaded ? [] : undefined)}
              loading={orgs.loading}
              rowKey={(o) => o.id}
              onRowClick={(o) => setSelectedOrgId(o.id)}
              defaultSort={{ key: 'name', dir: 'asc' }}
              emptyTitle="No organizations"
            />
          </div>
        </div>

        {/* Sites under selected Organization */}
        <div className="card">
          <div className="card-head" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>
              Sites for <b>{activeOrg?.name ?? 'Organization'}</b>
            </span>
            {isAdmin && activeOrg && (
              <Button size="sm" onClick={() => setCreatingSite(true)}>
                <IconPlus /> Add Site
              </Button>
            )}
          </div>
          <div className="card-body" style={{ padding: 0 }}>
            {sites.error && <ErrorBox error={sites.error} onRetry={sites.reload} />}
            <DataTable
              columns={siteColumns}
              rows={sites.data ?? (sites.loaded ? [] : undefined)}
              loading={sites.loading}
              rowKey={(s) => s.id}
              defaultSort={{ key: 'name', dir: 'asc' }}
              emptyTitle={`No sites for ${activeOrg?.name ?? 'this organization'}`}
            />
          </div>
        </div>
      </div>

      {creatingOrg && (
        <CreateOrgModal
          onClose={() => setCreatingOrg(false)}
          onCreated={(newOrg) => {
            setCreatingOrg(false);
            setSelectedOrgId(newOrg.id);
            void orgs.reload();
          }}
        />
      )}

      {creatingSite && activeOrg && (
        <CreateSiteModal
          org={activeOrg}
          onClose={() => setCreatingSite(false)}
          onCreated={() => {
            setCreatingSite(false);
            void sites.reload();
            void orgs.reload();
          }}
        />
      )}
    </>
  );
}

function CreateOrgModal({ onClose, onCreated }: { onClose: () => void; onCreated: (o: Organization) => void }) {
  const toast = useToast();
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const clean = name.trim();
    if (!clean) return;
    setBusy(true);
    try {
      const o = await api.createOrganization({ name: clean });
      toast.success('Organization created', `Created "${o.name}" with default site.`);
      onCreated(o);
    } catch (err) {
      toast.error('Failed to create organization', errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title="New Organization / Client" onClose={onClose}>
      <form onSubmit={submit} className="stack" style={{ gap: 14 }}>
        <Field label="Organization Name" hint="The name of your client or company, e.g. Acme Corp.">
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Corp" autoFocus required />
        </Field>
        <div className="form-actions" style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" busy={busy} disabled={!name.trim()}>
            Create Organization
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function CreateSiteModal({ org, onClose, onCreated }: { org: Organization; onClose: () => void; onCreated: (s: Site) => void }) {
  const toast = useToast();
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const clean = name.trim();
    if (!clean) return;
    setBusy(true);
    try {
      const s = await api.createSite(org.id, { name: clean });
      toast.success('Site created', `Created "${s.name}" under ${org.name}.`);
      onCreated(s);
    } catch (err) {
      toast.error('Failed to create site', errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title={`Add Site to ${org.name}`} onClose={onClose}>
      <form onSubmit={submit} className="stack" style={{ gap: 14 }}>
        <Field label="Site Name" hint="Physical office, branch, or datacenter location, e.g. HQ, Warehouse, Branch #2.">
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Branch #2" autoFocus required />
        </Field>
        <div className="form-actions" style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" busy={busy} disabled={!name.trim()}>
            Add Site
          </Button>
        </div>
      </form>
    </Modal>
  );
}
