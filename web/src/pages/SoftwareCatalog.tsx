import { useMemo, useState } from 'react';
import { api } from '../api/client';
import type { SoftwareCatalogItem } from '../api/types';
import { DataTable, textMatch, type Column } from '../components/DataTable';
import { IconPlus, IconRefresh } from '../components/Icons';
import { Modal, useConfirm } from '../components/Modal';
import { Button, Chip, ErrorBox } from '../components/ui';
import { useAsync, useDebounced } from '../hooks/useAsync';
import { useAuth } from '../state/auth';
import { errMsg, useToast } from '../state/toast';

export function SoftwareCatalog() {
  const { isAdmin } = useAuth();
  const toast = useToast();
  const confirm = useConfirm();

  const [q, setQ] = useState('');
  const [osFilter, setOsFilter] = useState('');
  const [catFilter, setCatFilter] = useState('');
  const dq = useDebounced(q);

  const [editingItem, setEditingItem] = useState<Partial<SoftwareCatalogItem> | null>(null);

  const catalog = useAsync(() => api.softwareCatalog(osFilter), [osFilter]);

  const items = catalog.data ?? [];

  const categories = useMemo(() => {
    const s = new Set<string>();
    items.forEach((it) => {
      if (it.category) s.add(it.category);
    });
    return Array.from(s).sort();
  }, [items]);

  const filtered = useMemo(() => {
    return items.filter((it) => {
      if (catFilter && it.category !== catFilter) return false;
      return textMatch(dq, it.name, it.publisher, it.category, it.description, it.install_cmd);
    });
  }, [items, catFilter, dq]);

  const handleDelete = async (it: SoftwareCatalogItem) => {
    const ok = await confirm({
      title: `Delete ${it.name}`,
      message: `Remove "${it.name}" from the software catalog? Devices will no longer be able to self-service install this package.`,
      danger: true,
      confirmLabel: 'Delete Catalog Item',
    });
    if (!ok) return;

    try {
      await api.deleteSoftwareCatalogItem(it.id);
      toast.success('Catalog item removed');
      void catalog.reload();
    } catch (err) {
      toast.error('Delete failed', errMsg(err));
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingItem) return;

    if (!editingItem.name?.trim() || !editingItem.install_cmd?.trim()) {
      toast.error('Validation error', 'Name and Install Command are required.');
      return;
    }

    try {
      if (editingItem.id) {
        await api.updateSoftwareCatalogItem(editingItem.id, editingItem);
        toast.success('Catalog item updated');
      } else {
        await api.createSoftwareCatalogItem(editingItem);
        toast.success('Catalog item created');
      }
      setEditingItem(null);
      void catalog.reload();
    } catch (err) {
      toast.error('Save failed', errMsg(err));
    }
  };

  const columns: Column<SoftwareCatalogItem>[] = [
    {
      key: 'name',
      header: 'Software',
      sort: (it) => it.name,
      render: (it) => (
        <div>
          <div style={{ fontWeight: 600 }}>{it.name}</div>
          {it.description && <div className="muted small">{it.description}</div>}
        </div>
      ),
    },
    {
      key: 'publisher',
      header: 'Publisher',
      sort: (it) => it.publisher,
      render: (it) => <span className="muted">{it.publisher || '—'}</span>,
    },
    {
      key: 'category',
      header: 'Category',
      sort: (it) => it.category,
      render: (it) => (it.category ? <Chip outline>{it.category}</Chip> : '—'),
    },
    {
      key: 'os',
      header: 'OS',
      sort: (it) => it.os,
      render: (it) => (
        <Chip tone={it.os === 'windows' ? 'accent' : it.os === 'linux' ? 'warn' : 'purple'}>
          {it.os.toUpperCase()}
        </Chip>
      ),
    },
    {
      key: 'install_cmd',
      header: 'Install Command',
      render: (it) => (
        <code className="small mono muted" style={{ display: 'block', maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={it.install_cmd}>
          {it.install_cmd}
        </code>
      ),
    },
    {
      key: 'actions',
      header: '',
      width: 130,
      render: (it) =>
        isAdmin && (
          <div className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
            <Button size="sm" variant="ghost" onClick={() => setEditingItem(it)}>
              Edit
            </Button>
            <Button size="sm" className="danger" onClick={() => handleDelete(it)}>
              Delete
            </Button>
          </div>
        ),
    },
  ];

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Self-Service Software Catalog</h1>
          <p className="muted small">
            Curate approved software packages that end users and technicians can install without requiring local administrator credentials.
          </p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button size="sm" onClick={() => catalog.reload()} disabled={catalog.loading} title="Refresh catalog">
            <IconRefresh /> Refresh
          </Button>
          {isAdmin && (
            <Button variant="primary" size="sm" onClick={() => setEditingItem({ os: 'all', category: 'Utilities' })}>
              <IconPlus /> Add Software Package
            </Button>
          )}
        </div>
      </div>

      {catalog.error && <ErrorBox error={catalog.error} onRetry={catalog.reload} />}

      <div className="toolbar">
        <input
          type="search"
          placeholder="Search catalog software, publisher, commands…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          style={{ maxWidth: 320 }}
          aria-label="Search software catalog"
        />
        <select
          value={osFilter}
          onChange={(e) => setOsFilter(e.target.value)}
          style={{ width: 140 }}
          aria-label="Filter by OS"
        >
          <option value="">All Operating Systems</option>
          <option value="windows">Windows</option>
          <option value="linux">Linux</option>
        </select>
        <select
          value={catFilter}
          onChange={(e) => setCatFilter(e.target.value)}
          style={{ width: 160 }}
          aria-label="Filter by Category"
        >
          <option value="">All Categories</option>
          {categories.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <span className="grow" />
        <span className="muted small">
          {filtered.length} of {items.length} packages
        </span>
      </div>

      <DataTable
        columns={columns}
        rows={catalog.data ? filtered : undefined}
        loading={catalog.loading}
        rowKey={(it) => it.id}
        defaultSort={{ key: 'name', dir: 'asc' }}
        csvName="software_catalog"
        emptyTitle="No catalog items"
        emptyBody="Add pre-approved software packages to empower user self-service installations."
      />

      {editingItem && (
        <Modal
          title={editingItem.id ? `Edit ${editingItem.name}` : 'New Software Catalog Package'}
          onClose={() => setEditingItem(null)}
        >
          <form onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>Software Name *</label>
              <input
                type="text"
                required
                value={editingItem.name || ''}
                onChange={(e) => setEditingItem({ ...editingItem, name: e.target.value })}
                placeholder="e.g. Google Chrome, Visual Studio Code"
                style={{ width: '100%' }}
              />
            </div>

            <div className="row" style={{ gap: 12 }}>
              <div style={{ flex: 1 }}>
                <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>Publisher</label>
                <input
                  type="text"
                  value={editingItem.publisher || ''}
                  onChange={(e) => setEditingItem({ ...editingItem, publisher: e.target.value })}
                  placeholder="e.g. Google LLC, Microsoft"
                  style={{ width: '100%' }}
                />
              </div>
              <div style={{ flex: 1 }}>
                <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>Category</label>
                <input
                  type="text"
                  value={editingItem.category || ''}
                  onChange={(e) => setEditingItem({ ...editingItem, category: e.target.value })}
                  placeholder="e.g. Browsers, Utilities, Developer Tools"
                  style={{ width: '100%' }}
                />
              </div>
            </div>

            <div className="row" style={{ gap: 12 }}>
              <div style={{ flex: 1 }}>
                <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>Target OS</label>
                <select
                  value={editingItem.os || 'all'}
                  onChange={(e) => setEditingItem({ ...editingItem, os: e.target.value })}
                  style={{ width: '100%' }}
                >
                  <option value="all">All (Cross-platform)</option>
                  <option value="windows">Windows Only</option>
                  <option value="linux">Linux Only</option>
                </select>
              </div>
              <div style={{ flex: 1 }}>
                <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>Version</label>
                <input
                  type="text"
                  value={editingItem.version || ''}
                  onChange={(e) => setEditingItem({ ...editingItem, version: e.target.value })}
                  placeholder="e.g. Latest, 1.0.0"
                  style={{ width: '100%' }}
                />
              </div>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>Description</label>
              <textarea
                rows={2}
                value={editingItem.description || ''}
                onChange={(e) => setEditingItem({ ...editingItem, description: e.target.value })}
                placeholder="Short description displayed to users in the self-service drawer..."
                style={{ width: '100%' }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>Silent Install Command *</label>
              <textarea
                rows={3}
                required
                value={editingItem.install_cmd || ''}
                onChange={(e) => setEditingItem({ ...editingItem, install_cmd: e.target.value })}
                placeholder="e.g. winget install --id Google.Chrome -e --silent --accept-source-agreements --accept-package-agreements"
                style={{ width: '100%', fontFamily: 'monospace', fontSize: 12 }}
              />
              <span className="muted small">Executed with elevated LocalSystem (Windows) or root (Linux) permissions.</span>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>Silent Uninstall Command (Optional)</label>
              <textarea
                rows={2}
                value={editingItem.uninstall_cmd || ''}
                onChange={(e) => setEditingItem({ ...editingItem, uninstall_cmd: e.target.value })}
                placeholder="e.g. winget uninstall --id Google.Chrome -e --silent"
                style={{ width: '100%', fontFamily: 'monospace', fontSize: 12 }}
              />
            </div>

            <div className="row" style={{ justifyContent: 'flex-end', gap: 8, marginTop: 12 }}>
              <Button variant="ghost" onClick={() => setEditingItem(null)}>
                Cancel
              </Button>
              <Button variant="primary" type="submit">
                {editingItem.id ? 'Save Changes' : 'Create Package'}
              </Button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}
