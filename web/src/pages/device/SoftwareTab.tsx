import { useMemo, useState } from 'react';
import { api } from '../../api/client';
import type { Software, SoftwareCatalogItem } from '../../api/types';
import { DataTable, textMatch, type Column } from '../../components/DataTable';
import { useConfirm } from '../../components/Modal';
import { Button, Chip, Loading } from '../../components/ui';
import { useAsync, useDebounced } from '../../hooks/useAsync';
import { relTime } from '../../lib/format';
import { errMsg, useToast } from '../../state/toast';
import type { TabProps } from './DeviceDetail';

export function SoftwareTab({ agent, canWrite }: TabProps) {
  const [subTab, setSubTab] = useState<'installed' | 'drawer'>('installed');
  const [q, setQ] = useState('');
  const [cat, setCat] = useState('');
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);
  const dq = useDebounced(q);
  const toast = useToast();
  const confirm = useConfirm();

  const allInstalled = agent.inventory?.software ?? [];

  // Load software catalog matching agent OS
  const catalog = useAsync(() => api.softwareCatalog(agent.os), [agent.os]);

  // Check if a catalog app is installed on this device
  const isAppInstalled = (app: SoftwareCatalogItem): boolean => {
    const appNameLower = app.name.toLowerCase().trim();
    return allInstalled.some((s) => {
      const sName = s.name.toLowerCase().trim();
      if (sName === appNameLower) return true;
      const escaped = appNameLower.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const wordBoundary = new RegExp(`(^|\\s|[-_])${escaped}($|\\s|[-_])`, 'i');
      return wordBoundary.test(sName);
    });
  };

  const handleInstall = async (app: SoftwareCatalogItem) => {
    if (!agent.online) {
      toast.warning('Device offline', 'The device must be online to install software.');
      return;
    }
    const ok = await confirm({
      title: `Install ${app.name}`,
      message: `Deploy and install "${app.name}" (${app.version || 'latest'}) onto ${agent.display_name} under privileged service credentials?`,
      confirmLabel: 'Install Software',
    });
    if (!ok) return;

    try {
      setActionInProgress(app.id);
      const res = await api.installSoftware(agent.id, { catalog_id: app.id });
      toast.success(`Installation started for ${app.name}`, `Task run ID: ${res.run_id}`);
    } catch (err) {
      toast.error(`Install failed for ${app.name}`, errMsg(err));
    } finally {
      setActionInProgress(null);
    }
  };

  const handleUninstall = async (app: SoftwareCatalogItem) => {
    if (!agent.online) {
      toast.warning('Device offline', 'The device must be online to uninstall software.');
      return;
    }
    const ok = await confirm({
      title: `Uninstall ${app.name}`,
      message: `Remove "${app.name}" from ${agent.display_name}? This will execute the silent uninstall command.`,
      danger: true,
      confirmLabel: 'Uninstall Software',
    });
    if (!ok) return;

    try {
      setActionInProgress(app.id);
      const res = await api.uninstallSoftware(agent.id, { catalog_id: app.id });
      toast.success(`Uninstallation started for ${app.name}`, `Task run ID: ${res.run_id}`);
    } catch (err) {
      toast.error(`Uninstall failed for ${app.name}`, errMsg(err));
    } finally {
      setActionInProgress(null);
    }
  };

  // Installed rows filter
  const installedRows = useMemo(
    () => allInstalled.filter((s) => textMatch(dq, s.name, s.version, s.publisher)),
    [allInstalled, dq],
  );

  // Catalog items filter
  const catalogItems = useMemo(() => {
    const items = catalog.data ?? [];
    return items.filter((item) => {
      if (cat && item.category !== cat) return false;
      return textMatch(dq, item.name, item.publisher, item.category, item.description);
    });
  }, [catalog.data, cat, dq]);

  const categories = useMemo(() => {
    const set = new Set<string>();
    (catalog.data ?? []).forEach((c) => {
      if (c.category) set.add(c.category);
    });
    return Array.from(set).sort();
  }, [catalog.data]);

  const installedColumns: Column<Software>[] = [
    { key: 'name', header: 'Name', sort: (s) => s.name, render: (s) => s.name },
    { key: 'version', header: 'Version', sort: (s) => s.version, render: (s) => <span className="mono small">{s.version || '—'}</span> },
    { key: 'publisher', header: 'Publisher', sort: (s) => s.publisher ?? '', render: (s) => <span className="muted">{s.publisher || '—'}</span> },
    { key: 'installed', header: 'Installed', sort: (s) => s.installed ?? '', render: (s) => <span className="muted">{s.installed || '—'}</span> },
  ];

  return (
    <>
      <div className="row" style={{ gap: 8, marginBottom: 12 }}>
        <button
          className={`btn sm ${subTab === 'installed' ? 'primary' : ''}`}
          onClick={() => {
            setSubTab('installed');
            setQ('');
          }}
        >
          Installed Software ({allInstalled.length})
        </button>
        <button
          className={`btn sm ${subTab === 'drawer' ? 'primary' : ''}`}
          onClick={() => {
            setSubTab('drawer');
            setQ('');
          }}
        >
          Self-Service Software Drawer ({(catalog.data ?? []).length})
        </button>
      </div>

      {subTab === 'installed' ? (
        <>
          <div className="toolbar">
            <input
              type="search"
              placeholder="Filter installed software…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              style={{ maxWidth: 320 }}
              aria-label="Filter software"
            />
            <span className="grow" />
            <span className="muted small">
              {installedRows.length} of {allInstalled.length} packages · inventory {relTime(agent.inventory?.collected_at)}
            </span>
          </div>
          <DataTable
            columns={installedColumns}
            rows={installedRows}
            rowKey={(s) => `${s.name}|${s.version}|${s.publisher ?? ''}`}
            defaultSort={{ key: 'name', dir: 'asc' }}
            compact
            csvName="software"
            emptyTitle="No software inventory"
            emptyBody="Refresh the inventory while the device is online."
          />
        </>
      ) : (
        <>
          <div className="toolbar">
            <input
              type="search"
              placeholder="Search software catalog…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              style={{ maxWidth: 280 }}
              aria-label="Search software catalog"
            />
            <select
              value={cat}
              onChange={(e) => setCat(e.target.value)}
              style={{ width: 170 }}
              aria-label="Filter by category"
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
              Pre-approved software catalog • Privileged execution (SYSTEM/root)
            </span>
          </div>

          {catalog.loading && <Loading label="Loading software catalog…" />}

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 16 }}>
            {catalogItems.map((app) => {
              const installed = isAppInstalled(app);
              const busy = actionInProgress === app.id;

              return (
                <div
                  key={app.id}
                  className="card"
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    padding: 16,
                    borderRadius: 8,
                    border: '1px solid var(--border)',
                    background: 'var(--card-bg, #fff)',
                    position: 'relative',
                  }}
                >
                  <div className="row" style={{ justifyContent: 'space-between', marginBottom: 8 }}>
                    <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>{app.name}</h3>
                    {installed ? (
                      <Chip tone="ok">Installed</Chip>
                    ) : (
                      <Chip tone="purple">Available</Chip>
                    )}
                  </div>

                  <div className="row" style={{ gap: 8, marginBottom: 8 }}>
                    {app.category && <Chip outline>{app.category}</Chip>}
                    {app.publisher && <span className="muted small">{app.publisher}</span>}
                    {app.version && <span className="mono small muted">{app.version}</span>}
                  </div>

                  <p className="muted small" style={{ margin: '0 0 16px 0', flexGrow: 1, minHeight: 36 }}>
                    {app.description || 'Pre-configured application package.'}
                  </p>

                  <div className="row" style={{ gap: 8, marginTop: 'auto', borderTop: '1px solid var(--border-subtle)', paddingTop: 12 }}>
                    {installed ? (
                      <>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => handleInstall(app)}
                          disabled={busy || !canWrite || !agent.online}
                          title="Reinstall or update to latest version"
                        >
                          Reinstall
                        </Button>
                        {app.uninstall_cmd && (
                          <Button
                            size="sm"
                            className="danger"
                            onClick={() => handleUninstall(app)}
                            disabled={busy || !canWrite || !agent.online}
                          >
                            {busy ? 'Uninstalling…' : 'Uninstall'}
                          </Button>
                        )}
                      </>
                    ) : (
                      <Button
                        size="sm"
                        variant="primary"
                        onClick={() => handleInstall(app)}
                        disabled={busy || !canWrite || !agent.online}
                        style={{ width: '100%' }}
                      >
                        {busy ? 'Starting install…' : 'Install on Device'}
                      </Button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {!catalog.loading && catalogItems.length === 0 && (
            <div style={{ textAlign: 'center', padding: 48 }} className="muted">
              No software catalog items match your search.
            </div>
          )}
        </>
      )}
    </>
  );
}
