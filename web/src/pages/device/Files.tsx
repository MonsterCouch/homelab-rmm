import { useMemo, useRef, useState } from 'react';
import { api } from '../../api/client';
import type { FsEntry } from '../../api/types';
import { DataTable, textMatch, type Column } from '../../components/DataTable';
import { IconDownload, IconFile, IconFolder, IconPlus, IconRefresh, IconUpload } from '../../components/Icons';
import { PromptDialog, useConfirm } from '../../components/Modal';
import { Button, ErrorBox } from '../../components/ui';
import { useAsync } from '../../hooks/useAsync';
import { bytes, dateTime } from '../../lib/format';
import { errMsg, useToast } from '../../state/toast';
import type { TabProps } from './DeviceDetail';

const isWin = (p: string) => /^[A-Za-z]:/.test(p) || p.includes('\\');
const sep = (p: string) => (isWin(p) ? '\\' : '/');

function join(dir: string, name: string): string {
  if (!dir) return name;
  const s = sep(dir);
  return dir.endsWith(s) ? dir + name : dir + s + name;
}

function crumbs(path: string): { label: string; path: string }[] {
  if (!path) return [];
  if (isWin(path)) {
    const parts = path.split(/[\\/]+/).filter(Boolean);
    const out: { label: string; path: string }[] = [];
    let acc = '';
    parts.forEach((p, i) => {
      acc = i === 0 ? `${p}\\` : join(acc, p);
      out.push({ label: i === 0 ? `${p}\\` : p, path: acc });
    });
    return out;
  }
  const parts = path.split('/').filter(Boolean);
  const out = [{ label: '/', path: '/' }];
  let acc = '';
  for (const p of parts) {
    acc += `/${p}`;
    out.push({ label: p, path: acc });
  }
  return out;
}

export function Files({ agent, canWrite }: TabProps) {
  const toast = useToast();
  const confirm = useConfirm();
  const [path, setPath] = useState('');
  const [pathInput, setPathInput] = useState('');
  const [q, setQ] = useState('');
  const listing = useAsync((signal) => api.fsList(agent.id, path, signal), [agent.id, path]);
  const [dialog, setDialog] = useState<{ kind: 'mkdir' } | { kind: 'rename'; entry: FsEntry } | null>(null);
  const [uploading, setUploading] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const cur = listing.data?.path ?? path;
  const rows = useMemo(() => (listing.data?.entries ?? []).filter((e) => textMatch(q, e.name)), [listing.data, q]);

  const go = (p: string) => {
    setPath(p);
    setPathInput(p);
    setQ('');
  };

  const upload = async (file: File) => {
    if (!cur) return toast.warning('Open a folder first');
    const dest = join(cur, file.name);
    setUploading(file.name);
    try {
      await api.fsUpload(agent.id, dest, file);
      toast.success('Uploaded', `${file.name} (${bytes(file.size)})`);
      void listing.reload();
    } catch (err) {
      toast.error('Upload failed', errMsg(err));
    } finally {
      setUploading(null);
    }
  };

  const del = async (e: FsEntry) => {
    if (!(await confirm({ title: e.is_dir ? 'Delete folder' : 'Delete file', message: `Delete "${e.name}"${e.is_dir ? ' and everything inside it' : ''}? This cannot be undone.`, danger: true, confirmLabel: 'Delete' }))) return;
    try {
      await api.fsDelete(agent.id, e.path);
      toast.success(`Deleted ${e.name}`);
      void listing.reload();
    } catch (err) {
      toast.error('Delete failed', errMsg(err));
    }
  };

  const columns: Column<FsEntry>[] = [
    {
      key: 'name',
      header: 'Name',
      sort: (e) => `${e.is_dir ? 0 : 1}|${e.name.toLowerCase()}`,
      render: (e) => (
        <span className="row" style={{ gap: 8, flexWrap: 'nowrap' }}>
          {e.is_dir ? <IconFolder style={{ color: 'var(--warn)' }} /> : <IconFile style={{ color: 'var(--text-faint)' }} />}
          {e.is_dir ? (
            <a
              href="#"
              onClick={(ev) => {
                ev.preventDefault();
                go(e.path);
              }}
            >
              {e.name}
            </a>
          ) : (
            e.name
          )}
        </span>
      ),
    },
    { key: 'size', header: 'Size', align: 'right', sort: (e) => (e.is_dir ? -1 : e.size), render: (e) => (e.is_dir ? <span className="faint">—</span> : bytes(e.size)) },
    { key: 'mtime', header: 'Modified', sort: (e) => e.mtime, render: (e) => <span className="muted">{e.mtime ? dateTime(e.mtime) : '—'}</span> },
    { key: 'mode', header: 'Mode', sort: (e) => e.mode, render: (e) => <span className="mono small muted">{e.mode}</span> },
    {
      key: 'actions',
      header: '',
      render: (e) => (
        <div className="cell-actions">
          {!e.is_dir && (
            <a className="btn xs" href={api.fsDownloadURL(agent.id, e.path)} download={e.name} onClick={(ev) => ev.stopPropagation()} title="Download">
              <IconDownload />
            </a>
          )}
          {canWrite && !!cur && (
            // The roots listing is drives / "/": renaming or deleting one of
            // those is never what an operator means, so the buttons stay hidden there.
            <>
              <Button size="xs" onClick={() => setDialog({ kind: 'rename', entry: e })}>
                Rename
              </Button>
              <Button size="xs" variant="danger" onClick={() => del(e)}>
                Delete
              </Button>
            </>
          )}
        </div>
      ),
    },
  ];

  const bc = crumbs(cur);

  return (
    <>
      <div className="toolbar">
        <form
          className="row"
          style={{ flex: 1, flexWrap: 'nowrap', maxWidth: 640 }}
          onSubmit={(e) => {
            e.preventDefault();
            go(pathInput.trim());
          }}
        >
          <input value={pathInput} placeholder={agent.os === 'windows' ? 'C:\\Users' : '/var/log'} className="mono" onChange={(e) => setPathInput(e.target.value)} aria-label="Path" />
          <Button type="submit">Go</Button>
        </form>
        <Button onClick={() => listing.reload()} busy={listing.loading && !!listing.data} icon aria-label="Refresh">
          <IconRefresh />
        </Button>
        <input type="search" placeholder="Filter…" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 160 }} aria-label="Filter entries" />
        {canWrite && cur && (
          <>
            <Button onClick={() => setDialog({ kind: 'mkdir' })}>
              <IconPlus /> New folder
            </Button>
            <Button onClick={() => fileInput.current?.click()} busy={!!uploading}>
              <IconUpload /> {uploading ? `Uploading ${uploading}…` : 'Upload'}
            </Button>
            <input
              ref={fileInput}
              type="file"
              hidden
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void upload(f);
                e.target.value = '';
              }}
            />
          </>
        )}
      </div>
      <div className="row mb" style={{ gap: 4 }}>
        <a
          href="#"
          onClick={(e) => {
            e.preventDefault();
            go('');
          }}
        >
          {agent.os === 'windows' ? 'Drives' : 'Root'}
        </a>
        {bc.map((c) => (
          <span key={c.path} className="row" style={{ gap: 4 }}>
            <span className="faint">›</span>
            <a
              href="#"
              onClick={(e) => {
                e.preventDefault();
                go(c.path);
              }}
            >
              {c.label}
            </a>
          </span>
        ))}
      </div>
      {listing.error && <ErrorBox error={listing.error} onRetry={listing.reload} />}
      <DataTable
        columns={columns}
        rows={listing.data ? rows : undefined}
        loading={listing.loading}
        rowKey={(e) => e.path}
        defaultSort={{ key: 'name', dir: 'asc' }}
        onRowClick={(e) => e.is_dir && go(e.path)}
        compact
        emptyTitle="Empty folder"
        footer={listing.data && <span>{listing.data.entries.length} entries</span>}
      />
      {dialog?.kind === 'mkdir' && (
        <PromptDialog
          title="New folder"
          label="Folder name"
          confirmLabel="Create"
          onClose={() => setDialog(null)}
          onSubmit={async (name) => {
            if (/[\\/]/.test(name)) return toast.error('Invalid name', 'A folder name cannot contain path separators.');
            try {
              await api.fsMkdir(agent.id, join(cur, name));
              setDialog(null);
              void listing.reload();
            } catch (err) {
              toast.error('Create failed', errMsg(err));
            }
          }}
        />
      )}
      {dialog?.kind === 'rename' && (
        <PromptDialog
          title={`Rename ${dialog.entry.name}`}
          label="New name"
          initial={dialog.entry.name}
          confirmLabel="Rename"
          onClose={() => setDialog(null)}
          onSubmit={async (name) => {
            if (/[\\/]/.test(name)) return toast.error('Invalid name', 'A name cannot contain path separators.');
            if (name === dialog.entry.name) return setDialog(null);
            try {
              await api.fsRename(agent.id, dialog.entry.path, join(cur, name));
              setDialog(null);
              void listing.reload();
            } catch (err) {
              toast.error('Rename failed', errMsg(err));
            }
          }}
        />
      )}
    </>
  );
}
