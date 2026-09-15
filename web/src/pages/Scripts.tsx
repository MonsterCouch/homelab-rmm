import { useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import type { Script } from '../api/types';
import { DataTable, textMatch, type Column } from '../components/DataTable';
import { IconPlus, IconRuns } from '../components/Icons';
import { useConfirm } from '../components/Modal';
import { RunDialog } from '../components/RunDialog';
import { Button, Chip, ErrorBox } from '../components/ui';
import { useAsync, useDebounced } from '../hooks/useAsync';
import { relTime } from '../lib/format';
import { useAuth } from '../state/auth';
import { errMsg, useToast } from '../state/toast';

export function Scripts() {
  const { canWrite } = useAuth();
  const toast = useToast();
  const confirm = useConfirm();
  const navigate = useNavigate();
  const scripts = useAsync(() => api.scripts(), []);
  const [q, setQ] = useState('');
  const dq = useDebounced(q);
  const [lang, setLang] = useState('');
  const [cat, setCat] = useState('');
  const [run, setRun] = useState<{ script?: Script; adHoc?: boolean } | null>(null);

  const cats = useMemo(() => Array.from(new Set((scripts.data ?? []).map((s) => s.category).filter(Boolean))).sort(), [scripts.data]);
  const rows = useMemo(
    () => (scripts.data ?? []).filter((s) => (!lang || s.language === lang) && (!cat || s.category === cat) && textMatch(dq, s.name, s.description, s.category, s.language)),
    [scripts.data, dq, lang, cat],
  );

  const remove = async (s: Script) => {
    if (!(await confirm({ title: 'Delete script', message: `Delete "${s.name}"? Tasks that reference it will fail until reassigned.`, danger: true, confirmLabel: 'Delete' }))) return;
    try {
      await api.deleteScript(s.id);
      toast.success('Script deleted');
      void scripts.reload();
    } catch (err) {
      toast.error('Delete failed', errMsg(err));
    }
  };

  const columns: Column<Script>[] = [
    {
      key: 'name',
      header: 'Name',
      sort: (s) => s.name,
      render: (s) => (
        <div>
          <Link to={`/scripts/${s.id}`} style={{ fontWeight: 500 }} onClick={(e) => e.stopPropagation()}>
            {s.name}
          </Link>
          {s.description && <div className="muted small truncate" style={{ maxWidth: 480 }}>{s.description}</div>}
        </div>
      ),
    },
    { key: 'cat', header: 'Category', sort: (s) => s.category, render: (s) => s.category || <span className="faint">—</span> },
    { key: 'lang', header: 'Language', sort: (s) => s.language, render: (s) => <Chip outline>{s.language}</Chip> },
    { key: 'os', header: 'OS', sort: (s) => s.os_filter, render: (s) => (s.os_filter ? <Chip tone={s.os_filter === 'windows' ? 'accent' : 'warn'}>{s.os_filter}</Chip> : <span className="muted">any</span>) },
    { key: 'params', header: 'Params', align: 'right', sort: (s) => s.params.length, render: (s) => s.params.length || <span className="faint">0</span> },
    { key: 'timeout', header: 'Timeout', align: 'right', sort: (s) => s.timeout_sec, render: (s) => `${s.timeout_sec}s` },
    { key: 'updated', header: 'Updated', sort: (s) => s.updated_at, render: (s) => <span className="muted">{relTime(s.updated_at)}</span> },
    {
      key: 'actions',
      header: '',
      render: (s) =>
        canWrite ? (
          <div className="cell-actions">
            <Button size="xs" variant="primary" onClick={() => setRun({ script: s })}>
              <IconRuns /> Run
            </Button>
            <Button size="xs" onClick={() => navigate(`/scripts/${s.id}`)}>
              Edit
            </Button>
            <Button size="xs" variant="danger" onClick={() => remove(s)}>
              Delete
            </Button>
          </div>
        ) : null,
    },
  ];

  return (
    <>
      <div className="page-head">
        <h1>Scripts</h1>
        {canWrite && (
          <>
            <Button onClick={() => setRun({ adHoc: true })}>
              <IconRuns /> Ad hoc run
            </Button>
            <Button variant="primary" onClick={() => navigate('/scripts/new')}>
              <IconPlus /> New script
            </Button>
          </>
        )}
      </div>
      <div className="toolbar">
        <input type="search" placeholder="Search scripts…" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 280 }} aria-label="Search scripts" />
        <select value={lang} onChange={(e) => setLang(e.target.value)} style={{ width: 140 }} aria-label="Language">
          <option value="">Any language</option>
          {['powershell', 'cmd', 'bash', 'sh', 'python'].map((l) => (
            <option key={l} value={l}>
              {l}
            </option>
          ))}
        </select>
        <select value={cat} onChange={(e) => setCat(e.target.value)} style={{ width: 160 }} aria-label="Category">
          <option value="">Any category</option>
          {cats.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <span className="grow" />
        {scripts.data && <span className="muted small">{rows.length} of {scripts.data.length} scripts</span>}
      </div>
      {scripts.error && <ErrorBox error={scripts.error} onRetry={scripts.reload} />}
      <DataTable
        columns={columns}
        rows={scripts.data ? rows : undefined}
        loading={scripts.loading}
        rowKey={(s) => String(s.id)}
        onRowClick={(s) => navigate(`/scripts/${s.id}`)}
        defaultSort={{ key: 'name', dir: 'asc' }}
        emptyTitle={scripts.data?.length ? 'No scripts match' : 'The library is empty'}
        emptyBody={!scripts.data?.length && canWrite ? 'Create a script, or use "Ad hoc run" to execute one without saving.' : undefined}
      />
      {run && <RunDialog onClose={() => setRun(null)} script={run.script} adHoc={run.adHoc} />}
    </>
  );
}
