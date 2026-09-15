import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api } from '../api/client';
import type { Language, Script, ScriptParam } from '../api/types';
import { CodeEditor } from '../components/CodeEditor';
import { IconPlus, IconRuns, IconTrash } from '../components/Icons';
import { useConfirm } from '../components/Modal';
import { RunDialog } from '../components/RunDialog';
import { Button, ErrorBox, Field, Loading } from '../components/ui';
import { useAsync } from '../hooks/useAsync';
import { useAuth } from '../state/auth';
import { errMsg, useToast } from '../state/toast';

const LANGS: { id: Language; label: string; template: string }[] = [
  { id: 'powershell', label: 'PowerShell', template: '# Arguments are available as $args[0], $args[1], ...\nWrite-Output "Hello from $env:COMPUTERNAME"\n' },
  { id: 'cmd', label: 'CMD (batch)', template: '@echo off\nrem Arguments: %1 %2 ...\necho Hello from %COMPUTERNAME%\n' },
  { id: 'bash', label: 'Bash', template: '#!/usr/bin/env bash\nset -euo pipefail\n# Arguments: $1 $2 ...\necho "Hello from $(hostname)"\n' },
  { id: 'sh', label: 'sh (POSIX)', template: '#!/bin/sh\nset -eu\necho "Hello from $(hostname)"\n' },
  { id: 'python', label: 'Python', template: 'import sys, platform\n# Arguments: sys.argv[1:]\nprint("Hello from", platform.node())\n' },
];

const blank = (): Script => ({
  id: 0,
  name: '',
  description: '',
  category: '',
  language: 'powershell',
  body: LANGS[0].template,
  params: [],
  timeout_sec: 300,
  os_filter: '',
  created_at: 0,
  updated_at: 0,
});

export function ScriptEditor() {
  const { id } = useParams();
  const isNew = !id || id === 'new';
  const navigate = useNavigate();
  const toast = useToast();
  const confirm = useConfirm();
  const { canWrite } = useAuth();
  const existing = useAsync(() => api.script(+id!), [id], { enabled: !isNew });
  const [form, setForm] = useState<Script>(blank);
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [runOpen, setRunOpen] = useState(false);

  useEffect(() => {
    if (existing.data) {
      setForm(existing.data);
      setDirty(false);
    }
  }, [existing.data]);

  const upd = (patch: Partial<Script>) => {
    setForm((f) => ({ ...f, ...patch }));
    setDirty(true);
  };

  const save = async (): Promise<Script | null> => {
    setError(null);
    if (!form.name.trim()) {
      setError('Name is required.');
      return null;
    }
    if (!form.body.trim()) {
      setError('The script body is empty.');
      return null;
    }
    const badParam = form.params.find((p) => !p.name.trim());
    if (badParam) {
      setError('Every parameter needs a name.');
      return null;
    }
    setBusy(true);
    try {
      const payload = { ...form, name: form.name.trim(), params: form.params.map((p) => ({ ...p, name: p.name.trim() })) };
      const saved = isNew ? await api.createScript(payload) : await api.updateScript(form.id, payload);
      setForm(saved);
      setDirty(false);
      toast.success(isNew ? 'Script created' : 'Script saved');
      if (isNew) navigate(`/scripts/${saved.id}`, { replace: true });
      return saved;
    } catch (err) {
      setError(errMsg(err));
      return null;
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    if (!(await confirm({ title: 'Delete script', message: `Delete "${form.name}"?`, danger: true, confirmLabel: 'Delete' }))) return;
    try {
      await api.deleteScript(form.id);
      toast.success('Script deleted');
      navigate('/scripts');
    } catch (err) {
      toast.error('Delete failed', errMsg(err));
    }
  };

  const setParam = (i: number, patch: Partial<ScriptParam>) => upd({ params: form.params.map((p, j) => (j === i ? { ...p, ...patch } : p)) });

  if (!isNew && existing.error && !existing.data) return <ErrorBox error={existing.error} onRetry={existing.reload} />;
  if (!isNew && !existing.data) return <Loading />;
  const ro = !canWrite;

  return (
    <>
      <div className="page-head">
        <div className="row" style={{ marginRight: 'auto' }}>
          <Link to="/scripts" className="muted small">
            Scripts
          </Link>
          <span className="faint">/</span>
          <h1>{isNew ? 'New script' : form.name || 'Script'}</h1>
          {dirty && <span className="chip warn">unsaved</span>}
        </div>
        {!isNew && canWrite && (
          <Button onClick={() => setRunOpen(true)} disabled={dirty} title={dirty ? 'Save first' : 'Run this script'}>
            <IconRuns /> Run
          </Button>
        )}
        {!isNew && canWrite && (
          <Button variant="danger" onClick={remove}>
            <IconTrash /> Delete
          </Button>
        )}
        {canWrite && (
          <Button variant="primary" onClick={save} busy={busy} disabled={!dirty && !isNew}>
            {isNew ? 'Create' : 'Save'}
          </Button>
        )}
      </div>
      {error && <div className="form-error" role="alert">{error}</div>}
      <div className="grid" style={{ gridTemplateColumns: '340px 1fr', gap: 16 }}>
        <div className="stack">
          <div className="card">
            <div className="card-body">
              <Field label="Name" htmlFor="sc-name">
                <input id="sc-name" value={form.name} disabled={ro} autoFocus={isNew} onChange={(e) => upd({ name: e.target.value })} />
              </Field>
              <Field label="Description" htmlFor="sc-desc">
                <textarea id="sc-desc" value={form.description} disabled={ro} rows={2} onChange={(e) => upd({ description: e.target.value })} />
              </Field>
              <Field label="Category" htmlFor="sc-cat" hint="Free text, used to group the library.">
                <input id="sc-cat" value={form.category} disabled={ro} placeholder="Maintenance" onChange={(e) => upd({ category: e.target.value })} />
              </Field>
              <div className="form-row">
                <Field label="Language" htmlFor="sc-lang">
                  <select
                    id="sc-lang"
                    value={form.language}
                    disabled={ro}
                    onChange={(e) => {
                      const l = e.target.value as Language;
                      const tpl = LANGS.find((x) => x.id === form.language)?.template;
                      // swap the template only if the body is still the untouched default
                      upd({ language: l, body: form.body === tpl ? LANGS.find((x) => x.id === l)!.template : form.body });
                    }}
                  >
                    {LANGS.map((l) => (
                      <option key={l.id} value={l.id}>
                        {l.label}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="OS filter" htmlFor="sc-os">
                  <select id="sc-os" value={form.os_filter} disabled={ro} onChange={(e) => upd({ os_filter: e.target.value })}>
                    <option value="">Any</option>
                    <option value="windows">Windows only</option>
                    <option value="linux">Linux only</option>
                  </select>
                </Field>
              </div>
              <Field label="Timeout (seconds)" htmlFor="sc-timeout">
                <input id="sc-timeout" type="number" min={5} max={86400} value={form.timeout_sec} disabled={ro} onChange={(e) => upd({ timeout_sec: +e.target.value || 300 })} />
              </Field>
            </div>
          </div>
          <div className="card">
            <div className="card-head">
              Parameters
              {canWrite && (
                <div className="actions">
                  <Button size="sm" onClick={() => upd({ params: [...form.params, { name: '', description: '', default: '', required: false }] })}>
                    <IconPlus /> Add
                  </Button>
                </div>
              )}
            </div>
            <div className="card-body stack">
              {form.params.length === 0 && <span className="muted small">No parameters. Values are passed as positional arguments in this order.</span>}
              {form.params.map((p, i) => (
                <div key={i} className="card" style={{ padding: 10 }}>
                  <div className="row" style={{ flexWrap: 'nowrap', marginBottom: 6 }}>
                    <span className="muted small mono" style={{ width: 24 }}>
                      ${i + 1}
                    </span>
                    <input value={p.name} placeholder="name" disabled={ro} onChange={(e) => setParam(i, { name: e.target.value })} aria-label="Parameter name" />
                    <label className="row small" style={{ gap: 4, whiteSpace: 'nowrap', flexWrap: 'nowrap' }}>
                      <input type="checkbox" checked={p.required} disabled={ro} onChange={(e) => setParam(i, { required: e.target.checked })} /> required
                    </label>
                    {canWrite && (
                      <Button size="sm" icon variant="ghost" aria-label="Remove parameter" onClick={() => upd({ params: form.params.filter((_, j) => j !== i) })}>
                        <IconTrash />
                      </Button>
                    )}
                  </div>
                  <div className="row" style={{ flexWrap: 'nowrap' }}>
                    <input value={p.description} placeholder="description" disabled={ro} onChange={(e) => setParam(i, { description: e.target.value })} aria-label="Parameter description" />
                    <input value={p.default} placeholder="default" disabled={ro} onChange={(e) => setParam(i, { default: e.target.value })} aria-label="Parameter default" style={{ maxWidth: 140 }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
        <div className="stack">
          <Field label="Body" hint="Tab indents, Shift+Tab outdents, Enter keeps indentation.">
            <CodeEditor value={form.body} onChange={(body) => upd({ body })} language={form.language} disabled={ro} minHeight={520} />
          </Field>
        </div>
      </div>
      {runOpen && !isNew && <RunDialog onClose={() => setRunOpen(false)} script={form} />}
    </>
  );
}
