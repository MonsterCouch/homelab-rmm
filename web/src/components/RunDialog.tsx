import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import type { Agent, Language, Run, RunEventData, RunScriptInput, Script, Targets } from '../api/types';
import { useAsync } from '../hooks/useAsync';
import { useEvents } from '../hooks/useEvents';
import { elapsed } from '../lib/format';
import { errMsg, useToast } from '../state/toast';
import { CodeEditor } from './CodeEditor';
import { Modal } from './Modal';
import { EMPTY_TARGETS, TargetPicker, targetsMatch } from './TargetPicker';
import { Button, Field, RunStatusChip, Tabs } from './ui';

interface Props {
  onClose: () => void;
  /** preselected library script */
  script?: Script;
  /** preselected device ids (bulk action) */
  agentIds?: string[];
  /** lock to one device (device detail page) */
  agentId?: string;
  /** start in ad hoc mode */
  adHoc?: boolean;
}

interface Result {
  agentId: string;
  name: string;
  runId: string | null;
  error?: string;
  status: string;
  stdout: string;
  stderr: string;
  exitCode?: number;
  startedAt: number;
  finishedAt: number;
}

const LANGS: Language[] = ['powershell', 'cmd', 'bash', 'sh', 'python'];

export function RunDialog({ onClose, script: preset, agentIds, agentId, adHoc }: Props) {
  const toast = useToast();
  const agents = useAsync(() => api.agents(), []);
  const groups = useAsync(() => api.groups(), []);
  const scripts = useAsync(() => api.scripts(), []);

  const [mode, setMode] = useState<'library' | 'adhoc'>(adHoc ? 'adhoc' : 'library');
  const [scriptId, setScriptId] = useState<number | null>(preset?.id ?? null);
  const [scriptQ, setScriptQ] = useState('');
  const [paramValues, setParamValues] = useState<Record<string, string>>({});
  const [language, setLanguage] = useState<Language>('powershell');
  const [body, setBody] = useState('');
  const [timeout, setTimeoutSec] = useState(300);
  const [targets, setTargets] = useState<Targets>(agentIds?.length ? { all: false, agents: agentIds } : agentId ? { all: false, agents: [agentId] } : EMPTY_TARGETS);
  const [starting, setStarting] = useState(false);
  const [results, setResults] = useState<Result[] | null>(null);
  const [outputTab, setOutputTab] = useState<'stdout' | 'stderr'>('stdout');
  const [selected, setSelected] = useState<string | null>(null);

  const script = useMemo(() => (mode === 'library' ? scripts.data?.find((s) => s.id === scriptId) ?? preset ?? null : null), [mode, scripts.data, scriptId, preset]);

  // Reset parameter values to defaults when the script changes.
  useEffect(() => {
    if (!script) return;
    setParamValues(Object.fromEntries(script.params.map((p) => [p.name, p.default ?? ''])));
  }, [script]);

  // pick a sensible default language for a single locked device
  useEffect(() => {
    if (agentId && agents.data) {
      const a = agents.data.find((x) => x.id === agentId);
      if (a?.os === 'linux') setLanguage('bash');
    }
  }, [agentId, agents.data]);

  const filteredScripts = useMemo(() => {
    const list = scripts.data ?? [];
    const q = scriptQ.toLowerCase();
    return q ? list.filter((s) => `${s.name} ${s.category} ${s.language}`.toLowerCase().includes(q)) : list;
  }, [scripts.data, scriptQ]);

  const matched = useMemo(() => (agents.data ?? []).filter((a) => targetsMatch(targets, a)), [agents.data, targets]);

  const missingRequired = script?.params.filter((p) => p.required && !(paramValues[p.name] ?? '').trim()).map((p) => p.name) ?? [];
  const canStart = mode === 'library' ? !!script && missingRequired.length === 0 : body.trim().length > 0;

  const start = async () => {
    if (!canStart || !agents.data) return;
    setStarting(true);
    try {
      const input: RunScriptInput =
        mode === 'library'
          ? { script_id: script!.id, args: script!.params.map((p) => paramValues[p.name] ?? ''), targets }
          : { language, body, timeout_sec: timeout, targets, args: [] };
      const res = await api.runScript(input);
      const list: Result[] = Object.entries(res.runs).map(([id, runId]) => {
        const a = agents.data!.find((x) => x.id === id);
        const isErr = runId.startsWith('error: ') || runId.startsWith('skipped: ');
        return {
          agentId: id,
          name: a?.display_name ?? id,
          runId: isErr ? null : runId,
          error: isErr ? runId : undefined,
          status: isErr ? (runId.startsWith('skipped') ? 'skipped' : 'failed') : 'running',
          stdout: '',
          stderr: '',
          startedAt: Math.floor(Date.now() / 1000),
          finishedAt: 0,
        };
      });
      list.sort((a, b) => a.name.localeCompare(b.name));
      setResults(list);
      setSelected(list.find((r) => r.runId)?.agentId ?? list[0]?.agentId ?? null);
      // Load the initial state of each run: the SSE stream may have started
      // before we subscribed to these ids.
      for (const r of list) {
        if (!r.runId) continue;
        api
          .run(r.runId)
          .then((run) => applyRun(r.agentId, run))
          .catch(() => undefined);
      }
    } catch (err) {
      toast.error('Could not start', errMsg(err));
    } finally {
      setStarting(false);
    }
  };

  const applyRun = (agentIdOf: string, run: Run) => {
    setResults((list) =>
      list?.map((r) =>
        r.agentId === agentIdOf
          ? {
              ...r,
              status: run.status,
              // The stored output is authoritative once the run finished;
              // while running, keep whichever is longer (SSE may be ahead).
              stdout: run.status === 'running' ? (run.stdout && run.stdout.length > r.stdout.length ? run.stdout : r.stdout) : run.stdout ?? r.stdout,
              stderr: run.status === 'running' ? (run.stderr && run.stderr.length > r.stderr.length ? run.stderr : r.stderr) : run.stderr ?? r.stderr,
              exitCode: run.exit_code,
              startedAt: run.started_at || r.startedAt,
              finishedAt: run.finished_at,
            }
          : r,
      ) ?? null,
    );
  };

  useEvents(['run'], (ev) => {
    const d = ev.data as RunEventData | undefined;
    if (!d?.run_id || !results) return;
    const target = results.find((r) => r.runId === d.run_id);
    if (!target) return;
    if (d.stream && d.data !== undefined) {
      setResults((list) =>
        list?.map((r) => (r.runId === d.run_id ? { ...r, [d.stream === 'stderr' ? 'stderr' : 'stdout']: r[d.stream === 'stderr' ? 'stderr' : 'stdout'] + d.data } : r)) ?? null,
      );
    }
    if (d.status) {
      const finished = d.status !== 'running' && d.status !== 'queued' && d.status !== 'pending';
      setResults((list) =>
        list?.map((r) =>
          r.runId === d.run_id ? { ...r, status: d.status!, exitCode: d.exit_code ?? r.exitCode, finishedAt: finished ? Math.floor(Date.now() / 1000) : r.finishedAt } : r,
        ) ?? null,
      );
      // Pull the final stored output so the tail is exact.
      if (finished) api.run(d.run_id).then((run) => applyRun(target.agentId, run)).catch(() => undefined);
    }
  });

  const cancel = async (r: Result) => {
    if (!r.runId) return;
    try {
      await api.cancelRun(r.runId);
      toast.info('Cancel requested', r.name);
    } catch (err) {
      toast.error('Cancel failed', errMsg(err));
    }
  };

  const active = results?.filter((r) => r.status === 'running' || r.status === 'queued') ?? [];
  const sel = results?.find((r) => r.agentId === selected) ?? null;
  const lockedAgent: Agent | undefined = agentId ? agents.data?.find((a) => a.id === agentId) : undefined;

  return (
    <Modal
      title={results ? 'Run results' : mode === 'adhoc' ? 'Run ad hoc script' : `Run script${script ? `: ${script.name}` : ''}`}
      onClose={onClose}
      size="xl"
      footer={
        results ? (
          <>
            {active.length > 0 && (
              <Button variant="danger" onClick={() => active.forEach(cancel)}>
                Cancel all ({active.length})
              </Button>
            )}
            <span className="muted small" style={{ marginRight: 'auto', alignSelf: 'center' }}>
              {results.filter((r) => r.status === 'done').length} done · {results.filter((r) => r.status === 'failed' || r.status === 'timeout').length} failed ·{' '}
              {active.length} running
            </span>
            <Button onClick={onClose}>Close</Button>
          </>
        ) : (
          <>
            <span className="muted small" style={{ marginRight: 'auto', alignSelf: 'center' }}>
              {matched.length} target {matched.length === 1 ? 'device' : 'devices'}
              {missingRequired.length > 0 && <span style={{ color: 'var(--danger)' }}> · missing: {missingRequired.join(', ')}</span>}
            </span>
            <Button onClick={onClose}>Cancel</Button>
            <Button variant="primary" onClick={start} busy={starting} disabled={!canStart || matched.length === 0}>
              Run on {matched.length} {matched.length === 1 ? 'device' : 'devices'}
            </Button>
          </>
        )
      }
    >
      {!results ? (
        <div className="stack" style={{ gap: 14 }}>
          {!preset && (
            <Tabs
              tabs={[
                { id: 'library', label: 'Library script' },
                { id: 'adhoc', label: 'Ad hoc' },
              ]}
              value={mode}
              onChange={setMode}
            />
          )}
          {mode === 'library' ? (
            <div className="grid cols-2" style={{ gap: 16 }}>
              <div>
                {!preset && (
                  <Field label="Script">
                    <input type="search" placeholder="Filter scripts…" value={scriptQ} onChange={(e) => setScriptQ(e.target.value)} style={{ marginBottom: 6 }} />
                    <div className="list card" style={{ maxHeight: 220, overflow: 'auto' }}>
                      {filteredScripts.map((s) => (
                        <label key={s.id} className="list-item" style={{ padding: '6px 10px', cursor: 'pointer' }}>
                          <input type="radio" name="run-script" checked={scriptId === s.id} onChange={() => setScriptId(s.id)} />
                          <span className="grow truncate">
                            {s.name}
                            {s.category && <span className="muted small"> · {s.category}</span>}
                          </span>
                          <span className="chip outline">{s.language}</span>
                        </label>
                      ))}
                      {!filteredScripts.length && (
                        <div className="muted small" style={{ padding: 10 }}>
                          {scripts.loading ? 'Loading…' : 'No scripts. Create one in the library first.'}
                        </div>
                      )}
                    </div>
                  </Field>
                )}
                {script && (
                  <>
                    <dl className="kv small mb">
                      <dt>Language</dt>
                      <dd>{script.language}</dd>
                      <dt>Timeout</dt>
                      <dd>{script.timeout_sec}s</dd>
                      {script.os_filter && (
                        <>
                          <dt>OS</dt>
                          <dd>{script.os_filter} only (others are skipped)</dd>
                        </>
                      )}
                      {script.description && (
                        <>
                          <dt>About</dt>
                          <dd>{script.description}</dd>
                        </>
                      )}
                    </dl>
                    {script.params.length > 0 ? (
                      <>
                        <div className="field-label mb">Parameters</div>
                        {script.params.map((p) => (
                          <Field key={p.name} label={`${p.name}${p.required ? ' *' : ''}`} hint={p.description}>
                            <input value={paramValues[p.name] ?? ''} placeholder={p.default} onChange={(e) => setParamValues((v) => ({ ...v, [p.name]: e.target.value }))} />
                          </Field>
                        ))}
                      </>
                    ) : (
                      <div className="muted small">This script takes no parameters.</div>
                    )}
                  </>
                )}
              </div>
              <div>
                <div className="field-label mb">Targets</div>
                {lockedAgent ? (
                  <div className="chip accent">{lockedAgent.display_name}</div>
                ) : (
                  <TargetPicker value={targets} onChange={setTargets} agents={agents.data ?? []} groups={groups.data ?? []} />
                )}
              </div>
            </div>
          ) : (
            <div className="grid cols-2" style={{ gap: 16 }}>
              <div>
                <div className="form-row">
                  <Field label="Language">
                    <select value={language} onChange={(e) => setLanguage(e.target.value as Language)}>
                      {LANGS.map((l) => (
                        <option key={l} value={l}>
                          {l}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Timeout (seconds)">
                    <input type="number" min={5} max={86400} value={timeout} onChange={(e) => setTimeoutSec(+e.target.value || 300)} />
                  </Field>
                </div>
                <Field label="Script body" hint="Ad hoc bodies are not saved and cannot be queued for offline devices.">
                  <CodeEditor value={body} onChange={setBody} language={language} minHeight={240} placeholder={language === 'powershell' ? 'Get-Service | Where Status -eq Running' : 'uname -a'} />
                </Field>
              </div>
              <div>
                <div className="field-label mb">Targets</div>
                {lockedAgent ? (
                  <div className="chip accent">{lockedAgent.display_name}</div>
                ) : (
                  <TargetPicker value={targets} onChange={setTargets} agents={agents.data ?? []} groups={groups.data ?? []} />
                )}
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="grid" style={{ gridTemplateColumns: '280px 1fr', gap: 12 }}>
          <div className="card list" style={{ maxHeight: 460, overflow: 'auto' }}>
            {results.map((r) => (
              <div
                key={r.agentId}
                className="list-item"
                style={{ cursor: 'pointer', background: r.agentId === selected ? 'var(--accent-soft)' : undefined }}
                onClick={() => setSelected(r.agentId)}
              >
                <div className="grow">
                  <div className="title truncate">{r.name}</div>
                  <div className="sub">{r.error ? r.error : r.finishedAt ? elapsed(r.startedAt, r.finishedAt) : r.status === 'running' ? 'running…' : r.status}</div>
                </div>
                <RunStatusChip status={r.status} />
              </div>
            ))}
          </div>
          <div className="stack" style={{ minWidth: 0 }}>
            {sel ? (
              <>
                <div className="row between">
                  <div className="row">
                    <b>{sel.name}</b>
                    <RunStatusChip status={sel.status} />
                    {sel.exitCode !== undefined && sel.status !== 'running' && <span className="muted small">exit {sel.exitCode}</span>}
                    {sel.runId && (
                      <Link to={`/runs?id=${sel.runId}`} className="small" onClick={onClose}>
                        open in Runs
                      </Link>
                    )}
                  </div>
                  {(sel.status === 'running' || sel.status === 'queued') && (
                    <Button size="sm" variant="danger" onClick={() => cancel(sel)}>
                      Cancel
                    </Button>
                  )}
                </div>
                {sel.error && <div className="banner danger">{sel.error}</div>}
                <Tabs
                  tabs={[
                    { id: 'stdout', label: 'stdout' },
                    { id: 'stderr', label: 'stderr', count: sel.stderr ? sel.stderr.split('\n').length : undefined },
                  ]}
                  value={outputTab}
                  onChange={setOutputTab}
                />
                <OutputPane text={outputTab === 'stdout' ? sel.stdout : sel.stderr} live={sel.status === 'running'} stderr={outputTab === 'stderr'} />
              </>
            ) : (
              <div className="muted">Select a device</div>
            )}
          </div>
        </div>
      )}
    </Modal>
  );
}

/** Monospace output that follows the tail while the run is live. */
export function OutputPane({ text, live, stderr, height = 360 }: { text: string; live?: boolean; stderr?: boolean; height?: number }) {
  const ref = useRef<HTMLPreElement>(null);
  const stick = useRef(true);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (live && stick.current) el.scrollTop = el.scrollHeight;
  }, [text, live]);
  return (
    <pre
      ref={ref}
      className={`output ${stderr ? 'stderr' : ''}`}
      style={{ height, maxHeight: height }}
      onScroll={(e) => {
        const el = e.currentTarget;
        stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
      }}
    >
      {text || <span className="faint">{live ? 'Waiting for output…' : '(no output)'}</span>}
    </pre>
  );
}
