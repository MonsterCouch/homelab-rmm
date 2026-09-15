import { useMemo, useState } from 'react';
import type { Agent, Group, Targets } from '../api/types';
import { osLabel } from '../lib/format';
import { textMatch } from './DataTable';
import { Checkbox, OnlineDot } from './ui';

export const EMPTY_TARGETS: Targets = { all: true };

/** Mirror of Targets.Matches in agents_db.go so the picker can preview its reach. */
export function targetsMatch(t: Targets, a: Agent): boolean {
  if (t.os && a.os !== t.os) return false;
  if (t.all) return true;
  if (t.agents?.includes(a.id)) return true;
  if (a.group_id !== null && t.groups?.includes(a.group_id)) return true;
  if (t.tags?.some((want) => a.tags.some((have) => have.toLowerCase() === want.toLowerCase()))) return true;
  return false;
}

export function targetsSummary(t: Targets | undefined, agents: Agent[] | undefined, groups: Group[] | undefined): string {
  if (!t) return '—';
  const parts: string[] = [];
  if (t.all) parts.push('All devices');
  else {
    if (t.agents?.length) {
      const names = t.agents.map((id) => agents?.find((a) => a.id === id)?.display_name ?? id);
      parts.push(names.length <= 2 ? names.join(', ') : `${names.length} devices`);
    }
    if (t.groups?.length) {
      const names = t.groups.map((id) => groups?.find((g) => g.id === id)?.name ?? `#${id}`);
      parts.push(`group ${names.join(', ')}`);
    }
    if (t.tags?.length) parts.push(`tag ${t.tags.join(', ')}`);
    if (!parts.length) parts.push('No targets');
  }
  if (t.os) parts.push(`(${osLabel(t.os)} only)`);
  return parts.join(' · ');
}

interface Props {
  value: Targets;
  onChange: (t: Targets) => void;
  agents: Agent[];
  groups: Group[];
  disabled?: boolean;
  /** hide the "all devices" option (e.g. ad hoc run) */
  noAll?: boolean;
}

export function TargetPicker({ value, onChange, agents, groups, disabled, noAll }: Props) {
  const [q, setQ] = useState('');
  const tags = useMemo(() => Array.from(new Set(agents.flatMap((a) => a.tags))).sort(), [agents]);
  const matched = useMemo(() => agents.filter((a) => targetsMatch(value, a)), [agents, value]);
  const filtered = useMemo(() => agents.filter((a) => textMatch(q, a.display_name, a.hostname, a.last_ip, a.group_name, ...a.tags)), [agents, q]);

  const set = (patch: Partial<Targets>) => onChange({ ...value, ...patch });
  const toggleIn = <K extends 'agents' | 'groups' | 'tags'>(key: K, item: NonNullable<Targets[K]>[number]) => {
    const list = (value[key] ?? []) as unknown[];
    const next = list.includes(item) ? list.filter((x) => x !== item) : [...list, item];
    set({ [key]: next } as Partial<Targets>);
  };

  return (
    <div className="stack" style={{ gap: 8 }}>
      <div className="row between">
        <div className="row">
          {!noAll && (
            <label className="row" style={{ gap: 6, cursor: 'pointer' }}>
              <input type="radio" name="tgt-mode" checked={value.all} disabled={disabled} onChange={() => set({ all: true })} /> All devices
            </label>
          )}
          <label className="row" style={{ gap: 6, cursor: 'pointer' }}>
            <input type="radio" name="tgt-mode" checked={!value.all} disabled={disabled} onChange={() => set({ all: false })} /> Selected devices, groups or tags
          </label>
        </div>
        <label className="row" style={{ gap: 6 }}>
          <span className="muted small">OS</span>
          <select value={value.os ?? ''} disabled={disabled} onChange={(e) => set({ os: e.target.value || undefined })} style={{ width: 120 }}>
            <option value="">Any</option>
            <option value="windows">Windows</option>
            <option value="linux">Linux</option>
          </select>
        </label>
      </div>
      {!value.all && (
        <div className="grid cols-3" style={{ gap: 10 }}>
          <div className="card" style={{ gridColumn: 'span 1' }}>
            <div className="card-head" style={{ padding: '6px 10px' }}>
              <span>Devices</span>
              <span className="muted small ml-auto">{value.agents?.length ?? 0} selected</span>
            </div>
            <div style={{ padding: 6 }}>
              <input type="search" placeholder="Filter devices…" value={q} onChange={(e) => setQ(e.target.value)} disabled={disabled} />
            </div>
            <div className="list" style={{ maxHeight: 220, overflow: 'auto' }}>
              {filtered.map((a) => (
                <label key={a.id} className="list-item" style={{ padding: '5px 10px', cursor: 'pointer' }}>
                  <input type="checkbox" checked={value.agents?.includes(a.id) ?? false} disabled={disabled} onChange={() => toggleIn('agents', a.id)} />
                  <OnlineDot online={a.online} />
                  <span className="grow truncate">{a.display_name}</span>
                  <span className="muted small">{osLabel(a.os)}</span>
                </label>
              ))}
              {!filtered.length && <div className="muted small" style={{ padding: 10 }}>No devices</div>}
            </div>
          </div>
          <div className="card">
            <div className="card-head" style={{ padding: '6px 10px' }}>
              Groups
            </div>
            <div className="list" style={{ maxHeight: 264, overflow: 'auto' }}>
              {groups.map((g) => (
                <label key={g.id} className="list-item" style={{ padding: '5px 10px', cursor: 'pointer' }}>
                  <input type="checkbox" checked={value.groups?.includes(g.id) ?? false} disabled={disabled} onChange={() => toggleIn('groups', g.id)} />
                  <span className="grow truncate">{g.name}</span>
                  <span className="muted small">{g.agent_count}</span>
                </label>
              ))}
              {!groups.length && <div className="muted small" style={{ padding: 10 }}>No groups yet</div>}
            </div>
          </div>
          <div className="card">
            <div className="card-head" style={{ padding: '6px 10px' }}>
              Tags
            </div>
            <div className="list" style={{ maxHeight: 264, overflow: 'auto' }}>
              {tags.map((t) => (
                <label key={t} className="list-item" style={{ padding: '5px 10px', cursor: 'pointer' }}>
                  <input type="checkbox" checked={value.tags?.includes(t) ?? false} disabled={disabled} onChange={() => toggleIn('tags', t)} />
                  <span className="grow truncate">{t}</span>
                </label>
              ))}
              {!tags.length && <div className="muted small" style={{ padding: 10 }}>No tags in use</div>}
            </div>
          </div>
        </div>
      )}
      <div className="muted small">
        Matches <b>{matched.length}</b> of {agents.length} devices
        {matched.length > 0 && matched.length <= 6 && <>: {matched.map((a) => a.display_name).join(', ')}</>}
      </div>
    </div>
  );
}

/** Simple multi-select of devices (bulk actions, ad hoc run). */
export function DeviceMultiSelect({
  agents,
  value,
  onChange,
  osFilter,
}: {
  agents: Agent[];
  value: Set<string>;
  onChange: (v: Set<string>) => void;
  osFilter?: string;
}) {
  const [q, setQ] = useState('');
  const list = agents.filter((a) => (!osFilter || a.os === osFilter) && textMatch(q, a.display_name, a.hostname, a.last_ip, ...a.tags));
  const toggle = (id: string) => {
    const next = new Set(value);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    onChange(next);
  };
  const all = list.length > 0 && list.every((a) => value.has(a.id));
  return (
    <div className="card">
      <div className="row" style={{ padding: 6 }}>
        <input type="search" placeholder="Filter devices…" value={q} onChange={(e) => setQ(e.target.value)} />
        <Checkbox
          checked={all}
          onChange={() => {
            const next = new Set(value);
            if (all) list.forEach((a) => next.delete(a.id));
            else list.forEach((a) => next.add(a.id));
            onChange(next);
          }}
          label="All"
        />
      </div>
      <div className="list" style={{ maxHeight: 240, overflow: 'auto' }}>
        {list.map((a) => (
          <label key={a.id} className="list-item" style={{ padding: '5px 10px', cursor: 'pointer' }}>
            <input type="checkbox" checked={value.has(a.id)} onChange={() => toggle(a.id)} />
            <OnlineDot online={a.online} />
            <span className="grow truncate">{a.display_name}</span>
            <span className="muted small">{a.group_name || osLabel(a.os)}</span>
          </label>
        ))}
        {!list.length && <div className="muted small" style={{ padding: 10 }}>No matching devices</div>}
      </div>
    </div>
  );
}
