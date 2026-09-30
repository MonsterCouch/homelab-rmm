import { useMemo, useState } from 'react';
import { api } from '../api/client';
import type { Agent, Group, Organization, Site, Targets } from '../api/types';
import { useAsync } from '../hooks/useAsync';
import { osLabel } from '../lib/format';
import { textMatch } from './DataTable';
import { Checkbox, OnlineDot } from './ui';

export const EMPTY_TARGETS: Targets = { all: true };

/** Mirror of Targets.Matches in agents_db.go so the picker can preview its reach. */
export function targetsMatch(t: Targets, a: Agent): boolean {
  if (t.os && a.os !== t.os) return false;
  if (t.organizations?.length && (!a.org_id || !t.organizations.includes(a.org_id))) {
    return false;
  }
  if (t.sites?.length && (!a.site_id || !t.sites.includes(a.site_id))) {
    return false;
  }
  if (t.all) return true;
  if (t.agents?.includes(a.id)) return true;
  if (a.group_id !== null && a.group_id !== undefined && t.groups?.includes(a.group_id)) return true;
  if (t.tags?.some((want) => a.tags?.some((have) => have.toLowerCase() === want.toLowerCase()))) return true;
  const hasSelector = Boolean(t.agents?.length || t.groups?.length || t.tags?.length);
  if (!hasSelector && Boolean(t.organizations?.length || t.sites?.length)) {
    return true;
  }
  return false;
}

export function targetsSummary(
  t: Targets | undefined,
  agents: Agent[] | undefined,
  groups: Group[] | undefined,
  orgs?: Organization[] | undefined,
  sites?: Site[] | undefined,
): string {
  if (!t) return '—';
  const parts: string[] = [];
  if (t.all) parts.push('All devices');
  else {
    if (t.organizations?.length) {
      const names = t.organizations.map((id) => orgs?.find((o) => o.id === id)?.name ?? id);
      parts.push(`client ${names.join(', ')}`);
    }
    if (t.sites?.length) {
      const names = t.sites.map((id) => sites?.find((s) => s.id === id)?.name ?? id);
      parts.push(`branch ${names.join(', ')}`);
    }
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

type TargetTab = 'devices' | 'orgs' | 'sites' | 'groups' | 'tags';

export function TargetPicker({ value, onChange, agents, groups, disabled, noAll }: Props) {
  const [q, setQ] = useState('');
  const [activeTab, setActiveTab] = useState<TargetTab>('devices');

  const orgsAsync = useAsync(api.organizations, []);
  const sitesAsync = useAsync(api.allSites, []);
  const orgs = orgsAsync.data ?? [];
  const sites = sitesAsync.data ?? [];

  const tags = useMemo(() => Array.from(new Set(agents.flatMap((a) => a.tags))).sort(), [agents]);
  const matched = useMemo(() => agents.filter((a) => targetsMatch(value, a)), [agents, value]);
  const filtered = useMemo(
    () =>
      agents.filter(
        (a) =>
          (!value.os || a.os === value.os) &&
          textMatch(q, a.display_name, a.hostname, a.last_ip, a.group_name, a.org_name, a.site_name, ...a.tags),
      ),
    [agents, q, value.os],
  );

  const set = (patch: Partial<Targets>) => onChange({ ...value, ...patch });
  const toggleIn = <K extends 'agents' | 'groups' | 'tags' | 'organizations' | 'sites'>(
    key: K,
    item: NonNullable<Targets[K]>[number],
  ) => {
    const list = (value[key] ?? []) as unknown[];
    const next = list.includes(item) ? list.filter((x) => x !== item) : [...list, item];
    set({ [key]: next } as Partial<Targets>);
  };

  const agentCount = value.agents?.length ?? 0;
  const orgCount = value.organizations?.length ?? 0;
  const siteCount = value.sites?.length ?? 0;
  const groupCount = value.groups?.length ?? 0;
  const tagCount = value.tags?.length ?? 0;

  return (
    <div className="stack" style={{ gap: 10 }}>
      {/* Top OS selector and target mode */}
      <div className="row between" style={{ padding: '8px 12px', background: 'var(--bg-subtle)', borderRadius: 6, border: '1px solid var(--border)' }}>
        <div className="row" style={{ gap: 16 }}>
          {!noAll && (
            <label className="row" style={{ gap: 6, cursor: 'pointer', fontWeight: value.all ? 600 : 400 }}>
              <input type="radio" name="tgt-mode" checked={value.all} disabled={disabled} onChange={() => set({ all: true })} /> All devices
            </label>
          )}
          <label className="row" style={{ gap: 6, cursor: 'pointer', fontWeight: !value.all ? 600 : 400 }}>
            <input type="radio" name="tgt-mode" checked={!value.all} disabled={disabled} onChange={() => set({ all: false })} /> Filter by Clients, Branches, Groups, Tags, or Devices
          </label>
        </div>
        <label className="row" style={{ gap: 8, alignItems: 'center' }}>
          <span className="muted small" style={{ fontWeight: 600 }}>Target OS:</span>
          <select
            value={value.os ?? ''}
            disabled={disabled}
            onChange={(e) => set({ os: e.target.value || undefined })}
            style={{ width: 130, padding: '3px 8px', fontWeight: 500 }}
          >
            <option value="">Cross-Platform</option>
            <option value="windows">Windows Only</option>
            <option value="linux">Linux Only</option>
          </select>
        </label>
      </div>

      {!value.all && (
        <div className="stack" style={{ gap: 8 }}>
          {/* Sub-scoping Tabs */}
          <div className="row" style={{ gap: 6, borderBottom: '1px solid var(--border)', paddingBottom: 6 }}>
            <button
              type="button"
              className={`chip ${activeTab === 'devices' ? 'active' : ''}`}
              style={{ cursor: 'pointer', padding: '4px 10px', fontSize: 13 }}
              onClick={() => setActiveTab('devices')}
            >
              Individual Devices {agentCount > 0 && <span className="badge" style={{ marginLeft: 6 }}>{agentCount}</span>}
            </button>
            <button
              type="button"
              className={`chip ${activeTab === 'orgs' ? 'active' : ''}`}
              style={{ cursor: 'pointer', padding: '4px 10px', fontSize: 13 }}
              onClick={() => setActiveTab('orgs')}
            >
              Clients / Organizations {orgCount > 0 && <span className="badge" style={{ marginLeft: 6 }}>{orgCount}</span>}
            </button>
            <button
              type="button"
              className={`chip ${activeTab === 'sites' ? 'active' : ''}`}
              style={{ cursor: 'pointer', padding: '4px 10px', fontSize: 13 }}
              onClick={() => setActiveTab('sites')}
            >
              Branches / Sites {siteCount > 0 && <span className="badge" style={{ marginLeft: 6 }}>{siteCount}</span>}
            </button>
            <button
              type="button"
              className={`chip ${activeTab === 'groups' ? 'active' : ''}`}
              style={{ cursor: 'pointer', padding: '4px 10px', fontSize: 13 }}
              onClick={() => setActiveTab('groups')}
            >
              Device Groups {groupCount > 0 && <span className="badge" style={{ marginLeft: 6 }}>{groupCount}</span>}
            </button>
            <button
              type="button"
              className={`chip ${activeTab === 'tags' ? 'active' : ''}`}
              style={{ cursor: 'pointer', padding: '4px 10px', fontSize: 13 }}
              onClick={() => setActiveTab('tags')}
            >
              Device Tags {tagCount > 0 && <span className="badge" style={{ marginLeft: 6 }}>{tagCount}</span>}
            </button>
          </div>

          {/* Active Tab Panel */}
          {activeTab === 'devices' && (
            <div className="card">
              <div className="card-head" style={{ padding: '6px 10px' }}>
                <span>Select Endpoints</span>
                <span className="muted small ml-auto">{agentCount} selected</span>
              </div>
              <div style={{ padding: 6 }}>
                <input type="search" placeholder="Search devices by name, IP, group, client…" value={q} onChange={(e) => setQ(e.target.value)} disabled={disabled} />
              </div>
              <div className="list" style={{ maxHeight: 260, overflow: 'auto' }}>
                {filtered.map((a) => (
                  <label key={a.id} className="list-item" style={{ padding: '6px 10px', cursor: 'pointer' }}>
                    <input type="checkbox" checked={value.agents?.includes(a.id) ?? false} disabled={disabled} onChange={() => toggleIn('agents', a.id)} />
                    <OnlineDot online={a.online} />
                    <span className="grow truncate">
                      {a.display_name} {a.org_name && <span className="muted small">({a.org_name}{a.site_name ? ` · ${a.site_name}` : ''})</span>}
                    </span>
                    <span className="muted small">{osLabel(a.os)}</span>
                  </label>
                ))}
                {!filtered.length && <div className="muted small" style={{ padding: 12 }}>No devices match the criteria</div>}
              </div>
            </div>
          )}

          {activeTab === 'orgs' && (
            <div className="card">
              <div className="card-head" style={{ padding: '6px 10px' }}>
                <span>Target Entire Clients / Organizations</span>
                <span className="muted small ml-auto">{orgCount} selected</span>
              </div>
              <div className="list" style={{ maxHeight: 260, overflow: 'auto' }}>
                {orgs.map((o) => (
                  <label key={o.id} className="list-item" style={{ padding: '6px 10px', cursor: 'pointer' }}>
                    <input type="checkbox" checked={value.organizations?.includes(o.id) ?? false} disabled={disabled} onChange={() => toggleIn('organizations', o.id)} />
                    <span className="grow truncate" style={{ fontWeight: 500 }}>{o.name}</span>
                    <span className="muted small">{o.device_count ?? 0} {(o.device_count ?? 0) === 1 ? 'device' : 'devices'}</span>
                  </label>
                ))}
                {!orgs.length && <div className="muted small" style={{ padding: 12 }}>No organizations created yet</div>}
              </div>
            </div>
          )}

          {activeTab === 'sites' && (
            <div className="card">
              <div className="card-head" style={{ padding: '6px 10px' }}>
                <span>Target Specific Branches / Sites</span>
                <span className="muted small ml-auto">{siteCount} selected</span>
              </div>
              <div className="list" style={{ maxHeight: 260, overflow: 'auto' }}>
                {sites.map((s) => (
                  <label key={s.id} className="list-item" style={{ padding: '6px 10px', cursor: 'pointer' }}>
                    <input type="checkbox" checked={value.sites?.includes(s.id) ?? false} disabled={disabled} onChange={() => toggleIn('sites', s.id)} />
                    <span className="grow truncate" style={{ fontWeight: 500 }}>{s.name}</span>
                    <span className="muted small">{s.device_count ?? 0} {(s.device_count ?? 0) === 1 ? 'device' : 'devices'}</span>
                  </label>
                ))}
                {!sites.length && <div className="muted small" style={{ padding: 12 }}>No sites created yet</div>}
              </div>
            </div>
          )}

          {activeTab === 'groups' && (
            <div className="card">
              <div className="card-head" style={{ padding: '6px 10px' }}>
                <span>Target Device Groups</span>
                <span className="muted small ml-auto">{groupCount} selected</span>
              </div>
              <div className="list" style={{ maxHeight: 260, overflow: 'auto' }}>
                {groups.map((g) => (
                  <label key={g.id} className="list-item" style={{ padding: '6px 10px', cursor: 'pointer' }}>
                    <input type="checkbox" checked={value.groups?.includes(g.id) ?? false} disabled={disabled} onChange={() => toggleIn('groups', g.id)} />
                    <span className="grow truncate" style={{ fontWeight: 500 }}>{g.name}</span>
                    <span className="muted small">{g.agent_count} {g.agent_count === 1 ? 'device' : 'devices'}</span>
                  </label>
                ))}
                {!groups.length && <div className="muted small" style={{ padding: 12 }}>No groups yet</div>}
              </div>
            </div>
          )}

          {activeTab === 'tags' && (
            <div className="card">
              <div className="card-head" style={{ padding: '6px 10px' }}>
                <span>Target Device Tags</span>
                <span className="muted small ml-auto">{tagCount} selected</span>
              </div>
              <div className="list" style={{ maxHeight: 260, overflow: 'auto' }}>
                {tags.map((t) => (
                  <label key={t} className="list-item" style={{ padding: '6px 10px', cursor: 'pointer' }}>
                    <input type="checkbox" checked={value.tags?.includes(t) ?? false} disabled={disabled} onChange={() => toggleIn('tags', t)} />
                    <span className="grow truncate" style={{ fontWeight: 500 }}>{t}</span>
                  </label>
                ))}
                {!tags.length && <div className="muted small" style={{ padding: 12 }}>No tags in use</div>}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Real-time match summary */}
      <div className="muted small" style={{ padding: '4px 8px', background: 'var(--bg-subtle)', borderRadius: 4 }}>
        Currently matches <b>{matched.length}</b> of {agents.length} total endpoints
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
