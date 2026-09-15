import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import type { Agent, Group, Metrics, PowerAction } from '../api/types';
import { DataTable, textMatch, type Column } from '../components/DataTable';
import { EnrollDrawer } from '../components/EnrollDrawer';
import { GroupsDialog } from '../components/GroupsDialog';
import { IconLinux, IconPlus, IconRefresh, IconWindows } from '../components/Icons';
import { Modal } from '../components/Modal';
import { PowerDialog } from '../components/PowerDialog';
import { RunDialog } from '../components/RunDialog';
import { Button, Chip, ErrorBox, Field, MiniBar, OnlineDot, TagInput } from '../components/ui';
import { useAsync, useDebounced } from '../hooks/useAsync';
import { useEvents, useLiveReload } from '../hooks/useEvents';
import { memPct, osLabel, relTime } from '../lib/format';
import { useAuth } from '../state/auth';
import { errMsg, useToast } from '../state/toast';

export function OSIcon({ os }: { os: string }) {
  if (os === 'windows') return <IconWindows style={{ color: 'var(--accent)' }} />;
  if (os === 'linux') return <IconLinux style={{ color: 'var(--warn)' }} />;
  return null;
}

function diskMax(m: Metrics | undefined): number | undefined {
  if (!m?.disks?.length) return undefined;
  return Math.max(...m.disks.map((d) => d.used_pct));
}

export function Devices() {
  const { canWrite } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const agents = useAsync(() => api.agents(), []);
  const groups = useAsync(() => api.groups(), []);
  useLiveReload(['agent_online', 'agent_offline', 'inventory', 'alert', 'patches', 'hello'], agents.reload, { debounceMs: 800 });

  // Metrics arrive per agent a few times a minute; patch the row in place
  // rather than refetching the whole list.
  useEvents(['metrics'], (ev) => {
    const m = ev.data as Metrics | undefined;
    if (!ev.agent_id || !m) return;
    agents.setData((list) => list?.map((a) => (a.id === ev.agent_id ? { ...a, last_metrics: m, online: true, pending_reboot: m.pending_reboot } : a)));
  });

  const q = params.get('q') ?? '';
  const dq = useDebounced(q, 150);
  const fGroup = params.get('group') ?? '';
  const fOS = params.get('os') ?? '';
  const fOnline = params.get('online') ?? '';
  const fTag = params.get('tag') ?? '';
  const setParam = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setParams(next, { replace: true });
  };

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [enroll, setEnroll] = useState(params.get('enroll') === '1');
  const [groupsOpen, setGroupsOpen] = useState(false);
  const [runOpen, setRunOpen] = useState(false);
  const [bulkEdit, setBulkEdit] = useState(false);
  const [power, setPower] = useState<PowerAction | null>(null);

  useEffect(() => {
    if (params.get('enroll') === '1') {
      setEnroll(true);
      setParam('enroll', '');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const tags = useMemo(() => Array.from(new Set((agents.data ?? []).flatMap((a) => a.tags))).sort(), [agents.data]);

  const rows = useMemo(() => {
    let list = agents.data ?? [];
    if (fGroup) list = list.filter((a) => (fGroup === 'none' ? a.group_id === null : String(a.group_id) === fGroup));
    if (fOS) list = list.filter((a) => a.os === fOS);
    if (fOnline) list = list.filter((a) => (fOnline === '1' ? a.online : !a.online));
    if (fTag) list = list.filter((a) => a.tags.includes(fTag));
    if (dq) list = list.filter((a) => textMatch(dq, a.display_name, a.hostname, a.last_ip, a.platform, a.group_name, ...a.tags));
    return list;
  }, [agents.data, fGroup, fOS, fOnline, fTag, dq]);

  // drop selections that are no longer in the list (deleted devices)
  useEffect(() => {
    if (!agents.data) return;
    const ids = new Set(agents.data.map((a) => a.id));
    setSelected((s) => {
      const next = new Set([...s].filter((id) => ids.has(id)));
      return next.size === s.size ? s : next;
    });
  }, [agents.data]);

  const selectedAgents = useMemo(() => (agents.data ?? []).filter((a) => selected.has(a.id)), [agents.data, selected]);

  const bulkScan = async () => {
    const online = selectedAgents.filter((a) => a.online);
    if (!online.length) return toast.warning('No online devices selected');
    toast.info(`Scanning ${online.length} device(s) for patches…`);
    const res = await Promise.allSettled(online.map((a) => api.patchScan(a.id)));
    const failed = res.filter((r) => r.status === 'rejected').length;
    if (failed) toast.warning('Patch scan finished', `${failed} of ${online.length} failed`);
    else toast.success('Patch scan finished', `${online.length} device(s)`);
    void agents.reload();
  };

  const bulkPower = async (delay: number, message: string) => {
    if (!power) return;
    const online = selectedAgents.filter((a) => a.online);
    const res = await Promise.allSettled(online.map((a) => api.power(a.id, power, delay, message)));
    const failed = res.filter((r) => r.status === 'rejected').length;
    if (failed) toast.warning(`${power} sent`, `${online.length - failed} ok, ${failed} failed`);
    else toast.success(`${power} sent to ${online.length} device(s)`);
  };

  const columns: Column<Agent>[] = [
    {
      key: 'status',
      header: '',
      width: 28,
      sort: (a) => (a.online ? 0 : 1),
      render: (a) => <OnlineDot online={a.online} title={a.online ? 'Online' : `Offline · last seen ${relTime(a.last_seen)}`} />,
    },
    {
      key: 'name',
      header: 'Name',
      sort: (a) => a.display_name,
      render: (a) => (
        <div>
          <Link to={`/devices/${a.id}`} style={{ fontWeight: 500 }} onClick={(e) => e.stopPropagation()}>
            {a.display_name}
          </Link>
          {a.display_name !== a.hostname && <span className="muted small"> {a.hostname}</span>}
          {a.pending_reboot && (
            <span style={{ marginLeft: 6 }}>
              <Chip tone="warn">reboot</Chip>
            </span>
          )}
          {a.maintenance_until > Date.now() / 1000 && (
            <span style={{ marginLeft: 6 }}>
              <Chip tone="purple">maintenance</Chip>
            </span>
          )}
        </div>
      ),
    },
    {
      key: 'os',
      header: 'OS',
      sort: (a) => `${a.os} ${a.platform}`,
      render: (a) => (
        <span className="row" style={{ gap: 6, flexWrap: 'nowrap' }}>
          <OSIcon os={a.os} />
          <span className="truncate" style={{ maxWidth: 180 }} title={a.platform}>
            {a.platform || osLabel(a.os)}
          </span>
        </span>
      ),
    },
    { key: 'ip', header: 'IP', sort: (a) => a.last_ip, render: (a) => <span className="mono">{a.last_ip || '—'}</span> },
    { key: 'group', header: 'Group', sort: (a) => a.group_name ?? '', render: (a) => a.group_name || <span className="faint">—</span> },
    {
      key: 'tags',
      header: 'Tags',
      sort: (a) => a.tags.join(','),
      render: (a) => (
        <span className="tags">
          {a.tags.map((t) => (
            <span
              key={t}
              className="chip outline"
              style={{ cursor: 'pointer' }}
              onClick={(e) => {
                e.stopPropagation();
                setParam('tag', t);
              }}
            >
              {t}
            </span>
          ))}
        </span>
      ),
    },
    { key: 'cpu', header: 'CPU', sort: (a) => a.last_metrics?.cpu ?? -1, render: (a) => <MiniBar value={a.online ? a.last_metrics?.cpu : undefined} /> },
    {
      key: 'mem',
      header: 'Memory',
      sort: (a) => memPct(a.last_metrics?.mem_used, a.last_metrics?.mem_total) ?? -1,
      render: (a) => <MiniBar value={a.online ? memPct(a.last_metrics?.mem_used, a.last_metrics?.mem_total) : undefined} />,
    },
    { key: 'disk', header: 'Disk', sort: (a) => diskMax(a.last_metrics) ?? -1, render: (a) => <MiniBar value={diskMax(a.last_metrics)} title="Fullest volume" /> },
    {
      key: 'alerts',
      header: 'Alerts',
      align: 'right',
      sort: (a) => a.open_alerts,
      render: (a) => (a.open_alerts ? <span className="badge">{a.open_alerts}</span> : <span className="faint">0</span>),
    },
    {
      key: 'patches',
      header: 'Patches',
      align: 'right',
      sort: (a) => a.patches_available,
      render: (a) => (a.patches_available ? <span className="badge muted">{a.patches_available}</span> : <span className="faint">0</span>),
    },
    { key: 'seen', header: 'Last seen', sort: (a) => a.last_seen, render: (a) => <span className="muted">{a.online ? 'now' : relTime(a.last_seen)}</span> },
  ];

  return (
    <>
      <div className="page-head">
        <h1>Devices</h1>
        <Button onClick={() => agents.reload()} icon title="Refresh" aria-label="Refresh">
          <IconRefresh />
        </Button>
        <Button onClick={() => setGroupsOpen(true)}>Groups</Button>
        {canWrite && (
          <Button variant="primary" onClick={() => setEnroll(true)}>
            <IconPlus /> Enrol device
          </Button>
        )}
      </div>
      {agents.error && <ErrorBox error={agents.error} onRetry={agents.reload} />}
      <div className="toolbar">
        <input type="search" placeholder="Search name, IP, tag…" value={q} onChange={(e) => setParam('q', e.target.value)} style={{ maxWidth: 280 }} aria-label="Search devices" />
        <select value={fOnline} onChange={(e) => setParam('online', e.target.value)} style={{ width: 130 }} aria-label="Status filter">
          <option value="">Any status</option>
          <option value="1">Online</option>
          <option value="0">Offline</option>
        </select>
        <select value={fOS} onChange={(e) => setParam('os', e.target.value)} style={{ width: 130 }} aria-label="OS filter">
          <option value="">Any OS</option>
          <option value="windows">Windows</option>
          <option value="linux">Linux</option>
        </select>
        <select value={fGroup} onChange={(e) => setParam('group', e.target.value)} style={{ width: 160 }} aria-label="Group filter">
          <option value="">Any group</option>
          <option value="none">No group</option>
          {(groups.data ?? []).map((g) => (
            <option key={g.id} value={g.id}>
              {g.name}
            </option>
          ))}
        </select>
        <select value={fTag} onChange={(e) => setParam('tag', e.target.value)} style={{ width: 150 }} aria-label="Tag filter">
          <option value="">Any tag</option>
          {tags.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        {(q || fGroup || fOS || fOnline || fTag) && (
          <Button variant="ghost" size="sm" onClick={() => setParams({}, { replace: true })}>
            Clear filters
          </Button>
        )}
        <span className="grow" />
        {selected.size > 0 && canWrite && (
          <div className="row">
            <span className="muted small">{selected.size} selected</span>
            <Button size="sm" onClick={() => setRunOpen(true)}>
              Run script
            </Button>
            <Button size="sm" onClick={bulkScan}>
              Patch scan
            </Button>
            <Button size="sm" onClick={() => setPower('reboot')}>
              Reboot
            </Button>
            <Button size="sm" onClick={() => setBulkEdit(true)}>
              Set group / tags
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>
              Clear
            </Button>
          </div>
        )}
      </div>
      <DataTable
        columns={columns}
        rows={agents.data ? rows : undefined}
        loading={agents.loading}
        rowKey={(a) => a.id}
        onRowClick={(a) => navigate(`/devices/${a.id}`)}
        selectable={canWrite}
        selected={selected}
        onSelect={setSelected}
        defaultSort={{ key: 'status', dir: 'asc' }}
        emptyTitle={agents.data?.length ? 'No devices match these filters' : 'No devices enrolled yet'}
        emptyBody={
          !agents.data?.length && canWrite ? (
            <>
              Click <b>Enrol device</b> to create an install token.
            </>
          ) : undefined
        }
        footer={
          agents.data && (
            <>
              <span>
                {rows.length} of {agents.data.length} devices
              </span>
              <span>{agents.data.filter((a) => a.online).length} online</span>
            </>
          )
        }
      />

      {enroll && <EnrollDrawer onClose={() => setEnroll(false)} groups={groups.data ?? []} />}
      {groupsOpen && (
        <GroupsDialog
          groups={groups.data ?? []}
          canWrite={canWrite}
          onClose={() => setGroupsOpen(false)}
          onChanged={() => {
            void groups.reload();
            void agents.reload();
          }}
        />
      )}
      {runOpen && <RunDialog onClose={() => setRunOpen(false)} agentIds={[...selected]} />}
      {power && <PowerDialog action={power} targetLabel={`${selected.size} device(s)`} onClose={() => setPower(null)} onConfirm={bulkPower} />}
      {bulkEdit && (
        <BulkEditDialog
          agents={selectedAgents}
          groups={groups.data ?? []}
          onClose={() => setBulkEdit(false)}
          onDone={() => {
            setBulkEdit(false);
            void agents.reload();
          }}
        />
      )}
    </>
  );
}

function BulkEditDialog({ agents, groups, onClose, onDone }: { agents: Agent[]; groups: Group[]; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [group, setGroup] = useState<string>('keep');
  const [add, setAdd] = useState<string[]>([]);
  const [remove, setRemove] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const apply = async () => {
    setBusy(true);
    try {
      const res = await Promise.allSettled(
        agents.map((a) => {
          const tags = Array.from(new Set([...a.tags.filter((t) => !remove.includes(t)), ...add]));
          return api.updateAgent(a.id, {
            tags,
            ...(group === 'keep' ? {} : group === 'none' ? { clear_group: true } : { group_id: +group }),
          });
        }),
      );
      const failed = res.filter((r) => r.status === 'rejected');
      if (failed.length) toast.warning('Some updates failed', `${failed.length} of ${agents.length}`);
      else toast.success(`Updated ${agents.length} device(s)`);
      onDone();
    } catch (err) {
      toast.error('Update failed', errMsg(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title={`Edit ${agents.length} device(s)`}
      onClose={onClose}
      size="sm"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={apply} busy={busy}>
            Apply
          </Button>
        </>
      }
    >
      <Field label="Group">
        <select value={group} onChange={(e) => setGroup(e.target.value)}>
          <option value="keep">Keep current group</option>
          <option value="none">Remove from group</option>
          {groups.map((g) => (
            <option key={g.id} value={g.id}>
              {g.name}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Add tags">
        <TagInput value={add} onChange={setAdd} placeholder="type a tag, press Enter" />
      </Field>
      <Field label="Remove tags">
        <TagInput value={remove} onChange={setRemove} placeholder="tags to remove" suggestions={Array.from(new Set(agents.flatMap((a) => a.tags)))} />
      </Field>
    </Modal>
  );
}
