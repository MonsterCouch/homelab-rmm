import { useState } from 'react';
import { api } from '../../api/client';
import type { EventLogEntry } from '../../api/types';
import { IconRefresh } from '../../components/Icons';
import { Button, Chip, Empty, ErrorBox, Skeleton } from '../../components/ui';
import { useAsync } from '../../hooks/useAsync';
import { dateTime } from '../../lib/format';
import type { TabProps } from './DeviceDetail';

const WIN_LOGS = ['System', 'Application', 'Security', 'Setup'];
const LINUX_LOGS = [
  { value: '', label: 'journal (all)' },
  { value: 'kernel', label: 'kernel' },
];

function levelTone(l: string): 'danger' | 'warn' | 'info' | '' {
  const v = l.toLowerCase();
  if (v.startsWith('err') || v === 'critical' || v === 'crit' || v === 'alert' || v === 'emerg') return 'danger';
  if (v.startsWith('warn')) return 'warn';
  if (v === 'info' || v === 'information' || v === 'notice') return 'info';
  return '';
}

export function EventLog({ agent }: TabProps) {
  const win = agent.os === 'windows';
  const [log, setLog] = useState(win ? 'System' : '');
  const [customLog, setCustomLog] = useState('');
  const [level, setLevel] = useState('all');
  const [limit, setLimit] = useState(200);
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState({ log: win ? 'System' : '', level: 'all', limit: 200, search: '' });
  const [open, setOpen] = useState<Set<number>>(new Set());

  const entries = useAsync((signal) => api.eventLog(agent.id, query, signal), [agent.id, query]);

  const run = () => setQuery({ log: log === '__custom' ? customLog.trim() : log, level, limit, search: search.trim() });

  const toggle = (i: number) => {
    setOpen((s) => {
      const n = new Set(s);
      if (n.has(i)) n.delete(i);
      else n.add(i);
      return n;
    });
  };

  return (
    <>
      <form
        className="toolbar"
        onSubmit={(e) => {
          e.preventDefault();
          run();
        }}
      >
        <select value={log} onChange={(e) => setLog(e.target.value)} style={{ width: 170 }} aria-label="Log">
          {win ? WIN_LOGS.map((l) => <option key={l} value={l}>{l}</option>) : LINUX_LOGS.map((l) => <option key={l.value} value={l.value}>{l.label}</option>)}
          <option value="__custom">{win ? 'Other log…' : 'Unit / identifier…'}</option>
        </select>
        {log === '__custom' && (
          <input value={customLog} placeholder={win ? 'Microsoft-Windows-TaskScheduler/Operational' : 'sshd'} onChange={(e) => setCustomLog(e.target.value)} style={{ width: 260 }} aria-label="Custom log name" />
        )}
        <select value={level} onChange={(e) => setLevel(e.target.value)} style={{ width: 120 }} aria-label="Level">
          <option value="all">All levels</option>
          <option value="error">Error</option>
          <option value="warning">Warning</option>
          <option value="info">Info</option>
        </select>
        <input type="search" placeholder="Search message…" value={search} onChange={(e) => setSearch(e.target.value)} style={{ width: 220 }} aria-label="Search" />
        <select value={limit} onChange={(e) => setLimit(+e.target.value)} style={{ width: 90 }} aria-label="Limit">
          {[50, 100, 200, 500, 1000].map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
        <Button type="submit" variant="primary" busy={entries.loading && !!entries.data}>
          <IconRefresh /> Query
        </Button>
        <span className="grow" />
        {entries.data && <span className="muted small">{entries.data.length} entries</span>}
      </form>
      {entries.error && <ErrorBox error={entries.error} onRetry={entries.reload} />}
      <div className="table-wrap">
        {!entries.data ? (
          <Skeleton />
        ) : entries.data.length === 0 ? (
          <Empty title="No entries">Try a different log, level or search.</Empty>
        ) : (
          <table className="tbl compact">
            <thead>
              <tr>
                <th style={{ width: 160 }}>Time</th>
                <th style={{ width: 90 }}>Level</th>
                <th style={{ width: 200 }}>Source</th>
                <th style={{ width: 70 }} className="num">
                  ID
                </th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {entries.data.map((e: EventLogEntry, i) => {
                const isOpen = open.has(i);
                return (
                  <tr key={i} className="clickable" onClick={() => toggle(i)}>
                    <td className="muted nowrap">{dateTime(e.ts)}</td>
                    <td>
                      <Chip tone={levelTone(e.level)}>{e.level || '—'}</Chip>
                    </td>
                    <td className="truncate" style={{ maxWidth: 200 }} title={e.source}>
                      {e.source}
                    </td>
                    <td className="num mono muted">{e.event_id || ''}</td>
                    <td className="wrap" style={{ whiteSpace: isOpen ? 'pre-wrap' : 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 600 }}>
                      {isOpen ? e.message : e.message.split('\n')[0]}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
