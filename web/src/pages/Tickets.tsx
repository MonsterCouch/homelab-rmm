import { useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import type { Ticket } from '../api/types';
import { DataTable, textMatch, type Column } from '../components/DataTable';
import { IconPlus, IconRefresh } from '../components/Icons';
import { Modal } from '../components/Modal';
import { Button, Chip, ErrorBox } from '../components/ui';
import { useAsync, useDebounced } from '../hooks/useAsync';
import { relTime } from '../lib/format';
import { useAuth } from '../state/auth';
import { errMsg, useToast } from '../state/toast';

export function Tickets() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();

  const [q, setQ] = useState('');
  const [fStatus, setFStatus] = useState('open');
  const [fPriority, setFPriority] = useState('');
  const [newModal, setNewModal] = useState(false);

  const dq = useDebounced(q);

  const tickets = useAsync(() => api.tickets({ status: fStatus, priority: fPriority }), [fStatus, fPriority]);
  const agents = useAsync(() => api.agents(), []);

  const [form, setForm] = useState({
    subject: '',
    description: '',
    requester_name: user?.username || '',
    requester_email: user?.email || '',
    requester_phone: '',
    priority: 'normal' as 'low' | 'normal' | 'high' | 'urgent',
    agent_id: '',
  });

  const all = tickets.data ?? [];

  const filtered = useMemo(() => {
    return all.filter((t) => {
      return textMatch(dq, t.subject, t.description, t.requester_name, t.requester_email, t.agent_name);
    });
  }, [all, dq]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.subject.trim() || !form.description.trim()) {
      toast.error('Validation error', 'Subject and description are required.');
      return;
    }

    try {
      const created = await api.createTicket(form);
      toast.success('Ticket created', `#${created.id}: ${created.subject}`);
      setNewModal(false);
      setForm({
        subject: '',
        description: '',
        requester_name: user?.username || '',
        requester_email: user?.email || '',
        requester_phone: '',
        priority: 'normal',
        agent_id: '',
      });
      void tickets.reload();
      navigate(`/tickets/${created.id}`);
    } catch (err) {
      toast.error('Failed to create ticket', errMsg(err));
    }
  };

  const columns: Column<Ticket>[] = [
    {
      key: 'id',
      header: '#',
      width: 60,
      sort: (t) => t.id,
      render: (t) => <span className="mono small" style={{ fontWeight: 600 }}>#{t.id}</span>,
    },
    {
      key: 'subject',
      header: 'Subject',
      sort: (t) => t.subject,
      render: (t) => (
        <div>
          <Link to={`/tickets/${t.id}`} style={{ fontWeight: 600 }} onClick={(e) => e.stopPropagation()}>
            {t.subject}
          </Link>
          <div className="muted small" style={{ maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {t.description}
          </div>
        </div>
      ),
    },
    {
      key: 'requester',
      header: 'Requester',
      sort: (t) => t.requester_name,
      render: (t) => (
        <div>
          <div>{t.requester_name}</div>
          {t.requester_email && <div className="muted small">{t.requester_email}</div>}
        </div>
      ),
    },
    {
      key: 'device',
      header: 'Device',
      render: (t) =>
        t.agent_id ? (
          <Link to={`/devices/${t.agent_id}`} className="muted small mono" onClick={(e) => e.stopPropagation()}>
            {t.agent_name || t.agent_id}
          </Link>
        ) : (
          <span className="muted small">—</span>
        ),
    },
    {
      key: 'priority',
      header: 'Priority',
      sort: (t) => t.priority,
      render: (t) => {
        let tone: 'accent' | 'warn' | 'ok' | 'purple' | 'danger' = 'purple';
        if (t.priority === 'urgent') tone = 'danger';
        else if (t.priority === 'high') tone = 'warn';
        else if (t.priority === 'normal') tone = 'accent';
        return <Chip tone={tone}>{t.priority.toUpperCase()}</Chip>;
      },
    },
    {
      key: 'status',
      header: 'Status',
      sort: (t) => t.status,
      render: (t) => {
        let tone: 'accent' | 'warn' | 'ok' | 'purple' | 'danger' = 'warn';
        if (t.status === 'open') tone = 'warn';
        else if (t.status === 'in_progress') tone = 'accent';
        else if (t.status === 'resolved') tone = 'ok';
        else if (t.status === 'closed') tone = 'purple';
        return <Chip tone={tone}>{t.status.replace('_', ' ').toUpperCase()}</Chip>;
      },
    },
    {
      key: 'comments',
      header: 'Replies',
      width: 70,
      render: (t) => <span className="muted small">{t.comments_count || 0}</span>,
    },
    {
      key: 'created_at',
      header: 'Created',
      sort: (t) => t.created_at,
      render: (t) => <span className="muted small">{relTime(t.created_at)}</span>,
    },
  ];

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Helpdesk & Support Tickets</h1>
          <p className="muted small">
            Manage end-user support requests, track hardware and software issues, and collaborate with internal notes.
          </p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button size="sm" onClick={() => tickets.reload()} disabled={tickets.loading} title="Refresh tickets">
            <IconRefresh /> Refresh
          </Button>
          <Button variant="primary" size="sm" onClick={() => setNewModal(true)}>
            <IconPlus /> New Support Ticket
          </Button>
        </div>
      </div>

      {tickets.error && <ErrorBox error={tickets.error} onRetry={tickets.reload} />}

      <div className="toolbar">
        <input
          type="search"
          placeholder="Search ticket subject, requester, device…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          style={{ maxWidth: 300 }}
          aria-label="Search tickets"
        />
        <select
          value={fStatus}
          onChange={(e) => setFStatus(e.target.value)}
          style={{ width: 140 }}
          aria-label="Filter by status"
        >
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="in_progress">In Progress</option>
          <option value="waiting">Waiting on User</option>
          <option value="resolved">Resolved</option>
          <option value="closed">Closed</option>
        </select>
        <select
          value={fPriority}
          onChange={(e) => setFPriority(e.target.value)}
          style={{ width: 140 }}
          aria-label="Filter by priority"
        >
          <option value="">All Priorities</option>
          <option value="low">Low</option>
          <option value="normal">Normal</option>
          <option value="high">High</option>
          <option value="urgent">Urgent</option>
        </select>
        <span className="grow" />
        <span className="muted small">
          {filtered.length} of {all.length} tickets
        </span>
      </div>

      <DataTable
        columns={columns}
        rows={tickets.data ? filtered : undefined}
        loading={tickets.loading}
        rowKey={(t) => String(t.id)}
        defaultSort={{ key: 'created_at', dir: 'desc' }}
        onRowClick={(t) => navigate(`/tickets/${t.id}`)}
        csvName="tickets"
        emptyTitle="No tickets found"
        emptyBody="Create a new ticket or adjust your filters above."
      />

      {newModal && (
        <Modal title="Create Support Ticket" onClose={() => setNewModal(false)}>
          <form onSubmit={handleCreate} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>Subject *</label>
              <input
                type="text"
                required
                value={form.subject}
                onChange={(e) => setForm({ ...form, subject: e.target.value })}
                placeholder="e.g. Outlook crashes on launch, VPN disconnects"
                style={{ width: '100%' }}
              />
            </div>

            <div className="row" style={{ gap: 12 }}>
              <div style={{ flex: 1 }}>
                <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>Requester Name *</label>
                <input
                  type="text"
                  required
                  value={form.requester_name}
                  onChange={(e) => setForm({ ...form, requester_name: e.target.value })}
                  placeholder="Your full name"
                  style={{ width: '100%' }}
                />
              </div>
              <div style={{ flex: 1 }}>
                <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>Requester Email</label>
                <input
                  type="email"
                  value={form.requester_email}
                  onChange={(e) => setForm({ ...form, requester_email: e.target.value })}
                  placeholder="user@example.com"
                  style={{ width: '100%' }}
                />
              </div>
            </div>

            <div className="row" style={{ gap: 12 }}>
              <div style={{ flex: 1 }}>
                <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>Associated Device</label>
                <select
                  value={form.agent_id}
                  onChange={(e) => setForm({ ...form, agent_id: e.target.value })}
                  style={{ width: '100%' }}
                >
                  <option value="">None / General Issue</option>
                  {(agents.data ?? []).map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.display_name} ({a.last_ip})
                    </option>
                  ))}
                </select>
              </div>
              <div style={{ flex: 1 }}>
                <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>Priority</label>
                <select
                  value={form.priority}
                  onChange={(e) => setForm({ ...form, priority: e.target.value as any })}
                  style={{ width: '100%' }}
                >
                  <option value="low">Low</option>
                  <option value="normal">Normal</option>
                  <option value="high">High</option>
                  <option value="urgent">Urgent</option>
                </select>
              </div>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>Issue Description *</label>
              <textarea
                rows={4}
                required
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                placeholder="Provide detailed information about the issue, error messages, and reproduction steps..."
                style={{ width: '100%' }}
              />
            </div>

            <div className="row" style={{ justifyContent: 'flex-end', gap: 8, marginTop: 12 }}>
              <Button variant="ghost" onClick={() => setNewModal(false)}>
                Cancel
              </Button>
              <Button variant="primary" type="submit">
                Submit Ticket
              </Button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}
