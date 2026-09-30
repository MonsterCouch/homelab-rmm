import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api } from '../api/client';
import { IconChevronDown } from '../components/Icons';
import { useConfirm } from '../components/Modal';
import { Button, Chip, Dropdown, ErrorBox, Loading } from '../components/ui';
import { useAsync } from '../hooks/useAsync';
import { relTime } from '../lib/format';
import { useAuth } from '../state/auth';
import { errMsg, useToast } from '../state/toast';

export function TicketDetail() {
  const { id = '' } = useParams();
  const ticketId = parseInt(id, 10);
  const navigate = useNavigate();
  const toast = useToast();
  const confirm = useConfirm();
  const { canWrite, isAdmin } = useAuth();

  const [commentBody, setCommentBody] = useState('');
  const [isInternal, setIsInternal] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const ticket = useAsync(() => api.ticket(ticketId), [ticketId]);

  const t = ticket.data;

  const handleAddComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!commentBody.trim()) return;

    try {
      setSubmitting(true);
      await api.addTicketComment(ticketId, {
        body: commentBody.trim(),
        is_internal: isInternal,
      });
      toast.success(isInternal ? 'Internal note added' : 'Reply posted');
      setCommentBody('');
      void ticket.reload();
    } catch (err) {
      toast.error('Failed to add comment', errMsg(err));
    } finally {
      setSubmitting(false);
    }
  };

  const handleStatusChange = async (newStatus: string) => {
    try {
      await api.updateTicket(ticketId, { status: newStatus as any });
      toast.success(`Status updated to ${newStatus}`);
      void ticket.reload();
    } catch (err) {
      toast.error('Failed to update status', errMsg(err));
    }
  };

  const handlePriorityChange = async (newPriority: string) => {
    try {
      await api.updateTicket(ticketId, { priority: newPriority as any });
      toast.success(`Priority updated to ${newPriority}`);
      void ticket.reload();
    } catch (err) {
      toast.error('Failed to update priority', errMsg(err));
    }
  };

  const handleDelete = async () => {
    const ok = await confirm({
      title: `Delete ticket #${ticketId}`,
      message: 'Are you sure you want to permanently delete this ticket and all of its conversation history?',
      danger: true,
      confirmLabel: 'Delete Ticket',
    });
    if (!ok) return;

    try {
      await api.deleteTicket(ticketId);
      toast.success('Ticket deleted');
      navigate('/tickets');
    } catch (err) {
      toast.error('Failed to delete ticket', errMsg(err));
    }
  };

  if (ticket.loading && !t) return <Loading label="Loading ticket..." />;
  if (ticket.error) return <ErrorBox error={ticket.error} onRetry={ticket.reload} />;
  if (!t) return <div className="muted">Ticket not found.</div>;

  return (
    <>
      <div className="page-head" style={{ marginBottom: 12 }}>
        <div className="row" style={{ gap: 10, marginRight: 'auto' }}>
          <Link to="/tickets" className="muted small">
            Tickets
          </Link>
          <span className="faint">/</span>
          <span className="mono small" style={{ fontWeight: 600 }}>#{t.id}</span>
          <h1 style={{ margin: 0, fontSize: 20 }}>{t.subject}</h1>
          <Chip tone={t.status === 'open' ? 'warn' : t.status === 'resolved' ? 'ok' : 'accent'}>
            {t.status.toUpperCase()}
          </Chip>
          <Chip tone={t.priority === 'urgent' ? 'danger' : t.priority === 'high' ? 'warn' : 'accent'}>
            {t.priority.toUpperCase()}
          </Chip>
        </div>

        {canWrite && (
          <div className="row" style={{ gap: 8 }}>
            <Dropdown
              trigger={
                <button className="btn sm">
                  Status: {t.status} <IconChevronDown />
                </button>
              }
            >
              <button onClick={() => handleStatusChange('open')}>Set Open</button>
              <button onClick={() => handleStatusChange('in_progress')}>Set In Progress</button>
              <button onClick={() => handleStatusChange('waiting')}>Set Waiting on User</button>
              <button onClick={() => handleStatusChange('resolved')}>Set Resolved</button>
              <button onClick={() => handleStatusChange('closed')}>Set Closed</button>
            </Dropdown>

            <Dropdown
              trigger={
                <button className="btn sm">
                  Priority: {t.priority} <IconChevronDown />
                </button>
              }
            >
              <button onClick={() => handlePriorityChange('low')}>Low</button>
              <button onClick={() => handlePriorityChange('normal')}>Normal</button>
              <button onClick={() => handlePriorityChange('high')}>High</button>
              <button onClick={() => handlePriorityChange('urgent')}>Urgent</button>
            </Dropdown>

            {isAdmin && (
              <Button size="sm" className="danger" onClick={handleDelete}>
                Delete
              </Button>
            )}
          </div>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) 300px', gap: 20 }}>
        {/* Main Conversation Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Initial Ticket Description Card */}
          <div className="card" style={{ padding: 16, borderRadius: 8, border: '1px solid var(--border)' }}>
            <div className="row" style={{ justifyContent: 'space-between', marginBottom: 8 }}>
              <span style={{ fontWeight: 600 }}>{t.requester_name}</span>
              <span className="muted small">{relTime(t.created_at)}</span>
            </div>
            <div style={{ whiteSpace: 'pre-wrap', lineHeight: 1.5 }}>{t.description}</div>
          </div>

          {/* Timeline of comments */}
          {t.comments.map((c) => (
            <div
              key={c.id}
              className="card"
              style={{
                padding: 14,
                borderRadius: 8,
                border: c.is_internal ? '1px solid var(--border-warn, #e0a800)' : '1px solid var(--border)',
                background: c.is_internal ? 'var(--bg-warn-subtle, rgba(255, 193, 7, 0.08))' : 'var(--card-bg, #fff)',
              }}
            >
              <div className="row" style={{ justifyContent: 'space-between', marginBottom: 6 }}>
                <div className="row" style={{ gap: 8 }}>
                  <span style={{ fontWeight: 600 }}>{c.author}</span>
                  {c.is_internal && <Chip tone="warn">INTERNAL NOTE</Chip>}
                </div>
                <span className="muted small">{relTime(c.created_at)}</span>
              </div>
              <div style={{ whiteSpace: 'pre-wrap', lineHeight: 1.5 }}>{c.body}</div>
            </div>
          ))}

          {/* Add Reply Form */}
          <form onSubmit={handleAddComment} className="card" style={{ padding: 16, borderRadius: 8, border: '1px solid var(--border)' }}>
            <div className="row" style={{ gap: 12, marginBottom: 8 }}>
              <button
                type="button"
                className={`btn sm ${!isInternal ? 'primary' : ''}`}
                onClick={() => setIsInternal(false)}
              >
                Public Reply
              </button>
              {canWrite && (
                <button
                  type="button"
                  className={`btn sm ${isInternal ? 'warn' : ''}`}
                  onClick={() => setIsInternal(true)}
                >
                  Internal Note (Technicians Only)
                </button>
              )}
            </div>

            <textarea
              rows={3}
              required
              value={commentBody}
              onChange={(e) => setCommentBody(e.target.value)}
              placeholder={isInternal ? 'Write an internal note only visible to staff...' : 'Type your reply to the user...'}
              style={{ width: '100%', marginBottom: 10 }}
            />

            <div className="row" style={{ justifyContent: 'flex-end', gap: 8 }}>
              <Button variant="primary" type="submit" disabled={submitting}>
                {submitting ? 'Posting…' : isInternal ? 'Add Internal Note' : 'Send Reply'}
              </Button>
            </div>
          </form>
        </div>

        {/* Sidebar Info Card */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="card" style={{ padding: 16, borderRadius: 8, border: '1px solid var(--border)' }}>
            <h3 style={{ margin: '0 0 12px 0', fontSize: 14, textTransform: 'uppercase', letterSpacing: 0.5 }}>
              Requester Info
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <div>
                <span className="muted small">Name:</span>
                <div>{t.requester_name}</div>
              </div>
              {t.requester_email && (
                <div>
                  <span className="muted small">Email:</span>
                  <div>
                    <a href={`mailto:${t.requester_email}`}>{t.requester_email}</a>
                  </div>
                </div>
              )}
              {t.requester_phone && (
                <div>
                  <span className="muted small">Phone:</span>
                  <div>{t.requester_phone}</div>
                </div>
              )}
            </div>
          </div>

          {t.agent_id && (
            <div className="card" style={{ padding: 16, borderRadius: 8, border: '1px solid var(--border)' }}>
              <h3 style={{ margin: '0 0 12px 0', fontSize: 14, textTransform: 'uppercase', letterSpacing: 0.5 }}>
                Associated Endpoint
              </h3>
              <div>
                <Link to={`/devices/${t.agent_id}`} style={{ fontWeight: 600 }}>
                  {t.agent_name || t.agent_id}
                </Link>
                <div className="mono small muted">{t.agent_id}</div>
              </div>
            </div>
          )}

          <div className="card" style={{ padding: 16, borderRadius: 8, border: '1px solid var(--border)' }}>
            <h3 style={{ margin: '0 0 12px 0', fontSize: 14, textTransform: 'uppercase', letterSpacing: 0.5 }}>
              Ticket Metadata
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 13 }}>
              <div>
                <span className="muted">Created:</span> {relTime(t.created_at)}
              </div>
              <div>
                <span className="muted">Last Updated:</span> {relTime(t.updated_at)}
              </div>
              {t.resolved_at > 0 && (
                <div>
                  <span className="muted">Resolved:</span> {relTime(t.resolved_at)}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
