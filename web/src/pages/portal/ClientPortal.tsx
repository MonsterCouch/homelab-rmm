import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { api, ApiError } from '../../api/client';
import type { PortalConfig, PortalSoftwareItem, Ticket, TicketWithComments } from '../../api/types';
import {
  IconBuilding,
  IconCheck,
  IconDevices,
  IconDownload,
  IconPackage,
  IconPlus,
  IconRefresh,
  IconSearch,
  IconTicket,
  IconTrash,
  IconUsers,
} from '../../components/Icons';
import { Modal, useConfirm } from '../../components/Modal';
import { Button, Chip, Empty, Field, Loading } from '../../components/ui';
import { dateTime, relTime } from '../../lib/format';
import { useAuth } from '../../state/auth';
import { errMsg, useToast } from '../../state/toast';

export function ClientPortal() {
  const [params, setParams] = useSearchParams();
  const toast = useToast();
  const confirm = useConfirm();

  // Only a console user viewing the portal for one device sets agent_id. For
  // someone sitting at the device the server already knows the device and
  // the user from their portal sign-in, and ignores anything sent here.
  const agentId = params.get('agent_id') || '';
  const initialTab = params.get('tab') === 'tickets' ? 'tickets' : 'software';

  const [tab, setTab] = useState<'software' | 'tickets'>(initialTab);
  const [config, setConfig] = useState<PortalConfig | null>(null);
  const [loadingConfig, setLoadingConfig] = useState(true);
  const [signedOut, setSignedOut] = useState(false);
  const domainUser = config?.domain_user || '';
  const computer = config?.computer_name || '';
  const isWorkgroup = config?.is_workgroup ?? false;
  // A client contact gets support tickets and nothing else.
  const ticketsOnly = !!config?.is_poc;
  const { logout } = useAuth();
  const navigate = useNavigate();

  // Software state
  const [software, setSoftware] = useState<PortalSoftwareItem[]>([]);
  const [loadingSoftware, setLoadingSoftware] = useState(false);
  const [softwareFilter, setSoftwareFilter] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [runningAction, setRunningAction] = useState<{ id: string; action: string; runId?: string } | null>(null);

  // Tickets state
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [loadingTickets, setLoadingTickets] = useState(false);
  const [ticketFilter, setTicketFilter] = useState('');
  const [ticketStatus, setTicketStatus] = useState<string>('all');
  const [creatingTicket, setCreatingTicket] = useState(params.get('new') === '1');
  const [selectedTicket, setSelectedTicket] = useState<TicketWithComments | null>(null);
  const [loadingTicketDetail, setLoadingTicketDetail] = useState(false);
  const [newComment, setNewComment] = useState('');
  const [postingComment, setPostingComment] = useState(false);

  // Load config on mount
  useEffect(() => {
    let active = true;
    setLoadingConfig(true);
    api.portalConfig({ agent_id: agentId })
      .then((cfg) => {
        if (active) setConfig(cfg);
      })
      .catch((err) => {
        if (err instanceof ApiError && err.status === 401) {
          if (active) setSignedOut(true);
          return;
        }
        console.error('Failed to load portal config:', err);
      })
      .finally(() => {
        if (active) setLoadingConfig(false);
      });
    return () => {
      active = false;
    };
  }, [agentId]);

  // Load software
  const loadSoftware = () => {
    setLoadingSoftware(true);
    api.portalSoftware({ agent_id: agentId })
      .then((list) => setSoftware(list || []))
      .catch((err) => toast.error('Failed to load software', errMsg(err)))
      .finally(() => setLoadingSoftware(false));
  };

  // Load tickets
  const loadTickets = () => {
    setLoadingTickets(true);
    api.portalTickets({
      agent_id: agentId,
      status: ticketStatus !== 'all' ? ticketStatus : undefined,
      q: ticketFilter || undefined,
    })
      .then((list) => setTickets(list || []))
      .catch((err) => toast.error('Failed to load tickets', errMsg(err)))
      .finally(() => setLoadingTickets(false));
  };

  useEffect(() => {
    if (ticketsOnly && tab === 'software') {
      setTab('tickets');
      return;
    }
    if (tab === 'software') {
      loadSoftware();
    } else {
      loadTickets();
    }
  }, [tab, agentId, ticketStatus, ticketsOnly]);

  // Switch tab and sync with URL query
  const switchTab = (newTab: 'software' | 'tickets') => {
    setTab(newTab);
    const nextParams = new URLSearchParams(params);
    nextParams.set('tab', newTab);
    nextParams.delete('new');
    setParams(nextParams, { replace: true });
  };

  // Execute software action (install, update, uninstall)
  const handleSoftwareAction = async (item: PortalSoftwareItem, action: 'install' | 'uninstall' | 'update') => {
    if (action === 'uninstall') {
      const ok = await confirm({
        title: `Uninstall ${item.name}`,
        message: `Are you sure you want to uninstall ${item.name}? Any unsaved work in this application should be saved first.`,
        danger: true,
        confirmLabel: 'Uninstall',
      });
      if (!ok) return;
    }

    setRunningAction({ id: item.id, action });
    try {
      const res = await api.portalSoftwareAction({
        agent_id: agentId || undefined,
        software_id: item.id,
        action,
      });

      toast.info(res.message || `${action} initiated for ${item.name}`);
      setRunningAction({ id: item.id, action, runId: res.run_id });

      // Poll run status
      let consecutiveErrors = 0;
      const pollInterval = window.setInterval(async () => {
        try {
          const run = await api.portalRun(res.run_id);
          consecutiveErrors = 0;
          if (run.status === 'done') {
            window.clearInterval(pollInterval);
            setRunningAction(null);
            if (run.exit_code === 0) {
              toast.success(`${item.name} ${action} completed successfully!`);
              // Optimistically update local software item so button state updates immediately
              setSoftware((prev) =>
                prev.map((s) => {
                  if (s.id !== item.id) return s;
                  if (action === 'uninstall') {
                    return { ...s, installed: false, installed_version: '', has_update: false };
                  }
                  return { ...s, installed: true, has_update: false };
                })
              );
            } else {
              toast.error(`${action} finished with code ${run.exit_code}`, run.stderr || run.stdout || 'Process returned non-zero code');
            }
            loadSoftware();
            window.setTimeout(loadSoftware, 2000);
            window.setTimeout(loadSoftware, 4500);
          } else if (run.status === 'failed' || run.status === 'timeout' || run.status === 'cancelled') {
            window.clearInterval(pollInterval);
            setRunningAction(null);
            toast.error(`${item.name} ${action} failed (code ${run.exit_code})`, run.stderr || run.stdout || 'Execution failed');
            loadSoftware();
          }
        } catch (pollErr) {
          consecutiveErrors++;
          if (consecutiveErrors >= 5) {
            window.clearInterval(pollInterval);
            setRunningAction(null);
            toast.error(`Lost connection checking ${action} status`, errMsg(pollErr));
          }
        }
      }, 2000);

      // Stop polling after 10 minutes max
      window.setTimeout(() => {
        window.clearInterval(pollInterval);
        setRunningAction((cur) => (cur?.runId === res.run_id ? null : cur));
      }, 600000);
    } catch (err) {
      setRunningAction(null);
      toast.error(`${action} failed`, errMsg(err));
    }
  };

  // View ticket details
  const viewTicket = async (ticketId: number) => {
    setLoadingTicketDetail(true);
    try {
      const detail = await api.portalTicket(ticketId);
      setSelectedTicket(detail);
    } catch (err) {
      toast.error('Failed to load ticket details', errMsg(err));
    } finally {
      setLoadingTicketDetail(false);
    }
  };

  // Post comment
  const handleAddComment = async () => {
    if (!selectedTicket || !newComment.trim()) return;
    setPostingComment(true);
    try {
      const added = await api.portalAddComment(selectedTicket.id, { body: newComment.trim() });
      setSelectedTicket({
        ...selectedTicket,
        comments: [...selectedTicket.comments, added],
      });
      setNewComment('');
      toast.success('Reply submitted');
    } catch (err) {
      toast.error('Failed to post comment', errMsg(err));
    } finally {
      setPostingComment(false);
    }
  };

  // Categories
  const categories = useMemo(() => {
    const set = new Set<string>();
    software.forEach((s) => {
      if (s.category) set.add(s.category);
    });
    return Array.from(set).sort();
  }, [software]);

  const filteredSoftware = useMemo(() => {
    return software.filter((item) => {
      const matchCat = selectedCategory === 'all' || item.category === selectedCategory;
      const matchSearch =
        !softwareFilter ||
        item.name.toLowerCase().includes(softwareFilter.toLowerCase()) ||
        item.description.toLowerCase().includes(softwareFilter.toLowerCase()) ||
        item.publisher.toLowerCase().includes(softwareFilter.toLowerCase());
      return matchCat && matchSearch;
    });
  }, [software, selectedCategory, softwareFilter]);

  if (signedOut) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', padding: 24, textAlign: 'center', background: 'var(--bg-app, #0f172a)', color: 'var(--text-main, #f8fafc)' }}>
        <div>
          <h2 style={{ marginBottom: 8 }}>Please reopen this window</h2>
          <p style={{ color: 'var(--text-muted, #94a3b8)' }}>Your support session has ended. Open it again from the Homelab icon next to the clock.</p>
        </div>
      </div>
    );
  }

  if (loadingConfig && !config) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', background: 'var(--bg-app, #0f172a)' }}>
        <Loading label="Connecting to Homelab RMM..." />
      </div>
    );
  }

  return (
    <div className="portal-container" style={{ minHeight: '100vh', background: 'var(--bg-app, #0f172a)', color: 'var(--text-main, #f8fafc)', display: 'flex', flexDirection: 'column' }}>
      {/* Top Client Header */}
      <header
        style={{
          borderBottom: '1px solid var(--border, #334155)',
          background: 'var(--bg-surface, #1e293b)',
          padding: '16px 24px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 16,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div
            style={{
              width: 40,
              height: 40,
              borderRadius: 10,
              background: 'linear-gradient(135deg, #2563eb, #3b82f6)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#ffffff',
              boxShadow: '0 4px 12px rgba(37, 99, 235, 0.3)',
            }}
          >
            <IconPackage width={22} height={22} />
          </div>
          <div>
            <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, letterSpacing: '-0.01em', color: '#ffffff' }}>
              Homelab Self-Service Portal
            </h1>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 4, fontSize: 12, color: 'var(--text-muted, #94a3b8)' }}>
              {(config?.computer_name || computer) && (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                  <IconDevices width={14} height={14} />
                  <b>{config?.computer_name || computer}</b>
                </span>
              )}
              {(domainUser || config?.domain_user || config?.user?.username) && (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                  <IconUsers width={14} height={14} />
                  {domainUser || config?.domain_user || config?.user?.username}
                </span>
              )}
              {config?.org_name && (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                  <IconBuilding width={14} height={14} />
                  {config.org_name}
                </span>
              )}
              {config?.is_poc && (
                <Chip tone="accent">Client contact</Chip>
              )}
            </div>
          </div>
        </div>

        {ticketsOnly && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 13 }}>
            <Link to="/account">My account</Link>
            <Button
              size="sm"
              onClick={async () => {
                await logout();
                navigate('/login', { replace: true });
              }}
            >
              Sign out
            </Button>
          </div>
        )}

        {/* Tab Switcher */}
        <div style={{ display: 'flex', background: 'var(--bg-app, #0f172a)', padding: 4, borderRadius: 8, border: '1px solid var(--border, #334155)' }}>
          {!ticketsOnly && (
          <button
            type="button"
            onClick={() => switchTab('software')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '6px 16px',
              borderRadius: 6,
              border: 'none',
              background: tab === 'software' ? 'var(--accent, #2563eb)' : 'transparent',
              color: tab === 'software' ? '#ffffff' : 'var(--text-muted, #94a3b8)',
              fontWeight: tab === 'software' ? 600 : 500,
              fontSize: 13,
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
          >
            <IconPackage width={16} height={16} />
            Software Drawer
          </button>
          )}
          <button
            type="button"
            onClick={() => switchTab('tickets')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '6px 16px',
              borderRadius: 6,
              border: 'none',
              background: tab === 'tickets' ? 'var(--accent, #2563eb)' : 'transparent',
              color: tab === 'tickets' ? '#ffffff' : 'var(--text-muted, #94a3b8)',
              fontWeight: tab === 'tickets' ? 600 : 500,
              fontSize: 13,
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
          >
            <IconTicket width={16} height={16} />
            Support Tickets
            {tickets.length > 0 && (
              <span style={{ padding: '1px 6px', borderRadius: 10, background: 'rgba(255,255,255,0.2)', fontSize: 11 }}>
                {tickets.length}
              </span>
            )}
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <main style={{ flex: 1, padding: 24, maxWidth: 1200, width: '100%', margin: '0 auto', boxSizing: 'border-box' }}>
        {tab === 'software' && (
          <div>
            {/* Search and Filters Bar */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12, marginBottom: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, maxWidth: 400 }}>
                <div style={{ position: 'relative', width: '100%' }}>
                  <IconSearch width={16} height={16} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted, #94a3b8)' }} />
                  <input
                    type="text"
                    placeholder="Search software catalog..."
                    value={softwareFilter}
                    onChange={(e) => setSoftwareFilter(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '8px 12px 8px 36px',
                      borderRadius: 6,
                      background: 'var(--bg-surface, #1e293b)',
                      border: '1px solid var(--border, #334155)',
                      color: '#ffffff',
                      fontSize: 13,
                      boxSizing: 'border-box',
                    }}
                  />
                </div>
              </div>

              <div style={{ display: 'flex', gap: 8, overflowX: 'auto', paddingBottom: 4 }}>
                <Button
                  size="xs"
                  variant={selectedCategory === 'all' ? 'primary' : 'default'}
                  onClick={() => setSelectedCategory('all')}
                >
                  All Categories
                </Button>
                {categories.map((cat) => (
                  <Button
                    key={cat}
                    size="xs"
                    variant={selectedCategory === cat ? 'primary' : 'default'}
                    onClick={() => setSelectedCategory(cat)}
                  >
                    {cat}
                  </Button>
                ))}
                <Button size="xs" onClick={loadSoftware} busy={loadingSoftware}>
                  <IconRefresh width={14} height={14} /> Refresh
                </Button>
              </div>
            </div>

            {loadingSoftware && software.length === 0 ? (
              <div style={{ padding: 60, textAlign: 'center' }}>
                <Loading />
                <div style={{ marginTop: 12, color: 'var(--text-muted, #94a3b8)' }}>Loading available software...</div>
              </div>
            ) : filteredSoftware.length === 0 ? (
              <Empty title="No software packages found">
                {softwareFilter ? 'No catalog items match your search or filter.' : 'No software packages are currently available for this device.'}
              </Empty>
            ) : (
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
                  gap: 16,
                }}
              >
                {filteredSoftware.map((item) => {
                  const isActing = runningAction?.id === item.id;
                  return (
                    <div
                      key={item.id}
                      style={{
                        background: 'var(--bg-surface, #1e293b)',
                        border: '1px solid var(--border, #334155)',
                        borderRadius: 10,
                        padding: 18,
                        display: 'flex',
                        flexDirection: 'column',
                        justifyContent: 'space-between',
                        boxShadow: '0 2px 8px rgba(0, 0, 0, 0.2)',
                        transition: 'transform 0.15s ease, border-color 0.15s ease',
                      }}
                    >
                      <div>
                        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                            <div
                              style={{
                                width: 44,
                                height: 44,
                                borderRadius: 8,
                                background: item.installed ? 'rgba(16, 185, 129, 0.15)' : 'rgba(37, 99, 235, 0.15)',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                color: item.installed ? '#10b981' : '#3b82f6',
                                flexShrink: 0,
                              }}
                            >
                              <IconPackage width={24} height={24} />
                            </div>
                            <div>
                              <div style={{ fontWeight: 600, fontSize: 15, color: '#ffffff' }}>{item.name}</div>
                              <div style={{ fontSize: 12, color: 'var(--text-muted, #94a3b8)', marginTop: 2 }}>
                                {item.publisher || 'Catalog Package'}
                              </div>
                            </div>
                          </div>

                          {item.installed ? (
                            <Chip tone="ok">
                              <IconCheck width={12} height={12} style={{ marginRight: 4 }} />
                              Installed {item.installed_version ? `(v${item.installed_version})` : ''}
                            </Chip>
                          ) : (
                            <span style={{ fontSize: 11, color: 'var(--text-muted, #94a3b8)', background: 'rgba(255,255,255,0.06)', padding: '2px 8px', borderRadius: 4 }}>
                              Available
                            </span>
                          )}
                        </div>

                        {item.description && (
                          <div style={{ fontSize: 13, color: 'var(--text-muted, #cbd5e1)', marginTop: 12, lineHeight: 1.4 }}>
                            {item.description}
                          </div>
                        )}

                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 12, fontSize: 12, color: 'var(--text-muted, #94a3b8)' }}>
                          {item.category && <span style={{ background: 'var(--bg-app, #0f172a)', padding: '2px 6px', borderRadius: 4 }}>{item.category}</span>}
                          {item.version && <span>Version: {item.version}</span>}
                        </div>
                      </div>

                      {/* Action Buttons */}
                      <div
                        style={{
                          marginTop: 18,
                          paddingTop: 12,
                          borderTop: '1px solid var(--border, #334155)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'flex-end',
                          gap: 8,
                        }}
                      >
                        {isActing ? (
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--accent, #3b82f6)' }}>
                            <span className="spinner" />
                            <span>{runningAction.action === 'install' ? 'Installing…' : runningAction.action === 'update' ? 'Updating…' : 'Uninstalling…'}</span>
                          </div>
                        ) : item.installed ? (
                          <>
                            {item.has_update && (
                              <Button
                                size="xs"
                                variant="primary"
                                onClick={() => handleSoftwareAction(item, 'update')}
                              >
                                <IconDownload width={14} height={14} /> Update
                              </Button>
                            )}
                            <Button
                              size="xs"
                              variant="danger"
                              onClick={() => handleSoftwareAction(item, 'uninstall')}
                            >
                              <IconTrash width={14} height={14} /> Uninstall
                            </Button>
                          </>
                        ) : (
                          <Button
                            size="xs"
                            variant="primary"
                            onClick={() => handleSoftwareAction(item, 'install')}
                          >
                            <IconDownload width={14} height={14} /> Install
                          </Button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {tab === 'tickets' && (
          <div>
            {/* Scoping Explanation Card */}
            <div
              style={{
                background: config?.is_poc ? 'rgba(37, 99, 235, 0.1)' : 'rgba(255, 255, 255, 0.04)',
                border: config?.is_poc ? '1px solid rgba(37, 99, 235, 0.3)' : '1px solid var(--border, #334155)',
                borderRadius: 8,
                padding: '12px 16px',
                marginBottom: 20,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: 12,
              }}
            >
              <div style={{ fontSize: 13, color: 'var(--text-main, #f8fafc)' }}>
                {config?.is_poc ? (
                  <span>
                    🏢 <b>Client contact:</b> You are viewing all support tickets across your organization. (Automated internal alert tickets are hidden.)
                  </span>
                ) : isWorkgroup ? (
                  <span>
                    💻 <b>Workstation Tickets:</b> Scoped to support tickets submitted from this computer (<b>{config?.computer_name || computer}</b>).
                  </span>
                ) : (
                  <span>
                    👤 <b>User Tickets:</b> Scoped to support tickets submitted by <b>{domainUser || config?.domain_user || 'your domain user account'}</b>.
                  </span>
                )}
              </div>

              <Button variant="primary" size="sm" onClick={() => setCreatingTicket(true)}>
                <IconPlus width={16} height={16} /> New Support Ticket
              </Button>
            </div>

            {/* Filter controls */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12, marginBottom: 16 }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', flex: 1, maxWidth: 360 }}>
                <input
                  type="text"
                  placeholder="Search tickets by subject or description..."
                  value={ticketFilter}
                  onChange={(e) => setTicketFilter(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && loadTickets()}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: 6,
                    background: 'var(--bg-surface, #1e293b)',
                    border: '1px solid var(--border, #334155)',
                    color: '#ffffff',
                    fontSize: 13,
                    boxSizing: 'border-box',
                  }}
                />
              </div>

              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <select
                  value={ticketStatus}
                  onChange={(e) => setTicketStatus(e.target.value)}
                  style={{
                    padding: '7px 12px',
                    borderRadius: 6,
                    background: 'var(--bg-surface, #1e293b)',
                    border: '1px solid var(--border, #334155)',
                    color: '#ffffff',
                    fontSize: 13,
                  }}
                >
                  <option value="all">All Statuses</option>
                  <option value="open">Open</option>
                  <option value="in_progress">In Progress</option>
                  <option value="waiting">Waiting on Client</option>
                  <option value="resolved">Resolved</option>
                  <option value="closed">Closed</option>
                </select>

                <Button size="xs" onClick={loadTickets} busy={loadingTickets}>
                  <IconRefresh width={14} height={14} /> Refresh
                </Button>
              </div>
            </div>

            {loadingTickets && tickets.length === 0 ? (
              <div style={{ padding: 60, textAlign: 'center' }}>
                <Loading />
                <div style={{ marginTop: 12, color: 'var(--text-muted, #94a3b8)' }}>Loading support tickets...</div>
              </div>
            ) : tickets.length === 0 ? (
              <Empty title="No support tickets found">
                <div>You haven't submitted any tickets matching the current filter.</div>
                <div style={{ marginTop: 12 }}>
                  <Button variant="primary" onClick={() => setCreatingTicket(true)}>
                    <IconPlus width={16} height={16} /> Submit Your First Ticket
                  </Button>
                </div>
              </Empty>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {tickets.map((t) => (
                  <div
                    key={t.id}
                    onClick={() => viewTicket(t.id)}
                    style={{
                      background: 'var(--bg-surface, #1e293b)',
                      border: '1px solid var(--border, #334155)',
                      borderRadius: 8,
                      padding: 16,
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: 16,
                      transition: 'border-color 0.15s ease, background 0.15s ease',
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.borderColor = 'var(--accent, #2563eb)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.borderColor = 'var(--border, #334155)';
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                      <div
                        style={{
                          width: 36,
                          height: 36,
                          borderRadius: 8,
                          background: 'rgba(37, 99, 235, 0.12)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          color: '#3b82f6',
                          flexShrink: 0,
                        }}
                      >
                        <IconTicket width={20} height={20} />
                      </div>
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{ fontWeight: 600, fontSize: 14, color: '#ffffff' }}>{t.subject}</span>
                          <span style={{ fontSize: 12, color: 'var(--text-muted, #94a3b8)' }}>#{t.id}</span>
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--text-muted, #94a3b8)', marginTop: 4, display: 'flex', gap: 12 }}>
                          <span>Submitted {relTime(t.created_at)}</span>
                          {t.requester_name && <span>By {t.requester_name}</span>}
                          {t.comments_count !== undefined && (
                            <span>💬 {t.comments_count} comment{t.comments_count === 1 ? '' : 's'}</span>
                          )}
                        </div>
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Chip
                        tone={
                          t.priority === 'urgent'
                            ? 'danger'
                            : t.priority === 'high'
                            ? 'warn'
                            : ''
                        }
                      >
                        {t.priority}
                      </Chip>
                      <Chip
                        tone={
                          t.status === 'open'
                            ? 'accent'
                            : t.status === 'in_progress'
                            ? 'info'
                            : t.status === 'resolved' || t.status === 'closed'
                            ? 'ok'
                            : ''
                        }
                      >
                        {t.status.replace('_', ' ')}
                      </Chip>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </main>

      {/* New Ticket Modal */}
      {creatingTicket && (
        <CreateTicketModal
          agentId={agentId || config?.agent_id || ''}
          defaultRequesterName={domainUser || config?.user?.username || ''}
          defaultEmail={config?.user?.email || ''}
          onClose={() => setCreatingTicket(false)}
          onCreated={() => {
            setCreatingTicket(false);
            loadTickets();
          }}
        />
      )}

      {/* Loading Ticket Indicator */}
      {loadingTicketDetail && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)', zIndex: 999, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Loading label="Loading ticket details..." />
        </div>
      )}

      {/* Ticket Details & Conversation Modal */}
      {selectedTicket && (
        <Modal
          title={`Ticket #${selectedTicket.id}: ${selectedTicket.subject}`}
          onClose={() => setSelectedTicket(null)}
          size="lg"
          footer={
            <Button onClick={() => setSelectedTicket(null)}>Close</Button>
          }
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Meta bar */}
            <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap', paddingBottom: 12, borderBottom: '1px solid var(--border, #334155)', fontSize: 13 }}>
              <span>Status: <Chip tone={selectedTicket.status === 'open' ? 'accent' : selectedTicket.status === 'resolved' ? 'ok' : 'info'}>{selectedTicket.status}</Chip></span>
              <span>Priority: <Chip tone={selectedTicket.priority === 'urgent' ? 'danger' : ''}>{selectedTicket.priority}</Chip></span>
              {selectedTicket.requester_name && <span>Requester: <b>{selectedTicket.requester_name}</b></span>}
              <span className="muted">Created: {dateTime(selectedTicket.created_at)}</span>
            </div>

            {/* Initial description */}
            <div style={{ background: 'var(--bg-app, #0f172a)', padding: 14, borderRadius: 8, fontSize: 13, lineHeight: 1.5, color: '#f8fafc', whiteSpace: 'pre-wrap' }}>
              {selectedTicket.description}
            </div>

            {/* Conversation / Comments thread */}
            <div>
              <h4 style={{ margin: '8px 0 12px 0', fontSize: 13, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted, #94a3b8)' }}>
                Activity &amp; Replies ({selectedTicket.comments?.length || 0})
              </h4>

              {selectedTicket.comments && selectedTicket.comments.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {selectedTicket.comments.map((c) => (
                    <div
                      key={c.id}
                      style={{
                        background: 'rgba(255, 255, 255, 0.03)',
                        border: '1px solid var(--border, #334155)',
                        borderRadius: 8,
                        padding: 12,
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontSize: 12 }}>
                        <span style={{ fontWeight: 600, color: 'var(--accent, #3b82f6)' }}>{c.author}</span>
                        <span style={{ color: 'var(--text-muted, #94a3b8)' }}>{relTime(c.created_at)}</span>
                      </div>
                      <div style={{ fontSize: 13, color: '#f8fafc', lineHeight: 1.4, whiteSpace: 'pre-wrap' }}>
                        {c.body}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ fontSize: 13, color: 'var(--text-muted, #94a3b8)', fontStyle: 'italic', padding: 8 }}>
                  No replies on this ticket yet.
                </div>
              )}
            </div>

            {/* Reply Input Box */}
            <div style={{ marginTop: 12, paddingTop: 12, borderTop: '1px solid var(--border, #334155)' }}>
              <Field label="Add a Reply">
                <textarea
                  rows={3}
                  placeholder="Type a message or additional details for the support technician..."
                  value={newComment}
                  onChange={(e) => setNewComment(e.target.value)}
                  style={{ width: '100%', boxSizing: 'border-box' }}
                />
              </Field>
              <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 8 }}>
                <Button variant="primary" size="sm" onClick={handleAddComment} busy={postingComment} disabled={!newComment.trim()}>
                  Post Reply
                </Button>
              </div>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

function CreateTicketModal({
  agentId,
  defaultRequesterName,
  defaultEmail,
  onClose,
  onCreated,
}: {
  agentId: string;
  defaultRequesterName: string;
  defaultEmail: string;
  onClose: () => void;
  onCreated: () => void;
}) {
  const toast = useToast();
  const [subject, setSubject] = useState('');
  const [description, setDescription] = useState('');
  const [priority, setPriority] = useState<string>('normal');
  const [requesterName, setRequesterName] = useState(defaultRequesterName || '');
  const [requesterEmail, setRequesterEmail] = useState(defaultEmail || '');
  const [requesterPhone, setRequesterPhone] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const save = async () => {
    setError(null);
    if (!subject.trim()) return setError('Subject is required.');
    if (!description.trim()) return setError('Description is required.');

    setBusy(true);
    try {
      await api.portalCreateTicket({
        agent_id: agentId,
        subject: subject.trim(),
        description: description.trim(),
        priority,
        requester_name: requesterName.trim() || 'Client User',
        requester_email: requesterEmail.trim(),
        requester_phone: requesterPhone.trim(),
      });
      toast.success('Support ticket submitted successfully!');
      onCreated();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Submit Support Ticket"
      onClose={onClose}
      size="md"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={save} busy={busy}>
            Submit Ticket
          </Button>
        </>
      }
    >
      {error && <div className="form-error" role="alert">{error}</div>}
      <Field label="Subject" hint="A brief summary of your issue or request.">
        <input
          value={subject}
          autoFocus
          placeholder="e.g. Need assistance with Outlook configuration"
          onChange={(e) => setSubject(e.target.value)}
        />
      </Field>
      <Field label="Priority">
        <select value={priority} onChange={(e) => setPriority(e.target.value)}>
          <option value="low">Low (General question / non-urgent request)</option>
          <option value="normal">Normal (Standard issue, work not blocked)</option>
          <option value="high">High (Major issue, productivity affected)</option>
          <option value="urgent">Urgent (System down / complete blocker)</option>
        </select>
      </Field>
      <Field label="Description" hint="Describe the problem, steps to reproduce, or what you need assistance with.">
        <textarea
          rows={4}
          placeholder="Provide as much detail as possible..."
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </Field>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <Field label="Your Name">
          <input
            value={requesterName}
            placeholder="Your full name"
            onChange={(e) => setRequesterName(e.target.value)}
          />
        </Field>
        <Field label="Email Address">
          <input
            type="email"
            value={requesterEmail}
            placeholder="you@company.com"
            onChange={(e) => setRequesterEmail(e.target.value)}
          />
        </Field>
      </div>
      <Field label="Phone (optional)">
        <input
          type="tel"
          value={requesterPhone}
          placeholder="Direct callback number"
          onChange={(e) => setRequesterPhone(e.target.value)}
        />
      </Field>
    </Modal>
  );
}
