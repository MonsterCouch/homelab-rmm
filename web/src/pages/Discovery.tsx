import { useMemo, useState } from 'react';
import { api } from '../api/client';
import type { DiscoveredDevice, NetworkScan } from '../api/types';
import { DataTable, textMatch, type Column } from '../components/DataTable';
import { IconRefresh, IconWifi } from '../components/Icons';
import { Modal, useConfirm } from '../components/Modal';
import { Button, Chip, ErrorBox } from '../components/ui';
import { useAsync, useDebounced } from '../hooks/useAsync';
import { dateTime, relTime } from '../lib/format';
import { useAuth } from '../state/auth';
import { errMsg, useToast } from '../state/toast';

function defaultSubnetForIp(ip: string): string {
  const parts = ip.split('.');
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }
  return '192.168.1.0/24';
}

export function Discovery() {
  const { canWrite } = useAuth();
  const toast = useToast();
  const confirm = useConfirm();

  const [q, setQ] = useState('');
  const [fType, setFType] = useState('');
  const [fStatus, setFStatus] = useState('');
  const [fOrg, setFOrg] = useState('');
  const [scanModal, setScanModal] = useState(false);
  const [probeMode, setProbeMode] = useState<'server' | 'agent'>('agent');
  const [selectedAgentId, setSelectedAgentId] = useState('');
  const [subnetInput, setSubnetInput] = useState('192.168.1.0/24');
  const [selectedDevice, setSelectedDevice] = useState<DiscoveredDevice | null>(null);
  const [pollingId, setPollingId] = useState<string | null>(null);

  const dq = useDebounced(q);

  const devices = useAsync(() => api.discoveredDevices(fOrg, '', fStatus), [fOrg, fStatus]);
  const scans = useAsync(() => api.networkScans(), []);
  const agents = useAsync(() => api.agents(), []);
  const orgs = useAsync(() => api.organizations(), []);
  const sites = useAsync(() => api.allSites(), []);

  const all = devices.data ?? [];

  const orgMap = useMemo(() => new Map((orgs.data ?? []).map((o) => [o.id, o.name])), [orgs.data]);
  const siteMap = useMemo(() => new Map((sites.data ?? []).map((s) => [s.id, s.name])), [sites.data]);
  const agentMap = useMemo(() => new Map((agents.data ?? []).map((a) => [a.id, a])), [agents.data]);

  const onlineAgents = useMemo(() => (agents.data ?? []).filter((a) => a.online), [agents.data]);

  const filtered = useMemo(() => {
    return all.filter((d) => {
      if (fType && d.device_type !== fType) return false;
      return textMatch(dq, d.ip, d.hostname, d.mac, d.vendor, d.device_type, d.snmp_sys_name, d.snmp_sys_descr);
    });
  }, [all, fType, dq]);

  const stats = useMemo(() => {
    const total = all.length;
    const snmpCount = all.filter((d) => d.snmp_enabled).length;
    const unmanaged = all.filter((d) => d.status === 'discovered').length;
    return { total, snmpCount, unmanaged };
  }, [all]);

  const handleOpenScanModal = () => {
    if (onlineAgents.length > 0) {
      setProbeMode('agent');
      setSelectedAgentId(onlineAgents[0].id);
      setSubnetInput(defaultSubnetForIp(onlineAgents[0].last_ip));
    } else {
      setProbeMode('server');
      setSelectedAgentId('');
      setSubnetInput('192.168.1.0/24');
    }
    setScanModal(true);
  };

  const handleAgentSelect = (agentId: string) => {
    setSelectedAgentId(agentId);
    const ag = agentMap.get(agentId);
    if (ag && ag.last_ip) {
      setSubnetInput(defaultSubnetForIp(ag.last_ip));
    }
  };

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    const subnet = subnetInput.trim();
    if (!subnet) return;

    const agentId = probeMode === 'agent' ? selectedAgentId : '';
    const probeAgent = agentId ? agentMap.get(agentId) : null;

    try {
      await api.startNetworkScan(subnet, agentId);
      if (probeAgent) {
        toast.success(
          'Remote client sweep started',
          `Dispatched scan of ${subnet} to ${probeAgent.display_name} in background...`
        );
      } else {
        toast.success('Network sweep started', `Scanning ${subnet} from server in background...`);
      }
      setScanModal(false);
      void scans.reload();
      setTimeout(() => {
        void devices.reload();
      }, 3500);
    } catch (err) {
      toast.error('Scan failed to start', errMsg(err));
    }
  };

  const handlePollSNMP = async (d: DiscoveredDevice) => {
    try {
      setPollingId(d.id);
      const updated = await api.pollSNMP(d.id);
      toast.success(`SNMP poll succeeded for ${d.ip}`, updated.snmp_sys_name || updated.snmp_sys_descr || 'Received response');
      void devices.reload();
      if (selectedDevice?.id === d.id) {
        setSelectedDevice(updated);
      }
    } catch (err) {
      toast.error(`SNMP poll failed for ${d.ip}`, errMsg(err));
    } finally {
      setPollingId(null);
    }
  };

  const handleSetStatus = async (d: DiscoveredDevice, status: string) => {
    try {
      await api.updateDiscoveredDevice(d.id, { status });
      toast.success(`Device status updated to ${status}`);
      void devices.reload();
    } catch (err) {
      toast.error('Update failed', errMsg(err));
    }
  };

  const handleDelete = async (d: DiscoveredDevice) => {
    const ok = await confirm({
      title: `Delete discovered device ${d.ip}`,
      message: 'Remove this device from the network discovery inventory?',
      danger: true,
      confirmLabel: 'Delete Device',
    });
    if (!ok) return;

    try {
      await api.deleteDiscoveredDevice(d.id);
      toast.success('Device removed');
      void devices.reload();
    } catch (err) {
      toast.error('Delete failed', errMsg(err));
    }
  };

  const columns: Column<DiscoveredDevice>[] = [
    {
      key: 'ip',
      header: 'IP Address',
      sort: (d) => d.ip,
      render: (d) => (
        <div>
          <button
            className="btn link"
            style={{ fontWeight: 600, padding: 0 }}
            onClick={() => setSelectedDevice(d)}
          >
            {d.ip}
          </button>
          {d.hostname && <div className="muted small">{d.hostname}</div>}
        </div>
      ),
    },
    {
      key: 'device_type',
      header: 'Device Type',
      sort: (d) => d.device_type,
      render: (d) => {
        let tone: 'accent' | 'warn' | 'ok' | 'purple' | 'danger' = 'purple';
        if (d.device_type === 'switch' || d.device_type === 'router') tone = 'accent';
        else if (d.device_type === 'printer') tone = 'warn';
        else if (d.device_type === 'server') tone = 'ok';
        else if (d.device_type === 'workstation') tone = 'accent';
        return <Chip tone={tone}>{d.device_type.toUpperCase()}</Chip>;
      },
    },
    {
      key: 'location',
      header: 'Client & Site',
      render: (d) => {
        const orgName = orgMap.get(d.org_id) || (d.org_id === 'org_default' ? 'Default Organization' : d.org_id || '—');
        const siteName = siteMap.get(d.site_id) || (d.site_id === 'site_default' ? 'Main Site' : d.site_id || '—');
        const ag = d.discovered_by ? agentMap.get(d.discovered_by) : null;
        return (
          <div>
            <div style={{ fontWeight: 500 }}>{orgName}</div>
            <div className="muted small">
              {siteName}
              {ag && ` (via ${ag.display_name})`}
            </div>
          </div>
        );
      },
    },
    {
      key: 'snmp',
      header: 'SNMP',
      render: (d) =>
        d.snmp_enabled ? (
          <span title={d.snmp_sys_descr || 'SNMP v2c responding'}>
            <Chip tone="ok">v2c Active</Chip>
          </span>
        ) : (
          <span className="muted small">—</span>
        ),
    },
    {
      key: 'ports',
      header: 'Open Ports',
      render: (d) => (
        <div className="row" style={{ gap: 4, flexWrap: 'wrap', maxWidth: 180 }}>
          {d.open_ports.map((p) => (
            <span key={p} className="mono small" style={{ background: 'var(--bg-subtle)', padding: '2px 5px', borderRadius: 4 }}>
              {p}
            </span>
          ))}
          {!d.open_ports.length && <span className="muted small">None</span>}
        </div>
      ),
    },
    {
      key: 'mac',
      header: 'MAC / Vendor',
      render: (d) => (
        <div>
          <div className="mono small">{d.mac || '—'}</div>
          {d.vendor && <div className="muted small">{d.vendor}</div>}
        </div>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      sort: (d) => d.status,
      render: (d) => (
        <Chip tone={d.status === 'managed' ? 'ok' : d.status === 'ignored' ? 'danger' : 'warn'}>
          {d.status}
        </Chip>
      ),
    },
    {
      key: 'last_seen',
      header: 'Last Seen',
      sort: (d) => d.last_seen,
      render: (d) => <span className="muted small">{relTime(d.last_seen)}</span>,
    },
    {
      key: 'actions',
      header: '',
      width: 140,
      render: (d) =>
        canWrite && (
          <div className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => handlePollSNMP(d)}
              disabled={pollingId === d.id}
              title="Poll device via SNMP v2c port 161 (proxied via agent if remote)"
            >
              {pollingId === d.id ? 'Polling…' : 'SNMP'}
            </Button>
            {d.status === 'discovered' ? (
              <Button size="sm" variant="primary" onClick={() => handleSetStatus(d, 'managed')}>
                Adopt
              </Button>
            ) : (
              <Button size="sm" className="danger" onClick={() => handleDelete(d)}>
                Delete
              </Button>
            )}
          </div>
        ),
    },
  ];

  const scanColumns: Column<NetworkScan>[] = [
    {
      key: 'started_at',
      header: 'Time',
      sort: (s) => s.started_at,
      render: (s) => <span className="muted small">{dateTime(s.started_at)}</span>,
      width: 170,
    },
    {
      key: 'subnet',
      header: 'Subnet CIDR',
      render: (s) => <span className="mono">{s.subnet}</span>,
    },
    {
      key: 'probe',
      header: 'Probed By',
      render: (s) => {
        if (!s.agent_id) return <span className="muted">RMM Server (Local)</span>;
        const ag = agentMap.get(s.agent_id);
        const orgName = ag?.org_id ? orgMap.get(ag.org_id) : '';
        return (
          <div>
            <strong>{ag?.display_name || s.agent_id}</strong>
            {orgName && <div className="muted small">{orgName}</div>}
          </div>
        );
      },
    },
    {
      key: 'status',
      header: 'Status',
      render: (s) => {
        let tone: 'ok' | 'warn' | 'danger' | 'purple' = 'purple';
        if (s.status === 'completed') tone = 'ok';
        else if (s.status === 'running') tone = 'warn';
        else if (s.status === 'failed') tone = 'danger';
        return <Chip tone={tone}>{s.status.toUpperCase()}</Chip>;
      },
    },
    {
      key: 'devices_found',
      header: 'Hosts Found',
      render: (s) => <strong>{s.devices_found}</strong>,
    },
  ];

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Network Discovery & SNMP</h1>
          <p className="muted small">
            Probe remote client LANs and local subnets via online agents behind NAT, discover switches, routers, and printers, and poll SNMP telemetry.
          </p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button size="sm" onClick={() => { void devices.reload(); void scans.reload(); }} disabled={devices.loading} title="Refresh discovered devices">
            <IconRefresh /> Refresh
          </Button>
          {canWrite && (
            <Button variant="primary" size="sm" onClick={handleOpenScanModal}>
              <IconWifi /> Scan Subnet…
            </Button>
          )}
        </div>
      </div>

      <div className="row" style={{ gap: 16, marginBottom: 16 }}>
        <div className="card" style={{ flex: 1, padding: 14, borderRadius: 8, border: '1px solid var(--border)' }}>
          <div className="muted small">Discovered Hosts</div>
          <div style={{ fontSize: 24, fontWeight: 700 }}>{stats.total}</div>
        </div>
        <div className="card" style={{ flex: 1, padding: 14, borderRadius: 8, border: '1px solid var(--border)' }}>
          <div className="muted small">SNMP Responding</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--success)' }}>{stats.snmpCount}</div>
        </div>
        <div className="card" style={{ flex: 1, padding: 14, borderRadius: 8, border: '1px solid var(--border)' }}>
          <div className="muted small">Unmanaged Candidates</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--warn)' }}>{stats.unmanaged}</div>
        </div>
      </div>

      {devices.error && <ErrorBox error={devices.error} onRetry={devices.reload} />}

      <div className="toolbar" style={{ flexWrap: 'wrap', gap: 8 }}>
        <input
          type="search"
          placeholder="Search IP, hostname, MAC, SNMP description…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          style={{ maxWidth: 300 }}
          aria-label="Search discovered devices"
        />
        {(orgs.data ?? []).length > 1 && (
          <select
            value={fOrg}
            onChange={(e) => setFOrg(e.target.value)}
            style={{ width: 160 }}
            aria-label="Filter by client"
          >
            <option value="">All Clients</option>
            {(orgs.data ?? []).map((o) => (
              <option key={o.id} value={o.id}>
                {o.name}
              </option>
            ))}
          </select>
        )}
        <select
          value={fType}
          onChange={(e) => setFType(e.target.value)}
          style={{ width: 140 }}
          aria-label="Filter by type"
        >
          <option value="">All Types</option>
          <option value="switch">Switches</option>
          <option value="router">Routers</option>
          <option value="printer">Printers</option>
          <option value="server">Servers</option>
          <option value="workstation">Workstations</option>
        </select>
        <select
          value={fStatus}
          onChange={(e) => setFStatus(e.target.value)}
          style={{ width: 140 }}
          aria-label="Filter by status"
        >
          <option value="">All Statuses</option>
          <option value="discovered">Discovered (Unmanaged)</option>
          <option value="managed">Managed / Adopted</option>
          <option value="ignored">Ignored</option>
        </select>
        <span className="grow" />
        <span className="muted small">
          {filtered.length} of {all.length} devices
        </span>
      </div>

      <DataTable
        columns={columns}
        rows={devices.data ? filtered : undefined}
        loading={devices.loading}
        rowKey={(d) => d.id}
        defaultSort={{ key: 'ip', dir: 'asc' }}
        csvName="discovered_devices"
        emptyTitle="No discovered devices"
        emptyBody="Click 'Scan Subnet' to probe client LANs or the local network."
      />

      {(scans.data ?? []).length > 0 && (
        <div style={{ marginTop: 28 }}>
          <h2 style={{ fontSize: 16, marginBottom: 8 }}>Recent Network Sweeps</h2>
          <DataTable
            columns={scanColumns}
            rows={scans.data ?? []}
            loading={scans.loading}
            rowKey={(s) => String(s.id)}
            defaultSort={{ key: 'started_at', dir: 'desc' }}
            compact
          />
        </div>
      )}

      {scanModal && (
        <Modal title="Sweep Network Subnet" onClose={() => setScanModal(false)}>
          <form onSubmit={handleStartScan} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <p className="muted small">
              Probes all IP addresses in the subnet for open management ports (22, 80, 443, 445, 3389, 9100) and queries SNMP v2c telemetry on UDP 161.
            </p>

            <div>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 600, marginBottom: 6 }}>
                Probe Source
              </label>
              <div className="row" style={{ gap: 16, marginBottom: 10 }}>
                <label className="row" style={{ gap: 6, cursor: 'pointer' }}>
                  <input
                    type="radio"
                    name="probeMode"
                    value="agent"
                    checked={probeMode === 'agent'}
                    onChange={() => {
                      setProbeMode('agent');
                      if (onlineAgents.length > 0 && !selectedAgentId) {
                        handleAgentSelect(onlineAgents[0].id);
                      }
                    }}
                  />
                  <span>Endpoint Agent (Remote Client LAN)</span>
                </label>
                <label className="row" style={{ gap: 6, cursor: 'pointer' }}>
                  <input
                    type="radio"
                    name="probeMode"
                    value="server"
                    checked={probeMode === 'server'}
                    onChange={() => {
                      setProbeMode('server');
                      setSubnetInput('192.168.1.0/24');
                    }}
                  />
                  <span>RMM Server (Local Network)</span>
                </label>
              </div>

              {probeMode === 'agent' && (
                <div>
                  <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>
                    Select Online Probe Agent *
                  </label>
                  {onlineAgents.length > 0 ? (
                    <select
                      value={selectedAgentId}
                      onChange={(e) => handleAgentSelect(e.target.value)}
                      required
                      style={{ width: '100%' }}
                    >
                      {onlineAgents.map((a) => {
                        const orgName = a.org_id ? orgMap.get(a.org_id) : '';
                        const siteName = a.site_id ? siteMap.get(a.site_id) : '';
                        const loc = [orgName, siteName].filter(Boolean).join(' / ');
                        return (
                          <option key={a.id} value={a.id}>
                            {a.display_name} ({a.last_ip} - {a.os}) {loc ? `— ${loc}` : ''}
                          </option>
                        );
                      })}
                    </select>
                  ) : (
                    <div className="banner warn" style={{ fontSize: 12, padding: 8 }}>
                      No online agents currently connected. Connect an endpoint agent or use the RMM Server probe.
                    </div>
                  )}
                  <p className="muted small" style={{ marginTop: 4 }}>
                    Discovered devices will be automatically ingested under this agent's client organization and branch site.
                  </p>
                </div>
              )}
            </div>

            <div>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 600, marginBottom: 4 }}>
                Subnet CIDR Range *
              </label>
              <input
                type="text"
                required
                value={subnetInput}
                onChange={(e) => setSubnetInput(e.target.value)}
                placeholder="e.g. 192.168.1.0/24 or 10.0.0.0/24"
                style={{ width: '100%', fontFamily: 'monospace' }}
              />
              <span className="muted small" style={{ display: 'block', marginTop: 4 }}>
                Supported ranges up to /22 (max 1024 IP addresses).
              </span>
            </div>

            <div className="row" style={{ justifyContent: 'flex-end', gap: 8, marginTop: 12 }}>
              <Button variant="ghost" onClick={() => setScanModal(false)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                type="submit"
                disabled={probeMode === 'agent' && !selectedAgentId}
              >
                Start Network Scan
              </Button>
            </div>
          </form>
        </Modal>
      )}

      {selectedDevice && (
        <Modal title={`Device Details: ${selectedDevice.ip}`} onClose={() => setSelectedDevice(null)}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div className="row" style={{ justifyContent: 'space-between' }}>
              <div>
                <h3 style={{ margin: 0 }}>{selectedDevice.hostname || selectedDevice.ip}</h3>
                <span className="mono small muted">{selectedDevice.ip}</span>
              </div>
              <Chip tone={selectedDevice.status === 'managed' ? 'ok' : 'warn'}>
                {selectedDevice.status.toUpperCase()}
              </Chip>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, background: 'var(--bg-subtle)', padding: 12, borderRadius: 6 }}>
              <div>
                <span className="muted small">Device Type:</span> <strong>{selectedDevice.device_type}</strong>
              </div>
              <div>
                <span className="muted small">OS:</span> <strong>{selectedDevice.os || 'Unknown'}</strong>
              </div>
              <div>
                <span className="muted small">MAC:</span> <span className="mono small">{selectedDevice.mac || '—'}</span>
              </div>
              <div>
                <span className="muted small">Vendor:</span> <span>{selectedDevice.vendor || '—'}</span>
              </div>
              <div>
                <span className="muted small">Client:</span> <span>{orgMap.get(selectedDevice.org_id) || selectedDevice.org_id || 'Default Organization'}</span>
              </div>
              <div>
                <span className="muted small">Site:</span> <span>{siteMap.get(selectedDevice.site_id) || selectedDevice.site_id || 'Main Site'}</span>
              </div>
            </div>

            <div>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 6 }}>Open Ports</div>
              <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
                {selectedDevice.open_ports.map((p) => (
                  <Chip key={p} outline>
                    Port {p}
                  </Chip>
                ))}
                {!selectedDevice.open_ports.length && <span className="muted small">None detected</span>}
              </div>
            </div>

            <div>
              <div className="row" style={{ justifyContent: 'space-between', marginBottom: 6 }}>
                <div style={{ fontSize: 13, fontWeight: 600 }}>SNMP MIB-2 Details</div>
                <Button size="sm" variant="ghost" onClick={() => handlePollSNMP(selectedDevice)} disabled={pollingId === selectedDevice.id}>
                  {pollingId === selectedDevice.id ? 'Polling…' : 'Poll SNMP Now'}
                </Button>
              </div>
              {selectedDevice.snmp_enabled ? (
                <div style={{ background: 'var(--bg-subtle)', padding: 12, borderRadius: 6, display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div>
                    <span className="muted small">SysName:</span> <strong>{selectedDevice.snmp_sys_name || '—'}</strong>
                  </div>
                  <div>
                    <span className="muted small">SysUpTime:</span> <span>{selectedDevice.snmp_sys_uptime ? `${selectedDevice.snmp_sys_uptime} seconds` : '—'}</span>
                  </div>
                  <div>
                    <span className="muted small">SysDescr:</span>
                    <pre style={{ margin: '4px 0 0', fontSize: 11, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                      {selectedDevice.snmp_sys_descr || '—'}
                    </pre>
                  </div>
                </div>
              ) : (
                <p className="muted small">Device has not answered SNMP v2c queries on UDP port 161.</p>
              )}
            </div>

            <div className="row" style={{ justifyContent: 'flex-end', gap: 8, marginTop: 12 }}>
              {selectedDevice.status === 'discovered' && (
                <Button
                  variant="primary"
                  onClick={() => {
                    void handleSetStatus(selectedDevice, 'managed');
                    setSelectedDevice(null);
                  }}
                >
                  Mark as Managed
                </Button>
              )}
              <Button variant="ghost" onClick={() => setSelectedDevice(null)}>
                Close
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </>
  );
}
