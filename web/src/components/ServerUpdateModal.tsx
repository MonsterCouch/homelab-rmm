import { useEffect, useState, useSyncExternalStore } from 'react';
import { api } from '../api/client';
import type { ServerVersionInfo } from '../api/types';
import { fleetUpdateRunning, fleetUpdateTone, subscribeFleetUpdate, summarizeFleetUpdate, updateFleet } from '../lib/fleetUpdate';
import { Modal } from './Modal';
import { Button, ErrorBox } from './ui';
import { IconCheck, IconDownload, IconRefresh, IconUpload } from './Icons';
import { errMsg, useToast } from '../state/toast';

interface ServerUpdateModalProps {
  onClose: () => void;
}

export function ServerUpdateModal({ onClose }: ServerUpdateModalProps) {
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<ServerVersionInfo | null>(null);

  const [updatingServer, setUpdatingServer] = useState(false);
  const [restarting, setRestarting] = useState(false);
  const [restartSuccess, setRestartSuccess] = useState(false);
  const [statusMessage, setStatusMessage] = useState('');

  const [updatingAgents, setUpdatingAgents] = useState(false);
  const [agentResult, setAgentResult] = useState<string | null>(null);
  // The run itself, not just the click that started it here: this modal is
  // unmounted when it is closed, and a run started from the Devices page is
  // going on as well, so a flag of its own would let a second run be joined.
  const fleetBusy = useSyncExternalStore(subscribeFleetUpdate, fleetUpdateRunning);

  const loadInfo = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.serverVersion();
      setInfo(data);
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadInfo();
  }, []);

  const handleApplyServerUpdate = async () => {
    if (!info?.staged_update?.available) return;
    setUpdatingServer(true);
    setStatusMessage('Applying staged binary and staging agent binaries...');
    try {
      await api.updateServer();
      setRestarting(true);
      setStatusMessage('Update applied. Server is restarting service, waiting for reconnection...');

      // Poll until the server comes back online
      let attempts = 0;
      const pollInterval = window.setInterval(async () => {
        attempts++;
        try {
          const res = await fetch('/api/auth/state', { cache: 'no-store' });
          if (res.ok) {
            window.clearInterval(pollInterval);
            setRestarting(false);
            setRestartSuccess(true);
            setStatusMessage('Server is back online with updated binary! Reloading page...');
            setTimeout(() => {
              window.location.reload();
            }, 1200);
          }
        } catch {
          // Still restarting
          if (attempts > 40) {
            window.clearInterval(pollInterval);
            setRestarting(false);
            setStatusMessage('Server took longer than expected to restart. Please refresh manually.');
          }
        }
      }, 1500);
    } catch (err) {
      setUpdatingServer(false);
      setRestarting(false);
      toast.error(errMsg(err));
    }
  };

  const handleUpdateAllAgents = async () => {
    setUpdatingAgents(true);
    setAgentResult(null);
    try {
      const s = await updateFleet();
      const text = summarizeFleetUpdate(s);
      setAgentResult(text);
      toast.push(fleetUpdateTone(s), text);
    } catch (err) {
      toast.error(errMsg(err));
    } finally {
      setUpdatingAgents(false);
    }
  };

  const staged = info?.staged_update;

  return (
    <Modal
      title="Server & Fleet Updates"
      onClose={restarting ? () => {} : onClose}
      size="lg"
      footer={
        <div className="row" style={{ justifyContent: 'space-between', width: '100%' }}>
          <Button variant="ghost" onClick={loadInfo} disabled={loading || restarting} title="Refresh status">
            <IconRefresh /> Refresh
          </Button>
          <Button variant="default" onClick={onClose} disabled={restarting}>
            Close
          </Button>
        </div>
      }
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {error && <ErrorBox error={error} onRetry={loadInfo} />}

        {loading && !info && (
          <div className="empty muted" style={{ padding: 24, textAlign: 'center' }}>
            <span className="spinner" style={{ marginRight: 8 }} /> Checking server and staged build status…
          </div>
        )}

        {info && (
          <>
            {/* Server Version Info */}
            <div className="card" style={{ padding: 16 }}>
              <h3 style={{ margin: '0 0 12px 0', fontSize: 15 }}>Running Server</h3>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, fontSize: 13 }}>
                <div>
                  <span className="muted">Version:</span> <strong>v{info.version || 'dev'}</strong>
                </div>
                <div>
                  <span className="muted">OS / Arch:</span> <code>{info.os}/{info.arch}</code>
                </div>
                <div>
                  <span className="muted">PID:</span> <code>{info.pid}</code>
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <span className="muted">Binary:</span> <code style={{ fontSize: 12, wordBreak: 'break-all' }}>{info.exe_path}</code>
                </div>
              </div>
            </div>

            {/* Staged Update Section */}
            <div className="card" style={{ padding: 16 }}>
              <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <h3 style={{ margin: 0, fontSize: 15 }}>Staged Server Build</h3>
                {staged?.available ? (
                  staged.differs ? (
                    <span className="chip" style={{ background: 'var(--accent)', color: '#fff' }}>New Build Available</span>
                  ) : (
                    <span className="chip outline">Matches Running Executable</span>
                  )
                ) : (
                  <span className="chip muted">No Staged Binary</span>
                )}
              </div>

              {staged?.available ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, fontSize: 13 }}>
                    <div style={{ gridColumn: '1 / -1' }}>
                      <span className="muted">Staged Path:</span> <code style={{ fontSize: 12, wordBreak: 'break-all' }}>{staged.path}</code>
                    </div>
                    <div>
                      <span className="muted">Size:</span> {(staged.size / (1024 * 1024)).toFixed(2)} MB
                    </div>
                    <div>
                      <span className="muted">Built / Modified:</span> {new Date(staged.mod_time * 1000).toLocaleString()}
                    </div>
                  </div>

                  {restarting || restartSuccess ? (
                    <div className="row" style={{ alignItems: 'center', gap: 10, padding: '12px 16px', background: 'var(--bg-elevated)', borderRadius: 6 }}>
                      {restartSuccess ? <IconCheck style={{ color: 'var(--success)' }} /> : <span className="spinner" />}
                      <span style={{ fontSize: 13, fontWeight: 500 }}>{statusMessage}</span>
                    </div>
                  ) : (
                    <div className="row" style={{ gap: 10, marginTop: 8 }}>
                      <Button
                        variant="primary"
                        onClick={handleApplyServerUpdate}
                        busy={updatingServer}
                        disabled={updatingServer || restarting}
                      >
                        <IconUpload /> {staged.differs ? 'Apply Update & Restart Server' : 'Re-apply Staged Server Build'}
                      </Button>
                      <span className="muted small" style={{ alignSelf: 'center' }}>
                        In-place binary swap with zero configuration data loss.
                      </span>
                    </div>
                  )}
                </div>
              ) : (
                <p className="muted small" style={{ margin: 0 }}>
                  No compiled binary found in <code>dist/</code> or <code>data/update/</code>. When you build new code using <code>powershell tools/build.ps1 -Target server</code> or <code>-Target all</code>, the new binary will automatically appear here ready to apply with one click.
                </p>
              )}
            </div>

            {/* Agent Auto-Update & Fleet Section */}
            <div className="card" style={{ padding: 16 }}>
              <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <h3 style={{ margin: 0, fontSize: 15 }}>Agent Auto-Update & Fleet</h3>
                <span className="chip outline">Auto-Chore Active</span>
              </div>
              <p className="muted small" style={{ margin: '0 0 12px 0' }}>
                Agents execute an automatic update chore every 5 minutes: they query the server for the current binary hash, download updates in-place if newer, and cleanly restart the agent service. Devices in organizations that enforce signed actions are not updated by the chore; they install only updates signed from here, one signature per organization and build. You can also broadcast an immediate update to all online agents below.
              </p>

              <div className="row" style={{ gap: 10, alignItems: 'center' }}>
                <Button
                  onClick={handleUpdateAllAgents}
                  busy={updatingAgents || fleetBusy}
                  disabled={updatingAgents || fleetBusy || restarting}
                >
                  <IconDownload /> Broadcast Update to All Online Agents
                </Button>
                {agentResult && <span className="small" style={{ color: 'var(--accent)' }}>{agentResult}</span>}
              </div>
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}
