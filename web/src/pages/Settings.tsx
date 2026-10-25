import { useEffect, useRef, useState } from 'react';
import { api } from '../api/client';
import type { Settings as SettingsT } from '../api/types';
import { PairCard } from '../components/PairCard';
import { Button, CopyButton, ErrorBox, Field, Loading, Switch, TagInput } from '../components/ui';
import { useAsync } from '../hooks/useAsync';
import { bytes, duration } from '../lib/format';
import { errMsg, useToast } from '../state/toast';
import '../styles/mobile-pages.css';

export function Settings() {
  const toast = useToast();
  const settings = useAsync(() => api.settings(), []);
  const system = useAsync(() => api.system(), []);
  const [form, setForm] = useState<SettingsT | null>(null);
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState(false);
  // What is on screen right now, readable from inside an awaited save. Every
  // edit makes a new object, so identity answers "was this changed while the
  // request was in flight?".
  const latest = useRef<SettingsT | null>(null);
  latest.current = form;

  useEffect(() => {
    if (settings.data && !dirty) setForm(settings.data);
  }, [settings.data, dirty]);

  if (settings.error && !form) return <ErrorBox error={settings.error} onRetry={settings.reload} />;
  if (!form) return <Loading />;

  const upd = (patch: Partial<SettingsT>) => {
    setForm((f) => (f ? { ...f, ...patch } : f));
    setDirty(true);
  };
  const smtp = (patch: Partial<SettingsT['smtp']>) => upd({ smtp: { ...form.smtp, ...patch } });
  const agent = (patch: Partial<SettingsT['agent_defaults']>) => upd({ agent_defaults: { ...form.agent_defaults, ...patch } });
  const mesh = form.mesh_cache ?? { enabled: false, port: 7443, max_bytes: 2 * 1024 ** 3 };
  const setMesh = (patch: Partial<NonNullable<SettingsT['mesh_cache']>>) => upd({ mesh_cache: { ...mesh, ...patch } });
  const ret = (patch: Partial<SettingsT['retention']>) => upd({ retention: { ...form.retention, ...patch } });

  const save = async () => {
    setBusy(true);
    const sent = form;
    try {
      const saved = await api.saveSettings(sent);
      // Taking the server's copy back is right only if nothing was typed
      // while the request was in flight; otherwise the newer edit would be
      // silently reverted and the form would go clean with it.
      if (latest.current === sent) {
        setForm(saved);
        setDirty(false);
      }
      toast.success('Settings saved', 'Agent intervals were pushed to connected devices.');
      void system.reload();
    } catch (err) {
      toast.error('Save failed', errMsg(err));
    } finally {
      setBusy(false);
    }
  };
  const testMail = async () => {
    setTesting(true);
    try {
      await api.testMail(form.smtp);
      toast.success('Test email sent', `to ${(form.smtp.to ?? []).join(', ')}`);
    } catch (err) {
      toast.error('Test email failed', errMsg(err));
    } finally {
      setTesting(false);
    }
  };

  return (
    <>
      <div className="page-head">
        <h1>Settings</h1>
        {dirty && (
          <Button
            variant="ghost"
            onClick={() => {
              setForm(settings.data ?? form);
              setDirty(false);
            }}
          >
            Discard
          </Button>
        )}
        <Button variant="primary" onClick={save} busy={busy} disabled={!dirty}>
          Save changes
        </Button>
      </div>
      <div className="grid cols-2">
        <div className="stack" style={{ gap: 14 }}>
          <div className="card">
            <div className="card-head">Server</div>
            <div className="card-body">
              <Field label="Public URL" hint="How agents and email links reach this server, e.g. https://rmm.home.lan:8443. Changing it does not move already-enrolled agents.">
                <input type="url" value={form.public_url} placeholder={system.data?.public_url} onChange={(e) => upd({ public_url: e.target.value })} />
              </Field>
            </div>
          </div>
          <div className="card">
            <div className="card-head">
              Email (SMTP)
              <div className="actions">
                <Switch checked={form.smtp.enabled} onChange={(enabled) => smtp({ enabled })} label="Enabled" />
              </div>
            </div>
            <div className="card-body">
              <div className="form-row">
                <Field label="Host">
                  <input value={form.smtp.host} placeholder="smtp.gmail.com" onChange={(e) => smtp({ host: e.target.value })} />
                </Field>
                <Field label="Port">
                  <input type="number" min={1} max={65535} value={form.smtp.port || ''} placeholder="587" onChange={(e) => smtp({ port: +e.target.value || 0 })} />
                </Field>
                <Field label="Encryption">
                  <select value={form.smtp.tls || 'starttls'} onChange={(e) => smtp({ tls: e.target.value })}>
                    <option value="starttls">STARTTLS (587)</option>
                    <option value="tls">TLS (465)</option>
                    <option value="none">None</option>
                  </select>
                </Field>
              </div>
              <div className="form-row">
                <Field label="Username">
                  <input value={form.smtp.username} autoComplete="off" onChange={(e) => smtp({ username: e.target.value })} />
                </Field>
                <Field label="Password" hint="Stored server-side; shown masked.">
                  <input type="password" value={form.smtp.password} autoComplete="new-password" onChange={(e) => smtp({ password: e.target.value })} />
                </Field>
              </div>
              <Field label="From address">
                <input type="email" value={form.smtp.from} placeholder="rmm@home.lan" onChange={(e) => smtp({ from: e.target.value })} />
              </Field>
              <Field label="Recipients" hint="Alert and automation emails go to every address here.">
                <TagInput value={form.smtp.to ?? []} onChange={(to) => smtp({ to })} placeholder="you@example.com" />
              </Field>
              <div className="form-actions">
                <Button onClick={testMail} busy={testing} disabled={!form.smtp.host}>
                  Send test email
                </Button>
              </div>
            </div>
          </div>
        </div>
        <div className="stack" style={{ gap: 14 }}>
          <div className="card">
            <div className="card-head">Agent defaults</div>
            <div className="card-body">
              <div className="form-row">
                <Field label="Metrics interval (s)" hint="Minimum 5.">
                  <input type="number" min={5} value={form.agent_defaults.metrics_interval_sec} onChange={(e) => agent({ metrics_interval_sec: +e.target.value || 30 })} />
                </Field>
                <Field label="Inventory interval (s)" hint="Minimum 60.">
                  <input type="number" min={60} value={form.agent_defaults.inventory_interval_sec} onChange={(e) => agent({ inventory_interval_sec: +e.target.value || 3600 })} />
                </Field>
                <Field label="Patch scan interval (s)" hint="0 disables the agent's own scans.">
                  <input type="number" min={0} value={form.agent_defaults.patch_scan_interval_sec} onChange={(e) => agent({ patch_scan_interval_sec: +e.target.value || 0 })} />
                </Field>
              </div>
            </div>
          </div>
          <div className="card">
            <div className="card-head">Retention (days)</div>
            <div className="card-body">
              <div className="form-row">
                <Field label="Metrics">
                  <input type="number" min={1} value={form.retention.metrics_days} onChange={(e) => ret({ metrics_days: +e.target.value || 30 })} />
                </Field>
                <Field label="Script runs">
                  <input type="number" min={1} value={form.retention.runs_days} onChange={(e) => ret({ runs_days: +e.target.value || 90 })} />
                </Field>
                <Field label="Audit log">
                  <input type="number" min={1} value={form.retention.audit_days} onChange={(e) => ret({ audit_days: +e.target.value || 365 })} />
                </Field>
                <Field label="Agent events">
                  <input type="number" min={1} value={form.retention.events_days} onChange={(e) => ret({ events_days: +e.target.value || 30 })} />
                </Field>
              </div>
            </div>
          </div>
          <div className="card">
            <div className="card-head">Update cache</div>
            <div className="card-body">
              <p className="muted small" style={{ marginTop: 0 }}>
                One device per subnet downloads an agent update once and shares it with its neighbours over the local network, so a hundred devices do not each pull it from the internet. Devices fall back to the server whenever the cache is unavailable, and every download is checked against its hash.
              </p>
              <Switch checked={mesh.enabled} onChange={(enabled) => setMesh({ enabled })} label="Share updates between devices on the same subnet" />
              <div className="form-row">
                <Field label="Port" hint="TCP and UDP, 1024 or higher. Devices open it to the local subnet only.">
                  <input type="number" min={1024} max={65535} value={mesh.port} disabled={!mesh.enabled} onChange={(e) => setMesh({ port: +e.target.value || 7443 })} />
                </Field>
                <Field label="Cache size per leader (MiB)" hint="Minimum 64.">
                  <input type="number" min={64} value={Math.round(mesh.max_bytes / 1048576)} disabled={!mesh.enabled} onChange={(e) => setMesh({ max_bytes: (+e.target.value || 2048) * 1048576 })} />
                </Field>
              </div>
            </div>
          </div>
          <div className="card">
            <div className="card-head">System</div>
            <div className="card-body">
              {system.data ? (
                <dl className="kv">
                  <dt>Version</dt>
                  <dd>{system.data.version}</dd>
                  <dt>Public URL</dt>
                  <dd className="mono">{system.data.public_url}</dd>
                  <dt>Certificate fingerprint</dt>
                  {/* SHA-256 of the leaf DER: the value every agent pins and
                      the value the Android app pins. It is compared character
                      by character against another screen, so it is shown in
                      full rather than truncated into a title tooltip that a
                      touch screen never opens. */}
                  <dd>
                    {system.data.fingerprint ? (
                      <div className="fp-block">
                        <code>{system.data.fingerprint}</code>
                        <CopyButton text={system.data.fingerprint} label="Copy fingerprint" size="md" />
                      </div>
                    ) : (
                      <span className="muted">— (this server is not terminating TLS itself)</span>
                    )}
                  </dd>
                  <dt>Data directory</dt>
                  <dd className="mono">{system.data.data_dir}</dd>
                  <dt>Database size</dt>
                  <dd>{bytes(system.data.db_bytes)}</dd>
                  {system.data.telemetry_engine && (
                    <>
                      <dt>Metrics storage</dt>
                      <dd>
                        {system.data.telemetry_engine}
                        {typeof system.data.telemetry_bytes === 'number' && system.data.telemetry_bytes >= 0 ? `, ${bytes(system.data.telemetry_bytes)}` : ''}
                        <span className="muted small"> (set with the server's --telemetry flag, not here)</span>
                      </dd>
                    </>
                  )}
                  <dt>Uptime</dt>
                  <dd>{duration(system.data.uptime)}</dd>
                  <dt>Agents connected</dt>
                  <dd>{system.data.agents_connected}</dd>
                </dl>
              ) : system.error ? (
                <ErrorBox error={system.error} onRetry={system.reload} />
              ) : (
                <Loading />
              )}
            </div>
          </div>
          <div className="card">
            <div className="card-head">Pair a phone</div>
            <div className="card-body">
              {system.data ? <PairCard url={system.data.public_url} fingerprint={system.data.fingerprint} /> : <Loading />}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
