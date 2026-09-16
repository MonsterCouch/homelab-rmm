// Add / edit one baseline check: a kind picker, a typed form per kind, and a
// raw-JSON escape hatch for power users. Everything is validated against the
// same rules the server enforces (components/baselines/kinds.ts) before the
// Save button enables, so a check never leaves this dialog only to come back
// as a 400.

import { useMemo, useState } from 'react';
import type { BaselineCheck, BaselineKind, BaselineParams, Severity } from '../../api/types';
import { CodeEditor } from '../CodeEditor';
import { Modal } from '../Modal';
import { Button, Field, Switch, TagInput } from '../ui';
import {
  KINDS,
  LIMITS,
  bool,
  cleanParams,
  fixableWith,
  kindDef,
  kindLabel,
  needsAdmin,
  numOr,
  osWarning,
  str,
  strList,
  validateCheck,
  validateParams,
} from './kinds';

interface Props {
  check: BaselineCheck;
  /** editing an existing saved check keeps its id; changing the kind does not */
  onSave: (c: BaselineCheck) => void;
  onClose: () => void;
  isAdmin: boolean;
}

const REBOOT_PHRASE = 'REBOOT';

/**
 * Drop the params a kind's own values make inapplicable, so the typed form can
 * never hold a value it no longer shows. `file` is the one that bites: the
 * content/sha256/contains/mode/owner fields are only rendered for `present`,
 * so switching to `absent` with any of them set used to leave the check
 * permanently invalid ("state absent: ... do not apply") with nothing on
 * screen to clear. The rule is the server's, from validateParams.
 */
function dropInapplicable(kind: string, p: BaselineParams): BaselineParams {
  if (kind !== 'file' || p.state !== 'absent') return p;
  const out = { ...p };
  for (const k of ['content', 'sha256', 'contains', 'mode', 'owner']) delete out[k];
  return out;
}

export function CheckDialog({ check, onSave, onClose, isAdmin }: Props) {
  const [form, setForm] = useState<BaselineCheck>({ ...check, params: { ...check.params } });
  const [rawMode, setRawMode] = useState(false);
  const [rawText, setRawText] = useState(() => JSON.stringify(check.params ?? {}, null, 2));
  const [rawErr, setRawErr] = useState<string | null>(null);
  const [rebootTyped, setRebootTyped] = useState('');

  const def = kindDef(form.kind);
  const isNew = check.id === 0 && !check.name;
  // Editing a SAVED check and changing its kind is a delete + insert on the
  // server, not an edit: the row says so before Save is pressed.
  const kindReplaced = check.id > 0 && form.kind !== check.kind;
  const upd = (patch: Partial<BaselineCheck>) => setForm((f) => ({ ...f, ...patch }));
  const setP = (patch: BaselineParams) => {
    setForm((f) => ({ ...f, params: dropInapplicable(f.kind, { ...f.params, ...patch }) }));
  };

  // The two editors are one state: the typed form owns `params`, and the raw
  // box is re-serialised from it every time it opens. Leaving raw mode drops
  // whatever would not parse (the form still holds the last valid params) and
  // clears the error with it - a JSON typo used to keep Save disabled for the
  // rest of the dialog with its message off screen.
  const setMode = (raw: boolean) => {
    if (raw) setRawText(JSON.stringify(form.params ?? {}, null, 2));
    else setRawErr(null);
    setRawMode(raw);
  };

  const changeKind = (kind: BaselineKind) => {
    const d = kindDef(kind);
    const params = d ? d.defaults() : {};
    setRawText(JSON.stringify(params, null, 2));
    setRawErr(null);
    setRebootTyped('');
    setForm((f) => ({
      ...f,
      kind,
      params,
      // A saved check that changes kind is a delete + insert on the server
      // (A3): expected/observed from the old kind are meaningless under the
      // new one. Dropping the id here makes that explicit.
      id: f.kind === kind ? f.id : 0,
      os_filter: d && d.os.length === 1 ? d.os[0] : f.os_filter,
      remediate: d?.fixable ? f.remediate : false,
    }));
  };

  const applyRaw = (text: string) => {
    setRawText(text);
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      setRawErr(err instanceof Error ? err.message : 'not valid JSON');
      return;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      setRawErr('params must be a JSON object');
      return;
    }
    const msg = validateParams(form.kind, parsed as BaselineParams);
    setRawErr(msg);
    // The raw editor is the escape hatch: whatever parsed is kept as typed,
    // inapplicable keys included, so the message names them instead of the
    // box silently rewriting what the operator wrote.
    setForm((f) => ({ ...f, params: parsed as BaselineParams }));
  };

  const candidate = useMemo<BaselineCheck>(() => ({ ...form, name: form.name.trim(), params: cleanParams(form.kind, form.params) }), [form]);
  const error = useMemo(() => validateCheck(candidate), [candidate]);
  const osNote = osWarning(candidate);
  const adminBlocked = needsAdmin(candidate) && !isAdmin;
  const wantsReboot = form.kind === 'reboot_pending' && bool(form.params, 'allow_reboot');
  const rebootOk = !wantsReboot || rebootTyped.trim().toUpperCase() === REBOOT_PHRASE;
  const canSave = !error && !rawErr && !adminBlocked && rebootOk;
  const fixable = fixableWith(form.kind, form.params);

  const save = () => {
    if (!canSave) return;
    onSave(candidate);
  };

  return (
    <Modal
      title={isNew ? 'Add check' : `Edit check: ${check.name}`}
      onClose={onClose}
      size="lg"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={save} disabled={!canSave} title={error ?? rawErr ?? undefined}>
            {isNew ? 'Add check' : 'Save check'}
          </Button>
        </>
      }
    >
      <div className="form-row">
        <Field label="Check name" htmlFor="chk-name" hint="What an alert and the status matrix will call it.">
          <input id="chk-name" data-autofocus value={form.name} maxLength={LIMITS.name} onChange={(e) => upd({ name: e.target.value })} />
        </Field>
        <Field label="Kind" htmlFor="chk-kind">
          <select id="chk-kind" value={form.kind} onChange={(e) => changeKind(e.target.value as BaselineKind)}>
            {KINDS.map((k) => (
              <option key={k.id} value={k.id}>
                {k.label} ({k.os.join(' + ')})
              </option>
            ))}
          </select>
        </Field>
      </div>
      {def && <p className="muted small">{def.help}</p>}

      {form.kind === 'command' && (
        <div className="banner danger" role="note">
          <span>
            <b>This script runs as SYSTEM (Windows) or root (Linux) on every matched device</b>, on the baseline's interval and without asking. Only an administrator can
            create or edit a check of this kind.
          </span>
        </div>
      )}
      {form.kind === 'group_members' && (
        <div className="banner warn" role="note">
          <span>
            Remediation <b>removes</b> group members that are not allowed and never adds any. The agent refuses to remove the built-in Administrator or root, the account it
            runs as, the last member of an admin group, and domain principals unless you allow them below.
          </span>
        </div>
      )}
      {adminBlocked && (
        <div className="banner danger" role="alert">
          <span>Only an administrator can save this check. Ask one, or pick a different kind.</span>
        </div>
      )}
      {kindReplaced && (
        <div className="banner warn" role="alert">
          <span>
            <b>Changing the kind replaces this check.</b> Saving the baseline deletes check #{check.id} — its results on every device go with it and its open drift
            alerts are resolved — and inserts a new {kindLabel(form.kind)} check in its place. Its history rows stay. Cancel and add a second check instead to keep both.
          </span>
        </div>
      )}

      <div className="card" style={{ marginBottom: 10 }}>
        <div className="card-head">
          Parameters
          <div className="actions">
            <Button size="xs" onClick={() => setMode(!rawMode)} aria-pressed={rawMode}>
              {rawMode ? 'Typed form' : 'Raw JSON'}
            </Button>
          </div>
        </div>
        <div className="card-body">
          {rawMode ? (
            <Field label="params" htmlFor="chk-raw" error={rawErr} hint="Exactly the JSON the API takes. Unknown keys are refused by the server, so they are refused here too.">
              <textarea id="chk-raw" className="mono" rows={12} spellCheck={false} value={rawText} onChange={(e) => applyRaw(e.target.value)} />
            </Field>
          ) : (
            <KindForm kind={form.kind} params={form.params} setP={setP} />
          )}
        </div>
      </div>

      {wantsReboot && (
        <div className="banner danger" role="alert">
          <div className="stack" style={{ gap: 6, width: '100%' }}>
            <span>
              <b>This check may restart devices.</b> When the baseline is enforced, a device that has been waiting for a reboot longer than the limit is rebooted with a 60 s
              notice, at most once a day. Type <b>{REBOOT_PHRASE}</b> to keep it.
            </span>
            <input aria-label={`Type ${REBOOT_PHRASE} to confirm`} id="chk-reboot-confirm" value={rebootTyped} onChange={(e) => setRebootTyped(e.target.value)} style={{ maxWidth: 220 }} />
          </div>
        </div>
      )}

      <div className="form-row">
        <Field label="Severity" htmlFor="chk-severity" hint="warning and critical open a drift alert; info never does.">
          <select id="chk-severity" value={form.severity} onChange={(e) => upd({ severity: e.target.value as Severity })}>
            <option value="info">info</option>
            <option value="warning">warning</option>
            <option value="critical">critical</option>
          </select>
        </Field>
        <Field label="Only on" htmlFor="chk-os" hint={osNote ?? 'Devices of another OS report this check as skipped.'}>
          <select id="chk-os" value={form.os_filter} onChange={(e) => upd({ os_filter: e.target.value })}>
            <option value="">Any OS</option>
            <option value="windows">Windows</option>
            <option value="linux">Linux</option>
          </select>
        </Field>
        <Field label="Timeout (s)" htmlFor="chk-timeout" hint={`${LIMITS.minTimeout}–${LIMITS.maxTimeout}. A check that runs longer is an error and the pass continues.`}>
          <input
            id="chk-timeout"
            type="number"
            min={LIMITS.minTimeout}
            max={LIMITS.maxTimeout}
            value={form.timeout_sec}
            onChange={(e) => upd({ timeout_sec: +e.target.value || LIMITS.defaultTimeout })}
          />
        </Field>
      </div>

      <Field label="Remediation" hint={def?.fixNote}>
        <span data-testid="chk-remediate">
          <Switch
            checked={form.remediate}
            disabled={!def?.fixable}
            onChange={(remediate) => upd({ remediate })}
            label={def?.fixable ? 'Let the agent fix this check (only when the baseline is enforced)' : 'This kind is check only'}
          />
        </span>
      </Field>
      {form.remediate && !fixable && (
        <p className="small" style={{ color: 'var(--warn)' }}>
          These parameters have nothing to fix, so the check stays read-only whatever this toggle says. {def?.fixNote}
        </p>
      )}

      <p className="muted small">
        Parameters are stored in the clear and are readable by every signed-in user, including viewers. Put no passwords, tokens or keys in them.
      </p>
      {error && !rawErr && (
        <div className="form-error" role="alert">
          {error}
        </div>
      )}
    </Modal>
  );
}

// ---------- the typed forms ----------

function KindForm({ kind, params, setP }: { kind: BaselineKind; params: BaselineParams; setP: (p: BaselineParams) => void }) {
  switch (kind) {
    case 'service':
      return (
        <div className="form-row">
          <Field label="Service or unit name" htmlFor="p-name" hint="Spooler on Windows, ssh or sshd.service on Linux.">
            <input id="p-name" value={str(params, 'name')} onChange={(e) => setP({ name: e.target.value })} />
          </Field>
          <Field label="State" htmlFor="p-state">
            <select id="p-state" value={str(params, 'state')} onChange={(e) => setP({ state: e.target.value })}>
              <option value="running">running</option>
              <option value="stopped">stopped</option>
            </select>
          </Field>
          <Field
            label="Start type"
            htmlFor="p-start-type"
            hint="auto also matches Windows' automatic (delayed start). On Linux there is no manual to set: that value is check only."
          >
            <select id="p-start-type" value={str(params, 'start_type') || 'any'} onChange={(e) => setP({ start_type: e.target.value })}>
              <option value="any">any</option>
              <option value="auto">auto</option>
              <option value="manual">manual</option>
              <option value="disabled">disabled</option>
            </select>
          </Field>
        </div>
      );
    case 'package':
      return (
        <>
          <div className="form-row">
            <Field
              label="Package name, winget id or program name"
              htmlFor="p-name"
              hint="On Windows the name Add/Remove Programs shows works too: GitHub CLI, 7-Zip 26.03 (x64)."
            >
              <input id="p-name" value={str(params, 'name')} onChange={(e) => setP({ name: e.target.value })} />
            </Field>
            <Field label="State" htmlFor="p-state">
              <select id="p-state" value={str(params, 'state')} onChange={(e) => setP({ state: e.target.value })}>
                <option value="present">present</option>
                <option value="absent">absent</option>
              </select>
            </Field>
            <Field label="Minimum version" htmlFor="p-min-version" hint="Optional, present only. Epoch and Debian/RPM revision are ignored.">
              <input id="p-min-version" value={str(params, 'min_version')} onChange={(e) => setP({ min_version: e.target.value })} />
            </Field>
          </div>
          <Switch
            checked={bool(params, 'allow_winget')}
            onChange={(v) => setP({ allow_winget: v })}
            label="Windows: allow winget to install this (usually unavailable to the agent service account)"
          />
        </>
      );
    case 'registry':
      return (
        <>
          <div className="form-row">
            <Field
              label="Key path"
              htmlFor="p-reg-path"
              hint="HKLM\… or HKCU\…. HKCU is the hive of the agent service account (SYSTEM), not the signed-in user."
            >
              <input id="p-reg-path" className="mono" value={str(params, 'path')} onChange={(e) => setP({ path: e.target.value })} />
            </Field>
            <Field label="Value name" htmlFor="p-reg-name" hint="Empty means the key's default value.">
              <input id="p-reg-name" value={str(params, 'name')} onChange={(e) => setP({ name: e.target.value })} />
            </Field>
          </div>
          <div className="form-row">
            <Field label="Type" htmlFor="p-reg-type">
              <select
                id="p-reg-type"
                value={str(params, 'type')}
                onChange={(e) => {
                  const t = e.target.value;
                  setP({ type: t, value: t === 'dword' || t === 'qword' ? 0 : t === 'multi_string' ? [] : '' });
                }}
              >
                <option value="dword">dword</option>
                <option value="qword">qword</option>
                <option value="string">string</option>
                <option value="expand_string">expand_string</option>
                <option value="multi_string">multi_string</option>
              </select>
            </Field>
            <Field label="Value" htmlFor="p-reg-value" hint={str(params, 'type') === 'expand_string' ? 'Compared unexpanded, exactly as stored.' : undefined}>
              {str(params, 'type') === 'multi_string' ? (
                <TagInput value={strList(params, 'value')} onChange={(v) => setP({ value: v })} placeholder="add string…" />
              ) : str(params, 'type') === 'dword' || str(params, 'type') === 'qword' ? (
                <input id="p-reg-value" type="number" min={0} value={typeof params.value === 'number' ? params.value : 0} onChange={(e) => setP({ value: Math.max(0, Math.floor(+e.target.value || 0)) })} />
              ) : (
                <input id="p-reg-value" value={typeof params.value === 'string' ? params.value : ''} onChange={(e) => setP({ value: e.target.value })} />
              )}
            </Field>
          </div>
        </>
      );
    case 'file':
      return (
        <>
          <div className="form-row">
            <Field label="Path" htmlFor="p-path" hint="Absolute. /proc, /sys, /dev, the files that decide who is root and the agent's own directory are refused.">
              <input id="p-path" className="mono" value={str(params, 'path')} onChange={(e) => setP({ path: e.target.value })} />
            </Field>
            <Field label="State" htmlFor="p-state" hint="absent removes a regular file only — never a directory.">
              <select id="p-state" value={str(params, 'state')} onChange={(e) => setP({ state: e.target.value })}>
                <option value="present">present</option>
                <option value="absent">absent</option>
              </select>
            </Field>
          </div>
          {str(params, 'state') === 'present' && (
            <>
              <Field label="Exact content" htmlFor="p-content" hint="The only fixable field: with content set, the agent writes the file (tmp + rename) when it differs.">
                <textarea id="p-content" className="mono" rows={6} spellCheck={false} value={str(params, 'content')} onChange={(e) => setP({ content: e.target.value })} />
              </Field>
              <div className="form-row">
                <Field label="sha256" htmlFor="p-sha256" hint="64 hex characters. Check only without content.">
                  <input id="p-sha256" className="mono" value={str(params, 'sha256')} onChange={(e) => setP({ sha256: e.target.value })} />
                </Field>
                <Field label="Contains" htmlFor="p-contains" hint="Substring that must appear. Check only without content.">
                  <input id="p-contains" value={str(params, 'contains')} onChange={(e) => setP({ contains: e.target.value })} />
                </Field>
              </div>
              <div className="form-row">
                <Field label="Mode (Linux)" htmlFor="p-mode" hint="3 or 4 octal digits, 0777 or lower, no setuid/setgid/sticky.">
                  <input id="p-mode" className="mono" placeholder="0644" value={str(params, 'mode')} onChange={(e) => setP({ mode: e.target.value })} />
                </Field>
                <Field label="Owner (Linux)" htmlFor="p-owner" hint="user or user:group.">
                  <input id="p-owner" placeholder="root:root" value={str(params, 'owner')} onChange={(e) => setP({ owner: e.target.value })} />
                </Field>
              </div>
            </>
          )}
        </>
      );
    case 'command':
      return (
        <>
          <div className="form-row">
            <Field label="Language" htmlFor="p-language">
              <select id="p-language" value={str(params, 'language')} onChange={(e) => setP({ language: e.target.value })}>
                <option value="bash">bash</option>
                <option value="sh">sh</option>
                <option value="powershell">powershell</option>
                <option value="cmd">cmd</option>
                <option value="python">python</option>
              </select>
            </Field>
            <Field label="Expected (label)" htmlFor="p-expected" hint="Shown as the expected value. It is never compared to anything.">
              <input id="p-expected" value={str(params, 'expected')} onChange={(e) => setP({ expected: e.target.value })} />
            </Field>
          </div>
          <Field label="Check script" hint="Exit 0 is compliant, anything else is drift. The first non-empty stdout line becomes the observed value.">
            <CodeEditor id="p-check" value={str(params, 'check')} onChange={(v) => setP({ check: v })} minHeight={160} placeholder="#!/usr/bin/env bash&#10;test -f /etc/rmm-marker" />
          </Field>
          <Field label="Fix script (optional)" hint="Runs before the re-check, only when the baseline is enforced and this check may remediate.">
            <CodeEditor id="p-fix" value={str(params, 'fix')} onChange={(v) => setP({ fix: v })} minHeight={120} placeholder="touch /etc/rmm-marker" />
          </Field>
        </>
      );
    case 'group_members':
      return (
        <>
          <div className="form-row">
            <Field label="Group" htmlFor="p-group" hint="Administrators on Windows; sudo, wheel, adm on Linux.">
              <input id="p-group" value={str(params, 'group')} onChange={(e) => setP({ group: e.target.value })} />
            </Field>
            <Field
              label="Mode"
              htmlFor="p-mode-sel"
              hint="subset: extras are drift and are removed. exact: membership must equal the list — extras are removed but missing members are never added, so an exact check with a missing member stays failed."
            >
              <select id="p-mode-sel" value={str(params, 'mode') || 'subset'} onChange={(e) => setP({ mode: e.target.value })}>
                <option value="subset">subset (default)</option>
                <option value="exact">exact</option>
              </select>
            </Field>
          </div>
          <Field label="Allowed members" hint="Compared case-insensitively, and by SID on Windows when it resolves. An empty list reports the current membership for review.">
            <TagInput value={strList(params, 'allowed')} onChange={(v) => setP({ allowed: v })} placeholder="add account…" />
          </Field>
          <Switch
            checked={bool(params, 'allow_domain')}
            onChange={(v) => setP({ allow_domain: v })}
            label="Allow removing domain principals (DOMAIN\\user, user@domain) from the local group"
          />
        </>
      );
    case 'firewall':
    case 'time_sync':
      return (
        <Field label="Desired state" hint={kind === 'firewall' ? 'Windows requires all three profiles on. On Linux ufw or firewalld is used; without either the check is skipped.' : 'Windows: w32time running with a source. Linux: timedatectl NTP=yes.'}>
          <Switch checked={params.enabled !== false} onChange={(v) => setP({ enabled: v })} label={params.enabled === false ? 'must be off' : 'must be on'} />
        </Field>
      );
    case 'sysctl':
      return (
        <div className="form-row">
          <Field label="Key" htmlFor="p-key" hint="Read from /proc/sys; the fix writes /etc/sysctl.d/90-homelab-rmm.conf and applies it.">
            <input id="p-key" className="mono" placeholder="net.ipv4.ip_forward" value={str(params, 'key')} onChange={(e) => setP({ key: e.target.value })} />
          </Field>
          <Field label="Value" htmlFor="p-value" hint="Always a string; compared after trimming.">
            <input id="p-value" className="mono" value={str(params, 'value')} onChange={(e) => setP({ value: e.target.value })} />
          </Field>
        </div>
      );
    case 'windows_feature':
      return (
        <div className="form-row">
          <Field label="Feature name" htmlFor="p-name" hint="As Get-WindowsOptionalFeature names it, e.g. SMB1Protocol.">
            <input id="p-name" value={str(params, 'name')} onChange={(e) => setP({ name: e.target.value })} />
          </Field>
          <Field label="State" htmlFor="p-state">
            <select id="p-state" value={str(params, 'state')} onChange={(e) => setP({ state: e.target.value })}>
              <option value="enabled">enabled</option>
              <option value="disabled">disabled</option>
            </select>
          </Field>
        </div>
      );
    case 'reboot_pending':
      return (
        <>
          <Field label="Maximum hours pending" htmlFor="p-max-hours" hint="The check fails once a device has been waiting to reboot for longer than this.">
            <input id="p-max-hours" type="number" min={1} max={8760} value={numOr(params, 'max_hours', 72)} onChange={(e) => setP({ max_hours: Math.max(1, Math.floor(+e.target.value || 1)) })} style={{ maxWidth: 160 }} />
          </Field>
          <Switch checked={bool(params, 'allow_reboot')} onChange={(v) => setP({ allow_reboot: v })} label="Allow the agent to reboot the device to clear it" />
        </>
      );
    case 'disk_free':
      return (
        <div className="form-row">
          <Field label="Mount or drive" htmlFor="p-mount" hint={'C: on Windows (C:\\ is accepted), / or /var on Linux. An unknown mount is an error, not drift.'}>
            <input id="p-mount" className="mono" value={str(params, 'mount')} onChange={(e) => setP({ mount: e.target.value })} />
          </Field>
          <Field label="Minimum free (%)" htmlFor="p-min-free" hint="Greater than 0 and less than 100.">
            <input id="p-min-free" type="number" min={1} max={99} value={numOr(params, 'min_free_pct', 10)} onChange={(e) => setP({ min_free_pct: +e.target.value || 0 })} style={{ maxWidth: 160 }} />
          </Field>
        </div>
      );
    default:
      return <p className="muted small">This kind has no typed form yet — use Raw JSON.</p>;
  }
}
