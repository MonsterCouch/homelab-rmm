import { useEffect, useState } from 'react';
import { buildCron, cronLooksValid, describeCron, detectPreset, DOW_NAMES, HOURS, type Preset, type PresetValues } from '../lib/cron';

interface Props {
  value: string;
  onChange: (expr: string) => void;
  /** validation message returned by the API on save */
  serverError?: string | null;
  disabled?: boolean;
  /** hide the "manual only" option (patch policy scan schedule must exist) */
  allowManual?: boolean;
}

/**
 * Preset-driven schedule editor with a raw cron escape hatch. The expression
 * is always the source of truth: presets just write into it, and editing the
 * raw field switches to "custom" if it no longer matches a preset.
 */
export function CronEditor({ value, onChange, serverError, disabled, allowManual = true }: Props) {
  const detected = detectPreset(value);
  const [preset, setPreset] = useState<Preset>(detected.preset);
  const [vals, setVals] = useState<PresetValues>(detected.values);
  const [raw, setRaw] = useState(value);

  // external reset (editor reopened with a different task)
  useEffect(() => {
    const d = detectPreset(value);
    if (value !== raw) {
      setPreset(d.preset);
      setVals(d.values);
      setRaw(value);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);

  const update = (p: Preset, v: PresetValues, customRaw = raw) => {
    setPreset(p);
    setVals(v);
    const expr = buildCron(p, v, customRaw);
    setRaw(expr);
    onChange(expr);
  };

  const localErr = cronLooksValid(raw);
  const err = serverError ?? localErr;
  const pad = (n: number) => String(n).padStart(2, '0');

  return (
    <div className="stack" style={{ gap: 8 }}>
      <div className="row">
        <select value={preset} disabled={disabled} onChange={(e) => update(e.target.value as Preset, vals)} style={{ width: 170 }}>
          {allowManual && <option value="manual">Manual only</option>}
          <option value="hourly">Hourly</option>
          <option value="daily">Daily at</option>
          <option value="weekly">Weekly on</option>
          <option value="monthly">Monthly on</option>
          <option value="custom">Custom cron</option>
        </select>
        {preset === 'weekly' && (
          <select value={vals.dow} disabled={disabled} onChange={(e) => update(preset, { ...vals, dow: +e.target.value })} style={{ width: 130 }}>
            {DOW_NAMES.map((d, i) => (
              <option key={d} value={i}>
                {d}
              </option>
            ))}
          </select>
        )}
        {preset === 'monthly' && (
          <select value={vals.dom} disabled={disabled} onChange={(e) => update(preset, { ...vals, dom: +e.target.value })} style={{ width: 90 }}>
            {Array.from({ length: 28 }, (_, i) => i + 1).map((d) => (
              <option key={d} value={d}>
                day {d}
              </option>
            ))}
          </select>
        )}
        {(preset === 'daily' || preset === 'weekly' || preset === 'monthly') && (
          <>
            <select value={vals.hour} disabled={disabled} onChange={(e) => update(preset, { ...vals, hour: +e.target.value })} style={{ width: 80 }}>
              {HOURS.map((h) => (
                <option key={h} value={h}>
                  {pad(h)}
                </option>
              ))}
            </select>
            <span className="muted">:</span>
          </>
        )}
        {preset !== 'manual' && preset !== 'custom' && (
          <select value={vals.minute} disabled={disabled} onChange={(e) => update(preset, { ...vals, minute: +e.target.value })} style={{ width: 80 }}>
            {[0, 5, 10, 15, 20, 30, 45].map((m) => (
              <option key={m} value={m}>
                {pad(m)}
              </option>
            ))}
          </select>
        )}
        {preset === 'hourly' && <span className="muted small">past the hour</span>}
      </div>
      {preset === 'custom' && (
        <input
          className="mono"
          value={raw}
          disabled={disabled}
          placeholder="*/15 * * * *"
          spellCheck={false}
          onChange={(e) => {
            setRaw(e.target.value);
            onChange(e.target.value.trim());
          }}
        />
      )}
      <div className={`small ${err ? 'err' : 'muted'}`} style={err ? { color: 'var(--danger)' } : undefined}>
        {err ? err : preset === 'manual' ? 'Runs only when triggered by hand.' : `${describeCron(raw)} · server local time`}
        {!err && preset !== 'manual' && preset !== 'custom' && (
          <span className="faint mono" style={{ marginLeft: 8 }}>
            {raw}
          </span>
        )}
      </div>
    </div>
  );
}
