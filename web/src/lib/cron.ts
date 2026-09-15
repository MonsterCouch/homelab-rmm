// Cron helpers for the task/policy editors. The server accepts the robfig
// 5-field syntax (minute hour dom month dow) plus @hourly/@daily/@weekly/
// @monthly/@every. We describe the common shapes in English and leave the
// rest to the server's validation error.

export type Preset = 'manual' | 'hourly' | 'daily' | 'weekly' | 'monthly' | 'custom';

const DOW = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const MON = ['', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

export interface PresetValues {
  hour: number; // 0-23
  minute: number; // 0-59
  dow: number; // 0-6, weekly
  dom: number; // 1-31, monthly
}

export function buildCron(preset: Preset, v: PresetValues, custom: string): string {
  switch (preset) {
    case 'manual':
      return '';
    case 'hourly':
      return `${v.minute} * * * *`;
    case 'daily':
      return `${v.minute} ${v.hour} * * *`;
    case 'weekly':
      return `${v.minute} ${v.hour} * * ${v.dow}`;
    case 'monthly':
      return `${v.minute} ${v.hour} ${v.dom} * *`;
    case 'custom':
      return custom.trim();
  }
}

/** Recognise a cron expression as one of the presets, for editing an existing task. */
export function detectPreset(expr: string): { preset: Preset; values: PresetValues } {
  const values: PresetValues = { hour: 3, minute: 0, dow: 1, dom: 1 };
  const e = expr.trim();
  if (!e) return { preset: 'manual', values };
  if (e === '@hourly') return { preset: 'hourly', values };
  if (e === '@daily' || e === '@midnight') return { preset: 'daily', values: { ...values, hour: 0 } };
  if (e === '@weekly') return { preset: 'weekly', values: { ...values, hour: 0, dow: 0 } };
  if (e === '@monthly') return { preset: 'monthly', values: { ...values, hour: 0, dom: 1 } };
  const f = e.split(/\s+/);
  if (f.length !== 5) return { preset: 'custom', values };
  const [mi, h, dom, mon, dow] = f;
  const isNum = (s: string) => /^\d+$/.test(s);
  if (isNum(mi) && h === '*' && dom === '*' && mon === '*' && dow === '*') {
    return { preset: 'hourly', values: { ...values, minute: +mi } };
  }
  if (isNum(mi) && isNum(h) && dom === '*' && mon === '*' && dow === '*') {
    return { preset: 'daily', values: { ...values, minute: +mi, hour: +h } };
  }
  if (isNum(mi) && isNum(h) && dom === '*' && mon === '*' && isNum(dow)) {
    return { preset: 'weekly', values: { ...values, minute: +mi, hour: +h, dow: +dow % 7 } };
  }
  if (isNum(mi) && isNum(h) && isNum(dom) && mon === '*' && dow === '*') {
    return { preset: 'monthly', values: { ...values, minute: +mi, hour: +h, dom: +dom } };
  }
  return { preset: 'custom', values };
}

function hhmm(h: string, m: string): string {
  const hh = +h;
  const mm = +m;
  const ampm = hh >= 12 ? 'PM' : 'AM';
  const h12 = hh % 12 === 0 ? 12 : hh % 12;
  return `${h12}:${String(mm).padStart(2, '0')} ${ampm}`;
}

function describeField(v: string, names?: string[], offset = 0): string {
  return v
    .split(',')
    .map((part) => {
      const m = part.match(/^(\d+)-(\d+)$/);
      if (m) {
        const a = names ? names[+m[1] - offset] : m[1];
        const b = names ? names[+m[2] - offset] : m[2];
        return `${a}–${b}`;
      }
      if (/^\d+$/.test(part)) return names ? names[+part - offset] ?? part : part;
      return part;
    })
    .join(', ');
}

/** English summary of a cron expression; falls back to the raw text. */
export function describeCron(expr: string): string {
  const e = expr.trim();
  if (!e) return 'Manual only';
  switch (e) {
    case '@hourly':
      return 'Every hour';
    case '@daily':
    case '@midnight':
      return 'Every day at midnight';
    case '@weekly':
      return 'Every Sunday at midnight';
    case '@monthly':
      return 'On the 1st of every month at midnight';
    case '@yearly':
    case '@annually':
      return 'Once a year';
  }
  if (e.startsWith('@every ')) return `Every ${e.slice(7)}`;
  const f = e.split(/\s+/);
  if (f.length !== 5) return e;
  const [mi, h, dom, mon, dow] = f;
  const isNum = (s: string) => /^\d+$/.test(s);
  const step = (s: string) => s.match(/^\*\/(\d+)$/);

  let when = '';
  if (isNum(mi) && isNum(h)) when = `at ${hhmm(h, mi)}`;
  else if (isNum(mi) && h === '*') when = `every hour at :${mi.padStart(2, '0')}`;
  else if (step(h) && (mi === '0' || isNum(mi))) when = `every ${step(h)![1]} hours at :${mi.padStart(2, '0')}`;
  else if (step(mi) && h === '*') when = `every ${step(mi)![1]} minutes`;
  else if (mi === '*' && h === '*') when = 'every minute';
  else if (isNum(mi) && h.includes(',')) when = `at ${h.split(',').map((x) => hhmm(x, mi)).join(', ')}`;
  else when = `at minute ${mi} hour ${h}`;

  let days = '';
  if (dom === '*' && dow === '*') days = 'every day';
  else if (dom === '*' && dow !== '*') {
    if (dow === '1-5') days = 'on weekdays';
    else if (dow === '0,6' || dow === '6,0') days = 'on weekends';
    else days = `on ${describeField(dow, DOW)}`;
  } else if (dom !== '*' && dow === '*') {
    days = `on day ${describeField(dom)} of the month`;
  } else days = `on day ${describeField(dom)} and ${describeField(dow, DOW)}`;

  let months = '';
  if (mon !== '*') months = ` in ${describeField(mon, MON)}`;

  const s = `${when}, ${days}${months}`;
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Cheap client-side syntax check so obvious typos show before the API round trip. */
export function cronLooksValid(expr: string): string | null {
  const e = expr.trim();
  if (!e) return null;
  if (e.startsWith('@')) {
    if (/^@(hourly|daily|midnight|weekly|monthly|yearly|annually)$/.test(e)) return null;
    if (/^@every \d+(ns|us|µs|ms|s|m|h)+$/.test(e) || /^@every (\d+[a-zµ]+)+$/.test(e)) return null;
    return 'unknown @descriptor';
  }
  const f = e.split(/\s+/);
  if (f.length !== 5) return `expected 5 fields (minute hour day month weekday), got ${f.length}`;
  const ranges = [
    [0, 59],
    [0, 23],
    [1, 31],
    [1, 12],
    [0, 7],
  ];
  for (let i = 0; i < 5; i++) {
    const field = f[i];
    const [lo, hi] = ranges[i];
    for (const part of field.split(',')) {
      const m = part.match(/^(\*|\d+(?:-\d+)?|[a-z]{3}(?:-[a-z]{3})?)(?:\/(\d+))?$/i);
      if (!m) return `field ${i + 1} ("${field}") is not valid`;
      if (/^\d/.test(m[1])) {
        for (const n of m[1].split('-').map(Number)) {
          if (n < lo || n > hi) return `field ${i + 1}: ${n} is outside ${lo}–${hi}`;
        }
      }
      if (m[2] !== undefined && +m[2] === 0) return `field ${i + 1}: step must be > 0`;
    }
  }
  return null;
}

export const HOURS = Array.from({ length: 24 }, (_, i) => i);
export const DOW_NAMES = DOW;
