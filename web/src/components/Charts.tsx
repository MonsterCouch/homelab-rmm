import { useEffect, useRef } from 'react';
import uPlot from 'uplot';

export interface Series {
  label: string;
  values: (number | null)[];
  color: string;
  /** fill under the line with a translucent version of color */
  fill?: boolean;
}

interface Props {
  /** Unix seconds */
  xs: number[];
  series: Series[];
  /** formatter for the y axis and legend values */
  format?: (v: number) => string;
  /** fixed y range, e.g. [0, 100] for percentages */
  range?: [number, number];
  /** fixed x window (Unix seconds) so sparse data still spans the selected range */
  xRange?: [number, number];
  height?: number;
  title?: string;
}

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || '#888';
}

function withAlpha(hex: string, alpha: number): string {
  const m = hex.match(/^#([0-9a-f]{6})$/i);
  if (!m) return hex;
  const n = parseInt(m[1], 16);
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${alpha})`;
}

/**
 * Thin uPlot wrapper. The chart is (re)built when the series shape or theme
 * changes and only setData'd on value updates, so live metrics do not churn
 * the DOM. Width follows the container through a ResizeObserver.
 */
export function TimeSeriesChart({ xs, series, format = (v) => String(v), range, xRange, height = 180, title }: Props) {
  const host = useRef<HTMLDivElement>(null);
  const plot = useRef<uPlot | null>(null);
  const shapeKey = series.map((s) => `${s.label}|${s.color}|${s.fill ? 1 : 0}`).join(';') + `|${range?.join(',') ?? ''}|${title ?? ''}`;
  const fmtRef = useRef(format);
  fmtRef.current = format;
  const xRangeRef = useRef(xRange);
  xRangeRef.current = xRange;

  useEffect(() => {
    const el = host.current;
    if (!el) return;
    const text = cssVar('--text-muted');
    const grid = cssVar('--border');
    const opts: uPlot.Options = {
      width: el.clientWidth || 300,
      height,
      title,
      cursor: { drag: { x: false, y: false }, points: { size: 6 } },
      legend: { live: true },
      scales: {
        x: { time: true, range: (_u, min, max) => (xRangeRef.current ? xRangeRef.current : [min, max]) },
        y: range ? { range } : { range: (_u, min, max) => [Math.min(0, min), max <= 0 ? 1 : max * 1.05] },
      },
      axes: [
        {
          stroke: text,
          grid: { stroke: grid, width: 1 },
          ticks: { stroke: grid, width: 1 },
          font: '11px sans-serif',
          values: (_u, vals) =>
            vals.map((v) => {
              const d = new Date(v * 1000);
              const span = (xs[xs.length - 1] ?? 0) - (xs[0] ?? 0);
              return span > 86400 * 2
                ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
                : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
            }),
        },
        {
          stroke: text,
          grid: { stroke: grid, width: 1 },
          ticks: { stroke: grid, width: 1 },
          font: '11px sans-serif',
          size: 56,
          values: (_u, vals) => vals.map((v) => fmtRef.current(v)),
        },
      ],
      series: [
        {
          value: (_u, v) => (v == null ? '' : new Date(v * 1000).toLocaleString()),
        },
        ...series.map<uPlot.Series>((s) => ({
          label: s.label,
          stroke: s.color,
          width: 1.5,
          fill: s.fill ? withAlpha(s.color, 0.15) : undefined,
          spanGaps: false,
          value: (_u, v) => (v == null ? '—' : fmtRef.current(v)),
          points: { show: false },
        })),
      ],
    };
    const u = new uPlot(opts, [xs, ...series.map((s) => s.values)], el);
    plot.current = u;
    const ro = new ResizeObserver(() => {
      if (el.clientWidth > 0) u.setSize({ width: el.clientWidth, height });
    });
    ro.observe(el);
    const mo = new MutationObserver(() => {
      // theme flip: rebuild colours by re-running this effect
      u.axes.forEach((a) => {
        a.stroke = cssVar('--text-muted');
      });
      u.redraw();
    });
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    return () => {
      ro.disconnect();
      mo.disconnect();
      u.destroy();
      plot.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [shapeKey, height]);

  useEffect(() => {
    plot.current?.setData([xs, ...series.map((s) => s.values)]);
  }, [xs, series, xRange]);

  return <div className="chart" ref={host} style={{ height: height + (title ? 28 : 0) + 30 }} />;
}

/** Tiny inline sparkline (no axes) for table cells. */
export function Sparkline({ values, color, width = 90, height = 22 }: { values: number[]; color: string; width?: number; height?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const c = ref.current;
    if (!c) return;
    const dpr = window.devicePixelRatio || 1;
    c.width = width * dpr;
    c.height = height * dpr;
    const ctx = c.getContext('2d');
    if (!ctx) return;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, width, height);
    if (values.length < 2) return;
    const max = Math.max(...values, 1);
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.2;
    ctx.beginPath();
    values.forEach((v, i) => {
      const x = (i / (values.length - 1)) * (width - 2) + 1;
      const y = height - 1 - (v / max) * (height - 2);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
  }, [values, color, width, height]);
  return <canvas ref={ref} style={{ width, height, display: 'block' }} aria-hidden="true" />;
}
