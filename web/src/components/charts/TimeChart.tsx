// Hand-rolled SVG line / area / stacked-area chart with a hover + keyboard tooltip and a
// data-table fallback. Colours are CSS custom properties so both themes work.

import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent, type PointerEvent } from "react";

export interface Series {
  key: string;
  label: string;
  /** CSS colour, usually var(--…). */
  color: string;
  values: number[];
}

interface Props {
  title: string;
  /** One label per x position (dates, step numbers…). */
  xLabels: string[];
  series: Series[];
  mode: "line" | "area" | "stacked";
  formatY?: (v: number) => string;
  /** Fixed y maximum (e.g. 100 for percentages). */
  yMax?: number;
  height?: number;
}

const PAD = { top: 12, right: 16, bottom: 26, left: 48 };

function niceMax(v: number): number {
  if (v <= 0) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  const n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * p;
}

export function TimeChart({ title, xLabels, series, mode, formatY = (v) => v.toLocaleString(), yMax, height = 220 }: Props) {
  const [active, setActive] = useState<number | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const boxRef = useRef<HTMLDivElement>(null);
  // Draw in real pixels so text and strokes keep their size at any width.
  const [W, setW] = useState(640);
  useEffect(() => {
    const el = boxRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => {
      if (entry && entry.contentRect.width > 0) setW(Math.round(entry.contentRect.width));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const titleId = useId();
  const n = xLabels.length;
  const innerW = W - PAD.left - PAD.right;
  const innerH = height - PAD.top - PAD.bottom;

  const stacks = useMemo(() => {
    // For stacked mode each series sits on the running total of the ones before it.
    const base = new Array<number>(n).fill(0);
    return series.map((s) => {
      const lo = [...base];
      const hi = s.values.map((v, i) => (mode === "stacked" ? lo[i]! + v : v));
      if (mode === "stacked") hi.forEach((v, i) => (base[i] = v));
      return { s, lo: mode === "stacked" ? lo : new Array<number>(n).fill(0), hi };
    });
  }, [series, mode, n]);

  const max = yMax ?? niceMax(Math.max(1, ...stacks.flatMap((st) => st.hi)));
  const x = (i: number) => PAD.left + (n <= 1 ? innerW / 2 : (i / (n - 1)) * innerW);
  const y = (v: number) => PAD.top + innerH - (v / max) * innerH;
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((t) => t * max);
  const labelEvery = Math.max(1, Math.ceil(n / 6));

  const onMove = (e: PointerEvent<SVGRectElement>) => {
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect || n === 0) return;
    const px = ((e.clientX - rect.left) / rect.width) * W;
    const i = Math.round(((px - PAD.left) / innerW) * (n - 1));
    setActive(Math.min(n - 1, Math.max(0, i)));
  };
  const onKey = (e: KeyboardEvent<SVGSVGElement>) => {
    if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      e.preventDefault();
      setActive((a) => Math.min(n - 1, Math.max(0, (a ?? (e.key === "ArrowRight" ? -1 : n)) + (e.key === "ArrowRight" ? 1 : -1))));
    } else if (e.key === "Escape") setActive(null);
  };

  if (n === 0) return <p className="muted small-text">No data yet.</p>;

  const tipLeft = active === null ? 0 : (x(active) / W) * 100;

  return (
    <figure className="chart">
      <figcaption id={titleId} className="chart-title">
        {title}
      </figcaption>
      {series.length > 1 && (
        <div className="chart-legend">
          {series.map((s) => (
            <span key={s.key} className="chart-legend-item">
              <span className="swatch" style={{ background: s.color }} />
              {s.label}
            </span>
          ))}
        </div>
      )}
      <div className="chart-box" ref={boxRef}>
        <svg
          ref={svgRef}
          viewBox={`0 0 ${W} ${height}`}
          className="chart-svg"
          role="img"
          aria-labelledby={titleId}
          tabIndex={0}
          onKeyDown={onKey}
          onBlur={() => setActive(null)}
        >
          {ticks.map((t) => (
            <g key={t}>
              <line x1={PAD.left} x2={W - PAD.right} y1={y(t)} y2={y(t)} className="chart-gridline" />
              <text x={PAD.left - 6} y={y(t) + 4} className="chart-axis" textAnchor="end">
                {formatY(t)}
              </text>
            </g>
          ))}
          {xLabels.map((l, i) =>
            i % labelEvery === 0 || i === n - 1 ? (
              <text key={i} x={x(i)} y={height - 8} className="chart-axis" textAnchor="middle">
                {l}
              </text>
            ) : null,
          )}
          {stacks.map(({ s, lo, hi }) => {
            const top = hi.map((v, i) => `${x(i)},${y(v)}`).join(" ");
            const bottom = lo.map((v, i) => `${x(i)},${y(v)}`).reverse().join(" ");
            return (
              <g key={s.key}>
                {mode !== "line" && <polygon points={`${top} ${bottom}`} fill={s.color} className="chart-area" />}
                <polyline points={top} fill="none" stroke={s.color} className="chart-line" />
                {n <= 40 && hi.map((v, i) => <circle key={i} cx={x(i)} cy={y(v)} r={active === i ? 4.5 : 2.5} fill={s.color} className="chart-dot" />)}
              </g>
            );
          })}
          {active !== null && <line x1={x(active)} x2={x(active)} y1={PAD.top} y2={PAD.top + innerH} className="chart-cursor" />}
          <rect
            x={PAD.left}
            y={PAD.top}
            width={innerW}
            height={innerH}
            fill="transparent"
            onPointerMove={onMove}
            onPointerLeave={() => setActive(null)}
          />
        </svg>
        {active !== null && (
          <div className={`chart-tip ${tipLeft > 60 ? "left" : ""}`} style={{ left: `${tipLeft}%` }} role="status">
            <div className="chart-tip-x">{xLabels[active]}</div>
            {series.map((s) => (
              <div key={s.key} className="chart-tip-row">
                <span className="swatch" style={{ background: s.color }} />
                <span>{s.label}</span>
                <strong className="num">{formatY(s.values[active] ?? 0)}</strong>
              </div>
            ))}
          </div>
        )}
      </div>
      <details className="chart-table">
        <summary>Show data table</summary>
        <table className="data-table compact">
          <thead>
            <tr>
              <th scope="col">Point</th>
              {series.map((s) => (
                <th key={s.key} scope="col" className="num">
                  {s.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {xLabels.map((l, i) => (
              <tr key={i}>
                <th scope="row">{l}</th>
                {series.map((s) => (
                  <td key={s.key} className="num">
                    {formatY(s.values[i] ?? 0)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </figure>
  );
}
