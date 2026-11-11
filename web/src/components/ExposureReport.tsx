import type { ChokePoint, ExposureRow, Tier0Report } from "../api/types";
import { kindShort } from "../graph/kinds";
import { EdgeKindLabel } from "./EdgeHelp";
import { KindBadge } from "./KindBadge";

const fmt = new Intl.NumberFormat();
export const pct = (a: number, b: number) => (b === 0 ? 0 : (a / b) * 100);
export const chokeKey = (cp: ChokePoint) => `${cp.src.id}|${cp.kind}|${cp.dst.id}`;

/** Horizontal bars: share of each kind with a path into the zone. Optional "after" values for comparisons. */
export function ExposureBars({ rows, after, label }: { rows: ExposureRow[]; after?: ExposureRow[]; label: string }) {
  const afterBy = new Map((after ?? []).map((r) => [r.kind, r]));
  // In before/after comparisons, kinds that were never exposed are just noise.
  const sorted = [...rows].filter((r) => r.total > 0 && (!after || r.with_path > 0)).sort((a, b) => pct(b.with_path, b.total) - pct(a.with_path, a.total));
  if (sorted.length === 0) return <p className="muted small-text">No principals.</p>;
  return (
    <ul className="bars" aria-label={label}>
      {sorted.map((row) => {
        const p = pct(row.with_path, row.total);
        const a = afterBy.get(row.kind);
        const pa = a ? pct(a.with_path, a.total) : null;
        return (
          <li key={row.kind} title={`${fmt.format(row.with_path)} of ${fmt.format(row.total)} ${row.kind} objects`}>
            <div className="bar-label">
              <span>{kindShort(row.kind)}</span>
              <span className="num">
                {pa === null ? (
                  <>
                    {p.toFixed(1)}% <span className="muted">· {fmt.format(row.with_path)}/{fmt.format(row.total)}</span>
                  </>
                ) : (
                  <>
                    {p.toFixed(1)}% → <strong>{pa.toFixed(1)}%</strong>
                  </>
                )}
              </span>
            </div>
            <div className="bar-track" role="presentation">
              <div className={`bar-fill ${pa !== null ? "before" : ""}`} style={{ width: `${Math.max(p, p > 0 ? 1 : 0)}%` }} />
            </div>
            {pa !== null && (
              <div className="bar-track after" role="presentation">
                <div className="bar-fill" style={{ width: `${Math.max(pa, pa > 0 ? 1 : 0)}%` }} />
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}

interface Props {
  report: Tier0Report;
  zoneName: string;
  activeKey: string | null;
  onShowChoke: (cp: ChokePoint) => void;
  onAddToFixList: (cp: ChokePoint) => void;
}

/** Exposure summary, per-kind bars and choke points for one zone (Tier Zero tab, Zones view). */
export function ExposureReport({ report, zoneName, activeKey, onShowChoke, onAddToFixList }: Props) {
  return (
    <>
      <div className="stat-grid">
        <div className="stat">
          <span className="stat-value">{fmt.format(report.tier0_nodes)}</span>
          <span className="stat-label">{zoneName} objects</span>
        </div>
        <div className="stat">
          <span className="stat-value">{fmt.format(report.exposed_principals)}</span>
          <span className="stat-label">principals with a path</span>
        </div>
        <div className="stat">
          <span className="stat-value">{report.max_depth}</span>
          <span className="stat-label">max depth (hops)</span>
        </div>
      </div>

      <ExposureBars rows={report.exposure} label={`Share of objects with a path to ${zoneName}, by kind`} />

      <h3>Choke points</h3>
      <p className="muted small-text">
        Edges carrying the most shortest paths into {zoneName}. Click a row to draw it, or add it to the what-if fix list.
      </p>
      <div className="table-scroll">
        <table className="data-table choke-table">
          <thead>
            <tr>
              <th>Source → edge → target</th>
              <th className="num">Flow</th>
              <th>
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {report.choke_points.map((cp) => {
              const key = chokeKey(cp);
              return (
                <tr
                  key={key}
                  className={`clickable ${activeKey === key ? "active" : ""}`}
                  tabIndex={0}
                  onClick={() => onShowChoke(cp)}
                  onKeyDown={(e) => {
                    if (e.target === e.currentTarget && (e.key === "Enter" || e.key === " ")) {
                      e.preventDefault();
                      onShowChoke(cp);
                    }
                  }}
                >
                  <td>
                    <div className="choke-node">
                      <KindBadge kind={cp.src.kind} dotOnly /> <span className="cell-name">{cp.src.name}</span>
                    </div>
                    <div className="edge-kind">
                      ↳ <EdgeKindLabel kind={cp.kind} />
                    </div>
                    <div className="choke-node">
                      <KindBadge kind={cp.dst.kind} dotOnly /> <span className="cell-name">{cp.dst.name}</span>
                    </div>
                  </td>
                  <td className="num">{fmt.format(Math.round(cp.flow))}</td>
                  <td>
                    <button
                      type="button"
                      className="icon-btn"
                      title="Add to what-if fix list"
                      aria-label={`Add ${cp.src.name} ${cp.kind} ${cp.dst.name} to the fix list`}
                      onClick={(e) => {
                        e.stopPropagation();
                        onAddToFixList(cp);
                      }}
                    >
                      ＋
                    </button>
                  </td>
                </tr>
              );
            })}
            {report.choke_points.length === 0 && (
              <tr>
                <td colSpan={3} className="muted">
                  No choke points — nothing reaches {zoneName}.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <p className="muted small-text">Computed in {fmt.format(Math.round(report.elapsed_ms))} ms.</p>
    </>
  );
}
