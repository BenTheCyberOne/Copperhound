// A finding across posture snapshots: item count trend and what changed in
// the latest snapshot (GET /findings/{id}/history).

import { useEffect, useState } from "react";
import { api } from "../../api/client";
import type { FindingHistory } from "../../api/types";
import { TimeChart } from "../../components/charts/TimeChart";

export function FindingTrend({ id, generation }: { id: string; generation: number | null }) {
  const [h, setH] = useState<FindingHistory | null>(null);
  useEffect(() => {
    let live = true;
    api.findingHistory(id).then(
      (r) => live && setH(r),
      () => live && setH(null),
    );
    return () => {
      live = false;
    };
  }, [id, generation]);
  if (!h || h.points.length === 0) return null;
  const c = h.latest_change;
  return (
    <section className="card finding-trend">
      <h2>Over time</h2>
      {h.points.length > 1 ? (
        <TimeChart
          title="Items per snapshot"
          mode="area"
          height={160}
          xLabels={h.points.map((p) => p.created_at.slice(0, 10))}
          series={[{ key: "n", label: "Items", color: "var(--accent-strong)", values: h.points.map((p) => p.count) }]}
        />
      ) : (
        <p className="muted small-text">Only one snapshot so far; the trend appears after the next ingest.</p>
      )}
      {c && (
        <div className="trend-change">
          <p>
            Since the previous snapshot ({c.from_at.slice(0, 10)}): <strong className="warn-text">+{c.added}</strong> new,{" "}
            <strong className="ok-text">−{c.removed}</strong> resolved.
          </p>
          {c.added_sample.length > 0 && (
            <details>
              <summary>New items</summary>
              <ul className="plain-list small-text">
                {c.added_sample.map((l) => (
                  <li key={l}>{l}</li>
                ))}
              </ul>
            </details>
          )}
          {c.removed_sample.length > 0 && (
            <details>
              <summary>Resolved items</summary>
              <ul className="plain-list small-text">
                {c.removed_sample.map((l) => (
                  <li key={l}>{l}</li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}
    </section>
  );
}
