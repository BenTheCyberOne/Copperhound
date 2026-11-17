// Principals with the cheapest path to Tier Zero (GET /tier0/cheapest), by
// effort or stealth. Loaded on demand: the search covers the whole graph.

import { useState } from "react";
import { api, errorMessage } from "../api/client";
import type { CheapestResponse, CostProfile } from "../api/types";
import { useApp } from "../state/AppContext";
import { KindBadge } from "./KindBadge";

export function CheapestToTier0() {
  const { select, track, setPathFrom, setTab } = useApp();
  const [profile, setProfile] = useState<CostProfile>("effort");
  const [data, setData] = useState<CheapestResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const load = async (p: CostProfile) => {
    setProfile(p);
    setLoading(true);
    setError(null);
    try {
      setData(await track(api.cheapestToTier0(p, 25)));
    } catch (e) {
      setData(null);
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  };
  return (
    <details className="cheapest" onToggle={(e) => (e.currentTarget as HTMLDetailsElement).open && !data && !loading && void load(profile)}>
      <summary>
        <strong>Cheapest routes to Tier Zero</strong>
      </summary>
      <p className="muted small-text">
        Principals outside Tier Zero ranked by the cost of their cheapest path, not its length. Costs come from the edge kinds and
        from how long ago sessions were seen.
      </p>
      <div className="seg" role="radiogroup" aria-label="Cost profile">
        {(["effort", "stealth"] as const).map((p) => (
          <button key={p} type="button" role="radio" aria-checked={profile === p} className={profile === p ? "on" : ""} onClick={() => void load(p)} disabled={loading}>
            {p === "effort" ? "Least effort" : "Stealthiest"}
          </button>
        ))}
      </div>
      {loading && <p className="muted small-text">Searching…</p>}
      {error && <p className="error small-text">{error}</p>}
      {data && !loading && (
        <>
          <p className="muted small-text">
            {data.reachable.toLocaleString()} principals reach Tier Zero
            {data.by_cost.length > 0 && <> · cheapest cost {data.by_cost[0]!.cost}</>} · {data.elapsed_ms.toFixed(0)} ms
          </p>
          <ol className="cheapest-list">
            {data.items.map(({ node, cost }) => (
              <li key={node.id}>
                <span className="tag hop-cost" title="Cost of the cheapest path">
                  {cost}
                </span>
                <button type="button" className="hop-node" onClick={() => select(node.id)} title="Show details">
                  <KindBadge kind={node.kind} />
                  <span className="ellipsis">{node.name || node.objectid}</span>
                </button>
                <button
                  type="button"
                  className="link-btn small-text"
                  title="Open this principal in the path tab"
                  onClick={() => {
                    setPathFrom(node);
                    setTab("path");
                  }}
                >
                  path
                </button>
              </li>
            ))}
          </ol>
        </>
      )}
    </details>
  );
}
