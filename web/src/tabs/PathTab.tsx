import { useEffect, useMemo, useState, type FormEvent } from "react";
import { api, errorMessage } from "../api/client";
import type { CostProfile, GraphResult } from "../api/types";
import { CategoryChecklist } from "../components/CategoryChecklist";
import { NodePicker } from "../components/NodePicker";
import { hopsOf, PathHops } from "../components/PathHops";
import { useApp } from "../state/AppContext";
import { useCatalog } from "../state/CatalogContext";

export function PathTab() {
  const { pathFrom, pathTo, setPathFrom, setPathTo, loadResult, track } = useApp();
  const { edgeKinds } = useCatalog();
  const [toTier0, setToTier0] = useState(false);
  const [allEdges, setAllEdges] = useState(false);
  const [allPaths, setAllPaths] = useState(false);
  const [network, setNetwork] = useState(false);
  const [mode, setMode] = useState<"hops" | CostProfile>("hops");
  const [hasConduits, setHasConduits] = useState(false);
  useEffect(() => {
    api.network().then(
      (s) => setHasConduits(s.conduits !== null),
      () => setHasConduits(false),
    );
  }, []);
  const useNetwork = network && hasConduits && mode === "hops";
  const [exclude, setExclude] = useState<Set<string>>(new Set());
  const [result, setResult] = useState<GraphResult | null>(null);
  const [status, setStatus] = useState<{ text: string; error: boolean } | null>(null);
  const [running, setRunning] = useState(false);

  const items = useMemo(
    () =>
      edgeKinds
        .filter((k) => allEdges || k.traversable)
        .map((k) => ({ name: k.name, category: k.category, count: k.count, muted: !k.traversable })),
    [edgeKinds, allEdges],
  );

  const canRun = pathFrom !== null && (toTier0 || pathTo !== null) && !running;

  const run = async (e?: FormEvent) => {
    e?.preventDefault();
    if (!pathFrom || (!toTier0 && !pathTo)) return;
    setRunning(true);
    setStatus(null);
    try {
      // Object ids survive graph rebuilds; numeric ids do not.
      const res = await track(
        api.path({
          from: pathFrom.objectid,
          ...(toTier0 ? {} : { to: pathTo!.objectid }),
          to_tier0: toTier0,
          exclude: [...exclude],
          all_edges: allEdges,
          all: allPaths && !useNetwork && mode === "hops",
          ...(useNetwork ? { network: true } : {}),
          ...(mode !== "hops" ? { cost: mode } : {}),
        }),
      );
      const hops = hopsOf(res);
      if (hops.length === 0) {
        setResult(null);
        setStatus({ text: useNetwork ? "No path the network conduits allow." : "No path found.", error: false });
        return;
      }
      setResult(res);
      const many = res.all_paths;
      const zones = res.zones?.filter((z): z is string => z !== null) ?? [];
      const route = zones.filter((z, i) => i === 0 || z !== zones[i - 1]);
      const extra = res.cost
        ? ` · ${res.cost.profile} cost ${res.cost.total}`
        : many
          ? ` · all shortest paths: ${many.nodes} objects, ${many.edges} relationships${many.truncated ? " (capped)" : ""}`
          : res.network
            ? ` · network-feasible${route.length > 0 ? `: ${route.join(" → ")}` : ""}`
            : "";
      setStatus({ text: `${hops.length} hop${hops.length === 1 ? "" : "s"}${extra} · ${res.elapsed_ms.toFixed(1)} ms`, error: false });
      loadResult(res, { path: true });
    } catch (err) {
      setResult(null);
      setStatus({ text: errorMessage(err), error: true });
    } finally {
      setRunning(false);
    }
  };

  return (
    <form className="tab-body" onSubmit={(e) => void run(e)}>
      <div className="field-label">From</div>
      <NodePicker label="Path start" value={pathFrom} onSelect={setPathFrom} onClear={() => setPathFrom(null)} />

      <div className="field-label">To</div>
      <label className="toggle">
        <input type="checkbox" checked={toTier0} onChange={(e) => setToTier0(e.target.checked)} />
        Any Tier Zero object
      </label>
      {!toTier0 && <NodePicker label="Path end" value={pathTo} onSelect={setPathTo} onClear={() => setPathTo(null)} />}
      <div className="field-label">Optimise for</div>
      <div className="seg" role="radiogroup" aria-label="Optimise for">
        {(
          [
            ["hops", "Fewest hops", "The shortest path by number of steps"],
            ["effort", "Least effort", "The path that needs the least work: credential theft, cracking and coercion cost more"],
            ["stealth", "Stealthiest", "The path least likely to be noticed: DCSync, password resets and group membership changes cost more"],
          ] as const
        ).map(([v, label, title]) => (
          <button key={v} type="button" role="radio" aria-checked={mode === v} className={mode === v ? "on" : ""} title={title} onClick={() => setMode(v)}>
            {label}
          </button>
        ))}
      </div>
      {mode === "hops" && (
        <label className="toggle" title="Draw every path of the shortest length, not just one">
          <input type="checkbox" checked={allPaths && !useNetwork} disabled={useNetwork} onChange={(e) => setAllPaths(e.target.checked)} />
          All shortest paths
        </label>
      )}
      {hasConduits && mode === "hops" && (
        <label className="toggle" title="Follow only paths the network conduits allow (Admin → Server → Network conduits)">
          <input type="checkbox" checked={network} onChange={(e) => setNetwork(e.target.checked)} />
          Only paths the network allows
        </label>
      )}

      <details className="kind-filter">
        <summary>
          Excluded edge kinds {exclude.size > 0 && <span className="tag">{exclude.size}</span>}
        </summary>
        <label className="toggle">
          <input type="checkbox" checked={allEdges} onChange={(e) => setAllEdges(e.target.checked)} />
          Include non-traversable edge kinds
        </label>
        <CategoryChecklist label="Edge kinds to exclude" items={items} checked={exclude} onChange={setExclude} filterable open={false} />
      </details>

      <div className="row gap">
        <button type="submit" className="primary" disabled={!canRun}>
          {running ? "Searching…" : mode === "hops" ? "Find shortest path" : "Find cheapest path"}
        </button>
        <button
          type="button"
          onClick={() => {
            const f = pathFrom;
            setPathFrom(pathTo);
            setPathTo(f);
          }}
          disabled={toTier0 || (!pathFrom && !pathTo)}
          title="Swap start and end"
        >
          Swap
        </button>
      </div>

      {status && <p className={status.error ? "error" : "muted"}>{status.text}</p>}
      {result && <PathHops hops={hopsOf(result)} nodes={result.nodes} costs={result.cost?.hop_costs} />}
    </form>
  );
}
