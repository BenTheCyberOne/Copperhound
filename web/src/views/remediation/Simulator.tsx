import { useMemo, useState } from "react";
import { api, errorMessage } from "../../api/client";
import type { SimulateResponse } from "../../api/types";
import { CategoryChecklist } from "../../components/CategoryChecklist";
import { ExposureBars } from "../../components/ExposureReport";
import { KindBadge } from "../../components/KindBadge";
import { EmptyState } from "../../components/StatusView";
import { ZoneSelect } from "../../components/ZoneSelect";
import { useApp } from "../../state/AppContext";
import { useCatalog } from "../../state/CatalogContext";
import { HandOffDialog } from "../../components/HandOffDialog";
import { useFixList } from "../../state/FixListContext";
import { useZones } from "../../state/ZonesContext";
import { pctText } from "../../util/format";

const fmt = new Intl.NumberFormat();

function ResultCards({ r }: { r: SimulateResponse }) {
  return (
    <div className="sim-cards">
      <div className="stat">
        <span className="stat-label">Before</span>
        <span className="stat-value">{fmt.format(r.before.exposed_principals)}</span>
        <span className="stat-label">exposed principals · depth {r.before.max_depth}</span>
      </div>
      <div className="stat">
        <span className="stat-label">After</span>
        <span className="stat-value">{fmt.format(r.after.exposed_principals)}</span>
        <span className="stat-label">exposed principals · depth {r.after.max_depth}</span>
      </div>
      <div className={`stat reduction ${r.reduction > 0 ? "good" : ""}`}>
        <span className="stat-label">Reduction</span>
        <span className="stat-value">{pctText(r.reduction_percent)}</span>
        <span className="stat-label">{fmt.format(r.reduction)} principals lose every path</span>
      </div>
    </div>
  );
}

export function Simulator() {
  const fix = useFixList();
  const { edgeKinds } = useCatalog();
  const { zone } = useZones();
  const { track, notify } = useApp();
  const [result, setResult] = useState<SimulateResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [handOff, setHandOff] = useState(false);
  const { list } = fix;

  const kindItems = useMemo(
    () => edgeKinds.filter((k) => k.traversable).map((k) => ({ name: k.name, category: k.category, count: k.count })),
    [edgeKinds],
  );

  const run = async () => {
    setRunning(true);
    setError(null);
    try {
      const { request, missing } = await track(fix.prepare());
      if (missing > 0) notify(`${missing} fix-list item${missing === 1 ? " is" : "s are"} no longer in the graph and were dropped.`, "warn");
      setResult(await track(api.simulate(request)));
    } catch (e) {
      setResult(null);
      setError(errorMessage(e));
    } finally {
      setRunning(false);
    }
  };

  return (
    <section className="card pane" aria-labelledby="sim-title">
      {handOff && <HandOffDialog edges={list.edges} title="Fix-list remediation" onClose={() => setHandOff(false)} />}
      <div className="section-head">
        <h2 id="sim-title">What-if simulator</h2>
        <div className="head-actions">
          <button type="button" className="small" onClick={() => setHandOff(true)} disabled={list.edges.length === 0} title="Commands and tickets for the edges in the fix list">
            Hand off…
          </button>
          <button type="button" className="small" onClick={fix.clear} disabled={fix.size === 0}>
            Clear fix list
          </button>
        </div>
      </div>
      <div className="form-grid">
        <label htmlFor="sim-zone">Protect zone</label>
        <ZoneSelect id="sim-zone" value={list.zone} onChange={fix.setZone} />
      </div>

      <h3>
        Edges to remove <span className="muted num">{list.edges.length}</span>
      </h3>
      {list.edges.length === 0 ? (
        <EmptyState title="No edges yet">
          Add edges from a finding (“Simulate fix”), from a choke point (＋), or by right-clicking an edge on the canvas.
        </EmptyState>
      ) : (
        <ul className="fix-list">
          {list.edges.map((e) => (
            <li key={`${e.src.objectid}|${e.kind}|${e.dst.objectid}`}>
              <span className="fix-edge">
                <KindBadge kind={e.src.kind} dotOnly /> <span className="ellipsis">{e.src.name}</span>
                <span className="edge-kind">{e.kind} →</span>
                <KindBadge kind={e.dst.kind} dotOnly /> <span className="ellipsis">{e.dst.name}</span>
              </span>
              <button type="button" className="icon-btn danger" aria-label={`Remove ${e.kind} edge from the fix list`} onClick={() => fix.removeEdge(e)}>
                ×
              </button>
            </li>
          ))}
        </ul>
      )}

      <h3>
        Objects to remove <span className="muted num">{list.nodes.length}</span>
      </h3>
      {list.nodes.length === 0 ? (
        <p className="muted small-text">Right-click a node on the canvas → “Remove node in simulation”.</p>
      ) : (
        <ul className="fix-list">
          {list.nodes.map((n) => (
            <li key={n.objectid}>
              <span className="fix-edge">
                <KindBadge kind={n.kind} /> <span className="ellipsis">{n.name}</span>
              </span>
              <button type="button" className="icon-btn danger" aria-label={`Keep ${n.name}`} onClick={() => fix.removeNode(n)}>
                ×
              </button>
            </li>
          ))}
        </ul>
      )}

      <details className="kind-filter">
        <summary>
          Edge kinds to remove entirely {list.kinds.length > 0 && <span className="tag">{list.kinds.length}</span>}
        </summary>
        <CategoryChecklist
          label="Edge kinds to remove"
          items={kindItems}
          checked={new Set(list.kinds)}
          onChange={(s) => fix.setKinds([...s])}
          filterable
          open={false}
        />
      </details>

      <div className="row gap">
        <button type="button" className="primary" onClick={() => void run()} disabled={running || fix.size === 0}>
          {running ? "Simulating…" : "Run simulation"}
        </button>
        <span className="muted small-text">{fix.size} change{fix.size === 1 ? "" : "s"} · zone {zone(list.zone)?.name ?? list.zone}</span>
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {result && (
        <div className="sim-result" aria-live="polite">
          <ResultCards r={result} />
          <h3>Exposure by kind — before → after</h3>
          <ExposureBars rows={result.before.exposure} after={result.after.exposure} label="Exposure by kind before and after the simulated fixes" />
          <p className="muted small-text">Simulated in {result.elapsed_ms.toFixed(1)} ms.</p>
        </div>
      )}
    </section>
  );
}
