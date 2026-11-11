import { useMemo } from "react";
import { api, errorMessage } from "../../api/client";
import { SEVERITIES, type Snapshot } from "../../api/types";
import { TimeChart } from "../../components/charts/TimeChart";
import { EmptyState, StatusView } from "../../components/StatusView";
import { useAnalysis } from "../../hooks/useAnalysis";
import { navigate, routeHref, type Route } from "../../hooks/useRoute";
import { useApp } from "../../state/AppContext";
import { useCatalog } from "../../state/CatalogContext";
import { useSession } from "../../state/SessionContext";
import { SEVERITY_LABEL } from "../findings/findingParts";
import { PostureDiffView } from "./PostureDiffView";
import { pctText } from "../../util/format";

const fmt = new Intl.NumberFormat();
const shortDate = (iso: string) => new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });

export function PostureView({ route }: { route: Route }) {
  const { generation } = useCatalog();
  const { notify, track } = useApp();
  const isAdmin = useSession().atLeast("admin");
  const state = useAnalysis(api.posture, `posture|${generation}`);
  const snaps: Snapshot[] = useMemo(() => state.data ?? [], [state.data]);
  const from = route.params.get("from");
  const to = route.params.get("to");
  const selected = [from, to].filter((x): x is string => !!x);
  const current = snaps[snaps.length - 1]?.snapshot_id;

  const toggle = (id: string) => {
    let next = selected.includes(id) ? selected.filter((s) => s !== id) : [...selected, id].slice(-2);
    // Keep chronological order so the diff reads old → new.
    next = next.sort((a, b) => snaps.findIndex((s) => s.snapshot_id === a) - snaps.findIndex((s) => s.snapshot_id === b));
    navigate("posture", null, Object.fromEntries(next.map((id2, i) => [i === 0 ? "from" : "to", id2])));
  };

  const remove = async (s: Snapshot) => {
    if (!window.confirm(`Delete snapshot ${s.snapshot_id} from the posture history?`)) return;
    try {
      await track(api.deleteSnapshot(s.snapshot_id));
      if (selected.includes(s.snapshot_id)) navigate("posture");
      state.reload();
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  const labels = snaps.map((s) => shortDate(s.created_at));

  return (
    <div className="view-page">
      <header className="view-head">
        <div>
          <h1>Posture</h1>
          <p className="muted">How exposure and findings changed across graph snapshots. Pick two snapshots to compare them.</p>
        </div>
        <div className="head-actions">
          <a className="button-link" href={routeHref("reports")}>
            Export report
          </a>
          <button type="button" onClick={state.reload} disabled={state.loading}>
            Refresh
          </button>
        </div>
      </header>
      <StatusView state={state} what="posture history" />
      {state.data && snaps.length === 0 && <EmptyState title="No snapshots yet">Ingest data to record the first snapshot.</EmptyState>}
      {snaps.length > 0 && (
        <>
          <div className="chart-grid">
            <section className="card">
              <TimeChart
                title="Exposure — share of principals with a path to Tier Zero"
                mode="area"
                yMax={100}
                formatY={(v) => `${Math.round(v * 10) / 10}%`}
                xLabels={labels}
                series={[{ key: "exp", label: "Exposure", color: "var(--accent-strong)", values: snaps.map((s) => s.exposure_percent) }]}
              />
            </section>
            <section className="card">
              <TimeChart
                title="Exposed principals"
                mode="line"
                xLabels={labels}
                series={[{ key: "exposed", label: "Exposed principals", color: "var(--accent-strong)", values: snaps.map((s) => s.exposed_principals) }]}
              />
            </section>
            <section className="card span-2">
              <TimeChart
                title="Findings by severity"
                mode="stacked"
                xLabels={labels}
                series={SEVERITIES.map((sev) => ({
                  key: sev,
                  label: SEVERITY_LABEL[sev],
                  color: `var(--sev-${sev})`,
                  values: snaps.map((s) => s.findings[sev]),
                }))}
              />
            </section>
          </div>

          <section className="card">
            <div className="section-head">
              <h2>Snapshots</h2>
              <span className="muted small-text">
                {selected.length === 2 ? "Comparing the two selected snapshots below." : "Select two snapshots to compare."}
              </span>
            </div>
            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Compare</th>
                    <th>Date</th>
                    <th>Snapshot</th>
                    <th className="num">Nodes</th>
                    <th className="num">Edges</th>
                    <th className="num">Exposure</th>
                    <th className="num">Findings (C/H/M/L)</th>
                    <th>
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {[...snaps].reverse().map((s) => (
                    <tr key={s.snapshot_id} className={selected.includes(s.snapshot_id) ? "active" : ""}>
                      <td>
                        <input
                          type="checkbox"
                          aria-label={`Compare ${s.snapshot_id}`}
                          checked={selected.includes(s.snapshot_id)}
                          onChange={() => toggle(s.snapshot_id)}
                        />
                      </td>
                      <td className="nowrap">{new Date(s.created_at).toLocaleString()}</td>
                      <td>
                        <code>{s.snapshot_id}</code> {s.snapshot_id === current && <span className="tag ok">current</span>}
                      </td>
                      <td className="num">{fmt.format(s.nodes)}</td>
                      <td className="num">{fmt.format(s.edges)}</td>
                      <td className="num">
                        {pctText(s.exposure_percent)} <span className="muted small-text">({fmt.format(s.exposed_principals)}/{fmt.format(s.total_principals)})</span>
                      </td>
                      <td className="num sev-counts">
                        {SEVERITIES.map((sev) => (
                          <span key={sev} className={`sev-text sev-${sev}`} title={SEVERITY_LABEL[sev]}>
                            {s.findings[sev]}
                          </span>
                        ))}
                      </td>
                      <td>
                        {s.snapshot_id !== current && isAdmin && (
                          <button type="button" className="icon-btn danger" aria-label={`Delete snapshot ${s.snapshot_id}`} onClick={() => void remove(s)}>
                            ×
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          {from && to && <PostureDiffView from={from} to={to} />}
        </>
      )}
    </div>
  );
}
