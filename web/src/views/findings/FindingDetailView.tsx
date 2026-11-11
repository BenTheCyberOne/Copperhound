import { useState } from "react";
import { api, errorMessage } from "../../api/client";
import type { FindingDetail, FindingItem, GraphResult } from "../../api/types";
import { EdgeHelpList, EdgeKindLabel } from "../../components/EdgeHelp";
import { KindBadge } from "../../components/KindBadge";
import { Pager } from "../../components/Pager";
import { EmptyState, StatusView } from "../../components/StatusView";
import { useAnalysis } from "../../hooks/useAnalysis";
import { navigate, routeHref } from "../../hooks/useRoute";
import { useApp } from "../../state/AppContext";
import { useCatalog } from "../../state/CatalogContext";
import { useFixList, type FixEdge } from "../../state/FixListContext";
import { downloadCsv } from "../../util/csv";
import { ImpactBar, MitreChips, RichText, SeverityBadge } from "./findingParts";
import { FindingTrend } from "./FindingTrend";
import { RiskAcceptanceCard } from "./RiskAcceptanceCard";
import { useEnvironment } from "../../hooks/useEnvironment";

const PAGE = 100;
const EXPORT_MAX = 20000;

const isEdge = (i: FindingItem): i is FixEdge => "src" in i;

/** Fetches every item page (bounded), e.g. for CSV export or "simulate fixing all". */
async function allItems(id: string, total: number, env?: string): Promise<FindingItem[]> {
  const out: FindingItem[] = [];
  for (let offset = 0; offset < Math.min(total, EXPORT_MAX); offset += 1000) {
    out.push(...(await api.finding(id, offset, 1000, env)).items);
  }
  return out;
}

function itemGraph(items: FindingItem[]): GraphResult {
  const nodes = new Map(items.flatMap((i) => (isEdge(i) ? [i.src, i.dst] : [i.node])).map((n) => [n.id, n]));
  const edges = items.filter(isEdge).map((i) => ({ src: i.src.id, dst: i.dst.id, kind: i.kind }));
  return { nodes: [...nodes.values()], edges, truncated: false, elapsed_ms: 0 };
}

export function FindingDetailView({ id }: { id: string }) {
  const { generation } = useCatalog();
  const { loadResult, openInEditor, notify, track } = useApp();
  const fixList = useFixList();
  const [offset, setOffset] = useState(0);
  const [env, , envs] = useEnvironment(generation);
  const envName = envs.find((e) => e.id === env)?.name;
  const state = useAnalysis(() => api.finding(id, offset, PAGE, env), `${id}|${offset}|${generation}|${env}`);
  const f: FindingDetail | null = state.data && state.data.id === id ? state.data : null;

  const showOnCanvas = (g: GraphResult) => {
    loadResult(g, { forceMerge: false });
    navigate("explore");
  };

  const addToFixList = (edges: FixEdge[]) => {
    const n = fixList.addEdges(edges);
    notify(n > 0 ? `Added ${n} edge${n === 1 ? "" : "s"} to the fix list.` : "Those edges are already in the fix list.");
  };

  const exportCsv = async () => {
    if (!f) return;
    try {
      const items = await track(allItems(f.id, f.total, env));
      if (f.kind === "edges") {
        downloadCsv(
          `${f.id}.csv`,
          ["source", "source_kind", "source_objectid", "edge", "target", "target_kind", "target_objectid"],
          items.filter(isEdge).map((i) => [i.src.name, i.src.kind, i.src.objectid, i.kind, i.dst.name, i.dst.kind, i.dst.objectid]),
        );
      } else {
        downloadCsv(
          `${f.id}.csv`,
          ["name", "kind", "objectid", "enabled", "tier0"],
          items.flatMap((i) => ("node" in i ? [[i.node.name, i.node.kind, i.node.objectid, i.node.enabled, i.node.tier0]] : [])),
        );
      }
      if (f.total > EXPORT_MAX) notify(`Exported the first ${EXPORT_MAX.toLocaleString()} of ${f.total.toLocaleString()} items.`, "warn");
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  const simulateAll = async () => {
    if (!f) return;
    try {
      const items = await track(allItems(f.id, f.total, env));
      addToFixList(items.filter(isEdge));
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  return (
    <div className="view-page">
      <nav className="breadcrumbs" aria-label="Breadcrumb">
        <a href={routeHref("findings")}>Findings</a> <span aria-hidden="true">/</span> <span>{f?.title ?? id}</span>
      </nav>
      <StatusView state={state} what="this finding" />
      {state.error && state.data && <p className="error">{state.error}</p>}
      {f && (
        <>
          <header className="view-head">
            <div>
              <div className="row gap wrap">
                <SeverityBadge severity={f.severity} />
                {f.accepted && <span className="tag off">accepted risk</span>}
                <span className="muted small-text">
                  {f.category} · {f.kind === "edges" ? "edge finding" : "node finding"} · <code>{f.id}</code>
                  {envName && <> · only {envName}</>}
                </span>
              </div>
              <h1>{f.title}</h1>
              <MitreChips ids={f.mitre} />
            </div>
            <div className="head-actions">
              <button type="button" className="primary" onClick={() => showOnCanvas(f.graph)}>
                Show on canvas
              </button>
              {f.kind === "edges" && (
                <button type="button" onClick={() => void simulateAll()}>
                  Simulate fixing all
                </button>
              )}
              <button type="button" onClick={() => void exportCsv()}>
                Export CSV
              </button>
            </div>
          </header>

          <div className="stat-grid wide">
            <div className="stat">
              <span className="stat-value">{f.total.toLocaleString()}</span>
              <span className="stat-label">{f.kind === "edges" ? "affected edges" : "affected objects"}</span>
            </div>
            {f.exposure && (
              <div className="stat stat-wide">
                <span className="stat-value">{f.exposure.principals_cut.toLocaleString()}</span>
                <span className="stat-label">principals would lose every path to Tier Zero if fixed</span>
                <ImpactBar cut={f.exposure.principals_cut} percent={f.exposure.percent_of_exposed} />
              </div>
            )}
          </div>

          <RiskAcceptanceCard id={f.id} accepted={f.accepted} onChange={state.reload} />
          <FindingTrend id={f.id} generation={generation} />

          <div className="finding-grid">
            <section className="card">
              <h2>What it is</h2>
              <RichText text={f.description} />
              <h2>Why it matters</h2>
              <RichText text={f.impact} />
              <h2>How to fix it</h2>
              <RichText text={f.remediation} />
            </section>
            <section className="card">
              <div className="section-head">
                <h2>Detection query</h2>
                <button
                  type="button"
                  className="small"
                  onClick={() => {
                    openInEditor(f.query);
                    navigate("explore");
                  }}
                >
                  Open in editor
                </button>
              </div>
              <pre className="code-block">{f.query}</pre>
              {f.kind === "edges" && <EdgeHelpList title="About these edges" kinds={f.items.filter(isEdge).map((i) => i.kind)} />}
            </section>
          </div>

          <section className="card">
            <div className="section-head">
              <h2>
                Items <span className="muted num">{f.total.toLocaleString()}</span>
              </h2>
              <Pager offset={offset} total={f.total} page={PAGE} onChange={setOffset} />
            </div>
            {f.items.length === 0 ? (
              <EmptyState title="No items on this page" />
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    {f.kind === "edges" ? (
                      <>
                        <th>Source</th>
                        <th>Edge</th>
                        <th>Target</th>
                      </>
                    ) : (
                      <>
                        <th>Object</th>
                        <th>Kind</th>
                      </>
                    )}
                    <th>
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {f.items.map((i, k) => (
                    <tr key={isEdge(i) ? `${i.src.id}|${i.kind}|${i.dst.id}` : `${i.node.id}-${k}`}>
                      {isEdge(i) ? (
                        <>
                          <td>
                            <KindBadge kind={i.src.kind} dotOnly /> {i.src.name}
                          </td>
                          <td className="edge-kind">
                            <EdgeKindLabel kind={i.kind} />
                          </td>
                          <td>
                            <KindBadge kind={i.dst.kind} dotOnly /> {i.dst.name}
                          </td>
                        </>
                      ) : (
                        <>
                          <td>{i.node.name}</td>
                          <td>
                            <KindBadge kind={i.node.kind} />
                          </td>
                        </>
                      )}
                      <td className="row-actions">
                        <button type="button" className="small" onClick={() => showOnCanvas(itemGraph([i]))}>
                          Show
                        </button>
                        {isEdge(i) && (
                          <button type="button" className="small" onClick={() => addToFixList([i])}>
                            Simulate fix
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </>
      )}
    </div>
  );
}
