import { useMemo, useState } from "react";
import { api } from "../../api/client";
import { KIND_CATEGORIES, SEVERITIES, type Finding, type Severity } from "../../api/types";
import { EmptyState, StatusView } from "../../components/StatusView";
import { useAnalysis } from "../../hooks/useAnalysis";
import { routeHref } from "../../hooks/useRoute";
import { useCatalog } from "../../state/CatalogContext";
import { FindingDetailView } from "./FindingDetailView";
import { ImpactBar, MitreChips, SEVERITY_LABEL, SEVERITY_RANK, SeverityBadge } from "./findingParts";
import { EnvironmentSelect } from "../../components/EnvironmentSelect";
import { useEnvironment } from "../../hooks/useEnvironment";

type SortKey = "severity" | "title" | "count" | "exposure" | "category";

const compare: Record<SortKey, (a: Finding, b: Finding) => number> = {
  severity: (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || b.count - a.count,
  title: (a, b) => a.title.localeCompare(b.title),
  count: (a, b) => a.count - b.count,
  exposure: (a, b) => (a.exposure?.principals_cut ?? -1) - (b.exposure?.principals_cut ?? -1),
  category: (a, b) => a.category.localeCompare(b.category),
};

export function FindingsView({ findingId }: { findingId: string | null }) {
  if (findingId) return <FindingDetailView id={findingId} />;
  return <FindingsList />;
}

function FindingsList() {
  const { generation } = useCatalog();
  const [env, setEnv, envs] = useEnvironment(generation);
  const state = useAnalysis(() => api.findings(env), `findings|${generation}|${env}`);
  const [severities, setSeverities] = useState<Set<Severity>>(new Set());
  const [category, setCategory] = useState("");
  const [kind, setKind] = useState("");
  const [status, setStatus] = useState<"open" | "accepted" | "all">("open");
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({ key: "severity", desc: false });

  const findings = state.data?.findings;
  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    const list = (findings ?? []).filter(
      (f) =>
        (severities.size === 0 || severities.has(f.severity)) &&
        (!category || f.category === category) &&
        (!kind || f.kind === kind) &&
        (status === "all" || (status === "accepted") === !!f.accepted) &&
        (!q || [f.title, f.description, f.id, ...f.mitre].some((s) => s.toLowerCase().includes(q))),
    );
    const cmp = compare[sort.key];
    return list.sort((a, b) => (sort.desc ? -cmp(a, b) : cmp(a, b)));
  }, [findings, severities, category, kind, status, search, sort]);

  const toggleSeverity = (s: Severity) =>
    setSeverities((cur) => {
      const next = new Set(cur);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });

  const th = (key: SortKey, label: string, className = "") => (
    <th className={className} aria-sort={sort.key === key ? (sort.desc ? "descending" : "ascending") : "none"}>
      <button type="button" className="th-btn" onClick={() => setSort((s) => ({ key, desc: s.key === key ? !s.desc : key !== "severity" && key !== "title" && key !== "category" }))}>
        {label} {sort.key === key ? (sort.desc ? "▼" : "▲") : ""}
      </button>
    </th>
  );

  return (
    <div className="view-page">
      <header className="view-head">
        <div>
          <h1>Findings</h1>
          <p className="muted">
            Misconfigurations detected in the loaded graph, ranked by severity and by how much attack-path exposure fixing
            them removes.
          </p>
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

      <StatusView state={state} what="findings" />
      {state.data && (
        <>
          <div className="sev-cards" role="group" aria-label="Filter by severity">
            {SEVERITIES.map((s) => (
              <button
                key={s}
                type="button"
                className={`sev-card sev-${s} ${severities.has(s) ? "on" : ""}`}
                aria-pressed={severities.has(s)}
                onClick={() => toggleSeverity(s)}
              >
                <span className="sev-card-count">{state.data!.summary[s]}</span>
                <span className="sev-card-label">{SEVERITY_LABEL[s]}</span>
              </button>
            ))}
          </div>

          <div className="filter-bar">
            <input type="search" placeholder="Search title, description, MITRE id…" aria-label="Search findings" value={search} onChange={(e) => setSearch(e.target.value)} />
            <EnvironmentSelect value={env} onChange={setEnv} list={envs} />
            <select aria-label="Category" value={category} onChange={(e) => setCategory(e.target.value)}>
              <option value="">All categories</option>
              {KIND_CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
            <select aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value as "open" | "accepted" | "all")}>
              <option value="open">Open</option>
              <option value="accepted">Accepted risks{state.data.accepted_count ? ` (${state.data.accepted_count})` : ""}</option>
              <option value="all">Open and accepted</option>
            </select>
            <select aria-label="Finding kind" value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="">Edges and nodes</option>
              <option value="edges">Edge findings</option>
              <option value="nodes">Node findings</option>
            </select>
            <span className="muted small-text">
              {rows.length} of {state.data.findings.length} · snapshot <code>{state.data.snapshot_id}</code> · {Math.round(state.data.computed_ms)} ms
            </span>
          </div>

          {state.data.findings.length === 0 ? (
            <EmptyState title="No findings">Nothing in this graph matched a detection. Nice.</EmptyState>
          ) : rows.length === 0 ? (
            <EmptyState title="No finding matches the filters" />
          ) : (
            <div className="table-card">
              <table className="data-table findings-table">
                <thead>
                  <tr>
                    {th("severity", "Severity")}
                    {th("title", "Finding")}
                    {th("category", "Category")}
                    {th("count", "Count", "num")}
                    {th("exposure", "Exposure impact")}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((f) => (
                    <tr key={f.id}>
                      <td>
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td>
                        <a className="finding-link" href={routeHref("findings", f.id)}>
                          {f.title}
                        </a>
                        {f.accepted && (
                          <span className="tag off small-tag" title={`Accepted by ${f.accepted.accepted_by}: ${f.accepted.reason}`}>
                            accepted risk
                          </span>
                        )}
                        <div>
                          <MitreChips ids={f.mitre} />
                        </div>
                      </td>
                      <td className="nowrap">
                        {f.category} <span className="muted small-text">· {f.kind}</span>
                      </td>
                      <td className="num">{f.count.toLocaleString()}</td>
                      <td className="impact-cell">
                        {f.exposure ? (
                          <ImpactBar cut={f.exposure.principals_cut} percent={f.exposure.percent_of_exposed} />
                        ) : (
                          <span className="muted small-text">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
