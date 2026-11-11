import { useMemo, useState } from "react";
import type { Source, SourcesResponse } from "../api/types";
import { MergeHelp } from "../components/MergeHelp";
import { when } from "../util/format";
import { collectedSourceHelp, collectedSourceLabel, MERGE_POLICY_HELP, sourceWarnings } from "../util/sources";

const fmt = new Intl.NumberFormat();
const FILTER_FROM = 8;

function Superseded({ objects, edges }: { objects: number; edges: number }) {
  if (objects === 0 && edges === 0) return <span className="muted">—</span>;
  return (
    <span title={`${fmt.format(objects)} object records overridden by newer sources; ${fmt.format(edges)} edge records dropped or restated`}>
      {fmt.format(objects)} / {fmt.format(edges)}
    </span>
  );
}

export function SourceRow({ s, all }: { s: Source; all: Source[] }) {
  const warnings = sourceWarnings(s, all);
  return (
    <tr>
      <td className="num muted">{s.id}</td>
      <td>
        <div className="source-file">
          <span className="break">{s.file}</span>
          {s.entry && <span className="muted small-text break">› {s.entry}</span>}
          {warnings.length > 0 && (
            <span className="tags">
              {warnings.map((w) => (
                <span key={w.id} className="tag warn small-tag" title={w.title}>
                  ⚠ {w.label}
                </span>
              ))}
            </span>
          )}
        </div>
      </td>
      <td>
        {s.format}
        {s.kind && <span className="muted small-text"> · {s.kind}</span>}
      </td>
      <td className="small-text">
        {s.domains.length === 0 ? (
          <span className="muted">—</span>
        ) : (
          <span className="break" title={s.domains.join("\n")}>
            {s.domains.slice(0, 3).join(", ")}
            {s.domains.length > 3 && <span className="muted"> +{s.domains.length - 3}</span>}
          </span>
        )}
      </td>
      <td className="nowrap">
        {s.collected_at ? when(s.collected_at) : <span className="warn-text">undated</span>}
        <div className={`small-text ${s.collected_at_source === "whenchanged" || !s.collected_at_source ? "warn-text" : "muted"}`} title={collectedSourceHelp(s.collected_at_source)}>
          {collectedSourceLabel(s.collected_at_source)}
          {s.collected_at_source === "whenchanged" && " (lower bound)"}
        </div>
      </td>
      <td className="num">{fmt.format(s.objects)}</td>
      <td className="num">{fmt.format(s.edges)}</td>
      <td className="num">
        <Superseded objects={s.superseded_objects} edges={s.superseded_edges} />
      </td>
      <td className={`num ${s.parse_errors > 0 ? "warn-text" : ""}`}>{fmt.format(s.parse_errors)}</td>
    </tr>
  );
}

/** "Sources" card of the Data view: every input file / zip entry of the loaded graph. */
export function SourcesSection({ data }: { data: SourcesResponse | null }) {
  const [filter, setFilter] = useState("");
  const sources = useMemo(() => data?.sources ?? [], [data]);
  const shown = useMemo(() => {
    const f = filter.trim().toLowerCase();
    if (!f) return sources;
    return sources.filter((s) =>
      [s.file, s.entry ?? "", s.format, s.kind ?? "", ...s.domains].some((x) => x.toLowerCase().includes(f)),
    );
  }, [sources, filter]);

  const totals = useMemo(() => {
    const dated = sources.filter((s) => s.collected_at !== null).length;
    const warned = sources.filter((s) => sourceWarnings(s, sources).length > 0).length;
    return {
      dated,
      undated: sources.length - dated,
      warned,
      objects: sources.reduce((a, s) => a + s.objects, 0),
      edges: sources.reduce((a, s) => a + s.edges, 0),
      parseErrors: sources.reduce((a, s) => a + s.parse_errors, 0),
    };
  }, [sources]);

  return (
    <section className="card span-2" aria-labelledby="sources-head">
      <div className="section-head">
        <h2 id="sources-head">
          Sources <span className="muted num">{sources.length}</span>
        </h2>
        <MergeHelp />
      </div>
      {data === null ? (
        <p className="muted small-text">This server does not report sources.</p>
      ) : data.merge_policy === null ? (
        <p className="muted small-text">
          The loaded graph was built before source tracking existed (or no graph is loaded). Rebuild the graph to see where each
          object came from.
        </p>
      ) : (
        <>
          <dl className="source-totals">
            <dt>Merge policy</dt>
            <dd>
              <span className="tag" title={MERGE_POLICY_HELP[data.merge_policy]}>
                {data.merge_policy}
              </span>{" "}
              <span className="muted small-text">{MERGE_POLICY_HELP[data.merge_policy]}</span>
            </dd>
            <dt>Sources</dt>
            <dd>
              {fmt.format(sources.length)} ({fmt.format(totals.dated)} dated
              {totals.undated > 0 && <span className="warn-text">, {fmt.format(totals.undated)} undated</span>})
            </dd>
            <dt>Read</dt>
            <dd>
              {fmt.format(totals.objects)} object records, {fmt.format(totals.edges)} edge records
              {totals.parseErrors > 0 && <span className="warn-text">, {fmt.format(totals.parseErrors)} parse errors</span>}
            </dd>
            <dt>Superseded</dt>
            <dd>
              {fmt.format(data.superseded_objects ?? 0)} object records, {fmt.format(data.superseded_edges ?? 0)} edge records
              <span className="muted small-text"> overridden by newer collections</span>
            </dd>
          </dl>
          {totals.warned > 0 && (
            <p className="notice warn">
              <span>
                {totals.warned} source{totals.warned === 1 ? " has" : "s have"} no reliable collection time. Undated files are merged as a
                plain union; prefix the file name with <code>YYYYMMDDHHMMSS_</code> (UTC) and rebuild to order them.
              </span>
            </p>
          )}
          {sources.length >= FILTER_FROM && (
            <input
              type="search"
              className="sources-filter"
              placeholder="Filter by file, format, kind or domain…"
              aria-label="Filter sources"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
          )}
          {sources.length === 0 ? (
            <p className="muted small-text">No sources.</p>
          ) : (
            <div className="table-scroll">
              <table className="data-table compact sources-table">
                <thead>
                  <tr>
                    <th className="num">#</th>
                    <th>File</th>
                    <th>Format</th>
                    <th>Domains / tenants</th>
                    <th>Collected</th>
                    <th className="num">Objects</th>
                    <th className="num">Edges</th>
                    <th className="num" title="Object records / edge records overridden by a newer source">
                      Superseded
                    </th>
                    <th className="num">Errors</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((s) => (
                    <SourceRow key={s.id} s={s} all={sources} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </section>
  );
}
