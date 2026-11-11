import { api } from "../../api/client";
import { EmptyState, StatusView } from "../../components/StatusView";
import { useAnalysis } from "../../hooks/useAnalysis";
import { routeHref } from "../../hooks/useRoute";
import { SEVERITY_RANK, SeverityBadge } from "../findings/findingParts";

/** Findings that changed between two snapshots; added items in red, resolved in green. */
export function PostureDiffView({ from, to }: { from: string; to: string }) {
  const state = useAnalysis(() => api.postureDiff(from, to), `${from}|${to}`);
  const findings = [...(state.data?.findings ?? [])].sort(
    (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || b.added - a.added,
  );
  const added = findings.reduce((n, f) => n + f.added, 0);
  const removed = findings.reduce((n, f) => n + f.removed, 0);

  return (
    <section className="card" aria-labelledby="diff-title">
      <div className="section-head">
        <h2 id="diff-title">
          Changes <code>{from}</code> → <code>{to}</code>
        </h2>
        {state.data && (
          <span className="small-text">
            <span className="diff-added">+{added} new</span> · <span className="diff-removed">−{removed} resolved</span>
          </span>
        )}
      </div>
      <StatusView state={state} what="the comparison" />
      {state.data && findings.length === 0 && <EmptyState title="No finding changed between these snapshots" />}
      <ul className="diff-list">
        {findings.map((f) => (
          <li key={f.id}>
            <details>
              <summary>
                <SeverityBadge severity={f.severity} />
                <span className="diff-title">{f.title}</span>
                {f.added > 0 && <span className="diff-added">+{f.added}</span>}
                {f.removed > 0 && <span className="diff-removed">−{f.removed}</span>}
                <a className="small-text" href={routeHref("findings", f.id)} onClick={(e) => e.stopPropagation()}>
                  open finding
                </a>
              </summary>
              <div className="diff-items">
                {f.added_items.length > 0 && (
                  <div>
                    <h4 className="diff-added">New</h4>
                    <ul>
                      {f.added_items.map((i) => (
                        <li key={i.key} className="diff-added">
                          + {i.label}
                        </li>
                      ))}
                      {f.added > f.added_items.length && <li className="muted">… {f.added - f.added_items.length} more</li>}
                    </ul>
                  </div>
                )}
                {f.removed_items.length > 0 && (
                  <div>
                    <h4 className="diff-removed">Resolved</h4>
                    <ul>
                      {f.removed_items.map((i) => (
                        <li key={i.key} className="diff-removed">
                          − {i.label}
                        </li>
                      ))}
                      {f.removed > f.removed_items.length && <li className="muted">… {f.removed - f.removed_items.length} more</li>}
                    </ul>
                  </div>
                )}
              </div>
            </details>
          </li>
        ))}
      </ul>
    </section>
  );
}
