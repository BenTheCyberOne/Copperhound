import { useCallback, useEffect, useState } from "react";
import { api, errorMessage } from "../api/client";
import type { Alert, AlertNewPath } from "../api/types";
import { EmptyState } from "../components/StatusView";
import { navigate, routeHref } from "../hooks/useRoute";
import { useApp } from "../state/AppContext";
import { useSession } from "../state/SessionContext";
import { pctText, when } from "../util/format";
import { DeliveryList } from "./admin/notify/parts";
import { SeverityBadge } from "./findings/findingParts";

const RULE_LABEL: Record<string, string> = {
  grade_worse: "Grade worse",
  exposure_increase: "Exposure up",
  new_findings: "New findings",
  new_tier0_principals: "New Tier Zero paths",
  choke_points_changed: "Choke points changed",
  watched_gained_path: "Watched principal exposed",
};

/** Letter grades: A best. A higher index is worse. */
const gradeWorse = (a: string | null, b: string | null) => !!a && !!b && b > a;

function Delta({ before, after }: { before: number | null; after: number | null }) {
  if (before === null || after === null) return <span className="muted">—</span>;
  const d = after - before;
  return (
    <span>
      {pctText(before)} → <strong>{pctText(after)}</strong>{" "}
      <span className={d > 0 ? "warn-text" : d < 0 ? "ok-text" : "muted"}>
        ({d > 0 ? "+" : ""}
        {d.toFixed(1)} pts)
      </span>
    </span>
  );
}

function AlertCard({ a }: { a: Alert }) {
  const worse = gradeWorse(a.grade_before, a.grade_after);
  const failed = a.deliveries.filter((d) => !d.ok).length;
  const { loadResult, notify, track } = useApp();
  /** Draw the stored path, resolving its objects in the current graph. */
  const showPath = async (p: AlertNewPath) => {
    try {
      const oids = [p.objectid, ...p.hops.map((h) => h.dst)];
      const found = await track(api.resolve(oids));
      const byOid = new Map(found.map((n) => [n.objectid.toUpperCase(), n]));
      const id = (o: string) => byOid.get(o.toUpperCase())?.id;
      const edges = p.hops.flatMap((h) => {
        const s = id(h.src);
        const d = id(h.dst);
        return s !== undefined && d !== undefined ? [{ src: s, dst: d, kind: h.kind }] : [];
      });
      if (edges.length < p.hops.length) notify("Some objects on this path are no longer in the graph; showing what is left.", "warn");
      const path = oids.map(id).filter((x): x is number => x !== undefined);
      loadResult({ nodes: found, edges, paths: [path], truncated: false, elapsed_ms: 0 });
      navigate("explore");
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };
  return (
    <article className="card alert-card">
      <header className="section-head">
        <div>
          <h2>{when(a.ts)}</h2>
          <span className="muted small-text">
            Snapshot <code>{a.snapshot_id}</code>
            {a.previous_snapshot_id && (
              <>
                {" "}
                vs <code>{a.previous_snapshot_id}</code> ·{" "}
                <a href={routeHref("posture", null, { from: a.previous_snapshot_id, to: a.snapshot_id })}>compare</a>
              </>
            )}
          </span>
        </div>
        <div className="tags">
          {a.triggers.map((t) => (
            <span key={t.rule} className="tag warn">
              {RULE_LABEL[t.rule] ?? t.rule}
            </span>
          ))}
        </div>
      </header>
      <div className="alert-grid">
        <div className="stat">
          <span className="stat-label">Grade</span>
          <span className="stat-value">
            {a.grade_before ?? "—"} → <span className={worse ? "warn-text" : ""}>{a.grade_after ?? "—"}</span>
          </span>
        </div>
        <div className="stat">
          <span className="stat-label">Exposure</span>
          <span className="stat-value small-value">
            <Delta before={a.exposure_before} after={a.exposure_after} />
          </span>
        </div>
        <div className="stat">
          <span className="stat-label">Newly exposed principals</span>
          <span className="stat-value">{a.new_tier0_principals.toLocaleString()}</span>
        </div>
      </div>
      <ul className="plain-list trigger-list">
        {a.triggers.map((t) => (
          <li key={t.rule}>• {t.message}</li>
        ))}
      </ul>
      {a.new_findings.length > 0 && (
        <section>
          <h3>New findings</h3>
          <ul className="plain-list">
            {a.new_findings.map((f) => (
              <li key={f.id} className="row gap">
                <SeverityBadge severity={f.severity} />
                <a href={routeHref("findings", f.id)}>{f.title}</a>
                <span className="muted small-text num">{f.count.toLocaleString()} items</span>
              </li>
            ))}
          </ul>
        </section>
      )}
      {(a.new_paths?.length ?? 0) > 0 && (
        <section>
          <h3>New paths to Tier Zero</h3>
          <ul className="plain-list alert-paths">
            {a.new_paths!.map((p) => (
              <li key={p.objectid}>
                <div className="row gap wrap">
                  <strong>{p.name}</strong>
                  {p.watched && <span className="tag warn">watched</span>}
                  <span className="muted small-text">
                    {p.hops.length} hop{p.hops.length === 1 ? "" : "s"}
                  </span>
                  <span className="spacer" />
                  {p.hops.length > 0 && (
                    <button type="button" className="small" onClick={() => void showPath(p)}>
                      Show on canvas
                    </button>
                  )}
                </div>
                <div className="path-chain small-text">
                  {p.hops.map((h, i) => (
                    <span key={i}>
                      <span className="edge-kind">{h.kind} →</span> {h.dst_name}{" "}
                    </span>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}
      {a.new_tier0_sample.length > 0 && !(a.new_paths?.length) && (
        <section>
          <h3>Newly exposed (sample)</h3>
          <div className="tags">
            {a.new_tier0_sample.map((n) => (
              <span key={n} className="tag">
                {n}
              </span>
            ))}
          </div>
        </section>
      )}
      {(a.choke_points_added.length > 0 || a.choke_points_removed.length > 0) && (
        <section>
          <h3>Choke points</h3>
          <ul className="plain-list diff-list">
            {a.choke_points_added.map((c) => (
              <li key={`+${c}`} className="diff-added">
                + <code>{c}</code>
              </li>
            ))}
            {a.choke_points_removed.map((c) => (
              <li key={`-${c}`} className="diff-removed">
                − <code>{c}</code>
              </li>
            ))}
          </ul>
        </section>
      )}
      <details className="deliveries" open={failed > 0}>
        <summary className="small-text">
          Delivery: {a.deliveries.length === 0 ? "no channels" : failed === 0 ? `all ${a.deliveries.length} delivered` : `${failed} of ${a.deliveries.length} failed`}
        </summary>
        <DeliveryList deliveries={a.deliveries} />
      </details>
    </article>
  );
}

/** #/alerts: change alerts raised after ingests (analyst and up). */
export function AlertsView() {
  const { atLeast, role } = useSession();
  const [alerts, setAlerts] = useState<Alert[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [limit, setLimit] = useState(50);
  const allowed = atLeast("analyst");

  const load = useCallback(() => {
    if (!allowed) return;
    api.alerts(limit).then(
      (r) => {
        setAlerts(r.alerts);
        setError(null);
      },
      (e: unknown) => setError(errorMessage(e)),
    );
  }, [allowed, limit]);
  useEffect(load, [load]);

  if (!allowed) {
    return (
      <div className="view-page">
        <EmptyState title="Analysts only">The alert history needs the analyst role; you are signed in as {role}.</EmptyState>
      </div>
    );
  }

  return (
    <div className="view-page">
      <header className="view-head">
        <div>
          <h1>Alerts</h1>
          <p className="muted">
            Posture changes detected after an ingest: grade, exposure, new findings, newly exposed principals and choke points.
            Newest first.
          </p>
        </div>
        <div className="head-actions">
          {atLeast("admin") && (
            <a className="button-link" href={routeHref("admin", "notifications", { tab: "alerts" })}>
              Alert rules
            </a>
          )}
          <button type="button" onClick={load}>
            Refresh
          </button>
        </div>
      </header>
      {error && <p className="error">{error}</p>}
      {!alerts && !error && <p className="muted">Loading alerts…</p>}
      {alerts && alerts.length === 0 && (
        <EmptyState title="No alerts yet">
          Alerts are recorded when a rule fires after an ingest.{" "}
          {atLeast("admin") ? (
            <a href={routeHref("admin", "notifications", { tab: "alerts" })}>Configure alert rules.</a>
          ) : (
            "An administrator configures the rules."
          )}
        </EmptyState>
      )}
      {alerts && alerts.length > 0 && (
        <div className="alert-list">
          {alerts.map((a) => (
            <AlertCard key={a.id} a={a} />
          ))}
          {alerts.length >= limit && limit < 500 && (
            <button type="button" onClick={() => setLimit((l) => Math.min(500, l + 50))}>
              Load older alerts
            </button>
          )}
        </div>
      )}
    </div>
  );
}
