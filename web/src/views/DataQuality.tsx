// Data view → Data quality: per AD domain / Entra tenant coverage and
// freshness (GET /quality), so missing paths can be told from missing data.

import { useEffect, useState } from "react";
import { api, errorMessage } from "../api/client";
import type { QualityResponse } from "../api/types";

function Pct({ v }: { v: number | null | undefined }) {
  if (v === null || v === undefined) return <span className="muted">—</span>;
  const cls = v >= 90 ? "ok-text" : v >= 10 ? "warn-text" : "error";
  return <span className={cls}>{v}%</span>;
}

function Age({ at, days, exact }: { at: string | null; days: number | null; exact?: boolean }) {
  if (!at) return <span className="muted">unknown</span>;
  return (
    <span title={exact ? "Collection time" : "File date (the collector recorded no collection time)"}>
      {at.slice(0, 10)}
      {days !== null && <span className={`small-text ${days > 30 ? "warn-text" : "muted"}`}> · {days} d{exact ? "" : " (file)"}</span>}
    </span>
  );
}

export function DataQuality({ generation }: { generation: number | null }) {
  const [q, setQ] = useState<QualityResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    api.quality().then(
      (r) => live && setQ(r),
      (e: unknown) => live && setError(errorMessage(e)),
    );
    return () => {
      live = false;
    };
  }, [generation]);
  if (error) return null;
  if (!q || (q.domains.length === 0 && q.tenants.length === 0)) return null;
  // Tenants can share a display name: label them with the start of their id.
  const tenantNames = new Map<string, number>();
  for (const t of q.tenants) tenantNames.set(t.name, (tenantNames.get(t.name) ?? 0) + 1);
  const label = (x: { name: string; objectid: string; type: string }) =>
    x.type === "tenant" && (tenantNames.get(x.name) ?? 0) > 1 ? `${x.name} (${x.objectid.slice(0, 8)})` : x.name;
  // One entry per warning code: the facts per domain / tenant, then the advice once.
  const groups = new Map<string, { code: string; items: { name: string; fact: string }[] }>();
  for (const x of [...q.domains, ...q.tenants]) {
    x.warnings.forEach((w, i) => {
      const code = x.warning_codes?.[i] ?? w;
      const g = groups.get(code) ?? { code, items: [] };
      g.items.push({ name: label(x), fact: w });
      groups.set(code, g);
    });
  }
  return (
    <section className="card data-quality">
      <h2>Data quality</h2>
      <p className="muted small-text">How complete the collection is. Low coverage means attack paths of that type may be missing, not absent.</p>
      {q.domains.length > 0 && (
        <table className="data-table compact">
          <thead>
            <tr>
              <th>Domain</th>
              <th className="num">Users</th>
              <th className="num">Computers</th>
              <th className="num" title="Enabled computers with session data (HasSession)">Sessions</th>
              <th className="num" title="Enabled computers with local group data (AdminTo, CanRDP, …)">Local groups</th>
              <th className="num" title="Objects whose security descriptor was read">ACLs</th>
              <th>Collected</th>
            </tr>
          </thead>
          <tbody>
            {q.domains.map((d) => (
              <tr key={d.objectid}>
                <td>{d.name}</td>
                <td className="num">{d.users.toLocaleString()}</td>
                <td className="num">{d.computers_enabled.toLocaleString()}</td>
                <td className="num">
                  <Pct v={d.session_coverage} />
                </td>
                <td className="num">
                  <Pct v={d.local_group_coverage} />
                </td>
                <td className="num">
                  <Pct v={d.acl_coverage} />
                </td>
                <td>
                  <Age at={d.collected_at} days={d.age_days} exact={d.collected_at_exact} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {q.tenants.length > 0 && (
        <table className="data-table compact">
          <thead>
            <tr>
              <th>Tenant</th>
              <th className="num">Users</th>
              <th className="num">Groups</th>
              <th className="num">Apps / SPs</th>
              <th className="num" title="Directory role assignments">Role assignments</th>
              <th className="num" title="Applications with an owner">App owners</th>
              <th className="num">Subscriptions</th>
              <th>Collected</th>
            </tr>
          </thead>
          <tbody>
            {q.tenants.map((t) => (
              <tr key={t.objectid}>
                <td title={t.objectid}>{label(t)}</td>
                <td className="num">{t.users.toLocaleString()}</td>
                <td className="num">{t.groups.toLocaleString()}</td>
                <td className="num">
                  {t.apps.toLocaleString()} / {t.service_principals.toLocaleString()}
                </td>
                <td className="num">{t.role_assignments.toLocaleString()}</td>
                <td className="num">
                  <Pct v={t.app_owner_coverage} />
                </td>
                <td className="num">{t.subscriptions.toLocaleString()}</td>
                <td>
                  <Age at={t.collected_at} days={t.age_days} exact={t.collected_at_exact} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {groups.size > 0 && (
        <ul className="plain-list quality-warnings">
          {[...groups.values()].map((g) => (
            <li key={g.code} className="small-text">
              <div className="warn-text">
                ⚠{" "}
                {g.items.map((it, i) => (
                  <span key={it.name + i}>
                    {i > 0 && " · "}
                    <strong>{it.name}</strong>: {it.fact}
                  </span>
                ))}
              </div>
              {q.advice?.[g.code] && <div className="muted">{q.advice[g.code]}</div>}
            </li>
          ))}
        </ul>
      )}
      {(q.unknown_objects ?? 0) > 0 && (
        <p className="muted small-text">
          <strong>{q.unknown_objects!.toLocaleString()}</strong> objects of unknown kind. {q.advice?.unknown}
        </p>
      )}
    </section>
  );
}
