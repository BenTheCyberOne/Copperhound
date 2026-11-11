import { useState } from "react";
import { api, errorMessage } from "../../api/client";
import type { ReviewStatus, Zone } from "../../api/types";
import { KindBadge } from "../../components/KindBadge";
import { Pager } from "../../components/Pager";
import { EmptyState, StatusView } from "../../components/StatusView";
import { useAnalysis } from "../../hooks/useAnalysis";
import { useApp } from "../../state/AppContext";
import { useCatalog } from "../../state/CatalogContext";
import { useSession } from "../../state/SessionContext";
import { useZones } from "../../state/ZonesContext";

const PAGE = 200;
const FILTERS: { id: ReviewStatus | ""; label: string }[] = [
  { id: "pending", label: "Pending" },
  { id: "certified", label: "Certified" },
  { id: "revoked", label: "Revoked" },
  { id: "", label: "All" },
];

/**
 * Certify or revoke each object a zone's selector matches. Revoked objects
 * leave the zone (and its exposure and paths) until reset to pending.
 */
export function ZoneReviewPanel({ zone }: { zone: Zone }) {
  const { generation } = useCatalog();
  const { reload } = useZones();
  const { notify, track } = useApp();
  const { gate } = useSession();
  const [filter, setFilter] = useState<ReviewStatus | "">("pending");
  const [offset, setOffset] = useState(0);
  const [version, setVersion] = useState(0);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const review = useAnalysis(() => api.zoneReview(zone.id, filter, offset, PAGE), `${zone.id}|${filter}|${offset}|${generation}|${version}`, true);
  const rows = review.data?.items ?? [];
  const allPicked = rows.length > 0 && rows.every((r) => picked.has(r.node.objectid));

  const decide = async (objectids: string[], status: ReviewStatus) => {
    if (objectids.length === 0) return;
    if (status === "revoked" && !window.confirm(`Revoke ${objectids.length.toLocaleString()} object(s) from “${zone.name}”? They leave the zone until reset to pending.`)) return;
    setBusy(true);
    try {
      await track(api.reviewZone(zone.id, objectids, status, note.trim()));
      notify(`${objectids.length.toLocaleString()} object(s) ${status === "pending" ? "reset to pending" : status}`, "info");
      setPicked(new Set());
      setNote("");
      setVersion((v) => v + 1);
      reload();
    } catch (e) {
      notify(errorMessage(e), "error");
    } finally {
      setBusy(false);
    }
  };

  const toggle = (oid: string) =>
    setPicked((s) => {
      const n = new Set(s);
      if (n.has(oid)) n.delete(oid);
      else n.add(oid);
      return n;
    });

  const counts = review.data?.counts;
  const g = gate("analyst");
  const gated = { ...g, disabled: g.disabled || busy || picked.size === 0 };
  return (
    <div role="tabpanel" className="zone-review">
      <p className="muted small-text">
        Certify objects that belong in this zone; revoke ones the selector picked up by mistake. Revoked objects drop out of the zone, its exposure and paths. New matches show up as
        pending.
      </p>
      <div className="section-head wrap">
        <div className="seg" role="group" aria-label="Review status">
          {FILTERS.map((f) => (
            <button
              key={f.id || "all"}
              type="button"
              className={filter === f.id ? "on" : ""}
              aria-pressed={filter === f.id}
              onClick={() => {
                setFilter(f.id);
                setOffset(0);
                setPicked(new Set());
              }}
            >
              {f.label}
              {counts && f.id && <span className="num muted"> {counts[f.id].toLocaleString()}</span>}
            </button>
          ))}
        </div>
        {review.data && <Pager offset={offset} total={review.data.total} page={PAGE} onChange={setOffset} />}
      </div>
      <div className="row gap wrap review-actions">
        <input type="text" placeholder="Note (optional)" value={note} maxLength={1000} onChange={(e) => setNote(e.target.value)} aria-label="Review note" />
        <button type="button" className="small primary" {...gated} onClick={() => void decide([...picked], "certified")}>
          Certify {picked.size > 0 ? picked.size.toLocaleString() : ""}
        </button>
        <button type="button" className="small danger" {...gated} onClick={() => void decide([...picked], "revoked")}>
          Revoke {picked.size > 0 ? picked.size.toLocaleString() : ""}
        </button>
        <button type="button" className="small" {...gated} onClick={() => void decide([...picked], "pending")}>
          Reset to pending
        </button>
      </div>
      <StatusView state={review} what="zone review" />
      {review.data &&
        (rows.length === 0 ? (
          <EmptyState title={filter === "pending" ? "Nothing pending" : "No objects"}>{filter === "pending" ? "Every object this zone matches has been reviewed." : null}</EmptyState>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    aria-label="Select all on this page"
                    checked={allPicked}
                    onChange={() => setPicked(allPicked ? new Set() : new Set(rows.map((r) => r.node.objectid)))}
                  />
                </th>
                <th>Name</th>
                <th>Kind</th>
                <th>Status</th>
                <th>Decided</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.node.id}>
                  <td>
                    <input type="checkbox" aria-label={`Select ${r.node.name}`} checked={picked.has(r.node.objectid)} onChange={() => toggle(r.node.objectid)} />
                  </td>
                  <td>{r.node.name}</td>
                  <td>
                    <KindBadge kind={r.node.kind} />
                  </td>
                  <td>
                    <span className={`tag ${r.status === "certified" ? "ok" : r.status === "revoked" ? "off" : "warn"}`}>{r.status}</span>
                  </td>
                  <td className="muted small-text">
                    {r.decision ? (
                      <>
                        {r.decision.by} · {new Date(r.decision.at).toLocaleDateString()}
                        {r.decision.note && <div title={r.decision.note}>“{r.decision.note}”</div>}
                      </>
                    ) : (
                      "—"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ))}
    </div>
  );
}
