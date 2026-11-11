import { useState } from "react";
import { api, errorMessage } from "../../api/client";
import type { Zone } from "../../api/types";
import { ExposureReport } from "../../components/ExposureReport";
import { KindBadge } from "../../components/KindBadge";
import { Pager } from "../../components/Pager";
import { EmptyState, StatusView } from "../../components/StatusView";
import { useChokeActions } from "../../components/useChokeActions";
import { useAnalysis } from "../../hooks/useAnalysis";
import { navigate, routeHref } from "../../hooks/useRoute";
import { useSettings } from "../../settings/SettingsContext";
import { useApp } from "../../state/AppContext";
import { useCatalog } from "../../state/CatalogContext";
import { ReadOnlyNote, useSession } from "../../state/SessionContext";
import { MEMBER_FETCH_LIMIT, useZones } from "../../state/ZonesContext";
import { ZoneDialog } from "./ZoneDialog";
import { ZoneReviewPanel } from "./ZoneReviewPanel";

const PAGE = 200;

export function ZonesView({ zoneId }: { zoneId: string | null }) {
  const { zones, error, loaded, reload } = useZones();
  const { gate } = useSession();
  const [dialog, setDialog] = useState<{ editing: Zone | null } | null>(null);
  const selected = zones.find((z) => z.id === zoneId) ?? zones[0] ?? null;

  return (
    <div className="view-page">
      <header className="view-head">
        <div>
          <h1>Zones</h1>
          <p className="muted">Privilege zones are sets of targets you protect. Exposure, simulation and planning can work against any zone.</p>
        </div>
        <button type="button" className="primary" onClick={() => setDialog({ editing: null })} {...gate("analyst")}>
          New zone
        </button>
      </header>
      {error && <p className="error">{error}</p>}
      <ReadOnlyNote need="analyst" what="creating, editing and deleting zones" />
      {!loaded && <p className="muted">Loading zones…</p>}
      {loaded && (
        <div className="zones-layout">
          <ul className="zone-list" aria-label="Zones">
            {zones.map((z) => (
              <li key={z.id}>
                <a href={routeHref("zones", z.id)} className={`zone-item ${selected?.id === z.id ? "active" : ""}`} aria-current={selected?.id === z.id ? "page" : undefined}>
                  <span className="zone-swatch" style={{ background: z.color }} />
                  <span className="zone-name">{z.name}</span>
                  {z.builtin && <span className="tag">built-in</span>}
                  <span className="muted num small-text">{z.member_count.toLocaleString()}</span>
                </a>
              </li>
            ))}
          </ul>
          {selected ? <ZoneDetail key={selected.id} zone={selected} onEdit={() => setDialog({ editing: selected })} /> : <EmptyState title="No zones" />}
        </div>
      )}
      {dialog && (
        <ZoneDialog
          editing={dialog.editing}
          onClose={() => setDialog(null)}
          onSaved={(z) => {
            setDialog(null);
            reload();
            navigate("zones", z.id);
          }}
        />
      )}
    </div>
  );
}

function ZoneDetail({ zone, onEdit }: { zone: Zone; onEdit: () => void }) {
  const { generation } = useCatalog();
  const { reload } = useZones();
  const { loadResult, openInEditor, notify, track } = useApp();
  const { settings, update } = useSettings();
  const { gate } = useSession();
  const [tab, setTab] = useState<"exposure" | "members" | "review">("exposure");
  const [offset, setOffset] = useState(0);
  const members = useAnalysis(() => api.zoneMembers(zone.id, offset, PAGE), `${zone.id}|${offset}|${generation}|${zone.member_count}`, tab === "members");
  const exposure = useAnalysis(
    () => (zone.id === "tier0" ? api.tier0(25) : api.zoneExposure(zone.id, 25)),
    `${zone.id}|${generation}|${zone.member_count}`,
    tab === "exposure",
  );
  const { shown, showChoke, addChoke } = useChokeActions(zone.id);
  const ringOn = !settings.hiddenZoneRings.includes(zone.id);

  const remove = async () => {
    if (!window.confirm(`Delete zone “${zone.name}”?`)) return;
    try {
      await track(api.deleteZone(zone.id));
      reload();
      navigate("zones");
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  return (
    <section className="card zone-detail" aria-labelledby="zone-title">
      <div className="section-head">
        <h2 id="zone-title" className="row gap">
          <span className="zone-swatch big" style={{ background: zone.color }} /> {zone.name}
        </h2>
        <div className="head-actions">
          <label className="toggle" title={zone.member_count > MEMBER_FETCH_LIMIT ? `Rings are drawn only for zones up to ${MEMBER_FETCH_LIMIT.toLocaleString()} members` : undefined}>
            <input
              type="checkbox"
              checked={ringOn}
              disabled={zone.member_count > MEMBER_FETCH_LIMIT}
              onChange={() =>
                update({
                  hiddenZoneRings: ringOn ? [...settings.hiddenZoneRings, zone.id] : settings.hiddenZoneRings.filter((z) => z !== zone.id),
                })
              }
            />
            Ring on canvas
          </label>
          {!zone.builtin && (
            <>
              <button type="button" className="small" onClick={onEdit} {...gate("analyst")}>
                Edit
              </button>
              <button type="button" className="small danger" onClick={() => void remove()} {...gate("analyst")}>
                Delete
              </button>
            </>
          )}
        </div>
      </div>
      {zone.description && <p>{zone.description}</p>}
      <div className="selector-row">
        <pre className="code-block">{zone.selector}</pre>
        <button
          type="button"
          className="small"
          onClick={() => {
            openInEditor(zone.selector);
            navigate("explore");
          }}
        >
          Open in editor
        </button>
      </div>

      <div className="tabs inline-tabs" role="tablist">
        {(zone.builtin ? (["exposure", "members"] as const) : (["exposure", "members", "review"] as const)).map((t) => (
          <button key={t} type="button" role="tab" aria-selected={tab === t} className={tab === t ? "active" : ""} onClick={() => setTab(t)}>
            {t === "exposure" ? "Exposure & choke points" : t === "members" ? `Members (${zone.member_count.toLocaleString()})` : "Review"}
          </button>
        ))}
      </div>

      {tab === "exposure" && (
        <div role="tabpanel">
          <StatusView state={exposure} what={`${zone.name} exposure`} />
          {exposure.data && (
            <ExposureReport
              report={exposure.data}
              zoneName={zone.name}
              activeKey={shown?.key ?? null}
              onShowChoke={(cp) => void showChoke(cp).then((ok) => ok && navigate("explore"))}
              onAddToFixList={addChoke}
            />
          )}
        </div>
      )}
      {tab === "review" && <ZoneReviewPanel zone={zone} />}
      {tab === "members" && (
        <div role="tabpanel">
          <StatusView state={members} what="members" />
          {members.data && (
            <>
              <div className="section-head">
                <button
                  type="button"
                  className="small"
                  disabled={members.data.items.length === 0}
                  onClick={() => {
                    loadResult({ nodes: members.data!.items, edges: [], truncated: false, elapsed_ms: 0 });
                    navigate("explore");
                  }}
                >
                  Show this page on canvas
                </button>
                <Pager offset={offset} total={members.data.total} page={PAGE} onChange={setOffset} />
              </div>
              {members.data.items.length === 0 ? (
                <EmptyState title="This zone has no members">Check the selector — it must return nodes.</EmptyState>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Kind</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {members.data.items.map((n) => (
                      <tr key={n.id}>
                        <td>{n.name}</td>
                        <td>
                          <KindBadge kind={n.kind} />
                        </td>
                        <td className="tags">
                          {!n.enabled && <span className="tag off">disabled</span>}
                          {n.tier0 && <span className="tag tier0">Tier Zero</span>}
                          {n.owned && <span className="tag owned">owned</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          )}
        </div>
      )}
    </section>
  );
}
