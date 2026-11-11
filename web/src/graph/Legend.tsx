import { useState } from "react";
import { readLocal, writeLocal } from "../hooks/localStore";
import { useSettings } from "../settings/SettingsContext";
import { useApp } from "../state/AppContext";
import { useZones } from "../state/ZonesContext";
import { CATEGORY_ORDER, kindShort, OWNED_RING_COLOR } from "./kinds";
import { useCanvasKinds } from "./useCanvasKinds";

const OPEN_KEY = "copperhound.legendOpen";

/** Canvas legend grouped by category. Clicking a kind toggles its visibility. */
export function Legend() {
  const { store } = useApp();
  const { settings, update } = useSettings();
  const { nodeItems } = useCanvasKinds(store);
  const { zones, members } = useZones();
  const [open, setOpen] = useState(() => readLocal(OPEN_KEY, true));
  if (nodeItems.length === 0) return null;

  const toggleOpen = () => {
    setOpen(!open);
    writeLocal(OPEN_KEY, !open);
  };
  const toggleKind = (kind: string) => {
    const hidden = settings.hiddenNodeKinds;
    update({ hiddenNodeKinds: hidden.includes(kind) ? hidden.filter((k) => k !== kind) : [...hidden, kind] });
  };
  const zoneRows = zones
    .filter((z) => !settings.hiddenZoneRings.includes(z.id) && members.has(z.id))
    .map((z) => ({ z, count: store.graph.filterNodes((k) => members.get(z.id)!.has(Number(k))).length }))
    .filter((r) => r.count > 0);
  const groups = CATEGORY_ORDER.map((category) => ({
    category,
    items: nodeItems.filter((i) => i.category === category).sort((a, b) => (b.count ?? 0) - (a.count ?? 0)),
  })).filter((g) => g.items.length > 0);

  return (
    <div className="legend">
      <button type="button" className="legend-toggle" aria-expanded={open} onClick={toggleOpen}>
        Legend {open ? "▾" : "▸"}
      </button>
      {open && (
        <div className="legend-body">
          {groups.map((g) => (
            <div key={g.category} className="legend-group">
              <div className="legend-family">{g.category}</div>
              {g.items.map((i) => {
                const hidden = settings.hiddenNodeKinds.includes(i.name);
                return (
                  <button
                    key={i.name}
                    type="button"
                    className={`legend-item ${hidden ? "is-hidden" : ""}`}
                    aria-pressed={!hidden}
                    title={hidden ? `Show ${i.name}` : `Hide ${i.name}`}
                    onClick={() => toggleKind(i.name)}
                  >
                    <span className="swatch" style={{ background: i.color }} />
                    <span className="legend-kind">{kindShort(i.name)}</span>
                    <span className="muted num">{i.count}</span>
                  </button>
                );
              })}
            </div>
          ))}
          {zoneRows.length > 0 && (
            <div className="legend-group">
              <div className="legend-family">Zones</div>
              {zoneRows.map(({ z, count }) => (
                <div key={z.id} className="legend-item static">
                  <span className="swatch ring" style={{ borderColor: z.color }} />
                  <span className="legend-kind">{z.name}</span>
                  <span className="muted num">{count}</span>
                </div>
              ))}
            </div>
          )}
          <div className="legend-group">
            <div className="legend-family">Markers</div>
            <div className="legend-item static">
              <span className="swatch ring tier0" />
              <span>Tier Zero</span>
            </div>
            <div className="legend-item static">
              <span className="swatch ring" style={{ borderColor: OWNED_RING_COLOR }} />
              <span>Owned</span>
            </div>
            <div className="legend-item static">
              <span className="swatch line" />
              <span>Path edge</span>
            </div>
            <div className="legend-item static">
              <span className="swatch line edge-plain" />
              <span>Attack edge</span>
            </div>
            <div className="legend-item static" title="Informational (e.g. CrossForestTrust, SyncedToADGroup): never part of an attack path">
              <span className="swatch line edge-faded" />
              <span>Non-traversable</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
