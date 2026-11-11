import { CategoryChecklist } from "../components/CategoryChecklist";
import { useCanvasKinds } from "../graph/useCanvasKinds";
import { useApp } from "../state/AppContext";
import { MEMBER_FETCH_LIMIT, useZones } from "../state/ZonesContext";
import { useSettings } from "./SettingsContext";

/** Show/hide node and edge kinds on the current canvas. Checked = visible. */
export function CanvasFilters() {
  const { store } = useApp();
  const { settings, update } = useSettings();
  const { nodeItems, edgeItems } = useCanvasKinds(store);
  const { zones } = useZones();

  const visible = (items: { name: string }[], hidden: string[]) =>
    new Set(items.map((i) => i.name).filter((n) => !hidden.includes(n)));
  // Hidden kinds that are not on the canvas right now stay hidden.
  const keepOffCanvas = (hidden: string[], items: { name: string }[]) => hidden.filter((h) => !items.some((i) => i.name === h));
  const hiddenElsewhere = keepOffCanvas(settings.hiddenNodeKinds, nodeItems).length + keepOffCanvas(settings.hiddenEdgeKinds, edgeItems).length;

  return (
    <div className="settings-section">
      <p className="muted small-text">Hidden kinds stay hidden for new results until you show them again.</p>
      <label className="toggle">
        <input
          type="checkbox"
          checked={settings.hideNonTraversable}
          onChange={(e) => update({ hideNonTraversable: e.target.checked })}
        />
        Hide non-traversable edges
      </label>
      <label className="toggle">
        <input type="checkbox" checked={settings.dimOffPath} onChange={(e) => update({ dimOffPath: e.target.checked })} />
        Dim nodes and edges not on the highlighted path
      </label>

      {zones.length > 0 && (
        <>
          <h3>Zone rings</h3>
          <div className="zone-toggles">
            {zones.map((z) => {
              const tooBig = z.member_count > MEMBER_FETCH_LIMIT;
              const on = !settings.hiddenZoneRings.includes(z.id);
              return (
                <label key={z.id} className="check" title={tooBig ? `More than ${MEMBER_FETCH_LIMIT.toLocaleString()} members: not drawn` : undefined}>
                  <input
                    type="checkbox"
                    checked={on && !tooBig}
                    disabled={tooBig}
                    onChange={() =>
                      update({
                        hiddenZoneRings: on ? [...settings.hiddenZoneRings, z.id] : settings.hiddenZoneRings.filter((x) => x !== z.id),
                      })
                    }
                  />
                  <span className="zone-swatch" style={{ background: z.color }} />
                  {z.name}
                  <span className="muted small-text num">{z.member_count.toLocaleString()}</span>
                </label>
              );
            })}
          </div>
        </>
      )}

      <h3>Node kinds on canvas</h3>
      {nodeItems.length === 0 ? (
        <p className="muted small-text">The canvas is empty.</p>
      ) : (
        <CategoryChecklist
          label="Visible node kinds"
          items={nodeItems}
          checked={visible(nodeItems, settings.hiddenNodeKinds)}
          onChange={(on) =>
            update({
              hiddenNodeKinds: [
                ...keepOffCanvas(settings.hiddenNodeKinds, nodeItems),
                ...nodeItems.map((i) => i.name).filter((n) => !on.has(n)),
              ],
            })
          }
        />
      )}

      <h3>Edge kinds on canvas</h3>
      {edgeItems.length === 0 ? (
        <p className="muted small-text">No edges on the canvas.</p>
      ) : (
        <CategoryChecklist
          label="Visible edge kinds"
          items={edgeItems}
          checked={visible(edgeItems, settings.hiddenEdgeKinds)}
          onChange={(on) =>
            update({
              hiddenEdgeKinds: [
                ...keepOffCanvas(settings.hiddenEdgeKinds, edgeItems),
                ...edgeItems.map((i) => i.name).filter((n) => !on.has(n)),
              ],
            })
          }
        />
      )}

      {hiddenElsewhere > 0 && (
        <p className="small-text">
          {hiddenElsewhere} hidden kind{hiddenElsewhere === 1 ? " is" : "s are"} not on the canvas.{" "}
          <button type="button" className="link-btn" onClick={() => update({ hiddenNodeKinds: [], hiddenEdgeKinds: [] })}>
            Show everything
          </button>
        </p>
      )}
    </div>
  );
}
