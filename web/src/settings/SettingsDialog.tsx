import { useMemo } from "react";
import { ADCS_KINDS, AD_KINDS, AZURE_KINDS } from "../api/types";
import { Modal } from "../components/Modal";
import { NumberField } from "../components/NumberField";
import { CATEGORY_ORDER, kindColor as defaultKindColor, kindShort } from "../graph/kinds";
import { useApp, type SettingsSection } from "../state/AppContext";
import { useCatalog } from "../state/CatalogContext";
import { CanvasFilters } from "./CanvasFilters";
import { NODE_CAP_DEFAULT, NODE_CAP_MAX, type LabelMode, type LayoutMode, type PathHighlight } from "./settings";
import { useSettings } from "./SettingsContext";

const SECTIONS: { id: SettingsSection; label: string }[] = [
  { id: "appearance", label: "Appearance" },
  { id: "filters", label: "Canvas filters" },
  { id: "layout", label: "Layout" },
  { id: "behaviour", label: "Behaviour" },
];

function KindColors() {
  const { settings, update, kindColor } = useSettings();
  const { nodeKinds, nodeCategory } = useCatalog();
  const groups = useMemo(() => {
    const names = nodeKinds.length > 0 ? nodeKinds.map((k) => k.name) : [...AD_KINDS, ...ADCS_KINDS, ...AZURE_KINDS, "Unknown"];
    return CATEGORY_ORDER.map((c) => ({ category: c, kinds: names.filter((n) => nodeCategory(n) === c) })).filter(
      (g) => g.kinds.length > 0,
    );
  }, [nodeKinds, nodeCategory]);
  const setColor = (kind: string, color: string | null) => {
    const next = { ...settings.kindColors };
    if (color === null || color === defaultKindColor(kind)) delete next[kind];
    else next[kind] = color;
    update({ kindColors: next });
  };
  const overridden = Object.keys(settings.kindColors).length;

  return (
    <div>
      <div className="section-head">
        <h3>Node colours</h3>
        <button type="button" className="small" disabled={overridden === 0} onClick={() => update({ kindColors: {} })}>
          Reset colours
        </button>
      </div>
      {groups.map((g) => (
        <details key={g.category} className="checklist-group" open={g.category === "Active Directory"}>
          <summary>
            <span className="checklist-cat">{g.category}</span>
            <span className="muted small-text">{g.kinds.length}</span>
          </summary>
          <div className="color-grid">
            {g.kinds.map((k) => (
              <label key={k} className="color-item">
                <input type="color" value={kindColor(k)} onChange={(e) => setColor(k, e.target.value)} aria-label={`${k} colour`} />
                <span className="ellipsis">{kindShort(k)}</span>
                {settings.kindColors[k] && (
                  <button type="button" className="link-btn" onClick={() => setColor(k, null)} aria-label={`Reset ${k} colour`}>
                    reset
                  </button>
                )}
              </label>
            ))}
          </div>
        </details>
      ))}
    </div>
  );
}

function Appearance() {
  const { settings, update } = useSettings();
  return (
    <div className="settings-section">
      <div className="form-grid">
        <label htmlFor="set-theme">Theme</label>
        <select id="set-theme" value={settings.theme} onChange={(e) => update({ theme: e.target.value as typeof settings.theme })}>
          <option value="dark">Dark</option>
          <option value="light">Light</option>
          <option value="system">Follow system</option>
        </select>

        <label htmlFor="set-size">Node size</label>
        <select id="set-size" value={settings.nodeSize} onChange={(e) => update({ nodeSize: e.target.value as typeof settings.nodeSize })}>
          <option value="fixed">Fixed (by kind)</option>
          <option value="degree">By degree on canvas</option>
        </select>

        <label htmlFor="set-labels">Node labels</label>
        <select id="set-labels" value={settings.labelMode} onChange={(e) => update({ labelMode: e.target.value as LabelMode })}>
          <option value="auto">Automatic (avoid overlap)</option>
          <option value="always">Always</option>
          <option value="hover">On hover</option>
          <option value="selected">Selected node only</option>
          <option value="off">Off</option>
        </select>

        <label htmlFor="set-path">Path highlight</label>
        <select id="set-path" value={settings.pathHighlight} onChange={(e) => update({ pathHighlight: e.target.value as PathHighlight })}>
          <option value="accent">Accent colour</option>
          <option value="bold">Accent colour, thick</option>
          <option value="thick">Thick only</option>
        </select>
      </div>
      <label className="toggle">
        <input type="checkbox" checked={settings.edgeLabels} onChange={(e) => update({ edgeLabels: e.target.checked })} />
        Show edge labels
      </label>
      <label className="toggle">
        <input type="checkbox" checked={settings.edgeCurves} onChange={(e) => update({ edgeCurves: e.target.checked })} />
        Curved edges (separates parallel edges)
      </label>
      <KindColors />
    </div>
  );
}

function Layout() {
  const { settings, update } = useSettings();
  const { relayout, store } = useApp();
  const fa2 = settings.fa2;
  return (
    <div className="settings-section">
      <div className="form-grid">
        <label htmlFor="set-layout">Layout</label>
        <select id="set-layout" value={settings.layout} onChange={(e) => update({ layout: e.target.value as LayoutMode })}>
          <option value="force">Force-directed (ForceAtlas2)</option>
          <option value="hierarchical-lr">Hierarchical, left → right</option>
          <option value="hierarchical-tb">Hierarchical, top → bottom</option>
          <option value="circular">Circular (grouped by kind)</option>
          <option value="grid">Grid (grouped by kind)</option>
        </select>
      </div>
      <label className="toggle">
        <input type="checkbox" checked={settings.autoLayout} onChange={(e) => update({ autoLayout: e.target.checked })} />
        Lay out automatically when results are added
      </label>
      <p className="muted small-text">Path results always use a hierarchical layout (top → bottom when that is selected).</p>
      <details className="advanced">
        <summary>Advanced: ForceAtlas2</summary>
        <div className="form-grid">
          <label htmlFor="fa2-g">Gravity</label>
          <NumberField id="fa2-g" min={0} max={50} step={0.1} value={fa2.gravity} onCommit={(v) => update({ fa2: { ...fa2, gravity: v } })} />
          <label htmlFor="fa2-s">Scaling ratio</label>
          <NumberField
            id="fa2-s"
            min={0.1}
            max={200}
            step={0.5}
            value={fa2.scalingRatio}
            onCommit={(v) => update({ fa2: { ...fa2, scalingRatio: v } })}
          />
          <label htmlFor="fa2-d">Run time (s)</label>
          <NumberField
            id="fa2-d"
            min={0.5}
            max={30}
            step={0.5}
            value={fa2.durationMs / 1000}
            onCommit={(v) => update({ fa2: { ...fa2, durationMs: v * 1000 } })}
          />
        </div>
        <label className="toggle">
          <input type="checkbox" checked={fa2.linLogMode} onChange={(e) => update({ fa2: { ...fa2, linLogMode: e.target.checked } })} />
          LinLog mode (tighter clusters)
        </label>
      </details>
      <button type="button" onClick={() => relayout()} disabled={store.graph.order === 0}>
        Apply layout to canvas now
      </button>
    </div>
  );
}

function Behaviour() {
  const { settings, update } = useSettings();
  const { health } = useCatalog();
  const maxLimit = health?.limits.max_query_limit ?? 100000;
  const maxTimeoutS = (health?.limits.max_query_timeout_ms ?? 300000) / 1000;
  const defaultTimeoutS = (health?.limits.default_query_timeout_ms ?? 30000) / 1000;
  return (
    <div className="settings-section">
      <div className="form-grid">
        <label htmlFor="b-limit">Default query limit</label>
        <NumberField id="b-limit" min={1} max={maxLimit} value={settings.queryLimit} onCommit={(v) => update({ queryLimit: Math.round(v) })} />
        <label htmlFor="b-timeout">Query timeout (s)</label>
        <NumberField
          id="b-timeout"
          min={0}
          max={maxTimeoutS}
          value={settings.queryTimeoutMs / 1000}
          onCommit={(v) => update({ queryTimeoutMs: Math.round(v * 1000) })}
        />
        <label htmlFor="b-max">Max nodes rendered</label>
        <NumberField
          id="b-max"
          min={100}
          max={NODE_CAP_MAX}
          step={500}
          value={settings.maxNodes}
          onCommit={(v) => update({ maxNodes: Math.round(v) })}
        />
      </div>
      <p className="muted small-text">Timeout 0 uses the server default ({defaultTimeoutS} s). Server maximum: {maxTimeoutS} s.</p>
      {settings.maxNodes > NODE_CAP_DEFAULT && (
        <p className="warn-text small-text">
          More than {NODE_CAP_DEFAULT.toLocaleString()} nodes can make the canvas slow, especially with labels and curved edges.
        </p>
      )}
      <label className="toggle">
        <input type="checkbox" checked={settings.replaceByDefault} onChange={(e) => update({ replaceByDefault: e.target.checked })} />
        Results replace the canvas by default (applies at next sign-in)
      </label>
      <label className="toggle">
        <input type="checkbox" checked={settings.confirmClear} onChange={(e) => update({ confirmClear: e.target.checked })} />
        Ask before clearing the canvas
      </label>
    </div>
  );
}

export function SettingsDialog() {
  const { settingsSection, openSettings } = useApp();
  const { reset } = useSettings();
  if (!settingsSection) return null;
  const close = () => openSettings(null);
  return (
    <Modal
      title="Settings"
      onClose={close}
      wide
      footer={
        <>
          <button
            type="button"
            className="danger"
            onClick={() => {
              if (window.confirm("Reset all settings to their defaults?")) reset();
            }}
          >
            Reset to defaults
          </button>
          <span className="spacer" />
          <button type="button" className="primary" onClick={close}>
            Done
          </button>
        </>
      }
    >
      <div className="settings-layout">
        <div className="settings-nav" role="tablist" aria-orientation="vertical">
          {SECTIONS.map((s) => (
            <button
              key={s.id}
              type="button"
              role="tab"
              aria-selected={settingsSection === s.id}
              className={settingsSection === s.id ? "active" : ""}
              onClick={() => openSettings(s.id)}
            >
              {s.label}
            </button>
          ))}
        </div>
        <div className="settings-content" role="tabpanel">
          {settingsSection === "appearance" && <Appearance />}
          {settingsSection === "filters" && <CanvasFilters />}
          {settingsSection === "layout" && <Layout />}
          {settingsSection === "behaviour" && <Behaviour />}
        </div>
      </div>
    </Modal>
  );
}
