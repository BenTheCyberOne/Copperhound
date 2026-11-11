import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react";
import type Sigma from "sigma";
import type { Node } from "../api/types";
import { Derivation } from "../components/Derivation";
import { EdgeHelpView } from "../components/EdgeHelp";
import { KindBadge } from "../components/KindBadge";
import { useNodeActions, type NodeAction } from "../components/useNodeActions";
import { useSettings } from "../settings/SettingsContext";
import { useApp } from "../state/AppContext";
import { useCatalog } from "../state/CatalogContext";
import { useFixList } from "../state/FixListContext";
import { useZones } from "../state/ZonesContext";
import { downloadCanvas, parseCanvasFile, positionsOf, resolveCanvasFile } from "./canvasFile";
import { ContextMenu } from "./ContextMenu";
import { stopForceLayout } from "./layout";
import { Legend } from "./Legend";
import { createRenderer, exportPng, labelAwareBBox, readThemeColors, sigmaSettingsFor, type ViewState } from "./renderer";
import type { EdgeAttrs, NodeAttrs } from "./store";

type MenuState = { type: "node" | "edge"; id: string; x: number; y: number };

function NodeMenu({ node, x, y, onClose }: { node: Node; x: number; y: number; onClose: () => void }) {
  const actions = useNodeActions(node, { includeRemove: true });
  return <ContextMenu title={node.name} actions={actions} x={x} y={y} onClose={onClose} />;
}

/** Details for a clicked edge: every kind between the two nodes, with its help text. */
function EdgePanel({ edgeKey, onClose }: { edgeKey: string; onClose: () => void }) {
  const { store, select, notify } = useApp();
  const { isComposite } = useCatalog();
  const fixList = useFixList();
  const g = store.graph;
  const s = g.source(edgeKey);
  const d = g.target(edgeKey);
  const src = g.getNodeAttribute(s, "node");
  const dst = g.getNodeAttribute(d, "node");
  const kinds = g.edges(s, d).map((e) => g.getEdgeAttribute(e, "kind"));
  const clicked = g.getEdgeAttribute(edgeKey, "kind");
  const ordered = [clicked, ...kinds.filter((k) => k !== clicked)];
  return (
    <aside className="edge-panel" aria-label="Edge details">
      <div className="drawer-head">
        <h2 className="drawer-title">{kinds.length > 1 ? `${kinds.length} edges` : "Edge"}</h2>
        <button type="button" className="icon-btn" aria-label="Close edge details" onClick={onClose}>
          ×
        </button>
      </div>
      <div className="edge-panel-body">
        <div className="edge-ends">
          <button type="button" className="hop-node" onClick={() => select(src.id)} title="Show details">
            <KindBadge kind={src.kind} />
            <span className="ellipsis">{src.name}</span>
          </button>
          <span className="muted" aria-hidden="true">
            ↓
          </span>
          <button type="button" className="hop-node" onClick={() => select(dst.id)} title="Show details">
            <KindBadge kind={dst.kind} />
            <span className="ellipsis">{dst.name}</span>
          </button>
        </div>
        {ordered.map((kind) => (
          <div key={kind} className="edge-panel-kind">
            <EdgeHelpView kind={kind} />
            {isComposite(kind) && <Derivation key={`${src.id}-${dst.id}-${kind}`} src={src.id} dst={dst.id} kind={kind} />}
            <button
              type="button"
              className="small"
              onClick={() => {
                const added = fixList.addEdges([{ src, dst, kind }]);
                notify(added > 0 ? `Added ${kind} edge to the fix list (Remediation view).` : "That edge is already in the fix list.");
              }}
            >
              Add to fix list
            </button>
          </div>
        ))}
      </div>
    </aside>
  );
}

interface Tooltip {
  x: number;
  y: number;
  kinds: string[];
  src: string;
  dst: string;
}

export function GraphCanvas({
  active,
  tableOpen,
  onToggleTable,
}: {
  active: boolean;
  tableOpen: boolean;
  onToggleTable: (open: boolean) => void;
}) {
  const { store, selectedId, select, replaceMode, setReplaceMode, relayout, openSettings, stale, reloadCanvas, notify } = useApp();
  const { settings, theme } = useSettings();
  const { isTraversable, generation, kindStylesVersion } = useCatalog();
  useEffect(() => {
    if (kindStylesVersion > 0) store.recolor();
  }, [kindStylesVersion, store]);
  const importInput = useRef<HTMLInputElement>(null);
  const importCanvas = async (file: File) => {
    try {
      const f = parseCanvasFile(await file.text());
      const r = await resolveCanvasFile(f);
      store.clear();
      store.generation = generation;
      store.merge({ nodes: r.nodes, edges: r.edges }, true);
      store.setPositions(positionsOf(f, r.nodes));
      store.requestFit();
      select(null);
      const missing = [
        r.missingNodes > 0 ? `${r.missingNodes} objects` : null,
        r.missingEdges > 0 ? `${r.missingEdges} relationships` : null,
      ].filter(Boolean);
      notify(
        `Imported ${r.nodes.length} nodes and ${r.edges.length} edges.${missing.length > 0 ? ` Not in the current graph: ${missing.join(", ")}.` : ""}`,
        missing.length > 0 ? "warn" : "info",
      );
    } catch (e) {
      notify(`Canvas import failed: ${e instanceof Error ? e.message : String(e)}`, "error");
    }
  };
  const { zones, members } = useZones();
  const fixList = useFixList();
  const containerRef = useRef<HTMLDivElement>(null);
  const sigmaRef = useRef<Sigma<NodeAttrs, EdgeAttrs> | null>(null);
  const view = useRef<ViewState>({
    colors: readThemeColors(),
    settings,
    isTraversable,
    selected: null,
    hoveredNode: null,
    hoveredEdge: null,
    zoneColor: () => null,
  });
  const selectRef = useRef(select);
  selectRef.current = select;
  const [menu, setMenu] = useState<MenuState | null>(null);
  /** Edge whose details panel is open (clicked, or "About this edge"). */
  const [edgePanel, setEdgePanel] = useState<string | null>(null);
  const [tooltip, setTooltip] = useState<Tooltip | null>(null);
  const [layingOut, setLayingOut] = useState(false);
  const [reloading, setReloading] = useState(false);

  useSyncExternalStore(store.subscribe, store.version);
  const g = store.graph;

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const sigma = createRenderer(container, store, view);
    sigmaRef.current = sigma;
    // Reducers only re-run for re-processed items, so hover changes refresh just those items.
    const refreshItems = (nodes: string[], edges: string[]) => sigma.refresh({ partialGraph: { nodes, edges } });

    let dragged: string | null = null;
    sigma.on("clickNode", ({ node }) => {
      selectRef.current(Number(node));
      setMenu(null);
    });
    sigma.on("rightClickNode", ({ node, event }) => {
      event.original.preventDefault();
      setMenu({ type: "node", id: node, x: event.x, y: event.y });
    });
    sigma.on("rightClickEdge", ({ edge, event }) => {
      event.original.preventDefault();
      setMenu({ type: "edge", id: edge, x: event.x, y: event.y });
    });
    sigma.on("clickEdge", ({ edge }) => {
      setEdgePanel(edge);
      setMenu(null);
    });
    sigma.on("clickStage", () => setMenu(null));
    sigma.on("enterNode", ({ node }) => {
      view.current.hoveredNode = node;
      if (view.current.settings.labelMode === "selected") refreshItems([node], []);
    });
    sigma.on("leaveNode", ({ node }) => {
      view.current.hoveredNode = null;
      if (view.current.settings.labelMode === "selected") refreshItems([node], []);
    });
    sigma.on("enterEdge", ({ edge, event }) => {
      view.current.hoveredEdge = edge;
      const s = store.graph.source(edge);
      const d = store.graph.target(edge);
      setTooltip({
        x: event.x,
        y: event.y,
        kinds: store.graph.edges(s, d).map((e) => store.graph.getEdgeAttribute(e, "kind")),
        src: store.graph.getNodeAttribute(s, "label"),
        dst: store.graph.getNodeAttribute(d, "label"),
      });
      refreshItems([], [edge]);
    });
    sigma.on("leaveEdge", ({ edge }) => {
      view.current.hoveredEdge = null;
      setTooltip(null);
      refreshItems([], [edge]);
    });

    // Node dragging.
    sigma.on("downNode", ({ node }) => {
      dragged = node;
      stopForceLayout();
      if (!sigma.getCustomBBox()) sigma.setCustomBBox(sigma.getBBox());
    });
    sigma.on("moveBody", ({ event }) => {
      if (!dragged) return;
      const pos = sigma.viewportToGraph(event);
      store.graph.mergeNodeAttributes(dragged, { x: pos.x, y: pos.y });
      event.preventSigmaDefault();
      event.original.preventDefault();
    });
    const endDrag = () => {
      dragged = null;
    };
    sigma.on("upNode", endDrag);
    sigma.on("upStage", endDrag);

    const preventNative = (e: MouseEvent) => e.preventDefault();
    container.addEventListener("contextmenu", preventNative);
    // The bottom dock resizes the canvas without a window resize event.
    const resizeObs = new ResizeObserver(() => {
      if (container.clientWidth > 0 && container.clientHeight > 0) sigma.refresh();
    });
    resizeObs.observe(container);

    const offFit = store.onFitRequest(() => {
      // Full refresh recomputes the graph extent (partial refreshes after
      // per-node position updates do not), so the reset frames everything,
      // including the labels beside the right-most nodes.
      const bbox = labelAwareBBox(sigma);
      if (bbox) sigma.setCustomBBox(bbox);
      sigma.refresh();
      sigma.getCamera().animatedReset({ duration: 400 });
    });

    // Centre the camera on a node (canvas table double-click).
    const offFocus = store.onFocusRequest((key) => {
      const d = sigma.getNodeDisplayData(key);
      if (!d) return;
      const cam = sigma.getCamera();
      void cam.animate({ x: d.x, y: d.y, ratio: Math.min(cam.ratio, 0.6) }, { duration: 400 });
    });

    return () => {
      offFit();
      offFocus();
      resizeObs.disconnect();
      container.removeEventListener("contextmenu", preventNative);
      stopForceLayout();
      sigma.kill();
      sigmaRef.current = null;
    };
  }, [store]);

  // Push theme / settings / catalog changes into the renderer.
  useEffect(() => {
    view.current.colors = readThemeColors();
    view.current.settings = settings;
    view.current.isTraversable = isTraversable;
    const sigma = sigmaRef.current;
    if (!sigma) return;
    sigma.setSettings(sigmaSettingsFor(view.current));
    sigma.refresh();
  }, [theme, settings, isTraversable]);

  // Zone rings: first zone (in list order) the node belongs to whose ring is enabled.
  useEffect(() => {
    const visible = zones.filter((z) => !settings.hiddenZoneRings.includes(z.id) && members.has(z.id));
    view.current.zoneColor = (key) => {
      const id = Number(key);
      return visible.find((z) => members.get(z.id)!.has(id))?.color ?? null;
    };
    sigmaRef.current?.refresh();
  }, [zones, members, settings.hiddenZoneRings]);

  // The canvas is kept mounted while other views are shown; re-measure when it returns.
  useEffect(() => {
    if (!active) return;
    sigmaRef.current?.resize();
    sigmaRef.current?.refresh();
  }, [active]);

  useEffect(() => {
    view.current.selected = selectedId === null ? null : String(selectedId);
    sigmaRef.current?.refresh();
  }, [selectedId]);

  const closeMenu = useCallback(() => setMenu(null), []);

  const runRelayout = () => {
    setLayingOut(true);
    sigmaRef.current?.setCustomBBox(null);
    relayout(() => setLayingOut(false));
  };

  const clear = () => {
    if (settings.confirmClear && !window.confirm(`Remove all ${g.order} nodes from the canvas?`)) return;
    store.clear();
    select(null);
  };

  const reload = async () => {
    setReloading(true);
    await reloadCanvas();
    setReloading(false);
  };

  const menuNode = menu?.type === "node" && g.hasNode(menu.id) ? g.getNodeAttribute(menu.id, "node") : null;
  const edgeActions = (key: string): NodeAction[] => {
    const src = g.getNodeAttribute(g.source(key), "node");
    const dst = g.getNodeAttribute(g.target(key), "node");
    const kind = g.getEdgeAttribute(key, "kind");
    return [
      { id: "about", label: "About this edge", run: () => setEdgePanel(key) },
      {
        id: "fix",
        separatorBefore: true,
        label: "Add edge to fix list",
        run: () => {
          const added = fixList.addEdges([{ src, dst, kind }]);
          notify(added > 0 ? `Added ${kind} edge to the fix list (Remediation view).` : "That edge is already in the fix list.");
        },
      },
      { id: "src", label: `Select ${src.name}`, separatorBefore: true, run: () => select(src.id) },
      { id: "dst", label: `Select ${dst.name}`, run: () => select(dst.id) },
      { id: "drop", label: "Remove edge from canvas", danger: true, separatorBefore: true, run: () => store.removeEdge(key) },
    ];
  };
  const menuEdge = menu?.type === "edge" && g.hasEdge(menu.id) ? menu.id : null;
  const panelEdge = edgePanel !== null && g.hasEdge(edgePanel) ? edgePanel : null;
  const empty = g.order === 0;
  const hiddenCount = g.reduceNodes((n, _, a) => n + (settings.hiddenNodeKinds.includes(a.node.kind) ? 1 : 0), 0);
  const filtersActive =
    settings.hiddenNodeKinds.length + settings.hiddenEdgeKinds.length > 0 || settings.hideNonTraversable || settings.dimOffPath;

  return (
    <div className="canvas-wrap">
      <div className="canvas-toolbar" role="toolbar" aria-label="Canvas">
        <button type="button" onClick={runRelayout} disabled={empty || layingOut} title="Apply the layout chosen in Settings → Layout">
          {layingOut ? "Laying out…" : "Re-layout"}
        </button>
        <button type="button" onClick={() => store.requestFit()} disabled={empty} title="Fit graph to view">
          Fit
        </button>
        <button type="button" onClick={clear} disabled={empty}>
          Clear
        </button>
        <button
          type="button"
          onClick={() => sigmaRef.current && exportPng(sigmaRef.current, view.current.colors.background)}
          disabled={empty}
        >
          Export PNG
        </button>
        <button type="button" onClick={() => downloadCanvas(store)} disabled={empty} title="Save the canvas (objects, relationships and positions) as JSON">
          Export JSON
        </button>
        <button type="button" onClick={() => importInput.current?.click()} title="Load a canvas saved with Export JSON (re-resolved against the current graph)">
          Import
        </button>
        <input
          ref={importInput}
          type="file"
          accept=".json,application/json"
          hidden
          onChange={(e) => {
            const file = e.target.files?.[0];
            e.target.value = "";
            if (file) void importCanvas(file);
          }}
        />
        <button
          type="button"
          className={filtersActive ? "active-filter" : ""}
          onClick={() => openSettings("filters")}
          aria-label={filtersActive ? "Filters (active)" : "Filters"}
        >
          Filters{filtersActive ? " •" : ""}
        </button>
        <button type="button" onClick={() => void reload()} disabled={empty || reloading} title="Re-fetch canvas nodes from the server">
          {reloading ? "Refreshing…" : "Refresh"}
        </button>
        <button
          type="button"
          className={tableOpen ? "active-filter" : ""}
          aria-pressed={tableOpen}
          onClick={() => onToggleTable(!tableOpen)}
          title="Show the canvas nodes as a sortable table"
        >
          Table
        </button>
        <label className="toggle" title="When on, query and path results replace the canvas instead of merging into it">
          <input type="checkbox" checked={replaceMode} onChange={(e) => setReplaceMode(e.target.checked)} />
          Replace on load
        </label>
        <span className="muted canvas-count">
          {g.order} nodes · {g.size} edges{hiddenCount > 0 ? ` · ${hiddenCount} hidden` : ""}
        </span>
      </div>

      <div className="canvas-banners">
        {stale && (
          <div className="canvas-banner stale" role="alert">
            <span>Graph was rebuilt — canvas ids are stale.</span>
            <button type="button" className="small primary" onClick={() => void reload()} disabled={reloading}>
              {reloading ? "Reloading…" : "Reload canvas"}
            </button>
            <button type="button" className="small" onClick={() => store.clear()}>
              Clear
            </button>
          </div>
        )}
        {store.capDropped > 0 && (
          <div className="canvas-banner" role="status">
            Rendering capped at {store.maxNodes.toLocaleString()} nodes — {store.capDropped} nodes from the last result are not
            shown. Narrow the query, switch to replace mode, or raise the cap in Settings → Behaviour.
          </div>
        )}
      </div>

      <div ref={containerRef} className="sigma-container" aria-label="Graph canvas" />

      {empty && (
        <div className="canvas-empty">
          <p>The canvas is empty.</p>
          <p className="muted">Search for an object above, run a prebuilt query, or find a path.</p>
        </div>
      )}

      {tooltip && (
        <div className="edge-tooltip" style={{ left: tooltip.x + 14, top: tooltip.y + 14 }} role="tooltip">
          <div className="edge-tooltip-kinds">{tooltip.kinds.join(" · ")}</div>
          <div className="muted">
            {tooltip.src} → {tooltip.dst}
          </div>
        </div>
      )}

      {menu && menuNode && <NodeMenu node={menuNode} x={menu.x} y={menu.y} onClose={closeMenu} />}
      {menu && menuEdge && (
        <ContextMenu
          title={`${g.getEdgeAttribute(menuEdge, "kind")} edge`}
          actions={edgeActions(menuEdge)}
          x={menu.x}
          y={menu.y}
          onClose={closeMenu}
        />
      )}

      {panelEdge && <EdgePanel edgeKey={panelEdge} onClose={() => setEdgePanel(null)} />}

      <Legend />
    </div>
  );
}
