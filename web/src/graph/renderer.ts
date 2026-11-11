// Sigma setup: programs, theme- and settings-aware reducers, hover drawing and PNG export.

import { createEdgeCurveProgram } from "@sigma/edge-curve";
import { createNodeBorderProgram } from "@sigma/node-border";
import Sigma from "sigma";
import { createEdgeArrowProgram, type NodeHoverDrawingFunction } from "sigma/rendering";
import type { Settings as SigmaSettings } from "sigma/settings";
import type { EdgeDisplayData, NodeDisplayData } from "sigma/types";
import type { Settings } from "../settings/settings";
import { OWNED_RING_COLOR } from "./kinds";
import type { CanvasGraph, EdgeAttrs, GraphStore, NodeAttrs } from "./store";

export interface ThemeColors {
  background: string;
  surface: string;
  text: string;
  textMuted: string;
  edge: string;
  accent: string;
  tier0Ring: string;
}

export function readThemeColors(): ThemeColors {
  const css = getComputedStyle(document.documentElement);
  const v = (name: string) => css.getPropertyValue(name).trim();
  return {
    background: v("--canvas-bg"),
    surface: v("--surface-2"),
    text: v("--text"),
    textMuted: v("--text-muted"),
    edge: v("--graph-edge"),
    accent: v("--accent"),
    tier0Ring: v("--tier0-ring"),
  };
}

export interface ViewState {
  colors: ThemeColors;
  settings: Settings;
  isTraversable: (edgeKind: string) => boolean;
  selected: string | null;
  hoveredNode: string | null;
  hoveredEdge: string | null;
  /** Colour of the first visible zone the node belongs to, if any. */
  zoneColor: (nodeKey: string) => string | null;
}

type DisplayNode = Partial<NodeDisplayData> & Record<string, unknown>;
type DisplayEdge = Partial<EdgeDisplayData> & EdgeAttrs & Record<string, unknown>;

const NodeProgram = createNodeBorderProgram<NodeAttrs, EdgeAttrs>({
  borders: [
    { size: { attribute: "ringTier0", defaultValue: 0 }, color: { attribute: "ringTier0Color", defaultValue: "#ffffff" } },
    { size: { attribute: "ringGap", defaultValue: 0 }, color: { attribute: "ringGapColor", defaultValue: "#000000" } },
    { size: { attribute: "ringZone", defaultValue: 0 }, color: { attribute: "ringZoneColor", defaultValue: "#ffffff" } },
    { size: { attribute: "ringOwned", defaultValue: 0 }, color: { value: OWNED_RING_COLOR } },
    { size: { fill: true }, color: { attribute: "color" } },
  ],
});

const ArrowProgram = createEdgeArrowProgram<NodeAttrs, EdgeAttrs>();
const CurvedArrowProgram = createEdgeCurveProgram<NodeAttrs, EdgeAttrs>({
  arrowHead: { extremity: "target", lengthToThicknessRatio: 2.5, widenessToThicknessRatio: 2 },
});

/** Mixes two #rrggbb colours; returns `a` unchanged if either is not a hex colour. */
function mix(a: string, b: string, t: number): string {
  const parse = (c: string) => (/^#[0-9a-f]{6}$/i.test(c) ? [1, 3, 5].map((i) => parseInt(c.slice(i, i + 2), 16)) : null);
  const x = parse(a);
  const y = parse(b);
  if (!x || !y) return a;
  return `#${x.map((v, i) => Math.round(v * (1 - t) + y[i]! * t).toString(16).padStart(2, "0")).join("")}`;
}

function hoverRenderer(view: { current: ViewState }): NodeHoverDrawingFunction<NodeAttrs, EdgeAttrs> {
  return (ctx, data, settings) => {
    const { colors } = view.current;
    ctx.beginPath();
    ctx.arc(data.x, data.y, data.size + 3, 0, Math.PI * 2);
    ctx.strokeStyle = colors.accent;
    ctx.lineWidth = 2;
    ctx.stroke();
    if (view.current.settings.labelMode === "off") return;
    const label = typeof data.label === "string" ? data.label : "";
    if (!label) return;
    const size = settings.labelSize;
    ctx.font = `600 ${size}px ${settings.labelFont}`;
    const w = ctx.measureText(label).width;
    const pad = 4;
    ctx.fillStyle = colors.surface;
    ctx.shadowColor = "rgba(0,0,0,0.45)";
    ctx.shadowBlur = 10;
    ctx.beginPath();
    ctx.roundRect(data.x + data.size + 2, data.y - size / 2 - pad, w + pad * 2, size + pad * 2, 4);
    ctx.fill();
    ctx.shadowBlur = 0;
    ctx.fillStyle = colors.text;
    ctx.fillText(label, data.x + data.size + 2 + pad, data.y + size / 3);
  };
}

type BBox = { x: [number, number]; y: [number, number] };

/**
 * The graph extent, widened on the right so that the labels drawn beside the
 * right-most nodes stay on screen once the camera frames it. Sigma frames node
 * positions only, which cuts long labels off at the right edge.
 */
export function labelAwareBBox(sigma: Sigma<NodeAttrs, EdgeAttrs>): BBox | null {
  sigma.setCustomBBox(null);
  sigma.refresh();
  const bbox = sigma.getBBox();
  const { width, height } = sigma.getDimensions();
  const pad = sigma.getSetting("stagePadding") ?? 0;
  const availW = width - 2 * pad;
  const availH = height - 2 * pad;
  const graph = sigma.getGraph();
  if (availW <= 0 || availH <= 0 || graph.order === 0 || graph.order > 5000 || !sigma.getSetting("renderLabels")) return null;
  const ctx = document.createElement("canvas").getContext("2d");
  if (!ctx) return null;
  const size = sigma.getSetting("labelSize");
  ctx.font = `${sigma.getSetting("labelWeight")} ${size}px ${sigma.getSetting("labelFont")}`;
  // Pixel width each label needs to the right of its node centre.
  const labels: { x: number; w: number }[] = [];
  graph.forEachNode((_, a) => {
    if (a.label) labels.push({ x: a.x, w: a.size + 4 + ctx.measureText(a.label).width });
  });
  const [x0] = bbox.x;
  let x1 = bbox.x[1];
  const ySpan = bbox.y[1] - bbox.y[0];
  // Widening the box shrinks the scale, which makes labels take more graph
  // units; a few rounds settle it.
  for (let i = 0; i < 4; i++) {
    const span = Math.max(x1 - x0, 1e-9);
    const scale = Math.min(availW / span, ySpan > 0 ? availH / ySpan : Infinity);
    let need = bbox.x[1];
    for (const l of labels) need = Math.max(need, l.x + l.w / scale);
    if (need <= x1 + 1e-9 && i > 0) break;
    x1 = need;
  }
  return { x: [x0, x1], y: bbox.y };
}

function baseSize(attrs: NodeAttrs, graph: CanvasGraph, key: string, mode: Settings["nodeSize"]): number {
  if (mode === "fixed") return attrs.size;
  const boost = attrs.node.kind === "Domain" || attrs.node.kind === "AZTenant" ? 3 : 0;
  return Math.min(22, 4 + boost + 2.2 * Math.sqrt(graph.degree(key)));
}

/** Settings that depend on the appearance options rather than on individual items. */
export function sigmaSettingsFor(view: ViewState): Partial<SigmaSettings<NodeAttrs, EdgeAttrs>> {
  const { settings, colors } = view;
  return {
    labelColor: { color: colors.text },
    edgeLabelColor: { color: colors.textMuted },
    renderLabels: settings.labelMode !== "hover" && settings.labelMode !== "off",
    renderEdgeLabels: settings.edgeLabels,
    labelRenderedSizeThreshold: settings.labelMode === "auto" ? 6 : 0,
  };
}

export function createRenderer(
  container: HTMLElement,
  store: GraphStore,
  view: { current: ViewState },
): Sigma<NodeAttrs, EdgeAttrs> {
  const graph: CanvasGraph = store.graph;
  return new Sigma<NodeAttrs, EdgeAttrs>(graph, container, {
    allowInvalidContainer: true,
    enableEdgeEvents: true,
    defaultNodeType: "ring",
    defaultEdgeType: "arrow",
    nodeProgramClasses: { ring: NodeProgram },
    edgeProgramClasses: { arrow: ArrowProgram, curved: CurvedArrowProgram },
    labelFont: "Inter, 'Segoe UI', system-ui, sans-serif",
    labelSize: 12,
    labelWeight: "500",
    edgeLabelSize: 11,
    labelDensity: 0.9,
    stagePadding: 64,
    zIndex: true,
    minCameraRatio: 0.02,
    maxCameraRatio: 20,
    defaultDrawNodeHover: hoverRenderer(view),
    ...sigmaSettingsFor(view.current),
    nodeReducer: (key, attrs) => {
      const { colors, selected, hoveredNode, settings } = view.current;
      const n = attrs.node;
      const res: DisplayNode = { ...attrs };
      if (settings.hiddenNodeKinds.includes(n.kind)) {
        res.hidden = true;
        return res;
      }
      res.color = settings.kindColors[n.kind] ?? attrs.color;
      res.size = baseSize(attrs, graph, key, settings.nodeSize);
      if (n.tier0) {
        res.ringTier0 = 0.22;
        res.ringTier0Color = colors.tier0Ring;
        res.ringGap = 0.08;
        res.ringGapColor = colors.background;
      }
      const zc = view.current.zoneColor(key);
      if (zc) {
        res.ringZone = 0.3;
        res.ringZoneColor = zc;
      }
      if (n.owned) res.ringOwned = 0.24;

      const onPath = store.highlight.nodes.has(key);
      if (settings.dimOffPath && store.highlight.nodes.size > 0 && !onPath && key !== selected) {
        res.color = mix(res.color as string, colors.background, 0.75);
        res.label = "";
      }
      if (settings.labelMode === "always") res.forceLabel = true;
      if (settings.labelMode === "selected") {
        if (key === selected || key === hoveredNode) res.forceLabel = true;
        else res.label = "";
      }
      if (key === selected) {
        res.highlighted = true;
        res.zIndex = 2;
        res.size = (res.size as number) * 1.35;
      } else if (onPath) {
        res.zIndex = 1;
      }
      return res;
    },
    edgeReducer: (key, attrs) => {
      const { colors, selected, hoveredEdge, settings, isTraversable } = view.current;
      const traversable = isTraversable(attrs.kind);
      // Non-traversable kinds (trust records, TrustedBy, SyncedToADGroup, ADCS plumbing …) are
      // informational: drawn faded and thinner so attack edges stand out.
      const res: DisplayEdge = { ...attrs, color: traversable ? colors.edge : mix(colors.edge, colors.background, 0.55) };
      if (!traversable) res.size = Math.max(0.5, (attrs.size ?? 1) * 0.6);
      if (settings.hiddenEdgeKinds.includes(attrs.kind) || (settings.hideNonTraversable && !traversable)) {
        res.hidden = true;
        return res;
      }
      const src = graph.source(key);
      const dst = graph.target(key);
      if (settings.edgeCurves) {
        res.type = "curved";
        // Spread parallel edges between the same pair so every kind stays visible.
        res.curvature = 0.2 + 0.18 * Math.max(0, graph.edges(src, dst).indexOf(key));
      }
      const highlighted = store.highlight.edges.has(key);
      if (highlighted) {
        const style = settings.pathHighlight;
        res.color = style === "thick" ? colors.edge : colors.accent;
        res.size = style === "accent" ? 3 : 5;
        res.zIndex = 1;
      } else if (settings.dimOffPath && store.highlight.edges.size > 0) {
        res.color = mix(colors.edge, colors.background, 0.6);
        res.label = "";
      }
      if (selected && (src === selected || dst === selected)) {
        res.size = Math.max(res.size, 2.4);
        res.zIndex = 1;
      }
      if (key === hoveredEdge) {
        res.color = colors.accent;
        res.size = Math.max(res.size, 3.5);
        res.zIndex = 2;
      }
      return res;
    },
  });
}

/** Flattens sigma's layered canvases into one PNG and downloads it. */
export function exportPng(sigma: Sigma<NodeAttrs, EdgeAttrs>, background: string): void {
  sigma.refresh(); // synchronous render so WebGL buffers are still populated below
  const layers = sigma.getCanvases();
  const ref = layers.edges ?? Object.values(layers)[0];
  if (!ref) return;
  const out = document.createElement("canvas");
  out.width = ref.width;
  out.height = ref.height;
  const ctx = out.getContext("2d");
  if (!ctx) return;
  ctx.fillStyle = background;
  ctx.fillRect(0, 0, out.width, out.height);
  for (const id of ["edges", "edgeLabels", "nodes", "labels", "hovers", "hoverNodes"]) {
    const layer = layers[id];
    if (layer) ctx.drawImage(layer, 0, 0, out.width, out.height);
  }
  out.toBlob((blob) => {
    if (!blob) return;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `copperhound-${new Date().toISOString().replace(/[:.]/g, "-")}.png`;
    a.click();
    window.setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
}
