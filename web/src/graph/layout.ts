// Layouts: ForceAtlas2 in a web worker, layered (left->right or top->bottom) for
// paths and hierarchies, plus circular and grid arrangements grouped by node kind.

import forceAtlas2 from "graphology-layout-forceatlas2";
import FA2Layout from "graphology-layout-forceatlas2/worker";
import type { NodeId } from "../api/types";
import type { Fa2Settings, LayoutMode } from "../settings/settings";
import { nodeKey, type CanvasGraph } from "./store";

let running: { layout: FA2Layout; timer: number } | null = null;

export function stopForceLayout(): void {
  if (!running) return;
  window.clearTimeout(running.timer);
  running.layout.kill();
  running = null;
}

/** Runs ForceAtlas2 in a worker; duration comes from settings, scaled up for big graphs. */
function runForceLayout(graph: CanvasGraph, fa2: Fa2Settings, onDone: () => void): void {
  if (graph.order < 2) {
    onDone();
    return;
  }
  const settings = {
    ...forceAtlas2.inferSettings(graph),
    gravity: fa2.gravity,
    scalingRatio: fa2.scalingRatio,
    linLogMode: fa2.linLogMode,
    barnesHutOptimize: graph.order > 400,
    adjustSizes: graph.order < 1500,
    slowDown: 3,
  };
  const layout = new FA2Layout(graph, { settings });
  layout.start();
  const ms = Math.min(30000, fa2.durationMs + graph.order * 2);
  const timer = window.setTimeout(() => {
    stopForceLayout();
    onDone();
  }, ms);
  running = { layout, timer };
}

export interface LayoutRequest {
  mode: LayoutMode;
  fa2: Fa2Settings;
  /** Restrict layered layouts to these nodes (default: the whole canvas). */
  nodeIds?: NodeId[];
  paths?: NodeId[][];
  /** Layered only: place the block below the rest of the drawing. */
  besideExisting?: boolean;
  onDone: () => void;
}

/** Applies a layout. Synchronous layouts call onDone immediately. */
export function runLayout(graph: CanvasGraph, req: LayoutRequest): void {
  stopForceLayout();
  switch (req.mode) {
    case "force":
      runForceLayout(graph, req.fa2, req.onDone);
      return;
    case "hierarchical-lr":
    case "hierarchical-tb": {
      const ids = req.nodeIds ?? graph.nodes().map(Number);
      layeredLayout(graph, ids, req.paths ?? [], req.besideExisting ?? false, req.mode === "hierarchical-tb");
      break;
    }
    case "circular":
      circularLayout(graph);
      break;
    case "grid":
      gridLayout(graph);
      break;
  }
  req.onDone();
}

/** Nodes sorted by kind then name, so circular/grid layouts group kinds together. */
function byKind(graph: CanvasGraph): string[] {
  return graph.nodes().sort((a, b) => {
    const x = graph.getNodeAttributes(a);
    const y = graph.getNodeAttributes(b);
    return x.node.kind.localeCompare(y.node.kind) || x.label.localeCompare(y.label);
  });
}

function circularLayout(graph: CanvasGraph): void {
  const keys = byKind(graph);
  const r = Math.max(100, (keys.length * 28) / (2 * Math.PI));
  keys.forEach((k, i) => {
    const a = (i / keys.length) * Math.PI * 2;
    graph.mergeNodeAttributes(k, { x: Math.cos(a) * r, y: Math.sin(a) * r });
  });
}

function gridLayout(graph: CanvasGraph): void {
  const keys = byKind(graph);
  const cols = Math.max(1, Math.ceil(Math.sqrt(keys.length * 1.6)));
  keys.forEach((k, i) => {
    graph.mergeNodeAttributes(k, { x: (i % cols) * 120, y: -Math.floor(i / cols) * 60 });
  });
}

const LAYER_GAP = 180;
const ROW_GAP = 70;

/**
 * Places `nodeIds` in layers by hop distance from the path starts
 * (rank = smallest index at which a node appears in any path); other nodes of
 * the result are ranked by BFS over the canvas edges. When `besideExisting` is
 * set the block is placed below the current drawing.
 */
function layeredLayout(graph: CanvasGraph, nodeIds: NodeId[], paths: NodeId[][], besideExisting: boolean, vertical: boolean): void {
  const keys = new Set(nodeIds.map(nodeKey).filter((k) => graph.hasNode(k)));
  if (keys.size === 0) return;

  const rank = new Map<string, number>();
  for (const p of paths) {
    p.forEach((id, i) => {
      const k = nodeKey(id);
      if (keys.has(k)) rank.set(k, Math.min(rank.get(k) ?? Infinity, i));
    });
  }
  if (rank.size === 0) {
    // No explicit paths: rank from sources (no inbound edge inside the set).
    for (const k of keys) {
      if (!graph.inNeighbors(k).some((n) => keys.has(n))) rank.set(k, 0);
    }
    if (rank.size === 0) rank.set([...keys][0]!, 0);
  }
  const queue = [...rank.keys()];
  while (queue.length > 0) {
    const k = queue.shift()!;
    const r = rank.get(k)!;
    for (const n of graph.outNeighbors(k)) {
      if (keys.has(n) && !rank.has(n)) {
        rank.set(n, r + 1);
        queue.push(n);
      }
    }
  }
  for (const k of keys) if (!rank.has(k)) rank.set(k, 0);

  const columns = new Map<number, string[]>();
  for (const [k, r] of rank) columns.set(r, [...(columns.get(r) ?? []), k]);

  const ranks = [...columns.keys()].sort((a, b) => a - b);
  const tallest = Math.max(...[...columns.values()].map((c) => c.length));

  let offsetX = 0;
  let offsetY = 0;
  // When merging, scale spacing to the existing drawing so the block is not dwarfed by it.
  let scale = 1;
  if (besideExisting) {
    let minX = Infinity;
    let maxX = -Infinity;
    let minY = Infinity;
    graph.forEachNode((k, a) => {
      if (keys.has(k)) return;
      minX = Math.min(minX, a.x);
      maxX = Math.max(maxX, a.x);
      minY = Math.min(minY, a.y);
    });
    if (Number.isFinite(minY)) {
      scale = Math.max(1, (maxX - minX) / Math.max(1, (ranks.length - 1) * LAYER_GAP));
      // Centre the block horizontally under the existing drawing (sigma's y axis points up).
      if (vertical) {
        offsetX = (minX + maxX) / 2;
        offsetY = minY - ROW_GAP * 2 * scale;
      } else {
        offsetX = (minX + maxX) / 2 - ((ranks.length - 1) * LAYER_GAP * scale) / 2;
        offsetY = minY - (ROW_GAP * 2 + (tallest * ROW_GAP) / 2) * scale;
      }
    }
  }
  const layerGap = LAYER_GAP * scale;
  const rowGap = ROW_GAP * scale;

  // Order each column by the mean row of its predecessors to reduce crossings.
  const row = new Map<string, number>();
  for (const r of ranks) {
    const col = columns.get(r)!;
    const bary = (k: string) => {
      const ys = graph.inNeighbors(k).flatMap((n) => (row.has(n) ? [row.get(n)!] : []));
      return ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : 0;
    };
    col.sort((a, b) => bary(a) - bary(b));
    // Single-node columns zig-zag slightly so neighbouring labels do not collide.
    const zig = tallest === 1 && !vertical ? (r % 2 === 0 ? -0.4 : 0.4) * rowGap : 0;
    col.forEach((k, i) => {
      const y = (i - (col.length - 1) / 2) * rowGap + zig;
      row.set(k, y);
      // Sigma's y axis points up; negate so the first row is at the top.
      const along = r * layerGap * (vertical ? 0.6 : 1);
      graph.mergeNodeAttributes(
        k,
        vertical ? { x: offsetX + y * 2.2, y: offsetY - along } : { x: offsetX + along, y: offsetY - y },
      );
    });
  }
}
