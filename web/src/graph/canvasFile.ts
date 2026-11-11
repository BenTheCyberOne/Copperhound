// Canvas export / import as JSON. Nodes are stored by object id (node ids
// change with every graph), with their positions; on import they are
// re-resolved against the current graph and only edges that still exist there
// are drawn.

import { api } from "../api/client";
import type { Edge, Node } from "../api/types";
import type { GraphStore } from "./store";

export const CANVAS_FORMAT = "copperhound-canvas";

export interface CanvasFile {
  format: typeof CANVAS_FORMAT;
  version: 1;
  exported_at: string;
  nodes: { objectid: string; name: string; kind: string; x: number; y: number }[];
  edges: { src: string; dst: string; kind: string }[];
}

export function canvasToFile(store: GraphStore): CanvasFile {
  const g = store.graph;
  const oidOf = new Map<string, string>();
  const nodes: CanvasFile["nodes"] = [];
  g.forEachNode((k, a) => {
    oidOf.set(k, a.node.objectid);
    nodes.push({ objectid: a.node.objectid, name: a.node.name, kind: a.node.kind, x: a.x, y: a.y });
  });
  const edges: CanvasFile["edges"] = [];
  g.forEachEdge((_, a, s, d) => {
    edges.push({ src: oidOf.get(s)!, dst: oidOf.get(d)!, kind: a.kind });
  });
  return { format: CANVAS_FORMAT, version: 1, exported_at: new Date().toISOString(), nodes, edges };
}

export function downloadCanvas(store: GraphStore): void {
  const blob = new Blob([JSON.stringify(canvasToFile(store), null, 1)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `copperhound-canvas-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.json`;
  a.click();
  window.setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

export function parseCanvasFile(text: string): CanvasFile {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    throw new Error("not a JSON file");
  }
  const f = v as Partial<CanvasFile>;
  if (f.format !== CANVAS_FORMAT || !Array.isArray(f.nodes) || !Array.isArray(f.edges)) {
    throw new Error("not a CopperHound canvas export");
  }
  return f as CanvasFile;
}

export interface ImportOutcome {
  nodes: Node[];
  edges: Edge[];
  /** Object ids not in the current graph. */
  missingNodes: number;
  /** Exported edges that no longer exist. */
  missingEdges: number;
}

/** Resolve an export against the current graph (5000 objects per request). */
export async function resolveCanvasFile(f: CanvasFile): Promise<ImportOutcome> {
  const oids = [...new Set(f.nodes.map((n) => n.objectid))];
  const nodes: Node[] = [];
  for (let i = 0; i < oids.length; i += 5000) nodes.push(...(await api.resolve(oids.slice(i, i + 5000))));
  const idOf = new Map(nodes.map((n) => [n.objectid.toUpperCase(), n.id]));
  const wanted = new Set(
    f.edges.flatMap((e) => {
      const s = idOf.get(e.src.toUpperCase());
      const d = idOf.get(e.dst.toUpperCase());
      return s === undefined || d === undefined ? [] : [`${s}|${d}|${e.kind}`];
    }),
  );
  const edges: Edge[] = [];
  if (nodes.length > 0 && nodes.length <= 5000) {
    const sub = await api.subgraph(nodes.map((n) => n.id));
    edges.push(...sub.edges.filter((e) => wanted.has(`${e.src}|${e.dst}|${e.kind}`)));
  }
  return { nodes, edges, missingNodes: oids.length - nodes.length, missingEdges: f.edges.length - edges.length };
}

/** Exported positions for the resolved nodes, by node id. */
export function positionsOf(f: CanvasFile, nodes: Node[]): Map<number, { x: number; y: number }> {
  const byOid = new Map(f.nodes.map((n) => [n.objectid.toUpperCase(), n]));
  const out = new Map<number, { x: number; y: number }>();
  for (const n of nodes) {
    const p = byOid.get(n.objectid.toUpperCase());
    if (p && Number.isFinite(p.x) && Number.isFinite(p.y)) out.set(n.id, { x: p.x, y: p.y });
  }
  return out;
}
