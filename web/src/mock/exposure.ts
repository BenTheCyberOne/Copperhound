// Exposure analysis over the mock graph: who can reach a target set, through which
// edges, and how that changes when edges / kinds / nodes are removed.

import type { ChokePoint, Edge, ExposureRow, ExposureState, NodeId, Tier0Report } from "../api/types";
import { nodes } from "./data";
import { edgeAllowed, inAdj, publicNode } from "./graph";

export interface Removal {
  edges?: Set<string>;
  kinds?: Set<string>;
  nodes?: Set<NodeId>;
}

export const edgeId = (e: Edge) => `${e.src}|${e.kind}|${e.dst}`;

export interface ExposureResult {
  /** principal -> first hop of one shortest path into the targets (null for targets). */
  next: Map<NodeId, Edge | null>;
  exposed: NodeId[];
  depth: number;
  byKind: ExposureRow[];
  /** Number of principals whose (BFS-tree) path crosses each edge. */
  flow: Map<Edge, number>;
}

export function computeExposure(targets: Set<NodeId>, removal: Removal = {}): ExposureResult {
  const next = new Map<NodeId, Edge | null>();
  let frontier: NodeId[] = [];
  for (const id of targets) {
    if (removal.nodes?.has(id)) continue;
    next.set(id, null);
    frontier.push(id);
  }
  let depth = 0;
  while (frontier.length > 0) {
    const nf: NodeId[] = [];
    for (const id of frontier) {
      for (const edge of inAdj[id] ?? []) {
        if (next.has(edge.src) || !edgeAllowed(edge, {})) continue;
        if (removal.kinds?.has(edge.kind) || removal.edges?.has(edgeId(edge)) || removal.nodes?.has(edge.src)) continue;
        next.set(edge.src, edge);
        nf.push(edge.src);
      }
    }
    if (nf.length > 0) depth++;
    frontier = nf;
  }
  const flow = new Map<Edge, number>();
  for (const [id, first] of next) {
    if (!first || targets.has(id)) continue;
    let cur: Edge | null | undefined = first;
    while (cur) {
      flow.set(cur, (flow.get(cur) ?? 0) + 1);
      cur = next.get(cur.dst);
    }
  }
  const byKindMap = new Map<string, { with_path: number; total: number }>();
  for (const n of nodes) {
    if (targets.has(n.id) || removal.nodes?.has(n.id)) continue;
    const row = byKindMap.get(n.kind) ?? { with_path: 0, total: 0 };
    row.total++;
    if (next.has(n.id)) row.with_path++;
    byKindMap.set(n.kind, row);
  }
  return {
    next,
    exposed: [...next.keys()].filter((id) => !targets.has(id)),
    depth,
    byKind: [...byKindMap.entries()].map(([kind, r]) => ({ kind, ...r })).sort((a, b) => b.total - a.total),
    flow,
  };
}

export function exposureState(r: ExposureResult): ExposureState {
  return { exposed_principals: r.exposed.length, exposure: r.byKind, max_depth: r.depth };
}

export function exposureReport(targets: Set<NodeId>, top: number): Tier0Report {
  const r = computeExposure(targets);
  const choke: ChokePoint[] = [...r.flow.entries()]
    .filter(([x]) => !targets.has(x.src))
    .sort((a, b) => b[1] - a[1])
    .slice(0, top)
    .map(([x, f]) => ({ src: publicNode(nodes[x.src]!), dst: publicNode(nodes[x.dst]!), kind: x.kind, flow: f }));
  return {
    tier0_nodes: targets.size,
    max_depth: r.depth,
    exposed_principals: r.exposed.length,
    exposure: r.byKind,
    choke_points: choke,
    elapsed_ms: 3.2,
  };
}

export const tier0Targets = () => new Set(nodes.filter((n) => n.tier0).map((n) => n.id));
