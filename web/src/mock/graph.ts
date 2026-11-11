// Adjacency index + traversal helpers over the mock dataset.

import type { Edge, GraphResult, Node, NodeId } from "../api/types";
import { edges, NON_TRAVERSABLE, nodes, type MockNode } from "./data";

export const outAdj: Edge[][] = nodes.map(() => []);
export const inAdj: Edge[][] = nodes.map(() => []);
for (const edge of edges) {
  outAdj[edge.src]!.push(edge);
  inAdj[edge.dst]!.push(edge);
}

export function getNode(id: NodeId): MockNode | undefined {
  return nodes[id];
}

export function publicNode(n: MockNode): Node {
  return { id: n.id, objectid: n.objectid, name: n.name, kind: n.kind, tier0: n.tier0, owned: n.owned, enabled: n.enabled };
}

export interface EdgeFilter {
  kinds?: Set<string>;
  exclude?: Set<string>;
  allEdges?: boolean;
}

export function edgeAllowed(edge: Edge, f: EdgeFilter): boolean {
  if (f.kinds && f.kinds.size > 0) return f.kinds.has(edge.kind);
  if (f.exclude?.has(edge.kind)) return false;
  return f.allEdges === true || !NON_TRAVERSABLE.has(edge.kind);
}

/** BFS from `from` until `isTarget`; returns the edge sequence of one shortest path. */
export function shortestPath(from: NodeId, isTarget: (id: NodeId) => boolean, f: EdgeFilter, maxHops = Infinity): Edge[] | null {
  const prev = new Map<NodeId, Edge | null>([[from, null]]);
  let frontier = [from];
  for (let depth = 0; frontier.length > 0 && depth < maxHops; depth++) {
    const next: NodeId[] = [];
    for (const id of frontier) {
      for (const edge of outAdj[id] ?? []) {
        if (prev.has(edge.dst) || !edgeAllowed(edge, f)) continue;
        prev.set(edge.dst, edge);
        if (isTarget(edge.dst)) {
          const path: Edge[] = [];
          let cur: Edge | null | undefined = edge;
          while (cur) {
            path.unshift(cur);
            cur = prev.get(cur.src);
          }
          return path;
        }
        next.push(edge.dst);
      }
    }
    frontier = next;
  }
  return null;
}

/** All edges lying on some shortest path from `from` to its nearest targets. */
export function allShortestPathEdges(from: NodeId, isTarget: (id: NodeId) => boolean, f: EdgeFilter): Edge[] {
  const dist = new Map<NodeId, number>([[from, 0]]);
  const preds = new Map<NodeId, Edge[]>();
  let frontier = [from];
  const hits: NodeId[] = [];
  for (let depth = 0; frontier.length > 0 && hits.length === 0; depth++) {
    const next: NodeId[] = [];
    for (const id of frontier) {
      for (const edge of outAdj[id] ?? []) {
        if (!edgeAllowed(edge, f)) continue;
        const d = dist.get(edge.dst);
        if (d === undefined) {
          dist.set(edge.dst, depth + 1);
          preds.set(edge.dst, [edge]);
          next.push(edge.dst);
          if (isTarget(edge.dst)) hits.push(edge.dst);
        } else if (d === depth + 1) {
          preds.get(edge.dst)!.push(edge);
        }
      }
    }
    frontier = next;
  }
  const out = new Set<Edge>();
  const stack = [...hits];
  const seen = new Set<NodeId>();
  while (stack.length > 0) {
    const id = stack.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    for (const edge of preds.get(id) ?? []) {
      out.add(edge);
      stack.push(edge.src);
    }
  }
  return [...out];
}

export function resultFrom(nodeIds: Iterable<NodeId>, edgeList: Edge[], extra: Partial<GraphResult> = {}): GraphResult {
  const ids = new Set(nodeIds);
  for (const edge of edgeList) {
    ids.add(edge.src);
    ids.add(edge.dst);
  }
  return {
    nodes: [...ids].map((id) => publicNode(nodes[id]!)),
    edges: edgeList.map((x) => ({ ...x })),
    truncated: false,
    elapsed_ms: 0,
    ...extra,
  };
}
