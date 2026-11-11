// Holds the canvas graph (graphology) and the bits of view state the renderer needs.
// React subscribes through useSyncExternalStore on `version`.

import { MultiDirectedGraph } from "graphology";
import type { Edge, GraphResult, Node, NodeId } from "../api/types";
import { NODE_CAP_DEFAULT } from "../settings/settings";
import { kindColor } from "./kinds";

export interface NodeAttrs {
  x: number;
  y: number;
  size: number;
  label: string;
  color: string;
  node: Node;
}

export interface EdgeAttrs {
  kind: string;
  /** Shown when edge labels are enabled. */
  label: string;
  size: number;
}

export type CanvasGraph = MultiDirectedGraph<NodeAttrs, EdgeAttrs>;

export interface MergeOutcome {
  /** Node keys that were not on the canvas before. */
  added: string[];
  /** Result nodes dropped because of the render cap (`maxNodes`). */
  dropped: number;
}

export const nodeKey = (id: NodeId) => String(id);
export const edgeKey = (e: Edge) => `${e.src}|${e.kind}|${e.dst}`;

function nodeSize(n: Node): number {
  if (n.kind === "Domain" || n.kind === "AZTenant") return 11;
  return n.tier0 ? 9 : 6;
}

type Listener = () => void;

export class GraphStore {
  readonly graph: CanvasGraph = new MultiDirectedGraph<NodeAttrs, EdgeAttrs>();
  /** Edges/nodes of the most recent path result, drawn highlighted. */
  highlight = { nodes: new Set<string>(), edges: new Set<string>() };
  /** Number of nodes dropped by the render cap in the last merge (0 = none). */
  capDropped = 0;
  /** Render cap, from settings. */
  maxNodes = NODE_CAP_DEFAULT;
  /** Server graph generation the canvas ids belong to (null = empty canvas). */
  generation: number | null = null;
  private versionNo = 0;
  private listeners = new Set<Listener>();
  private fitListeners = new Set<Listener>();
  private focusListeners = new Set<(key: string) => void>();

  subscribe = (l: Listener): (() => void) => {
    this.listeners.add(l);
    return () => this.listeners.delete(l);
  };
  version = (): number => this.versionNo;

  private emit(): void {
    this.versionNo++;
    this.listeners.forEach((l) => l());
  }

  onFitRequest(l: Listener): () => void {
    this.fitListeners.add(l);
    return () => this.fitListeners.delete(l);
  }
  requestFit(): void {
    this.fitListeners.forEach((l) => l());
  }

  onFocusRequest(l: (key: string) => void): () => void {
    this.focusListeners.add(l);
    return () => this.focusListeners.delete(l);
  }
  /** Ask the renderer to centre the camera on a node. */
  requestFocus(id: NodeId): void {
    const k = nodeKey(id);
    if (this.graph.hasNode(k)) this.focusListeners.forEach((l) => l(k));
  }

  has(id: NodeId): boolean {
    return this.graph.hasNode(nodeKey(id));
  }

  merge(result: Pick<GraphResult, "nodes" | "edges">, replace: boolean): MergeOutcome {
    const g = this.graph;
    if (replace) {
      g.clear();
      this.highlight = { nodes: new Set(), edges: new Set() };
    }
    const added: string[] = [];
    let dropped = 0;
    const center = this.center();
    for (const n of result.nodes) {
      const k = nodeKey(n.id);
      if (g.hasNode(k)) {
        this.applyNode(k, n);
        continue;
      }
      if (g.order >= this.maxNodes) {
        dropped++;
        continue;
      }
      const angle = Math.random() * Math.PI * 2;
      const r = 20 + Math.random() * 40;
      g.addNode(k, {
        x: center.x + Math.cos(angle) * r,
        y: center.y + Math.sin(angle) * r,
        size: nodeSize(n),
        label: n.name,
        color: kindColor(n.kind),
        node: n,
      });
      added.push(k);
    }
    for (const e of result.edges) {
      const s = nodeKey(e.src);
      const d = nodeKey(e.dst);
      const k = edgeKey(e);
      if (!g.hasNode(s) || !g.hasNode(d) || g.hasEdge(k)) continue;
      g.addDirectedEdgeWithKey(k, s, d, { kind: e.kind, label: e.kind, size: 1.6 });
    }
    this.placeNearNeighbours(added);
    this.capDropped = dropped;
    this.emit();
    return { added, dropped };
  }

  /** Move freshly added nodes next to an already placed neighbour so layouts start sensibly. */
  private placeNearNeighbours(added: string[]): void {
    const fresh = new Set(added);
    for (const k of added) {
      const anchor = this.graph.neighbors(k).find((n) => !fresh.has(n));
      if (!anchor) continue;
      const a = this.graph.getNodeAttributes(anchor);
      const angle = Math.random() * Math.PI * 2;
      this.graph.mergeNodeAttributes(k, { x: a.x + Math.cos(angle) * 15, y: a.y + Math.sin(angle) * 15 });
    }
  }

  private center(): { x: number; y: number } {
    const g = this.graph;
    if (g.order === 0) return { x: 0, y: 0 };
    let x = 0;
    let y = 0;
    g.forEachNode((_, a) => {
      x += a.x;
      y += a.y;
    });
    return { x: x / g.order, y: y / g.order };
  }

  private applyNode(k: string, n: Node): void {
    this.graph.mergeNodeAttributes(k, { node: n, label: n.name, size: nodeSize(n), color: kindColor(n.kind) });
  }

  /** Move nodes to saved positions (canvas import). */
  setPositions(pos: Map<NodeId, { x: number; y: number }>): void {
    for (const [id, p] of pos) {
      const k = nodeKey(id);
      if (this.graph.hasNode(k)) this.graph.mergeNodeAttributes(k, p);
    }
    this.emit();
  }

  /** Re-apply default kind colours (shared styles changed). */
  recolor(): void {
    this.graph.updateEachNodeAttributes((_, a) => ({ ...a, color: kindColor(a.node.kind) }));
    this.emit();
  }

  updateNode(n: Node): void {
    const k = nodeKey(n.id);
    if (!this.graph.hasNode(k)) return;
    this.applyNode(k, n);
    this.emit();
  }

  removeNode(id: NodeId): void {
    const k = nodeKey(id);
    if (!this.graph.hasNode(k)) return;
    this.graph.dropNode(k);
    this.highlight.nodes.delete(k);
    this.emit();
  }

  removeEdge(key: string): void {
    if (!this.graph.hasEdge(key)) return;
    this.graph.dropEdge(key);
    this.highlight.edges.delete(key);
    this.emit();
  }

  clear(): void {
    this.graph.clear();
    this.highlight = { nodes: new Set(), edges: new Set() };
    this.capDropped = 0;
    this.generation = null;
    this.emit();
  }

  /** Force a re-render of subscribers (e.g. after positions were rewritten). */
  touch(): void {
    this.emit();
  }

  setHighlight(nodeIds: NodeId[], edges: Edge[]): void {
    this.highlight = { nodes: new Set(nodeIds.map(nodeKey)), edges: new Set(edges.map(edgeKey)) };
    this.emit();
  }

  /** Node kinds currently on the canvas with counts (legend, filters). */
  kinds(): Map<string, number> {
    const m = new Map<string, number>();
    this.graph.forEachNode((_, a) => m.set(a.node.kind, (m.get(a.node.kind) ?? 0) + 1));
    return m;
  }

  /** Edge kinds currently on the canvas with counts. */
  edgeKinds(): Map<string, number> {
    const m = new Map<string, number>();
    this.graph.forEachEdge((_, a) => m.set(a.kind, (m.get(a.kind) ?? 0) + 1));
    return m;
  }
}
