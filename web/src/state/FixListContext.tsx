// The what-if "fix list": edges, edge kinds and nodes to remove in a simulation.
// Persisted in localStorage. Node ids are re-resolved by objectid when the graph
// generation changed since items were added.

import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { api } from "../api/client";
import type { Node, SimulateRequest } from "../api/types";
import { readLocal, writeLocal } from "../hooks/localStore";
import { useCatalog } from "./CatalogContext";

const KEY = "copperhound.fixList";

export interface FixEdge {
  src: Node;
  dst: Node;
  kind: string;
}

export interface FixList {
  zone: string;
  edges: FixEdge[];
  kinds: string[];
  nodes: Node[];
  /** Generation the node ids belong to. */
  generation: number | null;
}

const EMPTY: FixList = { zone: "tier0", edges: [], kinds: [], nodes: [], generation: null };

function load(): FixList {
  const raw = readLocal<Partial<FixList>>(KEY, {});
  const isNode = (n: unknown): n is Node => !!n && typeof n === "object" && typeof (n as Node).objectid === "string";
  return {
    zone: typeof raw.zone === "string" ? raw.zone : "tier0",
    edges: Array.isArray(raw.edges) ? raw.edges.filter((e) => isNode(e?.src) && isNode(e?.dst) && typeof e.kind === "string") : [],
    kinds: Array.isArray(raw.kinds) ? raw.kinds.filter((k): k is string => typeof k === "string") : [],
    nodes: Array.isArray(raw.nodes) ? raw.nodes.filter(isNode) : [],
    generation: typeof raw.generation === "number" ? raw.generation : null,
  };
}

const edgeKey = (e: FixEdge) => `${e.src.objectid}|${e.kind}|${e.dst.objectid}`;

interface FixListState {
  list: FixList;
  size: number;
  addEdges: (edges: FixEdge[]) => number;
  removeEdge: (e: FixEdge) => void;
  setKinds: (kinds: string[]) => void;
  addNode: (n: Node) => void;
  removeNode: (n: Node) => void;
  setZone: (zone: string) => void;
  clear: () => void;
  /** Builds a request with ids valid for the current graph; reports items no longer found. */
  prepare: () => Promise<{ request: SimulateRequest; missing: number }>;
}

const Ctx = createContext<FixListState | null>(null);

export function FixListProvider({ children }: { children: ReactNode }) {
  const { generation } = useCatalog();
  const [list, setList] = useState<FixList>(load);

  const update = useCallback(
    (f: (l: FixList) => FixList) =>
      setList((l) => {
        const next = f(l);
        writeLocal(KEY, next);
        return next;
      }),
    [],
  );

  /** Adds edges not already listed; returns how many were new. */
  const addEdges = useCallback(
    (edges: FixEdge[]) => {
      const have = new Set(list.edges.map(edgeKey));
      const fresh: FixEdge[] = [];
      for (const e of edges) {
        if (have.has(edgeKey(e))) continue;
        have.add(edgeKey(e));
        fresh.push(e);
      }
      if (fresh.length > 0) {
        update((l) => ({ ...l, edges: [...l.edges, ...fresh], generation: l.generation ?? generation }));
      }
      return fresh.length;
    },
    [generation, list.edges, update],
  );

  const prepare = useCallback(async () => {
    let current = list;
    let missing = 0;
    if (current.generation !== null && generation !== null && current.generation !== generation) {
      const objectids = [...new Set([...current.edges.flatMap((e) => [e.src.objectid, e.dst.objectid]), ...current.nodes.map((n) => n.objectid)])];
      const resolved = new Map((await api.resolve(objectids)).map((n) => [n.objectid.toUpperCase(), n]));
      const get = (n: Node) => resolved.get(n.objectid.toUpperCase());
      const edges = current.edges.flatMap((e) => {
        const src = get(e.src);
        const dst = get(e.dst);
        return src && dst ? [{ src, dst, kind: e.kind }] : [];
      });
      const nodes = current.nodes.flatMap((n) => {
        const r = get(n);
        return r ? [r] : [];
      });
      missing = current.edges.length - edges.length + current.nodes.length - nodes.length;
      current = { ...current, edges, nodes, generation };
      update(() => current);
    }
    return {
      request: {
        zone: current.zone,
        remove_edges: current.edges.map((e) => ({ src: e.src.id, dst: e.dst.id, kind: e.kind })),
        remove_kinds: current.kinds,
        remove_nodes: current.nodes.map((n) => n.id),
      },
      missing,
    };
  }, [generation, list, update]);

  const value = useMemo<FixListState>(
    () => ({
      list,
      size: list.edges.length + list.kinds.length + list.nodes.length,
      addEdges,
      removeEdge: (e) => update((l) => ({ ...l, edges: l.edges.filter((x) => edgeKey(x) !== edgeKey(e)) })),
      setKinds: (kinds) => update((l) => ({ ...l, kinds })),
      addNode: (n) =>
        update((l) =>
          l.nodes.some((x) => x.objectid === n.objectid) ? l : { ...l, nodes: [...l.nodes, n], generation: l.generation ?? generation },
        ),
      removeNode: (n) => update((l) => ({ ...l, nodes: l.nodes.filter((x) => x.objectid !== n.objectid) })),
      setZone: (zone) => update((l) => ({ ...l, zone })),
      clear: () => update((l) => ({ ...EMPTY, zone: l.zone })),
      prepare,
    }),
    [list, addEdges, update, generation, prepare],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useFixList(): FixListState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useFixList must be used inside FixListProvider");
  return v;
}
