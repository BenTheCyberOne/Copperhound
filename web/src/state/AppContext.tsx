import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, errorMessage } from "../api/client";
import type { Direction, Edge, GraphResult, MarksRequest, Node, NodeId } from "../api/types";
import { runLayout } from "../graph/layout";
import { GraphStore, nodeKey } from "../graph/store";
import { useSettings } from "../settings/SettingsContext";
import { useCatalog } from "./CatalogContext";

export type SidebarTab = "path" | "queries" | "tier0";
export type SettingsSection = "appearance" | "filters" | "layout" | "behaviour";

export interface TableData {
  title: string;
  columns: string[];
  rows: unknown[][];
  truncated: boolean;
}

export interface Notice {
  id: number;
  text: string;
  kind: "info" | "warn" | "error";
}

export interface LoadOptions {
  /** Path results use the hierarchical layout and are highlighted. */
  path?: boolean;
  /** Always merge, ignoring the replace toggle (expansions, search picks). */
  forceMerge?: boolean;
  select?: NodeId;
}

interface AppState {
  store: GraphStore;
  selectedId: NodeId | null;
  select: (id: NodeId | null) => void;
  pathFrom: Node | null;
  pathTo: Node | null;
  setPathFrom: (n: Node | null) => void;
  setPathTo: (n: Node | null) => void;
  replaceMode: boolean;
  setReplaceMode: (v: boolean) => void;
  table: TableData | null;
  setTable: (t: TableData | null) => void;
  notices: Notice[];
  notify: (text: string, kind?: Notice["kind"]) => void;
  dismiss: (id: number) => void;
  tab: SidebarTab;
  setTab: (t: SidebarTab) => void;
  settingsSection: SettingsSection | null;
  openSettings: (section: SettingsSection | null) => void;
  /** Bumped whenever marks change so views can refetch. */
  marksVersion: number;
  busy: boolean;
  track: <T>(p: Promise<T>) => Promise<T>;
  loadResult: (result: GraphResult, opts?: LoadOptions) => void;
  /** Re-applies the configured layout to the whole canvas. */
  relayout: (onDone?: () => void) => void;
  expand: (id: NodeId, dir: Direction, kind?: string) => Promise<void>;
  setMarks: (id: NodeId, marks: MarksRequest) => Promise<void>;
  /** Canvas ids belong to an older graph generation than the server's. */
  stale: boolean;
  /** Re-resolves canvas nodes (by objectid when stale) and redraws them. */
  reloadCanvas: () => Promise<void>;
  /** Query text handed to the Queries tab editor ("open in editor"). */
  editorRequest: { text: string; nonce: number } | null;
  openInEditor: (text: string) => void;
}

const Ctx = createContext<AppState | null>(null);

/** Max ids per /nodes, /nodes/resolve and /subgraph call. */
const BATCH = 5000;

export function AppProvider({ children }: { children: ReactNode }) {
  const { settings } = useSettings();
  const catalog = useCatalog();
  const [store] = useState(() => new GraphStore());
  const [selectedId, setSelectedId] = useState<NodeId | null>(null);
  const [pathFrom, setPathFrom] = useState<Node | null>(null);
  const [pathTo, setPathTo] = useState<Node | null>(null);
  const [replaceMode, setReplaceMode] = useState(settings.replaceByDefault);
  const [table, setTable] = useState<TableData | null>(null);
  const [notices, setNotices] = useState<Notice[]>([]);
  const [tab, setTab] = useState<SidebarTab>("path");
  const [settingsSection, openSettings] = useState<SettingsSection | null>(null);
  const [marksVersion, setMarksVersion] = useState(0);
  const [pending, setPending] = useState(0);
  const [, setStoreVersion] = useState(0);
  const [editorRequest, setEditorRequest] = useState<{ text: string; nonce: number } | null>(null);
  const openInEditor = useCallback((text: string) => {
    setEditorRequest((r) => ({ text, nonce: (r?.nonce ?? 0) + 1 }));
    setTab("queries");
  }, []);
  const noticeSeq = useRef(0);

  store.maxNodes = settings.maxNodes;
  useEffect(() => store.subscribe(() => setStoreVersion(store.version())), [store]);

  const generation = catalog.generation;
  const stale = store.graph.order > 0 && store.generation !== null && generation !== null && store.generation !== generation;

  // Selection would point at a different object in the new graph.
  useEffect(() => {
    if (stale) setSelectedId(null);
  }, [stale]);

  const dismiss = useCallback((id: number) => setNotices((ns) => ns.filter((n) => n.id !== id)), []);

  const notify = useCallback(
    (text: string, kind: Notice["kind"] = "info") => {
      const id = ++noticeSeq.current;
      // The same message from two places (e.g. the global 403 toast and the caller) shows once.
      setNotices((ns) => (ns.some((n) => n.text === text) ? ns : [...ns.slice(-4), { id, text, kind }]));
      window.setTimeout(() => dismiss(id), kind === "error" ? 9000 : 5000);
    },
    [dismiss],
  );

  const track = useCallback(<T,>(p: Promise<T>): Promise<T> => {
    setPending((n) => n + 1);
    return p.finally(() => setPending((n) => n - 1));
  }, []);

  const relayout = useCallback(
    (onDone?: () => void) => {
      runLayout(store.graph, {
        mode: settings.layout,
        fa2: settings.fa2,
        onDone: () => {
          store.requestFit();
          onDone?.();
        },
      });
    },
    [settings.layout, settings.fa2, store],
  );

  const loadResult = useCallback(
    (result: GraphResult, opts: LoadOptions = {}) => {
      const replace = replaceMode && !opts.forceMerge;
      if (replace || store.graph.order === 0) store.generation = generation;
      const outcome = store.merge(result, replace);
      if (opts.path) store.setHighlight(result.nodes.map((n) => n.id), result.edges);

      if (opts.path) {
        // Paths are always laid out as layers; direction follows the hierarchical setting.
        runLayout(store.graph, {
          mode: settings.layout === "hierarchical-tb" ? "hierarchical-tb" : "hierarchical-lr",
          fa2: settings.fa2,
          nodeIds: result.nodes.map((n) => n.id),
          paths: result.paths ?? [],
          besideExisting: !replace,
          onDone: () => store.requestFit(),
        });
      } else if (outcome.added.length > 0 && settings.autoLayout) {
        const layered = settings.layout.startsWith("hierarchical");
        runLayout(store.graph, {
          mode: settings.layout,
          fa2: settings.fa2,
          nodeIds: layered ? result.nodes.map((n) => n.id) : undefined,
          besideExisting: layered && !replace,
          onDone: () => store.requestFit(),
        });
      }
      if (opts.select !== undefined && store.has(opts.select)) setSelectedId(opts.select);
      if (outcome.dropped > 0) {
        notify(`Canvas is capped at ${store.maxNodes} nodes: ${outcome.dropped} nodes were not drawn.`, "warn");
      }
      if (result.truncated) notify("The server truncated this result (limit reached).", "warn");
    },
    [generation, notify, replaceMode, settings.autoLayout, settings.fa2, settings.layout, store],
  );

  const expand = useCallback(
    async (id: NodeId, dir: Direction, kind?: string) => {
      try {
        const res = await track(api.nodeEdges(id, dir, kind));
        if (res.edges.length === 0) {
          notify(`No ${dir === "out" ? "outbound" : "inbound"} ${kind ? `${kind} ` : ""}edges.`);
        }
        loadResult(res, { forceMerge: true });
      } catch (e) {
        notify(errorMessage(e), "error");
      }
    },
    [loadResult, notify, track],
  );

  const setMarks = useCallback(
    async (id: NodeId, marks: MarksRequest) => {
      try {
        const node = await track(api.setMarks(id, marks));
        store.updateNode(node);
        setMarksVersion((v) => v + 1);
      } catch (e) {
        notify(errorMessage(e), "error");
      }
    },
    [notify, store, track],
  );

  const reloadCanvas = useCallback(async () => {
    const g = store.graph;
    if (g.order === 0) return;
    const old = g.nodes().map((k) => g.getNodeAttributes(k));

    if (!stale) {
      // Same graph: just refresh flags (tier0/owned may have been changed by someone else).
      try {
        const ids = old.map((a) => a.node.id);
        for (let i = 0; i < ids.length; i += BATCH) {
          for (const n of await track(api.nodes(ids.slice(i, i + BATCH)))) store.updateNode(n);
        }
        notify("Canvas refreshed.");
      } catch (e) {
        notify(errorMessage(e), "error");
      }
      return;
    }

    // New graph: ids are meaningless, objectids are stable. Resolve them in bulk, then
    // fetch every edge among the resolved nodes in one subgraph call (v1.1 extras).
    const byObjectId = new Map<string, Node>();
    let edges: Edge[] = [];
    try {
      const objectids = old.map((a) => a.node.objectid);
      for (let i = 0; i < objectids.length; i += BATCH) {
        for (const n of await track(api.resolve(objectids.slice(i, i + BATCH)))) byObjectId.set(n.objectid.toUpperCase(), n);
      }
      const ids = [...byObjectId.values()].map((n) => n.id);
      // The canvas is capped well below the 5000-id limit in most setups; chunking keeps
      // larger canvases working, at the cost of edges between chunks.
      for (let i = 0; i < ids.length; i += BATCH) edges = edges.concat((await track(api.subgraph(ids.slice(i, i + BATCH)))).edges);
    } catch (e) {
      notify(`Reload failed: ${errorMessage(e)}`, "error");
      return;
    }

    const missing = old.length - byObjectId.size;
    store.merge({ nodes: [...byObjectId.values()], edges }, true);
    store.generation = generation;
    for (const a of old) {
      const n = byObjectId.get(a.node.objectid.toUpperCase());
      if (n) g.mergeNodeAttributes(nodeKey(n.id), { x: a.x, y: a.y });
    }
    store.touch();
    store.requestFit();
    setSelectedId(null);
    const remap = (n: Node | null) => (n ? (byObjectId.get(n.objectid.toUpperCase()) ?? null) : null);
    setPathFrom(remap);
    setPathTo(remap);
    notify(
      missing > 0
        ? `Canvas reloaded: ${byObjectId.size} nodes found, ${missing} no longer exist.`
        : `Canvas reloaded: all ${byObjectId.size} nodes found.`,
      missing > 0 ? "warn" : "info",
    );
  }, [generation, notify, stale, store, track]);

  const value = useMemo<AppState>(
    () => ({
      store,
      selectedId,
      select: setSelectedId,
      pathFrom,
      pathTo,
      setPathFrom,
      setPathTo,
      replaceMode,
      setReplaceMode,
      table,
      setTable,
      notices,
      notify,
      dismiss,
      tab,
      setTab,
      settingsSection,
      openSettings,
      marksVersion,
      busy: pending > 0,
      track,
      loadResult,
      relayout,
      expand,
      setMarks,
      stale,
      reloadCanvas,
      editorRequest,
      openInEditor,
    }),
    [
      store,
      selectedId,
      pathFrom,
      pathTo,
      replaceMode,
      table,
      notices,
      notify,
      dismiss,
      tab,
      settingsSection,
      marksVersion,
      pending,
      track,
      loadResult,
      relayout,
      expand,
      setMarks,
      stale,
      reloadCanvas,
      editorRequest,
      openInEditor,
    ],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useApp(): AppState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useApp must be used inside AppProvider");
  return v;
}
