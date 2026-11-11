// Server-side facts the whole UI depends on: /health (generation, limits, polled every
// 30 s) and the categorised node/edge kind lists, refetched when the generation changes.

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api } from "../api/client";
import type { EdgeKindInfo, Health, NodeKindInfo } from "../api/types";
import { fallbackNodeCategory, type Category } from "../graph/kinds";
import { setSharedKindStyles } from "../graph/kinds";

const HEALTH_POLL_MS = 30_000;

interface CatalogState {
  health: Health | null;
  /** Current server graph generation (null until the first /health). */
  generation: number | null;
  nodeKinds: NodeKindInfo[];
  edgeKinds: EdgeKindInfo[];
  nodeCategory: (kind: string) => Category;
  edgeCategory: (kind: string) => Category;
  /** Unknown edge kinds are treated as traversable. */
  isTraversable: (kind: string) => boolean;
  /** Derived by post-processing, with an explanation (GET /edges/composition). */
  isComposite: (kind: string) => boolean;
  /** Bumped when shared kind styles load or change (re-colour the canvas). */
  kindStylesVersion: number;
  reloadKindStyles: () => void;
  refreshHealth: () => void;
}

const Ctx = createContext<CatalogState | null>(null);

export function CatalogProvider({ children }: { children: ReactNode }) {
  const [health, setHealth] = useState<Health | null>(null);
  const [nodeKinds, setNodeKinds] = useState<NodeKindInfo[]>([]);
  const [edgeKinds, setEdgeKinds] = useState<EdgeKindInfo[]>([]);
  const [kindStylesVersion, setKindStylesVersion] = useState(0);
  const reloadKindStyles = useCallback(() => {
    api.kindStyles().then(
      (m) => {
        setSharedKindStyles(m);
        setKindStylesVersion((v) => v + 1);
      },
      () => undefined,
    );
  }, []);

  const refreshHealth = useCallback(() => {
    api.health().then(setHealth, () => undefined);
  }, []);

  useEffect(() => {
    refreshHealth();
    const t = window.setInterval(refreshHealth, HEALTH_POLL_MS);
    return () => window.clearInterval(t);
  }, [refreshHealth]);

  const generation = health?.generation ?? null;
  useEffect(() => {
    if (generation === null) return;
    api.nodeKinds().then(setNodeKinds, () => undefined);
    api.edgeKinds().then(setEdgeKinds, () => undefined);
    reloadKindStyles();
  }, [generation, reloadKindStyles]);

  const value = useMemo<CatalogState>(() => {
    const nodeCat = new Map(nodeKinds.map((k) => [k.name, k.category]));
    const edgeCat = new Map(edgeKinds.map((k) => [k.name, k]));
    return {
      health,
      generation,
      nodeKinds,
      edgeKinds,
      nodeCategory: (kind) => nodeCat.get(kind) ?? fallbackNodeCategory(kind),
      edgeCategory: (kind) => edgeCat.get(kind)?.category ?? "Other",
      isTraversable: (kind) => edgeCat.get(kind)?.traversable ?? true,
      isComposite: (kind) => edgeCat.get(kind)?.composite === true,
      kindStylesVersion,
      reloadKindStyles,
      refreshHealth,
    };
  }, [health, generation, nodeKinds, edgeKinds, refreshHealth, kindStylesVersion, reloadKindStyles]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useCatalog(): CatalogState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useCatalog must be used inside CatalogProvider");
  return v;
}
