// Privilege zones (v1.2): the zone list plus member sets used to draw zone rings on
// the canvas. Members are fetched for zones with at most MEMBER_FETCH_LIMIT members.

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api } from "../api/client";
import type { Node, NodeId, Zone } from "../api/types";
import { useCatalog } from "./CatalogContext";

export const MEMBER_FETCH_LIMIT = 20000;
const PAGE = 5000;

interface ZonesState {
  zones: Zone[];
  error: string | null;
  loaded: boolean;
  reload: () => void;
  /** Member ids per zone id (only zones small enough to fetch). */
  members: Map<string, Set<NodeId>>;
  zone: (id: string) => Zone | undefined;
  /** Objects waiting in the "Add to zone…" dialog (null when closed). */
  addToZone: Node[] | null;
  openAddToZone: (nodes: Node[] | null) => void;
}

const Ctx = createContext<ZonesState | null>(null);

async function fetchAllMembers(zone: Zone): Promise<Set<NodeId>> {
  const ids = new Set<NodeId>();
  for (let offset = 0; offset < zone.member_count; offset += PAGE) {
    const page = await api.zoneMembers(zone.id, offset, PAGE);
    page.items.forEach((n) => ids.add(n.id));
    if (page.items.length === 0) break;
  }
  return ids;
}

export function ZonesProvider({ children }: { children: ReactNode }) {
  const { generation } = useCatalog();
  const [zones, setZones] = useState<Zone[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [members, setMembers] = useState<Map<string, Set<NodeId>>>(new Map());
  const [nonce, setNonce] = useState(0);
  const [addToZone, openAddToZone] = useState<Node[] | null>(null);

  useEffect(() => {
    if (generation === null) return;
    let live = true;
    api
      .zones()
      .then(async (zs) => {
        if (!live) return;
        // Built-in Tier Zero first, then by name.
        zs.sort((a, b) => Number(b.builtin) - Number(a.builtin) || a.name.localeCompare(b.name));
        setZones(zs);
        setError(null);
        setLoaded(true);
        const next = new Map<string, Set<NodeId>>();
        for (const z of zs) {
          if (z.member_count > 0 && z.member_count <= MEMBER_FETCH_LIMIT) next.set(z.id, await fetchAllMembers(z));
        }
        if (live) setMembers(next);
      })
      .catch((e: unknown) => {
        if (live) {
          setError(e instanceof Error ? e.message : String(e));
          setLoaded(true);
        }
      });
    return () => {
      live = false;
    };
  }, [generation, nonce]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  const value = useMemo<ZonesState>(
    () => ({ zones, error, loaded, reload, members, zone: (id) => zones.find((z) => z.id === id), addToZone, openAddToZone }),
    [zones, error, loaded, reload, members, addToZone],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useZones(): ZonesState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useZones must be used inside ZonesProvider");
  return v;
}
