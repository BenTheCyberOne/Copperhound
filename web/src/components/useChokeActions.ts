import { useState } from "react";
import { api, errorMessage } from "../api/client";
import type { ChokePoint, GraphResult } from "../api/types";
import { useApp } from "../state/AppContext";
import { useFixList } from "../state/FixListContext";
import { chokeKey } from "./ExposureReport";
import { hopsOf } from "./PathHops";

/**
 * A path guaranteed to cross the choke point: the choke edge itself, followed (for
 * Tier Zero) by the shortest path from its destination into Tier Zero. The API has
 * no "path to zone", so custom zones draw only the choke edge.
 */
async function chokePointPath(cp: ChokePoint, zone: string): Promise<GraphResult> {
  const edge = { src: cp.src.id, dst: cp.dst.id, kind: cp.kind };
  const tail =
    zone === "tier0" && !cp.dst.tier0
      ? await api.path({ from: cp.dst.objectid, to_tier0: true, exclude: [], all_edges: false })
      : null;
  const tailHops = tail ? hopsOf(tail) : [];
  const nodes = new Map([cp.src, cp.dst, ...(tail?.nodes ?? [])].map((n) => [n.id, n]));
  return {
    nodes: [...nodes.values()],
    edges: [edge, ...(tail?.edges ?? [])],
    paths: [[cp.src.id, cp.dst.id, ...tailHops.map((h) => h.dst)]],
    hops: [edge, ...tailHops],
    truncated: false,
    elapsed_ms: tail?.elapsed_ms ?? 0,
  };
}

/** Draw-on-canvas and add-to-fix-list actions for choke point rows. */
export function useChokeActions(zone: string) {
  const { loadResult, track, notify } = useApp();
  const { addEdges } = useFixList();
  const [shown, setShown] = useState<{ key: string; result: GraphResult } | null>(null);

  const showChoke = async (cp: ChokePoint) => {
    try {
      const result = await track(chokePointPath(cp, zone));
      setShown({ key: chokeKey(cp), result });
      loadResult(result, { path: true, select: cp.src.id });
      return true;
    } catch (e) {
      notify(errorMessage(e), "error");
      return false;
    }
  };

  const addChoke = (cp: ChokePoint) => {
    const n = addEdges([{ src: cp.src, dst: cp.dst, kind: cp.kind }]);
    notify(n > 0 ? `Added ${cp.kind} edge to the fix list.` : "That edge is already in the fix list.");
  };

  return { shown, showChoke, addChoke };
}
