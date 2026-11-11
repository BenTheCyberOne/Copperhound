import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { SourcesResponse } from "../api/types";
import { useCatalog } from "../state/CatalogContext";

// One /sources request per graph generation, shared by every caller.
let cached: { generation: number | null; promise: Promise<SourcesResponse | null> } | null = null;

function load(generation: number | null): Promise<SourcesResponse | null> {
  if (cached && cached.generation === generation) return cached.promise;
  // Older servers have no /sources: treat as "no provenance" instead of an error.
  const promise = api.sources().catch(() => null);
  cached = { generation, promise };
  // A failed request is not cached, so the next caller retries.
  void promise.then((r) => {
    if (r === null && cached?.promise === promise) cached = null;
  });
  return promise;
}

/**
 * Sources of the loaded graph, refetched when the generation changes. `enabled` false
 * skips the request (e.g. a node without `_sources`).
 */
export function useSources(enabled = true): SourcesResponse | null {
  const { generation } = useCatalog();
  const [data, setData] = useState<SourcesResponse | null>(null);
  useEffect(() => {
    if (!enabled) return;
    let live = true;
    void load(generation).then((r) => live && setData(r));
    return () => {
      live = false;
    };
  }, [enabled, generation]);
  return enabled ? data : null;
}
