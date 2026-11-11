import { useCallback, useRef, useState } from "react";
import { ApiError, api, errorMessage } from "../../api/client";
import type { GraphResult } from "../../api/types";
import { readLocal, writeLocal } from "../../hooks/localStore";
import { useSettings } from "../../settings/SettingsContext";
import { useApp } from "../../state/AppContext";

const RECENT_KEY = "copperhound.recentQueries";
const RECENT_MAX = 20;

export interface RecentQuery {
  query: string;
  name?: string;
  at: string;
}

export type QueryFailure =
  | { kind: "syntax" | "semantic"; message: string; position: number | null }
  | { kind: "timeout" | "cancelled" | "other"; message: string };

function loadRecent(): RecentQuery[] {
  const raw = readLocal<unknown>(RECENT_KEY, []);
  if (!Array.isArray(raw)) return [];
  return raw.filter(
    (r): r is RecentQuery => !!r && typeof r === "object" && typeof (r as RecentQuery).query === "string",
  );
}

/** Client-chosen id for DELETE /query/{id}; crypto.randomUUID needs a secure context, so avoid it. */
const newQueryId = () => `q-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;

/** Runs CHQL with timeout + cancel support and routes results to the canvas / table. */
export function useQueryRunner() {
  const { loadResult, setTable, track } = useApp();
  const { settings } = useSettings();
  const [running, setRunning] = useState(false);
  const [failure, setFailure] = useState<QueryFailure | null>(null);
  const [summary, setSummary] = useState<string | null>(null);
  const [result, setResult] = useState<GraphResult | null>(null);
  const [recent, setRecent] = useState<RecentQuery[]>(loadRecent);
  const currentId = useRef<string | null>(null);

  const remember = useCallback((query: string, name?: string) => {
    setRecent((r) => {
      const next = [{ query, name, at: new Date().toISOString() }, ...r.filter((x) => x.query !== query)].slice(0, RECENT_MAX);
      writeLocal(RECENT_KEY, next);
      return next;
    });
  }, []);

  const clearRecent = useCallback(() => {
    setRecent([]);
    writeLocal(RECENT_KEY, []);
  }, []);

  const run = useCallback(
    async (query: string, opts: { title?: string; limit: number }) => {
      const q = query.trim();
      if (!q || currentId.current) return;
      const queryId = newQueryId();
      currentId.current = queryId;
      setRunning(true);
      setFailure(null);
      setSummary(null);
      setResult(null);
      remember(q, opts.title);
      try {
        const res = await track(
          api.query({
            query: q,
            limit: opts.limit,
            query_id: queryId,
            ...(settings.queryTimeoutMs > 0 ? { timeout_ms: settings.queryTimeoutMs } : {}),
          }),
        );
        const parts: string[] = [];
        if (res.columns && res.rows) {
          setTable({ title: opts.title ?? q, columns: res.columns, rows: res.rows, truncated: res.truncated });
          parts.push(`${res.rows.length} rows`);
        }
        if (res.nodes.length > 0) {
          const isPath = (res.paths?.length ?? 0) > 0;
          loadResult(res, { path: isPath });
          parts.push(`${res.nodes.length} nodes`, `${res.edges.length} edges`);
          if (isPath) parts.push(`${res.paths!.length} paths`);
        }
        if (parts.length === 0) parts.push("no results");
        setSummary(`${parts.join(" · ")} · ${res.elapsed_ms.toFixed(1)} ms${res.truncated ? " · truncated" : ""}`);
        setResult(res);
      } catch (e) {
        if (e instanceof ApiError && (e.code === "timeout" || e.status === 408)) {
          setFailure({ kind: "timeout", message: e.message });
        } else if (e instanceof ApiError && (e.code === "cancelled" || e.status === 409)) {
          setFailure({ kind: "cancelled", message: e.message });
        } else if (e instanceof ApiError && e.status === 400) {
          setFailure({ kind: e.code === "semantic" ? "semantic" : "syntax", message: e.message, position: e.position });
        } else {
          setFailure({ kind: "other", message: errorMessage(e) });
        }
      } finally {
        currentId.current = null;
        setRunning(false);
      }
    },
    [loadResult, remember, setTable, settings.queryTimeoutMs, track],
  );

  const cancel = useCallback(async () => {
    const id = currentId.current;
    if (!id) return;
    try {
      await api.cancelQuery(id);
    } catch (e) {
      setFailure({ kind: "other", message: `Cancel failed: ${errorMessage(e)}` });
    }
  }, []);

  return { run, cancel, running, failure, clearFailure: () => setFailure(null), summary, result, recent, clearRecent };
}
