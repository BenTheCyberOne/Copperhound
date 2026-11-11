import { useCallback, useEffect, useRef, useState } from "react";
import { ComputingError, errorMessage } from "../api/client";

const RETRY_MS = 2000;

export interface AnalysisState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  /** 0-100 while the server answers 202 "computing"; null otherwise. */
  progress: number | null;
  reload: () => void;
}

/**
 * Loads `fetcher()` and, while the server answers 202 computing, retries every 2 s
 * and exposes the progress. Re-runs whenever `key` changes.
 */
export function useAnalysis<T>(fetcher: () => Promise<T>, key: string, enabled = true): AnalysisState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [nonce, setNonce] = useState(0);
  const fetchRef = useRef(fetcher);
  fetchRef.current = fetcher;

  useEffect(() => {
    if (!enabled) return;
    let live = true;
    let timer = 0;
    const attempt = () => {
      setLoading(true);
      fetchRef
        .current()
        .then((d) => {
          if (!live) return;
          setData(d);
          setError(null);
          setProgress(null);
          setLoading(false);
        })
        .catch((e: unknown) => {
          if (!live) return;
          if (e instanceof ComputingError) {
            setProgress(e.progress);
            timer = window.setTimeout(attempt, RETRY_MS);
            return;
          }
          setError(errorMessage(e));
          setProgress(null);
          setLoading(false);
        });
    };
    attempt();
    return () => {
      live = false;
      window.clearTimeout(timer);
    };
  }, [key, nonce, enabled]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return { data, loading, error, progress, reload };
}
