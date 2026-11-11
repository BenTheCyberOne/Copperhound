import type { ReactNode } from "react";
import type { AnalysisState } from "../hooks/useAnalysis";

/**
 * Shared loading / computing / error presentation for analysis-backed views.
 * Returns null once data is available so callers can render their content.
 */
export function StatusView<T>({ state, what }: { state: AnalysisState<T>; what: string }) {
  if (state.progress !== null) {
    return (
      <div className="status-view" role="status">
        <p>
          <strong>Analysis in progress.</strong> The server is still computing {what} for the new graph. This retries
          automatically.
        </p>
        <div className="progress" role="progressbar" aria-label="Analysis progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={state.progress}>
          <div className="progress-fill" style={{ width: `${state.progress}%` }} />
          <span className="progress-text">{Math.round(state.progress)}%</span>
        </div>
      </div>
    );
  }
  if (state.error && !state.data) {
    return (
      <div className="status-view error-state" role="alert">
        <p className="error">Could not load {what}: {state.error}</p>
        <button type="button" onClick={state.reload}>
          Retry
        </button>
      </div>
    );
  }
  if (!state.data) {
    return (
      <div className="status-view" role="status">
        <span className="spinner" aria-hidden="true" /> <span className="muted">Loading {what}…</span>
      </div>
    );
  }
  return null;
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty-state">
      <p className="empty-title">{title}</p>
      {children && <div className="muted small-text">{children}</div>}
    </div>
  );
}
