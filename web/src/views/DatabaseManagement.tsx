// Admin: selectively clear stored data (POST /database/clear).

import { useState } from "react";
import { api, errorMessage } from "../api/client";
import type { ClearRequest } from "../api/types";
import { useApp } from "../state/AppContext";
import { useCatalog } from "../state/CatalogContext";

const OPTIONS: { key: keyof Omit<ClearRequest, "confirm" | "uploads">; label: string; help: string }[] = [
  { key: "graph", label: "Loaded graph", help: "Unload the graph and delete its stored snapshots (uploads stay, re-ingest to rebuild)." },
  { key: "marks", label: "Owned / Tier Zero marks", help: "Marks made in the UI or API; ingest's own Tier Zero tagging is kept." },
  { key: "zones", label: "Privilege zones", help: "User-defined zones and their selectors." },
  { key: "saved_queries", label: "Saved queries", help: "Queries saved by users (the built-in library stays)." },
  { key: "posture_history", label: "Posture history", help: "Posture snapshots and trend data." },
];

export function DatabaseManagement({ onCleared }: { onCleared: () => void }) {
  const { notify, track, store } = useApp();
  const { refreshHealth } = useCatalog();
  const [opts, setOpts] = useState<Record<string, boolean>>({});
  const [uploads, setUploads] = useState(false);
  const [rebuild, setRebuild] = useState(false);
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const any = uploads || Object.values(opts).some(Boolean);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const body: ClearRequest = { confirm, ...opts, ...(uploads ? { uploads: "all" } : {}), rebuild: uploads && rebuild };
      const r = await track(api.clearDatabase(body));
      const parts = [
        r.uploads_removed?.length ? `${r.uploads_removed.length} uploads removed` : null,
        r.graph_snapshots_removed !== undefined ? "graph unloaded" : null,
        r.marks_cleared ? "marks cleared" : null,
        r.zones_cleared ? "zones cleared" : null,
        r.saved_queries_cleared ? "saved queries cleared" : null,
        r.posture_history_cleared ? "posture history cleared" : null,
        r.job_id ? `rebuild started (${r.job_id})` : null,
      ].filter(Boolean);
      notify(parts.length > 0 ? `Cleared: ${parts.join(", ")}.` : "Nothing to clear.");
      setOpts({});
      setUploads(false);
      setRebuild(false);
      setConfirm("");
      if (r.graph_snapshots_removed !== undefined) store.clear();
      refreshHealth();
      onCleared();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card form-stack db-manage">
      <h2>Database management</h2>
      <p className="muted small-text">Permanently delete stored data. Users, single sign-on and notification settings and the audit log are never affected.</p>
      <label className="toggle">
        <input type="checkbox" checked={uploads} onChange={(e) => setUploads(e.target.checked)} />
        All uploaded files
      </label>
      {uploads && (
        <label className="toggle indent">
          <input type="checkbox" checked={rebuild} onChange={(e) => setRebuild(e.target.checked)} />
          Then rebuild the graph from what is left (nothing left: unload it)
        </label>
      )}
      {OPTIONS.map((o) => (
        <label key={o.key} className="toggle" title={o.help}>
          <input type="checkbox" checked={!!opts[o.key]} onChange={(e) => setOpts((s) => ({ ...s, [o.key]: e.target.checked }))} />
          {o.label} <span className="muted small-text">— {o.help}</span>
        </label>
      ))}
      <label className="form-field">
        <span className="field-title">
          Type <code>DELETE</code> to confirm
        </span>
        <input value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder="DELETE" autoComplete="off" />
      </label>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div className="row gap">
        <button type="button" className="danger" disabled={!any || confirm !== "DELETE" || busy} onClick={() => void run()}>
          {busy ? "Clearing…" : "Clear selected data"}
        </button>
      </div>
    </section>
  );
}
