// Admin → Server: download a backup, or stage one for restore.

import { useRef, useState } from "react";
import { api, errorMessage } from "../../api/client";
import { useApp } from "../../state/AppContext";

export function BackupPanel() {
  const { notify, track } = useApp();
  const [uploads, setUploads] = useState(false);
  const [tls, setTls] = useState(false);
  const [busy, setBusy] = useState(false);
  const [staged, setStaged] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);

  const download = async () => {
    setBusy(true);
    setError(null);
    try {
      const { blob, filename } = await track(api.backup(uploads, tls));
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = filename;
      a.click();
      window.setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const restore = async (file: File) => {
    if (!window.confirm(`Restore from ${file.name}? It replaces accounts, settings, zones and history at the next restart.`)) return;
    setBusy(true);
    setError(null);
    try {
      const r = await track(api.restoreBackup(file));
      setStaged(`${r.staged_files} files from the backup of ${r.backup_created_at?.slice(0, 16).replace("T", " ") ?? "?"} are staged${r.includes_uploads ? " (with uploads; the graph is rebuilt)" : ""}.`);
      notify("Restore staged: restart CopperHound to apply it.", "warn");
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card form-stack">
      <h2>Backup and restore</h2>
      <p className="muted small-text">
        A backup holds accounts, SSO and SAML settings, notifications, schedules, zones, saved queries, marks, accepted risks,
        collectors, posture history and the audit log. Graphs are rebuilt from the uploads, so include them to move to a new server.
      </p>
      <label className="toggle">
        <input type="checkbox" checked={uploads} onChange={(e) => setUploads(e.target.checked)} />
        Include uploaded collector files (can be large)
      </label>
      <label className="toggle">
        <input type="checkbox" checked={tls} onChange={(e) => setTls(e.target.checked)} />
        Include the TLS certificate and private key
      </label>
      <p className="warn-text small-text">The backup contains password hashes, API token hashes and SSO secrets: store it like a credential.</p>
      <div className="row gap wrap">
        <button type="button" className="primary" disabled={busy} onClick={() => void download()}>
          Download backup
        </button>
        <button type="button" disabled={busy} onClick={() => input.current?.click()}>
          Restore from backup…
        </button>
        <input
          ref={input}
          type="file"
          accept=".zip,application/zip"
          hidden
          onChange={(e) => {
            const f = e.target.files?.[0];
            e.target.value = "";
            if (f) void restore(f);
          }}
        />
      </div>
      {staged && (
        <p className="notice warn">
          <span>
            {staged} Restart CopperHound (<code>docker compose restart</code>) to apply them.
          </span>
        </p>
      )}
      {error && <p className="error">{error}</p>}
    </section>
  );
}
