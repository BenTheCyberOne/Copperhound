import { useEffect, useState, type FormEvent } from "react";
import { api, errorMessage } from "../../api/client";
import type { AnalysisSettings, IngestSettings, ServerSettings, SettingsResponse, WatchSettings } from "../../api/types";
import { MergeHelp } from "../../components/MergeHelp";
import { NumberField } from "../../components/NumberField";
import { routeHref } from "../../hooks/useRoute";
import { useApp } from "../../state/AppContext";
import { useSession } from "../../state/SessionContext";
import { when } from "../../util/format";
import { BackupPanel } from "./BackupPanel";
import { KindStylesPanel } from "./KindStylesPanel";

const POLL_MS = 10_000;

function WatchStatusPanel({ data }: { data: SettingsResponse }) {
  const s = data.watch_status;
  const enabled = data.settings.watch.enabled;
  return (
    <section className="card" aria-live="polite">
      <div className="section-head">
        <h2>Watch status</h2>
        <span className={`tag ${enabled ? "ok" : "off"}`}>{enabled ? "watching" : "off"}</span>
      </div>
      <dl className="fields wide-fields">
        <dt>Folder</dt>
        <dd>
          <code className="break">{data.watch_dir_resolved}</code>
        </dd>
        <dt>Last scan</dt>
        <dd>{when(s.last_scan)}</dd>
        <dt>Last import</dt>
        <dd>{when(s.last_import)}</dd>
        <dt>Last job</dt>
        <dd>{s.last_job ? <a href={routeHref("data")}>{s.last_job}</a> : "—"}</dd>
        <dt>Files imported</dt>
        <dd className="num">{s.imported_files.toLocaleString()}</dd>
        <dt>Waiting to settle</dt>
        <dd>
          {s.pending.length === 0 ? (
            <span className="muted">none</span>
          ) : (
            <ul className="plain-list">
              {s.pending.map((f) => (
                <li key={f}>
                  <code>{f}</code>
                </li>
              ))}
            </ul>
          )}
        </dd>
        {s.last_error && (
          <>
            <dt>Last error</dt>
            <dd className="error">{s.last_error}</dd>
          </>
        )}
      </dl>
      <p className="muted small-text">Refreshes every {POLL_MS / 1000} s.</p>
    </section>
  );
}

const DEFAULT_ANALYSIS: AnalysisSettings = { unified_tier0: true };
const DEFAULT_INGEST: IngestSettings = { merge_policy: "newest", session_window_hours: 0 };

/**
 * PUT /settings replaces the whole object and omitted sections reset to their defaults,
 * so every save starts from everything the server returned and changes one section.
 */
function withSection(data: SettingsResponse, patch: Partial<ServerSettings>): ServerSettings {
  return { ...data.settings, ...patch };
}

/** Analysis options (v1.4). Saved separately from the watch folder form. */
function AnalysisPanel({ data, onSaved }: { data: SettingsResponse; onSaved: (r: SettingsResponse) => void }) {
  const { notify, track } = useApp();
  const current = data.settings.analysis ?? DEFAULT_ANALYSIS;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const setUnified = async (unified: boolean) => {
    setBusy(true);
    setError(null);
    try {
      const r = await track(api.saveServerSettings(withSection(data, { analysis: { ...current, unified_tier0: unified } })));
      onSaved(r);
      notify(unified ? "Unified Tier Zero on: AD and Entra ID are analysed as one target set." : "Unified Tier Zero off: AD and Entra ID are analysed separately.");
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card form-stack">
      <h2>Analysis</h2>
      {data.settings.analysis === undefined && <p className="muted small-text">This server does not support analysis settings.</p>}
      <label className="toggle">
        <input
          type="checkbox"
          checked={current.unified_tier0}
          disabled={busy || data.settings.analysis === undefined}
          onChange={(e) => void setUnified(e.target.checked)}
        />
        <strong>Unified Tier Zero</strong> (AD + Entra ID as one target set)
      </label>
      <p className="small-text">
        <strong>On</strong> (default): Active Directory and Entra ID Tier Zero form one target set. Exposure, choke points and
        paths follow the hybrid edges (<code>SyncedToEntraUser</code>, <code>SyncedToEntraGroup</code>, <code>SeamlessSSO</code>,{" "}
        <code>EntraConnectCredentials</code>, …), so an on-premises user who can reach Global Administrator through a synced
        group counts as exposed.
      </p>
      <p className="muted small-text">
        <strong>Off</strong>: no edge between an AD object and an Azure object is followed. AD principals are measured against AD
        Tier Zero only and Entra principals against Entra Tier Zero only. Changing this recomputes the Tier Zero report.
      </p>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}

/** Merge policy for multiple dumps (v1.5). Applies to the next ingest. */
function IngestPanel({ data, onSaved }: { data: SettingsResponse; onSaved: (r: SettingsResponse) => void }) {
  const { notify, track } = useApp();
  const reingestGate = useSession().gate("analyst");
  const supported = data.settings.ingest !== undefined;
  const saved = data.settings.ingest ?? DEFAULT_INGEST;
  const [form, setForm] = useState<IngestSettings>(saved);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedOnce, setSavedOnce] = useState(false);
  const dirty = JSON.stringify(form) !== JSON.stringify(saved);

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await track(api.saveServerSettings(withSection(data, { ingest: form })));
      onSaved(r);
      setForm(r.settings.ingest ?? form);
      setSavedOnce(true);
      notify(`Merge policy “${form.merge_policy}” saved. It applies to the next graph rebuild.`);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const reingest = async () => {
    if (
      !window.confirm(
        "Rebuild the graph now from all current uploads with the saved merge settings? Node ids change, so open canvases go stale.",
      )
    ) {
      return;
    }
    try {
      const { job_id } = await track(api.ingest());
      notify(`Ingest job ${job_id} started. Follow it on the Data page.`);
    } catch (err) {
      notify(errorMessage(err), "error");
    }
  };

  return (
    <form className="card form-stack" onSubmit={(e) => void save(e)}>
      <div className="section-head">
        <h2>Ingest: multiple dumps</h2>
        <MergeHelp />
      </div>
      {!supported && <p className="muted small-text">This server does not support ingest settings.</p>}
      <fieldset className="role-choice" disabled={!supported || busy}>
        <legend>Merge policy</legend>
        <label className="check role-option">
          <input
            type="radio"
            name="merge_policy"
            checked={form.merge_policy === "newest"}
            onChange={() => setForm((f) => ({ ...f, merge_policy: "newest" }))}
          />
          <strong>Newest wins</strong> (default)
          <span className="muted small-text">
            When several dated collections describe one object, the newest defines its name, kind and flags (properties merge
            per key), and the relationships its record lists (ACEs, members, sessions, …) replace older ones, so removed rights
            disappear. Undated files are merged as a union.
          </span>
        </label>
        <label className="check role-option">
          <input
            type="radio"
            name="merge_policy"
            checked={form.merge_policy === "union"}
            onChange={() => setForm((f) => ({ ...f, merge_policy: "union" }))}
          />
          <strong>Union</strong>
          <span className="muted small-text">
            Every edge from every file is kept, flags are OR&apos;d and the last record&apos;s properties win (behaviour before
            v1.5). Stale rights from old dumps stay in the graph.
          </span>
        </label>
      </fieldset>
      <div className="form-grid">
        <label htmlFor="session-window">Session window (hours)</label>
        <NumberField
          id="session-window"
          min={0}
          max={8760}
          value={form.session_window_hours}
          onCommit={(v) => setForm((f) => ({ ...f, session_window_hours: Math.round(v) }))}
        />
      </div>
      <span className="muted small-text">
        Newest wins only. 0 keeps just each computer&apos;s newest session data; N also keeps <code>HasSession</code> edges from
        collections up to N hours older, useful when sessions are collected separately and often (0–8760).
      </span>
      <p className="notice">
        <span>
          Changes apply to the <strong>next ingest</strong> (Rebuild graph, the API or the watch folder). The loaded graph keeps
          the policy it was built with.
        </span>
      </p>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div className="row gap wrap">
        <button type="submit" className="primary" disabled={busy || !dirty || !supported}>
          {busy ? "Saving…" : "Save ingest settings"}
        </button>
        {dirty && (
          <button type="button" onClick={() => setForm(saved)}>
            Discard changes
          </button>
        )}
        <button
          type="button"
          onClick={() => void reingest()}
          disabled={reingestGate.disabled || dirty}
          title={dirty ? "Save the settings first" : (reingestGate.title ?? "Rebuild the graph from all uploads with the saved settings")}
        >
          Re-ingest now
        </button>
      </div>
      {savedOnce && !dirty && <p className="muted small-text">Saved. Re-ingest to apply it to the loaded graph.</p>}
    </form>
  );
}

export function ServerSettingsView() {
  const { notify, track } = useApp();
  const [data, setData] = useState<SettingsResponse | null>(null);
  const [form, setForm] = useState<WatchSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let live = true;
    let first = true;
    const load = () =>
      api.serverSettings().then(
        (r) => {
          if (!live) return;
          setData(r);
          // Only seed the form once so polling doesn't overwrite edits in progress.
          if (first) setForm(r.settings.watch);
          first = false;
        },
        (e: unknown) => live && setError(errorMessage(e)),
      );
    void load();
    const t = window.setInterval(() => void load(), POLL_MS);
    return () => {
      live = false;
      window.clearInterval(t);
    };
  }, []);

  const set = <K extends keyof WatchSettings>(k: K, v: WatchSettings[K]) => setForm((f) => (f ? { ...f, [k]: v } : f));
  const dirty = !!form && !!data && JSON.stringify(form) !== JSON.stringify(data.settings.watch);

  const save = async (e: FormEvent) => {
    e.preventDefault();
    if (!form || !data) return;
    setSaving(true);
    setError(null);
    try {
      // Keep the analysis and ingest options: omitted sections would be reset to their defaults.
      const r = await track(api.saveServerSettings(withSection(data, { watch: form })));
      setData(r);
      setForm(r.settings.watch);
      notify(form.enabled ? `Watching ${r.watch_dir_resolved}.` : "Watch folder disabled.");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="view-page">
      <header className="view-head">
        <div>
          <h1>Server settings</h1>
          <p className="muted">
            Analysis options, how multiple dumps are merged, and automatic ingest from a watch folder: drop collector output (.json / .zip, LDIF or AD
            Explorer snapshots) there, for example from a scheduled SharpHound task, and CopperHound imports it and rebuilds
            the graph.
          </p>
        </div>
      </header>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {!form && !error && <p className="muted">Loading settings…</p>}
      {form && data && (
        <div className="data-grid">
          <form className="card form-stack" onSubmit={(e) => void save(e)}>
            <h2>Watch folder</h2>
            <label className="toggle">
              <input type="checkbox" checked={form.enabled} onChange={(e) => set("enabled", e.target.checked)} />
              Import files dropped into the watch folder
            </label>
            <label>
              Folder
              <input value={form.dir} onChange={(e) => set("dir", e.target.value)} placeholder={data.watch_dir_resolved} spellCheck={false} />
              <span className="muted small-text">
                Leave empty for <code>&lt;data&gt;/watch</code>. It must not be the data, uploads or graphs directory.
              </span>
            </label>
            <fieldset className="role-choice">
              <legend>Mode</legend>
              <label className="check role-option">
                <input type="radio" name="mode" checked={form.mode === "replace"} onChange={() => set("mode", "replace")} />
                <strong>Replace</strong>
                <span className="muted small-text">
                  New files replace all current uploads, so the graph shows only the latest collection. Use this for scheduled
                  full collections.
                </span>
              </label>
              <label className="check role-option">
                <input type="radio" name="mode" checked={form.mode === "merge"} onChange={() => set("mode", "merge")} />
                <strong>Merge</strong>
                <span className="muted small-text">
                  New files are added next to existing uploads (a file with the same name is replaced). Use this when
                  different collectors or domains drop files separately; the ingest merge policy decides which data wins.
                </span>
              </label>
            </fieldset>
            <div className="form-grid">
              <label htmlFor="settle">Settle time (s)</label>
              <NumberField id="settle" min={5} max={86400} value={form.settle_seconds} onCommit={(v) => set("settle_seconds", Math.round(v))} />
            </div>
            <span className="muted small-text">
              A file is imported only after its size has not changed for this long, so half-copied zips are never read.
            </span>
            <label className="toggle">
              <input type="checkbox" checked={form.archive} onChange={(e) => set("archive", e.target.checked)} />
              Archive replaced uploads instead of deleting them
            </label>
            <div className="form-grid">
              <label htmlFor="keep">Archives to keep</label>
              <NumberField id="keep" min={1} max={100} value={form.keep_archives} onCommit={(v) => set("keep_archives", Math.round(v))} />
            </div>
            <p className="notice">
              <span>
                Imported files are <strong>moved out</strong> of the watch folder into the uploads directory, so the folder
                empties itself. Other file types are left alone.
              </span>
            </p>
            <div className="row gap">
              <button type="submit" className="primary" disabled={saving || !dirty}>
                {saving ? "Saving…" : "Save settings"}
              </button>
              {dirty && (
                <button type="button" onClick={() => setForm(data.settings.watch)}>
                  Discard changes
                </button>
              )}
            </div>
          </form>
          <div className="form-stack">
            <AnalysisPanel data={data} onSaved={setData} />
            <IngestPanel data={data} onSaved={setData} />
            <WatchStatusPanel data={data} />
            <BackupPanel />
            <KindStylesPanel />
          </div>
        </div>
      )}
    </div>
  );
}
