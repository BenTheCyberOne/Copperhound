import { useCallback, useEffect, useRef, useState, type DragEvent } from "react";
import { api, errorMessage } from "../api/client";
import type { Job, Source, SourcesResponse, Stats, UploadInfo } from "../api/types";
import { useApp } from "../state/AppContext";
import { useCatalog } from "../state/CatalogContext";
import { when } from "../util/format";
import { ReadOnlyNote, useSession } from "../state/SessionContext";
import { DatabaseManagement } from "./DatabaseManagement";
import { DataQuality } from "./DataQuality";
import { MergeHelp } from "../components/MergeHelp";
import { collectedSourceLabel, MERGE_POLICY_HELP, sourceWarnings } from "../util/sources";
import { SourcesSection } from "./SourcesSection";

const fmt = new Intl.NumberFormat();
/** Fallback when /health has no limits (older servers). */
const DEFAULT_EXTENSIONS = [".json", ".zip", ".ldif", ".ldf", ".ldif.gz", ".dat"];

/**
 * The file picker matches `accept` against the last extension only, so ".ldif.gz" also
 * needs ".gz" there; the full name is still checked before uploading.
 */
function acceptAttr(extensions: string[]): string {
  const last = extensions.map((e) => `.${e.split(".").pop()}`);
  return [...new Set([...extensions, ...last])].join(",");
}

function humanSize(bytes: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

const TRIGGER_TITLE: Record<NonNullable<Job["trigger"]>, string> = {
  manual: "Started from the UI (Rebuild graph)",
  watch: "Started by the watch folder",
  api: "Started through the API with a token",
};

const isActive = (j: Job) => j.state === "queued" || j.state === "running";

function topEntries(m: Record<string, number>, n: number): [string, number][] {
  return Object.entries(m)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n);
}

/** Which sources an upload produced (one per zip entry), collapsed by default. */
function UploadSources({ upload, all }: { upload: UploadInfo; all: Source[] }) {
  const srcs = upload.sources ?? [];
  if (srcs.length === 0) return null;
  const warned = srcs.filter((s) => sourceWarnings(s, all).length > 0).length;
  const dates = [...new Set(srcs.map((s) => (s.collected_at ? when(s.collected_at) : "undated")))];
  return (
    <details className="upload-sources">
      <summary>
        {srcs.length} source{srcs.length === 1 ? "" : "s"} · {dates.length === 1 ? dates[0] : `${dates.length} collection times`}
        {warned > 0 && <span className="warn-text"> · ⚠ {warned} without a reliable time</span>}
      </summary>
      <ul>
        {srcs.map((s) => (
          <li key={s.id}>
            <span className="muted num">#{s.id}</span> {s.entry ?? s.format}
            {s.kind && <span className="muted"> · {s.kind}</span>} ·{" "}
            {s.collected_at ? (
              <>
                {when(s.collected_at)} <span className="muted">({collectedSourceLabel(s.collected_at_source)})</span>
              </>
            ) : (
              <span className="warn-text" title="Merged as union: prefix the file name with YYYYMMDDHHMMSS_ to order it.">
                undated
              </span>
            )}{" "}
            · {fmt.format(s.objects)} objects
            {s.superseded_objects > 0 && <span className="muted"> ({fmt.format(s.superseded_objects)} superseded)</span>}
          </li>
        ))}
      </ul>
    </details>
  );
}

function StatsSummary({ stats }: { stats: Stats }) {
  return (
    <>
      <div className="stat-grid">
        <div className="stat">
          <span className="stat-value">{fmt.format(stats.nodes)}</span>
          <span className="stat-label">nodes</span>
        </div>
        <div className="stat">
          <span className="stat-value">{fmt.format(stats.edges)}</span>
          <span className="stat-label">edges</span>
        </div>
        <div className="stat">
          <span className="stat-value">{fmt.format(stats.tier0)}</span>
          <span className="stat-label">Tier Zero</span>
        </div>
        <div className="stat">
          <span className="stat-value">{fmt.format(stats.owned)}</span>
          <span className="stat-label">owned</span>
        </div>
      </div>
      <p className="muted small-text">
        Graph loaded: {stats.loaded_at ? when(stats.loaded_at) : "no graph loaded yet"}
        {stats.snapshot_id && <> · snapshot <code>{stats.snapshot_id}</code></>} · generation {stats.generation}
      </p>
      {stats.nodes > 0 && (
        <div className="two-col">
          <table className="data-table compact">
            <thead>
              <tr>
                <th>Node kind</th>
                <th className="num">Count</th>
              </tr>
            </thead>
            <tbody>
              {topEntries(stats.node_kinds, 12).map(([k, v]) => (
                <tr key={k}>
                  <td>{k}</td>
                  <td className="num">{fmt.format(v)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <table className="data-table compact">
            <thead>
              <tr>
                <th>Edge kind</th>
                <th className="num">Count</th>
              </tr>
            </thead>
            <tbody>
              {topEntries(stats.edge_kinds, 12).map(([k, v]) => (
                <tr key={k}>
                  <td>{k}</td>
                  <td className="num">{fmt.format(v)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

export function DataView() {
  const { track, notify } = useApp();
  const { health, refreshHealth } = useCatalog();
  const modify = useSession().gate("analyst");
  const isAdmin = useSession().atLeast("admin");
  const extensions = health?.limits.upload_extensions ?? DEFAULT_EXTENSIONS;
  const maxBytes = health?.limits.max_upload_bytes ?? null;
  const [stats, setStats] = useState<Stats | null>(null);
  const [uploads, setUploads] = useState<UploadInfo[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  // undefined = not loaded yet; null = the server has no /sources (before v1.5).
  const [sources, setSources] = useState<SourcesResponse | null | undefined>(undefined);
  const [progress, setProgress] = useState<number | null>(null);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const refresh = useCallback(async () => {
    try {
      const [s, u, j, src] = await track(
        Promise.all([api.stats(), api.uploads(), api.jobs(), api.sources().catch(() => null)]),
      );
      setStats(s);
      setUploads(u);
      setJobs(j);
      setSources(src);
      setError(null);
    } catch (e) {
      setError(errorMessage(e));
    }
  }, [track]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Poll every running job every 2 s until it finishes.
  const activeIds = jobs.filter(isActive).map((j) => j.id);
  const activeKey = activeIds.join(",");
  useEffect(() => {
    if (!activeKey) return;
    const ids = activeKey.split(",");
    const timer = window.setInterval(() => {
      void Promise.all(ids.map((id) => api.job(id)))
        .then((fresh) => {
          setJobs((js) => js.map((j) => fresh.find((f) => f.id === j.id) ?? j));
          for (const f of fresh) {
            if (f.state === "done") {
              notify(`Ingest ${f.id} finished: ${f.message ?? "done"}.`);
              void api.stats().then(setStats, () => undefined);
              void api.sources().then(setSources, () => setSources(null));
              void api.uploads().then(setUploads, () => undefined);
              // Picks up the new generation right away (stale-canvas banner, kind lists).
              refreshHealth();
            } else if (f.state === "failed") {
              notify(`Ingest ${f.id} failed: ${f.message ?? "unknown error"}`, "error");
            }
          }
        })
        .catch((e: unknown) => setError(errorMessage(e)));
    }, 2000);
    return () => window.clearInterval(timer);
  }, [activeKey, notify, refreshHealth]);

  const upload = async (list: FileList | File[]) => {
    const files = [...list];
    // Validate against the server's limits before sending anything.
    const badType = files.filter((f) => !extensions.some((ext) => f.name.toLowerCase().endsWith(ext.toLowerCase())));
    const tooBig = maxBytes === null ? [] : files.filter((f) => f.size > maxBytes);
    const ok = files.filter((f) => !badType.includes(f) && !tooBig.includes(f));
    if (badType.length > 0) {
      notify(`Skipped ${badType.map((f) => f.name).join(", ")}: accepted types are ${extensions.join(", ")}.`, "warn");
    }
    if (tooBig.length > 0 && maxBytes !== null) {
      notify(`Skipped ${tooBig.map((f) => f.name).join(", ")}: larger than the ${humanSize(maxBytes)} limit.`, "warn");
    }
    if (ok.length === 0) return;
    setProgress(0);
    try {
      const res = await api.upload(ok, setProgress);
      notify(`Uploaded ${res.uploaded.length} file${res.uploaded.length === 1 ? "" : "s"}. Rebuild the graph to load them.`);
      setUploads(await api.uploads());
    } catch (e) {
      notify(errorMessage(e), "error");
    } finally {
      setProgress(null);
      if (fileInput.current) fileInput.current.value = "";
    }
  };

  const remove = async (name: string) => {
    if (!window.confirm(`Delete upload ${name}?`)) return;
    try {
      await track(api.deleteUpload(name));
      setUploads((u) => u.filter((x) => x.name !== name));
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  const ingest = async () => {
    try {
      const { job_id } = await track(api.ingest());
      notify(`Ingest job ${job_id} started.`);
      setJobs(await api.jobs());
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    if (modify.disabled) {
      notify(modify.title ?? "Uploading requires the analyst role", "warn");
      return;
    }
    if (progress === null && e.dataTransfer.files.length > 0) void upload(e.dataTransfer.files);
  };

  return (
    <div className="view-page">
      <header className="view-head">
        <div>
          <h1>Data</h1>
          <p className="muted">Collector uploads, graph rebuilds and what is loaded right now.</p>
        </div>
        <button type="button" onClick={() => void refresh()}>
          Refresh
        </button>
      </header>
      {error && <p className="error">{error}</p>}
      <ReadOnlyNote need="analyst" what="uploading, deleting uploads and rebuilding the graph" />
      <div className="data-grid">
      <section className="card">
        <div className="section-head">
          <h2>Loaded graph</h2>
          <MergeHelp />
        </div>
        {stats ? <StatsSummary stats={stats} /> : !error && <p className="muted">Loading…</p>}
      </section>
      <section className="card">
      <h2>Upload collector data</h2>
      <div
        className={`dropzone ${dragging ? "over" : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
      >
        {progress === null ? (
          <>
            <p>Drop {extensions.join(" / ")} files here</p>
            <p className="muted small-text upload-help">
              SharpHound / AzureHound JSON or zip, LDIF exports (<code>ldapsearch</code>, <code>ldifde</code>; also gzipped) and
              Sysinternals AD Explorer snapshots (<code>.dat</code>), plus OpenGraph JSON for custom node and edge kinds from any other
              system.
            </p>
            {maxBytes !== null && <p className="muted small-text">Up to {humanSize(maxBytes)} per file</p>}
            <button type="button" onClick={() => fileInput.current?.click()} {...modify}>
              Choose files…
            </button>
          </>
        ) : (
          <div className="progress" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(progress * 100)}>
            <div className="progress-fill" style={{ width: `${progress * 100}%` }} />
            <span className="progress-text">Uploading… {Math.round(progress * 100)}%</span>
          </div>
        )}
        <input
          ref={fileInput}
          type="file"
          accept={acceptAttr(extensions)}
          multiple
          hidden
          onChange={(e) => e.target.files && void upload(e.target.files)}
        />
      </div>

      <div className="section-head">
        <h3>
          Uploads <span className="muted num">{uploads.length}</span>
        </h3>
        <button type="button" className="primary small" onClick={() => void ingest()} disabled={uploads.length === 0 || activeIds.length > 0 || modify.disabled} title={modify.title}>
          Rebuild graph
        </button>
      </div>
      {uploads.length === 0 ? (
        <p className="muted small-text">No uploads yet.</p>
      ) : (
        <ul className="upload-list">
          {uploads.map((u) => (
            <li key={u.name}>
              <span className="ellipsis" title={u.name}>
                {u.name}
              </span>
              <span className="muted num">{humanSize(u.size)}</span>
              <span className="muted small-text">
                {when(u.uploaded_at)}{" "}
                {u.in_graph !== undefined &&
                  (u.in_graph ? (
                    <span className="tag ok small-tag" title="This file is part of the loaded graph">
                      in graph
                    </span>
                  ) : (
                    <span className="tag small-tag" title="Not part of the loaded graph yet: rebuild the graph to load it">
                      not loaded
                    </span>
                  ))}
              </span>
              <button type="button" className="icon-btn danger" aria-label={`Delete ${u.name}`} onClick={() => void remove(u.name)} {...modify}>
                ×
              </button>
              <UploadSources upload={u} all={sources?.sources ?? []} />
            </li>
          ))}
        </ul>
      )}

      <h3>Jobs</h3>
      {jobs.length === 0 ? (
        <p className="muted small-text">No ingest jobs yet.</p>
      ) : (
        <ul className="job-list">
          {jobs.map((j) => (
            <li key={j.id} className={`job ${j.state}`}>
              <div className="job-head">
                <strong>{j.id}</strong>
                <span className={`tag state-${j.state}`}>{j.state}</span>
                {j.trigger && (
                  <span className={`tag trigger-${j.trigger}`} title={TRIGGER_TITLE[j.trigger]}>
                    {j.trigger}
                  </span>
                )}
                <span className="muted small-text">{when(j.created_at)}</span>
              </div>
              {isActive(j) && (
                <div
                  className="progress small"
                  role="progressbar"
                  aria-label={`Job ${j.id} progress`}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={j.percent ?? 0}
                >
                  <div className="progress-fill" style={{ width: `${j.percent ?? 0}%` }} />
                  <span className="progress-text">
                    {j.phase ?? j.state} · {Math.round(j.percent ?? 0)}%
                  </span>
                </div>
              )}
              {j.message && !isActive(j) && <div className="small-text">{j.message}</div>}
              {j.report && (
                <dl className="job-report">
                  <dt>files</dt>
                  <dd>{fmt.format(j.report.files)}</dd>
                  <dt>records</dt>
                  <dd>{fmt.format(j.report.records)}</dd>
                  <dt>nodes</dt>
                  <dd>{fmt.format(j.report.nodes)}</dd>
                  <dt>edges</dt>
                  <dd>{fmt.format(j.report.edges)}</dd>
                  <dt>parse errors</dt>
                  <dd className={j.report.parse_errors > 0 ? "warn-text" : ""}>{fmt.format(j.report.parse_errors)}</dd>
                  <dt>time</dt>
                  <dd>{j.report.seconds.toFixed(1)} s</dd>
                  {j.report.merge_policy && (
                    <>
                      <dt>merge</dt>
                      <dd title={MERGE_POLICY_HELP[j.report.merge_policy]}>{j.report.merge_policy}</dd>
                    </>
                  )}
                  {j.report.sources !== undefined && (
                    <>
                      <dt>sources</dt>
                      <dd>{fmt.format(j.report.sources)}</dd>
                    </>
                  )}
                  {j.report.superseded_objects !== undefined && (
                    <>
                      <dt title="Object records overridden by a newer collection">superseded objects</dt>
                      <dd>{fmt.format(j.report.superseded_objects)}</dd>
                    </>
                  )}
                  {j.report.superseded_edges !== undefined && (
                    <>
                      <dt title="Edge records dropped because a newer record of their owner claims that relationship type">superseded edges</dt>
                      <dd>{fmt.format(j.report.superseded_edges)}</dd>
                    </>
                  )}
                </dl>
              )}
            </li>
          ))}
        </ul>
      )}
      </section>
      <DataQuality generation={health?.generation ?? null} />
      {sources !== undefined && <SourcesSection data={sources} />}
      {isAdmin && <DatabaseManagement onCleared={() => void refresh()} />}
      </div>
    </div>
  );
}
