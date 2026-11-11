// The whole app for upload-only accounts: upload collector files, start an
// ingest and follow the jobs. Such accounts cannot read the graph.

import { useCallback, useEffect, useRef, useState } from "react";
import { api, errorMessage } from "../api/client";
import type { ApiTokenInfo, Job, UploadInfo } from "../api/types";
import { Logo } from "../components/Logo";

const EXTENSIONS = ".json,.zip,.ldif,.ldf,.gz,.dat";

function humanSize(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

/** API tokens of this account, for collectors that upload unattended. */
function TokensCard() {
  const [tokens, setTokens] = useState<ApiTokenInfo[]>([]);
  const [name, setName] = useState("collector");
  const [created, setCreated] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => {
    api.myTokens().then((r) => setTokens(r.tokens), () => undefined);
  }, []);
  useEffect(load, [load]);
  return (
    <section className="card form-stack">
      <h2>API tokens</h2>
      {created && (
        <p className="notice warn">
          <span>
            New token (shown once): <code className="break">{created}</code>
          </span>
        </p>
      )}
      {tokens.length > 0 && (
        <ul className="plain-list">
          {tokens.map((t) => (
            <li key={t.id} className="row gap">
              <code>{t.prefix}…</code> {t.name} <span className="muted small-text">{t.last_used ? `last used ${t.last_used}` : "never used"}</span>
              <button
                type="button"
                className="link-btn"
                onClick={() => {
                  api.deleteToken(t.id).then(load, (e: unknown) => setError(errorMessage(e)));
                }}
              >
                revoke
              </button>
            </li>
          ))}
        </ul>
      )}
      <form
        className="row gap"
        onSubmit={(e) => {
          e.preventDefault();
          setError(null);
          api.createToken(name.trim() || "collector").then(
            (t) => {
              setCreated(t.token);
              load();
            },
            (err: unknown) => setError(errorMessage(err)),
          );
        }}
      >
        <input aria-label="Token name" value={name} maxLength={64} onChange={(e) => setName(e.target.value)} />
        <button type="submit">Create token</button>
      </form>
      {error && <p className="error">{error}</p>}
    </section>
  );
}

export function UploadOnlyView({ username, onLogout }: { username: string; onLogout: () => void }) {
  const [uploads, setUploads] = useState<UploadInfo[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [progress, setProgress] = useState<number | null>(null);
  const [message, setMessage] = useState<{ text: string; error?: boolean } | null>(null);
  const input = useRef<HTMLInputElement>(null);

  const refresh = useCallback(() => {
    api.uploads().then(setUploads, () => undefined);
    api.jobs().then(setJobs, () => undefined);
  }, []);
  useEffect(() => {
    refresh();
    const t = window.setInterval(refresh, 3000);
    return () => window.clearInterval(t);
  }, [refresh]);

  const send = async (files: File[]) => {
    if (files.length === 0) return;
    setMessage(null);
    setProgress(0);
    try {
      const r = await api.upload(files, setProgress);
      setMessage({ text: `Uploaded ${r.uploaded.length} file${r.uploaded.length === 1 ? "" : "s"}.` });
      refresh();
    } catch (e) {
      setMessage({ text: errorMessage(e), error: true });
    } finally {
      setProgress(null);
    }
  };

  const ingest = async () => {
    try {
      const r = await api.ingest();
      setMessage({ text: `Ingest started (job ${r.job_id}).` });
      refresh();
    } catch (e) {
      setMessage({ text: errorMessage(e), error: true });
    }
  };

  return (
    <main className="upload-only">
      <header className="upload-only-head">
        <Logo size={32} />
        <h1>CopperHound uploads</h1>
        <span className="muted small-text">
          Signed in as <strong>{username}</strong> (upload-only)
        </span>
        <button type="button" onClick={onLogout}>
          Sign out
        </button>
      </header>
      <section className="card form-stack">
        <p className="muted small-text">
          This account can upload collector output (SharpHound / AzureHound JSON or zip, LDIF, AD Explorer snapshots, OpenGraph JSON)
          and start an ingest. Analysts and administrators see the results. Collectors can post with an API token (below):{" "}
          <code>curl -H "Authorization: Bearer cht_…" -F files=@data.zip {window.location.origin}/api/v1/upload</code>.
        </p>
        <div
          className="drop-zone"
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault();
            void send([...e.dataTransfer.files]);
          }}
        >
          {progress === null ? (
            <>
              <p>Drop files here</p>
              <button type="button" className="primary" onClick={() => input.current?.click()}>
                Choose files…
              </button>
            </>
          ) : (
            <p>Uploading… {Math.round(progress * 100)}%</p>
          )}
          <input
            ref={input}
            type="file"
            multiple
            hidden
            accept={EXTENSIONS}
            onChange={(e) => {
              void send([...(e.target.files ?? [])]);
              e.target.value = "";
            }}
          />
        </div>
        {message && <p className={message.error ? "error" : "muted"}>{message.text}</p>}
        <div className="row gap">
          <button type="button" onClick={() => void ingest()} disabled={uploads.length === 0}>
            Start ingest
          </button>
        </div>
      </section>
      <section className="card">
        <h2>Uploaded files</h2>
        {uploads.length === 0 ? (
          <p className="muted">No uploads yet.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>File</th>
                <th className="num">Size</th>
                <th>Uploaded</th>
              </tr>
            </thead>
            <tbody>
              {uploads.map((u) => (
                <tr key={u.name}>
                  <td>{u.name}</td>
                  <td className="num">{humanSize(u.size)}</td>
                  <td>{u.uploaded_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      <TokensCard />
      <section className="card">
        <h2>Ingest jobs</h2>
        {jobs.length === 0 ? (
          <p className="muted">No jobs yet.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Job</th>
                <th>State</th>
                <th>Started</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((j) => (
                <tr key={j.id}>
                  <td className="mono">{j.id}</td>
                  <td>
                    <span className={`tag ${j.state === "done" ? "ok" : j.state === "failed" ? "off" : ""}`}>{j.state}</span>
                  </td>
                  <td>{j.started_at ?? j.created_at}</td>
                  <td>{j.message ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </main>
  );
}
