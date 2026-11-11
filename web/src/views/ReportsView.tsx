import { useState } from "react";
import { ApiError, ComputingError, api, errorMessage } from "../api/client";
import type { ReportFormat } from "../api/types";
import { EnvironmentSelect } from "../components/EnvironmentSelect";
import { NumberField } from "../components/NumberField";
import { useEnvironment } from "../hooks/useEnvironment";
import { useCatalog } from "../state/CatalogContext";

type Action = { format: ReportFormat; download: boolean };

function saveBlob(blob: Blob, filename: string): void {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  window.setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

/**
 * Assessment report export. The endpoint needs the bearer header, so the file is
 * fetched as a blob and opened / saved locally instead of linking to it directly.
 */
export function ReportsView() {
  const { generation } = useCatalog();
  const [env, setEnv, envs] = useEnvironment(generation);
  const [title, setTitle] = useState("Attack path assessment");
  const [planSteps, setPlanSteps] = useState(10);
  const [items, setItems] = useState(25);
  const [busy, setBusy] = useState<string | null>(null);
  const [status, setStatus] = useState<{ text: string; kind: "error" | "info" } | null>(null);

  const run = async ({ format, download }: Action) => {
    // Open the tab synchronously (inside the click) so popup blockers allow it.
    const win = download ? null : window.open("", "_blank");
    if (win) {
      win.document.write("<p style='font:14px system-ui;padding:24px'>Generating report…</p>");
      win.document.close();
    }
    setBusy(`${format}-${download}`);
    setStatus(null);
    try {
      const { blob, filename } = await api.report({ format, title, plan_steps: planSteps, items, download, env });
      if (download) {
        saveBlob(blob, filename.endsWith(`.${format}`) ? filename : `copperhound-report.${format}`);
        setStatus({ text: `Saved ${filename}.`, kind: "info" });
      } else {
        const url = URL.createObjectURL(new Blob([blob], { type: "text/html" }));
        if (win) win.location.href = url;
        else window.open(url, "_blank");
        // Keep the URL alive long enough for the tab (and its print preview) to load it.
        window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
        setStatus({ text: "Report opened in a new tab.", kind: "info" });
      }
    } catch (e) {
      win?.close();
      if (e instanceof ComputingError) {
        setStatus({ text: `The analysis for the current graph is still running (${Math.round(e.progress)}%). Try again in a moment.`, kind: "info" });
      } else if (e instanceof ApiError && e.status === 409) {
        setStatus({ text: "No graph is loaded yet. Upload data and rebuild the graph first.", kind: "error" });
      } else {
        setStatus({ text: errorMessage(e), kind: "error" });
      }
    } finally {
      setBusy(null);
    }
  };

  const button = (label: string, a: Action, primary = false) => (
    <button type="button" className={primary ? "primary" : ""} disabled={busy !== null} onClick={() => void run(a)}>
      {busy === `${a.format}-${a.download}` ? "Generating…" : label}
    </button>
  );

  return (
    <div className="view-page">
      <header className="view-head">
        <div>
          <h1>Reports</h1>
          <p className="muted">
            A self-contained assessment of the current snapshot: Tier Zero exposure, every finding with sample items, the
            remediation plan and the posture trend.
          </p>
        </div>
      </header>
      <div className="data-grid">
        <section className="card form-stack">
          <h2>Report options</h2>
          {envs.length > 1 && (
            <label>
              Scope
              <EnvironmentSelect value={env} onChange={setEnv} list={envs} />
            </label>
          )}
          <label>
            Title
            <input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} />
          </label>
          <div className="form-grid">
            <label htmlFor="rep-steps">Remediation plan steps</label>
            <NumberField id="rep-steps" min={0} max={50} value={planSteps} onCommit={(v) => setPlanSteps(Math.round(v))} />
            <label htmlFor="rep-items">Items listed per finding</label>
            <NumberField id="rep-items" min={1} max={10000} value={items} onCommit={(v) => setItems(Math.round(v))} />
          </div>
          <p className="muted small-text">0 plan steps leaves the plan out. The CSV export lists finding items only.</p>
          <div className="row gap wrap">
            {button("Open HTML report", { format: "html", download: false }, true)}
            {button("Download HTML", { format: "html", download: true })}
            {button("Download Markdown", { format: "md", download: true })}
            {button("Download CSV", { format: "csv", download: true })}
          </div>
          {status && (
            <p className={status.kind === "error" ? "error" : "muted"} role={status.kind === "error" ? "alert" : "status"}>
              {status.text}
            </p>
          )}
        </section>
        <section className="card">
          <h2>Need a PDF?</h2>
          <p>
            Open the HTML report, then use your browser&apos;s <strong>Print → Save as PDF</strong>. The report has print styles,
            so pages break cleanly and the colours carry over.
          </p>
          <p className="muted small-text">
            The HTML file has no scripts and loads nothing from the network, so it is safe to email or attach to a ticket.
            Markdown suits wikis and pull requests; CSV suits spreadsheets and ticket imports.
          </p>
        </section>
      </div>
    </div>
  );
}
