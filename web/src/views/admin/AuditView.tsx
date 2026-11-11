import { useEffect, useState } from "react";
import { api, errorMessage } from "../../api/client";
import type { AuditEntry } from "../../api/types";
import { EmptyState } from "../../components/StatusView";
import { useDebounced } from "../../hooks/useDebounced";
import { downloadCsv } from "../../util/csv";

const REFRESH_MS = 5000;
const ACTIONS = [
  { value: "", label: "All actions" },
  { value: "login", label: "Sign-ins (incl. failed, locked)" },
  { value: "login-failed", label: "Failed sign-ins" },
  { value: "login-locked", label: "Lockouts" },
  { value: "denied", label: "Denied (role too low)" },
  { value: "POST", label: "POST (creates, runs)" },
  { value: "PUT", label: "PUT (updates)" },
  { value: "DELETE", label: "DELETE" },
];

function statusClass(e: AuditEntry): string {
  if (e.status === 401 || e.status === 403 || e.status === 429 || e.status >= 500) return "audit-bad";
  if (e.status >= 400) return "audit-warn";
  return "audit-ok";
}

export function AuditView() {
  const [user, setUser] = useState("");
  const [action, setAction] = useState("");
  const [custom, setCustom] = useState("");
  const [limit, setLimit] = useState(200);
  const [auto, setAuto] = useState(false);
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  const u = useDebounced(user.trim(), 300);
  const a = useDebounced((custom.trim() || action).trim(), 300);

  useEffect(() => {
    let live = true;
    api.audit({ limit, user: u || undefined, action: a || undefined }).then(
      (r) => {
        if (!live) return;
        setEntries(r.entries);
        setError(null);
      },
      (e: unknown) => live && setError(errorMessage(e)),
    );
    return () => {
      live = false;
    };
  }, [u, a, limit, nonce]);

  useEffect(() => {
    if (!auto) return;
    const t = window.setInterval(() => setNonce((n) => n + 1), REFRESH_MS);
    return () => window.clearInterval(t);
  }, [auto]);

  return (
    <div className="view-page">
      <header className="view-head">
        <div>
          <h1>Audit log</h1>
          <p className="muted">Sign-ins, denied requests and every change or analysis request, newest first.</p>
        </div>
        <div className="head-actions">
          <label className="toggle">
            <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
            Auto-refresh ({REFRESH_MS / 1000} s)
          </label>
          <button type="button" onClick={() => setNonce((n) => n + 1)}>
            Refresh
          </button>
          <button
            type="button"
            disabled={!entries?.length}
            onClick={() =>
              entries &&
              downloadCsv(
                "copperhound-audit.csv",
                ["ts", "user", "role", "action", "method", "path", "status", "ip", "detail"],
                entries.map((e) => [e.ts, e.user, e.role, e.action, e.method, e.path, e.status, e.ip ?? "", e.detail ?? ""]),
              )
            }
          >
            Export CSV
          </button>
        </div>
      </header>
      <div className="filter-bar">
        <input type="search" placeholder="User (exact)" aria-label="Filter by user" value={user} onChange={(e) => setUser(e.target.value)} />
        <select aria-label="Action" value={action} onChange={(e) => setAction(e.target.value)}>
          {ACTIONS.map((x) => (
            <option key={x.value} value={x.value}>
              {x.label}
            </option>
          ))}
        </select>
        <input
          type="search"
          placeholder="…or action prefix, e.g. POST /zones"
          aria-label="Action prefix"
          value={custom}
          onChange={(e) => setCustom(e.target.value)}
        />
        <select aria-label="Number of entries" value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
          {[100, 200, 500, 1000, 5000].map((n) => (
            <option key={n} value={n}>
              last {n}
            </option>
          ))}
        </select>
        {entries && <span className="muted small-text">{entries.length} entries</span>}
      </div>
      {error && <p className="error">{error}</p>}
      {entries && entries.length === 0 && <EmptyState title="No matching audit entries" />}
      {entries && entries.length > 0 && (
        <div className="table-card">
          <table className="data-table audit-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>User</th>
                <th>Action</th>
                <th>Path</th>
                <th className="num">Status</th>
                <th>Client</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e, i) => (
                <tr key={`${e.ts}-${i}`} className={statusClass(e)}>
                  <td className="nowrap">{new Date(e.ts).toLocaleString()}</td>
                  <td className="nowrap">
                    <button type="button" className="link-btn" onClick={() => setUser(e.user)} title="Filter by this user">
                      {e.user}
                    </button>
                    {e.role && <span className="muted small-text"> {e.role}</span>}
                  </td>
                  <td>
                    <code>{e.action}</code>
                  </td>
                  <td className="audit-path">
                    <code>{e.path}</code>
                  </td>
                  <td className="num">
                    <span className="status-pill">{e.status}</span>
                  </td>
                  <td className="nowrap muted">{e.ip ?? ""}</td>
                  <td className="small-text">{e.detail ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
