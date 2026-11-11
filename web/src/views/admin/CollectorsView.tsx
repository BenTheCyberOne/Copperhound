// Admin → Collectors: registered collection clients with check-in status and
// generated collection / upload commands.

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, errorMessage } from "../../api/client";
import type { CollectorInfo, CollectorKind, NewCollectorResponse } from "../../api/types";
import { Modal } from "../../components/Modal";
import { EmptyState } from "../../components/StatusView";
import { useApp } from "../../state/AppContext";
import { LdapTargets } from "./LdapTargets";

const KINDS: { id: CollectorKind; label: string }[] = [
  { id: "sharphound", label: "SharpHound (Windows)" },
  { id: "azurehound", label: "AzureHound" },
  { id: "bloodhound-python", label: "bloodhound-python (Linux)" },
  { id: "ldap", label: "ldapsearch (LDIF)" },
];

const STATUS: Record<CollectorInfo["status"], { cls: string; text: string }> = {
  ok: { cls: "ok", text: "reporting" },
  stale: { cls: "warn", text: "stale" },
  never: { cls: "off", text: "never uploaded" },
};

function Created({ r, onClose }: { r: NewCollectorResponse; onClose: () => void }) {
  return (
    <Modal title={`Collector ${r.collector.name} registered`} onClose={onClose} wide>
      <div className="form-stack">
        <p className="notice warn">
          <span>
            Upload token (shown once): <code className="break">{r.token}</code>
          </span>
        </p>
        <p className="muted small-text">
          It belongs to the upload-only account <code>{r.collector.username}</code>: it can upload files and start an ingest, nothing
          else. Save the script below as <code>{r.commands.script_name}</code> next to the collector and schedule it.
        </p>
        {r.bloodhound_key && r.token_id && (
          <p className="muted small-text">
            BloodHound-compatible tools: token ID <code>{r.token_id}</code>, key <code className="break">{r.bloodhound_key}</code>.
          </p>
        )}
        <span className="field-title">{r.commands.script_name}</span>
        <pre className="code-block">{r.commands.script}</pre>
        <span className="field-title">Schedule</span>
        <pre className="code-block">{r.commands.schedule}</pre>
        <div className="row gap">
          <button type="button" className="primary" onClick={onClose}>
            Done
          </button>
        </div>
      </div>
    </Modal>
  );
}

export function CollectorsView() {
  const { notify, track } = useApp();
  const [list, setList] = useState<CollectorInfo[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<CollectorKind>("sharphound");
  const [hours, setHours] = useState(24);
  const [created, setCreated] = useState<NewCollectorResponse | null>(null);

  const load = useCallback(() => {
    api.collectors().then(setList, (e: unknown) => setError(errorMessage(e)));
  }, []);
  useEffect(() => {
    load();
    const t = window.setInterval(load, 30_000);
    return () => window.clearInterval(t);
  }, [load]);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const r = await track(api.createCollector(name.trim(), kind, hours));
      setCreated(r);
      setName("");
      load();
    } catch (err) {
      setError(errorMessage(err));
    }
  };

  const remove = async (c: CollectorInfo) => {
    if (!window.confirm(`Remove collector ${c.name}? Its account ${c.username} and token are deleted.`)) return;
    try {
      await track(api.deleteCollector(c.id));
      notify(`Collector ${c.name} removed.`);
      load();
    } catch (err) {
      notify(errorMessage(err), "error");
    }
  };

  return (
    <div className="view-page">
      <header className="view-head">
        <div>
          <h1>Collectors</h1>
          <p className="muted">
            Scheduled collection jobs that upload to CopperHound. Each gets its own upload-only account and token; a collector is
            stale when it has not uploaded within twice its interval.
          </p>
        </div>
      </header>
      <form className="card row gap wrap" onSubmit={(e) => void create(e)}>
        <input aria-label="Collector name" placeholder="Name, e.g. corp.local DC01" value={name} maxLength={64} onChange={(e) => setName(e.target.value)} required />
        <select aria-label="Collector type" value={kind} onChange={(e) => setKind(e.target.value as CollectorKind)}>
          {KINDS.map((k) => (
            <option key={k.id} value={k.id}>
              {k.label}
            </option>
          ))}
        </select>
        <label className="row gap">
          every
          <input type="number" min={1} max={744} value={hours} onChange={(e) => setHours(Number(e.target.value) || 24)} style={{ width: 80 }} />
          hours
        </label>
        <button type="submit" className="primary" disabled={!name.trim()}>
          Register collector
        </button>
      </form>
      {error && <p className="error">{error}</p>}
      {list === null ? (
        <p className="muted">Loading…</p>
      ) : list.length === 0 ? (
        <EmptyState title="No collectors yet">Register one to get a token and ready-to-schedule commands.</EmptyState>
      ) : (
        <div className="table-card">
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Status</th>
                <th>Last upload</th>
                <th className="num">Uploads</th>
                <th>Account</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.map((c) => (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td>{KINDS.find((k) => k.id === c.kind)?.label ?? c.kind}</td>
                  <td>
                    <span className={`tag ${STATUS[c.status].cls}`}>{STATUS[c.status].text}</span>
                    <span className="muted small-text"> every {c.interval_hours} h</span>
                  </td>
                  <td>
                    {c.last_upload_at ?? <span className="muted">—</span>}
                    {c.last_files.length > 0 && <div className="muted small-text">{c.last_files.join(", ")}</div>}
                  </td>
                  <td className="num">{c.uploads}</td>
                  <td>
                    <code>{c.username}</code>
                  </td>
                  <td>
                    <button type="button" className="link-btn" onClick={() => void remove(c)}>
                      remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <LdapTargets />
      {created && <Created r={created} onClose={() => setCreated(null)} />}
    </div>
  );
}
