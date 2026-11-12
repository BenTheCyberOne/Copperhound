import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, errorMessage } from "../../../api/client";
import type { TicketRecord, TicketTarget, TicketTargetIn, TicketTargetType } from "../../../api/types";
import { Modal } from "../../../components/Modal";
import { KEEP_SECRET, SecretField, secretPayload, type SecretEdit } from "../../../components/SecretField";
import { EmptyState } from "../../../components/StatusView";
import { useApp } from "../../../state/AppContext";
import { webHref } from "../../../util/format";

const LABEL: Record<TicketTargetType, string> = { jira: "Jira", servicenow: "ServiceNow", webhook: "Webhook" };

/** What GET returned, as a PUT item (no token: the server keeps it). */
function toInput(t: TicketTarget): TicketTargetIn {
  return { id: t.id, name: t.name, type: t.type, enabled: t.enabled, url: t.url, username: t.username, project: t.project, issue_type: t.issue_type, table: t.table, labels: t.labels, fields: t.fields };
}

function TargetDialog({ target, onClose, onSave }: { target: TicketTarget | null; onClose: () => void; onSave: (t: TicketTargetIn) => Promise<void> }) {
  const [type, setType] = useState<TicketTargetType>(target?.type ?? "jira");
  const [name, setName] = useState(target?.name ?? "");
  const [enabled, setEnabled] = useState(target?.enabled ?? true);
  const [url, setUrl] = useState(target?.url ?? "");
  const [username, setUsername] = useState(target?.username ?? "");
  const [token, setToken] = useState<SecretEdit>(target?.token_set ? KEEP_SECRET : { mode: "set", text: "" });
  const [project, setProject] = useState(target?.project ?? "");
  const [issueType, setIssueType] = useState(target?.issue_type || "Task");
  const [table, setTable] = useState(target?.table || "incident");
  const [labels, setLabels] = useState((target?.labels ?? ["copperhound"]).join(" "));
  const [fields, setFields] = useState(target && Object.keys(target.fields).length ? JSON.stringify(target.fields, null, 2) : "");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    let extra: Record<string, unknown> = {};
    if (fields.trim()) {
      try {
        const v: unknown = JSON.parse(fields);
        if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error("not an object");
        extra = v as Record<string, unknown>;
      } catch {
        setError("Extra fields must be a JSON object, e.g. {\"assignment_group\": \"AD Team\"}");
        return;
      }
    }
    setSaving(true);
    setError(null);
    try {
      await onSave({
        id: target?.id,
        name: name.trim(),
        type,
        enabled,
        url: url.trim(),
        username: username.trim(),
        token: secretPayload(token),
        project: project.trim(),
        issue_type: issueType.trim(),
        table: table.trim(),
        labels: labels.split(/\s+/).filter(Boolean),
        fields: extra,
      });
    } catch (err) {
      setError(errorMessage(err));
      setSaving(false);
    }
  };

  const tokenLabel = type === "jira" ? "API token / personal access token" : type === "servicenow" ? "Password" : "HMAC secret (optional)";
  return (
    <Modal title={target ? `Edit “${target.name}”` : "New ticket target"} onClose={onClose}>
      <form className="form-stack" onSubmit={(e) => void submit(e)}>
        <label>
          Type
          <select value={type} onChange={(e) => setType(e.target.value as TicketTargetType)} disabled={!!target}>
            {(Object.keys(LABEL) as TicketTargetType[]).map((t) => (
              <option key={t} value={t}>
                {LABEL[t]}
              </option>
            ))}
          </select>
        </label>
        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} required autoFocus />
        </label>
        <label>
          {type === "jira" ? "Jira URL" : type === "servicenow" ? "Instance URL" : "Webhook URL"}
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            required
            placeholder={type === "jira" ? "https://acme.atlassian.net" : type === "servicenow" ? "https://acme.service-now.com" : "https://soar.example.com/hook"}
          />
        </label>
        {type !== "webhook" && (
          <label>
            {type === "jira" ? "Account email (empty for a Data Center personal access token)" : "User"}
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" required={type === "servicenow"} />
          </label>
        )}
        <SecretField label={tokenLabel} isSet={!!target?.token_set} edit={token} onChange={setToken} required={type !== "webhook"} />
        {type === "jira" && (
          <>
            <label>
              Project key
              <input value={project} onChange={(e) => setProject(e.target.value)} required placeholder="SEC" />
            </label>
            <label>
              Issue type
              <input value={issueType} onChange={(e) => setIssueType(e.target.value)} />
            </label>
            <label>
              Labels (space separated)
              <input value={labels} onChange={(e) => setLabels(e.target.value)} />
            </label>
          </>
        )}
        {type === "servicenow" && (
          <label>
            Table
            <input value={table} onChange={(e) => setTable(e.target.value)} />
          </label>
        )}
        {type !== "webhook" && (
          <label>
            Extra fields (JSON, optional)
            <textarea
              rows={3}
              className="chql-editor"
              spellCheck={false}
              value={fields}
              onChange={(e) => setFields(e.target.value)}
              placeholder={type === "jira" ? '{"priority": {"name": "High"}}' : '{"assignment_group": "AD Team", "urgency": "2"}'}
            />
          </label>
        )}
        <label className="toggle">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enabled
        </label>
        {error && <p className="error">{error}</p>}
        <div className="row gap">
          <span className="spacer" />
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="primary" disabled={saving || !name.trim() || !url.trim()}>
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** Notifications → Ticketing: where "Hand off…" creates tickets. */
export function TicketingTab() {
  const { notify, track } = useApp();
  const [targets, setTargets] = useState<TicketTarget[] | null>(null);
  const [log, setLog] = useState<TicketRecord[]>([]);
  const [dialog, setDialog] = useState<{ target: TicketTarget | null } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(() => {
    api.ticketTargets().then(setTargets, (e: unknown) => setError(errorMessage(e)));
    api.tickets().then(setLog, () => setLog([]));
  }, []);
  useEffect(reload, [reload]);

  const save = async (list: TicketTargetIn[]) => setTargets(await track(api.saveTicketTargets(list)));

  const test = async (t: TicketTarget) => {
    try {
      const r = await track(api.testTicketTarget(t.id));
      notify(r.ok ? `${t.name}: ${r.detail ?? "ok"}` : `${t.name}: ${r.error ?? "failed"}`, r.ok ? "info" : "error");
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  const remove = async (t: TicketTarget) => {
    if (!targets || !window.confirm(`Delete ticket target “${t.name}”?`)) return;
    try {
      await save(targets.filter((x) => x.id !== t.id).map(toInput));
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  return (
    <section className="card">
      <div className="section-head">
        <div>
          <h2>Ticketing</h2>
          <p className="muted small-text">
            “Hand off…” in Remediation turns fix-list edges and plan steps into Jira issues, ServiceNow records or webhook events, each edge with its guidance and a
            suggested command.
          </p>
        </div>
        <button type="button" className="primary" onClick={() => setDialog({ target: null })}>
          Add target
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      {targets && targets.length === 0 && <EmptyState title="No ticket targets">Add Jira, ServiceNow or a webhook.</EmptyState>}
      {targets && targets.length > 0 && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Where</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {targets.map((t) => (
              <tr key={t.id} className={t.enabled ? "" : "row-disabled"}>
                <td>
                  {t.name} {!t.enabled && <span className="tag off">disabled</span>}
                </td>
                <td>{LABEL[t.type]}</td>
                <td className="small-text ellipsis">
                  {t.url}
                  {t.project && ` · ${t.project}`}
                  {t.type === "servicenow" && ` · ${t.table}`}
                </td>
                <td className="row-actions">
                  <button type="button" className="small" onClick={() => void test(t)}>
                    Test
                  </button>
                  <button type="button" className="small" onClick={() => setDialog({ target: t })}>
                    Edit
                  </button>
                  <button type="button" className="small danger" onClick={() => void remove(t)}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <h3>Recent tickets</h3>
      {log.length === 0 ? (
        <p className="muted small-text">None yet.</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Ticket</th>
              <th>Title</th>
              <th>Target</th>
              <th>By</th>
              <th>When</th>
            </tr>
          </thead>
          <tbody>
            {log.slice(0, 50).map((r, i) => (
              <tr key={`${r.key}-${r.at}-${i}`}>
                <td>
                  {webHref(r.url) ? (
                    <a href={webHref(r.url)} target="_blank" rel="noreferrer noopener">
                      {r.key}
                    </a>
                  ) : (
                    r.key
                  )}
                </td>
                <td title={r.edges.join("\n")}>{r.title}</td>
                <td>{r.target_name}</td>
                <td>{r.by}</td>
                <td className="small-text">{new Date(r.at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {dialog && (
        <TargetDialog
          target={dialog.target}
          onClose={() => setDialog(null)}
          onSave={async (t) => {
            const rest = (targets ?? []).filter((x) => x.id !== t.id).map(toInput);
            const list = dialog.target ? (targets ?? []).map((x) => (x.id === t.id ? t : toInput(x))) : [...rest, t];
            await save(list);
            setDialog(null);
          }}
        />
      )}
    </section>
  );
}
