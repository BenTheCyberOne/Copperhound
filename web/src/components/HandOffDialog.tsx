import { useEffect, useMemo, useState } from "react";
import { api, errorMessage } from "../api/client";
import type { EdgeRef, FixItem, Node, TicketCreated, TicketTarget } from "../api/types";
import { useApp } from "../state/AppContext";
import { useSession } from "../state/SessionContext";
import { KindBadge } from "./KindBadge";
import { Modal } from "./Modal";
import { webHref } from "../util/format";

export interface HandOffEdge {
  src: Pick<Node, "objectid" | "name">;
  kind: string;
  dst: Pick<Node, "objectid" | "name">;
}

const TYPE_LABEL: Record<TicketTarget["type"], string> = { jira: "Jira", servicenow: "ServiceNow", webhook: "Webhook" };

async function copy(text: string, notify: (m: string, k?: "error" | "info" | "warn") => void) {
  try {
    await navigator.clipboard.writeText(text);
    notify("Copied");
  } catch {
    notify("Clipboard not available: select the text and copy it", "warn");
  }
}

/**
 * Hand fixes to the people who make them: each edge's guidance and a
 * suggested PowerShell command, as a script to copy or as Jira / ServiceNow /
 * webhook tickets.
 */
export function HandOffDialog({ edges, title: defaultTitle = "", more = 0, onClose }: { edges: HandOffEdge[]; title?: string; more?: number; onClose: () => void }) {
  const { notify, track } = useApp();
  const { gate, atLeast } = useSession();
  const refs: EdgeRef[] = useMemo(() => edges.map((e) => ({ src: e.src.objectid, kind: e.kind, dst: e.dst.objectid })), [edges]);
  const [items, setItems] = useState<FixItem[] | null>(null);
  const [missing, setMissing] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [targets, setTargets] = useState<TicketTarget[]>([]);
  const [target, setTarget] = useState("");
  const [title, setTitle] = useState(defaultTitle);
  const [note, setNote] = useState("");
  const [split, setSplit] = useState(false);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<TicketCreated[] | null>(null);

  useEffect(() => {
    api.remediationCommands(refs.slice(0, 200)).then(
      (r) => {
        setItems(r.items);
        setMissing(r.missing.length);
      },
      (e: unknown) => setError(errorMessage(e)),
    );
    api.ticketTargets().then(
      (t) => {
        const on = t.filter((x) => x.enabled);
        setTargets(on);
        setTarget((cur) => cur || on[0]?.id || "");
      },
      () => setTargets([]),
    );
  }, [refs]);

  const script = useMemo(() => {
    if (!items) return "";
    const parts = items.map((i, n) => {
      const head = `# ${n + 1}. ${i.src.name} -[${i.kind}]-> ${i.dst.name}`;
      return i.command ? `${head}\n${i.command}` : `${head}\n# No single scripted fix: ${i.guidance ?? "see the edge help"}`;
    });
    return `# CopperHound remediation (review each command before running it)\n\n${parts.join("\n\n")}\n`;
  }, [items]);

  const download = () => {
    const url = URL.createObjectURL(new Blob([script], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "copperhound-remediation.ps1";
    a.click();
    URL.revokeObjectURL(url);
  };

  const send = async () => {
    setBusy(true);
    try {
      const r = await track(api.createTickets({ target, edges: refs.slice(0, 200), title: title.trim() || undefined, note: note.trim() || undefined, split }));
      setCreated(r.created);
      if (r.errors.length) notify(`${r.errors.length} ticket(s) failed: ${r.errors[0]!.error}`, "warn");
    } catch (e) {
      notify(errorMessage(e), "error");
    } finally {
      setBusy(false);
    }
  };

  const scripted = items?.filter((i) => i.command).length ?? 0;
  const g = gate("analyst");
  const sendGate = { ...g, disabled: g.disabled || busy || !target || !items || items.length === 0 };
  return (
    <Modal title="Hand off fixes" onClose={onClose} wide>
      <div className="form-stack handoff">
        {error && <p className="error">{error}</p>}
        {!items && !error && <p className="muted">Building commands…</p>}
        {items && (
          <>
            <p className="muted small-text">
              {items.length.toLocaleString()} edge{items.length === 1 ? "" : "s"}, {scripted.toLocaleString()} with a suggested command.
              {missing > 0 && ` ${missing} no longer in the graph and left out.`}
              {edges.length > 200 && " Only the first 200 are included."}
              {more > 0 && ` The plan lists 50 edges per step; ${more.toLocaleString()} more are not included.`} Commands identify objects by SID / object id; review them before running, and fix the source
              (a GPO, an inherited ACE, a parent scope) when a right comes from one.
            </p>
            <ol className="handoff-items">
              {items.map((i) => (
                <li key={`${i.src.id}|${i.kind}|${i.dst.id}`}>
                  <div className="fix-edge">
                    <KindBadge kind={i.src.kind} dotOnly /> <span className="ellipsis">{i.src.name}</span>
                    <span className="edge-kind">{i.kind} →</span>
                    <KindBadge kind={i.dst.kind} dotOnly /> <span className="ellipsis">{i.dst.name}</span>
                  </div>
                  {i.guidance && <p className="small-text">{i.guidance}</p>}
                  {i.command ? (
                    <div className="handoff-cmd">
                      <pre className="code-block">{i.command}</pre>
                      <button type="button" className="small" onClick={() => void copy(i.command!, notify)}>
                        Copy
                      </button>
                    </div>
                  ) : (
                    <p className="muted small-text">No single scripted fix for this edge type.</p>
                  )}
                </li>
              ))}
            </ol>
            <div className="row gap wrap">
              <button type="button" onClick={() => void copy(script, notify)} disabled={items.length === 0}>
                Copy as script
              </button>
              <button type="button" onClick={download} disabled={items.length === 0}>
                Download .ps1
              </button>
            </div>

            <h3>Create tickets</h3>
            {targets.length === 0 ? (
              <p className="muted small-text">
                No ticket targets yet.{" "}
                {atLeast("admin") ? (
                  <a href="#/admin/notifications?tab=ticketing">Add Jira, ServiceNow or a webhook</a>
                ) : (
                  "An admin can add Jira, ServiceNow or a webhook under Notifications → Ticketing."
                )}
              </p>
            ) : created ? (
              <ul className="handoff-created">
                {created.map((c) => (
                  <li key={c.key + c.title}>
                    {webHref(c.url) ? (
                      <a href={webHref(c.url)} target="_blank" rel="noreferrer noopener">
                        {c.key}
                      </a>
                    ) : (
                      <strong>{c.key}</strong>
                    )}{" "}
                    — {c.title} <span className="muted">({c.edges} edge{c.edges === 1 ? "" : "s"})</span>
                  </li>
                ))}
              </ul>
            ) : (
              <>
                <label>
                  Send to
                  <select value={target} onChange={(e) => setTarget(e.target.value)}>
                    {targets.map((t) => (
                      <option key={t.id} value={t.id}>
                        {t.name} ({TYPE_LABEL[t.type]})
                      </option>
                    ))}
                  </select>
                </label>
                <label className="toggle">
                  <input type="checkbox" checked={split} onChange={(e) => setSplit(e.target.checked)} />
                  One ticket per edge
                </label>
                {!split && (
                  <label>
                    Title
                    <input value={title} maxLength={250} placeholder={items.length === 1 ? "Remove this edge" : `Remove ${items.length} attack path edges (CopperHound)`} onChange={(e) => setTitle(e.target.value)} />
                  </label>
                )}
                <label>
                  Note for the assignee
                  <textarea rows={2} maxLength={4000} value={note} onChange={(e) => setNote(e.target.value)} />
                </label>
                <div className="row gap">
                  <span className="spacer" />
                  <button type="button" className="primary" onClick={() => void send()} {...sendGate}>
                    {busy ? "Creating…" : split ? `Create ${items.length} tickets` : "Create ticket"}
                  </button>
                </div>
              </>
            )}
          </>
        )}
      </div>
    </Modal>
  );
}
