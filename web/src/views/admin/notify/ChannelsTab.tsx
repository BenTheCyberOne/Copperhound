import { useState, type FormEvent } from "react";
import { api, errorMessage } from "../../../api/client";
import type { ChannelIn, ChannelOut, ChannelType, Delivery, SmtpSecurity, TeamsFormat } from "../../../api/types";
import { ListEditor } from "../../../components/ListEditor";
import { Modal } from "../../../components/Modal";
import { NumberField } from "../../../components/NumberField";
import { KEEP_SECRET, SecretField, secretPayload, type SecretEdit } from "../../../components/SecretField";
import { EmptyState } from "../../../components/StatusView";
import { useApp } from "../../../state/AppContext";
import { DeliveryChip } from "./parts";

export const CHANNEL_TYPE_LABEL: Record<ChannelType, string> = {
  webhook: "Webhook",
  slack: "Slack",
  teams: "Microsoft Teams",
  email: "Email",
};

const DEFAULT_PORT: Record<SmtpSecurity, number> = { starttls: 587, tls: 465, none: 25 };

/** What GET returned, as a PUT item: no secret fields, so the server keeps them. */
export function channelInput(c: ChannelOut): ChannelIn {
  const base: ChannelIn = { id: c.id, name: c.name, type: c.type, enabled: c.enabled };
  if (c.type === "teams") base.teams_format = c.teams_format ?? "adaptive";
  if (c.type === "email") {
    Object.assign(base, {
      smtp_host: c.smtp_host,
      smtp_port: c.smtp_port,
      smtp_security: c.smtp_security,
      smtp_username: c.smtp_username,
      email_from: c.email_from,
      email_to: c.email_to,
    });
  }
  return base;
}

function target(c: ChannelOut): string {
  if (c.type === "email") return (c.email_to ?? []).join(", ") || "—";
  return c.url_hint ?? (c.url_set ? "set" : "—");
}

interface DialogProps {
  channel: ChannelOut | null;
  onClose: () => void;
  /** Saves the edited channel (merged into the full list by the caller). */
  onSave: (c: ChannelIn) => Promise<void>;
}

function ChannelDialog({ channel, onClose, onSave }: DialogProps) {
  const isNew = channel === null;
  const [type, setType] = useState<ChannelType>(channel?.type ?? "webhook");
  const [name, setName] = useState(channel?.name ?? "");
  const [enabled, setEnabled] = useState(channel?.enabled ?? true);
  const [url, setUrl] = useState<SecretEdit>(isNew ? { mode: "set", text: "" } : KEEP_SECRET);
  const [secret, setSecret] = useState<SecretEdit>(KEEP_SECRET);
  const [teamsFormat, setTeamsFormat] = useState<TeamsFormat>(channel?.teams_format ?? "adaptive");
  const [host, setHost] = useState(channel?.smtp_host ?? "");
  const [security, setSecurity] = useState<SmtpSecurity>(channel?.smtp_security ?? "starttls");
  const [port, setPort] = useState(channel?.smtp_port ?? 587);
  const [user, setUser] = useState(channel?.smtp_username ?? "");
  const [password, setPassword] = useState<SecretEdit>(KEEP_SECRET);
  const [from, setFrom] = useState(channel?.email_from ?? "");
  const [to, setTo] = useState<string[]>(channel?.email_to ?? []);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Secrets of a channel whose type changed are not carried over by the server.
  const typeChanged = !isNew && channel.type !== type;
  const stored = (flag: boolean | undefined) => !typeChanged && !!flag;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const c: ChannelIn = { id: channel?.id, name: name.trim(), type, enabled };
    if (type === "email") {
      Object.assign(c, {
        smtp_host: host.trim(),
        smtp_port: port,
        smtp_security: security,
        smtp_username: user.trim(),
        email_from: from.trim(),
        email_to: to,
      });
      const p = secretPayload(password);
      if (p !== undefined) c.smtp_password = p;
    } else {
      const u = secretPayload(url);
      if (u !== undefined) c.url = u;
      if (type === "webhook") {
        const s = secretPayload(secret);
        if (s !== undefined) c.secret = s;
      }
      if (type === "teams") c.teams_format = teamsFormat;
    }
    setBusy(true);
    setError(null);
    try {
      await onSave(c);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  };

  return (
    <Modal title={isNew ? "New channel" : `Edit ${channel.name}`} onClose={onClose} wide>
      <form className="form-stack" onSubmit={(e) => void submit(e)}>
        <div className="form-grid">
          <label htmlFor="ch-name">Name</label>
          <input id="ch-name" value={name} maxLength={100} required onChange={(e) => setName(e.target.value)} autoFocus={isNew} />
          <label htmlFor="ch-type">Type</label>
          <select
            id="ch-type"
            value={type}
            onChange={(e) => {
              const t = e.target.value as ChannelType;
              setType(t);
              if (!isNew && t !== channel.type) setUrl({ mode: "set", text: "" });
            }}
          >
            {(Object.keys(CHANNEL_TYPE_LABEL) as ChannelType[]).map((t) => (
              <option key={t} value={t}>
                {CHANNEL_TYPE_LABEL[t]}
              </option>
            ))}
          </select>
        </div>
        <label className="toggle">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enabled (disabled channels are skipped by schedules and alerts, but can still be tested)
        </label>

        {type !== "email" && (
          <SecretField
            label={type === "webhook" ? "Webhook URL" : type === "slack" ? "Slack incoming-webhook URL" : "Teams webhook URL"}
            isSet={stored(channel?.url_set)}
            hint={typeChanged ? undefined : channel?.url_hint}
            edit={url}
            onChange={setUrl}
            required
            inputType="url"
            placeholder="https://…"
            help="Treated as a secret (webhook URLs often embed a token): only a shortened hint is shown after saving. http(s) only; redirects are not followed."
          />
        )}
        {type === "webhook" && (
          <SecretField
            label="Signing secret (optional)"
            isSet={stored(channel?.secret_set)}
            edit={secret}
            onChange={setSecret}
            help="When set, each request carries X-CopperHound-Signature: sha256=<HMAC-SHA256 of the raw body>."
          />
        )}
        {type === "teams" && (
          <fieldset className="role-choice">
            <legend>Message format</legend>
            <label className="check role-option">
              <input type="radio" name="tf" checked={teamsFormat === "adaptive"} onChange={() => setTeamsFormat("adaptive")} />
              <strong>Adaptive card</strong>
              <span className="muted small-text">For Teams Workflows / Power Automate webhooks.</span>
            </label>
            <label className="check role-option">
              <input type="radio" name="tf" checked={teamsFormat === "messagecard"} onChange={() => setTeamsFormat("messagecard")} />
              <strong>MessageCard</strong>
              <span className="muted small-text">Legacy Office 365 connector webhooks.</span>
            </label>
          </fieldset>
        )}
        {type === "email" && (
          <>
            <div className="form-grid">
              <label htmlFor="ch-host">SMTP host</label>
              <input id="ch-host" value={host} placeholder="smtp.corp.example" spellCheck={false} onChange={(e) => setHost(e.target.value)} required />
              <label htmlFor="ch-sec">Security</label>
              <select
                id="ch-sec"
                value={security}
                onChange={(e) => {
                  const s = e.target.value as SmtpSecurity;
                  if (port === DEFAULT_PORT[security]) setPort(DEFAULT_PORT[s]);
                  setSecurity(s);
                }}
              >
                <option value="starttls">STARTTLS (required upgrade)</option>
                <option value="tls">Implicit TLS</option>
                <option value="none">None (plain text, no credentials)</option>
              </select>
              <label htmlFor="ch-port">Port</label>
              <NumberField id="ch-port" min={1} max={65535} value={port} onCommit={(v) => setPort(Math.round(v))} />
              <label htmlFor="ch-user">Username</label>
              <input id="ch-user" value={user} autoComplete="off" disabled={security === "none"} onChange={(e) => setUser(e.target.value)} />
            </div>
            {security !== "none" ? (
              <SecretField label="SMTP password" isSet={stored(channel?.smtp_password_set)} edit={password} onChange={setPassword} />
            ) : (
              <span className="muted small-text">Credentials are refused without TLS, so they cannot leak in clear text.</span>
            )}
            <div className="form-grid">
              <label htmlFor="ch-from">From</label>
              <input id="ch-from" value={from} placeholder="CopperHound <copperhound@corp.example>" onChange={(e) => setFrom(e.target.value)} required />
            </div>
            <div className="form-field">
              <span className="field-title">Recipients</span>
              <ListEditor
                label="Recipients"
                values={to}
                onChange={setTo}
                placeholder="soc@corp.example"
                validate={(v) => (/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(v) ? null : `${v} is not an email address`)}
              />
            </div>
          </>
        )}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <div className="row gap">
          <span className="spacer" />
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="primary" disabled={busy || !name.trim()}>
            {busy ? "Saving…" : "Save channel"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function ChannelsTab({ channels, onChange }: { channels: ChannelOut[]; onChange: (c: ChannelOut[]) => void }) {
  const { notify, track } = useApp();
  const [editing, setEditing] = useState<ChannelOut | "new" | null>(null);
  const [tests, setTests] = useState<Record<string, Delivery | "running">>({});

  /** PUT replaces the whole list: unchanged channels are sent back without secrets (kept). */
  const saveList = async (list: ChannelIn[]) => {
    const r = await track(api.saveChannels(list));
    onChange(r.channels);
  };

  const saveOne = async (c: ChannelIn) => {
    const list = channels.map((x) => (x.id === c.id ? c : channelInput(x)));
    if (!c.id) list.push(c);
    await saveList(list);
    setEditing(null);
    notify(`Channel ${c.name} saved.`);
  };

  const toggle = async (c: ChannelOut) => {
    try {
      await saveList(channels.map((x) => (x.id === c.id ? { ...channelInput(x), enabled: !x.enabled } : channelInput(x))));
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  const remove = async (c: ChannelOut) => {
    if (!window.confirm(`Delete channel ${c.name}? Schedules or alert rules that use it will report “unknown channel”.`)) return;
    try {
      await saveList(channels.filter((x) => x.id !== c.id).map(channelInput));
      notify(`Channel ${c.name} deleted.`);
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  const test = async (c: ChannelOut) => {
    setTests((t) => ({ ...t, [c.id]: "running" }));
    try {
      const d = await api.testChannel(c.id);
      setTests((t) => ({ ...t, [c.id]: d }));
    } catch (e) {
      setTests((t) => ({ ...t, [c.id]: { channel: c.id, ok: false, error: errorMessage(e) } }));
    }
  };

  return (
    <>
      <div className="section-head">
        <p className="muted small-text">
          Secrets (webhook URLs, signing secrets, SMTP passwords) are write-only: they are never shown again after saving.
        </p>
        <button type="button" className="primary" onClick={() => setEditing("new")}>
          New channel
        </button>
      </div>
      {channels.length === 0 ? (
        <EmptyState title="No channels yet">Add a webhook, Slack, Teams or email channel, then use it in schedules and alert rules.</EmptyState>
      ) : (
        <div className="table-card">
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Target</th>
                <th>Enabled</th>
                <th>Test</th>
                <th>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {channels.map((c) => {
                const t = tests[c.id];
                return (
                  <tr key={c.id} className={c.enabled ? "" : "row-disabled"}>
                    <td>
                      <strong>{c.name}</strong>
                      <div className="muted small-text">
                        <code>{c.id}</code>
                      </div>
                    </td>
                    <td>
                      {CHANNEL_TYPE_LABEL[c.type]}
                      {c.type === "webhook" && c.secret_set && <span className="tag small-tag">signed</span>}
                    </td>
                    <td>
                      <code className="break small-text">{target(c)}</code>
                    </td>
                    <td>
                      <label className="toggle">
                        <input type="checkbox" checked={c.enabled} onChange={() => void toggle(c)} aria-label={`Enable ${c.name}`} />
                        {c.enabled ? <span className="tag ok">on</span> : <span className="tag off">off</span>}
                      </label>
                    </td>
                    <td className="test-cell">
                      <button type="button" className="small" disabled={t === "running"} onClick={() => void test(c)}>
                        {t === "running" ? "Sending…" : "Send test"}
                      </button>
                      {t && t !== "running" && <DeliveryChip d={t} />}
                    </td>
                    <td className="row-actions">
                      <button type="button" className="small" onClick={() => setEditing(c)}>
                        Edit
                      </button>
                      <button type="button" className="small danger" onClick={() => void remove(c)}>
                        Delete
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <p className="muted small-text">
        A test is sent even to a disabled channel. Unreachable targets are retried (up to 3 attempts), so a failing test can
        take up to a minute. Only admins can configure targets; restrict outbound traffic at the network level if CopperHound
        should not reach internal services.
      </p>
      {editing && <ChannelDialog channel={editing === "new" ? null : editing} onClose={() => setEditing(null)} onSave={saveOne} />}
    </>
  );
}
