import { useEffect, useState, type FormEvent } from "react";
import { api, errorMessage } from "../api/client";
import type { ApiTokenInfo, CreatedToken } from "../api/types";
import { Modal } from "../components/Modal";
import { EmptyState } from "../components/StatusView";
import { useApp } from "../state/AppContext";
import { RoleBadge, useSession } from "../state/SessionContext";
import { when } from "../util/format";
import { TwoFactor } from "./TwoFactor";

const MIN_PASSWORD = 12;
const EXPIRY_OPTIONS = [
  { days: 30, label: "30 days" },
  { days: 90, label: "90 days" },
  { days: 365, label: "1 year" },
  { days: 0, label: "Never" },
];

/** Shows a freshly created token exactly once, with a copy button. */
export function ShowOnceToken({ created, onClose }: { created: CreatedToken; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(created.token);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };
  return (
    <Modal title={`Token “${created.name}” created`} onClose={onClose}>
      <div className="form-stack">
        <p className="notice warn">
          <span>
            <strong>Copy it now.</strong> This is the only time the token is shown; CopperHound stores only a hash.
          </span>
        </p>
        <div className="token-box">
          <code className="break" aria-label="New API token">
            {created.token}
          </code>
          <button type="button" className="primary small" onClick={() => void copy()}>
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
        <p className="muted small-text">
          Use it as <code>Authorization: Bearer &lt;token&gt;</code>. It has the same role as your account
          {created.expires_at ? ` and expires ${when(created.expires_at)}` : " and does not expire"}.
        </p>
        {created.bloodhound_key && (
          <details>
            <summary className="small-text">For BloodHound-compatible tools (signed requests)</summary>
            <dl className="fields wide-fields small-text">
              <dt>Token ID</dt>
              <dd>
                <code className="break">{created.id}</code>
              </dd>
              <dt>Token key</dt>
              <dd>
                <code className="break">{created.bloodhound_key}</code>
              </dd>
            </dl>
            <p className="muted small-text">
              Tools that sign requests the BloodHound way (<code>bhesignature</code>) take this ID and key, with the server URL
              as the BloodHound URL; uploads go to <code>/api/v2/file-upload</code>.
            </p>
          </details>
        )}
        <div className="row gap">
          <span className="spacer" />
          <button type="button" className="primary" onClick={onClose}>
            I stored it
          </button>
        </div>
      </div>
    </Modal>
  );
}

function ChangePassword({ onSignedOut }: { onSignedOut: (notice: string) => void }) {
  const { me } = useSession();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const mismatch = confirm !== "" && confirm !== next;
  const tooShort = next !== "" && next.length < MIN_PASSWORD;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.changePassword(current, next);
      onSignedOut("Password changed. All your sessions were signed out — sign in with the new password.");
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  };

  if (me?.via_token) {
    return <p className="muted">You are signed in with an API token. Sign in with your password to change it.</p>;
  }
  return (
    <form className="form-stack narrow" onSubmit={(e) => void submit(e)}>
      <label>
        Current password
        <input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
      </label>
      <label>
        New password
        <input
          type="password"
          autoComplete="new-password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
          required
          minLength={MIN_PASSWORD}
          aria-describedby="pw-hint"
        />
      </label>
      <span id="pw-hint" className={`small-text ${tooShort ? "warn-text" : "muted"}`}>
        At least {MIN_PASSWORD} characters. Changing it signs out all your sessions, including this one.
      </span>
      <label>
        Confirm new password
        <input type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
      </label>
      {mismatch && <span className="warn-text small-text">The passwords do not match.</span>}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div>
        <button type="submit" className="primary" disabled={busy || !current || next.length < MIN_PASSWORD || next !== confirm}>
          {busy ? "Changing…" : "Change password"}
        </button>
      </div>
    </form>
  );
}

function Tokens() {
  const { notify } = useApp();
  const [tokens, setTokens] = useState<ApiTokenInfo[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [days, setDays] = useState(90);
  const [created, setCreated] = useState<CreatedToken | null>(null);
  const [busy, setBusy] = useState(false);

  const load = () =>
    api.myTokens().then(
      (r) => setTokens(r.tokens),
      (e: unknown) => setError(errorMessage(e)),
    );
  useEffect(() => {
    void load();
  }, []);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const t = await api.createToken(name.trim(), days || undefined);
      setCreated(t);
      setName("");
      void load();
    } catch (err) {
      notify(errorMessage(err), "error");
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (t: ApiTokenInfo) => {
    if (!window.confirm(`Revoke token “${t.name}”? Scripts using it stop working immediately.`)) return;
    try {
      await api.deleteToken(t.id);
      setTokens((ts) => ts?.filter((x) => x.id !== t.id) ?? null);
    } catch (err) {
      notify(errorMessage(err), "error");
    }
  };

  return (
    <>
      <form className="row gap wrap token-form" onSubmit={(e) => void create(e)}>
        <label className="inline-field">
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. nightly export" required maxLength={64} />
        </label>
        <label className="inline-field">
          Expires
          <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
            {EXPIRY_OPTIONS.map((o) => (
              <option key={o.days} value={o.days}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
        <button type="submit" className="primary" disabled={busy || !name.trim()}>
          Create token
        </button>
      </form>
      {error && <p className="error">{error}</p>}
      {tokens && tokens.length === 0 && <EmptyState title="No API tokens">Tokens let scripts call the API without your password.</EmptyState>}
      {tokens && tokens.length > 0 && <TokenTable tokens={tokens} onRevoke={(t) => void revoke(t)} />}
      {created && <ShowOnceToken created={created} onClose={() => setCreated(null)} />}
    </>
  );
}

export function TokenTable({ tokens, onRevoke }: { tokens: ApiTokenInfo[]; onRevoke: (t: ApiTokenInfo) => void }) {
  const expired = (t: ApiTokenInfo) => !!t.expires_at && Date.parse(t.expires_at) < Date.now();
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Token</th>
          <th>Created</th>
          <th>Expires</th>
          <th>Last used</th>
          <th>
            <span className="sr-only">Actions</span>
          </th>
        </tr>
      </thead>
      <tbody>
        {tokens.map((t) => (
          <tr key={t.id}>
            <td>{t.name}</td>
            <td>
              <code>{t.prefix}…</code>
            </td>
            <td className="nowrap">{when(t.created_at)}</td>
            <td className="nowrap">
              {t.expires_at ? when(t.expires_at) : <span className="muted">never</span>}
              {expired(t) && <span className="tag off"> expired</span>}
            </td>
            <td className="nowrap">{t.last_used ? when(t.last_used) : <span className="muted">never</span>}</td>
            <td>
              <button type="button" className="small danger" onClick={() => onRevoke(t)}>
                Revoke
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function AccountView({ onSignedOut }: { onSignedOut: (notice: string) => void }) {
  const { me, username, role } = useSession();
  return (
    <div className="view-page">
      <header className="view-head">
        <div>
          <h1>Account</h1>
          <p className="muted">Your profile, sign-in and personal API tokens.</p>
        </div>
      </header>
      <div className="data-grid">
        <section className="card">
          <h2>Profile</h2>
          <dl className="fields wide-fields">
            <dt>Username</dt>
            <dd>{username}</dd>
            <dt>Role</dt>
            <dd>
              <RoleBadge role={role} />{" "}
              <span className="muted small-text">
                {role === "uploader" && "Upload collector files and start an ingest."}
                {role === "viewer" && "Browse, search, query and run analyses."}
                {role === "analyst" && "Also marks, saved queries, zones, uploads and ingest."}
                {role === "admin" && "Also users, audit log and server settings."}
              </span>
            </dd>
            <dt>Created</dt>
            <dd>{me ? when(me.created_at) : "…"}</dd>
            <dt>Last sign-in</dt>
            <dd>{me?.last_login ? when(me.last_login) : "—"}</dd>
            <dt>Signed in with</dt>
            <dd>{me?.via_token ? "an API token" : me?.source === "oidc" ? "single sign-on" : "password"}</dd>
            <dt>Account type</dt>
            <dd>{me?.source === "oidc" ? "SSO (role set by your identity provider at each sign-in)" : "local"}</dd>
          </dl>
        </section>
        <section className="card">
          <h2>Change password</h2>
          {me?.source === "oidc" ? (
            <p className="muted">
              You sign in with single sign-on, so there is no CopperHound password to change. Manage your password at your
              identity provider.
            </p>
          ) : (
            <ChangePassword onSignedOut={onSignedOut} />
          )}
        </section>
      </div>
      {me?.source !== "oidc" && !me?.via_token && (
        <section className="card">
          <h2>Two-factor sign-in</h2>
          <TwoFactor />
        </section>
      )}
      <section className="card">
        <h2>Personal API tokens</h2>
        <p className="muted small-text">
          Tokens carry your role. Send one as a bearer token to script exports or ingests (jobs started this way show the
          trigger “api”).
        </p>
        <Tokens />
      </section>
    </div>
  );
}
