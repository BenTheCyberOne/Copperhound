import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, errorMessage } from "../../api/client";
import { ROLES, type ApiTokenInfo, type Role, type RoleInfo, type UserInfo } from "../../api/types";
import { Modal } from "../../components/Modal";
import { useApp } from "../../state/AppContext";
import { ROLE_LABEL, RoleBadge, useSession } from "../../state/SessionContext";
import { when } from "../../util/format";
import { TokenTable } from "../AccountView";

const MIN_PASSWORD = 12;

function PasswordField({ value, onChange, label }: { value: string; onChange: (v: string) => void; label: string }) {
  return (
    <label>
      {label}
      <input type="password" autoComplete="new-password" value={value} onChange={(e) => onChange(e.target.value)} minLength={MIN_PASSWORD} required />
      <span className={`small-text ${value && value.length < MIN_PASSWORD ? "warn-text" : "muted"}`}>At least {MIN_PASSWORD} characters.</span>
    </label>
  );
}

function CreateUserDialog({ roles, onClose, onCreated }: { roles: RoleInfo[]; onClose: () => void; onCreated: (u: UserInfo) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onCreated(await api.createUser(username.trim(), password, role));
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  };

  return (
    <Modal title="New user" onClose={onClose}>
      <form className="form-stack" onSubmit={(e) => void submit(e)}>
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus autoComplete="off" />
        </label>
        <PasswordField label="Initial password" value={password} onChange={setPassword} />
        <fieldset className="role-choice">
          <legend>Role</legend>
          {roles.map((r) => (
            <label key={r.id} className="check role-option">
              <input type="radio" name="role" value={r.id} checked={role === r.id} onChange={() => setRole(r.id)} />
              <RoleBadge role={r.id} />
              <span className="muted small-text">{r.description}</span>
            </label>
          ))}
        </fieldset>
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
          <button type="submit" className="primary" disabled={busy || !username.trim() || password.length < MIN_PASSWORD}>
            {busy ? "Creating…" : "Create user"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function ResetPasswordDialog({ user, onClose, onDone }: { user: UserInfo; onClose: () => void; onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await api.updateUser(user.username, { password });
      onDone();
    } catch (err) {
      setError(errorMessage(err));
    }
  };
  return (
    <Modal title={`Reset password for ${user.username}`} onClose={onClose}>
      <form className="form-stack" onSubmit={(e) => void submit(e)}>
        <PasswordField label="New password" value={password} onChange={setPassword} />
        <p className="muted small-text">Their existing sessions are signed out. Share the new password over a secure channel.</p>
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
          <button type="submit" className="primary" disabled={password.length < MIN_PASSWORD}>
            Reset password
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function UsersView() {
  const { notify, track } = useApp();
  const { username: self, reloadMe } = useSession();
  const [users, setUsers] = useState<UserInfo[] | null>(null);
  const [roles, setRoles] = useState<RoleInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [resetting, setResetting] = useState<UserInfo | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = useCallback(() => {
    api.users().then(
      (r) => {
        setUsers(r.users);
        setRoles(r.roles);
        setError(null);
      },
      (e: unknown) => setError(errorMessage(e)),
    );
  }, []);
  useEffect(load, [load]);

  /** Applies a change; the server rejects demoting / disabling the last admin with a message. */
  const update = async (u: UserInfo, change: Parameters<typeof api.updateUser>[1], what: string) => {
    try {
      const next = await track(api.updateUser(u.username, change));
      setUsers((us) => us?.map((x) => (x.username === u.username ? next : x)) ?? null);
      notify(`${u.username}: ${what}.`);
      if (u.username === self) reloadMe();
    } catch (e) {
      notify(errorMessage(e), "error");
      load();
    }
  };

  const remove = async (u: UserInfo) => {
    if (!window.confirm(`Delete user ${u.username}? Their API tokens stop working.`)) return;
    try {
      await track(api.deleteUser(u.username));
      setUsers((us) => us?.filter((x) => x.username !== u.username) ?? null);
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  const revoke = async (u: UserInfo, t: ApiTokenInfo) => {
    if (!window.confirm(`Revoke ${u.username}'s token “${t.name}”?`)) return;
    try {
      await track(api.revokeUserToken(u.username, t.id));
      load();
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  const resetMfa = async (u: UserInfo) => {
    if (!window.confirm(`Turn off two-factor sign-in for ${u.username}? Their sessions end; they can set it up again.`)) return;
    try {
      await api.resetUserMfa(u.username);
      setUsers((us) => (us ?? []).map((x) => (x.username === u.username ? { ...x, mfa: false } : x)));
      notify(`Two-factor sign-in reset for ${u.username}.`);
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  return (
    <div className="view-page">
      <header className="view-head">
        <div>
          <h1>Users</h1>
          <p className="muted">
            Accounts, roles and API tokens. Every change is recorded in the audit log. SSO accounts are created on first
            sign-in; their role is set again from the identity provider each time they sign in, and they have no password.
          </p>
        </div>
        <button type="button" className="primary" onClick={() => setCreating(true)} disabled={roles.length === 0}>
          New user
        </button>
      </header>

      {roles.length > 0 && (
        <div className="role-cards">
          {roles.map((r) => (
            <div key={r.id} className="stat">
              <RoleBadge role={r.id} />
              <span className="small-text">{r.description}</span>
            </div>
          ))}
        </div>
      )}

      {error && <p className="error">{error}</p>}
      {!users && !error && <p className="muted">Loading users…</p>}
      {users && (
        <div className="table-card">
          <table className="data-table users-table">
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Status</th>
                <th>Last sign-in</th>
                <th>Created</th>
                <th>Tokens</th>
                <th>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <UserRow
                  key={u.username}
                  u={u}
                  self={u.username === self}
                  expanded={expanded === u.username}
                  onToggleTokens={() => setExpanded((x) => (x === u.username ? null : u.username))}
                  onRole={(role) => void update(u, { role }, `role set to ${ROLE_LABEL[role].toLowerCase()}`)}
                  onToggleDisabled={() => void update(u, { disabled: !u.disabled }, u.disabled ? "enabled" : "disabled")}
                  onReset={() => setResetting(u)}
                  onResetMfa={() => void resetMfa(u)}
                  onDelete={() => void remove(u)}
                  onRevoke={(t) => void revoke(u, t)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {creating && (
        <CreateUserDialog
          roles={roles}
          onClose={() => setCreating(false)}
          onCreated={(u) => {
            setCreating(false);
            setUsers((us) => [...(us ?? []), u]);
            notify(`User ${u.username} created as ${u.role}.`);
          }}
        />
      )}
      {resetting && (
        <ResetPasswordDialog
          user={resetting}
          onClose={() => setResetting(null)}
          onDone={() => {
            notify(`Password for ${resetting.username} reset.`);
            setResetting(null);
          }}
        />
      )}
    </div>
  );
}

interface RowProps {
  u: UserInfo;
  self: boolean;
  expanded: boolean;
  onToggleTokens: () => void;
  onRole: (r: Role) => void;
  onToggleDisabled: () => void;
  onReset: () => void;
  onResetMfa: () => void;
  onDelete: () => void;
  onRevoke: (t: ApiTokenInfo) => void;
}

function UserRow({ u, self, expanded, onToggleTokens, onRole, onToggleDisabled, onReset, onResetMfa, onDelete, onRevoke }: RowProps) {
  return (
    <>
      <tr className={u.disabled ? "row-disabled" : ""}>
        <td>
          <strong>{u.username}</strong> {self && <span className="tag">you</span>}{" "}
          {u.source === "oidc" ? (
            <span className="tag source-oidc" title="Signs in with single sign-on; role re-evaluated from the IdP on every sign-in">
              SSO
            </span>
          ) : (
            <span className="tag source-local" title="Local account (password)">
              local
            </span>
          )}
        </td>
        <td>
          <select
            aria-label={`Role of ${u.username}`}
            value={u.role}
            onChange={(e) => {
              const r = e.target.value as Role;
              if (!self || window.confirm("Change your own role? You may lose access to this page.")) onRole(r);
            }}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {ROLE_LABEL[r]}
              </option>
            ))}
          </select>
        </td>
        <td>
          <label className="toggle" title={self ? "You cannot disable your own account here" : undefined}>
            <input type="checkbox" checked={!u.disabled} onChange={onToggleDisabled} disabled={self} />
            {u.disabled ? <span className="tag off">disabled</span> : <span className="tag ok">enabled</span>}
          </label>
          {u.mfa && (
            <span className="tag small-tag" title="Two-factor sign-in is on">
              2FA
            </span>
          )}
        </td>
        <td className="nowrap">{u.last_login ? when(u.last_login) : <span className="muted">never</span>}</td>
        <td className="nowrap">{when(u.created_at)}</td>
        <td>
          {u.tokens.length === 0 ? (
            <span className="muted">0</span>
          ) : (
            <button type="button" className="link-btn" aria-expanded={expanded} onClick={onToggleTokens}>
              {u.tokens.length} token{u.tokens.length === 1 ? "" : "s"} {expanded ? "▾" : "▸"}
            </button>
          )}
        </td>
        <td className="row-actions">
          {u.source !== "oidc" && (
            <button type="button" className="small" onClick={onReset}>
              Reset password
            </button>
          )}
          {u.mfa && (
            <button type="button" className="small" onClick={onResetMfa} title="Turn off two-factor sign-in (lost device); the user can set it up again">
              Reset 2FA
            </button>
          )}
          <button type="button" className="small danger" onClick={onDelete} disabled={self} title={self ? "You cannot delete your own account" : undefined}>
            Delete
          </button>
        </td>
      </tr>
      {expanded && u.tokens.length > 0 && (
        <tr className="subrow">
          <td colSpan={7}>
            <TokenTable tokens={u.tokens} onRevoke={onRevoke} />
          </td>
        </tr>
      )}
    </>
  );
}
