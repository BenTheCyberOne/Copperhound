import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { api, errorMessage } from "../../api/client";
import type { SsoMappedRole, SsoConfig, SsoDefaultRole, SsoSettingsResponse, SsoTestResult } from "../../api/types";
import { ListEditor } from "../../components/ListEditor";
import { KEEP_SECRET, SecretField, secretPayload, type SecretEdit } from "../../components/SecretField";
import { routeHref } from "../../hooks/useRoute";
import { useApp } from "../../state/AppContext";
import { RoleBadge } from "../../state/SessionContext";
import { SamlSettings } from "./SamlSettings";

/** Config field → COPPERHOUND_OIDC_<suffix> (see docs/API.md, SSO → Environment variables). */
const ENV_VAR: Record<string, string> = {
  enabled: "ENABLED",
  display_name: "DISPLAY_NAME",
  issuer: "ISSUER",
  client_id: "CLIENT_ID",
  client_secret: "CLIENT_SECRET",
  redirect_url: "REDIRECT_URL",
  scopes: "SCOPES",
  username_claim: "USERNAME_CLAIM",
  groups_claim: "GROUPS_CLAIM",
  default_role: "DEFAULT_ROLE",
  "role_mapping.admin": "ADMIN_GROUPS",
  "role_mapping.analyst": "ANALYST_GROUPS",
  "role_mapping.viewer": "VIEWER_GROUPS",
  allowed_email_domains: "ALLOWED_EMAIL_DOMAINS",
  allow_password_login: "ALLOW_PASSWORD_LOGIN",
  allow_insecure_http: "ALLOW_INSECURE_HTTP",
};

const MAPPED_ROLES: SsoMappedRole[] = ["admin", "analyst", "viewer"];

function editable(c: SsoConfig): SsoConfig {
  // Read-only / write-only keys are not part of the edited form.
  const { client_secret_set: _set, client_secret: _secret, ...rest } = c;
  return rest;
}

function Field({ label, env, children, help }: { label: string; env: string | null; children: ReactNode; help?: ReactNode }) {
  return (
    <div className="form-field">
      <span className="field-title">
        {label} {env && <span className="tag" title={`Set by COPPERHOUND_OIDC_${env}`}>env</span>}
      </span>
      {children}
      {env && (
        <span className="muted small-text">
          Set by the environment variable <code>COPPERHOUND_OIDC_{env}</code>; change it there and restart.
        </span>
      )}
      {help && <span className="muted small-text">{help}</span>}
    </div>
  );
}

function TestResult({ result }: { result: SsoTestResult }) {
  if (!result.ok) {
    return (
      <p className="notice error" role="alert">
        <span>
          <strong>Discovery failed.</strong> {result.error}
        </span>
      </p>
    );
  }
  const rows: [string, string | null | undefined][] = [
    ["Issuer", result.issuer],
    ["Authorization", result.authorization_endpoint],
    ["Token", result.token_endpoint],
    ["JWKS", result.jwks_uri],
    ["UserInfo", result.userinfo_endpoint],
    ["End session", result.end_session_endpoint],
  ];
  return (
    <div className="sso-test" role="status">
      <p>
        <span className="tag ok">discovery ok</span> <span className="muted small-text">{result.jwks_keys ?? 0} signing keys published</span>
      </p>
      <dl className="fields wide-fields">
        {rows
          .filter(([, v]) => v)
          .map(([k, v]) => (
            <div key={k} className="contents">
              <dt>{k}</dt>
              <dd>
                <code className="break">{v}</code>
              </dd>
            </div>
          ))}
        {result.scopes_supported && result.scopes_supported.length > 0 && (
          <>
            <dt>Scopes</dt>
            <dd className="tags">
              {result.scopes_supported.map((s) => (
                <span key={s} className="tag">
                  {s}
                </span>
              ))}
            </dd>
          </>
        )}
      </dl>
      {result.warnings && result.warnings.length > 0 && (
        <ul className="plain-list">
          {result.warnings.map((w) => (
            <li key={w} className="warn-text small-text">
              ⚠ {w}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function SsoView() {
  const { notify, track } = useApp();
  const [data, setData] = useState<SsoSettingsResponse | null>(null);
  const [form, setForm] = useState<SsoConfig | null>(null);
  const [secret, setSecret] = useState<SecretEdit>(KEEP_SECRET);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [test, setTest] = useState<SsoTestResult | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    api.ssoSettings().then(
      (r) => {
        setData(r);
        setForm(editable(r.config));
      },
      (e: unknown) => setError(errorMessage(e)),
    );
  }, []);

  if (!data || !form) {
    return (
      <div className="view-page">
        <h1>Single sign-on</h1>
        {error ? <p className="error">{error}</p> : <p className="muted">Loading…</p>}
      </div>
    );
  }

  const env = (field: string) => (data.env_overrides.includes(field) ? (ENV_VAR[field] ?? field.toUpperCase()) : null);
  const set = <K extends keyof SsoConfig>(k: K, v: SsoConfig[K]) => setForm((f) => (f ? { ...f, [k]: v } : f));
  const dirty = JSON.stringify(form) !== JSON.stringify(editable(data.config)) || secret.mode !== "keep";

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      const body: SsoConfig = { ...form };
      const s = secretPayload(secret);
      if (s !== undefined) body.client_secret = s;
      const r = await track(api.saveSsoSettings(body));
      setData(r);
      setForm(editable(r.config));
      setSecret(KEEP_SECRET);
      notify(r.config.enabled ? "Single sign-on settings saved." : "Single sign-on settings saved (SSO is off).");
    } catch (err) {
      // The server explains refusals (e.g. disabling the admin password too early).
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  };

  const runTest = async () => {
    setTesting(true);
    setTest(null);
    try {
      const saved = editable(data.config);
      // Test the typed issuer when it differs from the saved one, otherwise the effective config.
      const candidate =
        form.issuer !== saved.issuer || form.allow_insecure_http !== saved.allow_insecure_http
          ? { issuer: form.issuer, allow_insecure_http: form.allow_insecure_http }
          : undefined;
      setTest(await api.testSso(candidate));
    } catch (err) {
      setTest({ ok: false, error: errorMessage(err) });
    } finally {
      setTesting(false);
    }
  };

  const copyRedirect = async () => {
    try {
      await navigator.clipboard.writeText(data.redirect_url_effective);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      // clipboard unavailable; the URL is selectable
    }
  };

  const canDisableAdmin = form.enabled && !form.allow_password_login && data.sso_admin_signed_in;

  return (
    <div className="view-page">
      <header className="view-head">
        <div>
          <h1>Single sign-on</h1>
          <p className="muted">
            OpenID Connect sign-in (Entra ID, Okta, Keycloak, Google …). Accounts are created on first sign-in and get their role
            from the IdP's groups or roles on every sign-in.
          </p>
        </div>
        <span className={`tag ${data.config.enabled ? "ok" : "off"}`}>{data.config.enabled ? "enabled" : "off"}</span>
      </header>

      <div className="data-grid">
        <form className="card form-stack" onSubmit={(e) => void save(e)}>
          <h2>Identity provider</h2>
          <label className="toggle">
            <input type="checkbox" checked={form.enabled} disabled={!!env("enabled")} onChange={(e) => set("enabled", e.target.checked)} />
            Enable single sign-on {env("enabled") && <span className="tag">env</span>}
          </label>
          <Field label="Button label" env={env("display_name")}>
            <input value={form.display_name} maxLength={64} disabled={!!env("display_name")} onChange={(e) => set("display_name", e.target.value)} />
          </Field>
          <Field
            label="Issuer URL"
            env={env("issuer")}
            help={
              <>
                Must match the <code>issuer</code> of <code>&lt;issuer&gt;/.well-known/openid-configuration</code>, e.g.{" "}
                <code>https://login.microsoftonline.com/&lt;tenant-id&gt;/v2.0</code>.
              </>
            }
          >
            <div className="row gap">
              <input
                type="url"
                value={form.issuer}
                disabled={!!env("issuer")}
                placeholder="https://idp.example.com/realms/corp"
                spellCheck={false}
                onChange={(e) => {
                  set("issuer", e.target.value);
                  setTest(null);
                }}
              />
              <button type="button" onClick={() => void runTest()} disabled={testing || !form.issuer.trim()}>
                {testing ? "Testing…" : "Test discovery"}
              </button>
            </div>
          </Field>
          {test && <TestResult result={test} />}
          <Field label="Client ID" env={env("client_id")}>
            <input value={form.client_id} disabled={!!env("client_id")} spellCheck={false} onChange={(e) => set("client_id", e.target.value)} />
          </Field>
          <SecretField
            label="Client secret"
            isSet={!!data.config.client_secret_set}
            edit={secret}
            onChange={setSecret}
            envNote={env("client_secret") ? "Set by COPPERHOUND_OIDC_CLIENT_SECRET." : undefined}
            help="Optional: without a secret CopperHound acts as a public client (PKCE). Never shown again once saved."
          />
          <Field
            label="Redirect URL"
            env={env("redirect_url")}
            help={
              <>
                Leave empty to derive it from <code>COPPERHOUND_PUBLIC_URL</code> or the address you use. If set, it must end with{" "}
                <code>{data.callback_path}</code>.
              </>
            }
          >
            <input
              value={form.redirect_url}
              disabled={!!env("redirect_url")}
              placeholder={data.redirect_url_effective}
              spellCheck={false}
              onChange={(e) => set("redirect_url", e.target.value)}
            />
          </Field>
          <details className="advanced">
            <summary>Claims and scopes</summary>
            <div className="form-stack">
              <Field label="Scopes" env={env("scopes")} help="openid is always requested.">
                <ListEditor label="Scopes" values={form.scopes} disabled={!!env("scopes")} onChange={(v) => set("scopes", v)} placeholder="e.g. offline_access" />
              </Field>
              <Field label="Username claim" env={env("username_claim")} help="Falls back to email, then sub. Fixed when the account is created.">
                <input value={form.username_claim} disabled={!!env("username_claim")} onChange={(e) => set("username_claim", e.target.value)} />
              </Field>
              <Field
                label="Groups claim"
                env={env("groups_claim")}
                help={
                  <>
                    Comma-separated, dotted paths allowed: <code>groups,roles</code> (Entra groups + app roles), <code>realm_access.roles</code>{" "}
                    (Keycloak).
                  </>
                }
              >
                <input value={form.groups_claim} disabled={!!env("groups_claim")} onChange={(e) => set("groups_claim", e.target.value)} />
              </Field>
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={form.allow_insecure_http}
                  disabled={!!env("allow_insecure_http")}
                  onChange={(e) => set("allow_insecure_http", e.target.checked)}
                />
                Allow a plain http:// issuer (lab use only) {env("allow_insecure_http") && <span className="tag">env</span>}
              </label>
            </div>
          </details>

          <h2>Roles</h2>
          <p className="muted small-text">
            Claim values (group object IDs, group names or app role values; case-insensitive) that grant each role. The highest
            matching role wins, and the role is re-evaluated on every sign-in.
          </p>
          {MAPPED_ROLES.map((r) => {
            const key = `role_mapping.${r}`;
            return (
              <Field key={r} label="" env={env(key)}>
                <div className="role-map">
                  <RoleBadge role={r} />
                  <ListEditor
                    label={`${r} groups`}
                    values={form.role_mapping[r]}
                    disabled={!!env(key)}
                    onChange={(v) => set("role_mapping", { ...form.role_mapping, [r]: v })}
                    placeholder="group id, name or app role"
                  />
                </div>
              </Field>
            );
          })}
          <Field label="Users in no mapped group" env={env("default_role")}>
            <select value={form.default_role} disabled={!!env("default_role")} onChange={(e) => set("default_role", e.target.value as SsoDefaultRole)}>
              <option value="deny">Deny sign-in</option>
              <option value="viewer">Sign in as viewer</option>
              <option value="analyst">Sign in as analyst</option>
            </select>
          </Field>
          <Field
            label="Allowed email domains"
            env={env("allowed_email_domains")}
            help="Optional. When set, the email claim must be in one of these domains (and not marked unverified)."
          >
            <ListEditor
              label="Allowed email domains"
              values={form.allowed_email_domains}
              disabled={!!env("allowed_email_domains")}
              onChange={(v) => set("allowed_email_domains", v)}
              placeholder="corp.example"
              validate={(v) => (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v) ? null : `${v} is not a domain name`)}
            />
          </Field>

          <h2>Password sign-in</h2>
          <label className="toggle">
            <input
              type="checkbox"
              checked={form.allow_password_login}
              disabled={!!env("allow_password_login")}
              onChange={(e) => {
                set("allow_password_login", e.target.checked);
                if (e.target.checked) set("disable_admin_password_login", false);
              }}
            />
            Local accounts may sign in with a password {env("allow_password_login") && <span className="tag">env</span>}
          </label>
          <span className="muted small-text">
            Off: while SSO is enabled, only the built-in <code>admin</code> can use a password. API tokens keep working.
          </span>
          <label className="toggle" title={canDisableAdmin ? undefined : "See the break-glass rules"}>
            <input
              type="checkbox"
              checked={form.disable_admin_password_login}
              disabled={!form.disable_admin_password_login && !canDisableAdmin}
              onChange={(e) => set("disable_admin_password_login", e.target.checked)}
            />
            Also disable the built-in admin's password
          </label>

          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          <div className="row gap">
            <button type="submit" className="primary" disabled={saving || !dirty}>
              {saving ? "Saving…" : "Save"}
            </button>
            {dirty && (
              <button
                type="button"
                onClick={() => {
                  setForm(editable(data.config));
                  setSecret(KEEP_SECRET);
                  setError(null);
                }}
              >
                Discard changes
              </button>
            )}
          </div>
        </form>

        <div className="form-stack">
          <section className="card">
            <h2>Register at the IdP</h2>
            <p className="muted small-text">Add this redirect (reply) URI to the application registration, exactly as shown:</p>
            <div className="row gap">
              <code className="break">{data.redirect_url_effective}</code>
              <button type="button" className="link-btn" onClick={() => void copyRedirect()}>
                {copied ? "copied" : "copy"}
              </button>
            </div>
            <p className="muted small-text">
              Reached through a reverse proxy? Set <code>COPPERHOUND_PUBLIC_URL</code> so this matches the external address.
            </p>
          </section>
          <section className="card">
            <h2>Break-glass access</h2>
            <dl className="fields wide-fields">
              <dt>Admin password</dt>
              <dd>
                {data.admin_password_login ? <span className="tag ok">usable</span> : <span className="tag off">disabled</span>}
              </dd>
              <dt>SSO admin signed in</dt>
              <dd>{data.sso_admin_signed_in ? "yes" : <span className="muted">not yet</span>}</dd>
              <dt title="COPPERHOUND_SSO_BREAK_GLASS">Break-glass env</dt>
              <dd>{data.break_glass_env ? <span className="tag warn">set: admin password forced on</span> : <span className="muted">not set</span>}</dd>
            </dl>
            <p className="small-text">
              The built-in <code>admin</code> can always use its password unless <em>all</em> of these hold: SSO is enabled,
              password sign-in for local accounts is off, “Also disable the built-in admin's password” is on, an SSO account with
              the admin role has signed in at least once, and <code>COPPERHOUND_SSO_BREAK_GLASS</code> is not set.
            </p>
            <p className="muted small-text">
              Disabling SSO, or disabling / demoting the last SSO admin, restores the admin password automatically. If the IdP is
              down, set <code>COPPERHOUND_SSO_BREAK_GLASS=1</code> and restart. SSO accounts are listed under{" "}
              <a href={routeHref("admin", "users")}>Users</a>; sign-ins and failures are in the{" "}
              <a href={routeHref("admin", "audit")}>audit log</a>.
            </p>
          </section>
        </div>
      </div>
      <SamlSettings />
    </div>
  );
}
