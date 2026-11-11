// SAML 2.0 sign-on settings (GET/PUT /settings/saml), shown on the SSO page
// next to OpenID Connect.

import { useEffect, useState, type FormEvent } from "react";
import { api, errorMessage } from "../../api/client";
import type { SsoMappedRole, SamlConfig, SamlSettingsResponse, SsoDefaultRole } from "../../api/types";
import { ListEditor } from "../../components/ListEditor";
import { useApp } from "../../state/AppContext";
import { RoleBadge } from "../../state/SessionContext";

const MAPPED_ROLES: SsoMappedRole[] = ["admin", "analyst", "viewer"];

function Copyable({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="row gap">
      <code className="break">{value}</code>
      <button
        type="button"
        className="link-btn"
        onClick={() => {
          navigator.clipboard.writeText(value).then(
            () => {
              setCopied(true);
              window.setTimeout(() => setCopied(false), 1200);
            },
            () => undefined,
          );
        }}
      >
        {copied ? "copied" : "copy"}
      </button>
    </div>
  );
}

export function SamlSettings() {
  const { notify, track } = useApp();
  const [data, setData] = useState<SamlSettingsResponse | null>(null);
  const [form, setForm] = useState<SamlConfig | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api.samlSettings().then(
      (r) => {
        setData(r);
        setForm(r.config);
      },
      (e: unknown) => setError(errorMessage(e)),
    );
  }, []);

  if (!data || !form) {
    return <section className="card">{error ? <p className="error">{error}</p> : <p className="muted">Loading SAML settings…</p>}</section>;
  }
  const set = <K extends keyof SamlConfig>(k: K, v: SamlConfig[K]) => setForm((f) => (f ? { ...f, [k]: v } : f));
  const dirty = JSON.stringify(form) !== JSON.stringify(data.config);

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      const r = await track(api.saveSamlSettings(form));
      setData(r);
      setForm(r.config);
      notify(r.config.enabled ? "SAML settings saved." : "SAML settings saved (SAML is off).");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="data-grid saml-settings">
      <form className="card form-stack" onSubmit={(e) => void save(e)}>
        <header className="row gap wrap">
          <h2>SAML 2.0</h2>
          <span className={`tag ${data.config.enabled ? "ok" : "off"}`}>{data.config.enabled ? "enabled" : "off"}</span>
        </header>
        <p className="muted small-text">
          For identity providers without OpenID Connect (AD FS, Shibboleth, PingFederate …). Responses must be signed (RSA-SHA256 or
          stronger) and unencrypted; sign-in starts at CopperHound (IdP-initiated sign-in is refused).
        </p>
        <label className="toggle">
          <input type="checkbox" checked={form.enabled} onChange={(e) => set("enabled", e.target.checked)} />
          Enable SAML sign-on
        </label>
        <label className="form-field">
          <span className="field-title">Button label</span>
          <input value={form.display_name} maxLength={64} onChange={(e) => set("display_name", e.target.value)} />
        </label>
        <label className="form-field">
          <span className="field-title">IdP metadata XML</span>
          <textarea
            className="mono"
            rows={6}
            spellCheck={false}
            placeholder='<md:EntityDescriptor entityID="…">…</md:EntityDescriptor>'
            value={form.idp_metadata}
            onChange={(e) => set("idp_metadata", e.target.value)}
          />
          <span className="muted small-text">Download it from the IdP (federation metadata) and paste it here; it supplies the entity ID, the sign-in URL and the signing certificates.</span>
        </label>
        {data.idp && (
          <dl className="fields wide-fields">
            <dt>IdP entity ID</dt>
            <dd>
              <code className="break">{data.idp.entity_id}</code>
            </dd>
            <dt>Sign-in URL</dt>
            <dd>
              <code className="break">{data.idp.sso_url}</code>
            </dd>
            <dt>Signing certificates</dt>
            <dd>
              {data.idp.certificates.map((c) => (
                <code key={c} className="break small-text" title="SHA-256 fingerprint">
                  {c}
                </code>
              ))}
            </dd>
          </dl>
        )}
        <details className="advanced">
          <summary>Attributes and endpoints</summary>
          <div className="form-stack">
            <label className="form-field">
              <span className="field-title">Username attribute</span>
              <input value={form.username_attribute} placeholder="NameID" onChange={(e) => set("username_attribute", e.target.value)} />
              <span className="muted small-text">Empty: the NameID. Fixed when the account is created.</span>
            </label>
            <label className="form-field">
              <span className="field-title">Groups attribute(s)</span>
              <input value={form.groups_attribute} onChange={(e) => set("groups_attribute", e.target.value)} />
              <span className="muted small-text">Comma-separated attribute names (or friendly names).</span>
            </label>
            <label className="form-field">
              <span className="field-title">E-mail attribute(s)</span>
              <input value={form.email_attribute} onChange={(e) => set("email_attribute", e.target.value)} />
            </label>
            <label className="form-field">
              <span className="field-title">SP entity ID</span>
              <input value={form.sp_entity_id} placeholder={data.sp_entity_id_effective} spellCheck={false} onChange={(e) => set("sp_entity_id", e.target.value)} />
            </label>
            <label className="form-field">
              <span className="field-title">ACS URL</span>
              <input value={form.acs_url} placeholder={data.acs_url_effective} spellCheck={false} onChange={(e) => set("acs_url", e.target.value)} />
            </label>
          </div>
        </details>
        <h3>Roles</h3>
        {MAPPED_ROLES.map((r) => (
          <div key={r} className="role-map">
            <RoleBadge role={r} />
            <ListEditor
              label={`${r} groups (SAML)`}
              values={form.role_mapping[r]}
              onChange={(v) => set("role_mapping", { ...form.role_mapping, [r]: v })}
              placeholder="group value"
            />
          </div>
        ))}
        <label className="form-field">
          <span className="field-title">Users in no mapped group</span>
          <select value={form.default_role} onChange={(e) => set("default_role", e.target.value as SsoDefaultRole)}>
            <option value="deny">Deny sign-in</option>
            <option value="viewer">Sign in as viewer</option>
            <option value="analyst">Sign in as analyst</option>
          </select>
        </label>
        <div className="form-field">
          <span className="field-title">Allowed email domains</span>
          <ListEditor
            label="Allowed email domains (SAML)"
            values={form.allowed_email_domains}
            onChange={(v) => set("allowed_email_domains", v)}
            placeholder="corp.example"
            validate={(v) => (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v) ? null : `${v} is not a domain name`)}
          />
        </div>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <div className="row gap">
          <button type="submit" className="primary" disabled={saving || !dirty}>
            {saving ? "Saving…" : "Save SAML settings"}
          </button>
          {dirty && (
            <button type="button" onClick={() => setForm(data.config)}>
              Discard changes
            </button>
          )}
        </div>
      </form>
      <section className="card form-stack">
        <h2>Register at the IdP</h2>
        <p className="muted small-text">Give the IdP these values (or the metadata URL):</p>
        <span className="field-title">SP metadata</span>
        <Copyable value={data.metadata_url} />
        <span className="field-title">Entity ID (audience)</span>
        <Copyable value={data.sp_entity_id_effective} />
        <span className="field-title">Assertion consumer service (HTTP-POST)</span>
        <Copyable value={data.acs_url_effective} />
        <p className="muted small-text">
          Sign-in needs HTTPS (or <code>localhost</code>): the IdP posts the response back cross-site, and browsers only send the
          sign-in cookie with it on secure origins. The password sign-in rules above apply while SAML is enabled.
        </p>
      </section>
    </div>
  );
}
