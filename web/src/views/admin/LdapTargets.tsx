// Admin → Collectors → built-in LDAP collection: targets (DCs) the server
// reads itself on a schedule (GET/PUT /collect/ldap).

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, errorMessage } from "../../api/client";
import type { LdapTarget, LdapTargetInput } from "../../api/types";
import { Modal } from "../../components/Modal";
import { useApp } from "../../state/AppContext";

const EMPTY: LdapTargetInput = {
  name: "",
  enabled: true,
  url: "ldaps://",
  starttls: false,
  allow_plain: false,
  insecure_skip_verify: false,
  bind_dn: "",
  password: "",
  base_dn: "",
  include_configuration: true,
  interval_hours: 24,
};

function Editor({ initial, onClose, onSaved }: { initial: LdapTargetInput; onClose: () => void; onSaved: () => void }) {
  const { track } = useApp();
  const [f, setF] = useState<LdapTargetInput>(initial);
  const [error, setError] = useState<string | null>(null);
  const set = <K extends keyof LdapTargetInput>(k: K, v: LdapTargetInput[K]) => setF((x) => ({ ...x, [k]: v }));
  const save = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await track(api.saveLdapTarget({ ...f, password: f.password || null }));
      onSaved();
    } catch (err) {
      setError(errorMessage(err));
    }
  };
  return (
    <Modal title={initial.id ? `Edit ${initial.name}` : "Add LDAP target"} onClose={onClose}>
      <form className="form-stack" onSubmit={(e) => void save(e)}>
        <label className="form-field">
          <span className="field-title">Name</span>
          <input value={f.name} onChange={(e) => set("name", e.target.value)} placeholder="corp.local" required maxLength={64} />
        </label>
        <label className="form-field">
          <span className="field-title">Domain controller URL</span>
          <input value={f.url} onChange={(e) => set("url", e.target.value)} placeholder="ldaps://dc01.corp.local" required spellCheck={false} />
        </label>
        <label className="toggle">
          <input type="checkbox" checked={f.starttls} onChange={(e) => set("starttls", e.target.checked)} />
          StartTLS (for ldap:// on port 389)
        </label>
        <label className="form-field">
          <span className="field-title">Bind account (read-only)</span>
          <input value={f.bind_dn} onChange={(e) => set("bind_dn", e.target.value)} placeholder="svc-copperhound@corp.local" required spellCheck={false} />
        </label>
        <label className="form-field">
          <span className="field-title">Password</span>
          <input
            type="password"
            value={f.password ?? ""}
            onChange={(e) => set("password", e.target.value)}
            placeholder={initial.id ? "unchanged" : ""}
            required={!initial.id}
            autoComplete="new-password"
          />
        </label>
        <details className="advanced">
          <summary>More options</summary>
          <div className="form-stack">
            <label className="form-field">
              <span className="field-title">Base DN</span>
              <input value={f.base_dn} onChange={(e) => set("base_dn", e.target.value)} placeholder="from the RootDSE" spellCheck={false} />
            </label>
            <label className="toggle">
              <input type="checkbox" checked={f.include_configuration} onChange={(e) => set("include_configuration", e.target.checked)} />
              Also read the configuration partition (ADCS, sites, trusts' forest data)
            </label>
            <label className="toggle">
              <input type="checkbox" checked={f.insecure_skip_verify} onChange={(e) => set("insecure_skip_verify", e.target.checked)} />
              Do not verify the DC certificate (lab only)
            </label>
            <label className="toggle">
              <input type="checkbox" checked={f.allow_plain} onChange={(e) => set("allow_plain", e.target.checked)} />
              Allow plain LDAP without TLS (lab only; sends the password in clear)
            </label>
          </div>
        </details>
        <label className="form-field">
          <span className="field-title">Collect every (hours, 0 = manual only)</span>
          <input type="number" min={0} max={744} value={f.interval_hours} onChange={(e) => set("interval_hours", Number(e.target.value) || 0)} />
        </label>
        <label className="toggle">
          <input type="checkbox" checked={f.enabled} onChange={(e) => set("enabled", e.target.checked)} />
          Enabled
        </label>
        {error && <p className="error">{error}</p>}
        <div className="row gap">
          <button type="submit" className="primary">
            Save
          </button>
          <button type="button" onClick={onClose}>
            Cancel
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function LdapTargets() {
  const { notify, track } = useApp();
  const [list, setList] = useState<LdapTarget[] | null>(null);
  const [edit, setEdit] = useState<LdapTargetInput | null>(null);
  const load = useCallback(() => {
    api.ldapTargets().then(setList, () => setList([]));
  }, []);
  useEffect(() => {
    load();
    const t = window.setInterval(load, 15_000);
    return () => window.clearInterval(t);
  }, [load]);

  const act = async (f: () => Promise<unknown>, ok: string) => {
    try {
      await track(f());
      notify(ok);
      load();
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  return (
    <section className="card form-stack">
      <div className="row gap wrap">
        <h2>Built-in LDAP collection</h2>
        <span className="spacer" />
        <button type="button" onClick={() => setEdit(EMPTY)}>
          Add LDAP target
        </button>
      </div>
      <p className="muted small-text">
        CopperHound reads a domain controller itself — users, groups, computers, ACLs, GPOs, trusts and ADCS — with a read-only
        account over LDAPS, and ingests the result. Nothing to install. Sessions and local groups are not in LDAP; use SharpHound
        for those.
      </p>
      {list && list.length > 0 && (
        <table className="data-table compact">
          <thead>
            <tr>
              <th>Name</th>
              <th>Server</th>
              <th>Schedule</th>
              <th>Last run</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {list.map((t) => (
              <tr key={t.id}>
                <td>
                  {t.name} {!t.enabled && <span className="tag off">off</span>}
                </td>
                <td>
                  <code>{t.url}</code>
                </td>
                <td>{t.interval_hours > 0 ? `every ${t.interval_hours} h` : "manual"}</td>
                <td>
                  {t.running ? (
                    <span className="tag">running…</span>
                  ) : t.last_error ? (
                    <span className="error small-text" title={t.last_error}>
                      failed: {t.last_error.slice(0, 80)}
                    </span>
                  ) : t.last_ok ? (
                    <span className="small-text">
                      {t.last_ok.slice(0, 16).replace("T", " ")} · {t.last_objects.toLocaleString()} objects · {t.last_seconds}s
                    </span>
                  ) : (
                    <span className="muted">never</span>
                  )}
                </td>
                <td className="row-actions">
                  <button
                    type="button"
                    className="small"
                    onClick={() =>
                      void (async () => {
                        try {
                          const r = await track(api.testLdapTarget(t.id));
                          notify(r.ok ? `Connected: ${r.dns_host_name ?? ""} (${r.default_naming_context ?? ""})` : `Test failed: ${r.error}`, r.ok ? "info" : "error");
                        } catch (e) {
                          notify(errorMessage(e), "error");
                        }
                      })()
                    }
                  >
                    Test
                  </button>
                  <button type="button" className="small" disabled={t.running} onClick={() => void act(() => api.runLdapTarget(t.id), `Collecting ${t.name}…`)}>
                    Collect now
                  </button>
                  <button type="button" className="small" onClick={() => setEdit({ ...t, password: "" })}>
                    Edit
                  </button>
                  <button
                    type="button"
                    className="small danger"
                    onClick={() => window.confirm(`Remove ${t.name}?`) && void act(() => api.deleteLdapTarget(t.id), `${t.name} removed.`)}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {edit && (
        <Editor
          initial={edit}
          onClose={() => setEdit(null)}
          onSaved={() => {
            setEdit(null);
            notify("LDAP target saved.");
            load();
          }}
        />
      )}
    </section>
  );
}
