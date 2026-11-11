import { useEffect, useState, type FormEvent } from "react";
import { api, errorMessage } from "../../../api/client";
import { SEVERITIES, type AlertRules, type ChannelOut } from "../../../api/types";
import { NumberField } from "../../../components/NumberField";
import { routeHref } from "../../../hooks/useRoute";
import { useApp } from "../../../state/AppContext";
import { SEVERITY_LABEL } from "../../findings/findingParts";
import { ChannelChecklist } from "./parts";

export function AlertRulesTab({ channels }: { channels: ChannelOut[] }) {
  const { notify, track } = useApp();
  const [saved, setSaved] = useState<AlertRules | null>(null);
  const [form, setForm] = useState<AlertRules | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Remember the last number while a threshold is switched off (null = rule off).
  const [lastPoints, setLastPoints] = useState(5);
  const [lastMin, setLastMin] = useState(10);
  const [watchText, setWatchText] = useState("");

  useEffect(() => {
    api.alertRules().then(
      (r) => {
        setSaved(r);
        setForm(r);
        if (r.exposure_increase_points !== null) setLastPoints(r.exposure_increase_points);
        if (r.new_tier0_principals_min !== null) setLastMin(r.new_tier0_principals_min);
        setWatchText((r.watch ?? []).join("\n"));
      },
      (e: unknown) => setError(errorMessage(e)),
    );
  }, []);

  if (!form || !saved) return error ? <p className="error">{error}</p> : <p className="muted">Loading alert rules…</p>;
  const set = <K extends keyof AlertRules>(k: K, v: AlertRules[K]) => setForm((f) => (f ? { ...f, [k]: v } : f));
  const dirty = JSON.stringify(form) !== JSON.stringify(saved);
  const anyRule =
    form.grade_worse ||
    form.exposure_increase_points !== null ||
    form.new_finding_severities.length > 0 ||
    form.new_tier0_principals_min !== null ||
    form.choke_points_changed ||
    form.watch.length > 0;

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await track(api.saveAlertRules(form));
      setSaved(r);
      setForm(r);
      notify(r.enabled ? "Alert rules saved; they apply from the next ingest." : "Alert rules saved (alerts are off).");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="card form-stack narrow-form" onSubmit={(e) => void save(e)}>
      <p className="muted small-text">
        After every ingest that produces a new posture snapshot, CopperHound compares it with the previous one and alerts when
        any enabled rule fires. Past alerts are in <a href={routeHref("alerts")}>Alerts</a> (visible to analysts).
      </p>
      <label className="toggle">
        <input type="checkbox" checked={form.enabled} onChange={(e) => set("enabled", e.target.checked)} />
        <strong>Send change alerts</strong>
      </label>
      <ChannelChecklist legend="Send to" channels={channels} selected={form.channels} onChange={(ids) => set("channels", ids)} />
      {form.enabled && form.channels.length === 0 && <span className="warn-text small-text">Choose at least one channel.</span>}

      <fieldset className="rule-list">
        <legend>Alert when</legend>
        <label className="check">
          <input type="checkbox" checked={form.grade_worse} onChange={(e) => set("grade_worse", e.target.checked)} />
          the posture grade gets worse (e.g. B → C)
        </label>
        <div className="rule-row">
          <label className="check">
            <input
              type="checkbox"
              checked={form.exposure_increase_points !== null}
              onChange={(e) => set("exposure_increase_points", e.target.checked ? lastPoints : null)}
            />
            exposure rises by at least
          </label>
          <NumberField
            min={0}
            max={100}
            step={0.5}
            value={form.exposure_increase_points ?? lastPoints}
            onCommit={(v) => {
              setLastPoints(v);
              set("exposure_increase_points", v);
            }}
          />
          <span>percentage points</span>
        </div>
        <div className="rule-row">
          <span>a finding type appears that had no items before, with severity</span>
          {SEVERITIES.map((s) => (
            <label key={s} className="check">
              <input
                type="checkbox"
                checked={form.new_finding_severities.includes(s)}
                onChange={(e) =>
                  set(
                    "new_finding_severities",
                    e.target.checked ? SEVERITIES.filter((x) => x === s || form.new_finding_severities.includes(x)) : form.new_finding_severities.filter((x) => x !== s),
                  )
                }
              />
              <span className={`sev-text sev-${s}`}>{SEVERITY_LABEL[s]}</span>
            </label>
          ))}
        </div>
        <div className="rule-row">
          <label className="check">
            <input
              type="checkbox"
              checked={form.new_tier0_principals_min !== null}
              onChange={(e) => set("new_tier0_principals_min", e.target.checked ? lastMin : null)}
            />
            at least
          </label>
          <NumberField
            min={1}
            max={100000000}
            value={form.new_tier0_principals_min ?? lastMin}
            onCommit={(v) => {
              setLastMin(Math.round(v));
              set("new_tier0_principals_min", Math.round(v));
            }}
          />
          <span>principals newly have a path to Tier Zero</span>
        </div>
        <div className="rule-row">
          <label className="check">
            <input type="checkbox" checked={form.choke_points_changed} onChange={(e) => set("choke_points_changed", e.target.checked)} />
            the top
          </label>
          <NumberField min={1} max={100} value={form.choke_points_top} onCommit={(v) => set("choke_points_top", Math.round(v))} />
          <span>choke points change</span>
        </div>
        <label className="rule-block">
          <span>
            any of these principals or groups gains an attack path to Tier Zero (one object id or name per line; the alert draws the path)
          </span>
          <textarea
            rows={3}
            spellCheck={false}
            value={watchText}
            placeholder={"SVC_BACKUP@CORP.LOCAL\nS-1-5-21-…-1105"}
            onChange={(e) => {
              setWatchText(e.target.value);
              set(
                "watch",
                e.target.value
                  .split("\n")
                  .map((l) => l.trim())
                  .filter(Boolean),
              );
            }}
          />
        </label>
      </fieldset>
      {!anyRule && <span className="warn-text small-text">No rule is selected, so no alert can fire.</span>}
      <p className="muted small-text">
        The first ingest has nothing to compare with. The Tier Zero and choke-point rules need state saved by a previous ingest,
        so they start working from the second ingest after an upgrade.
      </p>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div className="row gap">
        <button type="submit" className="primary" disabled={busy || !dirty}>
          {busy ? "Saving…" : "Save rules"}
        </button>
        {dirty && (
          <button
            type="button"
            onClick={() => {
              setForm(saved);
              setWatchText(saved.watch.join("\n"));
            }}
          >
            Discard changes
          </button>
        )}
      </div>
    </form>
  );
}
