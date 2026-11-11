import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { api, errorMessage } from "../../../api/client";
import { WEEKDAYS, type ChannelOut, type ReportFormat, type Schedule, type ScheduleInput, type ScheduleWhen, type Weekday } from "../../../api/types";
import { Modal } from "../../../components/Modal";
import { NumberField } from "../../../components/NumberField";
import { EmptyState } from "../../../components/StatusView";
import { useApp } from "../../../state/AppContext";
import { when as fmtWhen } from "../../../util/format";
import { ChannelChecklist, DeliveryList, localHint, RunStatusTag, WEEKDAY_LABEL, whenText } from "./parts";

const IDLE_POLL_MS = 15_000;
const ACTIVE_POLL_MS = 2_000;

const NEW_SCHEDULE: ScheduleInput = {
  name: "",
  enabled: true,
  when: { kind: "weekly", weekday: "mon", at: "07:00" },
  format: "html",
  title: "",
  plan_steps: 10,
  channels: [],
};

function inputOf(s: Schedule): ScheduleInput {
  return { name: s.name, enabled: s.enabled, when: s.when, format: s.format, title: s.title, plan_steps: s.plan_steps, channels: s.channels };
}

function ScheduleDialog({
  initial,
  isNew,
  channels,
  onClose,
  onSave,
}: {
  initial: ScheduleInput;
  isNew: boolean;
  channels: ChannelOut[];
  onClose: () => void;
  onSave: (s: ScheduleInput) => Promise<void>;
}) {
  const [s, setS] = useState<ScheduleInput>(initial);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = <K extends keyof ScheduleInput>(k: K, v: ScheduleInput[K]) => setS((x) => ({ ...x, [k]: v }));
  const at = s.when.kind === "interval" ? "07:00" : s.when.at;

  const setKind = (kind: ScheduleWhen["kind"]) => {
    if (kind === "interval") set("when", { kind, hours: s.when.kind === "interval" ? s.when.hours : 24 });
    else if (kind === "daily") set("when", { kind, at });
    else set("when", { kind, at, weekday: s.when.kind === "weekly" ? s.when.weekday : "mon" });
  };
  const hint = localHint(s.when);
  const hasEmail = s.channels.some((id) => channels.find((c) => c.id === id)?.type === "email");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onSave({ ...s, name: s.name.trim() });
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  };

  return (
    <Modal title={isNew ? "New scheduled report" : `Edit ${initial.name}`} onClose={onClose} wide>
      <form className="form-stack" onSubmit={(e) => void submit(e)}>
        <div className="form-grid">
          <label htmlFor="sc-name">Name</label>
          <input id="sc-name" value={s.name} maxLength={100} required autoFocus={isNew} onChange={(e) => set("name", e.target.value)} />
          <label htmlFor="sc-kind">Repeat</label>
          <select id="sc-kind" value={s.when.kind} onChange={(e) => setKind(e.target.value as ScheduleWhen["kind"])}>
            <option value="daily">Daily</option>
            <option value="weekly">Weekly</option>
            <option value="interval">Every N hours</option>
          </select>
          {s.when.kind === "weekly" && (
            <>
              <label htmlFor="sc-day">Day (UTC)</label>
              <select id="sc-day" value={s.when.weekday} onChange={(e) => set("when", { kind: "weekly", at, weekday: e.target.value as Weekday })}>
                {WEEKDAYS.map((d) => (
                  <option key={d} value={d}>
                    {WEEKDAY_LABEL[d]}
                  </option>
                ))}
              </select>
            </>
          )}
          {s.when.kind !== "interval" ? (
            <>
              <label htmlFor="sc-at">Time (UTC)</label>
              <input
                id="sc-at"
                type="time"
                value={at}
                required
                onChange={(e) =>
                  set("when", s.when.kind === "weekly" ? { kind: "weekly", weekday: s.when.weekday, at: e.target.value } : { kind: "daily", at: e.target.value })
                }
              />
            </>
          ) : (
            <>
              <label htmlFor="sc-hours">Hours</label>
              <NumberField id="sc-hours" min={1} max={744} value={s.when.hours} onCommit={(v) => set("when", { kind: "interval", hours: Math.round(v) })} />
            </>
          )}
        </div>
        <span className="muted small-text">
          {s.when.kind === "interval"
            ? "Counted from the previous run (a manual run also restarts the interval)."
            : `Times are UTC${hint ? ` — that is ${hint}` : ""}.`}
        </span>
        <ChannelChecklist legend="Send to" channels={channels} selected={s.channels} onChange={(ids) => set("channels", ids)} />
        <div className="form-grid">
          <label htmlFor="sc-title">Title</label>
          <input id="sc-title" value={s.title} maxLength={200} placeholder={s.name || "defaults to the name"} onChange={(e) => set("title", e.target.value)} />
          <label htmlFor="sc-format">Attachment</label>
          <select id="sc-format" value={s.format} onChange={(e) => set("format", e.target.value as ReportFormat)}>
            <option value="html">HTML report</option>
            <option value="md">Markdown report</option>
            <option value="csv">CSV (one row per finding item)</option>
          </select>
          <label htmlFor="sc-steps">Plan steps</label>
          <NumberField id="sc-steps" min={0} max={50} value={s.plan_steps} onCommit={(v) => set("plan_steps", Math.round(v))} />
        </div>
        <span className="muted small-text">
          Every channel gets the grade, exposure, finding counts, top findings and the change since the previous snapshot. The
          full report (with {s.plan_steps} remediation-plan steps) is attached to emails only
          {hasEmail ? "." : " — none of the selected channels is email."}
        </span>
        <label className="toggle">
          <input type="checkbox" checked={s.enabled} onChange={(e) => set("enabled", e.target.checked)} />
          Enabled
        </label>
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
          <button type="submit" className="primary" disabled={busy || !s.name.trim()}>
            {busy ? "Saving…" : "Save schedule"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function SchedulesTab({ channels }: { channels: ChannelOut[] }) {
  const { notify, track } = useApp();
  const [schedules, setSchedules] = useState<Schedule[] | null>(null);
  const [publicUrl, setPublicUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<Schedule | "new" | null>(null);
  /** Schedules whose manual run was requested but not yet seen finishing. */
  const [awaiting, setAwaiting] = useState<Record<string, string | null>>({});
  const awaitingRef = useRef(awaiting);
  const live = useRef(true);

  const load = useCallback(() => {
    api.schedules().then(
      (r) => {
        if (!live.current) return;
        setSchedules(r.schedules);
        setPublicUrl(r.public_url);
        setError(null);
        // A run is done once the schedule is no longer running and last_run moved on.
        const done = r.schedules.filter((s) => s.id in awaitingRef.current && !s.running && s.last_run !== awaitingRef.current[s.id]);
        if (done.length === 0) return;
        const next = { ...awaitingRef.current };
        for (const s of done) {
          delete next[s.id];
          if (s.last_status) notify(`${s.name}: ${s.last_status}${s.last_error ? ` — ${s.last_error}` : ""}`, s.last_status === "ok" ? "info" : "warn");
        }
        awaitingRef.current = next;
        setAwaiting(next);
      },
      (e: unknown) => live.current && setError(errorMessage(e)),
    );
  }, [notify]);

  useEffect(() => {
    live.current = true;
    load();
    return () => {
      live.current = false;
    };
  }, [load]);

  const busy = Object.keys(awaiting).length > 0 || (schedules ?? []).some((s) => s.running);
  useEffect(() => {
    const t = window.setInterval(load, busy ? ACTIVE_POLL_MS : IDLE_POLL_MS);
    return () => window.clearInterval(t);
  }, [busy, load]);

  const save = async (input: ScheduleInput) => {
    if (editing === "new") await track(api.createSchedule(input));
    else if (editing) await track(api.updateSchedule(editing.id, input));
    setEditing(null);
    notify(`Schedule ${input.name} saved.`);
    load();
  };

  const toggle = async (s: Schedule) => {
    try {
      await track(api.updateSchedule(s.id, { ...inputOf(s), enabled: !s.enabled }));
      load();
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  const remove = async (s: Schedule) => {
    if (!window.confirm(`Delete schedule ${s.name}?`)) return;
    try {
      await track(api.deleteSchedule(s.id));
      load();
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  const runNow = async (s: Schedule) => {
    try {
      await api.runSchedule(s.id);
      awaitingRef.current = { ...awaitingRef.current, [s.id]: s.last_run };
      setAwaiting(awaitingRef.current);
      setSchedules((xs) => xs?.map((x) => (x.id === s.id ? { ...x, running: true } : x)) ?? null);
      notify(`${s.name}: run started.`);
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  return (
    <>
      <div className="section-head">
        <p className="muted small-text">
          Scheduled posture reports. Times are UTC; your browser's local time is shown next to them.
          {!publicUrl && (
            <>
              {" "}
              Set <code>COPPERHOUND_PUBLIC_URL</code> to include a link back to CopperHound in messages.
            </>
          )}
        </p>
        <button type="button" className="primary" onClick={() => setEditing("new")} disabled={channels.length === 0} title={channels.length === 0 ? "Add a channel first" : undefined}>
          New schedule
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      {!schedules && !error && <p className="muted">Loading schedules…</p>}
      {schedules && schedules.length === 0 && (
        <EmptyState title="No scheduled reports">E.g. a weekly posture summary to the SOC channel and an HTML report by email.</EmptyState>
      )}
      {schedules && schedules.length > 0 && (
        <div className="table-card">
          <table className="data-table schedules-table">
            <thead>
              <tr>
                <th>Schedule</th>
                <th>When</th>
                <th>Channels</th>
                <th>Enabled</th>
                <th>Next run</th>
                <th>Last run</th>
                <th>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {schedules.map((s) => {
                const hint = localHint(s.when);
                const running = s.running || s.id in awaiting;
                return (
                  <tr key={s.id} className={s.enabled ? "" : "row-disabled"}>
                    <td>
                      <strong>{s.name}</strong>
                      <div className="muted small-text">
                        {s.format.toUpperCase()} · {s.plan_steps} plan steps
                      </div>
                    </td>
                    <td className="nowrap">
                      {whenText(s.when)}
                      {hint && <div className="muted small-text">{hint}</div>}
                    </td>
                    <td>
                      {s.channels.map((id) => {
                        const c = channels.find((x) => x.id === id);
                        return (
                          <span key={id} className={`tag ${c ? (c.enabled ? "" : "off") : "off"}`} title={c ? (c.enabled ? c.type : "disabled") : "deleted channel"}>
                            {c?.name ?? id}
                          </span>
                        );
                      })}
                    </td>
                    <td>
                      <label className="toggle">
                        <input type="checkbox" checked={s.enabled} onChange={() => void toggle(s)} aria-label={`Enable ${s.name}`} />
                      </label>
                    </td>
                    <td className="nowrap">{s.enabled ? fmtWhen(s.next_run) : <span className="muted">—</span>}</td>
                    <td>
                      {running ? (
                        <span className="tag state-running">
                          <span className="spinner small" aria-hidden="true" /> running
                        </span>
                      ) : (
                        <>
                          <RunStatusTag status={s.last_status} /> <span className="small-text nowrap">{s.last_run ? fmtWhen(s.last_run) : ""}</span>
                          {s.last_error && <div className="error small-text">{s.last_error}</div>}
                          {s.last_deliveries.length > 0 && (
                            <details className="deliveries">
                              <summary className="small-text">deliveries</summary>
                              <DeliveryList deliveries={s.last_deliveries} />
                            </details>
                          )}
                        </>
                      )}
                    </td>
                    <td className="row-actions">
                      <button type="button" className="small" disabled={running} onClick={() => void runNow(s)}>
                        Run now
                      </button>
                      <button type="button" className="small" onClick={() => setEditing(s)}>
                        Edit
                      </button>
                      <button type="button" className="small danger" onClick={() => void remove(s)}>
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
        A run without a finished analysis (no graph yet, or still computing) is recorded as <em>skipped</em>; <em>partial</em>{" "}
        means some channels failed.
      </p>
      {editing && (
        <ScheduleDialog
          initial={editing === "new" ? NEW_SCHEDULE : inputOf(editing)}
          isNew={editing === "new"}
          channels={channels}
          onClose={() => setEditing(null)}
          onSave={save}
        />
      )}
    </>
  );
}
