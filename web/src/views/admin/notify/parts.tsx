import type { ChannelOut, Delivery, RunStatus, ScheduleWhen, Weekday } from "../../../api/types";
import { WEEKDAYS } from "../../../api/types";

/** One delivery outcome: ok / failed with the error and attempts in the tooltip. */
export function DeliveryChip({ d, showName }: { d: Delivery; showName?: boolean }) {
  const attempts = d.attempts && d.attempts > 1 ? ` after ${d.attempts} attempts` : "";
  const title = d.ok ? `Delivered${attempts}` : `${d.error ?? "failed"}${attempts}`;
  return (
    <span className={`delivery ${d.ok ? "ok" : "failed"}`} title={title}>
      <span aria-hidden="true">{d.ok ? "✓" : "✕"}</span> {showName && <strong>{d.name ?? d.channel}</strong>}{" "}
      {d.ok ? "delivered" : (d.error ?? "failed")}
    </span>
  );
}

export function DeliveryList({ deliveries }: { deliveries: Delivery[] }) {
  if (deliveries.length === 0) return <span className="muted small-text">no deliveries</span>;
  return (
    <ul className="plain-list delivery-list">
      {deliveries.map((d, i) => (
        <li key={`${d.channel}-${i}`}>
          <DeliveryChip d={d} showName />
        </li>
      ))}
    </ul>
  );
}

const STATUS_CLASS: Record<RunStatus, string> = { ok: "ok", partial: "warn", failed: "off", skipped: "" };

export function RunStatusTag({ status }: { status: RunStatus | null }) {
  if (!status) return <span className="muted small-text">never run</span>;
  return <span className={`tag ${STATUS_CLASS[status]}`}>{status}</span>;
}

/** Checkbox list of channels (disabled ones flagged); ids of deleted channels are kept visible. */
export function ChannelChecklist({
  channels,
  selected,
  onChange,
  legend,
}: {
  channels: ChannelOut[];
  selected: string[];
  onChange: (ids: string[]) => void;
  legend: string;
}) {
  const unknown = selected.filter((id) => !channels.some((c) => c.id === id));
  return (
    <fieldset className="channel-checklist">
      <legend>{legend}</legend>
      {channels.length === 0 && <span className="muted small-text">No channels configured yet (Channels tab).</span>}
      {channels.map((c) => (
        <label key={c.id} className="check">
          <input
            type="checkbox"
            checked={selected.includes(c.id)}
            onChange={(e) => onChange(e.target.checked ? [...selected, c.id] : selected.filter((x) => x !== c.id))}
          />
          {c.name} <span className="muted small-text">({c.type})</span>
          {!c.enabled && <span className="tag off small-tag">disabled</span>}
        </label>
      ))}
      {unknown.map((id) => (
        <label key={id} className="check">
          <input type="checkbox" checked onChange={() => onChange(selected.filter((x) => x !== id))} />
          <code>{id}</code> <span className="tag off small-tag">deleted channel</span>
        </label>
      ))}
    </fieldset>
  );
}

const WEEKDAY_LABEL: Record<Weekday, string> = {
  mon: "Monday",
  tue: "Tuesday",
  wed: "Wednesday",
  thu: "Thursday",
  fri: "Friday",
  sat: "Saturday",
  sun: "Sunday",
};
export { WEEKDAY_LABEL };

/** Next UTC occurrence of a daily/weekly time, as a Date (for local-time hints). */
function nextOccurrence(at: string, weekday?: Weekday): Date | null {
  const m = /^(\d{1,2}):(\d{2})$/.exec(at);
  if (!m) return null;
  const now = new Date();
  let t = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), Number(m[1]), Number(m[2]));
  if (weekday) {
    const today = (now.getUTCDay() + 6) % 7;
    t += ((WEEKDAYS.indexOf(weekday) - today + 7) % 7) * 86400_000;
  }
  return new Date(t);
}

/** "Mondays 07:30 UTC", "every 6 h", … */
export function whenText(w: ScheduleWhen): string {
  if (w.kind === "interval") return `every ${w.hours} h`;
  if (w.kind === "daily") return `daily ${w.at} UTC`;
  return `${WEEKDAY_LABEL[w.weekday]}s ${w.at} UTC`;
}

/** The same time in the browser's time zone, e.g. "08:30 local (Europe/Berlin)". */
export function localHint(w: ScheduleWhen): string | null {
  if (w.kind === "interval") return null;
  const d = nextOccurrence(w.at, w.kind === "weekly" ? w.weekday : undefined);
  if (!d) return null;
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const day = w.kind === "weekly" ? `${d.toLocaleDateString([], { weekday: "long" })}s ` : "";
  return `${day}${time} local${tz ? ` (${tz})` : ""}`;
}
