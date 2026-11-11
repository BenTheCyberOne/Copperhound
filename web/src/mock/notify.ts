// Mock notification channels, scheduled reports and change alerts, mirroring
// crates/server/src/{notify.rs,schedule.rs,alerts.rs}. Nothing leaves the browser:
// deliveries "succeed" unless the target looks broken (a host containing "invalid"
// or "down"), so failure handling can be tried out.

import type { ApiResponse } from "../api/client";
import type {
  Alert,
  AlertRules,
  ChannelIn,
  ChannelOut,
  Delivery,
  Schedule,
  ScheduleInput,
  ScheduleWhen,
  Severity,
  Weekday,
} from "../api/types";
import { WEEKDAYS } from "../api/types";
import { NON_TRAVERSABLE, nodes } from "./data";
import { shortestPath } from "./graph";

const ok = (body: unknown): ApiResponse => ({ status: 200, body });
const fail = (status: number, error: string): ApiResponse => ({ status, body: { error } });
const now = () => new Date().toISOString();
const hex = (n: number) => Array.from({ length: n }, () => Math.floor(Math.random() * 16).toString(16)).join("");
const hoursAgo = (h: number) => new Date(Date.now() - h * 3600_000).toISOString();

// --- channels -------------------------------------------------------------------------

interface StoredChannel extends Omit<ChannelIn, "url" | "secret" | "smtp_password" | "id"> {
  id: string;
  enabled: boolean;
  url: string;
  secret: string;
  smtp_password: string;
}

let channels: StoredChannel[] = [
  {
    id: "c-5f1e0a9b2c3d",
    name: "SOC Teams",
    type: "teams",
    enabled: true,
    url: "https://corp.webhook.office.com/workflows/abc123/triggers/manual",
    secret: "",
    smtp_password: "",
    teams_format: "adaptive",
  },
  {
    id: "c-7a8b9c0d1e2f",
    name: "Security mailbox",
    type: "email",
    enabled: true,
    url: "",
    secret: "",
    smtp_host: "smtp.corp.example",
    smtp_port: 587,
    smtp_security: "starttls",
    smtp_username: "copperhound",
    smtp_password: "mock-smtp-password",
    email_from: "CopperHound <copperhound@corp.example>",
    email_to: ["soc@corp.example", "ad-team@corp.example"],
  },
  {
    id: "c-0e1d2c3b4a59",
    name: "SIEM relay (down)",
    type: "webhook",
    enabled: false,
    url: "https://siem-down.corp.example/hooks/copperhound",
    secret: "mock-hmac-secret",
    smtp_password: "",
  },
];

function hint(url: string): string {
  const m = /^(https?:\/\/[^/]+)(\/.*)?$/i.exec(url);
  if (!m) return "…";
  return m[2] && m[2] !== "/" ? `${m[1]}/…` : m[1]!;
}

function channelOut(c: StoredChannel): ChannelOut {
  const base = { id: c.id, name: c.name, type: c.type, enabled: c.enabled };
  switch (c.type) {
    case "webhook":
      return { ...base, url_set: !!c.url, url_hint: c.url ? hint(c.url) : undefined, secret_set: !!c.secret };
    case "slack":
      return { ...base, url_set: !!c.url, url_hint: c.url ? hint(c.url) : undefined };
    case "teams":
      return { ...base, url_set: !!c.url, url_hint: c.url ? hint(c.url) : undefined, teams_format: c.teams_format ?? "adaptive" };
    case "email":
      return {
        ...base,
        smtp_host: c.smtp_host,
        smtp_port: c.smtp_port,
        smtp_security: c.smtp_security,
        smtp_username: c.smtp_username,
        smtp_password_set: !!c.smtp_password,
        email_from: c.email_from,
        email_to: c.email_to,
      };
  }
}

const EMAIL = /^(?:[^<>@\s]+\s*<)?[^<>@\s]+@[^<>@\s]+\.[^<>@\s]+>?$/;

/** Secret semantics: absent/null keeps the stored value, "" clears, a string replaces. */
function keep(input: string | null | undefined, stored: string | undefined): string {
  return input === undefined || input === null ? (stored ?? "") : input;
}

export function getChannels(): ApiResponse {
  return ok({ channels: channels.map(channelOut) });
}

export function putChannels(body: { channels?: ChannelIn[] }): ApiResponse {
  const list = body.channels;
  if (!Array.isArray(list)) return fail(400, "channels must be a list");
  if (list.length > 50) return fail(400, "at most 50 channels");
  const next: StoredChannel[] = [];
  const ids = new Set<string>();
  for (const [i, c] of list.entries()) {
    const label = `channel ${i + 1}`;
    const name = (c.name ?? "").trim();
    if (name.length < 1 || name.length > 100) return fail(400, `${label}: name must be 1-100 characters`);
    if (!["webhook", "slack", "teams", "email"].includes(c.type)) return fail(400, `${label}: unknown type`);
    const old = channels.find((x) => x.id === c.id && x.type === c.type);
    const id = c.id ?? `c-${hex(12)}`;
    if (ids.has(id)) return fail(400, `${label}: duplicate id ${id}`);
    ids.add(id);
    const ch: StoredChannel = {
      id,
      name,
      type: c.type,
      enabled: c.enabled ?? true,
      url: keep(c.url, old?.url),
      secret: c.type === "webhook" ? keep(c.secret, old?.secret) : "",
      smtp_password: c.type === "email" ? keep(c.smtp_password, old?.smtp_password) : "",
    };
    if (c.type === "email") {
      const security = c.smtp_security ?? "starttls";
      Object.assign(ch, {
        url: "",
        smtp_host: (c.smtp_host ?? "").trim(),
        smtp_security: security,
        smtp_port: c.smtp_port || (security === "tls" ? 465 : security === "none" ? 25 : 587),
        smtp_username: (c.smtp_username ?? "").trim(),
        email_from: (c.email_from ?? "").trim(),
        email_to: (c.email_to ?? []).map((x) => x.trim()).filter(Boolean),
      });
      if (!/^[A-Za-z0-9.-]+$/.test(ch.smtp_host ?? "")) return fail(400, `${name}: smtp_host must be a host name`);
      if (!EMAIL.test(ch.email_from ?? "")) return fail(400, `${name}: email_from is not a valid address`);
      const to = ch.email_to ?? [];
      if (to.length < 1 || to.length > 50) return fail(400, `${name}: email_to needs 1-50 addresses`);
      const bad = to.find((a) => !EMAIL.test(a));
      if (bad) return fail(400, `${name}: invalid email_to address ${bad}`);
      if (security === "none" && (ch.smtp_username || ch.smtp_password)) {
        return fail(400, `${name}: SMTP credentials are refused with smtp_security "none" (they would be sent in clear text)`);
      }
    } else {
      if (!ch.url) return fail(400, `${name}: url is required`);
      if (!/^https?:\/\/[^/\s]+/i.test(ch.url)) return fail(400, `${name}: url must be http(s) with a host`);
      if (c.type === "teams") ch.teams_format = c.teams_format ?? "adaptive";
    }
    next.push(ch);
  }
  channels = next;
  return getChannels();
}

function deliver(channelId: string): Delivery {
  const c = channels.find((x) => x.id === channelId);
  if (!c) return { channel: channelId, ok: false, attempts: 0, error: "unknown channel" };
  const target = c.type === "email" ? (c.smtp_host ?? "") : c.url;
  if (/invalid|down/i.test(target)) {
    const error = c.type === "email" ? "SMTP connect failed: connection refused" : "HTTP 503: service unavailable";
    return { channel: c.id, name: c.name, ok: false, attempts: 3, error };
  }
  return { channel: c.id, name: c.name, ok: true, attempts: 1 };
}

function deliverAll(ids: string[]): Delivery[] {
  return ids.map((id) => {
    const c = channels.find((x) => x.id === id);
    if (c && !c.enabled) return { channel: id, name: c.name, ok: false, attempts: 0, error: "channel disabled" };
    return deliver(id);
  });
}

export async function testChannel(id: string): Promise<ApiResponse> {
  if (!channels.some((c) => c.id === id)) return fail(404, "unknown channel");
  const d = deliver(id);
  // Failing targets are retried (2 s, 6 s on a real server); keep the mock quick.
  await new Promise((r) => setTimeout(r, d.ok ? 600 : 2000));
  return ok(d);
}

// --- schedules ------------------------------------------------------------------------

const DAY_MS = 86400_000;

function parseAt(at: string): [number, number] | null {
  const m = /^(\d{2}):(\d{2})$/.exec(at);
  if (!m) return null;
  const h = Number(m[1]);
  const min = Number(m[2]);
  return h < 24 && min < 60 ? [h, min] : null;
}

function nextRun(when: ScheduleWhen, lastRun: string | null): string {
  const t = Date.now();
  if (when.kind === "interval") {
    const base = lastRun ? Date.parse(lastRun) : t;
    return new Date(Math.max(base + when.hours * 3600_000, t)).toISOString();
  }
  const [h, m] = parseAt(when.at) ?? [0, 0];
  const d = new Date(t);
  let next = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), h, m);
  if (when.kind === "daily") {
    if (next <= t) next += DAY_MS;
  } else {
    const want = WEEKDAYS.indexOf(when.weekday); // 0 = mon
    const today = (d.getUTCDay() + 6) % 7;
    next += ((want - today + 7) % 7) * DAY_MS;
    if (next <= t) next += 7 * DAY_MS;
  }
  return new Date(next).toISOString();
}

const schedules: Schedule[] = [
  {
    id: "s-1c2d3e4f5a6b",
    name: "Weekly posture to SOC",
    enabled: true,
    when: { kind: "weekly", weekday: "mon", at: "07:30" },
    format: "html",
    title: "",
    plan_steps: 10,
    channels: ["c-5f1e0a9b2c3d", "c-7a8b9c0d1e2f"],
    created_at: hoursAgo(24 * 30),
    next_run: null,
    running: false,
    last_run: hoursAgo(24 * 3),
    last_status: "ok",
    last_error: null,
    last_deliveries: [
      { channel: "c-5f1e0a9b2c3d", name: "SOC Teams", ok: true, attempts: 1 },
      { channel: "c-7a8b9c0d1e2f", name: "Security mailbox", ok: true, attempts: 1 },
    ],
  },
  {
    id: "s-9f8e7d6c5b4a",
    name: "SIEM every 6 h",
    enabled: false,
    when: { kind: "interval", hours: 6 },
    format: "csv",
    title: "CopperHound posture feed",
    plan_steps: 0,
    channels: ["c-0e1d2c3b4a59"],
    created_at: hoursAgo(24 * 10),
    next_run: null,
    running: false,
    last_run: hoursAgo(30),
    last_status: "failed",
    last_error: "all channels failed",
    last_deliveries: [{ channel: "c-0e1d2c3b4a59", name: "SIEM relay (down)", ok: false, attempts: 3, error: "HTTP 503: service unavailable" }],
  },
];
for (const s of schedules) s.next_run = s.enabled ? nextRun(s.when, s.last_run) : null;

function validateSchedule(b: Partial<ScheduleInput>): string | null {
  const name = (b.name ?? "").trim();
  if (name.length < 1 || name.length > 100) return "name must be 1-100 characters";
  const w = b.when;
  if (!w) return "when is required";
  if (w.kind === "daily" || w.kind === "weekly") {
    if (!parseAt(w.at ?? "")) return "when.at must be HH:MM (UTC)";
    if (w.kind === "weekly" && !WEEKDAYS.includes(w.weekday as Weekday)) return "when.weekday must be mon…sun";
  } else if (w.kind === "interval") {
    if (!(Number.isInteger(w.hours) && w.hours >= 1 && w.hours <= 744)) return "when.hours must be 1-744";
  } else return "when.kind must be daily, weekly or interval";
  if (b.format && !["html", "md", "csv"].includes(b.format)) return "format must be html, md or csv";
  if ((b.title ?? "").length > 200) return "title must be at most 200 characters";
  if ((b.plan_steps ?? 10) > 50 || (b.plan_steps ?? 10) < 0) return "plan_steps must be 0-50";
  const chs = b.channels ?? [];
  if (chs.length < 1 || chs.length > 20) return "choose 1-20 channels";
  const unknown = chs.find((id) => !channels.some((c) => c.id === id));
  if (unknown) return `unknown channel ${unknown}`;
  return null;
}

export function listSchedules(): ApiResponse {
  return ok({ schedules, public_url: null });
}

export function saveSchedule(b: Partial<ScheduleInput>, id?: string): ApiResponse {
  const err = validateSchedule(b);
  if (err) return fail(400, err);
  const def = {
    name: b.name!.trim(),
    enabled: b.enabled ?? true,
    when: b.when!,
    format: b.format ?? "html",
    title: b.title ?? "",
    plan_steps: b.plan_steps ?? 10,
    channels: b.channels!,
  };
  if (id) {
    const s = schedules.find((x) => x.id === id);
    if (!s) return fail(404, "unknown schedule");
    Object.assign(s, def);
    s.next_run = s.enabled ? nextRun(s.when, s.last_run) : null;
    return ok(s);
  }
  if (schedules.length >= 100) return fail(400, "at most 100 schedules");
  const s: Schedule = {
    id: `s-${hex(12)}`,
    ...def,
    created_at: now(),
    next_run: null,
    running: false,
    last_run: null,
    last_status: null,
    last_error: null,
    last_deliveries: [],
  };
  s.next_run = s.enabled ? nextRun(s.when, null) : null;
  schedules.push(s);
  return ok(s);
}

export function deleteSchedule(id: string): ApiResponse {
  const i = schedules.findIndex((s) => s.id === id);
  if (i < 0) return fail(404, "unknown schedule");
  schedules.splice(i, 1);
  return ok({});
}

export function runSchedule(id: string, analysisReady: boolean): ApiResponse {
  const s = schedules.find((x) => x.id === id);
  if (!s) return fail(404, "unknown schedule");
  if (s.running) return fail(409, "this schedule is already running");
  s.running = true;
  window.setTimeout(() => {
    s.running = false;
    s.last_run = now();
    if (!analysisReady) {
      s.last_status = "skipped";
      s.last_error = "no finished analysis yet";
      s.last_deliveries = [];
    } else {
      s.last_deliveries = deliverAll(s.channels);
      const failed = s.last_deliveries.filter((d) => !d.ok).length;
      s.last_status = failed === 0 ? "ok" : failed === s.last_deliveries.length ? "failed" : "partial";
      s.last_error = failed === 0 ? null : `${failed} of ${s.last_deliveries.length} channels failed`;
    }
    if (s.when.kind === "interval" && s.enabled) s.next_run = nextRun(s.when, s.last_run);
  }, 3000);
  return { status: 202, body: { started: true } };
}

// --- alert rules & history ---------------------------------------------------------------

let rules: AlertRules = {
  enabled: true,
  channels: ["c-5f1e0a9b2c3d"],
  grade_worse: true,
  exposure_increase_points: 5,
  new_finding_severities: ["critical", "high"],
  new_tier0_principals_min: 10,
  choke_points_changed: false,
  choke_points_top: 10,
  watch: ["SVC_BACKUP@CORP.LOCAL"],
};

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

export function getRules(): ApiResponse {
  return ok(rules);
}

export function putRules(b: Partial<AlertRules>): ApiResponse {
  const next: AlertRules = {
    enabled: b.enabled ?? false,
    channels: b.channels ?? [],
    grade_worse: b.grade_worse ?? true,
    exposure_increase_points: b.exposure_increase_points === undefined ? 5 : b.exposure_increase_points,
    new_finding_severities: b.new_finding_severities ?? ["critical", "high"],
    new_tier0_principals_min: b.new_tier0_principals_min === undefined ? 10 : b.new_tier0_principals_min,
    choke_points_changed: b.choke_points_changed ?? false,
    choke_points_top: b.choke_points_top ?? 10,
    watch: (b.watch ?? []).map((w) => w.trim()).filter(Boolean),
  };
  if (next.channels.length > 20) return fail(400, "at most 20 channels");
  const unknown = next.channels.find((id) => !channels.some((c) => c.id === id));
  if (unknown) return fail(400, `unknown channel ${unknown}`);
  if (next.enabled && next.channels.length === 0) return fail(400, "choose at least one channel when alerts are enabled");
  const p = next.exposure_increase_points;
  if (p !== null && !(p >= 0 && p <= 100)) return fail(400, "exposure_increase_points must be 0-100");
  const t = next.new_tier0_principals_min;
  if (t !== null && !(Number.isInteger(t) && t >= 1)) return fail(400, "new_tier0_principals_min must be at least 1");
  if (!(Number.isInteger(next.choke_points_top) && next.choke_points_top >= 1 && next.choke_points_top <= 100)) {
    return fail(400, "choke_points_top must be 1-100");
  }
  if (next.new_finding_severities.some((s) => !SEVERITIES.includes(s))) return fail(400, "unknown severity");
  rules = next;
  return ok(rules);
}

const alerts: Alert[] = [
  {
    id: "a-3b4c5d6e7f80",
    ts: hoursAgo(26),
    snapshot_id: "snap-0009",
    previous_snapshot_id: "snap-0008",
    grade_before: "C",
    grade_after: "D",
    exposure_before: 18.2,
    exposure_after: 27.9,
    triggers: [
      { rule: "grade_worse", message: "Posture grade dropped from C to D" },
      { rule: "exposure_increase", message: "Exposure rose by 9.7 points (18.2% → 27.9%)" },
      { rule: "new_findings", message: "1 new critical/high finding type: Non-Tier Zero principals can DCSync" },
      { rule: "new_tier0_principals", message: "14 principals newly have a path to Tier Zero" },
    ],
    new_findings: [{ id: "dcsync-non-tier0", title: "Non-Tier Zero principals can DCSync", severity: "critical", count: 1 }],
    new_tier0_principals: 14,
    new_tier0_sample: ["SVC_BACKUP@CORP.LOCAL", "FRANK@CORP.LOCAL", "WKS-004.CORP.LOCAL", "HELPDESK@CORP.LOCAL"],
    choke_points_added: ["SVC_BACKUP@CORP.LOCAL -[DCSync]-> CORP.LOCAL"],
    choke_points_removed: ["IT SUPPORT@CORP.LOCAL -[AddMember]-> SERVER OPERATORS@CORP.LOCAL"],
    deliveries: [
      { channel: "c-5f1e0a9b2c3d", name: "SOC Teams", ok: true, attempts: 1 },
      { channel: "c-0e1d2c3b4a59", name: "SIEM relay (down)", ok: false, attempts: 0, error: "channel disabled" },
    ],
  },
  {
    id: "a-0a1b2c3d4e5f",
    ts: hoursAgo(24 * 8),
    snapshot_id: "snap-0006",
    previous_snapshot_id: "snap-0005",
    grade_before: "C",
    grade_after: "C",
    exposure_before: 12.4,
    exposure_after: 18.6,
    triggers: [{ rule: "exposure_increase", message: "Exposure rose by 6.2 points (12.4% → 18.6%)" }],
    new_findings: [],
    new_tier0_principals: 6,
    new_tier0_sample: ["GRACE@CORP.LOCAL"],
    choke_points_added: [],
    choke_points_removed: [],
    deliveries: [{ channel: "c-5f1e0a9b2c3d", name: "SOC Teams", ok: true, attempts: 1 }],
  },
];

/** Paths for the sample alert, from the mock graph (computed once). */
function withPaths(a: Alert): Alert {
  if (a.new_paths || a.id !== "a-3b4c5d6e7f80") return a;
  const t0 = new Set(nodes.filter((n) => n.tier0).map((n) => n.id));
  a.new_paths = a.new_tier0_sample.flatMap((name) => {
    const n = nodes.find((x) => x.name === name);
    if (!n || t0.has(n.id)) return [];
    const path = shortestPath(n.id, (id) => t0.has(id), { exclude: NON_TRAVERSABLE }) ?? [];
    const nm = (id: number) => nodes.find((x) => x.id === id);
    return [
      {
        objectid: n.objectid,
        name: n.name,
        kind: n.kind,
        watched: rules.watch.includes(n.name),
        hops: path.map((e) => ({ src: nm(e.src)!.objectid, src_name: nm(e.src)!.name, kind: e.kind, dst: nm(e.dst)!.objectid, dst_name: nm(e.dst)!.name })),
      },
    ];
  });
  return a;
}

export function listAlerts(limit: number): ApiResponse {
  return ok({ alerts: alerts.slice(0, Math.min(500, Math.max(1, limit))).map(withPaths) });
}

/** Called after a mock ingest installs a new snapshot: records an alert if a rule fires. */
export function evaluateAlerts(snapshotId: string, previous: string): void {
  if (!rules.enabled || rules.exposure_increase_points === null) return;
  const before = alerts[0]?.exposure_after ?? 20;
  const after = Math.round((before + rules.exposure_increase_points + 1.3) * 10) / 10;
  alerts.unshift({
    id: `a-${hex(12)}`,
    ts: now(),
    snapshot_id: snapshotId,
    previous_snapshot_id: previous,
    grade_before: "D",
    grade_after: "D",
    exposure_before: before,
    exposure_after: after,
    triggers: [{ rule: "exposure_increase", message: `Exposure rose by ${(after - before).toFixed(1)} points (${before}% → ${after}%)` }],
    new_findings: [],
    new_tier0_principals: 0,
    new_tier0_sample: [],
    choke_points_added: [],
    choke_points_removed: [],
    deliveries: deliverAll(rules.channels),
  });
}
