// In-browser implementation of the REST API for `npm run dev:mock`.
// Only loaded via dynamic import when import.meta.env.VITE_MOCK === "1".

import type { ApiRequest, ApiResponse, Backend } from "../api/client";
import {
  ADCS_KINDS,
  AD_KINDS,
  AZURE_KINDS,
  type Edge,
  type EdgeKindInfo,
  type ErrorCode,
  type GraphResult,
  type Health,
  type Job,
  type JobPhase,
  type MarksRequest,
  type NodeDetail,
  type NodeId,
  type NodeKindInfo,
  type PathRequest,
  type PlanRequest,
  type QueryRequest,
  type SavedQuery,
  type SavedQueryInput,
  type SimulateRequest,
  type Stats,
  type UploadInfo,
  type ZoneInput,
  type CollectorInfo,
  type KindStyle,
  type NetworkConfig,
  type EdgeRef,
  type FixItem,
  type TicketCreated,
  type TicketRecord,
  type TicketTarget,
  type TicketTargetIn,
  type CollectorKind,
  type NewCollectorResponse,
  type SamlConfig,
  type SamlSettingsResponse,
} from "../api/types";
import {
  computingProgress,
  deleteSnapshot,
  deleteZone,
  setZoneWeight,
  zoneObjects,
  findingDetail,
  acceptances,
  findingsResponse,
  installSnapshot,
  listZones,
  posture,
  postureDiff,
  remediationPlan,
  saveZone,
  simulate,
  state,
  ZoneError,
  zoneMembers,
  zoneReviews,
  zoneSelectorMatches,
  zoneTargets,
} from "./analysis";
import { atLeast, audited, authenticate, denied, ingestSettings, login, logout, oidcExchange, requiredRole, routeAccounts, uploaderMay, type Principal } from "./accounts";
import { EDGE_HELP } from "./edgeHelp";
import { columns, filterNodes } from "./filter";
import {
  deleteSchedule,
  evaluateAlerts,
  getChannels,
  getRules,
  listAlerts,
  listSchedules,
  putChannels,
  putRules,
  runSchedule,
  saveSchedule,
  testChannel,
} from "./notify";
import { getSsoSettings, providers, putSsoSettings, testSso } from "./sso";
import { renderReport } from "./report";
import { edgeCategory, edges, nodeCategory, NON_TRAVERSABLE, nodes, prebuiltQueries, type MockNode } from "./data";
import { exposureReport, tier0Targets } from "./exposure";
import { getNode, inAdj, outAdj, publicNode, resultFrom, shortestPath } from "./graph";
import { parseChql, ChqlError, runChql } from "./chql";
import { buildManifest, nodeSources, sourcesResponse, uploadsWithSources } from "./sources";


const LIMITS: Health["limits"] = {
  max_query_limit: 100000,
  default_query_timeout_ms: 30000,
  max_query_timeout_ms: 300000,
  upload_extensions: [".json", ".zip", ".ldif", ".ldf", ".ldif.gz", ".dat"],
  max_upload_bytes: 512 * 1024 * 1024,
};

// Two dated SharpHound collections of CORP.LOCAL, an LDIF dated only by whenChanged
// (a lower bound next to SharpHound data) and an undated AzureHound dump.
const uploads: UploadInfo[] = [
  { name: "20261104091200_BloodHound.zip", size: 1_482_331, uploaded_at: "2026-11-04T09:12:44Z" },
  { name: "20261020083000_BloodHound.zip", size: 1_391_027, uploaded_at: "2026-11-04T09:12:45Z" },
  { name: "corp_dc01_export.ldif", size: 9_612_904, uploaded_at: "2026-11-04T09:13:30Z" },
  { name: "azurehound_corp.json", size: 3_904_118, uploaded_at: "2026-11-04T09:15:02Z" },
];
const initialManifest = buildManifest(uploads, "newest");
const jobs: Job[] = [
  {
    id: "j-1",
    state: "done",
    trigger: "manual",
    phase: "done",
    percent: 100,
    created_at: "2026-11-04T09:16:00Z",
    started_at: "2026-11-04T09:16:00Z",
    finished_at: "2026-11-04T09:16:02Z",
    message: `ingested ${nodes.length} nodes`,
    report: {
      files: uploads.length,
      records: nodes.length,
      nodes: nodes.length,
      edges: edges.length,
      parse_errors: 0,
      seconds: 1.9,
      merge_policy: initialManifest.merge_policy,
      superseded_objects: initialManifest.superseded_objects,
      superseded_edges: initialManifest.superseded_edges,
      sources: initialManifest.sources.length,
    },
  },
];

const ok = (body: unknown): ApiResponse => ({ status: 200, body });
const fail = (status: number, error: string, position?: number | null, code?: ErrorCode): ApiResponse => ({
  status,
  body: { error, ...(position === undefined ? {} : { position }), ...(code ? { code } : {}) },
});
const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

function resolveNode(ref: NodeId | string | undefined): MockNode | undefined {
  if (ref === undefined || ref === "") return undefined;
  if (typeof ref === "number" || /^\d+$/.test(ref)) return getNode(Number(ref));
  const up = ref.toUpperCase();
  return nodes.find((n) => n.name.toUpperCase() === up || n.objectid.toUpperCase() === up);
}

function stats(): Stats {
  const count = <T,>(xs: T[], key: (x: T) => string) =>
    xs.reduce<Record<string, number>>((acc, x) => ((acc[key(x)] = (acc[key(x)] ?? 0) + 1), acc), {});
  return {
    nodes: nodes.length,
    edges: edges.length,
    tier0: nodes.filter((n) => n.tier0).length,
    owned: nodes.filter((n) => n.owned).length,
    node_kinds: count(nodes, (n) => n.kind),
    edge_kinds: count(edges, (x) => x.kind),
    loaded_at: state.loadedAt,
    generation: state.generation,
    snapshot_id: state.snapshotId,
  };
}

function detail(n: MockNode): NodeDetail {
  const countKinds = (es: Edge[]) =>
    es.reduce<Record<string, number>>((acc, x) => ((acc[x.kind] = (acc[x.kind] ?? 0) + 1), acc), {});
  const flags = Object.entries(n.properties)
    .filter(([, v]) => v === true)
    .map(([k]) => k);
  if (n.enabled) flags.unshift("enabled");
  const srcs = nodeSources(n);
  return {
    ...publicNode(n),
    properties: srcs ? { ...n.properties, _sources: srcs } : n.properties,
    flags,
    in_degree: inAdj[n.id]!.length,
    out_degree: outAdj[n.id]!.length,
    edge_counts: { out: countKinds(outAdj[n.id]!), in: countKinds(inAdj[n.id]!) },
  };
}

/** v1.1 ranking: exact name/objectid, then name prefix, then name substring; shorter names first, then alphabetically. */
function search(q: string, limit: number, kind: string | undefined) {
  const up = q.toUpperCase();
  const pool = nodes.filter((n) => !kind || n.kind === kind);
  const byLength = (a: MockNode, b: MockNode) => a.name.length - b.name.length || a.name.localeCompare(b.name);
  const exact = pool.filter((n) => n.name.toUpperCase() === up || n.objectid.toUpperCase() === up);
  const prefix = pool.filter((n) => !exact.includes(n) && n.name.toUpperCase().startsWith(up)).sort(byLength);
  const substring = pool
    .filter((n) => !exact.includes(n) && !n.name.toUpperCase().startsWith(up) && n.name.toUpperCase().includes(up))
    .sort(byLength);
  return [...exact, ...prefix, ...substring].slice(0, limit).map(publicNode);
}

function nodeKinds(): NodeKindInfo[] {
  const all = [...AD_KINDS, ...ADCS_KINDS, ...AZURE_KINDS, "Unknown"];
  return all.map((name) => ({ name, category: nodeCategory(name), count: nodes.filter((n) => n.kind === name).length }));
}

function edgeKinds(): EdgeKindInfo[] {
  const counts = new Map<string, number>();
  for (const x of edges) counts.set(x.kind, (counts.get(x.kind) ?? 0) + 1);
  return [...counts.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([name, count]) => ({
      name,
      traversable: !NON_TRAVERSABLE.has(name),
      category: edgeCategory(name),
      count,
      help: EDGE_HELP[name] ?? null,
      composite: COMPOSITE.has(name),
    }));
}

/** Derived kinds the real server explains (ch_ingest::postprocess::explain). */
const COMPOSITE = new Set([
  "DCSync", "SyncLAPSPassword", "CoerceToTGT", "HasTrustKeys", "GoldenCert", "ADCSESC1", "ADCSESC3", "ADCSESC4", "ADCSESC6a", "ADCSESC6b",
  "ADCSESC9a", "ADCSESC9b", "ADCSESC10a", "ADCSESC10b", "ADCSESC13", "AZGlobalAdmin", "AZPrivilegedRoleAdmin",
  "AZPrivilegedAuthAdmin", "AZAddMembers", "AZAddSecret", "AZAddOwner", "AZExecuteCommand", "AZResetPassword", "AZMGAddSecret",
  "AZMGAddOwner", "AZMGAddMember", "AZMGGrantAppRoles", "AZMGGrantRole", "SyncedToEntraUser", "SyncedToADUser",
  "SyncedToEntraGroup", "SyncedToADGroup", "EntraConnectCredentials", "SeamlessSSO",
]);

/** Mock composition: the source's group chain and the other edges into the target. */
function composition(src: NodeId, dst: NodeId, kind: string): ApiResponse {
  if (!COMPOSITE.has(kind)) return fail(400, `${kind} is not a derived edge kind`);
  const edge = edges.find((e) => e.src === src && e.dst === dst && e.kind === kind);
  if (!edge) return fail(404, "edge not found");
  const groups = new Set([src]);
  const chain = edges.filter((e) => e.src === src && e.kind === "MemberOf");
  for (const e of chain) groups.add(e.dst);
  const into = edges.filter((e) => groups.has(e.src) && e.dst === dst && e.kind !== kind);
  const used = [...chain.filter((e) => into.some((i) => i.src === e.dst)), ...into];
  const ids = new Set([src, dst, ...used.flatMap((e) => [e.src, e.dst])]);
  return ok({
    ...resultFrom(ids, used, { generation: state.generation }),
    edge,
    notes: [`Mock data: ${kind} is shown with the source's other edges into the target.`],
    complete: used.length > 0,
  });
}

function path(req: PathRequest): ApiResponse {
  const from = resolveNode(req.from);
  if (!from) return fail(404, `start node not found: ${String(req.from)}`);
  const to = req.to_tier0 ? undefined : resolveNode(req.to);
  if (!req.to_tier0 && !to) return fail(404, `target node not found: ${String(req.to ?? "")}`);
  const filter = { exclude: new Set(req.exclude), allEdges: req.all_edges };
  const isTarget = req.to_tier0 ? (id: NodeId) => nodes[id]!.tier0 && id !== from.id : (id: NodeId) => id === to!.id;
  const hops = shortestPath(from.id, isTarget, filter);
  if (!hops) {
    return ok({ nodes: [], edges: [], paths: [], hops: [], truncated: false, elapsed_ms: 0.2, generation: state.generation } satisfies GraphResult);
  }
  return ok(
    resultFrom([from.id], hops, {
      paths: [[from.id, ...hops.map((x) => x.dst)]],
      hops: hops.map((x) => ({ ...x })),
      elapsed_ms: 0.4,
      generation: state.generation,
    }),
  );
}

// --- ingest jobs -------------------------------------------------------------

const PHASES: JobPhase[] = ["extracting", "scanning", "parsing", "merging", "building", "post-processing", "writing", "loading"];

let jobSeq = jobs.length;
function startIngest(trigger: Job["trigger"]): string {
  const job: Job = {
    id: `j-${++jobSeq}`,
    state: "queued",
    phase: "queued",
    percent: 0,
    created_at: new Date().toISOString(),
    trigger,
  };
  jobs.unshift(job);
  let step = 0;
  const tick = () => {
    if (step === 0) {
      job.state = "running";
      job.started_at = new Date().toISOString();
    }
    if (step < PHASES.length) {
      job.phase = PHASES[step];
      job.percent = Math.round(((step + 0.5) / PHASES.length) * 100);
      job.message = `${job.phase}…`;
      step++;
      setTimeout(tick, 700);
      return;
    }
    job.state = "done";
    job.phase = "done";
    job.percent = 100;
    job.finished_at = new Date().toISOString();
    job.message = `ingested ${nodes.length} nodes`;
    const m = buildManifest(uploads, ingestSettings().merge_policy);
    job.report = {
      files: uploads.length,
      records: nodes.length + 3,
      nodes: nodes.length,
      edges: edges.length,
      parse_errors: m.sources.reduce((a, s) => a + s.parse_errors, 0),
      seconds: 5.6,
      merge_policy: m.merge_policy,
      superseded_objects: m.superseded_objects,
      superseded_edges: m.superseded_edges,
      sources: m.sources.length,
    };
    // The mock keeps the same data, but a rebuilt graph always gets a new generation
    // and snapshot, and the analysis endpoints answer 202 for a few seconds.
    const previous = state.snapshotId;
    installSnapshot();
    evaluateAlerts(state.snapshotId, previous);
  };
  setTimeout(tick, 1000);
  return job.id;
}

// --- saved queries -------------------------------------------------------------

const savedQueries: SavedQuery[] = [
  {
    id: "sq-1",
    name: "Finance group members",
    category: "Team: Red",
    description: "Who is in FINANCE",
    query: "MATCH (u:User)-[:MemberOf]->(g:Group {name:'FINANCE@CORP.LOCAL'}) RETURN u, g",
    created_at: "2026-11-01T10:00:00Z",
    updated_at: "2026-11-01T10:00:00Z",
  },
];
let savedSeq = savedQueries.length;

function saveQuery(input: Partial<SavedQueryInput>, existing?: SavedQuery): ApiResponse {
  if (!input.name?.trim()) return fail(400, "name is required");
  if (!input.query?.trim()) return fail(400, "query is required");
  try {
    parseChql(input.query);
  } catch (e) {
    if (e instanceof ChqlError) return fail(400, e.message, e.position, e.code);
    throw e;
  }
  const now = new Date().toISOString();
  const fields = {
    name: input.name.trim(),
    category: input.category?.trim() || "Custom",
    description: input.description?.trim() ?? "",
    query: input.query.trim(),
  };
  if (existing) {
    Object.assign(existing, fields, { updated_at: now });
    return ok(existing);
  }
  const created: SavedQuery = { id: `sq-${++savedSeq}`, ...fields, created_at: now, updated_at: now };
  savedQueries.push(created);
  return ok(created);
}

// --- queries with timeout / cancel ------------------------------------------------

const runningQueries = new Map<string, () => void>();

function runQuery(body: Partial<QueryRequest>): Promise<ApiResponse> {
  const text = body.query ?? "";
  const timeout = Math.min(body.timeout_ms || LIMITS.default_query_timeout_ms, LIMITS.max_query_timeout_ms);
  // Path queries are artificially slow so cancel and timeout can be tried out.
  const latency = /shortestpath/i.test(text) ? 1800 : 350;
  return new Promise((resolve) => {
    const finish = (res: ApiResponse) => {
      window.clearTimeout(work);
      window.clearTimeout(timer);
      if (body.query_id) runningQueries.delete(body.query_id);
      resolve(res);
    };
    const work = window.setTimeout(() => {
      try {
        finish(ok({ ...runChql(text, Math.min(body.limit ?? 1000, LIMITS.max_query_limit)), generation: state.generation }));
      } catch (e) {
        if (e instanceof ChqlError) finish(fail(400, e.message, e.position, e.code));
        else finish(fail(500, String(e)));
      }
    }, latency);
    const timer = window.setTimeout(
      () => finish(fail(408, `query exceeded the ${timeout} ms timeout`, undefined, "timeout")),
      timeout,
    );
    if (body.query_id) {
      runningQueries.set(body.query_id, () => finish(fail(409, "query was cancelled", undefined, "cancelled")));
    }
  });
}

// --- v1.2 routes ------------------------------------------------------------------------

function zoneFail(e: unknown): ApiResponse {
  if (e instanceof ZoneError) return fail(e.message.includes("not found") ? 404 : 400, e.message, e.position ?? undefined, e.code);
  throw e;
}

function routeV12(
  method: ApiRequest["method"],
  p: string,
  str: (k: string) => string | undefined,
  num: (k: string, d: number) => number,
  body: unknown,
): ApiResponse | null {
  let m: RegExpExecArray | null;
  // Analysis-backed endpoints are unavailable for a few seconds after an ingest.
  const progress = computingProgress();
  const analysis = /^\/(findings|posture)/.test(p) || /^\/zones\/[^/]+\/exposure$/.test(p);
  if (analysis && method === "GET" && progress !== null) return { status: 202, body: { status: "computing", progress } };

  if (method === "GET" && p === "/zones") return ok(listZones());
  if (method === "POST" && p === "/zones") {
    try {
      return ok(saveZone((body ?? {}) as Partial<ZoneInput>));
    } catch (e) {
      return zoneFail(e);
    }
  }
  if ((m = /^\/zones\/([^/]+)$/.exec(p))) {
    const id = decodeURIComponent(m[1]!);
    try {
      if (method === "PUT") return ok(saveZone((body ?? {}) as Partial<ZoneInput>, id));
      if (method === "DELETE") {
        deleteZone(id);
        return ok({});
      }
    } catch (e) {
      return zoneFail(e);
    }
  }
  if (method === "POST" && (m = /^\/zones\/([^/]+)\/objects$/.exec(p))) {
    try {
      return ok(zoneObjects(decodeURIComponent(m[1]!), (body ?? {}) as { add?: string[]; remove?: string[] }));
    } catch (e) {
      return zoneFail(e);
    }
  }
  if (method === "PUT" && (m = /^\/zones\/([^/]+)\/weight$/.exec(p))) {
    try {
      return ok(setZoneWeight(decodeURIComponent(m[1]!), (body as { weight?: unknown } | undefined)?.weight));
    } catch (e) {
      if (e instanceof ZoneError) return fail(e.message.includes("not found") ? 404 : 400, e.message);
      throw e;
    }
  }
  if (method === "GET" && (m = /^\/zones\/([^/]+)\/members$/.exec(p))) {
    const members = zoneMembers(decodeURIComponent(m[1]!));
    if (!members) return fail(404, "zone not found");
    const offset = num("offset", 0);
    return ok({ total: members.length, items: members.slice(offset, offset + num("limit", 200)).map(publicNode) });
  }
  if ((m = /^\/zones\/([^/]+)\/review$/.exec(p))) {
    const id = decodeURIComponent(m[1]!);
    if (id === "tier0") return fail(400, "Tier Zero is reviewed with marks, not zone review");
    const matched = zoneSelectorMatches(id);
    if (!matched) return fail(404, `no zone '${id}'`);
    if (!zoneReviews.has(id)) zoneReviews.set(id, new Map());
    const dec = zoneReviews.get(id)!;
    if (method === "POST") {
      const r = (body ?? {}) as { objectids?: string[]; status?: string; note?: string };
      if (!["certified", "revoked", "pending"].includes(r.status ?? "")) return fail(400, "status must be certified, revoked or pending");
      for (const o of r.objectids ?? []) {
        const k = o.toUpperCase();
        if (r.status === "pending") dec.delete(k);
        else dec.set(k, { status: r.status as "certified" | "revoked", by: "admin", at: new Date().toISOString(), note: r.note || undefined });
      }
      return ok({ zone: id, updated: r.objectids?.length ?? 0, status: r.status });
    }
    const counts = { pending: 0, certified: 0, revoked: 0 };
    const want = str("status") ?? "";
    const rows = matched.flatMap((n) => {
      const d = dec.get(n.objectid.toUpperCase()) ?? null;
      const status = d?.status ?? "pending";
      counts[status] += 1;
      return !want || want === status ? [{ node: publicNode(n), status, decision: d }] : [];
    });
    const offset = num("offset", 0);
    return ok({ zone: id, counts, total: rows.length, offset, items: rows.slice(offset, offset + num("limit", 200)) });
  }
  if (method === "GET" && (m = /^\/zones\/([^/]+)\/exposure$/.exec(p))) {
    const targets = zoneTargets(decodeURIComponent(m[1]!));
    return targets ? ok(exposureReport(targets, num("top", 25))) : fail(404, "zone not found");
  }
  if (method === "GET" && p === "/findings") return ok(findingsResponse());
  if (method === "GET" && (m = /^\/findings\/([^/]+)\/history$/.exec(p))) {
    const id = decodeURIComponent(m[1]!);
    const f = findingsResponse().findings.find((x) => x.id === id);
    if (!f) return fail(404, "no finding");
    const day = (d: number) => new Date(Date.now() - d * 86400_000).toISOString();
    const counts = [f.count + 3, f.count + 1, f.count + 2, f.count];
    return ok({
      id,
      points: counts.map((count, i) => ({ snapshot_id: `snap-${i}`, created_at: day(3 - i), count })),
      latest_change: { from: "snap-2", to: "snap-3", from_at: day(1), to_at: day(0), added: 1, removed: 3, added_sample: ["NEWUSER@CORP.LOCAL"], removed_sample: ["OLDUSER@CORP.LOCAL"] },
    });
  }
  if ((m = /^\/findings\/([^/]+)\/acceptance$/.exec(p))) {
    const id = decodeURIComponent(m[1]!);
    if (method === "DELETE") return acceptances.delete(id) ? ok({ id, acceptance: null }) : fail(404, "not accepted");
    if (method === "PUT") {
      const r = (body ?? {}) as { reason?: string; expires_days?: number };
      if (!r.reason?.trim()) return fail(400, "a reason (1-2000 characters) is required");
      const a = {
        reason: r.reason.trim(),
        accepted_by: "admin",
        accepted_at: new Date().toISOString(),
        ...(r.expires_days ? { expires_at: new Date(Date.now() + r.expires_days * 86400_000).toISOString() } : {}),
      };
      acceptances.set(id, a);
      return ok({ id, acceptance: a });
    }
  }
  if (method === "GET" && (m = /^\/findings\/([^/]+)$/.exec(p))) {
    const f = findingDetail(decodeURIComponent(m[1]!), num("offset", 0), num("limit", 100));
    return f ? ok(f) : fail(404, "finding not found");
  }
  if (method === "POST" && p === "/simulate") {
    const r = simulate((body ?? {}) as SimulateRequest);
    return r ? ok(r) : fail(404, "zone not found");
  }
  if (method === "POST" && p === "/remediation-plan") {
    try {
      const r = remediationPlan((body ?? {}) as PlanRequest);
      return r ? ok(r) : fail(404, "zone not found");
    } catch (e) {
      if (e instanceof ZoneError) return fail(400, e.message);
      throw e;
    }
  }
  if (method === "GET" && p === "/posture") return ok(posture());
  if (method === "GET" && p === "/posture/diff") {
    const d = postureDiff(str("from") ?? "", str("to") ?? "");
    return d ? ok(d) : fail(404, "snapshot not found");
  }
  if (method === "DELETE" && (m = /^\/posture\/([^/]+)$/.exec(p))) {
    return deleteSnapshot(decodeURIComponent(m[1]!)) ? ok({}) : fail(404, "snapshot not found (the current snapshot cannot be deleted)");
  }
  return null;
}

// --- routing -------------------------------------------------------------------------

/** Authenticates, enforces the role for the route, routes, and writes the audit trail. */
function route(req: ApiRequest): ApiResponse {
  if (req.path === "/health" || req.path === "/login" || req.path.startsWith("/auth/")) return routePublic(req);
  const who = authenticate(req.token);
  if (!who) return fail(401, "unauthorized");
  const need = requiredRole(req.method, req.path);
  if (who.role === "uploader" ? !uploaderMay(req.method, req.path) : !atLeast(who, need)) return denied(who, req, need);
  return audited(who, req, routeAccounts(who, req) ?? routeData(req, who));
}

/** Mock ticket targets and created tickets. */
let mockTicketTargets: TicketTarget[] = [
  { id: "jira", name: "Security Jira", type: "jira", enabled: true, url: "https://jira.example.com", username: "bot@example.com", token_set: true, project: "SEC", issue_type: "Task", table: "", labels: ["copperhound"], fields: {} },
];
const mockTickets: TicketRecord[] = [];

function mockFixCommand(kind: string, s: MockNode, d: MockNode): string | null {
  if (kind === "MemberOf" && d.kind === "Group") return `Import-Module ActiveDirectory\n# Remove ${s.name} from ${d.name}\nRemove-ADGroupMember -Identity '${d.objectid}' -Members '${s.objectid}' -Confirm:$false`;
  if (kind === "AdminTo") return `# Remove ${s.name} from the local Administrators group on ${d.name}\nInvoke-Command -ComputerName '${d.name}' -ScriptBlock { Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member '${s.objectid}' }`;
  if (kind === "HasSession") return `# ${d.name} has a session on ${s.name}: list sessions, then sign it out\nquery user /server:'${s.name}'`;
  return null;
}

/** Mock shared kind styles. */
let mockKindStyles: Record<string, KindStyle> = { Domain: { icon: "🏰" } };
let mockNetwork: NetworkConfig | null = null;

/** Mock LDAP collection targets. */
let mockLdap: Record<string, unknown>[] = [];

/** Mock two-factor state of the signed-in account. */
const mockMfa = { enabled: false, pending: false };

/** Mock collector clients (in memory). */
const mockCollectors: CollectorInfo[] = [
  {
    id: "c1",
    name: "corp.local DC01",
    kind: "sharphound",
    interval_hours: 24,
    username: "collector-corp-local-dc01",
    token_id: "t1",
    created_at: "2026-10-01T08:00:00Z",
    created_by: "admin",
    last_upload_at: "2026-11-04T02:05:00Z",
    last_files: ["20261104020000_BloodHound.zip"],
    uploads: 34,
    status: "stale",
  },
];

/** Mock SAML settings (in memory). */
let mockSaml: SamlConfig = {
  enabled: false,
  display_name: "SAML single sign-on",
  idp_metadata: "",
  sp_entity_id: "",
  acs_url: "",
  username_attribute: "",
  groups_attribute: "groups",
  email_attribute: "email",
  role_mapping: { admin: [], analyst: [], viewer: [] },
  default_role: "deny",
  allowed_email_domains: [],
};

/** v1.4: notification channels, scheduled reports, alerts, SSO settings. */
function routeV14(method: ApiRequest["method"], p: string, num: (k: string, d: number) => number, body: unknown): ApiResponse | null {
  let m: RegExpExecArray | null;
  const b = (body ?? {}) as Record<string, unknown>;
  if (p === "/settings/sso") {
    if (method === "GET") return getSsoSettings();
    if (method === "PUT") return putSsoSettings(b);
  }
  if (method === "POST" && p === "/settings/sso/test") return testSso(b);
  if (p === "/collectors") {
    if (method === "GET") return ok(mockCollectors);
    if (method === "POST") {
      const r = b as { name?: string; kind?: CollectorKind; interval_hours?: number };
      if (!r.name?.trim()) return fail(400, "name must be 1-64 characters with at least one letter or digit");
      const slug = r.name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
      const c: CollectorInfo = {
        id: Math.random().toString(16).slice(2, 10),
        name: r.name.trim(),
        kind: r.kind ?? "sharphound",
        interval_hours: r.interval_hours ?? 24,
        username: `collector-${slug}`,
        token_id: "t-mock",
        created_at: new Date().toISOString(),
        created_by: "admin",
        last_upload_at: null,
        last_files: [],
        uploads: 0,
        status: "never",
      };
      mockCollectors.push(c);
      const token = "cht_mock" + Math.random().toString(16).slice(2);
      return ok({
        collector: c,
        token,
        note: "store this token now; it is not shown again",
        commands: {
          script_name: "collect.ps1",
          script: `& C:\\CopperHound\\SharpHound.exe -c All --outputdirectory C:\\CopperHound\ncurl.exe -H "Authorization: Bearer ${token}" -F "files=@..." ${location.origin}/api/v1/upload`,
          schedule: "schtasks /Create /TN CopperHound-Collect /SC DAILY /ST 02:00 ...",
        },
      } satisfies NewCollectorResponse);
    }
  }
  if ((m = /^\/collectors\/([^/]+)$/.exec(p)) && method === "DELETE") {
    const i = mockCollectors.findIndex((c) => c.id === m![1]);
    if (i < 0) return fail(404, "no such collector");
    mockCollectors.splice(i, 1);
    return ok({});
  }
  if (p === "/me/mfa" && method === "GET") return ok({ enabled: mockMfa.enabled, pending: mockMfa.pending, recovery_codes_left: mockMfa.enabled ? 10 : 0 });
  if (p === "/me/mfa/setup" && method === "POST") {
    mockMfa.pending = true;
    const qr = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="#fff"/><rect x="1" y="1" width="3" height="3"/><rect x="6" y="1" width="3" height="3"/><rect x="1" y="6" width="3" height="3"/><rect x="5" y="5" width="2" height="2"/></svg>';
    return ok({ secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", uri: "otpauth://totp/CopperHound:admin?secret=JBSWY3DPEHPK3PXP", qr_svg: qr });
  }
  if (p === "/me/mfa/enable" && method === "POST") {
    if ((b as { code?: string }).code !== "123456") return fail(400, "that code is not valid; check the device clock (mock: use 123456)");
    mockMfa.enabled = true;
    mockMfa.pending = false;
    return ok({ enabled: true, recovery_codes: Array.from({ length: 10 }, (_, i) => `mock-${i}abc-def${i}`) });
  }
  if (p === "/me/mfa/disable" && method === "POST") {
    mockMfa.enabled = false;
    return ok({ enabled: false });
  }
  if (p === "/network") {
    if (method === "PUT") mockNetwork = b as unknown as NetworkConfig;
    if (method === "DELETE") mockNetwork = null;
    return ok({ conduits: mockNetwork, zones: mockNetwork ? [{ name: mockNetwork.attacker_zone, hosts: 0 }] : [], error: null });
  }
  if (p === "/network/exposure") {
    if (!mockNetwork) return fail(400, "no network conduits configured");
    return ok({ zone: "tier0", identity_exposed: 0, network_exposed: 0, total_principals: 0, elapsed_ms: 0.4 });
  }
  if (p === "/kind-styles") {
    if (method === "PUT") mockKindStyles = b as Record<string, KindStyle>;
    return ok(mockKindStyles);
  }
  if (p === "/collect/ldap") {
    if (method === "GET") return ok(mockLdap);
    if (method === "PUT") {
      const t = b as Record<string, unknown>;
      const id = (t.id as string) || Math.random().toString(16).slice(2, 8);
      const rec = { ...t, id, password_set: true, running: false, last_run: null, last_ok: null, last_error: null, last_objects: 0, last_seconds: 0 };
      delete (rec as Record<string, unknown>).password;
      const i = mockLdap.findIndex((x) => x.id === id);
      if (i >= 0) mockLdap[i] = rec;
      else mockLdap.push(rec);
      return ok(rec);
    }
  }
  if ((m = /^\/collect\/ldap\/([^/]+)(\/(run|test))?$/.exec(p))) {
    const id = m[1]!;
    if (method === "DELETE") {
      mockLdap = mockLdap.filter((x) => x.id !== id);
      return ok({});
    }
    if (m[3] === "test") return ok({ ok: false, error: "mock mode: no domain controller to reach" });
    if (m[3] === "run") return ok({ started: id });
  }
  if (method === "GET" && p === "/environments") {
    return ok([
      { id: "S-1-5-21-3623811015-3361044348-30300820", name: "CORP.LOCAL", kind: "ad", objects: 60 },
      { id: "6c12b0b0-0000-4000-8000-000000000001", name: "CORP", kind: "tenant", objects: 14 },
    ]);
  }
  if (method === "GET" && p === "/quality") {
    return ok({
      domains: [
        { type: "ad", id: 0, name: "CORP.LOCAL", objectid: "S-1-5-21-3623811015-3361044348-30300820", users: 15, users_enabled: 14, groups: 12, computers: 8, computers_enabled: 8,
          session_coverage: 37.5, local_group_coverage: 62.5, acl_coverage: 100, collected_at: "2026-11-04T09:12:00Z", collected_at_exact: true, age_days: 6, sources: 6, warnings: [] },
      ],
      tenants: [
        { type: "tenant", id: 1, name: "CORP", objectid: "6c12b0b0-0000-4000-8000-000000000001", users: 5, groups: 2, apps: 2, service_principals: 3, devices: 1, roles: 4,
          role_assignments: 3, memberships: 4, app_owner_coverage: 50, device_owner_coverage: 0, subscriptions: 0, collected_at: "2026-11-04T09:15:02Z", collected_at_exact: false, age_days: 6, sources: 1,
          warnings: ["No Azure subscriptions: Azure RBAC (resource) paths are not covered — collect with an identity that can read subscriptions."] },
      ],
    });
  }
  if (method === "POST" && p === "/database/clear") {
    if (b.confirm !== "DELETE") return fail(400, 'set "confirm": "DELETE" to clear data');
    return ok({
      ...(b.uploads ? { uploads_removed: [] } : {}),
      ...(b.graph ? { graph_snapshots_removed: 0 } : {}),
      ...(b.marks ? { marks_cleared: true } : {}),
      ...(b.zones ? { zones_cleared: true } : {}),
      ...(b.saved_queries ? { saved_queries_cleared: true } : {}),
      ...(b.posture_history ? { posture_history_cleared: true } : {}),
    });
  }
  if (p === "/settings/saml") {
    if (method === "PUT") mockSaml = { ...mockSaml, ...(b as Partial<SamlConfig>) };
    return ok({
      config: mockSaml,
      sp_entity_id_effective: `${location.origin}/api/v1/auth/saml/metadata`,
      acs_url_effective: `${location.origin}/api/v1/auth/saml/acs`,
      metadata_url: `${location.origin}/api/v1/auth/saml/metadata`,
      idp: mockSaml.idp_metadata ? { entity_id: "https://idp.example.com/saml", sso_url: "https://idp.example.com/sso", certificates: ["AB:CD:EF"] } : null,
    } satisfies SamlSettingsResponse);
  }
  if (p === "/remediation/commands" && method === "POST") {
    const refs = ((b as { edges?: EdgeRef[] })?.edges ?? []) as EdgeRef[];
    const items: FixItem[] = [];
    const missing: EdgeRef[] = [];
    for (const e of refs) {
      const s = resolveNode(e.src);
      const d = resolveNode(e.dst);
      if (!s || !d) {
        missing.push(e);
        continue;
      }
      items.push({ src: publicNode(s), dst: publicNode(d), kind: e.kind, guidance: EDGE_HELP[e.kind]?.remediation ?? null, command: mockFixCommand(e.kind, s, d) });
    }
    return ok({ items, missing });
  }
  if (p === "/tickets/targets") {
    if (method === "PUT") {
      const list = ((b as { targets?: TicketTargetIn[] })?.targets ?? []) as TicketTargetIn[];
      mockTicketTargets = list.map((t, i) => {
        const old = mockTicketTargets.find((o) => o.id === t.id);
        return {
          id: t.id || `t-${Date.now().toString(16)}${i}`,
          name: t.name,
          type: t.type,
          enabled: t.enabled,
          url: t.url,
          username: t.username ?? "",
          token_set: t.token === undefined ? (old?.token_set ?? false) : t.token !== "",
          project: t.project ?? "",
          issue_type: t.issue_type || (t.type === "jira" ? "Task" : ""),
          table: t.table || (t.type === "servicenow" ? "incident" : ""),
          labels: t.labels ?? [],
          fields: t.fields ?? {},
        };
      });
    }
    return ok(mockTicketTargets);
  }
  if ((m = /^\/tickets\/targets\/([^/]+)\/test$/.exec(p)) && method === "POST") {
    const t = mockTicketTargets.find((x) => x.id === decodeURIComponent(m![1]!));
    if (!t) return fail(404, "no ticket target");
    return ok(t.token_set || t.type === "webhook" ? { ok: true, detail: t.type === "jira" ? "signed in as Demo Bot" : "connected" } : { ok: false, error: "HTTP 401: unauthorized" });
  }
  if (p === "/tickets") {
    if (method === "GET") return ok([...mockTickets].reverse());
    if (method === "POST") {
      const r = (b ?? {}) as { target?: string; edges?: EdgeRef[]; title?: string; split?: boolean };
      const t = mockTicketTargets.find((x) => x.id === r.target);
      if (!t) return fail(404, "no ticket target");
      const edgesIn = r.edges ?? [];
      const groups = r.split ? edgesIn.map((e) => [e]) : [edgesIn];
      const created: TicketCreated[] = groups.map((g, i) => {
        const key = t.type === "jira" ? `${t.project || "SEC"}-${101 + mockTickets.length + i}` : t.type === "servicenow" ? `INC00${10001 + mockTickets.length + i}` : "sent";
        const title = !r.split && r.title ? r.title : g.length === 1 ? `Remove ${g[0]!.kind} edge` : `Remove ${g.length} attack path edges (CopperHound)`;
        return { key, url: t.type === "jira" ? `${t.url}/browse/${key}` : null, title, edges: g.length };
      });
      for (const c of created) mockTickets.push({ at: new Date().toISOString(), by: "admin", target: t.id, target_name: t.name, key: c.key, url: c.url, title: c.title, edges: [] });
      return ok({ created, errors: [], missing: [] });
    }
  }
  if (p === "/notify/channels") {
    if (method === "GET") return getChannels();
    if (method === "PUT") return putChannels(b);
  }
  if (p === "/schedules") {
    if (method === "GET") return listSchedules();
    if (method === "POST") return saveSchedule(b);
  }
  if ((m = /^\/schedules\/([^/]+)$/.exec(p))) {
    const id = decodeURIComponent(m[1]!);
    if (method === "PUT") return saveSchedule(b, id);
    if (method === "DELETE") return deleteSchedule(id);
  }
  if (method === "POST" && (m = /^\/schedules\/([^/]+)\/run$/.exec(p))) {
    return runSchedule(decodeURIComponent(m[1]!), computingProgress() === null);
  }
  if (p === "/alerts/rules") {
    if (method === "GET") return getRules();
    if (method === "PUT") return putRules(b);
  }
  if (method === "GET" && p === "/alerts") return listAlerts(num("limit", 100));
  if (method === "POST" && p === "/nodes/filter") return filterNodes(b);
  if (method === "GET" && p === "/columns") return columns();
  return null;
}

function routePublic(req: ApiRequest): ApiResponse {
  const { method, path: p, body } = req;
  if (method === "GET" && p === "/auth/providers") return ok(providers());
  if (method === "POST" && p === "/auth/oidc/exchange") return oidcExchange(String((body as { code?: unknown } | undefined)?.code ?? ""));
  if (method === "GET" && p === "/health") {
    return ok({
      status: "ok",
      graph_loaded: true,
      version: "0.3.0-mock",
      generation: state.generation,
      limits: LIMITS,
      snapshot_id: state.snapshotId,
    } satisfies Health);
  }
  if (method === "POST" && p === "/login") {
    const { username, password } = (body ?? {}) as { username?: string; password?: string };
    return login(username ?? "", password ?? "");
  }
  return fail(404, "no such endpoint");
}

function routeData(req: ApiRequest, who: Principal): ApiResponse {
  const { method, path: p, query = {}, body } = req;

  const str = (k: string) => (query[k] === undefined ? undefined : String(query[k]));
  const num = (k: string, d: number) => (query[k] === undefined ? d : Number(query[k]));
  let m: RegExpExecArray | null;

  if (method === "POST" && p === "/logout") {
    logout(req.token ?? "");
    return ok({});
  }
  if (method === "GET" && p === "/stats") return ok(stats());
  if (method === "GET" && p === "/search") return ok(search(str("q") ?? "", num("limit", 20), str("kind")));
  if (method === "GET" && p === "/nodes") {
    const ids = (str("ids") ?? "").split(",").filter(Boolean).slice(0, 5000).map(Number);
    return ok(ids.flatMap((id) => {
      const n = getNode(id);
      return n ? [publicNode(n)] : [];
    }));
  }
  if (method === "GET" && (m = /^\/nodes\/(\d+)$/.exec(p))) {
    const n = getNode(Number(m[1]));
    return n ? ok(detail(n)) : fail(404, "node not found");
  }
  if (method === "GET" && (m = /^\/nodes\/(\d+)\/edges$/.exec(p))) {
    const n = getNode(Number(m[1]));
    if (!n) return fail(404, "node not found");
    const dir = str("dir") === "in" ? "in" : "out";
    const kind = str("kind");
    const limit = num("limit", 500);
    const all = (dir === "out" ? outAdj : inAdj)[n.id]!.filter((x) => !kind || x.kind === kind);
    return ok(resultFrom([n.id], all.slice(0, limit), { truncated: all.length > limit, elapsed_ms: 0.1 }));
  }
  if (method === "POST" && (m = /^\/nodes\/(\d+)\/marks$/.exec(p))) {
    const n = getNode(Number(m[1]));
    if (!n) return fail(404, "node not found");
    const marks = (body ?? {}) as MarksRequest;
    if (typeof marks.owned === "boolean") n.owned = marks.owned;
    if (typeof marks.tier0 === "boolean") n.tier0 = marks.tier0;
    return ok(publicNode(n));
  }
  if (method === "POST" && p === "/path") return path(body as PathRequest);
  if (method === "GET" && p === "/tier0") return ok(exposureReport(tier0Targets(), num("top", 25)));
  if (method === "POST" && p === "/nodes/resolve") {
    const ids = new Set(((body as { objectids?: string[] })?.objectids ?? []).slice(0, 5000).map((o) => o.toUpperCase()));
    return ok(nodes.filter((n) => ids.has(n.objectid.toUpperCase())).map(publicNode));
  }
  if (method === "POST" && p === "/subgraph") {
    const ids = new Set(((body as { ids?: NodeId[] })?.ids ?? []).slice(0, 5000).filter((id) => getNode(id)));
    const es = edges.filter((e) => ids.has(e.src) && ids.has(e.dst));
    return ok(resultFrom(ids, es, { generation: state.generation }));
  }
  const v12 = routeV12(method, p, str, num, body);
  if (v12) return v12;
  const v14 = routeV14(method, p, num, body);
  if (v14) return v14;
  if (method === "DELETE" && (m = /^\/query\/(.+)$/.exec(p))) {
    const cancel = runningQueries.get(decodeURIComponent(m[1]!));
    cancel?.();
    return ok({ cancelled: cancel !== undefined });
  }
  if (method === "GET" && p === "/queries") return ok(prebuiltQueries);
  if (method === "GET" && p === "/saved-queries") return ok(savedQueries);
  if (method === "POST" && p === "/saved-queries") return saveQuery((body ?? {}) as Partial<SavedQueryInput>);
  if ((m = /^\/saved-queries\/(.+)$/.exec(p))) {
    const id = decodeURIComponent(m[1]!);
    const i = savedQueries.findIndex((q) => q.id === id);
    if (i < 0) return fail(404, "saved query not found");
    if (method === "PUT") return saveQuery((body ?? {}) as Partial<SavedQueryInput>, savedQueries[i]);
    if (method === "DELETE") {
      savedQueries.splice(i, 1);
      return ok({});
    }
  }
  if (method === "GET" && p === "/edge-kinds") return ok(edgeKinds());
  if (method === "GET" && p === "/edges/composition") return composition(num("src", -1), num("dst", -1), str("kind") ?? "");
  if (method === "GET" && p === "/node-kinds") return ok(nodeKinds());
  if (method === "GET" && p === "/uploads") return ok(uploadsWithSources(uploads));
  if (method === "GET" && p === "/sources") return ok(sourcesResponse(state.generation));
  if (method === "DELETE" && (m = /^\/uploads\/(.+)$/.exec(p))) {
    const name = decodeURIComponent(m[1]!);
    const i = uploads.findIndex((u) => u.name === name);
    if (i < 0) return fail(404, "upload not found");
    uploads.splice(i, 1);
    return ok({});
  }
  if (method === "POST" && p === "/ingest") {
    if (uploads.length === 0) return fail(400, "no uploads to ingest");
    return ok({ job_id: startIngest(who.viaToken ? "api" : "manual") });
  }
  if (method === "GET" && p === "/jobs") return ok(jobs);
  if (method === "GET" && (m = /^\/jobs\/(.+)$/.exec(p))) {
    const job = jobs.find((j) => j.id === decodeURIComponent(m![1]!));
    return job ? ok(job) : fail(404, "job not found");
  }
  return fail(404, `no route for ${method} ${p}`);
}

// Deep-copy so UI code can never mutate the mock's state by reference.
const copy = (res: ApiResponse): ApiResponse => ({ status: res.status, body: JSON.parse(JSON.stringify(res.body)) as unknown });

export const mockBackend: Backend = {
  async request(req) {
    if (req.method === "POST" && req.path === "/query" && authenticate(req.token)) {
      return copy(await runQuery((req.body ?? {}) as Partial<QueryRequest>));
    }
    // Channel tests take a while (retries on a real server); admin-only.
    const test = /^\/notify\/channels\/([^/]+)\/test$/.exec(req.path);
    if (req.method === "POST" && test) {
      const who = authenticate(req.token);
      if (!who) return fail(401, "unauthorized");
      if (!atLeast(who, "admin")) return denied(who, req, "admin");
      return copy(audited(who, req, await testChannel(decodeURIComponent(test[1]!))));
    }
    await delay(80 + Math.random() * 120);
    return copy(route(req));
  },

  async upload(files, token, onProgress) {
    const who = authenticate(token);
    if (!who) return fail(401, "unauthorized");
    if (who.role !== "uploader" && !atLeast(who, "analyst")) return denied(who, { method: "POST", path: "/upload", token }, "analyst");
    const bad = files.find((f) => !LIMITS.upload_extensions.some((ext) => f.name.toLowerCase().endsWith(ext)));
    if (bad) return fail(400, `unsupported file type: ${bad.name}`);
    for (let i = 1; i <= 10; i++) {
      await delay(120);
      onProgress(i / 10);
    }
    const now = new Date().toISOString();
    for (const f of files) {
      const existing = uploads.findIndex((u) => u.name === f.name);
      if (existing >= 0) uploads.splice(existing, 1);
      uploads.push({ name: f.name, size: f.size, uploaded_at: now });
    }
    return ok({ uploaded: files.map((f) => f.name) });
  },

  async fetchFile(req) {
    await delay(300);
    const who = authenticate(req.token);
    if (!who) return { status: 401, body: { error: "unauthorized" }, blob: null, filename: null };
    const progress = computingProgress();
    if (progress !== null) return { status: 202, body: { status: "computing", progress }, blob: null, filename: null };
    const q = req.query ?? {};
    const format = String(q.format ?? "html");
    if (format !== "html" && format !== "md" && format !== "csv") {
      return { status: 400, body: { error: "format must be html, md or csv" }, blob: null, filename: null };
    }
    const { text, type } = renderReport(format, {
      title: String(q.title ?? "").trim() || "Attack path assessment",
      planSteps: Math.min(50, Number(q.plan_steps ?? 10)),
      items: Math.min(10000, Number(q.items ?? 25)),
    });
    return {
      status: 200,
      body: null,
      blob: new Blob([text], { type: `${type};charset=utf-8` }),
      filename: q.download ? `copperhound-report-${state.snapshotId}.${format}` : null,
    };
  },
};
