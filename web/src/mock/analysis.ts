// Mock v1.2 analysis: zones, findings, what-if simulation, remediation plans, posture.

import type {
  Edge,
  Finding,
  FindingDetail,
  FindingItem,
  FindingsResponse,
  ItemLabel,
  NodeId,
  PlanRequest,
  PlanResponse,
  PostureDiff,
  Severity,
  SeverityCounts,
  SimulateRequest,
  SimulateResponse,
  Snapshot,
  ZoneReviewDecision,
  Zone,
  ZoneInput, ZoneObjectsResponse, RiskAcceptance } from "../api/types";
import { edges, nodes, type MockNode } from "./data";
import { computeExposure, edgeId, exposureState, tier0Targets, type Removal } from "./exposure";
import { edgeAllowed, outAdj, publicNode, resultFrom } from "./graph";
import { parseChql, ChqlError, runChql } from "./chql";

// --- shared snapshot state ------------------------------------------------------

export const state = {
  generation: 1,
  snapshotId: "snap-0009",
  loadedAt: new Date().toISOString(),
  /** Analysis endpoints answer 202 until this time (ms epoch). */
  computingFrom: 0,
  computingUntil: 0,
};

/** Progress 0-100 while analysis is "running", or null when ready. */
export function computingProgress(): number | null {
  const now = Date.now();
  if (now >= state.computingUntil) return null;
  return Math.round(((now - state.computingFrom) / (state.computingUntil - state.computingFrom)) * 100);
}

export function installSnapshot(): void {
  recordSnapshot(); // keep the outgoing graph in history before replacing it
  state.generation++;
  state.snapshotId = `snap-${String(Number(state.snapshotId.slice(5)) + 1).padStart(4, "0")}`;
  state.loadedAt = new Date().toISOString();
  state.computingFrom = Date.now();
  state.computingUntil = Date.now() + 6000;
}

// --- zones ---------------------------------------------------------------------------

export class ZoneError extends Error {
  constructor(
    message: string,
    readonly position: number | null = null,
    readonly code: "syntax" | "semantic" | undefined = undefined,
  ) {
    super(message);
  }
}

const zoneDefs: Omit<Zone, "member_count">[] = [
  {
    id: "tier0",
    name: "Tier Zero",
    description: "Objects flagged Tier Zero (built in).",
    selector: "MATCH (n {tier0:true}) RETURN n",
    color: "#f5f5f4",
    objects: [],
    builtin: true,
    weight: 5,
  },
  {
    id: "z-azure-control",
    name: "Azure control plane",
    description: "Entra ID roles, the tenant and production subscription.",
    selector: "MATCH (n:AZRole|AZTenant|AZSubscription) RETURN n",
    color: "#38bdf8",
    objects: [],
    builtin: false,
    weight: 3,
  },
  {
    id: "z-db",
    name: "Database servers",
    description: "SQL servers and their admin group.",
    selector: "MATCH (n) WHERE n.name STARTS WITH 'SQL' RETURN n",
    color: "#f59e0b",
    objects: [],
    builtin: false,
    weight: 2,
  },
];
let zoneSeq = 0;
const PALETTE = ["#a78bfa", "#34d399", "#fb7185", "#facc15", "#60a5fa"];

/** Mock zone review decisions: zone id → objectid → decision. */
export const zoneReviews = new Map<string, Map<string, ZoneReviewDecision>>();

export function zoneSelectorMatches(zoneId: string): MockNode[] | null {
  const z = zoneDefs.find((x) => x.id === zoneId);
  if (!z) return null;
  if (z.builtin) return nodes.filter((n) => n.tier0);
  const byHand = new Set(z.objects);
  let ids = new Set<NodeId>();
  try {
    if (z.selector.trim()) ids = new Set(runChql(z.selector, 100000).nodes.map((n) => n.id));
  } catch {
    // A broken selector matches nothing; hand-added objects still count.
  }
  return nodes.filter((n) => ids.has(n.id) || byHand.has(n.objectid.toUpperCase()));
}

export function zoneMembers(zoneId: string): MockNode[] | null {
  const m = zoneSelectorMatches(zoneId);
  const r = zoneReviews.get(zoneId);
  return m && r ? m.filter((n) => r.get(n.objectid.toUpperCase())?.status !== "revoked") : m;
}

export function listZones(): Zone[] {
  return zoneDefs.map((z) => ({ ...z, member_count: zoneMembers(z.id)?.length ?? 0 }));
}

export function saveZone(input: Partial<ZoneInput>, id?: string): Zone {
  const existing = id ? zoneDefs.find((z) => z.id === id) : undefined;
  if (id && !existing) throw new ZoneError("zone not found");
  if (existing?.builtin) throw new ZoneError("the built-in Tier Zero zone cannot be edited");
  if (!input.name?.trim()) throw new ZoneError("name is required");
  if (input.weight !== undefined && !validWeight(input.weight)) throw new ZoneError("weight must be 0-100");
  const selector = input.selector?.trim() ?? "";
  const objects = input.objects ? cleanOids(input.objects) : undefined;
  if (selector) {
    try {
      parseChql(selector);
      if (runChql(selector, 100000).columns) throw new ZoneError("selector must return nodes, not columns", null, "semantic");
    } catch (e) {
      if (e instanceof ChqlError) throw new ZoneError(e.message, e.position, e.code);
      throw e;
    }
  }
  const fields = {
    name: input.name.trim(),
    description: input.description?.trim() ?? "",
    selector,
    color: input.color && /^#[0-9a-f]{6}$/i.test(input.color) ? input.color : (existing?.color ?? PALETTE[zoneSeq % PALETTE.length]!),
  };
  if (existing) {
    Object.assign(existing, fields);
    if (input.weight !== undefined) existing.weight = input.weight;
    if (objects) existing.objects = objects;
    return { ...existing, member_count: zoneMembers(existing.id)!.length };
  }
  const z = { id: `z-${++zoneSeq}-${Date.now().toString(36)}`, builtin: false, weight: input.weight ?? 1, objects: objects ?? [], ...fields };
  zoneDefs.push(z);
  certify(z.id, z.objects);
  return { ...z, member_count: zoneMembers(z.id)!.length };
}

function cleanOids(oids: unknown[]): string[] {
  const out = new Set<string>();
  for (const o of oids) {
    const s = String(o).trim().toUpperCase();
    if (!s || s.length > 256) throw new ZoneError("object ids must be 1-256 characters");
    if (!nodes.some((n) => n.objectid.toUpperCase() === s)) throw new ZoneError(`not in the graph: ${s}`);
    out.add(s);
  }
  return [...out].sort();
}

/** Hand-added objects are certified in zone review. */
function certify(zoneId: string, oids: string[]) {
  if (oids.length === 0) return;
  const m = zoneReviews.get(zoneId) ?? new Map<string, ZoneReviewDecision>();
  for (const o of oids) m.set(o, { status: "certified", by: "admin", at: new Date().toISOString(), note: "added by hand" });
  zoneReviews.set(zoneId, m);
}

/** POST /zones/{id}/objects. */
export function zoneObjects(id: string, change: { add?: string[]; remove?: string[] }): ZoneObjectsResponse {
  const z = zoneDefs.find((x) => x.id === id);
  if (!z) throw new ZoneError("zone not found");
  if (z.builtin) throw new ZoneError("add objects to Tier Zero with Mark Tier Zero");
  const add = cleanOids(change.add ?? []);
  const remove = (change.remove ?? []).map((o) => o.trim().toUpperCase());
  if (add.length === 0 && remove.length === 0) throw new ZoneError("nothing to add or remove");
  const added = add.filter((o) => !z.objects.includes(o));
  const removed = remove.filter((o) => z.objects.includes(o) && !add.includes(o));
  z.objects = [...z.objects.filter((o) => !removed.includes(o)), ...added].sort();
  certify(id, add);
  removed.forEach((o) => zoneReviews.get(id)?.delete(o));
  const still = new Set((zoneSelectorMatches(id) ?? []).map((n) => n.objectid.toUpperCase()));
  return {
    zone: { ...z, member_count: zoneMembers(id)!.length },
    added: added.length,
    removed: removed.length,
    still_matched: removed.filter((o) => still.has(o)),
  };
}

const validWeight = (w: unknown): w is number => typeof w === "number" && Number.isInteger(w) && w >= 0 && w <= 100;

/** PUT /zones/{id}/weight (Tier Zero included). */
export function setZoneWeight(id: string, weight: unknown): { id: string; weight: number } {
  const z = zoneDefs.find((x) => x.id === id);
  if (!z) throw new ZoneError("zone not found");
  if (!validWeight(weight)) throw new ZoneError("weight must be 0-100");
  z.weight = weight;
  return { id, weight };
}

export function deleteZone(id: string): void {
  const i = zoneDefs.findIndex((z) => z.id === id);
  if (i < 0) throw new ZoneError("zone not found");
  if (zoneDefs[i]!.builtin) throw new ZoneError("the built-in Tier Zero zone cannot be deleted");
  zoneDefs.splice(i, 1);
}

export function zoneTargets(zoneId: string | undefined): Set<NodeId> | null {
  if (!zoneId || zoneId === "tier0") return tier0Targets();
  const m = zoneMembers(zoneId);
  return m ? new Set(m.map((n) => n.id)) : null;
}

// --- findings ------------------------------------------------------------------------

interface FindingDef extends Omit<Finding, "count" | "exposure"> {
  detect: () => FindingItem[];
}

const node = (n: MockNode) => ({ node: publicNode(n) });
const edgeItem = (e: Edge) => ({ src: publicNode(nodes[e.src]!), dst: publicNode(nodes[e.dst]!), kind: e.kind });
const edgesWhere = (f: (e: Edge, s: MockNode, d: MockNode) => boolean) =>
  edges.filter((e) => f(e, nodes[e.src]!, nodes[e.dst]!)).map(edgeItem);
const prop = (n: MockNode, k: string) => n.properties[k];
const DAY = 86400;

const FINDINGS: FindingDef[] = [
  {
    id: "dcsync-non-tier0",
    title: "Non-Tier Zero principals can DCSync",
    severity: "critical",
    category: "Active Directory",
    kind: "edges",
    description:
      "These principals hold replication rights (DS-Replication-Get-Changes and -All) on the domain without being Tier Zero.",
    impact: "Anyone controlling them can request password hashes for every account, including krbtgt, and forge tickets.",
    remediation:
      "Remove the replication rights from the domain object's ACL.\n\n- Only domain controllers and Tier Zero administrators should hold them.\n- Re-run the analysis after the change to confirm the edge is gone.",
    mitre: ["T1003.006"],
    query: "MATCH (p)-[r:DCSync]->(d:Domain) WHERE NOT p.tier0 RETURN p, r, d",
    detect: () => edgesWhere((e, s) => e.kind === "DCSync" && !s.tier0),
  },
  {
    id: "adcs-esc1",
    title: "Certificate template allows enrollee-supplied subject (ESC1)",
    severity: "critical",
    category: "ADCS",
    kind: "edges",
    description: "A published template lets the requester choose the subject and allows client authentication.",
    impact: "Any principal that can enroll can request a certificate as a domain admin and authenticate as them.",
    remediation:
      "On the template:\n\n1. Clear “Supply in the request”.\n2. Require manager approval, or remove Client Authentication from the EKUs.\n3. Restrict enrollment rights to the accounts that need them.",
    mitre: ["T1649"],
    query: "MATCH (p)-[r:ADCSESC1]->(d:Domain) RETURN p, r, d",
    detect: () => edgesWhere((e) => e.kind === "ADCSESC1"),
  },
  {
    id: "generic-all-privileged",
    title: "Full control over privileged groups or hosts",
    severity: "high",
    category: "Active Directory",
    kind: "edges",
    description: "Non-Tier Zero principals hold GenericAll on groups or computers.",
    impact: "Full control lets an attacker add members, reset passwords or take over the computer object.",
    remediation: "Remove the GenericAll ACE, or replace it with the narrow right that is actually required.",
    mitre: ["T1098", "T1484"],
    query: "MATCH (a)-[r:GenericAll]->(t:Group|Computer) WHERE NOT a.tier0 RETURN a, r, t",
    detect: () => edgesWhere((e, s, d) => e.kind === "GenericAll" && !s.tier0 && (d.kind === "Group" || d.kind === "Computer")),
  },
  {
    id: "acl-write-users",
    title: "Write rights over other users",
    severity: "high",
    category: "Active Directory",
    kind: "edges",
    description: "GenericWrite, WriteDacl, WriteOwner or ForceChangePassword on users, groups or GPOs.",
    impact: "Lets an attacker set an SPN (targeted Kerberoasting), add shadow credentials, or reset the password.",
    remediation: "Review each ACE. Delegate password resets through a dedicated, monitored group.",
    mitre: ["T1098", "T1222.001"],
    query: "MATCH (a)-[r:GenericWrite|WriteDacl|WriteOwner|ForceChangePassword]->(b) RETURN a, r, b",
    detect: () => edgesWhere((e) => ["GenericWrite", "WriteDacl", "WriteOwner", "ForceChangePassword"].includes(e.kind)),
  },
  {
    id: "unconstrained-delegation",
    title: "Unconstrained delegation outside Tier Zero",
    severity: "high",
    category: "Active Directory",
    kind: "nodes",
    description: "Computers trusted for unconstrained delegation that are not domain controllers.",
    impact: "Any user authenticating to them leaves a forwardable TGT in memory. Coerced DC authentication leads to domain compromise.",
    remediation: "Switch to constrained or resource-based constrained delegation, and add admins to Protected Users.",
    mitre: ["T1558"],
    query: "MATCH (c:Computer {unconstraineddelegation:true}) WHERE NOT c.tier0 RETURN c",
    detect: () => nodes.filter((n) => n.kind === "Computer" && prop(n, "unconstraineddelegation") === true && !n.tier0).map(node),
  },
  {
    id: "kerberoastable",
    title: "Kerberoastable user accounts",
    severity: "medium",
    category: "Active Directory",
    kind: "nodes",
    description: "Enabled users with a service principal name.",
    impact: "Any domain user can request a service ticket and crack the account's password offline.",
    remediation: "Use gMSAs for services, or set 25+ character random passwords and AES-only encryption types.",
    mitre: ["T1558.003"],
    query: "MATCH (u:User {hasspn:true}) WHERE u.enabled RETURN u",
    detect: () => nodes.filter((n) => n.kind === "User" && n.enabled && prop(n, "hasspn") === true).map(node),
  },
  {
    id: "asrep-roastable",
    title: "AS-REP roastable users",
    severity: "medium",
    category: "Active Directory",
    kind: "nodes",
    description: "Users that do not require Kerberos pre-authentication.",
    impact: "Anyone on the network can request encrypted material for these accounts and crack it offline.",
    remediation: "Enable Kerberos pre-authentication (clear DONT_REQ_PREAUTH).",
    mitre: ["T1558.004"],
    query: "MATCH (u:User {dontreqpreauth:true}) RETURN u",
    detect: () => nodes.filter((n) => n.kind === "User" && prop(n, "dontreqpreauth") === true).map(node),
  },
  {
    id: "rdp-broad",
    title: "Broad RDP access to servers and workstations",
    severity: "medium",
    category: "Active Directory",
    kind: "edges",
    description: "Groups with CanRDP to computers.",
    impact: "Interactive logon exposes the credentials of other users on those hosts.",
    remediation: "Limit Remote Desktop Users membership. Use a jump host for administration.",
    mitre: ["T1021.001"],
    query: "MATCH (a)-[r:CanRDP]->(c:Computer) RETURN a, r, c",
    detect: () => edgesWhere((e) => e.kind === "CanRDP"),
  },
  {
    id: "privileged-sessions",
    title: "Sessions on hosts administered from outside Tier Zero",
    severity: "high",
    category: "Active Directory",
    kind: "edges",
    description: "Users have sessions on computers that non-Tier-Zero principals can administer.",
    impact: "Local admins on those hosts can harvest the logged-on users' credentials.",
    remediation: "Enforce tiered logon restrictions, and use Credential Guard and Protected Users.",
    mitre: ["T1003.001"],
    query: "MATCH (a)-[:AdminTo]->(c:Computer)-[r:HasSession]->(u:User) RETURN c, r, u",
    detect: () => edgesWhere((e, s) => e.kind === "HasSession" && edges.some((x) => x.kind === "AdminTo" && x.dst === s.id)),
  },
  {
    id: "stale-enabled-users",
    title: "Enabled users inactive for 90+ days",
    severity: "low",
    category: "Active Directory",
    kind: "nodes",
    description: "Enabled accounts that have not logged on in 90 days.",
    impact: "Dormant accounts are attractive targets, because their compromise goes unnoticed.",
    remediation: "Disable the accounts, then delete them after a retention period.",
    mitre: ["T1078.002"],
    query: "MATCH (u:User {enabled:true}) WHERE u.lastlogontimestamp < days_ago(90) RETURN u",
    detect: () =>
      nodes
        .filter((n) => n.kind === "User" && n.enabled && (prop(n, "lastlogontimestamp") as number) < Date.now() / 1000 - 90 * DAY)
        .map(node),
  },
  {
    id: "pwd-never-expires",
    title: "Passwords set to never expire",
    severity: "low",
    category: "Active Directory",
    kind: "nodes",
    description: "Enabled users with DONT_EXPIRE_PASSWORD.",
    impact: "Long-lived passwords are more likely to be reused, leaked or cracked.",
    remediation: "Clear the flag and rely on banned-password lists plus MFA.",
    mitre: ["T1078"],
    query: "MATCH (u:User {pwdneverexpires:true}) WHERE u.enabled RETURN u",
    detect: () => nodes.filter((n) => n.kind === "User" && n.enabled && prop(n, "pwdneverexpires") === true).map(node),
  },
  {
    id: "az-sp-global-admin",
    title: "Service principal holds Global Administrator",
    severity: "critical",
    category: "Azure",
    kind: "edges",
    description: "An application identity is assigned the Global Administrator role.",
    impact: "Anyone who can add a secret to the app, or who owns it, controls the whole tenant.",
    remediation: "Give the pipeline a least-privilege role and use PIM for any remaining elevation.",
    mitre: ["T1098.003"],
    query: "MATCH (sp:AZServicePrincipal)-[r:AZHasRole]->(role:AZRole {name:'GLOBAL ADMINISTRATOR@CORP TENANT'}) RETURN sp, r, role",
    detect: () =>
      edgesWhere((e, s, d) => e.kind === "AZHasRole" && s.kind === "AZServicePrincipal" && d.name.startsWith("GLOBAL ADMINISTRATOR")),
  },
  {
    id: "az-app-secret",
    title: "Roles that can add secrets to privileged applications",
    severity: "high",
    category: "Azure",
    kind: "edges",
    description: "AZAddSecret edges into applications whose service principal is privileged.",
    impact: "Adding a credential to the app gives the attacker the app's privileges.",
    remediation: "Restrict Application Administrator, and use app instance lock on privileged apps.",
    mitre: ["T1098.001"],
    query: "MATCH (a)-[r:AZAddSecret]->(app:AZApp) RETURN a, r, app",
    detect: () => edgesWhere((e) => e.kind === "AZAddSecret"),
  },
  {
    id: "hybrid-synced-privileged",
    title: "Synced on-prem users with cloud access",
    severity: "medium",
    category: "Hybrid",
    kind: "edges",
    description: "On-premises accounts synchronised to Entra ID.",
    impact: "Compromising the on-prem account, or the sync server, carries over to the cloud identity.",
    remediation: "Use cloud-only accounts for cloud administration and protect the sync server as Tier Zero.",
    mitre: ["T1078.004"],
    query: "MATCH (u:User)-[r:SyncedToEntraUser]->(a:AZUser) RETURN u, r, a",
    detect: () => edgesWhere((e) => e.kind === "SyncedToEntraUser"),
  },
];

/** Item keys as used for posture diffs. */
const itemKey = (i: FindingItem) => ("node" in i ? `n:${i.node.objectid}` : `e:${i.src.objectid}|${i.kind}|${i.dst.objectid}`);
const itemLabel = (i: FindingItem) => ("node" in i ? i.node.name : `${i.src.name} -[${i.kind}]-> ${i.dst.name}`);

function evaluate(def: FindingDef): Finding & { items: FindingItem[] } {
  const items = def.detect();
  let exposure: Finding["exposure"] = null;
  if (def.kind === "edges" && items.length > 0) {
    const targets = tier0Targets();
    const before = computeExposure(targets).exposed.length;
    const removeIds = new Set(
      items.map((i) => ("src" in i ? `${i.src.id}|${i.kind}|${i.dst.id}` : "")),
    );
    const after = computeExposure(targets, { edges: removeIds }).exposed.length;
    exposure = {
      principals_cut: before - after,
      percent_of_exposed: before ? Math.round(((before - after) / before) * 1000) / 10 : 0,
      target: "Tier Zero",
    };
  }
  const { detect: _detect, ...rest } = def;
  return { ...rest, count: items.length, exposure, items };
}

/** Mock risk acceptances by finding id. */
export const acceptances = new Map<string, RiskAcceptance>();

export function findingsResponse(): FindingsResponse {
  const all = FINDINGS.map(evaluate).filter((f) => f.count > 0);
  const summary: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  const summaryAll: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of all) {
    summaryAll[f.severity]++;
    if (!acceptances.has(f.id)) summary[f.severity]++;
  }
  return {
    status: "ready",
    snapshot_id: state.snapshotId,
    computed_ms: 41,
    summary,
    summary_all: summaryAll,
    accepted_count: all.filter((f) => acceptances.has(f.id)).length,
    findings: all.map(({ items: _items, ...f }) => ({ ...f, accepted: acceptances.get(f.id) ?? null })),
  };
}

export function findingDetail(id: string, offset: number, limit: number): FindingDetail | null {
  const def = FINDINGS.find((f) => f.id === id);
  if (!def) return null;
  const f = evaluate(def);
  if (f.count === 0) return null;
  const drawn = f.items.slice(0, 500);
  const ids = new Set<NodeId>();
  const es: Edge[] = [];
  for (const i of drawn) {
    if ("node" in i) ids.add(i.node.id);
    else es.push({ src: i.src.id, dst: i.dst.id, kind: i.kind });
  }
  return { ...f, accepted: acceptances.get(id) ?? null, items: f.items.slice(offset, offset + limit), total: f.items.length, graph: resultFrom(ids, es) };
}

// --- simulation & planning ------------------------------------------------------------

export function simulate(req: SimulateRequest): SimulateResponse | null {
  const targets = zoneTargets(req.zone);
  if (!targets) return null;
  for (const t of req.add_targets ?? []) targets.add(t);
  const before = computeExposure(zoneTargets(req.zone)!);
  const removal: Removal = {
    edges: new Set((req.remove_edges ?? []).map(edgeId)),
    kinds: new Set(req.remove_kinds ?? []),
    nodes: new Set(req.remove_nodes ?? []),
  };
  const after = computeExposure(targets, removal);
  const reduction = before.exposed.length - after.exposed.length;
  return {
    before: exposureState(before),
    after: exposureState(after),
    reduction,
    reduction_percent: before.exposed.length ? Math.round((reduction / before.exposed.length) * 1000) / 10 : 0,
    elapsed_ms: 2.4,
  };
}

/**
 * Mock of the dominator-tree planner. The graph is tiny, so exact cuts can be found by
 * brute force: for every exposed object, remove its onward attack edges and measure how
 * many principals lose every path. Pick the best object, repeat.
 */
export function remediationPlan(req: PlanRequest): PlanResponse | null {
  if (req.weighted) return weightedPlan(req);
  const zone = zoneTargets(req.zone);
  if (!zone) return null;
  const fixed = new Set(req.fixed_kinds ?? []);
  const targets = new Set(zone);
  if (req.protect_target_membership ?? true) {
    // Members of zone groups count as part of the zone (transitively).
    let grew = true;
    while (grew) {
      grew = false;
      for (const e of edges) {
        if (e.kind === "MemberOf" && targets.has(e.dst) && !targets.has(e.src)) {
          targets.add(e.src);
          grew = true;
        }
      }
    }
  }
  const removed = new Set<string>();
  const baseline = computeExposure(zone).exposed.length;
  const steps: PlanResponse["steps"] = [];
  const maxSteps = Math.min(50, Math.max(1, req.steps ?? 10));
  let exposedNow = computeExposure(targets).exposed.length;
  for (let i = 0; i < maxSteps && exposedNow > 0; i++) {
    const cur = computeExposure(targets, { edges: removed });
    let best: { id: NodeId; edges: Edge[]; after: number } | null = null;
    for (const id of cur.exposed) {
      const onward = (outAdj[id] ?? []).filter(
        (e) => !fixed.has(e.kind) && !removed.has(edgeId(e)) && edgeAllowed(e, {}) && cur.next.has(e.dst),
      );
      if (onward.length === 0) continue;
      const trial = new Set([...removed, ...onward.map(edgeId)]);
      const after = computeExposure(targets, { edges: trial }).exposed.length;
      if (!best || after < best.after || (after === best.after && onward.length < best.edges.length)) {
        best = { id, edges: onward, after };
      }
    }
    if (!best || best.after >= exposedNow) break;
    best.edges.forEach((e) => removed.add(edgeId(e)));
    const cut = exposedNow - best.after;
    exposedNow = best.after;
    // Report against the zone as requested (protected members are not principals to cut).
    const exposedAfter = computeExposure(zone, { edges: removed }).exposed.length;
    steps.push({
      node: publicNode(nodes[best.id]!),
      edges: best.edges.slice(0, 50).map((e) => ({ src: publicNode(nodes[e.src]!), dst: publicNode(nodes[e.dst]!), kind: e.kind })),
      edge_count: best.edges.length,
      principals_cut: cut,
      exposed_after: exposedAfter,
      cumulative_reduction_percent: baseline ? Math.round(((baseline - exposedAfter) / baseline) * 1000) / 10 : 0,
      needs_window: false,
    });
  }
  return { baseline, truncated: false, steps, elapsed_ms: 18.4 };
}

/** Zone members plus everything that joins them through group membership. */
function expandMembership(zone: Set<NodeId>): Set<NodeId> {
  const targets = new Set(zone);
  let grew = true;
  while (grew) {
    grew = false;
    for (const e of edges) {
      if (e.kind === "MemberOf" && targets.has(e.dst) && !targets.has(e.src)) {
        targets.add(e.src);
        grew = true;
      }
    }
  }
  return targets;
}

/**
 * Mock of the cross-zone planner, by brute force: each step severs the object whose onward
 * edges cut the most weighted exposure (sum over zones of weight × principals cut off).
 */
function weightedPlan(req: PlanRequest): PlanResponse | null {
  const overrides = req.weights ?? {};
  if (Object.keys(overrides).some((id) => !zoneDefs.some((z) => z.id === id))) throw new ZoneError("unknown zone in weights");
  if (Object.values(overrides).some((w) => !validWeight(w))) throw new ZoneError("weight must be 0-100");
  const all = zoneDefs.map((z) => ({ def: z, weight: overrides[z.id] ?? z.weight }));
  const used = all.filter((z) => z.weight > 0);
  if (used.length === 0) throw new ZoneError("every zone has weight 0");
  const protect = req.protect_target_membership ?? true;
  const zs = used.map((z) => {
    const members = zoneTargets(z.def.id)!;
    return { ...z, targets: protect ? expandMembership(members) : members };
  });
  const fixed = new Set(req.fixed_kinds ?? []);
  const removed = new Set<string>();
  const exposedNow = zs.map((z) => computeExposure(z.targets).exposed.length);
  const zoneBaselines = [...exposedNow];
  const baseline = zs.reduce((s, z, i) => s + z.weight * exposedNow[i]!, 0);
  let left = baseline;
  const steps: PlanResponse["steps"] = [];
  const maxSteps = Math.min(50, Math.max(1, req.steps ?? 10));
  for (let i = 0; i < maxSteps && left > 0; i++) {
    const cur = zs.map((z) => computeExposure(z.targets, { edges: removed }));
    const candidates = new Set(cur.flatMap((c) => c.exposed));
    let best: { id: NodeId; edges: Edge[]; after: number[]; score: number } | null = null;
    for (const id of candidates) {
      const own = cur.filter((c, z) => c.exposed.includes(id) && !zs[z]!.targets.has(id));
      const onward = (outAdj[id] ?? []).filter(
        (e) => !fixed.has(e.kind) && !removed.has(edgeId(e)) && edgeAllowed(e, {}) && own.some((c) => c.next.has(e.dst)),
      );
      if (onward.length === 0) continue;
      const trial = new Set([...removed, ...onward.map(edgeId)]);
      const after = zs.map((z) => computeExposure(z.targets, { edges: trial }).exposed.length);
      const score = zs.reduce((s, z, k) => s + z.weight * (exposedNow[k]! - after[k]!), 0);
      if (score > 0 && (!best || score > best.score || (score === best.score && onward.length < best.edges.length))) {
        best = { id, edges: onward, after, score };
      }
    }
    if (!best) break;
    best.edges.forEach((e) => removed.add(edgeId(e)));
    const cuts = zs.map((z, k) => ({ id: z.def.id, principals_cut: exposedNow[k]! - best.after[k]!, exposed_after: best.after[k]! }));
    best.after.forEach((a, k) => (exposedNow[k] = a));
    left -= best.score;
    steps.push({
      node: publicNode(nodes[best.id]!),
      edges: best.edges.slice(0, 50).map((e) => ({ src: publicNode(nodes[e.src]!), dst: publicNode(nodes[e.dst]!), kind: e.kind })),
      edge_count: best.edges.length,
      principals_cut: cuts.reduce((s, c) => s + c.principals_cut, 0),
      exposed_after: cuts.reduce((s, c) => s + c.exposed_after, 0),
      score: best.score,
      score_after: left,
      zones: cuts,
      cumulative_reduction_percent: baseline ? Math.round(((baseline - left) / baseline) * 1000) / 10 : 0,
      needs_window: false,
    });
  }
  return {
    weighted: true,
    baseline,
    truncated: false,
    zones: zs.map((z, k) => ({ id: z.def.id, name: z.def.name, color: z.def.color, weight: z.weight, baseline: zoneBaselines[k]! })),
    excluded_zones: all.filter((z) => z.weight === 0).map((z) => z.def.id),
    steps,
    elapsed_ms: 24.1,
  };
}

// --- posture -------------------------------------------------------------------------

interface StoredSnapshot extends Snapshot {
  items: Record<string, ItemLabel[]>;
}

function currentItems(): Record<string, ItemLabel[]> {
  const out: Record<string, ItemLabel[]> = {};
  for (const def of FINDINGS) out[def.id] = def.detect().map((i) => ({ key: itemKey(i), label: itemLabel(i) }));
  return out;
}

function snapshotOf(id: string, createdAt: string, items: Record<string, ItemLabel[]>, weeksAgo = 0): StoredSnapshot {
  const targets = tier0Targets();
  const r = computeExposure(targets);
  const total = nodes.length - targets.size;
  // Older snapshots were a bit worse (about 2.5 percentage points per week).
  const exposed = Math.min(total, r.exposed.length + Math.round(weeksAgo * 0.025 * total));
  const findings: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  const finding_counts: Record<string, number> = {};
  for (const def of FINDINGS) {
    const n = items[def.id]?.length ?? 0;
    if (n === 0) continue;
    finding_counts[def.id] = n;
    findings[def.severity as Severity]++;
  }
  return {
    snapshot_id: id,
    created_at: createdAt,
    nodes: nodes.length + weeksAgo * 3,
    edges: edges.length + weeksAgo * 7,
    tier0: targets.size,
    exposed_principals: exposed,
    total_principals: total,
    exposure_percent: Math.round((exposed / total) * 1000) / 10,
    findings,
    finding_counts,
    items,
  };
}

/** Synthetic history: older snapshots had more stale accounts and broader rights. */
function buildHistory(): StoredSnapshot[] {
  const cur = currentItems();
  const out: StoredSnapshot[] = [];
  const weeks = 8;
  for (let w = weeks; w >= 1; w--) {
    const items: Record<string, ItemLabel[]> = {};
    for (const [id, list] of Object.entries(cur)) {
      const extra = Math.max(0, Math.round((w * (id.length % 3)) / 2));
      const legacy = Array.from({ length: extra }, (_, k) => ({
        key: `legacy:${id}:${k}`,
        label: id.includes("users") || id.includes("roast") || id.includes("pwd") || id.includes("stale")
          ? `OLD-ACCOUNT-${k + 1}@CORP.LOCAL`
          : `LEGACY-SVC-${k + 1}@CORP.LOCAL -[GenericAll]-> SRV-${String(k + 1).padStart(2, "0")}@CORP.LOCAL`,
      }));
      // A few current items only appeared recently.
      items[id] = [...legacy, ...list.slice(0, Math.max(0, list.length - (w > 5 ? 1 : 0)))];
    }
    const created = new Date(Date.now() - w * 7 * 86400_000).toISOString();
    out.push(snapshotOf(`snap-${String(9 - w).padStart(4, "0")}`, created, items, w));
  }
  return out;
}

let history: StoredSnapshot[] | null = null;
const historyList = () => (history ??= buildHistory());

function recordSnapshot(): void {
  historyList().push(snapshotOf(state.snapshotId, state.loadedAt, currentItems()));
}

const strip = ({ items: _items, ...s }: StoredSnapshot): Snapshot => s;

export function posture(): Snapshot[] {
  return [...historyList(), snapshotOf(state.snapshotId, state.loadedAt, currentItems())].map(strip);
}

export function deleteSnapshot(id: string): boolean {
  const h = historyList();
  const i = h.findIndex((s) => s.snapshot_id === id);
  if (i < 0) return false;
  h.splice(i, 1);
  return true;
}

export function postureDiff(from: string, to: string): PostureDiff | null {
  const all = [...historyList(), snapshotOf(state.snapshotId, state.loadedAt, currentItems())];
  const a = all.find((s) => s.snapshot_id === from);
  const b = all.find((s) => s.snapshot_id === to);
  if (!a || !b) return null;
  const out: PostureDiff = { from, to, findings: [] };
  for (const def of FINDINGS) {
    const before = new Map((a.items[def.id] ?? []).map((i) => [i.key, i]));
    const after = new Map((b.items[def.id] ?? []).map((i) => [i.key, i]));
    const added = [...after.values()].filter((i) => !before.has(i.key));
    const removed = [...before.values()].filter((i) => !after.has(i.key));
    if (added.length === 0 && removed.length === 0) continue;
    out.findings.push({
      id: def.id,
      title: def.title,
      severity: def.severity,
      added: added.length,
      removed: removed.length,
      added_items: added.slice(0, 200),
      removed_items: removed.slice(0, 200),
    });
  }
  return out;
}
