// Small but realistic sample environment for mock mode: one AD domain (CORP.LOCAL)
// with ADCS and a synced Entra ID tenant. Deterministic so screenshots are stable.

import type { Edge, KindCategory, Node, NodeKind, PrebuiltQuery } from "../api/types";

export interface MockNode extends Node {
  properties: Record<string, unknown>;
}

const DOMAIN = "CORP.LOCAL";
const DOMAIN_SID = "S-1-5-21-3623811015-3361044348-30300820";
const TENANT = "corp.onmicrosoft.com";
const TENANT_ID = "6f1c2a4e-9b8d-4e1a-8c3f-2d7b5a9e0c41";
// Timestamps are relative to "now" so days_ago() queries give stable, meaningful results.
const BASE_TIME = Math.floor(Date.now() / 1000) - 86400;

export const nodes: MockNode[] = [];
export const edges: Edge[] = [];
const byName = new Map<string, MockNode>();

let rid = 1100;
function add(
  kind: NodeKind,
  shortName: string,
  opts: { tier0?: boolean; enabled?: boolean; props?: Record<string, unknown>; objectid?: string; fullName?: string } = {},
): MockNode {
  const isAz = kind.startsWith("AZ");
  const name = opts.fullName ?? (isAz ? shortName : `${shortName}@${DOMAIN}`);
  const objectid =
    opts.objectid ??
    (isAz
      ? `${(0x1000_0000 + nodes.length * 7919).toString(16)}-4a2b-4c3d-9e8f-${(1e11 + nodes.length * 104729).toString(16).slice(0, 12)}`
      : `${DOMAIN_SID}-${rid++}`);
  const node: MockNode = {
    id: nodes.length,
    objectid,
    name,
    kind,
    tier0: opts.tier0 ?? false,
    owned: false,
    enabled: opts.enabled ?? true,
    properties: {
      name,
      objectid,
      domain: isAz ? TENANT : DOMAIN,
      ...(isAz ? { tenantid: TENANT_ID } : { distinguishedname: `CN=${shortName},DC=CORP,DC=LOCAL` }),
      ...opts.props,
    },
  };
  nodes.push(node);
  byName.set(shortName, node);
  return node;
}

function e(src: string, kind: string, dst: string): void {
  const s = byName.get(src);
  const d = byName.get(dst);
  if (!s || !d) throw new Error(`mock data: unknown node in edge ${src} -${kind}-> ${dst}`);
  edges.push({ src: s.id, dst: d.id, kind });
}

const userProps = (i: number, extra: Record<string, unknown> = {}) => ({
  pwdlastset: BASE_TIME - i * 86400 * 23,
  // Ages grow quadratically (capped at ~15 months) so some accounts look stale.
  lastlogon: BASE_TIME - Math.min(i, 30) ** 2 * 43200,
  lastlogontimestamp: BASE_TIME - Math.min(i, 30) ** 2 * 43200 - 3600,
  whencreated: BASE_TIME - 86400 * (900 + i * 11),
  pwdneverexpires: i % 6 === 0,
  sensitive: false,
  admincount: false,
  hasspn: false,
  dontreqpreauth: false,
  unconstraineddelegation: false,
  ...extra,
});

// --- Domain, containers, OUs, GPOs -----------------------------------------
add("Domain", DOMAIN, {
  tier0: true,
  fullName: DOMAIN,
  objectid: DOMAIN_SID,
  props: { functionallevel: "2016", highvalue: true, distinguishedname: "DC=CORP,DC=LOCAL" },
});
add("Container", "USERS");
add("OU", "WORKSTATIONS", { props: { blocksinheritance: false } });
add("OU", "SERVERS", { props: { blocksinheritance: false } });
add("OU", "CORP USERS", { props: { blocksinheritance: true } });
add("GPO", "DEFAULT DOMAIN POLICY", { props: { gpcpath: "\\\\CORP.LOCAL\\SYSVOL\\CORP.LOCAL\\POLICIES\\{31B2F340-016D-11D2-945F-00C04FB984F9}" } });
add("GPO", "WORKSTATION BASELINE", { props: { gpcpath: "\\\\CORP.LOCAL\\SYSVOL\\CORP.LOCAL\\POLICIES\\{6AC1786C-016F-11D2-945F-00C04FB984F9}" } });

// --- Groups ----------------------------------------------------------------
for (const [g, t0] of [
  ["DOMAIN ADMINS", true],
  ["ENTERPRISE ADMINS", true],
  ["ADMINISTRATORS", true],
  ["DOMAIN CONTROLLERS", true],
  ["DOMAIN USERS", false],
  ["DOMAIN COMPUTERS", false],
  ["HELPDESK", false],
  ["IT SUPPORT", false],
  ["SQL ADMINS", false],
  ["BACKUP OPERATORS", false],
  ["ACCOUNT OPERATORS", false],
  ["REMOTE DESKTOP USERS", false],
  ["FINANCE", false],
  ["HR", false],
  ["CERT PUBLISHERS", false],
] as const) {
  add("Group", g, { tier0: t0, props: { admincount: t0, highvalue: t0, description: `${g.toLowerCase()} group` } });
}

// --- Users -----------------------------------------------------------------
add("User", "ADMINISTRATOR", { tier0: true, props: userProps(1, { admincount: true, description: "Built-in account for administering the domain" }) });
add("User", "KRBTGT", { enabled: false, props: userProps(400, { admincount: true, hasspn: true, description: "Key Distribution Center Service Account" }) });
const people = ["ALICE", "BOB", "CAROL", "DAVE", "EVE", "FRANK", "GRACE", "HEIDI", "IVAN", "JUDY", "MALLORY", "OSCAR", "PEGGY", "TRENT", "WALTER"];
people.forEach((p, i) =>
  add("User", p, {
    props: userProps(i + 2, {
      displayname: p.charAt(0) + p.slice(1).toLowerCase(),
      email: `${p.toLowerCase()}@corp.local`,
      title: ["Analyst", "Engineer", "Helpdesk Technician", "Accountant", "Recruiter"][i % 5],
      dontreqpreauth: p === "OSCAR",
    }),
  }),
);
add("User", "SVC_SQL", { props: userProps(90, { hasspn: true, serviceprincipalnames: ["MSSQLSvc/sql01.corp.local:1433"], description: "SQL Server service account" }) });
add("User", "SVC_BACKUP", { props: userProps(300, { description: "Veeam backup service account, password never expires" }) });
add("User", "SVC_WEB", { props: userProps(200, { hasspn: true, dontreqpreauth: true, serviceprincipalnames: ["HTTP/web01.corp.local"] }) });

// --- Computers -------------------------------------------------------------
const comp = (i: number, extra: Record<string, unknown> = {}) => ({
  operatingsystem: "Windows Server 2022 Standard",
  lastlogontimestamp: BASE_TIME - Math.min(i, 20) ** 2 * 86400,
  whencreated: BASE_TIME - 86400 * (1200 + i * 7),
  unconstraineddelegation: false,
  haslaps: true,
  ...extra,
});
add("Computer", "DC01", { tier0: true, props: comp(1, { unconstraineddelegation: true, haslaps: false }) });
add("Computer", "DC02", { tier0: true, props: comp(2, { unconstraineddelegation: true, haslaps: false }) });
add("Computer", "FS01", { props: comp(3) });
add("Computer", "SQL01", { props: comp(4, { unconstraineddelegation: true }) });
add("Computer", "WEB01", { props: comp(5, { haslaps: false }) });
add("Computer", "CA01", { props: comp(6) });
add("Computer", "JUMP01", { props: comp(7) });
for (let i = 1; i <= 6; i++) {
  add("Computer", `WKS-00${i}`, { props: comp(10 + i, { operatingsystem: "Windows 11 Enterprise" }) });
}

// --- ADCS ------------------------------------------------------------------
add("RootCA", "CORP-ROOT-CA", { props: { certthumbprint: "8F1C6A0D3E5B47C2A9E1F0B3D6C8A2E4F7B9C1D3" } });
add("EnterpriseCA", "CORP-ISSUING-CA", { props: { caname: "CORP-ISSUING-CA", dnshostname: "ca01.corp.local", isuserspecifiessanenabled: false } });
add("NTAuthStore", "NTAUTHCERTIFICATES", { props: { domainsid: DOMAIN_SID } });
add("CertTemplate", "USER", { props: { enrolleesuppliessubject: false, authenticationenabled: true, requiresmanagerapproval: false } });
add("CertTemplate", "WEBSERVER-LEGACY", {
  props: {
    enrolleesuppliessubject: true,
    authenticationenabled: true,
    requiresmanagerapproval: false,
    description: "Legacy template: enrollee supplies subject and client auth EKU (ESC1)",
    ekus: ["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1"],
  },
});

// --- Entra ID / Azure ------------------------------------------------------
add("AZTenant", "CORP TENANT", { tier0: true, fullName: "CORP TENANT", objectid: TENANT_ID });
add("AZUser", `alice@${TENANT}`, { fullName: `ALICE@${TENANT.toUpperCase()}`, props: { onpremsyncenabled: true, userprincipalname: `alice@${TENANT}` } });
add("AZUser", `bob@${TENANT}`, { fullName: `BOB@${TENANT.toUpperCase()}`, props: { onpremsyncenabled: true, userprincipalname: `bob@${TENANT}` } });
add("AZUser", `breakglass@${TENANT}`, { tier0: true, fullName: `BREAKGLASS@${TENANT.toUpperCase()}`, props: { onpremsyncenabled: false } });
add("AZGroup", "CLOUD OPS", { fullName: "CLOUD OPS@CORP TENANT", props: { isassignabletorole: true } });
add("AZRole", "GLOBAL ADMINISTRATOR", { tier0: true, fullName: "GLOBAL ADMINISTRATOR@CORP TENANT", props: { templateid: "62e90394-69f5-4237-9190-012177145e10" } });
add("AZRole", "APPLICATION ADMINISTRATOR", { fullName: "APPLICATION ADMINISTRATOR@CORP TENANT", props: { templateid: "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" } });
add("AZApp", "DEPLOY-PIPELINE", { fullName: "DEPLOY-PIPELINE@CORP TENANT", props: { appid: "0b6f2c1e-7d4a-4f3b-8a9e-1c2d3e4f5a6b" } });
add("AZServicePrincipal", "DEPLOY-PIPELINE-SP", { fullName: "DEPLOY-PIPELINE-SP@CORP TENANT", props: { serviceprincipaltype: "Application" } });
add("AZSubscription", "PROD", { fullName: "PROD@CORP TENANT" });
add("AZKeyVault", "KV-PROD-SECRETS", { fullName: "KV-PROD-SECRETS@CORP TENANT" });
add("AZVM", "VM-APP-01", { fullName: "VM-APP-01@CORP TENANT", props: { operatingsystem: "Ubuntu 22.04" } });

// --- Trusts and hybrid identity infrastructure (v1.4 edge kinds) -------------
add("Domain", "FABRIKAM.LOCAL", {
  tier0: true,
  fullName: "FABRIKAM.LOCAL",
  objectid: "S-1-5-21-1004336348-1177238915-682003330",
  props: { domain: "FABRIKAM.LOCAL", functionallevel: "2012 R2", distinguishedname: "DC=FABRIKAM,DC=LOCAL" },
});
add("Computer", "AADCONNECT01", { tier0: true, props: comp(8, { description: "Entra Connect sync server" }) });
add("Computer", "AZUREADSSOACC", { tier0: true, props: comp(9, { description: "Seamless SSO computer account" }) });
add("User", "MSOL_5c1d9e0a7b3f", {
  tier0: true,
  props: userProps(30, { description: "Account created by Microsoft Azure Active Directory Connect with installation identifier 5c1d9e0a7b3f running on computer AADCONNECT01" }),
});

// --- Edges -----------------------------------------------------------------
// Containment
e(DOMAIN, "Contains", "USERS");
e(DOMAIN, "Contains", "WORKSTATIONS");
e(DOMAIN, "Contains", "SERVERS");
e(DOMAIN, "Contains", "CORP USERS");
e("DEFAULT DOMAIN POLICY", "GPLink", DOMAIN);
e("WORKSTATION BASELINE", "GPLink", "WORKSTATIONS");
for (let i = 1; i <= 6; i++) e("WORKSTATIONS", "Contains", `WKS-00${i}`);
for (const s of ["FS01", "SQL01", "WEB01", "CA01", "JUMP01"]) e("SERVERS", "Contains", s);
for (const p of people) e("CORP USERS", "Contains", p);
e("USERS", "Contains", "ADMINISTRATOR");
e("USERS", "Contains", "KRBTGT");

// Memberships
for (const u of [...people, "SVC_SQL", "SVC_BACKUP", "SVC_WEB", "ADMINISTRATOR"]) e(u, "MemberOf", "DOMAIN USERS");
e("ADMINISTRATOR", "MemberOf", "DOMAIN ADMINS");
e("ADMINISTRATOR", "MemberOf", "ENTERPRISE ADMINS");
e("DOMAIN ADMINS", "MemberOf", "ADMINISTRATORS");
e("ENTERPRISE ADMINS", "MemberOf", "ADMINISTRATORS");
e("TRENT", "MemberOf", "DOMAIN ADMINS");
e("CAROL", "MemberOf", "HELPDESK");
e("DAVE", "MemberOf", "HELPDESK");
e("HELPDESK", "MemberOf", "IT SUPPORT");
e("FRANK", "MemberOf", "IT SUPPORT");
e("GRACE", "MemberOf", "SQL ADMINS");
e("SVC_SQL", "MemberOf", "SQL ADMINS");
e("SVC_BACKUP", "MemberOf", "BACKUP OPERATORS");
e("HEIDI", "MemberOf", "ACCOUNT OPERATORS");
e("ALICE", "MemberOf", "FINANCE");
e("BOB", "MemberOf", "FINANCE");
e("EVE", "MemberOf", "HR");
e("IVAN", "MemberOf", "HR");
e("IT SUPPORT", "MemberOf", "REMOTE DESKTOP USERS");
e("DC01", "MemberOf", "DOMAIN CONTROLLERS");
e("DC02", "MemberOf", "DOMAIN CONTROLLERS");
e("CA01", "MemberOf", "CERT PUBLISHERS");
for (const c of ["FS01", "SQL01", "WEB01", "CA01", "JUMP01", "WKS-001", "WKS-002", "WKS-003", "WKS-004", "WKS-005", "WKS-006"]) {
  e(c, "MemberOf", "DOMAIN COMPUTERS");
}

// Local admin / RDP / sessions
for (let i = 1; i <= 6; i++) e("IT SUPPORT", "AdminTo", `WKS-00${i}`);
e("HELPDESK", "AdminTo", "JUMP01");
e("SQL ADMINS", "AdminTo", "SQL01");
e("FRANK", "AdminTo", "FS01");
e("REMOTE DESKTOP USERS", "CanRDP", "JUMP01");
e("FINANCE", "CanRDP", "WKS-003");
e("JUDY", "AdminTo", "WEB01");
e("SVC_WEB", "AdminTo", "WEB01");
e("WKS-002", "HasSession", "ALICE");
e("WKS-004", "HasSession", "FRANK");
e("JUMP01", "HasSession", "TRENT");
e("SQL01", "HasSession", "SVC_SQL");
e("FS01", "HasSession", "SVC_BACKUP");
e("WEB01", "HasSession", "GRACE");
e("WKS-001", "HasSession", "CAROL");
e("WKS-006", "HasSession", "MALLORY");

// ACLs
e("ACCOUNT OPERATORS", "GenericAll", "HELPDESK");
e("HELPDESK", "ForceChangePassword", "GRACE");
e("MALLORY", "GenericWrite", "SVC_SQL");
e("WALTER", "WriteDacl", "IT SUPPORT");
e("PEGGY", "Owns", "WORKSTATION BASELINE");
e("DOMAIN USERS", "GenericWrite", "WORKSTATION BASELINE");
e("WORKSTATION BASELINE", "GenericAll", "WKS-005");
e("IT SUPPORT", "AddMember", "REMOTE DESKTOP USERS");
e("BACKUP OPERATORS", "GenericAll", "DC01");
e("SVC_BACKUP", "ReadLAPSPassword", "FS01");
e("DOMAIN ADMINS", "GenericAll", DOMAIN);
e("ENTERPRISE ADMINS", "GenericAll", DOMAIN);
e("ADMINISTRATORS", "DCSync", DOMAIN);
e("DOMAIN CONTROLLERS", "DCSync", DOMAIN);
e("SVC_BACKUP", "DCSync", DOMAIN); // misconfiguration surfaced by the dcsync-non-tier0 finding
e("SVC_BACKUP", "GetChanges", DOMAIN);
e("SVC_BACKUP", "GetChangesAll", DOMAIN);
e("OSCAR", "WriteOwner", "FINANCE");
e("SQL01", "AllowedToDelegate", "DC01");
e("DOMAIN ADMINS", "AdminTo", "DC01");
e("DOMAIN ADMINS", "AdminTo", "DC02");
e("SVC_SQL", "GenericAll", "SQL ADMINS");

// ADCS
e("CORP-ISSUING-CA", "IssuedSignedBy", "CORP-ROOT-CA");
e("CORP-ISSUING-CA", "TrustedForNTAuth", "NTAUTHCERTIFICATES");
e("NTAUTHCERTIFICATES", "NTAuthStoreFor", DOMAIN);
e("CORP-ROOT-CA", "RootCAFor", DOMAIN);
e("USER", "PublishedTo", "CORP-ISSUING-CA");
e("WEBSERVER-LEGACY", "PublishedTo", "CORP-ISSUING-CA");
e("DOMAIN USERS", "Enroll", "USER");
e("DOMAIN COMPUTERS", "Enroll", "WEBSERVER-LEGACY");
e("DOMAIN COMPUTERS", "ADCSESC1", DOMAIN);
e("CA01", "HostsCAService", "CORP-ISSUING-CA");

// Hybrid identity / Azure
e("ALICE", "SyncedToEntraUser", `alice@${TENANT}`);
e("BOB", "SyncedToEntraUser", `bob@${TENANT}`);
e(`bob@${TENANT}`, "AZMemberOf", "CLOUD OPS");
e("CLOUD OPS", "AZHasRole", "APPLICATION ADMINISTRATOR");
e("APPLICATION ADMINISTRATOR", "AZAddSecret", "DEPLOY-PIPELINE");
e("DEPLOY-PIPELINE", "AZRunsAs", "DEPLOY-PIPELINE-SP");
e("DEPLOY-PIPELINE-SP", "AZHasRole", "GLOBAL ADMINISTRATOR");
e(`breakglass@${TENANT}`, "AZHasRole", "GLOBAL ADMINISTRATOR");
e("GLOBAL ADMINISTRATOR", "AZGlobalAdmin", "CORP TENANT");
e("CORP TENANT", "AZContains", "PROD");
e("PROD", "AZContains", "KV-PROD-SECRETS");
e("PROD", "AZContains", "VM-APP-01");
e("DEPLOY-PIPELINE-SP", "AZOwner", "PROD");
e(`alice@${TENANT}`, "AZGetSecrets", "KV-PROD-SECRETS");
e("VM-APP-01", "AZManagedIdentity", "DEPLOY-PIPELINE-SP");

// Trusts: CORP trusts FABRIKAM (forest trust) with SID filtering off, so FABRIKAM can spoof SID history.
e(DOMAIN, "TrustedBy", "FABRIKAM.LOCAL");
e(DOMAIN, "CrossForestTrust", "FABRIKAM.LOCAL");
e("FABRIKAM.LOCAL", "SpoofSIDHistory", DOMAIN);
e("FABRIKAM.LOCAL", "AbuseTGTDelegation", DOMAIN);
e("SQL01", "CoerceToTGT", DOMAIN);

// Hybrid: synced group, Entra Connect, Seamless SSO.
e("IT SUPPORT", "SyncedToEntraGroup", "CLOUD OPS");
e("CLOUD OPS", "SyncedToADGroup", "IT SUPPORT");
e("AADCONNECT01", "EntraConnectCredentials", "MSOL_5c1d9e0a7b3f");
e("MSOL_5c1d9e0a7b3f", "DCSync", DOMAIN);
e("AZUREADSSOACC", "SeamlessSSO", `alice@${TENANT}`);
e("AZUREADSSOACC", "SeamlessSSO", `bob@${TENANT}`);
e(`alice@${TENANT}`, "SyncedToADUser", "ALICE");
e("HELPDESK", "AdminTo", "AADCONNECT01");

export const NON_TRAVERSABLE = new Set([
  "TrustedBy",
  "CrossForestTrust",
  "SyncedToADGroup",
  "IssuedSignedBy",
  "TrustedForNTAuth",
  "NTAuthStoreFor",
  "RootCAFor",
  "PublishedTo",
  "HostsCAService",
]);

const ADCS_EDGES = new Set([
  "Enroll",
  "PublishedTo",
  "IssuedSignedBy",
  "TrustedForNTAuth",
  "NTAuthStoreFor",
  "RootCAFor",
  "HostsCAService",
  "ADCSESC1",
]);
const HYBRID_EDGES = new Set([
  "SyncedToEntraUser",
  "SyncedToADUser",
  "SyncedToEntraGroup",
  "SyncedToADGroup",
  "SeamlessSSO",
  "EntraConnectCredentials",
]);

export function edgeCategory(kind: string): KindCategory {
  if (HYBRID_EDGES.has(kind)) return "Hybrid";
  if (kind === "CanProgram") return "OT";
  if (ADCS_EDGES.has(kind)) return "ADCS";
  return kind.startsWith("AZ") ? "Azure" : "Active Directory";
}

const ADCS_NODE_KINDS = new Set(["CertTemplate", "EnterpriseCA", "RootCA", "AIACA", "NTAuthStore", "IssuancePolicy"]);

export function nodeCategory(kind: string): KindCategory {
  if (kind === "Unknown") return "Other";
  if (ADCS_NODE_KINDS.has(kind)) return "ADCS";
  return kind.startsWith("AZ") ? "Azure" : "Active Directory";
}

export const prebuiltQueries: PrebuiltQuery[] = [
  {
    id: "domain-controllers",
    name: "Domain controllers",
    category: "Domain Information",
    description: "Computers that are members of DOMAIN CONTROLLERS.",
    query: "MATCH (c:Computer)-[:MemberOf]->(g:Group {name:'DOMAIN CONTROLLERS@CORP.LOCAL'}) RETURN c, g",
    tags: ["dc", "inventory"],
  },
  {
    id: "domains",
    name: "All domains",
    category: "Domain Information",
    description: "Every domain object in the graph.",
    query: "MATCH (d:Domain) RETURN d",
    tags: ["inventory"],
  },
  {
    id: "object-counts",
    name: "Users per domain (count)",
    category: "Domain Information",
    description: "Number of user objects.",
    query: "MATCH (u:User) RETURN count(u)",
    tags: ["inventory", "stats"],
  },
  {
    id: "dcsync-principals",
    name: "DCSync principals",
    category: "Dangerous Privileges",
    description: "Principals with DCSync rights on a domain.",
    query: "MATCH (p)-[r:DCSync]->(d:Domain) RETURN p, r, d",
    tags: ["dcsync", "credential-access"],
  },
  {
    id: "generic-all-groups",
    name: "GenericAll on groups",
    category: "Dangerous Privileges",
    description: "Principals with full control over a group.",
    query: "MATCH (p)-[r:GenericAll]->(g:Group) RETURN p, r, g",
    tags: ["acl", "privilege-escalation"],
  },
  {
    id: "asrep",
    name: "AS-REP roastable users",
    category: "Kerberos",
    description: "Users that do not require Kerberos pre-authentication.",
    query: "MATCH (u:User {dontreqpreauth:true}) RETURN u",
    tags: ["asrep", "credential-access"],
  },
  {
    id: "kerberoast",
    name: "Kerberoastable users",
    category: "Kerberos",
    description: "Enabled users with a service principal name.",
    query: "MATCH (u:User {hasspn:true}) WHERE u.enabled RETURN u",
    tags: ["kerberoast", "credential-access"],
  },
  {
    id: "kerberoast-admins",
    name: "Kerberoastable users with a path to Tier Zero",
    category: "Kerberos",
    description: "Roastable accounts that also lead to Tier Zero.",
    query: "MATCH p = shortestPath((u:User {hasspn:true})-[*1..]->(t {tier0:true})) WHERE u.enabled RETURN p",
    tags: ["kerberoast", "tier0", "path"],
  },
  {
    id: "unconstrained",
    name: "Unconstrained delegation (non Tier Zero)",
    category: "Delegation",
    description: "Computers trusted for unconstrained delegation outside Tier Zero.",
    query: "MATCH (c:Computer {unconstraineddelegation:true}) WHERE NOT c.tier0 RETURN c.name",
    tags: ["delegation", "table"],
  },
  {
    id: "constrained",
    name: "Constrained delegation",
    category: "Delegation",
    description: "AllowedToDelegate relationships.",
    query: "MATCH (a)-[r:AllowedToDelegate]->(b) RETURN a, r, b",
    tags: ["delegation"],
  },
  {
    id: "acl-write",
    name: "Write rights on users",
    category: "ACL Abuse",
    description: "GenericWrite, WriteDacl, WriteOwner or ForceChangePassword on users or groups.",
    query: "MATCH (a)-[r:GenericWrite|WriteDacl|WriteOwner|ForceChangePassword]->(b) RETURN a, r, b",
    tags: ["acl"],
  },
  {
    id: "add-member",
    name: "Can add members to groups",
    category: "ACL Abuse",
    description: "AddMember edges.",
    query: "MATCH (a)-[r:AddMember]->(g:Group) RETURN a, r, g",
    tags: ["acl", "groups"],
  },
  {
    id: "sessions-admin",
    name: "Sessions on admin-able computers",
    category: "Sessions & Lateral Movement",
    description: "Computers with sessions together with who can administer them.",
    query: "MATCH (a)-[:AdminTo]->(c:Computer)-[:HasSession]->(u:User) RETURN a, c, u",
    tags: ["sessions", "lateral-movement"],
  },
  {
    id: "local-admins-count",
    name: "Local admins on computers (count)",
    category: "Sessions & Lateral Movement",
    description: "How many principals have direct AdminTo rights.",
    query: "MATCH (u)-[:AdminTo]->(c:Computer) RETURN count(u)",
    tags: ["lateral-movement", "stats"],
  },
  {
    id: "rdp",
    name: "RDP rights",
    category: "Sessions & Lateral Movement",
    description: "Principals that can RDP to computers.",
    query: "MATCH (a)-[r:CanRDP]->(c:Computer) RETURN a, r, c",
    tags: ["rdp", "lateral-movement"],
  },
  {
    id: "gpo-links",
    name: "GPO links",
    category: "GPO & OU",
    description: "Group policy objects and where they are linked.",
    query: "MATCH (g:GPO)-[r:GPLink]->(t) RETURN g, r, t",
    tags: ["gpo"],
  },
  {
    id: "gpo-control",
    name: "Control over GPOs",
    category: "GPO & OU",
    description: "Principals that can modify a GPO.",
    query: "MATCH (a)-[r:Owns|GenericAll|GenericWrite]->(g:GPO) RETURN a, r, g",
    tags: ["gpo", "acl"],
  },
  {
    id: "stale-users",
    name: "Enabled users inactive for 90 days",
    category: "Hygiene",
    description: "Enabled users whose last logon is older than 90 days.",
    query: "MATCH (u:User {enabled:true}) WHERE u.lastlogontimestamp < days_ago(90) RETURN u.name, u.lastlogontimestamp",
    tags: ["stale", "table"],
  },
  {
    id: "pwd-never-expires",
    name: "Passwords that never expire",
    category: "Hygiene",
    description: "Enabled users with pwdneverexpires set.",
    query: "MATCH (u:User {pwdneverexpires:true}) WHERE u.enabled RETURN u",
    tags: ["passwords"],
  },
  {
    id: "domain-users-t0",
    name: "Shortest paths from Domain Users to Tier Zero",
    category: "Shortest Paths",
    description: "Union of all shortest paths from DOMAIN USERS to any Tier Zero object.",
    query: "MATCH p = allShortestPaths((g:Group {name:'DOMAIN USERS@CORP.LOCAL'})-[*1..]->(t {tier0:true})) RETURN p",
    tags: ["path", "tier0"],
  },
  {
    id: "tier0-objects",
    name: "Tier Zero objects",
    category: "Tier Zero",
    description: "Everything currently tagged Tier Zero.",
    query: "MATCH (n {tier0:true}) RETURN n",
    tags: ["tier0", "inventory"],
  },
  {
    id: "tier0-non-admin",
    name: "Non-Tier-Zero principals with rights on Tier Zero",
    category: "Tier Zero",
    description: "Direct edges from outside Tier Zero into it.",
    query: "MATCH (a)-[r]->(t {tier0:true}) WHERE NOT a.tier0 RETURN a, r, t",
    tags: ["tier0", "acl"],
  },
  {
    id: "owned-paths",
    name: "Shortest paths from owned principals",
    category: "Owned",
    description: "One shortest path to Tier Zero for every owned principal.",
    query: "MATCH p = shortestPath((o {owned:true})-[*1..]->(t {tier0:true})) RETURN p",
    tags: ["owned", "path", "tier0"],
  },
  {
    id: "owned-list",
    name: "Owned principals",
    category: "Owned",
    description: "Everything marked owned.",
    query: "MATCH (o {owned:true}) RETURN o",
    tags: ["owned"],
  },
  {
    id: "esc1",
    name: "Enrollable ESC1 templates",
    category: "ADCS",
    description: "Templates where the enrollee supplies the subject.",
    query: "MATCH (t:CertTemplate {enrolleesuppliessubject:true}) RETURN t.name, t.description",
    tags: ["esc1", "table"],
  },
  {
    id: "adcs-chain",
    name: "Certificate authority chain",
    category: "ADCS",
    description: "Templates, CAs and trust stores.",
    query: "MATCH (a)-[r:PublishedTo|IssuedSignedBy|TrustedForNTAuth|NTAuthStoreFor|RootCAFor]->(b) RETURN a, r, b",
    tags: ["pki"],
  },
  {
    id: "az-roles",
    name: "Entra ID role holders",
    category: "Azure / Entra ID",
    description: "Principals holding an Entra ID directory role.",
    query: "MATCH (p)-[r:AZHasRole]->(role:AZRole) RETURN p, r, role",
    tags: ["roles", "entra"],
  },
  {
    id: "az-global-admin",
    name: "Paths to Global Administrator",
    category: "Azure / Entra ID",
    description: "Shortest path from every Entra user to Global Administrator.",
    query: "MATCH p = shortestPath((u:AZUser)-[*1..]->(r:AZRole {name:'GLOBAL ADMINISTRATOR@CORP TENANT'})) RETURN p",
    tags: ["path", "entra"],
  },
  {
    id: "az-keyvault",
    name: "Key vault access",
    category: "Azure Resources",
    description: "Who can read key vault secrets.",
    query: "MATCH (a)-[r:AZGetSecrets]->(k:AZKeyVault) RETURN a, r, k",
    tags: ["secrets", "resources"],
  },
  {
    id: "az-contains",
    name: "Subscription contents",
    category: "Azure Resources",
    description: "Resources contained in subscriptions.",
    query: "MATCH (s:AZSubscription)-[r:AZContains]->(x) RETURN s, r, x",
    tags: ["resources"],
  },
  {
    id: "hybrid-sync",
    name: "Synced on-prem users",
    category: "Hybrid",
    description: "AD users synchronised to Entra ID.",
    query: "MATCH (u:User)-[r:SyncedToEntraUser]->(a:AZUser) RETURN u, r, a",
    tags: ["sync", "entra"],
  },
];
