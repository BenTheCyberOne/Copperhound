// Mock accounts, RBAC, API tokens, audit trail and server settings, mirroring
// crates/server/src/{auth.rs,users.rs,audit.rs,watch.rs}.

import type { ApiRequest, ApiResponse } from "../api/client";
import type {
  ApiTokenInfo,
  AuditEntry,
  Role,
  ServerSettings,
  SettingsResponse,
  UserInfo,
  WatchStatus,
} from "../api/types";
import { MOCK_IDP_CODE, MOCK_IDP_USER, mappedRole, noteSsoAdminSignIn, passwordRefusal } from "./sso";

const MIN_PASSWORD_LEN = 12;
const MAX_FAILURES = 5;
const LOCKOUT_MS = 5 * 60_000;
const RANK: Record<Role, number> = { uploader: -1, viewer: 0, analyst: 1, admin: 2 };

interface MockUser extends Omit<UserInfo, "tokens"> {
  /** Empty for SSO accounts (they have no password). */
  password: string;
  tokens: (ApiTokenInfo & { secret: string })[];
}

export interface Principal {
  username: string;
  role: Role;
  viaToken: boolean;
}

const daysAgo = (d: number) => new Date(Date.now() - d * 86400_000).toISOString();

// Demo accounts: admin / copperhound, analyst / analyst-password, viewer / viewer-password,
// collector / collector-password (upload-only).
const users: MockUser[] = [
  { username: "collector", role: "uploader", source: "local", password: "collector-password", created_at: daysAgo(30), disabled: false, last_login: null, tokens: [] },
  { username: "admin", role: "admin", source: "local", password: "copperhound", created_at: daysAgo(60), disabled: false, last_login: daysAgo(1), tokens: [] },
  {
    username: "analyst",
    role: "analyst",
    source: "local",
    password: "analyst-password",
    created_at: daysAgo(40),
    disabled: false,
    last_login: daysAgo(2),
    tokens: [
      {
        id: "t-ci",
        name: "CI pipeline",
        prefix: "cht_9f2c",
        created_at: daysAgo(30),
        expires_at: new Date(Date.now() + 60 * 86400_000).toISOString(),
        last_used: daysAgo(0.2),
        secret: "cht_9f2c-mock-ci-token",
      },
    ],
  },
  { username: "viewer", role: "viewer", source: "local", password: "viewer-password", created_at: daysAgo(20), disabled: false, last_login: null, tokens: [] },
  // Created just-in-time by an earlier SSO sign-in.
  { username: "bob@corp.example", role: "viewer", source: "oidc", password: "", created_at: daysAgo(12), disabled: false, last_login: daysAgo(3), tokens: [] },
];

const sessions = new Map<string, string>(); // token -> username
const failures = new Map<string, { count: number; until: number }>();
const audit: AuditEntry[] = [];

const ok = (body: unknown): ApiResponse => ({ status: 200, body });
const fail = (status: number, error: string): ApiResponse => ({ status, body: { error } });
const now = () => new Date().toISOString();
const randomHex = (n: number) => Array.from({ length: n }, () => Math.floor(Math.random() * 16).toString(16)).join("");

const publicUser = (u: MockUser): UserInfo => ({
  username: u.username,
  role: u.role,
  source: u.source ?? "local",
  created_at: u.created_at,
  disabled: u.disabled,
  last_login: u.last_login,
  tokens: u.tokens.map(({ secret: _secret, ...t }) => t),
});

export function record(e: Omit<AuditEntry, "ts">): void {
  audit.push({ ts: now(), ...e });
  if (audit.length > 5000) audit.shift();
}

// Seed some history so the audit view is not empty.
record({ user: "admin", role: "admin", action: "login", method: "POST", path: "/api/v1/login", status: 200, ip: "10.0.0.5" });
record({ user: "analyst", role: "analyst", action: "POST /zones", method: "POST", path: "/api/v1/zones", status: 200, ip: "10.0.0.7" });
record({ user: "viewer", role: "viewer", action: "denied", method: "POST", path: "/api/v1/nodes/12/marks", status: 403, ip: "10.0.0.9", detail: "requires analyst" });
record({ user: "mallory", role: "", action: "login-failed", method: "POST", path: "/api/v1/login", status: 401, ip: "203.0.113.4" });

export function login(username: string, password: string): ApiResponse {
  const f = failures.get(username);
  const entry = (action: string, status: number, role = "") =>
    record({ user: username, role, action, method: "POST", path: "/api/v1/login", status, ip: "127.0.0.1" });
  if (f && f.until > Date.now()) {
    entry("login-locked", 429);
    return fail(429, `too many failed attempts; try again in ${Math.ceil((f.until - Date.now()) / 1000)} s`);
  }
  const u = users.find((x) => x.username === username);
  if (!u || u.disabled || !u.password || u.password !== password) {
    const count = (f?.count ?? 0) + 1;
    failures.set(username, { count, until: count >= MAX_FAILURES ? Date.now() + LOCKOUT_MS : 0 });
    entry("login-failed", 401);
    return fail(401, "invalid username or password");
  }
  failures.delete(username);
  const refusal = passwordRefusal(u.username);
  if (refusal) {
    entry("login-failed", 403);
    return fail(403, refusal);
  }
  u.last_login = now();
  const token = `mock-${randomHex(24)}`;
  sessions.set(token, u.username);
  entry("login", 200, u.role);
  return ok({ token, username: u.username, role: u.role });
}

const usedCodes = new Set<string>();

/** POST /auth/oidc/exchange: the mock IdP code signs in (and JIT-creates) the demo SSO user. */
export function oidcExchange(code: string): ApiResponse {
  const audit = (action: string, status: number, user: string, role = "", detail?: string) =>
    record({ user, role, action, method: "POST", path: "/api/v1/auth/oidc/exchange", status, ip: "127.0.0.1", detail });
  if (!code.startsWith(`${MOCK_IDP_CODE}-`) || usedCodes.has(code)) {
    audit("sso-login-failed", 401, "", "", "invalid or expired sign-in code");
    return fail(401, "invalid or expired sign-in code");
  }
  usedCodes.add(code);
  const { username, groups } = MOCK_IDP_USER;
  const role = mappedRole(groups);
  if (!role) {
    audit("sso-login-failed", 403, username, "", "denied: not in any mapped group and default_role is deny");
    return fail(403, "your account is not allowed to use CopperHound (no mapped group)");
  }
  let u = users.find((x) => x.username === username);
  if (u && u.source !== "oidc") {
    audit("sso-login-failed", 409, username, "", "conflict: username belongs to a local account");
    return fail(403, "the username already belongs to a local account");
  }
  if (!u) {
    u = { username, role, source: "oidc", password: "", created_at: now(), disabled: false, last_login: null, tokens: [] };
    users.push(u);
  }
  if (u.disabled) return fail(403, "this account is disabled");
  u.role = role; // the IdP is authoritative on every sign-in
  u.last_login = now();
  if (role === "admin") noteSsoAdminSignIn();
  const token = `mock-${randomHex(24)}`;
  sessions.set(token, u.username);
  audit("sso-login", 200, u.username, role, `sub=mock-${randomHex(6)}; groups=${groups.length}`);
  return ok({ token, username: u.username, role: u.role, return_to: "/" });
}

export function logout(token: string): void {
  sessions.delete(token);
}

export function authenticate(token: string | null): Principal | null {
  if (!token) return null;
  const name = sessions.get(token);
  if (name) {
    const u = users.find((x) => x.username === name);
    return u && !u.disabled ? { username: u.username, role: u.role, viaToken: false } : null;
  }
  for (const u of users) {
    const t = u.tokens.find((x) => x.secret === token);
    if (t && !u.disabled && (!t.expires_at || Date.parse(t.expires_at) > Date.now())) {
      t.last_used = now();
      return { username: u.username, role: u.role, viaToken: true };
    }
  }
  return null;
}

/** Same rules as api::required_role on the server. */
export function requiredRole(method: string, p: string): Role {
  if (p.startsWith("/users") || p.startsWith("/audit") || p.startsWith("/settings")) return "admin";
  if (p.startsWith("/notify") || p.startsWith("/schedules") || p.startsWith("/alerts/rules")) return "admin";
  if (p === "/alerts") return "analyst";
  if (method === "DELETE" && p.startsWith("/posture/")) return "admin";
  if (method === "GET" || p.startsWith("/me") || p === "/logout") return "viewer";
  const analysis = ["/query", "/path", "/nodes/filter", "/subgraph", "/nodes/resolve", "/simulate", "/remediation-plan", "/zones/membership", "/report"];
  if (analysis.includes(p) || (method === "DELETE" && p.startsWith("/query/"))) return "viewer";
  return "analyst";
}

/** Same as api::uploader_may on the server. */
export function uploaderMay(method: string, p: string): boolean {
  if (p.startsWith("/me") || p === "/logout") return true;
  return (method === "POST" && (p === "/upload" || p === "/ingest")) || (method === "GET" && (p === "/uploads" || p === "/jobs" || /^\/jobs\/[^/]+$/.test(p)));
}

export function atLeast(who: Principal, need: Role): boolean {
  return RANK[who.role] >= RANK[need];
}

/** Audit template: ids replaced by placeholders, like the server's matched route. */
const template = (p: string) => p.replace(/\/(\d+|j-\d+|z-[\w-]+|sq-\d+|snap-\d+|t-[\w-]+|[cs]-[0-9a-f]{12})(?=\/|$)/g, "/{id}");

export function audited(who: Principal, req: ApiRequest, res: ApiResponse): ApiResponse {
  if (req.method !== "GET") {
    record({
      user: who.username,
      role: who.role,
      action: `${req.method} ${template(req.path)}`,
      method: req.method,
      path: `/api/v1${req.path}`,
      status: res.status,
      ip: "127.0.0.1",
    });
  }
  return res;
}

export function denied(who: Principal, req: ApiRequest, need: Role): ApiResponse {
  record({
    user: who.username,
    role: who.role,
    action: "denied",
    method: req.method,
    path: `/api/v1${req.path}`,
    status: 403,
    ip: "127.0.0.1",
    detail: `requires ${need}`,
  });
  return fail(403, `this action requires the ${need} role`);
}

// --- server settings & watch folder ------------------------------------------------

let settings: ServerSettings = {
  watch: { enabled: false, dir: "", mode: "replace", settle_seconds: 30, archive: true, keep_archives: 5 },
  analysis: { unified_tier0: true },
  ingest: { merge_policy: "newest", session_window_hours: 0 },
};

/** Ingest options the next mock ingest job uses (v1.5). */
export function ingestSettings(): NonNullable<ServerSettings["ingest"]> {
  return { merge_policy: "newest", session_window_hours: 0, ...settings.ingest };
}
const watchStatus: WatchStatus = {
  last_scan: null,
  last_import: null,
  last_job: null,
  imported_files: 0,
  pending: [],
  last_error: null,
};
const DATA_DIR = "C:\\ProgramData\\CopperHound\\data";

// Simulated watcher: scans every 10 s while enabled; a file shows up as pending now and then.
window.setInterval(() => {
  if (!settings.watch.enabled) return;
  watchStatus.last_scan = now();
  watchStatus.pending = Math.random() < 0.3 ? [`sharphound_${new Date().toISOString().slice(0, 10).replace(/-/g, "")}.zip`] : [];
}, 10_000);

function settingsResponse(): SettingsResponse {
  return {
    settings,
    watch_dir_resolved: settings.watch.dir || `${DATA_DIR}\\watch`,
    watch_status: { ...watchStatus, pending: [...watchStatus.pending] },
  };
}

// --- routes ----------------------------------------------------------------------------

export function routeAccounts(who: Principal, req: ApiRequest): ApiResponse | null {
  const { method, path: p, body, query = {} } = req;
  const b = (body ?? {}) as Record<string, unknown>;
  const me = users.find((u) => u.username === who.username)!;
  let m: RegExpExecArray | null;

  if (method === "GET" && p === "/me") {
    return ok({
      ...publicUser(me),
      via_token: who.viaToken,
      permissions: { analyse: atLeast(who, "viewer"), upload: who.role === "uploader" || atLeast(who, "analyst"), modify: atLeast(who, "analyst"), admin: atLeast(who, "admin") },
    });
  }
  if (method === "PUT" && p === "/me/password") {
    if (who.viaToken) return fail(403, "sign in with a password to change it");
    if (me.source === "oidc") return fail(400, "this account signs in with single sign-on and has no password");
    if (b.current_password !== me.password) return fail(400, "current password is wrong");
    if (typeof b.new_password !== "string" || b.new_password.length < MIN_PASSWORD_LEN) {
      return fail(400, `password must be at least ${MIN_PASSWORD_LEN} characters`);
    }
    me.password = b.new_password;
    for (const [t, u] of sessions) if (u === me.username) sessions.delete(t);
    return ok({ changed: true, note: "other sessions were signed out; sign in again" });
  }
  if (method === "GET" && p === "/me/tokens") return ok({ tokens: publicUser(me).tokens });
  if (method === "POST" && p === "/me/tokens") {
    const days = b.expires_days as number | undefined;
    if (days !== undefined && (days < 1 || days > 3650)) return fail(400, "expires_days must be 1-3650");
    if (typeof b.name !== "string" || !b.name.trim()) return fail(400, "token name is required");
    const secret = `cht_${randomHex(40)}`;
    const t = {
      id: `t-${randomHex(8)}`,
      name: b.name.trim(),
      prefix: secret.slice(0, 8),
      created_at: now(),
      expires_at: days ? new Date(Date.now() + days * 86400_000).toISOString() : null,
      last_used: null,
      secret,
    };
    me.tokens.push(t);
    const { secret: _s, ...pub } = t;
    return ok({ ...pub, token: secret, note: "store this token now; it is not shown again" });
  }
  if (method === "DELETE" && (m = /^\/me\/tokens\/(.+)$/.exec(p))) {
    const i = me.tokens.findIndex((t) => t.id === decodeURIComponent(m![1]!));
    if (i < 0) return fail(404, "no such token");
    me.tokens.splice(i, 1);
    return ok({ deleted: m[1] });
  }

  // ---- admin ----
  if (method === "GET" && p === "/users") {
    return ok({
      users: users.map(publicUser),
      roles: [
        { id: "viewer", description: "Browse, search, query and run analyses; cannot change data." },
        { id: "analyst", description: "Viewer plus marks, saved queries, zones, uploads and ingest." },
        { id: "admin", description: "Analyst plus users, audit log, settings and snapshot deletion." },
      ],
    });
  }
  const admins = () => users.filter((u) => u.role === "admin" && !u.disabled).length;
  const validRole = (r: unknown): r is Role => r === "viewer" || r === "analyst" || r === "admin";
  if (method === "POST" && p === "/users") {
    const name = typeof b.username === "string" ? b.username.trim() : "";
    if (!/^[A-Za-z0-9._@-]{1,64}$/.test(name)) return fail(400, "username must be 1-64 characters of letters, digits, . _ @ -");
    if (users.some((u) => u.username === name)) return fail(400, `user ${name} already exists`);
    if (!validRole(b.role)) return fail(400, "role must be viewer, analyst or admin");
    if (typeof b.password !== "string" || b.password.length < MIN_PASSWORD_LEN) {
      return fail(400, `password must be at least ${MIN_PASSWORD_LEN} characters`);
    }
    const u: MockUser = { username: name, role: b.role, source: "local", password: b.password, created_at: now(), disabled: false, last_login: null, tokens: [] };
    users.push(u);
    return ok(publicUser(u));
  }
  if ((m = /^\/users\/([^/]+)$/.exec(p))) {
    const name = decodeURIComponent(m[1]!);
    const u = users.find((x) => x.username === name);
    if (!u) return fail(404, "no such user");
    if (method === "PUT") {
      if (b.role !== undefined && !validRole(b.role)) return fail(400, "role must be viewer, analyst or admin");
      const losingAdmin = u.role === "admin" && !u.disabled && ((b.role !== undefined && b.role !== "admin") || b.disabled === true);
      if (losingAdmin && admins() <= 1) return fail(400, "cannot demote or disable the last admin");
      if (b.password !== undefined && u.source === "oidc") return fail(400, "SSO accounts have no password");
      if (b.password !== undefined && (typeof b.password !== "string" || b.password.length < MIN_PASSWORD_LEN)) {
        return fail(400, `password must be at least ${MIN_PASSWORD_LEN} characters`);
      }
      if (validRole(b.role)) u.role = b.role;
      if (typeof b.disabled === "boolean") u.disabled = b.disabled;
      if (typeof b.password === "string") u.password = b.password;
      if (u.disabled || b.password !== undefined) for (const [t, n] of sessions) if (n === u.username) sessions.delete(t);
      return ok(publicUser(u));
    }
    if (method === "DELETE") {
      if (name === who.username) return fail(400, "you cannot delete your own account");
      if (u.role === "admin" && admins() <= 1) return fail(400, "cannot delete the last admin");
      users.splice(users.indexOf(u), 1);
      for (const [t, n] of sessions) if (n === name) sessions.delete(t);
      return ok({ deleted: name });
    }
  }
  if (method === "DELETE" && (m = /^\/users\/([^/]+)\/tokens\/(.+)$/.exec(p))) {
    const u = users.find((x) => x.username === decodeURIComponent(m![1]!));
    const i = u ? u.tokens.findIndex((t) => t.id === decodeURIComponent(m![2]!)) : -1;
    if (!u || i < 0) return fail(404, "no such token");
    u.tokens.splice(i, 1);
    return ok({ deleted: m[2] });
  }
  if (method === "GET" && p === "/audit") {
    const limit = Math.min(10000, Math.max(1, Number(query.limit ?? 200)));
    const user = query.user ? String(query.user) : undefined;
    const action = query.action ? String(query.action) : undefined;
    const entries = [...audit]
      .reverse()
      .filter((e) => (!user || e.user === user) && (!action || e.action.startsWith(action)))
      .slice(0, limit);
    return ok({ entries });
  }
  if (method === "GET" && p === "/settings") return ok(settingsResponse());
  if (method === "PUT" && p === "/settings") {
    const w = (b as Partial<ServerSettings>).watch;
    const analysis = (b as Partial<ServerSettings>).analysis;
    const ingest = (b as Partial<ServerSettings>).ingest;
    if (!w) return fail(400, "missing watch settings");
    if (!(w.settle_seconds >= 5 && w.settle_seconds <= 86400)) return fail(400, "watch.settle_seconds must be 5-86400");
    if (!(w.keep_archives >= 1 && w.keep_archives <= 100)) return fail(400, "watch.keep_archives must be 1-100");
    const hours = ingest?.session_window_hours ?? 0;
    if (!(Number.isInteger(hours) && hours >= 0 && hours <= 8760)) return fail(400, "ingest.session_window_hours must be 0-8760");
    if (ingest?.merge_policy !== undefined && ingest.merge_policy !== "newest" && ingest.merge_policy !== "union") {
      return fail(400, "ingest.merge_policy must be newest or union");
    }
    if (w.enabled && /[\\/]data[\\/]?(uploads|graphs)?$/i.test(w.dir)) {
      return fail(400, "the watch folder must not be the data, uploads or graphs directory");
    }
    // Omitted sections take their defaults, as on the server.
    settings = {
      watch: { ...w },
      analysis: { unified_tier0: analysis?.unified_tier0 ?? true },
      ingest: { merge_policy: ingest?.merge_policy ?? "newest", session_window_hours: hours },
    };
    if (w.enabled) watchStatus.last_scan = now();
    return ok(settingsResponse());
  }
  return null;
}
