// Typed client for the CopperHound REST API (docs/API.md).
// All calls go through a pluggable Backend so the in-browser mock can be swapped in
// during development (VITE_MOCK=1) without shipping it in the production bundle.

import type {
  Alert,
  NetworkConfig,
  NetworkExposure,
  NetworkStatus,
  AlertRules,
  AuthProviders,
  ChannelIn,
  ChannelOut,
  ColumnsResponse,
  Delivery,
  FilterRequest,
  FilterResponse,
  OidcExchangeResponse,
  Schedule,
  ScheduleInput,
  SchedulesResponse,
  SsoConfig,
  SsoSettingsResponse,
  SsoTestResult,
  ApiTokenInfo,
  AuditEntry,
  CreatedToken,
  Me,
  ReportParams,
  Role,
  ServerSettings,
  SettingsResponse,
  SourcesResponse,
  UserInfo,
  UsersResponse,
  UserUpdate,
  CancelResponse,
  ComputingBody,
  FindingDetail,
  FindingsResponse,
  Page,
  PlanRequest,
  PlanResponse,
  PostureDiff,
  SimulateRequest,
  SimulateResponse,
  Snapshot,
  ReviewStatus,
  ZoneReview,
  EdgeRef,
  FixItem,
  TicketCreated,
  TicketRecord,
  TicketTarget,
  TicketTargetIn,
  Zone,
  ZoneInput,
  ZoneObjectsResponse,
  Direction,
  ClearRequest,
  ClearResponse,
  CollectorInfo,
  CollectorKind,
  NewCollectorResponse,
  QualityResponse,
  EdgeComposition,
  Environment,
  KindStyle,
  LdapTarget,
  LdapTargetInput,
  FindingHistory,
  RiskAcceptance,
  SamlConfig,
  SamlSettingsResponse,
  EdgeKindInfo,
  ErrorBody,
  ErrorCode,
  GraphResult,
  Health,
  IngestResponse,
  Job,
  LoginRequest,
  LoginResponse,
  MarksRequest,
  Node,
  NodeDetail,
  NodeId,
  NodeKindInfo,
  PathRequest,
  PrebuiltQuery,
  QueryRequest,
  SavedQuery,
  SavedQueryInput,
  Stats,
  Tier0Report,
  UploadInfo,
  UploadResponse,
} from "./types";

export const API_BASE = "/api/v1";

type Method = "GET" | "POST" | "PUT" | "DELETE";
type QueryParams = Record<string, string | number | undefined>;

export interface ApiRequest {
  method: Method;
  /** Path relative to API_BASE, starting with "/". */
  path: string;
  query?: QueryParams;
  body?: unknown;
  token: string | null;
}

export interface ApiResponse {
  status: number;
  body: unknown;
}

export interface FileResponse {
  status: number;
  /** Error / 202 bodies are JSON; successful downloads are files. */
  body: unknown;
  blob: Blob | null;
  filename: string | null;
}

export interface Backend {
  request(req: ApiRequest): Promise<ApiResponse>;
  upload(files: File[], token: string | null, onProgress: (fraction: number) => void): Promise<ApiResponse>;
  /** GET returning a file (e.g. /report) rather than JSON. */
  fetchFile(req: ApiRequest): Promise<FileResponse>;
}

export class ApiError extends Error {
  readonly status: number;
  /** Byte offset into the query for CHQL syntax errors. */
  readonly position: number | null;
  /** Machine-readable error class (v1.1): timeout, cancelled, syntax, semantic. */
  readonly code: ErrorCode | null;
  /** Sign-in needs a two-factor code (POST /login). */
  readonly mfaRequired: boolean;

  constructor(status: number, message: string, position: number | null = null, code: ErrorCode | null = null, mfaRequired = false) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.position = position;
    this.code = code;
    this.mfaRequired = mfaRequired;
  }
}

/** 202 from an endpoint whose background analysis is not ready yet (v1.2). */
export class ComputingError extends Error {
  readonly progress: number;
  constructor(progress: number) {
    super(`Analysis in progress (${Math.round(progress)}%)`);
    this.name = "ComputingError";
    this.progress = progress;
  }
}

// ---------------------------------------------------------------------------
// Session token

const TOKEN_KEY = "copperhound.token";
const USER_KEY = "copperhound.user";
const ROLE_KEY = "copperhound.role";

function storageGet(key: string): string | null {
  try {
    return sessionStorage.getItem(key);
  } catch {
    return null;
  }
}

function storageSet(key: string, value: string | null): void {
  try {
    if (value === null) sessionStorage.removeItem(key);
    else sessionStorage.setItem(key, value);
  } catch {
    // storage unavailable (private mode); the session just won't survive reloads
  }
}

let token: string | null = storageGet(TOKEN_KEY);
let unauthorizedHandler: (() => void) | null = null;
let forbiddenHandler: ((message: string) => void) | null = null;

export interface Session {
  token: string;
  username: string;
  role: Role;
}

const asRole = (r: string | null): Role => (r === "admin" || r === "analyst" || r === "uploader" ? r : "viewer");

export function getSession(): Session | null {
  return token ? { token, username: storageGet(USER_KEY) ?? "", role: asRole(storageGet(ROLE_KEY)) } : null;
}

function setSession(session: LoginResponse | null): void {
  token = session?.token ?? null;
  storageSet(TOKEN_KEY, token);
  storageSet(USER_KEY, session?.username ?? null);
  storageSet(ROLE_KEY, session?.role ?? null);
}

/** Drops the local session without calling the server (e.g. after a password change). */
export function endSession(): void {
  setSession(null);
}

/** Called once by the app; invoked whenever an authenticated call returns 401. */
export function onUnauthorized(handler: () => void): void {
  unauthorizedHandler = handler;
}

/** Invoked with the server message whenever a call returns 403 (role too low). */
export function onForbidden(handler: ((message: string) => void) | null): void {
  forbiddenHandler = handler;
}

// ---------------------------------------------------------------------------
// Backends

function buildUrl(path: string, query?: QueryParams): string {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query ?? {})) {
    if (v !== undefined && v !== "") params.set(k, String(v));
  }
  const qs = params.toString();
  return `${API_BASE}${path}${qs ? `?${qs}` : ""}`;
}

function parseJson(text: string): unknown {
  if (!text) return {};
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return { error: text };
  }
}

const httpBackend: Backend = {
  async request({ method, path, query, body, token: tok }) {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (tok) headers.Authorization = `Bearer ${tok}`;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetch(buildUrl(path, query), {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, body: parseJson(await res.text()) };
  },

  upload(files, tok, onProgress) {
    return new Promise((resolve, reject) => {
      const form = new FormData();
      for (const f of files) form.append("files", f, f.name);
      const xhr = new XMLHttpRequest();
      xhr.open("POST", buildUrl("/upload"));
      if (tok) xhr.setRequestHeader("Authorization", `Bearer ${tok}`);
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) onProgress(e.loaded / e.total);
      };
      xhr.onload = () => resolve({ status: xhr.status, body: parseJson(xhr.responseText) });
      xhr.onerror = () => reject(new ApiError(0, "Network error during upload"));
      xhr.onabort = () => reject(new ApiError(0, "Upload aborted"));
      xhr.send(form);
    });
  },

  async fetchFile({ path, query, token: tok }) {
    const headers: Record<string, string> = {};
    if (tok) headers.Authorization = `Bearer ${tok}`;
    const res = await fetch(buildUrl(path, query), { headers });
    if (res.status !== 200) return { status: res.status, body: parseJson(await res.text()), blob: null, filename: null };
    const cd = res.headers.get("Content-Disposition") ?? "";
    const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(cd);
    return { status: 200, body: null, blob: await res.blob(), filename: m ? decodeURIComponent(m[1]!) : null };
  },
};

// The mock is only referenced behind this compile-time env check, so the
// production build (VITE_MOCK unset) never emits the mock chunk.
const backendPromise: Promise<Backend> =
  import.meta.env.VITE_MOCK === "1"
    ? import("../mock/server").then((m) => m.mockBackend)
    : Promise.resolve(httpBackend);

export const isMockMode = import.meta.env.VITE_MOCK === "1";

function unwrap<T>(res: ApiResponse, path: string): T {
  if (res.status === 202) {
    const b = (res.body ?? {}) as Partial<ComputingBody>;
    if (b.status === "computing") throw new ComputingError(typeof b.progress === "number" ? b.progress : 0);
  }
  if (res.status >= 200 && res.status < 300) return res.body as T;
  const err = (res.body ?? {}) as Partial<ErrorBody>;
  // Sign-in endpoints answer 401 for bad credentials / codes, not for an expired session.
  if (res.status === 401 && path !== "/login" && !path.startsWith("/auth/")) {
    setSession(null);
    unauthorizedHandler?.();
  }
  const message = typeof err.error === "string" ? err.error : `HTTP ${res.status}`;
  if (res.status === 403) forbiddenHandler?.(message);
  throw new ApiError(
    res.status,
    message,
    typeof err.position === "number" ? err.position : null,
    typeof err.code === "string" ? err.code : null,
    (err as { mfa_required?: unknown }).mfa_required === true,
  );
}

async function call<T>(method: Method, path: string, opts: { query?: QueryParams; body?: unknown } = {}): Promise<T> {
  const backend = await backendPromise;
  let res: ApiResponse;
  try {
    res = await backend.request({ method, path, query: opts.query, body: opts.body, token });
  } catch (e) {
    if (e instanceof ApiError) throw e;
    throw new ApiError(0, "Cannot reach the CopperHound server");
  }
  return unwrap<T>(res, path);
}

// ---------------------------------------------------------------------------
// Endpoints

export const api = {
  health: () => call<Health>("GET", "/health"),

  async login(username: string, password: string, otp?: string): Promise<LoginResponse> {
    const res = await call<LoginResponse>("POST", "/login", { body: { username, password, ...(otp ? { otp } : {}) } satisfies LoginRequest });
    setSession(res);
    return res;
  },

  /** Public: which sign-in methods the login page should offer (v1.4). */
  authProviders: () => call<AuthProviders>("GET", "/auth/providers"),

  /** Redeems the one-time code from #/sso for a session token (v1.4). */
  async oidcExchange(code: string): Promise<OidcExchangeResponse> {
    const res = await call<OidcExchangeResponse>("POST", "/auth/oidc/exchange", { body: { code } });
    setSession(res);
    return res;
  },

  async logout(): Promise<void> {
    try {
      await call<object>("POST", "/logout");
    } finally {
      setSession(null);
    }
  },

  stats: () => call<Stats>("GET", "/stats"),

  // --- accounts & administration ---
  me: () => call<Me>("GET", "/me"),
  async changePassword(current_password: string, new_password: string): Promise<void> {
    await call<object>("PUT", "/me/password", { body: { current_password, new_password } });
    // The server signs out every session of this user.
    setSession(null);
  },
  myTokens: () => call<{ tokens: ApiTokenInfo[] }>("GET", "/me/tokens"),
  createToken: (name: string, expires_days?: number) =>
    call<CreatedToken>("POST", "/me/tokens", { body: { name, ...(expires_days ? { expires_days } : {}) } }),
  deleteToken: (id: string) => call<object>("DELETE", `/me/tokens/${encodeURIComponent(id)}`),
  users: () => call<UsersResponse>("GET", "/users"),
  createUser: (username: string, password: string, role: Role) => call<UserInfo>("POST", "/users", { body: { username, password, role } }),
  updateUser: (name: string, update: UserUpdate) => call<UserInfo>("PUT", `/users/${encodeURIComponent(name)}`, { body: update }),
  deleteUser: (name: string) => call<object>("DELETE", `/users/${encodeURIComponent(name)}`),
  revokeUserToken: (name: string, id: string) =>
    call<object>("DELETE", `/users/${encodeURIComponent(name)}/tokens/${encodeURIComponent(id)}`),
  audit: (q: { limit?: number; user?: string; action?: string }) =>
    call<{ entries: AuditEntry[] }>("GET", "/audit", { query: { limit: q.limit, user: q.user, action: q.action } }),
  serverSettings: () => call<SettingsResponse>("GET", "/settings"),
  saveServerSettings: (s: ServerSettings) => call<SettingsResponse>("PUT", "/settings", { body: s }),
  mfaStatus: () => call<{ enabled: boolean; pending: boolean; recovery_codes_left: number }>("GET", "/me/mfa"),
  mfaSetup: () => call<{ secret: string; uri: string; qr_svg: string }>("POST", "/me/mfa/setup", { body: {} }),
  mfaEnable: (code: string) => call<{ enabled: true; recovery_codes: string[] }>("POST", "/me/mfa/enable", { body: { code } }),
  mfaDisable: (code: string) => call<{ enabled: false }>("POST", "/me/mfa/disable", { body: { code } }),
  resetUserMfa: (name: string) => call<object>("DELETE", `/users/${encodeURIComponent(name)}/mfa`),
  ssoSettings: () => call<SsoSettingsResponse>("GET", "/settings/sso"),
  samlSettings: () => call<SamlSettingsResponse>("GET", "/settings/saml"),
  saveSamlSettings: (c: SamlConfig) => call<SamlSettingsResponse>("PUT", "/settings/saml", { body: c }),
  saveSsoSettings: (c: SsoConfig) => call<SsoSettingsResponse>("PUT", "/settings/sso", { body: c }),
  /** Empty body tests the saved config; otherwise a candidate issuer. Always 200 (check ok). */
  testSso: (candidate?: { issuer: string; allow_insecure_http: boolean }) =>
    call<SsoTestResult>("POST", "/settings/sso/test", { body: candidate ?? {} }),

  // --- notifications, schedules, alerts (v1.4) ---
  channels: () => call<{ channels: ChannelOut[] }>("GET", "/notify/channels"),
  /** Replaces the whole channel list. */
  saveChannels: (channels: ChannelIn[]) => call<{ channels: ChannelOut[] }>("PUT", "/notify/channels", { body: { channels } }),
  remediationCommands: (edges: EdgeRef[]) => call<{ items: FixItem[]; missing: EdgeRef[] }>("POST", "/remediation/commands", { body: { edges } }),
  ticketTargets: () => call<TicketTarget[]>("GET", "/tickets/targets"),
  /** Replaces the whole ticket target list. */
  saveTicketTargets: (targets: TicketTargetIn[]) => call<TicketTarget[]>("PUT", "/tickets/targets", { body: { targets } }),
  testTicketTarget: (id: string) => call<{ ok: boolean; detail?: string; error?: string }>("POST", `/tickets/targets/${encodeURIComponent(id)}/test`, { body: {} }),
  createTickets: (r: { target: string; edges: EdgeRef[]; title?: string; note?: string; split?: boolean }) =>
    call<{ created: TicketCreated[]; errors: { title: string; error: string }[]; missing: EdgeRef[] }>("POST", "/tickets", { body: r }),
  tickets: () => call<TicketRecord[]>("GET", "/tickets"),
  testChannel: (id: string) => call<Delivery>("POST", `/notify/channels/${encodeURIComponent(id)}/test`),
  schedules: () => call<SchedulesResponse>("GET", "/schedules"),
  createSchedule: (s: ScheduleInput) => call<Schedule>("POST", "/schedules", { body: s }),
  updateSchedule: (id: string, s: ScheduleInput) => call<Schedule>("PUT", `/schedules/${encodeURIComponent(id)}`, { body: s }),
  deleteSchedule: (id: string) => call<object>("DELETE", `/schedules/${encodeURIComponent(id)}`),
  runSchedule: (id: string) => call<{ started: boolean }>("POST", `/schedules/${encodeURIComponent(id)}/run`),
  alertRules: () => call<AlertRules>("GET", "/alerts/rules"),
  saveAlertRules: (r: AlertRules) => call<AlertRules>("PUT", "/alerts/rules", { body: r }),
  alerts: (limit = 100) => call<{ alerts: Alert[] }>("GET", "/alerts", { query: { limit } }),

  /** Assessment report as a file (self-contained HTML, Markdown or CSV). */
  async report(p: ReportParams): Promise<{ blob: Blob; filename: string }> {
    const backend = await backendPromise;
    const query = {
      format: p.format,
      title: p.title,
      plan_steps: p.plan_steps,
      items: p.items,
      download: p.download ? 1 : undefined,
      env: p.env || undefined,
    };
    let res: FileResponse;
    try {
      res = await backend.fetchFile({ method: "GET", path: "/report", query, token });
    } catch {
      throw new ApiError(0, "Cannot reach the CopperHound server");
    }
    if (res.status !== 200 || !res.blob) {
      unwrap<never>({ status: res.status, body: res.body }, "/report");
      throw new ApiError(res.status, `HTTP ${res.status}`);
    }
    return { blob: res.blob, filename: res.filename ?? `copperhound-report.${p.format}` };
  },

  /** Server backup zip (admin). */
  async backup(uploads: boolean, tls: boolean): Promise<{ blob: Blob; filename: string }> {
    const backend = await backendPromise;
    let res: FileResponse;
    try {
      res = await backend.fetchFile({ method: "GET", path: "/backup", query: { uploads: uploads ? 1 : undefined, tls: tls ? 1 : undefined }, token });
    } catch {
      throw new ApiError(0, "Cannot reach the CopperHound server");
    }
    if (res.status !== 200 || !res.blob) {
      unwrap<never>({ status: res.status, body: res.body }, "/backup");
      throw new ApiError(res.status, `HTTP ${res.status}`);
    }
    return { blob: res.blob, filename: res.filename ?? "copperhound-backup.zip" };
  },

  /** Stage a backup for restore (applied at the next server start). */
  async restoreBackup(file: File): Promise<{ staged_files: number; includes_uploads: boolean; backup_created_at: string | null }> {
    if (isMockMode) return { staged_files: 12, includes_uploads: false, backup_created_at: new Date().toISOString() };
    const form = new FormData();
    form.append("backup", file, file.name);
    let res: Response;
    try {
      res = await fetch(buildUrl("/restore"), { method: "POST", headers: token ? { Authorization: `Bearer ${token}` } : {}, body: form });
    } catch {
      throw new ApiError(0, "Cannot reach the CopperHound server");
    }
    return unwrap(
      { status: res.status, body: await res.json().catch(() => null) },
      "/restore",
    );
  },

  search: (q: string, limit = 20, kind?: string) =>
    call<Node[]>("GET", "/search", { query: { q, limit, kind } }),

  /** Property filter over every node (v1.1), paged. */
  filterNodes: (req: FilterRequest) => call<FilterResponse>("POST", "/nodes/filter", { body: req }),

  /** Typed property columns; ready:false while they build after a graph load. */
  columns: () => call<ColumnsResponse>("GET", "/columns"),

  node: (id: NodeId) => call<NodeDetail>("GET", `/nodes/${id}`),

  /** Batch lookup; unknown ids are omitted (max 5000 per call). */
  nodes: (ids: NodeId[]) => call<Node[]>("GET", "/nodes", { query: { ids: ids.join(",") } }),

  /** objectid -> Node in the current graph; unknown omitted (max 5000). */
  resolve: (objectids: string[]) => call<Node[]>("POST", "/nodes/resolve", { body: { objectids } }),

  /** The given nodes and every edge among them (max 5000 ids). */
  subgraph: (ids: NodeId[]) => call<GraphResult>("POST", "/subgraph", { body: { ids } }),

  /** Why a derived edge exists (404 when the edge is not in the graph). */
  edgeComposition: (src: NodeId, dst: NodeId, kind: string) =>
    call<EdgeComposition>("GET", "/edges/composition", { query: { src, dst, kind } }),

  nodeEdges: (id: NodeId, dir: Direction, kind?: string, limit = 500) =>
    call<GraphResult>("GET", `/nodes/${id}/edges`, { query: { dir, kind, limit } }),

  setMarks: (id: NodeId, marks: MarksRequest) =>
    call<Node>("POST", `/nodes/${id}/marks`, { body: marks }),

  path: (req: PathRequest) => call<GraphResult>("POST", "/path", { body: req }),

  tier0: (top = 25) => call<Tier0Report>("GET", "/tier0", { query: { top } }),

  query: (req: QueryRequest) => call<GraphResult>("POST", "/query", { body: req }),

  cancelQuery: (queryId: string) => call<CancelResponse>("DELETE", `/query/${encodeURIComponent(queryId)}`),

  queries: () => call<PrebuiltQuery[]>("GET", "/queries"),

  savedQueries: () => call<SavedQuery[]>("GET", "/saved-queries"),

  createSavedQuery: (q: SavedQueryInput) => call<SavedQuery>("POST", "/saved-queries", { body: q }),

  updateSavedQuery: (id: string, q: SavedQueryInput) =>
    call<SavedQuery>("PUT", `/saved-queries/${encodeURIComponent(id)}`, { body: q }),

  deleteSavedQuery: (id: string) => call<object>("DELETE", `/saved-queries/${encodeURIComponent(id)}`),

  edgeKinds: () => call<EdgeKindInfo[]>("GET", "/edge-kinds"),

  nodeKinds: () => call<NodeKindInfo[]>("GET", "/node-kinds"),

  async upload(files: File[], onProgress: (fraction: number) => void): Promise<UploadResponse> {
    const backend = await backendPromise;
    return unwrap<UploadResponse>(await backend.upload(files, token, onProgress), "/upload");
  },

  uploads: () => call<UploadInfo[]>("GET", "/uploads"),
  /** v1.5: sources (input files / zip entries) of the loaded graph. */
  sources: () => call<SourcesResponse>("GET", "/sources"),

  deleteUpload: (name: string) => call<object>("DELETE", `/uploads/${encodeURIComponent(name)}`),

  ingest: () => call<IngestResponse>("POST", "/ingest"),
  clearDatabase: (r: ClearRequest) => call<ClearResponse>("POST", "/database/clear", { body: r }),
  collectors: () => call<CollectorInfo[]>("GET", "/collectors"),
  quality: () => call<QualityResponse>("GET", "/quality"),
  kindStyles: () => call<Record<string, KindStyle>>("GET", "/kind-styles"),
  network: () => call<NetworkStatus>("GET", "/network"),
  saveNetwork: (c: NetworkConfig) => call<NetworkStatus>("PUT", "/network", { body: c }),
  deleteNetwork: () => call<NetworkStatus>("DELETE", "/network"),
  networkExposure: (zone?: string) => call<NetworkExposure>("GET", `/network/exposure${zone ? `?zone=${encodeURIComponent(zone)}` : ""}`),
  saveKindStyles: (m: Record<string, KindStyle>) => call<Record<string, KindStyle>>("PUT", "/kind-styles", { body: m }),
  ldapTargets: () => call<LdapTarget[]>("GET", "/collect/ldap"),
  saveLdapTarget: (t: LdapTargetInput) => call<LdapTarget>("PUT", "/collect/ldap", { body: t }),
  deleteLdapTarget: (id: string) => call<object>("DELETE", `/collect/ldap/${encodeURIComponent(id)}`),
  runLdapTarget: (id: string) => call<object>("POST", `/collect/ldap/${encodeURIComponent(id)}/run`, { body: {} }),
  testLdapTarget: (id: string) =>
    call<{ ok: boolean; error?: string; dns_host_name?: string; default_naming_context?: string }>("POST", `/collect/ldap/${encodeURIComponent(id)}/test`, { body: {} }),
  createCollector: (name: string, kind: CollectorKind, interval_hours: number) =>
    call<NewCollectorResponse>("POST", "/collectors", { body: { name, kind, interval_hours } }),
  deleteCollector: (id: string) => call<object>("DELETE", `/collectors/${encodeURIComponent(id)}`),

  jobs: () => call<Job[]>("GET", "/jobs"),

  // --- v1.2 ---
  zones: () => call<Zone[]>("GET", "/zones"),
  createZone: (z: ZoneInput) => call<Zone>("POST", "/zones", { body: z }),
  updateZone: (id: string, z: ZoneInput) => call<Zone>("PUT", `/zones/${encodeURIComponent(id)}`, { body: z }),
  deleteZone: (id: string) => call<object>("DELETE", `/zones/${encodeURIComponent(id)}`),
  zoneObjects: (id: string, change: { add?: string[]; remove?: string[] }) =>
    call<ZoneObjectsResponse>("POST", `/zones/${encodeURIComponent(id)}/objects`, { body: change }),
  setZoneWeight: (id: string, weight: number) =>
    call<{ id: string; weight: number }>("PUT", `/zones/${encodeURIComponent(id)}/weight`, { body: { weight } }),
  zoneMembers: (id: string, offset = 0, limit = 200) =>
    call<Page<Node>>("GET", `/zones/${encodeURIComponent(id)}/members`, { query: { offset, limit } }),
  zoneReview: (id: string, status: ReviewStatus | "", offset = 0, limit = 200) =>
    call<ZoneReview>("GET", `/zones/${encodeURIComponent(id)}/review`, { query: { status: status || undefined, offset, limit } }),
  reviewZone: (id: string, objectids: string[], status: ReviewStatus, note = "") =>
    call<{ updated: number }>("POST", `/zones/${encodeURIComponent(id)}/review`, { body: { objectids, status, note } }),
  zoneExposure: (id: string, top = 25) => call<Tier0Report>("GET", `/zones/${encodeURIComponent(id)}/exposure`, { query: { top } }),

  findings: (env?: string) => call<FindingsResponse>("GET", "/findings", { query: { env: env || undefined } }),
  environments: () => call<Environment[]>("GET", "/environments"),
  acceptFinding: (id: string, reason: string, expires_days?: number) =>
    call<{ id: string; acceptance: RiskAcceptance }>("PUT", `/findings/${encodeURIComponent(id)}/acceptance`, {
      body: { reason, ...(expires_days ? { expires_days } : {}) },
    }),
  revokeAcceptance: (id: string) => call<object>("DELETE", `/findings/${encodeURIComponent(id)}/acceptance`),
  findingHistory: (id: string) => call<FindingHistory>("GET", `/findings/${encodeURIComponent(id)}/history`),
  finding: (id: string, offset = 0, limit = 100, env?: string) =>
    call<FindingDetail>("GET", `/findings/${encodeURIComponent(id)}`, { query: { offset, limit, env: env || undefined } }),

  simulate: (req: SimulateRequest) => call<SimulateResponse>("POST", "/simulate", { body: req }),
  remediationPlan: (req: PlanRequest) => call<PlanResponse>("POST", "/remediation-plan", { body: req }),

  posture: () => call<Snapshot[]>("GET", "/posture"),
  postureDiff: (from: string, to: string) => call<PostureDiff>("GET", "/posture/diff", { query: { from, to } }),
  deleteSnapshot: (id: string) => call<object>("DELETE", `/posture/${encodeURIComponent(id)}`),

  job: (id: string) => call<Job>("GET", `/jobs/${encodeURIComponent(id)}`),
};

export function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}
