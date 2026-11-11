// Types mirroring docs/API.md (REST API v1). Keep in sync with the contract.

export const AD_KINDS = ["User", "Group", "Computer", "Domain", "GPO", "OU", "Container"] as const;
export const ADCS_KINDS = [
  "CertTemplate",
  "EnterpriseCA",
  "RootCA",
  "AIACA",
  "NTAuthStore",
  "IssuancePolicy",
] as const;
export const AZURE_KINDS = [
  "AZTenant",
  "AZUser",
  "AZGroup",
  "AZApp",
  "AZServicePrincipal",
  "AZDevice",
  "AZRole",
  "AZSubscription",
  "AZResourceGroup",
  "AZManagementGroup",
  "AZKeyVault",
  "AZVM",
  "AZAutomationAccount",
  "AZContainerRegistry",
  "AZFunctionApp",
  "AZLogicApp",
  "AZManagedCluster",
  "AZVMScaleSet",
  "AZWebApp",
] as const;

export type NodeKind =
  | (typeof AD_KINDS)[number]
  | (typeof ADCS_KINDS)[number]
  | (typeof AZURE_KINDS)[number]
  | "Unknown";

/** Custom node kind name from OpenGraph data (any string not a built-in kind). */
export type CustomKind = string & { readonly __custom?: never };

export type NodeId = number;

export interface Node {
  id: NodeId;
  objectid: string;
  name: string;
  /** A built-in kind, or a custom kind imported from OpenGraph data. */
  kind: NodeKind | CustomKind;
  tier0: boolean;
  owned: boolean;
  enabled: boolean;
}

export interface Edge {
  src: NodeId;
  dst: NodeId;
  kind: string;
}

/** One traversed hop of a path, in path order (v1.1). */
export type Hop = Edge;

export interface GraphResult {
  nodes: Node[];
  edges: Edge[];
  columns?: string[];
  rows?: unknown[][];
  paths?: NodeId[][];
  /** POST /path: hops of the single path (v1.1). */
  hops?: Hop[];
  /** POST /query: one hops list per entry of `paths` (v1.1). */
  path_hops?: Hop[][];
  /** POST /path with all: true. */
  all_paths?: { length: number; edges: number; nodes: number; truncated: boolean };
  truncated: boolean;
  elapsed_ms: number;
  /** /path, /query, /subgraph (v1.1). */
  generation?: number;
}

export interface Limits {
  max_query_limit: number;
  default_query_timeout_ms: number;
  max_query_timeout_ms: number;
  upload_extensions: string[];
  /** null = unlimited */
  max_upload_bytes: number | null;
}

export interface Health {
  status: string;
  graph_loaded: boolean;
  version: string;
  /** Changes whenever a new graph is installed; 0 = no graph (v1.1). */
  generation: number;
  limits: Limits;
  /** Stable id of the installed graph snapshot (v1.2). */
  snapshot_id?: string;
}

export interface LoginRequest {
  username: string;
  password: string;
  /** Two-factor or recovery code. */
  otp?: string;
}

export const ROLES = ["uploader", "viewer", "analyst", "admin"] as const;
/** viewer < analyst < admin; uploader (upload-only) sees no data and only gets the upload page. */
export type Role = (typeof ROLES)[number];

export interface LoginResponse {
  token: string;
  username: string;
  role: Role;
}

export interface Stats {
  nodes: number;
  edges: number;
  tier0: number;
  owned: number;
  node_kinds: Record<string, number>;
  edge_kinds: Record<string, number>;
  loaded_at: string | null;
  generation: number;
  snapshot_id?: string;
}

export interface NodeDetail extends Node {
  properties: Record<string, unknown>;
  flags: string[];
  in_degree: number;
  out_degree: number;
  edge_counts: { out: Record<string, number>; in: Record<string, number> };
}

export type Direction = "out" | "in";

export interface MarksRequest {
  owned?: boolean;
  tier0?: boolean;
}

export interface PathRequest {
  from: NodeId | string;
  to?: NodeId | string;
  to_tier0: boolean;
  exclude: string[];
  all_edges: boolean;
  /** Every shortest path, as one subgraph. */
  all?: boolean;
}

export interface ExposureRow {
  kind: string;
  with_path: number;
  total: number;
}

export interface ChokePoint {
  src: Node;
  dst: Node;
  kind: string;
  flow: number;
}

export interface Tier0Report {
  tier0_nodes: number;
  max_depth: number;
  exposed_principals: number;
  exposure: ExposureRow[];
  choke_points: ChokePoint[];
  elapsed_ms: number;
}

export interface QueryRequest {
  query: string;
  limit: number;
  timeout_ms?: number;
  /** Client-chosen id (<= 64 chars) usable with DELETE /query/{id}. */
  query_id?: string;
}

export interface CancelResponse {
  cancelled: boolean;
}

export interface PrebuiltQuery {
  id: string;
  name: string;
  category: string;
  description: string;
  query: string;
  tags: string[];
}

export interface SavedQueryInput {
  name: string;
  category?: string;
  description?: string;
  query: string;
}

export interface SavedQuery {
  id: string;
  name: string;
  category: string;
  description: string;
  query: string;
  created_at: string;
  updated_at: string;
}

export const KIND_CATEGORIES = ["Active Directory", "ADCS", "Azure", "Hybrid", "Custom", "Other"] as const;
export type KindCategory = (typeof KIND_CATEGORIES)[number];

/** Curated help for derived / hybrid / trust edge kinds (GET /edge-kinds, v1.4). */
export interface EdgeHelp {
  description: string;
  abuse: string;
  remediation: string;
}

export interface EdgeKindInfo {
  name: string;
  traversable: boolean;
  category: KindCategory;
  count: number;
  /** null for kinds without curated text; absent on older servers. */
  help?: EdgeHelp | null;
  /** Derived by post-processing; GET /edges/composition explains it. */
  composite?: boolean;
}

/** GET /edges/composition: the collected edges and facts behind a derived edge. */
export interface EdgeComposition extends GraphResult {
  edge: Edge;
  notes: string[];
  /** Every requirement of the derivation rule was found in the graph. */
  complete: boolean;
}

export interface NodeKindInfo {
  name: string;
  category: KindCategory;
  count: number;
}

/** Shared style of a node kind (GET /kind-styles). */
export interface KindStyle {
  color?: string;
  /** Short glyph (emoji or letters). */
  icon?: string;
  /** Icon name from BloodHound custom-node definitions (informational). */
  icon_name?: string;
}

/** GET /environments: an AD domain or Entra tenant to scope to. */
export interface Environment {
  id: string;
  name: string;
  kind: "ad" | "tenant";
  objects: number;
}

export interface QualityDomain {
  type: "ad";
  id: number;
  name: string;
  objectid: string;
  users: number;
  users_enabled: number;
  groups: number;
  computers: number;
  computers_enabled: number;
  session_coverage: number | null;
  local_group_coverage: number | null;
  acl_coverage: number | null;
  collected_at: string | null;
  collected_at_exact?: boolean;
  age_days: number | null;
  sources: number;
  warnings: string[];
}

export interface QualityTenant {
  type: "tenant";
  id: number;
  name: string;
  objectid: string;
  users: number;
  groups: number;
  apps: number;
  service_principals: number;
  devices: number;
  roles: number;
  role_assignments: number;
  memberships: number;
  app_owner_coverage: number | null;
  device_owner_coverage: number | null;
  subscriptions: number;
  collected_at: string | null;
  collected_at_exact?: boolean;
  age_days: number | null;
  sources: number;
  warnings: string[];
}

export interface QualityResponse {
  domains: QualityDomain[];
  tenants: QualityTenant[];
}

export interface LdapTargetInput {
  id?: string;
  name: string;
  enabled: boolean;
  url: string;
  starttls: boolean;
  allow_plain: boolean;
  insecure_skip_verify: boolean;
  bind_dn: string;
  /** null/empty keeps the stored password. */
  password?: string | null;
  base_dn: string;
  include_configuration: boolean;
  interval_hours: number;
}

export interface LdapTarget extends Omit<LdapTargetInput, "password"> {
  id: string;
  password_set: boolean;
  running: boolean;
  last_run: string | null;
  last_ok: string | null;
  last_error: string | null;
  last_objects: number;
  last_seconds: number;
}

export type CollectorKind = "sharphound" | "azurehound" | "bloodhound-python" | "ldap";

export interface CollectorInfo {
  id: string;
  name: string;
  kind: CollectorKind;
  interval_hours: number;
  username: string;
  token_id: string;
  created_at: string;
  created_by: string;
  last_upload_at: string | null;
  last_files: string[];
  uploads: number;
  status: "ok" | "stale" | "never";
}

export interface NewCollectorResponse {
  collector: CollectorInfo;
  token: string;
  token_id?: string;
  bloodhound_key?: string;
  note: string;
  commands: { script_name: string; script: string; schedule: string };
}

/** POST /database/clear (admin). */
export interface ClearRequest {
  confirm: string;
  uploads?: "all" | string[];
  graph?: boolean;
  rebuild?: boolean;
  marks?: boolean;
  zones?: boolean;
  saved_queries?: boolean;
  posture_history?: boolean;
}

export interface ClearResponse {
  uploads_removed?: string[];
  /** Present when the graph was unloaded. */
  graph_snapshots_removed?: number;
  marks_cleared?: boolean;
  zones_cleared?: boolean;
  saved_queries_cleared?: boolean;
  posture_history_cleared?: boolean;
  /** Rebuild ingest job. */
  job_id?: string;
}

export interface UploadResponse {
  uploaded: string[];
}

export interface UploadInfo {
  name: string;
  size: number;
  uploaded_at: string;
  /** v1.5: the file is part of the loaded graph. */
  in_graph?: boolean;
  /** v1.5: sources of the loaded graph read from this upload (one per zip entry; [] if not ingested). */
  sources?: Source[];
}

// v1.5: collection-aware merging and source provenance

export type MergePolicy = "newest" | "union";

/** Where a source's collection time came from (null = undated). */
export type CollectedAtSource = "snapshot" | "meta" | "filename" | "zip-entry" | "whenchanged";

/** One input file or zip entry of the loaded graph. */
export interface Source {
  id: number;
  /** Path relative to the uploads dir (the archive for zip entries). */
  file: string;
  /** Zip entry, or null. */
  entry: string | null;
  /** sharphound | azurehound | ldapdomaindump | ldif | adexplorer | json */
  format: string;
  /** Object type of the file when known. */
  kind: string | null;
  /** AD domain names / Azure tenant ids in the records (at most 64). */
  domains: string[];
  /** null = undated: merged as a plain union. */
  collected_at: string | null;
  collected_at_unix: number | null;
  collected_at_source: CollectedAtSource | null;
  /** Informational only, never used for ordering. */
  file_mtime: string | null;
  records: number;
  objects: number;
  edges: number;
  superseded_objects: number;
  superseded_edges: number;
  parse_errors: number;
}

export interface SourcesResponse {
  generation: number;
  /** null for graphs built before v1.5. */
  merge_policy: MergePolicy | null;
  superseded_objects: number | null;
  superseded_edges: number | null;
  sources: Source[];
}

export interface IngestResponse {
  job_id: string;
}

export type JobState = "queued" | "running" | "done" | "failed";

export type JobPhase =
  | "queued"
  | "extracting"
  | "scanning"
  | "parsing"
  | "merging"
  | "building"
  | "post-processing"
  | "writing"
  | "loading"
  | "done"
  | "failed";

export interface JobReport {
  files: number;
  records: number;
  nodes: number;
  edges: number;
  parse_errors: number;
  seconds: number;
  /** v1.5 */
  merge_policy?: MergePolicy;
  superseded_objects?: number;
  superseded_edges?: number;
  /** Number of sources (files and zip entries). */
  sources?: number;
}

export interface Job {
  id: string;
  state: JobState;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  message?: string | null;
  report?: JobReport | null;
  phase?: JobPhase;
  /** 0-100, approximate */
  percent?: number;
  /** What started the job. */
  trigger?: "manual" | "watch" | "api";
}

export type ErrorCode = "timeout" | "cancelled" | "syntax" | "semantic";

export interface ErrorBody {
  error: string;
  position?: number | null;
  code?: ErrorCode;
}

// ---------------------------------------------------------------------------
// v1.2: analysis results. Endpoints that depend on background analysis answer
// 202 {"status":"computing","progress":0-100} until it is ready.

export interface ComputingBody {
  status: "computing";
  progress: number;
}

export type Severity = "critical" | "high" | "medium" | "low";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
export type SeverityCounts = Record<Severity, number>;

export interface Zone {
  id: string;
  name: string;
  description: string;
  selector: string;
  color: string;
  builtin: boolean;
  member_count: number;
}

export type TicketTargetType = "jira" | "servicenow" | "webhook";

export interface TicketTarget {
  id: string;
  name: string;
  type: TicketTargetType;
  enabled: boolean;
  url: string;
  username: string;
  token_set: boolean;
  project: string;
  issue_type: string;
  table: string;
  labels: string[];
  fields: Record<string, unknown>;
}

/** `token`: undefined keeps the stored one, "" clears it. */
export interface TicketTargetIn {
  id?: string;
  name: string;
  type: TicketTargetType;
  enabled: boolean;
  url: string;
  username?: string;
  token?: string;
  project?: string;
  issue_type?: string;
  table?: string;
  labels?: string[];
  fields?: Record<string, unknown>;
}

/** An edge by object id. */
export interface EdgeRef {
  src: string;
  kind: string;
  dst: string;
}

export interface FixItem {
  src: Node;
  dst: Node;
  kind: string;
  guidance: string | null;
  command: string | null;
}

export interface TicketCreated {
  key: string;
  url?: string | null;
  title: string;
  edges: number;
}

export interface TicketRecord {
  at: string;
  by: string;
  target: string;
  target_name: string;
  key: string;
  url?: string | null;
  title: string;
  edges: string[];
}

export type ReviewStatus = "pending" | "certified" | "revoked";

export interface ZoneReviewDecision {
  status: "certified" | "revoked";
  by: string;
  at: string;
  note?: string;
}

export interface ZoneReviewRow {
  node: Node;
  status: ReviewStatus;
  decision: ZoneReviewDecision | null;
}

export interface ZoneReview {
  zone: string;
  counts: Record<ReviewStatus, number>;
  total: number;
  offset: number;
  items: ZoneReviewRow[];
}

export interface ZoneInput {
  name: string;
  description?: string;
  selector: string;
  color?: string;
}

export interface Page<T> {
  total: number;
  items: T[];
}

export interface FindingExposure {
  principals_cut: number;
  percent_of_exposed: number;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: KindCategory;
  kind: "edges" | "nodes";
  count: number;
  exposure: FindingExposure | null;
  description: string;
  impact: string;
  remediation: string;
  mitre: string[];
  query: string;
  /** Accepted as a risk (absent on older servers). */
  accepted?: RiskAcceptance | null;
}

export interface FindingHistory {
  id: string;
  /** Oldest first. */
  points: { snapshot_id: string; created_at: string; count: number }[];
  latest_change: {
    from: string;
    to: string;
    from_at: string;
    to_at: string;
    added: number;
    removed: number;
    added_sample: string[];
    removed_sample: string[];
  } | null;
}

export interface RiskAcceptance {
  reason: string;
  accepted_by: string;
  accepted_at: string;
  expires_at?: string;
}

export interface FindingsResponse {
  status: "ready";
  snapshot_id: string;
  computed_ms: number;
  /** Set when scoped with ?env=. */
  environment?: Environment | null;
  /** Open findings (accepted risks excluded). */
  summary: SeverityCounts;
  summary_all?: SeverityCounts;
  accepted_count?: number;
  findings: Finding[];
}

export type FindingItem = { src: Node; dst: Node; kind: string } | { node: Node };

export interface FindingDetail extends Finding {
  items: FindingItem[];
  total: number;
  graph: GraphResult;
}

export interface SimulateRequest {
  zone?: string;
  remove_edges?: Edge[];
  remove_kinds?: string[];
  remove_nodes?: NodeId[];
  add_targets?: NodeId[];
}

/** Per-kind exposure, same shape as Tier0Report.exposure. */
export type KindExposure = ExposureRow;

export interface ExposureState {
  exposed_principals: number;
  exposure: KindExposure[];
  max_depth: number;
}

export interface SimulateResponse {
  before: ExposureState;
  after: ExposureState;
  reduction: number;
  reduction_percent: number;
  elapsed_ms: number;
}

export interface PlanRequest {
  zone?: string;
  steps?: number;
  fixed_kinds?: string[];
  protect_target_membership?: boolean;
  timeout_ms?: number;
}

export interface PlanEdge {
  src: Node;
  dst: Node;
  kind: string;
}

/** One dominator-tree step: remove `node`'s onward attack edges (exact cut). */
export interface PlanStep {
  node: Node;
  /** Capped at 50; see edge_count. */
  edges: PlanEdge[];
  edge_count: number;
  principals_cut: number;
  exposed_after: number;
  cumulative_reduction_percent: number;
}

export interface PlanResponse {
  baseline: number;
  truncated: boolean;
  steps: PlanStep[];
  elapsed_ms: number;
}

export interface Snapshot {
  snapshot_id: string;
  created_at: string;
  nodes: number;
  edges: number;
  tier0: number;
  exposed_principals: number;
  total_principals: number;
  exposure_percent: number;
  findings: SeverityCounts;
  finding_counts: Record<string, number>;
}

export interface ItemLabel {
  key: string;
  label: string;
}

export interface FindingDiff {
  id: string;
  title: string;
  severity: Severity;
  added: number;
  removed: number;
  added_items: ItemLabel[];
  removed_items: ItemLabel[];
}

export interface PostureDiff {
  from: string;
  to: string;
  findings: FindingDiff[];
}

// ---------------------------------------------------------------------------
// Accounts, RBAC, audit, server settings (crates/server/src/users.rs, watch.rs)

export interface ApiTokenInfo {
  id: string;
  name: string;
  /** First characters of the token, for display. */
  prefix: string;
  created_at: string;
  expires_at: string | null;
  last_used: string | null;
}

/** POST /me/tokens: the plaintext token is only returned once. */
export interface CreatedToken extends ApiTokenInfo {
  token: string;
  note: string;
  /** Key for BloodHound-compatible clients (bhesignature) with the token id. */
  bloodhound_key?: string;
}

/** How an account signs in (v1.4): local password or OpenID Connect. */
export type UserSource = "local" | "oidc";

export interface UserInfo {
  username: string;
  role: Role;
  /** Absent on servers before v1.4 (= local). */
  source?: UserSource;
  created_at: string;
  disabled: boolean;
  last_login: string | null;
  tokens: ApiTokenInfo[];
  /** Two-factor sign-in on (absent on older servers). */
  mfa?: boolean;
}

export interface Me extends UserInfo {
  via_token: boolean;
  permissions: { analyse: boolean; upload?: boolean; modify: boolean; admin: boolean };
}

export interface RoleInfo {
  id: Role;
  description: string;
}

export interface UsersResponse {
  users: UserInfo[];
  roles: RoleInfo[];
}

export interface UserUpdate {
  role?: Role;
  password?: string;
  disabled?: boolean;
}

export interface AuditEntry {
  ts: string;
  user: string;
  role: string;
  action: string;
  method: string;
  path: string;
  status: number;
  ip?: string;
  detail?: string;
}

export interface WatchSettings {
  enabled: boolean;
  /** Empty = <data>/watch */
  dir: string;
  mode: "replace" | "merge";
  settle_seconds: number;
  archive: boolean;
  keep_archives: number;
}

export interface AnalysisSettings {
  /** AD and Entra ID Tier Zero form one target set (default true). */
  unified_tier0: boolean;
}

export interface IngestSettings {
  /** "newest" (default): newest collection wins per object; "union": plain union. */
  merge_policy: MergePolicy;
  /** newest only: keep HasSession edges up to N hours older than a computer's newest session data. 0-8760. */
  session_window_hours: number;
}

export interface ServerSettings {
  watch: WatchSettings;
  /** Absent on servers before v1.4. */
  analysis?: AnalysisSettings;
  /** Absent on servers before v1.5. */
  ingest?: IngestSettings;
}

export interface WatchStatus {
  last_scan: string | null;
  last_import: string | null;
  last_job: string | null;
  imported_files: number;
  /** Files seen but not yet stable. */
  pending: string[];
  last_error: string | null;
}

export interface SettingsResponse {
  settings: ServerSettings;
  watch_dir_resolved: string;
  watch_status: WatchStatus;
}

export type ReportFormat = "html" | "md" | "csv";

export interface ReportParams {
  format: ReportFormat;
  title?: string;
  plan_steps?: number;
  items?: number;
  download?: boolean;
  /** Environment object id (domain / tenant). */
  env?: string;
}

// ---------------------------------------------------------------------------
// v1.1 property filters (POST /nodes/filter, GET /columns)

export const FILTER_OPS = ["eq", "ne", "lt", "le", "gt", "ge", "starts_with", "ends_with", "contains", "in"] as const;
export type FilterOp = (typeof FILTER_OPS)[number];
export type FilterScalar = string | number | boolean | null;
export type FilterValue = FilterScalar | FilterScalar[];

export type Filter =
  | { const: boolean }
  | { kind: string | string[] }
  | { cmp: { key: string; op: FilterOp; value: FilterValue } }
  | { is_null: { key: string; null?: boolean } }
  | { truthy: string }
  | { and: Filter[] }
  | { or: Filter[] }
  | { not: Filter };

export interface FilterRequest {
  filter: Filter;
  limit?: number;
  offset?: number;
}

export interface FilterResponse {
  total: number;
  offset: number;
  nodes: Node[];
  filter_ms: number;
  elapsed_ms: number;
}

export type ColumnType = "bool" | "int" | "float" | "str" | "raw" | "null";

export interface ColumnInfo {
  key: string;
  type: ColumnType;
  count: number;
  /** Distinct values (string columns only). */
  distinct: number | null;
  eq_index: boolean;
}

export interface ColumnsResponse {
  ready: boolean;
  complete?: boolean;
  columns?: ColumnInfo[];
}

// ---------------------------------------------------------------------------
// v1.4: single sign-on (OpenID Connect)

export interface AuthProviders {
  password_login: boolean;
  admin_password_login: boolean;
  sso: { enabled: boolean; type: "oidc"; display_name: string; login_url: string };
  /** SAML 2.0 sign-on (absent on older servers). */
  saml?: { enabled: boolean; display_name: string; login_url: string };
}

/** PUT /settings/saml body; GET returns it inside SamlSettingsResponse. */
export interface SamlConfig {
  enabled: boolean;
  display_name: string;
  /** IdP metadata XML (EntityDescriptor). */
  idp_metadata: string;
  /** Empty: derived from the public URL. */
  sp_entity_id: string;
  acs_url: string;
  /** Empty: the NameID. */
  username_attribute: string;
  groups_attribute: string;
  email_attribute: string;
  role_mapping: { admin: string[]; analyst: string[]; viewer: string[] };
  default_role: SsoDefaultRole;
  allowed_email_domains: string[];
}

export interface SamlSettingsResponse {
  config: SamlConfig;
  sp_entity_id_effective: string;
  acs_url_effective: string;
  metadata_url: string;
  /** Parsed IdP metadata, null when missing or invalid. */
  idp: { entity_id: string; sso_url: string; certificates: string[] } | null;
}

export interface OidcExchangeResponse extends LoginResponse {
  return_to: string;
}

export type SsoDefaultRole = "viewer" | "analyst" | "deny";
/** Roles SSO groups can grant (upload-only accounts are local or token-based). */
export type SsoMappedRole = "admin" | "analyst" | "viewer";

export interface SsoConfig {
  enabled: boolean;
  display_name: string;
  issuer: string;
  client_id: string;
  /** Read-only: whether a client secret is stored. */
  client_secret_set?: boolean;
  /** Write-only: omitted/null keeps, "" clears, a string replaces. */
  client_secret?: string | null;
  redirect_url: string;
  scopes: string[];
  username_claim: string;
  groups_claim: string;
  role_mapping: Record<SsoMappedRole, string[]>;
  default_role: SsoDefaultRole;
  allowed_email_domains: string[];
  allow_password_login: boolean;
  disable_admin_password_login: boolean;
  allow_insecure_http: boolean;
}

export interface SsoSettingsResponse {
  config: SsoConfig;
  /** Config field names set by environment variables (read-only in the UI). */
  env_overrides: string[];
  redirect_url_effective: string;
  callback_path: string;
  sso_admin_signed_in: boolean;
  admin_password_login: boolean;
  break_glass_env: boolean;
}

export interface SsoTestResult {
  ok: boolean;
  error?: string;
  issuer?: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  jwks_uri?: string;
  userinfo_endpoint?: string | null;
  end_session_endpoint?: string | null;
  scopes_supported?: string[];
  jwks_keys?: number;
  warnings?: string[];
}

// ---------------------------------------------------------------------------
// v1.4: notification channels, scheduled reports, change alerts

export type ChannelType = "webhook" | "slack" | "teams" | "email";
export type SmtpSecurity = "starttls" | "tls" | "none";
export type TeamsFormat = "adaptive" | "messagecard";

/** GET /notify/channels item: secrets are never returned, only *_set flags. */
export interface ChannelOut {
  id: string;
  name: string;
  type: ChannelType;
  enabled: boolean;
  url_set?: boolean;
  url_hint?: string;
  secret_set?: boolean;
  teams_format?: TeamsFormat;
  smtp_host?: string;
  smtp_port?: number;
  smtp_security?: SmtpSecurity;
  smtp_username?: string;
  smtp_password_set?: boolean;
  email_from?: string;
  email_to?: string[];
}

/** PUT /notify/channels item. Secret fields: omit/null = keep, "" = clear, string = replace. */
export interface ChannelIn {
  id?: string;
  name: string;
  type: ChannelType;
  enabled?: boolean;
  url?: string | null;
  secret?: string | null;
  teams_format?: TeamsFormat;
  smtp_host?: string;
  smtp_port?: number;
  smtp_security?: SmtpSecurity;
  smtp_username?: string;
  smtp_password?: string | null;
  email_from?: string;
  email_to?: string[];
}

export interface Delivery {
  channel: string;
  name?: string;
  ok: boolean;
  attempts?: number;
  error?: string | null;
}

export const WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"] as const;
export type Weekday = (typeof WEEKDAYS)[number];

export type ScheduleWhen =
  | { kind: "daily"; at: string }
  | { kind: "weekly"; weekday: Weekday; at: string }
  | { kind: "interval"; hours: number };

export interface ScheduleInput {
  name: string;
  enabled: boolean;
  when: ScheduleWhen;
  format: ReportFormat;
  title: string;
  plan_steps: number;
  channels: string[];
}

export type RunStatus = "ok" | "partial" | "failed" | "skipped";

export interface Schedule extends ScheduleInput {
  id: string;
  created_at: string;
  next_run: string | null;
  running: boolean;
  last_run: string | null;
  last_status: RunStatus | null;
  last_error: string | null;
  last_deliveries: Delivery[];
}

export interface SchedulesResponse {
  schedules: Schedule[];
  public_url: string | null;
}

export interface AlertRules {
  enabled: boolean;
  channels: string[];
  grade_worse: boolean;
  exposure_increase_points: number | null;
  new_finding_severities: Severity[];
  new_tier0_principals_min: number | null;
  choke_points_changed: boolean;
  choke_points_top: number;
  /** Object ids or names; alert when one newly reaches Tier Zero. */
  watch: string[];
}

export interface AlertPathHop {
  src: string;
  src_name: string;
  kind: string;
  dst: string;
  dst_name: string;
}

/** A principal that newly reaches Tier Zero, with a shortest path as of the snapshot. */
export interface AlertNewPath {
  objectid: string;
  name: string;
  kind: string;
  watched: boolean;
  hops: AlertPathHop[];
}

export interface AlertTrigger {
  rule: string;
  message: string;
}

export interface Alert {
  id: string;
  ts: string;
  snapshot_id: string;
  previous_snapshot_id: string | null;
  grade_before: string | null;
  grade_after: string | null;
  exposure_before: number | null;
  exposure_after: number | null;
  triggers: AlertTrigger[];
  new_findings: { id: string; title: string; severity: Severity; count: number }[];
  new_tier0_principals: number;
  new_tier0_sample: string[];
  choke_points_added: string[];
  choke_points_removed: string[];
  /** Absent on alerts from older versions. */
  new_paths?: AlertNewPath[];
  deliveries: Delivery[];
}
