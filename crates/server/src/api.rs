//! REST handlers. See docs/API.md for the contract.

use crate::audit::AuditEntry;
use crate::auth::{LoginError, Role};
use crate::state::{now_rfc3339, AppState, Job};
use axum::extract::{Multipart, Path, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use ch_engine::{shortest_path, tier0_analysis, EdgeFilter};
use ch_model::{flags, NodeKind};
use ch_store::Graph;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

pub type St = State<Arc<AppState>>;

// ------------------------------------------------------------- errors

pub struct ApiError(StatusCode, Value);

impl ApiError {
    pub fn new(code: StatusCode, msg: impl Into<String>) -> Self {
        ApiError(code, json!({ "error": msg.into() }))
    }
    pub fn raw(code: StatusCode, body: Value) -> Self {
        ApiError(code, body)
    }
    pub fn bad(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg)
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, msg)
    }
    fn no_graph() -> Self {
        Self::new(StatusCode::CONFLICT, "no graph loaded yet — upload collector data and run an ingest")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!("{e:#}");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
    }
}

type ApiResult<T = Json<Value>> = Result<T, ApiError>;

/// Run CPU-heavy work off the async runtime with read access to the graph.
async fn with_graph<T: Send + 'static>(
    st: Arc<AppState>,
    f: impl FnOnce(&Graph) -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(move || {
        let guard = st.graph.read_recursive();
        let loaded = guard.as_ref().ok_or_else(ApiError::no_graph)?;
        f(&loaded.graph)
    })
    .await
    .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

/// Like [`with_graph`], also passing the graph generation.
async fn with_graph_gen<T: Send + 'static>(
    st: Arc<AppState>,
    f: impl FnOnce(&Graph, u64) -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(move || {
        let guard = st.graph.read_recursive();
        let loaded = guard.as_ref().ok_or_else(ApiError::no_graph)?;
        f(&loaded.graph, loaded.generation)
    })
    .await
    .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

// ------------------------------------------------------------ helpers

pub fn node_json(g: &Graph, id: u32) -> Value {
    json!({
        "id": id,
        "objectid": g.oid(id),
        "name": g.name(id),
        "kind": g.kind_name(id),
        "tier0": g.has_flag(id, flags::TIER0),
        "owned": g.has_flag(id, flags::OWNED),
        "enabled": g.has_flag(id, flags::ENABLED),
    })
}

fn edge_json(g: &Graph, (s, d, k): (u32, u32, u16)) -> Value {
    json!({ "src": s, "dst": d, "kind": g.edge_kind_name(k) })
}

fn graph_result(g: &Graph, nodes: &[u32], edges: &[(u32, u32, u16)], paths: &[Vec<u32>], truncated: bool, t: Instant) -> Value {
    json!({
        "nodes": nodes.iter().map(|&n| node_json(g, n)).collect::<Vec<_>>(),
        "edges": edges.iter().map(|&e| edge_json(g, e)).collect::<Vec<_>>(),
        "paths": paths,
        "truncated": truncated,
        "elapsed_ms": t.elapsed().as_secs_f64() * 1e3,
    })
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum IdOrName {
    Id(u32),
    Name(String),
}

fn resolve(g: &Graph, x: &IdOrName) -> Result<u32, ApiError> {
    match x {
        IdOrName::Id(id) if (*id as usize) < g.node_count() => Ok(*id),
        IdOrName::Id(id) => Err(ApiError::not_found(format!("no node with id {id}"))),
        IdOrName::Name(s) => {
            if let Ok(id) = s.parse::<u32>() {
                if (id as usize) < g.node_count() {
                    return Ok(id);
                }
            }
            g.lookup(s).ok_or_else(|| ApiError::not_found(format!("no object named or identified by '{s}'")))
        }
    }
}

fn check_id(g: &Graph, id: u32) -> Result<(), ApiError> {
    if (id as usize) < g.node_count() {
        Ok(())
    } else {
        Err(ApiError::not_found(format!("no node with id {id}")))
    }
}

fn edge_filter(g: &Graph, all_edges: bool, exclude: &[String]) -> Result<EdgeFilter, ApiError> {
    let mut f = if all_edges { EdgeFilter::all(g) } else { EdgeFilter::traversable(g) };
    for k in exclude {
        f.set(g, k, false).map_err(|e| ApiError::bad(e.to_string()))?;
    }
    Ok(f)
}

// --------------------------------------------------------------- auth

fn bearer(req: &Request) -> Option<&str> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
}

pub(crate) fn client_ip(req: &Request) -> Option<String> {
    req.extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip().to_string())
}

/// Routes the upload-only role may use (besides its own account under `/me`
/// and `/logout`): uploads, ingest and job status.
pub fn uploader_may(method: &axum::http::Method, path: &str) -> bool {
    use axum::http::Method;
    // BloodHound-compatible upload API (/api/v2/file-upload…).
    if path.trim_start_matches("/api/v2").starts_with("/file-upload") {
        return true;
    }
    let p = path.strip_prefix("/api/v1").unwrap_or(path);
    if p.starts_with("/me") || p == "/logout" {
        return true;
    }
    matches!(
        (method, p),
        (&Method::POST, "/upload") | (&Method::POST, "/ingest") | (&Method::GET, "/uploads") | (&Method::GET, "/jobs") | (&Method::GET, "/jobs/{id}")
    )
}

/// Minimum role for a route (`path` is the matched route template).
pub fn required_role(method: &axum::http::Method, path: &str) -> Role {
    use axum::http::Method;
    let p = path.strip_prefix("/api/v1").unwrap_or(path);
    if p.starts_with("/users") || p.starts_with("/audit") || p.starts_with("/settings") || p.starts_with("/database") || p.starts_with("/collectors") || p.starts_with("/collect/") || p == "/backup" || p == "/restore" {
        return Role::Admin;
    }
    // Notification channels, report schedules and alert rules hold webhook
    // targets and secrets: admin only. Alert history: analysts and up.
    if p.starts_with("/notify") || p.starts_with("/schedules") || p.starts_with("/alerts/rules") {
        return Role::Admin;
    }
    if p == "/alerts" {
        return Role::Analyst;
    }
    // Ticket targets hold credentials: admin only to change or test.
    if p.starts_with("/tickets/targets") && method != Method::GET {
        return Role::Admin;
    }
    if (p == "/kind-styles" || p.ends_with("/custom-nodes")) && method != Method::GET {
        return Role::Admin;
    }
    if method == Method::DELETE && p.starts_with("/posture/") {
        return Role::Admin;
    }
    if method == Method::GET || p.starts_with("/me") || p == "/logout" {
        return Role::Viewer;
    }
    // Read-only analysis that happens to take a request body.
    const ANALYSIS: &[&str] = &[
        "/query", "/query/{id}", "/path", "/subgraph", "/nodes/resolve", "/nodes/filter", "/simulate", "/remediation-plan",
        "/zones/membership", "/report", "/remediation/commands",
    ];
    if ANALYSIS.contains(&p) {
        return Role::Viewer;
    }
    Role::Analyst
}

pub async fn require_auth(State(st): St, req: Request, next: Next) -> Response {
    let auth_header = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let signed = auth_header.starts_with(crate::hmac_auth::SCHEME);
    let (who, mut req) = if auth_header.to_ascii_lowercase().starts_with(crate::compat::BH_SCHEME) {
        match crate::compat::verify_bh_signature(&st, req).await {
            Ok(x) => x,
            Err(e) => return e.into_response(),
        }
    } else if signed {
        match crate::hmac_auth::authenticate(&st, req).await {
            Ok(x) => x,
            Err(e) => return e.into_response(),
        }
    } else {
        let Some(who) = bearer(&req).and_then(|t| st.auth.check(t)) else {
            return ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        };
        (who, req)
    };
    let method = req.method().clone();
    let template = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    // Nested routers see the path without the /api/v1 prefix; log the full one.
    let path = match req.uri().path() {
        p if p.starts_with("/api/v1") => p.to_string(),
        p => format!("/api/v1{p}"),
    };
    let ip = client_ip(&req);
    let need = required_role(&method, &template);
    let allowed = if who.role == Role::Uploader { uploader_may(&method, &template) } else { who.role >= need };
    if !allowed {
        st.audit.record(AuditEntry {
            ts: now_rfc3339(),
            user: who.username.clone(),
            role: who.role.as_str().into(),
            action: "denied".into(),
            method: method.to_string(),
            path,
            status: 403,
            ip,
            detail: Some(format!("requires {}", need.as_str())),
        });
        let msg = if who.role == Role::Uploader {
            "upload-only accounts may only upload files and start an ingest".to_string()
        } else {
            format!("this action requires the {} role", need.as_str())
        };
        return ApiError::new(StatusCode::FORBIDDEN, msg).into_response();
    }
    req.extensions_mut().insert(who.clone());
    let resp = next.run(req).await;
    if method != axum::http::Method::GET {
        let action = template.strip_prefix("/api/v1").unwrap_or(&template).to_string();
        st.audit.record(AuditEntry {
            ts: now_rfc3339(),
            user: who.username,
            role: who.role.as_str().into(),
            action: format!("{method} {action}"),
            method: method.to_string(),
            path,
            status: resp.status().as_u16(),
            ip,
            detail: if who.via_token { Some("api token".into()) } else { None },
        });
    }
    resp
}

#[derive(Deserialize)]
pub struct LoginReq {
    username: String,
    password: String,
    /// Two-factor code or recovery code, for accounts with TOTP on.
    #[serde(default)]
    otp: Option<String>,
}

pub async fn login(State(st): St, req: Request) -> ApiResult {
    let ip = client_ip(&req);
    let body = axum::body::to_bytes(req.into_body(), 64 << 10).await.map_err(|_| ApiError::bad("body too large"))?;
    let r: LoginReq = serde_json::from_slice(&body).map_err(|e| ApiError::bad(format!("invalid login request: {e}")))?;
    let st2 = st.clone();
    let (user, pass, otp) = (r.username.clone(), r.password, r.otp);
    // Argon2 is deliberately slow; keep it off the async workers.
    // Single sign-on policy may refuse password sign-in (see sso.rs).
    let res = tokio::task::spawn_blocking(move || st2.auth.login_with(&user, &pass, otp.as_deref(), |u| st2.sso.password_login_allowed(&st2.auth, u)))
        .await
        .map_err(|e| ApiError::from(anyhow::anyhow!("login task: {e}")))?;
    let entry = |action: &str, status: u16, role: &str, detail: Option<String>| AuditEntry {
        ts: now_rfc3339(),
        user: r.username.clone(),
        role: role.into(),
        action: action.into(),
        method: "POST".into(),
        path: "/api/v1/login".into(),
        status,
        ip: ip.clone(),
        detail,
    };
    match res {
        Ok((token, who)) => {
            st.audit.record(entry("login", 200, who.role.as_str(), None));
            Ok(Json(json!({ "token": token, "username": who.username, "role": who.role })))
        }
        Err(LoginError::Locked(secs)) => {
            st.audit.record(entry("login-locked", 429, "", None));
            Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                format!("too many failed attempts; try again in {secs} s"),
            ))
        }
        Err(LoginError::PasswordDisabled) => {
            st.audit.record(entry("login-failed", 403, "", Some("password sign-in disabled by SSO policy".into())));
            Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "password sign-in is disabled for this account; use single sign-on",
            ))
        }
        Err(LoginError::MfaRequired) => Err(ApiError(StatusCode::UNAUTHORIZED, json!({"error": "two-factor code required", "mfa_required": true}))),
        Err(LoginError::MfaInvalid) => {
            st.audit.record(entry("login-failed", 401, "", Some("wrong two-factor code".into())));
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            Err(ApiError(StatusCode::UNAUTHORIZED, json!({"error": "invalid two-factor code", "mfa_required": true})))
        }
        Err(LoginError::Invalid) => {
            st.audit.record(entry("login-failed", 401, "", None));
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            Err(ApiError::new(StatusCode::UNAUTHORIZED, "invalid username or password"))
        }
    }
}

pub async fn logout(State(st): St, req: Request) -> Json<Value> {
    if let Some(t) = bearer(&req) {
        st.auth.logout(t);
    }
    Json(json!({}))
}

// ------------------------------------------------------------- simple

pub const DEFAULT_QUERY_TIMEOUT_MS: u64 = 30_000;
pub const MAX_QUERY_TIMEOUT_MS: u64 = 300_000;

pub async fn health(State(st): St) -> Json<Value> {
    let (generation, snapshot_id) = st
        .graph
        .read()
        .as_ref()
        .map(|l| (l.generation, l.snapshot_id()))
        .unwrap_or((0, String::new()));
    Json(json!({
        "status": "ok",
        "graph_loaded": generation > 0,
        "generation": generation,
        "snapshot_id": snapshot_id,
        "version": env!("CARGO_PKG_VERSION"),
        "limits": {
            "max_query_limit": ch_query::MAX_LIMIT,
            "default_query_timeout_ms": DEFAULT_QUERY_TIMEOUT_MS,
            "max_query_timeout_ms": MAX_QUERY_TIMEOUT_MS,
            "upload_extensions": UPLOAD_EXTENSIONS,
            "max_upload_bytes": null,
        },
    }))
}

pub async fn stats(State(st): St) -> Json<Value> {
    let guard = st.graph.read_recursive();
    let Some(l) = guard.as_ref() else {
        return Json(json!({"nodes":0,"edges":0,"tier0":0,"owned":0,"node_kinds":{},"edge_kinds":{},"loaded_at":null,"generation":0}));
    };
    let g = &l.graph;
    let (tier0, owned) = g
        .flags_column()
        .iter()
        .fold((0u64, 0u64), |(t, o), f| (t + (f & flags::TIER0 != 0) as u64, o + (f & flags::OWNED != 0) as u64));
    let map = |v: &[(String, u64)]| v.iter().map(|(k, c)| (k.clone(), json!(c))).collect::<serde_json::Map<_, _>>();
    Json(json!({
        "nodes": g.node_count(),
        "edges": g.edge_count(),
        "tier0": tier0,
        "owned": owned,
        "node_kinds": map(&l.node_kinds),
        "edge_kinds": map(&l.edge_kinds),
        "loaded_at": humantime::format_rfc3339_seconds(l.loaded_at).to_string(),
        "generation": l.generation,
        "snapshot_id": l.snapshot_id(),
    }))
}

pub async fn edge_kinds(State(st): St) -> Json<Value> {
    let guard = st.graph.read_recursive();
    let (names, trav, counts): (Vec<String>, Vec<bool>, Vec<(String, u64)>) = match guard.as_ref() {
        Some(l) => (l.graph.meta().edge_kinds.clone(), l.graph.meta().traversable.clone(), l.edge_kinds.clone()),
        None => {
            let (n, t) = ch_model::builtin_kind_tables();
            (n, t, Vec::new())
        }
    };
    let count = |n: &str| counts.iter().find(|(k, _)| k == n).map(|c| c.1).unwrap_or(0);
    Json(Value::Array(
        names
            .into_iter()
            .zip(trav)
            .map(|(n, t)| {
                let help = ch_model::edge_help(&n)
                    .map(|h| json!({"description": h.description, "abuse": h.abuse, "remediation": h.remediation}));
                let composite = ch_ingest::postprocess::explain::is_composite(&n);
                json!({"name": n, "traversable": t, "category": ch_model::edge_category(&n), "count": count(&n), "help": help, "composite": composite})
            })
            .collect(),
    ))
}

pub async fn node_kinds(State(st): St) -> Json<Value> {
    let guard = st.graph.read_recursive();
    let counts = guard.as_ref().map(|l| l.node_kinds.clone()).unwrap_or_default();
    let custom: Vec<String> = guard.as_ref().map(|l| l.graph.custom_node_kinds().to_vec()).unwrap_or_default();
    let count = |name: &str| counts.iter().find(|(n, _)| n == name).map(|c| c.1).unwrap_or(0);
    let mut out: Vec<Value> = NodeKind::ALL
        .iter()
        .map(|k| json!({"name": k.as_str(), "category": ch_model::node_category(*k), "count": count(k.as_str())}))
        .collect();
    out.extend(custom.iter().map(|k| json!({"name": k, "category": "Custom", "count": count(k), "custom": true})));
    Json(Value::Array(out))
}

pub async fn queries() -> Json<Value> {
    Json(serde_json::to_value(ch_query::PREBUILT).unwrap_or(Value::Null))
}

// ------------------------------------------------------------- search

#[derive(Deserialize)]
pub struct SearchQ {
    q: String,
    kind: Option<String>,
    limit: Option<usize>,
}

pub async fn search(State(st): St, Query(q): Query<SearchQ>) -> ApiResult {
    with_graph(st, move |g| {
        let limit = q.limit.unwrap_or(20).min(200);
        let kind = q.kind.as_deref().and_then(|k| g.raw_kind_of(k)).filter(|&k| k != NodeKind::Unknown as u8);
        // Exact name / objectid, then prefix matches, then substring matches
        // (each by name length, then name); case-insensitive. Substring
        // matches need the property columns, which load in the background
        // after a graph is installed; until then this is prefix-only.
        let ids = g.search_raw(&q.q, kind, limit);
        Ok(Json(Value::Array(ids.iter().map(|&i| node_json(g, i)).collect())))
    })
    .await
}

// ------------------------------------------------------- node filtering

#[derive(Deserialize)]
pub struct FilterReq {
    filter: ch_store::Filter,
    limit: Option<usize>,
    offset: Option<usize>,
}

/// Maximum nodes returned by one `/nodes/filter` page.
pub const MAX_FILTER_PAGE: usize = 10_000;

/// Nodes matching a property filter, in id order, paged.
pub async fn filter_nodes(State(st): St, Json(r): Json<FilterReq>) -> ApiResult {
    with_graph(st, move |g| {
        let t = Instant::now();
        let hits = g.filter(&r.filter);
        let filter_ms = t.elapsed().as_secs_f64() * 1e3;
        let limit = r.limit.unwrap_or(100).min(MAX_FILTER_PAGE);
        let offset = r.offset.unwrap_or(0);
        let nodes: Vec<Value> = hits.iter().skip(offset).take(limit).map(|i| node_json(g, i)).collect();
        Ok(Json(json!({
            "total": hits.len(),
            "offset": offset,
            "nodes": nodes,
            "filter_ms": filter_ms,
            "elapsed_ms": t.elapsed().as_secs_f64() * 1e3,
        })))
    })
    .await
}

/// Property columns of the loaded graph (`null` while they are being built).
pub async fn columns(State(st): St) -> ApiResult {
    with_graph(st, move |g| {
        Ok(Json(match g.columns_ready() {
            None => json!({ "ready": false }),
            Some(c) => json!({ "ready": true, "origin": c.origin, "complete": c.complete(), "columns": c.info() }),
        }))
    })
    .await
}

// -------------------------------------------------------------- nodes

pub async fn node(State(st): St, Path(id): Path<u32>) -> ApiResult {
    with_graph(st, move |g| {
        check_id(g, id)?;
        let mut v = node_json(g, id);
        let props: Value = serde_json::from_str(g.props(id)).unwrap_or_else(|_| json!({}));
        let f = g.flags(id);
        let flag_names: Vec<&str> = [
            (flags::ENABLED, "enabled"),
            (flags::TIER0, "tier0"),
            (flags::OWNED, "owned"),
            (flags::ADMINCOUNT, "admincount"),
            (flags::HIGHVALUE, "highvalue"),
            (flags::UNCONSTRAINED_DELEGATION, "unconstraineddelegation"),
            (flags::DONT_REQ_PREAUTH, "dontreqpreauth"),
            (flags::HAS_SPN, "hasspn"),
        ]
        .into_iter()
        .filter(|(b, _)| f & b != 0)
        .map(|(_, n)| n)
        .collect();
        let count = |kinds: &[u16]| {
            let mut m = serde_json::Map::new();
            let mut c = vec![0u64; g.edge_kind_count()];
            for &k in kinds {
                c[k as usize] += 1;
            }
            for (k, n) in c.into_iter().enumerate().filter(|(_, n)| *n > 0) {
                m.insert(g.edge_kind_name(k as u16).to_string(), json!(n));
            }
            Value::Object(m)
        };
        let o = v.as_object_mut().expect("object");
        o.insert("properties".into(), props);
        o.insert("flags".into(), json!(flag_names));
        o.insert("in_degree".into(), json!(g.in_degree(id)));
        o.insert("out_degree".into(), json!(g.out_degree(id)));
        o.insert("edge_counts".into(), json!({ "out": count(g.out_edges(id).1), "in": count(g.in_edges(id).1) }));
        Ok(Json(v))
    })
    .await
}

#[derive(Deserialize)]
pub struct EdgesQ {
    dir: Option<String>,
    kind: Option<String>,
    limit: Option<usize>,
}

pub async fn node_edges(State(st): St, Path(id): Path<u32>, Query(q): Query<EdgesQ>) -> ApiResult {
    with_graph(st, move |g| {
        let t = Instant::now();
        check_id(g, id)?;
        let limit = q.limit.unwrap_or(500).min(20_000);
        let out = match q.dir.as_deref().unwrap_or("out") {
            "out" => true,
            "in" => false,
            d => return Err(ApiError::bad(format!("dir must be 'in' or 'out', got '{d}'"))),
        };
        let kind = match &q.kind {
            Some(k) => Some(g.edge_kind_id(k).ok_or_else(|| ApiError::bad(format!("unknown edge kind '{k}'")))?),
            None => None,
        };
        let (ns, ks) = if out { g.out_edges(id) } else { g.in_edges(id) };
        let mut nodes = vec![id];
        let mut edges = Vec::new();
        let mut truncated = false;
        for (&n, &k) in ns.iter().zip(ks) {
            if kind.is_some_and(|x| x != k) {
                continue;
            }
            if edges.len() >= limit {
                truncated = true;
                break;
            }
            nodes.push(n);
            edges.push(if out { (id, n, k) } else { (n, id, k) });
        }
        nodes.sort_unstable();
        nodes.dedup();
        Ok(Json(graph_result(g, &nodes, &edges, &[], truncated, t)))
    })
    .await
}

#[derive(Deserialize)]
pub struct MarksReq {
    owned: Option<bool>,
    tier0: Option<bool>,
}

pub async fn mark(State(st): St, Path(id): Path<u32>, Json(r): Json<MarksReq>) -> ApiResult {
    let tier0_changed = r.tier0.is_some();
    let st2 = st.clone();
    let res = tokio::task::spawn_blocking(move || -> ApiResult {
        let mut guard = st2.graph.write();
        let loaded = guard.as_mut().ok_or_else(ApiError::no_graph)?;
        let g = &mut loaded.graph;
        check_id(g, id)?;
        let oid = g.oid(id).to_string();
        let ingest_t0 = {
            let mut base = st2.ingest_tier0.write();
            *base.entry(id).or_insert(g.has_flag(id, flags::TIER0))
        };
        if let Some(o) = r.owned {
            g.set_flag(id, flags::OWNED, o);
        }
        if let Some(t) = r.tier0 {
            g.set_flag(id, flags::TIER0, t);
            loaded.tier0_cache = None;
        }
        let mut marks = st2.marks.lock();
        marks.mark(&oid, r.owned, r.tier0, ingest_t0);
        marks.save(&st2.marks_path())?;
        Ok(Json(node_json(&loaded.graph, id)))
    })
    .await
    .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if tier0_changed && res.is_ok() {
        // Findings depend on Tier Zero membership; recompute (no new posture snapshot).
        crate::analysis::start_analysis(&st, false);
    }
    res
}

// --------------------------------------------------------------- path

#[derive(Deserialize)]
pub struct PathReq {
    from: IdOrName,
    to: Option<IdOrName>,
    #[serde(default)]
    to_tier0: bool,
    /// Target the nearest member of this zone (overrides `to` / `to_tier0`).
    to_zone: Option<String>,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    all_edges: bool,
    /// Return every shortest path (as one subgraph) instead of one.
    #[serde(default)]
    all: bool,
}

/// Edges drawn at most for `all: true`.
const ALL_PATHS_MAX_EDGES: usize = 2000;

pub async fn path(State(st): St, Json(r): Json<PathReq>) -> ApiResult {
    let st2 = st.clone();
    with_graph_gen(st, move |g, generation| {
        let t = Instant::now();
        let unified = st2.settings.lock().analysis.unified_tier0;
        let f = edge_filter(g, r.all_edges, &r.exclude)?.unified_tier0(unified);
        let src = resolve(g, &r.from)?;
        let targets = if let Some(zone) = &r.to_zone {
            crate::analysis::zone_members(&st2, g, generation, zone)?.iter().copied().filter(|&x| x != src).collect()
        } else if r.to_tier0 {
            g.nodes_with_flag(flags::TIER0).into_iter().filter(|&x| x != src).collect()
        } else {
            let to = r.to.as_ref().ok_or_else(|| ApiError::bad("'to' is required unless to_tier0 is set"))?;
            vec![resolve(g, to)?]
        };
        if r.all {
            let mut v = match ch_engine::all_shortest_paths(g, &[src], &targets, &f, ALL_PATHS_MAX_EDGES) {
                Some(a) => {
                    let one_edges: Vec<_> = a.one.nodes.windows(2).zip(&a.one.kinds).map(|(w, &k)| (w[0], w[1], k)).collect();
                    let mut v = graph_result(g, &a.nodes, &a.edges, std::slice::from_ref(&a.one.nodes), a.truncated, t);
                    v["hops"] = Value::Array(one_edges.iter().map(|&e| edge_json(g, e)).collect());
                    v["all_paths"] = json!({"length": a.length, "edges": a.edges.len(), "nodes": a.nodes.len(), "truncated": a.truncated});
                    v
                }
                None => {
                    let mut v = graph_result(g, &[], &[], &[], false, t);
                    v["hops"] = json!([]);
                    v
                }
            };
            v["generation"] = json!(generation);
            return Ok(Json(v));
        }
        let mut v = match shortest_path(g, &[src], &targets, &f) {
            Some(p) => {
                let edges: Vec<_> = p.nodes.windows(2).zip(&p.kinds).map(|(w, &k)| (w[0], w[1], k)).collect();
                let mut v = graph_result(g, &p.nodes, &edges, std::slice::from_ref(&p.nodes), false, t);
                v["hops"] = Value::Array(edges.iter().map(|&e| edge_json(g, e)).collect());
                v
            }
            None => {
                let mut v = graph_result(g, &[], &[], &[], false, t);
                v["hops"] = json!([]);
                v
            }
        };
        v["generation"] = json!(generation);
        Ok(Json(v))
    })
    .await
}

// -------------------------------------------------------------- tier0

#[derive(Deserialize)]
pub struct Tier0Q {
    top: Option<usize>,
}

pub async fn tier0(State(st): St, Query(q): Query<Tier0Q>) -> ApiResult {
    let top = q.top.unwrap_or(25).min(1000);
    let st2 = st.clone();
    tokio::task::spawn_blocking(move || -> ApiResult {
        // Fast path: cached report with enough choke points.
        {
            let guard = st2.graph.read_recursive();
            let l = guard.as_ref().ok_or_else(ApiError::no_graph)?;
            if let Some((k, rep, ms)) = &l.tier0_cache {
                if *k >= top {
                    return Ok(Json(tier0_json(&l.graph, rep, top, *ms)));
                }
            }
        }
        let t = Instant::now();
        let (rep, ms) = {
            let guard = st2.graph.read_recursive();
            let g = &guard.as_ref().ok_or_else(ApiError::no_graph)?.graph;
            let f = EdgeFilter::traversable(g).unified_tier0(st2.settings.lock().analysis.unified_tier0);
            (tier0_analysis(g, &f, top.max(25)), t.elapsed().as_secs_f64() * 1e3)
        };
        let mut guard = st2.graph.write();
        let l = guard.as_mut().ok_or_else(ApiError::no_graph)?;
        let out = tier0_json(&l.graph, &rep, top, ms);
        l.tier0_cache = Some((top.max(25), rep, ms));
        Ok(Json(out))
    })
    .await
    .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

pub fn tier0_json(g: &Graph, r: &ch_engine::Tier0Report, top: usize, ms: f64) -> Value {
    json!({
        "tier0_nodes": r.tier0_nodes,
        "max_depth": r.max_depth,
        "exposed_principals": r.exposed_principals,
        "total_principals": r.total_principals,
        "exposure": r.exposure,
        "choke_points": r.choke_points.iter().take(top).map(|c| json!({
            "src": node_json(g, c.src), "dst": node_json(g, c.dst),
            "kind": g.edge_kind_name(c.kind), "flow": c.flow,
        })).collect::<Vec<_>>(),
        "elapsed_ms": ms,
    })
}

// -------------------------------------------------------------- query

#[derive(Deserialize)]
pub struct QueryReq {
    query: String,
    limit: Option<usize>,
    timeout_ms: Option<u64>,
    query_id: Option<String>,
}

/// Ordered hops for each path, picking the result edge for each consecutive pair.
fn path_hops(g: &Graph, paths: &[Vec<u32>], edges: &[(u32, u32, u16)]) -> Value {
    let mut by_pair: ahash::AHashMap<(u32, u32), u16> = ahash::AHashMap::new();
    for &(s, d, k) in edges {
        by_pair.entry((s, d)).or_insert(k);
    }
    Value::Array(
        paths
            .iter()
            .map(|p| {
                Value::Array(
                    p.windows(2)
                        .map(|w| {
                            // Paths follow pattern direction; an `<-` hop is stored reversed.
                            match (by_pair.get(&(w[0], w[1])), by_pair.get(&(w[1], w[0]))) {
                                (Some(&k), _) => edge_json(g, (w[0], w[1], k)),
                                (None, Some(&k)) => edge_json(g, (w[1], w[0], k)),
                                _ => json!({"src": w[0], "dst": w[1], "kind": null}),
                            }
                        })
                        .collect(),
                )
            })
            .collect(),
    )
}

/// Removes a query from the running registry when the request ends.
struct RunningGuard(Arc<AppState>, Option<String>);
impl Drop for RunningGuard {
    fn drop(&mut self) {
        if let Some(id) = &self.1 {
            self.0.running.lock().remove(id);
        }
    }
}

pub async fn query(State(st): St, Json(r): Json<QueryReq>) -> ApiResult {
    if r.query_id.as_ref().is_some_and(|id| id.is_empty() || id.len() > 64) {
        return Err(ApiError::bad("query_id must be 1-64 characters"));
    }
    let timeout = r.timeout_ms.unwrap_or(DEFAULT_QUERY_TIMEOUT_MS).clamp(1, MAX_QUERY_TIMEOUT_MS);
    let cancel = ch_query::Cancel::new(Some(std::time::Duration::from_millis(timeout)));
    if let Some(id) = &r.query_id {
        st.running.lock().insert(id.clone(), cancel.clone());
    }
    let guard = RunningGuard(st.clone(), r.query_id.clone());
    let res = with_graph_gen(st, move |g, generation| {
        let t = Instant::now();
        let res = ch_query::run_with(g, &r.query, r.limit.unwrap_or(1000), &cancel).map_err(|e| {
            let status = match e.code {
                "timeout" => StatusCode::REQUEST_TIMEOUT,
                "cancelled" => StatusCode::CONFLICT,
                _ => StatusCode::BAD_REQUEST,
            };
            ApiError(status, json!({ "error": e.message, "position": e.position, "code": e.code }))
        })?;
        let mut v = graph_result(g, &res.nodes, &res.edges, &res.paths, res.truncated, Instant::now());
        let o = v.as_object_mut().expect("object");
        if !res.columns.is_empty() {
            o.insert("columns".into(), json!(res.columns));
            o.insert("rows".into(), json!(res.rows));
        }
        if !res.paths.is_empty() {
            o.insert("path_hops".into(), path_hops(g, &res.paths, &res.edges));
        }
        o.insert("elapsed_ms".into(), json!(t.elapsed().as_secs_f64() * 1e3));
        o.insert("generation".into(), json!(generation));
        Ok(Json(v))
    })
    .await;
    drop(guard);
    res
}

#[derive(Deserialize)]
pub struct ResolveReq {
    objectids: Vec<String>,
}

/// Bulk objectid → Node (unknown ids omitted; max 5000).
pub async fn resolve_nodes(State(st): St, Json(r): Json<ResolveReq>) -> ApiResult {
    with_graph(st, move |g| {
        Ok(Json(Value::Array(
            r.objectids.iter().take(5000).filter_map(|o| g.lookup(o)).map(|id| node_json(g, id)).collect(),
        )))
    })
    .await
}

#[derive(Deserialize)]
pub struct CompositionQ {
    src: u32,
    dst: u32,
    kind: String,
}

/// Why a derived edge exists: the collected edges and facts it was built from
/// (`ch_ingest::postprocess::explain`). GraphResult plus `edge`, `notes` and
/// `complete`.
pub async fn edge_composition(State(st): St, Query(q): Query<CompositionQ>) -> ApiResult {
    with_graph_gen(st, move |g, generation| {
        let t = Instant::now();
        if !ch_ingest::postprocess::explain::is_composite(&q.kind) {
            return Err(ApiError::bad(format!("{} is not a derived edge kind", q.kind)));
        }
        let k = g.edge_kind_id(&q.kind).ok_or_else(|| ApiError::not_found("edge not found"))?;
        let c = ch_ingest::postprocess::explain::compose(g, q.src, q.dst, k).ok_or_else(|| ApiError::not_found("edge not found"))?;
        let mut v = graph_result(g, &c.nodes, &c.edges, &[], false, t);
        v["edge"] = edge_json(g, (q.src, q.dst, k));
        v["notes"] = json!(c.notes);
        v["complete"] = json!(c.complete);
        v["generation"] = json!(generation);
        Ok(Json(v))
    })
    .await
}

#[derive(Deserialize)]
pub struct SubgraphReq {
    ids: Vec<u32>,
}

/// The given nodes plus every edge (any kind) among them. Max 5000 ids.
pub async fn subgraph(State(st): St, Json(r): Json<SubgraphReq>) -> ApiResult {
    with_graph_gen(st, move |g, generation| {
        let t = Instant::now();
        let mut ids: Vec<u32> = r.ids.into_iter().filter(|&i| (i as usize) < g.node_count()).take(5000).collect();
        ids.sort_unstable();
        ids.dedup();
        let set: ahash::AHashSet<u32> = ids.iter().copied().collect();
        let mut edges = Vec::new();
        for &u in &ids {
            let (ds, ks) = g.out_edges(u);
            for (&v, &k) in ds.iter().zip(ks) {
                if set.contains(&v) {
                    edges.push((u, v, k));
                }
            }
        }
        let mut v = graph_result(g, &ids, &edges, &[], false, t);
        v["generation"] = json!(generation);
        Ok(Json(v))
    })
    .await
}

pub async fn cancel_query(State(st): St, Path(id): Path<String>) -> Json<Value> {
    let found = st.running.lock().get(&id).cloned();
    if let Some(c) = &found {
        c.cancel();
    }
    Json(json!({ "cancelled": found.is_some() }))
}

// ------------------------------------------------------------ batch nodes

#[derive(Deserialize)]
pub struct NodesQ {
    ids: String,
}

pub async fn nodes_batch(State(st): St, Query(q): Query<NodesQ>) -> ApiResult {
    with_graph(st, move |g| {
        let ids: Vec<u32> = q
            .ids
            .split(',')
            .filter_map(|s| s.trim().parse::<u32>().ok())
            .filter(|&id| (id as usize) < g.node_count())
            .take(5000)
            .collect();
        Ok(Json(Value::Array(ids.iter().map(|&i| node_json(g, i)).collect())))
    })
    .await
}

// ---------------------------------------------------------- saved queries

#[derive(Deserialize)]
pub struct SavedReq {
    name: String,
    category: Option<String>,
    description: Option<String>,
    query: String,
}

fn validate_saved(r: &SavedReq) -> Result<(), ApiError> {
    if r.name.trim().is_empty() || r.name.len() > 200 {
        return Err(ApiError::bad("name must be 1-200 characters"));
    }
    if r.query.len() > 20_000 {
        return Err(ApiError::bad("query is too long"));
    }
    ch_query::parse_syntax(&r.query).map_err(|e| {
        ApiError(StatusCode::BAD_REQUEST, json!({ "error": e.message, "position": e.position, "code": e.code }))
    })?;
    Ok(())
}

pub async fn list_saved(State(st): St) -> Json<Value> {
    Json(serde_json::to_value(&*st.saved.lock()).unwrap_or(Value::Null))
}

pub async fn create_saved(State(st): St, Json(r): Json<SavedReq>) -> ApiResult {
    validate_saved(&r)?;
    let now = now_rfc3339();
    let item = crate::state::SavedQuery {
        id: format!("q-{}", crate::auth::random_hex(8)),
        name: r.name.trim().to_string(),
        category: r.category.filter(|c| !c.trim().is_empty()).unwrap_or_else(|| "Custom".into()),
        description: r.description.unwrap_or_default(),
        query: r.query,
        created_at: now.clone(),
        updated_at: now,
    };
    let mut saved = st.saved.lock();
    saved.push(item.clone());
    crate::state::store_saved(&st.saved_path(), &saved)?;
    Ok(Json(serde_json::to_value(item).unwrap_or(Value::Null)))
}

pub async fn update_saved(State(st): St, Path(id): Path<String>, Json(r): Json<SavedReq>) -> ApiResult {
    validate_saved(&r)?;
    let mut saved = st.saved.lock();
    let item = saved.iter_mut().find(|s| s.id == id).ok_or_else(|| ApiError::not_found(format!("no saved query '{id}'")))?;
    item.name = r.name.trim().to_string();
    item.category = r.category.filter(|c| !c.trim().is_empty()).unwrap_or_else(|| "Custom".into());
    item.description = r.description.unwrap_or_default();
    item.query = r.query;
    item.updated_at = now_rfc3339();
    let out = serde_json::to_value(&*item).unwrap_or(Value::Null);
    crate::state::store_saved(&st.saved_path(), &saved)?;
    Ok(Json(out))
}

pub async fn delete_saved(State(st): St, Path(id): Path<String>) -> ApiResult {
    let mut saved = st.saved.lock();
    let before = saved.len();
    saved.retain(|s| s.id != id);
    if saved.len() == before {
        return Err(ApiError::not_found(format!("no saved query '{id}'")));
    }
    crate::state::store_saved(&st.saved_path(), &saved)?;
    Ok(Json(json!({})))
}

// ------------------------------------------------------------ uploads

/// Accepted upload extensions: collector JSON / zips, LDIF (ldapsearch,
/// ldifde, gzip) and AD Explorer snapshots.
pub const UPLOAD_EXTENSIONS: &[&str] = &[".json", ".zip", ".ldif", ".ldf", ".ldif.gz", ".dat"];

/// Keep only a safe base file name with an accepted extension.
pub fn sanitize_upload_name(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next()?.trim();
    let clean: String = base
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
        .collect();
    let lower = clean.to_ascii_lowercase();
    let ok = UPLOAD_EXTENSIONS.iter().any(|x| lower.ends_with(x)) && !clean.starts_with('.') && clean.len() <= 200;
    ok.then_some(clean)
}

pub async fn upload(State(st): St, axum::Extension(who): axum::Extension<crate::auth::Principal>, mut mp: Multipart) -> ApiResult {
    use tokio::io::AsyncWriteExt;
    let dir = st.uploads_dir();
    let mut saved = Vec::new();
    while let Some(mut field) = mp.next_field().await.map_err(|e| ApiError::bad(e.to_string()))? {
        let Some(raw) = field.file_name().map(str::to_string) else { continue };
        let name = sanitize_upload_name(&raw)
            .ok_or_else(|| {
                ApiError::bad(format!("'{raw}': accepted files are {}", UPLOAD_EXTENSIONS.join(", ")))
            })?;
        let tmp = dir.join(format!(".{name}.part"));
        let mut f = tokio::fs::File::create(&tmp).await.map_err(|e| anyhow::anyhow!(e))?;
        while let Some(chunk) = field.chunk().await.map_err(|e| ApiError::bad(e.to_string()))? {
            f.write_all(&chunk).await.map_err(|e| anyhow::anyhow!(e))?;
        }
        f.flush().await.map_err(|e| anyhow::anyhow!(e))?;
        drop(f);
        tokio::fs::rename(&tmp, dir.join(&name)).await.map_err(|e| anyhow::anyhow!(e))?;
        saved.push(name);
    }
    if saved.is_empty() {
        return Err(ApiError::bad("no files in upload (multipart field 'files')"));
    }
    crate::collectors::record_upload(&st, &who.username, &saved);
    Ok(Json(json!({ "uploaded": saved })))
}

/// The `ingest` provenance object of the loaded graph's `meta.json`.
fn ingest_meta(st: &AppState) -> Option<Value> {
    st.graph.read_recursive().as_ref().and_then(|l| l.graph.meta().ingest.clone())
}

/// `GET /sources`: merge policy, counters and the source manifest of the
/// loaded graph (`null` fields for graphs built before provenance existed).
pub async fn sources(State(st): St) -> Json<Value> {
    let m = ingest_meta(&st);
    let generation = st.graph.read_recursive().as_ref().map_or(0, |l| l.generation);
    let get = |k: &str| m.as_ref().and_then(|m| m.get(k)).cloned().unwrap_or(Value::Null);
    Json(json!({
        "generation": generation,
        "merge_policy": get("merge_policy"),
        "superseded_objects": get("superseded_objects"),
        "superseded_edges": get("superseded_edges"),
        "sources": m.as_ref().and_then(|m| m.get("sources")).cloned().unwrap_or_else(|| json!([])),
    }))
}

pub async fn list_uploads(State(st): St) -> ApiResult {
    // Sources of the loaded graph by top-level upload file.
    let mut by_file: std::collections::HashMap<String, Vec<Value>> = std::collections::HashMap::new();
    if let Some(Value::Array(srcs)) = ingest_meta(&st).and_then(|m| m.get("sources").cloned()) {
        for s in srcs {
            if let Some(f) = s.get("file").and_then(Value::as_str) {
                by_file.entry(f.to_string()).or_default().push(s);
            }
        }
    }
    let mut out = Vec::new();
    let mut rd = tokio::fs::read_dir(st.uploads_dir()).await.map_err(|e| anyhow::anyhow!(e))?;
    while let Some(e) = rd.next_entry().await.map_err(|e| anyhow::anyhow!(e))? {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let md = e.metadata().await.map_err(|e| anyhow::anyhow!(e))?;
        if !md.is_file() {
            continue;
        }
        let at = md.modified().map(|t| humantime::format_rfc3339_seconds(t).to_string()).ok();
        let sources = by_file.remove(&name);
        out.push(json!({
            "name": name,
            "size": md.len(),
            "uploaded_at": at,
            "in_graph": sources.is_some(),
            "sources": sources.unwrap_or_default(),
        }));
    }
    out.sort_by(|a, b| b["uploaded_at"].as_str().cmp(&a["uploaded_at"].as_str()));
    Ok(Json(Value::Array(out)))
}

pub async fn delete_upload(State(st): St, Path(name): Path<String>) -> ApiResult {
    let clean = sanitize_upload_name(&name).filter(|c| *c == name).ok_or_else(|| ApiError::bad("invalid upload name"))?;
    let path = st.uploads_dir().join(clean);
    tokio::fs::remove_file(&path).await.map_err(|_| ApiError::not_found(format!("no upload named '{name}'")))?;
    Ok(Json(json!({})))
}

// --------------------------------------------------------------- jobs

pub async fn start_ingest(State(st): St) -> ApiResult {
    let id = queue_ingest(&st, "manual")?;
    Ok(Json(json!({ "job_id": id })))
}

/// Queue an ingest of everything in the uploads directory.
pub fn queue_ingest(st: &Arc<AppState>, trigger: &str) -> Result<String, ApiError> {
    let id = {
        let mut jobs = st.jobs.lock();
        if jobs.iter().any(|j| j.state == "queued" || j.state == "running") {
            return Err(ApiError::new(StatusCode::CONFLICT, "an ingest job is already running"));
        }
        let mut seq = st.job_seq.lock();
        *seq += 1;
        let id = format!("j-{}", *seq);
        jobs.insert(
            0,
            Job {
                id: id.clone(),
                state: "queued",
                phase: "queued",
                percent: 0,
                created_at: now_rfc3339(),
                started_at: None,
                finished_at: None,
                message: "queued".into(),
                report: None,
                trigger: trigger.to_string(),
            },
        );
        jobs.truncate(50);
        id
    };
    let st2 = st.clone();
    let job_id = id.clone();
    std::thread::spawn(move || run_ingest_job(st2, job_id));
    Ok(id)
}

fn update_job(st: &AppState, id: &str, f: impl FnOnce(&mut Job)) {
    if let Some(j) = st.jobs.lock().iter_mut().find(|j| j.id == id) {
        f(j);
    }
}

fn run_ingest_job(st: Arc<AppState>, id: String) {
    update_job(&st, &id, |j| {
        j.state = "running";
        j.started_at = Some(now_rfc3339());
        j.message = "parsing collector files".into();
    });
    let t = Instant::now();
    let progress = |phase: &'static str, percent: u8| {
        update_job(&st, &id, |j| {
            j.phase = phase;
            j.percent = percent.min(99);
            j.message = format!("{phase}…");
        })
    };
    let result = (|| -> anyhow::Result<Value> {
        let opts = st.settings.lock().ingest.options();
        let built = ch_ingest::build_graph_with_progress(&[st.uploads_dir()], &opts, &progress)?;
        progress("writing", 88);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let dir: PathBuf = st.graphs_dir().join(format!("g-{stamp:015}"));
        built.graph.write(&dir)?;
        let nodes = built.graph.node_count();
        let edges = built.graph.edge_count();
        drop(built.graph);
        progress("loading", 96);
        let g = Graph::open(&dir)?;
        st.install(g, dir);
        crate::state::warm_columns(&st);
        crate::analysis::start_analysis(&st, true);
        Ok(json!({
            "files": built.ingest.files,
            "records": built.ingest.records,
            "nodes": nodes,
            "edges": edges,
            "parse_errors": built.ingest.parse_errors,
            "first_error": built.ingest.first_error,
            "derived": built.post.passes,
            "merge_policy": built.ingest.merge_policy,
            "superseded_objects": built.ingest.superseded_objects,
            "superseded_edges": built.ingest.superseded_edges,
            "sources": built.ingest.sources.len(),
            "seconds": t.elapsed().as_secs_f64(),
        }))
    })();
    update_job(&st, &id, |j| {
        j.finished_at = Some(now_rfc3339());
        match result {
            Ok(rep) => {
                j.state = "done";
                j.phase = "done";
                j.percent = 100;
                j.message = format!(
                    "ingested {} nodes / {} edges in {:.1}s",
                    rep["nodes"], rep["edges"], rep["seconds"].as_f64().unwrap_or(0.0)
                );
                j.report = Some(rep);
            }
            Err(e) => {
                j.state = "failed";
                j.phase = "failed";
                j.message = format!("{e:#}");
            }
        }
    });
}

pub async fn jobs(State(st): St) -> Json<Value> {
    Json(serde_json::to_value(&*st.jobs.lock()).unwrap_or(Value::Null))
}

pub async fn job(State(st): St, Path(id): Path<String>) -> ApiResult {
    st.jobs
        .lock()
        .iter()
        .find(|j| j.id == id)
        .map(|j| Json(serde_json::to_value(j).unwrap_or(Value::Null)))
        .ok_or_else(|| ApiError::not_found(format!("no job '{id}'")))
}
