//! v1.2: background analysis (findings + posture), zones, simulation and
//! remediation planning endpoints.

use crate::api::{node_json, ApiError, St};
use crate::state::{now_rfc3339, store_json, load_json, Analysis, AnalysisResult, AppState, ZoneDef};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use ch_analysis::findings::{baseline, evaluate_one, sort_results, FindingResult, Items, CATALOG};
use ch_analysis::posture::{diff, snapshot_items, Snapshot, SnapshotItems};
use ch_analysis::simulate::{exposure_with, fix_costs, plan, simulate, PlanOptions};
use ch_analysis::Removal;
use ch_model::flags;
use ch_store::Graph;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

pub const TIER0_ZONE: &str = "tier0";

// ------------------------------------------------------------ background

/// Compute findings for the current graph; with `record_posture`, append a
/// posture snapshot (once per snapshot id) and store finding items for diffs.
pub fn start_analysis(st: &Arc<AppState>, record_posture: bool) {
    let Some(generation) = st.graph.read_recursive().as_ref().map(|l| l.generation) else { return };
    *st.analysis.write() = Analysis::Computing { generation, progress: 0 };
    let st = st.clone();
    std::thread::spawn(move || {
        let t = Instant::now();
        // Hold the graph read lock per step only, so marks / installs (writers)
        // never wait for the whole analysis.
        let current = |st: &AppState| -> bool { st.graph.read_recursive().as_ref().is_some_and(|l| l.generation == generation) };
        let (snapshot_id, tier0, base) = {
            let guard = st.graph.read_recursive();
            let Some(l) = guard.as_ref().filter(|l| l.generation == generation) else { return };
            let tier0 = l.graph.nodes_with_flag(flags::TIER0);
            let base = baseline(&l.graph, &tier0);
            (l.snapshot_id(), tier0, base)
        };
        let cancel = ch_query::Cancel::never();
        let mut findings = Vec::new();
        for (i, def) in CATALOG.iter().enumerate() {
            {
                let mut a = st.analysis.write();
                if let Analysis::Computing { generation: gen, progress } = &mut *a {
                    if *gen == generation {
                        *progress = (90 * i / CATALOG.len()) as u8;
                    }
                }
            }
            let guard = st.graph.read_recursive();
            let Some(l) = guard.as_ref().filter(|l| l.generation == generation) else { return };
            findings.extend(evaluate_one(&l.graph, def, &tier0, base, &cancel));
        }
        sort_results(&mut findings);
        let mut new_snapshot = false;
        if record_posture && current(&st) {
            let guard = st.graph.read_recursive();
            if let Some(l) = guard.as_ref().filter(|l| l.generation == generation) {
                match record(&st, &l.graph, &snapshot_id, &tier0, &findings) {
                    Ok(new) => new_snapshot = new,
                    Err(e) => tracing::warn!("posture snapshot failed: {e:#}"),
                }
            }
        }
        let result =
            Arc::new(AnalysisResult { generation, snapshot_id, computed_ms: t.elapsed().as_secs_f64() * 1e3, findings });
        {
            let mut a = st.analysis.write();
            // A newer graph may have been installed meanwhile; keep only current results.
            if matches!(&*a, Analysis::Computing { generation: gen, .. } if *gen == generation) {
                *a = Analysis::Ready(result.clone());
            }
        }
        tracing::info!("analysis ready in {:.0} ms", t.elapsed().as_secs_f64() * 1e3);
        // Change alerts: once per new posture snapshot (i.e. after each ingest).
        if new_snapshot {
            let guard = st.graph.read_recursive();
            if let Some(l) = guard.as_ref().filter(|l| l.generation == generation) {
                crate::alerts::after_snapshot(&st, &l.graph, &result.snapshot_id, &tier0, &result.findings);
            }
        }
    });
}

fn severity_counts(findings: &[FindingResult]) -> BTreeMap<String, u64> {
    let mut m: BTreeMap<String, u64> = ["critical", "high", "medium", "low"].iter().map(|s| (s.to_string(), 0)).collect();
    for f in findings {
        let s = serde_json::to_value(f.def.severity).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
        *m.entry(s).or_default() += 1;
    }
    m
}

/// Append a posture snapshot; `Ok(false)` if `snapshot_id` was already recorded.
fn record(st: &AppState, g: &Graph, snapshot_id: &str, tier0: &[u32], findings: &[FindingResult]) -> anyhow::Result<bool> {
    let mut history: Vec<Snapshot> = load_json(&st.posture_path());
    if history.iter().any(|s| s.snapshot_id == snapshot_id) {
        return Ok(false);
    }
    let rep = exposure_with(g, tier0, &Removal::default(), 0);
    history.push(Snapshot {
        snapshot_id: snapshot_id.to_string(),
        created_at: now_rfc3339(),
        nodes: g.node_count() as u64,
        edges: g.edge_count() as u64,
        tier0: tier0.len() as u64,
        exposed_principals: rep.exposed_principals,
        total_principals: rep.total_principals,
        exposure_percent: if rep.total_principals == 0 { 0.0 } else { 100.0 * rep.exposed_principals as f64 / rep.total_principals as f64 },
        findings: severity_counts(findings),
        finding_counts: findings.iter().map(|f| (f.def.id.to_string(), f.items.len() as u64)).collect(),
    });
    store_json(&st.snapshot_items_path(snapshot_id), &snapshot_items(g, findings))?;
    store_json(&st.posture_path(), &history)?;
    Ok(true)
}

/// Finished analysis for the currently loaded graph, if any.
pub fn current_analysis(st: &AppState) -> Option<Arc<AnalysisResult>> {
    let gen = st.graph.read_recursive().as_ref().map(|l| l.generation)?;
    match &*st.analysis.read() {
        Analysis::Ready(r) if r.generation == gen => Some(r.clone()),
        _ => None,
    }
}

/// `202 {"status":"computing"}` until analysis for the current graph is ready.
#[allow(clippy::result_large_err)] // the error is the HTTP response itself
fn ready(st: &AppState) -> Result<Arc<AnalysisResult>, Response> {
    let gen = st.graph.read_recursive().as_ref().map(|l| l.generation);
    match (&*st.analysis.read(), gen) {
        (_, None) => Err(ApiError::new(StatusCode::CONFLICT, "no graph loaded yet").into_response()),
        (Analysis::Ready(r), Some(g)) if r.generation == g => Ok(r.clone()),
        (Analysis::Computing { progress, .. }, _) => {
            Err((StatusCode::ACCEPTED, Json(json!({"status": "computing", "progress": progress}))).into_response())
        }
        _ => Err((StatusCode::ACCEPTED, Json(json!({"status": "computing", "progress": 0}))).into_response()),
    }
}

// ------------------------------------------------------------- findings

fn finding_json(f: &FindingResult, accepted: Option<&crate::risk::Acceptance>) -> Value {
    let d = f.def;
    json!({
        "accepted": accepted,
        "id": d.id, "title": d.title, "severity": d.severity, "category": d.category, "kind": d.kind,
        "count": f.items.len(), "truncated": f.truncated,
        "exposure": f.exposure,
        "description": d.description, "impact": d.impact, "remediation": d.remediation,
        "mitre": d.mitre, "query": d.query,
    })
}

#[derive(Deserialize, Default)]
pub struct EnvQ {
    /// Object id of an AD domain or Entra tenant (see `/environments`).
    #[serde(default)]
    env: Option<String>,
}

/// Findings of `a`, restricted to environment `env` when given.
pub(crate) fn scoped_findings(st: &AppState, a: &AnalysisResult, env: Option<&str>) -> Result<(Vec<FindingResult>, Option<crate::env::EnvInfo>), ApiError> {
    let Some(env) = env.filter(|e| !e.is_empty()) else {
        return Ok((a.findings.clone(), None));
    };
    let guard = st.graph.read_recursive();
    let l = guard.as_ref().ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "no graph loaded yet"))?;
    let envs = crate::env::of_loaded(l);
    let ix = envs.index(env).ok_or_else(|| ApiError::not_found(format!("no domain or tenant '{env}'")))?;
    Ok((crate::env::scope(&a.findings, &envs, ix), Some(envs.list[ix as usize].clone())))
}

pub async fn environments(State(st): St) -> Result<Json<Value>, ApiError> {
    let st2 = st.clone();
    tokio::task::spawn_blocking(move || {
        let guard = st2.graph.read_recursive();
        let l = guard.as_ref().ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "no graph loaded yet"))?;
        let mut list = crate::env::of_loaded(l).list.clone();
        list.sort_by(|a, b| (a.kind, &a.name).cmp(&(b.kind, &b.name)));
        Ok(Json(json!(list)))
    })
    .await
    .map_err(|e| ApiError::from(anyhow::anyhow!("task: {e}")))?
}

pub async fn findings(State(st): St, Query(q): Query<EnvQ>) -> Response {
    match ready(&st) {
        Err(r) => r,
        Ok(a) => {
            let st2 = st.clone();
            let scoped = tokio::task::spawn_blocking(move || scoped_findings(&st2, &a, q.env.as_deref()).map(|r| (a, r))).await;
            let (a, (list, env)) = match scoped {
                Ok(Ok(x)) => x,
                Ok(Err(e)) => return e.into_response(),
                Err(e) => return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            };
            let acc = crate::risk::active(&st);
            let open: Vec<FindingResult> = list.iter().filter(|f| !acc.contains_key(f.def.id)).cloned().collect();
            Json(json!({
                "status": "ready",
                "snapshot_id": a.snapshot_id,
                "computed_ms": a.computed_ms,
                "environment": env,
                "summary": severity_counts(&open),
                "summary_all": severity_counts(&list),
                "accepted_count": list.len() - open.len(),
                "findings": list.iter().map(|f| finding_json(f, acc.get(f.def.id))).collect::<Vec<_>>(),
            }))
            .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct PageQ {
    offset: Option<usize>,
    limit: Option<usize>,
    top: Option<usize>,
    #[serde(default)]
    env: Option<String>,
}

pub async fn finding(State(st): St, Path(id): Path<String>, Query(q): Query<PageQ>) -> Response {
    let a = match ready(&st) {
        Err(r) => return r,
        Ok(a) => a,
    };
    let list = match q.env.as_deref() {
        None | Some("") => a.findings.clone(),
        Some(env) => {
            let st2 = st.clone();
            let env = env.to_string();
            match tokio::task::spawn_blocking(move || scoped_findings(&st2, &a, Some(&env))).await {
                Ok(Ok((l, _))) => l,
                Ok(Err(e)) => return e.into_response(),
                Err(e) => return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
    };
    let Some(f) = list.into_iter().find(|f| f.def.id == id) else {
        return ApiError::new(StatusCode::NOT_FOUND, format!("no finding '{id}' in this snapshot or environment")).into_response();
    };
    let (offset, limit) = (q.offset.unwrap_or(0), q.limit.unwrap_or(100).min(5000));
    let st2 = st.clone();
    tokio::task::spawn_blocking(move || {
        let guard = st2.graph.read_recursive();
        let Some(l) = guard.as_ref() else { return ApiError::new(StatusCode::CONFLICT, "no graph").into_response() };
        let g = &l.graph;
        let mut v = finding_json(&f, crate::risk::active(&st2).get(f.def.id));
        type Drawn = (Vec<Value>, Vec<u32>, Vec<(u32, u32, u16)>);
        let (items, gnodes, gedges): Drawn = match &f.items {
            Items::Edges(es) => {
                let page = es.iter().skip(offset).take(limit).map(|&(s, d, k)| {
                    json!({"src": node_json(g, s), "dst": node_json(g, d), "kind": g.edge_kind_name(k)})
                });
                let drawn: Vec<_> = es.iter().take(500).copied().collect();
                let mut ns: Vec<u32> = drawn.iter().flat_map(|e| [e.0, e.1]).collect();
                ns.sort_unstable();
                ns.dedup();
                (page.collect(), ns, drawn)
            }
            Items::Nodes(ns) => {
                let page = ns.iter().skip(offset).take(limit).map(|&n| json!({"node": node_json(g, n)}));
                (page.collect(), ns.iter().take(500).copied().collect(), Vec::new())
            }
        };
        v["total"] = json!(f.items.len());
        v["items"] = Value::Array(items);
        v["graph"] = json!({
            "nodes": gnodes.iter().map(|&n| node_json(g, n)).collect::<Vec<_>>(),
            "edges": gedges.iter().map(|&(s, d, k)| json!({"src": s, "dst": d, "kind": g.edge_kind_name(k)})).collect::<Vec<_>>(),
            "paths": [], "truncated": f.items.len() > 500, "elapsed_ms": 0.0,
        });
        Json(v).into_response()
    })
    .await
    .unwrap_or_else(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
}

// ---------------------------------------------------------------- zones

const PALETTE: &[&str] = &["#e5484d", "#f76b15", "#ffc53d", "#30a46c", "#12a594", "#0090ff", "#6e56cf", "#d6409f"];

pub(crate) fn zone_members(st: &AppState, g: &Graph, generation: u64, zone: &str) -> Result<Arc<Vec<u32>>, ApiError> {
    if zone == TIER0_ZONE {
        return Ok(Arc::new(g.nodes_with_flag(flags::TIER0)));
    }
    if let Some(m) = st.zone_cache.lock().get(&(generation, zone.to_string())) {
        return Ok(m.clone());
    }
    // Objects revoked in zone review stay out of the zone.
    let revoked = crate::zonereview::revoked(st, zone);
    let mut nodes = zone_selector_matches(st, g, zone)?;
    if !revoked.is_empty() {
        nodes.retain(|&n| !revoked.contains(&g.oid(n).to_ascii_uppercase()));
    }
    let m = Arc::new(nodes);
    let mut cache = st.zone_cache.lock();
    cache.retain(|(gen, _), _| *gen == generation);
    cache.insert((generation, zone.to_string()), m.clone());
    Ok(m)
}

/// Everything a custom zone's selector matches, sorted, before zone review.
pub(crate) fn zone_selector_matches(st: &AppState, g: &Graph, zone: &str) -> Result<Vec<u32>, ApiError> {
    let def = st.zones.lock().iter().find(|z| z.id == zone).cloned().ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, format!("no zone '{zone}'")))?;
    let r = ch_query::run_capped(g, &def.selector, usize::MAX, 50_000_000, &ch_query::Cancel::never()).map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, format!("zone selector: {e}")))?;
    let mut nodes = r.nodes;
    nodes.sort_unstable();
    nodes.dedup();
    Ok(nodes)
}

fn zone_json(st: &AppState, z: Option<&ZoneDef>) -> Value {
    let guard = st.graph.read_recursive();
    let count = guard.as_ref().and_then(|l| {
        let id = z.map(|z| z.id.as_str()).unwrap_or(TIER0_ZONE);
        zone_members(st, &l.graph, l.generation, id).ok().map(|m| m.len())
    });
    match z {
        None => json!({"id": TIER0_ZONE, "name": "Tier Zero", "description": "Objects tagged Tier Zero by ingest rules and operator marks.",
                       "selector": "MATCH (t {tier0:true}) RETURN t", "color": "#e5484d", "builtin": true, "member_count": count.unwrap_or(0)}),
        Some(z) => json!({"id": z.id, "name": z.name, "description": z.description, "selector": z.selector, "color": z.color,
                          "builtin": false, "member_count": count.unwrap_or(0)}),
    }
}

pub async fn list_zones(State(st): St) -> Json<Value> {
    let st2 = st.clone();
    let v = tokio::task::spawn_blocking(move || {
        let zones = st2.zones.lock().clone();
        let mut out = vec![zone_json(&st2, None)];
        out.extend(zones.iter().map(|z| zone_json(&st2, Some(z))));
        Value::Array(out)
    })
    .await
    .unwrap_or(Value::Null);
    Json(v)
}

#[derive(Deserialize)]
pub struct ZoneReq {
    name: String,
    description: Option<String>,
    selector: String,
    color: Option<String>,
}

fn validate_zone(r: &ZoneReq) -> Result<(), ApiError> {
    if r.name.trim().is_empty() || r.name.len() > 100 {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "name must be 1-100 characters"));
    }
    if let Some(c) = &r.color {
        let ok = c.len() == 7 && c.starts_with('#') && c[1..].chars().all(|x| x.is_ascii_hexdigit());
        if !ok {
            return Err(ApiError::new(StatusCode::BAD_REQUEST, "color must be #rrggbb"));
        }
    }
    ch_query::parse_syntax(&r.selector).map(|_| ()).map_err(|e| {
        crate::api::ApiError::raw(StatusCode::BAD_REQUEST, json!({"error": e.message, "position": e.position, "code": e.code}))
    })
}

pub async fn create_zone(State(st): St, Json(r): Json<ZoneReq>) -> Result<Json<Value>, ApiError> {
    validate_zone(&r)?;
    let z = {
        let mut zones = st.zones.lock();
        let z = ZoneDef {
            id: format!("z-{}", crate::auth::random_hex(6)),
            name: r.name.trim().to_string(),
            description: r.description.unwrap_or_default(),
            selector: r.selector,
            color: r.color.unwrap_or_else(|| PALETTE[(zones.len() + 1) % PALETTE.len()].to_string()),
        };
        zones.push(z.clone());
        store_json(&st.zones_path(), &*zones)?;
        z
    };
    let st2 = st.clone();
    Ok(Json(tokio::task::spawn_blocking(move || zone_json(&st2, Some(&z))).await.unwrap_or(Value::Null)))
}

pub async fn update_zone(State(st): St, Path(id): Path<String>, Json(r): Json<ZoneReq>) -> Result<Json<Value>, ApiError> {
    if id == TIER0_ZONE {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "the Tier Zero zone is built in; change it with Tier Zero marks"));
    }
    validate_zone(&r)?;
    let z = {
        let mut zones = st.zones.lock();
        let z = zones.iter_mut().find(|z| z.id == id).ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, format!("no zone '{id}'")))?;
        z.name = r.name.trim().to_string();
        z.description = r.description.unwrap_or_default();
        z.selector = r.selector;
        if let Some(c) = r.color {
            z.color = c;
        }
        let out = z.clone();
        store_json(&st.zones_path(), &*zones)?;
        out
    };
    st.zone_cache.lock().retain(|(_, zid), _| *zid != id);
    let st2 = st.clone();
    Ok(Json(tokio::task::spawn_blocking(move || zone_json(&st2, Some(&z))).await.unwrap_or(Value::Null)))
}

pub async fn delete_zone(State(st): St, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let mut zones = st.zones.lock();
    let before = zones.len();
    zones.retain(|z| z.id != id);
    if zones.len() == before {
        return Err(ApiError::new(StatusCode::NOT_FOUND, format!("no zone '{id}'")));
    }
    store_json(&st.zones_path(), &*zones)?;
    drop(zones);
    crate::zonereview::forget_zone(&st, &id)?;
    st.zone_cache.lock().retain(|(_, zid), _| *zid != id);
    Ok(Json(json!({})))
}

async fn with_zone<T: Send + 'static>(
    st: Arc<AppState>,
    zone: String,
    f: impl FnOnce(&Graph, &[u32]) -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(move || {
        let guard = st.graph.read_recursive();
        let l = guard.as_ref().ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "no graph loaded yet"))?;
        let members = zone_members(&st, &l.graph, l.generation, &zone)?;
        f(&l.graph, &members)
    })
    .await
    .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

pub async fn zone_members_api(State(st): St, Path(id): Path<String>, Query(q): Query<PageQ>) -> Result<Json<Value>, ApiError> {
    let (offset, limit) = (q.offset.unwrap_or(0), q.limit.unwrap_or(200).min(20_000));
    with_zone(st, id, move |g, m| {
        Ok(Json(json!({"total": m.len(), "items": m.iter().skip(offset).take(limit).map(|&n| node_json(g, n)).collect::<Vec<_>>()})))
    })
    .await
}

pub async fn zone_exposure(State(st): St, Path(id): Path<String>, Query(q): Query<PageQ>) -> Result<Json<Value>, ApiError> {
    let top = q.top.unwrap_or(25).min(1000);
    with_zone(st, id, move |g, m| {
        let t = Instant::now();
        let rep = exposure_with(g, m, &Removal::default(), top);
        Ok(Json(crate::api::tier0_json(g, &rep, top, t.elapsed().as_secs_f64() * 1e3)))
    })
    .await
}

#[derive(Deserialize)]
pub struct IdsReq {
    ids: Vec<u32>,
}

/// Zone ids each node belongs to: `{"<node id>": ["tier0", "z-…"]}` (max 20000 ids).
pub async fn zone_membership(State(st): St, Json(r): Json<IdsReq>) -> Result<Json<Value>, ApiError> {
    let st2 = st.clone();
    tokio::task::spawn_blocking(move || {
        let guard = st2.graph.read_recursive();
        let l = guard.as_ref().ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "no graph loaded yet"))?;
        let mut ids: Vec<String> = vec![TIER0_ZONE.to_string()];
        ids.extend(st2.zones.lock().iter().map(|z| z.id.clone()));
        let wanted: Vec<u32> = r.ids.into_iter().take(20_000).collect();
        let mut out = serde_json::Map::new();
        for zid in &ids {
            let members = zone_members(&st2, &l.graph, l.generation, zid)?;
            for &n in &wanted {
                // Member lists are sorted (Tier Zero via an ordered parallel scan).
                if members.binary_search(&n).is_ok() {
                    out.entry(n.to_string()).or_insert_with(|| json!([])).as_array_mut().expect("array").push(json!(zid));
                }
            }
        }
        Ok(Json(Value::Object(out)))
    })
    .await
    .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

#[derive(Deserialize)]
pub struct InvolvingQ {
    node: u32,
}

/// Findings whose items involve a node: `[{"id","title","severity","items": n}]`.
pub async fn findings_involving(State(st): St, Query(q): Query<InvolvingQ>) -> Response {
    let a = match ready(&st) {
        Err(r) => return r,
        Ok(a) => a,
    };
    let out: Vec<Value> = a
        .findings
        .iter()
        .filter_map(|f| {
            let n = match &f.items {
                Items::Edges(es) => es.iter().filter(|e| e.0 == q.node || e.1 == q.node).count(),
                Items::Nodes(ns) => ns.iter().filter(|&&x| x == q.node).count(),
            };
            (n > 0).then(|| json!({"id": f.def.id, "title": f.def.title, "severity": f.def.severity, "items": n}))
        })
        .collect();
    Json(Value::Array(out)).into_response()
}

// ------------------------------------------------------------- simulate

#[derive(Deserialize)]
pub struct EdgeRef {
    src: u32,
    dst: u32,
    kind: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct SimReq {
    zone: Option<String>,
    remove_edges: Vec<EdgeRef>,
    remove_kinds: Vec<String>,
    remove_nodes: Vec<u32>,
    add_targets: Vec<u32>,
}

fn summary(r: &ch_engine::Tier0Report) -> Value {
    json!({"exposed_principals": r.exposed_principals, "total_principals": r.total_principals, "exposure": r.exposure, "max_depth": r.max_depth})
}

pub async fn simulate_api(State(st): St, Json(r): Json<SimReq>) -> Result<Json<Value>, ApiError> {
    let zone = r.zone.clone().unwrap_or_else(|| TIER0_ZONE.into());
    with_zone(st, zone, move |g, members| {
        let t = Instant::now();
        let kind = |k: &str| g.edge_kind_id(k).ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, format!("unknown edge kind '{k}'")));
        let mut removal = Removal::default();
        for e in &r.remove_edges {
            removal.edges.insert((e.src, e.dst, kind(&e.kind)?));
        }
        for k in &r.remove_kinds {
            removal.kinds.insert(kind(k)?);
        }
        removal.nodes.extend(r.remove_nodes.iter().copied());
        let add: Vec<u32> = r.add_targets.iter().copied().filter(|&i| (i as usize) < g.node_count()).collect();
        let s = simulate(g, members, &add, &removal);
        Ok(Json(json!({
            "before": summary(&s.before), "after": summary(&s.after),
            "reduction": s.reduction, "reduction_percent": s.reduction_percent,
            "elapsed_ms": t.elapsed().as_secs_f64() * 1e3,
        })))
    })
    .await
}

#[derive(Deserialize)]
pub struct PlanReq {
    zone: Option<String>,
    steps: Option<usize>,
    #[serde(default)]
    fixed_kinds: Vec<String>,
    protect_target_membership: Option<bool>,
    /// Honour the `fix_cost` node property (default true).
    respect_fix_cost: Option<bool>,
    /// Propose fixes that need no maintenance window first.
    #[serde(default)]
    live_first: bool,
    timeout_ms: Option<u64>,
}

pub async fn plan_api(State(st): St, Json(r): Json<PlanReq>) -> Result<Json<Value>, ApiError> {
    let zone = r.zone.clone().unwrap_or_else(|| TIER0_ZONE.into());
    with_zone(st, zone, move |g, members| {
        let t = Instant::now();
        let mut fixed = Vec::new();
        for k in &r.fixed_kinds {
            fixed.push(g.edge_kind_id(k).ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, format!("unknown edge kind '{k}'")))?);
        }
        let opts = PlanOptions {
            steps: r.steps.unwrap_or(10).clamp(1, 50),
            fixed_kinds: fixed,
            protect_target_membership: r.protect_target_membership.unwrap_or(true),
            node_cost: if r.respect_fix_cost.unwrap_or(true) { fix_costs(g) } else { None },
            live_first: r.live_first,
        };
        let cancel = ch_query::Cancel::new(Some(std::time::Duration::from_millis(r.timeout_ms.unwrap_or(120_000).clamp(1000, 600_000))));
        let p = plan(g, members, &opts, &cancel);
        Ok(Json(json!({
            "baseline": p.baseline,
            "truncated": p.truncated,
            "steps": p.steps.iter().map(|s| json!({
                "node": node_json(g, s.node),
                "edges": s.edges.iter().take(50).map(|&(a, b, k)| json!({"src": node_json(g, a), "dst": node_json(g, b), "kind": g.edge_kind_name(k)})).collect::<Vec<_>>(),
                "edge_count": s.edges.len(),
                "principals_cut": s.principals_cut,
                "exposed_after": s.exposed_after,
                "cumulative_reduction_percent": s.cumulative_reduction_percent,
                "needs_window": s.needs_window,
            })).collect::<Vec<_>>(),
            "elapsed_ms": t.elapsed().as_secs_f64() * 1e3,
        })))
    })
    .await
}

// -------------------------------------------------------------- posture

pub async fn posture(State(st): St) -> Json<Value> {
    let history: Vec<Snapshot> = load_json(&st.posture_path());
    Json(serde_json::to_value(history).unwrap_or(Value::Null))
}

#[derive(Deserialize)]
pub struct DiffQ {
    from: String,
    to: String,
}

fn valid_snapshot_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub async fn posture_diff(State(st): St, Query(q): Query<DiffQ>) -> Result<Json<Value>, ApiError> {
    if !valid_snapshot_id(&q.from) || !valid_snapshot_id(&q.to) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid snapshot id"));
    }
    let load = |id: &str| -> Result<SnapshotItems, ApiError> {
        let p = st.snapshot_items_path(id);
        if !p.exists() {
            return Err(ApiError::new(StatusCode::NOT_FOUND, format!("no snapshot '{id}'")));
        }
        Ok(load_json(&p))
    };
    let (a, b) = (load(&q.from)?, load(&q.to)?);
    Ok(Json(json!({"from": q.from, "to": q.to, "findings": diff(&a, &b, 200)})))
}

/// One finding over the posture history: item count per snapshot (oldest
/// first) and the items that appeared / disappeared in the latest change.
pub async fn finding_history(State(st): St, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    if !ch_analysis::findings::CATALOG.iter().any(|d| d.id == id) {
        return Err(ApiError::not_found(format!("no finding '{id}'")));
    }
    let st2 = st.clone();
    let out = tokio::task::spawn_blocking(move || {
        let history: Vec<Snapshot> = load_json(&st2.posture_path());
        let points: Vec<Value> = history
            .iter()
            .map(|s| json!({"snapshot_id": s.snapshot_id, "created_at": s.created_at, "count": s.finding_counts.get(&id).copied().unwrap_or(0)}))
            .collect();
        // Latest two snapshots with stored items.
        let with_items: Vec<&Snapshot> = history.iter().rev().filter(|s| st2.snapshot_items_path(&s.snapshot_id).exists()).take(2).collect();
        let change = if let [to, from] = with_items.as_slice() {
            let a: SnapshotItems = load_json(&st2.snapshot_items_path(&from.snapshot_id));
            let b: SnapshotItems = load_json(&st2.snapshot_items_path(&to.snapshot_id));
            let empty = std::collections::BTreeMap::new();
            let (fa, fb) = (a.findings.get(&id).unwrap_or(&empty), b.findings.get(&id).unwrap_or(&empty));
            let added: Vec<&String> = fb.iter().filter(|(k, _)| !fa.contains_key(*k)).map(|(_, l)| l).collect();
            let removed: Vec<&String> = fa.iter().filter(|(k, _)| !fb.contains_key(*k)).map(|(_, l)| l).collect();
            json!({
                "from": from.snapshot_id, "to": to.snapshot_id, "from_at": from.created_at, "to_at": to.created_at,
                "added": added.len(), "removed": removed.len(),
                "added_sample": added.iter().take(50).collect::<Vec<_>>(),
                "removed_sample": removed.iter().take(50).collect::<Vec<_>>(),
            })
        } else {
            Value::Null
        };
        json!({"id": id, "points": points, "latest_change": change})
    })
    .await
    .map_err(|e| ApiError::from(anyhow::anyhow!("task: {e}")))?;
    Ok(Json(out))
}

pub async fn delete_snapshot(State(st): St, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    if !valid_snapshot_id(&id) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid snapshot id"));
    }
    let mut history: Vec<Snapshot> = load_json(&st.posture_path());
    let before = history.len();
    history.retain(|s| s.snapshot_id != id);
    if history.len() == before {
        return Err(ApiError::new(StatusCode::NOT_FOUND, format!("no snapshot '{id}'")));
    }
    store_json(&st.posture_path(), &history)?;
    let _ = std::fs::remove_file(st.snapshot_items_path(&id));
    Ok(Json(json!({})))
}

// --------------------------------------------------------------- report

#[derive(Deserialize)]
pub struct ReportQ {
    /// `html` (default), `md` or `csv`.
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    plan_steps: Option<usize>,
    #[serde(default)]
    items: Option<usize>,
    /// `1` to send `Content-Disposition: attachment`.
    #[serde(default)]
    download: Option<u8>,
    /// Restrict findings to one domain / tenant (object id).
    #[serde(default)]
    env: Option<String>,
}

/// Render the assessment report (`ext`: `html`, `md` or `csv`) for the
/// current graph; returns `(text, snapshot id)`. Blocking (runs the planner).
pub fn render_report(
    st: &AppState,
    res: &AnalysisResult,
    ext: &str,
    title: Option<&str>,
    plan_steps: usize,
    items: usize,
) -> Result<(String, String), ApiError> {
    let posture: Vec<Snapshot> = load_json(&st.posture_path());
    let guard = st.graph.read_recursive();
    let l = guard.as_ref().ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "no graph loaded yet"))?;
    let g = &l.graph;
    let tier0 = g.nodes_with_flag(flags::TIER0);
    let rep = exposure_with(g, &tier0, &Removal::default(), 10);
    let steps = plan_steps.min(50);
    let p = (steps > 0 && ext != "csv").then(|| {
        let opts = PlanOptions { steps, protect_target_membership: true, node_cost: fix_costs(g), ..Default::default() };
        plan(g, &tier0, &opts, &ch_query::Cancel::new(Some(std::time::Duration::from_secs(120))))
    });
    let snap = l.snapshot_id();
    let title = title.filter(|t| !t.trim().is_empty()).unwrap_or("Attack path assessment");
    let generated = now_rfc3339();
    let acc = crate::risk::active(st);
    let open: Vec<FindingResult> = res.findings.iter().filter(|f| !acc.contains_key(f.def.id)).cloned().collect();
    let accepted: Vec<ch_analysis::report::AcceptedRisk> = res
        .findings
        .iter()
        .filter_map(|f| {
            let a = acc.get(f.def.id)?;
            Some(ch_analysis::report::AcceptedRisk {
                id: f.def.id.to_string(),
                title: f.def.title.to_string(),
                severity: f.def.severity,
                items: f.items.len(),
                reason: a.reason.clone(),
                accepted_by: a.accepted_by.clone(),
                accepted_at: a.accepted_at.clone(),
                expires_at: a.expires_at.clone(),
            })
        })
        .collect();
    let input = ch_analysis::report::ReportInput {
        title,
        generated_at: &generated,
        snapshot_id: &snap,
        graph: g,
        tier0: &rep,
        findings: &open,
        accepted: &accepted,
        posture: &posture,
        plan: p.as_ref(),
        items_per_finding: items.min(10_000),
    };
    let out = match ext {
        "html" => ch_analysis::report::render_html(&input),
        "md" => ch_analysis::report::render_markdown(&input),
        _ => ch_analysis::report::render_csv(&input),
    };
    Ok((out, snap))
}

/// Assessment report for the current snapshot (`GET /report`).
pub async fn report(State(st): St, Query(q): Query<ReportQ>) -> Response {
    let res = match ready(&st) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let format = q.format.clone().unwrap_or_else(|| "html".into()).to_ascii_lowercase();
    let (ctype, ext) = match format.as_str() {
        "html" => ("text/html; charset=utf-8", "html"),
        "md" | "markdown" => ("text/markdown; charset=utf-8", "md"),
        "csv" => ("text/csv; charset=utf-8", "csv"),
        _ => return ApiError::new(StatusCode::BAD_REQUEST, "format must be html, md or csv").into_response(),
    };
    let st2 = st.clone();
    let body = tokio::task::spawn_blocking(move || {
        let (findings, env) = scoped_findings(&st2, &res, q.env.as_deref())?;
        let res = AnalysisResult { generation: res.generation, snapshot_id: res.snapshot_id.clone(), computed_ms: res.computed_ms, findings };
        let title = match (&q.title, &env) {
            (Some(t), _) if !t.trim().is_empty() => t.clone(),
            (_, Some(e)) => format!("Attack path assessment — {}", e.name),
            _ => String::new(),
        };
        render_report(&st2, &res, ext, Some(&title), q.plan_steps.unwrap_or(10), q.items.unwrap_or(25))
    })
    .await;
    let (text, snap) = match body {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return e.into_response(),
        Err(e) => return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(axum::http::header::CONTENT_TYPE, axum::http::HeaderValue::from_static(ctype));
    // The HTML is self-contained: forbid scripts and remote loads outright.
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; img-src data:"),
    );
    if q.download == Some(1) {
        let name = format!("copperhound-report-{snap}.{ext}");
        if let Ok(v) = axum::http::HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
            headers.insert(axum::http::header::CONTENT_DISPOSITION, v);
        }
    }
    (StatusCode::OK, headers, text).into_response()
}
