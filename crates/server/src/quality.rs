//! Data quality: how complete and how fresh the collected data is, per AD
//! domain and Entra tenant, so that "no attack path" can be told apart from
//! "not collected".
//!
//! * **AD** (objects grouped by their domain SID): enabled computers with
//!   session data (`HasSession`), with local group data (any inbound
//!   `AdminTo` / `CanRDP` / `CanPSRemote` / `ExecuteDCOM`), and objects with
//!   ACL data (an `isaclprotected` property, which SharpHound and the LDIF /
//!   AD Explorer readers set whenever they read the security descriptor;
//!   unknown when no object has it, e.g. older collectors).
//! * **Entra** (objects a tenant `AZContains`): role assignments, group
//!   memberships, application ownership and devices.
//! * **Freshness**: the newest collection time of the sources naming the
//!   domain / tenant.
//!
//! Warnings flag coverage below the thresholds below. GET /quality, cached
//! per graph generation.

use crate::api::{ApiError, St};
use crate::state::AppState;
use ahash::AHashMap;
use axum::extract::State;
use axum::Json;
use parking_lot::Mutex;
use ch_model::{flags, NodeKind};
use ch_store::Graph;
use serde_json::{json, Value};
use std::sync::Arc;

const SESSION_MIN: f64 = 0.10;
const LOCAL_GROUP_MIN: f64 = 0.10;
const ACL_MIN: f64 = 0.90;
const STALE_DAYS: i64 = 30;

/// How to fix each warning, keyed by the codes in `warning_codes`. The UI shows
/// each once, with the domains / tenants it applies to.
const ADVICE: &[(&str, &str)] = &[
    ("sessions", "User-on-computer paths (HasSession) are mostly missing. Collect sessions (SharpHound -c Session,LoggedOn, ideally looped), or upload logon data: scripts/Export-CopperHoundLogons.ps1 (Security event 4624) or a Defender XDR DeviceLogonEvents export."),
    ("local_groups", "Local admin / RDP rights are mostly missing. Collect LocalGroup (needs admin or remote SAM access)."),
    ("acl", "The collector could not read some security descriptors, so control edges are incomplete."),
    ("stale", "Collect again: paths that were removed or added since are not reflected."),
    ("az_roles", "AzureHound could not read role members, so role-based paths are missing."),
    ("az_members", "Group-based Entra paths are missing."),
    ("az_owners", "Owner-based application paths are missing."),
    ("az_subscriptions", "Azure RBAC (resource) paths are not covered: collect with an identity that can read subscriptions."),
    ("unknown", "Objects referenced by SID or id that no collected record describes: principals of domains or forests not collected, deleted objects, or well-known SIDs. Their paths are real, but their kind is unknown."),
];

#[derive(Default)]
struct Ad {
    users: u64,
    users_enabled: u64,
    groups: u64,
    computers: u64,
    computers_enabled: u64,
    with_sessions: u64,
    with_local_groups: u64,
    objects: u64,
    with_acl: u64,
}

#[derive(Default)]
struct Az {
    users: u64,
    groups: u64,
    apps: u64,
    service_principals: u64,
    devices: u64,
    roles: u64,
    role_assignments: u64,
    memberships: u64,
    app_owners: u64,
    devices_with_owner: u64,
    subscriptions: u64,
}

fn pct(a: u64, b: u64) -> Option<f64> {
    (b > 0).then(|| (a as f64 / b as f64 * 1000.0).round() / 10.0)
}

pub fn compute(g: &Graph, sources: &[Value]) -> Value {
    let k = |n: &str| g.edge_kind_id(n);
    let has_session = k("HasSession");
    let local: Vec<u16> = ["AdminTo", "CanRDP", "CanPSRemote", "ExecuteDCOM"].iter().filter_map(|n| k(n)).collect();
    let (contains, has_role, member_of, az_owns) = (k("AZContains"), k("AZHasRole"), k("AZMemberOf"), k("AZOwns"));
    let n = g.node_count() as u32;

    // ---- AD, by domain SID prefix
    let mut ad: AHashMap<u32, Ad> = AHashMap::new();
    for id in 0..n {
        let kind = g.kind(id);
        if !matches!(kind, NodeKind::User | NodeKind::Computer | NodeKind::Group) {
            continue;
        }
        let oid = g.oid(id);
        let Some(dom) = oid.starts_with("S-1-5-21-").then(|| oid.rsplit_once('-')).flatten().and_then(|(p, _)| g.lookup(p)) else {
            continue;
        };
        if g.kind(dom) != NodeKind::Domain {
            continue;
        }
        let d = ad.entry(dom).or_default();
        let enabled = g.has_flag(id, flags::ENABLED);
        let (_, iks) = g.in_edges(id);
        d.objects += 1;
        if g.props(id).contains("\"isaclprotected\"") {
            d.with_acl += 1;
        }
        match kind {
            NodeKind::User => {
                d.users += 1;
                d.users_enabled += enabled as u64;
            }
            NodeKind::Group => d.groups += 1,
            _ => {
                d.computers += 1;
                if enabled {
                    d.computers_enabled += 1;
                    let (_, oks) = g.out_edges(id);
                    if has_session.is_some_and(|h| oks.contains(&h)) {
                        d.with_sessions += 1;
                    }
                    if iks.iter().any(|x| local.contains(x)) {
                        d.with_local_groups += 1;
                    }
                }
            }
        }
    }

    // ---- Entra, by containing tenant
    let mut az: AHashMap<u32, Az> = AHashMap::new();
    for t in (0..n).filter(|&i| g.kind(i) == NodeKind::AzTenant) {
        let mut a = Az::default();
        let (ds, ks) = g.out_edges(t);
        for (&x, &kk) in ds.iter().zip(ks) {
            if Some(kk) != contains {
                continue;
            }
            let (_, oks) = g.out_edges(x);
            let (_, iks) = g.in_edges(x);
            match g.kind(x) {
                NodeKind::AzUser => {
                    a.users += 1;
                    a.role_assignments += oks.iter().filter(|&&k| Some(k) == has_role).count() as u64;
                    a.memberships += oks.iter().filter(|&&k| Some(k) == member_of).count() as u64;
                }
                NodeKind::AzGroup => {
                    a.groups += 1;
                    a.role_assignments += oks.iter().filter(|&&k| Some(k) == has_role).count() as u64;
                }
                NodeKind::AzApp => {
                    a.apps += 1;
                    if az_owns.is_some_and(|o| iks.contains(&o)) {
                        a.app_owners += 1;
                    }
                }
                NodeKind::AzServicePrincipal => {
                    a.service_principals += 1;
                    a.role_assignments += oks.iter().filter(|&&k| Some(k) == has_role).count() as u64;
                }
                NodeKind::AzDevice => {
                    a.devices += 1;
                    if az_owns.is_some_and(|o| iks.contains(&o)) {
                        a.devices_with_owner += 1;
                    }
                }
                NodeKind::AzRole => a.roles += 1,
                NodeKind::AzSubscription => a.subscriptions += 1,
                _ => {}
            }
        }
        az.insert(t, a);
    }

    // ---- freshness from the source manifest
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    // Sources naming the domain / tenant (by name, or by id: AzureHound
    // records the tenant id). Collection time, else the file's date.
    let newest = |name: &str, oid: &str| -> (Option<String>, Option<i64>, u64, bool) {
        let mut best: Option<(i64, String, bool)> = None;
        let mut count = 0;
        for s in sources {
            let doms = s.get("domains").and_then(Value::as_array);
            let hit = |x: &str| x.eq_ignore_ascii_case(name) || x.eq_ignore_ascii_case(oid);
            if !doms.is_some_and(|d| d.iter().any(|x| x.as_str().is_some_and(hit))) {
                continue;
            }
            count += 1;
            let collected = s.get("collected_at").and_then(Value::as_str).map(|a| (a, true));
            let when = collected.or_else(|| s.get("file_mtime").and_then(Value::as_str).map(|a| (a, false)));
            if let Some((at, exact)) = when {
                if let Ok(t) = humantime::parse_rfc3339_weak(at) {
                    let t = t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
                    if best.as_ref().is_none_or(|b| t > b.0) {
                        best = Some((t, at.to_string(), exact));
                    }
                }
            }
        }
        let age = best.as_ref().map(|b| (now - b.0) / 86_400);
        let exact = best.as_ref().is_some_and(|b| b.2);
        (best.map(|b| b.1), age, count, exact)
    };

    let mut domains: Vec<Value> = ad
        .iter()
        .map(|(&dom, d)| {
            let name = g.name(dom).to_string();
            let (at, age, nsrc, exact) = newest(&name, g.oid(dom));
            let sess = pct(d.with_sessions, d.computers_enabled);
            let lg = pct(d.with_local_groups, d.computers_enabled);
            let acl = if d.with_acl == 0 { None } else { pct(d.with_acl, d.objects) };
            let mut warnings: Vec<(&str, String)> = Vec::new();
            if d.computers_enabled > 0 && sess.is_some_and(|p| p < SESSION_MIN * 100.0) {
                warnings.push(("sessions", format!("Session data for {}% of enabled computers.", sess.unwrap_or(0.0))));
            }
            if d.computers_enabled > 0 && lg.is_some_and(|p| p < LOCAL_GROUP_MIN * 100.0) {
                warnings.push(("local_groups", format!("Local group data for {}% of enabled computers.", lg.unwrap_or(0.0))));
            }
            if d.objects > 0 && acl.is_some_and(|p| p < ACL_MIN * 100.0) {
                warnings.push(("acl", format!("Only {}% of objects have ACL data.", acl.unwrap_or(0.0))));
            }
            if age.is_some_and(|a| a > STALE_DAYS) {
                warnings.push(("stale", format!("Newest collection is {} days old.", age.unwrap_or(0))));
            }
            let (codes, warnings): (Vec<&str>, Vec<String>) = warnings.into_iter().unzip();
            json!({
                "type": "ad", "id": dom, "name": name, "objectid": g.oid(dom),
                "users": d.users, "users_enabled": d.users_enabled, "groups": d.groups,
                "computers": d.computers, "computers_enabled": d.computers_enabled,
                "session_coverage": sess, "local_group_coverage": lg, "acl_coverage": acl,
                "collected_at": at, "collected_at_exact": exact, "age_days": age, "sources": nsrc, "warnings": warnings,
                "warning_codes": codes,
            })
        })
        .collect();
    domains.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    let mut tenants: Vec<Value> = az
        .iter()
        .map(|(&t, a)| {
            let name = g.name(t).to_string();
            let (at, age, nsrc, exact) = newest(&name, g.oid(t));
            let mut warnings: Vec<(&str, String)> = Vec::new();
            if a.roles > 0 && a.role_assignments == 0 {
                warnings.push(("az_roles", "No directory role assignments.".into()));
            }
            if a.groups > 0 && a.memberships == 0 {
                warnings.push(("az_members", "No group memberships were collected.".into()));
            }
            if a.apps > 0 && a.app_owners == 0 {
                warnings.push(("az_owners", "No application owners were collected.".into()));
            }
            if a.subscriptions == 0 {
                warnings.push(("az_subscriptions", "No Azure subscriptions.".into()));
            }
            if age.is_some_and(|x| x > STALE_DAYS) {
                warnings.push(("stale", format!("Newest collection is {} days old.", age.unwrap_or(0))));
            }
            let (codes, warnings): (Vec<&str>, Vec<String>) = warnings.into_iter().unzip();
            json!({
                "type": "tenant", "id": t, "name": name, "objectid": g.oid(t),
                "users": a.users, "groups": a.groups, "apps": a.apps, "service_principals": a.service_principals,
                "devices": a.devices, "roles": a.roles, "role_assignments": a.role_assignments,
                "memberships": a.memberships, "app_owner_coverage": pct(a.app_owners, a.apps),
                "device_owner_coverage": pct(a.devices_with_owner, a.devices), "subscriptions": a.subscriptions,
                "collected_at": at, "collected_at_exact": exact, "age_days": age, "sources": nsrc, "warnings": warnings,
                "warning_codes": codes,
            })
        })
        .collect();
    tenants.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()).then(a["objectid"].as_str().cmp(&b["objectid"].as_str())));
    let unknown = (0..g.node_count() as u32).filter(|&i| g.kind(i) == NodeKind::Unknown).count();
    json!({
        "domains": domains,
        "tenants": tenants,
        "unknown_objects": unknown,
        "advice": ADVICE.iter().map(|(k, v)| (k.to_string(), json!(v))).collect::<serde_json::Map<String, Value>>(),
    })
}

type Cache = Mutex<Option<(u64, Arc<Value>)>>;

fn cache() -> &'static Cache {
    static C: std::sync::OnceLock<Cache> = std::sync::OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

pub async fn quality(State(st): St) -> Result<Json<Value>, ApiError> {
    let st2: Arc<AppState> = st.clone();
    let v = tokio::task::spawn_blocking(move || -> Result<Arc<Value>, ApiError> {
        let guard = st2.graph.read_recursive();
        let l = guard.as_ref().ok_or_else(|| ApiError::new(axum::http::StatusCode::CONFLICT, "no graph loaded yet"))?;
        if let Some((g, v)) = cache().lock().as_ref() {
            if *g == l.generation {
                return Ok(v.clone());
            }
        }
        let sources: Vec<Value> = l.graph.meta().ingest.as_ref().and_then(|m| m.get("sources")).and_then(Value::as_array).cloned().unwrap_or_default();
        let v = Arc::new(compute(&l.graph, &sources));
        *cache().lock() = Some((l.generation, v.clone()));
        Ok(v)
    })
    .await
    .map_err(|e| ApiError::from(anyhow::anyhow!("task: {e}")))??;
    Ok(Json((*v).clone()))
}
