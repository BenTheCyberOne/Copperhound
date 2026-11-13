//! Privilege zone review: each object a zone's selector picks up is
//! `pending` until someone certifies it (`certified`) or removes it from the
//! zone (`revoked`). Revoked objects are left out of the zone's membership,
//! and so of its exposure and path analysis, while the selector still
//! matches them; objects the selector picks up later start as pending.
//! Objects added to a zone by hand are certified when added.
//! Built-in Tier Zero is managed with marks instead.
//!
//! Stored in `<data>/zone_reviews.json`: zone id → object id → decision.

use crate::api::{ApiError, St};
use crate::auth::Principal;
use crate::state::{load_json, now_rfc3339, store_json, AppState};
use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Decision {
    /// `certified` or `revoked`.
    pub status: String,
    pub by: String,
    pub at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

pub type Reviews = BTreeMap<String, BTreeMap<String, Decision>>;

static LOCK: Mutex<()> = Mutex::new(());

fn path(st: &AppState) -> std::path::PathBuf {
    st.data_dir.join("zone_reviews.json")
}

pub fn load(st: &AppState) -> Reviews {
    load_json(&path(st))
}

/// Upper-cased object ids revoked from `zone`.
pub fn revoked(st: &AppState, zone: &str) -> ahash::AHashSet<String> {
    load(st)
        .get(zone)
        .map(|m| m.iter().filter(|(_, d)| d.status == "revoked").map(|(k, _)| k.to_ascii_uppercase()).collect())
        .unwrap_or_default()
}

/// Set (`Some(status)`) or clear (`None`) the decision on `oids` in `zone`.
pub(crate) fn set_status(st: &AppState, zone: &str, oids: &[String], status: Option<&str>, by: &str, note: &str) -> anyhow::Result<()> {
    let _g = LOCK.lock();
    let mut all = load(st);
    let z = all.entry(zone.to_string()).or_default();
    for oid in oids {
        let key = oid.trim().to_ascii_uppercase();
        match status {
            None => {
                z.remove(&key);
            }
            Some(s) => {
                z.insert(key, Decision { status: s.to_string(), by: by.to_string(), at: now_rfc3339(), note: note.trim().to_string() });
            }
        }
    }
    all.retain(|_, m| !m.is_empty());
    store_json(&path(st), &all)?;
    Ok(())
}

/// Drop a deleted zone's decisions.
pub fn forget_zone(st: &AppState, zone: &str) -> anyhow::Result<()> {
    let _g = LOCK.lock();
    let mut all = load(st);
    if all.remove(zone).is_some() {
        store_json(&path(st), &all)?;
    }
    Ok(())
}

#[derive(Deserialize, Default)]
pub struct ReviewQ {
    /// `pending`, `certified`, `revoked` or empty for all.
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
}

pub async fn get_review(State(st): St, Path(id): Path<String>, Query(q): Query<ReviewQ>) -> Result<Json<Value>, ApiError> {
    if id == crate::analysis::TIER0_ZONE {
        return Err(ApiError::bad("Tier Zero is reviewed with marks, not zone review"));
    }
    let st2 = st.clone();
    tokio::task::spawn_blocking(move || {
        let guard = st2.graph.read_recursive();
        let l = guard.as_ref().ok_or_else(|| ApiError::new(axum::http::StatusCode::CONFLICT, "no graph loaded yet"))?;
        let g = &l.graph;
        let matched = crate::analysis::zone_selector_matches(&st2, g, &id)?;
        let decisions = load(&st2).remove(&id).unwrap_or_default();
        let by_oid: BTreeMap<String, &Decision> = decisions.iter().map(|(k, v)| (k.to_ascii_uppercase(), v)).collect();
        let mut counts = BTreeMap::from([("pending", 0u64), ("certified", 0), ("revoked", 0)]);
        let mut rows: Vec<Value> = Vec::new();
        for &n in matched.iter() {
            let d = by_oid.get(&g.oid(n).to_ascii_uppercase());
            let status = d.map_or("pending", |d| d.status.as_str());
            *counts.entry(if status == "revoked" { "revoked" } else if status == "certified" { "certified" } else { "pending" }).or_default() += 1;
            if q.status.as_deref().is_none_or(|s| s.is_empty() || s == status) {
                rows.push(json!({"node": crate::api::node_json(g, n), "status": status, "decision": d}));
            }
        }
        let total = rows.len();
        let (offset, limit) = (q.offset.unwrap_or(0), q.limit.unwrap_or(200).min(5000));
        let page: Vec<Value> = rows.into_iter().skip(offset).take(limit).collect();
        Ok(Json(json!({"zone": id, "counts": counts, "total": total, "offset": offset, "items": page})))
    })
    .await
    .map_err(|e| ApiError::from(anyhow::anyhow!("task: {e}")))?
}

#[derive(Deserialize)]
pub struct ReviewReq {
    objectids: Vec<String>,
    /// `certified`, `revoked` or `pending` (clears the decision).
    status: String,
    #[serde(default)]
    note: String,
}

pub async fn post_review(State(st): St, Extension(who): Extension<Principal>, Path(id): Path<String>, Json(r): Json<ReviewReq>) -> Result<Json<Value>, ApiError> {
    if id == crate::analysis::TIER0_ZONE {
        return Err(ApiError::bad("Tier Zero is reviewed with marks, not zone review"));
    }
    if !st.zones.lock().iter().any(|z| z.id == id) {
        return Err(ApiError::not_found(format!("no zone '{id}'")));
    }
    if !["certified", "revoked", "pending"].contains(&r.status.as_str()) {
        return Err(ApiError::bad("status must be certified, revoked or pending"));
    }
    if r.objectids.is_empty() || r.objectids.len() > 10_000 || r.note.len() > 1000 {
        return Err(ApiError::bad("1-10000 objectids and a note of at most 1000 characters"));
    }
    let status = (r.status != "pending").then_some(r.status.as_str());
    set_status(&st, &id, &r.objectids, status, &who.username, &r.note)?;
    let n = r.objectids.len();
    // Membership changed (the request itself is audited by the middleware).
    st.zone_cache.lock().retain(|(_, zid), _| *zid != id);
    Ok(Json(json!({"zone": id, "updated": n, "status": r.status})))
}
