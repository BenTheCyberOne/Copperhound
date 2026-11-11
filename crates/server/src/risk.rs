//! Risk acceptance: a finding can be accepted (with a reason and an optional
//! expiry) so that it no longer counts as open: it is left out of severity
//! counts, new-finding alerts and the report's findings (listed under
//! "Accepted risks" instead). Accepted findings are still computed and shown.
//! An expired acceptance lapses on its own.
//!
//! Stored in `<data>/accepted_risks.json`, keyed by finding id.

use crate::api::{ApiError, St};
use crate::auth::Principal;
use crate::state::{load_json, now_rfc3339, store_json, AppState};
use axum::extract::{Path, State};
use axum::{Extension, Json};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Acceptance {
    pub reason: String,
    pub accepted_by: String,
    pub accepted_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

impl Acceptance {
    pub fn active(&self, now: SystemTime) -> bool {
        self.expires_at.as_deref().and_then(|e| humantime::parse_rfc3339_weak(e).ok()).is_none_or(|e| e > now)
    }
}

static LOCK: Mutex<()> = Mutex::new(());

fn path(st: &AppState) -> std::path::PathBuf {
    st.data_dir.join("accepted_risks.json")
}

/// Every stored acceptance, expired ones included.
pub fn all(st: &AppState) -> BTreeMap<String, Acceptance> {
    load_json(&path(st))
}

/// Acceptances in force now.
pub fn active(st: &AppState) -> BTreeMap<String, Acceptance> {
    let now = SystemTime::now();
    all(st).into_iter().filter(|(_, a)| a.active(now)).collect()
}

#[derive(Deserialize)]
pub struct AcceptReq {
    reason: String,
    /// Days until the acceptance lapses (1–3650); omit for no expiry.
    #[serde(default)]
    expires_days: Option<u64>,
}

pub async fn accept(State(st): St, Extension(who): Extension<Principal>, Path(id): Path<String>, Json(r): Json<AcceptReq>) -> Result<Json<Value>, ApiError> {
    if !ch_analysis::findings::CATALOG.iter().any(|d| d.id == id) {
        return Err(ApiError::not_found(format!("no finding '{id}'")));
    }
    let reason = r.reason.trim();
    if reason.is_empty() || reason.len() > 2000 {
        return Err(ApiError::bad("a reason (1-2000 characters) is required"));
    }
    if r.expires_days.is_some_and(|d| d == 0 || d > 3650) {
        return Err(ApiError::bad("expires_days must be 1-3650"));
    }
    let a = Acceptance {
        reason: reason.to_string(),
        accepted_by: who.username,
        accepted_at: now_rfc3339(),
        expires_at: r.expires_days.map(|d| humantime::format_rfc3339_seconds(SystemTime::now() + Duration::from_secs(d * 86_400)).to_string()),
    };
    {
        let _g = LOCK.lock();
        let mut m = all(&st);
        m.insert(id.clone(), a.clone());
        store_json(&path(&st), &m)?;
    }
    Ok(Json(json!({ "id": id, "acceptance": a })))
}

pub async fn revoke(State(st): St, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let _g = LOCK.lock();
    let mut m = all(&st);
    if m.remove(&id).is_none() {
        return Err(ApiError::not_found(format!("finding '{id}' is not accepted")));
    }
    store_json(&path(&st), &m)?;
    Ok(Json(json!({ "id": id, "acceptance": null })))
}

pub async fn list(State(st): St) -> Json<Value> {
    let now = SystemTime::now();
    Json(json!(all(&st)
        .into_iter()
        .map(|(id, a)| json!({"id": id, "active": a.active(now), "acceptance": a}))
        .collect::<Vec<_>>()))
}

