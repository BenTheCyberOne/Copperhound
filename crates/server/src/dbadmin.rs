//! Database management (admin): selectively clear stored data.
//!
//! `POST /database/clear` with `"confirm": "DELETE"` and any of:
//!
//! * `uploads`: `"all"` or a list of upload names — removes the files;
//! * `graph`: unload the active graph and delete stored graph snapshots;
//! * `rebuild`: afterwards, ingest the remaining uploads (an empty uploads
//!   directory unloads the graph instead);
//! * `marks`: owned / Tier Zero marks made in the UI or API;
//! * `posture_history`: posture snapshots and their stored items;
//! * `saved_queries`, `zones`: user-defined queries and privilege zones.
//!
//! Users, SSO and notification settings and the audit log are never touched.
//! Refused (`409`) while an ingest job is queued or running.

use crate::api::{queue_ingest, ApiError, St};
use crate::audit::AuditEntry;
use crate::auth::Principal;
use crate::state::{now_rfc3339, store_json, store_saved, Analysis, AppState, Marks, ZoneDef};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use ch_store::Graph;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(untagged)]
pub enum Uploads {
    All(String),
    Names(Vec<String>),
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct ClearReq {
    pub confirm: String,
    pub uploads: Option<Uploads>,
    pub graph: bool,
    pub rebuild: bool,
    pub marks: bool,
    pub posture_history: bool,
    pub saved_queries: bool,
    pub zones: bool,
}

/// Unload the active graph and remove every stored graph directory.
fn unload_graph(st: &AppState) -> usize {
    let old = st.graph.write().take();
    st.generation.fetch_add(1, Ordering::SeqCst);
    drop(old); // unmap before deleting
    *st.analysis.write() = Analysis::Idle;
    st.zone_cache.lock().clear();
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir(st.graphs_dir()) {
        for e in rd.flatten() {
            if e.path().is_dir() && std::fs::remove_dir_all(e.path()).is_ok() {
                n += 1;
            }
        }
    }
    n
}

/// Reopen the active graph so marks are re-applied from scratch.
fn reload_graph(st: &Arc<AppState>) {
    let dir = st.graph.read().as_ref().map(|l| l.dir.clone());
    if let Some(dir) = dir {
        match Graph::open(&dir) {
            Ok(g) => {
                st.install(g, dir);
                crate::state::warm_columns(st);
                crate::analysis::start_analysis(st, false);
            }
            Err(e) => tracing::warn!("reloading {}: {e:#}", dir.display()),
        }
    }
}

pub async fn clear(State(st): St, Extension(who): Extension<Principal>, Json(r): Json<ClearReq>) -> Result<Json<Value>, ApiError> {
    if r.confirm != "DELETE" {
        return Err(ApiError::bad(r#"set "confirm": "DELETE" to clear data"#));
    }
    if st.jobs.lock().iter().any(|j| j.state == "queued" || j.state == "running") {
        return Err(ApiError::new(StatusCode::CONFLICT, "an ingest job is running; try again when it has finished"));
    }
    let flags = [
        (r.uploads.is_some(), "uploads"),
        (r.graph, "graph"),
        (r.rebuild, "rebuild"),
        (r.marks, "marks"),
        (r.posture_history, "posture history"),
        (r.saved_queries, "saved queries"),
        (r.zones, "zones"),
    ];
    let rebuild = r.rebuild;
    let st2 = st.clone();
    let done = tokio::task::spawn_blocking(move || -> Result<Value, ApiError> {
        let st = st2;
        let mut out = serde_json::Map::new();
        // Uploads.
        let mut removed: Vec<String> = Vec::new();
        let up = st.uploads_dir();
        match &r.uploads {
            None => {}
            Some(Uploads::All(s)) if s == "all" => {
                for e in std::fs::read_dir(&up).map_err(|e| ApiError::from(anyhow::anyhow!("{e}")))?.flatten() {
                    if e.path().is_file() && std::fs::remove_file(e.path()).is_ok() {
                        removed.push(e.file_name().to_string_lossy().into_owned());
                    }
                }
            }
            Some(Uploads::All(s)) => return Err(ApiError::bad(format!("uploads must be \"all\" or a list of names, not {s:?}"))),
            Some(Uploads::Names(names)) => {
                for n in names {
                    let clean = crate::api::sanitize_upload_name(n).filter(|c| c == n).ok_or_else(|| ApiError::bad(format!("invalid upload name {n:?}")))?;
                    if std::fs::remove_file(up.join(&clean)).is_ok() {
                        removed.push(clean);
                    }
                }
            }
        }
        removed.sort();
        out.insert("uploads_removed".into(), json!(removed));
        if r.marks {
            *st.marks.lock() = Marks::default();
            Marks::default().save(&st.marks_path()).map_err(ApiError::from)?;
            out.insert("marks_cleared".into(), json!(true));
        }
        if r.posture_history {
            let _ = std::fs::remove_file(st.posture_path());
            let _ = std::fs::remove_dir_all(st.data_dir.join("snapshots"));
            out.insert("posture_history_cleared".into(), json!(true));
        }
        if r.saved_queries {
            st.saved.lock().clear();
            store_saved(&st.saved_path(), &[]).map_err(ApiError::from)?;
            out.insert("saved_queries_cleared".into(), json!(true));
        }
        if r.zones {
            st.zones.lock().clear();
            st.zone_cache.lock().clear();
            store_json::<[ZoneDef]>(&st.zones_path(), &[]).map_err(ApiError::from)?;
            let _ = std::fs::remove_file(st.data_dir.join("zone_reviews.json"));
            st.zone_weights.lock().clear();
            let _ = std::fs::remove_file(st.zone_weights_path());
            out.insert("zones_cleared".into(), json!(true));
        }
        if r.graph {
            out.insert("graph_snapshots_removed".into(), json!(unload_graph(&st)));
        } else if r.marks {
            reload_graph(&st);
        }
        Ok(Value::Object(out))
    })
    .await
    .map_err(|e| ApiError::from(anyhow::anyhow!("task: {e}")))??;
    let mut out = done;
    if rebuild {
        let any_left = std::fs::read_dir(st.uploads_dir()).map(|mut d| d.any(|e| e.is_ok_and(|e| e.path().is_file()))).unwrap_or(false);
        if any_left {
            out["job_id"] = json!(queue_ingest(&st, "database-clear")?);
        } else {
            out["graph_snapshots_removed"] = json!(unload_graph(&st));
        }
    }
    let what: Vec<&str> = flags
        .into_iter()
    .filter_map(|(on, n)| on.then_some(n))
    .collect();
    st.audit.record(AuditEntry {
        ts: now_rfc3339(),
        user: who.username,
        role: who.role.as_str().into(),
        action: "database-cleared".into(),
        method: "POST".into(),
        path: "/api/v1/database/clear".into(),
        status: 200,
        ip: None,
        detail: Some(format!("cleared: {}", if what.is_empty() { "nothing".into() } else { what.join(", ") })),
    });
    Ok(Json(out))
}
