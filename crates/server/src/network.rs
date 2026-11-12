//! Network conduits between zones (docs/OT.md, "Network reachability").
//!
//! `GET /network` (everyone): the configuration, its zones resolved against
//! the loaded graph, and any error. `PUT /network` (admin) replaces it,
//! `DELETE /network` (admin) removes it. `GET /network/exposure?zone=`
//! compares identity exposure with network-feasible exposure. `POST /path`
//! with `"network": true` returns the shortest path the conduits allow.
//! Stored in `<data>/conduits.json`.

use crate::api::{ApiError, St};
use crate::state::{store_json, AppState};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use ch_analysis::network::{build_model, Conduits};
use ch_analysis::simulate::exposure_with;
use ch_analysis::Removal;
use ch_engine::net::{net_exposure, NetModel};
use ch_engine::EdgeFilter;
use ch_store::Graph;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Instant;

fn path(st: &AppState) -> PathBuf {
    st.data_dir.join("conduits.json")
}

/// The stored configuration, if any.
pub fn load(st: &AppState) -> Option<Conduits> {
    let text = std::fs::read_to_string(path(st)).ok()?;
    serde_json::from_str(&text).ok()
}

/// The network model for `g`, or a 400 when none is configured or it does not resolve.
pub fn model(st: &AppState, g: &Graph) -> Result<NetModel, ApiError> {
    let c = load(st).ok_or_else(|| ApiError::bad("no network conduits configured (Admin → Server → Network conduits)"))?;
    build_model(g, &c).map(|(m, _)| m).map_err(|e| ApiError::bad(format!("network conduits: {e}")))
}

fn status(st: &AppState) -> Value {
    let Some(c) = load(st) else {
        return json!({"conduits": null, "zones": [], "error": null});
    };
    let guard = st.graph.read_recursive();
    match guard.as_ref() {
        None => json!({"conduits": c, "zones": [], "error": null}),
        Some(l) => match build_model(&l.graph, &c) {
            Ok((_, zones)) => json!({"conduits": c, "zones": zones, "error": null}),
            Err(e) => json!({"conduits": c, "zones": [], "error": e}),
        },
    }
}

pub async fn get_network(State(st): St) -> Result<Json<Value>, ApiError> {
    tokio::task::spawn_blocking(move || Json(status(&st))).await.map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

pub async fn put_network(State(st): St, Json(c): Json<Conduits>) -> Result<Json<Value>, ApiError> {
    c.validate().map_err(ApiError::bad)?;
    tokio::task::spawn_blocking(move || {
        if let Some(l) = st.graph.read_recursive().as_ref() {
            build_model(&l.graph, &c).map_err(ApiError::bad)?;
        }
        store_json(&path(&st), &c)?;
        Ok(Json(status(&st)))
    })
    .await
    .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

pub async fn delete_network(State(st): St) -> Result<Json<Value>, ApiError> {
    match std::fs::remove_file(path(&st)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
    Ok(Json(json!({"conduits": null, "zones": [], "error": null})))
}

#[derive(Deserialize)]
pub struct ExposureQ {
    zone: Option<String>,
}

/// Identity exposure vs network-feasible exposure toward a zone (default Tier Zero).
pub async fn network_exposure(State(st): St, Query(q): Query<ExposureQ>) -> Result<Json<Value>, ApiError> {
    let zone = q.zone.unwrap_or_else(|| crate::analysis::TIER0_ZONE.to_string());
    tokio::task::spawn_blocking(move || {
        let guard = st.graph.read_recursive();
        let l = guard.as_ref().ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "no graph loaded yet"))?;
        let g = &l.graph;
        let m = model(&st, g)?;
        let members = crate::analysis::zone_members(&st, g, l.generation, &zone)?;
        let t = Instant::now();
        let identity = exposure_with(g, &members, &Removal::default(), 0);
        let f = EdgeFilter::traversable(g);
        let net = net_exposure(g, &members, |_, _, k| f.allows(k), &m);
        Ok(Json(json!({
            "zone": zone,
            "identity_exposed": identity.exposed_principals,
            "network_exposed": net.exposed.len(),
            "total_principals": net.total_principals,
            "elapsed_ms": t.elapsed().as_secs_f64() * 1e3,
        })))
    })
    .await
    .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}
