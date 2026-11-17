//! Path costs (`ch_engine::cost`): per-kind overrides stored in
//! `<data>/path_costs.json`, and the cheapest-to-Tier-Zero ranking.

use crate::api::{edge_filter, node_json, with_graph_gen, ApiError, ApiResult, St};
use crate::state::{load_json, store_json, AppState};
use axum::extract::{Query, State};
use axum::Json;
use ch_engine::cost::{cost_to_targets, default_cost, CostModel, CostOverrides, Profile, MAX_COST};
use ch_model::{flags, NodeKind};
use serde::Deserialize;
use serde_json::{json, Value};

pub fn path(st: &AppState) -> std::path::PathBuf {
    st.data_dir.join("path_costs.json")
}

pub fn overrides(st: &AppState) -> CostOverrides {
    load_json(&path(st))
}

/// `GET /path-costs` → `{"overrides": {effort, stealth}, "defaults": {effort: {kind: cost}, stealth: {...}},
/// "default_custom": 2, "max": 1000}` (defaults for the loaded graph's kinds).
pub async fn get_costs(State(st): St) -> ApiResult {
    let o = overrides(&st);
    with_graph_gen(st, move |g, _| {
        let mut defaults = json!({"effort": {}, "stealth": {}});
        for p in [Profile::Effort, Profile::Stealth] {
            let m = defaults[p.as_str()].as_object_mut().expect("object");
            for k in 0..g.edge_kind_count() as u16 {
                if g.is_traversable(k) {
                    let name = g.edge_kind_name(k);
                    m.insert(name.to_string(), json!(default_cost(p, name).unwrap_or(ch_engine::cost::DEFAULT_CUSTOM_COST)));
                }
            }
        }
        Ok(Json(json!({"overrides": o, "defaults": defaults, "default_custom": ch_engine::cost::DEFAULT_CUSTOM_COST, "max": MAX_COST})))
    })
    .await
}

/// `PUT /path-costs` (admin) with `{effort: {kind: cost}, stealth: {...}}`; replaces the overrides.
pub async fn put_costs(State(st): St, Json(o): Json<CostOverrides>) -> Result<Json<Value>, ApiError> {
    for map in [&o.effort, &o.stealth] {
        if map.len() > 1000 {
            return Err(ApiError::bad("at most 1000 overrides per profile"));
        }
        for (k, &v) in map {
            if k.is_empty() || k.len() > 128 {
                return Err(ApiError::bad("edge kind names must be 1-128 characters"));
            }
            if v > MAX_COST {
                return Err(ApiError::bad(format!("costs must be 0-{MAX_COST}")));
            }
        }
    }
    store_json(&path(&st), &o)?;
    Ok(Json(json!({"overrides": o})))
}

#[derive(Deserialize)]
pub struct CheapestQ {
    #[serde(default = "effort")]
    profile: String,
    #[serde(default = "fifty")]
    limit: usize,
}

fn effort() -> String {
    "effort".into()
}
fn fifty() -> usize {
    50
}

/// Principals that can act: users, computers and Entra users / service principals.
fn actor(k: NodeKind) -> bool {
    matches!(k, NodeKind::User | NodeKind::Computer | NodeKind::AzUser | NodeKind::AzServicePrincipal)
}

/// `GET /tier0/cheapest?profile=effort&limit=50`: the principals outside Tier
/// Zero with the cheapest path to it, by cost then name, and how many
/// principals reach Tier Zero at each cost.
pub async fn cheapest(State(st): St, Query(q): Query<CheapestQ>) -> ApiResult {
    let profile = Profile::parse(&q.profile).ok_or_else(|| ApiError::bad("profile must be effort or stealth"))?;
    let o = overrides(&st);
    let unified = st.settings.lock().analysis.unified_tier0;
    let limit = q.limit.clamp(1, 1000);
    with_graph_gen(st, move |g, generation| {
        let t = std::time::Instant::now();
        let f = edge_filter(g, false, &[])?.unified_tier0(unified);
        let model = CostModel::new(g, profile, &o);
        let tier0 = g.nodes_with_flag(flags::TIER0);
        let dist = cost_to_targets(g, &tier0, &f, &model);
        let mut rows: Vec<(u64, u32)> = (0..g.node_count() as u32)
            .filter(|&i| dist[i as usize] != u64::MAX && !g.has_flag(i, flags::TIER0) && actor(g.kind(i)))
            .map(|i| (dist[i as usize], i))
            .collect();
        let reachable = rows.len();
        let mut by_cost: std::collections::BTreeMap<u64, u64> = Default::default();
        for (c, _) in &rows {
            *by_cost.entry(*c).or_default() += 1;
        }
        let k = limit.min(rows.len());
        if k > 0 {
            rows.select_nth_unstable_by(k - 1, |a, b| (a.0, g.name(a.1), a.1).cmp(&(b.0, g.name(b.1), b.1)));
            rows.truncate(k);
            rows.sort_by(|a, b| (a.0, g.name(a.1), a.1).cmp(&(b.0, g.name(b.1), b.1)));
        }
        Ok(Json(json!({
            "profile": profile.as_str(),
            "items": rows.iter().map(|&(c, i)| json!({"node": node_json(g, i), "cost": c})).collect::<Vec<_>>(),
            "reachable": reachable,
            "by_cost": by_cost.iter().take(30).map(|(c, n)| json!({"cost": c, "count": n})).collect::<Vec<_>>(),
            "session_reference": model.session_reference(),
            "elapsed_ms": t.elapsed().as_secs_f64() * 1e3,
            "generation": generation,
        })))
    })
    .await
}
