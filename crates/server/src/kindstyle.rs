//! Shared node kind styles: a colour and an optional icon (1–2 characters,
//! e.g. an emoji) per node kind, for custom (OpenGraph) kinds in particular,
//! so every user sees imported data the same way. Users' own colour choices
//! (web settings) still take precedence in their browser.
//!
//! `GET /kind-styles` (everyone), `PUT /kind-styles` (admin) with the full map,
//! and BloodHound's `POST /api/v2/custom-nodes`
//! (`{"custom_types": {"Kind": {"icon": {"color": "#rrggbb", …}}}}`; Font
//! Awesome icon names are kept but not drawn). Stored in `<data>/kind_styles.json`.

use crate::api::{ApiError, St};
use crate::state::{load_json, store_json, AppState};
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct KindStyle {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// Short glyph shown in badges and the legend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    /// Icon name from BloodHound custom-node definitions (informational).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_name: Option<String>,
}

pub type Styles = BTreeMap<String, KindStyle>;

fn path(st: &AppState) -> std::path::PathBuf {
    st.data_dir.join("kind_styles.json")
}

pub fn load(st: &AppState) -> Styles {
    load_json(&path(st))
}

fn valid_color(c: &str) -> bool {
    c.len() == 7 && c.starts_with('#') && c[1..].chars().all(|x| x.is_ascii_hexdigit())
}

fn validate(m: &Styles) -> Result<(), ApiError> {
    if m.len() > 500 {
        return Err(ApiError::bad("at most 500 kind styles"));
    }
    for (k, s) in m {
        if k.is_empty() || k.len() > 100 {
            return Err(ApiError::bad("kind names must be 1-100 characters"));
        }
        if s.color.as_deref().is_some_and(|c| !valid_color(c)) {
            return Err(ApiError::bad(format!("{k}: color must be #rrggbb")));
        }
        if let Some(i) = &s.icon {
            if i.chars().count() > 4 || i.chars().any(char::is_control) {
                return Err(ApiError::bad(format!("{k}: icon must be at most 2 characters (an emoji or letters)")));
            }
        }
        if s.icon_name.as_deref().is_some_and(|n| n.len() > 64) {
            return Err(ApiError::bad(format!("{k}: icon name too long")));
        }
    }
    Ok(())
}

pub async fn get_styles(State(st): St) -> Json<Value> {
    Json(json!(load(&st)))
}

pub async fn put_styles(State(st): St, Json(m): Json<Styles>) -> Result<Json<Value>, ApiError> {
    let m: Styles = m.into_iter().filter(|(_, s)| s.color.is_some() || s.icon.as_deref().is_some_and(|i| !i.is_empty())).collect();
    validate(&m)?;
    store_json(&path(&st), &m)?;
    Ok(Json(json!(m)))
}

#[derive(Deserialize)]
pub struct CustomNodes {
    custom_types: BTreeMap<String, Value>,
}

/// BloodHound CE `POST /api/v2/custom-nodes`: merge colours (and icon names).
pub async fn bh_custom_nodes(State(st): St, Json(r): Json<CustomNodes>) -> Result<Json<Value>, ApiError> {
    let mut m = load(&st);
    for (kind, def) in r.custom_types {
        let icon = def.get("icon");
        let color = icon.and_then(|i| i.get("color")).and_then(Value::as_str).map(str::to_string).filter(|c| valid_color(c));
        let name = icon.and_then(|i| i.get("name")).and_then(Value::as_str).map(str::to_string);
        let e = m.entry(kind).or_default();
        if color.is_some() {
            e.color = color;
        }
        if name.is_some() {
            e.icon_name = name;
        }
    }
    validate(&m)?;
    store_json(&path(&st), &m)?;
    Ok(Json(json!({"data": m})))
}
