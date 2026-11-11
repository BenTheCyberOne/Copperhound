//! Account, user-management, API-token and audit endpoints.

use crate::api::{ApiError, St};
use crate::auth::{ApiToken, Principal, Role, User};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};

type ApiResult = Result<Json<Value>, ApiError>;

fn bad(e: anyhow::Error) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, format!("{e:#}"))
}

fn token_json(t: &ApiToken) -> Value {
    json!({
        "id": t.id, "name": t.name, "prefix": t.prefix, "created_at": t.created_at,
        "expires_at": t.expires_at, "last_used": t.last_used,
    })
}

fn user_json(u: &User) -> Value {
    json!({
        "username": u.username, "role": u.role, "created_at": u.created_at, "disabled": u.disabled,
        "last_login": u.last_login, "tokens": u.tokens.iter().map(token_json).collect::<Vec<_>>(),
        "source": u.source, "mfa": u.mfa_enabled(),
    })
}

/// Hashing is slow by design; run account changes off the async workers.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f).await.map_err(|e| ApiError::from(anyhow::anyhow!("task: {e}")))
}

// ---------------------------------------------------------------- me

pub async fn me(State(st): St, Extension(who): Extension<Principal>) -> ApiResult {
    let u = st.auth.get(&who.username).ok_or_else(|| ApiError::not_found("no such user"))?;
    let mut v = user_json(&u);
    v["via_token"] = json!(who.via_token);
    v["permissions"] = json!({
        "analyse": who.role >= Role::Viewer,
        "upload": who.role >= Role::Analyst || who.role == Role::Uploader,
        "modify": who.role >= Role::Analyst,
        "admin": who.role >= Role::Admin,
    });
    Ok(Json(v))
}

// ---------------------------------------------------------------- MFA

fn interactive(who: &Principal) -> Result<(), ApiError> {
    if who.via_token {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "sign in interactively to change two-factor settings"));
    }
    Ok(())
}

pub async fn mfa_status(State(st): St, Extension(who): Extension<Principal>) -> ApiResult {
    let (enabled, pending, left) = st.auth.mfa_status(&who.username).ok_or_else(|| ApiError::not_found("no such user"))?;
    Ok(Json(json!({ "enabled": enabled, "pending": pending, "recovery_codes_left": left })))
}

/// Start enrolment: a new secret, as an otpauth URI and a QR code (SVG).
pub async fn mfa_setup(State(st): St, Extension(who): Extension<Principal>) -> ApiResult {
    interactive(&who)?;
    let secret = st.auth.mfa_setup(&who.username).map_err(bad)?;
    let uri = crate::mfa::otpauth_uri("CopperHound", &who.username, &secret);
    Ok(Json(json!({ "secret": secret, "uri": uri, "qr_svg": crate::mfa::qr_svg(&uri) })))
}

#[derive(Deserialize)]
pub struct CodeReq {
    code: String,
}

pub async fn mfa_enable(State(st): St, Extension(who): Extension<Principal>, Json(r): Json<CodeReq>) -> ApiResult {
    interactive(&who)?;
    let codes = st.auth.mfa_enable(&who.username, &r.code).map_err(bad)?;
    Ok(Json(json!({ "enabled": true, "recovery_codes": codes, "note": "store the recovery codes now; they are not shown again" })))
}

pub async fn mfa_disable(State(st): St, Extension(who): Extension<Principal>, Json(r): Json<CodeReq>) -> ApiResult {
    interactive(&who)?;
    st.auth.mfa_disable(&who.username, &r.code).map_err(bad)?;
    Ok(Json(json!({ "enabled": false })))
}

/// Admin: remove a user's two-factor sign-in (lost device).
pub async fn reset_user_mfa(State(st): St, Path(name): Path<String>) -> ApiResult {
    st.auth.mfa_reset(&name).map_err(|e| ApiError::not_found(format!("{e:#}")))?;
    st.auth.drop_sessions_of(&name);
    Ok(Json(json!({ "username": name, "mfa": false })))
}

#[derive(Deserialize)]
pub struct PasswordReq {
    current_password: String,
    new_password: String,
}

pub async fn change_password(State(st): St, Extension(who): Extension<Principal>, Json(r): Json<PasswordReq>) -> ApiResult {
    if who.via_token {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "sign in with a password to change it"));
    }
    let st2 = st.clone();
    blocking(move || st2.auth.change_own_password(&who.username, &r.current_password, &r.new_password))
        .await?
        .map_err(bad)?;
    Ok(Json(json!({ "changed": true, "note": "other sessions were signed out; sign in again" })))
}

#[derive(Deserialize)]
pub struct TokenReq {
    name: String,
    #[serde(default)]
    expires_days: Option<u64>,
}

pub async fn list_my_tokens(State(st): St, Extension(who): Extension<Principal>) -> ApiResult {
    let u = st.auth.get(&who.username).ok_or_else(|| ApiError::not_found("no such user"))?;
    Ok(Json(json!({ "tokens": u.tokens.iter().map(token_json).collect::<Vec<_>>() })))
}

pub async fn create_my_token(State(st): St, Extension(who): Extension<Principal>, Json(r): Json<TokenReq>) -> ApiResult {
    if r.expires_days.is_some_and(|d| d == 0 || d > 3650) {
        return Err(ApiError::bad("expires_days must be 1-3650"));
    }
    let (rec, plain) = st.auth.create_token(&who.username, &r.name, r.expires_days).map_err(bad)?;
    let mut v = token_json(&rec);
    v["token"] = json!(plain);
    // For BloodHound-compatible clients (bhesignature): token id + this key.
    v["bloodhound_key"] = json!(rec.hash);
    v["note"] = json!("store this token now; it is not shown again");
    Ok(Json(v))
}

pub async fn delete_my_token(State(st): St, Extension(who): Extension<Principal>, Path(id): Path<String>) -> ApiResult {
    if !st.auth.delete_token(&who.username, &id).map_err(bad)? {
        return Err(ApiError::not_found("no such token"));
    }
    Ok(Json(json!({ "deleted": id })))
}

// ------------------------------------------------------------- admin

pub async fn list_users(State(st): St) -> ApiResult {
    Ok(Json(json!({
        "users": st.auth.list().iter().map(user_json).collect::<Vec<_>>(),
        "roles": [
            { "id": "uploader", "description": "Upload-only: upload collector files and start an ingest (for collector service accounts and their API tokens); no access to the graph." },
            { "id": "viewer", "description": "Browse, search, query and run analyses; cannot change data." },
            { "id": "analyst", "description": "Viewer plus marks, saved queries, zones, uploads and ingest." },
            { "id": "admin", "description": "Analyst plus users, audit log, settings and snapshot deletion." },
        ],
    })))
}

#[derive(Deserialize)]
pub struct CreateUserReq {
    username: String,
    password: String,
    role: String,
}

pub async fn create_user(State(st): St, Json(r): Json<CreateUserReq>) -> ApiResult {
    let role = Role::parse(&r.role).ok_or_else(|| ApiError::bad("role must be viewer, analyst or admin"))?;
    let st2 = st.clone();
    let u = blocking(move || st2.auth.create(&r.username, &r.password, role)).await?.map_err(bad)?;
    Ok(Json(user_json(&u)))
}

#[derive(Deserialize)]
pub struct UpdateUserReq {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    disabled: Option<bool>,
}

pub async fn update_user(State(st): St, Path(name): Path<String>, Json(r): Json<UpdateUserReq>) -> ApiResult {
    let role = r
        .role
        .as_deref()
        .map(|s| Role::parse(s).ok_or_else(|| ApiError::bad("role must be viewer, analyst or admin")))
        .transpose()?;
    let st2 = st.clone();
    let u = blocking(move || st2.auth.update(&name, role, r.password.as_deref(), r.disabled)).await?.map_err(bad)?;
    Ok(Json(user_json(&u)))
}

pub async fn delete_user(State(st): St, Extension(who): Extension<Principal>, Path(name): Path<String>) -> ApiResult {
    if name == who.username {
        return Err(ApiError::bad("you cannot delete your own account"));
    }
    st.auth.delete(&name).map_err(bad)?;
    Ok(Json(json!({ "deleted": name })))
}

pub async fn revoke_user_token(State(st): St, Path((name, id)): Path<(String, String)>) -> ApiResult {
    if !st.auth.delete_token(&name, &id).map_err(bad)? {
        return Err(ApiError::not_found("no such token"));
    }
    Ok(Json(json!({ "deleted": id })))
}

#[derive(Deserialize)]
pub struct AuditQ {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    action: Option<String>,
}

pub async fn audit(State(st): St, Query(q): Query<AuditQ>) -> ApiResult {
    let limit = q.limit.unwrap_or(200).clamp(1, 10_000);
    let st2 = st.clone();
    let entries = blocking(move || st2.audit.recent(limit, q.user.as_deref(), q.action.as_deref())).await?;
    Ok(Json(json!({ "entries": entries })))
}
