//! BloodHound CE–compatible API subset under `/api/v2`, so existing upload
//! scripts and tools work against CopperHound unchanged:
//!
//! * `POST /api/v2/login` `{"login_method":"secret","username","secret"}` →
//!   `{"data":{"session_token", "user_id", "auth_expired": false}}`.
//! * `POST /api/v2/file-upload/start` → `{"data":{"id", …}}`;
//!   `POST /api/v2/file-upload/{id}` with a JSON or zip body (one file per
//!   call); `POST /api/v2/file-upload/{id}/end` stores the files as uploads and
//!   starts an ingest. `GET /api/v2/file-upload` lists the upload jobs.
//! * Authentication: `Authorization: Bearer <session or cht_ token>`, or
//!   BloodHound's request signing (`Authorization: bhesignature <token id>`,
//!   `RequestDate`, `Signature`; see [`verify_bh_signature`]) with the token's
//!   BloodHound-compatible key, shown when the token is created.

use crate::api::{ApiError, St};
use crate::auth::{LoginError, Principal};
use crate::state::now_rfc3339;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{header, StatusCode};
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use std::sync::OnceLock;

pub const BH_SCHEME: &str = "bhesignature ";

struct UploadJob {
    id: u64,
    user: String,
    started: String,
    ended: Option<String>,
    files: Vec<String>,
    ingest_job: Option<String>,
}

fn jobs() -> &'static Mutex<(u64, Vec<UploadJob>)> {
    static J: OnceLock<Mutex<(u64, Vec<UploadJob>)>> = OnceLock::new();
    J.get_or_init(|| Mutex::new((0, Vec::new())))
}

fn job_json(j: &UploadJob) -> Value {
    json!({
        "id": j.id, "user_email_address": j.user, "status": if j.ended.is_some() { 2 } else { 0 },
        "status_message": if j.ended.is_some() { "Complete" } else { "Running" },
        "start_time": j.started, "end_time": j.ended, "total_files": j.files.len(), "ingest_job": j.ingest_job,
    })
}

#[derive(Deserialize)]
pub struct LoginReq {
    #[serde(default)]
    login_method: Option<String>,
    username: String,
    secret: String,
}

pub async fn login(State(st): St, Json(r): Json<LoginReq>) -> Result<Json<Value>, ApiError> {
    if r.login_method.as_deref().is_some_and(|m| m != "secret") {
        return Err(ApiError::bad("only login_method \"secret\" is supported"));
    }
    let st2 = st.clone();
    let (u, p) = (r.username.clone(), r.secret);
    let res = tokio::task::spawn_blocking(move || st2.auth.login_with(&u, &p, None, |x| st2.sso.password_login_allowed(&st2.auth, x)))
        .await
        .map_err(|e| ApiError::from(anyhow::anyhow!("login task: {e}")))?;
    match res {
        Ok((token, who)) => Ok(Json(json!({"data": {"user_id": who.username, "auth_expired": false, "session_token": token}}))),
        Err(LoginError::MfaRequired | LoginError::MfaInvalid) => Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "this account uses two-factor sign-in; use an API token (Bearer cht_… or bhesignature) instead",
        )),
        Err(LoginError::Locked(s)) => Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, format!("too many failed attempts; try again in {s} s"))),
        Err(_) => Err(ApiError::new(StatusCode::UNAUTHORIZED, "invalid username or secret")),
    }
}

pub async fn list(Extension(who): Extension<Principal>) -> Json<Value> {
    let j = jobs().lock();
    Json(json!({"data": j.1.iter().rev().filter(|x| x.user == who.username || who.role == crate::auth::Role::Admin).take(100).map(job_json).collect::<Vec<_>>()}))
}

pub async fn start(Extension(who): Extension<Principal>) -> Json<Value> {
    let mut j = jobs().lock();
    j.0 += 1;
    let job = UploadJob { id: j.0, user: who.username, started: now_rfc3339(), ended: None, files: Vec::new(), ingest_job: None };
    let v = job_json(&job);
    j.1.push(job);
    if j.1.len() > 1000 {
        j.1.remove(0);
    }
    Json(json!({"data": v}))
}

fn open_job(id: u64, who: &Principal) -> Result<(), ApiError> {
    let j = jobs().lock();
    match j.1.iter().find(|x| x.id == id) {
        Some(x) if x.user != who.username => Err(ApiError::new(StatusCode::FORBIDDEN, "not your upload job")),
        Some(x) if x.ended.is_some() => Err(ApiError::bad("upload job already ended")),
        Some(_) => Ok(()),
        None => Err(ApiError::not_found("no such upload job")),
    }
}

pub async fn upload_file(State(st): St, Extension(who): Extension<Principal>, Path(id): Path<u64>, req: Request) -> Result<Json<Value>, ApiError> {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;
    open_job(id, &who)?;
    let ctype = req.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
    let ext = if ctype.contains("zip") {
        "zip"
    } else if ctype.contains("json") || ctype.is_empty() {
        "json"
    } else {
        return Err(ApiError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "send application/json or application/zip"));
    };
    let n = jobs().lock().1.iter().find(|x| x.id == id).map_or(0, |x| x.files.len());
    let name = format!("bh-upload-{id}-{:03}.{ext}", n + 1);
    let dir = st.uploads_dir();
    let tmp = dir.join(format!(".{name}.part"));
    let mut f = tokio::fs::File::create(&tmp).await.map_err(|e| ApiError::from(anyhow::anyhow!(e)))?;
    let mut stream = req.into_body().into_data_stream();
    let mut size = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| ApiError::bad(e.to_string()))?;
        size += chunk.len() as u64;
        f.write_all(&chunk).await.map_err(|e| ApiError::from(anyhow::anyhow!(e)))?;
    }
    f.flush().await.map_err(|e| ApiError::from(anyhow::anyhow!(e)))?;
    drop(f);
    if size == 0 {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(ApiError::bad("empty file"));
    }
    tokio::fs::rename(&tmp, dir.join(&name)).await.map_err(|e| ApiError::from(anyhow::anyhow!(e)))?;
    if let Some(j) = jobs().lock().1.iter_mut().find(|x| x.id == id) {
        j.files.push(name.clone());
    }
    crate::collectors::record_upload(&st, &who.username, std::slice::from_ref(&name));
    Ok(Json(json!({"data": {"file": name, "size": size}})))
}

pub async fn end(State(st): St, Extension(who): Extension<Principal>, Path(id): Path<u64>) -> Result<(StatusCode, Json<Value>), ApiError> {
    open_job(id, &who)?;
    let ingest = crate::api::queue_ingest(&st, "api-v2").ok();
    let mut j = jobs().lock();
    let job = j.1.iter_mut().find(|x| x.id == id).ok_or_else(|| ApiError::not_found("no such upload job"))?;
    job.ended = Some(now_rfc3339());
    job.ingest_job = ingest.clone();
    let mut v = job_json(job);
    if ingest.is_none() {
        v["note"] = json!("files stored; an ingest is already running — start another when it finishes");
    }
    Ok((StatusCode::OK, Json(json!({"data": v}))))
}

// ------------------------------------------------------------ signing

/// Unix seconds of an RFC 3339 time with `Z` or a `±HH:MM` offset.
pub fn parse_rfc3339_offset(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, rest) = s.split_once('T').or_else(|| s.split_once(' '))?;
    let mut d = date.split('-');
    let (y, mo, da): (i64, i64, i64) = (d.next()?.parse().ok()?, d.next()?.parse().ok()?, d.next()?.parse().ok()?);
    let (time, off) = if let Some(t) = rest.strip_suffix('Z').or_else(|| rest.strip_suffix('z')) {
        (t, 0i64)
    } else {
        let i = rest.rfind(['+', '-'])?;
        let (t, o) = rest.split_at(i);
        let sign = if o.starts_with('-') { -1 } else { 1 };
        let (oh, om) = o[1..].split_once(':').unwrap_or((&o[1..3.min(o.len())], &o[3.min(o.len())..]));
        (t, sign * (oh.parse::<i64>().ok()? * 3600 + om.parse::<i64>().unwrap_or(0) * 60))
    };
    let mut t = time.split(':');
    let (h, mi): (i64, i64) = (t.next()?.parse().ok()?, t.next()?.parse().ok()?);
    let sec: i64 = t.next().map(|x| x.split('.').next().unwrap_or("0")).unwrap_or("0").parse().ok()?;
    // Days from civil (Howard Hinnant).
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * (mo + if mo > 2 { -3 } else { 9 }) + 2) / 5 + da - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + sec - off)
}

/// BloodHound's request signature: HMAC-SHA256 chained over
/// `METHOD + URI`, then the first 13 characters of `RequestDate`
/// (`YYYY-MM-DDTHH`), then the body; keyed by the token key.
pub fn bh_signature(key: &[u8], method: &str, uri: &str, request_date: &str, body: &[u8]) -> String {
    let step = |k: &[u8], data: &[u8]| {
        let mut m = <Hmac<Sha256>>::new_from_slice(k).expect("any key length");
        m.update(data);
        m.finalize().into_bytes().to_vec()
    };
    let k1 = step(key, format!("{method}{uri}").as_bytes());
    let k2 = step(&k1, request_date.get(..13).unwrap_or(request_date).as_bytes());
    STANDARD.encode(step(&k2, body))
}

/// Verify a `bhesignature` request. The body is read (spooled to disk when
/// large) to check the signature and handed on unchanged.
pub async fn verify_bh_signature(st: &crate::state::AppState, req: Request) -> Result<(Principal, Request), ApiError> {
    use futures_util::StreamExt;
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};
    let unauthorized = |m: &str| ApiError::new(StatusCode::UNAUTHORIZED, format!("signed request rejected: {m}"));
    let (auth, date, sig) = {
        let hv = |n: &str| req.headers().get(n).and_then(|v| v.to_str().ok()).map(|s| s.trim().to_string());
        (hv("authorization"), hv("requestdate"), hv("signature"))
    };
    let token_id = auth.and_then(|a| a.strip_prefix(BH_SCHEME.trim_end()).map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).ok_or_else(|| unauthorized("no token id"))?;
    let date = date.ok_or_else(|| unauthorized("missing RequestDate"))?;
    let sig = sig.ok_or_else(|| unauthorized("missing Signature"))?;
    let t = parse_rfc3339_offset(&date).ok_or_else(|| unauthorized("RequestDate is not an RFC 3339 time"))?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    if (now - t).abs() > 3600 {
        return Err(unauthorized("RequestDate is more than an hour off"));
    }
    let uri = req
        .extensions()
        .get::<axum::extract::OriginalUri>()
        .map(|u| u.0.clone())
        .unwrap_or_else(|| req.uri().clone());
    let uri = uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    let method = req.method().as_str().to_string();
    let key = st.auth.token_hash_by_id(&token_id).ok_or_else(|| unauthorized("unknown, expired or disabled token"))?;
    // Chain up to the body, then stream the body through the last HMAC.
    let step = |k: &[u8], data: &[u8]| {
        let mut m = <Hmac<Sha256>>::new_from_slice(k).expect("any key length");
        m.update(data);
        m.finalize().into_bytes().to_vec()
    };
    let k1 = step(key.as_bytes(), format!("{method}{uri}").as_bytes());
    let k2 = step(&k1, date.get(..13).unwrap_or(&date).as_bytes());
    let mut mac = <Hmac<Sha256>>::new_from_slice(&k2).expect("any key length");
    let (parts, body) = req.into_parts();
    let spool = st.data_dir.join(format!(".bhsig-{}.part", crate::auth::random_hex(8)));
    let mut buf: Vec<u8> = Vec::new();
    let mut file: Option<tokio::fs::File> = None;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| ApiError::bad(e.to_string()))?;
        mac.update(&chunk);
        if file.is_none() && buf.len() + chunk.len() > (8 << 20) {
            let mut f = tokio::fs::File::create(&spool).await.map_err(|e| ApiError::from(anyhow::anyhow!(e)))?;
            f.write_all(&buf).await.map_err(|e| ApiError::from(anyhow::anyhow!(e)))?;
            buf.clear();
            file = Some(f);
        }
        match file.as_mut() {
            Some(f) => f.write_all(&chunk).await.map_err(|e| ApiError::from(anyhow::anyhow!(e)))?,
            None => buf.extend_from_slice(&chunk),
        }
    }
    let given = STANDARD.decode(&sig).map_err(|_| unauthorized("Signature is not base64"))?;
    if mac.verify_slice(&given).is_err() {
        drop(file);
        let _ = tokio::fs::remove_file(&spool).await;
        return Err(unauthorized("bad signature"));
    }
    // No replay cache: the scheme signs only the hour of RequestDate, so
    // identical requests (e.g. polling) legitimately repeat a signature
    // within the hour, as BloodHound accepts. CH-HMAC is the replay-proof
    // alternative (hmac_auth.rs).
    let body = match file {
        None => Body::from(buf),
        Some(mut f) => {
            f.flush().await.map_err(|e| ApiError::from(anyhow::anyhow!(e)))?;
            f.seek(std::io::SeekFrom::Start(0)).await.map_err(|e| ApiError::from(anyhow::anyhow!(e)))?;
            // Unlink now (Unix keeps the open file); Windows cleans up at the next start.
            let _ = std::fs::remove_file(&spool);
            Body::from_stream(tokio_util::io::ReaderStream::new(f))
        }
    };
    let who = st.auth.token_principal_by_id(&token_id).ok_or_else(|| unauthorized("unknown, expired or disabled token"))?;
    Ok((who, Request::from_parts(parts, body)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(parse_rfc3339_offset("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_offset("2024-03-01T12:30:15.123456+02:00"), Some(1_709_289_015));
        assert_eq!(parse_rfc3339_offset("2024-03-01T10:30:15Z"), Some(1_709_289_015));
        assert_eq!(parse_rfc3339_offset("2024-03-01T05:30:15-05:00"), Some(1_709_289_015));
        assert!(parse_rfc3339_offset("nope").is_none());
    }
}


