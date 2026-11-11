//! Signed API requests: authenticate with an API token without sending it.
//!
//! ```text
//! Authorization:       CH-HMAC <token id>
//! X-CH-Date:           2026-11-10T12:00:00Z          (within ±5 minutes)
//! X-CH-Content-SHA256: <hex SHA-256 of the body> | UNSIGNED-PAYLOAD
//! X-CH-Signature:      base64(HMAC-SHA256(K, METHOD "\n" PATH?QUERY "\n" DATE "\n" CONTENT-SHA256))
//! K = SHA-256(token)   (32 raw bytes)
//! ```
//!
//! The token itself never crosses the wire, a captured request cannot be
//! altered (method, path, query and — unless `UNSIGNED-PAYLOAD` — the body are
//! signed) and it cannot be replayed: each signature is accepted once within
//! the time window. Bodies are verified up to [`MAX_SIGNED_BODY`]; larger ones
//! (uploads) must use `UNSIGNED-PAYLOAD`.
//!
//! The server stores `K` (the token's SHA-256, also used for bearer lookups),
//! so whoever can read `users.json` can sign requests, exactly as with
//! BloodHound's HMAC keys; bearer tokens are not exposed by that file.

use crate::api::ApiError;
use crate::auth::Principal;
use crate::state::AppState;
use ahash::AHashMap;
use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime};

pub const SCHEME: &str = "CH-HMAC ";
pub const UNSIGNED: &str = "UNSIGNED-PAYLOAD";
/// Largest body whose hash is verified (larger requests use `UNSIGNED-PAYLOAD`).
pub const MAX_SIGNED_BODY: usize = 16 << 20;
const WINDOW: Duration = Duration::from_secs(300);

fn seen() -> &'static Mutex<AHashMap<String, Instant>> {
    static S: OnceLock<Mutex<AHashMap<String, Instant>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(AHashMap::new()))
}

/// The string that is signed.
pub fn canonical(method: &str, path_and_query: &str, date: &str, content_sha256: &str) -> String {
    format!("{method}\n{path_and_query}\n{date}\n{content_sha256}")
}

/// Signature for `token` (clients; also used by tests).
pub fn sign(token: &str, canonical: &str) -> String {
    let key = Sha256::digest(token.as_bytes());
    let mut mac = <Hmac<Sha256>>::new_from_slice(&key).expect("any key length");
    mac.update(canonical.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}

fn header<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok()).map(str::trim)
}

fn unauthorized(msg: &str) -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, format!("signed request rejected: {msg}"))
}

/// Verify a `CH-HMAC` request. Returns the principal and the request with its
/// body restored (it is read to check its hash).
pub async fn authenticate(st: &AppState, req: Request) -> Result<(Principal, Request), ApiError> {
    let auth = header(&req, "authorization").unwrap_or("");
    let token_id = auth.strip_prefix(SCHEME).map(str::trim).filter(|s| !s.is_empty()).ok_or_else(|| unauthorized("no token id"))?.to_string();
    let date = header(&req, "x-ch-date").ok_or_else(|| unauthorized("missing X-CH-Date"))?.to_string();
    let sig = header(&req, "x-ch-signature").ok_or_else(|| unauthorized("missing X-CH-Signature"))?.to_string();
    // Signed as sent (the hex digest is compared case-insensitively below).
    let content = header(&req, "x-ch-content-sha256").ok_or_else(|| unauthorized("missing X-CH-Content-SHA256"))?.to_string();
    let t = humantime::parse_rfc3339_weak(&date).map_err(|_| unauthorized("X-CH-Date is not an RFC 3339 time"))?;
    let now = SystemTime::now();
    let skew = now.duration_since(t).or_else(|e| Ok::<_, ()>(e.duration())).unwrap_or_default();
    if skew > WINDOW {
        return Err(unauthorized("X-CH-Date is more than 5 minutes off"));
    }
    let method = req.method().as_str().to_string();
    let pq = req
        .extensions()
        .get::<axum::extract::OriginalUri>()
        .map(|u| u.0.clone())
        .unwrap_or_else(|| req.uri().clone());
    let pq = pq.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    let key_hex = st.auth.token_hash_by_id(&token_id).ok_or_else(|| unauthorized("unknown, expired or disabled token"))?;
    let key = (0..key_hex.len() / 2).filter_map(|i| u8::from_str_radix(&key_hex[2 * i..2 * i + 2], 16).ok()).collect::<Vec<u8>>();
    let mut mac = <Hmac<Sha256>>::new_from_slice(&key).expect("any key length");
    mac.update(canonical(&method, &pq, &date, &content).as_bytes());
    let given = STANDARD.decode(&sig).map_err(|_| unauthorized("X-CH-Signature is not base64"))?;
    mac.verify_slice(&given).map_err(|_| unauthorized("bad signature"))?;
    // Body hash.
    let (parts, body) = req.into_parts();
    let body = if content == UNSIGNED {
        body
    } else {
        if content.len() != 64 || !content.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(unauthorized("X-CH-Content-SHA256 must be a hex SHA-256 or UNSIGNED-PAYLOAD"));
        }
        let bytes = axum::body::to_bytes(body, MAX_SIGNED_BODY)
            .await
            .map_err(|_| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "signed bodies are limited to 16 MiB; use UNSIGNED-PAYLOAD"))?;
        let h: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
        if !h.eq_ignore_ascii_case(&content) {
            return Err(unauthorized("body does not match X-CH-Content-SHA256"));
        }
        Body::from(bytes)
    };
    // One use per signature within the window.
    {
        let mut s = seen().lock();
        let now = Instant::now();
        s.retain(|_, t| now.duration_since(*t) < WINDOW * 2);
        if s.insert(sig, now).is_some() {
            return Err(unauthorized("replayed request"));
        }
    }
    let who = st.auth.token_principal_by_id(&token_id).ok_or_else(|| unauthorized("unknown, expired or disabled token"))?;
    Ok((who, Request::from_parts(parts, body)))
}
