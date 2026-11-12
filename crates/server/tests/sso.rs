//! OpenID Connect sign-in against an in-process mock identity provider
//! (discovery, JWKS with key rotation, token endpoint with PKCE check).
//!
//! The RSA keys in `tests/fixtures/` are throwaway test keys.

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ch_server::state::AppState;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

const KEY1: &str = include_str!("fixtures/oidc_test_key1.pem");
const KEY2: &str = include_str!("fixtures/oidc_test_key2.pem");
const N1: &str = "t---znn6j2VGWmhxSYy8XUM8aK9Kf9hXWwwxrkRhrKhOtncNb3iINXw5hWef9cNqBDyB98nh_KVHMn_V9UhlxqMRUT1sKBuzRFd4TKxb8v56rfDwZ7B82WhUfCsuDnJ9CjMJETbKS2s5fDaqp7qZ0Qd0dq7ZxTaJfJO7_dl5_GSUE6IsyTZ4ViU1MdzZhDpqbc7AVmvkbbKZ2TKtajHW1us3V21VXVZL3hNDLh4oH57hTLVppb_g1uG7HFDxOMpckHk1593Rt5ICo6-xdLA4cUivNFrPnUOFezQa1Fa-NjHMFgmkZ2CiW7-uPKo-meM3DEADfSKCe8ashFXRSs99EQ";
const N2: &str = "kiQhtzwUOqgUhgK2uQA3wkfIEG3yuwtn0DTDhh9HSWdqjhHDdLhqBKW0EdASrRm2n_gxQ12E7PWEqbrGKDzFxAILfCCDGsdiDOJVlLS1sQ5ZmGyIM_c0AiDJ-3iiQcq2ct7Gy1TXO5d6CmKT5Trkl1dx6iK1d2Iro8eDLAlyQPzlwkfDR1t5cozg7nmPBb7nnCCjQT0-OTTbLV9uCPJkifeVvDuRP4p0kddflsKkUi-r4hm3xkoZOncsgejr_vpHLybfkUbGgggJiyFRIHDqeM2Eh55HMx2-0VSOlSP7RZ9AVELoKbMSH1kuF6M3tsZ0y7Nkqtv3I9KTghlIh0U3Tw";
const CLIENT_ID: &str = "ch-client";
const CLIENT_SECRET: &str = "ch secret/+";

// ------------------------------------------------------------ mock IdP

struct Grant {
    claims: Value,
    kid: &'static str,
    challenge: String,
    redirect_uri: String,
}

struct Idp {
    issuer: String,
    rotated: AtomicBool,
    grants: Mutex<HashMap<String, Grant>>,
}

type IdpState = State<Arc<Idp>>;

async fn discovery(State(idp): IdpState) -> Json<Value> {
    let i = &idp.issuer;
    Json(json!({
        "issuer": i,
        "authorization_endpoint": format!("{i}/authorize"),
        "token_endpoint": format!("{i}/token"),
        "jwks_uri": format!("{i}/jwks"),
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    }))
}

async fn jwks(State(idp): IdpState) -> Json<Value> {
    let key = |kid: &str, n: &str| json!({"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": "AQAB"});
    let mut keys = vec![key("k1", N1), json!({"kty": "RSA", "use": "enc", "kid": "enc1", "n": N2, "e": "AQAB"})];
    if idp.rotated.load(Ordering::SeqCst) {
        keys.push(key("k2", N2));
    }
    Json(json!({ "keys": keys }))
}

async fn token(State(idp): IdpState, headers: HeaderMap, Form(f): Form<HashMap<String, String>>) -> axum::response::Response {
    let err = |e: &str| (StatusCode::BAD_REQUEST, Json(json!({"error": e, "error_description": "mock"}))).into_response();
    // client_secret_basic with form-encoded parts.
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    let want = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", enc(CLIENT_ID), enc(CLIENT_SECRET)))
    );
    if headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) != Some(want.as_str()) {
        return err("invalid_client");
    }
    if f.get("grant_type").map(String::as_str) != Some("authorization_code") {
        return err("unsupported_grant_type");
    }
    let Some(g) = f.get("code").and_then(|c| idp.grants.lock().unwrap().remove(c)) else {
        return err("invalid_grant");
    };
    let verifier = f.get("code_verifier").cloned().unwrap_or_default();
    if URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) != g.challenge {
        return err("invalid_grant");
    }
    if f.get("redirect_uri") != Some(&g.redirect_uri) {
        return err("invalid_grant");
    }
    let pem = if g.kid == "k1" { KEY1 } else { KEY2 };
    let mut h = Header::new(Algorithm::RS256);
    h.kid = Some(g.kid.into());
    let id_token = jsonwebtoken::encode(&h, &g.claims, &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap()).unwrap();
    Json(json!({"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": id_token})).into_response()
}

async fn start_idp() -> Arc<Idp> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let idp = Arc::new(Idp { issuer, rotated: AtomicBool::new(false), grants: Mutex::new(HashMap::new()) });
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .with_state(idp.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    idp
}

// -------------------------------------------------------------- client

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, HeaderMap, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let (status, headers) = (resp.status(), resp.headers().clone());
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn json_req(method: &str, uri: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri).header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn get_req(uri: &str, token: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().uri(uri).header(header::HOST, "pd.test");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::empty()).unwrap()
}

struct Started {
    state: String,
    nonce: String,
    challenge: String,
    redirect_uri: String,
    cookie: String,
}

async fn start_login(app: &Router, idp: &Idp) -> Started {
    let (s, h, _) = send(app, get_req("/api/v1/auth/oidc/login?return_to=%2F%23%2Ffindings", None)).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let loc = h[header::LOCATION].to_str().unwrap();
    assert!(loc.starts_with(&format!("{}/authorize?", idp.issuer)), "{loc}");
    let q: HashMap<String, String> = url::Url::parse(loc).unwrap().query_pairs().into_owned().collect();
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["client_id"], CLIENT_ID);
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["redirect_uri"], "http://pd.test/api/v1/auth/oidc/callback");
    assert!(q["scope"].split(' ').any(|s| s == "openid"));
    let set_cookie = h[header::SET_COOKIE].to_str().unwrap();
    assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Lax"), "{set_cookie}");
    Started {
        state: q["state"].clone(),
        nonce: q["nonce"].clone(),
        challenge: q["code_challenge"].clone(),
        redirect_uri: q["redirect_uri"].clone(),
        cookie: set_cookie.split(';').next().unwrap().to_string(),
    }
}

fn claims(idp: &Idp, sub: &str, user: &str, groups: &[&str], nonce: &str) -> Value {
    json!({
        "iss": idp.issuer, "aud": CLIENT_ID, "sub": sub, "iat": now(), "exp": now() + 300, "nonce": nonce,
        "preferred_username": user, "email": format!("{user}@corp.example"), "groups": groups,
    })
}

/// Have the IdP "authorise" with `claims` and deliver the callback.
async fn callback(app: &Router, idp: &Idp, st: &Started, claims: Value, kid: &'static str, cookie: Option<&str>) -> String {
    let code = format!("code-{}", st.state);
    idp.grants
        .lock()
        .unwrap()
        .insert(code.clone(), Grant { claims, kid, challenge: st.challenge.clone(), redirect_uri: st.redirect_uri.clone() });
    let mut b = Request::builder().uri(format!("/api/v1/auth/oidc/callback?code={code}&state={}", st.state)).header(header::HOST, "pd.test");
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, format!("theme=dark; {c}"));
    }
    let (s, h, _) = send(app, b.body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let loc = h[header::LOCATION].to_str().unwrap().to_string();
    // Remember the exchange cookie the browser would now hold.
    if let (Some(code), Some(c)) = (loc.strip_prefix("/#/sso?code="), exchange_cookie(&h)) {
        exchange_cookies().lock().unwrap().insert(code.to_string(), c);
    }
    loc
}

/// `ch_oidc=<binding>` from a sign-in response, if it set one.
fn exchange_cookie(h: &HeaderMap) -> Option<String> {
    h.get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|c| c.split(';').next())
        .find(|c| c.starts_with("ch_oidc=") && c.len() > "ch_oidc=".len())
        .map(str::to_string)
}

fn exchange_cookies() -> &'static std::sync::Mutex<std::collections::HashMap<String, String>> {
    static M: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, String>>> = std::sync::OnceLock::new();
    M.get_or_init(Default::default)
}

/// Redeem `code` from the browser that finished the sign-in.
fn exchange_req(code: &str) -> Request<Body> {
    let mut r = json_req("POST", "/api/v1/auth/oidc/exchange", None, json!({ "code": code }));
    if let Some(c) = exchange_cookies().lock().unwrap().get(code) {
        r.headers_mut().insert(header::COOKIE, c.parse().unwrap());
    }
    r
}

async fn full_login(app: &Router, idp: &Idp, sub: &str, user: &str, groups: &[&str]) -> String {
    let st = start_login(app, idp).await;
    let c = claims(idp, sub, user, groups, &st.nonce);
    callback(app, idp, &st, c, "k1", Some(&st.cookie)).await
}

fn sso_code(location: &str) -> String {
    location.strip_prefix("/#/sso?code=").unwrap_or_else(|| panic!("unexpected redirect {location}")).to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn oidc_sign_in_flow() {
    let idp = start_idp().await;
    let data = std::env::temp_dir().join(format!("ch-sso-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::env::set_var("COPPERHOUND_ADMIN_PASSWORD", "test-password");
    let (st, _) = AppState::new(data.clone(), None).unwrap();
    let app = ch_server::router(st);

    // SSO off by default.
    let (_, _, v) = send(&app, get_req("/api/v1/auth/providers", None)).await;
    assert_eq!(v["sso"]["enabled"], false);
    assert_eq!(v["password_login"], true);
    let (_, h, _) = send(&app, get_req("/api/v1/auth/oidc/login", None)).await;
    assert_eq!(h[header::LOCATION], "/#/login?sso_error=disabled");

    let (_, _, v) = send(&app, json_req("POST", "/api/v1/login", None, json!({"username":"admin","password":"test-password"}))).await;
    let admin = v["token"].as_str().unwrap().to_string();

    // Admin configuration; the secret is write-only.
    let cfg = json!({
        "enabled": true, "display_name": "Corp SSO", "issuer": idp.issuer, "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET, "groups_claim": "groups",
        "role_mapping": {"admin": ["ch-admins"], "analyst": ["ch-analysts"], "viewer": []},
        "default_role": "deny",
    });
    let (s, _, v) = send(&app, json_req("PUT", "/api/v1/settings/sso", Some(&admin), cfg.clone())).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["config"].get("client_secret").is_none());
    assert_eq!(v["config"]["client_secret_set"], true);
    assert_eq!(v["config"]["scopes"], json!(["openid", "profile", "email"]));
    // Round-tripping GET output without a secret keeps the secret.
    let mut again = v["config"].clone();
    again["display_name"] = json!("Corp SSO");
    let (s, _, v) = send(&app, json_req("PUT", "/api/v1/settings/sso", Some(&admin), again)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["config"]["client_secret_set"], true);
    let (s, _, v) = send(&app, get_req("/api/v1/settings/sso", Some(&admin))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["redirect_url_effective"], "http://pd.test/api/v1/auth/oidc/callback");
    assert!(!v.to_string().contains(CLIENT_SECRET));
    let (s, _, _) = send(&app, json_req("PUT", "/api/v1/settings/sso", Some(&admin), json!({"enabled": true, "issuer": "http://idp.example", "client_id": "x"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "plain-http non-loopback issuer refused");
    let (_, _, v) = send(&app, json_req("POST", "/api/v1/settings/sso/test", Some(&admin), json!({}))).await;
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["issuer"], idp.issuer.as_str());
    assert_eq!(v["jwks_keys"], 1, "encryption key skipped");
    let (_, _, v) = send(&app, json_req("POST", "/api/v1/settings/sso/test", Some(&admin), json!({"issuer": "http://127.0.0.1:9"}))).await;
    assert_eq!(v["ok"], false);

    let (_, _, v) = send(&app, get_req("/api/v1/auth/providers", None)).await;
    assert_eq!(v["sso"]["enabled"], true);
    assert_eq!(v["sso"]["display_name"], "Corp SSO");
    assert_eq!(v["sso"]["login_url"], "/api/v1/auth/oidc/login");

    // Happy path: analyst via group, one-time exchange code.
    let loc = full_login(&app, &idp, "sub-alice", "alice", &["ch-analysts", "other"]).await;
    let code = sso_code(&loc);
    let (s, _, v) = send(&app, exchange_req(&code)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["username"], "alice");
    assert_eq!(v["role"], "analyst");
    assert_eq!(v["return_to"], "/#/findings");
    let alice = v["token"].as_str().unwrap().to_string();
    let (s, _, _) = send(&app, exchange_req(&code)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "exchange codes are one-time");
    // Login CSRF: a code redeemed from another browser (no binding cookie) is refused.
    let loc = full_login(&app, &idp, "sub-alice", "alice", &["ch-analysts"]).await;
    let (s, _, _) = send(&app, json_req("POST", "/api/v1/auth/oidc/exchange", None, json!({ "code": sso_code(&loc) }))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "exchange code without the browser's binding cookie");
    let (s, _, v) = send(&app, get_req("/api/v1/me", Some(&alice))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["source"], "oidc");
    assert_eq!(v["role"], "analyst");
    // SSO accounts cannot use password sign-in.
    let (s, _, _) = send(&app, json_req("POST", "/api/v1/login", None, json!({"username":"alice","password":""}))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Role is re-evaluated on every sign-in (same subject → same account).
    let loc = full_login(&app, &idp, "sub-alice", "alice-renamed", &["ch-admins"]).await;
    let (_, _, v) = send(&app, exchange_req(&sso_code(&loc))).await;
    assert_eq!((v["username"].as_str(), v["role"].as_str()), (Some("alice"), Some("admin")));

    // Bad nonce.
    let st = start_login(&app, &idp).await;
    let loc = callback(&app, &idp, &st, claims(&idp, "sub-alice", "alice", &["ch-admins"], "forged"), "k1", Some(&st.cookie)).await;
    assert_eq!(loc, "/#/login?sso_error=token");
    // Wrong audience.
    let st = start_login(&app, &idp).await;
    let mut c = claims(&idp, "sub-alice", "alice", &["ch-admins"], &st.nonce);
    c["aud"] = json!("someone-else");
    assert_eq!(callback(&app, &idp, &st, c, "k1", Some(&st.cookie)).await, "/#/login?sso_error=token");
    // Wrong issuer.
    let st = start_login(&app, &idp).await;
    let mut c = claims(&idp, "sub-alice", "alice", &["ch-admins"], &st.nonce);
    c["iss"] = json!("https://evil.example");
    assert_eq!(callback(&app, &idp, &st, c, "k1", Some(&st.cookie)).await, "/#/login?sso_error=token");
    // Expired.
    let st = start_login(&app, &idp).await;
    let mut c = claims(&idp, "sub-alice", "alice", &["ch-admins"], &st.nonce);
    c["exp"] = json!(now() - 600);
    assert_eq!(callback(&app, &idp, &st, c, "k1", Some(&st.cookie)).await, "/#/login?sso_error=token");
    // Signed with a key the IdP does not publish.
    let st = start_login(&app, &idp).await;
    let c = claims(&idp, "sub-alice", "alice", &["ch-admins"], &st.nonce);
    assert_eq!(callback(&app, &idp, &st, c, "k2", Some(&st.cookie)).await, "/#/login?sso_error=token");
    // Missing browser-binding cookie (login CSRF), and state replay.
    let st = start_login(&app, &idp).await;
    let c = claims(&idp, "sub-alice", "alice", &["ch-admins"], &st.nonce);
    assert_eq!(callback(&app, &idp, &st, c.clone(), "k1", None).await, "/#/login?sso_error=state");
    assert_eq!(callback(&app, &idp, &st, c, "k1", Some(&st.cookie)).await, "/#/login?sso_error=state");
    // IdP error.
    let st = start_login(&app, &idp).await;
    let req = Request::builder()
        .uri(format!("/api/v1/auth/oidc/callback?error=access_denied&error_description=nope&state={}", st.state))
        .header(header::COOKIE, &st.cookie)
        .body(Body::empty())
        .unwrap();
    let (_, h, _) = send(&app, req).await;
    assert_eq!(h[header::LOCATION], "/#/login?sso_error=idp_error");
    // Not in any mapped group with default_role deny.
    assert_eq!(full_login(&app, &idp, "sub-bob", "bob", &["unrelated"]).await, "/#/login?sso_error=denied");
    // An IdP user named like the local admin is never linked to it.
    assert_eq!(full_login(&app, &idp, "sub-x", "admin", &["ch-admins"]).await, "/#/login?sso_error=conflict");

    // Key rotation: a token signed with a new kid triggers a JWKS refetch.
    tokio::time::sleep(Duration::from_millis(2100)).await;
    idp.rotated.store(true, Ordering::SeqCst);
    let st = start_login(&app, &idp).await;
    let c = claims(&idp, "sub-carol", "carol", &["ch-analysts"], &st.nonce);
    let loc = callback(&app, &idp, &st, c, "k2", Some(&st.cookie)).await;
    let (s, _, v) = send(&app, exchange_req(&sso_code(&loc))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["username"], "carol");

    // Disabled accounts are refused.
    let (s, _, _) = send(&app, json_req("PUT", "/api/v1/users/carol", Some(&admin), json!({"disabled": true}))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(full_login(&app, &idp, "sub-carol", "carol", &["ch-analysts"]).await, "/#/login?sso_error=disabled_user");

    // Password policy: alice (SSO admin) has signed in, so the break-glass
    // admin password may now be disabled as well.
    let mut strict = cfg.clone();
    strict["allow_password_login"] = json!(false);
    strict["disable_admin_password_login"] = json!(true);
    let (s, _, v) = send(&app, json_req("PUT", "/api/v1/settings/sso", Some(&admin), strict)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, _, v) = send(&app, get_req("/api/v1/auth/providers", None)).await;
    assert_eq!((v["password_login"].as_bool(), v["admin_password_login"].as_bool()), (Some(false), Some(false)));
    let (s, _, _) = send(&app, json_req("POST", "/api/v1/login", None, json!({"username":"admin","password":"test-password"}))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = send(&app, json_req("POST", "/api/v1/login", None, json!({"username":"admin","password":"wrong"}))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "policy is only revealed after a correct password");
    // Demoting the only SSO admin restores break-glass access.
    let (s, _, _) = send(&app, json_req("PUT", "/api/v1/users/alice", Some(&admin), json!({"role": "viewer"}))).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = send(&app, json_req("POST", "/api/v1/login", None, json!({"username":"admin","password":"test-password"}))).await;
    assert_eq!(s, StatusCode::OK);

    // Audit trail.
    let (_, _, v) = send(&app, get_req("/api/v1/audit?action=sso&limit=100", Some(&admin))).await;
    let entries = v["entries"].as_array().unwrap();
    let has = |action: &str, needle: &str| {
        entries.iter().any(|e| e["action"] == action && e["detail"].as_str().unwrap_or("").contains(needle))
    };
    assert!(has("sso-login", "sub=sub-alice"));
    assert!(has("sso-login-failed", "nonce"));
    assert!(has("sso-login-failed", "audience"));
    assert!(has("sso-login-failed", "denied"));
    assert!(has("sso-config-changed", "client_secret"));
    assert!(!v.to_string().contains(CLIENT_SECRET));
    let _ = std::fs::remove_dir_all(&data);
}
