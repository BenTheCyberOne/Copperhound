//! OpenID Connect single sign-on (authorization-code flow with PKCE, `state`
//! and `nonce`). Tested against the shapes used by Entra ID, Okta, Keycloak
//! and Google.
//!
//! Flow:
//!
//! 1. `GET /api/v1/auth/oidc/login` stores a pending login (state, nonce, PKCE
//!    verifier, redirect URI, `return_to`) in memory for 10 minutes, sets an
//!    HttpOnly cookie that binds it to this browser (login-CSRF protection),
//!    and redirects to the IdP's authorization endpoint.
//! 2. `GET /api/v1/auth/oidc/callback` consumes the pending login (one-time),
//!    checks the browser-binding cookie, redeems the code at the token
//!    endpoint (with the PKCE verifier), validates the ID token (signature via
//!    the discovery JWKS, refetched on an unknown `kid`; `iss`, `aud`/`azp`,
//!    `exp`/`nbf` with 60 s skew, `nonce`), maps groups to a role, and
//!    just-in-time creates/updates the `source: "oidc"` account.
//! 3. The browser is redirected to `/#/sso?code=<one-time code>`; the SPA
//!    trades it at `POST /api/v1/auth/oidc/exchange` (valid 60 s, once) for a
//!    normal session token. The token never appears in a URL or log.
//!
//! Configuration lives in `<data>/sso.json` (admin API `/settings/sso`);
//! `COPPERHOUND_OIDC_*` environment variables override individual fields.
//!
//! Password sign-in policy (break-glass): see [`Sso::password_login_allowed`].

use crate::api::{client_ip, ApiError, St};
use crate::audit::AuditEntry;
use crate::auth::{random_hex, Auth, OidcLinkError, Principal, Role, User, UserSource, ADMIN_USER};
use crate::state::{now_rfc3339, AppState};
use ahash::AHashMap;
use anyhow::{anyhow, bail, Context, Result};
use axum::body::{Body, Bytes};
use axum::extract::{Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use jsonwebtoken::jwk::{Jwk, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The server itself terminates TLS (see `tls.rs`): request origins are https.
pub static TLS_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Route of the redirect URI (relative to the public base URL).
pub const CALLBACK_PATH: &str = "/api/v1/auth/oidc/callback";
const LOGIN_TTL: Duration = Duration::from_secs(10 * 60);
const EXCHANGE_TTL: Duration = Duration::from_secs(60);
/// Bound on in-flight logins / unredeemed exchange codes (oldest evicted).
const MAX_PENDING: usize = 10_000;
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);
const JWKS_TTL: Duration = Duration::from_secs(3600);
/// Minimum interval between JWKS refetches triggered by an unknown `kid`.
const JWKS_MIN_REFRESH: Duration = Duration::from_secs(2);
const CLOCK_SKEW_SECS: u64 = 60;
const MAX_DOC_BYTES: usize = 1 << 20;
const COOKIE: &str = "ch_oidc";
const ENV_PREFIX: &str = "COPPERHOUND_OIDC_";
const ALLOWED_ALGS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

// ------------------------------------------------------------- config

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RoleMapping {
    /// Group / app-role values (case-insensitive) granting each role; the
    /// highest matching role wins.
    pub admin: Vec<String>,
    pub analyst: Vec<String>,
    pub viewer: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SsoConfig {
    pub enabled: bool,
    /// Button label on the sign-in page.
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    /// Never returned by the API (`client_secret_set` instead).
    pub client_secret: String,
    /// Empty: `<COPPERHOUND_PUBLIC_URL or request origin>/api/v1/auth/oidc/callback`.
    pub redirect_url: String,
    pub scopes: Vec<String>,
    /// Claim used as the CopperHound username; falls back to `email`, then `sub`.
    pub username_claim: String,
    /// Claim(s) holding groups or app roles; comma-separated, dotted paths
    /// allowed (`groups`, `groups,roles`, `realm_access.roles`).
    pub groups_claim: String,
    pub role_mapping: RoleMapping,
    /// Role for users matching no mapping: `viewer`, `analyst` or `deny`.
    pub default_role: String,
    /// If set, only users whose (verified) `email` is in one of these domains.
    pub allowed_email_domains: Vec<String>,
    /// Local (non-SSO) accounts other than the built-in `admin` may sign in
    /// with a password.
    pub allow_password_login: bool,
    /// Also refuse password sign-in for the built-in `admin`. Only accepted
    /// with `allow_password_login: false` once an SSO admin has signed in,
    /// and only enforced while that remains true.
    pub disable_admin_password_login: bool,
    /// Allow `http://` IdP URLs other than loopback (lab use only).
    pub allow_insecure_http: bool,
}

impl Default for SsoConfig {
    fn default() -> Self {
        SsoConfig {
            enabled: false,
            display_name: "Single sign-on".into(),
            issuer: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            redirect_url: String::new(),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            username_claim: "preferred_username".into(),
            groups_claim: "groups".into(),
            role_mapping: RoleMapping::default(),
            default_role: "deny".into(),
            allowed_email_domains: Vec::new(),
            allow_password_login: true,
            disable_admin_password_login: false,
            allow_insecure_http: false,
        }
    }
}

impl SsoConfig {
    /// Enabled and minimally configured.
    pub fn is_usable(&self) -> bool {
        self.enabled && !self.issuer.trim().is_empty() && !self.client_id.trim().is_empty()
    }

    fn normalize(&mut self) {
        let d = SsoConfig::default();
        for s in [&mut self.issuer, &mut self.client_id, &mut self.redirect_url, &mut self.display_name] {
            *s = s.trim().to_string();
        }
        if self.display_name.is_empty() {
            self.display_name = d.display_name;
        }
        if self.username_claim.trim().is_empty() {
            self.username_claim = d.username_claim;
        }
        if self.groups_claim.trim().is_empty() {
            self.groups_claim = d.groups_claim;
        }
        self.default_role = self.default_role.trim().to_ascii_lowercase();
        if self.default_role.is_empty() {
            self.default_role = d.default_role;
        }
        self.scopes.retain(|s| !s.trim().is_empty());
        if !self.scopes.iter().any(|s| s == "openid") {
            self.scopes.insert(0, "openid".into());
        }
        for l in [&mut self.role_mapping.admin, &mut self.role_mapping.analyst, &mut self.role_mapping.viewer, &mut self.allowed_email_domains] {
            for g in l.iter_mut() {
                *g = g.trim().to_string();
            }
            l.retain(|g| !g.is_empty());
        }
    }
}

fn split_groups(s: &str) -> Vec<String> {
    s.split([',', ';']).map(str::trim).filter(|x| !x.is_empty()).map(String::from).collect()
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Overlay `COPPERHOUND_OIDC_*` variables; returns the overridden field names.
pub fn apply_env(c: &mut SsoConfig, get: impl Fn(&str) -> Option<String>) -> Vec<&'static str> {
    let var = |name: &str| get(&format!("{ENV_PREFIX}{name}")).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let mut set = Vec::new();
    macro_rules! text {
        ($env:literal, $field:ident) => {
            if let Some(v) = var($env) {
                c.$field = v;
                set.push(stringify!($field));
            }
        };
    }
    text!("ISSUER", issuer);
    text!("CLIENT_ID", client_id);
    text!("CLIENT_SECRET", client_secret);
    text!("REDIRECT_URL", redirect_url);
    text!("USERNAME_CLAIM", username_claim);
    text!("GROUPS_CLAIM", groups_claim);
    text!("DEFAULT_ROLE", default_role);
    text!("DISPLAY_NAME", display_name);
    if let Some(v) = var("SCOPES") {
        c.scopes = v.split([',', ' ']).filter(|s| !s.is_empty()).map(String::from).collect();
        set.push("scopes");
    }
    for (env, list, name) in [
        ("ADMIN_GROUPS", &mut c.role_mapping.admin, "role_mapping.admin"),
        ("ANALYST_GROUPS", &mut c.role_mapping.analyst, "role_mapping.analyst"),
        ("VIEWER_GROUPS", &mut c.role_mapping.viewer, "role_mapping.viewer"),
        ("ALLOWED_EMAIL_DOMAINS", &mut c.allowed_email_domains, "allowed_email_domains"),
    ] {
        if let Some(v) = var(env) {
            *list = split_groups(&v);
            set.push(name);
        }
    }
    for (env, flag, name) in [
        ("ALLOW_PASSWORD_LOGIN", &mut c.allow_password_login, "allow_password_login"),
        ("ALLOW_INSECURE_HTTP", &mut c.allow_insecure_http, "allow_insecure_http"),
    ] {
        if let Some(b) = var(env).as_deref().and_then(parse_bool) {
            *flag = b;
            set.push(name);
        }
    }
    match var("ENABLED").as_deref().and_then(parse_bool) {
        Some(b) => {
            c.enabled = b;
            set.push("enabled");
        }
        // Setting the issuer in the environment turns SSO on.
        None if set.contains(&"issuer") => {
            c.enabled = true;
            set.push("enabled");
        }
        None => {}
    }
    set
}

fn is_loopback(u: &url::Url) -> bool {
    match u.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Parse an absolute URL; `https` unless loopback or explicitly allowed.
fn check_url(u: &str, allow_http: bool, what: &str) -> Result<url::Url> {
    let url = url::Url::parse(u.trim()).map_err(|e| anyhow!("{what} {u:?} is not a valid URL: {e}"))?;
    if url.host_str().is_none_or(str::is_empty) {
        bail!("{what} {u:?} has no host");
    }
    match url.scheme() {
        "https" => Ok(url),
        "http" if allow_http || is_loopback(&url) => Ok(url),
        "http" => bail!("{what} must use https (or enable allow_insecure_http)"),
        s => bail!("{what} has unsupported scheme {s:?}"),
    }
}

/// Check an effective configuration before saving it.
pub fn validate_config(c: &SsoConfig, sso_admin_signed_in: bool) -> Result<(), String> {
    if !["viewer", "analyst", "deny"].contains(&c.default_role.as_str()) {
        return Err("default_role must be viewer, analyst or deny".into());
    }
    if c.display_name.chars().count() > 64 {
        return Err("display_name must be at most 64 characters".into());
    }
    let n = c.role_mapping.admin.len() + c.role_mapping.analyst.len() + c.role_mapping.viewer.len();
    if n > 1000 || c.allowed_email_domains.len() > 1000 {
        return Err("too many role mapping or domain entries".into());
    }
    if c.enabled {
        if c.issuer.is_empty() || c.client_id.is_empty() {
            return Err("issuer and client_id are required when single sign-on is enabled".into());
        }
        check_url(&c.issuer, c.allow_insecure_http, "issuer").map_err(|e| e.to_string())?;
        if !c.redirect_url.is_empty() {
            let u = url::Url::parse(&c.redirect_url).map_err(|e| format!("redirect_url is not a valid URL: {e}"))?;
            if !matches!(u.scheme(), "https" | "http") || !u.path().ends_with(CALLBACK_PATH) {
                return Err(format!("redirect_url must be an http(s) URL ending in {CALLBACK_PATH}"));
            }
        }
    }
    if c.disable_admin_password_login {
        if !c.enabled || c.allow_password_login {
            return Err("disable_admin_password_login requires single sign-on enabled and allow_password_login false".into());
        }
        if !sso_admin_signed_in {
            return Err("disable_admin_password_login: an admin must first sign in successfully through single sign-on".into());
        }
    }
    Ok(())
}

// ------------------------------------------------------- pure helpers

fn claim_path<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    if let Some(v) = claims.get(path) {
        return Some(v);
    }
    let mut cur = claims;
    for p in path.split('.') {
        cur = cur.get(p)?;
    }
    Some(cur)
}

/// Group / role values from the configured claim(s).
pub fn extract_groups(claims: &Value, groups_claim: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in groups_claim.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        match claim_path(claims, name) {
            Some(Value::Array(a)) => out.extend(a.iter().filter_map(Value::as_str).map(String::from)),
            Some(Value::String(s)) => out.push(s.clone()),
            _ => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Highest mapped role; `None` means deny.
pub fn map_role(c: &SsoConfig, groups: &[String]) -> Option<Role> {
    let has = |list: &[String]| list.iter().any(|m| groups.iter().any(|g| g.eq_ignore_ascii_case(m.trim())));
    if has(&c.role_mapping.admin) {
        Some(Role::Admin)
    } else if has(&c.role_mapping.analyst) {
        Some(Role::Analyst)
    } else if has(&c.role_mapping.viewer) {
        Some(Role::Viewer)
    } else {
        // `admin` is deliberately not accepted as a default role.
        match c.default_role.as_str() {
            "viewer" => Some(Role::Viewer),
            "analyst" => Some(Role::Analyst),
            _ => None,
        }
    }
}

fn sanitize_username(s: &str) -> String {
    s.trim()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "._-@".contains(c) { c } else { '_' })
        .take(64)
        .collect()
}

/// Username from `username_claim`, then `email`, then `sub`.
pub fn pick_username(claims: &Value, username_claim: &str) -> Option<String> {
    [username_claim, "email", "sub"]
        .iter()
        .filter_map(|n| claim_path(claims, n).and_then(Value::as_str))
        .map(sanitize_username)
        .find(|u| !u.is_empty() && u.chars().any(|c| c.is_ascii_alphanumeric()))
}

/// Only same-origin relative paths (`/…`, not `//host` or `/\host`).
pub fn valid_return_to(s: &str) -> bool {
    s.len() <= 512
        && s.starts_with('/')
        && !s.starts_with("//")
        && !s.contains('\\')
        && !s.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// `allowed_email_domains` check on `claims.email` (also used by SAML).
pub fn email_domain_check(c: &SsoConfig, claims: &Value) -> Result<(), String> {
    email_domain_allowed(c, claims)
}

fn email_domain_allowed(c: &SsoConfig, claims: &Value) -> Result<(), String> {
    if c.allowed_email_domains.is_empty() {
        return Ok(());
    }
    let email = claims.get("email").and_then(Value::as_str).ok_or("no email claim (allowed_email_domains is set)")?;
    let verified = claims.get("email_verified");
    if verified == Some(&Value::Bool(false)) || verified.and_then(Value::as_str) == Some("false") {
        return Err(format!("email {email} is not verified"));
    }
    let domain = email.rsplit_once('@').map(|(_, d)| d.to_ascii_lowercase()).unwrap_or_default();
    if c.allowed_email_domains.iter().any(|d| d.trim_start_matches('@').eq_ignore_ascii_case(&domain)) {
        Ok(())
    } else {
        Err(format!("email domain {domain:?} is not allowed"))
    }
}

/// Path prefix the app is served under, from the redirect URI.
fn app_base_path(redirect_uri: &str) -> String {
    url::Url::parse(redirect_uri)
        .ok()
        .and_then(|u| u.path().strip_suffix(CALLBACK_PATH).map(|p| p.trim_end_matches('/').to_string()))
        .unwrap_or_default()
}

pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

fn truncate(s: &str, n: usize) -> String {
    let s: String = s.chars().filter(|c| !c.is_control()).take(n).collect();
    s
}

// -------------------------------------------------------------- state

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProviderMeta {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    pub code_challenge_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub scopes_supported: Option<Vec<String>>,
}

#[derive(Default)]
struct JwksCache {
    keys: Vec<Jwk>,
    fetched: Option<Instant>,
}

struct Provider {
    /// Configured issuer this was discovered for.
    issuer_cfg: String,
    meta: ProviderMeta,
    fetched: Instant,
    jwks: Mutex<JwksCache>,
}

struct Pending {
    nonce: String,
    verifier: String,
    redirect_uri: String,
    return_to: String,
    /// Value of the browser-binding cookie.
    binding: String,
    created: Instant,
}

#[derive(Debug, Clone)]
pub struct Exchange {
    pub username: String,
    pub return_to: String,
    /// Value of the browser cookie set with the code: a code redeemed by
    /// another browser (login CSRF with an attacker's code) is refused.
    binding: String,
    created: Instant,
}

pub struct Sso {
    path: PathBuf,
    file: RwLock<SsoConfig>,
    /// `COPPERHOUND_OIDC_*` snapshot taken at start-up.
    env: AHashMap<String, String>,
    /// `COPPERHOUND_PUBLIC_URL`, used to derive the redirect URI.
    public_url: Option<String>,
    /// `COPPERHOUND_SSO_BREAK_GLASS`: always allow the built-in admin's password.
    break_glass_env: bool,
    http: reqwest::Client,
    provider: Mutex<Option<Arc<Provider>>>,
    pending: Mutex<AHashMap<String, Pending>>,
    exchanges: Mutex<AHashMap<String, Exchange>>,
    /// SAML 2.0 service provider (`<data>/saml.json`).
    pub saml: crate::saml::Saml,
}

fn http_client(ca_file: Option<&str>) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("CopperHound/", env!("CARGO_PKG_VERSION")));
    if let Some(f) = ca_file {
        let pem = std::fs::read(f).with_context(|| format!("reading COPPERHOUND_OIDC_CA_FILE {f}"))?;
        for c in reqwest::Certificate::from_pem_bundle(&pem).context("parsing COPPERHOUND_OIDC_CA_FILE")? {
            b = b.add_root_certificate(c);
        }
    }
    b.build().context("building HTTP client")
}

/// Bounded one-time map: drop expired entries, evict the oldest when full.
fn insert_bounded<T>(m: &mut AHashMap<String, T>, key: String, v: T, created: impl Fn(&T) -> Instant, ttl: Duration) {
    let now = Instant::now();
    m.retain(|_, x| now.duration_since(created(x)) < ttl);
    if m.len() >= MAX_PENDING {
        if let Some(oldest) = m.iter().min_by_key(|(_, x)| created(x)).map(|(k, _)| k.clone()) {
            m.remove(&oldest);
        }
    }
    m.insert(key, v);
}

/// Why a sign-in failed: `code` goes to the browser, `reason` to the audit log.
struct Fail {
    code: &'static str,
    reason: String,
    user: String,
}

fn fail(code: &'static str, reason: impl Into<String>) -> Fail {
    Fail { code, reason: reason.into(), user: String::new() }
}

struct Done {
    code: String,
    /// Exchange cookie value binding `code` to this browser.
    binding: String,
    username: String,
    role: Role,
    detail: String,
}

impl Sso {
    pub fn init(data_dir: &Path) -> Result<Sso> {
        let path = data_dir.join("sso.json");
        let file: SsoConfig = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).with_context(|| format!("parsing {}", path.display()))?,
            Err(_) => SsoConfig::default(),
        };
        let env: AHashMap<String, String> = std::env::vars().filter(|(k, _)| k.starts_with(ENV_PREFIX)).collect();
        let public_url = std::env::var("COPPERHOUND_PUBLIC_URL").ok().map(|s| s.trim().trim_end_matches('/').to_string()).filter(|s| !s.is_empty());
        let break_glass_env = std::env::var("COPPERHOUND_SSO_BREAK_GLASS").ok().as_deref().and_then(parse_bool).unwrap_or(false);
        let http = http_client(env.get("COPPERHOUND_OIDC_CA_FILE").map(String::as_str))?;
        let mut s = Sso::from_parts(path, file, env, public_url, break_glass_env, http);
        s.saml = crate::saml::Saml::init(data_dir)?;
        Ok(s)
    }

    fn from_parts(
        path: PathBuf,
        file: SsoConfig,
        env: AHashMap<String, String>,
        public_url: Option<String>,
        break_glass_env: bool,
        http: reqwest::Client,
    ) -> Sso {
        Sso {
            path,
            file: RwLock::new(file),
            env,
            public_url,
            break_glass_env,
            http,
            provider: Mutex::new(None),
            pending: Mutex::new(AHashMap::new()),
            exchanges: Mutex::new(AHashMap::new()),
            saml: crate::saml::Saml::with(PathBuf::new(), crate::saml::SamlConfig::default()),
        }
    }

    /// Stored configuration with the environment applied.
    pub fn effective(&self) -> SsoConfig {
        let mut c = self.file.read().clone();
        apply_env(&mut c, |k| self.env.get(k).cloned());
        c.normalize();
        c
    }

    pub fn env_overrides(&self) -> Vec<&'static str> {
        apply_env(&mut SsoConfig::default(), |k| self.env.get(k).cloned())
    }

    fn save(&self, c: SsoConfig) -> Result<()> {
        if !self.path.as_os_str().is_empty() {
            let tmp = self.path.with_extension("json.tmp");
            std::fs::write(&tmp, serde_json::to_vec_pretty(&c)?)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
            }
            std::fs::rename(&tmp, &self.path)?;
        }
        *self.file.write() = c;
        *self.provider.lock() = None;
        Ok(())
    }

    // ----------------------------------------------------- password policy

    /// Password sign-in policy.
    ///
    /// * SSO accounts never sign in with a password.
    /// * SSO off (or incomplete): every local account may.
    /// * SSO on: local accounts other than the built-in `admin` only with
    ///   `allow_password_login`.
    /// * The built-in `admin` is the break-glass account and keeps password
    ///   sign-in unless `disable_admin_password_login` is set, password login
    ///   is off, **and** an enabled SSO admin has signed in at least once
    ///   (re-checked on every attempt, so disabling or demoting the last SSO
    ///   admin restores it). `COPPERHOUND_SSO_BREAK_GLASS=1` always restores it.
    pub fn password_login_allowed(&self, auth: &Auth, u: &User) -> bool {
        if u.source != UserSource::Local {
            return false;
        }
        let c = self.effective();
        if !self.any_sso_usable(&c) {
            return true;
        }
        if u.username == ADMIN_USER {
            return self.admin_password_ok(&c, auth);
        }
        c.allow_password_login
    }

    /// OIDC or SAML sign-on is enabled and configured.
    pub fn any_sso_usable(&self, c: &SsoConfig) -> bool {
        c.is_usable() || self.saml.effective().is_usable()
    }

    pub fn admin_password_login_allowed(&self, auth: &Auth) -> bool {
        self.admin_password_ok(&self.effective(), auth)
    }

    fn admin_password_ok(&self, c: &SsoConfig, auth: &Auth) -> bool {
        self.break_glass_env
            || !self.any_sso_usable(c)
            || c.allow_password_login
            || !c.disable_admin_password_login
            || !auth.sso_admin_has_signed_in()
    }

    // ------------------------------------------------- one-time stores

    fn put_pending(&self, state: String, p: Pending) {
        insert_bounded(&mut self.pending.lock(), state, p, |p| p.created, LOGIN_TTL);
    }

    fn take_pending(&self, state: &str, now: Instant) -> Option<Pending> {
        let p = self.pending.lock().remove(state)?;
        (now.duration_since(p.created) < LOGIN_TTL).then_some(p)
    }

    /// Store a one-time exchange code for a signed-in user. Returns the code
    /// and the browser binding to set as the exchange cookie.
    pub fn put_exchange(&self, username: &str, return_to: &str) -> (String, String) {
        let code = random_hex(32);
        let binding = random_hex(32);
        let x = Exchange { username: username.into(), return_to: return_to.into(), binding: binding.clone(), created: Instant::now() };
        insert_bounded(&mut self.exchanges.lock(), code.clone(), x, |x| x.created, EXCHANGE_TTL);
        (code, binding)
    }

    /// Redeem an exchange code (once; valid for 60 s) from the browser that
    /// holds its binding cookie.
    pub fn take_exchange(&self, code: &str, binding: Option<&str>, now: Instant) -> Option<Exchange> {
        let x = self.exchanges.lock().remove(code)?;
        (now.duration_since(x.created) < EXCHANGE_TTL && binding == Some(x.binding.as_str())).then_some(x)
    }

    // ------------------------------------------------------------ HTTP

    async fn get_json(&self, url: &str) -> Result<Value> {
        let resp = self
            .http
            .get(url)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .with_context(|| format!("fetching {url}"))?;
        let status = resp.status();
        let body = read_limited(resp).await?;
        if !status.is_success() {
            bail!("{url} returned HTTP {status}");
        }
        serde_json::from_slice(&body).with_context(|| format!("{url} did not return JSON"))
    }

    /// Fetch and check the discovery document (not cached).
    pub async fn discover(&self, issuer: &str, allow_http: bool) -> Result<ProviderMeta> {
        let base = issuer.trim().trim_end_matches('/');
        check_url(base, allow_http, "issuer")?;
        let url = format!("{base}/.well-known/openid-configuration");
        let meta: ProviderMeta = serde_json::from_value(self.get_json(&url).await?).context("invalid discovery document")?;
        if meta.issuer.trim_end_matches('/') != base {
            bail!("discovery document issuer {:?} does not match the configured issuer {base:?}", meta.issuer);
        }
        check_url(&meta.authorization_endpoint, allow_http, "authorization_endpoint")?;
        check_url(&meta.token_endpoint, allow_http, "token_endpoint")?;
        check_url(&meta.jwks_uri, allow_http, "jwks_uri")?;
        Ok(meta)
    }

    async fn provider(&self, c: &SsoConfig) -> Result<Arc<Provider>> {
        if let Some(p) = self.provider.lock().clone() {
            if p.issuer_cfg == c.issuer && p.fetched.elapsed() < DISCOVERY_TTL {
                return Ok(p);
            }
        }
        let meta = self.discover(&c.issuer, c.allow_insecure_http).await?;
        let p = Arc::new(Provider { issuer_cfg: c.issuer.clone(), meta, fetched: Instant::now(), jwks: Mutex::new(JwksCache::default()) });
        *self.provider.lock() = Some(p.clone());
        Ok(p)
    }

    /// Signature keys from a JWKS (encryption keys and unknown key types skipped).
    pub async fn fetch_jwks(&self, uri: &str) -> Result<Vec<Jwk>> {
        let v = self.get_json(uri).await?;
        let keys = v.get("keys").and_then(Value::as_array).ok_or_else(|| anyhow!("JWKS has no keys array"))?;
        Ok(keys
            .iter()
            .filter_map(|k| serde_json::from_value::<Jwk>(k.clone()).ok())
            .filter(|k| !matches!(k.common.public_key_use, Some(PublicKeyUse::Encryption)))
            .collect())
    }

    /// Candidate keys for `kid`; refetches the JWKS when it is stale or the
    /// `kid` is unknown (key rotation), at most every [`JWKS_MIN_REFRESH`].
    async fn signing_keys(&self, prov: &Provider, kid: Option<&str>) -> Result<Vec<Jwk>> {
        let select = |keys: &[Jwk]| -> Vec<Jwk> {
            keys.iter().filter(|k| kid.is_none() || k.common.key_id.as_deref() == kid).cloned().collect()
        };
        let (cached, fresh, may_refetch) = {
            let c = prov.jwks.lock();
            (
                select(&c.keys),
                c.fetched.is_some_and(|f| f.elapsed() < JWKS_TTL),
                c.fetched.is_none_or(|f| f.elapsed() >= JWKS_MIN_REFRESH),
            )
        };
        if fresh && (!cached.is_empty() || !may_refetch) {
            return Ok(cached);
        }
        let keys = self.fetch_jwks(&prov.meta.jwks_uri).await?;
        let out = select(&keys);
        let mut c = prov.jwks.lock();
        c.keys = keys;
        c.fetched = Some(Instant::now());
        Ok(out)
    }

    /// Redeem the authorization code; returns the raw ID token.
    async fn redeem_code(&self, c: &SsoConfig, prov: &Provider, code: &str, verifier: &str, redirect_uri: &str) -> Result<String, String> {
        let mut form: Vec<(&str, &str)> =
            vec![("grant_type", "authorization_code"), ("code", code), ("redirect_uri", redirect_uri), ("code_verifier", verifier)];
        let mut req = self.http.post(&prov.meta.token_endpoint).header(header::ACCEPT, "application/json");
        let methods = prov.meta.token_endpoint_auth_methods_supported.clone().unwrap_or_default();
        let post_only = methods.iter().any(|m| m == "client_secret_post") && !methods.iter().any(|m| m == "client_secret_basic");
        if c.client_secret.is_empty() {
            form.push(("client_id", &c.client_id));
        } else if post_only {
            form.push(("client_id", &c.client_id));
            form.push(("client_secret", &c.client_secret));
        } else {
            // RFC 6749 §2.3.1: form-encode both parts before Base64.
            let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
            let basic = STANDARD.encode(format!("{}:{}", enc(&c.client_id), enc(&c.client_secret)));
            req = req.header(header::AUTHORIZATION, format!("Basic {basic}"));
        }
        let resp = req.form(&form).send().await.map_err(|e| format!("token endpoint unreachable: {e}"))?;
        let status = resp.status();
        let body = read_limited(resp).await.map_err(|e| format!("token endpoint: {e:#}"))?;
        let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        if !status.is_success() {
            let err = v.get("error").and_then(Value::as_str).unwrap_or("");
            let desc = v.get("error_description").and_then(Value::as_str).unwrap_or("");
            return Err(format!("token endpoint returned HTTP {status}: {}", truncate(&format!("{err} {desc}"), 300)));
        }
        v.get("id_token").and_then(Value::as_str).map(String::from).ok_or_else(|| "token response has no id_token".into())
    }

    /// Verify an ID token and return its claims.
    async fn validate_id_token(&self, c: &SsoConfig, prov: &Provider, token: &str, nonce: &str) -> Result<Value, String> {
        let h = jsonwebtoken::decode_header(token).map_err(|e| format!("malformed ID token: {e}"))?;
        if !ALLOWED_ALGS.contains(&h.alg) {
            return Err(format!("ID token algorithm {:?} is not allowed", h.alg));
        }
        let keys = self.signing_keys(prov, h.kid.as_deref()).await.map_err(|e| format!("fetching signing keys: {e:#}"))?;
        if keys.is_empty() {
            return Err(format!("no signing key with kid {:?} in the provider's JWKS", h.kid.unwrap_or_default()));
        }
        let mut v = Validation::new(h.alg);
        v.leeway = CLOCK_SKEW_SECS;
        v.validate_exp = true;
        v.validate_nbf = true;
        v.set_audience(&[&c.client_id]);
        let mut issuers = vec![prov.meta.issuer.clone()];
        if prov.meta.issuer == "https://accounts.google.com" {
            // Google may omit the scheme in `iss`.
            issuers.push("accounts.google.com".into());
        }
        v.set_issuer(&issuers);
        v.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);
        let alg_name = format!("{:?}", h.alg);
        let mut last = String::from("no usable key");
        for k in &keys {
            if k.common.key_algorithm.is_some_and(|ka| format!("{ka:?}") != alg_name) {
                continue;
            }
            let Ok(dk) = DecodingKey::from_jwk(k) else { continue };
            match jsonwebtoken::decode::<Value>(token, &dk, &v) {
                Ok(data) => {
                    let claims = data.claims;
                    if claims.get("nonce").and_then(Value::as_str) != Some(nonce) {
                        return Err("ID token nonce does not match (replayed or injected token)".into());
                    }
                    let multi_aud = claims.get("aud").and_then(Value::as_array).is_some_and(|a| a.len() > 1);
                    let azp = claims.get("azp").and_then(Value::as_str);
                    if (multi_aud || azp.is_some()) && azp != Some(c.client_id.as_str()) {
                        return Err("ID token azp does not match the client id".into());
                    }
                    return Ok(claims);
                }
                Err(e) => {
                    use jsonwebtoken::errors::ErrorKind as K;
                    last = match e.kind() {
                        K::InvalidSignature => "invalid signature".into(),
                        K::InvalidAudience => "audience does not include the client id".into(),
                        K::InvalidIssuer => "unexpected issuer".into(),
                        K::ExpiredSignature => "token expired".into(),
                        K::ImmatureSignature => "token not yet valid (nbf)".into(),
                        K::MissingRequiredClaim(c) => format!("missing claim {c}"),
                        _ => e.to_string(),
                    };
                    // A different key cannot fix a claim error.
                    if !matches!(e.kind(), K::InvalidSignature | K::InvalidKeyFormat | K::InvalidAlgorithm | K::InvalidRsaKey(_)) {
                        break;
                    }
                }
            }
        }
        Err(format!("ID token rejected: {last}"))
    }

    /// Redirect URI for this request: configured, `COPPERHOUND_PUBLIC_URL`, or
    /// the request origin (`X-Forwarded-Proto`/`-Host` honoured).
    pub fn redirect_uri(&self, c: &SsoConfig, headers: &HeaderMap) -> Result<String> {
        if !c.redirect_url.is_empty() {
            return Ok(c.redirect_url.clone());
        }
        Ok(format!("{}{CALLBACK_PATH}", self.origin(headers)?))
    }

    /// Public origin (and path prefix) of the app: `COPPERHOUND_PUBLIC_URL`, or
    /// the request origin (`X-Forwarded-Proto`/`-Host` honoured).
    pub fn origin(&self, headers: &HeaderMap) -> Result<String> {
        if let Some(base) = &self.public_url {
            return Ok(base.clone());
        }
        let first = |h: &str| {
            headers.get(h).and_then(|v| v.to_str().ok()).and_then(|v| v.split(',').next()).map(|v| v.trim().to_string())
        };
        let default = if TLS_ON.load(std::sync::atomic::Ordering::Relaxed) { "https" } else { "http" };
        let proto = first("x-forwarded-proto").filter(|p| p == "https" || p == "http").unwrap_or_else(|| default.into());
        let host = first("x-forwarded-host").or_else(|| first("host")).ok_or_else(|| anyhow!("no Host header"))?;
        if host.is_empty() || !host.chars().all(|c| c.is_ascii_alphanumeric() || ".-:[]".contains(c)) {
            bail!("invalid Host header");
        }
        Ok(format!("{proto}://{host}"))
    }

    /// Start a login: returns the authorization URL and the binding cookie value.
    async fn begin(&self, c: &SsoConfig, redirect_uri: String, return_to: String) -> Result<(String, String)> {
        let prov = self.provider(c).await?;
        let state = random_hex(32);
        let nonce = random_hex(32);
        let verifier = random_hex(32);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let binding = random_hex(24);
        let mut url = url::Url::parse(&prov.meta.authorization_endpoint)?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &c.client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("scope", &c.scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        self.put_pending(
            state,
            Pending { nonce, verifier, redirect_uri, return_to, binding: binding.clone(), created: Instant::now() },
        );
        Ok((url.to_string(), binding))
    }

    /// Finish a login from the callback query.
    async fn complete(&self, auth: &Auth, q: &AHashMap<String, String>, cookie: Option<String>) -> (String, Result<Done, Fail>) {
        let Some(state) = q.get("state") else {
            return (String::new(), Err(fail("state", "callback without state")));
        };
        let Some(p) = self.take_pending(state, Instant::now()) else {
            return (String::new(), Err(fail("state", "unknown, expired or already used state")));
        };
        let base = app_base_path(&p.redirect_uri);
        let res = self.complete_pending(auth, q, cookie, p).await;
        (base, res)
    }

    async fn complete_pending(&self, auth: &Auth, q: &AHashMap<String, String>, cookie: Option<String>, p: Pending) -> Result<Done, Fail> {
        if cookie.as_deref() != Some(p.binding.as_str()) {
            return Err(fail("state", "sign-in cookie missing or mismatched (started in another browser?)"));
        }
        if let Some(e) = q.get("error") {
            let desc = q.get("error_description").map(String::as_str).unwrap_or("");
            return Err(fail("idp_error", format!("identity provider returned {}", truncate(&format!("{e}: {desc}"), 300))));
        }
        let code = q.get("code").filter(|c| !c.is_empty()).ok_or_else(|| fail("idp_error", "callback without code"))?;
        let c = self.effective();
        if !c.is_usable() {
            return Err(fail("disabled", "single sign-on is disabled"));
        }
        let prov = self.provider(&c).await.map_err(|e| fail("idp_unreachable", format!("{e:#}")))?;
        let id_token = self.redeem_code(&c, &prov, code, &p.verifier, &p.redirect_uri).await.map_err(|e| fail("token", e))?;
        let claims = self.validate_id_token(&c, &prov, &id_token, &p.nonce).await.map_err(|e| fail("token", e))?;
        let sub = claims.get("sub").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(|| fail("token", "ID token has no sub"))?;
        let username = pick_username(&claims, &c.username_claim).ok_or_else(|| fail("token", "no usable username claim"))?;
        let user_fail = |code, reason: String| Fail { code, reason, user: username.clone() };
        email_domain_allowed(&c, &claims).map_err(|r| user_fail("denied", r))?;
        let groups = extract_groups(&claims, &c.groups_claim);
        let Some(role) = map_role(&c, &groups) else {
            let overage = claims.get("_claim_names").is_some_and(|n| n.get("groups").is_some());
            let mut reason = format!("not in any mapped group (claim {:?}: {:?})", c.groups_claim, groups.iter().take(20).collect::<Vec<_>>());
            if overage {
                reason.push_str("; Entra group overage: emit app roles or only groups assigned to the application");
            }
            // Revoke live sessions of an existing account that lost access.
            if let Some(u) = auth.list().into_iter().find(|u| {
                u.source == UserSource::Oidc && u.oidc_issuer.as_deref() == Some(prov.meta.issuer.as_str()) && u.oidc_subject.as_deref() == Some(sub)
            }) {
                auth.drop_sessions_of(&u.username);
            }
            return Err(user_fail("denied", reason));
        };
        let user = auth.upsert_oidc_user(&prov.meta.issuer, sub, &username, role).map_err(|e| match e {
            OidcLinkError::Disabled(u) => Fail { code: "disabled_user", reason: "account is disabled".into(), user: u },
            OidcLinkError::Conflict(r) => user_fail("conflict", r),
            OidcLinkError::Other(r) => user_fail("server", r),
        })?;
        let (code, binding) = self.put_exchange(&user.username, &p.return_to);
        Ok(Done {
            code,
            binding,
            username: user.username,
            role,
            detail: format!("sub={}; groups={}", truncate(sub, 128), groups.len()),
        })
    }
}

async fn read_limited(mut resp: reqwest::Response) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if out.len() + chunk.len() > MAX_DOC_BYTES {
            bail!("response larger than {MAX_DOC_BYTES} bytes");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

// ------------------------------------------------------------- routes

/// Unauthenticated endpoints (merged into `/api/v1`).
pub fn public_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/providers", get(providers))
        .route("/auth/oidc/login", get(oidc_login))
        .route("/auth/oidc/callback", get(oidc_callback))
        .route("/auth/oidc/exchange", post(oidc_exchange))
}

/// Admin endpoints (merged into the authenticated router; `/settings*` is admin-only).
pub fn admin_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/settings/sso", get(get_settings).put(put_settings))
        .route("/settings/sso/test", post(test_settings))
}

fn redirect(location: &str, cookie: String) -> Response {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(header::SET_COOKIE, cookie)
        .body(Body::empty())
        .unwrap_or_else(|_| Response::new(Body::from("redirect failed")))
}

fn cookie_header(base: &str, value: &str, secure: bool, max_age: u64) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("{COOKIE}={value}; Path={base}/api/v1/auth/oidc; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}")
}

fn error_redirect(base: &str, code: &str) -> Response {
    redirect(&format!("{base}/#/login?sso_error={code}"), cookie_header(base, "", false, 0))
}

/// Cookie binding an exchange code to the browser that finished sign-in;
/// sent only to `/api/v1/auth/oidc/…`, where the code is redeemed (OIDC and
/// SAML alike).
pub(crate) fn exchange_cookie(base: &str, binding: &str) -> String {
    cookie_header(base, binding, false, EXCHANGE_TTL.as_secs())
}

async fn providers(State(st): St) -> Json<Value> {
    let c = st.sso.effective();
    let on = c.is_usable();
    let saml = st.sso.saml.effective();
    Json(json!({
        "password_login": !st.sso.any_sso_usable(&c) || c.allow_password_login,
        "saml": {
            "enabled": saml.is_usable(),
            "display_name": saml.display_name,
            "login_url": crate::saml::LOGIN_PATH,
        },
        "admin_password_login": st.sso.admin_password_login_allowed(&st.auth),
        "sso": {
            "enabled": on,
            "type": "oidc",
            "display_name": c.display_name,
            "login_url": "/api/v1/auth/oidc/login",
        },
    }))
}

#[derive(Deserialize)]
struct LoginQ {
    #[serde(default)]
    return_to: Option<String>,
}

async fn oidc_login(State(st): St, headers: HeaderMap, Query(q): Query<LoginQ>) -> Response {
    let c = st.sso.effective();
    if !c.is_usable() {
        return error_redirect("", "disabled");
    }
    let return_to = q.return_to.filter(|r| valid_return_to(r)).unwrap_or_else(|| "/".into());
    let redirect_uri = match st.sso.redirect_uri(&c, &headers) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("single sign-on: cannot derive redirect URI: {e:#}");
            return error_redirect("", "config");
        }
    };
    let base = app_base_path(&redirect_uri);
    let secure = redirect_uri.starts_with("https://");
    match st.sso.begin(&c, redirect_uri, return_to).await {
        Ok((url, binding)) => redirect(&url, cookie_header(&base, &binding, secure, LOGIN_TTL.as_secs())),
        Err(e) => {
            tracing::warn!("single sign-on: identity provider unavailable: {e:#}");
            error_redirect(&base, "idp_unreachable")
        }
    }
}

async fn oidc_callback(State(st): St, req: Request) -> Response {
    let ip = client_ip(&req);
    let q: AHashMap<String, String> =
        url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes()).into_owned().collect();
    let cookie = cookie_value(req.headers(), COOKIE);
    let (base, res) = st.sso.complete(&st.auth, &q, cookie).await;
    let entry = |action: &str, user: String, role: &str, status: u16, detail: String| AuditEntry {
        ts: now_rfc3339(),
        user,
        role: role.into(),
        action: action.into(),
        method: "GET".into(),
        path: CALLBACK_PATH.into(),
        status,
        ip: ip.clone(),
        detail: Some(detail),
    };
    match res {
        Ok(d) => {
            tracing::info!("single sign-on: {} signed in as {}", d.username, d.role.as_str());
            st.audit.record(entry("sso-login", d.username, d.role.as_str(), 303, d.detail));
            // The login cookie becomes the exchange binding (same path).
            redirect(&format!("{base}/#/sso?code={}", d.code), exchange_cookie(&base, &d.binding))
        }
        Err(f) => {
            tracing::warn!("single sign-on failed ({}): {}", f.code, f.reason);
            st.audit.record(entry("sso-login-failed", f.user, "", 303, format!("{}: {}", f.code, f.reason)));
            error_redirect(&base, f.code)
        }
    }
}

#[derive(Deserialize)]
struct ExchangeReq {
    code: String,
}

async fn oidc_exchange(State(st): St, headers: HeaderMap, Json(r): Json<ExchangeReq>) -> Result<Json<Value>, ApiError> {
    let binding = cookie_value(&headers, COOKIE);
    let x = st
        .sso
        .take_exchange(r.code.trim(), binding.as_deref(), Instant::now())
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "invalid or expired sign-in code (sign in again in this browser)"))?;
    let (token, who) = st
        .auth
        .start_session(&x.username)
        .ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "account is disabled"))?;
    // The binding is single-use (removed with the code); its cookie expires in 60 s.
    Ok(Json(json!({ "token": token, "username": who.username, "role": who.role, "return_to": x.return_to })))
}

// -------------------------------------------------------------- admin

fn settings_json(st: &AppState, headers: &HeaderMap) -> Value {
    let c = st.sso.effective();
    let mut cfg = serde_json::to_value(&c).unwrap_or_else(|_| json!({}));
    if let Some(o) = cfg.as_object_mut() {
        o.remove("client_secret");
        o.insert("client_secret_set".into(), json!(!c.client_secret.is_empty()));
    }
    json!({
        "config": cfg,
        "env_overrides": st.sso.env_overrides(),
        "redirect_url_effective": st.sso.redirect_uri(&c, headers).ok(),
        "callback_path": CALLBACK_PATH,
        "sso_admin_signed_in": st.auth.sso_admin_has_signed_in(),
        "admin_password_login": st.sso.admin_password_login_allowed(&st.auth),
        "break_glass_env": st.sso.break_glass_env,
    })
}

async fn get_settings(State(st): St, headers: HeaderMap) -> Json<Value> {
    Json(settings_json(&st, &headers))
}

async fn put_settings(
    State(st): St,
    Extension(who): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let mut obj = body.as_object().cloned().ok_or_else(|| ApiError::bad("expected a JSON object"))?;
    let secret = obj.remove("client_secret");
    obj.remove("client_secret_set");
    let mut new: SsoConfig = serde_json::from_value(Value::Object(obj)).map_err(|e| ApiError::bad(format!("invalid SSO settings: {e}")))?;
    let old = st.sso.file.read().clone();
    new.client_secret = match secret {
        None | Some(Value::Null) => old.client_secret.clone(),
        Some(Value::String(s)) => s.trim().to_string(),
        Some(_) => return Err(ApiError::bad("client_secret must be a string or null")),
    };
    new.normalize();
    let mut effective = new.clone();
    apply_env(&mut effective, |k| st.sso.env.get(k).cloned());
    effective.normalize();
    validate_config(&effective, st.auth.sso_admin_has_signed_in()).map_err(ApiError::bad)?;
    let (a, b) = (serde_json::to_value(&old).unwrap_or_default(), serde_json::to_value(&new).unwrap_or_default());
    let changed: Vec<String> = b
        .as_object()
        .map(|o| o.iter().filter(|(k, v)| a.get(k.as_str()) != Some(v)).map(|(k, _)| k.clone()).collect())
        .unwrap_or_default();
    st.sso.save(new)?;
    st.audit.record(AuditEntry {
        ts: now_rfc3339(),
        user: who.username,
        role: who.role.as_str().into(),
        action: "sso-config-changed".into(),
        method: "PUT".into(),
        path: "/api/v1/settings/sso".into(),
        status: 200,
        ip: None,
        detail: Some(if changed.is_empty() { "no changes".into() } else { format!("changed: {}", changed.join(", ")) }),
    });
    Ok(Json(settings_json(&st, &headers)))
}

#[derive(Deserialize, Default)]
struct TestReq {
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    allow_insecure_http: Option<bool>,
}

async fn test_settings(State(st): St, body: Bytes) -> Json<Value> {
    let r: TestReq = if body.iter().all(u8::is_ascii_whitespace) {
        TestReq::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => return Json(json!({ "ok": false, "error": format!("invalid request: {e}") })),
        }
    };
    let c = st.sso.effective();
    let issuer = r.issuer.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or(c.issuer);
    if issuer.is_empty() {
        return Json(json!({ "ok": false, "error": "no issuer configured" }));
    }
    let allow_http = r.allow_insecure_http.unwrap_or(c.allow_insecure_http);
    let meta = match st.sso.discover(&issuer, allow_http).await {
        Ok(m) => m,
        Err(e) => return Json(json!({ "ok": false, "error": format!("{e:#}") })),
    };
    let mut warnings: Vec<String> = Vec::new();
    if meta.code_challenge_methods_supported.as_ref().is_some_and(|m| !m.iter().any(|x| x == "S256")) {
        warnings.push("provider does not advertise PKCE S256 support".into());
    }
    let jwks_keys = match st.sso.fetch_jwks(&meta.jwks_uri).await {
        Ok(k) if k.is_empty() => {
            warnings.push("JWKS contains no usable signature keys".into());
            json!(0)
        }
        Ok(k) => json!(k.len()),
        Err(e) => {
            warnings.push(format!("JWKS: {e:#}"));
            Value::Null
        }
    };
    Json(json!({
        "ok": true,
        "issuer": meta.issuer,
        "authorization_endpoint": meta.authorization_endpoint,
        "token_endpoint": meta.token_endpoint,
        "jwks_uri": meta.jwks_uri,
        "userinfo_endpoint": meta.userinfo_endpoint,
        "end_session_endpoint": meta.end_session_endpoint,
        "scopes_supported": meta.scopes_supported,
        "jwks_keys": jwks_keys,
        "warnings": warnings,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SsoConfig {
        SsoConfig {
            enabled: true,
            issuer: "https://idp.example".into(),
            client_id: "pd".into(),
            role_mapping: RoleMapping {
                admin: vec!["CH-Admins".into()],
                analyst: vec!["ch-analysts".into()],
                viewer: vec!["ch-viewers".into()],
            },
            ..Default::default()
        }
    }

    fn sso(c: SsoConfig) -> Sso {
        Sso::from_parts(PathBuf::new(), c, AHashMap::new(), None, false, reqwest::Client::new())
    }

    fn g(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn role_mapping() {
        let mut c = cfg();
        assert_eq!(map_role(&c, &g(&["ch-admins", "ch-viewers"])), Some(Role::Admin), "highest wins, case-insensitive");
        assert_eq!(map_role(&c, &g(&["ch-viewers", "CH-ANALYSTS"])), Some(Role::Analyst));
        assert_eq!(map_role(&c, &g(&["ch-viewers"])), Some(Role::Viewer));
        assert_eq!(map_role(&c, &g(&["other"])), None, "default is deny");
        assert_eq!(map_role(&c, &[]), None);
        c.default_role = "viewer".into();
        assert_eq!(map_role(&c, &g(&["other"])), Some(Role::Viewer));
        c.default_role = "admin".into();
        assert_eq!(map_role(&c, &[]), None, "admin is never a default");
    }

    #[test]
    fn groups_and_usernames() {
        let claims = json!({
            "sub": "abc", "email": "Alice@Corp.example", "preferred_username": "alice smith",
            "groups": ["g1", "g2"], "roles": "CopperHound.Admin",
            "realm_access": { "roles": ["kc-admin"] },
        });
        assert_eq!(extract_groups(&claims, "groups"), g(&["g1", "g2"]));
        assert_eq!(extract_groups(&claims, "groups, roles"), g(&["CopperHound.Admin", "g1", "g2"]));
        assert_eq!(extract_groups(&claims, "realm_access.roles"), g(&["kc-admin"]));
        assert!(extract_groups(&claims, "missing").is_empty());
        assert_eq!(pick_username(&claims, "preferred_username").as_deref(), Some("alice_smith"));
        assert_eq!(pick_username(&claims, "upn").as_deref(), Some("Alice@Corp.example"));
        assert_eq!(pick_username(&json!({"sub": "s-1"}), "preferred_username").as_deref(), Some("s-1"));
        assert_eq!(pick_username(&json!({"sub": "!!"}), "x"), None);
    }

    #[test]
    fn return_to_validation() {
        for ok in ["/", "/#/findings", "/#/graph?node=12&x=1", "/copperhound/#/sso"] {
            assert!(valid_return_to(ok), "{ok}");
        }
        for bad in [
            "", "//evil.example", "/\\evil.example", "https://evil.example", "evil.example", "javascript:alert(1)",
            "/ok\r\nSet-Cookie: x", "/a b", "\\\\evil",
        ] {
            assert!(!valid_return_to(bad), "{bad}");
        }
        assert!(!valid_return_to(&format!("/{}", "a".repeat(600))));
    }

    #[test]
    fn exchange_codes_are_one_time_and_expire() {
        let s = sso(cfg());
        let (code, b) = s.put_exchange("alice", "/#/x");
        assert!(s.take_exchange("nope", Some(&b), Instant::now()).is_none());
        let x = s.take_exchange(&code, Some(&b), Instant::now()).unwrap();
        assert_eq!((x.username.as_str(), x.return_to.as_str()), ("alice", "/#/x"));
        assert!(s.take_exchange(&code, Some(&b), Instant::now()).is_none(), "second use refused");
        let (code, b) = s.put_exchange("bob", "/");
        assert!(s.take_exchange(&code, Some(&b), Instant::now() + Duration::from_secs(61)).is_none(), "expired after 60 s");
        assert!(s.take_exchange(&code, Some(&b), Instant::now()).is_none(), "an expired code is consumed too");
    }

    /// Login CSRF: a code is only redeemed by the browser that finished the
    /// sign-in (holding its binding cookie).
    #[test]
    fn exchange_codes_are_bound_to_the_browser() {
        let s = sso(cfg());
        let (code, _) = s.put_exchange("attacker", "/");
        assert!(s.take_exchange(&code, None, Instant::now()).is_none(), "no cookie");
        let (code, _) = s.put_exchange("attacker", "/");
        assert!(s.take_exchange(&code, Some("someone-elses-cookie"), Instant::now()).is_none(), "wrong cookie");
    }

    #[test]
    fn pending_logins_are_one_time_and_expire() {
        let s = sso(cfg());
        let mk = || Pending {
            nonce: "n".into(),
            verifier: "v".into(),
            redirect_uri: "https://ch.example/api/v1/auth/oidc/callback".into(),
            return_to: "/".into(),
            binding: "b".into(),
            created: Instant::now(),
        };
        s.put_pending("s1".into(), mk());
        assert!(s.take_pending("s1", Instant::now()).is_some());
        assert!(s.take_pending("s1", Instant::now()).is_none());
        s.put_pending("s2".into(), mk());
        assert!(s.take_pending("s2", Instant::now() + LOGIN_TTL).is_none());
    }

    #[test]
    fn env_overlay() {
        let env: AHashMap<String, String> = [
            ("COPPERHOUND_OIDC_ISSUER", "https://login.microsoftonline.com/t/v2.0"),
            ("COPPERHOUND_OIDC_CLIENT_SECRET", "s3cret"),
            ("COPPERHOUND_OIDC_SCOPES", "openid profile,email"),
            ("COPPERHOUND_OIDC_ADMIN_GROUPS", "CopperHound Admins, 0000-1111"),
            ("COPPERHOUND_OIDC_ALLOW_PASSWORD_LOGIN", "false"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let mut c = SsoConfig::default();
        let set = apply_env(&mut c, |k| env.get(k).cloned());
        assert!(c.enabled, "issuer in env enables SSO");
        assert_eq!(c.client_secret, "s3cret");
        assert_eq!(c.scopes, g(&["openid", "profile", "email"]));
        assert_eq!(c.role_mapping.admin, g(&["CopperHound Admins", "0000-1111"]));
        assert!(!c.allow_password_login);
        for f in ["issuer", "client_secret", "scopes", "role_mapping.admin", "allow_password_login", "enabled"] {
            assert!(set.contains(&f), "{f}");
        }
    }

    #[test]
    fn config_validation() {
        let mut c = cfg();
        assert!(validate_config(&c, false).is_ok());
        c.issuer = "http://idp.example".into();
        assert!(validate_config(&c, false).is_err(), "plain http refused");
        c.issuer = "http://127.0.0.1:8080/realms/x".into();
        assert!(validate_config(&c, false).is_ok(), "loopback allowed");
        c.redirect_url = "https://ch.example/wrong".into();
        assert!(validate_config(&c, false).is_err());
        c.redirect_url = "https://ch.example/pd/api/v1/auth/oidc/callback".into();
        assert!(validate_config(&c, false).is_ok());
        c.default_role = "admin".into();
        assert!(validate_config(&c, false).is_err());
        c.default_role = "deny".into();
        c.disable_admin_password_login = true;
        assert!(validate_config(&c, true).is_err(), "needs allow_password_login false");
        c.allow_password_login = false;
        assert!(validate_config(&c, false).is_err(), "needs a proven SSO admin");
        assert!(validate_config(&c, true).is_ok());
        assert_eq!(app_base_path(&c.redirect_url), "/pd");
        assert_eq!(app_base_path("https://ch.example/api/v1/auth/oidc/callback"), "");
    }

    #[test]
    fn password_policy() {
        let auth = Auth::with_password("s3cret-password".into());
        auth.create("bob", "bob-long-password", Role::Analyst).unwrap();
        let admin = auth.get("admin").unwrap();
        let bob = auth.get("bob").unwrap();
        // SSO off: everyone.
        let s = sso(SsoConfig::default());
        assert!(s.password_login_allowed(&auth, &admin) && s.password_login_allowed(&auth, &bob));
        // SSO on, password login off: only the built-in admin.
        let mut c = cfg();
        c.allow_password_login = false;
        let s = sso(c.clone());
        assert!(s.password_login_allowed(&auth, &admin));
        assert!(!s.password_login_allowed(&auth, &bob));
        // Admin disabled too, but no SSO admin has signed in yet: still allowed.
        c.disable_admin_password_login = true;
        let s = sso(c.clone());
        assert!(s.password_login_allowed(&auth, &admin));
        auth.upsert_oidc_user("https://idp.example", "1", "carol", Role::Admin).unwrap();
        auth.start_session("carol").unwrap();
        assert!(!s.password_login_allowed(&auth, &admin));
        // Disabling the SSO admin restores break-glass access.
        auth.update("carol", None, None, Some(true)).unwrap();
        assert!(s.password_login_allowed(&auth, &admin));
        auth.update("carol", None, None, Some(false)).unwrap();
        let s = Sso::from_parts(PathBuf::new(), c, AHashMap::new(), None, true, reqwest::Client::new());
        assert!(s.password_login_allowed(&auth, &admin), "COPPERHOUND_SSO_BREAK_GLASS");
        let carol = auth.get("carol").unwrap();
        assert!(!s.password_login_allowed(&auth, &carol), "SSO accounts never use passwords");
    }
}
