//! SAML 2.0 single sign-on (service provider, SP-initiated, HTTP-Redirect
//! request / HTTP-POST response). XML handling is in [`crate::samlxml`].
//!
//! Flow:
//!
//! 1. `GET /api/v1/auth/saml/login` builds an AuthnRequest, remembers its ID
//!    under a random `RelayState` for 10 minutes, binds it to this browser
//!    with an HttpOnly cookie (`SameSite=None; Secure`, because the IdP's
//!    response arrives as a cross-site POST; browsers keep such cookies on
//!    HTTPS and on `localhost`), and redirects to the IdP.
//! 2. `POST /api/v1/auth/saml/acs` takes the `RelayState` (once), checks the
//!    cookie, verifies the response (signature with the IdP metadata's
//!    certificates, `InResponseTo`, destination, issuer, audience, bearer
//!    confirmation, validity window with 2 minutes' skew) and refuses replayed
//!    assertion IDs. The user is mapped like an OIDC sign-in (groups → role,
//!    optional e-mail domain allow-list) and just-in-time provisioned as an
//!    SSO account linked to (`saml:<IdP entity id>`, NameID).
//! 3. The browser is sent to `/#/sso?code=…`, redeemed at
//!    `POST /api/v1/auth/oidc/exchange` exactly like an OIDC sign-in.
//!
//! IdP-initiated sign-in (unsolicited responses) is refused. The password
//! sign-in policy of `/settings/sso` also applies while SAML is enabled.
//! Configuration: `<data>/saml.json`, admin API `/settings/saml`.

use crate::api::{client_ip, ApiError, St};
use crate::audit::AuditEntry;
use crate::auth::{random_hex, Auth, OidcLinkError, Principal, Role};
use crate::samlxml::{self, Expect};
use crate::sso::{self, RoleMapping, SsoConfig};
use crate::state::now_rfc3339;
use ahash::AHashMap;
use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::{Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const ACS_PATH: &str = "/api/v1/auth/saml/acs";
pub const METADATA_PATH: &str = "/api/v1/auth/saml/metadata";
pub const LOGIN_PATH: &str = "/api/v1/auth/saml/login";
const COOKIE: &str = "ch_saml";
const LOGIN_TTL: Duration = Duration::from_secs(10 * 60);
const SKEW_SECS: i64 = 120;
const MAX_PENDING: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SamlConfig {
    pub enabled: bool,
    /// Button label on the sign-in page.
    pub display_name: String,
    /// IdP metadata XML (EntityDescriptor): entity id, SSO URL, signing certificates.
    pub idp_metadata: String,
    /// Empty: `<public URL>/api/v1/auth/saml/metadata`.
    pub sp_entity_id: String,
    /// Empty: `<public URL>/api/v1/auth/saml/acs`.
    pub acs_url: String,
    /// Attribute used as the username; empty = the NameID.
    pub username_attribute: String,
    /// Attribute(s) holding groups or roles, comma-separated.
    pub groups_attribute: String,
    /// Attribute holding the e-mail address (for `allowed_email_domains`).
    pub email_attribute: String,
    pub role_mapping: RoleMapping,
    /// `viewer`, `analyst` or `deny`.
    pub default_role: String,
    pub allowed_email_domains: Vec<String>,
}

impl Default for SamlConfig {
    fn default() -> Self {
        SamlConfig {
            enabled: false,
            display_name: "SAML single sign-on".into(),
            idp_metadata: String::new(),
            sp_entity_id: String::new(),
            acs_url: String::new(),
            username_attribute: String::new(),
            groups_attribute: "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups,groups,memberOf,Role".into(),
            email_attribute: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress,email,mail".into(),
            role_mapping: RoleMapping::default(),
            default_role: "deny".into(),
            allowed_email_domains: Vec::new(),
        }
    }
}

impl SamlConfig {
    pub fn is_usable(&self) -> bool {
        self.enabled && !self.idp_metadata.trim().is_empty()
    }

    fn normalize(&mut self) {
        let d = SamlConfig::default();
        for s in [&mut self.display_name, &mut self.sp_entity_id, &mut self.acs_url, &mut self.username_attribute] {
            *s = s.trim().to_string();
        }
        if self.display_name.is_empty() {
            self.display_name = d.display_name;
        }
        self.default_role = self.default_role.trim().to_ascii_lowercase();
        if self.default_role.is_empty() {
            self.default_role = d.default_role;
        }
        for l in [&mut self.role_mapping.admin, &mut self.role_mapping.analyst, &mut self.role_mapping.viewer, &mut self.allowed_email_domains] {
            for g in l.iter_mut() {
                *g = g.trim().to_string();
            }
            l.retain(|g| !g.is_empty());
        }
    }

    /// The OIDC-shaped settings used for role and e-mail checks.
    fn mapping(&self) -> SsoConfig {
        SsoConfig {
            role_mapping: self.role_mapping.clone(),
            default_role: self.default_role.clone(),
            allowed_email_domains: self.allowed_email_domains.clone(),
            ..SsoConfig::default()
        }
    }
}

pub fn validate(c: &SamlConfig) -> Result<(), String> {
    if !["viewer", "analyst", "deny"].contains(&c.default_role.as_str()) {
        return Err("default_role must be viewer, analyst or deny".into());
    }
    if !c.idp_metadata.trim().is_empty() {
        let md = samlxml::parse_idp_metadata(&c.idp_metadata)?;
        for cert in &md.certs {
            samlxml::cert_key(cert)?;
        }
        url::Url::parse(&md.sso_url).map_err(|e| format!("IdP SSO URL: {e}"))?;
    } else if c.enabled {
        return Err("IdP metadata is required to enable SAML".into());
    }
    for (u, what) in [(&c.sp_entity_id, "sp_entity_id"), (&c.acs_url, "acs_url")] {
        if !u.is_empty() && url::Url::parse(u).is_err() {
            return Err(format!("{what} must be an absolute URL"));
        }
    }
    Ok(())
}

struct Pending {
    request_id: String,
    binding: String,
    return_to: String,
    acs_url: String,
    sp_entity_id: String,
    created: Instant,
}

pub struct Saml {
    path: PathBuf,
    file: RwLock<SamlConfig>,
    pending: Mutex<AHashMap<String, Pending>>,
    /// Consumed assertion IDs → expiry (unix seconds).
    seen: Mutex<AHashMap<String, i64>>,
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

impl Saml {
    pub fn init(data_dir: &Path) -> Result<Saml> {
        let path = data_dir.join("saml.json");
        let file: SamlConfig = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).with_context(|| format!("parsing {}", path.display()))?,
            Err(_) => SamlConfig::default(),
        };
        Ok(Saml::with(path, file))
    }

    pub fn with(path: PathBuf, file: SamlConfig) -> Saml {
        Saml { path, file: RwLock::new(file), pending: Mutex::new(AHashMap::new()), seen: Mutex::new(AHashMap::new()) }
    }

    pub fn effective(&self) -> SamlConfig {
        let mut c = self.file.read().clone();
        c.normalize();
        c
    }

    fn save(&self, c: SamlConfig) -> Result<()> {
        if !self.path.as_os_str().is_empty() {
            let tmp = self.path.with_extension("json.tmp");
            std::fs::write(&tmp, serde_json::to_vec_pretty(&c)?)?;
            std::fs::rename(&tmp, &self.path)?;
        }
        *self.file.write() = c;
        Ok(())
    }

    fn put_pending(&self, relay: String, p: Pending) {
        let mut m = self.pending.lock();
        let now = Instant::now();
        m.retain(|_, x| now.duration_since(x.created) < LOGIN_TTL);
        if m.len() >= MAX_PENDING {
            if let Some(k) = m.iter().min_by_key(|(_, x)| x.created).map(|(k, _)| k.clone()) {
                m.remove(&k);
            }
        }
        m.insert(relay, p);
    }

    fn take_pending(&self, relay: &str) -> Option<Pending> {
        let p = self.pending.lock().remove(relay)?;
        (p.created.elapsed() < LOGIN_TTL).then_some(p)
    }

    /// Records an assertion ID; false if it was already used.
    fn first_use(&self, id: &str, expires: i64) -> bool {
        let now = now_unix();
        let mut s = self.seen.lock();
        s.retain(|_, &mut e| e + SKEW_SECS > now);
        if s.contains_key(id) {
            return false;
        }
        if s.len() < 100_000 {
            s.insert(id.to_string(), expires);
        }
        true
    }

    /// `(sp_entity_id, acs_url)` for this request.
    pub fn endpoints(&self, c: &SamlConfig, origin: &str) -> (String, String) {
        let sp = if c.sp_entity_id.is_empty() { format!("{origin}{METADATA_PATH}") } else { c.sp_entity_id.clone() };
        let acs = if c.acs_url.is_empty() { format!("{origin}{ACS_PATH}") } else { c.acs_url.clone() };
        (sp, acs)
    }
}

/// Values of the first configured attribute that has any.
fn attr<'a>(attrs: &'a std::collections::BTreeMap<String, Vec<String>>, names: &str) -> Vec<&'a str> {
    let mut out: Vec<&str> = Vec::new();
    for n in names.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        if let Some(v) = attrs.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v) {
            out.extend(v.iter().map(String::as_str));
        }
    }
    out
}

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

fn complete(sso: &sso::Sso, auth: &Auth, p: Pending, cookie: Option<String>, b64: &str) -> Result<Done, Fail> {
    if cookie.as_deref() != Some(p.binding.as_str()) {
        return Err(fail("state", "sign-in cookie missing or mismatched (started in another browser, or not served over HTTPS?)"));
    }
    let saml = &sso.saml;
    let c = saml.effective();
    if !c.is_usable() {
        return Err(fail("disabled", "SAML sign-on is disabled"));
    }
    let md = samlxml::parse_idp_metadata(&c.idp_metadata).map_err(|e| fail("config", e))?;
    let keys: Vec<_> = md.certs.iter().filter_map(|k| samlxml::cert_key(k).ok()).collect();
    let clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
    let raw = STANDARD.decode(clean).map_err(|_| fail("token", "SAMLResponse is not base64"))?;
    let xml = String::from_utf8(raw).map_err(|_| fail("token", "SAMLResponse is not UTF-8"))?;
    let x = Expect {
        idp_entity_id: &md.entity_id,
        sp_entity_id: &p.sp_entity_id,
        acs_url: &p.acs_url,
        request_id: &p.request_id,
        keys: &keys,
        now: now_unix(),
        skew_secs: SKEW_SECS,
    };
    let v = samlxml::verify_response(&xml, &x).map_err(|e| fail("token", e))?;
    if !saml.first_use(&v.assertion_id, v.not_on_or_after) {
        return Err(fail("token", "assertion already used (replay)"));
    }
    // Claims in the OIDC shape, so the same mapping helpers apply.
    let mut claims = Map::new();
    let user_val = if c.username_attribute.is_empty() {
        Some(v.name_id.clone())
    } else {
        attr(&v.attributes, &c.username_attribute).first().map(|s| s.to_string())
    };
    if let Some(u) = user_val {
        claims.insert("username".into(), json!(u));
    }
    if let Some(e) = attr(&v.attributes, &c.email_attribute).first() {
        claims.insert("email".into(), json!(e));
    }
    claims.insert("sub".into(), json!(v.name_id));
    let groups: Vec<String> = attr(&v.attributes, &c.groups_attribute).into_iter().map(String::from).collect();
    claims.insert("groups".into(), json!(groups));
    let claims = Value::Object(claims);
    if v.name_id.is_empty() {
        return Err(fail("token", "assertion has no NameID"));
    }
    let username = sso::pick_username(&claims, "username").ok_or_else(|| fail("token", "no usable username"))?;
    let user_fail = |code, reason: String| Fail { code, reason, user: username.clone() };
    let mapping = c.mapping();
    sso::email_domain_check(&mapping, &claims).map_err(|r| user_fail("denied", r))?;
    let issuer = format!("saml:{}", md.entity_id);
    let Some(role) = sso::map_role(&mapping, &groups) else {
        auth.drop_sessions_of_identity(&issuer, &v.name_id);
        return Err(user_fail("denied", format!("not in any mapped group ({} group values)", groups.len())));
    };
    let user = auth.upsert_oidc_user(&issuer, &v.name_id, &username, role).map_err(|e| match e {
        OidcLinkError::Disabled(u) => Fail { code: "disabled_user", reason: "account is disabled".into(), user: u },
        OidcLinkError::Conflict(r) => user_fail("conflict", r),
        OidcLinkError::Other(r) => user_fail("server", r),
    })?;
    let (code, binding) = sso.put_exchange(&user.username, &p.return_to);
    Ok(Done { code, binding, username: user.username, role, detail: format!("saml nameid={}; groups={}", v.name_id.chars().take(128).collect::<String>(), groups.len()) })
}

// ------------------------------------------------------------- routes

pub fn public_routes() -> Router<Arc<crate::state::AppState>> {
    Router::new()
        .route("/auth/saml/login", get(login))
        .route("/auth/saml/acs", post(acs))
        .route("/auth/saml/metadata", get(metadata))
}

pub fn admin_routes() -> Router<Arc<crate::state::AppState>> {
    Router::new().route("/settings/saml", get(get_settings).put(put_settings))
}

/// Path prefix the app is served under, from the ACS URL.
fn base_path(acs: &str) -> String {
    url::Url::parse(acs)
        .ok()
        .and_then(|u| u.path().strip_suffix(ACS_PATH).map(|p| p.trim_end_matches('/').to_string()))
        .unwrap_or_default()
}

fn cookie(base: &str, value: &str, max_age: u64) -> String {
    format!("{COOKIE}={value}; Path={base}/api/v1/auth/saml; Max-Age={max_age}; HttpOnly; SameSite=None; Secure")
}

fn redirect(location: &str, set_cookie: String) -> Response {
    redirect_cookies(location, &[set_cookie])
}

fn redirect_cookies(location: &str, set_cookies: &[String]) -> Response {
    let mut b = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::REFERRER_POLICY, "no-referrer");
    for c in set_cookies {
        b = b.header(header::SET_COOKIE, c);
    }
    b.body(Body::empty()).unwrap_or_else(|_| Response::new(Body::from("redirect failed")))
}

fn error_redirect(base: &str, code: &str) -> Response {
    redirect(&format!("{base}/#/login?sso_error={code}"), cookie(base, "", 0))
}

#[derive(Deserialize)]
struct LoginQ {
    #[serde(default)]
    return_to: Option<String>,
}

async fn login(State(st): St, headers: HeaderMap, Query(q): Query<LoginQ>) -> Response {
    let c = st.sso.saml.effective();
    if !c.is_usable() {
        return error_redirect("", "disabled");
    }
    let origin = match st.sso.origin(&headers) {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!("SAML: cannot derive the public URL: {e:#}");
            return error_redirect("", "config");
        }
    };
    let (sp, acs) = st.sso.saml.endpoints(&c, &origin);
    let base = base_path(&acs);
    let md = match samlxml::parse_idp_metadata(&c.idp_metadata) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("SAML: invalid IdP metadata: {e}");
            return error_redirect(&base, "config");
        }
    };
    let request_id = format!("_{}", random_hex(20));
    let xml = samlxml::authn_request(&request_id, &now_rfc3339(), &md.sso_url, &acs, &sp);
    let relay = random_hex(24);
    let binding = random_hex(24);
    let Ok(mut url) = url::Url::parse(&md.sso_url) else {
        return error_redirect(&base, "config");
    };
    url.query_pairs_mut().append_pair("SAMLRequest", &samlxml::deflate_b64(&xml)).append_pair("RelayState", &relay);
    let return_to = q.return_to.filter(|r| sso::valid_return_to(r)).unwrap_or_else(|| "/".into());
    st.sso.saml.put_pending(
        relay,
        Pending { request_id, binding: binding.clone(), return_to, acs_url: acs, sp_entity_id: sp, created: Instant::now() },
    );
    redirect(url.as_str(), cookie(&base, &binding, LOGIN_TTL.as_secs()))
}

async fn acs(State(st): St, req: Request) -> Response {
    let ip = client_ip(&req);
    let cookie_v = sso::cookie_value(req.headers(), COOKIE);
    let body = match axum::body::to_bytes(req.into_body(), 4 * samlxml::MAX_XML_BYTES / 3 + 4096).await {
        Ok(b) => b,
        Err(_) => return error_redirect("", "token"),
    };
    let form: AHashMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
    let entry = |action: &str, user: String, role: &str, detail: String| AuditEntry {
        ts: now_rfc3339(),
        user,
        role: role.into(),
        action: action.into(),
        method: "POST".into(),
        path: ACS_PATH.into(),
        status: 303,
        ip: ip.clone(),
        detail: Some(detail),
    };
    let Some(p) = form.get("RelayState").and_then(|r| st.sso.saml.take_pending(r)) else {
        st.audit.record(entry("sso-login-failed", String::new(), "", "state: unknown, expired or already used RelayState (IdP-initiated sign-in is not supported)".into()));
        return error_redirect("", "state");
    };
    let base = base_path(&p.acs_url);
    let res = match form.get("SAMLResponse") {
        Some(r) => complete(&st.sso, &st.auth, p, cookie_v, r),
        None => Err(fail("idp_error", "no SAMLResponse in the POST")),
    };
    match res {
        Ok(d) => {
            tracing::info!("SAML sign-on: {} signed in as {}", d.username, d.role.as_str());
            st.audit.record(entry("sso-login", d.username, d.role.as_str(), d.detail));
            // Clear the SAML login cookie; bind the exchange code to this browser.
            redirect_cookies(&format!("{base}/#/sso?code={}", d.code), &[cookie(&base, "", 0), sso::exchange_cookie(&base, &d.binding)])
        }
        Err(f) => {
            tracing::warn!("SAML sign-on failed ({}): {}", f.code, f.reason);
            st.audit.record(entry("sso-login-failed", f.user, "", format!("{}: {}", f.code, f.reason)));
            error_redirect(&base, f.code)
        }
    }
}

async fn metadata(State(st): St, headers: HeaderMap) -> Response {
    let c = st.sso.saml.effective();
    let origin = st.sso.origin(&headers).unwrap_or_default();
    let (sp, acs) = st.sso.saml.endpoints(&c, &origin);
    Response::builder()
        .header(header::CONTENT_TYPE, "application/samlmetadata+xml")
        .body(Body::from(samlxml::sp_metadata(&sp, &acs)))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn settings_json(st: &crate::state::AppState, headers: &HeaderMap) -> Value {
    let c = st.sso.saml.effective();
    let origin = st.sso.origin(headers).unwrap_or_default();
    let (sp, acs) = st.sso.saml.endpoints(&c, &origin);
    let idp = samlxml::parse_idp_metadata(&c.idp_metadata).ok().map(|m| {
        json!({
            "entity_id": m.entity_id,
            "sso_url": m.sso_url,
            "certificates": m.certs.iter().filter_map(|x| samlxml::cert_fingerprint(x)).collect::<Vec<_>>(),
        })
    });
    json!({
        "config": c,
        "sp_entity_id_effective": sp,
        "acs_url_effective": acs,
        "metadata_url": format!("{origin}{METADATA_PATH}"),
        "idp": idp,
    })
}

async fn get_settings(State(st): St, headers: HeaderMap) -> Json<Value> {
    Json(settings_json(&st, &headers))
}

async fn put_settings(State(st): St, Extension(who): Extension<Principal>, headers: HeaderMap, Json(body): Json<SamlConfig>) -> Result<Json<Value>, ApiError> {
    let mut c = body;
    c.normalize();
    validate(&c).map_err(ApiError::bad)?;
    let changed = st.sso.saml.effective() != c;
    st.sso.saml.save(c)?;
    st.audit.record(AuditEntry {
        ts: now_rfc3339(),
        user: who.username,
        role: who.role.as_str().into(),
        action: "saml-config-changed".into(),
        method: "PUT".into(),
        path: "/api/v1/settings/saml".into(),
        status: 200,
        ip: None,
        detail: Some(if changed { "updated".into() } else { "no changes".into() }),
    });
    Ok(Json(settings_json(&st, &headers)))
}
