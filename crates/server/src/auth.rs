//! Multi-user authentication and role-based access control.
//!
//! * Users live in `<data>/users.json` with Argon2id password hashes.
//! * The built-in `admin` account is bootstrapped from
//!   `COPPERHOUND_ADMIN_PASSWORD` (authoritative when set), else from
//!   `<data>/admin_password`, else a generated password written there.
//! * Interactive logins get an in-memory session token with a sliding expiry.
//! * Personal API tokens (`cht_…`) are long-lived, optionally expiring, and
//!   stored only as SHA-256 hashes.
//! * Repeated failed logins lock the account for a while.
//! * Roles: `viewer` (read and analyse), `analyst` (also change data: marks,
//!   saved queries, zones, uploads, ingest), `admin` (also users, audit,
//!   settings). The role is resolved on every request, so changes apply at once.
//! * Accounts created by OpenID Connect sign-in (`source: "oidc"`, see
//!   `sso.rs`) have no password and are bound to the IdP's (issuer, subject).

use ahash::AHashMap;
use anyhow::{anyhow, bail, Context, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const MAX_FAILURES: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(5 * 60);
pub const MIN_PASSWORD_LEN: usize = 12;
pub const ADMIN_USER: &str = "admin";
const TOKEN_PREFIX: &str = "cht_";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Upload-only (collector service accounts): upload files, start an
    /// ingest and follow its jobs; no access to the graph or analysis. Lowest
    /// rank, so every rank check excludes it; its few routes are allowed in
    /// [`crate::api::uploader_may`].
    Uploader,
    Viewer,
    Analyst,
    Admin,
}

impl Role {
    pub fn parse(s: &str) -> Option<Role> {
        match s.to_ascii_lowercase().as_str() {
            "uploader" => Some(Role::Uploader),
            "viewer" => Some(Role::Viewer),
            "analyst" => Some(Role::Analyst),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Uploader => "uploader",
            Role::Viewer => "viewer",
            Role::Analyst => "analyst",
            Role::Admin => "admin",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    pub id: String,
    pub name: String,
    /// SHA-256 of the full token, hex.
    pub hash: String,
    /// First characters of the token, for display.
    pub prefix: String,
    pub created_at: String,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub last_used: Option<String>,
}

/// Where an account comes from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserSource {
    /// Created by an admin (or the built-in admin); signs in with a password.
    #[default]
    Local,
    /// Created just-in-time by OpenID Connect sign-in; has no password.
    Oidc,
}

impl UserSource {
    fn is_local(&self) -> bool {
        *self == UserSource::Local
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub role: Role,
    pub password_hash: String,
    pub created_at: String,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub last_login: Option<String>,
    #[serde(default)]
    pub tokens: Vec<ApiToken>,
    #[serde(default, skip_serializing_if = "UserSource::is_local")]
    pub source: UserSource,
    /// OIDC issuer and subject the account is bound to (`source: oidc` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_subject: Option<String>,
    /// Two-factor sign-in (TOTP); pending until confirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa: Option<crate::mfa::Mfa>,
}

impl User {
    pub fn mfa_enabled(&self) -> bool {
        self.mfa.as_ref().is_some_and(|m| m.enabled)
    }
}

fn token_expired(t: &ApiToken, now: SystemTime) -> bool {
    t.expires_at.as_deref().and_then(|e| humantime::parse_rfc3339(e).ok()).is_some_and(|e| e <= now)
}

/// The authenticated caller, attached to each request.
#[derive(Debug, Clone)]
pub struct Principal {
    pub username: String,
    pub role: Role,
    /// Authenticated with a personal API token rather than a session.
    pub via_token: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LoginError {
    Invalid,
    /// Locked out; seconds remaining.
    Locked(u64),
    /// Correct credentials, but password sign-in is disabled for this
    /// account by the single sign-on policy.
    PasswordDisabled,
    /// Password correct; the account needs its two-factor code.
    MfaRequired,
    /// Two-factor code (or recovery code) wrong or already used.
    MfaInvalid,
}

/// Why an OIDC sign-in could not be linked to an account.
#[derive(Debug, PartialEq, Eq)]
pub enum OidcLinkError {
    /// The linked account is disabled.
    Disabled(String),
    /// The username is taken by a local account or another IdP identity.
    Conflict(String),
    Other(String),
}

pub struct Auth {
    path: PathBuf,
    users: RwLock<Vec<User>>,
    sessions: Mutex<AHashMap<String, (String, Instant)>>,
    failures: Mutex<AHashMap<String, (u32, Instant)>>,
    /// Hash verified when the username is unknown, so timing does not reveal it.
    dummy_hash: String,
}

pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::getrandom(&mut buf).expect("OS random source");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn random_password() -> String {
    // 24 chars from an unambiguous alphabet.
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut buf = [0u8; 24];
    getrandom::getrandom(&mut buf).expect("OS random source");
    buf.iter().map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char).collect()
}

fn now_rfc3339() -> String {
    humantime::format_rfc3339_seconds(SystemTime::now()).to_string()
}

pub fn hash_password(password: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).map_err(|e| anyhow!("random: {e}"))?;
    let salt = SaltString::encode_b64(&salt).map_err(|e| anyhow!("salt: {e}"))?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("hashing password: {e}"))?
        .to_string())
}

fn verify_password(hash: &str, password: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
}

fn sha256_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

pub fn valid_username(u: &str) -> bool {
    (1..=64).contains(&u.len()) && u.chars().all(|c| c.is_ascii_alphanumeric() || "._-@".contains(c))
}

fn check_password_policy(p: &str) -> Result<()> {
    if p.chars().count() < MIN_PASSWORD_LEN {
        bail!("password must be at least {MIN_PASSWORD_LEN} characters");
    }
    Ok(())
}

impl Auth {
    /// Load users and bootstrap the admin account; returns the generated
    /// admin password when one was created.
    pub fn init(data_dir: &Path) -> Result<(Auth, Option<String>)> {
        let path = data_dir.join("users.json");
        let users: Vec<User> = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).with_context(|| format!("parsing {}", path.display()))?,
            Err(_) => Vec::new(),
        };
        let auth = Auth::from_users(path, users);
        let env = std::env::var("COPPERHOUND_ADMIN_PASSWORD").ok().filter(|p| !p.is_empty());
        let has_admin = auth.users.read().iter().any(|u| u.username == ADMIN_USER);
        let mut generated = None;
        if let Some(p) = env {
            // The environment is authoritative for the built-in admin.
            let needs = auth.users.read().iter().find(|u| u.username == ADMIN_USER).is_none_or(|u| !verify_password(&u.password_hash, &p));
            if needs {
                auth.upsert_admin(&p)?;
            }
        } else if !has_admin {
            let file = data_dir.join("admin_password");
            let p = match std::fs::read_to_string(&file).map(|s| s.trim().to_string()) {
                Ok(p) if !p.is_empty() => p,
                _ => {
                    let p = random_password();
                    std::fs::write(&file, &p).with_context(|| format!("writing {}", file.display()))?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600));
                    }
                    generated = Some(p.clone());
                    p
                }
            };
            auth.upsert_admin(&p)?;
        }
        Ok((auth, generated))
    }

    fn from_users(path: PathBuf, users: Vec<User>) -> Auth {
        Auth {
            path,
            users: RwLock::new(users),
            sessions: Mutex::new(AHashMap::new()),
            failures: Mutex::new(AHashMap::new()),
            dummy_hash: hash_password("copperhound-timing-equaliser").unwrap_or_default(),
        }
    }

    /// In-memory auth with a single admin (tests).
    pub fn with_password(password: String) -> Auth {
        let a = Auth::from_users(PathBuf::new(), Vec::new());
        a.upsert_admin(&password).expect("hash");
        a
    }

    fn upsert_admin(&self, password: &str) -> Result<()> {
        let hash = hash_password(password)?;
        {
            let mut us = self.users.write();
            match us.iter_mut().find(|u| u.username == ADMIN_USER) {
                Some(u) => {
                    u.password_hash = hash;
                    u.role = Role::Admin;
                    u.disabled = false;
                }
                None => us.insert(
                    0,
                    User {
                        username: ADMIN_USER.into(),
                        role: Role::Admin,
                        password_hash: hash,
                        created_at: now_rfc3339(),
                        disabled: false,
                        last_login: None,
                        tokens: Vec::new(),
                        source: UserSource::Local,
                        oidc_issuer: None,
                        oidc_subject: None,
                        mfa: None,
                    },
                ),
            }
        }
        self.persist()
    }

    fn persist(&self) -> Result<()> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&*self.users.read())?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    // ---------------------------------------------------------- sessions

    pub fn login(&self, username: &str, password: &str) -> Result<(String, Principal), LoginError> {
        self.login_with(username, password, None, |_| true)
    }

    /// Password login; `allowed` is consulted only after the password has
    /// been verified (so it never reveals whether an account exists) and can
    /// refuse the account by policy (single sign-on only).
    pub fn login_with(
        &self,
        username: &str,
        password: &str,
        otp: Option<&str>,
        allowed: impl Fn(&User) -> bool,
    ) -> Result<(String, Principal), LoginError> {
        let key = username.to_ascii_lowercase();
        if let Some(secs) = self.locked(&key) {
            return Err(LoginError::Locked(secs));
        }
        let user = self.users.read().iter().find(|u| u.username.eq_ignore_ascii_case(username)).cloned();
        let ok = match &user {
            Some(u) => u.source == UserSource::Local && verify_password(&u.password_hash, password) && !u.disabled,
            None => {
                let _ = verify_password(&self.dummy_hash, password);
                false
            }
        };
        if !ok {
            self.fail(&key);
            return Err(LoginError::Invalid);
        }
        let user = user.expect("checked");
        if !allowed(&user) {
            self.failures.lock().remove(&key);
            return Err(LoginError::PasswordDisabled);
        }
        if user.mfa_enabled() {
            let Some(code) = otp.map(str::trim).filter(|c| !c.is_empty()) else {
                return Err(LoginError::MfaRequired);
            };
            if !self.check_second_factor(&user.username, code) {
                self.fail(&key);
                return Err(LoginError::MfaInvalid);
            }
        }
        self.failures.lock().remove(&key);
        self.start_session(&user.username).ok_or(LoginError::Invalid)
    }

    /// Seconds left while `key` is locked out after repeated failures.
    fn locked(&self, key: &str) -> Option<u64> {
        let now = Instant::now();
        let f = self.failures.lock();
        let &(n, last) = f.get(key)?;
        (n >= MAX_FAILURES && now.duration_since(last) < LOCKOUT).then(|| (LOCKOUT - now.duration_since(last)).as_secs().max(1))
    }

    /// Count a failed attempt for `key`.
    fn fail(&self, key: &str) {
        let now = Instant::now();
        let mut f = self.failures.lock();
        // Forget expired entries so guesses at random names cannot grow the map without bound.
        if f.len() > 10_000 {
            f.retain(|_, e| now.duration_since(e.1) < LOCKOUT);
        }
        let e = f.entry(key.to_string()).or_insert((0, now));
        if now.duration_since(e.1) >= LOCKOUT {
            e.0 = 0;
        }
        e.0 += 1;
        e.1 = now;
    }

    /// Accept a TOTP code (once per time step) or consume a recovery code.
    fn check_second_factor(&self, username: &str, code: &str) -> bool {
        let unix = SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let ok = {
            let mut us = self.users.write();
            let Some(m) = us.iter_mut().find(|u| u.username == username).and_then(|u| u.mfa.as_mut()).filter(|m| m.enabled) else {
                return false;
            };
            if let Some(step) = crate::mfa::verify(&m.secret, code, unix, m.last_step) {
                m.last_step = step;
                true
            } else {
                let h = crate::mfa::hash_recovery(code);
                match m.recovery.iter().position(|r| *r == h) {
                    Some(i) => {
                        m.recovery.remove(i);
                        true
                    }
                    None => false,
                }
            }
        };
        if ok {
            let _ = self.persist();
        }
        ok
    }

    /// `(enabled, setup pending, recovery codes left)`.
    pub fn mfa_status(&self, username: &str) -> Option<(bool, bool, usize)> {
        let us = self.users.read();
        let u = us.iter().find(|u| u.username == username)?;
        Some(match &u.mfa {
            Some(m) => (m.enabled, !m.enabled, m.recovery.len()),
            None => (false, false, 0),
        })
    }

    /// Start (or restart) enrolment: a new pending secret.
    pub fn mfa_setup(&self, username: &str) -> Result<String> {
        let secret = crate::mfa::new_secret();
        {
            let mut us = self.users.write();
            let u = us.iter_mut().find(|u| u.username == username).ok_or_else(|| anyhow!("no such user"))?;
            if u.source != UserSource::Local {
                bail!("single sign-on accounts use their identity provider's multi-factor authentication");
            }
            if u.mfa_enabled() {
                bail!("two-factor sign-in is already on; turn it off first");
            }
            u.mfa = Some(crate::mfa::Mfa { secret: secret.clone(), ..Default::default() });
        }
        self.persist()?;
        Ok(secret)
    }

    /// Confirm enrolment with a code; returns the recovery codes (shown once).
    pub fn mfa_enable(&self, username: &str, code: &str) -> Result<Vec<String>> {
        let unix = SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let plain = {
            let mut us = self.users.write();
            let u = us.iter_mut().find(|u| u.username == username).ok_or_else(|| anyhow!("no such user"))?;
            let m = u.mfa.as_mut().filter(|m| !m.enabled).ok_or_else(|| anyhow!("start the setup first"))?;
            let step = crate::mfa::verify(&m.secret, code, unix, 0).ok_or_else(|| anyhow!("that code is not valid; check the device clock"))?;
            let (plain, hashed) = crate::mfa::recovery_codes(crate::mfa::RECOVERY_CODES);
            m.enabled = true;
            m.last_step = step;
            m.recovery = hashed;
            plain
        };
        self.persist()?;
        Ok(plain)
    }

    /// Turn two-factor sign-in off after checking a current code (or a recovery code).
    /// Turn off two-factor sign-in with a current code. Wrong codes count
    /// toward a lockout like sign-in does (separately, so a held session
    /// cannot lock the account out of signing in).
    pub fn mfa_disable(&self, username: &str, code: &str) -> Result<()> {
        let key = format!("mfa-disable:{}", username.to_ascii_lowercase());
        if let Some(secs) = self.locked(&key) {
            bail!("too many wrong codes; try again in {secs} s");
        }
        if !self.check_second_factor(username, code) {
            self.fail(&key);
            bail!("that code is not valid");
        }
        self.failures.lock().remove(&key);
        self.mfa_reset(username)
    }

    /// Remove two-factor sign-in (admin reset, or after `mfa_disable`'s check).
    pub fn mfa_reset(&self, username: &str) -> Result<()> {
        {
            let mut us = self.users.write();
            let u = us.iter_mut().find(|u| u.username == username).ok_or_else(|| anyhow!("no such user"))?;
            u.mfa = None;
        }
        self.persist()
    }

    /// Open a session for an existing, enabled account (records the login).
    /// Used after password verification and after single sign-on.
    pub fn start_session(&self, username: &str) -> Option<(String, Principal)> {
        let principal = {
            let mut us = self.users.write();
            let u = us.iter_mut().find(|u| u.username == username && !u.disabled)?;
            u.last_login = Some(now_rfc3339());
            Principal { username: u.username.clone(), role: u.role, via_token: false }
        };
        let _ = self.persist();
        let now = Instant::now();
        let token = random_hex(32);
        let mut s = self.sessions.lock();
        s.retain(|_, (_, exp)| *exp > now);
        s.insert(token.clone(), (principal.username.clone(), now + SESSION_TTL));
        Some((token, principal))
    }

    /// Find or just-in-time create the account for an OIDC identity and set
    /// its role (re-evaluated on every sign-in; the IdP is authoritative).
    ///
    /// Accounts are matched by (issuer, subject), never by username alone, so
    /// an IdP user called `admin` cannot take over the local `admin`.
    pub fn upsert_oidc_user(&self, issuer: &str, subject: &str, username: &str, role: Role) -> Result<User, OidcLinkError> {
        let out = {
            let mut us = self.users.write();
            let linked = us.iter().position(|u| {
                u.source == UserSource::Oidc && u.oidc_issuer.as_deref() == Some(issuer) && u.oidc_subject.as_deref() == Some(subject)
            });
            match linked {
                Some(i) => {
                    let u = &mut us[i];
                    if u.disabled {
                        return Err(OidcLinkError::Disabled(u.username.clone()));
                    }
                    u.role = role;
                    u.clone()
                }
                None => {
                    if !valid_username(username) {
                        return Err(OidcLinkError::Other(format!("unusable username {username:?}")));
                    }
                    if let Some(u) = us.iter().find(|u| u.username.eq_ignore_ascii_case(username)) {
                        let what = if u.source == UserSource::Local { "a local account" } else { "another single sign-on identity" };
                        return Err(OidcLinkError::Conflict(format!("username {} already belongs to {what}", u.username)));
                    }
                    let u = User {
                        username: username.to_string(),
                        role,
                        password_hash: String::new(),
                        created_at: now_rfc3339(),
                        disabled: false,
                        last_login: None,
                        tokens: Vec::new(),
                        source: UserSource::Oidc,
                        oidc_issuer: Some(issuer.to_string()),
                        oidc_subject: Some(subject.to_string()),
                        mfa: None,
                    };
                    us.push(u.clone());
                    u
                }
            }
        };
        self.persist().map_err(|e| OidcLinkError::Other(format!("{e:#}")))?;
        Ok(out)
    }

    /// Whether an enabled single sign-on account with the admin role has
    /// signed in at least once (proves SSO admin access works).
    pub fn sso_admin_has_signed_in(&self) -> bool {
        self.users
            .read()
            .iter()
            .any(|u| u.source == UserSource::Oidc && u.role == Role::Admin && !u.disabled && u.last_login.is_some())
    }

    /// Validate a session or API token and resolve the caller.
    pub fn check(&self, token: &str) -> Option<Principal> {
        if token.starts_with(TOKEN_PREFIX) {
            return self.check_api_token(token);
        }
        let username = {
            let mut s = self.sessions.lock();
            let now = Instant::now();
            match s.get_mut(token) {
                Some((u, exp)) if *exp > now => {
                    *exp = now + SESSION_TTL;
                    u.clone()
                }
                Some(_) => {
                    s.remove(token);
                    return None;
                }
                None => return None,
            }
        };
        let us = self.users.read();
        let u = us.iter().find(|u| u.username == username && !u.disabled)?;
        Some(Principal { username: u.username.clone(), role: u.role, via_token: false })
    }

    fn check_api_token(&self, token: &str) -> Option<Principal> {
        let hash = sha256_hex(token);
        self.token_principal(|t| t.hash == hash)
    }

    /// Stored hash (the HMAC key of signed requests) of a usable token.
    pub fn token_hash_by_id(&self, id: &str) -> Option<String> {
        let now = SystemTime::now();
        let us = self.users.read();
        us.iter().filter(|u| !u.disabled).flat_map(|u| u.tokens.iter()).find(|t| t.id == id).filter(|t| !token_expired(t, now)).map(|t| t.hash.clone())
    }

    /// Principal of the token with this id (records its use).
    pub fn token_principal_by_id(&self, id: &str) -> Option<Principal> {
        self.token_principal(|t| t.id == id)
    }

    fn token_principal(&self, pick: impl Fn(&ApiToken) -> bool) -> Option<Principal> {
        let now = SystemTime::now();
        let mut dirty = false;
        let found = {
            let mut us = self.users.write();
            let mut found = None;
            for u in us.iter_mut().filter(|u| !u.disabled) {
                if let Some(t) = u.tokens.iter_mut().find(|t| pick(t)) {
                    if token_expired(t, now) {
                        return None;
                    }
                    let stale = t
                        .last_used
                        .as_deref()
                        .and_then(|l| humantime::parse_rfc3339(l).ok())
                        .is_none_or(|l| now.duration_since(l).unwrap_or_default() > Duration::from_secs(600));
                    if stale {
                        t.last_used = Some(now_rfc3339());
                        dirty = true;
                    }
                    found = Some(Principal { username: u.username.clone(), role: u.role, via_token: true });
                    break;
                }
            }
            found
        };
        if dirty {
            let _ = self.persist();
        }
        found
    }

    pub fn logout(&self, token: &str) {
        self.sessions.lock().remove(token);
    }

    pub fn drop_sessions_of(&self, username: &str) {
        self.sessions.lock().retain(|_, (u, _)| u != username);
    }

    /// Revoke the sessions of the SSO account linked to `(issuer, subject)`, if any.
    pub fn drop_sessions_of_identity(&self, issuer: &str, subject: &str) {
        let user = self.users.read().iter().find(|u| {
            u.source == UserSource::Oidc && u.oidc_issuer.as_deref() == Some(issuer) && u.oidc_subject.as_deref() == Some(subject)
        }).map(|u| u.username.clone());
        if let Some(u) = user {
            self.drop_sessions_of(&u);
        }
    }

    // ------------------------------------------------------- management

    pub fn list(&self) -> Vec<User> {
        self.users.read().clone()
    }

    pub fn get(&self, username: &str) -> Option<User> {
        self.users.read().iter().find(|u| u.username == username).cloned()
    }

    fn enabled_admins_except(us: &[User], name: &str) -> usize {
        us.iter().filter(|u| u.role == Role::Admin && !u.disabled && u.username != name).count()
    }

    pub fn create(&self, username: &str, password: &str, role: Role) -> Result<User> {
        if !valid_username(username) {
            bail!("usernames are 1-64 characters: letters, digits and . _ - @");
        }
        check_password_policy(password)?;
        let hash = hash_password(password)?;
        let user = User {
            username: username.to_string(),
            role,
            password_hash: hash,
            created_at: now_rfc3339(),
            disabled: false,
            last_login: None,
            tokens: Vec::new(),
            source: UserSource::Local,
            oidc_issuer: None,
            oidc_subject: None,
            mfa: None,
        };
        {
            let mut us = self.users.write();
            if us.iter().any(|u| u.username.eq_ignore_ascii_case(username)) {
                bail!("user {username} already exists");
            }
            us.push(user.clone());
        }
        self.persist()?;
        Ok(user)
    }

    /// Change role, password or disabled state. Refuses to leave the server
    /// without an enabled admin.
    pub fn update(&self, username: &str, role: Option<Role>, password: Option<&str>, disabled: Option<bool>) -> Result<User> {
        if let Some(p) = password {
            check_password_policy(p)?;
        }
        let hash = password.map(hash_password).transpose()?;
        let out = {
            let mut us = self.users.write();
            let others = Self::enabled_admins_except(&us, username);
            let u = us.iter_mut().find(|u| u.username == username).ok_or_else(|| anyhow!("no such user"))?;
            if hash.is_some() && u.source == UserSource::Oidc {
                bail!("single sign-on accounts have no password; manage them at the identity provider");
            }
            let will_admin = role.unwrap_or(u.role) == Role::Admin && !disabled.unwrap_or(u.disabled);
            if others == 0 && !will_admin {
                bail!("at least one enabled admin must remain");
            }
            if let Some(r) = role {
                u.role = r;
            }
            if let Some(h) = hash {
                u.password_hash = h;
            }
            if let Some(d) = disabled {
                u.disabled = d;
            }
            u.clone()
        };
        if password.is_some() || out.disabled {
            self.drop_sessions_of(username);
        }
        self.persist()?;
        Ok(out)
    }

    pub fn delete(&self, username: &str) -> Result<()> {
        {
            let mut us = self.users.write();
            let idx = us.iter().position(|u| u.username == username).ok_or_else(|| anyhow!("no such user"))?;
            if Self::enabled_admins_except(&us, username) == 0 {
                bail!("at least one enabled admin must remain");
            }
            us.remove(idx);
        }
        self.drop_sessions_of(username);
        self.persist()
    }

    pub fn change_own_password(&self, username: &str, current: &str, new: &str) -> Result<()> {
        let u = self.get(username).ok_or_else(|| anyhow!("no such user"))?;
        if u.source == UserSource::Oidc {
            bail!("single sign-on accounts have no password; change it at the identity provider");
        }
        if !verify_password(&u.password_hash, current) {
            bail!("current password is incorrect");
        }
        self.update(username, None, Some(new), None)?;
        Ok(())
    }

    // ------------------------------------------------------- API tokens

    /// Returns the stored record and the plaintext token (shown once).
    pub fn create_token(&self, username: &str, name: &str, expires_days: Option<u64>) -> Result<(ApiToken, String)> {
        let name = name.trim();
        if name.is_empty() || name.len() > 100 {
            bail!("token name must be 1-100 characters");
        }
        let plain = format!("{TOKEN_PREFIX}{}", random_hex(24));
        let rec = ApiToken {
            id: random_hex(8),
            name: name.to_string(),
            hash: sha256_hex(&plain),
            prefix: plain[..12].to_string(),
            created_at: now_rfc3339(),
            expires_at: expires_days.map(|d| {
                humantime::format_rfc3339_seconds(SystemTime::now() + Duration::from_secs(d * 86_400)).to_string()
            }),
            last_used: None,
        };
        {
            let mut us = self.users.write();
            let u = us.iter_mut().find(|u| u.username == username).ok_or_else(|| anyhow!("no such user"))?;
            if u.tokens.len() >= 50 {
                bail!("a user can hold at most 50 API tokens");
            }
            u.tokens.push(rec.clone());
        }
        self.persist()?;
        Ok((rec, plain))
    }

    pub fn delete_token(&self, username: &str, id: &str) -> Result<bool> {
        let removed = {
            let mut us = self.users.write();
            let u = us.iter_mut().find(|u| u.username == username).ok_or_else(|| anyhow!("no such user"))?;
            let before = u.tokens.len();
            u.tokens.retain(|t| t.id != id);
            before != u.tokens.len()
        };
        if removed {
            self.persist()?;
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_check_logout() {
        let a = Auth::with_password("s3cret-password".into());
        assert_eq!(a.login("admin", "wrong").unwrap_err(), LoginError::Invalid);
        assert!(a.login("root", "s3cret-password").is_err());
        let (t, p) = a.login("admin", "s3cret-password").unwrap();
        assert_eq!(p.role, Role::Admin);
        assert!(a.check(&t).is_some());
        a.logout(&t);
        assert!(a.check(&t).is_none());
    }

    #[test]
    fn mfa_disable_wrong_codes_lock_out() {
        use crate::mfa::{base32_decode, code_at, STEP_SECS};
        let a = Auth::with_password("s3cret-password".into());
        let secret = a.mfa_setup("admin").unwrap();
        let step = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / STEP_SECS;
        let recovery = a.mfa_enable("admin", &format!("{:06}", code_at(&base32_decode(&secret).unwrap(), step))).unwrap();
        for _ in 0..MAX_FAILURES {
            assert!(a.mfa_disable("admin", "000000").is_err());
        }
        let e = a.mfa_disable("admin", &recovery[0]).unwrap_err();
        assert!(e.to_string().contains("too many"), "{e}");
        assert!(a.mfa_status("admin").unwrap().0, "still enabled");
        // Sign-in has its own counter.
        assert!(a.login_with("admin", "s3cret-password", Some(&recovery[1]), |_| true).is_ok());
    }

    #[test]
    fn lockout_after_failures() {
        let a = Auth::with_password("s3cret-password".into());
        for _ in 0..MAX_FAILURES {
            assert_eq!(a.login("admin", "nope").unwrap_err(), LoginError::Invalid);
        }
        assert!(matches!(a.login("admin", "s3cret-password"), Err(LoginError::Locked(_))));
    }

    #[test]
    fn users_roles_tokens() {
        let a = Auth::with_password("s3cret-password".into());
        assert!(a.create("bob", "short", Role::Viewer).is_err());
        a.create("bob", "bob-long-password", Role::Viewer).unwrap();
        assert!(a.create("BOB", "bob-long-password", Role::Viewer).is_err());
        let (t, p) = a.login("bob", "bob-long-password").unwrap();
        assert_eq!(p.role, Role::Viewer);
        // Role changes apply to live sessions.
        a.update("bob", Some(Role::Analyst), None, None).unwrap();
        assert_eq!(a.check(&t).unwrap().role, Role::Analyst);
        // Disabling ends sessions.
        a.update("bob", None, None, Some(true)).unwrap();
        assert!(a.check(&t).is_none());
        a.update("bob", None, None, Some(false)).unwrap();
        // Last admin is protected.
        assert!(a.update("admin", Some(Role::Viewer), None, None).is_err());
        assert!(a.delete("admin").is_err());
        // API tokens.
        let (rec, plain) = a.create_token("bob", "ci", Some(30)).unwrap();
        assert!(plain.starts_with("cht_"));
        let p = a.check(&plain).unwrap();
        assert!(p.via_token && p.username == "bob");
        assert!(a.delete_token("bob", &rec.id).unwrap());
        assert!(a.check(&plain).is_none());
        a.delete("bob").unwrap();
    }

    #[test]
    fn oidc_accounts() {
        let a = Auth::with_password("s3cret-password".into());
        // Never links to a local account by name.
        assert!(matches!(a.upsert_oidc_user("https://idp", "sub-1", "admin", Role::Admin), Err(OidcLinkError::Conflict(_))));
        let u = a.upsert_oidc_user("https://idp", "sub-1", "alice@corp.example", Role::Viewer).unwrap();
        assert_eq!(u.source, UserSource::Oidc);
        // Same identity: role re-evaluated, username kept.
        let u = a.upsert_oidc_user("https://idp", "sub-1", "renamed", Role::Analyst).unwrap();
        assert_eq!((u.username.as_str(), u.role), ("alice@corp.example", Role::Analyst));
        // Different subject, same name: conflict.
        assert!(matches!(
            a.upsert_oidc_user("https://idp", "sub-2", "ALICE@corp.example", Role::Viewer),
            Err(OidcLinkError::Conflict(_))
        ));
        // No password sign-in, no password set.
        assert_eq!(a.login("alice@corp.example", "").unwrap_err(), LoginError::Invalid);
        assert!(a.update("alice@corp.example", None, Some("a-long-password"), None).is_err());
        assert!(!a.sso_admin_has_signed_in());
        a.upsert_oidc_user("https://idp", "sub-1", "x", Role::Admin).unwrap();
        a.start_session("alice@corp.example").unwrap();
        assert!(a.sso_admin_has_signed_in());
        a.update("alice@corp.example", None, None, Some(true)).unwrap();
        assert!(matches!(a.upsert_oidc_user("https://idp", "sub-1", "x", Role::Admin), Err(OidcLinkError::Disabled(_))));
        assert!(a.start_session("alice@corp.example").is_none());
        // Policy refusal only after a correct password.
        assert_eq!(a.login_with("admin", "wrong", None, |_| false).unwrap_err(), LoginError::Invalid);
        assert_eq!(a.login_with("admin", "s3cret-password", None, |_| false).unwrap_err(), LoginError::PasswordDisabled);
    }
}
