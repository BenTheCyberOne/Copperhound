//! Built-in LDAP collector: the server reads a domain controller directly
//! (no agent or SharpHound run needed) and ingests the result as LDIF.
//!
//! Per target: connect over LDAPS (or StartTLS; plain LDAP only when
//! explicitly allowed), simple-bind with a read-only account, read the
//! RootDSE, then page through the domain naming context and (optionally) the
//! configuration context with the security-descriptor flags control (owner,
//! group and DACL, readable by non-admins), fetch `member` beyond 1,500 values
//! through range retrieval, and read the LAPS schema GUIDs. The entries are
//! written as `uploads/ldap-<target>.ldif.gz` (one file per target, replaced on
//! each run) and an ingest is queued; the LDIF reader does the rest.
//!
//! Data that LDAP does not hold (sessions, local groups, user rights) is not
//! collected; see the data-quality page. Configuration: `<data>/ldap_collect.json`
//! (the bind password is stored there and never returned by the API).

use crate::api::{ApiError, St};
use crate::auth::Principal;
use crate::state::{now_rfc3339, AppState};
use axum::extract::{Path, State};
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::controls::RawControl;
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

const SD_FLAGS_OID: &str = "1.2.840.113556.1.4.801";
/// BER `SEQUENCE { INTEGER 7 }`: owner, group and DACL (no SACL).
const SD_FLAGS_VALUE: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x07];
const ATTRS: &[&str] = &["*", "nTSecurityDescriptor", "msDS-GroupMSAMembership", "msDS-AllowedToActOnBehalfOfOtherIdentity"];
const PAGE: i32 = 1000;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct Target {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// `ldaps://dc01.corp.local` (or `ldap://…` with StartTLS / plain).
    pub url: String,
    pub starttls: bool,
    /// Accept plain `ldap://` without TLS (lab use only).
    pub allow_plain: bool,
    /// Skip certificate verification (self-signed DC certificates in labs).
    pub insecure_skip_verify: bool,
    /// `user@corp.local` or a DN.
    pub bind_dn: String,
    /// Write-only; never returned.
    pub password: String,
    /// Empty: the RootDSE `defaultNamingContext`.
    pub base_dn: String,
    pub include_configuration: bool,
    pub interval_hours: u32,
    // ---- status (written by the collector)
    pub last_run: Option<String>,
    pub last_ok: Option<String>,
    pub last_error: Option<String>,
    pub last_objects: u64,
    pub last_seconds: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Store {
    targets: Vec<Target>,
}

static LOCK: Mutex<()> = Mutex::new(());
static RUNNING: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn path(st: &AppState) -> std::path::PathBuf {
    st.data_dir.join("ldap_collect.json")
}

fn load(st: &AppState) -> Store {
    crate::state::load_json(&path(st))
}

fn save(st: &AppState, s: &Store) -> anyhow::Result<()> {
    crate::state::store_json(&path(st), s)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path(st), std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn public(t: &Target) -> Value {
    let mut v = serde_json::to_value(t).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        o.remove("password");
        o.insert("password_set".into(), json!(!t.password.is_empty()));
        o.insert("running".into(), json!(RUNNING.lock().contains(&t.id)));
    }
    v
}

fn update_status(st: &AppState, id: &str, f: impl FnOnce(&mut Target)) {
    let _g = LOCK.lock();
    let mut s = load(st);
    if let Some(t) = s.targets.iter_mut().find(|t| t.id == id) {
        f(t);
        let _ = save(st, &s);
    }
}

fn slug(s: &str) -> String {
    let s: String = s.to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
    s.split('-').filter(|p| !p.is_empty()).collect::<Vec<_>>().join("-").chars().take(40).collect()
}

// ------------------------------------------------------------------ LDIF

fn safe_string(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with([' ', ':', '<'])
        && !s.ends_with(' ')
        && s.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// One `attr: value` / `attr:: base64` line (RFC 2849, unwrapped).
pub fn ldif_line(out: &mut Vec<u8>, attr: &str, value: &[u8]) {
    match std::str::from_utf8(value) {
        Ok(s) if safe_string(s) => {
            let _ = writeln!(out, "{attr}: {s}");
        }
        _ => {
            let _ = writeln!(out, "{attr}:: {}", STANDARD.encode(value));
        }
    }
}

/// Write an entry; `ranged` holds the complete values of range-retrieved attributes.
pub fn ldif_entry(out: &mut Vec<u8>, e: &SearchEntry, ranged: &[(String, Vec<Vec<u8>>)]) {
    ldif_line(out, "dn", e.dn.as_bytes());
    let mut keys: Vec<&String> = e.attrs.keys().chain(e.bin_attrs.keys()).collect();
    keys.sort();
    keys.dedup();
    for k in keys {
        if k.contains(";range=") {
            continue;
        }
        for v in e.attrs.get(k).into_iter().flatten() {
            ldif_line(out, k, v.as_bytes());
        }
        for v in e.bin_attrs.get(k).into_iter().flatten() {
            ldif_line(out, k, v);
        }
    }
    for (k, vals) in ranged {
        for v in vals {
            ldif_line(out, k, v);
        }
    }
    out.push(b'\n');
}

/// `member;range=0-1499` → (`member`, next start) when more values remain.
pub fn range_next(key: &str) -> Option<(String, Option<u64>)> {
    let (attr, r) = key.split_once(";range=")?;
    let (_, end) = r.split_once('-')?;
    Some((attr.to_string(), if end == "*" { None } else { end.parse::<u64>().ok().map(|e| e + 1) }))
}

// ------------------------------------------------------------ collection

async fn connect(t: &Target) -> anyhow::Result<ldap3::Ldap> {
    let url = t.url.trim();
    let tls = url.starts_with("ldaps://") || t.starttls;
    if !tls && !t.allow_plain {
        anyhow::bail!("refusing plain LDAP: use ldaps:// or StartTLS (or allow plain LDAP for a lab)");
    }
    let mut settings = LdapConnSettings::new().set_conn_timeout(Duration::from_secs(15)).set_starttls(t.starttls && !url.starts_with("ldaps://"));
    if t.insecure_skip_verify {
        settings = settings.set_no_tls_verify(true);
    }
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, url).await?;
    ldap3::drive!(conn);
    ldap.with_timeout(Duration::from_secs(60)).simple_bind(t.bind_dn.trim(), &t.password).await?.success().map_err(|e| anyhow::anyhow!("bind failed: {e}"))?;
    Ok(ldap)
}

struct RootDse {
    default_nc: String,
    config_nc: String,
    schema_nc: String,
    dns_host: String,
}

async fn root_dse(ldap: &mut ldap3::Ldap) -> anyhow::Result<RootDse> {
    let (rs, _) = ldap
        .search("", Scope::Base, "(objectClass=*)", vec!["defaultNamingContext", "configurationNamingContext", "schemaNamingContext", "dnsHostName"])
        .await?
        .success()?;
    let e = SearchEntry::construct(rs.into_iter().next().ok_or_else(|| anyhow::anyhow!("empty RootDSE"))?);
    let get = |k: &str| e.attrs.get(k).and_then(|v| v.first()).cloned().unwrap_or_default();
    Ok(RootDse { default_nc: get("defaultNamingContext"), config_nc: get("configurationNamingContext"), schema_nc: get("schemaNamingContext"), dns_host: get("dnsHostName") })
}

/// All values of a range-retrieved attribute of `dn`, starting at `from`.
async fn rest_of_range(ldap: &mut ldap3::Ldap, dn: &str, attr: &str, mut from: u64) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    loop {
        let want = format!("{attr};range={from}-*");
        let (rs, _) = ldap.search(dn, Scope::Base, "(objectClass=*)", vec![want.as_str()]).await?.success()?;
        let Some(re) = rs.into_iter().next() else { break };
        let e = SearchEntry::construct(re);
        let mut next = None;
        for (k, vals) in e.attrs.iter() {
            if let Some((a, n)) = range_next(k) {
                if a.eq_ignore_ascii_case(attr) {
                    out.extend(vals.iter().map(|v| v.as_bytes().to_vec()));
                    next = n;
                }
            }
        }
        match next {
            Some(n) if n > from => from = n,
            _ => break,
        }
    }
    Ok(out)
}

/// Page through `base` (subtree) into `out`; returns the entry count.
async fn dump_nc(ldap: &mut ldap3::Ldap, base: &str, filter: &str, attrs: &[&str], out: &mut Vec<u8>) -> anyhow::Result<u64> {
    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![Box::new(EntriesOnly::new()), Box::new(PagedResults::new(PAGE))];
    // Not critical: servers without the control (non-AD) just ignore it.
    let sd = RawControl { ctype: SD_FLAGS_OID.to_string(), crit: false, val: Some(SD_FLAGS_VALUE.to_vec()) };
    let mut search = ldap.with_controls(vec![sd]).streaming_search_with(adapters, base, Scope::Subtree, filter, attrs.to_vec()).await?;
    let mut entries = Vec::new();
    while let Some(re) = search.next().await? {
        entries.push(SearchEntry::construct(re));
    }
    search.finish().await.success().map_err(|e| anyhow::anyhow!("search {base}: {e}"))?;
    let mut n = 0;
    for e in &entries {
        let mut ranged = Vec::new();
        for k in e.attrs.keys() {
            if let Some((attr, next)) = range_next(k) {
                let mut vals: Vec<Vec<u8>> = e.attrs[k].iter().map(|v| v.as_bytes().to_vec()).collect();
                if let Some(from) = next {
                    vals.extend(rest_of_range(ldap, &e.dn, &attr, from).await?);
                }
                ranged.push((attr, vals));
            }
        }
        ldif_entry(out, e, &ranged);
        n += 1;
    }
    Ok(n)
}

/// Run one target: returns `(objects, file name)`.
pub async fn collect(st: &AppState, t: &Target) -> anyhow::Result<(u64, String)> {
    let mut ldap = connect(t).await?;
    let dse = root_dse(&mut ldap).await?;
    let base = if t.base_dn.trim().is_empty() { dse.default_nc.clone() } else { t.base_dn.trim().to_string() };
    if base.is_empty() {
        anyhow::bail!("no base DN (RootDSE has no defaultNamingContext)");
    }
    let mut out: Vec<u8> = Vec::new();
    let _ = writeln!(out, "# CopperHound LDAP collector · {} · {} · {}", t.name, dse.dns_host, now_rfc3339());
    out.push(b'\n');
    let mut n = dump_nc(&mut ldap, &base, "(objectClass=*)", ATTRS, &mut out).await?;
    if t.include_configuration && !dse.config_nc.is_empty() {
        n += dump_nc(&mut ldap, &dse.config_nc, "(objectClass=*)", ATTRS, &mut out).await?;
    }
    if !dse.schema_nc.is_empty() {
        let f = "(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=msLAPS-Password)(lDAPDisplayName=msLAPS-EncryptedPassword))";
        n += dump_nc(&mut ldap, &dse.schema_nc, f, &["lDAPDisplayName", "schemaIDGUID", "objectClass"], &mut out).await.unwrap_or(0);
    }
    let _ = ldap.unbind().await;
    let name = format!("ldap-{}.ldif.gz", if slug(&t.name).is_empty() { t.id.clone() } else { slug(&t.name) });
    let dir = st.uploads_dir();
    let tmp = dir.join(format!(".{name}.part"));
    {
        let f = std::fs::File::create(&tmp)?;
        let mut gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
        gz.write_all(&out)?;
        gz.finish()?;
    }
    std::fs::rename(&tmp, dir.join(&name))?;
    Ok((n, name))
}

/// Run a target now (in the background); `Err` if it is already running.
pub fn start_run(st: &Arc<AppState>, id: &str) -> Result<(), ApiError> {
    let t = load(st).targets.into_iter().find(|t| t.id == id).ok_or_else(|| ApiError::not_found("no such LDAP target"))?;
    {
        let mut r = RUNNING.lock();
        if r.contains(&t.id) {
            return Err(ApiError::new(axum::http::StatusCode::CONFLICT, "this target is already being collected"));
        }
        r.push(t.id.clone());
    }
    let st = st.clone();
    tokio::spawn(async move {
        let started = std::time::Instant::now();
        update_status(&st, &t.id, |x| x.last_run = Some(now_rfc3339()));
        let res = collect(&st, &t).await;
        let secs = started.elapsed().as_secs_f64();
        match res {
            Ok((n, file)) => {
                tracing::info!("LDAP collection {}: {n} objects in {secs:.1}s → {file}", t.name);
                update_status(&st, &t.id, |x| {
                    x.last_ok = Some(now_rfc3339());
                    x.last_error = None;
                    x.last_objects = n;
                    x.last_seconds = (secs * 10.0).round() / 10.0;
                });
                crate::collectors::record_upload(&st, &format!("ldap:{}", t.id), std::slice::from_ref(&file));
                // Retry for a while if another ingest is running.
                for _ in 0..60 {
                    if crate::api::queue_ingest(&st, "ldap-collector").is_ok() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            }
            Err(e) => {
                tracing::warn!("LDAP collection {} failed: {e:#}", t.name);
                update_status(&st, &t.id, |x| x.last_error = Some(format!("{e:#}")));
            }
        }
        RUNNING.lock().retain(|x| x != &t.id);
    });
    Ok(())
}

/// Scheduler: run enabled targets whose interval has elapsed.
pub fn spawn(st: &Arc<AppState>) {
    let st = st.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let now = std::time::SystemTime::now();
            for t in load(&st).targets.into_iter().filter(|t| t.enabled && t.interval_hours > 0) {
                let due = t
                    .last_run
                    .as_deref()
                    .and_then(|r| humantime::parse_rfc3339_weak(r).ok())
                    .is_none_or(|r| now.duration_since(r).unwrap_or_default() >= Duration::from_secs(t.interval_hours as u64 * 3600));
                if due {
                    let _ = start_run(&st, &t.id);
                }
            }
        }
    });
}

// ------------------------------------------------------------------ API

pub async fn list(State(st): St) -> Json<Value> {
    Json(json!(load(&st).targets.iter().map(public).collect::<Vec<_>>()))
}

#[derive(Deserialize)]
pub struct TargetIn {
    #[serde(default)]
    id: Option<String>,
    name: String,
    #[serde(default)]
    enabled: bool,
    url: String,
    #[serde(default)]
    starttls: bool,
    #[serde(default)]
    allow_plain: bool,
    #[serde(default)]
    insecure_skip_verify: bool,
    bind_dn: String,
    /// `null` / absent keeps the stored password.
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    base_dn: String,
    #[serde(default = "yes")]
    include_configuration: bool,
    #[serde(default = "day")]
    interval_hours: u32,
}

fn yes() -> bool {
    true
}
fn day() -> u32 {
    24
}

fn validate(t: &Target) -> Result<(), ApiError> {
    if t.name.trim().is_empty() || t.name.len() > 64 {
        return Err(ApiError::bad("name must be 1-64 characters"));
    }
    let u = t.url.trim();
    if !(u.starts_with("ldaps://") || u.starts_with("ldap://")) || url::Url::parse(u).is_err() {
        return Err(ApiError::bad("url must be ldaps://host[:port] or ldap://host[:port]"));
    }
    if u.starts_with("ldap://") && !t.starttls && !t.allow_plain {
        return Err(ApiError::bad("ldap:// needs StartTLS (or explicitly allow plain LDAP)"));
    }
    if t.bind_dn.trim().is_empty() || t.password.is_empty() {
        return Err(ApiError::bad("bind_dn and password are required"));
    }
    if t.interval_hours > 24 * 31 {
        return Err(ApiError::bad("interval_hours must be 0-744 (0 = manual only)"));
    }
    Ok(())
}

pub async fn upsert(State(st): St, Extension(who): Extension<Principal>, Json(r): Json<TargetIn>) -> Result<Json<Value>, ApiError> {
    let t = {
        let _g = LOCK.lock();
        let mut s = load(&st);
        let existing = r.id.as_ref().and_then(|id| s.targets.iter().position(|t| &t.id == id));
        let base = existing.map(|i| s.targets[i].clone()).unwrap_or_default();
        let t = Target {
            id: if base.id.is_empty() { crate::auth::random_hex(6) } else { base.id.clone() },
            name: r.name.trim().to_string(),
            enabled: r.enabled,
            url: r.url.trim().to_string(),
            starttls: r.starttls,
            allow_plain: r.allow_plain,
            insecure_skip_verify: r.insecure_skip_verify,
            bind_dn: r.bind_dn.trim().to_string(),
            // The stored password is reused only for the same server, and
            // not once TLS protection is weakened (StartTLS off, plain LDAP
            // or certificate checks turned off).
            password: r.password.filter(|p| !p.is_empty()).unwrap_or_else(|| {
                let same_server = crate::notify::same_origin(&base.url, r.url.trim());
                let weakened = (base.starttls && !r.starttls) || (!base.allow_plain && r.allow_plain) || (!base.insecure_skip_verify && r.insecure_skip_verify);
                if same_server && !weakened { base.password.clone() } else { String::new() }
            }),
            base_dn: r.base_dn.trim().to_string(),
            include_configuration: r.include_configuration,
            interval_hours: r.interval_hours,
            ..base.clone()
        };
        validate(&t)?;
        match existing {
            Some(i) => s.targets[i] = t.clone(),
            None => s.targets.push(t.clone()),
        }
        save(&st, &s)?;
        t
    };
    st.audit.record(crate::audit::AuditEntry {
        ts: now_rfc3339(),
        user: who.username,
        role: who.role.as_str().into(),
        action: "ldap-target-saved".into(),
        method: "PUT".into(),
        path: "/api/v1/collect/ldap".into(),
        status: 200,
        ip: None,
        detail: Some(format!("{} ({})", t.name, t.url)),
    });
    Ok(Json(public(&t)))
}

pub async fn remove(State(st): St, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let _g = LOCK.lock();
    let mut s = load(&st);
    let before = s.targets.len();
    s.targets.retain(|t| t.id != id);
    if s.targets.len() == before {
        return Err(ApiError::not_found("no such LDAP target"));
    }
    save(&st, &s)?;
    Ok(Json(json!({"deleted": id})))
}

pub async fn run_now(State(st): St, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    start_run(&st, &id)?;
    Ok(Json(json!({"started": id})))
}

/// Connect, bind and read the RootDSE without collecting.
pub async fn test(State(st): St, Path(id): Path<String>) -> Json<Value> {
    let Some(t) = load(&st).targets.into_iter().find(|t| t.id == id) else {
        return Json(json!({"ok": false, "error": "no such LDAP target"}));
    };
    let res = async {
        let mut l = connect(&t).await?;
        let d = root_dse(&mut l).await?;
        let _ = l.unbind().await;
        anyhow::Ok(d)
    };
    match tokio::time::timeout(Duration::from_secs(30), res).await {
        Ok(Ok(d)) => Json(json!({"ok": true, "default_naming_context": d.default_nc, "configuration_naming_context": d.config_nc, "dns_host_name": d.dns_host})),
        Ok(Err(e)) => Json(json!({"ok": false, "error": format!("{e:#}")})),
        Err(_) => Json(json!({"ok": false, "error": "timed out"})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn ldif_encoding_and_ranges() {
        let mut out = Vec::new();
        ldif_line(&mut out, "cn", b"alice");
        ldif_line(&mut out, "description", b" leading space");
        ldif_line(&mut out, "objectSid", &[1, 5, 0, 0]);
        ldif_line(&mut out, "name", "Jürgen".as_bytes());
        let s = String::from_utf8(out).unwrap();
        assert_eq!(s, "cn: alice\ndescription:: IGxlYWRpbmcgc3BhY2U=\nobjectSid:: AQUAAA==\nname:: SsO8cmdlbg==\n");
        assert_eq!(range_next("member;range=0-1499"), Some(("member".into(), Some(1500))));
        assert_eq!(range_next("member;range=1500-*"), Some(("member".into(), None)));
        assert_eq!(range_next("member"), None);

        let e = SearchEntry {
            dn: "CN=G,DC=corp,DC=local".into(),
            attrs: HashMap::from([("cn".into(), vec!["G".into()]), ("member;range=0-1".into(), vec!["CN=a".into(), "CN=b".into()])]),
            bin_attrs: HashMap::from([("objectSid".into(), vec![vec![1, 2]])]),
        };
        let mut out = Vec::new();
        ldif_entry(&mut out, &e, &[("member".into(), vec![b"CN=a".to_vec(), b"CN=b".to_vec(), b"CN=c".to_vec()])]);
        let s = String::from_utf8(out).unwrap();
        assert_eq!(s, "dn: CN=G,DC=corp,DC=local\ncn: G\nobjectSid:: AQI=\nmember: CN=a\nmember: CN=b\nmember: CN=c\n\n");
    }
}

#[cfg(test)]
mod live {
    use super::*;

    /// `cargo test -p ch-server --lib ldapcollect::live -- --ignored --nocapture`
    /// (needs internet: the public forumsys OpenLDAP test server).
    #[tokio::test]
    #[ignore]
    async fn public_test_server() {
        let t = Target {
            name: "forumsys".into(),
            url: "ldap://ldap.forumsys.com:389".into(),
            allow_plain: true,
            bind_dn: "cn=read-only-admin,dc=example,dc=com".into(),
            password: "password".into(),
            base_dn: "dc=example,dc=com".into(),
            ..Default::default()
        };
        let mut l = connect(&t).await.expect("bind");
        let dse = root_dse(&mut l).await.expect("rootdse");
        eprintln!("rootdse default nc: {:?}", dse.default_nc);
        let mut out = Vec::new();
        let n = dump_nc(&mut l, "dc=example,dc=com", "(objectClass=*)", ATTRS, &mut out).await.expect("search");
        eprintln!("{n} entries, {} bytes LDIF\n{}", out.len(), String::from_utf8_lossy(&out[..out.len().min(400)]));
        assert!(n > 5);
    }
}
