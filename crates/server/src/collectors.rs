//! Collector clients (admin): registered SharpHound / AzureHound / LDAP
//! collection jobs that upload on a schedule.
//!
//! Registering a client creates an upload-only account (`collector-<name>`,
//! random password, never shown) with an API token, returned once together
//! with ready-to-run collection and upload commands. Each upload by that
//! account is recorded as a check-in; a client is `stale` when it has not
//! uploaded within twice its expected interval (`never` before the first).
//! Removing a client deletes its account and token.
//!
//! Stored in `<data>/collectors.json`.

use crate::api::{ApiError, St};
use crate::auth::{random_hex, Principal, Role};
use crate::state::{load_json, now_rfc3339, store_json, AppState};
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::{Extension, Json};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collector {
    pub id: String,
    pub name: String,
    /// `sharphound`, `azurehound`, `bloodhound-python` or `ldap`.
    pub kind: String,
    pub interval_hours: u32,
    pub username: String,
    pub token_id: String,
    pub created_at: String,
    pub created_by: String,
    #[serde(default)]
    pub last_upload_at: Option<String>,
    #[serde(default)]
    pub last_files: Vec<String>,
    #[serde(default)]
    pub uploads: u64,
}

const KINDS: &[&str] = &["sharphound", "azurehound", "bloodhound-python", "ldap"];
static LOCK: Mutex<()> = Mutex::new(());

fn path(st: &AppState) -> std::path::PathBuf {
    st.data_dir.join("collectors.json")
}

fn load(st: &AppState) -> Vec<Collector> {
    load_json(&path(st))
}

/// `ok`, `stale` or `never`.
pub fn status(c: &Collector, now: SystemTime) -> &'static str {
    match c.last_upload_at.as_deref().and_then(|t| humantime::parse_rfc3339_weak(t).ok()) {
        None => "never",
        Some(t) => {
            let age = now.duration_since(t).unwrap_or_default().as_secs();
            if age > 2 * 3600 * c.interval_hours as u64 {
                "stale"
            } else {
                "ok"
            }
        }
    }
}

fn json_of(c: &Collector, now: SystemTime) -> Value {
    let mut v = serde_json::to_value(c).unwrap_or_default();
    v["status"] = json!(status(c, now));
    v
}

/// Record an upload by `username` if it is a collector account.
pub fn record_upload(st: &AppState, username: &str, files: &[String]) {
    let _g = LOCK.lock();
    let mut all = load(st);
    let Some(c) = all.iter_mut().find(|c| c.username == username) else { return };
    c.last_upload_at = Some(now_rfc3339());
    c.last_files = files.iter().take(20).cloned().collect();
    c.uploads += 1;
    if let Err(e) = store_json(&path(st), &all) {
        tracing::warn!("saving collectors: {e:#}");
    }
}

pub async fn list(State(st): St) -> Json<Value> {
    let now = SystemTime::now();
    Json(json!(load(&st).iter().map(|c| json_of(c, now)).collect::<Vec<_>>()))
}

#[derive(Deserialize)]
pub struct NewCollector {
    name: String,
    kind: String,
    #[serde(default = "default_interval")]
    interval_hours: u32,
}

fn default_interval() -> u32 {
    24
}

fn slug(s: &str) -> String {
    let s: String = s.trim().to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
    s.split('-').filter(|p| !p.is_empty()).collect::<Vec<_>>().join("-").chars().take(40).collect()
}

/// Collection + upload commands for a client.
pub fn commands(kind: &str, base: &str, token: &str) -> Value {
    let upload_ps = format!(
        "curl.exe -sf -H \"Authorization: Bearer {token}\" -F \"files=@$($f.FullName)\" {base}/api/v1/upload\ncurl.exe -sf -X POST -H \"Authorization: Bearer {token}\" {base}/api/v1/ingest"
    );
    let upload_sh = |file: &str| {
        format!(
            "curl -sf -H 'Authorization: Bearer {token}' -F 'files=@{file}' {base}/api/v1/upload\ncurl -sf -X POST -H 'Authorization: Bearer {token}' {base}/api/v1/ingest"
        )
    };
    match kind {
        "sharphound" => json!({
            "script_name": "collect.ps1",
            "script": format!(
                "# Run as a domain user (the collection's identity).\n$out = 'C:\\CopperHound'\nNew-Item -ItemType Directory -Force $out | Out-Null\n& \"$out\\SharpHound.exe\" -c All --outputdirectory $out --zipfilename copperhound.zip\n$f = Get-ChildItem \"$out\\*copperhound.zip\" | Sort-Object LastWriteTime | Select-Object -Last 1\n{upload_ps}\nRemove-Item $f.FullName\n"
            ),
            "schedule": "schtasks /Create /TN CopperHound-Collect /SC DAILY /ST 02:00 /RU CORP\\svc-collect /RP * /TR \"powershell -NoProfile -ExecutionPolicy Bypass -File C:\\CopperHound\\collect.ps1\"",
        }),
        "azurehound" => json!({
            "script_name": "collect.sh",
            "script": format!(
                "#!/bin/sh\nset -e\nazurehound list --tenant \"$TENANT_ID\" --app \"$APP_ID\" --secret \"$APP_SECRET\" -o /tmp/copperhound-azure.json\n{}\nrm -f /tmp/copperhound-azure.json\n",
                upload_sh("/tmp/copperhound-azure.json")
            ),
            "schedule": "0 3 * * * /opt/copperhound/collect.sh",
        }),
        "bloodhound-python" => json!({
            "script_name": "collect.sh",
            "script": format!(
                "#!/bin/sh\nset -e\ncd /tmp\nbloodhound-python -c All -d \"$DOMAIN\" -u \"$USER\" -p \"$PASS\" -ns \"$DC_IP\" --zip\nf=$(ls -t /tmp/*_bloodhound.zip | head -1)\n{}\nrm -f \"$f\"\n",
                upload_sh("$f")
            ),
            "schedule": "0 2 * * * /opt/copperhound/collect.sh",
        }),
        _ => json!({
            "script_name": "collect.sh",
            "script": format!(
                "#!/bin/sh\nset -e\nBASE='DC=corp,DC=local'; DC=dc01.corp.local\nldapsearch -LLL -o ldif-wrap=no -H ldap://$DC -Y GSSAPI -E pr=1000/noprompt -E '!1.2.840.113556.1.4.801=::MAMCAQc=' -b \"$BASE\" '(objectClass=*)' '*' nTSecurityDescriptor msDS-GroupMSAMembership msDS-AllowedToActOnBehalfOfOtherIdentity | gzip > /tmp/copperhound.ldif.gz\n{}\nrm -f /tmp/copperhound.ldif.gz\n",
                upload_sh("/tmp/copperhound.ldif.gz")
            ),
            "schedule": "0 2 * * * /opt/copperhound/collect.sh",
        }),
    }
}

pub async fn create(State(st): St, Extension(who): Extension<Principal>, headers: HeaderMap, Json(r): Json<NewCollector>) -> Result<Json<Value>, ApiError> {
    let name = r.name.trim();
    let s = slug(name);
    if s.is_empty() || name.len() > 64 {
        return Err(ApiError::bad("name must be 1-64 characters with at least one letter or digit"));
    }
    if !KINDS.contains(&r.kind.as_str()) {
        return Err(ApiError::bad(format!("kind must be one of {}", KINDS.join(", "))));
    }
    if !(1..=24 * 31).contains(&r.interval_hours) {
        return Err(ApiError::bad("interval_hours must be 1-744"));
    }
    let username = format!("collector-{s}");
    let st2 = st.clone();
    let u2 = username.clone();
    let (token_rec, token) = tokio::task::spawn_blocking(move || -> Result<_, ApiError> {
        st2.auth.create(&u2, &random_hex(32), Role::Uploader).map_err(|e| ApiError::bad(format!("{e:#}")))?;
        st2.auth.create_token(&u2, "collector", None).map_err(|e| ApiError::bad(format!("{e:#}")))
    })
    .await
    .map_err(|e| ApiError::from(anyhow::anyhow!("task: {e}")))??;
    let token_rec_hash = token_rec.hash.clone();
    let c = Collector {
        id: random_hex(8),
        name: name.to_string(),
        kind: r.kind.clone(),
        interval_hours: r.interval_hours,
        username,
        token_id: token_rec.id,
        created_at: now_rfc3339(),
        created_by: who.username,
        last_upload_at: None,
        last_files: Vec::new(),
        uploads: 0,
    };
    {
        let _g = LOCK.lock();
        let mut all = load(&st);
        all.push(c.clone());
        store_json(&path(&st), &all)?;
    }
    let base = st.sso.origin(&headers).unwrap_or_default();
    Ok(Json(json!({
        "collector": json_of(&c, SystemTime::now()),
        "token": token,
        "token_id": c.token_id,
        "bloodhound_key": token_rec_hash,
        "note": "store this token now; it is not shown again",
        "commands": commands(&c.kind, &base, &token),
    })))
}

pub async fn delete(State(st): St, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let removed = {
        let _g = LOCK.lock();
        let mut all = load(&st);
        let Some(i) = all.iter().position(|c| c.id == id) else {
            return Err(ApiError::not_found("no such collector"));
        };
        let c = all.remove(i);
        store_json(&path(&st), &all)?;
        c
    };
    let _ = st.auth.delete(&removed.username);
    Ok(Json(json!({ "deleted": id, "account_removed": removed.username })))
}
