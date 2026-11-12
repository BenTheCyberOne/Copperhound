//! Remediation hand-off: turn attack edges (from the fix list, a
//! remediation-plan step or a finding) into tickets in Jira, ServiceNow or
//! any system behind a JSON webhook, each edge with its guidance and a
//! suggested command ([`ch_model::fix_command`]).
//!
//! Ticket targets are configured by admins in `<data>/ticket_targets.json`;
//! the token / password / HMAC secret is write-only like notification
//! secrets. Created tickets are logged in `<data>/tickets.json`.

use crate::api::{node_json, ApiError, St};
use crate::auth::Principal;
use crate::notify::{public_url, signature, validate_http_url};
use crate::state::{load_json, now_rfc3339, store_json, AppState};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use base64::Engine;
use parking_lot::Mutex;
use ch_store::Graph;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::time::Duration;

const MAX_TARGETS: usize = 20;
const MAX_EDGES: usize = 200;
const MAX_TICKETS_PER_CALL: usize = 50;
const LOG_KEEP: usize = 500;
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);

static LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    Jira,
    Servicenow,
    Webhook,
}

/// A stored ticket target. Secret: `token`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: TargetKind,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Jira base URL, ServiceNow instance URL or webhook URL.
    pub url: String,
    /// Jira account email (empty: `token` is a bearer personal access
    /// token) or ServiceNow user.
    #[serde(default)]
    pub username: String,
    /// Jira API token / PAT, ServiceNow password or webhook HMAC secret.
    #[serde(default)]
    pub token: String,
    /// Jira project key.
    #[serde(default)]
    pub project: String,
    /// Jira issue type (default `Task`).
    #[serde(default)]
    pub issue_type: String,
    /// ServiceNow table (default `incident`).
    #[serde(default)]
    pub table: String,
    /// Jira labels.
    #[serde(default)]
    pub labels: Vec<String>,
    /// Extra fields: merged into Jira `fields` or the ServiceNow record
    /// (e.g. `{"assignment_group": "AD Team"}`).
    #[serde(default)]
    pub fields: Map<String, Value>,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct TargetIn {
    #[serde(default)]
    id: Option<String>,
    name: String,
    #[serde(rename = "type")]
    kind: TargetKind,
    #[serde(default)]
    enabled: Option<bool>,
    url: String,
    #[serde(default)]
    username: Option<String>,
    /// Absent or `null` keeps the stored token, `""` clears it.
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    issue_type: Option<String>,
    #[serde(default)]
    table: Option<String>,
    #[serde(default)]
    labels: Option<Vec<String>>,
    #[serde(default)]
    fields: Option<Map<String, Value>>,
}

fn path(st: &AppState) -> std::path::PathBuf {
    st.data_dir.join("ticket_targets.json")
}

fn log_path(st: &AppState) -> std::path::PathBuf {
    st.data_dir.join("tickets.json")
}

pub fn load(st: &AppState) -> Vec<Target> {
    load_json(&path(st))
}

pub fn target_public(t: &Target) -> Value {
    json!({
        "id": t.id, "name": t.name, "type": t.kind, "enabled": t.enabled, "url": t.url,
        "username": t.username, "token_set": !t.token.is_empty(), "project": t.project,
        "issue_type": t.issue_type, "table": t.table, "labels": t.labels, "fields": t.fields,
    })
}

fn word(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

pub fn merge_target(old: Option<&Target>, i: TargetIn) -> Result<Target, String> {
    let name = i.name.trim().to_string();
    if name.is_empty() || name.len() > 100 {
        return Err("target name must be 1-100 characters".into());
    }
    let id = match i.id.filter(|s| !s.is_empty()) {
        Some(id) if word(&id, 64) => id,
        Some(id) => return Err(format!("invalid target id '{id}'")),
        None => format!("t-{}", crate::auth::random_hex(6)),
    };
    let old = old.filter(|o| o.kind == i.kind);
    let url = match i.kind {
        TargetKind::Webhook => i.url.trim().to_string(),
        _ => i.url.trim().trim_end_matches('/').to_string(),
    };
    validate_http_url(&url).map_err(|e| format!("target '{name}': {e}"))?;
    let kept_token = old.filter(|o| crate::notify::same_origin(&o.url, &url)).map(|o| o.token.clone()).unwrap_or_default();
    let mut t = Target {
        id,
        name: name.clone(),
        kind: i.kind,
        enabled: i.enabled.unwrap_or(true),
        url,
        username: i.username.unwrap_or_default().trim().to_string(),
        // The stored token goes only to the origin it was entered for.
        token: i.token.unwrap_or(kept_token),
        project: i.project.unwrap_or_default().trim().to_string(),
        issue_type: i.issue_type.unwrap_or_default().trim().to_string(),
        table: i.table.unwrap_or_default().trim().to_string(),
        labels: i.labels.unwrap_or_default().into_iter().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect(),
        fields: i.fields.unwrap_or_default(),
    };
    match t.kind {
        TargetKind::Jira => {
            if !word(&t.project, 30) {
                return Err(format!("target '{name}': Jira project key is required"));
            }
            if t.issue_type.is_empty() {
                t.issue_type = "Task".into();
            }
            if t.token.is_empty() {
                return Err(format!("target '{name}': a Jira API token or personal access token is required"));
            }
            if t.labels.iter().any(|l| l.contains(char::is_whitespace) || l.len() > 255) || t.labels.len() > 20 {
                return Err(format!("target '{name}': labels cannot contain spaces (at most 20)"));
            }
            t.table.clear();
        }
        TargetKind::Servicenow => {
            if t.table.is_empty() {
                t.table = "incident".into();
            }
            if !t.table.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') || t.table.len() > 80 {
                return Err(format!("target '{name}': invalid ServiceNow table"));
            }
            if t.username.is_empty() || t.token.is_empty() {
                return Err(format!("target '{name}': ServiceNow user and password are required"));
            }
            t.project.clear();
            t.issue_type.clear();
            t.labels.clear();
        }
        TargetKind::Webhook => {
            t.username.clear();
            t.project.clear();
            t.issue_type.clear();
            t.table.clear();
            t.labels.clear();
            t.fields.clear();
        }
    }
    if serde_json::to_vec(&t.fields).map_or(0, |v| v.len()) > 8192 {
        return Err(format!("target '{name}': extra fields are too large"));
    }
    Ok(t)
}

// ------------------------------------------------------------ edge items

#[derive(Debug, Clone, Deserialize)]
pub struct EdgeRef {
    /// Object id (or name) of the source.
    pub src: String,
    pub kind: String,
    pub dst: String,
}

/// An edge with its guidance and suggested command.
#[derive(Debug, Clone, Serialize)]
pub struct FixItem {
    pub src: Value,
    pub dst: Value,
    pub kind: String,
    pub guidance: Option<&'static str>,
    pub command: Option<String>,
}

fn items_for(g: &Graph, edges: &[EdgeRef]) -> (Vec<FixItem>, Vec<Value>) {
    let mut items = Vec::new();
    let mut missing = Vec::new();
    for e in edges {
        let (Some(s), Some(d)) = (g.lookup(&e.src), g.lookup(&e.dst)) else {
            missing.push(json!({"src": e.src, "kind": e.kind, "dst": e.dst}));
            continue;
        };
        let end = |n: u32| ch_model::FixEnd { oid: g.oid(n), name: g.name(n), kind: g.kind_name(n) };
        items.push(FixItem {
            src: node_json(g, s),
            dst: node_json(g, d),
            kind: e.kind.clone(),
            guidance: ch_model::edge_help(&e.kind).map(|h| h.remediation),
            command: ch_model::fix_command(&e.kind, end(s), end(d)),
        });
    }
    (items, missing)
}

async fn with_items(st: &std::sync::Arc<AppState>, edges: Vec<EdgeRef>) -> Result<(Vec<FixItem>, Vec<Value>), ApiError> {
    if edges.is_empty() || edges.len() > MAX_EDGES {
        return Err(ApiError::bad(format!("1-{MAX_EDGES} edges")));
    }
    let st = st.clone();
    tokio::task::spawn_blocking(move || {
        let guard = st.graph.read_recursive();
        let l = guard.as_ref().ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "no graph loaded yet"))?;
        Ok(items_for(&l.graph, &edges))
    })
    .await
    .map_err(|e| ApiError::from(anyhow::anyhow!("task: {e}")))?
}

#[derive(Deserialize)]
pub struct CommandsReq {
    edges: Vec<EdgeRef>,
}

/// `POST /remediation/commands` — guidance and a suggested command per edge.
pub async fn commands(State(st): St, Json(r): Json<CommandsReq>) -> Result<Json<Value>, ApiError> {
    let (items, missing) = with_items(&st, r.edges).await?;
    Ok(Json(json!({"items": items, "missing": missing})))
}

fn sv(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or_default().to_string()
}

fn edge_line(i: &FixItem) -> String {
    format!("{} -[{}]-> {}", sv(&i.src, "name"), i.kind, sv(&i.dst, "name"))
}

/// Ticket text. `code` wraps a command block (Jira wiki markup or plain).
fn describe(items: &[FixItem], note: &str, code: fn(&str) -> String) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "CopperHound found {} attack path edge{} to remove. Each one gives the source control over the target; removing it cuts the attack paths that run through it.\n",
        items.len(),
        if items.len() == 1 { "" } else { "s" }
    ));
    if !note.is_empty() {
        s.push_str(&format!("\n{note}\n"));
    }
    for (n, i) in items.iter().enumerate() {
        s.push_str(&format!("\n{}. {}\n", n + 1, edge_line(i)));
        s.push_str(&format!("   Source object id: {}\n   Target object id: {}\n", sv(&i.src, "objectid"), sv(&i.dst, "objectid")));
        if let Some(g) = i.guidance {
            s.push_str(&format!("   Fix: {g}\n"));
        }
        match &i.command {
            Some(c) => s.push_str(&format!("   Suggested command (review before running):\n{}\n", code(c))),
            None => s.push_str("   No single scripted fix for this edge type: follow the guidance above.\n"),
        }
    }
    if let Some(u) = public_url() {
        s.push_str(&format!("\nOpen CopperHound: {u}\n"));
    }
    s
}

fn jira_code(c: &str) -> String {
    format!("{{noformat}}\n{c}\n{{noformat}}")
}

fn plain_code(c: &str) -> String {
    c.lines().map(|l| format!("      {l}")).collect::<Vec<_>>().join("\n")
}

fn title_for(items: &[FixItem], title: &str) -> String {
    let t = if !title.trim().is_empty() {
        title.trim().to_string()
    } else if let [one] = items {
        format!("Remove {} from {} to {}", one.kind, sv(&one.src, "name"), sv(&one.dst, "name"))
    } else {
        format!("Remove {} attack path edges (CopperHound)", items.len())
    };
    t.chars().filter(|c| !c.is_control()).take(250).collect()
}

// ------------------------------------------------------------ delivery

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Created {
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("CopperHound/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("http client: {e}"))
}

fn basic(user: &str, pass: &str) -> String {
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}")))
}

fn auth_header(t: &Target) -> Option<String> {
    match t.kind {
        TargetKind::Jira if t.username.is_empty() => Some(format!("Bearer {}", t.token)),
        TargetKind::Jira | TargetKind::Servicenow => Some(basic(&t.username, &t.token)),
        TargetKind::Webhook => None,
    }
}

async fn check(resp: reqwest::Response) -> Result<Value, String> {
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        let t: String = text.chars().take(300).collect();
        return Err(format!("HTTP {}: {}", status.as_u16(), t.trim()));
    }
    Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
}

async fn post(t: &Target, url: &str, body: &Value, event: &str) -> Result<Value, String> {
    validate_http_url(url)?;
    let bytes = serde_json::to_vec(body).map_err(|e| e.to_string())?;
    let mut req = client()?.post(url).header("content-type", "application/json").header("accept", "application/json");
    if let Some(a) = auth_header(t) {
        req = req.header("authorization", a);
    }
    if t.kind == TargetKind::Webhook {
        req = req.header("x-copperhound-event", event);
        if !t.token.is_empty() {
            req = req.header("x-copperhound-signature", signature(&t.token, &bytes));
        }
    }
    check(req.body(bytes).send().await.map_err(crate::notify::request_error)?).await
}

/// Create one ticket for `items`.
pub async fn create_one(t: &Target, title: &str, items: &[FixItem], note: &str) -> Result<Created, String> {
    match t.kind {
        TargetKind::Jira => {
            let mut fields = t.fields.clone();
            fields.insert("project".into(), json!({"key": t.project}));
            fields.insert("summary".into(), json!(title));
            fields.insert("description".into(), json!(describe(items, note, jira_code)));
            fields.insert("issuetype".into(), json!({"name": t.issue_type}));
            if !t.labels.is_empty() {
                fields.insert("labels".into(), json!(t.labels));
            }
            let v = post(t, &format!("{}/rest/api/2/issue", t.url), &json!({"fields": fields}), "ticket").await?;
            let key = v["key"].as_str().ok_or("Jira did not return an issue key")?.to_string();
            Ok(Created { url: Some(format!("{}/browse/{key}", t.url)), key })
        }
        TargetKind::Servicenow => {
            let mut rec = t.fields.clone();
            rec.insert("short_description".into(), json!(title.chars().take(160).collect::<String>()));
            rec.insert("description".into(), json!(describe(items, note, plain_code)));
            let v = post(t, &format!("{}/api/now/table/{}", t.url, t.table), &Value::Object(rec), "ticket").await?;
            let r = &v["result"];
            let sys_id = r["sys_id"].as_str().ok_or("ServiceNow did not return a sys_id")?;
            let key = r["number"].as_str().unwrap_or(sys_id).to_string();
            Ok(Created { url: Some(format!("{}/nav_to.do?uri=%2F{}.do%3Fsys_id%3D{sys_id}", t.url, t.table)), key })
        }
        TargetKind::Webhook => {
            let body = json!({
                "event": "remediation.ticket",
                "title": title,
                "note": note,
                "description": describe(items, note, plain_code),
                "items": items,
                "link": public_url(),
            });
            let v = post(t, &t.url, &body, "remediation.ticket").await?;
            let key = ["key", "id", "number"].iter().find_map(|k| v[*k].as_str().map(str::to_string).or_else(|| v[*k].as_u64().map(|n| n.to_string())));
            // The receiver's link is shown as a link: only web URLs.
            let url = v["url"].as_str().map(str::trim).filter(|u| validate_http_url(u).is_ok()).map(str::to_string);
            Ok(Created { key: key.unwrap_or_else(|| "sent".into()), url })
        }
    }
}

// ------------------------------------------------------------ handlers

/// Everyone may list targets (to hand off to them); a webhook URL is a
/// secret, so only admins see it in full, others get its host.
pub async fn get_targets(State(st): St, axum::Extension(who): axum::Extension<crate::auth::Principal>) -> Json<Value> {
    let admin = who.role == crate::auth::Role::Admin;
    Json(Value::Array(
        load(&st)
            .iter()
            .map(|t| {
                let mut v = target_public(t);
                if !admin && t.kind == TargetKind::Webhook {
                    v["url"] = json!(crate::notify::url_hint(&t.url));
                }
                v
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct TargetsReq {
    targets: Vec<TargetIn>,
}

pub async fn put_targets(State(st): St, Json(r): Json<TargetsReq>) -> Result<Json<Value>, ApiError> {
    if r.targets.len() > MAX_TARGETS {
        return Err(ApiError::bad(format!("at most {MAX_TARGETS} ticket targets")));
    }
    let out = {
        let _g = LOCK.lock();
        let old = load(&st);
        let mut out: Vec<Target> = Vec::new();
        for i in r.targets {
            let prev = i.id.as_ref().and_then(|id| old.iter().find(|o| &o.id == id));
            let t = merge_target(prev, i).map_err(ApiError::bad)?;
            if out.iter().any(|o| o.id == t.id) {
                return Err(ApiError::bad(format!("duplicate target id '{}'", t.id)));
            }
            out.push(t);
        }
        store_json(&path(&st), &out)?;
        out
    };
    Ok(Json(Value::Array(out.iter().map(target_public).collect())))
}

fn find(st: &AppState, id: &str) -> Result<Target, ApiError> {
    load(st).into_iter().find(|t| t.id == id).ok_or_else(|| ApiError::not_found(format!("no ticket target '{id}'")))
}

/// `POST /tickets/targets/{id}/test` — checks the connection and credentials
/// without creating anything (webhooks get a `test` event).
pub async fn test_target(State(st): St, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let t = find(&st, &id)?;
    let r: Result<String, String> = async {
        match t.kind {
            TargetKind::Jira | TargetKind::Servicenow => {
                let url = if t.kind == TargetKind::Jira { format!("{}/rest/api/2/myself", t.url) } else { format!("{}/api/now/table/{}?sysparm_limit=1", t.url, t.table) };
                let mut req = client()?.get(&url).header("accept", "application/json");
                if let Some(a) = auth_header(&t) {
                    req = req.header("authorization", a);
                }
                let v = check(req.send().await.map_err(crate::notify::request_error)?).await?;
                Ok(v["displayName"].as_str().map(|n| format!("signed in as {n}")).unwrap_or_else(|| "connected".into()))
            }
            TargetKind::Webhook => {
                post(&t, &t.url, &json!({"event": "test", "title": "CopperHound test", "target": t.id}), "test").await?;
                Ok("delivered".into())
            }
        }
    }
    .await;
    Ok(Json(match r {
        Ok(d) => json!({"ok": true, "detail": d}),
        Err(e) => json!({"ok": false, "error": e}),
    }))
}

#[derive(Deserialize)]
pub struct CreateReq {
    target: String,
    edges: Vec<EdgeRef>,
    #[serde(default)]
    title: String,
    #[serde(default)]
    note: String,
    /// One ticket per edge instead of one for all.
    #[serde(default)]
    split: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketRecord {
    pub at: String,
    pub by: String,
    pub target: String,
    pub target_name: String,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub title: String,
    pub edges: Vec<String>,
}

/// `POST /tickets` — create tickets for edges.
pub async fn create(State(st): St, Extension(who): Extension<Principal>, Json(r): Json<CreateReq>) -> Result<Json<Value>, ApiError> {
    let t = find(&st, &r.target)?;
    if !t.enabled {
        return Err(ApiError::bad(format!("ticket target '{}' is disabled", t.name)));
    }
    if r.note.len() > 4000 || r.title.len() > 250 {
        return Err(ApiError::bad("title at most 250 and note at most 4000 characters"));
    }
    let (items, missing) = with_items(&st, r.edges).await?;
    if items.is_empty() {
        return Err(ApiError::bad("none of the edges' objects are in the loaded graph"));
    }
    let groups: Vec<Vec<FixItem>> = if r.split { items.into_iter().map(|i| vec![i]).collect() } else { vec![items] };
    if groups.len() > MAX_TICKETS_PER_CALL {
        return Err(ApiError::bad(format!("at most {MAX_TICKETS_PER_CALL} tickets per request")));
    }
    let note = r.note.trim().to_string();
    let mut created = Vec::new();
    let mut errors = Vec::new();
    let mut records = Vec::new();
    for g in &groups {
        let title = if r.split { title_for(g, "") } else { title_for(g, &r.title) };
        match create_one(&t, &title, g, &note).await {
            Ok(c) => {
                records.push(TicketRecord {
                    at: now_rfc3339(),
                    by: who.username.clone(),
                    target: t.id.clone(),
                    target_name: t.name.clone(),
                    key: c.key.clone(),
                    url: c.url.clone(),
                    title: title.clone(),
                    edges: g.iter().map(edge_line).collect(),
                });
                created.push(json!({"key": c.key, "url": c.url, "title": title, "edges": g.len()}));
            }
            Err(e) => {
                tracing::warn!("ticket target '{}': {e}", t.name);
                errors.push(json!({"title": title, "error": e}));
                // A failure for one edge is likely a failure for all (auth, project).
                if created.is_empty() {
                    break;
                }
            }
        }
    }
    if !records.is_empty() {
        let _g = LOCK.lock();
        let mut log: Vec<TicketRecord> = load_json(&log_path(&st));
        log.extend(records);
        let n = log.len();
        if n > LOG_KEEP {
            log.drain(..n - LOG_KEEP);
        }
        store_json(&log_path(&st), &log)?;
    }
    if created.is_empty() {
        let msg = errors.first().and_then(|e| e["error"].as_str()).unwrap_or("ticket creation failed").to_string();
        return Err(ApiError::new(StatusCode::BAD_GATEWAY, format!("{}: {msg}", t.name)));
    }
    Ok(Json(json!({"created": created, "errors": errors, "missing": missing})))
}

/// `GET /tickets` — tickets created from CopperHound, newest first.
pub async fn list(State(st): St) -> Json<Value> {
    let mut log: Vec<TicketRecord> = load_json(&log_path(&st));
    log.reverse();
    Json(serde_json::to_value(log).unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(v: Value) -> TargetIn {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn targets_validate_and_keep_secrets() {
        let t = merge_target(None, input(json!({"name":"Jira","type":"jira","url":"https://acme.atlassian.net/","username":"a@b.c","token":"tokqq","project":"SEC"}))).unwrap();
        assert_eq!((t.url.as_str(), t.issue_type.as_str()), ("https://acme.atlassian.net", "Task"));
        let p = target_public(&t).to_string();
        assert!(!p.contains("tokqq") && p.contains("\"token_set\":true"), "{p}");
        let t2 = merge_target(Some(&t), input(json!({"id": t.id, "name":"Jira","type":"jira","url":"https://acme.atlassian.net","project":"SEC"}))).unwrap();
        assert_eq!(t2.token, "tokqq");
        assert!(merge_target(None, input(json!({"name":"J","type":"jira","url":"https://x","token":"t"}))).is_err(), "project required");
        assert!(merge_target(None, input(json!({"name":"S","type":"servicenow","url":"https://x.service-now.com","username":"u","token":"p","table":"bad table"}))).is_err());
        let s = merge_target(None, input(json!({"name":"S","type":"servicenow","url":"https://x.service-now.com","username":"u","token":"p"}))).unwrap();
        assert_eq!(s.table, "incident");
        assert!(merge_target(None, input(json!({"name":"W","type":"webhook","url":"ftp://x"}))).is_err());
    }

    #[test]
    fn descriptions() {
        let item = FixItem {
            src: json!({"name":"BOB@CORP.LOCAL","objectid":"S-1-5-21-1-2-3-1105"}),
            dst: json!({"name":"DOMAIN ADMINS@CORP.LOCAL","objectid":"S-1-5-21-1-2-3-512"}),
            kind: "MemberOf".into(),
            guidance: Some("Remove it."),
            command: Some("Remove-ADGroupMember x".into()),
        };
        let d = describe(std::slice::from_ref(&item), "Q3 cleanup", jira_code);
        assert!(d.contains("1 attack path edge to remove") && d.contains("Q3 cleanup") && d.contains("{noformat}\nRemove-ADGroupMember x\n{noformat}"), "{d}");
        assert_eq!(title_for(std::slice::from_ref(&item), ""), "Remove MemberOf from BOB@CORP.LOCAL to DOMAIN ADMINS@CORP.LOCAL");
        assert_eq!(title_for(&[item.clone(), item], "  Custom\n "), "Custom");
    }
}
