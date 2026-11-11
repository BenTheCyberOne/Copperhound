//! Notification channels: generic JSON webhook (optional HMAC-SHA256
//! signature), Slack and Microsoft Teams incoming webhooks, and SMTP email.
//!
//! Channels are configured by admins and stored in `<data>/notify.json`.
//! Secrets (webhook URLs, the HMAC secret, the SMTP password) are write-only:
//! the API reports `*_set: true` instead of returning them.
//!
//! Every delivery runs with timeouts and up to [`MAX_ATTEMPTS`] attempts with
//! backoff. Webhook URLs must be `http`/`https`; redirects are not followed.
//! Because only admins can configure targets, the server-side request forgery
//! surface is limited to what an admin could reach anyway.

use crate::api::{ApiError, St};
use crate::state::{load_json, now_rfc3339, store_json, AppState};
use axum::extract::{Path, State};
use axum::Json;
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

pub const MAX_ATTEMPTS: u32 = 3;
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SMTP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CHANNELS: usize = 50;

// ---------------------------------------------------------------- state

/// Notification, schedule and alert configuration (one per server).
pub struct NotifyState {
    pub channels: Mutex<Vec<Channel>>,
    pub schedules: Mutex<Vec<crate::schedule::Schedule>>,
    pub rules: Mutex<crate::alerts::AlertRules>,
    pub alert_log: crate::alerts::AlertLog,
    /// Schedule ids currently running.
    pub running: Mutex<Vec<String>>,
    data_dir: PathBuf,
}

impl NotifyState {
    pub fn load(data_dir: &std::path::Path) -> NotifyState {
        let cfg: NotifyFile = load_json(&data_dir.join("notify.json"));
        NotifyState {
            channels: Mutex::new(cfg.channels),
            schedules: Mutex::new({
                let mut list: Vec<crate::schedule::Schedule> = load_json(&data_dir.join("schedules.json"));
                list.iter_mut().for_each(|s| s.running = false); // interrupted by a restart
                list
            }),
            rules: Mutex::new(load_json(&data_dir.join("alert_rules.json"))),
            alert_log: crate::alerts::AlertLog::new(data_dir.join("alerts.jsonl")),
            running: Mutex::new(Vec::new()),
            data_dir: data_dir.to_path_buf(),
        }
    }
    pub fn channels_path(&self) -> PathBuf {
        self.data_dir.join("notify.json")
    }
    pub fn schedules_path(&self) -> PathBuf {
        self.data_dir.join("schedules.json")
    }
    pub fn rules_path(&self) -> PathBuf {
        self.data_dir.join("alert_rules.json")
    }
    pub fn alert_state_path(&self) -> PathBuf {
        self.data_dir.join("alert_state.json")
    }
}

#[derive(Default, Serialize, Deserialize)]
struct NotifyFile {
    #[serde(default)]
    channels: Vec<Channel>,
}

/// `COPPERHOUND_PUBLIC_URL` without a trailing slash, if set.
pub fn public_url() -> Option<String> {
    std::env::var("COPPERHOUND_PUBLIC_URL").ok().map(|u| u.trim().trim_end_matches('/').to_string()).filter(|u| !u.is_empty())
}

// ------------------------------------------------------------- channels

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChannelType {
    Webhook,
    Slack,
    Teams,
    Email,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmtpSecurity {
    /// Plain connection upgraded with STARTTLS (required), default port 587.
    #[default]
    Starttls,
    /// Implicit TLS (SMTPS), default port 465.
    Tls,
    /// No encryption (internal relays only; credentials are refused).
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TeamsFormat {
    /// Adaptive Card in a `message` envelope (Teams Workflows webhooks).
    #[default]
    Adaptive,
    /// Legacy Office 365 connector MessageCard.
    Messagecard,
}

/// A stored channel. Secret fields: `url`, `secret`, `smtp_password`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ChannelType,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Webhook / Slack / Teams URL.
    #[serde(default)]
    pub url: String,
    /// HMAC-SHA256 key for generic webhooks (empty: unsigned).
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub teams_format: TeamsFormat,
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    pub smtp_port: u16,
    #[serde(default)]
    pub smtp_security: SmtpSecurity,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password: String,
    #[serde(default)]
    pub email_from: String,
    #[serde(default)]
    pub email_to: Vec<String>,
}

fn yes() -> bool {
    true
}

/// `scheme://host[:port]/…` — enough to recognise a URL without leaking its token.
fn url_hint(url: &str) -> Option<String> {
    let u = reqwest::Url::parse(url).ok()?;
    let host = u.host_str()?;
    Some(match u.port() {
        Some(p) => format!("{}://{host}:{p}/…", u.scheme()),
        None => format!("{}://{host}/…", u.scheme()),
    })
}

/// Channel as returned by the API: secrets replaced by `*_set` flags.
pub fn channel_public(c: &Channel) -> Value {
    let mut v = json!({
        "id": c.id, "name": c.name, "type": c.kind, "enabled": c.enabled,
    });
    match c.kind {
        ChannelType::Webhook | ChannelType::Slack | ChannelType::Teams => {
            v["url_set"] = json!(!c.url.is_empty());
            v["url_hint"] = json!(url_hint(&c.url));
            if c.kind == ChannelType::Webhook {
                v["secret_set"] = json!(!c.secret.is_empty());
            }
            if c.kind == ChannelType::Teams {
                v["teams_format"] = json!(c.teams_format);
            }
        }
        ChannelType::Email => {
            v["smtp_host"] = json!(c.smtp_host);
            v["smtp_port"] = json!(c.smtp_port);
            v["smtp_security"] = json!(c.smtp_security);
            v["smtp_username"] = json!(c.smtp_username);
            v["smtp_password_set"] = json!(!c.smtp_password.is_empty());
            v["email_from"] = json!(c.email_from);
            v["email_to"] = json!(c.email_to);
        }
    }
    v
}

/// A channel in `PUT /notify/channels`. Secret fields: absent or `null` keeps
/// the stored value (matched by `id`), `""` clears it, a string replaces it.
#[derive(Debug, Deserialize)]
pub struct ChannelIn {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ChannelType,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub teams_format: Option<TeamsFormat>,
    #[serde(default)]
    pub smtp_host: Option<String>,
    #[serde(default)]
    pub smtp_port: Option<u16>,
    #[serde(default)]
    pub smtp_security: Option<SmtpSecurity>,
    #[serde(default)]
    pub smtp_username: Option<String>,
    #[serde(default)]
    pub smtp_password: Option<String>,
    #[serde(default)]
    pub email_from: Option<String>,
    #[serde(default)]
    pub email_to: Option<Vec<String>>,
}

pub fn validate_http_url(url: &str) -> Result<(), String> {
    let u = reqwest::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    if u.scheme() != "http" && u.scheme() != "https" {
        return Err("URL must use http or https".into());
    }
    if !matches!(u.host_str(), Some(h) if !h.is_empty()) {
        return Err("URL needs a host".into());
    }
    Ok(())
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Merge an incoming channel over the stored one (secrets kept unless given).
pub fn merge_channel(old: Option<&Channel>, i: ChannelIn) -> Result<Channel, String> {
    let name = i.name.trim().to_string();
    if name.is_empty() || name.len() > 100 {
        return Err("channel name must be 1-100 characters".into());
    }
    let id = match &i.id {
        Some(id) if !id.is_empty() => {
            if !valid_id(id) {
                return Err(format!("invalid channel id '{id}'"));
            }
            id.clone()
        }
        _ => format!("c-{}", crate::auth::random_hex(6)),
    };
    let old = old.filter(|o| o.kind == i.kind);
    let keep = |new: Option<String>, old: Option<&String>| new.unwrap_or_else(|| old.cloned().unwrap_or_default());
    let security = i.smtp_security.or(old.map(|o| o.smtp_security)).unwrap_or_default();
    let mut c = Channel {
        id,
        name,
        kind: i.kind,
        enabled: i.enabled.unwrap_or(true),
        url: keep(i.url.map(|u| u.trim().to_string()), old.map(|o| &o.url)),
        secret: keep(i.secret, old.map(|o| &o.secret)),
        teams_format: i.teams_format.or(old.map(|o| o.teams_format)).unwrap_or_default(),
        smtp_host: i.smtp_host.unwrap_or_default().trim().to_string(),
        smtp_port: i.smtp_port.unwrap_or(0),
        smtp_security: security,
        smtp_username: i.smtp_username.unwrap_or_default().trim().to_string(),
        smtp_password: keep(i.smtp_password, old.map(|o| &o.smtp_password)),
        email_from: i.email_from.unwrap_or_default().trim().to_string(),
        email_to: i.email_to.unwrap_or_default().into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
    };
    match c.kind {
        ChannelType::Webhook | ChannelType::Slack | ChannelType::Teams => {
            if c.url.is_empty() {
                return Err(format!("channel '{}': url is required", c.name));
            }
            validate_http_url(&c.url).map_err(|e| format!("channel '{}': {e}", c.name))?;
            if c.kind != ChannelType::Webhook {
                c.secret.clear();
            }
            c.smtp_password.clear();
        }
        ChannelType::Email => {
            c.url.clear();
            c.secret.clear();
            if c.smtp_host.is_empty() || c.smtp_host.len() > 253 || c.smtp_host.contains(['/', ' ', ':']) {
                return Err(format!("channel '{}': smtp_host must be a host name or address", c.name));
            }
            if c.smtp_port == 0 {
                c.smtp_port = match c.smtp_security {
                    SmtpSecurity::Starttls => 587,
                    SmtpSecurity::Tls => 465,
                    SmtpSecurity::None => 25,
                };
            }
            if c.smtp_security == SmtpSecurity::None && !c.smtp_username.is_empty() {
                return Err(format!("channel '{}': refusing to send SMTP credentials without TLS", c.name));
            }
            c.email_from
                .parse::<lettre::message::Mailbox>()
                .map_err(|e| format!("channel '{}': invalid email_from: {e}", c.name))?;
            if c.email_to.is_empty() || c.email_to.len() > 50 {
                return Err(format!("channel '{}': email_to needs 1-50 addresses", c.name));
            }
            for t in &c.email_to {
                t.parse::<lettre::message::Mailbox>().map_err(|e| format!("channel '{}': invalid recipient '{t}': {e}", c.name))?;
            }
        }
    }
    Ok(c)
}

// -------------------------------------------------------------- message

pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

/// A notification, rendered per channel type.
pub struct Message {
    /// `report`, `alert` or `test`.
    pub event: &'static str,
    pub title: String,
    /// Body lines (plain text; `• ` bullets allowed).
    pub lines: Vec<String>,
    pub facts: Vec<(String, String)>,
    pub link: Option<String>,
    /// Hex colour without `#` (Teams theme colour).
    pub color: &'static str,
    /// Structured payload for generic webhooks.
    pub data: Value,
    /// Attached to emails only.
    pub attachment: Option<Attachment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delivery {
    pub channel: String,
    pub name: String,
    pub ok: bool,
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn plain_text(m: &Message) -> String {
    let mut s = m.lines.join("\n");
    if !m.facts.is_empty() {
        s.push_str("\n\n");
        for (k, v) in &m.facts {
            s.push_str(&format!("{k}: {v}\n"));
        }
    }
    if let Some(l) = &m.link {
        s.push_str(&format!("\nOpen CopperHound: {l}\n"));
    }
    s
}

pub fn webhook_body(m: &Message) -> Value {
    json!({
        "source": "copperhound",
        "event": m.event,
        "sent_at": now_rfc3339(),
        "title": m.title,
        "text": m.lines.join("\n"),
        "facts": m.facts.iter().map(|(k, v)| json!({"name": k, "value": v})).collect::<Vec<_>>(),
        "link": m.link,
        "data": m.data,
    })
}

fn slack_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

pub fn slack_body(m: &Message) -> Value {
    let mut text = format!("*{}*\n{}", slack_escape(&m.title), slack_escape(&m.lines.join("\n")));
    if !m.facts.is_empty() {
        text.push('\n');
        for (k, v) in &m.facts {
            text.push_str(&format!("\n*{}:* {}", slack_escape(k), slack_escape(v)));
        }
    }
    if let Some(l) = &m.link {
        text.push_str(&format!("\n<{}|Open CopperHound>", l.replace('|', "%7C").replace('>', "%3E")));
    }
    json!({ "text": text, "unfurl_links": false })
}

pub fn teams_body(m: &Message, format: TeamsFormat) -> Value {
    let facts: Vec<Value> = m.facts.iter().map(|(k, v)| json!({"title": k, "value": v})).collect();
    match format {
        TeamsFormat::Messagecard => {
            let mut v = json!({
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": m.title,
                "themeColor": m.color,
                "title": m.title,
                "text": m.lines.join("\n\n"),
                "sections": [{"facts": m.facts.iter().map(|(k, v)| json!({"name": k, "value": v})).collect::<Vec<_>>()}],
            });
            if let Some(l) = &m.link {
                v["potentialAction"] =
                    json!([{"@type": "OpenUri", "name": "Open CopperHound", "targets": [{"os": "default", "uri": l}]}]);
            }
            v
        }
        TeamsFormat::Adaptive => {
            let mut card = json!({
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {"type": "TextBlock", "text": m.title, "weight": "Bolder", "size": "Medium", "wrap": true},
                    {"type": "TextBlock", "text": m.lines.join("\n\n"), "wrap": true},
                    {"type": "FactSet", "facts": facts},
                ],
            });
            if let Some(l) = &m.link {
                card["actions"] = json!([{"type": "Action.OpenUrl", "title": "Open CopperHound", "url": l}]);
            }
            json!({
                "type": "message",
                "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": null, "content": card}],
            })
        }
    }
}

/// `sha256=<hex HMAC-SHA256(secret, body)>`.
pub fn signature(secret: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(body);
    let tag = mac.finalize().into_bytes();
    let mut s = String::from("sha256=");
    for b in tag {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ------------------------------------------------------------- delivery

/// A retryable failure (network error, 429 or 5xx) or a permanent one.
struct SendError {
    retry: bool,
    msg: String,
}

fn client() -> Result<reqwest::Client, SendError> {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("CopperHound/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| SendError { retry: false, msg: format!("http client: {e}") })
}

async fn post_json(url: &str, body: &Value, extra: &[(&str, String)]) -> Result<(), SendError> {
    validate_http_url(url).map_err(|msg| SendError { retry: false, msg })?;
    let bytes = serde_json::to_vec(body).map_err(|e| SendError { retry: false, msg: e.to_string() })?;
    let mut req = client()?.post(url).header("content-type", "application/json");
    for (k, v) in extra {
        req = req.header(*k, v);
    }
    let resp = req.body(bytes).send().await.map_err(|e| SendError { retry: true, msg: format!("request failed: {e}") })?;
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let text = resp.text().await.unwrap_or_default();
    let text: String = text.chars().take(200).collect();
    Err(SendError {
        retry: status.as_u16() == 429 || status.is_server_error(),
        msg: format!("HTTP {}: {}", status.as_u16(), text.trim()),
    })
}

async fn send_email(c: &Channel, m: &Message) -> Result<(), SendError> {
    use lettre::message::{header::ContentType, Attachment as MailAttachment, Mailbox, MultiPart, SinglePart};
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
    let perm = |msg: String| SendError { retry: false, msg };
    let builder = match c.smtp_security {
        SmtpSecurity::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&c.smtp_host),
        SmtpSecurity::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&c.smtp_host),
        SmtpSecurity::None => Ok(AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&c.smtp_host)),
    }
    .map_err(|e| perm(format!("smtp: {e}")))?;
    let mut builder = builder.port(c.smtp_port).timeout(Some(SMTP_TIMEOUT));
    if !c.smtp_username.is_empty() {
        builder = builder.credentials(Credentials::new(c.smtp_username.clone(), c.smtp_password.clone()));
    }
    let mailer = builder.build();
    let mut mb = lettre::Message::builder()
        .from(c.email_from.parse::<Mailbox>().map_err(|e| perm(format!("email_from: {e}")))?)
        .subject(m.title.clone());
    for t in &c.email_to {
        mb = mb.to(t.parse::<Mailbox>().map_err(|e| perm(format!("recipient {t}: {e}")))?);
    }
    let text = plain_text(m);
    let email = match &m.attachment {
        Some(a) => {
            let ct = ContentType::parse(&a.content_type).map_err(|e| perm(format!("attachment type: {e}")))?;
            mb.multipart(
                MultiPart::mixed()
                    .singlepart(SinglePart::plain(text))
                    .singlepart(MailAttachment::new(a.filename.clone()).body(a.body.clone(), ct)),
            )
        }
        None => mb.header(ContentType::TEXT_PLAIN).body(text),
    }
    .map_err(|e| perm(format!("building email: {e}")))?;
    match tokio::time::timeout(SMTP_TIMEOUT * 2, mailer.send(email)).await {
        Err(_) => Err(SendError { retry: true, msg: "smtp: timed out".into() }),
        Ok(Err(e)) => Err(SendError { retry: !e.is_permanent(), msg: format!("smtp: {e}") }),
        Ok(Ok(_)) => Ok(()),
    }
}

async fn send_once(c: &Channel, m: &Message) -> Result<(), SendError> {
    match c.kind {
        ChannelType::Webhook => {
            let body = webhook_body(m);
            let mut extra = vec![("x-copperhound-event", m.event.to_string())];
            if !c.secret.is_empty() {
                // Sign exactly the bytes that are sent.
                let bytes = serde_json::to_vec(&body).map_err(|e| SendError { retry: false, msg: e.to_string() })?;
                extra.push(("x-copperhound-signature", signature(&c.secret, &bytes)));
            }
            post_json(&c.url, &body, &extra).await
        }
        ChannelType::Slack => post_json(&c.url, &slack_body(m), &[]).await,
        ChannelType::Teams => post_json(&c.url, &teams_body(m, c.teams_format), &[]).await,
        ChannelType::Email => send_email(c, m).await,
    }
}

/// Deliver with up to [`MAX_ATTEMPTS`] attempts (backoff 2 s, 6 s).
pub async fn send(c: &Channel, m: &Message) -> Delivery {
    let mut attempts = 0;
    loop {
        attempts += 1;
        match send_once(c, m).await {
            Ok(()) => return Delivery { channel: c.id.clone(), name: c.name.clone(), ok: true, attempts, error: None },
            Err(e) if e.retry && attempts < MAX_ATTEMPTS => {
                tracing::warn!("notify '{}' attempt {attempts} failed: {}", c.name, e.msg);
                tokio::time::sleep(Duration::from_secs(2 * 3u64.pow(attempts - 1))).await;
            }
            Err(e) => {
                tracing::warn!("notify '{}' failed: {}", c.name, e.msg);
                return Delivery { channel: c.id.clone(), name: c.name.clone(), ok: false, attempts, error: Some(e.msg) };
            }
        }
    }
}

/// Deliver to the enabled channels among `ids`, concurrently.
pub async fn send_to(st: &AppState, ids: &[String], m: &Message) -> Vec<Delivery> {
    let channels = st.notify.channels.lock().clone();
    let mut futs = Vec::new();
    let mut out = Vec::new();
    for id in ids {
        match channels.iter().find(|c| &c.id == id) {
            Some(c) if c.enabled => futs.push(send(c, m)),
            Some(c) => out.push(Delivery { channel: id.clone(), name: c.name.clone(), ok: false, attempts: 0, error: Some("channel disabled".into()) }),
            None => out.push(Delivery { channel: id.clone(), name: String::new(), ok: false, attempts: 0, error: Some("unknown channel".into()) }),
        }
    }
    let mut sent = join_all(futs).await;
    sent.append(&mut out);
    sent
}

/// Poll all deliveries together (small fan-out, no extra dependency).
async fn join_all<F: std::future::Future<Output = Delivery>>(futs: Vec<F>) -> Vec<Delivery> {
    let mut pinned: Vec<std::pin::Pin<Box<F>>> = futs.into_iter().map(Box::pin).collect();
    let mut done: Vec<Option<Delivery>> = (0..pinned.len()).map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (f, slot) in pinned.iter_mut().zip(done.iter_mut()) {
            if slot.is_none() {
                match f.as_mut().poll(cx) {
                    std::task::Poll::Ready(d) => *slot = Some(d),
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    done.into_iter().flatten().collect()
}

/// Run `f` to completion on a private single-threaded runtime in a new
/// thread (used from blocking contexts such as the analysis thread).
pub fn spawn_detached<F>(name: &str, f: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let r = std::thread::Builder::new().name(name.into()).spawn(move || {
        match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt.block_on(f),
            Err(e) => tracing::error!("notify runtime: {e}"),
        }
    });
    if let Err(e) = r {
        tracing::error!("spawning notifier thread: {e}");
    }
}

// ------------------------------------------------------------------ API

fn channels_json(st: &AppState) -> Value {
    json!({ "channels": st.notify.channels.lock().iter().map(channel_public).collect::<Vec<_>>() })
}

/// `GET /notify/channels`
pub async fn get_channels(State(st): St) -> Json<Value> {
    Json(channels_json(&st))
}

#[derive(Deserialize)]
pub struct ChannelsReq {
    channels: Vec<ChannelIn>,
}

/// `PUT /notify/channels` — replaces the whole list.
pub async fn put_channels(State(st): St, Json(r): Json<ChannelsReq>) -> Result<Json<Value>, ApiError> {
    if r.channels.len() > MAX_CHANNELS {
        return Err(ApiError::bad(format!("at most {MAX_CHANNELS} channels")));
    }
    {
        let mut channels = st.notify.channels.lock();
        let mut out: Vec<Channel> = Vec::with_capacity(r.channels.len());
        for i in r.channels {
            let old = i.id.as_ref().and_then(|id| channels.iter().find(|c| &c.id == id));
            let c = merge_channel(old, i).map_err(ApiError::bad)?;
            if out.iter().any(|o| o.id == c.id) {
                return Err(ApiError::bad(format!("duplicate channel id '{}'", c.id)));
            }
            out.push(c);
        }
        store_json(&st.notify.channels_path(), &NotifyFile { channels: out.clone() })?;
        *channels = out;
    }
    Ok(Json(channels_json(&st)))
}

/// `POST /notify/channels/{id}/test` — sends a test message (even if disabled).
pub async fn test_channel(State(st): St, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let c = st.notify.channels.lock().iter().find(|c| c.id == id).cloned().ok_or_else(|| ApiError::not_found(format!("no channel '{id}'")))?;
    let m = Message {
        event: "test",
        title: "CopperHound test notification".into(),
        lines: vec![format!("This is a test message for the channel \"{}\".", c.name)],
        facts: vec![("Sent at".into(), now_rfc3339())],
        link: public_url(),
        color: "0090FF",
        data: json!({"channel": c.id}),
        attachment: None,
    };
    let d = send(&c, &m).await;
    Ok(Json(serde_json::to_value(d).unwrap_or(Value::Null)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(v: Value) -> ChannelIn {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn secrets_kept_cleared_and_redacted() {
        // Values that cannot occur in the random (hex) channel id.
        let c = merge_channel(None, input(json!({"name":"hook","type":"webhook","url":"https://example.com/x?token=tokzzq","secret":"s3qq"}))).unwrap();
        let pub_ = channel_public(&c);
        let text = pub_.to_string();
        assert!(!text.contains("tokzzq") && !text.contains("s3qq"), "{text}");
        assert_eq!(pub_["url_set"], true);
        assert_eq!(pub_["secret_set"], true);
        assert_eq!(pub_["url_hint"], "https://example.com/…");
        // Omitted secret is kept; empty string clears it.
        let c2 = merge_channel(Some(&c), input(json!({"id": c.id, "name":"hook2","type":"webhook"}))).unwrap();
        assert_eq!((c2.url.as_str(), c2.secret.as_str()), (c.url.as_str(), "s3qq"));
        let c3 = merge_channel(Some(&c2), input(json!({"id": c.id, "name":"hook2","type":"webhook","secret":""}))).unwrap();
        assert!(c3.secret.is_empty());
    }

    #[test]
    fn validation() {
        assert!(merge_channel(None, input(json!({"name":"x","type":"slack","url":"file:///etc/passwd"}))).is_err());
        assert!(merge_channel(None, input(json!({"name":"x","type":"teams","url":"ftp://h/x"}))).is_err());
        assert!(merge_channel(None, input(json!({"name":"x","type":"webhook"}))).is_err());
        let e = merge_channel(
            None,
            input(json!({"name":"m","type":"email","smtp_host":"smtp.example.com","email_from":"CopperHound <ch@example.com>","email_to":["a@example.com"]})),
        )
        .unwrap();
        assert_eq!(e.smtp_port, 587);
        assert!(merge_channel(
            None,
            input(json!({"name":"m","type":"email","smtp_host":"h","smtp_security":"none","smtp_username":"u","email_from":"a@b.c","email_to":["a@b.c"]}))
        )
        .is_err());
        assert!(merge_channel(None, input(json!({"name":"m","type":"email","smtp_host":"h","email_from":"nope","email_to":["a@b.c"]}))).is_err());
    }

    #[test]
    fn hmac_signature_known_vector() {
        // RFC 4231 test case 2.
        assert_eq!(
            signature("Jefe", b"what do ya want for nothing?"),
            "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
