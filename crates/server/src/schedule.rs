//! Scheduled reports (`<data>/schedules.json`).
//!
//! A schedule fires `daily` at HH:MM UTC, `weekly` on a weekday at HH:MM UTC,
//! or every N hours (`interval`). Each run sends a posture summary (grade,
//! exposure, top findings, delta vs the previous snapshot) to its channels;
//! email channels also get the rendered report attached. A background thread
//! checks for due schedules every [`TICK`]; a schedule that came due while
//! the server was down runs once on the next tick.

use crate::api::{ApiError, St};
use crate::notify::{public_url, send_to, Attachment, Delivery, Message};
use crate::state::{load_json, now_rfc3339, store_json, AppState};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use ch_analysis::posture::Snapshot;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TICK: Duration = Duration::from_secs(20);
const MAX_SCHEDULES: usize = 100;
const DAY: i64 = 86_400;
const WEEKDAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum When {
    /// Every day at `at` (`HH:MM`, UTC).
    Daily { at: String },
    /// Every week on `weekday` (`mon`..`sun`) at `at` (UTC).
    Weekly { weekday: String, at: String },
    /// Every `hours` hours (1-744) after the previous run.
    Interval { hours: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub when: When,
    /// Report format for email attachments: `html`, `md` or `csv`.
    pub format: String,
    pub title: String,
    pub plan_steps: usize,
    pub channels: Vec<String>,
    pub created_at: String,
    #[serde(default)]
    pub last_run: Option<String>,
    /// `ok`, `partial`, `failed` or `skipped`.
    #[serde(default)]
    pub last_status: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_deliveries: Vec<Delivery>,
    #[serde(default)]
    pub next_run: Option<String>,
    #[serde(default)]
    pub running: bool,
}

// ----------------------------------------------------------------- time

pub fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub fn fmt_ts(secs: i64) -> String {
    humantime::format_rfc3339_seconds(UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64)).to_string()
}

pub fn parse_ts(s: &str) -> Option<i64> {
    humantime::parse_rfc3339(s).ok()?.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs() as i64)
}

fn parse_hm(at: &str) -> Result<i64, String> {
    let bad = || format!("invalid time '{at}': use HH:MM (24-hour, UTC)");
    let (h, m) = at.split_once(':').ok_or_else(bad)?;
    if h.len() != 2 || m.len() != 2 {
        return Err(bad());
    }
    let (h, m): (i64, i64) = (h.parse().map_err(|_| bad())?, m.parse().map_err(|_| bad())?);
    if !(0..24).contains(&h) || !(0..60).contains(&m) {
        return Err(bad());
    }
    Ok(h * 3600 + m * 60)
}

fn parse_weekday(w: &str) -> Result<i64, String> {
    let w = w.trim().to_ascii_lowercase();
    const FULL: [&str; 7] = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"];
    (0..7)
        .find(|&i| w == WEEKDAYS[i] || w == FULL[i])
        .map(|i| i as i64)
        .ok_or_else(|| format!("invalid weekday '{w}': use mon, tue, wed, thu, fri, sat or sun"))
}

/// Validate and normalise (`weekday` to its 3-letter form).
pub fn validate_when(w: &When) -> Result<When, String> {
    match w {
        When::Daily { at } => parse_hm(at).map(|_| w.clone()),
        When::Weekly { weekday, at } => {
            parse_hm(at)?;
            let d = parse_weekday(weekday)?;
            Ok(When::Weekly { weekday: WEEKDAYS[d as usize].into(), at: at.clone() })
        }
        When::Interval { hours } => {
            if (1..=744).contains(hours) {
                Ok(w.clone())
            } else {
                Err("interval hours must be 1-744".into())
            }
        }
    }
}

/// Next run strictly after `now` (unix seconds, UTC). `Interval` counts from
/// `last_run` (or `now` if it never ran) and may lie in the past (= due).
pub fn next_run(w: &When, now: i64, last_run: Option<i64>) -> Result<i64, String> {
    match w {
        When::Daily { at } => {
            let t = now.div_euclid(DAY) * DAY + parse_hm(at)?;
            Ok(if t <= now { t + DAY } else { t })
        }
        When::Weekly { weekday, at } => {
            let today = now.div_euclid(DAY);
            // 1970-01-01 was a Thursday (index 3 with Monday = 0).
            let wd = (today + 3).rem_euclid(7);
            let delta = (parse_weekday(weekday)? - wd).rem_euclid(7);
            let t = (today + delta) * DAY + parse_hm(at)?;
            Ok(if t <= now { t + 7 * DAY } else { t })
        }
        When::Interval { hours } => Ok(last_run.unwrap_or(now) + *hours as i64 * 3600),
    }
}

// --------------------------------------------------------------- runner

/// Start the scheduler thread (one per process).
pub fn spawn(st: &Arc<AppState>) {
    let weak = Arc::downgrade(st);
    crate::notify::spawn_detached("copperhound-schedule", async move {
        loop {
            tokio::time::sleep(TICK).await;
            let Some(st) = weak.upgrade() else { return };
            let now = unix_now();
            let due: Vec<String> = st
                .notify
                .schedules
                .lock()
                .iter()
                .filter(|s| s.enabled && !s.running && s.next_run.as_deref().and_then(parse_ts).is_some_and(|t| t <= now))
                .map(|s| s.id.clone())
                .collect();
            for id in due {
                run_schedule(st.clone(), id, true).await;
            }
        }
    });
}

fn save(st: &AppState, list: &[Schedule]) {
    if let Err(e) = store_json(&st.notify.schedules_path(), list) {
        tracing::warn!("saving schedules: {e:#}");
    }
}

fn severity_of(s: &Snapshot, sev: &str) -> usize {
    s.findings.get(sev).copied().unwrap_or(0) as usize
}

pub fn snapshot_grade(s: &Snapshot) -> char {
    ch_analysis::report::grade(s.exposure_percent, severity_of(s, "critical"), severity_of(s, "high")).0
}

/// Summary message for the current analysis (no attachment).
pub fn summary_message(st: &AppState, res: &crate::state::AnalysisResult, title: &str) -> Message {
    let history: Vec<Snapshot> = load_json(&st.posture_path());
    let idx = history.iter().rposition(|s| s.snapshot_id == res.snapshot_id);
    let cur = idx.map(|i| &history[i]);
    let prev = idx.and_then(|i| i.checked_sub(1)).map(|i| &history[i]);
    let mut by_sev = [0usize; 4];
    for f in &res.findings {
        by_sev[f.def.severity as usize] += 1;
    }
    let exposure = cur.map(|c| c.exposure_percent).unwrap_or(0.0);
    let grade = ch_analysis::report::grade(exposure, by_sev[0], by_sev[1]).0;
    let mut lines = Vec::new();
    let mut facts = vec![("Grade".to_string(), grade.to_string())];
    if let Some(c) = cur {
        let mut l = format!(
            "Grade {grade}. {:.1}% of principals ({} of {}) have an attack path to Tier Zero.",
            c.exposure_percent, c.exposed_principals, c.total_principals
        );
        if let Some(p) = prev {
            l.push_str(&format!(" Previous snapshot: grade {}, {:.1}% ({:+.1} points).", snapshot_grade(p), p.exposure_percent, c.exposure_percent - p.exposure_percent));
        }
        lines.push(l);
        facts.push(("Exposure".into(), format!("{:.1}%", c.exposure_percent)));
        facts.push(("Exposed principals".into(), format!("{} / {}", c.exposed_principals, c.total_principals)));
    } else {
        lines.push(format!("Grade {grade}."));
    }
    lines.push(format!("Open findings: {} critical, {} high, {} medium, {} low.", by_sev[0], by_sev[1], by_sev[2], by_sev[3]));
    let top: Vec<Value> = res
        .findings
        .iter()
        .take(5)
        .map(|f| json!({"id": f.def.id, "title": f.def.title, "severity": f.def.severity, "count": f.items.len()}))
        .collect();
    if !top.is_empty() {
        lines.push("Top findings:".into());
        for f in &res.findings[..top.len()] {
            let sev = serde_json::to_value(f.def.severity).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
            lines.push(format!("• [{sev}] {} — {} item(s)", f.def.title, f.items.len()));
        }
    }
    let mut delta = Value::Null;
    if let (Some(c), Some(p)) = (cur, prev) {
        let mut new_ids = Vec::new();
        let mut resolved_ids = Vec::new();
        let mut changed = 0i64;
        for (id, &n) in &c.finding_counts {
            let before = p.finding_counts.get(id).copied().unwrap_or(0);
            changed += n as i64 - before as i64;
            if before == 0 && n > 0 {
                new_ids.push(id.clone());
            }
        }
        for (id, &n) in &p.finding_counts {
            if n > 0 && c.finding_counts.get(id).copied().unwrap_or(0) == 0 {
                resolved_ids.push(id.clone());
                changed -= n as i64;
            }
        }
        lines.push(format!(
            "Since the previous snapshot: {} new finding type(s), {} resolved, {:+} finding item(s) overall.",
            new_ids.len(),
            resolved_ids.len(),
            changed
        ));
        delta = json!({
            "previous_snapshot_id": p.snapshot_id,
            "previous_grade": snapshot_grade(p).to_string(),
            "previous_exposure_percent": p.exposure_percent,
            "exposure_points": c.exposure_percent - p.exposure_percent,
            "new_findings": new_ids,
            "resolved_findings": resolved_ids,
            "item_change": changed,
        });
    }
    facts.push(("Snapshot".into(), res.snapshot_id.clone()));
    Message {
        event: "report",
        title: format!("{title} — grade {grade}"),
        lines,
        facts,
        link: public_url(),
        color: match grade {
            'A' | 'B' => "30A46C",
            'C' => "FFC53D",
            _ => "E5484D",
        },
        data: json!({
            "snapshot_id": res.snapshot_id,
            "grade": grade.to_string(),
            "exposure_percent": exposure,
            "exposed_principals": cur.map(|c| c.exposed_principals),
            "total_principals": cur.map(|c| c.total_principals),
            "findings": {"critical": by_sev[0], "high": by_sev[1], "medium": by_sev[2], "low": by_sev[3]},
            "top_findings": top,
            "delta": delta,
        }),
        attachment: None,
    }
}

/// Run one schedule now. `scheduled`: advance `next_run` (manual runs leave it).
pub async fn run_schedule(st: Arc<AppState>, id: String, scheduled: bool) {
    let sched = {
        let mut list = st.notify.schedules.lock();
        let Some(s) = list.iter_mut().find(|s| s.id == id) else { return };
        if s.running {
            return;
        }
        s.running = true;
        s.clone()
    };
    let started = unix_now();
    let (status, error, deliveries) = match crate::analysis::current_analysis(&st) {
        None => ("skipped", Some("no analysis available (no graph loaded, or analysis still running)".to_string()), Vec::new()),
        Some(res) => {
            let title = if sched.title.trim().is_empty() { sched.name.clone() } else { sched.title.clone() };
            let mut msg = summary_message(&st, &res, &title);
            let wants_email = {
                let ch = st.notify.channels.lock();
                sched.channels.iter().any(|id| ch.iter().any(|c| &c.id == id && c.kind == crate::notify::ChannelType::Email))
            };
            let mut err = None;
            if wants_email {
                let (st2, res2, fmt, t2, steps) = (st.clone(), res.clone(), sched.format.clone(), title.clone(), sched.plan_steps);
                let rendered = tokio::task::spawn_blocking(move || {
                    crate::analysis::render_report(&st2, &res2, &fmt, Some(&t2), steps, 25)
                })
                .await;
                match rendered {
                    Ok(Ok((text, snap))) => {
                        let ct = match sched.format.as_str() {
                            "md" => "text/markdown; charset=utf-8",
                            "csv" => "text/csv; charset=utf-8",
                            _ => "text/html; charset=utf-8",
                        };
                        msg.attachment = Some(Attachment {
                            filename: format!("copperhound-report-{snap}.{}", sched.format),
                            content_type: ct.into(),
                            body: text.into_bytes(),
                        });
                    }
                    Ok(Err(_)) | Err(_) => err = Some("report rendering failed; summary sent without attachment".to_string()),
                }
            }
            let d = send_to(&st, &sched.channels, &msg).await;
            let ok = d.iter().filter(|d| d.ok).count();
            let status = if d.is_empty() {
                "skipped"
            } else if ok == d.len() {
                "ok"
            } else if ok > 0 {
                "partial"
            } else {
                "failed"
            };
            if err.is_none() && ok < d.len() {
                err = d.iter().find_map(|d| d.error.as_ref().map(|e| format!("{}: {e}", d.name)));
            }
            (status, err, d)
        }
    };
    tracing::info!("schedule '{}' ran: {status}", sched.name);
    let mut list = st.notify.schedules.lock();
    if let Some(s) = list.iter_mut().find(|s| s.id == id) {
        s.running = false;
        s.last_run = Some(fmt_ts(started));
        s.last_status = Some(status.into());
        s.last_error = error;
        s.last_deliveries = deliveries;
        if scheduled || s.next_run.is_none() || matches!(s.when, When::Interval { .. }) {
            s.next_run = next_run(&s.when, unix_now(), Some(started)).ok().map(fmt_ts);
        }
        save(&st, &list);
    }
}

// ------------------------------------------------------------------ API

#[derive(Deserialize)]
pub struct ScheduleIn {
    name: String,
    #[serde(default)]
    enabled: Option<bool>,
    when: When,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    plan_steps: Option<usize>,
    #[serde(default)]
    channels: Vec<String>,
}

fn validate(st: &AppState, r: &ScheduleIn) -> Result<(When, String), ApiError> {
    if r.name.trim().is_empty() || r.name.len() > 100 {
        return Err(ApiError::bad("name must be 1-100 characters"));
    }
    let when = validate_when(&r.when).map_err(ApiError::bad)?;
    let format = r.format.clone().unwrap_or_else(|| "html".into()).to_ascii_lowercase();
    let format = match format.as_str() {
        "html" | "md" | "csv" => format,
        "markdown" => "md".into(),
        _ => return Err(ApiError::bad("format must be html, md or csv")),
    };
    if r.title.as_ref().is_some_and(|t| t.len() > 200) {
        return Err(ApiError::bad("title must be at most 200 characters"));
    }
    if r.plan_steps.is_some_and(|n| n > 50) {
        return Err(ApiError::bad("plan_steps must be 0-50"));
    }
    if r.channels.is_empty() || r.channels.len() > 20 {
        return Err(ApiError::bad("channels needs 1-20 channel ids"));
    }
    let ch = st.notify.channels.lock();
    for id in &r.channels {
        if !ch.iter().any(|c| &c.id == id) {
            return Err(ApiError::bad(format!("unknown channel '{id}'")));
        }
    }
    Ok((when, format))
}

/// `GET /schedules`
pub async fn list(State(st): St) -> Json<Value> {
    Json(json!({"schedules": *st.notify.schedules.lock(), "public_url": public_url()}))
}

/// `POST /schedules`
pub async fn create(State(st): St, Json(r): Json<ScheduleIn>) -> Result<Json<Schedule>, ApiError> {
    let (when, format) = validate(&st, &r)?;
    let mut list = st.notify.schedules.lock();
    if list.len() >= MAX_SCHEDULES {
        return Err(ApiError::bad(format!("at most {MAX_SCHEDULES} schedules")));
    }
    let next = next_run(&when, unix_now(), None).map_err(ApiError::bad)?;
    let s = Schedule {
        id: format!("s-{}", crate::auth::random_hex(6)),
        name: r.name.trim().into(),
        enabled: r.enabled.unwrap_or(true),
        when,
        format,
        title: r.title.unwrap_or_default().trim().into(),
        plan_steps: r.plan_steps.unwrap_or(10),
        channels: r.channels,
        created_at: now_rfc3339(),
        last_run: None,
        last_status: None,
        last_error: None,
        last_deliveries: Vec::new(),
        next_run: Some(fmt_ts(next)),
        running: false,
    };
    list.push(s.clone());
    store_json(&st.notify.schedules_path(), &*list)?;
    Ok(Json(s))
}

/// `PUT /schedules/{id}` — replaces the definition; run history is kept.
pub async fn update(State(st): St, Path(id): Path<String>, Json(r): Json<ScheduleIn>) -> Result<Json<Schedule>, ApiError> {
    let (when, format) = validate(&st, &r)?;
    let mut list = st.notify.schedules.lock();
    let s = list.iter_mut().find(|s| s.id == id).ok_or_else(|| ApiError::not_found(format!("no schedule '{id}'")))?;
    let last = s.last_run.as_deref().and_then(parse_ts);
    s.next_run = Some(fmt_ts(next_run(&when, unix_now(), last).map_err(ApiError::bad)?));
    s.name = r.name.trim().into();
    s.enabled = r.enabled.unwrap_or(true);
    s.when = when;
    s.format = format;
    s.title = r.title.unwrap_or_default().trim().into();
    s.plan_steps = r.plan_steps.unwrap_or(10);
    s.channels = r.channels;
    let out = s.clone();
    store_json(&st.notify.schedules_path(), &*list)?;
    Ok(Json(out))
}

/// `DELETE /schedules/{id}`
pub async fn remove(State(st): St, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let mut list = st.notify.schedules.lock();
    let before = list.len();
    list.retain(|s| s.id != id);
    if list.len() == before {
        return Err(ApiError::not_found(format!("no schedule '{id}'")));
    }
    store_json(&st.notify.schedules_path(), &*list)?;
    Ok(Json(json!({})))
}

/// `POST /schedules/{id}/run` — `202 {"started": true}`; poll `GET /schedules`.
pub async fn run_now(State(st): St, Path(id): Path<String>) -> Response {
    {
        let list = st.notify.schedules.lock();
        match list.iter().find(|s| s.id == id) {
            None => return ApiError::not_found(format!("no schedule '{id}'")).into_response(),
            Some(s) if s.running => return ApiError::new(StatusCode::CONFLICT, "this schedule is already running").into_response(),
            Some(_) => {}
        }
    }
    tokio::spawn(run_schedule(st.clone(), id, false));
    (StatusCode::ACCEPTED, Json(json!({"started": true}))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> i64 {
        parse_ts(s).unwrap()
    }

    #[test]
    fn daily_next_run() {
        let w = When::Daily { at: "07:30".into() };
        assert_eq!(fmt_ts(next_run(&w, ts("2026-11-09T06:00:00Z"), None).unwrap()), "2026-11-09T07:30:00Z");
        assert_eq!(fmt_ts(next_run(&w, ts("2026-11-09T07:30:00Z"), None).unwrap()), "2026-11-10T07:30:00Z");
        assert_eq!(fmt_ts(next_run(&w, ts("2026-12-31T23:59:00Z"), None).unwrap()), "2027-01-01T07:30:00Z");
    }

    #[test]
    fn weekly_next_run() {
        // 2026-11-09 is a Monday.
        let w = When::Weekly { weekday: "mon".into(), at: "08:00".into() };
        assert_eq!(fmt_ts(next_run(&w, ts("2026-11-09T07:00:00Z"), None).unwrap()), "2026-11-09T08:00:00Z");
        assert_eq!(fmt_ts(next_run(&w, ts("2026-11-09T09:00:00Z"), None).unwrap()), "2026-11-16T08:00:00Z");
        let fri = When::Weekly { weekday: "Friday".into(), at: "17:05".into() };
        assert_eq!(fmt_ts(next_run(&fri, ts("2026-11-09T09:00:00Z"), None).unwrap()), "2026-11-13T17:05:00Z");
        let sun = When::Weekly { weekday: "sun".into(), at: "00:00".into() };
        assert_eq!(fmt_ts(next_run(&sun, ts("2026-11-14T23:00:00Z"), None).unwrap()), "2026-11-15T00:00:00Z");
    }

    #[test]
    fn interval_next_run() {
        let w = When::Interval { hours: 6 };
        let now = ts("2026-11-09T10:00:00Z");
        assert_eq!(fmt_ts(next_run(&w, now, None).unwrap()), "2026-11-09T16:00:00Z");
        assert_eq!(fmt_ts(next_run(&w, now, Some(ts("2026-11-09T09:00:00Z"))).unwrap()), "2026-11-09T15:00:00Z");
        // Long-overdue: in the past, i.e. due immediately.
        assert!(next_run(&w, now, Some(ts("2026-11-01T00:00:00Z"))).unwrap() < now);
    }

    #[test]
    fn when_validation() {
        assert!(validate_when(&When::Daily { at: "24:00".into() }).is_err());
        assert!(validate_when(&When::Daily { at: "7:30".into() }).is_err());
        assert!(validate_when(&When::Daily { at: "07:60".into() }).is_err());
        assert!(validate_when(&When::Weekly { weekday: "funday".into(), at: "07:00".into() }).is_err());
        assert_eq!(
            validate_when(&When::Weekly { weekday: "TUESDAY".into(), at: "07:00".into() }).unwrap(),
            When::Weekly { weekday: "tue".into(), at: "07:00".into() }
        );
        assert!(validate_when(&When::Interval { hours: 0 }).is_err());
        assert!(validate_when(&When::Interval { hours: 745 }).is_err());
        let w: When = serde_json::from_value(json!({"kind":"weekly","weekday":"wed","at":"12:00"})).unwrap();
        assert!(validate_when(&w).is_ok());
    }
}
