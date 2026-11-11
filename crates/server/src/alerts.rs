//! Change alerts: after every ingest that produces a new posture snapshot
//! (manual upload, watch folder or API), the new posture is compared with the
//! previous one and the configured rules (`<data>/alert_rules.json`) decide
//! whether to notify. Fired alerts are kept in `<data>/alerts.jsonl`
//! (rotated to `alerts.1.jsonl` past [`ROTATE_BYTES`]).
//!
//! The comparison state (exposed-principal set as 64-bit FNV hashes of
//! object ids, top choke points) is kept in `<data>/alert_state.json`.
//! Delivery runs on a separate thread, so it never delays ingest or analysis.

use crate::api::{ApiError, St};
use crate::notify::{public_url, send_to, Delivery, Message};
use crate::state::{load_json, now_rfc3339, store_json, AppState};
use axum::extract::{Query, State};
use axum::Json;
use parking_lot::Mutex;
use ch_analysis::findings::{FindingResult, CATALOG};
use ch_analysis::posture::Snapshot;
use ch_engine::{par_bfs, Dir, EdgeFilter};
use ch_store::Graph;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Arc;

const ROTATE_BYTES: u64 = 8 << 20;
pub const HISTORY_LIMIT: usize = 500;
const SAMPLE: usize = 10;

// ---------------------------------------------------------------- rules

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertRules {
    pub enabled: bool,
    pub channels: Vec<String>,
    /// The letter grade got worse (e.g. B → C).
    pub grade_worse: bool,
    /// Exposure rose by at least this many percentage points (`null`: off).
    pub exposure_increase_points: Option<f64>,
    /// Finding types (ids) that had no items before and have some now, with
    /// one of these severities. Empty: off.
    pub new_finding_severities: Vec<String>,
    /// At least this many principals newly have a path to Tier Zero (`null`: off).
    pub new_tier0_principals_min: Option<u64>,
    /// The set of the top `choke_points_top` choke-point edges changed.
    pub choke_points_changed: bool,
    pub choke_points_top: usize,
    /// Principals to watch (object ids or names): alert when one of them
    /// newly has an attack path to Tier Zero. A watched group fires when
    /// the group itself gains a path.
    pub watch: Vec<String>,
}

/// Most watched principals.
pub const MAX_WATCH: usize = 500;

impl Default for AlertRules {
    fn default() -> Self {
        AlertRules {
            enabled: false,
            channels: Vec::new(),
            grade_worse: true,
            exposure_increase_points: Some(5.0),
            new_finding_severities: vec!["critical".into(), "high".into()],
            new_tier0_principals_min: Some(10),
            choke_points_changed: false,
            choke_points_top: 10,
            watch: Vec::new(),
        }
    }
}

/// What alerts compare: one per snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PostureView {
    pub snapshot_id: String,
    pub grade: char,
    pub exposure_percent: f64,
    pub exposed_principals: u64,
    /// Item count per finding id.
    pub finding_counts: BTreeMap<String, u64>,
    /// Sorted FNV-1a hashes of exposed principals' object ids (`None`: unknown).
    #[serde(default)]
    pub exposed: Option<Vec<u64>>,
    /// Top choke points `(key, label)` (`None`: unknown).
    #[serde(default)]
    pub choke_points: Option<Vec<(String, String)>>,
    /// Hashes of the watched objects that existed (`None`: unknown).
    #[serde(default)]
    pub watched_known: Option<Vec<u64>>,
    /// Hashes of the watched objects (any kind) with a path to Tier Zero.
    #[serde(default)]
    pub watched_exposed: Option<Vec<u64>>,
}

impl PostureView {
    /// From a stored posture snapshot (no exposed set / choke points).
    pub fn from_snapshot(s: &Snapshot) -> PostureView {
        PostureView {
            snapshot_id: s.snapshot_id.clone(),
            grade: crate::schedule::snapshot_grade(s),
            exposure_percent: s.exposure_percent,
            exposed_principals: s.exposed_principals,
            finding_counts: s.finding_counts.clone(),
            exposed: None,
            choke_points: None,
            watched_known: None,
            watched_exposed: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trigger {
    /// `grade_worse`, `exposure_increase`, `new_findings`, `new_tier0_principals`, `choke_points_changed`.
    pub rule: String,
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Evaluation {
    pub triggers: Vec<Trigger>,
    pub new_findings: Vec<Value>,
    pub new_tier0_principals: u64,
    pub choke_points_added: Vec<String>,
    pub choke_points_removed: Vec<String>,
}

fn severity_str(id: &str) -> Option<(&'static str, &'static str)> {
    let d = CATALOG.iter().find(|d| d.id == id)?;
    let sev = match d.severity {
        ch_analysis::findings::Severity::Critical => "critical",
        ch_analysis::findings::Severity::High => "high",
        ch_analysis::findings::Severity::Medium => "medium",
        ch_analysis::findings::Severity::Low => "low",
    };
    Some((sev, d.title))
}

/// Count of hashes in sorted `after` that are not in sorted `before`.
fn new_in(before: &[u64], after: &[u64]) -> u64 {
    after.iter().filter(|h| before.binary_search(h).is_err()).count() as u64
}

/// Evaluate `rules` on a before/after pair (pure; ignores `enabled`).
pub fn evaluate(rules: &AlertRules, before: &PostureView, after: &PostureView) -> Evaluation {
    let mut ev = Evaluation::default();
    if rules.grade_worse && after.grade > before.grade {
        ev.triggers.push(Trigger { rule: "grade_worse".into(), message: format!("Grade got worse: {} → {}.", before.grade, after.grade) });
    }
    if let Some(points) = rules.exposure_increase_points {
        let d = after.exposure_percent - before.exposure_percent;
        if d > 0.0 && d >= points {
            ev.triggers.push(Trigger {
                rule: "exposure_increase".into(),
                message: format!(
                    "Tier Zero exposure rose {:.1} points: {:.1}% → {:.1}%.",
                    d, before.exposure_percent, after.exposure_percent
                ),
            });
        }
    }
    if !rules.new_finding_severities.is_empty() {
        for (id, &n) in &after.finding_counts {
            if n == 0 || before.finding_counts.get(id).copied().unwrap_or(0) > 0 {
                continue;
            }
            let Some((sev, title)) = severity_str(id) else { continue };
            if rules.new_finding_severities.iter().any(|s| s == sev) {
                ev.new_findings.push(json!({"id": id, "title": title, "severity": sev, "count": n}));
            }
        }
        if !ev.new_findings.is_empty() {
            let names: Vec<String> = ev
                .new_findings
                .iter()
                .map(|f| format!("[{}] {} ({})", f["severity"].as_str().unwrap_or(""), f["title"].as_str().unwrap_or(""), f["count"]))
                .collect();
            ev.triggers.push(Trigger { rule: "new_findings".into(), message: format!("New findings: {}.", names.join("; ")) });
        }
    }
    if let (Some(min), Some(b), Some(a)) = (rules.new_tier0_principals_min, &before.exposed, &after.exposed) {
        let n = new_in(b, a);
        ev.new_tier0_principals = n;
        if n >= min.max(1) {
            ev.triggers.push(Trigger {
                rule: "new_tier0_principals".into(),
                message: format!("{n} principal(s) gained an attack path to Tier Zero."),
            });
        }
    }
    if rules.choke_points_changed {
        if let (Some(b), Some(a)) = (&before.choke_points, &after.choke_points) {
            let top = rules.choke_points_top.max(1);
            let (b, a) = (&b[..b.len().min(top)], &a[..a.len().min(top)]);
            ev.choke_points_added = a.iter().filter(|x| !b.iter().any(|y| y.0 == x.0)).map(|x| x.1.clone()).collect();
            ev.choke_points_removed = b.iter().filter(|x| !a.iter().any(|y| y.0 == x.0)).map(|x| x.1.clone()).collect();
            if !ev.choke_points_added.is_empty() || !ev.choke_points_removed.is_empty() {
                ev.triggers.push(Trigger {
                    rule: "choke_points_changed".into(),
                    message: format!(
                        "Top choke points changed: {} new, {} gone.",
                        ev.choke_points_added.len(),
                        ev.choke_points_removed.len()
                    ),
                });
            }
        }
    }
    ev
}

// ---------------------------------------------------------------- hook

pub fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn hashes(g: &Graph, nodes: impl Iterator<Item = u32>) -> Vec<u64> {
    let mut h: Vec<u64> = nodes.map(|n| fnv1a(g.oid(n))).collect();
    h.sort_unstable();
    h.dedup();
    h
}

/// Compute the view of the current graph: exposed set and top choke points.
/// Returns the view, the exposed principals and the exposed watched nodes
/// (of any kind, e.g. groups).
fn current_view(g: &Graph, snapshot_id: &str, tier0: &[u32], findings: &[FindingResult], top: usize, watch: &ahash::AHashSet<u32>) -> (PostureView, Vec<u32>, Vec<u32>) {
    let f = EdgeFilter::traversable(g);
    let bfs = par_bfs(g, tier0, Dir::Reverse, &|_, _, k| f.allows(k));
    let t0 = bfs.levels.get(1).copied().unwrap_or(bfs.order.len());
    let exposed_nodes: Vec<u32> = bfs.order[t0..].iter().copied().filter(|&n| ch_engine::is_principal(g.kind(n))).collect();
    let watched_exposed: Vec<u32> = if watch.is_empty() { Vec::new() } else { bfs.order[t0..].iter().copied().filter(|n| watch.contains(n)).collect() };
    let mut exposed: Vec<u64> = exposed_nodes.iter().map(|&n| fnv1a(g.oid(n))).collect();
    exposed.sort_unstable();
    exposed.dedup();
    let rep = ch_analysis::simulate::exposure_with(g, tier0, &ch_analysis::Removal::default(), top.max(1));
    let choke = rep
        .choke_points
        .iter()
        .map(|c| (format!("{}|{}|{}", g.oid(c.src), g.edge_kind_name(c.kind), g.oid(c.dst)), ch_analysis::edge_label(g, (c.src, c.dst, c.kind))))
        .collect();
    let exposure_percent =
        if rep.total_principals == 0 { 0.0 } else { 100.0 * rep.exposed_principals as f64 / rep.total_principals as f64 };
    let mut by_sev = [0usize; 4];
    for f in findings {
        by_sev[f.def.severity as usize] += 1;
    }
    let view = PostureView {
        snapshot_id: snapshot_id.to_string(),
        grade: ch_analysis::report::grade(exposure_percent, by_sev[0], by_sev[1]).0,
        exposure_percent,
        exposed_principals: rep.exposed_principals,
        finding_counts: findings.iter().map(|f| (f.def.id.to_string(), f.items.len() as u64)).collect(),
        exposed: Some(exposed),
        choke_points: Some(choke),
        watched_known: Some(hashes(g, watch.iter().copied())),
        watched_exposed: Some(hashes(g, watched_exposed.iter().copied())),
    };
    (view, exposed_nodes, watched_exposed)
}

/// One hop of a stored path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PathHop {
    pub src: String,
    pub src_name: String,
    pub kind: String,
    pub dst: String,
    pub dst_name: String,
}

/// A principal that newly reaches Tier Zero, with one shortest path as of
/// the snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NewPath {
    pub objectid: String,
    pub name: String,
    pub kind: String,
    /// On the watch list.
    #[serde(default)]
    pub watched: bool,
    pub hops: Vec<PathHop>,
}

/// Shortest path from `n` into `tier0` over traversable edges.
fn path_to_tier0(g: &Graph, n: u32, tier0: &[u32], f: &EdgeFilter, watched: bool) -> NewPath {
    let hops = ch_engine::shortest_path(g, &[n], tier0, f)
        .map(|p| {
            p.nodes
                .windows(2)
                .zip(&p.kinds)
                .map(|(w, &k)| PathHop {
                    src: g.oid(w[0]).to_string(),
                    src_name: g.name(w[0]).to_string(),
                    kind: g.edge_kind_name(k).to_string(),
                    dst: g.oid(w[1]).to_string(),
                    dst_name: g.name(w[1]).to_string(),
                })
                .collect()
        })
        .unwrap_or_default();
    NewPath { objectid: g.oid(n).to_string(), name: g.name(n).to_string(), kind: g.kind_name(n).to_string(), watched, hops }
}

/// `A -[MemberOf]-> B -[AdminTo]-> C`
pub fn path_text(p: &NewPath) -> String {
    let mut s = p.name.clone();
    for h in &p.hops {
        s.push_str(&format!(" -[{}]-> {}", h.kind, h.dst_name));
    }
    s
}

/// Watched nodes exposed now that were known to be unexposed before: on the
/// previous watch list and not exposed then, or (for principals added to the
/// list since) not in the previous exposed-principal set. Others are unknown
/// and stay quiet.
fn watched_newly_exposed(g: &Graph, watched_exposed: &[u32], before: &PostureView) -> Vec<u32> {
    let has = |v: &Option<Vec<u64>>, h: u64| v.as_ref().map(|v| v.binary_search(&h).is_ok());
    watched_exposed
        .iter()
        .copied()
        .filter(|&n| {
            let h = fnv1a(g.oid(n));
            if has(&before.watched_known, h) == Some(true) {
                has(&before.watched_exposed, h) == Some(false)
            } else {
                ch_engine::is_principal(g.kind(n)) && has(&before.exposed, h) == Some(false)
            }
        })
        .collect()
}

/// Up to [`SAMPLE`] principals exposed now and not before, skipping `skip`.
fn newly_exposed_sample(g: &Graph, exposed_nodes: &[u32], before: &[u64], skip: &[u32]) -> Vec<u32> {
    exposed_nodes.iter().copied().filter(|n| !skip.contains(n) && before.binary_search(&fnv1a(g.oid(*n))).is_err()).take(SAMPLE).collect()
}

/// Called from the analysis thread once a new posture snapshot was recorded.
/// Computes the comparison state, evaluates rules and (if any fire) delivers
/// on a separate thread.
pub fn after_snapshot(st: &Arc<AppState>, g: &Graph, snapshot_id: &str, tier0: &[u32], findings: &[FindingResult]) {
    let rules = st.notify.rules.lock().clone();
    let state_path = st.notify.alert_state_path();
    let mut before: Option<PostureView> = std::fs::read(&state_path).ok().and_then(|b| serde_json::from_slice(&b).ok());
    if before.as_ref().is_some_and(|b| b.snapshot_id == snapshot_id) {
        return;
    }
    if before.is_none() {
        // First run with alerts: fall back to the previous posture snapshot.
        let history: Vec<Snapshot> = load_json(&st.posture_path());
        before = history.iter().rev().find(|s| s.snapshot_id != snapshot_id).map(PostureView::from_snapshot);
    }
    // Accepted risks do not raise new-finding alerts.
    let accepted = crate::risk::active(st);
    let open: Vec<FindingResult> = findings.iter().filter(|f| !accepted.contains_key(f.def.id)).cloned().collect();
    let watch: ahash::AHashSet<u32> = rules.watch.iter().filter_map(|w| g.lookup(w)).collect();
    let (after, exposed_nodes, watched_exposed) = current_view(g, snapshot_id, tier0, &open, rules.choke_points_top.max(10), &watch);
    if let Err(e) = store_json(&state_path, &after) {
        tracing::warn!("saving alert state: {e:#}");
    }
    let Some(before) = before else { return };
    if !rules.enabled {
        return;
    }
    let mut ev = evaluate(&rules, &before, &after);
    // Watched principals and paths of newly exposed ones.
    let watched_new = watched_newly_exposed(g, &watched_exposed, &before);
    let sample_nodes = before.exposed.as_deref().map(|b| newly_exposed_sample(g, &exposed_nodes, b, &watched_new)).unwrap_or_default();
    if !watched_new.is_empty() {
        let names: Vec<&str> = watched_new.iter().take(SAMPLE).map(|&n| g.name(n)).collect();
        let more = watched_new.len().saturating_sub(SAMPLE);
        ev.triggers.push(Trigger {
            rule: "watched_gained_path".into(),
            message: format!(
                "Watched principal{} gained an attack path to Tier Zero: {}{}.",
                if watched_new.len() == 1 { "" } else { "s" },
                names.join(", "),
                if more > 0 { format!(" and {more} more") } else { String::new() }
            ),
        });
    }
    if ev.triggers.is_empty() {
        return;
    }
    let f = EdgeFilter::traversable(g);
    let show_sample = ev.new_tier0_principals > 0 && ev.triggers.iter().any(|t| t.rule == "new_tier0_principals");
    let mut new_paths: Vec<NewPath> = watched_new.iter().take(SAMPLE).map(|&n| path_to_tier0(g, n, tier0, &f, true)).collect();
    if show_sample {
        new_paths.extend(sample_nodes.iter().map(|&n| path_to_tier0(g, n, tier0, &f, false)));
    }
    let sample: Vec<String> = if show_sample { sample_nodes.iter().map(|&n| g.name(n).to_string()).collect() } else { Vec::new() };
    let alert = Alert {
        id: format!("a-{}", crate::auth::random_hex(6)),
        ts: now_rfc3339(),
        snapshot_id: after.snapshot_id.clone(),
        previous_snapshot_id: before.snapshot_id.clone(),
        grade_before: before.grade.to_string(),
        grade_after: after.grade.to_string(),
        exposure_before: before.exposure_percent,
        exposure_after: after.exposure_percent,
        triggers: ev.triggers,
        new_findings: ev.new_findings,
        new_tier0_principals: ev.new_tier0_principals,
        new_tier0_sample: sample,
        choke_points_added: ev.choke_points_added.into_iter().take(SAMPLE).collect(),
        choke_points_removed: ev.choke_points_removed.into_iter().take(SAMPLE).collect(),
        new_paths,
        deliveries: Vec::new(),
    };
    let st = st.clone();
    crate::notify::spawn_detached("copperhound-alert", async move {
        let mut alert = alert;
        let msg = alert_message(&alert);
        alert.deliveries = send_to(&st, &rules.channels, &msg).await;
        st.notify.alert_log.append(&alert);
    });
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub ts: String,
    pub snapshot_id: String,
    pub previous_snapshot_id: String,
    pub grade_before: String,
    pub grade_after: String,
    pub exposure_before: f64,
    pub exposure_after: f64,
    pub triggers: Vec<Trigger>,
    pub new_findings: Vec<Value>,
    pub new_tier0_principals: u64,
    pub new_tier0_sample: Vec<String>,
    pub choke_points_added: Vec<String>,
    pub choke_points_removed: Vec<String>,
    /// Newly exposed principals (watched first) with a path each.
    #[serde(default)]
    pub new_paths: Vec<NewPath>,
    pub deliveries: Vec<Delivery>,
}

pub fn alert_message(a: &Alert) -> Message {
    let mut lines: Vec<String> = a.triggers.iter().map(|t| format!("• {}", t.message)).collect();
    if !a.new_tier0_sample.is_empty() {
        lines.push(format!("Newly exposed (sample): {}", a.new_tier0_sample.join(", ")));
    }
    for p in a.new_paths.iter().take(5) {
        if !p.hops.is_empty() {
            lines.push(format!("Path{}: {}", if p.watched { " (watched)" } else { "" }, path_text(p)));
        }
    }
    for c in a.choke_points_added.iter().take(5) {
        lines.push(format!("+ choke point: {c}"));
    }
    for c in a.choke_points_removed.iter().take(5) {
        lines.push(format!("− choke point: {c}"));
    }
    Message {
        event: "alert",
        title: format!("CopperHound alert: {} rule(s) triggered", a.triggers.len()),
        lines,
        facts: vec![
            ("Grade".into(), format!("{} → {}", a.grade_before, a.grade_after)),
            ("Exposure".into(), format!("{:.1}% → {:.1}%", a.exposure_before, a.exposure_after)),
            ("Snapshot".into(), a.snapshot_id.clone()),
        ],
        link: public_url(),
        color: "E5484D",
        data: serde_json::to_value(a).unwrap_or(Value::Null),
        attachment: None,
    }
}

// ------------------------------------------------------------- history

pub struct AlertLog {
    path: PathBuf,
    lock: Mutex<()>,
}

impl AlertLog {
    pub fn new(path: PathBuf) -> AlertLog {
        AlertLog { path, lock: Mutex::new(()) }
    }

    pub fn append(&self, a: &Alert) {
        let Ok(mut line) = serde_json::to_vec(a) else { return };
        line.push(b'\n');
        let _g = self.lock.lock();
        if std::fs::metadata(&self.path).is_ok_and(|m| m.len() > ROTATE_BYTES) {
            let _ = std::fs::rename(&self.path, self.path.with_extension("1.jsonl"));
        }
        match OpenOptions::new().create(true).append(true).open(&self.path) {
            Ok(mut f) => {
                if let Err(e) = f.write_all(&line) {
                    tracing::warn!("writing alert history: {e}");
                }
            }
            Err(e) => tracing::warn!("opening alert history: {e}"),
        }
    }

    /// Newest first.
    pub fn recent(&self, limit: usize) -> Vec<Alert> {
        let _g = self.lock.lock();
        let mut out = Vec::new();
        for p in [self.path.with_extension("1.jsonl"), self.path.clone()] {
            let Ok(f) = File::open(&p) else { continue };
            out.extend(BufReader::new(f).lines().map_while(Result::ok).filter_map(|l| serde_json::from_str::<Alert>(&l).ok()));
        }
        out.reverse();
        out.truncate(limit);
        out
    }
}

// ------------------------------------------------------------------ API

/// `GET /alerts/rules`
pub async fn get_rules(State(st): St) -> Json<AlertRules> {
    Json(st.notify.rules.lock().clone())
}

/// `PUT /alerts/rules`
pub async fn put_rules(State(st): St, Json(mut r): Json<AlertRules>) -> Result<Json<AlertRules>, ApiError> {
    let mut seen = std::collections::HashSet::new();
    r.watch = r.watch.iter().map(|w| w.trim().to_string()).filter(|w| !w.is_empty() && seen.insert(w.to_ascii_uppercase())).collect();
    if r.watch.len() > MAX_WATCH || r.watch.iter().any(|w| w.len() > 300) {
        return Err(ApiError::bad(format!("at most {MAX_WATCH} watched principals")));
    }
    if r.exposure_increase_points.is_some_and(|p| !(0.0..=100.0).contains(&p) || p.is_nan()) {
        return Err(ApiError::bad("exposure_increase_points must be 0-100 or null"));
    }
    if r.new_tier0_principals_min == Some(0) {
        return Err(ApiError::bad("new_tier0_principals_min must be at least 1, or null"));
    }
    if !(1..=100).contains(&r.choke_points_top) {
        return Err(ApiError::bad("choke_points_top must be 1-100"));
    }
    for s in &r.new_finding_severities {
        if !["critical", "high", "medium", "low"].contains(&s.as_str()) {
            return Err(ApiError::bad(format!("unknown severity '{s}'")));
        }
    }
    if r.channels.len() > 20 {
        return Err(ApiError::bad("at most 20 channels"));
    }
    {
        let ch = st.notify.channels.lock();
        for id in &r.channels {
            if !ch.iter().any(|c| &c.id == id) {
                return Err(ApiError::bad(format!("unknown channel '{id}'")));
            }
        }
    }
    if r.enabled && r.channels.is_empty() {
        return Err(ApiError::bad("enabled alerts need at least one channel"));
    }
    store_json(&st.notify.rules_path(), &r)?;
    *st.notify.rules.lock() = r.clone();
    Ok(Json(r))
}

#[derive(Deserialize)]
pub struct AlertsQ {
    limit: Option<usize>,
}

/// `GET /alerts?limit=` — newest first, at most 500.
pub async fn history(State(st): St, Query(q): Query<AlertsQ>) -> Json<Value> {
    let limit = q.limit.unwrap_or(100).clamp(1, HISTORY_LIMIT);
    let st2 = st.clone();
    let alerts = tokio::task::spawn_blocking(move || st2.notify.alert_log.recent(limit)).await.unwrap_or_default();
    Json(json!({ "alerts": alerts }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(id: &str, grade: char, exposure: f64, counts: &[(&str, u64)], exposed: Option<Vec<u64>>, choke: Option<Vec<&str>>) -> PostureView {
        PostureView {
            snapshot_id: id.into(),
            grade,
            exposure_percent: exposure,
            exposed_principals: exposed.as_ref().map(|e| e.len() as u64).unwrap_or(0),
            finding_counts: counts.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            exposed: exposed.map(|mut e| {
                e.sort_unstable();
                e
            }),
            choke_points: choke.map(|c| c.into_iter().map(|k| (k.to_string(), format!("label {k}"))).collect()),
            ..Default::default()
        }
    }

    fn sev_id(sev: ch_analysis::findings::Severity) -> &'static str {
        CATALOG.iter().find(|d| d.severity == sev).unwrap().id
    }

    /// 0 alice -MemberOf-> 1 helpdesk -AdminTo-> 2 ws -HasSession-> 3 bob
    /// -MemberOf-> 4 DA (Tier Zero); 5 carol -MemberOf-> 1.
    fn small() -> Graph {
        use ch_model::{ek, flags};
        use ch_store::{Edge, GraphParts};
        let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
        Graph::build(GraphParts {
            kinds: vec![1, 2, 3, 1, 2, 1],
            flags: vec![0, 0, 0, 0, flags::TIER0, 0],
            names: ["ALICE", "HELPDESK", "WS", "BOB", "DA", "CAROL"].iter().map(|n| Some(n.to_string())).collect(),
            oids: (0..6).map(|i| format!("S-1-5-21-1-{i}")).collect(),
            props: vec![None; 6],
            edge_chunks: vec![vec![
                Edge::new(0, 1, ek::MEMBER_OF),
                Edge::new(1, 2, ek::ADMIN_TO),
                Edge::new(2, 3, ek::HAS_SESSION),
                Edge::new(3, 4, ek::MEMBER_OF),
                Edge::new(5, 1, ek::MEMBER_OF),
            ]],
            edge_kinds,
            traversable,
            node_kinds: Vec::new(),
        })
        .unwrap()
        .0
    }

    #[test]
    fn watched_principals_and_paths() {
        let g = small();
        let tier0 = [4u32];
        // Watch carol (user), helpdesk (group) and bob.
        let watch: ahash::AHashSet<u32> = [5u32, 1, 3].into_iter().collect();
        let (view, exposed, watched_exposed) = current_view(&g, "s2", &tier0, &[], 5, &watch);
        let mut e = exposed.clone();
        e.sort_unstable();
        assert_eq!(e, vec![0, 2, 3, 5], "principals (users, computers) that reach DA");
        let mut w = watched_exposed.clone();
        w.sort_unstable();
        assert_eq!(w, vec![1, 3, 5], "watched nodes of any kind, groups included");
        assert_eq!(view.watched_exposed.as_ref().unwrap().len(), 3);

        // Before: helpdesk was watched and unexposed; bob was exposed; carol
        // was not watched yet (falls back to the exposed-principal set).
        let h = |ns: &[u32]| hashes(&g, ns.iter().copied());
        let before = PostureView { exposed: Some(h(&[2, 3])), watched_known: Some(h(&[1, 3])), watched_exposed: Some(h(&[3])), ..Default::default() };
        let mut new = watched_newly_exposed(&g, &watched_exposed, &before);
        new.sort_unstable();
        assert_eq!(new, vec![1, 5]);
        // Unknown history (no stored state) never fires.
        assert!(watched_newly_exposed(&g, &watched_exposed, &PostureView::default()).is_empty());
        // A watched group added since the last snapshot is unknown too.
        let before2 = PostureView { exposed: Some(h(&[2, 3])), watched_known: Some(h(&[3])), watched_exposed: Some(h(&[3])), ..Default::default() };
        assert_eq!(watched_newly_exposed(&g, &[1], &before2), Vec::<u32>::new());

        let sample = newly_exposed_sample(&g, &exposed, before.exposed.as_ref().unwrap(), &new);
        assert_eq!(sample, vec![0], "alice is new and not watched");
        let f = EdgeFilter::traversable(&g);
        let p = path_to_tier0(&g, 5, &tier0, &f, true);
        assert_eq!(path_text(&p), "CAROL -[MemberOf]-> HELPDESK -[AdminTo]-> WS -[HasSession]-> BOB -[MemberOf]-> DA");
        assert_eq!((p.hops[0].src.as_str(), p.hops[3].dst.as_str()), ("S-1-5-21-1-5", "S-1-5-21-1-4"));
    }

    #[test]
    fn rules_fire_on_worse_posture() {
        use ch_analysis::findings::Severity;
        let crit = sev_id(Severity::Critical);
        let low = sev_id(Severity::Low);
        let rules = AlertRules {
            enabled: true,
            new_tier0_principals_min: Some(2),
            choke_points_changed: true,
            choke_points_top: 2,
            ..Default::default()
        };
        let before = view("g-1", 'B', 3.0, &[(low, 0)], Some(vec![1, 2, 3]), Some(vec!["e1", "e2", "e9"]));
        let after = view("g-2", 'D', 9.5, &[(crit, 4), (low, 7)], Some(vec![1, 2, 3, 4, 5, 6]), Some(vec!["e1", "e3"]));
        let ev = evaluate(&rules, &before, &after);
        let fired: Vec<&str> = ev.triggers.iter().map(|t| t.rule.as_str()).collect();
        assert_eq!(fired, ["grade_worse", "exposure_increase", "new_findings", "new_tier0_principals", "choke_points_changed"]);
        // Only the critical one counts as a new finding (low is not selected).
        assert_eq!(ev.new_findings.len(), 1);
        assert_eq!(ev.new_findings[0]["id"], crit);
        assert_eq!(ev.new_tier0_principals, 3);
        // e9 is outside the top 2, so it is not "removed".
        assert_eq!(ev.choke_points_added, vec!["label e3".to_string()]);
        assert_eq!(ev.choke_points_removed, vec!["label e2".to_string()]);
    }

    #[test]
    fn rules_quiet_when_better_or_below_threshold() {
        let rules = AlertRules { enabled: true, choke_points_changed: true, ..Default::default() };
        let before = view("g-1", 'D', 20.0, &[], Some(vec![1, 2, 3]), Some(vec!["e1"]));
        let better = view("g-2", 'C', 10.0, &[], Some(vec![1, 2]), Some(vec!["e1"]));
        assert!(evaluate(&rules, &before, &better).triggers.is_empty());
        // +4.9 points is below the default 5-point threshold; 9 new principals < 10.
        let slight = view("g-3", 'D', 24.9, &[], Some((1..=12).collect()), Some(vec!["e1"]));
        assert!(evaluate(&rules, &before, &slight).triggers.is_empty());
        // Unknown exposed set / choke points (first comparison): those rules are skipped.
        let unknown = view("g-4", 'D', 20.0, &[], None, None);
        assert!(evaluate(&rules, &unknown, &slight).triggers.is_empty());
        // Disabled individual rules.
        let off = AlertRules { grade_worse: false, exposure_increase_points: None, new_finding_severities: vec![], new_tier0_principals_min: None, ..Default::default() };
        let worse = view("g-5", 'F', 90.0, &[], Some((1..=100).collect()), None);
        assert!(evaluate(&off, &before, &worse).triggers.is_empty());
    }

    #[test]
    fn history_newest_first_and_rotates() {
        let dir = std::env::temp_dir().join(format!("ch-alerts-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = AlertLog::new(dir.join("alerts.jsonl"));
        let mk = |i: usize| Alert {
            id: format!("a-{i}"),
            ts: now_rfc3339(),
            snapshot_id: "s".into(),
            previous_snapshot_id: "p".into(),
            grade_before: "A".into(),
            grade_after: "B".into(),
            exposure_before: 0.0,
            exposure_after: 1.0,
            triggers: vec![],
            new_findings: vec![],
            new_tier0_principals: 0,
            new_tier0_sample: vec![],
            choke_points_added: vec![],
            choke_points_removed: vec![],
            new_paths: vec![],
            deliveries: vec![],
        };
        for i in 0..5 {
            log.append(&mk(i));
        }
        let r = log.recent(3);
        assert_eq!(r.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(), ["a-4", "a-3", "a-2"]);
        std::fs::rename(dir.join("alerts.jsonl"), dir.join("alerts.1.jsonl")).unwrap();
        log.append(&mk(5));
        assert_eq!(log.recent(10).len(), 6);
        assert_eq!(log.recent(10)[0].id, "a-5");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
