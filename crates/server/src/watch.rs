//! Watched-folder auto-ingest and server settings.
//!
//! A background thread polls the watch directory (polling, not filesystem
//! events, so it works on Docker volumes and network shares). A collector
//! file (see `api::UPLOAD_EXTENSIONS`) is imported once its size and modification time have been
//! stable for `settle_seconds`, so half-copied collector output is never
//! read. Ready files are moved into the uploads directory and an ingest job
//! starts.
//!
//! * `replace` mode (default): each drop is a new collection; the previous
//!   uploads are moved to `<data>/archive/<stamp>/` (last `keep_archives`
//!   kept) or deleted.
//! * `merge` mode: files are added next to the existing uploads (same-named
//!   files are overwritten).

use crate::api::{queue_ingest, sanitize_upload_name, ApiError, St};
use crate::state::{load_json, now_rfc3339, store_json, AppState};
use ahash::AHashMap;
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

const POLL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WatchMode {
    Replace,
    Merge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WatchSettings {
    pub enabled: bool,
    /// Directory to watch; empty means `<data>/watch`.
    pub dir: String,
    pub mode: WatchMode,
    pub settle_seconds: u64,
    /// Archive replaced uploads instead of deleting them.
    pub archive: bool,
    pub keep_archives: usize,
}

impl Default for WatchSettings {
    fn default() -> Self {
        WatchSettings { enabled: false, dir: String::new(), mode: WatchMode::Replace, settle_seconds: 30, archive: true, keep_archives: 5 }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub watch: WatchSettings,
    pub analysis: AnalysisSettings,
    pub ingest: IngestSettings,
}

/// How uploads describing the same objects are combined (see
/// `ch_ingest::merge` and docs/ARCHITECTURE.md "Merge semantics").
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IngestSettings {
    /// `newest` (default): per object, the newest collection's record wins and
    /// superseded ACEs / members / sessions are dropped. `union`: plain union.
    pub merge_policy: ch_ingest::MergePolicy,
    /// `newest` only: also keep sessions from older collections up to this
    /// many hours older than a computer's newest session data (0 = newest only).
    pub session_window_hours: u64,
}

impl Default for IngestSettings {
    fn default() -> Self {
        IngestSettings { merge_policy: ch_ingest::MergePolicy::Newest, session_window_hours: 0 }
    }
}

impl IngestSettings {
    pub fn options(&self) -> ch_ingest::IngestOptions {
        ch_ingest::IngestOptions {
            merge_policy: self.merge_policy,
            session_window_secs: self.session_window_hours.saturating_mul(3600),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalysisSettings {
    /// Treat AD and Entra ID Tier Zero as one target set: attack paths may
    /// cross the hybrid boundary (see `ch_engine::EdgeFilter`). Applies to
    /// `/tier0` and `/path`.
    pub unified_tier0: bool,
}

impl Default for AnalysisSettings {
    fn default() -> Self {
        AnalysisSettings { unified_tier0: true }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct WatchStatus {
    pub last_scan: Option<String>,
    pub last_import: Option<String>,
    pub last_job: Option<String>,
    pub imported_files: u64,
    /// Files seen but not yet stable.
    pub pending: Vec<String>,
    pub last_error: Option<String>,
}

pub fn settings_path(st: &AppState) -> PathBuf {
    st.data_dir.join("settings.json")
}

pub fn load_settings(data_dir: &Path) -> Settings {
    let path = data_dir.join("settings.json");
    if path.exists() {
        return load_json(&path);
    }
    let mut s = Settings::default();
    if let Ok(d) = std::env::var("COPPERHOUND_WATCH_DIR") {
        if !d.is_empty() {
            s.watch.enabled = true;
            s.watch.dir = d;
        }
    }
    s
}

pub fn watch_dir(st: &AppState, w: &WatchSettings) -> PathBuf {
    if w.dir.trim().is_empty() {
        st.data_dir.join("watch")
    } else {
        PathBuf::from(w.dir.trim())
    }
}

/// Start the watcher thread (one per process).
pub fn spawn(st: &Arc<AppState>) {
    let st = Arc::downgrade(st);
    std::thread::Builder::new()
        .name("copperhound-watch".into())
        .spawn(move || {
            let mut seen: AHashMap<PathBuf, (u64, SystemTime, Instant)> = AHashMap::new();
            loop {
                std::thread::sleep(POLL);
                let Some(st) = st.upgrade() else { return };
                let w = st.settings.lock().watch.clone();
                if !w.enabled {
                    seen.clear();
                    continue;
                }
                if let Err(e) = tick(&st, &w, &mut seen) {
                    tracing::warn!("watch folder: {e:#}");
                    st.watch_status.lock().last_error = Some(format!("{e:#}"));
                }
            }
        })
        .expect("spawn watcher");
}

fn ingest_busy(st: &AppState) -> bool {
    st.jobs.lock().iter().any(|j| j.state == "queued" || j.state == "running")
}

fn tick(st: &Arc<AppState>, w: &WatchSettings, seen: &mut AHashMap<PathBuf, (u64, SystemTime, Instant)>) -> anyhow::Result<()> {
    let dir = watch_dir(st, w);
    std::fs::create_dir_all(&dir)?;
    let now = Instant::now();
    let settle = Duration::from_secs(w.settle_seconds.max(5));
    let mut present = Vec::new();
    for e in std::fs::read_dir(&dir)? {
        let e = e?;
        let p = e.path();
        let md = e.metadata()?;
        let name = e.file_name().to_string_lossy().into_owned();
        if !md.is_file() || sanitize_upload_name(&name).is_none() {
            continue;
        }
        let key = (md.len(), md.modified().unwrap_or(SystemTime::UNIX_EPOCH));
        match seen.get(&p) {
            Some(&(len, mt, _)) if (len, mt) == key => {}
            _ => {
                seen.insert(p.clone(), (key.0, key.1, now));
            }
        }
        present.push(p);
    }
    seen.retain(|p, _| present.contains(p));
    let (ready, pending): (Vec<PathBuf>, Vec<PathBuf>) =
        present.into_iter().partition(|p| seen.get(p).is_some_and(|&(_, _, since)| now.duration_since(since) >= settle));
    {
        let mut s = st.watch_status.lock();
        s.last_scan = Some(now_rfc3339());
        s.pending = pending.iter().chain(&ready).filter_map(|p| p.file_name()).map(|f| f.to_string_lossy().into_owned()).collect();
    }
    // Wait until every file in the drop has settled and no ingest is running.
    if ready.is_empty() || !pending.is_empty() || ingest_busy(st) {
        return Ok(());
    }
    let uploads = st.uploads_dir();
    if w.mode == WatchMode::Replace {
        retire_uploads(st, w)?;
    }
    std::fs::create_dir_all(&uploads)?;
    let mut n = 0u64;
    for p in &ready {
        let name = sanitize_upload_name(&p.file_name().unwrap_or_default().to_string_lossy()).expect("filtered");
        move_file(p, &uploads.join(&name))?;
        seen.remove(p);
        n += 1;
    }
    let job = queue_ingest(st, "watch").map_err(|_| anyhow::anyhow!("could not queue ingest"))?;
    tracing::info!("watch folder: imported {n} file(s) from {}, started {job}", dir.display());
    let mut s = st.watch_status.lock();
    s.last_import = Some(now_rfc3339());
    s.last_job = Some(job);
    s.imported_files += n;
    s.pending.clear();
    s.last_error = None;
    Ok(())
}

/// Move the current uploads aside (archive) or delete them.
fn retire_uploads(st: &AppState, w: &WatchSettings) -> anyhow::Result<()> {
    let uploads = st.uploads_dir();
    let files: Vec<PathBuf> = match std::fs::read_dir(&uploads) {
        Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.is_file()).collect(),
        Err(_) => return Ok(()),
    };
    if files.is_empty() {
        return Ok(());
    }
    if !w.archive {
        for f in files {
            std::fs::remove_file(f)?;
        }
        return Ok(());
    }
    let root = st.data_dir.join("archive");
    let stamp = humantime::format_rfc3339_seconds(SystemTime::now()).to_string().replace(':', "-");
    let dest = root.join(stamp);
    std::fs::create_dir_all(&dest)?;
    for f in files {
        move_file(&f, &dest.join(f.file_name().unwrap_or_default()))?;
    }
    let mut archives: Vec<PathBuf> = std::fs::read_dir(&root)?.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.is_dir()).collect();
    archives.sort();
    let keep = w.keep_archives.max(1);
    if archives.len() > keep {
        for old in &archives[..archives.len() - keep] {
            let _ = std::fs::remove_dir_all(old);
        }
    }
    Ok(())
}

/// Rename, falling back to copy + delete across filesystems.
fn move_file(from: &Path, to: &Path) -> std::io::Result<()> {
    if std::fs::rename(from, to).is_ok() {
        return Ok(());
    }
    std::fs::copy(from, to)?;
    std::fs::remove_file(from)
}

// ----------------------------------------------------------------- API

pub async fn get_settings(State(st): St) -> Json<Value> {
    let s = st.settings.lock().clone();
    let dir = watch_dir(&st, &s.watch);
    Json(json!({
        "settings": s,
        "watch_dir_resolved": dir,
        "watch_status": *st.watch_status.lock(),
    }))
}

pub async fn put_settings(State(st): St, Json(new): Json<Settings>) -> Result<Json<Value>, ApiError> {
    if !(5..=86_400).contains(&new.watch.settle_seconds) {
        return Err(ApiError::bad("watch.settle_seconds must be 5-86400"));
    }
    if !(1..=100).contains(&new.watch.keep_archives) {
        return Err(ApiError::bad("watch.keep_archives must be 1-100"));
    }
    if new.ingest.session_window_hours > 24 * 365 {
        return Err(ApiError::bad("ingest.session_window_hours must be 0-8760"));
    }
    let dir = watch_dir(&st, &new.watch);
    if new.watch.enabled {
        if dir.starts_with(st.uploads_dir()) || dir.starts_with(st.graphs_dir()) || dir == st.data_dir {
            return Err(ApiError::bad("the watch folder must not be the data, uploads or graphs directory"));
        }
        std::fs::create_dir_all(&dir)
            .map_err(|e| ApiError::bad(format!("cannot create watch folder {}: {e}", dir.display())))?;
    }
    store_json(&settings_path(&st), &new)?;
    let toggled = st.settings.lock().analysis.unified_tier0 != new.analysis.unified_tier0;
    *st.settings.lock() = new;
    if toggled {
        if let Some(l) = st.graph.write().as_mut() {
            l.tier0_cache = None;
        }
    }
    Ok(get_settings(State(st)).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn age(seen: &mut AHashMap<PathBuf, (u64, SystemTime, Instant)>) {
        for v in seen.values_mut() {
            v.2 = Instant::now() - Duration::from_secs(3600);
        }
    }

    #[test]
    fn upload_names_accept_raw_dumps() {
        for ok in ["a.json", "b.ZIP", "corp.ldif", "config.ldf", "corp.ldif.gz", "snap.dat"] {
            assert_eq!(sanitize_upload_name(ok).as_deref(), Some(ok), "{ok}");
        }
        assert_eq!(sanitize_upload_name("x/../corp dump.ldif").as_deref(), Some("corp_dump.ldif"));
        for bad in ["a.exe", ".ldif", "a.gz", "notes.txt"] {
            assert!(sanitize_upload_name(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn imports_settled_files_and_archives() {
        let data = std::env::temp_dir().join(format!("ch-watch-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data);
        std::env::set_var("COPPERHOUND_ADMIN_PASSWORD", "test-password");
        let (st, _) = AppState::new(data.clone(), None).unwrap();
        let w = WatchSettings { enabled: true, ..Default::default() };
        let dir = watch_dir(&st, &w);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(st.uploads_dir()).unwrap();
        std::fs::write(st.uploads_dir().join("old.json"), b"{}").unwrap();
        std::fs::write(dir.join("a.json"), b"{\"data\":[],\"meta\":{\"type\":\"users\",\"count\":0,\"version\":6}}").unwrap();
        std::fs::write(dir.join("ignored.txt"), b"x").unwrap();

        let mut seen = AHashMap::new();
        tick(&st, &w, &mut seen).unwrap();
        assert_eq!(st.watch_status.lock().pending, vec!["a.json".to_string()]);
        assert!(dir.join("a.json").exists(), "not imported before settling");

        age(&mut seen);
        tick(&st, &w, &mut seen).unwrap();
        assert!(!dir.join("a.json").exists());
        assert!(st.uploads_dir().join("a.json").exists());
        assert!(!st.uploads_dir().join("old.json").exists(), "replaced uploads are archived");
        let archived: Vec<_> = std::fs::read_dir(data.join("archive")).unwrap().collect();
        assert_eq!(archived.len(), 1);
        assert!(dir.join("ignored.txt").exists());
        let job = st.watch_status.lock().last_job.clone().unwrap();
        assert!(st.jobs.lock().iter().any(|j| j.id == job && j.trigger == "watch"));

        // A file still being written (changing size) is not imported.
        for _ in 0..200 {
            if !ingest_busy(&st) {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        std::fs::write(dir.join("b.json"), b"{").unwrap();
        tick(&st, &w, &mut seen).unwrap();
        age(&mut seen);
        std::fs::write(dir.join("b.json"), b"{\"data\":[]").unwrap();
        tick(&st, &w, &mut seen).unwrap();
        assert!(dir.join("b.json").exists());
        let _ = std::fs::remove_dir_all(&data);
    }
}
