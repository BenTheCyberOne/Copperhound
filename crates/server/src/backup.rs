//! Backup and restore of the server's state (admin).
//!
//! `GET /backup[?uploads=1&tls=1]` streams a zip with a `manifest.json` and
//! the configuration and history files: accounts, SSO / SAML, settings,
//! notifications and schedules, zones, saved queries, marks, accepted risks,
//! collectors, posture history and its snapshots, alert state and the audit
//! log; optionally the uploaded collector files and the TLS certificate and
//! key. Graphs are not included: they are rebuilt from the uploads.
//!
//! `POST /restore` (multipart field `backup`) checks the archive (manifest,
//! allow-listed names only, bounded sizes) and stages it in
//! `<data>/restore-pending/`. It is applied at the next start, before any
//! state is loaded; uploads in the backup replace the current uploads and a
//! rebuild is queued. The running server is not changed until then.

use crate::api::{sanitize_upload_name, ApiError, St};
use crate::auth::Principal;
use crate::state::now_rfc3339;
use axum::body::Body;
use axum::extract::{Multipart, Query, State};
use axum::http::header;
use axum::response::Response;
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const FORMAT: &str = "copperhound-backup";
const PENDING: &str = "restore-pending";
const INGEST_MARKER: &str = "restore-ingest";
/// Files restored to the data directory root.
const ROOT_FILES: &[&str] = &[
    "users.json",
    "sso.json",
    "saml.json",
    "settings.json",
    "notify.json",
    "alert_rules.json",
    "schedules.json",
    "zones.json",
    "zone_weights.json",
    "saved_queries.json",
    "marks.json",
    "accepted_risks.json",
    "collectors.json",
    "posture.json",
    "alert_state.json",
    "kind_styles.json",
    "ldap_collect.json",
    "zone_reviews.json",
    "ticket_targets.json",
    "tickets.json",
    "conduits.json",
    "audit.jsonl",
    "alerts.jsonl",
];
const TLS_FILES: &[&str] = &["tls/cert.pem", "tls/key.pem"];
/// Largest single non-upload file accepted in a backup.
const MAX_FILE: u64 = 512 << 20;

/// Is `name` a path a backup may contain?
pub fn allowed(name: &str) -> bool {
    if ROOT_FILES.contains(&name) || TLS_FILES.contains(&name) || name == "manifest.json" {
        return true;
    }
    if let Some(s) = name.strip_prefix("snapshots/") {
        return !s.contains('/') && s.ends_with(".json") && s.len() <= 200 && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) && !s.starts_with('.');
    }
    if let Some(u) = name.strip_prefix("uploads/") {
        return sanitize_upload_name(u).is_some_and(|c| c == u);
    }
    false
}

#[derive(Deserialize, Default)]
pub struct BackupQ {
    #[serde(default)]
    uploads: Option<u8>,
    #[serde(default)]
    tls: Option<u8>,
}

fn add_file(zip: &mut zip::ZipWriter<std::fs::File>, name: &str, path: &Path) -> anyhow::Result<bool> {
    let Ok(mut f) = std::fs::File::open(path) else { return Ok(false) };
    let opts = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated).large_file(true);
    zip.start_file(name, opts)?;
    std::io::copy(&mut f, zip)?;
    Ok(true)
}

/// Write a backup of `data` to `out`; returns the archived names.
pub fn write_backup(data: &Path, out: &Path, uploads: bool, tls: bool) -> anyhow::Result<Vec<String>> {
    let mut zip = zip::ZipWriter::new(std::fs::File::create(out)?);
    let mut names = Vec::new();
    for f in ROOT_FILES {
        if add_file(&mut zip, f, &data.join(f))? {
            names.push(f.to_string());
        }
    }
    let mut add_dir = |dir: &str, pred: &dyn Fn(&str) -> bool| -> anyhow::Result<()> {
        if let Ok(rd) = std::fs::read_dir(data.join(dir)) {
            let mut files: Vec<String> = rd.flatten().filter(|e| e.path().is_file()).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
            files.sort();
            for f in files {
                let name = format!("{dir}/{f}");
                if pred(&name) && add_file(&mut zip, &name, &data.join(dir).join(&f))? {
                    names.push(name);
                }
            }
        }
        Ok(())
    };
    add_dir("snapshots", &allowed)?;
    if uploads {
        add_dir("uploads", &allowed)?;
    }
    if tls {
        for f in TLS_FILES {
            if add_file(&mut zip, f, &data.join(f))? {
                names.push(f.to_string());
            }
        }
    }
    let manifest = json!({
        "format": FORMAT, "version": 1, "created_at": now_rfc3339(),
        "server_version": env!("CARGO_PKG_VERSION"), "files": names,
    });
    zip.start_file("manifest.json", zip::write::SimpleFileOptions::default())?;
    zip.write_all(serde_json::to_string_pretty(&manifest)?.as_bytes())?;
    zip.finish()?;
    Ok(names)
}

pub async fn backup(State(st): St, Query(q): Query<BackupQ>) -> Result<Response, ApiError> {
    let data = st.data_dir.clone();
    let tmp = data.join(format!(".backup-{}.zip", crate::auth::random_hex(8)));
    let (uploads, tls) = (q.uploads == Some(1), q.tls == Some(1));
    let tmp2 = tmp.clone();
    tokio::task::spawn_blocking(move || write_backup(&data, &tmp2, uploads, tls))
        .await
        .map_err(|e| ApiError::from(anyhow::anyhow!("task: {e}")))??;
    let file = tokio::fs::File::open(&tmp).await.map_err(|e| ApiError::from(anyhow::anyhow!(e)))?;
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    // Unlinking an open file works on Unix; on Windows it is removed at the next backup.
    let _ = std::fs::remove_file(&tmp);
    let stamp = now_rfc3339().replace([':', '-'], "");
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/zip")
        .header(header::CONTENT_LENGTH, len)
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"copperhound-backup-{}.zip\"", &stamp[..15.min(stamp.len())]))
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from_stream(tokio_util::io::ReaderStream::new(file)))
        .unwrap_or_else(|_| Response::new(Body::empty())))
}

/// Check `zip_path` and extract it into `dest` (emptied first).
pub fn stage(zip_path: &Path, dest: &Path) -> anyhow::Result<(Value, usize, bool)> {
    let mut z = zip::ZipArchive::new(std::fs::File::open(zip_path)?).map_err(|e| anyhow::anyhow!("not a zip file: {e}"))?;
    let manifest: Value = {
        let mut m = z.by_name("manifest.json").map_err(|_| anyhow::anyhow!("not a CopperHound backup (no manifest.json)"))?;
        let mut s = String::new();
        m.by_ref().take(1 << 20).read_to_string(&mut s)?;
        serde_json::from_str(&s)?
    };
    if manifest.get("format").and_then(Value::as_str) != Some(FORMAT) {
        anyhow::bail!("not a CopperHound backup");
    }
    for i in 0..z.len() {
        let f = z.by_index(i)?;
        let name = f.name().to_string();
        if f.is_dir() {
            continue;
        }
        if !allowed(&name) {
            anyhow::bail!("unexpected file in backup: {name:?}");
        }
        if !name.starts_with("uploads/") && f.size() > MAX_FILE {
            anyhow::bail!("{name} is too large");
        }
    }
    let _ = std::fs::remove_dir_all(dest);
    std::fs::create_dir_all(dest)?;
    let mut files = 0;
    let mut has_uploads = false;
    for i in 0..z.len() {
        let mut f = z.by_index(i)?;
        if f.is_dir() {
            continue;
        }
        let name = f.name().to_string();
        let out = dest.join(&name);
        if let Some(p) = out.parent() {
            std::fs::create_dir_all(p)?;
        }
        let mut w = std::fs::File::create(&out)?;
        std::io::copy(&mut f, &mut w)?;
        files += 1;
        has_uploads |= name.starts_with("uploads/");
    }
    Ok((manifest, files, has_uploads))
}

pub async fn restore(State(st): St, Extension(who): Extension<Principal>, mut mp: Multipart) -> Result<Json<Value>, ApiError> {
    use tokio::io::AsyncWriteExt;
    let tmp = st.data_dir.join(format!(".restore-{}.zip", crate::auth::random_hex(8)));
    let mut got = false;
    while let Some(mut field) = mp.next_field().await.map_err(|e| ApiError::bad(e.to_string()))? {
        if field.name() != Some("backup") {
            continue;
        }
        let mut f = tokio::fs::File::create(&tmp).await.map_err(|e| ApiError::from(anyhow::anyhow!(e)))?;
        while let Some(chunk) = field.chunk().await.map_err(|e| ApiError::bad(e.to_string()))? {
            f.write_all(&chunk).await.map_err(|e| ApiError::from(anyhow::anyhow!(e)))?;
        }
        f.flush().await.map_err(|e| ApiError::from(anyhow::anyhow!(e)))?;
        got = true;
        break;
    }
    if !got {
        return Err(ApiError::bad("no backup file (multipart field 'backup')"));
    }
    let (data, tmp2) = (st.data_dir.clone(), tmp.clone());
    let res = tokio::task::spawn_blocking(move || stage(&tmp2, &data.join(PENDING))).await;
    let _ = std::fs::remove_file(&tmp);
    let (manifest, files, uploads) = res.map_err(|e| ApiError::from(anyhow::anyhow!("task: {e}")))?.map_err(|e| ApiError::bad(format!("{e:#}")))?;
    st.audit.record(crate::audit::AuditEntry {
        ts: now_rfc3339(),
        user: who.username,
        role: who.role.as_str().into(),
        action: "restore-staged".into(),
        method: "POST".into(),
        path: "/api/v1/restore".into(),
        status: 200,
        ip: None,
        detail: Some(format!("{files} files from a backup of {}", manifest.get("created_at").and_then(Value::as_str).unwrap_or("?"))),
    });
    Ok(Json(json!({
        "staged_files": files,
        "includes_uploads": uploads,
        "backup_created_at": manifest.get("created_at"),
        "restart_required": true,
        "note": "restart CopperHound to apply the restore",
    })))
}

/// Apply a staged restore (called at start-up, before state is loaded).
/// Returns whether a graph rebuild should be queued.
pub fn apply_pending(data: &Path) -> anyhow::Result<bool> {
    let pending = data.join(PENDING);
    if !pending.join("manifest.json").exists() {
        return Ok(false);
    }
    let walk = |dir: &Path| -> Vec<PathBuf> {
        std::fs::read_dir(dir).map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect()).unwrap_or_default()
    };
    let has_uploads = pending.join("uploads").is_dir();
    if has_uploads {
        for f in walk(&data.join("uploads")) {
            let _ = std::fs::remove_file(f);
        }
    }
    let mut moved = 0;
    for sub in ["", "snapshots", "uploads", "tls"] {
        let from = if sub.is_empty() { pending.clone() } else { pending.join(sub) };
        let to = if sub.is_empty() { data.to_path_buf() } else { data.join(sub) };
        let files = walk(&from);
        if files.is_empty() {
            continue;
        }
        std::fs::create_dir_all(&to)?;
        for f in files {
            let name = f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if sub.is_empty() && name == "manifest.json" {
                continue;
            }
            let rel = if sub.is_empty() { name.clone() } else { format!("{sub}/{name}") };
            if !allowed(&rel) {
                continue;
            }
            std::fs::rename(&f, to.join(&name)).or_else(|_| std::fs::copy(&f, to.join(&name)).map(|_| ()))?;
            moved += 1;
        }
    }
    std::fs::remove_dir_all(&pending)?;
    tracing::info!("restored {moved} files from a backup");
    if has_uploads {
        std::fs::write(data.join(INGEST_MARKER), b"1")?;
    }
    Ok(has_uploads)
}

/// Consume the rebuild marker left by [`apply_pending`].
pub fn take_ingest_marker(data: &Path) -> bool {
    std::fs::remove_file(data.join(INGEST_MARKER)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in ["users.json", "snapshots/g-1.json", "uploads/a.zip", "tls/key.pem", "manifest.json"] {
            assert!(allowed(ok), "{ok}");
        }
        for bad in ["../users.json", "graphs/g/meta.json", "uploads/../x.zip", "snapshots/a/b.json", "admin_password", "uploads/x.exe", "/etc/passwd"] {
            assert!(!allowed(bad), "{bad}");
        }
    }

    #[test]
    fn round_trip() {
        let base = std::env::temp_dir().join(format!("ch-backup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (a, b) = (base.join("a"), base.join("b"));
        for d in [&a, &b] {
            std::fs::create_dir_all(d.join("uploads")).unwrap();
            std::fs::create_dir_all(d.join("snapshots")).unwrap();
        }
        std::fs::write(a.join("users.json"), "[1]").unwrap();
        std::fs::write(a.join("zones.json"), "[2]").unwrap();
        std::fs::write(a.join("admin_password"), "secret").unwrap();
        std::fs::write(a.join("snapshots/g-1.json"), "{}").unwrap();
        std::fs::write(a.join("uploads/x.zip"), "zip").unwrap();
        std::fs::write(b.join("uploads/old.json"), "old").unwrap();
        std::fs::write(b.join("users.json"), "[old]").unwrap();
        let z = base.join("b.zip");
        let names = write_backup(&a, &z, true, false).unwrap();
        assert!(names.contains(&"uploads/x.zip".to_string()) && !names.iter().any(|n| n.contains("admin_password")));
        let (_, files, uploads) = stage(&z, &b.join(PENDING)).unwrap();
        assert!(uploads && files >= 4);
        assert_eq!(std::fs::read_to_string(b.join("users.json")).unwrap(), "[old]", "nothing applied before restart");
        assert!(apply_pending(&b).unwrap());
        assert_eq!(std::fs::read_to_string(b.join("users.json")).unwrap(), "[1]");
        assert_eq!(std::fs::read_to_string(b.join("snapshots/g-1.json")).unwrap(), "{}");
        assert!(b.join("uploads/x.zip").exists() && !b.join("uploads/old.json").exists(), "uploads replaced");
        assert!(take_ingest_marker(&b) && !take_ingest_marker(&b));
        assert!(!b.join(PENDING).exists());
        // A zip with a foreign file is refused.
        let evil = base.join("evil.zip");
        let mut w = zip::ZipWriter::new(std::fs::File::create(&evil).unwrap());
        w.start_file("manifest.json", zip::write::SimpleFileOptions::default()).unwrap();
        w.write_all(json!({"format": FORMAT}).to_string().as_bytes()).unwrap();
        w.start_file("../escape.json", zip::write::SimpleFileOptions::default()).unwrap();
        w.finish().unwrap();
        assert!(stage(&evil, &b.join(PENDING)).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }
}
