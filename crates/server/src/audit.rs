//! Append-only audit trail (`<data>/audit.jsonl`, one JSON object per line).
//!
//! Every state-changing or analysis request is recorded with the caller,
//! role, method, path, status and client address, plus login successes and
//! failures. The file rotates to `audit.1.jsonl` past [`ROTATE_BYTES`].

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

const ROTATE_BYTES: u64 = 64 << 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: String,
    pub user: String,
    #[serde(default)]
    pub role: String,
    pub action: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

pub struct Audit {
    path: PathBuf,
    file: Mutex<Option<File>>,
}

impl Audit {
    pub fn new(path: PathBuf) -> Audit {
        Audit { path, file: Mutex::new(None) }
    }

    pub fn record(&self, e: AuditEntry) {
        if self.path.as_os_str().is_empty() {
            return;
        }
        let Ok(mut line) = serde_json::to_vec(&e) else { return };
        line.push(b'\n');
        let mut f = self.file.lock();
        if f.as_ref().and_then(|f| f.metadata().ok()).is_some_and(|m| m.len() > ROTATE_BYTES) {
            *f = None;
            let _ = std::fs::rename(&self.path, self.path.with_extension("1.jsonl"));
        }
        if f.is_none() {
            *f = OpenOptions::new().create(true).append(true).open(&self.path).ok();
        }
        if let Some(file) = f.as_mut() {
            if file.write_all(&line).is_err() {
                *f = None;
            }
        }
    }

    /// Most recent entries first, optionally filtered by user or action prefix.
    pub fn recent(&self, limit: usize, user: Option<&str>, action: Option<&str>) -> Vec<AuditEntry> {
        let mut out: Vec<AuditEntry> = Vec::new();
        for p in [self.path.with_extension("1.jsonl"), self.path.clone()] {
            let Ok(f) = File::open(&p) else { continue };
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                let Ok(e) = serde_json::from_str::<AuditEntry>(&line) else { continue };
                if user.is_some_and(|u| e.user != u) || action.is_some_and(|a| !e.action.starts_with(a)) {
                    continue;
                }
                out.push(e);
            }
        }
        out.reverse();
        out.truncate(limit);
        out
    }
}
