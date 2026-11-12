//! Server state: the loaded graph (hot-swappable), operator marks, ingest jobs.

use crate::auth::Auth;
use ahash::AHashMap;
use anyhow::{Context, Result};
use parking_lot::{Mutex, RwLock};
use ch_engine::Tier0Report;
use ch_model::flags;
use ch_store::Graph;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

pub struct Loaded {
    pub graph: Graph,
    pub dir: PathBuf,
    /// Increments on every install; node ids are only valid within one generation.
    pub generation: u64,
    pub loaded_at: SystemTime,
    pub node_kinds: Vec<(String, u64)>,
    pub edge_kinds: Vec<(String, u64)>,
    pub tier0_cache: Option<(usize, Tier0Report, f64)>,
}

impl Loaded {
    /// Stable id of this snapshot (the graph directory name).
    pub fn snapshot_id(&self) -> String {
        self.dir.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default()
    }

    pub fn new(graph: Graph, dir: PathBuf, generation: u64) -> Loaded {
        // Raw kinds: built-ins below CUSTOM_KIND_BASE, custom (OpenGraph) above.
        let mut nk = vec![0u64; 256];
        for &k in graph.kinds() {
            nk[k as usize] += 1;
        }
        let mut ek = vec![0u64; graph.edge_kind_count()];
        for &k in graph.all_edge_kinds() {
            ek[k as usize] += 1;
        }
        let node_kinds = nk
            .iter()
            .enumerate()
            .filter(|(_, c)| **c > 0)
            .map(|(raw, &c)| (graph.raw_kind_name(raw as u8).to_string(), c))
            .collect();
        let mut edge_kinds: Vec<(String, u64)> = ek
            .into_iter()
            .enumerate()
            .filter(|(_, c)| *c > 0)
            .map(|(k, c)| (graph.edge_kind_name(k as u16).to_string(), c))
            .collect();
        edge_kinds.sort_by_key(|e| std::cmp::Reverse(e.1));
        Loaded { graph, dir, generation, loaded_at: SystemTime::now(), node_kinds, edge_kinds, tier0_cache: None }
    }
}

/// Operator marks, keyed by object id so they survive re-ingest.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Marks {
    #[serde(default)]
    pub owned: Vec<String>,
    #[serde(default)]
    pub tier0_add: Vec<String>,
    #[serde(default)]
    pub tier0_remove: Vec<String>,
}

impl Marks {
    pub fn load(path: &Path) -> Marks {
        std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
    pub fn apply(&self, g: &mut Graph) {
        for oid in &self.owned {
            if let Some(id) = g.lookup(oid) {
                g.set_flag(id, flags::OWNED, true);
            }
        }
        for oid in &self.tier0_add {
            if let Some(id) = g.lookup(oid) {
                g.set_flag(id, flags::TIER0, true);
            }
        }
        for oid in &self.tier0_remove {
            if let Some(id) = g.lookup(oid) {
                g.set_flag(id, flags::TIER0, false);
            }
        }
    }
    fn set(list: &mut Vec<String>, oid: &str, on: bool) {
        list.retain(|x| x != oid);
        if on {
            list.push(oid.to_string());
        }
    }
    pub fn mark(&mut self, oid: &str, owned: Option<bool>, tier0: Option<bool>, ingest_tier0: bool) {
        if let Some(o) = owned {
            Self::set(&mut self.owned, oid, o);
        }
        if let Some(t) = tier0 {
            // Store only deviations from what ingest decided.
            Self::set(&mut self.tier0_add, oid, t && !ingest_tier0);
            Self::set(&mut self.tier0_remove, oid, !t && ingest_tier0);
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Job {
    pub id: String,
    pub state: &'static str,
    pub phase: &'static str,
    pub percent: u8,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub message: String,
    pub report: Option<serde_json::Value>,
    /// What started the job: `manual`, `watch` or `api`.
    pub trigger: String,
}

pub struct AppState {
    pub data_dir: PathBuf,
    pub web_dir: Option<PathBuf>,
    pub auth: Auth,
    pub audit: crate::audit::Audit,
    /// OpenID Connect single sign-on (`<data>/sso.json` + env).
    pub sso: crate::sso::Sso,
    pub settings: Mutex<crate::watch::Settings>,
    pub watch_status: Mutex<crate::watch::WatchStatus>,
    pub graph: RwLock<Option<Loaded>>,
    pub marks: Mutex<Marks>,
    /// Tier Zero flags as ingest set them, before operator marks (by object id).
    pub ingest_tier0: RwLock<AHashMap<u32, bool>>,
    pub jobs: Mutex<Vec<Job>>,
    pub job_seq: Mutex<u64>,
    pub generation: AtomicU64,
    /// Running queries by client-supplied id, for cancellation.
    pub running: Mutex<AHashMap<String, ch_query::Cancel>>,
    pub saved: Mutex<Vec<SavedQuery>>,
    /// Background analysis (findings, posture) for the current generation.
    pub analysis: RwLock<Analysis>,
    pub zones: Mutex<Vec<ZoneDef>>,
    /// Zone members per (generation, zone id).
    pub zone_cache: Mutex<ZoneCache>,
    /// Notification channels, report schedules and alert rules.
    pub notify: crate::notify::NotifyState,
}

/// Zone members keyed by (graph generation, zone id).
pub type ZoneCache = AHashMap<(u64, String), Arc<Vec<u32>>>;

pub enum Analysis {
    Idle,
    Computing { generation: u64, progress: u8 },
    Ready(Arc<AnalysisResult>),
}

pub struct AnalysisResult {
    pub generation: u64,
    pub snapshot_id: String,
    pub computed_ms: f64,
    pub findings: Vec<ch_analysis::findings::FindingResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneDef {
    pub id: String,
    pub name: String,
    pub description: String,
    pub selector: String,
    pub color: String,
}

pub fn load_json<T: serde::de::DeserializeOwned + Default>(path: &Path) -> T {
    std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

pub fn store_json<T: Serialize + ?Sized>(path: &Path, v: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(v)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedQuery {
    pub id: String,
    pub name: String,
    pub category: String,
    pub description: String,
    pub query: String,
    pub created_at: String,
    pub updated_at: String,
}

pub fn load_saved(path: &Path) -> Vec<SavedQuery> {
    std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

pub fn store_saved(path: &Path, items: &[SavedQuery]) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(items)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn now_rfc3339() -> String {
    humantime::format_rfc3339_seconds(SystemTime::now()).to_string()
}

impl AppState {
    pub fn uploads_dir(&self) -> PathBuf {
        self.data_dir.join("uploads")
    }
    pub fn graphs_dir(&self) -> PathBuf {
        self.data_dir.join("graphs")
    }
    pub fn marks_path(&self) -> PathBuf {
        self.data_dir.join("marks.json")
    }
    pub fn saved_path(&self) -> PathBuf {
        self.data_dir.join("saved_queries.json")
    }
    pub fn zones_path(&self) -> PathBuf {
        self.data_dir.join("zones.json")
    }
    pub fn posture_path(&self) -> PathBuf {
        self.data_dir.join("posture.json")
    }
    pub fn snapshot_items_path(&self, snapshot_id: &str) -> PathBuf {
        self.data_dir.join("snapshots").join(format!("{snapshot_id}.json"))
    }

    pub fn new(data_dir: PathBuf, web_dir: Option<PathBuf>) -> Result<(Arc<AppState>, Option<String>)> {
        for d in [data_dir.clone(), data_dir.join("uploads"), data_dir.join("graphs")] {
            std::fs::create_dir_all(&d).with_context(|| format!("creating {}", d.display()))?;
        }
        // A restore staged by POST /restore applies before anything is loaded.
        crate::backup::apply_pending(&data_dir).context("applying the staged restore")?;
        crate::compat::remove_stale_spools(&data_dir);
        if let Ok(rd) = std::fs::read_dir(&data_dir) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if (n.starts_with(".backup-") || n.starts_with(".restore-")) && n.ends_with(".zip") {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        let (auth, generated) = Auth::init(&data_dir)?;
        let marks = Marks::load(&data_dir.join("marks.json"));
        let saved = load_saved(&data_dir.join("saved_queries.json"));
        let data_dir_zones = data_dir.join("zones.json");
        let audit = crate::audit::Audit::new(data_dir.join("audit.jsonl"));
        let settings = crate::watch::load_settings(&data_dir);
        let data_dir_notify = data_dir.clone();
        let sso = crate::sso::Sso::init(&data_dir)?;
        let st = Arc::new(AppState {
            data_dir,
            web_dir,
            auth,
            audit,
            sso,
            settings: Mutex::new(settings),
            watch_status: Mutex::new(Default::default()),
            graph: RwLock::new(None),
            marks: Mutex::new(marks),
            ingest_tier0: RwLock::new(AHashMap::new()),
            jobs: Mutex::new(Vec::new()),
            job_seq: Mutex::new(0),
            generation: AtomicU64::new(0),
            running: Mutex::new(AHashMap::new()),
            saved: Mutex::new(saved),
            analysis: RwLock::new(Analysis::Idle),
            zones: Mutex::new(load_json(&data_dir_zones)),
            zone_cache: Mutex::new(AHashMap::new()),
            notify: crate::notify::NotifyState::load(&data_dir_notify),
        });
        if let Some(dir) = latest_graph_dir(&st.graphs_dir()) {
            match Graph::open(&dir) {
                Ok(g) => {
                    st.install(g, dir);
                    warm_columns(&st);
                    crate::analysis::start_analysis(&st, true);
                }
                Err(e) => tracing::warn!("could not open {}: {e:#}", dir.display()),
            }
        }
        Ok((st, generated))
    }

    /// Apply marks and make `g` the active graph; older graph dirs are removed.
    pub fn install(&self, mut g: Graph, dir: PathBuf) {
        // Remember ingest's own Tier Zero decisions for nodes the operator touched.
        let marks = self.marks.lock().clone();
        let mut base = AHashMap::new();
        for oid in marks.tier0_add.iter().chain(&marks.tier0_remove) {
            if let Some(id) = g.lookup(oid) {
                base.insert(id, g.has_flag(id, flags::TIER0));
            }
        }
        marks.apply(&mut g);
        *self.ingest_tier0.write() = base;
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let old = self.graph.write().replace(Loaded::new(g, dir.clone(), generation));
        if let Some(old) = old {
            let old_dir = old.dir.clone();
            drop(old); // unmap before deleting
            if old_dir != dir {
                let _ = std::fs::remove_dir_all(&old_dir);
            }
        }
        tracing::info!("graph loaded from {}", dir.display());
    }
}

/// Load (or, for graphs written before property columns existed, build and
/// persist) the active graph's property columns in the background, so the
/// first search or filter does not pay for it.
pub fn warm_columns(st: &Arc<AppState>) {
    let st = st.clone();
    std::thread::spawn(move || {
        let guard = st.graph.read_recursive();
        let Some(l) = guard.as_ref() else { return };
        let t = std::time::Instant::now();
        let c = l.graph.columns();
        let o = &c.origin;
        tracing::info!(
            "property columns {} in {:.2}s ({} columns, {:.1} MB)",
            if o.loaded { "loaded" } else { "built" },
            t.elapsed().as_secs_f64(),
            c.info().len(),
            o.bytes as f64 / 1048576.0
        );
        if let Some(e) = &o.persist_error {
            tracing::warn!("property columns kept in memory only: {e}");
        }
    });
}

fn latest_graph_dir(graphs: &Path) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(graphs)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.join("meta.json").exists())
        .collect();
    dirs.sort();
    dirs.pop()
}
