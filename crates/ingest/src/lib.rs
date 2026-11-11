//! CopperHound ingest.
//!
//! Pipeline:
//! 1. Expand inputs (files, directories, `.zip` archives; zips are extracted to
//!    a temp directory in parallel). Every file (and zip entry) is a *source*
//!    with a collection time ([`SourceInfo`]).
//! 2. Memory-map each JSON file and split it into record byte ranges with a
//!    structural scanner ([`scan`]) — no full parse, no per-file memory blow-up.
//! 3. Deserialise record batches in parallel across all cores; even a single
//!    50 GB `computers.json` is parsed by every core.
//! 4. Intern object identifiers to dense `u32` ids, merge node attributes and
//!    drop superseded edges collection-aware ([`merge`]), resolve DN
//!    references, tag Tier Zero, renumber nodes by object id
//!    ([`merge::canonical_numbering`], so the graph is identical for any
//!    thread count, batch size or input order), and hand the result to
//!    [`ch_store::Graph::build`]. Composite edges that need the built graph
//!    (DCSync, ADCS, Azure roles, hybrid links) are derived by [`postprocess`]
//!    passes in [`build_graph`].
//!
//! Supported formats: SharpHound / bloodhound-python (`{"data":[..],"meta":{..}}`,
//! v4–v6), ldapdomaindump JSON (`[{"attributes":{..},"dn":..}]`), AzureHound,
//! and raw directory dumps — LDIF (plain or `.gz`) and AD Explorer snapshots —
//! via [`ldap`].

pub mod de;
pub mod emit;
pub mod ldap;
pub mod ldapdomaindump;
pub mod merge;
pub mod opengraph;
pub mod pipeline;
pub mod postprocess;
pub mod scan;
pub mod sharphound;
pub mod azurehound;

pub use merge::SourceInfo;
pub use pipeline::{build_graph, build_graph_with_progress, Built, PostReport};

use anyhow::{bail, Context, Result};
use emit::{Emitted, Emitter, Shared};
use memmap2::Mmap;
use parking_lot::Mutex;
use ch_model::NodeKind;
use ch_store::GraphParts;
use rayon::prelude::*;
use scan::Layout;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// How records of the same object from several sources are combined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MergePolicy {
    /// Collection-aware: the newest collection's record defines an object
    /// and the edges it owns (see [`merge`]).
    #[default]
    Newest,
    /// Plain union of all records (flags OR'd, last record's properties,
    /// every edge kept).
    Union,
}

impl MergePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            MergePolicy::Newest => "newest",
            MergePolicy::Union => "union",
        }
    }
}

#[derive(Debug, Clone)]
pub struct IngestOptions {
    /// Where zip archives are extracted. Defaults to the system temp dir.
    pub temp_dir: Option<PathBuf>,
    /// Target bytes of JSON per parallel parse task.
    pub batch_bytes: usize,
    /// Keep raw collector properties (needed for property queries and the UI;
    /// costs roughly the size of the `Properties` objects in the input).
    pub keep_props: bool,
    pub merge_policy: MergePolicy,
    /// `newest` policy: keep session edges of older collections whose time is
    /// within this many seconds of the newest session collection of the same
    /// computer. 0 (default): sessions of the newest collection only.
    pub session_window_secs: u64,
}

impl Default for IngestOptions {
    fn default() -> Self {
        Self {
            temp_dir: None,
            batch_bytes: 4 << 20,
            keep_props: true,
            merge_policy: MergePolicy::Newest,
            session_window_secs: 0,
        }
    }
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}
fn is_zero_usize(v: &usize) -> bool {
    *v == 0
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct IngestReport {
    pub files: usize,
    pub zip_entries: usize,
    pub bytes: u64,
    pub records: u64,
    pub parse_errors: u64,
    pub first_error: Option<String>,
    pub nodes: usize,
    pub raw_edges: u64,
    pub dn_edges_resolved: u64,
    pub dn_edges_unresolved: u64,
    /// OpenGraph edges with an end matched by name (`match_by: "name"`):
    /// resolved, and dropped because no node or several nodes matched.
    #[serde(skip_serializing_if = "is_zero")]
    pub name_edges_resolved: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub name_edges_unresolved: u64,
    /// Custom (OpenGraph) node kinds registered.
    #[serde(skip_serializing_if = "is_zero_usize")]
    pub custom_node_kinds: usize,
    /// DCSync edges derived by the `repl` post-processing pass (set by
    /// [`build_graph`]; zero after [`ingest`] alone).
    pub dcsync_edges: u64,
    pub tier0_nodes: u64,
    pub extract_secs: f64,
    /// Structural scan (part of `parse_secs`).
    pub scan_secs: f64,
    pub parse_secs: f64,
    pub merge_secs: f64,
    /// Canonical renumbering of nodes and edge kinds (part of `merge_secs`).
    pub renumber_secs: f64,
    /// `newest` or `union`.
    pub merge_policy: &'static str,
    /// Object records overridden by a newer collection's record.
    pub superseded_objects: u64,
    /// Edge records dropped as superseded by a newer record of their owner
    /// (including ones the newer record states again).
    pub superseded_edges: u64,
    /// One entry per input file / zip entry.
    pub sources: Vec<SourceInfo>,
}

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// An input file and its name relative to the ingested directory.
struct InFile {
    path: PathBuf,
    rel: String,
}

/// `others`: files that are neither `.json` nor `.zip`, sniffed later for
/// LDIF / gzip / AD Explorer content.
fn collect_inputs(p: &Path, root: &Path, jsons: &mut Vec<InFile>, zips: &mut Vec<InFile>, others: &mut Vec<InFile>) -> Result<()> {
    let md = fs::metadata(p).with_context(|| format!("reading {}", p.display()))?;
    if md.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(p)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        entries.sort();
        for e in entries {
            collect_inputs(&e, root, jsons, zips, others)?;
        }
    } else {
        let rel = p
            .strip_prefix(root)
            .ok()
            .filter(|r| !r.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(p.file_name().unwrap_or(p.as_os_str())))
            .to_string_lossy()
            .replace('\\', "/");
        let f = InFile { path: p.to_path_buf(), rel };
        match p
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref()
        {
            Some("json") => jsons.push(f),
            Some("zip") => zips.push(f),
            _ => others.push(f),
        }
    }
    Ok(())
}

/// Zip entries worth extracting: collector JSON and raw directory dumps.
fn wanted_zip_entry(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [".json", ".ldif", ".ldf", ".gz", ".dat"].iter().any(|x| l.ends_with(x))
}

fn mtime(p: &Path) -> Option<String> {
    let t = fs::metadata(p).ok()?.modified().ok()?;
    let secs = t.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64;
    Some(merge::rfc3339(secs))
}

/// Extract wanted entries; each becomes a source. Returns `(path, source)`.
fn extract_zips(zips: &[InFile], tmp: &Path, sources: &mut Vec<SourceInfo>) -> Result<Vec<(PathBuf, u32)>> {
    let mut jobs = Vec::new();
    for (zi, z) in zips.iter().enumerate() {
        let mut a = zip::ZipArchive::new(BufReader::new(File::open(&z.path)?))
            .with_context(|| format!("opening zip {}", z.path.display()))?;
        let zip_mtime = mtime(&z.path);
        for i in 0..a.len() {
            let e = a.by_index_raw(i)?;
            if !e.is_dir() && wanted_zip_entry(e.name()) {
                // Keep only the base name (prevents zip-slip; keeps the kind suffix).
                let base = Path::new(e.name())
                    .file_name()
                    .map(|b| b.to_string_lossy().into_owned());
                if let Some(base) = base {
                    let mut s = SourceInfo::new(z.rel.clone(), Some(e.name().to_string()), "json");
                    s.t_zip = e.last_modified().and_then(|d| {
                        merge::filename_time(&format!(
                            "{:04}{:02}{:02}{:02}{:02}{:02}_",
                            d.year(),
                            d.month(),
                            d.day(),
                            d.hour(),
                            d.minute(),
                            d.second()
                        ))
                    });
                    // SharpHound names entries `<stamp>_users.json`; also accept
                    // a stamped archive name for every entry.
                    if s.t_name.is_none() {
                        let zb = z.rel.rsplit('/').next().unwrap_or(&z.rel);
                        s.t_name = merge::filename_time(zb);
                    }
                    s.file_mtime = zip_mtime.clone();
                    s.path = z.path.to_string_lossy().into_owned();
                    s.id = sources.len() as u32;
                    sources.push(s);
                    jobs.push((zi, i, base, sources.len() as u32 - 1));
                }
            }
        }
    }
    jobs.par_iter()
        .map(|(zi, i, base, src)| -> Result<(PathBuf, u32)> {
            let z = &zips[*zi].path;
            let mut a = zip::ZipArchive::new(BufReader::new(File::open(z)?))?;
            let mut e = a.by_index(*i).with_context(|| {
                format!(
                    "reading {} from {} (encrypted zips are not supported)",
                    base,
                    z.display()
                )
            })?;
            let out = tmp.join(format!("{zi}_{i}_{base}"));
            let mut w = BufWriter::with_capacity(1 << 20, File::create(&out)?);
            std::io::copy(&mut e, &mut w)?;
            w.flush()?;
            Ok((out, *src))
        })
        .collect()
}

fn peek_layout(buf: &[u8]) -> Option<Layout> {
    let start = if buf.starts_with(&[0xEF, 0xBB, 0xBF]) {
        3
    } else {
        0
    };
    buf[start..]
        .iter()
        .find(|c| !c.is_ascii_whitespace())
        .and_then(|c| match c {
            b'{' => Some(Layout::Wrapped),
            b'[' => Some(Layout::Array),
            _ => None,
        })
}

/// Collector format of one input file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    SharpHound,
    LdapDomainDump,
    AzureHound,
    /// BloodHound CE OpenGraph (`{"graph": {"nodes", "edges"}}`), parsed whole.
    OpenGraph,
}

impl Format {
    fn name(self) -> &'static str {
        match self {
            Format::SharpHound => "sharphound",
            Format::LdapDomainDump => "ldapdomaindump",
            Format::AzureHound => "azurehound",
            Format::OpenGraph => "opengraph",
        }
    }
}

fn parse_batch(
    buf: &[u8],
    ranges: &[(usize, usize)],
    format: Format,
    file_kind: Option<NodeKind>,
    sh: &Shared,
    file: &str,
    source: u32,
) -> Emitted {
    let mut em = Emitter::new(sh, file_kind);
    em.out.source = source;
    for &(s, e) in ranges {
        let bytes = &buf[s..e];
        em.begin();
        let res = match format {
            Format::SharpHound => serde_json::from_slice::<sharphound::Record>(bytes)
                .map(|r| sharphound::extract(r, &mut em)),
            Format::LdapDomainDump => serde_json::from_slice::<ldapdomaindump::Record>(bytes)
                .map(|r| ldapdomaindump::extract(r, file_kind, &mut em)),
            Format::AzureHound => serde_json::from_slice::<azurehound::Record>(bytes)
                .map(|r| azurehound::extract(r, &mut em)),
            Format::OpenGraph => serde_json::from_slice::<opengraph::File>(bytes).map(|f| opengraph::extract(f, &mut em)),
        };
        if let Err(err) = res {
            em.error(|| format!("{file} @ byte {s}: {err}"));
        }
    }
    em.out.records = ranges.len() as u64;
    em.finish()
}

/// A memory-mapped input file split into record ranges.
struct ScannedFile {
    display: String,
    map: Mmap,
    format: Format,
    kind: Option<NodeKind>,
    ranges: Vec<(usize, usize)>,
    source: u32,
    meta_type: Option<String>,
    meta_time: Option<i64>,
}

/// AzureHound records start with a `"kind"` key (`{"kind":"AZUser","data":…}`).
fn looks_like_azurehound(record: &[u8]) -> bool {
    let head = &record[..record.len().min(64)];
    let s = String::from_utf8_lossy(head);
    let t = s.trim_start_matches(['{', ' ', '\n', '\r', '\t']);
    t.starts_with("\"kind\"")
}

fn scan_file(path: &Path, source: u32) -> Result<Option<ScannedFile>> {
    let f = File::open(path)?;
    if f.metadata()?.len() == 0 {
        return Ok(None);
    }
    // SAFETY: input files are only read; modifying them during ingest is unsupported.
    let map = unsafe { Mmap::map(&f)? };
    let display = path.display().to_string();
    let Some(layout) = peek_layout(&map) else {
        bail!("not a JSON object or array")
    };
    if layout == Layout::Wrapped && opengraph::is_opengraph(&map) {
        let len = map.len();
        return Ok(Some(ScannedFile {
            display,
            map,
            format: Format::OpenGraph,
            kind: None,
            ranges: vec![(0, len)],
            source,
            meta_type: None,
            meta_time: None,
        }));
    }
    let summary = scan::scan_records(&map)?;
    let meta_time = summary.meta.and_then(merge::meta_time);
    let meta_type = summary
        .meta
        .and_then(|m| serde_json::from_slice::<sharphound::Meta>(m).ok())
        .and_then(|m| m.ty);
    let ranges = summary.ranges;
    let format = match layout {
        Layout::Array => Format::LdapDomainDump,
        Layout::Wrapped
            if meta_type.as_deref().is_some_and(|t| t.eq_ignore_ascii_case("azure"))
                || ranges.first().is_some_and(|&(s, e)| looks_like_azurehound(&map[s..e])) =>
        {
            Format::AzureHound
        }
        Layout::Wrapped => Format::SharpHound,
    };
    // Kind from the file name, else from `meta.type` (v6 writes meta after data).
    // AzureHound files mix kinds; each record carries its own.
    let kind = if format == Format::AzureHound {
        None
    } else {
        NodeKind::from_file_name(&display).or_else(|| {
            meta_type
                .as_deref()
                .map(NodeKind::parse)
                .filter(|k| *k != NodeKind::Unknown)
        })
    };
    Ok(Some(ScannedFile {
        display,
        map,
        format,
        kind,
        ranges,
        source,
        meta_type,
        meta_time,
    }))
}

/// Phase 1: scan all files in parallel. Phase 2: parse every batch of every
/// file in one flat parallel loop, so one huge file still uses every core.
fn parse_files(
    paths: &[(PathBuf, u32)],
    sh: &Shared,
    batch_bytes: usize,
    file_errors: &Mutex<Vec<String>>,
    report: &mut IngestReport,
    sources: &mut [SourceInfo],
    progress: Progress,
) -> Vec<Emitted> {
    progress("scanning", 10);
    let t = Instant::now();
    let files: Vec<ScannedFile> = paths
        .par_iter()
        .filter_map(|(p, src)| match scan_file(p, *src) {
            Ok(f) => f,
            Err(e) => {
                file_errors.lock().push(format!("{}: {e:#}", p.display()));
                None
            }
        })
        .collect();
    report.scan_secs = t.elapsed().as_secs_f64();
    for f in &files {
        let s = &mut sources[f.source as usize];
        s.format = f.format.name();
        s.t_meta = f.meta_time;
        s.kind = f.meta_type.clone().filter(|t| !t.eq_ignore_ascii_case("azure")).or_else(|| f.kind.map(|k| k.as_str().to_string()));
    }

    let mut batches: Vec<(&ScannedFile, &[(usize, usize)])> = Vec::new();
    for f in &files {
        let mut start = 0;
        let mut acc = 0;
        for (i, (s, e)) in f.ranges.iter().enumerate() {
            acc += e - s;
            if acc >= batch_bytes {
                batches.push((f, &f.ranges[start..=i]));
                start = i + 1;
                acc = 0;
            }
        }
        if start < f.ranges.len() {
            batches.push((f, &f.ranges[start..]));
        }
    }

    progress("parsing", 15);
    let done = std::sync::atomic::AtomicUsize::new(0);
    let total = batches.len().max(1);
    batches
        .par_iter()
        .map(|(f, r)| {
            let out = parse_batch(&f.map, r, f.format, f.kind, sh, &f.display, f.source);
            let d = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if d * 20 / total != (d - 1) * 20 / total {
                progress("parsing", (15 + 35 * d / total) as u8);
            }
            out
        })
        .collect()
}

/// Progress callback: `(phase, percent)`.
pub type Progress<'a> = &'a (dyn Fn(&'static str, u8) + Sync);

/// Ingest collector output into graph parts ready for [`ch_store::Graph::build`].
pub fn ingest(inputs: &[PathBuf], opts: &IngestOptions) -> Result<(GraphParts, IngestReport)> {
    ingest_with_progress(inputs, opts, &|_, _| {})
}

/// [`ingest`] reporting phases `extracting`, `scanning`, `parsing`, `merging`
/// with approximate percentages (0–60).
pub fn ingest_with_progress(inputs: &[PathBuf], opts: &IngestOptions, progress: Progress) -> Result<(GraphParts, IngestReport)> {
    let mut report = IngestReport { merge_policy: opts.merge_policy.as_str(), ..Default::default() };
    let mut jsons = Vec::new();
    let mut zips = Vec::new();
    let mut others = Vec::new();
    for p in inputs {
        let root = if p.is_dir() { p.as_path() } else { p.parent().unwrap_or(Path::new("")) };
        collect_inputs(p, root, &mut jsons, &mut zips, &mut others)?;
    }
    // Non-JSON files: keep only recognised raw directory dumps.
    let mut raw: Vec<(InFile, scan::InputKind)> =
        others.into_iter().filter_map(|f| scan::detect(&f.path).map(|k| (f, k))).collect();
    raw.retain(|(f, k)| match k {
        scan::InputKind::Json => {
            jsons.push(InFile { path: f.path.clone(), rel: f.rel.clone() });
            false
        }
        scan::InputKind::Zip => {
            zips.push(InFile { path: f.path.clone(), rel: f.rel.clone() });
            false
        }
        _ => true,
    });

    // Sources: plain JSON and raw dumps here, zip entries when extracted.
    let mut sources: Vec<SourceInfo> = Vec::new();
    let add_source = |sources: &mut Vec<SourceInfo>, f: &InFile, format: &'static str| -> u32 {
        let mut s = SourceInfo::new(f.rel.clone(), None, format);
        s.file_mtime = mtime(&f.path);
        s.path = f.path.to_string_lossy().into_owned();
        s.id = sources.len() as u32;
        sources.push(s);
        sources.len() as u32 - 1
    };
    let mut json_files: Vec<(PathBuf, u32)> =
        jsons.iter().map(|f| (f.path.clone(), add_source(&mut sources, f, "json"))).collect();
    let mut raw_files: Vec<(PathBuf, scan::InputKind, u32)> = raw
        .iter()
        .map(|(f, k)| {
            let fmt = if *k == scan::InputKind::AdExplorer { "adexplorer" } else { "ldif" };
            (f.path.clone(), *k, add_source(&mut sources, f, fmt))
        })
        .collect();

    progress("extracting", 2);
    let t = Instant::now();
    let needs_tmp = !zips.is_empty() || raw_files.iter().any(|(_, k, _)| *k == scan::InputKind::Gzip);
    let _tmp = if !needs_tmp {
        None
    } else {
        let base = opts.temp_dir.clone().unwrap_or_else(std::env::temp_dir);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = base.join(format!("copperhound-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let tmp = TempDir(dir);
        let extracted = extract_zips(&zips, &tmp.0, &mut sources)?;
        report.zip_entries = extracted.len();
        for (p, src) in extracted {
            match scan::detect(&p) {
                Some(scan::InputKind::Json) => json_files.push((p, src)),
                Some(k @ (scan::InputKind::Ldif | scan::InputKind::Gzip | scan::InputKind::AdExplorer)) => {
                    sources[src as usize].format = if k == scan::InputKind::AdExplorer { "adexplorer" } else { "ldif" };
                    raw_files.push((p, k, src))
                }
                _ => {}
            }
        }
        Some(tmp)
    };
    // Number sources canonically (not by argument / discovery order) so the
    // merge sees records in the same order whatever order inputs came in.
    let remap = merge::canonical_source_order(&mut sources);
    for f in json_files.iter_mut() {
        f.1 = remap[f.1 as usize];
    }
    for f in raw_files.iter_mut() {
        f.2 = remap[f.2 as usize];
    }
    raw_files.sort_by_key(|f| f.2);
    // Open raw dumps (gzip LDIF is decompressed into the temp dir).
    let ldap_errors: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let tmp_path = _tmp.as_ref().map(|t| t.0.clone()).unwrap_or_else(std::env::temp_dir);
    let ldap_inputs: Vec<ldap::Input> = raw_files
        .par_iter()
        .filter_map(|(p, k, src)| match ldap::open(p, *k, &tmp_path) {
            Ok(i) => i.map(|mut i| {
                i.source = *src;
                i
            }),
            Err(e) => {
                ldap_errors.lock().push(format!("{}: {e:#}", p.display()));
                None
            }
        })
        .collect();
    for i in &ldap_inputs {
        sources[i.source as usize].t_snapshot = i.header_time();
    }
    report.extract_secs = t.elapsed().as_secs_f64();
    if json_files.is_empty() && ldap_inputs.is_empty() {
        bail!("no collector files (.json, .zip, LDIF or AD Explorer snapshot) found in the given inputs");
    }

    // Largest files first so the long tail doesn't serialise the run.
    let mut sized: Vec<(u64, PathBuf, u32)> = json_files
        .into_iter()
        .map(|(p, s)| (fs::metadata(&p).map(|m| m.len()).unwrap_or(0), p, s))
        .collect();
    sized.sort_by_key(|s| std::cmp::Reverse(s.0));
    report.files = sized.len() + ldap_inputs.len();
    report.bytes = sized.iter().map(|s| s.0).sum::<u64>() + ldap_inputs.iter().map(|i| i.len()).sum::<u64>();

    let t = Instant::now();
    let mut shared = Shared::new(opts.keep_props);
    shared.track = opts.merge_policy == MergePolicy::Newest;
    let file_errors: Mutex<Vec<String>> = Mutex::new(ldap_errors.into_inner());
    let paths: Vec<(PathBuf, u32)> = sized.into_iter().map(|(_, p, s)| (p, s)).collect();
    let mut outputs = if paths.is_empty() {
        Vec::new()
    } else {
        parse_files(&paths, &shared, opts.batch_bytes, &file_errors, &mut report, &mut sources, progress)
    };
    let mut ldap_stats = ldap::Stats::default();
    if !ldap_inputs.is_empty() {
        let (o, s) = ldap::ingest(&ldap_inputs, &shared, progress);
        outputs.extend(o);
        report.scan_secs += s.index_secs;
        ldap_stats = s;
    }
    progress("merging", 52);
    drop(ldap_inputs); // unmap before the temp dir is removed
    drop(_tmp);
    report.parse_secs = t.elapsed().as_secs_f64();

    let t = Instant::now();
    let mut file_errors = file_errors.into_inner();
    file_errors.sort();
    // Merge in source order (each source's batches stay in record order), not
    // in parse-scheduling order: see `merge::canonical_source_order`.
    outputs.sort_by_key(|o| o.source);
    report.parse_errors = file_errors.len() as u64 + outputs.iter().map(|o| o.errors).sum::<u64>();
    report.first_error = file_errors
        .into_iter()
        .next()
        .or_else(|| outputs.iter().find_map(|o| o.first_error.clone()));
    report.records = outputs.iter().map(|o| o.records).sum();

    let parts = merge::merge(outputs, shared, &mut report, opts, &mut sources);
    report.dn_edges_resolved += ldap_stats.refs_resolved;
    report.dn_edges_unresolved += ldap_stats.refs_unresolved;
    report.sources = sources;
    report.merge_secs = t.elapsed().as_secs_f64();
    Ok((parts, report))
}
