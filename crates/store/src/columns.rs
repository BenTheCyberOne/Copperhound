//! Columnar node properties and search indexes.
//!
//! Collector properties are stored per node as JSON text (`props.blob`),
//! which is fine for showing one node but means every property filter parses
//! JSON for every node. This module derives typed, memory-mappable columns
//! from that blob once (at write time for new graphs, lazily for graphs
//! written before columns existed) so filters run over compact arrays and
//! bitmaps instead.
//!
//! Two files live next to the graph columns:
//!
//! - `columns.json` — manifest: format version, the graph it was built for
//!   (node count and blob lengths), and for every column its key, type and
//!   the byte ranges of its sections.
//! - `columns.bin`  — every section concatenated, each 8-byte aligned, so the
//!   whole file is one memory map and typed slices are zero-copy.
//!
//! Per property key (lower-cased; collectors are case-insensitive about keys)
//! one column with a single type, chosen from the non-null values seen:
//!
//! | type    | sections                                                         |
//! |---------|------------------------------------------------------------------|
//! | `bool`  | `present`, `trues` (roaring bitmaps)                             |
//! | `int`   | `present`, `ids` (`u32`, omitted when every node has a value), `values` (`i64`) |
//! | `float` | as `int` with `f64` values                                       |
//! | `str`   | `present`, `ids`, `codes` (`u8`/`u16`/`u32` by dictionary size), dictionary (`dict_off` `u64`, `dict_blob`) sorted by ASCII-case-folded value; low-cardinality columns add an equality index (one roaring bitmap per code) |
//! | `raw`   | `present` only — mixed types, lists, objects; filters fall back to JSON |
//! | `null`  | key seen but always `null`                                       |
//!
//! Name search uses the graph's own `name.blob`/`name.sorted` when names are
//! already upper case (what ingest produces); otherwise a case-folded copy
//! and a folded sort order are added here.

use crate::{Graph, StoreBytes};
use anyhow::{ensure, Context, Result};
use bytemuck::Pod;
use rayon::prelude::*;
use roaring::RoaringBitmap;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::borrow::Cow;
use ahash::AHashMap as HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Instant;

/// Version of `columns.json` / `columns.bin`. A mismatch rebuilds the columns.
pub const COLUMNS_VERSION: u32 = 1;
pub(crate) const MANIFEST: &str = "columns.json";
pub(crate) const DATA: &str = "columns.bin";

/// At most this many property keys get a column (most frequent first); the
/// rest are filtered by scanning JSON.
pub const MAX_COLUMNS: usize = 1024;
/// String columns with at most this many distinct values get an equality
/// index (one bitmap per value).
pub const EQ_INDEX_MAX_CARDINALITY: usize = 4096;

const PARSE_BLOCK: usize = 1 << 13;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ColType {
    Bool,
    Int,
    Float,
    Str,
    Raw,
    Null,
}

/// Byte range of a section inside `columns.bin`.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub(crate) struct Sec {
    off: u64,
    len: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ColMeta {
    pub key: String,
    #[serde(rename = "type")]
    pub ty: ColType,
    /// Nodes with a non-null value.
    pub count: u64,
    present: Sec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ids: Option<Sec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    values: Option<Sec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trues: Option<Sec>,
    #[serde(default)]
    code_width: u8,
    #[serde(default)]
    dict_len: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dict_off: Option<Sec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dict_blob: Option<Sec>,
    /// `u64` offsets (dict_len + 1) into `eq_bitmaps`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    eq_offs: Option<Sec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    eq_bitmaps: Option<Sec>,
}

impl ColMeta {
    fn shift(&mut self, base: u64) {
        self.present.off += base;
        for s in [
            &mut self.ids,
            &mut self.values,
            &mut self.trues,
            &mut self.dict_off,
            &mut self.dict_blob,
            &mut self.eq_offs,
            &mut self.eq_bitmaps,
        ]
        .into_iter()
        .flatten()
        {
            s.off += base;
        }
    }
}

/// Property keys that filters never read from the JSON because a node
/// attribute or flag answers them (`enabled` is read from both).
fn shadowed(k: &str) -> bool {
    matches!(k, "name" | "objectid" | "kind" | "label" | "id") || (k != "enabled" && crate::filter::flag_key(k).is_some())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Manifest {
    version: u32,
    node_count: u64,
    props_len: u64,
    name_len: u64,
    /// Every property key has a column (false when [`MAX_COLUMNS`] was hit).
    complete: bool,
    build_secs: f64,
    /// No object id contains lower-case ASCII, so the exact-match `oid.idx`
    /// answers case-insensitive object id equality.
    oids_upper: bool,
    /// Node ids with an empty raw name (display name is the object id).
    nameless: Sec,
    /// `u32[n]` ids by case-folded display name, when display names contain
    /// lower-case ASCII (else `name.sorted` is already in folded order).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name_fold_sorted: Option<Sec>,
    /// Upper-cased copy of `name.blob`, when it contains lower-case ASCII.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name_fold_blob: Option<Sec>,
    columns: Vec<ColMeta>,
}

/// Summary of a column for diagnostics and APIs.
#[derive(Clone, Debug, Serialize)]
pub struct ColumnInfo {
    pub key: String,
    #[serde(rename = "type")]
    pub ty: ColType,
    pub count: u64,
    pub distinct: Option<u64>,
    pub eq_index: bool,
}

/// Typed property columns of one graph. Obtain with [`Graph::columns`].
pub struct Columns {
    man: Manifest,
    data: StoreBytes,
    by_key: HashMap<String, usize>,
    present: Vec<OnceLock<RoaringBitmap>>,
    trues: Vec<OnceLock<RoaringBitmap>>,
    eq: Vec<OnceLock<Vec<RoaringBitmap>>>,
    nameless: Vec<u32>,
    /// Where the columns came from (`built`, `loaded`) and any persist error.
    pub origin: ColumnsOrigin,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ColumnsOrigin {
    /// Loaded from `columns.bin` (false: built from `props.blob` now).
    pub loaded: bool,
    /// Seconds spent building (0 when loaded).
    pub build_secs: f64,
    /// Bytes of `columns.bin`.
    pub bytes: u64,
    /// Set when freshly built columns could not be written next to the graph.
    pub persist_error: Option<String>,
}

/// A typed view of one column.
pub(crate) enum ColView<'a> {
    Bool,
    Num { ids: Option<&'a [u32]>, vals: NumVals<'a> },
    Str { ids: Option<&'a [u32]>, codes: Codes<'a>, dict: Dict<'a>, has_eq: bool },
    Raw,
    Null,
}

#[derive(Clone, Copy)]
pub(crate) enum NumVals<'a> {
    I(&'a [i64]),
    F(&'a [f64]),
}

#[derive(Clone, Copy)]
pub(crate) enum Codes<'a> {
    U8(&'a [u8]),
    U16(&'a [u16]),
    U32(&'a [u32]),
}


/// A sorted (by case-folded value, then bytes) string dictionary.
#[derive(Clone, Copy)]
pub(crate) struct Dict<'a> {
    off: &'a [u64],
    blob: &'a [u8],
}

impl<'a> Dict<'a> {
    pub fn len(&self) -> usize {
        self.off.len().saturating_sub(1)
    }
    #[inline]
    pub fn get(&self, i: usize) -> &'a str {
        let b = &self.blob[self.off[i] as usize..self.off[i + 1] as usize];
        // Written from `String`s; fall back to "" on a corrupt file.
        std::str::from_utf8(b).unwrap_or("")
    }
    /// Codes whose value equals `s` ignoring ASCII case.
    pub fn eq_range(&self, s: &str) -> std::ops::Range<usize> {
        let lo = partition(self.len(), |i| cmp_fold(self.get(i).as_bytes(), s.as_bytes()).is_lt());
        let hi = lo + partition(self.len() - lo, |i| cmp_fold(self.get(lo + i).as_bytes(), s.as_bytes()).is_eq());
        lo..hi
    }
    /// Codes whose value starts with `p` ignoring ASCII case.
    pub fn prefix_range(&self, p: &str) -> std::ops::Range<usize> {
        let pb = p.as_bytes();
        let head = |i: usize| {
            let b = self.get(i).as_bytes();
            cmp_fold(&b[..b.len().min(pb.len())], pb)
        };
        let lo = partition(self.len(), |i| head(i).is_lt());
        let hi = lo + partition(self.len() - lo, |i| head(lo + i).is_eq());
        lo..hi
    }
}

/// First index in `0..n` for which `pred` is false (`pred` must be monotone).
pub(crate) fn partition(n: usize, pred: impl Fn(usize) -> bool) -> usize {
    let (mut lo, mut hi) = (0, n);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if pred(mid) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// Compare as if both were ASCII-upper-cased.
#[inline]
pub fn cmp_fold(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    for (x, y) in a.iter().zip(b) {
        let (x, y) = (x.to_ascii_uppercase(), y.to_ascii_uppercase());
        if x != y {
            return x.cmp(&y);
        }
    }
    a.len().cmp(&b.len())
}

impl Columns {
    pub(crate) fn col(&self, key_lower: &str) -> Option<usize> {
        self.by_key.get(key_lower).copied()
    }
    /// Every property key has a column; a key without one is always null.
    pub fn complete(&self) -> bool {
        self.man.complete
    }
    pub fn info(&self) -> Vec<ColumnInfo> {
        self.man
            .columns
            .iter()
            .map(|c| ColumnInfo {
                key: c.key.clone(),
                ty: c.ty,
                count: c.count,
                distinct: (c.ty == ColType::Str).then_some(c.dict_len),
                eq_index: c.eq_offs.is_some(),
            })
            .collect()
    }
    fn slice<T: Pod>(&self, s: Sec) -> &[T] {
        let b = &self.data.bytes()[s.off as usize..(s.off + s.len) as usize];
        bytemuck::cast_slice(b)
    }
    fn bitmap(&self, s: Sec) -> RoaringBitmap {
        RoaringBitmap::deserialize_from(self.slice::<u8>(s)).unwrap_or_default()
    }
    pub(crate) fn present(&self, c: usize) -> &RoaringBitmap {
        self.present[c].get_or_init(|| self.bitmap(self.man.columns[c].present))
    }
    pub(crate) fn trues(&self, c: usize) -> &RoaringBitmap {
        self.trues[c].get_or_init(|| self.man.columns[c].trues.map(|s| self.bitmap(s)).unwrap_or_default())
    }
    /// Per-code equality bitmaps, if this string column has an equality index.
    pub(crate) fn eq_index(&self, c: usize) -> Option<&[RoaringBitmap]> {
        let m = &self.man.columns[c];
        let (offs, bms) = (m.eq_offs?, m.eq_bitmaps?);
        Some(self.eq[c].get_or_init(|| {
            let offs: &[u64] = self.slice(offs);
            let bytes: &[u8] = self.slice(bms);
            offs.windows(2)
                .collect::<Vec<_>>()
                .par_iter()
                .map(|w| RoaringBitmap::deserialize_from(&bytes[w[0] as usize..w[1] as usize]).unwrap_or_default())
                .collect()
        }))
    }
    pub(crate) fn view(&self, c: usize) -> ColView<'_> {
        let m = &self.man.columns[c];
        let ids = m.ids.map(|s| self.slice::<u32>(s));
        match m.ty {
            ColType::Bool => ColView::Bool,
            ColType::Raw => ColView::Raw,
            ColType::Null => ColView::Null,
            ColType::Int => ColView::Num { ids, vals: NumVals::I(m.values.map(|s| self.slice(s)).unwrap_or(&[])) },
            ColType::Float => ColView::Num { ids, vals: NumVals::F(m.values.map(|s| self.slice(s)).unwrap_or(&[])) },
            ColType::Str => {
                let v = m.values.unwrap_or_default();
                let codes = match m.code_width {
                    1 => Codes::U8(self.slice(v)),
                    2 => Codes::U16(self.slice(v)),
                    _ => Codes::U32(self.slice(v)),
                };
                let dict = Dict {
                    off: m.dict_off.map(|s| self.slice(s)).unwrap_or(&[0]),
                    blob: m.dict_blob.map(|s| self.slice(s)).unwrap_or(&[]),
                };
                ColView::Str { ids, codes, dict, has_eq: m.eq_offs.is_some() }
            }
        }
    }
    pub(crate) fn oids_upper(&self) -> bool {
        self.man.oids_upper
    }
    pub(crate) fn nameless(&self) -> &[u32] {
        &self.nameless
    }
    pub(crate) fn name_fold_sorted(&self) -> Option<&[u32]> {
        self.man.name_fold_sorted.map(|s| self.slice(s))
    }
    pub(crate) fn name_fold_blob(&self) -> Option<&[u8]> {
        self.man.name_fold_blob.map(|s| self.slice(s))
    }

    fn from_parts(man: Manifest, data: StoreBytes, origin: ColumnsOrigin) -> Result<Columns> {
        let len = data.bytes().len() as u64;
        let mut secs = vec![man.nameless];
        secs.extend(man.name_fold_sorted);
        secs.extend(man.name_fold_blob);
        for c in &man.columns {
            secs.push(c.present);
            secs.extend([c.ids, c.values, c.trues, c.dict_off, c.dict_blob, c.eq_offs, c.eq_bitmaps].into_iter().flatten());
        }
        for s in &secs {
            ensure!(s.off % 8 == 0 && s.off.checked_add(s.len).is_some_and(|e| e <= len), "columns.bin section out of range");
        }
        let n = man.node_count as usize;
        if let Some(s) = man.name_fold_sorted {
            ensure!(s.len as usize == n * 4, "name_fold_sorted length");
        }
        for c in &man.columns {
            let p = c.count as usize;
            match c.ty {
                ColType::Int | ColType::Float | ColType::Str => {
                    let w = match c.ty {
                        ColType::Str => c.code_width as usize,
                        _ => 8,
                    };
                    ensure!(matches!(w, 1 | 2 | 4 | 8), "column {}: code width", c.key);
                    ensure!(c.values.is_some_and(|s| s.len as usize == p * w), "column {}: values length", c.key);
                    match c.ids {
                        Some(s) => ensure!(s.len as usize == p * 4, "column {}: ids length", c.key),
                        None => ensure!(p == n, "column {}: dense column without all nodes", c.key),
                    }
                    if c.ty == ColType::Str {
                        let off = c.dict_off.context("dict_off")?;
                        ensure!(off.len == (c.dict_len + 1) * 8, "column {}: dictionary length", c.key);
                    }
                }
                _ => {}
            }
        }
        let k = man.columns.len();
        let by_key = man.columns.iter().enumerate().map(|(i, c)| (c.key.clone(), i)).collect();
        let mut cols = Columns {
            nameless: Vec::new(),
            by_key,
            present: (0..k).map(|_| OnceLock::new()).collect(),
            trues: (0..k).map(|_| OnceLock::new()).collect(),
            eq: (0..k).map(|_| OnceLock::new()).collect(),
            man,
            data,
            origin,
        };
        cols.nameless = cols.slice::<u32>(cols.man.nameless).to_vec();
        ensure!(cols.nameless.iter().all(|&i| (i as usize) < n), "nameless ids");
        if let Some(s) = cols.man.name_fold_blob {
            ensure!(s.len == cols.man.name_len, "name_fold_blob length");
        }
        for c in &cols.man.columns {
            if let (Some(o), Some(b)) = (c.dict_off, c.dict_blob) {
                let off: &[u64] = cols.slice(o);
                ensure!(off.first() == Some(&0) && off.par_windows(2).all(|w| w[0] <= w[1]), "column {}: dictionary offsets", c.key);
                ensure!(off.last().is_some_and(|&e| e <= b.len), "column {}: dictionary blob", c.key);
            }
            if let (Some(o), Some(b)) = (c.eq_offs, c.eq_bitmaps) {
                let off: &[u64] = cols.slice(o);
                ensure!(off.len() as u64 == c.dict_len + 1, "column {}: equality index length", c.key);
                ensure!(off.windows(2).all(|w| w[0] <= w[1]) && off.last().is_some_and(|&e| e <= b.len), "column {}: equality index", c.key);
            }
        }
        if let Some(s) = cols.man.name_fold_sorted {
            ensure!(cols.slice::<u32>(s).iter().all(|&i| (i as usize) < n), "name_fold_sorted ids");
        }
        Ok(cols)
    }

    /// Open `columns.json`/`columns.bin` in `dir` if they match `g`.
    pub(crate) fn load(dir: &Path, g: &Graph) -> Result<Option<Columns>> {
        let mp = dir.join(MANIFEST);
        if !mp.exists() {
            return Ok(None);
        }
        let man: Manifest = serde_json::from_reader(std::io::BufReader::new(File::open(&mp)?)).context("parsing columns.json")?;
        if man.version != COLUMNS_VERSION
            || man.node_count != g.node_count() as u64
            || man.props_len != g.props_blob.len() as u64
            || man.name_len != g.name_blob.len() as u64
        {
            return Ok(None);
        }
        let data = StoreBytes::map(&dir.join(DATA))?;
        let bytes = data.bytes().len() as u64;
        Columns::from_parts(man, data, ColumnsOrigin { loaded: true, bytes, ..Default::default() }).map(Some)
    }

    /// Write `columns.bin` then `columns.json` (manifest last, both via
    /// rename, so readers never see a torn pair).
    pub(crate) fn write(&self, dir: &Path) -> Result<()> {
        let tag = std::process::id();
        let tmp = dir.join(format!("{DATA}.tmp-{tag}"));
        {
            let mut f = std::io::BufWriter::with_capacity(1 << 20, File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?);
            f.write_all(self.data.bytes())?;
            f.flush()?;
        }
        let _ = fs::remove_file(dir.join(MANIFEST));
        fs::rename(&tmp, dir.join(DATA)).inspect_err(|_| {
            let _ = fs::remove_file(&tmp);
        })?;
        let tmpm = dir.join(format!("{MANIFEST}.tmp-{tag}"));
        fs::write(&tmpm, serde_json::to_vec_pretty(&self.man)?)?;
        fs::rename(&tmpm, dir.join(MANIFEST))?;
        Ok(())
    }

    /// Persist freshly built columns into the graph directory and switch to
    /// the memory-mapped copy (releasing the heap copy).
    pub(crate) fn persist_and_remap(self, dir: &Path) -> Columns {
        let mut origin = self.origin.clone();
        match self.write(dir).and_then(|_| StoreBytes::map(&dir.join(DATA))) {
            Ok(data) => {
                let man = self.man.clone();
                match Columns::from_parts(man, data, origin.clone()) {
                    Ok(c) => c,
                    Err(e) => {
                        let mut s = self;
                        s.origin.persist_error = Some(format!("{e:#}"));
                        s
                    }
                }
            }
            Err(e) => {
                origin.persist_error = Some(format!("{e:#}"));
                let mut s = self;
                s.origin = origin;
                s
            }
        }
    }

    /// Build columns from a graph's property blob and name columns.
    pub fn build(g: &Graph) -> Columns {
        let t = Instant::now();
        let tracing = std::env::var_os("CH_COLUMNS_TRACE").is_some();
        let trace = |phase: &str| {
            if tracing {
                eprintln!("columns: {phase} done at {:.0} ms", t.elapsed().as_secs_f64() * 1e3);
            }
        };
        let n = g.node_count();
        let mut out = Out::default();

        // ---- names
        let nameless: Vec<u32> = (0..n as u32)
            .into_par_iter()
            .filter(|&i| g.name_off[i as usize] == g.name_off[i as usize + 1])
            .collect();
        let blob_lower = g.name_blob.par_chunks(1 << 20).any(|c| c.iter().any(u8::is_ascii_lowercase));
        let oid_lower = nameless.par_iter().any(|&i| g.oid(i).bytes().any(|b| b.is_ascii_lowercase()));
        let oids_upper = !g.oid_blob.par_chunks(1 << 20).any(|c| c.iter().any(u8::is_ascii_lowercase));
        let nameless_sec = out.push(&nameless);
        let name_fold_blob = blob_lower.then(|| {
            let folded: Vec<u8> = g.name_blob.par_iter().map(u8::to_ascii_uppercase).collect();
            out.push(&folded)
        });
        let name_fold_sorted = (blob_lower || oid_lower).then(|| {
            let mut ids: Vec<u32> = (0..n as u32).collect();
            ids.par_sort_unstable_by(|&a, &b| cmp_fold(g.name(a).as_bytes(), g.name(b).as_bytes()).then(a.cmp(&b)));
            out.push(&ids)
        });

        trace("names");
        // ---- property key discovery and typing
        let props = |i: usize| crate::str_at(&g.props_off, &g.props_blob, i as u32);
        let stats: HashMap<String, KeyStat> = (0..n.div_ceil(PARSE_BLOCK))
            .into_par_iter()
            .map(|b| {
                let mut m: HashMap<String, KeyStat> = HashMap::new();
                for i in b * PARSE_BLOCK..((b + 1) * PARSE_BLOCK).min(n) {
                    let p = props(i);
                    if p.is_empty() {
                        continue;
                    }
                    let stamp = i as u32 + 1;
                    let _ = parse_props(p, &mut |k, v| {
                        if shadowed(k) {
                            return;
                        }
                        let s = match m.get_mut(k) {
                            Some(s) => s,
                            None => m.entry(k.to_string()).or_default(),
                        };
                        if s.last != stamp {
                            s.last = stamp;
                            s.count += 1;
                            s.mask |= v.tag();
                        }
                    });
                }
                m
            })
            .reduce(HashMap::new, |mut a, b| {
                for (k, s) in b {
                    let e = a.entry(k).or_default();
                    e.count += s.count;
                    e.mask |= s.mask;
                }
                a
            });
        let mut keys: Vec<(String, KeyStat)> = stats.into_iter().collect();
        keys.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(&b.0)));
        let complete = keys.len() <= MAX_COLUMNS;
        keys.truncate(MAX_COLUMNS);
        keys.sort_by(|a, b| a.0.cmp(&b.0));
        let types: Vec<ColType> = keys.iter().map(|(_, s)| s.col_type()).collect();
        let key_idx: HashMap<&str, usize> = keys.iter().enumerate().map(|(i, (k, _))| (k.as_str(), i)).collect();

        trace("discovery");
        // ---- values, per block
        let blocks: Vec<Vec<Option<Part>>> = (0..n.div_ceil(PARSE_BLOCK))
            .into_par_iter()
            .map(|b| {
                let mut parts: Vec<Option<Part>> = (0..keys.len()).map(|_| None).collect();
                let mut last = vec![0u32; keys.len()];
                for i in b * PARSE_BLOCK..((b + 1) * PARSE_BLOCK).min(n) {
                    let p = props(i);
                    if p.is_empty() {
                        continue;
                    }
                    let stamp = i as u32 + 1;
                    let _ = parse_props(p, &mut |k, v| {
                        let Some(&c) = key_idx.get(k) else { return };
                        if last[c] == stamp {
                            return;
                        }
                        last[c] = stamp;
                        if !matches!(v, PVal::Null) {
                            parts[c].get_or_insert_with(|| Part::new(types[c])).push(i as u32, v);
                        }
                    });
                }
                parts
            })
            .collect();
        // Transpose to per-column block lists.
        let mut per_col: Vec<Vec<Part>> = (0..keys.len()).map(|_| Vec::new()).collect();
        for parts in blocks {
            for (c, p) in parts.into_iter().enumerate() {
                if let Some(p) = p {
                    per_col[c].push(p);
                }
            }
        }

        trace("values");
        // Finish columns in parallel, each into its own buffer, then append.
        let finished: Vec<(ColMeta, Out)> = per_col
            .into_par_iter()
            .enumerate()
            .map(|(c, parts)| {
                let mut o = Out::default();
                let m = finish_column(keys[c].0.clone(), types[c], parts, n, &mut o);
                (m, o)
            })
            .collect();
        let mut metas = Vec::with_capacity(keys.len());
        for (mut m, o) in finished {
            let base = out.append(&o);
            m.shift(base);
            metas.push(m);
        }

        trace("finish");
        let man = Manifest {
            version: COLUMNS_VERSION,
            node_count: n as u64,
            props_len: g.props_blob.len() as u64,
            name_len: g.name_blob.len() as u64,
            complete,
            build_secs: t.elapsed().as_secs_f64(),
            oids_upper,
            nameless: nameless_sec,
            name_fold_sorted,
            name_fold_blob,
            columns: metas,
        };
        let data = StoreBytes::Owned(out.buf, out.len);
        let bytes = data.bytes().len() as u64;
        let build_secs = t.elapsed().as_secs_f64();
        Columns::from_parts(man, data, ColumnsOrigin { loaded: false, build_secs, bytes, persist_error: None })
            .expect("freshly built columns are consistent")
    }
}

#[derive(Default, Clone, Copy)]
struct KeyStat {
    count: u64,
    mask: u8,
    /// Last node (id + 1) counted, so a duplicate key counts once.
    last: u32,
}

const T_BOOL: u8 = 1;
const T_INT: u8 = 2;
const T_FLOAT: u8 = 4;
const T_STR: u8 = 8;
const T_OTHER: u8 = 16;

impl KeyStat {
    fn col_type(&self) -> ColType {
        match self.mask {
            0 => ColType::Null,
            T_BOOL => ColType::Bool,
            T_INT => ColType::Int,
            m if m & !(T_INT | T_FLOAT) == 0 => ColType::Float,
            T_STR => ColType::Str,
            _ => ColType::Raw,
        }
    }
}

/// Section writer: 8-byte aligned sections in one `u64`-backed buffer.
#[derive(Default)]
struct Out {
    buf: Vec<u64>,
    len: usize,
}

impl Out {
    fn push<T: Pod>(&mut self, data: &[T]) -> Sec {
        let bytes: &[u8] = bytemuck::cast_slice(data);
        let off = self.len;
        let words = bytes.len().div_ceil(8);
        self.buf.resize(off / 8 + words, 0);
        let dst: &mut [u8] = bytemuck::cast_slice_mut(&mut self.buf[off / 8..]);
        dst[..bytes.len()].copy_from_slice(bytes);
        self.len = off + words * 8;
        Sec { off: off as u64, len: bytes.len() as u64 }
    }
    /// Append another buffer; returns the byte offset it starts at.
    fn append(&mut self, o: &Out) -> u64 {
        let base = self.len;
        self.buf.truncate(base / 8);
        self.buf.extend_from_slice(&o.buf);
        self.len = base + o.len;
        base as u64
    }
    fn push_bitmap(&mut self, bm: &RoaringBitmap) -> Sec {
        let mut v = Vec::with_capacity(bm.serialized_size());
        bm.serialize_into(&mut v).expect("in-memory write");
        self.push(&v)
    }
}

/// Values of one column for one block of nodes. Strings borrow from the
/// property blob unless they contained escapes.
enum Part<'a> {
    Bool { ids: Vec<u32>, trues: Vec<u32> },
    Int { ids: Vec<u32>, vals: Vec<i64> },
    Float { ids: Vec<u32>, vals: Vec<f64> },
    Str { ids: Vec<u32>, codes: Vec<u32>, dict: Vec<Cow<'a, str>>, map: HashMap<Cow<'a, str>, u32> },
    Raw { ids: Vec<u32> },
}

impl<'a> Part<'a> {
    fn new(t: ColType) -> Part<'a> {
        match t {
            ColType::Bool => Part::Bool { ids: Vec::new(), trues: Vec::new() },
            ColType::Int => Part::Int { ids: Vec::new(), vals: Vec::new() },
            ColType::Float => Part::Float { ids: Vec::new(), vals: Vec::new() },
            ColType::Str => Part::Str { ids: Vec::new(), codes: Vec::new(), dict: Vec::new(), map: HashMap::new() },
            ColType::Raw | ColType::Null => Part::Raw { ids: Vec::new() },
        }
    }
    fn push(&mut self, id: u32, v: PVal<'a>) {
        match (self, v) {
            (Part::Bool { ids, trues }, PVal::Bool(b)) => {
                ids.push(id);
                if b {
                    trues.push(id);
                }
            }
            (Part::Int { ids, vals }, PVal::Int(x)) => {
                ids.push(id);
                vals.push(x);
            }
            (Part::Float { ids, vals }, PVal::Int(x)) => {
                ids.push(id);
                vals.push(x as f64);
            }
            (Part::Float { ids, vals }, PVal::Float(x)) => {
                ids.push(id);
                vals.push(x);
            }
            (Part::Str { ids, codes, dict, map }, PVal::Str(s)) => {
                ids.push(id);
                let code = match map.get(s.as_ref()) {
                    Some(&c) => c,
                    None => {
                        let c = dict.len() as u32;
                        dict.push(s.clone());
                        map.insert(s, c);
                        c
                    }
                };
                codes.push(code);
            }
            (Part::Raw { ids }, _) => ids.push(id),
            // Types were fixed from the same data; anything else is impossible.
            _ => {}
        }
    }
}

/// First 8 bytes of `s`, ASCII-upper-cased, big-endian, zero-padded: orders
/// like [`cmp_fold`] whenever two prefixes differ.
fn fold_prefix(s: &str) -> u64 {
    let mut b = [0u8; 8];
    for (d, c) in b.iter_mut().zip(s.bytes()) {
        *d = c.to_ascii_uppercase();
    }
    u64::from_be_bytes(b)
}

fn concat<T: Copy + Send + Sync>(parts: Vec<&[T]>) -> Vec<T> {
    let total = parts.iter().map(|p| p.len()).sum();
    let mut v = Vec::with_capacity(total);
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

fn finish_column(key: String, ty: ColType, parts: Vec<Part<'_>>, n: usize, out: &mut Out) -> ColMeta {
    let ids: Vec<u32> = concat(
        parts
            .iter()
            .map(|p| match p {
                Part::Bool { ids, .. } | Part::Int { ids, .. } | Part::Float { ids, .. } | Part::Str { ids, .. } | Part::Raw { ids } => ids.as_slice(),
            })
            .collect(),
    );
    let count = ids.len() as u64;
    let present = bitmap_from_sorted(&ids);
    let mut m = ColMeta {
        key,
        ty,
        count,
        present: out.push_bitmap(&present),
        ids: None,
        values: None,
        trues: None,
        code_width: 0,
        dict_len: 0,
        dict_off: None,
        dict_blob: None,
        eq_offs: None,
        eq_bitmaps: None,
    };
    let dense = ids.len() == n;
    match ty {
        ColType::Bool => {
            let trues = concat(parts.iter().map(|p| if let Part::Bool { trues, .. } = p { trues.as_slice() } else { &[] }).collect());
            m.trues = Some(out.push_bitmap(&bitmap_from_sorted(&trues)));
        }
        ColType::Int => {
            let vals = concat(parts.iter().map(|p| if let Part::Int { vals, .. } = p { vals.as_slice() } else { &[] }).collect());
            m.ids = (!dense).then(|| out.push(&ids));
            m.values = Some(out.push(&vals));
        }
        ColType::Float => {
            let vals = concat(parts.iter().map(|p| if let Part::Float { vals, .. } = p { vals.as_slice() } else { &[] }).collect());
            m.ids = (!dense).then(|| out.push(&ids));
            m.values = Some(out.push(&vals));
        }
        ColType::Str => {
            // Global dictionary sorted by folded value, then bytes: sort every
            // (value, block, local code), assign codes walking the order.
            let dicts: Vec<&[Cow<str>]> = parts.iter().map(|p| if let Part::Str { dict, .. } = p { dict.as_slice() } else { &[] }).collect();
            // The folded 8-byte prefix decides most comparisons cheaply.
            let mut all: Vec<(u64, &str, u32, u32)> = dicts
                .par_iter()
                .enumerate()
                .flat_map_iter(|(b, d)| d.iter().enumerate().map(move |(l, s)| (fold_prefix(s), s.as_ref(), b as u32, l as u32)))
                .collect();
            all.par_sort_unstable_by(|a, b| {
                a.0.cmp(&b.0).then_with(|| cmp_fold(a.1.as_bytes(), b.1.as_bytes())).then_with(|| a.1.cmp(b.1))
            });
            let mut remap: Vec<Vec<u32>> = dicts.iter().map(|d| vec![0; d.len()]).collect();
            let mut off = vec![0u64];
            let mut blob = Vec::new();
            let mut prev: Option<&str> = None;
            for &(_, s, b, l) in &all {
                if prev != Some(s) {
                    blob.extend_from_slice(s.as_bytes());
                    off.push(blob.len() as u64);
                    prev = Some(s);
                }
                remap[b as usize][l as usize] = off.len() as u32 - 2;
            }
            drop(all);
            let codes: Vec<u32> = parts
                .par_iter()
                .zip(&remap)
                .flat_map_iter(|(p, r)| match p {
                    Part::Str { codes, .. } => codes.iter().map(|&c| r[c as usize]).collect::<Vec<_>>(),
                    _ => Vec::new(),
                })
                .collect();
            let d = off.len() - 1;
            m.ids = (!dense).then(|| out.push(&ids));
            m.code_width = if d <= 1 << 8 {
                1
            } else if d <= 1 << 16 {
                2
            } else {
                4
            };
            m.values = Some(match m.code_width {
                1 => out.push(&codes.iter().map(|&c| c as u8).collect::<Vec<_>>()),
                2 => out.push(&codes.iter().map(|&c| c as u16).collect::<Vec<_>>()),
                _ => out.push(&codes),
            });
            m.dict_len = d as u64;
            m.dict_off = Some(out.push(&off));
            m.dict_blob = Some(out.push(&blob));
            if d <= EQ_INDEX_MAX_CARDINALITY {
                let mut buckets: Vec<Vec<u32>> = vec![Vec::new(); d];
                for (&id, &c) in ids.iter().zip(&codes) {
                    buckets[c as usize].push(id);
                }
                let ser: Vec<Vec<u8>> = buckets
                    .par_iter()
                    .map(|b| {
                        let bm = bitmap_from_sorted(b);
                        let mut v = Vec::with_capacity(bm.serialized_size());
                        bm.serialize_into(&mut v).expect("in-memory write");
                        v
                    })
                    .collect();
                let mut eo = Vec::with_capacity(d + 1);
                eo.push(0u64);
                let mut bytes = Vec::new();
                for s in ser {
                    bytes.extend_from_slice(&s);
                    eo.push(bytes.len() as u64);
                }
                m.eq_offs = Some(out.push(&eo));
                m.eq_bitmaps = Some(out.push(&bytes));
            }
        }
        ColType::Raw | ColType::Null => {}
    }
    m
}

/// Bitmap from sorted, distinct ids, built in parallel per 2^16-id container.
pub(crate) fn bitmap_from_sorted(ids: &[u32]) -> RoaringBitmap {
    if ids.len() < 1 << 16 {
        return RoaringBitmap::from_sorted_iter(ids.iter().copied()).unwrap_or_else(|_| ids.iter().copied().collect());
    }
    // Split at container (high 16 bits) boundaries so partial bitmaps are disjoint.
    let mut cuts = vec![0usize];
    let step = (ids.len() / (rayon::current_num_threads() * 4)).max(1 << 16);
    let mut i = step;
    while i < ids.len() {
        let hi = ids[i] >> 16;
        let j = i + ids[i..].partition_point(|&x| x >> 16 == hi);
        if j >= ids.len() {
            break;
        }
        cuts.push(j);
        i = j + step;
    }
    cuts.push(ids.len());
    cuts.windows(2)
        .collect::<Vec<_>>()
        .into_par_iter()
        .map(|w| RoaringBitmap::from_sorted_iter(ids[w[0]..w[1]].iter().copied()).unwrap_or_else(|_| ids[w[0]..w[1]].iter().copied().collect()))
        .reduce(RoaringBitmap::new, |a, b| a | b)
}

// ------------------------------------------------------------ JSON parsing

/// A parsed property value. Strings borrow from the JSON when unescaped.
pub(crate) enum PVal<'a> {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(Cow<'a, str>),
    Other,
}

impl PVal<'_> {
    fn tag(&self) -> u8 {
        match self {
            PVal::Null => 0,
            PVal::Bool(_) => T_BOOL,
            PVal::Int(_) => T_INT,
            PVal::Float(_) => T_FLOAT,
            PVal::Str(_) => T_STR,
            PVal::Other => T_OTHER,
        }
    }
}

impl<'de> Deserialize<'de> for PVal<'de> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = PVal<'de>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_bool<E>(self, b: bool) -> Result<Self::Value, E> {
                Ok(PVal::Bool(b))
            }
            fn visit_i64<E>(self, i: i64) -> Result<Self::Value, E> {
                Ok(PVal::Int(i))
            }
            fn visit_u64<E>(self, u: u64) -> Result<Self::Value, E> {
                Ok(i64::try_from(u).map(PVal::Int).unwrap_or(PVal::Float(u as f64)))
            }
            fn visit_f64<E>(self, f: f64) -> Result<Self::Value, E> {
                Ok(PVal::Float(f))
            }
            fn visit_borrowed_str<E>(self, s: &'de str) -> Result<Self::Value, E> {
                Ok(PVal::Str(Cow::Borrowed(s)))
            }
            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E> {
                Ok(PVal::Str(Cow::Owned(s.to_string())))
            }
            fn visit_string<E>(self, s: String) -> Result<Self::Value, E> {
                Ok(PVal::Str(Cow::Owned(s)))
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(PVal::Null)
            }
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(PVal::Null)
            }
            fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
                PVal::deserialize(d)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                while a.next_element::<IgnoredAny>()?.is_some() {}
                Ok(PVal::Other)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                while a.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(PVal::Other)
            }
        }
        d.deserialize_any(V)
    }
}

/// Map key that borrows from the JSON when it has no escapes.
struct KeyCow<'de>(Cow<'de, str>);
impl<'de> Deserialize<'de> for KeyCow<'de> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = KeyCow<'de>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a key")
            }
            fn visit_borrowed_str<E>(self, s: &'de str) -> Result<Self::Value, E> {
                Ok(KeyCow(Cow::Borrowed(s)))
            }
            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E> {
                Ok(KeyCow(Cow::Owned(s.to_string())))
            }
            fn visit_string<E>(self, s: String) -> Result<Self::Value, E> {
                Ok(KeyCow(Cow::Owned(s)))
            }
        }
        d.deserialize_str(V)
    }
}

/// Visit every top-level `(lower-cased key, value)` of a JSON object in
/// order, but only if the whole object parses (a case-insensitive key lookup
/// over the same text fails on a malformed object too). Callers keep the
/// first occurrence of a duplicate key. Text after the object is ignored, as
/// in the lookup.
pub(crate) fn parse_props<'a>(json: &'a str, f: &mut dyn FnMut(&str, PVal<'a>)) -> Result<(), serde_json::Error> {
    struct Obj<'f, 'a> {
        f: &'f mut dyn FnMut(&str, PVal<'a>),
    }
    impl<'de: 'a, 'a> DeserializeSeed<'de> for Obj<'_, 'a> {
        type Value = ();
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
            d.deserialize_map(self)
        }
    }
    impl<'de: 'a, 'a> Visitor<'de> for Obj<'_, 'a> {
        type Value = ();
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("an object")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<(), A::Error> {
            let mut items: Vec<(Cow<'de, str>, PVal<'de>)> = Vec::new();
            while let Some(KeyCow(k)) = m.next_key()? {
                let k = if k.bytes().any(|b| b.is_ascii_uppercase()) { Cow::Owned(k.to_ascii_lowercase()) } else { k };
                items.push((k, m.next_value()?));
            }
            for (k, v) in items {
                (self.f)(&k, v);
            }
            Ok(())
        }
    }
    let mut de = serde_json::Deserializer::from_str(json);
    Obj { f }.deserialize(&mut de)
}
