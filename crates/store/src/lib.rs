//! CopperHound graph store.
//!
//! The graph is kept as two compressed-sparse-row (CSR) adjacency structures
//! (outbound and inbound) plus columnar node arrays. On disk every column is a
//! raw little-endian file inside a directory; [`Graph::open`] memory-maps them so
//! a multi-gigabyte graph opens instantly and pages in lazily.
//!
//! Layout of a graph directory:
//!
//! | file          | type        | len      |
//! |---------------|-------------|----------|
//! | `meta.json`   | JSON        |          |
//! | `nodes.kind`  | `u8`        | n        |
//! | `nodes.flags` | `u32`       | n        |
//! | `name.off`    | `u64`       | n + 1    |
//! | `name.blob`   | UTF-8 bytes |          |
//! | `oid.off`     | `u64`       | n + 1    |
//! | `oid.blob`    | UTF-8 bytes |          |
//! | `out.off`     | `u64`       | n + 1    |
//! | `out.dst`     | `u32`       | m        |
//! | `out.kind`    | `u16`       | m        |
//! | `in.off`      | `u64`       | n + 1    |
//! | `in.src`      | `u32`       | m        |
//! | `in.kind`     | `u16`       | m        |
//! | `oid.idx`     | `IdxEntry`  | n        |
//! | `name.idx`    | `IdxEntry`  | ≤ n      |
//! | `name.sorted` | `u32`       | n        |
//! | `props.off`   | `u64`       | n + 1    |
//! | `props.blob`  | JSON text   |          |
//! | `columns.json`, `columns.bin` | property columns ([`columns`]) | |
//!
//! Format 3 adds the property columns. Format 2 graphs still open; their
//! columns are built from `props.blob` on first use and written next to the
//! graph (see [`Graph::columns`]).

pub mod columns;
pub mod filter;

pub use columns::{ColType, ColumnInfo, Columns, ColumnsOrigin, COLUMNS_VERSION};
pub use filter::{Filter, Op, Val};
pub use roaring::RoaringBitmap;

use anyhow::{bail, ensure, Context, Result};
use bytemuck::{Pod, Zeroable};
use memmap2::Mmap;
use ch_model::{fnv1a64, NodeKind};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::OnceLock;
use std::time::Instant;

/// Format written by [`Graph::write`].
pub const FORMAT_VERSION: u32 = 3;
/// Oldest format [`Graph::open`] reads.
pub const MIN_FORMAT_VERSION: u32 = 2;

/// Bytes that are either owned (`u64`-aligned) or memory-mapped.
pub(crate) enum StoreBytes {
    Owned(Vec<u64>, usize),
    Mapped(Mmap),
    Empty,
}

impl StoreBytes {
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            StoreBytes::Owned(v, len) => &bytemuck::cast_slice::<u64, u8>(v)[..*len],
            StoreBytes::Mapped(m) => m,
            StoreBytes::Empty => &[],
        }
    }
    pub(crate) fn map(path: &Path) -> Result<StoreBytes> {
        let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        if f.metadata()?.len() == 0 {
            return Ok(StoreBytes::Empty);
        }
        // SAFETY: read-only map of a file CopperHound never modifies in place.
        let m = unsafe { Mmap::map(&f) }.with_context(|| format!("mapping {}", path.display()))?;
        Ok(StoreBytes::Mapped(m))
    }
}

/// A raw edge as produced by ingest.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
pub struct Edge {
    pub src: u32,
    pub dst: u32,
    pub kind: u16,
    pub pad: u16,
}

impl Edge {
    #[inline]
    pub fn new(src: u32, dst: u32, kind: u16) -> Self {
        Self {
            src,
            dst,
            kind,
            pad: 0,
        }
    }
}

/// Hash index entry, sorted by `(hash, id)`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct IdxEntry {
    pub hash: u64,
    pub id: u32,
    pub pad: u32,
}

/// A column that is either owned (freshly built) or memory-mapped from disk.
pub enum Buf<T: Pod> {
    Owned(Vec<T>),
    Mapped(Mmap, PhantomData<T>),
}

impl<T: Pod> std::ops::Deref for Buf<T> {
    type Target = [T];
    #[inline]
    fn deref(&self) -> &[T] {
        match self {
            Buf::Owned(v) => v,
            // An empty file maps to a dangling, possibly unaligned pointer.
            Buf::Mapped(m, _) if m.is_empty() => &[],
            Buf::Mapped(m, _) => bytemuck::cast_slice(&m[..]),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GraphMeta {
    pub format_version: u32,
    pub node_count: u64,
    pub edge_count: u64,
    pub edge_kinds: Vec<String>,
    pub traversable: Vec<bool>,
    pub created_by: String,
    /// Custom node kind names (OpenGraph): raw kind `CUSTOM_KIND_BASE + i`
    /// is `node_kinds[i]`. Built-in kinds are not listed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_kinds: Vec<String>,
    /// Ingest provenance: input sources (see `ch_ingest::SourceInfo`) and the
    /// merge policy. Absent in graphs written before it existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingest: Option<serde_json::Value>,
}

/// Everything needed to build a graph. Produced by ingest.
pub struct GraphParts {
    pub kinds: Vec<u8>,
    pub flags: Vec<u32>,
    pub names: Vec<Option<String>>,
    pub oids: Vec<String>,
    /// Raw collector properties as a JSON object string, if any.
    pub props: Vec<Option<String>>,
    /// Edges, possibly duplicated; consumed chunk by chunk to bound peak memory.
    pub edge_chunks: Vec<Vec<Edge>>,
    pub edge_kinds: Vec<String>,
    pub traversable: Vec<bool>,
    /// Custom node kind names (see [`GraphMeta::node_kinds`]).
    pub node_kinds: Vec<String>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct BuildStats {
    pub raw_edges: u64,
    pub edges: u64,
    pub csr_secs: f64,
    pub index_secs: f64,
}

pub struct Graph {
    meta: GraphMeta,
    kinds: Buf<u8>,
    flags: Buf<u32>,
    name_off: Buf<u64>,
    name_blob: Buf<u8>,
    oid_off: Buf<u64>,
    oid_blob: Buf<u8>,
    out_off: Buf<u64>,
    out_dst: Buf<u32>,
    out_kind: Buf<u16>,
    in_off: Buf<u64>,
    in_src: Buf<u32>,
    in_kind: Buf<u16>,
    oid_idx: Buf<IdxEntry>,
    name_idx: Buf<IdxEntry>,
    /// Node ids ordered by display name, for prefix search.
    name_sorted: Buf<u32>,
    props_off: Buf<u64>,
    props_blob: Buf<u8>,
    /// Directory the graph was opened from (columns are persisted there).
    dir: Option<PathBuf>,
    cols: OnceLock<Columns>,
    kind_bms: OnceLock<Vec<RoaringBitmap>>,
    flag_bms: [OnceLock<RoaringBitmap>; 32],
}

fn empty_caches() -> (OnceLock<Columns>, OnceLock<Vec<RoaringBitmap>>, [OnceLock<RoaringBitmap>; 32]) {
    (OnceLock::new(), OnceLock::new(), std::array::from_fn(|_| OnceLock::new()))
}

impl Graph {
    /// Property columns and name indexes, loaded from `columns.bin` or — for
    /// graphs written before format 3, or if the file is missing or stale —
    /// built from the stored JSON properties on first call (parallel; seconds
    /// per ~10M nodes) and persisted next to the graph. Later calls are free.
    /// Persist failures (e.g. a read-only directory) keep the columns in
    /// memory and are reported in [`Columns::origin`].
    pub fn columns(&self) -> &Columns {
        self.cols.get_or_init(|| {
            if let Some(dir) = &self.dir {
                if let Ok(Some(c)) = Columns::load(dir, self) {
                    return c;
                }
                return Columns::build(self).persist_and_remap(dir);
            }
            Columns::build(self)
        })
    }

    /// The columns if already loaded or built (never blocks to build them).
    pub fn columns_ready(&self) -> Option<&Columns> {
        self.cols.get()
    }

    /// Build an in-memory graph from ingest output: CSR construction with
    /// per-node edge dedup, reverse CSR, string blobs and lookup indexes.
    pub fn build(parts: GraphParts) -> Result<(Graph, BuildStats)> {
        let n = parts.kinds.len();
        ensure!(parts.flags.len() == n, "flags length mismatch");
        ensure!(parts.names.len() == n, "names length mismatch");
        ensure!(parts.oids.len() == n, "oids length mismatch");
        ensure!(parts.props.len() == n, "props length mismatch");
        ensure!(
            parts.edge_kinds.len() == parts.traversable.len(),
            "edge kind table mismatch"
        );
        ensure!((n as u64) < u32::MAX as u64, "too many nodes for u32 ids");

        let raw_edges: u64 = parts.edge_chunks.iter().map(|c| c.len() as u64).sum();
        let t = Instant::now();
        let (out_off, out_dst, out_kind) = build_csr(n, parts.edge_chunks)?;
        let (in_off, in_src, in_kind) = reverse_csr(n, &out_off, &out_dst, &out_kind);
        let csr_secs = t.elapsed().as_secs_f64();

        let t = Instant::now();
        let (name_off, name_blob) = blob(parts.names.iter().map(|s| s.as_deref().unwrap_or("")));
        let (oid_off, oid_blob) = blob(parts.oids.iter().map(|s| s.as_str()));
        let oid_idx = build_index(&parts.oids, |s| s.as_str());
        let name_idx = build_index(&parts.names, |s| s.as_deref().unwrap_or(""));
        let display = |i: u32| -> &str {
            parts.names[i as usize]
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or(&parts.oids[i as usize])
        };
        let mut name_sorted: Vec<u32> = (0..n as u32).collect();
        name_sorted.par_sort_unstable_by(|&a, &b| display(a).cmp(display(b)).then(a.cmp(&b)));
        let (props_off, props_blob) = blob(parts.props.iter().map(|s| s.as_deref().unwrap_or("")));
        let index_secs = t.elapsed().as_secs_f64();

        let meta = GraphMeta {
            format_version: FORMAT_VERSION,
            node_count: n as u64,
            edge_count: out_dst.len() as u64,
            edge_kinds: parts.edge_kinds,
            traversable: parts.traversable,
            node_kinds: parts.node_kinds,
            created_by: concat!("copperhound ", env!("CARGO_PKG_VERSION")).to_string(),
            ingest: None,
        };
        let stats = BuildStats {
            raw_edges,
            edges: meta.edge_count,
            csr_secs,
            index_secs,
        };
        let (cols, kind_bms, flag_bms) = empty_caches();
        let g = Graph {
            meta,
            kinds: Buf::Owned(parts.kinds),
            flags: Buf::Owned(parts.flags),
            name_off: Buf::Owned(name_off),
            name_blob: Buf::Owned(name_blob),
            oid_off: Buf::Owned(oid_off),
            oid_blob: Buf::Owned(oid_blob),
            out_off: Buf::Owned(out_off),
            out_dst: Buf::Owned(out_dst),
            out_kind: Buf::Owned(out_kind),
            in_off: Buf::Owned(in_off),
            in_src: Buf::Owned(in_src),
            in_kind: Buf::Owned(in_kind),
            oid_idx: Buf::Owned(oid_idx),
            name_idx: Buf::Owned(name_idx),
            name_sorted: Buf::Owned(name_sorted),
            props_off: Buf::Owned(props_off),
            props_blob: Buf::Owned(props_blob),
            dir: None,
            cols,
            kind_bms,
            flag_bms,
        };
        Ok((g, stats))
    }

    /// Rebuild the adjacency with additional (derived) edges, keeping all node
    /// columns. Used by post-processing passes that need the built graph to
    /// compute new edges (e.g. ADCS ESC edges over expanded group membership).
    pub fn with_extra_edges(self, extra: Vec<Edge>) -> Result<Graph> {
        if extra.is_empty() {
            return Ok(self);
        }
        let n = self.node_count();
        let existing: Vec<Edge> = (0..n as u32)
            .into_par_iter()
            .flat_map_iter(|u| {
                let (d, k) = self.out_edges(u);
                d.iter().zip(k).map(move |(&v, &k)| Edge::new(u, v, k))
            })
            .collect();
        let (out_off, out_dst, out_kind) = build_csr(n, vec![existing, extra])?;
        let (in_off, in_src, in_kind) = reverse_csr(n, &out_off, &out_dst, &out_kind);
        let mut g = self;
        g.meta.edge_count = out_dst.len() as u64;
        g.out_off = Buf::Owned(out_off);
        g.out_dst = Buf::Owned(out_dst);
        g.out_kind = Buf::Owned(out_kind);
        g.in_off = Buf::Owned(in_off);
        g.in_src = Buf::Owned(in_src);
        g.in_kind = Buf::Owned(in_kind);
        Ok(g)
    }

    /// Persist the graph to `dir`. `meta.json` is written last so a partially
    /// written directory never opens.
    pub fn write(&self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let _ = fs::remove_file(dir.join("meta.json"));
        // Columns are independent files; write them concurrently.
        let columns: [(&str, &[u8]); 17] = [
            ("name.sorted", bytemuck::cast_slice(&self.name_sorted)),
            ("props.off", bytemuck::cast_slice(&self.props_off)),
            ("props.blob", bytemuck::cast_slice(&self.props_blob)),
            ("nodes.kind", bytemuck::cast_slice(&self.kinds)),
            ("nodes.flags", bytemuck::cast_slice(&self.flags)),
            ("name.off", bytemuck::cast_slice(&self.name_off)),
            ("name.blob", bytemuck::cast_slice(&self.name_blob)),
            ("oid.off", bytemuck::cast_slice(&self.oid_off)),
            ("oid.blob", bytemuck::cast_slice(&self.oid_blob)),
            ("out.off", bytemuck::cast_slice(&self.out_off)),
            ("out.dst", bytemuck::cast_slice(&self.out_dst)),
            ("out.kind", bytemuck::cast_slice(&self.out_kind)),
            ("in.off", bytemuck::cast_slice(&self.in_off)),
            ("in.src", bytemuck::cast_slice(&self.in_src)),
            ("in.kind", bytemuck::cast_slice(&self.in_kind)),
            ("oid.idx", bytemuck::cast_slice(&self.oid_idx)),
            ("name.idx", bytemuck::cast_slice(&self.name_idx)),
        ];
        columns
            .par_iter()
            .try_for_each(|(name, data)| write_pod(dir, name, data))?;
        // Property columns (built now if nothing has filtered yet).
        self.columns().write(dir)?;
        let f = File::create(dir.join("meta.json"))?;
        let mut meta = self.meta.clone();
        meta.format_version = FORMAT_VERSION;
        serde_json::to_writer_pretty(BufWriter::new(f), &meta)?;
        Ok(())
    }

    /// Write only the property columns of an already written graph (e.g. to
    /// upgrade a format-2 directory ahead of time).
    pub fn write_columns(&self, dir: &Path) -> Result<()> {
        self.columns().write(dir)
    }

    /// Memory-map a graph directory written by [`Graph::write`].
    pub fn open(dir: &Path) -> Result<Graph> {
        let meta_path = dir.join("meta.json");
        let meta: GraphMeta = serde_json::from_reader(
            File::open(&meta_path).with_context(|| format!("opening {}", meta_path.display()))?,
        )
        .context("parsing meta.json")?;
        if !(MIN_FORMAT_VERSION..=FORMAT_VERSION).contains(&meta.format_version) {
            bail!("unsupported graph format version {}", meta.format_version);
        }
        let (cols, kind_bms, flag_bms) = empty_caches();
        let g = Graph {
            dir: Some(dir.to_path_buf()),
            cols,
            kind_bms,
            flag_bms,
            kinds: map(dir, "nodes.kind")?,
            flags: map(dir, "nodes.flags")?,
            name_off: map(dir, "name.off")?,
            name_blob: map(dir, "name.blob")?,
            oid_off: map(dir, "oid.off")?,
            oid_blob: map(dir, "oid.blob")?,
            out_off: map(dir, "out.off")?,
            out_dst: map(dir, "out.dst")?,
            out_kind: map(dir, "out.kind")?,
            in_off: map(dir, "in.off")?,
            in_src: map(dir, "in.src")?,
            in_kind: map(dir, "in.kind")?,
            oid_idx: map(dir, "oid.idx")?,
            name_idx: map(dir, "name.idx")?,
            name_sorted: map(dir, "name.sorted")?,
            props_off: map(dir, "props.off")?,
            props_blob: map(dir, "props.blob")?,
            meta,
        };
        g.validate()?;
        Ok(g)
    }

    fn validate(&self) -> Result<()> {
        let n = self.meta.node_count as usize;
        let m = self.meta.edge_count as usize;
        ensure!(self.kinds.len() == n, "nodes.kind length");
        ensure!(self.flags.len() == n, "nodes.flags length");
        ensure!(self.name_sorted.len() == n, "name.sorted length");
        for (name, off, blob_len) in [
            ("name.off", &self.name_off, self.name_blob.len()),
            ("oid.off", &self.oid_off, self.oid_blob.len()),
            ("props.off", &self.props_off, self.props_blob.len()),
        ] {
            ensure!(off.len() == n + 1, "{name} length");
            ensure!(off[n] as usize <= blob_len, "{name} exceeds blob");
        }
        ensure!(
            self.out_off.len() == n + 1 && self.out_off[n] as usize == m,
            "out.off"
        );
        ensure!(
            self.in_off.len() == n + 1 && self.in_off[n] as usize == m,
            "in.off"
        );
        ensure!(
            self.out_dst.len() == m && self.out_kind.len() == m,
            "out edge columns"
        );
        ensure!(
            self.in_src.len() == m && self.in_kind.len() == m,
            "in edge columns"
        );
        ensure!(
            self.meta.edge_kinds.len() == self.meta.traversable.len(),
            "edge kind table"
        );
        Ok(())
    }

    // ---- accessors -------------------------------------------------------

    pub fn meta(&self) -> &GraphMeta {
        &self.meta
    }
    /// Attach ingest provenance, written to `meta.json` by [`Graph::write`].
    pub fn set_ingest_meta(&mut self, v: serde_json::Value) {
        self.meta.ingest = Some(v);
    }
    #[inline]
    pub fn node_count(&self) -> usize {
        self.kinds.len()
    }
    #[inline]
    pub fn edge_count(&self) -> usize {
        self.out_dst.len()
    }
    /// Built-in kind; custom (OpenGraph) kinds are `Unknown` here, so
    /// analysis written for built-in kinds treats them as generic nodes.
    #[inline]
    pub fn kind(&self, id: u32) -> NodeKind {
        NodeKind::from_u8(self.kinds[id as usize])
    }
    /// Raw stored kind: a [`NodeKind`] discriminant, or
    /// `CUSTOM_KIND_BASE + i` for custom kind `i`.
    #[inline]
    pub fn kind_raw(&self, id: u32) -> u8 {
        self.kinds[id as usize]
    }
    /// Kind name, custom kinds included.
    pub fn kind_name(&self, id: u32) -> &str {
        self.raw_kind_name(self.kinds[id as usize])
    }
    /// Name of a raw kind value.
    pub fn raw_kind_name(&self, raw: u8) -> &str {
        match raw.checked_sub(ch_model::CUSTOM_KIND_BASE).and_then(|i| self.meta.node_kinds.get(i as usize)) {
            Some(n) => n,
            None => NodeKind::from_u8(raw).as_str(),
        }
    }
    /// Custom node kind names (index `i` ↔ raw kind `CUSTOM_KIND_BASE + i`).
    pub fn custom_node_kinds(&self) -> &[String] {
        &self.meta.node_kinds
    }
    /// Raw kind of a kind name (built-in or custom, case-insensitive).
    pub fn raw_kind_of(&self, name: &str) -> Option<u8> {
        if let Some(i) = self.meta.node_kinds.iter().position(|k| k.eq_ignore_ascii_case(name)) {
            return Some(ch_model::CUSTOM_KIND_BASE + i as u8);
        }
        match NodeKind::parse(name) {
            NodeKind::Unknown if !name.eq_ignore_ascii_case("unknown") => None,
            k => Some(k as u8),
        }
    }
    pub fn kinds(&self) -> &[u8] {
        &self.kinds
    }
    #[inline]
    pub fn flags(&self, id: u32) -> u32 {
        self.flags[id as usize]
    }
    #[inline]
    pub fn has_flag(&self, id: u32, f: u32) -> bool {
        self.flags[id as usize] & f != 0
    }
    pub fn oid(&self, id: u32) -> &str {
        str_at(&self.oid_off, &self.oid_blob, id)
    }
    fn raw_name(&self, id: u32) -> &str {
        str_at(&self.name_off, &self.name_blob, id)
    }
    /// Display name; falls back to the object identifier.
    pub fn name(&self, id: u32) -> &str {
        let n = self.raw_name(id);
        if n.is_empty() {
            self.oid(id)
        } else {
            n
        }
    }
    #[inline]
    pub fn out_edges(&self, u: u32) -> (&[u32], &[u16]) {
        let s = self.out_off[u as usize] as usize;
        let e = self.out_off[u as usize + 1] as usize;
        (&self.out_dst[s..e], &self.out_kind[s..e])
    }
    #[inline]
    pub fn in_edges(&self, v: u32) -> (&[u32], &[u16]) {
        let s = self.in_off[v as usize] as usize;
        let e = self.in_off[v as usize + 1] as usize;
        (&self.in_src[s..e], &self.in_kind[s..e])
    }
    #[inline]
    pub fn out_degree(&self, u: u32) -> usize {
        (self.out_off[u as usize + 1] - self.out_off[u as usize]) as usize
    }
    #[inline]
    pub fn in_degree(&self, v: u32) -> usize {
        (self.in_off[v as usize + 1] - self.in_off[v as usize]) as usize
    }
    /// All outbound edge kinds, in CSR order (for statistics).
    pub fn all_edge_kinds(&self) -> &[u16] {
        &self.out_kind
    }
    pub fn edge_kind_count(&self) -> usize {
        self.meta.edge_kinds.len()
    }
    pub fn edge_kind_name(&self, k: u16) -> &str {
        self.meta
            .edge_kinds
            .get(k as usize)
            .map(|s| s.as_str())
            .unwrap_or("?")
    }
    pub fn edge_kind_id(&self, name: &str) -> Option<u16> {
        self.meta
            .edge_kinds
            .iter()
            .position(|k| k.eq_ignore_ascii_case(name))
            .map(|p| p as u16)
    }
    #[inline]
    pub fn is_traversable(&self, k: u16) -> bool {
        self.meta
            .traversable
            .get(k as usize)
            .copied()
            .unwrap_or(false)
    }

    /// Resolve an object identifier (SID/GUID) or a name, case-insensitively.
    pub fn lookup(&self, query: &str) -> Option<u32> {
        let key = query.trim().to_ascii_uppercase();
        find(&self.oid_idx, &key, |id| self.oid(id))
            .or_else(|| find(&self.name_idx, &key, |id| self.raw_name(id)))
    }

    pub fn nodes_with_flag(&self, f: u32) -> Vec<u32> {
        (0..self.node_count() as u32)
            .into_par_iter()
            .filter(|&id| self.flags[id as usize] & f != 0)
            .collect()
    }

    /// Raw collector properties of a node as a JSON object string (`""` if none).
    pub fn props(&self, id: u32) -> &str {
        str_at(&self.props_off, &self.props_blob, id)
    }

    /// Nodes whose display name starts with `prefix` (case-insensitive), in
    /// name order, optionally filtered by kind.
    pub fn search_prefix(&self, prefix: &str, kind: Option<NodeKind>, limit: usize) -> Vec<u32> {
        self.search_prefix_raw(prefix, kind.map(|k| k as u8), limit)
    }

    /// [`Graph::search_prefix`] with a raw kind filter (custom kinds included).
    pub fn search_prefix_raw(&self, prefix: &str, kind: Option<u8>, limit: usize) -> Vec<u32> {
        let p = prefix.trim().to_ascii_uppercase();
        let sorted: &[u32] = &self.name_sorted;
        let start = sorted.partition_point(|&id| self.name(id) < p.as_str());
        sorted[start..]
            .iter()
            .copied()
            .take_while(|&id| self.name(id).starts_with(p.as_str()))
            .filter(|&id| kind.is_none_or(|k| self.kinds[id as usize] == k))
            .take(limit)
            .collect()
    }

    /// Set or clear a flag bit in memory. The flag column becomes an owned copy
    /// on first write; the on-disk graph is never modified.
    pub fn set_flag(&mut self, id: u32, f: u32, on: bool) {
        if let Buf::Mapped(..) = self.flags {
            self.flags = Buf::Owned(self.flags.to_vec());
        }
        if let Buf::Owned(v) = &mut self.flags {
            if on {
                v[id as usize] |= f;
            } else {
                v[id as usize] &= !f;
            }
        }
        for (bit, cache) in self.flag_bms.iter_mut().enumerate() {
            if f & (1 << bit) != 0 {
                *cache = OnceLock::new();
            }
        }
    }

    pub fn flags_column(&self) -> &[u32] {
        &self.flags
    }
}

fn str_at<'a>(off: &'a [u64], blob: &'a [u8], id: u32) -> &'a str {
    let s = off[id as usize] as usize;
    let e = off[id as usize + 1] as usize;
    blob.get(s..e)
        .and_then(|b| std::str::from_utf8(b).ok())
        .unwrap_or("")
}

fn find<'a>(idx: &[IdxEntry], key: &str, get: impl Fn(u32) -> &'a str) -> Option<u32> {
    let h = fnv1a64(key.as_bytes());
    let start = idx.partition_point(|e| e.hash < h);
    idx[start..]
        .iter()
        .take_while(|e| e.hash == h)
        .find(|e| get(e.id) == key)
        .map(|e| e.id)
}

/// Every id whose string equals `key` (duplicates included).
fn find_all<'a>(idx: &[IdxEntry], key: &str, get: impl Fn(u32) -> &'a str, mut f: impl FnMut(u32)) {
    let h = fnv1a64(key.as_bytes());
    let start = idx.partition_point(|e| e.hash < h);
    for e in idx[start..].iter().take_while(|e| e.hash == h) {
        if get(e.id) == key {
            f(e.id);
        }
    }
}

fn blob<'a>(strings: impl Iterator<Item = &'a str>) -> (Vec<u64>, Vec<u8>) {
    let mut off = vec![0u64];
    let mut data = Vec::new();
    for s in strings {
        data.extend_from_slice(s.as_bytes());
        off.push(data.len() as u64);
    }
    (off, data)
}

fn build_index<T: Sync>(items: &[T], get: impl Fn(&T) -> &str + Sync) -> Vec<IdxEntry> {
    let mut idx: Vec<IdxEntry> = items
        .par_iter()
        .enumerate()
        .filter_map(|(i, it)| {
            let s = get(it);
            (!s.is_empty()).then(|| IdxEntry {
                hash: fnv1a64(s.as_bytes()),
                id: i as u32,
                pad: 0,
            })
        })
        .collect();
    idx.par_sort_unstable_by_key(|e| (e.hash, e.id));
    idx
}

#[inline]
fn pack(dst: u32, kind: u16) -> u64 {
    ((dst as u64) << 16) | kind as u64
}

/// Raw pointer that may be shared across threads for disjoint parallel writes.
#[derive(Clone, Copy)]
struct SyncPtr(*mut u64);
unsafe impl Send for SyncPtr {}
unsafe impl Sync for SyncPtr {}
impl SyncPtr {
    /// # Safety
    /// `i` must be in bounds and written by exactly one thread.
    #[inline]
    unsafe fn write(self, i: usize, v: u64) {
        *self.0.add(i) = v;
    }
}

fn atomic_zeros(n: usize) -> Vec<AtomicU64> {
    (0..n).into_par_iter().map(|_| AtomicU64::new(0)).collect()
}

/// Exclusive prefix sum of atomic counters into CSR offsets; counters are
/// reset to the row start so they can serve as scatter cursors.
fn offsets_from_counts(counts: &[AtomicU64]) -> Vec<u64> {
    let n = counts.len();
    let mut off = vec![0u64; n + 1];
    for i in 0..n {
        off[i + 1] = off[i] + counts[i].load(Relaxed);
    }
    counts
        .par_iter()
        .enumerate()
        .for_each(|(i, c)| c.store(off[i], Relaxed));
    off
}

/// Parallel counting sort of the edge list into CSR (atomic degree counts and
/// atomic scatter cursors), then sort + dedup each adjacency list in parallel.
/// Peak memory ≈ raw edges (12 B/edge) + packed adjacency (8 B/edge).
fn build_csr(n: usize, chunks: Vec<Vec<Edge>>) -> Result<(Vec<u64>, Vec<u32>, Vec<u16>)> {
    let cur = atomic_zeros(n);
    chunks.par_iter().try_for_each(|c| -> Result<()> {
        for e in c {
            ensure!(
                (e.src as usize) < n && (e.dst as usize) < n,
                "edge {}->{} references a node outside 0..{n}",
                e.src,
                e.dst
            );
            cur[e.src as usize].fetch_add(1, Relaxed);
        }
        Ok(())
    })?;
    let off = offsets_from_counts(&cur);
    let m = off[n] as usize;
    let mut packed = vec![0u64; m];
    let ptr = SyncPtr(packed.as_mut_ptr());
    chunks.into_par_iter().for_each(|c| {
        for e in &c {
            let p = cur[e.src as usize].fetch_add(1, Relaxed) as usize;
            // SAFETY: fetch_add hands every edge a unique slot within its row.
            unsafe { ptr.write(p, pack(e.dst, e.kind)) };
        }
    });
    drop(cur);

    let uniq = sort_rows(&off, &mut packed);

    // Compact deduped lists to the front.
    let mut new_off = vec![0u64; n + 1];
    let mut w = 0usize;
    for i in 0..n {
        let s = off[i] as usize;
        let k = uniq[i] as usize;
        if s != w {
            packed.copy_within(s..s + k, w);
        }
        w += k;
        new_off[i + 1] = w as u64;
    }
    drop(off);
    drop(uniq);
    packed.truncate(w);

    let dst: Vec<u32> = packed.par_iter().map(|&p| (p >> 16) as u32).collect();
    let kind: Vec<u16> = packed.par_iter().map(|&p| (p & 0xFFFF) as u16).collect();
    Ok((new_off, dst, kind))
}

/// Sort and dedup every CSR row in place, in parallel over blocks of rows.
/// Returns the deduped length of each row.
fn sort_rows(off: &[u64], packed: &mut [u64]) -> Vec<u64> {
    const BLOCK: usize = 1 << 14;
    let n = off.len() - 1;
    let mut uniq = vec![0u64; n];
    {
        let mut tasks = Vec::with_capacity(n / BLOCK + 1);
        let mut rest: &mut [u64] = packed;
        let mut urest: &mut [u64] = &mut uniq;
        let mut start = 0;
        while start < n {
            let end = (start + BLOCK).min(n);
            let len = (off[end] - off[start]) as usize;
            let (a, b) = std::mem::take(&mut rest).split_at_mut(len);
            rest = b;
            let (ua, ub) = std::mem::take(&mut urest).split_at_mut(end - start);
            urest = ub;
            tasks.push((start, a, ua));
            start = end;
        }
        let off = &off;
        tasks.into_par_iter().for_each(|(start, adj, u)| {
            let base = off[start];
            for (i, slot) in u.iter_mut().enumerate() {
                let s = (off[start + i] - base) as usize;
                let e = (off[start + i + 1] - base) as usize;
                let list = &mut adj[s..e];
                // Hub rows (e.g. Domain Users' members) would serialise a
                // block; sort them with all cores instead.
                if list.len() >= GIANT_ROW {
                    list.par_sort_unstable();
                } else {
                    list.sort_unstable();
                }
                *slot = dedup_sorted(list) as u64;
            }
        });
    }
    uniq
}

const GIANT_ROW: usize = 1 << 18;

fn dedup_sorted(list: &mut [u64]) -> usize {
    let mut w = 0;
    for r in 0..list.len() {
        if w == 0 || list[r] != list[w - 1] {
            list[w] = list[r];
            w += 1;
        }
    }
    w
}

/// Inbound CSR from the (deduped) outbound CSR, built in parallel. Rows are
/// sorted so the result is deterministic.
fn reverse_csr(n: usize, off: &[u64], dst: &[u32], kind: &[u16]) -> (Vec<u64>, Vec<u32>, Vec<u16>) {
    let m = dst.len();
    let cur = atomic_zeros(n);
    dst.par_iter().for_each(|&d| {
        cur[d as usize].fetch_add(1, Relaxed);
    });
    let ioff = offsets_from_counts(&cur);
    let mut packed = vec![0u64; m];
    let ptr = SyncPtr(packed.as_mut_ptr());
    (0..n).into_par_iter().with_min_len(1 << 12).for_each(|u| {
        for j in off[u] as usize..off[u + 1] as usize {
            let p = cur[dst[j] as usize].fetch_add(1, Relaxed) as usize;
            // SAFETY: fetch_add hands every edge a unique slot within its row.
            unsafe { ptr.write(p, pack(u as u32, kind[j])) };
        }
    });
    drop(cur);
    sort_rows(&ioff, &mut packed); // rows are already unique; this only orders them
    let src: Vec<u32> = packed.par_iter().map(|&p| (p >> 16) as u32).collect();
    let k: Vec<u16> = packed.par_iter().map(|&p| (p & 0xFFFF) as u16).collect();
    (ioff, src, k)
}

fn write_pod<T: Pod>(dir: &Path, name: &str, data: &[T]) -> Result<()> {
    let path = dir.join(name);
    let f = File::create(&path).with_context(|| format!("creating {}", path.display()))?;
    let mut w = BufWriter::with_capacity(1 << 20, f);
    w.write_all(bytemuck::cast_slice(data))?;
    w.flush()?;
    Ok(())
}

fn map<T: Pod>(dir: &Path, name: &str) -> Result<Buf<T>> {
    let path = dir.join(name);
    let f = File::open(&path).with_context(|| format!("opening {}", path.display()))?;
    if f.metadata()?.len() == 0 {
        return Ok(Buf::Owned(Vec::new()));
    }
    // SAFETY: the file is opened read-only and CopperHound never mutates graph
    // files in place; concurrent external modification is unsupported.
    let m = unsafe { Mmap::map(&f) }.with_context(|| format!("mapping {}", path.display()))?;
    bytemuck::try_cast_slice::<u8, T>(&m)
        .map_err(|e| anyhow::anyhow!("{}: {e:?}", path.display()))?;
    Ok(Buf::Mapped(m, PhantomData))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts() -> GraphParts {
        let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
        GraphParts {
            kinds: vec![1, 2, 3],
            flags: vec![0, 0, 0],
            names: vec![Some("ALICE@X".into()), None, Some("PC1.X".into())],
            oids: vec!["S-1".into(), "S-2".into(), "S-3".into()],
            props: vec![Some(r#"{"name":"ALICE@X"}"#.into()), None, None],
            edge_chunks: vec![
                vec![Edge::new(0, 1, 0), Edge::new(0, 1, 0), Edge::new(1, 2, 1)],
                vec![Edge::new(0, 2, 2)],
            ],
            edge_kinds,
            traversable,
            node_kinds: Vec::new(),
        }
    }

    /// Zero nodes (e.g. an ingest of empty collector files) round-trips:
    /// empty column files map to dangling pointers that must not be cast.
    #[test]
    fn empty_graph_round_trip() {
        let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
        let parts = GraphParts {
            kinds: vec![],
            flags: vec![],
            names: vec![],
            oids: vec![],
            props: vec![],
            edge_chunks: vec![],
            edge_kinds,
            traversable,
            node_kinds: Vec::new(),
        };
        let (g, _) = Graph::build(parts).unwrap();
        let dir = std::env::temp_dir().join(format!("ch-empty-graph-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        g.write(&dir).unwrap();
        let g = Graph::open(&dir).unwrap();
        assert_eq!((g.node_count(), g.edge_count()), (0, 0));
        assert!(g.kinds().is_empty() && g.search_prefix("a", None, 5).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_dedups_and_reverses() {
        let (g, stats) = Graph::build(parts()).unwrap();
        assert_eq!(stats.raw_edges, 4);
        assert_eq!(g.edge_count(), 3);
        assert_eq!(g.out_edges(0).0, &[1, 2]);
        assert_eq!(g.in_edges(2).0, &[0, 1]);
        assert_eq!(g.name(1), "S-2");
    }

    #[test]
    fn write_open_roundtrip() {
        let dir = std::env::temp_dir().join(format!("ch-store-test-{}", std::process::id()));
        let (g, _) = Graph::build(parts()).unwrap();
        g.write(&dir).unwrap();
        let h = Graph::open(&dir).unwrap();
        assert_eq!(h.edge_count(), 3);
        assert_eq!(h.lookup("alice@x"), Some(0));
        assert_eq!(h.lookup("s-3"), Some(2));
        assert_eq!(h.lookup("nobody"), None);
        assert_eq!(h.search_prefix("al", None, 10), vec![0]);
        assert_eq!(h.search_prefix("", Some(NodeKind::Computer), 10), vec![2]);
        assert_eq!(h.props(0), r#"{"name":"ALICE@X"}"#);
        let mut h = h;
        h.set_flag(1, ch_model::flags::OWNED, true);
        assert!(h.has_flag(1, ch_model::flags::OWNED));
        drop(h);
        let _ = fs::remove_dir_all(&dir);
    }
}
