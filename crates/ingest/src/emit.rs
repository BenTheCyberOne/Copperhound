//! Shared ingest state (identifier interner, dynamic edge kinds) and the
//! per-batch [`Emitter`] that parsers write nodes and edges into.

use ahash::{AHashMap, RandomState};
use parking_lot::Mutex;
use ch_model::{builtin_edge_kind, NodeKind, BUILTIN_EDGE_KINDS};
use ch_store::Edge;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

const SHARDS: usize = 256;

/// Concurrent string → dense `u32` interner, sharded to keep lock contention low.
pub struct Interner {
    shards: Vec<Mutex<HashMap<Box<str>, u32, RandomState>>>,
    next: AtomicU32,
    shard_hasher: RandomState,
}

impl Interner {
    pub fn new() -> Self {
        Self {
            shards: (0..SHARDS)
                .map(|_| Mutex::new(HashMap::with_hasher(RandomState::new())))
                .collect(),
            next: AtomicU32::new(0),
            shard_hasher: RandomState::new(),
        }
    }

    #[inline]
    pub fn intern(&self, s: &str) -> u32 {
        let h = self.shard_hasher.hash_one(s);
        let shard = &self.shards[(h >> 56) as usize % SHARDS];
        let mut g = shard.lock();
        if let Some(&id) = g.get(s) {
            return id;
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        assert!(id < u32::MAX - 1, "node id space exhausted");
        g.insert(s.into(), id);
        id
    }

    pub fn get(&self, s: &str) -> Option<u32> {
        let h = self.shard_hasher.hash_one(s);
        self.shards[(h >> 56) as usize % SHARDS]
            .lock()
            .get(s)
            .copied()
    }

    pub fn len(&self) -> usize {
        self.next.load(Ordering::Relaxed) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Consume the interner, returning identifiers indexed by id.
    pub fn into_oids(self) -> Vec<String> {
        let n = self.len();
        let mut v = vec![String::new(); n];
        for shard in self.shards {
            for (k, id) in shard.into_inner() {
                v[id as usize] = k.into_string();
            }
        }
        v
    }
}

impl Default for Interner {
    fn default() -> Self {
        Self::new()
    }
}

/// Edge kind registry: built-ins resolve lock-free, unknown collector right
/// names are registered on first sight.
pub struct DynKinds {
    /// Names in registration order, and their index.
    extra: Mutex<(Vec<String>, AHashMap<String, u16>)>,
}

/// Returned by [`DynKinds::get`] when the registry is full; edges of this
/// kind are dropped by the emitter (never turned into another kind).
pub const KIND_DROPPED: u16 = u16::MAX;

impl DynKinds {
    pub fn new() -> Self {
        Self {
            extra: Mutex::new((Vec::new(), AHashMap::new())),
        }
    }

    #[inline]
    pub fn get(&self, name: &str) -> u16 {
        if let Some(k) = builtin_edge_kind(name) {
            return k;
        }
        let mut guard = self.extra.lock();
        let (extra, index) = &mut *guard;
        if let Some(&k) = index.get(name) {
            return k;
        }
        let base = BUILTIN_EDGE_KINDS.len();
        if base + extra.len() >= KIND_DROPPED as usize {
            return KIND_DROPPED;
        }
        let k = (base + extra.len()) as u16;
        extra.push(name.to_string());
        index.insert(name.to_string(), k);
        k
    }

    /// Kind name and traversability tables. Collector-specific kinds are
    /// registered in first-sight order, which depends on thread scheduling;
    /// they are numbered here in name order instead, so the returned `remap`
    /// (old id → new id, identity for built-ins) must be applied to every
    /// edge emitted with [`DynKinds::get`].
    pub fn into_tables(self) -> (Vec<String>, Vec<bool>, Vec<u16>) {
        let (mut names, mut trav) = ch_model::builtin_kind_tables();
        let base = names.len();
        let extra = self.extra.into_inner().0;
        let mut order: Vec<usize> = (0..extra.len()).collect();
        order.sort_unstable_by(|&a, &b| extra[a].cmp(&extra[b]));
        let mut remap: Vec<u16> = (0..(base + extra.len()) as u16).collect();
        for (new, &old) in order.iter().enumerate() {
            remap[base + old] = (base + new) as u16;
            names.push(extra[old].clone());
            trav.push(true);
        }
        (names, trav, remap)
    }
}

impl Default for DynKinds {
    fn default() -> Self {
        Self::new()
    }
}

/// Node kind registry for custom (OpenGraph) kinds: built-in names resolve to
/// their [`NodeKind`]; other names get raw kinds from
/// [`ch_model::CUSTOM_KIND_BASE`] up, numbered by name in [`DynNodeKinds::into_tables`].
pub struct DynNodeKinds {
    names: Mutex<Vec<String>>,
}

impl DynNodeKinds {
    pub fn new() -> Self {
        Self { names: Mutex::new(Vec::new()) }
    }

    /// Built-in kind whose name equals `name` (case-insensitive, no plurals).
    pub fn builtin(name: &str) -> Option<NodeKind> {
        NodeKind::ALL.iter().copied().find(|k| *k != NodeKind::Unknown && k.as_str().eq_ignore_ascii_case(name))
    }

    /// Raw kind for `name`, registering custom kinds on first sight. Empty
    /// names and a full registry give `Unknown`.
    pub fn get(&self, name: &str) -> u8 {
        let name = name.trim();
        if name.is_empty() || name.eq_ignore_ascii_case("unknown") {
            return NodeKind::Unknown as u8;
        }
        if let Some(k) = Self::builtin(name) {
            return k as u8;
        }
        let mut names = self.names.lock();
        if let Some(p) = names.iter().position(|e| e.eq_ignore_ascii_case(name)) {
            return ch_model::CUSTOM_KIND_BASE + p as u8;
        }
        if names.len() >= ch_model::MAX_CUSTOM_KINDS {
            return NodeKind::Unknown as u8;
        }
        names.push(name.to_string());
        ch_model::CUSTOM_KIND_BASE + (names.len() - 1) as u8
    }

    /// Custom kind names in name order and the raw-kind remap (identity for
    /// built-ins) to apply to every kind handed out by [`DynNodeKinds::get`].
    pub fn into_tables(self) -> (Vec<String>, [u8; 256]) {
        let names = self.names.into_inner();
        let mut order: Vec<usize> = (0..names.len()).collect();
        order.sort_unstable_by(|&a, &b| names[a].cmp(&names[b]));
        let mut remap = [0u8; 256];
        for (i, r) in remap.iter_mut().enumerate() {
            *r = i as u8;
        }
        let base = ch_model::CUSTOM_KIND_BASE as usize;
        let mut sorted = Vec::with_capacity(names.len());
        for (new, &old) in order.iter().enumerate() {
            remap[base + old] = (base + new) as u8;
            sorted.push(names[old].clone());
        }
        (sorted, remap)
    }
}

impl Default for DynNodeKinds {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Shared {
    pub interner: Interner,
    pub kinds: DynKinds,
    pub node_kinds: DynNodeKinds,
    /// Keep each record's raw properties JSON for the property column.
    pub keep_props: bool,
    /// Record edge ownership and claims for collection-aware merging
    /// ([`crate::merge`]). Off for the `union` merge policy.
    pub track: bool,
}

impl Shared {
    pub fn new(keep_props: bool) -> Self {
        Self { interner: Interner::new(), kinds: DynKinds::new(), node_kinds: DynNodeKinds::new(), keep_props, track: true }
    }
}

/// Node attribute update. `strength`: 3 = own record with known kind,
/// 2 = own record whose kind is resolved after the file finishes, 1 = hint.
pub struct NodeUpdate {
    pub id: u32,
    pub kind: u8,
    pub strength: u8,
    pub flags: u32,
    pub name: Option<Box<str>>,
    /// Raw properties JSON object (own records only).
    pub props: Option<Box<str>>,
    /// Merge these properties key by key into the node's other records
    /// instead of replacing them (OpenGraph enrichment of existing objects).
    pub merge: bool,
}

/// An edge where one endpoint is a distinguished name to resolve after all
/// files are parsed (ldapdomaindump references objects by DN).
pub struct DnEdge {
    pub fixed: u32,
    /// Ownership tag of the resolved edge (see [`own_pad`]).
    pub pad: u16,
    pub dn: Box<str>,
    pub kind: u16,
    /// `true`: fixed → dn. `false`: dn → fixed.
    pub fixed_is_src: bool,
    /// Create a placeholder node if the DN is never seen as an object.
    pub create: Option<NodeKind>,
}

/// One end of an edge addressed by object id or by display name (OpenGraph
/// `match_by: "name"`), resolved after all files are parsed.
pub enum EndRef {
    Id(u32),
    /// Upper-cased name and an optional kind filter.
    Name(Box<str>, Option<Box<str>>),
}

pub struct NameEdge {
    pub src: EndRef,
    pub dst: EndRef,
    pub kind: u16,
}

#[derive(Default)]
pub struct Emitted {
    /// Edges with at least one end addressed by name.
    pub name_edges: Vec<NameEdge>,
    pub edges: Vec<Edge>,
    pub updates: Vec<NodeUpdate>,
    /// Indices into `updates` whose kind awaits file-level resolution.
    pub pending: Vec<u32>,
    pub hints: Vec<(u32, u8)>,
    pub dn_aliases: Vec<(Box<str>, u32)>,
    pub dn_edges: Vec<DnEdge>,
    /// `(owner, category mask)`: the record of `owner` is authoritative for
    /// these edge categories (see [`crate::merge`]).
    pub claims: Vec<(u32, u32)>,
    /// Input source (index into the ingest source list).
    pub source: u32,
    /// Latest object modification time seen (LDAP `whenChanged`, unix secs).
    pub max_changed: Option<i64>,
    /// Own records emitted.
    pub objects: u64,
    /// Domains / tenants named by the records (bounded).
    pub domains: Vec<Box<str>>,
    pub records: u64,
    pub errors: u64,
    pub first_error: Option<String>,
}

pub struct Emitter<'a> {
    shared: &'a Shared,
    file_kind: Option<NodeKind>,
    hints: AHashMap<u32, u8>,
    /// Batch-local identifier cache. Collector data references a handful of
    /// objects (Domain Admins, Domain Users, the domain) from nearly every
    /// record; without this every thread would serialise on those shards.
    cache: AHashMap<Box<str>, u32>,
    /// Current ownership section `(owner, category)`; edges emitted while it
    /// is set are tagged with it. `None`: edges are unowned (always kept).
    section: Option<(u32, u8)>,
    pub out: Emitted,
}

/// Edge ownership tag kept in [`Edge::pad`] during ingest (the graph build
/// ignores `pad`): bits 0–1 say which endpoint is the owning record's object
/// (0 none, 1 src, 2 dst), bits 2–7 the edge category ([`crate::merge::cat`]).
#[inline]
pub fn own_pad(owner: u32, cat: u8, src: u32, dst: u32) -> u16 {
    let side = if src == owner {
        1
    } else if dst == owner {
        2
    } else {
        return 0;
    };
    side | (cat as u16) << 2
}

/// Max domains recorded per batch for the source manifest.
const MAX_DOMAINS: usize = 64;

#[inline]
pub fn upper(s: &str) -> Cow<'_, str> {
    if s.bytes().any(|c| c.is_ascii_lowercase()) {
        Cow::Owned(s.to_ascii_uppercase())
    } else {
        Cow::Borrowed(s)
    }
}

impl<'a> Emitter<'a> {
    pub fn new(shared: &'a Shared, file_kind: Option<NodeKind>) -> Self {
        Self {
            shared,
            file_kind,
            hints: AHashMap::new(),
            cache: AHashMap::new(),
            section: None,
            out: Emitted::default(),
        }
    }

    /// Start a new record: edges are unowned until [`Emitter::scope`].
    #[inline]
    pub fn begin(&mut self) {
        self.section = None;
    }

    /// Edges emitted from now on belong to `owner`'s record, category `cat`.
    /// `claim`: this record carries the complete data for that category
    /// (e.g. the `Aces` array is present), so a newer claim supersedes older
    /// records' edges of the same owner and category.
    #[inline]
    pub fn scope(&mut self, owner: u32, cat: u8, claim: bool) {
        if !self.shared.track {
            return;
        }
        self.section = Some((owner, cat));
        if claim {
            self.claim(owner, cat);
        }
    }

    /// Claim a category without changing the current section.
    #[inline]
    pub fn claim(&mut self, owner: u32, cat: u8) {
        if !self.shared.track {
            return;
        }
        let bit = 1u32 << cat;
        match self.out.claims.last_mut() {
            Some((o, m)) if *o == owner => *m |= bit,
            _ => self.out.claims.push((owner, bit)),
        }
    }

    /// Edges emitted from now on are unowned (never superseded).
    #[inline]
    pub fn unscoped(&mut self) {
        self.section = None;
    }

    /// Record a domain / tenant name for the source manifest.
    pub fn note_domain(&mut self, d: &str) {
        let d = d.trim();
        if d.is_empty() || self.out.domains.len() >= MAX_DOMAINS {
            return;
        }
        if !self.out.domains.iter().any(|x| x.eq_ignore_ascii_case(d)) {
            self.out.domains.push(d.to_ascii_uppercase().into_boxed_str());
        }
    }

    /// Record an object modification time (unix seconds).
    #[inline]
    pub fn note_changed(&mut self, t: i64) {
        self.out.max_changed = Some(self.out.max_changed.map_or(t, |m| m.max(t)));
    }

    /// Kind of the records in the file being parsed, if known.
    pub fn file_kind(&self) -> Option<NodeKind> {
        self.file_kind
    }

    pub fn keep_props(&self) -> bool {
        self.shared.keep_props
    }

    #[inline]
    pub fn id(&mut self, oid: &str) -> Option<u32> {
        let oid = oid.trim();
        if oid.is_empty() {
            return None;
        }
        let key = upper(oid);
        if let Some(&id) = self.cache.get(key.as_ref()) {
            return Some(id);
        }
        let id = self.shared.interner.intern(&key);
        self.cache.insert(key.into_owned().into_boxed_str(), id);
        Some(id)
    }

    /// Register the record's own node. `kind` overrides the file kind.
    /// `props` is the record's raw properties JSON object.
    pub fn own(
        &mut self,
        oid: &str,
        kind: Option<NodeKind>,
        name: Option<&str>,
        flags: u32,
        props: Option<Box<str>>,
    ) -> Option<u32> {
        let id = self.id(oid)?;
        let (kind, strength) = match kind.or(self.file_kind) {
            Some(k) => (k as u8, 3),
            None => {
                self.out.pending.push(self.out.updates.len() as u32);
                (NodeKind::Unknown as u8, 2)
            }
        };
        let name = name
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(|n| upper(n).into_owned().into_boxed_str());
        let props = props.filter(|_| self.shared.keep_props);
        self.out.objects += 1;
        self.out.updates.push(NodeUpdate {
            id,
            kind,
            strength,
            flags,
            name,
            props,
            merge: false,
        });
        Some(id)
    }

    /// Register the record's own node with a raw kind (custom kinds, see
    /// [`DynNodeKinds`]).
    pub fn own_raw(&mut self, oid: &str, kind: u8, name: Option<&str>, flags: u32, props: Option<Box<str>>) -> Option<u32> {
        let id = self.id(oid)?;
        let name = name
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(|n| upper(n).into_owned().into_boxed_str());
        let props = props.filter(|_| self.shared.keep_props);
        self.out.objects += 1;
        self.out.updates.push(NodeUpdate { id, kind, strength: 3, flags, name, props, merge: true });
        Some(id)
    }

    /// Raw kind for a kind name (registers custom kinds).
    pub fn node_kind_raw(&self, name: &str) -> u8 {
        self.shared.node_kinds.get(name)
    }

    /// Reference with a raw kind hint (`0` = none).
    pub fn hint_raw(&mut self, oid: &str, kind: u8) -> Option<u32> {
        let id = self.id(oid)?;
        if kind != 0 {
            self.hints.entry(id).or_insert(kind);
        }
        Some(id)
    }

    /// Edge with an end addressed by name.
    pub fn name_edge(&mut self, src: EndRef, dst: EndRef, kind: u16) {
        if kind == KIND_DROPPED {
            return self.kind_dropped();
        }
        self.out.name_edges.push(NameEdge { src, dst, kind });
    }

    #[cold]
    fn kind_dropped(&mut self) {
        self.error(|| format!("more than {} distinct relationship kinds: further kinds are dropped", KIND_DROPPED - 1));
    }

    /// Reference to another object, with an optional kind hint.
    #[inline]
    pub fn hint(&mut self, oid: &str, kind: Option<NodeKind>) -> Option<u32> {
        let id = self.id(oid)?;
        if let Some(k) = kind.filter(|k| *k != NodeKind::Unknown) {
            self.hints.entry(id).or_insert(k as u8);
        }
        Some(id)
    }

    #[inline]
    pub fn hint_str(&mut self, oid: &str, ty: Option<&str>) -> Option<u32> {
        self.hint(oid, ty.map(NodeKind::parse))
    }

    /// Reference that also carries a display name (e.g. trust targets).
    pub fn hint_named(&mut self, oid: &str, kind: NodeKind, name: Option<&str>) -> Option<u32> {
        let id = self.id(oid)?;
        let name = name
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(|n| upper(n).into_owned().into_boxed_str());
        self.out.updates.push(NodeUpdate {
            id,
            kind: kind as u8,
            strength: 1,
            flags: 0,
            name,
            props: None,
            merge: false,
        });
        Some(id)
    }

    #[inline]
    pub fn edge(&mut self, src: u32, dst: u32, kind: u16) {
        if kind == KIND_DROPPED {
            return self.kind_dropped();
        }
        if src != dst {
            let mut e = Edge::new(src, dst, kind);
            if let Some((owner, cat)) = self.section {
                e.pad = own_pad(owner, cat, src, dst);
            }
            self.out.edges.push(e);
        }
    }

    #[inline]
    pub fn kind_id(&self, right: &str) -> u16 {
        self.shared.kinds.get(right)
    }

    pub fn dn_alias(&mut self, dn: &str, id: u32) {
        let dn = normalize_dn(dn);
        if !dn.is_empty() {
            self.out.dn_aliases.push((dn.into_boxed_str(), id));
        }
    }

    pub fn dn_edge(
        &mut self,
        fixed: u32,
        dn: &str,
        kind: u16,
        fixed_is_src: bool,
        create: Option<NodeKind>,
    ) {
        if kind == KIND_DROPPED {
            return self.kind_dropped();
        }
        let dn = normalize_dn(dn);
        if !dn.is_empty() {
            let pad = match self.section {
                Some((owner, cat)) if owner == fixed => (if fixed_is_src { 1 } else { 2 }) | (cat as u16) << 2,
                _ => 0,
            };
            self.out.dn_edges.push(DnEdge {
                fixed,
                pad,
                dn: dn.into_boxed_str(),
                kind,
                fixed_is_src,
                create,
            });
        }
    }

    pub fn error(&mut self, msg: impl FnOnce() -> String) {
        self.out.errors += 1;
        if self.out.first_error.is_none() {
            self.out.first_error = Some(msg());
        }
    }

    pub fn finish(mut self) -> Emitted {
        self.out.hints = self.hints.into_iter().collect();
        self.out
    }
}

/// Uppercase and drop whitespace around RDN separators so DNs from different
/// tools compare equal.
pub fn normalize_dn(dn: &str) -> String {
    let mut out = String::with_capacity(dn.len());
    for (i, part) in dn.split(',').enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&part.trim().to_ascii_uppercase());
    }
    out
}

/// Parent DN (`CN=a,OU=b,DC=c` → `OU=b,DC=c`), respecting escaped commas.
pub fn parent_dn(dn: &str) -> Option<&str> {
    let b = dn.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b',' => return Some(dn[i + 1..].trim_start()).filter(|p| !p.is_empty()),
            _ => i += 1,
        }
    }
    None
}

/// `DC=contoso,DC=local` components → `CONTOSO.LOCAL`.
pub fn domain_from_dn(dn: &str) -> Option<String> {
    let parts: Vec<String> = dn
        .split(',')
        .filter_map(|p| {
            let p = p.trim();
            (p.len() > 3 && p[..3].eq_ignore_ascii_case("DC=")).then(|| p[3..].to_ascii_uppercase())
        })
        .collect();
    (!parts.is_empty()).then(|| parts.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dn_helpers() {
        assert_eq!(
            normalize_dn("CN=Bob, OU=Staff,DC=contoso,DC=local"),
            "CN=BOB,OU=STAFF,DC=CONTOSO,DC=LOCAL"
        );
        assert_eq!(
            parent_dn("CN=Smith\\, Bob,OU=Staff,DC=x"),
            Some("OU=Staff,DC=x")
        );
        assert_eq!(parent_dn("DC=x"), None);
        assert_eq!(
            domain_from_dn("CN=a,DC=contoso,DC=local").as_deref(),
            Some("CONTOSO.LOCAL")
        );
    }

    #[test]
    fn dynamic_kinds_numbered_by_name() {
        let k = DynKinds::new();
        let base = BUILTIN_EDGE_KINDS.len() as u16;
        let zeta = k.get("ZetaRight");
        let alpha = k.get("AlphaRight");
        assert_eq!((zeta, alpha), (base, base + 1));
        assert_eq!(k.get("MemberOf"), ch_model::ek::MEMBER_OF);
        let (names, trav, remap) = k.into_tables();
        assert_eq!(names[base as usize..], ["AlphaRight".to_string(), "ZetaRight".to_string()]);
        assert_eq!(trav.len(), names.len());
        assert_eq!(remap[zeta as usize], base + 1);
        assert_eq!(remap[alpha as usize], base);
        assert_eq!(remap[ch_model::ek::MEMBER_OF as usize], ch_model::ek::MEMBER_OF);
    }

    #[test]
    fn interner_dense_ids() {
        let i = Interner::new();
        let a = i.intern("A");
        let b = i.intern("B");
        assert_eq!(i.intern("A"), a);
        assert_ne!(a, b);
        assert_eq!(i.into_oids().len(), 2);
    }
}
