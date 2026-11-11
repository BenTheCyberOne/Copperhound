//! Collection-aware merging of parsed records into graph parts.
//!
//! Every input file is a *source* with a collection time (see
//! [`SourceInfo`]). When several sources describe the same object:
//!
//! * **Node attributes** — the record from the newest collection defines the
//!   kind, name and flags; properties are merged key by key, the newest
//!   value winning per key, so fields only an older collector wrote are kept.
//!   Nodes described by more than one source get a `_sources` property (ids
//!   into the source manifest, newest first, at most [`MAX_NODE_SOURCES`]).
//! * **Edges** — parsers tag each edge with the record that *owns* it (an
//!   endpoint of the edge) and an edge category ([`cat`]), and each record
//!   *claims* the categories it carries completely (e.g. a SharpHound record
//!   with an `Aces` array claims [`cat::ACES`]). An owned edge from a source
//!   older than the newest claim of its owner and category is dropped:
//!   ACEs, members, sessions … removed between two collections disappear.
//!   Unowned edges, unclaimed categories and edges of other owners are never
//!   dropped.
//!
//! Records whose collection time is unknown, and records with equal times,
//! merge exactly as with the `union` policy (flags OR'd, last record's
//! properties, all edges kept): ordering is never guessed. With one source,
//! or sources that describe disjoint objects, both policies produce the same
//! graph.

use crate::emit::{DynNodeKinds, Emitted, EndRef, NameEdge, Shared};
use crate::{IngestOptions, IngestReport, MergePolicy};
use ahash::{AHashMap, AHashSet};
use ch_model::{ek, ek_of, flags, is_default_tier0, NodeKind, DOMAIN_CONTROLLERS_SUFFIX};
use ch_store::{Edge, GraphParts};
use rayon::prelude::*;
use serde::Serialize;
use serde_json::{Map, Value};

/// Edge categories (bit positions in a claim mask; at most 32 per family).
/// The AD family (SharpHound, LDIF / AD Explorer, ldapdomaindump) and the
/// Azure family (AzureHound) share bit numbers: an object only ever has
/// records of one family.
pub mod cat {
    // ---- Active Directory
    /// `Aces` (SharpHound), `nTSecurityDescriptor` (LDIF / snapshot).
    pub const ACES: u8 = 0;
    /// Group `Members` / `member`.
    pub const MEMBERS: u8 = 1;
    /// `PrimaryGroupSID` / `primaryGroupID`.
    pub const PRIMARY_GROUP: u8 = 2;
    pub const SESSIONS: u8 = 3;
    pub const PRIV_SESSIONS: u8 = 4;
    pub const REG_SESSIONS: u8 = 5;
    /// Local group results (`LocalAdmins` / `LocalGroups` -544, …).
    pub const LOCAL_ADMINS: u8 = 6;
    pub const LOCAL_RDP: u8 = 7;
    pub const LOCAL_DCOM: u8 = 8;
    pub const LOCAL_PSREMOTE: u8 = 9;
    pub const DELEGATE: u8 = 10;
    pub const ALLOWED_TO_ACT: u8 = 11;
    pub const SID_HISTORY: u8 = 12;
    /// `ChildObjects` (container → child).
    pub const CHILDREN: u8 = 13;
    /// `ContainedBy` / parent DN (parent → object).
    pub const CONTAINED_BY: u8 = 14;
    /// `Links` / `gPLink`.
    pub const GP_LINKS: u8 = 15;
    pub const TRUSTS: u8 = 16;
    /// Enterprise CA `EnabledCertTemplates` / `certificateTemplates`.
    pub const PUBLISHED_TEMPLATES: u8 = 17;
    /// Enterprise CA `HostingComputer` / `dNSHostName`.
    pub const HOSTING: u8 = 18;
    /// Enterprise CA `CARegistryData.CASecurity`.
    pub const CA_SECURITY: u8 = 19;
    /// Root CA / NTAuth store `DomainSID`.
    pub const DOMAIN_STORE: u8 = 20;
    /// Issuance policy `GroupLink` / `msDS-OIDToGroupLink`.
    pub const GROUP_LINK: u8 = 21;
    /// `msDS-GroupMSAMembership`.
    pub const GMSA: u8 = 22;
    /// ldapdomaindump `memberOf` (object → group).
    pub const MEMBER_OF: u8 = 23;
    // ---- Azure
    /// Edges carried by an object record (tenant containment, resource
    /// group, managed identities, app → service principal).
    pub const AZ_NODE: u8 = 0;
    pub const AZ_MEMBERS: u8 = 1;
    pub const AZ_OWNERS: u8 = 2;
    /// Tenant-scope `AZRoleAssignment` (principal → role).
    pub const AZ_ROLE_ASSIGN: u8 = 3;
    pub const AZ_ROLE_APPROVERS: u8 = 4;
    /// `AZManagementGroupDescendant` (parent → child).
    pub const AZ_PARENT: u8 = 5;
    pub const AZ_FIC: u8 = 6;
    /// `AZ<Resource>RoleAssignment` (Azure RBAC on a resource).
    pub const AZ_RES_RBAC: u8 = 7;
    /// Role-filter records (`AZKeyVaultOwner`, …): `AZ_RBAC_LIST + i` for
    /// the i-th list key in [`super::RBAC_LISTS`].
    pub const AZ_RBAC_LIST: u8 = 8;

    /// Session categories (subject to the session window).
    pub fn is_session(c: u8) -> bool {
        matches!(c, SESSIONS | PRIV_SESSIONS | REG_SESSIONS)
    }
}

/// List keys of AzureHound role-filter records, for [`cat::AZ_RBAC_LIST`].
pub const RBAC_LISTS: &[&str] =
    &["owners", "contributors", "kvContributors", "userAccessAdmins", "avereContributors", "vmContributors", "adminLogins"];

/// Sources listed in a node's `_sources` property.
pub const MAX_NODE_SOURCES: usize = 4;

/// One input file (a zip entry counts as its own source).
#[derive(Debug, Clone, Default, Serialize)]
pub struct SourceInfo {
    /// Index in the manifest; `_sources` node properties refer to it.
    pub id: u32,
    /// Input file relative to the ingested directory (the archive for zip
    /// entries).
    pub file: String,
    /// Entry inside a zip archive.
    pub entry: Option<String>,
    /// `sharphound`, `azurehound`, `ldapdomaindump`, `ldif`, `adexplorer`.
    pub format: &'static str,
    /// Object type of the file (`users`, `computers`, …) when known.
    pub kind: Option<String>,
    /// Domains (AD) and tenants (Azure) named by the records (≤ 64).
    pub domains: Vec<String>,
    /// Collection time (RFC 3339, UTC); `null` when unknown.
    pub collected_at: Option<String>,
    /// Collection time as unix seconds.
    pub collected_at_unix: Option<i64>,
    /// Where the collection time came from: `snapshot` (AD Explorer header),
    /// `meta` (collector `meta` block), `filename` (`YYYYMMDDHHMMSS_` prefix),
    /// `zip-entry` (archive entry time), `whenchanged` (latest LDAP
    /// `whenChanged`, a lower bound).
    pub collected_at_source: Option<&'static str>,
    /// File modification time (informational; never used for ordering).
    pub file_mtime: Option<String>,
    pub records: u64,
    /// Object records (nodes the source describes itself).
    pub objects: u64,
    /// Edges emitted (before stale edges are dropped).
    pub edges: u64,
    /// Object records overridden by a newer source's record of the same object.
    pub superseded_objects: u64,
    /// Edges of this source dropped because a newer record of their owner
    /// claims their category. Includes edges the newer record states again
    /// (those stay in the graph, from the newer source).
    pub superseded_edges: u64,
    pub parse_errors: u64,
    /// Full path of the input file (the archive for zip entries); breaks
    /// ties when ordering sources (see [`canonical_source_order`]).
    #[serde(skip)]
    pub path: String,
    #[serde(skip)]
    pub t_snapshot: Option<i64>,
    #[serde(skip)]
    pub t_meta: Option<i64>,
    #[serde(skip)]
    pub t_name: Option<i64>,
    #[serde(skip)]
    pub t_zip: Option<i64>,
    #[serde(skip)]
    pub t_changed: Option<i64>,
}

impl SourceInfo {
    pub fn new(file: String, entry: Option<String>, format: &'static str) -> Self {
        let base = entry.as_deref().unwrap_or(&file);
        let base = base.rsplit(['/', '\\']).next().unwrap_or(base).to_string();
        SourceInfo { t_name: filename_time(&base), file, entry, format, ..Default::default() }
    }

    /// Pick the collection time from the available evidence. File mtimes are
    /// never used: uploads and copies reset them.
    fn resolve_time(&mut self) {
        let pick = [
            (self.t_snapshot, "snapshot"),
            (self.t_meta, "meta"),
            (self.t_name, "filename"),
            (self.t_zip, "zip-entry"),
            (self.t_changed, "whenchanged"),
        ]
        .into_iter()
        .find_map(|(t, s)| t.map(|t| (t, s)));
        self.collected_at_unix = pick.map(|p| p.0);
        self.collected_at = pick.map(|p| rfc3339(p.0));
        self.collected_at_source = pick.map(|p| p.1);
    }
}

// ------------------------------------------------------------------ times

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Unix seconds → `YYYY-MM-DDTHH:MM:SSZ`.
pub fn rfc3339(t: i64) -> String {
    let (y, m, d) = civil_from_days(t.div_euclid(86_400));
    let s = t.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, s / 60 % 60, s % 60)
}

/// Validated civil date-time → unix seconds.
fn civil_secs(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> Option<i64> {
    let ok = (1990..=2200).contains(&y)
        && (1..=12).contains(&mo)
        && (1..=31).contains(&d)
        && (0..24).contains(&h)
        && (0..60).contains(&mi)
        && (0..61).contains(&s);
    ok.then(|| days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s)
}

/// `YYYYMMDDHHMMSS_…` file name prefix (SharpHound, bloodhound-python, and the
/// documented way to date any input) → unix seconds, read as UTC.
pub fn filename_time(base: &str) -> Option<i64> {
    let b = base.as_bytes();
    if b.len() < 15 || !b[..14].iter().all(u8::is_ascii_digit) || b.get(14).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    let n = |r: std::ops::Range<usize>| base[r].parse::<i64>().ok();
    civil_secs(n(0..4)?, n(4..6)?, n(6..8)?, n(8..10)?, n(10..12)?, n(12..14)?)
}

/// RFC 3339 / ISO 8601 date-time (`2024-01-02T03:04:05[.fff](Z|±hh:mm)`).
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let base = civil_secs(n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?)?;
    let mut rest = &s[19..];
    if let Some(r) = rest.strip_prefix('.') {
        rest = r.trim_start_matches(|c: char| c.is_ascii_digit());
    }
    let off = match rest {
        "" | "Z" | "z" => 0,
        r if r.len() == 6 && (r.starts_with('+') || r.starts_with('-')) && &r[3..4] == ":" => {
            let h = r[1..3].parse::<i64>().ok()?;
            let m = r[4..6].parse::<i64>().ok()?;
            let o = h * 3600 + m * 60;
            if r.starts_with('+') {
                o
            } else {
                -o
            }
        }
        _ => return None,
    };
    Some(base - off)
}

/// Collection time from a collector `meta` block. Standard SharpHound and
/// AzureHound meta blocks carry none; some forks and wrappers add one.
pub fn meta_time(meta: &[u8]) -> Option<i64> {
    let v: Map<String, Value> = serde_json::from_slice(meta).ok()?;
    for (k, v) in &v {
        let k = k.to_ascii_lowercase();
        if !matches!(
            k.as_str(),
            "collected" | "collectedat" | "collected_at" | "collectiontime" | "collection_time" | "timestamp" | "date" | "time"
        ) {
            continue;
        }
        let t = match v {
            Value::String(s) => parse_rfc3339(s).or_else(|| filename_time(&format!("{s}_"))),
            // Unix seconds or milliseconds.
            Value::Number(n) => n.as_i64().map(|x| if x > 100_000_000_000 { x / 1000 } else { x }),
            _ => None,
        };
        if let Some(t) = t.filter(|t| (631_152_000..7_258_118_400).contains(t)) {
            return Some(t);
        }
    }
    None
}

/// GeneralizedTime `YYYYMMDDHHMMSS[.f]Z` → unix seconds.
pub fn gen_time(s: &str) -> Option<i64> {
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (n(0..4)?, n(4..6)?, n(6..8)?, n(8..10)?, n(10..12)?, n(12..14)?);
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se)
}

// ------------------------------------------------------------------ merge

const NONE: u32 = u32::MAX;

pub(crate) fn merge(
    mut outputs: Vec<Emitted>,
    shared: Shared,
    report: &mut IngestReport,
    opts: &IngestOptions,
    sources: &mut [SourceInfo],
) -> GraphParts {
    let newest = opts.merge_policy == MergePolicy::Newest;

    // --- per-source counters and collection times
    for o in &outputs {
        let s = &mut sources[o.source as usize];
        s.records += o.records;
        s.objects += o.objects;
        s.parse_errors += o.errors;
        if let Some(t) = o.max_changed {
            s.t_changed = Some(s.t_changed.map_or(t, |c| c.max(t)));
        }
        for d in &o.domains {
            if s.domains.len() < 64 && !s.domains.iter().any(|x| x.as_str() == &**d) {
                s.domains.push(d.to_string());
            }
        }
    }
    for s in sources.iter_mut() {
        s.resolve_time();
        s.domains.sort();
    }
    // Distinct known collection times → ranks 1.. (0 = unknown).
    let mut times: Vec<i64> = sources.iter().filter_map(|s| s.collected_at_unix).collect();
    times.sort_unstable();
    times.dedup();
    let src_rank: Vec<u32> = sources
        .iter()
        .map(|s| s.collected_at_unix.map_or(0, |t| times.binary_search(&t).map_or(0, |i| i as u32 + 1)))
        .collect();
    let rank_of = |o: &Emitted| src_rank[o.source as usize];

    // --- resolve DN-addressed edges (ldapdomaindump) while the interner is live
    let mut dn_map: AHashMap<Box<str>, u32> = AHashMap::new();
    for o in &mut outputs {
        for (dn, id) in o.dn_aliases.drain(..) {
            dn_map.insert(dn, id);
        }
    }
    let mut dn_created: Vec<(u32, NodeKind)> = Vec::new();
    for o in &mut outputs {
        let dn_edges = std::mem::take(&mut o.dn_edges);
        for e in dn_edges {
            let other = match dn_map.get(&e.dn) {
                Some(&id) => Some(id),
                None => e.create.map(|k| {
                    let id = shared.interner.intern(&e.dn);
                    dn_created.push((id, k));
                    id
                }),
            };
            match other {
                Some(other) => {
                    report.dn_edges_resolved += 1;
                    let (s, d) = if e.fixed_is_src { (e.fixed, other) } else { (other, e.fixed) };
                    if s != d {
                        let mut edge = Edge::new(s, d, e.kind);
                        edge.pad = e.pad;
                        o.edges.push(edge);
                    }
                }
                None => report.dn_edges_unresolved += 1,
            }
        }
    }
    drop(dn_map);
    let name_edges: Vec<NameEdge> = outputs.iter_mut().flat_map(|o| std::mem::take(&mut o.name_edges)).collect();

    let n = shared.interner.len();
    let oids = shared.interner.into_oids();
    let (edge_kinds, traversable, kind_remap) = shared.kinds.into_tables();
    let (node_kinds, node_remap) = shared.node_kinds.into_tables();
    report.custom_node_kinds = node_kinds.len();
    for o in &outputs {
        sources[o.source as usize].edges += o.edges.len() as u64;
    }

    // --- stale owned edges
    if newest && times.len() >= 2 {
        // Newest claim rank per owner, and the categories claimed at it.
        let mut top = vec![0u32; n];
        let mut top_mask = vec![0u32; n];
        for o in &outputs {
            let r = rank_of(o);
            if r == 0 {
                continue;
            }
            for &(owner, m) in &o.claims {
                let i = owner as usize;
                if r > top[i] {
                    top[i] = r;
                    top_mask[i] = m;
                } else if r == top[i] {
                    top_mask[i] |= m;
                }
            }
        }
        let window = opts.session_window_secs as i64;
        let dropped: Vec<(u32, u64)> = outputs
            .par_iter_mut()
            .map(|o| {
                let r = src_rank[o.source as usize];
                if r == 0 {
                    return (o.source, 0);
                }
                let before = o.edges.len();
                o.edges.retain(|e| {
                    let side = e.pad & 3;
                    if side == 0 {
                        return true;
                    }
                    let owner = if side == 1 { e.src } else { e.dst } as usize;
                    let t = top[owner];
                    let c = (e.pad >> 2) as u8;
                    if t <= r || top_mask[owner] >> c & 1 == 0 {
                        return true;
                    }
                    cat::is_session(c) && window > 0 && times[t as usize - 1] - times[r as usize - 1] <= window
                });
                (o.source, (before - o.edges.len()) as u64)
            })
            .collect();
        for (s, d) in dropped {
            sources[s as usize].superseded_edges += d;
        }
    }

    // --- merge node attributes
    let mut kinds = vec![0u8; n];
    let mut strength = vec![0u8; n];
    let mut fl = vec![0u32; n];
    let mut names: Vec<Option<String>> = vec![None; n];
    let mut props: Vec<Option<String>> = vec![None; n];
    let mut name_strength = vec![0u8; n];
    // Nodes with an OpenGraph record: same-collection properties merge key by key.
    let mut merged = vec![false; n];
    let add_layer = |layers: &mut AHashMap<u32, Vec<String>>, props: &mut [Option<String>], id: u32, p: String| {
        match (layers.get_mut(&id), props[id as usize].take()) {
            (Some(l), _) => l.push(p),
            (None, Some(old)) => {
                layers.insert(id, vec![old, p]);
            }
            (None, None) => props[id as usize] = Some(p),
        }
    };
    // Newest-wins state: source / rank of the record that defines the node,
    // whether its properties are a key-level merge, and all sources of nodes
    // described by more than one.
    let (mut attr_src, mut attr_rank) = if newest { (vec![NONE; n], vec![0u32; n]) } else { (Vec::new(), Vec::new()) };
    // Property layers of nodes merged key by key (later layers win), folded
    // in parallel after the loop.
    let mut layers: AHashMap<u32, Vec<String>> = AHashMap::new();
    let mut multi: AHashMap<u32, [u32; MAX_NODE_SOURCES]> = AHashMap::new();
    let mut superseded = vec![0u64; sources.len()];
    let mut chunks: Vec<Vec<Edge>> = Vec::with_capacity(outputs.len());
    for (id, k) in dn_created {
        if strength[id as usize] == 0 && k != NodeKind::Unknown {
            kinds[id as usize] = k as u8;
            strength[id as usize] = 1;
        }
    }
    for o in outputs {
        let src = o.source;
        let r = src_rank[src as usize];
        for u in o.updates {
            let i = u.id as usize;
            let union = |kinds: &mut [u8], strength: &mut [u8], fl: &mut [u32], names: &mut [Option<String>], name_strength: &mut [u8], name: Option<Box<str>>| {
                if u.kind != 0 && u.strength >= strength[i] {
                    kinds[i] = u.kind;
                    strength[i] = u.strength;
                }
                fl[i] |= u.flags;
                if let Some(nm) = name {
                    if u.strength >= name_strength[i] {
                        names[i] = Some(nm.into_string());
                        name_strength[i] = u.strength;
                    }
                }
            };
            // Hints and the union policy: kinds and names by strength, flags
            // OR'd, last record's properties.
            if !newest || u.strength < 2 {
                union(&mut kinds, &mut strength, &mut fl, &mut names, &mut name_strength, u.name);
                merged[i] |= u.merge;
                if let Some(p) = u.props {
                    if merged[i] {
                        add_layer(&mut layers, &mut props, u.id, p.into_string());
                    } else {
                        props[i] = Some(p.into_string());
                    }
                }
                continue;
            }
            let cur = attr_src[i];
            if cur != NONE && cur != src {
                let e = multi.entry(u.id).or_insert([cur, NONE, NONE, NONE]);
                if !e.contains(&src) {
                    // Keep the newest MAX_NODE_SOURCES sources.
                    let slot = e.iter().position(|&s| s == NONE).or_else(|| {
                        let (pos, &oldest) = e.iter().enumerate().min_by_key(|(_, &s)| src_rank[s as usize])?;
                        (src_rank[oldest as usize] < r).then_some(pos)
                    });
                    if let Some(p) = slot {
                        e[p] = src;
                    }
                }
            }
            let cr = attr_rank[i];
            if cur == NONE || r == cr || r == 0 || cr == 0 {
                // First record, same collection, or unknown time: union.
                union(&mut kinds, &mut strength, &mut fl, &mut names, &mut name_strength, u.name);
                merged[i] |= u.merge;
                if let Some(p) = u.props {
                    if merged[i] {
                        add_layer(&mut layers, &mut props, u.id, p.into_string());
                    } else {
                        match layers.get_mut(&u.id) {
                            Some(l) => l.push(p.into_string()),
                            None => props[i] = Some(p.into_string()),
                        }
                    }
                }
                if cur == NONE || r > cr {
                    attr_src[i] = src;
                    attr_rank[i] = r;
                }
            } else if r > cr {
                // Newer collection: its record defines the node.
                if u.kind != 0 && u.strength >= strength[i] {
                    kinds[i] = u.kind;
                    strength[i] = u.strength;
                }
                if let Some(nm) = u.name {
                    names[i] = Some(nm.into_string());
                    name_strength[i] = name_strength[i].max(u.strength);
                }
                fl[i] = u.flags;
                if let Some(p) = u.props {
                    match (layers.get_mut(&u.id), props[i].take()) {
                        (Some(l), _) => l.push(p.into_string()),
                        (None, Some(old)) => {
                            layers.insert(u.id, vec![old, p.into_string()]);
                        }
                        (None, None) => props[i] = Some(p.into_string()),
                    }
                }
                superseded[cur as usize] += 1;
                attr_src[i] = src;
                attr_rank[i] = r;
            } else {
                // Older collection: fills only what newer records lack.
                if u.kind != 0 && u.strength > strength[i] {
                    kinds[i] = u.kind;
                    strength[i] = u.strength;
                }
                if let Some(nm) = u.name {
                    if names[i].is_none() || u.strength > name_strength[i] {
                        names[i] = Some(nm.into_string());
                        name_strength[i] = u.strength;
                    }
                }
                if let Some(p) = u.props {
                    match (layers.get_mut(&u.id), props[i].take()) {
                        (Some(l), _) => l.insert(0, p.into_string()),
                        (None, Some(cur)) => {
                            layers.insert(u.id, vec![p.into_string(), cur]);
                        }
                        (None, None) => props[i] = Some(p.into_string()),
                    }
                }
                superseded[src as usize] += 1;
            }
        }
        for (id, k) in o.hints {
            let i = id as usize;
            if strength[i] == 0 {
                kinds[i] = k;
                strength[i] = 1;
            }
        }
        chunks.push(o.edges);
    }
    for (s, c) in sources.iter_mut().zip(superseded) {
        s.superseded_objects = c;
    }
    if !node_kinds.is_empty() {
        kinds.par_iter_mut().for_each(|k| *k = node_remap[*k as usize]);
    }
    if !name_edges.is_empty() {
        let (edges, ok, bad) = resolve_name_edges(name_edges, &names, &kinds, &node_kinds);
        report.name_edges_resolved = ok;
        report.name_edges_unresolved = bad;
        chunks.push(edges);
    }
    // Key-level property merges and provenance of nodes described by several
    // sources, in parallel (one parse / serialise per node).
    if !layers.is_empty() || (shared.keep_props && !multi.is_empty()) {
        let mut ids: Vec<u32> = layers.keys().chain(multi.keys()).copied().collect();
        ids.par_sort_unstable();
        ids.dedup();
        let updated: Vec<(u32, String)> = ids
            .par_iter()
            .map(|&id| {
                let mut m: Map<String, Value> = Map::new();
                match layers.get(&id) {
                    Some(l) => {
                        for p in l {
                            match serde_json::from_str::<Map<String, Value>>(p) {
                                Ok(t) => m.extend(t),
                                // Not an object: the later layer wins whole.
                                Err(_) => m.clear(),
                            }
                        }
                        let last = l.last().map_or("", |s| s.as_str());
                        if serde_json::from_str::<Map<String, Value>>(last).is_err() {
                            return (id, last.to_string());
                        }
                    }
                    None => {
                        if let Some(p) = props[id as usize].as_deref() {
                            m = serde_json::from_str(p).unwrap_or_default();
                        }
                    }
                }
                if let (true, Some(srcs)) = (shared.keep_props, multi.get(&id)) {
                    let mut v: Vec<u32> = srcs.iter().copied().filter(|&s| s != NONE).collect();
                    v.sort_by_key(|&s| (std::cmp::Reverse(src_rank[s as usize]), s));
                    m.insert("_sources".into(), Value::from(v));
                }
                (id, Value::Object(m).to_string())
            })
            .collect();
        for (id, p) in updated {
            props[id as usize] = Some(p);
        }
    }
    report.nodes = n;
    report.raw_edges = chunks.iter().map(|c| c.len() as u64).sum();
    report.superseded_objects = sources.iter().map(|s| s.superseded_objects).sum();
    report.superseded_edges = sources.iter().map(|s| s.superseded_edges).sum();

    // --- Tier Zero: well-known SIDs, domains, ADCS infrastructure, Azure
    // tenants / Tier Zero roles, legacy highvalue, DCs and CA host computers.
    for i in 0..n {
        if is_default_tier0(NodeKind::from_u8(kinds[i]), &oids[i]) || fl[i] & flags::HIGHVALUE != 0 {
            fl[i] |= flags::TIER0;
        }
    }
    let dc_groups: AHashSet<u32> = (0..n as u32).filter(|&i| oids[i as usize].ends_with(DOMAIN_CONTROLLERS_SUFFIX)).collect();
    let hosts_ca = ek_of("HostsCAService");
    let promoted: Vec<u32> = chunks
        .par_iter()
        .flat_map_iter(|c| {
            c.iter().filter(|e| (e.kind == ek::MEMBER_OF && dc_groups.contains(&e.dst)) || e.kind == hosts_ca).map(|e| e.src)
        })
        .collect();
    for d in promoted {
        fl[d as usize] |= flags::TIER0;
    }
    report.tier0_nodes = fl.iter().filter(|f| **f & flags::TIER0 != 0).count() as u64;

    let mut parts = GraphParts { kinds, flags: fl, names, oids, props, edge_chunks: chunks, edge_kinds, traversable, node_kinds };
    let t = std::time::Instant::now();
    canonical_numbering(&mut parts, &kind_remap);
    report.renumber_secs = t.elapsed().as_secs_f64();
    parts
}

/// Resolve OpenGraph edges addressed by name against the merged node names
/// (upper case, as stored). An end matches when exactly one node has the
/// name (and the kind, if the edge names one); otherwise the edge is dropped.
/// Returns `(edges, resolved, unresolved)`.
fn resolve_name_edges(name_edges: Vec<NameEdge>, names: &[Option<String>], kinds: &[u8], custom: &[String]) -> (Vec<Edge>, u64, u64) {
    let wanted: AHashSet<&str> = name_edges
        .iter()
        .flat_map(|e| [&e.src, &e.dst])
        .filter_map(|r| match r {
            EndRef::Name(n, _) => Some(&**n),
            EndRef::Id(_) => None,
        })
        .collect();
    let mut by_name: AHashMap<&str, Vec<u32>> = AHashMap::new();
    for (i, n) in names.iter().enumerate() {
        if let Some(n) = n.as_deref().filter(|n| wanted.contains(n)) {
            by_name.entry(n).or_default().push(i as u32);
        }
    }
    let raw_kind = |k: &str| -> Option<u8> {
        if let Some(p) = custom.iter().position(|c| c.eq_ignore_ascii_case(k)) {
            return Some(ch_model::CUSTOM_KIND_BASE + p as u8);
        }
        DynNodeKinds::builtin(k).map(|b| b as u8)
    };
    let resolve = |r: &EndRef| -> Option<u32> {
        match r {
            EndRef::Id(id) => Some(*id),
            EndRef::Name(n, kind) => {
                let all = by_name.get(&**n)?;
                let hits: Vec<u32> = match kind {
                    Some(k) => {
                        let want = raw_kind(k)?;
                        all.iter().copied().filter(|&i| kinds[i as usize] == want).collect()
                    }
                    None => all.clone(),
                };
                (hits.len() == 1).then(|| hits[0])
            }
        }
    };
    let (mut ok, mut bad) = (0, 0);
    let mut out = Vec::new();
    for e in &name_edges {
        match (resolve(&e.src), resolve(&e.dst)) {
            (Some(s), Some(d)) if s != d => {
                out.push(Edge::new(s, d, e.kind));
                ok += 1;
            }
            _ => bad += 1,
        }
    }
    (out, ok, bad)
}

// --------------------------------------------------------- determinism

/// Order sources canonically — by relative file name, zip entry, then full
/// path — instead of by command-line / discovery order, renumbering
/// [`SourceInfo::id`]. Returns old id → new id.
///
/// Source ids appear in the manifest and in `_sources` node properties, and
/// records are merged in source order (equal-time `union` merges keep the
/// last record's properties), so a fixed order makes the graph independent
/// of the order inputs were given in.
pub fn canonical_source_order(sources: &mut Vec<SourceInfo>) -> Vec<u32> {
    let mut order: Vec<usize> = (0..sources.len()).collect();
    order.sort_by(|&a, &b| {
        let (x, y) = (&sources[a], &sources[b]);
        (&x.file, &x.entry, &x.path).cmp(&(&y.file, &y.entry, &y.path))
    });
    let mut remap = vec![0u32; sources.len()];
    let mut old: Vec<Option<SourceInfo>> = std::mem::take(sources).into_iter().map(Some).collect();
    for (new, &o) in order.iter().enumerate() {
        remap[o] = new as u32;
        let mut s = old[o].take().expect("permutation");
        s.id = new as u32;
        sources.push(s);
    }
    remap
}

/// Number nodes by object id (byte order) and collector-specific edge kinds
/// by name, remapping every edge.
///
/// The interner hands out ids in first-sight order across parallel parse
/// batches, so without this the numbering — and with it analysis tie-breaks,
/// the order of equal-valued results and floating-point summation order —
/// would change from run to run and with the thread count. Object ids are
/// unique, so the order is total. Cost: one parallel sort of
/// `(object id, node)` pairs (24 bytes per node, transient) and an
/// `O(nodes + edges)` remap (8 bytes per node).
pub fn canonical_numbering(parts: &mut GraphParts, kind_remap: &[u16]) {
    let n = parts.oids.len();
    let oids = &parts.oids;
    // Sort (string, id) pairs: comparisons then touch only the string bytes,
    // not the `String` headers too.
    let mut keyed: Vec<(&str, u32)> = oids.par_iter().enumerate().map(|(i, s)| (s.as_str(), i as u32)).collect();
    keyed.par_sort_unstable_by(|a, b| a.0.cmp(b.0));
    // The interner makes object ids unique; equal ids would leave their
    // order to the (unstable) sort.
    assert!(keyed.par_windows(2).all(|w| w[0].0 < w[1].0), "duplicate object ids");
    let order: Vec<u32> = keyed.par_iter().map(|k| k.1).collect();
    drop(keyed);
    let nodes_moved = order.par_iter().enumerate().any(|(i, &o)| i as u32 != o);
    let kinds_moved = kind_remap.iter().enumerate().any(|(i, &k)| i as u16 != k);
    if !nodes_moved && !kinds_moved {
        return;
    }
    let mut new_id = Vec::new();
    if nodes_moved {
        new_id = vec![0u32; n];
        for (i, &o) in order.iter().enumerate() {
            new_id[o as usize] = i as u32;
        }
        parts.kinds = order.par_iter().map(|&o| parts.kinds[o as usize]).collect();
        parts.flags = order.par_iter().map(|&o| parts.flags[o as usize]).collect();
        parts.oids = permute(std::mem::take(&mut parts.oids), &order);
        parts.names = permute(std::mem::take(&mut parts.names), &order);
        parts.props = permute(std::mem::take(&mut parts.props), &order);
    }
    drop(order);
    let new_id = &new_id;
    parts.edge_chunks.par_iter_mut().for_each(|c| {
        c.par_iter_mut().with_min_len(1 << 14).for_each(|e| {
            if nodes_moved {
                e.src = new_id[e.src as usize];
                e.dst = new_id[e.dst as usize];
            }
            if kinds_moved {
                if let Some(&k) = kind_remap.get(e.kind as usize) {
                    e.kind = k;
                }
            }
        })
    });
}

/// `out[i] = v[order[i]]` for a permutation `order` of `0..v.len()`,
/// moving the elements in parallel without cloning them.
fn permute<T: Send>(mut v: Vec<T>, order: &[u32]) -> Vec<T> {
    assert_eq!(v.len(), order.len());
    struct Src<T>(*const T);
    impl<T> Clone for Src<T> {
        fn clone(&self) -> Self {
            *self
        }
    }
    impl<T> Copy for Src<T> {}
    // SAFETY: only used for reads of distinct elements (see below).
    unsafe impl<T: Send> Send for Src<T> {}
    unsafe impl<T: Send> Sync for Src<T> {}
    impl<T> Src<T> {
        fn at(self, i: usize) -> *const T {
            self.0.wrapping_add(i)
        }
    }
    let src = Src(v.as_ptr());
    let out: Vec<T> = order
        .par_iter()
        .with_min_len(1 << 12)
        // SAFETY: `order` is a permutation of `0..v.len()` (built from
        // `0..n` by sorting), so every element is read exactly once, in
        // bounds; `v`'s length is zeroed below so none is dropped twice. The
        // closure cannot panic, so no element is dropped on unwind either.
        .map(|&o| unsafe { std::ptr::read(src.at(o as usize)) })
        .collect();
    // SAFETY: every element was moved out above; free the buffer only.
    unsafe { v.set_len(0) };
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        assert_eq!(filename_time("20240102030405_users.json"), Some(1_704_164_645));
        assert_eq!(filename_time("20240102030405.json"), Some(1_704_164_645));
        assert_eq!(filename_time("202401020304051_x.json"), None);
        assert_eq!(filename_time("20241302030405_x.json"), None);
        assert_eq!(filename_time("users.json"), None);
        assert_eq!(parse_rfc3339("2024-01-02T03:04:05Z"), Some(1_704_164_645));
        assert_eq!(parse_rfc3339("2024-01-02T04:04:05.123+01:00"), Some(1_704_164_645));
        assert_eq!(rfc3339(1_704_164_645), "2024-01-02T03:04:05Z");
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(gen_time("20240102030405.0Z"), Some(1_704_164_645));
        assert_eq!(meta_time(br#"{"type":"users","count":1,"version":6}"#), None);
        assert_eq!(meta_time(br#"{"type":"users","collected":"2024-01-02T03:04:05Z"}"#), Some(1_704_164_645));
        assert_eq!(meta_time(br#"{"timestamp":1704164645000}"#), Some(1_704_164_645));
    }
}
