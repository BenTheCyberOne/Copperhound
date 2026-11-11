//! Replication-right composites: `DCSync` (GetChanges + GetChangesAll) and
//! `SyncLAPSPassword` (GetChanges + GetChangesInFilteredSet), membership-aware
//! like BloodHound CE (`PostDCSync`, `PostSyncLAPSPassword`,
//! `CalculateCrossProductNodeSets` in `packages/go/analysis/ad`).
//!
//! **Effective rights.** A principal holds a replication right on a domain if
//! it, or any group it belongs to through `MemberOf` (transitively), has the
//! right's edge to the domain. The rights are propagated *down* the membership
//! graph from their (few) holders, so the work is proportional to the holders'
//! transitive members, not to the graph.
//!
//! **Where the edge is emitted** ("first intersection", as in CE): from a node
//! whose effective rights complete the pair while none of its direct parent
//! groups' effective rights do. Members below that node reach it through
//! `MemberOf`, so per-member edges would only duplicate paths (CE's design
//! document gives the same rule: a user that holds both rights through one
//! group gets no edge of its own). A principal that holds both rights itself
//! always gets the edge. A group that completes the pair gets the edge even
//! when it has no members.
//!
//! **Authenticated Users / Everyone.** Every principal is implicitly a member,
//! though collectors do not record that membership. As in CE, a right held by
//! one of them (or by a group they are members of) counts as held by everyone:
//! direct holders of the other right of the pair complete it.
//!
//! **GenericAll / AllExtendedRights** on the domain include both replication
//! rights, but each is a traversable edge to the domain on its own, so it never
//! needs to complete a pair; they are not counted (as in CE).
//!
//! **SyncLAPSPassword** goes from each syncer to every computer of the domain
//! with `haslaps == true` (CE). Deviation: principals whose effective rights
//! also complete DCSync get no SyncLAPSPassword edges. DCSync already yields the
//! whole domain, and by default Administrators and the domain controller groups
//! hold all three rights, so CE's rule adds |holders| × |LAPS computers| edges
//! that only restate DCSync.

use super::ad::domain_of;
use ahash::{AHashMap, AHashSet};
use ch_model::{ek, NodeKind};
use ch_store::{Edge, Graph};
use rayon::prelude::*;

const GC: u8 = 1;
const GCA: u8 = 2;
const GCF: u8 = 4;
const DCSYNC_PAIR: u8 = GC | GCA;
const LAPS_PAIR: u8 = GC | GCF;

fn right_bit(k: u16) -> u8 {
    match k {
        ek::GET_CHANGES => GC,
        ek::GET_CHANGES_ALL => GCA,
        ek::GET_CHANGES_IN_FILTERED_SET => GCF,
        _ => 0,
    }
}

/// Authenticated Users (S-1-5-11) or Everyone (S-1-1-0); SharpHound prefixes
/// well-known SIDs with the domain name (`CORP.LOCAL-S-1-5-11`).
pub(crate) fn is_everyone(oid: &str) -> bool {
    ["S-1-5-11", "S-1-1-0"].iter().any(|s| oid == *s || oid.strip_suffix(s).is_some_and(|p| p.ends_with('-')))
}

#[inline]
fn complete(bits: u8, pair: u8) -> bool {
    bits & pair == pair
}

/// Syncers of one domain: `(DCSync sources, SyncLAPSPassword sources)`.
fn syncers(g: &Graph, d: u32) -> (Vec<u32>, Vec<u32>) {
    let mut own: AHashMap<u32, u8> = AHashMap::new();
    let (ss, ks) = g.in_edges(d);
    for (&s, &k) in ss.iter().zip(ks) {
        let b = right_bit(k);
        if b != 0 {
            *own.entry(s).or_default() |= b;
        }
    }
    if own.is_empty() {
        return Default::default();
    }

    // Propagate down the membership graph. Each node's bits only grow (three
    // bits), so it is re-queued at most three times; cycles are harmless.
    let mut eff = own.clone();
    let mut universal = 0u8;
    let mut stack: Vec<u32> = own.keys().copied().collect();
    while let Some(x) = stack.pop() {
        let bx = eff[&x];
        if g.kind(x) == NodeKind::Group && is_everyone(g.oid(x)) {
            universal |= bx;
        }
        let (ms, ks) = g.in_edges(x);
        for (&m, &k) in ms.iter().zip(ks) {
            if k == ek::MEMBER_OF {
                let e = eff.entry(m).or_default();
                if *e | bx != *e {
                    *e |= bx;
                    stack.push(m);
                }
            }
        }
    }

    let mut dcsync = Vec::new();
    let mut laps = Vec::new();
    for (&x, &b) in &eff {
        let b = b | universal;
        let o = own.get(&x).copied().unwrap_or(0);
        let wants_dc = complete(b, DCSYNC_PAIR);
        let wants_laps = complete(b, LAPS_PAIR) && !wants_dc;
        if !wants_dc && !wants_laps {
            continue;
        }
        // Does a direct parent group already complete the pair?
        let (mut parent_dc, mut parent_laps) = (false, false);
        let (ps, ks) = g.out_edges(x);
        for (&p, &k) in ps.iter().zip(ks) {
            if k == ek::MEMBER_OF {
                let pb = eff.get(&p).copied().unwrap_or(0) | universal;
                parent_dc |= complete(pb, DCSYNC_PAIR);
                parent_laps |= complete(pb, LAPS_PAIR);
            }
        }
        let first = |pair: u8, parent: bool| (o & pair != 0 && complete(o | universal, pair)) || !parent;
        if wants_dc && first(DCSYNC_PAIR, parent_dc) {
            dcsync.push(x);
        }
        if wants_laps && first(LAPS_PAIR, parent_laps) {
            laps.push(x);
        }
    }
    (dcsync, laps)
}

/// Computers with `haslaps == true`, by domain. Only called when a domain has
/// LAPS syncers.
fn laps_computers(g: &Graph) -> AHashMap<u32, Vec<u32>> {
    let found: Vec<(u32, u32)> = (0..g.node_count() as u32)
        .into_par_iter()
        .filter(|&i| g.kind(i) == NodeKind::Computer)
        .filter_map(|i| {
            let p = g.props(i);
            if !p.contains("haslaps") {
                return None;
            }
            let v: serde_json::Map<String, serde_json::Value> = serde_json::from_str(p).ok()?;
            (v.get("haslaps").and_then(|x| x.as_bool()) == Some(true)).then_some(())?;
            domain_of(g, i).map(|d| (d, i))
        })
        .collect();
    let mut m: AHashMap<u32, Vec<u32>> = AHashMap::new();
    for (d, c) in found {
        m.entry(d).or_default().push(c);
    }
    m
}

pub fn pass(g: &Graph) -> Vec<Edge> {
    let domains: Vec<u32> = (0..g.node_count() as u32).into_par_iter().filter(|&i| g.kind(i) == NodeKind::Domain).collect();
    let per_domain: Vec<(u32, Vec<u32>, Vec<u32>)> = domains
        .par_iter()
        .map(|&d| {
            let (dc, laps) = syncers(g, d);
            (d, dc, laps)
        })
        .filter(|(_, dc, laps)| !dc.is_empty() || !laps.is_empty())
        .collect();

    let mut out: Vec<Edge> = Vec::new();
    for (d, dc, _) in &per_domain {
        out.extend(dc.iter().filter(|&&s| s != *d).map(|&s| Edge::new(s, *d, ek::DCSYNC)));
    }
    if per_domain.iter().any(|(_, _, l)| !l.is_empty()) {
        let computers = laps_computers(g);
        let kind = ch_model::ek_of("SyncLAPSPassword");
        let mut seen = AHashSet::new();
        for (d, _, laps) in &per_domain {
            for &c in computers.get(d).into_iter().flatten() {
                for &s in laps {
                    if s != c && seen.insert((s, c)) {
                        out.push(Edge::new(s, c, kind));
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ch_model::{builtin_edge_kind, builtin_kind_tables};
    use ch_store::GraphParts;

    const D: &str = "S-1-5-21-1";

    /// Nodes: 0 = domain, then `(oid suffix, kind, props)`.
    fn graph(nodes: &[(&str, NodeKind, &str)], edges: &[(u32, u32, &str)]) -> Graph {
        let (edge_kinds, traversable) = builtin_kind_tables();
        let mut kinds = vec![NodeKind::Domain as u8];
        let mut oids = vec![D.to_string()];
        let mut props = vec![None];
        for (s, k, p) in nodes {
            kinds.push(*k as u8);
            oids.push(if s.starts_with("CORP") { s.to_string() } else { format!("{D}-{s}") });
            props.push((!p.is_empty()).then(|| p.to_string()));
        }
        let n = kinds.len();
        let parts = GraphParts {
            kinds,
            flags: vec![0; n],
            names: vec![None; n],
            oids,
            props,
            edge_chunks: vec![edges.iter().map(|&(s, d, k)| Edge::new(s, d, builtin_edge_kind(k).unwrap())).collect()],
            edge_kinds,
            traversable,
            node_kinds: Vec::new(),
        };
        Graph::build(parts).unwrap().0
    }

    fn pairs(e: &[Edge], kind: &str) -> Vec<(u32, u32)> {
        let k = builtin_edge_kind(kind).unwrap();
        let mut v: Vec<(u32, u32)> = e.iter().filter(|x| x.kind == k).map(|x| (x.src, x.dst)).collect();
        v.sort();
        v
    }

    use NodeKind::{Computer as C, Group as G, User as U};

    #[test]
    fn dcsync_through_membership_first_intersection() {
        // 1 = group A (GetChanges), 2 = group B (GetChangesAll),
        // 3 = user in A and B (completes the pair itself),
        // 4 = group N in A and B, 5 = user in N (covered by N),
        // 6 = user holding both directly, also in A (direct holders always),
        // 7 = group C holding both, 8 = user in C (covered by C),
        // 9 = user only in A (no pair), 10 = user holding GetChanges, in B.
        let g = graph(
            &[("1", G, ""), ("2", G, ""), ("3", U, ""), ("4", G, ""), ("5", U, ""), ("6", U, ""), ("7", G, ""), ("8", U, ""), ("9", U, ""), ("10", U, "")],
            &[
                (1, 0, "GetChanges"),
                (2, 0, "GetChangesAll"),
                (3, 1, "MemberOf"),
                (3, 2, "MemberOf"),
                (4, 1, "MemberOf"),
                (4, 2, "MemberOf"),
                (5, 4, "MemberOf"),
                (6, 0, "GetChanges"),
                (6, 0, "GetChangesAll"),
                (6, 1, "MemberOf"),
                (7, 0, "GetChanges"),
                (7, 0, "GetChangesAll"),
                (8, 7, "MemberOf"),
                (9, 1, "MemberOf"),
                (10, 0, "GetChanges"),
                (10, 2, "MemberOf"),
            ],
        );
        let e = pass(&g);
        assert_eq!(pairs(&e, "DCSync"), vec![(3, 0), (4, 0), (6, 0), (7, 0), (10, 0)]);
        assert!(pairs(&e, "SyncLAPSPassword").is_empty());
    }

    #[test]
    fn nested_cycle_and_transitive() {
        // 1 (GetChanges) <- 2 <- 3 <- 4; 3 also in 5 (GetChangesAll); 1 and 2 form a cycle.
        let g = graph(
            &[("1", G, ""), ("2", G, ""), ("3", G, ""), ("4", U, ""), ("5", G, "")],
            &[
                (1, 0, "GetChanges"),
                (5, 0, "GetChangesAll"),
                (2, 1, "MemberOf"),
                (1, 2, "MemberOf"),
                (3, 2, "MemberOf"),
                (4, 3, "MemberOf"),
                (3, 5, "MemberOf"),
            ],
        );
        assert_eq!(pairs(&pass(&g), "DCSync"), vec![(3, 0)]);
    }

    #[test]
    fn authenticated_users_shortcut() {
        // Authenticated Users holds GetChanges: every holder of GetChangesAll completes the pair.
        let g = graph(
            &[("CORP.LOCAL-S-1-5-11", G, ""), ("2", G, ""), ("3", U, "")],
            &[(1, 0, "GetChanges"), (2, 0, "GetChangesAll"), (3, 2, "MemberOf")],
        );
        assert_eq!(pairs(&pass(&g), "DCSync"), vec![(2, 0)]);
    }

    #[test]
    fn sync_laps_password() {
        let laps = r#"{"haslaps": true, "domainsid": "S-1-5-21-1"}"#;
        // 1 = group (GetChanges + GetChangesInFilteredSet), 2 = user in 1,
        // 3 = group with all three rights (DCSync only), 4/5 = LAPS / non-LAPS computers,
        // 6 = user with GetChangesInFilteredSet, member of group 7 with GetChanges.
        let g = graph(
            &[("1", G, ""), ("2", U, ""), ("3", G, ""), ("4", C, laps), ("5", C, r#"{"haslaps": false}"#), ("6", U, ""), ("7", G, "")],
            &[
                (1, 0, "GetChanges"),
                (1, 0, "GetChangesInFilteredSet"),
                (2, 1, "MemberOf"),
                (3, 0, "GetChanges"),
                (3, 0, "GetChangesAll"),
                (3, 0, "GetChangesInFilteredSet"),
                (6, 0, "GetChangesInFilteredSet"),
                (6, 7, "MemberOf"),
                (7, 0, "GetChanges"),
            ],
        );
        let e = pass(&g);
        assert_eq!(pairs(&e, "DCSync"), vec![(3, 0)]);
        assert_eq!(pairs(&e, "SyncLAPSPassword"), vec![(1, 4), (6, 4)]);
    }

    #[test]
    fn everyone_sid() {
        assert!(is_everyone("CORP.LOCAL-S-1-5-11") && is_everyone("S-1-1-0"));
        assert!(!is_everyone("S-1-5-21-1-2-3-1-5-11"));
        assert!(!is_everyone("CORP.LOCAL-S-1-5-111"));
    }
}
