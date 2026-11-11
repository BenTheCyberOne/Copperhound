//! AD post-processing: trust closure and `CoerceToTGT`.
//!
//! **Forest closure.** Intra-forest trusts (parent-child, tree-root, shortcut)
//! are two-way and transitive, and SID filtering does not apply inside a
//! forest, so the forest is one security boundary: control of any domain
//! yields every other (ExtraSids / Enterprise Admins SID history, or TGT
//! capture from another domain's DC). Domains connected by `SameForestTrust`
//! form a forest; the pass materialises `SameForestTrust` between every pair
//! of domains in a forest (forests of up to [`MAX_FOREST_CLOSURE`] domains), so
//! a path from one domain to any other is a single hop. Cross-forest trusts
//! are not transitive for abuse: only `SpoofSIDHistory` (SID filtering off)
//! and `AbuseTGTDelegation` (TGT delegation on) edges, emitted at ingest from
//! the trust's attributes, cross a forest boundary.
//!
//! **CoerceToTGT** (BloodHound CE): an enabled user or computer trusted for
//! unconstrained delegation can coerce a DC to authenticate to it and capture
//! the DC's TGT. Targets: its own domain, every domain in its forest (TGTs are
//! always delegable inside a forest), and every domain of a forest that trusts
//! its domain with TGT delegation enabled (`AbuseTGTDelegation`).
//!
//! **HasTrustKeys** (BloodHound CE): when domain A trusts domain B, B keeps a
//! trust account for A, a user named after A's NetBIOS name (`A$`), whose key
//! is the trust key A stores in its trusted domain object. Control of A's DCs
//! yields the key and so a logon as that account in B:
//! `A -HasTrustKeys-> A$@B`. The account is found by `samaccountname` (or the
//! name before `@`) among B's users; A's NetBIOS name is its `netbios` /
//! `flatname` property when collected, else the first label of its DNS name.

use super::Forests;
use ahash::{AHashMap, AHashSet};
use ch_model::{ek_of, flags, NodeKind};
use ch_store::{Edge, Graph};

/// Larger forests keep their collected trust edges only (paths still exist
/// through intermediate domains); avoids quadratic edge counts.
pub const MAX_FOREST_CLOSURE: usize = 64;

/// The domain of an AD object: `domainsid` property, else the SID prefix.
pub(crate) fn domain_of(g: &Graph, id: u32) -> Option<u32> {
    let props: serde_json::Map<String, serde_json::Value> = serde_json::from_str(g.props(id)).unwrap_or_default();
    let by_prop = props.get("domainsid").and_then(|v| v.as_str()).and_then(|s| g.lookup(s));
    by_prop
        .or_else(|| {
            let oid = g.oid(id);
            oid.starts_with("S-1-5-21-").then(|| oid.rsplit_once('-')).flatten().and_then(|(p, _)| g.lookup(p))
        })
        .filter(|&d| g.kind(d) == NodeKind::Domain)
}

pub fn pass(g: &Graph) -> Vec<Edge> {
    let mut out: AHashSet<(u32, u32, u16)> = AHashSet::new();
    let forests = Forests::new(g);

    // SameForestTrust closure.
    let sft = ek_of("SameForestTrust");
    for set in forests.all().iter().filter(|s| s.len() <= MAX_FOREST_CLOSURE) {
        for &a in set {
            for &b in set {
                if a != b {
                    out.insert((a, b, sft));
                }
            }
        }
    }

    // CoerceToTGT.
    let coerce = ek_of("CoerceToTGT");
    let tgt_deleg = g.edge_kind_id("AbuseTGTDelegation");
    // Targets depend only on the host's domain. Domain nodes have huge
    // out-degree (Contains), so compute each domain's target set once.
    let mut by_domain: AHashMap<u32, Vec<u32>> = AHashMap::new();
    for id in 0..g.node_count() as u32 {
        if !matches!(g.kind(id), NodeKind::Computer | NodeKind::User)
            || !g.has_flag(id, flags::UNCONSTRAINED_DELEGATION)
            || !g.has_flag(id, flags::ENABLED)
        {
            continue;
        }
        let Some(dom) = domain_of(g, id) else { continue };
        let targets = by_domain.entry(dom).or_insert_with(|| {
            let mut targets = forests.forest(dom);
            if let Some(k) = tgt_deleg {
                for src in forests.forest(dom) {
                    let (ds, ks) = g.out_edges(src);
                    for (&x, _) in ds.iter().zip(ks).filter(|(_, kk)| **kk == k) {
                        targets.extend(forests.forest(x));
                    }
                }
            }
            targets.sort_unstable();
            targets.dedup();
            targets
        });
        for &t in targets.iter() {
            if t != id {
                out.insert((id, t, coerce));
            }
        }
    }
    for (a, acct) in trust_accounts(g) {
        out.insert((a, acct, ek_of("HasTrustKeys")));
    }
    out.into_iter().map(|(s, d, k)| Edge::new(s, d, k)).collect()
}

/// "`trusting` trusts `trusted`" pairs from the collected trust edges.
pub(crate) fn trust_pairs(g: &Graph) -> Vec<(u32, u32)> {
    let direct: Vec<u16> = ["SameForestTrust", "CrossForestTrust"].iter().filter_map(|k| g.edge_kind_id(k)).collect();
    let trusted_by = g.edge_kind_id("TrustedBy");
    let mut pairs = Vec::new();
    for d in (0..g.node_count() as u32).filter(|&i| g.kind(i) == NodeKind::Domain) {
        let (ds, ks) = g.out_edges(d);
        for (&x, &k) in ds.iter().zip(ks) {
            if g.kind(x) != NodeKind::Domain || x == d {
                continue;
            }
            if direct.contains(&k) {
                pairs.push((d, x));
            } else if Some(k) == trusted_by {
                // "d TrustedBy x": x trusts d.
                pairs.push((x, d));
            }
        }
    }
    pairs.sort_unstable();
    pairs.dedup();
    pairs
}

/// NetBIOS name of a domain (upper case): `netbios` / `netbiosname` /
/// `flatname` property, else the first label of its DNS name.
pub(crate) fn netbios_name(g: &Graph, d: u32) -> Option<String> {
    let props: serde_json::Map<String, serde_json::Value> = serde_json::from_str(g.props(d)).unwrap_or_default();
    let prop = ["netbios", "netbiosname", "flatname"]
        .iter()
        .find_map(|k| props.iter().find(|(pk, _)| pk.eq_ignore_ascii_case(k)).and_then(|(_, v)| v.as_str()))
        .filter(|s| !s.is_empty());
    let name = match prop {
        Some(p) => p.to_string(),
        None => g.name(d).split('.').next().filter(|s| !s.is_empty())?.to_string(),
    };
    Some(name.to_ascii_uppercase())
}

/// `samaccountname` of a user, else its name before `@` (upper case).
pub(crate) fn sam_of(g: &Graph, u: u32) -> String {
    let props: serde_json::Map<String, serde_json::Value> = serde_json::from_str(g.props(u)).unwrap_or_default();
    match props.get("samaccountname").and_then(|v| v.as_str()) {
        Some(s) => s.to_ascii_uppercase(),
        None => g.name(u).split('@').next().unwrap_or("").to_ascii_uppercase(),
    }
}

/// `(trusting domain, trust account user in the trusted domain)` pairs.
pub(crate) fn trust_accounts(g: &Graph) -> Vec<(u32, u32)> {
    let pairs = trust_pairs(g);
    if pairs.is_empty() {
        return Vec::new();
    }
    // Candidate trust accounts: users whose account name ends with '$'.
    let mut by_domain: AHashMap<(u32, String), Vec<u32>> = AHashMap::new();
    for u in (0..g.node_count() as u32).filter(|&i| g.kind(i) == NodeKind::User) {
        let n = g.name(u);
        let looks = n.split('@').next().is_some_and(|x| x.ends_with('$')) || g.props(u).contains("$\"");
        if !looks {
            continue;
        }
        let sam = sam_of(g, u);
        if !sam.ends_with('$') {
            continue;
        }
        if let Some(d) = domain_of(g, u) {
            by_domain.entry((d, sam)).or_default().push(u);
        }
    }
    let mut out = Vec::new();
    for (a, b) in pairs {
        let Some(nb) = netbios_name(g, a) else { continue };
        for &u in by_domain.get(&(b, format!("{nb}$"))).into_iter().flatten() {
            out.push((a, u));
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ch_model::builtin_kind_tables;
    use ch_store::GraphParts;

    /// Domains 0 (root), 1 (child), 2 (other forest); 3 = UD host in child;
    /// 4 = disabled UD host.
    fn graph(edges: Vec<(u32, u32, &str)>) -> Graph {
        let (edge_kinds, traversable) = builtin_kind_tables();
        let k = |n: &str| ch_model::builtin_edge_kind(n).unwrap();
        let oids = ["S-1-5-21-1", "S-1-5-21-2", "S-1-5-21-3", "S-1-5-21-2-1105", "S-1-5-21-2-1106"];
        let ud = flags::UNCONSTRAINED_DELEGATION;
        let parts = GraphParts {
            kinds: vec![4, 4, 4, NodeKind::Computer as u8, NodeKind::Computer as u8],
            flags: vec![0, 0, 0, ud | flags::ENABLED, ud],
            names: vec![None; 5],
            oids: oids.iter().map(|s| s.to_string()).collect(),
            props: vec![None; 5],
            edge_chunks: vec![edges.into_iter().map(|(s, d, n)| Edge::new(s, d, k(n))).collect()],
            edge_kinds,
            traversable,
            node_kinds: Vec::new(),
        };
        Graph::build(parts).unwrap().0
    }

    fn has(edges: &[Edge], s: u32, d: u32, n: &str) -> bool {
        let k = ch_model::builtin_edge_kind(n).unwrap();
        edges.iter().any(|e| e.src == s && e.dst == d && e.kind == k)
    }

    #[test]
    fn coerce_within_forest_only() {
        let g = graph(vec![(1, 0, "SameForestTrust"), (0, 2, "CrossForestTrust")]);
        let e = pass(&g);
        assert!(has(&e, 0, 1, "SameForestTrust"), "closure adds the reverse direction");
        assert!(has(&e, 3, 1, "CoerceToTGT") && has(&e, 3, 0, "CoerceToTGT"));
        assert!(!has(&e, 3, 2, "CoerceToTGT"), "cross-forest without TGT delegation");
        assert!(!e.iter().any(|x| x.src == 4), "disabled host");
    }

    #[test]
    fn has_trust_keys() {
        // 0 = CORP.LOCAL trusts 1 = PARTNER.LOCAL (outbound), 2 = OTHER.LOCAL
        // (TrustedBy only: OTHER trusts CORP). Users: 3 = CORP$@PARTNER (trust
        // account for CORP), 4 = OTHER$@CORP (for OTHER), 5 = PARTNER$@CORP
        // (no trust in that direction), 6 = CORP$ in CORP itself.
        let (edge_kinds, traversable) = builtin_kind_tables();
        let k = |n: &str| ch_model::builtin_edge_kind(n).unwrap();
        let names = ["CORP.LOCAL", "PARTNER.LOCAL", "OTHER.LOCAL", "CORP$@PARTNER.LOCAL", "OTHER$@CORP.LOCAL", "PARTNER$@CORP.LOCAL", "CORP$@CORP.LOCAL"];
        let oids = ["S-1-5-21-1", "S-1-5-21-2", "S-1-5-21-3", "S-1-5-21-2-1201", "S-1-5-21-1-1202", "S-1-5-21-1-1203", "S-1-5-21-1-1204"];
        let props = [None, None, None, Some(r#"{"samaccountname":"CORP$"}"#), None, None, None];
        let parts = GraphParts {
            kinds: vec![4, 4, 4, NodeKind::User as u8, NodeKind::User as u8, NodeKind::User as u8, NodeKind::User as u8],
            flags: vec![0; 7],
            names: names.iter().map(|s| Some(s.to_string())).collect(),
            oids: oids.iter().map(|s| s.to_string()).collect(),
            props: props.iter().map(|p| p.map(str::to_string)).collect(),
            edge_chunks: vec![vec![Edge::new(0, 1, k("CrossForestTrust")), Edge::new(0, 2, k("TrustedBy"))]],
            edge_kinds,
            traversable,
            node_kinds: Vec::new(),
        };
        let g = Graph::build(parts).unwrap().0;
        let mut got: Vec<(u32, u32)> =
            pass(&g).into_iter().filter(|e| e.kind == k("HasTrustKeys")).map(|e| (e.src, e.dst)).collect();
        got.sort();
        assert_eq!(got, vec![(0, 3), (2, 4)]);
    }

    #[test]
    fn coerce_across_tgt_delegation() {
        // Domain 2 trusts domain 1 with TGT delegation: 1 -AbuseTGTDelegation-> 2.
        let g = graph(vec![(1, 0, "SameForestTrust"), (1, 2, "AbuseTGTDelegation")]);
        let e = pass(&g);
        assert!(has(&e, 3, 2, "CoerceToTGT"));
    }
}
