//! Cost-aware paths. Shortest paths count hops; an attacker picks the path
//! that is cheapest to walk (effort) or least likely to be noticed (stealth).
//! Each edge gets an integer cost from its kind ([`default_cost`], overridable
//! per kind), plus, for `HasSession`, a penalty that grows with the time since
//! the session was last seen ([`session_penalty`]): an old logon may no longer
//! have credentials in memory.
//!
//! Session age is measured against the newest session time in the graph, not
//! the wall clock, so the same graph always gives the same costs.
//!
//! [`cheapest_path`] is Dijkstra from the source set to the first target
//! reached. Ties on cost go to fewer hops, then to the first edge in storage
//! order, so results are deterministic. With every cost set to 1 it returns a
//! path of the same length as [`crate::shortest_path`].

use crate::EdgeFilter;
use ch_model::ek;
use ch_store::{Graph, SessionMeta};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};

/// What the cost measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Work and preconditions: credential theft, cracking, waiting for a
    /// logon, coercion.
    Effort,
    /// Likelihood of detection: DCSync, password resets and group membership
    /// changes are loud; using existing membership and most ACL rights is quieter.
    Stealth,
}

impl Profile {
    pub fn parse(s: &str) -> Option<Profile> {
        match s.to_ascii_lowercase().as_str() {
            "effort" => Some(Profile::Effort),
            "stealth" => Some(Profile::Stealth),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Effort => "effort",
            Profile::Stealth => "stealth",
        }
    }
}

/// Cost of a traversable kind not in the table (collector rights registered
/// at ingest, OpenGraph kinds).
pub const DEFAULT_CUSTOM_COST: u32 = 2;

/// Upper bound for a configured cost (keeps sums far from overflow).
pub const MAX_COST: u32 = 1000;

/// Built-in cost of an edge kind for a profile; `None` for kinds not listed
/// (they cost [`DEFAULT_CUSTOM_COST`]).
pub fn default_cost(p: Profile, kind: &str) -> Option<u32> {
    let (effort, stealth) = match kind {
        // Membership and containment of rights cost nothing to use.
        "MemberOf" | "AZMemberOf" => (0, 0),
        "HasSIDHistory" => (0, 1),
        "SameForestTrust" => (2, 2),
        "SpoofSIDHistory" | "AbuseTGTDelegation" | "HasTrustKeys" => (3, 3),
        // Code execution on a host.
        "AdminTo" => (1, 3),
        "CanRDP" | "CanPSRemote" => (2, 2),
        "ExecuteDCOM" => (3, 2),
        "SQLAdmin" => (2, 2),
        // Credential theft from a host (base; session age adds to it).
        "HasSession" => (2, 3),
        "DumpSMSAPassword" => (1, 2),
        "ReadLAPSPassword" | "ReadGMSAPassword" | "SyncLAPSPassword" => (1, 1),
        // Directory writes.
        "GenericAll" | "AllExtendedRights" => (1, 2),
        "GenericWrite" | "Owns" | "WriteDacl" | "WriteOwner" => (2, 3),
        "OwnsLimitedRights" | "WriteOwnerLimitedRights" => (3, 3),
        "AddMember" | "AddSelf" | "AZAddMembers" => (1, 3),
        "ForceChangePassword" | "AZResetPassword" => (1, 6),
        "AddKeyCredentialLink" | "WriteAltSecurityIdentities" | "WritePublicInformation" => (2, 2),
        "WriteSPN" => (4, 2),
        "AddAllowedToAct" | "AllowedToAct" | "AllowedToDelegate" | "WriteAccountRestrictions" => (3, 2),
        "WriteGPLink" | "GPLink" | "Contains" => (3, 4),
        "DCSync" => (1, 8),
        "DCFor" => (1, 3),
        "CoerceToTGT" => (3, 4),
        "ClaimSpecialIdentity" => (1, 1),
        // AD CS: request a certificate, then authenticate with it.
        "GoldenCert" => (3, 4),
        "ADCSESC1" | "ADCSESC3" | "ADCSESC6a" | "ADCSESC6b" | "ADCSESC13" | "ADCSESC16" => (2, 2),
        "ADCSESC4" | "ADCSESC9a" | "ADCSESC9b" | "ADCSESC10a" | "ADCSESC10b" => (3, 3),
        "ManageCA" | "ManageCertificates" => (3, 3),
        // NTLM relay: coercion plus a relay listener on the network.
        "CoerceAndRelayNTLMToSMB" | "CoerceAndRelayNTLMToLDAP" | "CoerceAndRelayNTLMToLDAPS" => (4, 5),
        "CoerceAndRelayNTLMToADCS" | "CoerceAndRelayNTLMToADCSRPC" => (4, 5),
        // Hybrid and Entra ID.
        "SyncedToEntraUser" | "SyncedToADUser" | "SyncedToEntraGroup" => (1, 1),
        "SeamlessSSO" | "EntraConnectCredentials" => (2, 3),
        "AZOwns" | "AZOwner" | "AZContributor" | "AZUserAccessAdministrator" => (1, 2),
        "AZHasRole" | "AZContains" | "AZRunsAs" | "AZManagedIdentity" | "AZNodeResourceGroup" | "AZAuthenticatesTo" => (1, 1),
        "AZGlobalAdmin" | "AZPrivilegedRoleAdmin" | "AZPrivilegedAuthAdmin" => (1, 2),
        "AZAddSecret" | "AZAddOwner" | "AZMGAddSecret" | "AZMGAddOwner" | "AZMGAddMember" | "AZMGGrantAppRoles" | "AZMGGrantRole" => (1, 2),
        "AZExecuteCommand" => (2, 3),
        "CanProgram" => (2, 2),
        k if k.starts_with("AZ") => (2, 2),
        _ => return None,
    };
    Some(match p {
        Profile::Effort => effort,
        Profile::Stealth => stealth,
    })
}

/// Extra cost of a `HasSession` edge by the time since it was last seen,
/// relative to the newest session time in the graph (`reference`).
pub fn session_penalty(m: Option<&SessionMeta>, reference: i64) -> u32 {
    let Some(m) = m.filter(|m| m.last_seen > 0 && reference > 0) else { return 2 };
    let days = (reference - m.last_seen).max(0) / 86_400;
    match days {
        0 => 0,
        1..=7 => 1,
        8..=30 => 3,
        _ => 6,
    }
}

/// Per-kind cost overrides, by kind name (`<data>/path_costs.json` on the server).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CostOverrides {
    pub effort: BTreeMap<String, u32>,
    pub stealth: BTreeMap<String, u32>,
}

impl CostOverrides {
    pub fn for_profile(&self, p: Profile) -> &BTreeMap<String, u32> {
        match p {
            Profile::Effort => &self.effort,
            Profile::Stealth => &self.stealth,
        }
    }
}

/// Edge costs for one graph and profile.
#[derive(Debug, Clone)]
pub struct CostModel {
    pub profile: Profile,
    kind_cost: Vec<u32>,
    session_reference: i64,
    session_age: bool,
}

impl CostModel {
    pub fn new(g: &Graph, profile: Profile, overrides: &CostOverrides) -> Self {
        let o = overrides.for_profile(profile);
        let kind_cost = (0..g.edge_kind_count())
            .map(|k| {
                let name = g.edge_kind_name(k as u16);
                o.get(name).copied().or_else(|| default_cost(profile, name)).unwrap_or(DEFAULT_CUSTOM_COST).min(MAX_COST)
            })
            .collect();
        let session_reference = g.sessions().iter().map(|s| s.last_seen).max().unwrap_or(0);
        CostModel { profile, kind_cost, session_reference, session_age: true }
    }

    /// Every edge costs `c` (no session penalty); `c = 1` is hop count.
    pub fn uniform(g: &Graph, c: u32) -> Self {
        CostModel { profile: Profile::Effort, kind_cost: vec![c; g.edge_kind_count()], session_reference: 0, session_age: false }
    }

    /// The newest session time the age penalty is measured from (0: none).
    pub fn session_reference(&self) -> i64 {
        self.session_reference
    }

    #[inline]
    pub fn cost(&self, g: &Graph, s: u32, d: u32, k: u16) -> u32 {
        let base = self.kind_cost.get(k as usize).copied().unwrap_or(DEFAULT_CUSTOM_COST);
        if self.session_age && k == ek::HAS_SESSION {
            base + session_penalty(g.session(s, d), self.session_reference)
        } else {
            base
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CostPath {
    /// `nodes[i] --kinds[i] (costs[i])--> nodes[i+1]`
    pub nodes: Vec<u32>,
    pub kinds: Vec<u16>,
    pub costs: Vec<u32>,
    pub total: u64,
    /// Nodes settled by the search.
    pub explored: usize,
}

const UNSEEN: u64 = u64::MAX;

/// The cheapest path from any of `sources` to any of `targets` over edges the
/// filter allows, or `None`. Dijkstra with lazy deletion; settles nodes in
/// `(cost, hops)` order.
pub fn cheapest_path(g: &Graph, sources: &[u32], targets: &[u32], f: &EdgeFilter, m: &CostModel) -> Option<CostPath> {
    let n = g.node_count();
    let mut is_target = vec![false; n];
    for &t in targets {
        if (t as usize) < n {
            is_target[t as usize] = true;
        }
    }
    let mut dist = vec![UNSEEN; n];
    let mut hops = vec![u32::MAX; n];
    let mut parent: Vec<(u32, u16, u32)> = vec![(u32::MAX, 0, 0); n];
    let mut heap: BinaryHeap<Reverse<(u64, u32, u32)>> = BinaryHeap::new();
    for &s in sources {
        if (s as usize) < n && dist[s as usize] != 0 {
            dist[s as usize] = 0;
            hops[s as usize] = 0;
            heap.push(Reverse((0, 0, s)));
        }
    }
    let mut explored = 0;
    while let Some(Reverse((d, h, u))) = heap.pop() {
        if d != dist[u as usize] || h != hops[u as usize] {
            continue;
        }
        explored += 1;
        if is_target[u as usize] {
            let mut nodes = vec![u];
            let mut kinds = Vec::new();
            let mut costs = Vec::new();
            let mut x = u;
            while parent[x as usize].0 != u32::MAX {
                let (p, k, c) = parent[x as usize];
                nodes.push(p);
                kinds.push(k);
                costs.push(c);
                x = p;
            }
            nodes.reverse();
            kinds.reverse();
            costs.reverse();
            return Some(CostPath { nodes, kinds, costs, total: d, explored });
        }
        let (ds, ks) = g.out_edges(u);
        for (&v, &k) in ds.iter().zip(ks) {
            if !f.permits(g, u, v, k) {
                continue;
            }
            let c = m.cost(g, u, v, k);
            let (nd, nh) = (d + c as u64, h + 1);
            let vi = v as usize;
            if (nd, nh) < (dist[vi], hops[vi]) {
                dist[vi] = nd;
                hops[vi] = nh;
                parent[vi] = (u, k, c);
                heap.push(Reverse((nd, nh, v)));
            }
        }
    }
    None
}

/// For every node, the cost of its cheapest path to any of `targets`
/// (`u64::MAX` when none): reverse Dijkstra from the targets. Targets cost 0.
pub fn cost_to_targets(g: &Graph, targets: &[u32], f: &EdgeFilter, m: &CostModel) -> Vec<u64> {
    let n = g.node_count();
    let mut dist = vec![UNSEEN; n];
    let mut hops = vec![u32::MAX; n];
    let mut heap: BinaryHeap<Reverse<(u64, u32, u32)>> = BinaryHeap::new();
    for &t in targets {
        if (t as usize) < n && dist[t as usize] != 0 {
            dist[t as usize] = 0;
            hops[t as usize] = 0;
            heap.push(Reverse((0, 0, t)));
        }
    }
    while let Some(Reverse((d, h, v))) = heap.pop() {
        if d != dist[v as usize] || h != hops[v as usize] {
            continue;
        }
        let (ss, ks) = g.in_edges(v);
        for (&u, &k) in ss.iter().zip(ks) {
            if !f.permits(g, u, v, k) {
                continue;
            }
            let nd = d + m.cost(g, u, v, k) as u64;
            let nh = h + 1;
            let ui = u as usize;
            if (nd, nh) < (dist[ui], hops[ui]) {
                dist[ui] = nd;
                hops[ui] = nh;
                heap.push(Reverse((nd, nh, u)));
            }
        }
    }
    dist
}

#[cfg(test)]
mod tests {
    use super::*;
    use ch_model::{ek, ek_of};
    use ch_store::{Edge, GraphParts};

    fn graph(n: usize, edges: Vec<Edge>, sessions: Vec<SessionMeta>) -> Graph {
        let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
        Graph::build(GraphParts {
            sessions,
            kinds: vec![1; n],
            flags: vec![0; n],
            names: (0..n).map(|i| Some(format!("N{i}"))).collect(),
            oids: (0..n).map(|i| format!("S-1-5-21-9-{i}")).collect(),
            props: vec![None; n],
            edge_chunks: vec![edges],
            edge_kinds,
            traversable,
            node_kinds: Vec::new(),
        })
        .unwrap()
        .0
    }

    /// Bellman-Ford reference: minimum total cost from `s` to any target.
    fn reference(g: &Graph, s: u32, targets: &[u32], f: &EdgeFilter, m: &CostModel) -> Option<u64> {
        let n = g.node_count();
        let mut d = vec![u64::MAX; n];
        d[s as usize] = 0;
        for _ in 0..n {
            let mut changed = false;
            for u in 0..n as u32 {
                if d[u as usize] == u64::MAX {
                    continue;
                }
                let (ds, ks) = g.out_edges(u);
                for (&v, &k) in ds.iter().zip(ks) {
                    if f.permits(g, u, v, k) {
                        let nd = d[u as usize] + m.cost(g, u, v, k) as u64;
                        if nd < d[v as usize] {
                            d[v as usize] = nd;
                            changed = true;
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }
        targets.iter().map(|&t| d[t as usize]).filter(|&x| x != u64::MAX).min()
    }

    fn rng(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    #[test]
    fn matches_reference_on_random_graphs() {
        let kinds = ["MemberOf", "AdminTo", "HasSession", "GenericAll", "DCSync", "ForceChangePassword", "WriteSPN", "GetChanges"];
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut checked = 0;
        for round in 0..300 {
            let n = 3 + (rng(&mut seed) % 30) as usize;
            let m = (rng(&mut seed) % (n as u64 * 3)) as usize;
            let mut edges = Vec::new();
            let mut sessions = Vec::new();
            for _ in 0..m {
                let (a, b) = ((rng(&mut seed) % n as u64) as u32, (rng(&mut seed) % n as u64) as u32);
                if a == b {
                    continue;
                }
                let k = ek_of(kinds[(rng(&mut seed) % kinds.len() as u64) as usize]);
                edges.push(Edge::new(a, b, k));
                if k == ek::HAS_SESSION && rng(&mut seed).is_multiple_of(2) {
                    let last = 1_000_000 + (rng(&mut seed) % 60) as i64 * 86_400;
                    sessions.push(SessionMeta { computer: a, user: b, first_seen: last, last_seen: last, sources: 1, logon_types: 0, pad: 0 });
                }
            }
            let g = graph(n, edges, sessions);
            let f = EdgeFilter::traversable(&g);
            let profile = if round % 2 == 0 { Profile::Effort } else { Profile::Stealth };
            let model = CostModel::new(&g, profile, &CostOverrides::default());
            let s = (rng(&mut seed) % n as u64) as u32;
            let targets: Vec<u32> = (0..n as u32).filter(|&x| x != s && rng(&mut seed).is_multiple_of(4)).collect();
            let want = reference(&g, s, &targets, &f, &model);
            let got = cheapest_path(&g, &[s], &targets, &f, &model);
            assert_eq!(got.as_ref().map(|p| p.total), want, "round {round}");
            if let Some(p) = got {
                // The path is real, its costs add up, and it ends at a target.
                assert_eq!(p.nodes[0], s);
                assert!(targets.contains(p.nodes.last().unwrap()));
                for (i, w) in p.nodes.windows(2).enumerate() {
                    let (ds, ks) = g.out_edges(w[0]);
                    assert!(ds.iter().zip(ks).any(|(&d, &k)| d == w[1] && k == p.kinds[i] && f.permits(&g, w[0], d, k)));
                    assert_eq!(p.costs[i], model.cost(&g, w[0], w[1], p.kinds[i]));
                }
                assert_eq!(p.costs.iter().map(|&c| c as u64).sum::<u64>(), p.total);
                checked += 1;
            }
            // Reverse search agrees for every node.
            let all = cost_to_targets(&g, &targets, &f, &model);
            for u in 0..n as u32 {
                let r = if targets.contains(&u) { Some(0) } else { reference(&g, u, &targets, &f, &model) };
                assert_eq!(all[u as usize], r.unwrap_or(u64::MAX), "round {round} node {u}");
            }
            // Uniform cost 1 gives the BFS hop count.
            let hop = CostModel::uniform(&g, 1);
            let bfs = crate::shortest_path(&g, &[s], &targets, &f).map(|p| p.kinds.len() as u64);
            assert_eq!(cheapest_path(&g, &[s], &targets, &f, &hop).map(|p| p.total), bfs, "round {round}");
        }
        assert!(checked > 100, "only {checked} rounds had a path");
    }

    #[test]
    fn session_age_raises_cost() {
        let day = 86_400;
        let m = |last: i64| SessionMeta { computer: 0, user: 1, first_seen: last, last_seen: last, sources: 1, logon_types: 0, pad: 0 };
        let r = 100 * day;
        assert_eq!(session_penalty(Some(&m(r)), r), 0);
        assert_eq!(session_penalty(Some(&m(r - 3 * day)), r), 1);
        assert_eq!(session_penalty(Some(&m(r - 20 * day)), r), 3);
        assert_eq!(session_penalty(Some(&m(r - 90 * day)), r), 6);
        assert_eq!(session_penalty(Some(&m(0)), r), 2);
        assert_eq!(session_penalty(None, r), 2);
        // Two routes to node 3: fresh session via 1, stale session via 2.
        let hs = ek::HAS_SESSION;
        let g = graph(
            4,
            vec![Edge::new(0, 1, ek::ADMIN_TO), Edge::new(0, 2, ek::ADMIN_TO), Edge::new(1, 3, hs), Edge::new(2, 3, hs)],
            vec![
                SessionMeta { computer: 1, user: 3, first_seen: 1, last_seen: r - 60 * day, sources: 8, logon_types: 4, pad: 0 },
                SessionMeta { computer: 2, user: 3, first_seen: 1, last_seen: r, sources: 8, logon_types: 4, pad: 0 },
            ],
        );
        let model = CostModel::new(&g, Profile::Effort, &CostOverrides::default());
        let p = cheapest_path(&g, &[0], &[3], &EdgeFilter::traversable(&g), &model).unwrap();
        assert_eq!(p.nodes, [0, 2, 3], "the fresh session wins");
        assert_eq!(p.total, 1 + 2);
        // Overrides apply by kind name.
        let mut o = CostOverrides::default();
        o.effort.insert("AdminTo".into(), 50);
        let model = CostModel::new(&g, Profile::Effort, &o);
        assert_eq!(cheapest_path(&g, &[0], &[3], &EdgeFilter::traversable(&g), &model).unwrap().total, 52);
    }

    #[test]
    fn every_builtin_traversable_kind_has_a_cost() {
        for (name, trav) in ch_model::BUILTIN_EDGE_KINDS {
            if *trav {
                for p in [Profile::Effort, Profile::Stealth] {
                    assert!(default_cost(p, name).is_some(), "{name} has no {} cost", p.as_str());
                }
            }
        }
    }
}
