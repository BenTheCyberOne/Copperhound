//! Network-aware traversal: attack paths that respect firewall conduits
//! between network zones (docs/OT.md, "Network reachability").
//!
//! Hosts carry a zone (`net_zone`); conduits list which services may cross
//! from one zone to another. A traversal tracks the attacker's network
//! position, so a state is `(node, zone)`:
//!
//! * **Remote access** (`AdminTo`, `CanRDP`, `CanPSRemote`, `ExecuteDCOM`,
//!   `SQLAdmin`, `CanProgram`) into a host with a zone needs a conduit from the
//!   current zone for one of the edge's services, and moves the attacker into
//!   the host's zone.
//! * **`HasSession`** (computer → user): taking the credentials needs
//!   administrative access to the computer from the current zone, and moves
//!   the attacker onto it.
//! * **Every other edge** (memberships, ACLs, delegation, cloud roles) is a
//!   directory or cloud operation: no conduit needed, position unchanged.
//! * Edges into hosts without a zone are never blocked.
//!
//! Within one zone every service is allowed. A principal starts in its own
//! zone when it is a host with one, otherwise in the attacker's origin zone.

use crate::{is_principal, EdgeFilter, PathResult};
use ahash::AHashMap;
use ch_store::Graph;
use std::collections::VecDeque;

/// Node without a network zone.
pub const NO_ZONE: u16 = u16::MAX;

/// Service bits of a conduit.
pub mod svc {
    pub const SMB: u8 = 1;
    pub const RDP: u8 = 2;
    pub const WINRM: u8 = 4;
    pub const RPC: u8 = 8;
    pub const MSSQL: u8 = 16;
    pub const PLC: u8 = 32;
    pub const SSH: u8 = 64;
    pub const ANY: u8 = 0xFF;
    /// Any service that gives an administrator a remote shell.
    pub const ADMIN: u8 = SMB | RDP | WINRM | RPC;

    /// Service bit by name (`smb`, `rdp`, `winrm`, `rpc`, `mssql`, `plc`, `ssh`, `*`).
    pub fn parse(name: &str) -> Option<u8> {
        Some(match name.trim().to_ascii_lowercase().as_str() {
            "smb" => SMB,
            "rdp" => RDP,
            "winrm" => WINRM,
            "rpc" | "dcom" | "wmi" => RPC,
            "mssql" | "sql" => MSSQL,
            "plc" => PLC,
            "ssh" => SSH,
            "*" | "any" => ANY,
            _ => return None,
        })
    }

    pub const NAMES: &[&str] = &["smb", "rdp", "winrm", "rpc", "mssql", "plc", "ssh"];
}

/// Services an edge kind needs to cross into its target host (0: none).
pub fn edge_services(name: &str) -> u8 {
    match name {
        "AdminTo" => svc::ADMIN,
        "CanRDP" => svc::RDP,
        "CanPSRemote" => svc::WINRM,
        "ExecuteDCOM" => svc::RPC,
        "SQLAdmin" => svc::MSSQL,
        "CanProgram" => svc::PLC,
        _ => 0,
    }
}

/// Zones, conduits and the attacker's origin, resolved against one graph.
#[derive(Debug, Clone)]
pub struct NetModel {
    pub zones: Vec<String>,
    /// Zone per node, [`NO_ZONE`] for none.
    pub zone_of: Vec<u16>,
    /// `allow[from * zones + to]`: services allowed from one zone to another.
    allow: Vec<u8>,
    pub origin: u16,
    /// Services needed per edge kind.
    need: Vec<u8>,
    session_kind: Option<u16>,
}

impl NetModel {
    /// `conduits`: `(from, to, services)` zone indices; `zone_of` per node.
    pub fn new(g: &Graph, zones: Vec<String>, zone_of: Vec<u16>, conduits: &[(u16, u16, u8)], origin: u16) -> Self {
        assert_eq!(zone_of.len(), g.node_count(), "zone_of must cover every node");
        let z = zones.len();
        assert!(z > 0 && (origin as usize) < z && z < NO_ZONE as usize, "invalid zones / origin");
        let mut allow = vec![0u8; z * z];
        for &(a, b, s) in conduits {
            allow[a as usize * z + b as usize] |= s;
        }
        let need = (0..g.edge_kind_count()).map(|k| edge_services(g.edge_kind_name(k as u16))).collect();
        NetModel { zones, zone_of, allow, origin, need, session_kind: g.edge_kind_id("HasSession") }
    }

    #[inline]
    fn z(&self) -> usize {
        self.zones.len()
    }

    /// Services allowed from zone `a` to zone `b` (all within one zone).
    #[inline]
    pub fn conduit(&self, a: u16, b: u16) -> u8 {
        if a == b {
            svc::ANY
        } else {
            self.allow[a as usize * self.z() + b as usize]
        }
    }

    /// Where an attacker holding `n` starts.
    #[inline]
    pub fn start(&self, n: u32) -> u16 {
        match self.zone_of[n as usize] {
            NO_ZONE => self.origin,
            z => z,
        }
    }

    /// Position after following `u -k-> v` from `pos`, or `None` when the
    /// network blocks it.
    #[inline]
    pub fn step(&self, pos: u16, u: u32, v: u32, k: u16) -> Option<u16> {
        if Some(k) == self.session_kind {
            let zu = self.zone_of[u as usize];
            return if zu == NO_ZONE {
                Some(pos)
            } else if self.conduit(pos, zu) & svc::ADMIN != 0 {
                Some(zu)
            } else {
                None
            };
        }
        let need = self.need.get(k as usize).copied().unwrap_or(0);
        if need == 0 {
            return Some(pos);
        }
        let zv = self.zone_of[v as usize];
        if zv == NO_ZONE {
            Some(pos)
        } else if self.conduit(pos, zv) & need != 0 {
            Some(zv)
        } else {
            None
        }
    }
}

/// Shortest network-feasible path from any of `sources` to any of `targets`
/// (forward BFS over `(node, zone)` states).
pub fn net_shortest_path(g: &Graph, sources: &[u32], targets: &[u32], f: &EdgeFilter, m: &NetModel) -> Option<PathResult> {
    const ROOT: (u32, u16) = (u32::MAX, 0);
    let is_target: ahash::AHashSet<u32> = targets.iter().copied().collect();
    // state -> (previous state, edge kind)
    let mut prev: AHashMap<(u32, u16), ((u32, u16), u16)> = AHashMap::new();
    let mut q = VecDeque::new();
    for &s in sources {
        let st = (s, m.start(s));
        if prev.insert(st, (ROOT, 0)).is_none() {
            q.push_back(st);
        }
    }
    let mut hit = None;
    while let Some((u, pos)) = q.pop_front() {
        if is_target.contains(&u) {
            hit = Some((u, pos));
            break;
        }
        let (ds, ks) = g.out_edges(u);
        for (&v, &k) in ds.iter().zip(ks) {
            if !f.permits(g, u, v, k) {
                continue;
            }
            let Some(p2) = m.step(pos, u, v, k) else { continue };
            if let std::collections::hash_map::Entry::Vacant(e) = prev.entry((v, p2)) {
                e.insert(((u, pos), k));
                q.push_back((v, p2));
            }
        }
    }
    let mut st = hit?;
    let mut nodes = vec![st.0];
    let mut kinds = Vec::new();
    loop {
        let (p, k) = prev[&st];
        if p == ROOT {
            break;
        }
        nodes.push(p.0);
        kinds.push(k);
        st = p;
    }
    nodes.reverse();
    kinds.reverse();
    Some(PathResult { nodes, kinds, explored: prev.len() })
}

/// Principals with a network-feasible attack path to `targets`.
#[derive(Debug, Clone)]
pub struct NetExposure {
    /// Sorted principal ids (targets excluded).
    pub exposed: Vec<u32>,
    pub total_principals: u64,
}

/// Exposure toward `targets` under the network model: a reverse BFS over
/// `(node, zone)` states. A principal is exposed when its start state reaches
/// a target. `allow(src, dst, kind)` filters edges as in
/// [`crate::exposure_analysis`].
pub fn net_exposure(g: &Graph, targets: &[u32], allow: impl Fn(u32, u32, u16) -> bool, m: &NetModel) -> NetExposure {
    let n = g.node_count();
    let z = m.z();
    let idx = |v: u32, p: u16| v as usize * z + p as usize;
    let mut seen = vec![0u64; (n * z).div_ceil(64)];
    let mark = |seen: &mut Vec<u64>, i: usize| -> bool {
        let (w, b) = (i / 64, 1u64 << (i % 64));
        let new = seen[w] & b == 0;
        seen[w] |= b;
        new
    };
    let mut is_target = vec![false; n];
    let mut q: VecDeque<(u32, u16)> = VecDeque::new();
    for &t in targets {
        is_target[t as usize] = true;
        for p in 0..z as u16 {
            if mark(&mut seen, idx(t, p)) {
                q.push_back((t, p));
            }
        }
    }
    while let Some((v, p2)) = q.pop_front() {
        let (ss, ks) = g.in_edges(v);
        for (&u, &k) in ss.iter().zip(ks) {
            if is_target[u as usize] || !allow(u, v, k) {
                continue;
            }
            for p in 0..z as u16 {
                if m.step(p, u, v, k) == Some(p2) && mark(&mut seen, idx(u, p)) {
                    q.push_back((u, p));
                }
            }
        }
    }
    let mut exposed = Vec::new();
    let mut total = 0u64;
    for v in 0..n as u32 {
        if !is_principal(g.kind(v)) || is_target[v as usize] {
            continue;
        }
        total += 1;
        let i = idx(v, m.start(v));
        if seen[i / 64] & (1u64 << (i % 64)) != 0 {
            exposed.push(v);
        }
    }
    NetExposure { exposed, total_principals: total }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{exposure_analysis, shortest_path};
    use ch_model::{ek, ek_of, flags};
    use ch_store::{Edge, GraphParts};

    struct Rng(u64);
    impl Rng {
        fn below(&mut self, n: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % n
        }
    }

    /// Users, groups and computers with remote-access, session, membership
    /// and ACL edges; most computers get a random zone.
    fn random(n: u32, m: usize, seed: u64, zones: u16) -> (Graph, Vec<u16>, Vec<u32>) {
        let mut r = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
        let kinds: Vec<u8> = (0..n).map(|_| [1u8, 1, 2, 3, 3][r.below(5) as usize]).collect();
        let ks = [ek::MEMBER_OF, ek::ADMIN_TO, ek::CAN_RDP, ek::HAS_SESSION, ek::GENERIC_ALL, ek_of("CanPSRemote"), ek_of("CanProgram")];
        let edges: Vec<Edge> = (0..m)
            .map(|_| {
                let a = r.below(n as u64) as u32;
                let b = if r.below(4) == 0 { r.below(n as u64) as u32 } else { r.below(a as u64 + 1) as u32 };
                Edge::new(a, b, ks[r.below(ks.len() as u64) as usize])
            })
            .collect();
        let mut fl = vec![0u32; n as usize];
        let mut targets = Vec::new();
        for _ in 0..3 {
            let t = r.below(n as u64 / 10 + 1) as u32;
            fl[t as usize] = flags::TIER0;
            targets.push(t);
        }
        targets.sort_unstable();
        targets.dedup();
        let zone_of = kinds.iter().map(|&k| if k == 3 && r.below(5) != 0 { r.below(zones as u64) as u16 } else { NO_ZONE }).collect();
        let g = Graph::build(GraphParts {
            kinds,
            flags: fl,
            names: vec![None; n as usize],
            oids: (0..n).map(|i| format!("S-{i}")).collect(),
            props: vec![None; n as usize],
            edge_chunks: vec![edges],
            edge_kinds,
            traversable,
            node_kinds: Vec::new(),
        })
        .unwrap()
        .0;
        (g, zone_of, targets)
    }

    fn model(g: &Graph, zone_of: Vec<u16>, zones: u16, conduits: &[(u16, u16, u8)], origin: u16) -> NetModel {
        NetModel::new(g, (0..zones).map(|i| format!("Z{i}")).collect(), zone_of, conduits, origin)
    }

    #[test]
    fn open_network_matches_identity_analysis() {
        for seed in 0..60u64 {
            let (g, zone_of, targets) = random(150 + (seed as u32 * 13) % 300, 900, seed, 4);
            let all: Vec<(u16, u16, u8)> = (0..4).flat_map(|a| (0..4).map(move |b| (a, b, svc::ANY))).collect();
            let m = model(&g, zone_of, 4, &all, 0);
            let f = EdgeFilter::traversable(&g);
            let rep = exposure_analysis(&g, &targets, |s, d, k| f.permits(&g, s, d, k), 0, |_, _, _| true);
            let ne = net_exposure(&g, &targets, |s, d, k| f.permits(&g, s, d, k), &m);
            assert_eq!(ne.exposed.len() as u64, rep.exposed_principals, "seed {seed}");
            assert_eq!(ne.total_principals, rep.total_principals, "seed {seed}");
            for s in (0..g.node_count() as u32).step_by(7) {
                let a = shortest_path(&g, &[s], &targets, &f).map(|p| p.kinds.len());
                let b = net_shortest_path(&g, &[s], &targets, &f, &m).map(|p| p.kinds.len());
                assert_eq!(a, b, "seed {seed} src {s}");
            }
        }
    }

    /// Restricted conduits: exposure equals "a network-feasible path exists"
    /// per principal, and every returned path is valid hop by hop.
    #[test]
    fn exposure_matches_per_principal_search() {
        let (mut blocked, mut exposed_total) = (0, 0);
        for seed in 0..80u64 {
            let zones = 2 + (seed % 3) as u16;
            let (g, zone_of, targets) = random(120 + (seed as u32 * 17) % 250, 800, 100 + seed, zones);
            let mut r = Rng(seed + 7);
            let conduits: Vec<(u16, u16, u8)> = (0..zones * 2)
                .map(|_| {
                    let s = [svc::RDP, svc::SMB, svc::WINRM, svc::PLC, svc::ADMIN][r.below(5) as usize];
                    (r.below(zones as u64) as u16, r.below(zones as u64) as u16, s)
                })
                .collect();
            let m = model(&g, zone_of, zones, &conduits, 0);
            let f = EdgeFilter::traversable(&g);
            let ne = net_exposure(&g, &targets, |s, d, k| f.permits(&g, s, d, k), &m);
            let full = exposure_analysis(&g, &targets, |s, d, k| f.permits(&g, s, d, k), 0, |_, _, _| true);
            let set: ahash::AHashSet<u32> = ne.exposed.iter().copied().collect();
            for v in 0..g.node_count() as u32 {
                if !is_principal(g.kind(v)) || targets.contains(&v) {
                    continue;
                }
                let p = net_shortest_path(&g, &[v], &targets, &f, &m);
                assert_eq!(p.is_some(), set.contains(&v), "seed {seed} node {v}");
                if let Some(p) = p {
                    let mut pos = m.start(v);
                    for (w, &k) in p.nodes.windows(2).zip(&p.kinds) {
                        pos = m.step(pos, w[0], w[1], k).expect("every hop is allowed");
                    }
                }
            }
            blocked += full.exposed_principals - ne.exposed.len() as u64;
            exposed_total += ne.exposed.len();
        }
        assert!(blocked > 100 && exposed_total > 100, "blocked {blocked}, exposed {exposed_total}");
    }

    #[test]
    fn step_rules() {
        // 0 user -AdminTo-> 1 host(Z1) -HasSession-> 2 user ; 1 -CanProgram-> 3 plc(Z2)
        let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
        let edges = vec![Edge::new(0, 1, ek::ADMIN_TO), Edge::new(1, 2, ek::HAS_SESSION), Edge::new(1, 3, ek_of("CanProgram"))];
        let (g, _) = Graph::build(GraphParts {
            kinds: vec![1, 3, 1, 0],
            flags: vec![0, 0, 0, flags::TIER0],
            names: vec![None; 4],
            oids: (0..4).map(|i| format!("S-{i}")).collect(),
            props: vec![None; 4],
            edge_chunks: vec![edges],
            edge_kinds,
            traversable,
            node_kinds: Vec::new(),
        })
        .unwrap();
        let zone_of = vec![NO_ZONE, 1, NO_ZONE, 2];
        let f = EdgeFilter::traversable(&g);
        // Z0 -> Z1 rdp only: AdminTo allowed (rdp is an admin service); Z1 -> Z2 without plc: blocked.
        let m = model(&g, zone_of.clone(), 3, &[(0, 1, svc::RDP)], 0);
        assert_eq!(m.step(0, 0, 1, ek::ADMIN_TO), Some(1));
        assert_eq!(m.step(1, 1, 3, ek_of("CanProgram")), None);
        assert!(net_shortest_path(&g, &[0], &[3], &f, &m).is_none());
        // Session theft from Z0 needs admin access to the host.
        assert_eq!(m.step(0, 1, 2, ek::HAS_SESSION), Some(1));
        let m2 = model(&g, zone_of.clone(), 3, &[(0, 1, svc::PLC)], 0);
        assert_eq!(m2.step(0, 1, 2, ek::HAS_SESSION), None);
        // With a plc conduit Z1 -> Z2 the path exists.
        let m3 = model(&g, zone_of, 3, &[(0, 1, svc::RDP), (1, 2, svc::PLC)], 0);
        let p = net_shortest_path(&g, &[0], &[3], &f, &m3).expect("path");
        assert_eq!(p.nodes, vec![0, 1, 3]);
        assert_eq!(net_exposure(&g, &[3], |s, d, k| f.permits(&g, s, d, k), &m3).exposed, vec![0, 1]);
    }
}
