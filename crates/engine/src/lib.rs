//! CopperHound graph algorithms. All run directly on the CSR store — no query
//! planner, no database round trips.
//!
//! * [`shortest_path`] — bidirectional BFS between node sets. Explores from
//!   whichever side is cheaper each level, so a path query on a billion-edge
//!   graph typically touches a tiny fraction of it.
//! * [`tier0_analysis`] — one reverse BFS from every Tier Zero node, then a
//!   Brandes-style pass that counts, for every edge, how many principals'
//!   shortest attack paths to Tier Zero go through it. The top edges are the
//!   choke points: remediating them cuts the most attack paths. O(V + E).
//! * [`reach`] — forward blast radius of a node set.
//! * [`par_bfs`] — the shared level-synchronous, direction-optimising parallel
//!   BFS behind exposure and reach; every level of the flow pass is parallel too.

use ahash::{AHashMap, AHashSet};
use anyhow::{anyhow, Result};
use ch_model::{flags, NodeKind};
use ch_store::Graph;
use serde::Serialize;
use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicU32, Ordering as AtOrd};
use rayon::prelude::*;

const INF: u32 = u32::MAX;
const ROOT: u32 = u32::MAX;

/// Which edges a traversal may follow: a per-kind allow list plus the
/// unified Tier Zero switch.
///
/// **Unified Tier Zero** (default on): AD Tier Zero and Entra ID Tier Zero
/// are one target set and attack paths may cross the hybrid boundary (synced
/// identities, Seamless SSO, Entra Connect credentials), so an AD user whose
/// synced cloud identity is Global Admin counts as exposed, and vice versa.
/// Off: an edge between an AD object and an Entra/Azure object is never
/// followed, so each realm's principals are measured only against that
/// realm's Tier Zero.
#[derive(Clone, Debug)]
pub struct EdgeFilter {
    allow: Vec<bool>,
    unified: bool,
}

impl EdgeFilter {
    /// Edge kinds marked traversable (the default for attack paths).
    pub fn traversable(g: &Graph) -> Self {
        Self {
            allow: (0..g.edge_kind_count())
                .map(|k| g.is_traversable(k as u16))
                .collect(),
            unified: true,
        }
    }
    pub fn all(g: &Graph) -> Self {
        Self {
            allow: vec![true; g.edge_kind_count()],
            unified: true,
        }
    }
    pub fn none(g: &Graph) -> Self {
        Self {
            allow: vec![false; g.edge_kind_count()],
            unified: true,
        }
    }
    /// Set the unified Tier Zero switch (see the type docs).
    pub fn unified_tier0(mut self, on: bool) -> Self {
        self.unified = on;
        self
    }
    pub fn is_unified(&self) -> bool {
        self.unified
    }
    /// Whether the edge `src -kind-> dst` may be followed.
    #[inline]
    pub fn permits(&self, g: &Graph, src: u32, dst: u32, k: u16) -> bool {
        self.allows(k) && (self.unified || g.kind(src).is_azure() == g.kind(dst).is_azure())
    }
    pub fn set(&mut self, g: &Graph, name: &str, allowed: bool) -> Result<()> {
        let k = g
            .edge_kind_id(name)
            .ok_or_else(|| anyhow!("unknown edge kind '{name}'"))?;
        self.allow[k as usize] = allowed;
        Ok(())
    }
    #[inline]
    pub fn allows(&self, k: u16) -> bool {
        self.allow.get(k as usize).copied().unwrap_or(false)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PathResult {
    /// `nodes[i] --kinds[i]--> nodes[i+1]`
    pub nodes: Vec<u32>,
    pub kinds: Vec<u16>,
    /// Nodes touched by the search.
    pub explored: usize,
}

struct Mark {
    link: u32,
    kind: u16,
    depth: u32,
}

/// Every shortest path from `sources` to `targets`, as one subgraph.
#[derive(Debug, Clone, Serialize)]
pub struct AllShortest {
    /// Length (hops) of every path in the subgraph.
    pub length: usize,
    pub nodes: Vec<u32>,
    pub edges: Vec<(u32, u32, u16)>,
    /// One of the paths (for a hop list).
    pub one: PathResult,
    /// `max_edges` (or the search budget) cut the subgraph short.
    pub truncated: bool,
}

/// Nodes the all-shortest search may touch before it gives up on
/// completeness (returns the paths found so far, `truncated`).
const ALL_SHORTEST_BUDGET: usize = 5_000_000;

/// Union of all shortest paths from any of `sources` to any of `targets`:
/// an edge `u → v` is on one when `d(src, u) + 1 + d(v, tgt) = D`, the
/// shortest distance. Breadth-first from both ends, each bounded by `D`.
pub fn all_shortest_paths(g: &Graph, sources: &[u32], targets: &[u32], f: &EdgeFilter, max_edges: usize) -> Option<AllShortest> {
    let one = shortest_path(g, sources, targets, f)?;
    let d = one.kinds.len() as u32;
    let mut truncated = false;
    let bfs = |starts: &[u32], forward: bool, truncated: &mut bool| -> AHashMap<u32, u32> {
        let mut dist: AHashMap<u32, u32> = starts.iter().map(|&s| (s, 0)).collect();
        let mut frontier: Vec<u32> = dist.keys().copied().collect();
        let mut depth = 0;
        while !frontier.is_empty() && depth < d {
            let mut next = Vec::new();
            for &x in &frontier {
                let (ns, ks) = if forward { g.out_edges(x) } else { g.in_edges(x) };
                for (&y, &k) in ns.iter().zip(ks) {
                    let ok = if forward { f.permits(g, x, y, k) } else { f.permits(g, y, x, k) };
                    if ok && !dist.contains_key(&y) {
                        dist.insert(y, depth + 1);
                        next.push(y);
                    }
                }
            }
            if dist.len() > ALL_SHORTEST_BUDGET {
                *truncated = true;
                break;
            }
            frontier = next;
            depth += 1;
        }
        dist
    };
    let ds = bfs(sources, true, &mut truncated);
    let dt = bfs(targets, false, &mut truncated);
    let mut edges: Vec<(u32, u32, u16)> = Vec::new();
    let mut nodes: AHashSet<u32> = AHashSet::new();
    'outer: for (&u, &du) in &ds {
        if du >= d {
            continue;
        }
        let (vs, ks) = g.out_edges(u);
        for (&v, &k) in vs.iter().zip(ks) {
            if f.permits(g, u, v, k) && dt.get(&v).is_some_and(|&dv| du + 1 + dv == d) {
                if edges.len() >= max_edges {
                    truncated = true;
                    break 'outer;
                }
                edges.push((u, v, k));
                nodes.insert(u);
                nodes.insert(v);
            }
        }
    }
    // The single path is always part of the result.
    for (w, &k) in one.nodes.windows(2).zip(&one.kinds) {
        if !edges.contains(&(w[0], w[1], k)) {
            edges.push((w[0], w[1], k));
        }
        nodes.insert(w[0]);
        nodes.insert(w[1]);
    }
    edges.sort_unstable();
    let mut nodes: Vec<u32> = nodes.into_iter().collect();
    nodes.sort_unstable();
    Some(AllShortest { length: d as usize, nodes, edges, one, truncated })
}

/// Shortest path from any of `sources` to any of `targets`.
pub fn shortest_path(
    g: &Graph,
    sources: &[u32],
    targets: &[u32],
    f: &EdgeFilter,
) -> Option<PathResult> {
    let mut fw: AHashMap<u32, Mark> = AHashMap::new();
    let mut bw: AHashMap<u32, Mark> = AHashMap::new();
    let mut ff = Vec::new();
    let mut fb = Vec::new();
    for &s in sources {
        if fw
            .insert(
                s,
                Mark {
                    link: ROOT,
                    kind: 0,
                    depth: 0,
                },
            )
            .is_none()
        {
            ff.push(s);
        }
    }
    for &t in targets {
        if bw
            .insert(
                t,
                Mark {
                    link: ROOT,
                    kind: 0,
                    depth: 0,
                },
            )
            .is_none()
        {
            fb.push(t);
        }
    }
    if let Some(&m) = ff.iter().find(|s| bw.contains_key(s)) {
        return Some(build_path(&fw, &bw, m));
    }

    while !ff.is_empty() && !fb.is_empty() {
        let cost_f: usize = ff.iter().map(|&u| g.out_degree(u)).sum();
        let cost_b: usize = fb.iter().map(|&v| g.in_degree(v)).sum();
        let mut best: Option<(u32, u32)> = None;
        let mut consider = |total: u32, meet: u32| {
            if best.is_none_or(|(b, _)| total < b) {
                best = Some((total, meet));
            }
        };
        if cost_f <= cost_b {
            let mut next = Vec::new();
            for &u in &ff {
                let du = fw[&u].depth;
                let (ds, ks) = g.out_edges(u);
                for (&v, &k) in ds.iter().zip(ks) {
                    if !f.permits(g, u, v, k) || fw.contains_key(&v) {
                        continue;
                    }
                    fw.insert(
                        v,
                        Mark {
                            link: u,
                            kind: k,
                            depth: du + 1,
                        },
                    );
                    if let Some(b) = bw.get(&v) {
                        consider(du + 1 + b.depth, v);
                    }
                    next.push(v);
                }
            }
            ff = next;
        } else {
            let mut next = Vec::new();
            for &v in &fb {
                let dv = bw[&v].depth;
                let (ss, ks) = g.in_edges(v);
                for (&u, &k) in ss.iter().zip(ks) {
                    if !f.permits(g, u, v, k) || bw.contains_key(&u) {
                        continue;
                    }
                    bw.insert(
                        u,
                        Mark {
                            link: v,
                            kind: k,
                            depth: dv + 1,
                        },
                    );
                    if let Some(a) = fw.get(&u) {
                        consider(a.depth + dv + 1, u);
                    }
                    next.push(u);
                }
            }
            fb = next;
        }
        if let Some((_, m)) = best {
            return Some(build_path(&fw, &bw, m));
        }
    }
    None
}

fn build_path(fw: &AHashMap<u32, Mark>, bw: &AHashMap<u32, Mark>, meet: u32) -> PathResult {
    let mut nodes = vec![meet];
    let mut kinds = Vec::new();
    let mut x = meet;
    while let Some(m) = fw.get(&x).filter(|m| m.link != ROOT) {
        kinds.push(m.kind);
        nodes.push(m.link);
        x = m.link;
    }
    nodes.reverse();
    kinds.reverse();
    let mut x = meet;
    while let Some(m) = bw.get(&x).filter(|m| m.link != ROOT) {
        kinds.push(m.kind);
        nodes.push(m.link);
        x = m.link;
    }
    PathResult {
        nodes,
        kinds,
        explored: fw.len() + bw.len(),
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ChokeEdge {
    pub src: u32,
    pub dst: u32,
    pub kind: u16,
    /// Principals (fractionally, split across equal-length paths) whose shortest
    /// attack paths to Tier Zero traverse this edge.
    pub flow: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct KindExposure {
    pub kind: &'static str,
    pub with_path: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Tier0Report {
    pub tier0_nodes: u64,
    pub max_depth: u32,
    /// Principals (AD users/computers, Entra users/service principals/devices)
    /// with any path to Tier Zero.
    pub exposed_principals: u64,
    /// Principals outside the target set (denominator for exposure %).
    pub total_principals: u64,
    pub exposure: Vec<KindExposure>,
    pub choke_points: Vec<ChokeEdge>,
}

struct HeapItem(ChokeEdge);
impl PartialEq for HeapItem {
    fn eq(&self, o: &Self) -> bool {
        self.cmp(o) == Ordering::Equal
    }
}
impl Eq for HeapItem {}
impl PartialOrd for HeapItem {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for HeapItem {
    fn cmp(&self, o: &Self) -> Ordering {
        self.0
            .flow
            .total_cmp(&o.0.flow)
            .then_with(|| o.0.src.cmp(&self.0.src))
            .then_with(|| o.0.dst.cmp(&self.0.dst))
            .then_with(|| o.0.kind.cmp(&self.0.kind))
    }
}

/// Identities an attacker can start from: AD users and computers, Entra users,
/// service principals and devices.
pub fn is_principal(k: NodeKind) -> bool {
    matches!(
        k,
        NodeKind::User | NodeKind::Computer | NodeKind::AzUser | NodeKind::AzServicePrincipal | NodeKind::AzDevice
    )
}

/// Exposure of Tier Zero and the edges whose removal cuts the most attack paths.
pub fn tier0_analysis(g: &Graph, f: &EdgeFilter, top_k: usize) -> Tier0Report {
    let targets = g.nodes_with_flag(flags::TIER0);
    exposure_analysis(g, &targets, |s, d, k| f.permits(g, s, d, k), top_k, |_, _, _| true)
}

/// Generalised exposure analysis toward an arbitrary target set.
///
/// * `allow(src, dst, kind)` decides whether an edge may be traversed — used
///   for edge-kind filters, what-if edge / node removal and zones.
/// * `choke_ok(src, dst, kind)` filters which edges may be reported as choke
///   points (e.g. the remediation planner skips non-removable edges); it does
///   not affect exposure.
pub fn exposure_analysis(
    g: &Graph,
    targets: &[u32],
    allow: impl Fn(u32, u32, u16) -> bool + Sync,
    top_k: usize,
    choke_ok: impl Fn(u32, u32, u16) -> bool + Sync,
) -> Tier0Report {
    let n = g.node_count();
    // Reverse BFS: distance from every node to the nearest target.
    let bfs = par_bfs(g, targets, Dir::Reverse, &allow);
    let (dist, order, levels) = (&bfs.dist, &bfs.order, &bfs.levels);
    let t0 = levels.get(1).copied().unwrap_or(order.len());
    let max_depth = levels.len().saturating_sub(2) as u32;

    let on_dag = |du: u32, u: u32, v: u32, k: u16| {
        dist[v as usize] != INF && dist[v as usize] + 1 == du && allow(u, v, k)
    };

    // sigma[u] = number of shortest paths from u to a target. Level L only
    // reads level L-1, so each level is computed in parallel.
    let mut sigma = vec![0f64; n];
    for &v in &order[..t0] {
        sigma[v as usize] = 1.0;
    }
    for w in levels.windows(2).skip(1) {
        let lvl = &order[w[0]..w[1]];
        let vals: Vec<f64> = par_map(lvl, |&u| {
            let du = dist[u as usize];
            let (ds, ks) = g.out_edges(u);
            ds.iter().zip(ks).filter(|(&v, &k)| on_dag(du, u, v, k)).map(|(&v, _)| sigma[v as usize]).sum()
        });
        for (&u, s) in lvl.iter().zip(vals) {
            sigma[u as usize] = s;
        }
    }

    // One unit of flow from every exposed principal toward the targets,
    // split by path counts. Pull form: a node gathers inflow from in-edges one
    // level further out, so each level runs in parallel without write
    // conflicts, from the outermost level inward.
    let mut inflow = vec![0f64; n];
    let mut exposed = 0u64;
    for &u in &order[t0..] {
        if is_principal(g.kind(u)) {
            inflow[u as usize] = 1.0;
            exposed += 1;
        }
    }
    let by_rank = |a: &ChokeEdge, b: &ChokeEdge| HeapItem(*b).cmp(&HeapItem(*a));
    let mut heap: BinaryHeap<Reverse<HeapItem>> = BinaryHeap::with_capacity(top_k.saturating_add(1).min(1 << 16));
    for w in levels.windows(2).rev() {
        let lvl = &order[w[0]..w[1]];
        let pulled: Vec<(f64, Vec<ChokeEdge>)> = par_map(lvl, |&v| {
            let dv = dist[v as usize];
            let sv = sigma[v as usize];
            let (ss, ks) = g.in_edges(v);
            let mut acc = 0.0;
            let mut local: Vec<ChokeEdge> = Vec::new();
            for (&u, &k) in ss.iter().zip(ks) {
                let fin = inflow[u as usize];
                if fin == 0.0 || dist[u as usize] != dv + 1 || !allow(u, v, k) {
                    continue;
                }
                let fl = fin * sv / sigma[u as usize];
                acc += fl;
                if top_k > 0 && choke_ok(u, v, k) {
                    local.push(ChokeEdge { src: u, dst: v, kind: k, flow: fl });
                }
            }
            if local.len() > top_k {
                local.select_nth_unstable_by(top_k, by_rank);
                local.truncate(top_k);
            }
            (acc, local)
        });
        for (&v, (acc, local)) in lvl.iter().zip(pulled) {
            if dist[v as usize] > 0 {
                inflow[v as usize] += acc;
            }
            for item in local {
                let item = HeapItem(item);
                if heap.len() < top_k {
                    heap.push(Reverse(item));
                } else if heap.peek().is_some_and(|m| item > m.0) {
                    heap.pop();
                    heap.push(Reverse(item));
                }
            }
        }
    }
    let mut choke: Vec<ChokeEdge> = heap.into_iter().map(|r| r.0 .0).collect();
    choke.sort_by(by_rank);

    let mut total = [0u64; NodeKind::COUNT];
    let mut with = [0u64; NodeKind::COUNT];
    let mut total_principals = 0u64;
    for (i, &k) in g.kinds().iter().enumerate() {
        let k = (k as usize).min(NodeKind::COUNT - 1);
        total[k] += 1;
        if dist[i] != INF && dist[i] > 0 {
            with[k] += 1;
        }
        if dist[i] != 0 && is_principal(NodeKind::ALL[k]) {
            total_principals += 1;
        }
    }
    let exposure = NodeKind::ALL
        .iter()
        .enumerate()
        .filter(|(i, _)| total[*i] > 0)
        .map(|(i, k)| KindExposure {
            kind: k.as_str(),
            with_path: with[i],
            total: total[i],
        })
        .collect();

    Tier0Report {
        tier0_nodes: t0 as u64,
        max_depth,
        exposed_principals: exposed,
        total_principals,
        exposure,
        choke_points: choke,
    }
}

/// Below this many items a level is processed on the calling thread.
const PAR_MIN: usize = 2048;

fn par_map<T: Sync, R: Send>(xs: &[T], f: impl Fn(&T) -> R + Sync + Send) -> Vec<R> {
    if xs.len() < PAR_MIN {
        xs.iter().map(f).collect()
    } else {
        xs.par_iter().map(f).collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// Follow edges forward (`u -> v`): what the seeds can reach.
    Forward,
    /// Follow edges backward: who can reach the seeds.
    Reverse,
}

/// Result of [`par_bfs`]. `order` lists visited nodes level by level: level
/// `i` is `order[levels[i]..levels[i + 1]]`, sorted by id.
pub struct Bfs {
    pub dist: Vec<u32>,
    pub order: Vec<u32>,
    pub levels: Vec<usize>,
}

/// Level-synchronous, direction-optimising parallel BFS (Beamer et al.).
///
/// Small frontiers expand top-down, claiming nodes with a CAS. Once the
/// frontier's edges exceed a fraction of the unvisited edges it switches to
/// bottom-up: every unvisited node scans its own adjacency for a frontier
/// neighbour and stops at the first hit, which visits far fewer edges on the
/// dense middle levels of real AD / Entra graphs. `allow(u, v, k)` always
/// receives the edge in its stored direction. Output is deterministic.
pub fn par_bfs(g: &Graph, seeds: &[u32], dir: Dir, allow: &(impl Fn(u32, u32, u16) -> bool + Sync)) -> Bfs {
    let n = g.node_count();
    let dist: Vec<AtomicU32> = (0..n).map(|_| AtomicU32::new(INF)).collect();
    let mut frontier: Vec<u32> = Vec::new();
    for &s in seeds {
        if (s as usize) < n && dist[s as usize].swap(0, AtOrd::Relaxed) == INF {
            frontier.push(s);
        }
    }
    frontier.sort_unstable();
    let fwd = |x: u32| if dir == Dir::Forward { g.out_edges(x) } else { g.in_edges(x) };
    let back = |x: u32| if dir == Dir::Forward { g.in_edges(x) } else { g.out_edges(x) };
    let edge_ok = |from: u32, to: u32, k: u16| {
        if dir == Dir::Forward {
            allow(from, to, k)
        } else {
            allow(to, from, k)
        }
    };

    let mut order: Vec<u32> = Vec::with_capacity(frontier.len());
    let mut levels: Vec<usize> = vec![0];
    let parallel = n > PAR_MIN;
    let mut unvisited_edges = g.edge_count() as u64;
    let mut level = 0u32;
    while !frontier.is_empty() {
        order.extend_from_slice(&frontier);
        levels.push(order.len());
        let next_lvl = level + 1;
        let frontier_edges: u64 = if frontier.len() < PAR_MIN {
            frontier.iter().map(|&x| fwd(x).0.len() as u64).sum()
        } else {
            frontier.par_iter().map(|&x| fwd(x).0.len() as u64).sum()
        };
        unvisited_edges = unvisited_edges.saturating_sub(frontier_edges);
        let bottom_up = parallel && frontier_edges.saturating_mul(14) > unvisited_edges;
        let mut next: Vec<u32> = if bottom_up {
            let found: Vec<u32> = (0..n as u32)
                .into_par_iter()
                .filter(|&x| {
                    if dist[x as usize].load(AtOrd::Relaxed) != INF {
                        return false;
                    }
                    let (ys, ks) = back(x);
                    ys.iter()
                        .zip(ks)
                        .any(|(&y, &k)| dist[y as usize].load(AtOrd::Relaxed) == level && edge_ok(y, x, k))
                })
                .collect();
            // Marked after the scan so every check above saw a stable level.
            found.par_iter().for_each(|&x| dist[x as usize].store(next_lvl, AtOrd::Relaxed));
            found
        } else {
            let expand = |x: u32, out: &mut Vec<u32>| {
                let (ys, ks) = fwd(x);
                for (&y, &k) in ys.iter().zip(ks) {
                    if dist[y as usize].load(AtOrd::Relaxed) == INF
                        && edge_ok(x, y, k)
                        && dist[y as usize].compare_exchange(INF, next_lvl, AtOrd::Relaxed, AtOrd::Relaxed).is_ok()
                    {
                        out.push(y);
                    }
                }
            };
            if frontier.len() < PAR_MIN {
                let mut out = Vec::new();
                for &x in &frontier {
                    expand(x, &mut out);
                }
                out
            } else {
                frontier
                    .par_iter()
                    .fold(Vec::new, |mut out, &x| {
                        expand(x, &mut out);
                        out
                    })
                    .reduce(Vec::new, |mut a, mut b| {
                        a.append(&mut b);
                        a
                    })
            }
        };
        if next.len() < PAR_MIN {
            next.sort_unstable();
        } else {
            next.par_sort_unstable();
        }
        frontier = next;
        level = next_lvl;
    }
    let dist = dist.into_iter().map(AtomicU32::into_inner).collect();
    Bfs { dist, order, levels }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReachReport {
    pub reachable: u64,
    pub max_depth: u32,
    pub tier0_reached: u64,
    pub by_kind: Vec<KindExposure>,
}

/// Forward blast radius: everything reachable from `sources`.
pub fn reach(g: &Graph, sources: &[u32], f: &EdgeFilter) -> ReachReport {
    let bfs = par_bfs(g, sources, Dir::Forward, &|s, d, k| f.permits(g, s, d, k));
    let (dist, q) = (&bfs.dist, &bfs.order);
    let seeds = bfs.levels.get(1).copied().unwrap_or(0);
    let mut by = [0u64; NodeKind::COUNT];
    let mut tier0 = 0;
    for &v in &q[seeds..] {
        by[(g.kind(v) as usize).min(NodeKind::COUNT - 1)] += 1;
        if g.has_flag(v, flags::TIER0) {
            tier0 += 1;
        }
    }
    let by_kind = NodeKind::ALL
        .iter()
        .enumerate()
        .filter(|(i, _)| by[*i] > 0)
        .map(|(i, k)| KindExposure {
            kind: k.as_str(),
            with_path: by[i],
            total: 0,
        })
        .collect();
    ReachReport {
        reachable: (q.len() - seeds) as u64,
        max_depth: q.last().map(|&v| dist[v as usize]).unwrap_or(0),
        tier0_reached: tier0,
        by_kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ch_model::ek;
    use ch_store::{Edge, GraphParts};

    /// 0 alice(User) -MemberOf-> 1 helpdesk(Group) -AdminTo-> 2 ws(Computer)
    /// -HasSession-> 3 bob(User) -MemberOf-> 4 DA(Group, T0);
    /// 0 -GetChanges-> 4 (non-traversable)
    fn graph() -> Graph {
        let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
        let (g, _) = Graph::build(GraphParts {
            kinds: vec![1, 2, 3, 1, 2],
            flags: vec![0, 0, 0, 0, flags::TIER0],
            names: vec![None; 5],
            oids: (0..5).map(|i| format!("S-{i}")).collect(),
            props: vec![None; 5],
            edge_chunks: vec![vec![
                Edge::new(0, 1, ek::MEMBER_OF),
                Edge::new(1, 2, ek::ADMIN_TO),
                Edge::new(2, 3, ek::HAS_SESSION),
                Edge::new(3, 4, ek::MEMBER_OF),
                Edge::new(0, 4, ek::GET_CHANGES),
            ]],
            edge_kinds,
            traversable,
            node_kinds: Vec::new(),
        })
        .unwrap();
        g
    }

    /// Every shortest path, checked against brute-force enumeration of all
    /// paths of the shortest length on small random graphs.
    #[test]
    fn all_shortest_paths_match_enumeration() {
        for seed in 1..40u64 {
            let g = random_graph(40, 110, seed);
            let f = EdgeFilter::traversable(&g);
            let (src, dst) = ((seed % 40) as u32, ((seed * 7 + 3) % 40) as u32);
            if src == dst {
                continue;
            }
            let got = all_shortest_paths(&g, &[src], &[dst], &f, usize::MAX);
            let Some(one) = shortest_path(&g, &[src], &[dst], &f) else {
                assert!(got.is_none());
                continue;
            };
            let d = one.kinds.len();
            // Enumerate every walk of exactly d permitted hops from src ending at dst.
            let mut want: AHashSet<(u32, u32, u16)> = AHashSet::new();
            fn walk(g: &Graph, f: &EdgeFilter, u: u32, dst: u32, left: usize, path: &mut Vec<(u32, u32, u16)>, out: &mut AHashSet<(u32, u32, u16)>) {
                if left == 0 {
                    if u == dst {
                        out.extend(path.iter().copied());
                    }
                    return;
                }
                let (vs, ks) = g.out_edges(u);
                for (&v, &k) in vs.iter().zip(ks) {
                    if f.permits(g, u, v, k) {
                        path.push((u, v, k));
                        walk(g, f, v, dst, left - 1, path, out);
                        path.pop();
                    }
                }
            }
            walk(&g, &f, src, dst, d, &mut Vec::new(), &mut want);
            let got = got.expect("a path exists");
            assert_eq!(got.length, d);
            let got_set: AHashSet<(u32, u32, u16)> = got.edges.iter().copied().collect();
            assert_eq!(got_set, want, "seed {seed}");
            assert!(!got.truncated);
        }
    }

    #[test]
    fn all_shortest_paths_diamond() {
        // 0→1→3, 0→2→3 (both length 2), 0→4→5→3 (longer); 1→3 twice via different kinds.
        let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
        let (g, _) = Graph::build(GraphParts {
            kinds: vec![1; 6],
            flags: vec![0; 6],
            names: vec![None; 6],
            oids: (0..6).map(|i| format!("S-{i}")).collect(),
            props: vec![None; 6],
            edge_chunks: vec![vec![
                Edge::new(0, 1, ek::MEMBER_OF),
                Edge::new(1, 3, ek::ADMIN_TO),
                Edge::new(0, 2, ek::MEMBER_OF),
                Edge::new(2, 3, ek::ADMIN_TO),
                Edge::new(0, 4, ek::MEMBER_OF),
                Edge::new(4, 5, ek::MEMBER_OF),
                Edge::new(5, 3, ek::MEMBER_OF),
            ]],
            edge_kinds,
            traversable,
            node_kinds: Vec::new(),
        })
        .unwrap();
        let r = all_shortest_paths(&g, &[0], &[3], &EdgeFilter::traversable(&g), 100).unwrap();
        assert_eq!(r.length, 2);
        assert_eq!(r.nodes, vec![0, 1, 2, 3]);
        assert_eq!(r.edges.len(), 4);
        let capped = all_shortest_paths(&g, &[0], &[3], &EdgeFilter::traversable(&g), 1).unwrap();
        assert!(capped.truncated);
        assert!(capped.edges.len() >= 2, "the single path is always included");
    }

    /// Random graph large enough to exercise the parallel and bottom-up paths.
    fn random_graph(n: u32, m: usize, seed: u64) -> Graph {
        let mut x = seed;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
        let kinds: Vec<u8> = (0..n).map(|_| [1u8, 2, 3][(rnd() % 3) as usize]).collect();
        let flags: Vec<u32> = (0..n).map(|i| if i % 997 == 0 { flags::TIER0 } else { 0 }).collect();
        let edges: Vec<Edge> = (0..m)
            .map(|_| {
                let kind = [ek::MEMBER_OF, ek::ADMIN_TO, ek::GET_CHANGES][(rnd() % 3) as usize];
                Edge::new((rnd() % n as u64) as u32, (rnd() % n as u64) as u32, kind)
            })
            .collect();
        Graph::build(GraphParts {
            kinds,
            flags,
            names: vec![None; n as usize],
            oids: (0..n).map(|i| format!("S-{i}")).collect(),
            props: vec![None; n as usize],
            edge_chunks: vec![edges],
            edge_kinds,
            traversable,
            node_kinds: Vec::new(),
        })
        .unwrap()
        .0
    }

    /// Plain sequential BFS distances (reverse direction) as the reference.
    fn reference_dist(g: &Graph, seeds: &[u32], f: &EdgeFilter) -> Vec<u32> {
        let mut d = vec![INF; g.node_count()];
        let mut q = std::collections::VecDeque::new();
        for &s in seeds {
            d[s as usize] = 0;
            q.push_back(s);
        }
        while let Some(v) = q.pop_front() {
            let (ss, ks) = g.in_edges(v);
            for (&u, &k) in ss.iter().zip(ks) {
                if f.allows(k) && d[u as usize] == INF {
                    d[u as usize] = d[v as usize] + 1;
                    q.push_back(u);
                }
            }
        }
        d
    }

    #[test]
    fn parallel_bfs_matches_sequential() {
        for (n, m, seed) in [(60_000u32, 90_000usize, 7u64), (40_000, 400_000, 11), (5_000, 4_000, 3)] {
            let g = random_graph(n, m, seed);
            let f = EdgeFilter::traversable(&g);
            let seeds = g.nodes_with_flag(flags::TIER0);
            let want = reference_dist(&g, &seeds, &f);
            let got = par_bfs(&g, &seeds, Dir::Reverse, &|_, _, k| f.allows(k));
            assert_eq!(got.dist, want, "n={n} m={m}");
            assert_eq!(got.order.len(), want.iter().filter(|&&d| d != INF).count());
            for (i, w) in got.levels.windows(2).enumerate() {
                assert!(got.order[w[0]..w[1]].iter().all(|&v| got.dist[v as usize] == i as u32));
            }
            let r = tier0_analysis(&g, &f, 10);
            let exposed = (0..n).filter(|&i| want[i as usize] != INF && want[i as usize] > 0).count() as u64;
            assert!(r.exposed_principals <= exposed);
            // Flow is conserved: every exposed principal's unit arrives at a target.
            let full = exposure_analysis(&g, &seeds, |_, _, k| f.allows(k), usize::MAX, |u, v, _| {
                want[v as usize] == 0 && want[u as usize] == 1
            });
            let total: f64 = full.choke_points.iter().map(|c| c.flow).sum();
            assert!((total - full.exposed_principals as f64).abs() < 1e-6 * total.max(1.0), "{total} vs {}", full.exposed_principals);
            let fwd = reach(&g, &[0], &f);
            assert_eq!(fwd.reachable as usize + 1, {
                let mut d = vec![false; n as usize];
                let mut st = vec![0u32];
                d[0] = true;
                let mut c = 1;
                while let Some(u) = st.pop() {
                    let (ds, ks) = g.out_edges(u);
                    for (&v, &k) in ds.iter().zip(ks) {
                        if f.allows(k) && !d[v as usize] {
                            d[v as usize] = true;
                            c += 1;
                            st.push(v);
                        }
                    }
                }
                c
            });
        }
    }

    #[test]
    fn path_respects_filter() {
        let g = graph();
        let p = shortest_path(&g, &[0], &[4], &EdgeFilter::traversable(&g)).unwrap();
        assert_eq!(p.nodes, vec![0, 1, 2, 3, 4]);
        assert_eq!(
            p.kinds,
            vec![ek::MEMBER_OF, ek::ADMIN_TO, ek::HAS_SESSION, ek::MEMBER_OF]
        );
        let p = shortest_path(&g, &[0], &[4], &EdgeFilter::all(&g)).unwrap();
        assert_eq!(p.nodes, vec![0, 4]);
        assert!(shortest_path(&g, &[4], &[0], &EdgeFilter::all(&g)).is_none());
    }

    #[test]
    fn tier0_choke_points() {
        let g = graph();
        let r = tier0_analysis(&g, &EdgeFilter::traversable(&g), 3);
        assert_eq!(r.tier0_nodes, 1);
        assert_eq!(r.max_depth, 4);
        assert_eq!(r.exposed_principals, 3); // alice, ws, bob
        let top = r.choke_points[0];
        assert_eq!((top.src, top.dst), (3, 4));
        assert!((top.flow - 3.0).abs() < 1e-9);
    }

    #[test]
    fn unified_tier0_crosses_hybrid_boundary() {
        // 0 AD user -SyncedToEntraUser-> 1 AZUser -AZGlobalAdmin-> 2 AZTenant (T0)
        let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
        let k = |n: &str| ch_model::builtin_edge_kind(n).unwrap();
        let (g, _) = Graph::build(GraphParts {
            kinds: vec![NodeKind::User as u8, NodeKind::AzUser as u8, NodeKind::AzTenant as u8],
            flags: vec![0, 0, flags::TIER0],
            names: vec![None; 3],
            oids: (0..3).map(|i| format!("X-{i}")).collect(),
            props: vec![None; 3],
            edge_chunks: vec![vec![Edge::new(0, 1, k("SyncedToEntraUser")), Edge::new(1, 2, k("AZGlobalAdmin"))]],
            edge_kinds,
            traversable,
            node_kinds: Vec::new(),
        })
        .unwrap();
        let unified = EdgeFilter::traversable(&g);
        assert!(unified.is_unified());
        let r = tier0_analysis(&g, &unified, 3);
        assert_eq!(r.exposed_principals, 2);
        assert!(shortest_path(&g, &[0], &[2], &unified).is_some());

        let split = EdgeFilter::traversable(&g).unified_tier0(false);
        let r = tier0_analysis(&g, &split, 3);
        assert_eq!(r.exposed_principals, 1, "only the Entra user stays exposed");
        assert!(shortest_path(&g, &[0], &[2], &split).is_none());
        assert_eq!(reach(&g, &[0], &split).reachable, 0);
    }

    #[test]
    fn reach_counts() {
        let g = graph();
        let r = reach(&g, &[0], &EdgeFilter::traversable(&g));
        assert_eq!(r.reachable, 4);
        assert_eq!(r.tier0_reached, 1);
    }
}
