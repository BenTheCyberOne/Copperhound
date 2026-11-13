//! What-if exposure and greedy remediation planning.

use crate::{EdgeKey, Removal};
use ch_engine::{exposure_analysis, par_bfs, Dir, EdgeFilter, Tier0Report};
use ch_model::ek;
use ch_query::Cancel;
use ch_store::Graph;
use rayon::prelude::*;
use serde::Serialize;

/// Exposure toward `targets` with traversable edges, minus `removal`.
pub fn exposure_with(g: &Graph, targets: &[u32], removal: &Removal, top_k: usize) -> Tier0Report {
    let f = EdgeFilter::traversable(g);
    exposure_analysis(g, targets, |s, d, k| f.allows(k) && !removal.blocks(s, d, k), top_k, |_, _, _| true)
}

#[derive(Debug, Clone, Serialize)]
pub struct SimResult {
    pub before: Tier0Report,
    pub after: Tier0Report,
    pub reduction: u64,
    pub reduction_percent: f64,
}

pub fn simulate(g: &Graph, targets: &[u32], added_targets: &[u32], removal: &Removal) -> SimResult {
    let before = exposure_with(g, targets, &Removal::default(), 0);
    let mut t2: Vec<u32> = targets.to_vec();
    t2.extend_from_slice(added_targets);
    t2.sort_unstable();
    t2.dedup();
    let after = exposure_with(g, &t2, removal, 0);
    let reduction = before.exposed_principals.saturating_sub(after.exposed_principals);
    let reduction_percent = if before.exposed_principals == 0 {
        0.0
    } else {
        100.0 * (before.exposed_principals as f64 - after.exposed_principals as f64) / before.exposed_principals as f64
    };
    SimResult { before, after, reduction, reduction_percent }
}

#[derive(Debug, Clone, Default)]
pub struct PlanOptions {
    pub steps: usize,
    pub fixed_kinds: Vec<u16>,
    /// Do not propose removing `MemberOf` / `AZMemberOf` edges into target members.
    pub protect_target_membership: bool,
    /// Per-node fix cost ([`FixCost`] as `u8`), e.g. from [`fix_costs`]. An
    /// edge costs the higher of its two ends. Choke objects with a `Fixed`
    /// onward edge are never proposed; steps with a `Window` edge are flagged.
    pub node_cost: Option<Vec<u8>>,
    /// Prefer choke objects that need no maintenance window: every live step
    /// comes before any window step (each group ordered by cut).
    pub live_first: bool,
}

/// How hard it is to change an object (node property `fix_cost`, docs/OT.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum FixCost {
    /// Can be changed any time (default).
    Live = 0,
    /// Needs a maintenance window (reboot, process stop, vendor visit).
    Window = 1,
    /// Must not be changed (certified configuration, safety system).
    Fixed = 2,
}

/// Fix costs from the `fix_cost` node property (`window` / `fixed`, case-
/// insensitive); `None` when no node has one.
pub fn fix_costs(g: &Graph) -> Option<Vec<u8>> {
    let mut cost = vec![FixCost::Live as u8; g.node_count()];
    let mut any = false;
    for (value, c) in [("window", FixCost::Window), ("fixed", FixCost::Fixed)] {
        let q = format!("MATCH (n) WHERE n.fix_cost = '{value}' RETURN n");
        let cap = g.node_count().max(1);
        match ch_query::run_capped(g, &q, cap, cap, &Cancel::never()) {
            Ok(r) => {
                for n in r.nodes {
                    cost[n as usize] = cost[n as usize].max(c as u8);
                    any = true;
                }
            }
            Err(e) => panic!("fix_cost selector failed: {e}"),
        }
    }
    any.then_some(cost)
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanStep {
    /// The choke object: every path from the cut principals passes through it.
    pub node: u32,
    /// Its onward attack edges to remove (all of them, so the cut is exact).
    pub edges: Vec<EdgeKey>,
    pub principals_cut: u64,
    pub exposed_after: u64,
    pub cumulative_reduction_percent: f64,
    /// Some edge of this step touches an object whose fix needs a maintenance window.
    pub needs_window: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub baseline: u64,
    pub steps: Vec<PlanStep>,
    /// True when the planner stopped early (cancelled / timed out).
    pub truncated: bool,
}

/// Targets plus everything that reaches them through group membership only
/// (members of Tier Zero groups are Tier Zero in practice).
pub fn expand_membership(g: &Graph, targets: &[u32]) -> Vec<u32> {
    let kinds = [ek::MEMBER_OF, ch_model::ek_of("AZMemberOf")];
    let mut seen = vec![false; g.node_count()];
    let mut out: Vec<u32> = Vec::with_capacity(targets.len());
    for &t in targets {
        if !seen[t as usize] {
            seen[t as usize] = true;
            out.push(t);
        }
    }
    let mut head = 0;
    while head < out.len() {
        let v = out[head];
        head += 1;
        let (ss, ks) = g.in_edges(v);
        for (&u, k) in ss.iter().zip(ks) {
            if kinds.contains(k) && !seen[u as usize] {
                seen[u as usize] = true;
                out.push(u);
            }
        }
    }
    out
}

const UNDEF: u32 = u32::MAX;
/// `pre` marker for a reached leaf (leaves get no preorder number).
const LEAF_REACHED: u32 = u32::MAX - 1;
/// Candidates the planner inspects per step for one whose edges are all removable.
const PICK_WINDOW: usize = 256;

/// Compact adjacency lists over planner-local node ids.
struct Csr {
    off: Vec<usize>,
    adj: Vec<u32>,
}

impl Csr {
    /// Build in parallel; `fill(i, out)` appends node `i`'s neighbours.
    fn build(m: usize, fill: impl Fn(usize, &mut Vec<u32>) + Sync) -> Csr {
        const CHUNK: usize = 1 << 14;
        let parts: Vec<(Vec<u32>, Vec<u32>)> = (0..m.div_ceil(CHUNK))
            .into_par_iter()
            .map(|c| {
                let (lo, hi) = (c * CHUNK, ((c + 1) * CHUNK).min(m));
                let mut deg = Vec::with_capacity(hi - lo);
                let mut adj = Vec::new();
                for i in lo..hi {
                    let before = adj.len();
                    fill(i, &mut adj);
                    deg.push((adj.len() - before) as u32);
                }
                (deg, adj)
            })
            .collect();
        let mut off = Vec::with_capacity(m + 1);
        off.push(0);
        let mut adj = Vec::with_capacity(parts.iter().map(|p| p.1.len()).sum());
        let mut end = 0usize;
        for (deg, a) in parts {
            for d in deg {
                end += d as usize;
                off.push(end);
            }
            adj.extend_from_slice(&a);
        }
        Csr { off, adj }
    }
    #[inline]
    fn get(&self, i: u32) -> &[u32] {
        &self.adj[self.off[i as usize]..self.off[i as usize + 1]]
    }
}

/// One dominator analysis: exposure and the best choke objects.
struct DomResult {
    exposed: u64,
    /// `(node, principals it alone cuts off)`, best first (ties: lower id);
    /// only the top [`PICK_WINDOW`].
    ranked: Vec<(u32, u64)>,
}

/// Incremental state of the remediation planner.
///
/// The reverse attack graph (virtual root → zone → their attackers, …) is
/// extracted once, after a parallel reachability BFS, into compact local ids
/// and CSR arrays. Severing a choke object (all its onward edges) is the same
/// as deleting that node — it and everything it dominated become unreachable,
/// and reachability only ever shrinks — so later steps just mark it dead and
/// rerun the dominator pass on the same arrays, reusing every buffer.
///
/// Dominators use Semi-NCA (Georgiadis/Tarjan, as in LLVM): one DFS plus a
/// near-linear semidominator pass, instead of iterating to a fixpoint. It runs
/// on the *core* only — nodes that have attackers. Leaves of the reverse graph
/// (nobody attacks them, typically most users) never lie on another node's
/// path, so they are left out of the DFS and get their immediate dominator
/// afterwards, in parallel, as the nearest common dominator-tree ancestor of
/// their onward targets. Dominator trees are unique, so the plan is identical
/// to recomputing everything from scratch each step (see the reference test).
struct Planner {
    /// Local → global id. Local 0 is the virtual root, `1..ncore` the core in
    /// DFS preorder (so later DFS passes walk memory almost sequentially),
    /// `ncore..` the leaves.
    nodes: Vec<u32>,
    ncore: usize,
    /// Global → local id, `UNDEF` if never reachable.
    local: Vec<u32>,
    /// Reverse-graph successors (attackers) of core nodes, core only; for the
    /// root, the zone's core nodes.
    succ: Csr,
    /// Reverse-graph predecessors (onward targets) of every node; `[0]` for
    /// zone nodes. Never contains a leaf.
    pred: Csr,
    /// Counts as exposed when reachable (a principal outside the zone).
    principal: Vec<bool>,
    target: Vec<bool>,
    dead: Vec<bool>,
    /// `pre`/`vert`/`parent` already hold the DFS of the current graph.
    fresh: bool,
    // Per-step scratch, reused: `pre` is indexed by local id, the rest by preorder.
    pre: Vec<u32>,
    vert: Vec<u32>,
    parent: Vec<u32>,
    semi: Vec<u32>,
    /// `[ancestor, min semidominator on the compressed path]` per vertex, packed
    /// so each hop of `eval` is one cache miss.
    link: Vec<[u32; 2]>,
    idom: Vec<u32>,
    cnt: Vec<u64>,
}

/// Preorder DFS over the live core from the root: fills `pre` (local → preorder),
/// `vert` (preorder → local) and `parent` (preorder → preorder). `None` if cancelled.
fn core_dfs(
    succ: &Csr,
    dead: &[bool],
    pre: &mut [u32],
    vert: &mut Vec<u32>,
    parent: &mut Vec<u32>,
    cancel: &Cancel,
) -> Option<()> {
    pre.fill(UNDEF);
    vert.clear();
    parent.clear();
    pre[0] = 0;
    vert.push(0);
    parent.push(0);
    let mut stack: Vec<(u32, usize)> = vec![(0, 0)];
    while let Some(&mut (v, ref mut i)) = stack.last_mut() {
        let s = succ.get(v);
        let mut next = None;
        while *i < s.len() {
            let u = s[*i];
            *i += 1;
            if pre[u as usize] == UNDEF && !dead[u as usize] {
                next = Some(u);
                break;
            }
        }
        match next {
            Some(u) => {
                pre[u as usize] = vert.len() as u32;
                parent.push(pre[v as usize]);
                vert.push(u);
                stack.push((u, 0));
                if vert.len().is_multiple_of(1 << 16) && cancel.hit() {
                    return None;
                }
            }
            None => {
                stack.pop();
            }
        }
    }
    Some(())
}

impl Planner {
    fn new(g: &Graph, zone: &[u32], f: &EdgeFilter, cancel: &Cancel) -> Option<Self> {
        let n = g.node_count();
        let mut is_target = vec![false; n];
        for &t in zone {
            is_target[t as usize] = true;
        }
        // An attack edge u → v in the reverse graph: zone nodes are only entered
        // from the root, and self-loops never matter for dominance.
        let attack = |u: u32, v: u32, k: u16| u != v && f.allows(k) && !is_target[u as usize];
        let bfs = par_bfs(g, zone, Dir::Reverse, &|_, _, k| f.allows(k));
        let order = &bfs.order;
        let m = order.len() + 1;
        // Provisional local ids in BFS order. Every attacker of a reachable node
        // is reachable, so `local[u]` is defined for every attack edge below.
        let mut local = vec![UNDEF; n];
        for (i, &v) in order.iter().enumerate() {
            local[v as usize] = i as u32 + 1;
        }
        let mut core = vec![true];
        core.par_extend(order.par_iter().map(|&v| {
            let (ss, ks) = g.in_edges(v);
            ss.iter().zip(ks).any(|(&u, &k)| attack(u, v, k))
        }));
        // Dense ids for the core alone (root = 0), so the first DFS stays in cache.
        let mut cid = vec![UNDEF; m];
        let mut corder: Vec<u32> = Vec::new();
        for (l, _) in core.iter().enumerate().filter(|c| *c.1) {
            cid[l] = corder.len() as u32;
            corder.push(l as u32);
        }
        let ncore = corder.len();
        let core_id = |u: u32| cid[local[u as usize] as usize];
        let mut zone_core: Vec<u32> = zone.iter().map(|&t| core_id(t)).filter(|&c| c != UNDEF).collect();
        zone_core.sort_unstable();
        zone_core.dedup();
        let succ0 = Csr::build(ncore, |c, out| {
            if c == 0 {
                out.extend_from_slice(&zone_core);
                return;
            }
            let v = order[corder[c] as usize - 1];
            let (ss, ks) = g.in_edges(v);
            out.extend(ss.iter().zip(ks).filter(|&(&u, &k)| attack(u, v, k)).map(|(&u, _)| core_id(u)).filter(|&c| c != UNDEF));
        });
        let (mut vert, mut parent) = (Vec::new(), Vec::new());
        let mut pre0 = vec![UNDEF; ncore];
        core_dfs(&succ0, &vec![false; ncore], &mut pre0, &mut vert, &mut parent, cancel)?;
        // Every core node is reachable through core nodes only.
        debug_assert_eq!(vert.len(), ncore);
        // Final ids: root, core in DFS preorder, then the leaves. Relabelled,
        // that DFS tree is exactly the first step's (preorder = local id).
        let mut nodes = Vec::with_capacity(m);
        nodes.push(UNDEF);
        nodes.extend(vert[1..].iter().map(|&c| order[corder[c as usize] as usize - 1]));
        nodes.extend((1..m).filter(|&i| !core[i]).map(|i| order[i - 1]));
        debug_assert_eq!(nodes.len(), m);
        drop((cid, corder));
        for (i, &v) in nodes.iter().enumerate().skip(1) {
            local[v as usize] = i as u32;
        }
        let succ = Csr::build(ncore, |i, out| out.extend(succ0.get(vert[i]).iter().map(|&u| pre0[u as usize])));
        drop((succ0, pre0));
        let dead = vec![false; m];
        let mut pre = vec![UNDEF; m];
        for (i, p) in pre[..ncore].iter_mut().enumerate() {
            *p = i as u32;
        }
        for (i, v) in vert.iter_mut().enumerate() {
            *v = i as u32;
        }
        let pred = Csr::build(m, |i, out| {
            if i == 0 {
                return;
            }
            let b = nodes[i];
            if is_target[b as usize] {
                out.push(0);
                return;
            }
            let (ds, ks) = g.out_edges(b);
            out.extend(ds.iter().zip(ks).filter(|&(&v, &k)| attack(b, v, k) && local[v as usize] != UNDEF).map(|(&v, _)| local[v as usize]));
        });
        let target: Vec<bool> = nodes.iter().map(|&v| v != UNDEF && is_target[v as usize]).collect();
        let principal: Vec<bool> =
            nodes.iter().zip(&target).map(|(&v, &t)| v != UNDEF && !t && crate::is_principal(g.kind(v))).collect();
        Some(Planner {
            nodes,
            ncore,
            local,
            succ,
            pred,
            principal,
            target,
            dead,
            fresh: true,
            pre,
            vert,
            parent,
            semi: Vec::new(),
            link: Vec::new(),
            idom: Vec::new(),
            cnt: Vec::new(),
        })
    }

    /// Reachable (exposed or zone) in the last [`Self::dominate`] run.
    fn reachable(&self, v: u32) -> bool {
        let l = self.local[v as usize];
        l != UNDEF && self.pre[l as usize] != UNDEF
    }

    /// `v` is a zone member (after membership expansion).
    fn is_target(&self, v: u32) -> bool {
        let l = self.local[v as usize];
        l != UNDEF && self.target[l as usize]
    }

    /// Principals `v` alone cuts off in the last [`Self::dominate`] run (0 for
    /// zone members and unreachable nodes).
    fn cut_of(&self, v: u32) -> u64 {
        let l = self.local[v as usize];
        if l == UNDEF || self.target[l as usize] {
            return 0;
        }
        match self.pre[l as usize] {
            UNDEF => 0,
            LEAF_REACHED => self.principal[l as usize] as u64,
            p => self.cnt[p as usize],
        }
    }

    /// Every node that cuts at least one principal off in the last
    /// [`Self::dominate`] run, with its cut (zone members excluded).
    fn for_each_cut(&self, mut f: impl FnMut(u32, u64)) {
        for (w, &c) in self.cnt.iter().enumerate().skip(1) {
            let l = self.vert[w] as usize;
            if c > 0 && !self.target[l] {
                f(self.nodes[l], c);
            }
        }
        for l in self.ncore..self.nodes.len() {
            if self.principal[l] && self.pre[l] == LEAF_REACHED {
                f(self.nodes[l], 1);
            }
        }
    }

    /// Sever a choke object: it and everything it dominates drop out.
    fn kill(&mut self, v: u32) {
        let l = self.local[v as usize];
        if l != UNDEF {
            self.dead[l as usize] = true;
        }
    }

    fn dominate(&mut self, cancel: &Cancel) -> Option<DomResult> {
        let Planner {
            nodes, ncore, succ, pred, principal, target, dead, fresh, pre, vert, parent, semi, link, idom, cnt, ..
        } = self;
        let ncore = *ncore;
        if !std::mem::take(fresh) {
            core_dfs(succ, dead, pre, vert, parent, cancel)?;
        }
        let nn = vert.len();
        // Semidominators in reverse preorder, with path-compressed `eval`.
        semi.clear();
        semi.extend(0..nn as u32);
        link.clear();
        link.extend(parent.iter().zip(0..).map(|(&p, i)| [p, i]));
        let mut stk: Vec<u32> = Vec::new();
        for w in (1..nn).rev() {
            let last = w as u32 + 1;
            let mut s = parent[w];
            for &pl in pred.get(vert[w]) {
                let v = pre[pl as usize];
                if v < w as u32 {
                    // Not yet processed: its semidominator candidate is itself.
                    s = s.min(v);
                } else if v != UNDEF {
                    s = s.min(eval(v, last, link, &mut stk));
                }
            }
            semi[w] = s;
            link[w][1] = s;
            if w.is_multiple_of(1 << 18) && cancel.hit() {
                return None;
            }
        }
        // Immediate dominator: the nearest tree ancestor at or above the semidominator.
        idom.clear();
        idom.extend_from_slice(parent);
        for w in 1..nn {
            let s = semi[w];
            let mut c = idom[w];
            while c > s {
                c = idom[c as usize];
            }
            idom[w] = c;
        }
        // Leaves: nearest common ancestor of their onward targets (preorder
        // numbers decrease towards the root, so climb the larger one).
        let (pre_r, idom_r, dead_r) = (&*pre, &*idom, &*dead);
        let leaf_dom: Vec<u32> = (ncore as u32..nodes.len() as u32)
            .into_par_iter()
            .map(|l| {
                if dead_r[l as usize] {
                    return UNDEF;
                }
                let mut a = UNDEF;
                for &pl in pred.get(l) {
                    let mut b = pre_r[pl as usize];
                    if b == UNDEF {
                        continue;
                    }
                    if a == UNDEF {
                        a = b;
                        continue;
                    }
                    while a != b {
                        if a > b {
                            a = idom_r[a as usize];
                        } else {
                            b = idom_r[b as usize];
                        }
                    }
                }
                a
            })
            .collect();
        if cancel.hit() {
            return None;
        }
        // Principals each choke object alone cuts off: dominator subtree sums.
        cnt.clear();
        cnt.extend(vert.iter().map(|&l| principal[l as usize] as u64));
        let mut exposed: u64 = cnt.iter().sum();
        for (l, &d) in (ncore..).zip(&leaf_dom) {
            if d == UNDEF {
                continue;
            }
            pre[l] = LEAF_REACHED;
            if principal[l] {
                cnt[d as usize] += 1;
                exposed += 1;
            }
        }
        for w in (1..nn).rev() {
            cnt[idom[w] as usize] += cnt[w];
        }
        let mut ranked: Vec<(u32, u64)> =
            (1..nn).filter(|&w| cnt[w] > 0 && !target[vert[w] as usize]).map(|w| (nodes[vert[w] as usize], cnt[w])).collect();
        // A leaf cuts only itself; it can only make the window if fewer than
        // PICK_WINDOW core candidates cut more.
        if ranked.iter().filter(|c| c.1 > 1).count() < PICK_WINDOW {
            ranked.extend(
                (ncore..nodes.len()).filter(|&l| principal[l] && pre[l] == LEAF_REACHED).map(|l| (nodes[l], 1)),
            );
        }
        let order = |a: &(u32, u64), b: &(u32, u64)| b.1.cmp(&a.1).then(a.0.cmp(&b.0));
        if ranked.len() > PICK_WINDOW {
            ranked.select_nth_unstable_by(PICK_WINDOW - 1, order);
            ranked.truncate(PICK_WINDOW);
        }
        ranked.sort_unstable_by(order);
        Some(DomResult { exposed, ranked })
    }
}

/// Semi-NCA `eval`: the minimum semidominator on the (compressed) ancestor
/// path of `v` through already processed vertices (`>= last`).
#[inline]
fn eval(v: u32, last: u32, link: &mut [[u32; 2]], stack: &mut Vec<u32>) -> u32 {
    let [a, best] = link[v as usize];
    if a < last {
        return best;
    }
    stack.clear();
    let mut x = v;
    loop {
        stack.push(x);
        x = link[x as usize][0];
        if link[x as usize][0] < last {
            break;
        }
    }
    let [top_anc, mut best] = link[x as usize];
    while let Some(y) = stack.pop() {
        let e = &mut link[y as usize];
        e[0] = top_anc;
        if best < e[1] {
            e[1] = best;
        } else {
            best = e[1];
        }
    }
    best
}

/// The best qualifying choke object among `ranked` (best first): all its
/// onward attack edges (from `onward`) are removable — none of a
/// `fixed_kinds` kind, no end with fix cost `Fixed`. With `live_first`, the
/// first live candidate wins over the first window one. Returns
/// `(node, score, onward edges, needs_window)`.
fn pick_candidate(
    opts: &PlanOptions,
    ranked: impl Iterator<Item = (u32, u64)>,
    onward: impl Fn(u32) -> Vec<EdgeKey>,
) -> Option<(u32, u64, Vec<EdgeKey>, bool)> {
    let cost = |n: u32| opts.node_cost.as_ref().map_or(FixCost::Live as u8, |c| c[n as usize]);
    let mut window_pick = None;
    for (d, score) in ranked {
        let edges = onward(d);
        if edges.is_empty() || edges.iter().any(|e| opts.fixed_kinds.contains(&e.2)) {
            continue;
        }
        let worst = edges.iter().map(|e| cost(e.0).max(cost(e.1))).max().unwrap_or(0);
        if worst >= FixCost::Fixed as u8 {
            continue;
        }
        let needs_window = worst == FixCost::Window as u8;
        if needs_window && opts.live_first {
            window_pick.get_or_insert((d, score, edges, true));
            continue;
        }
        return Some((d, score, edges, needs_window));
    }
    window_pick
}

/// One zone of a weighted plan: its weight and members.
#[derive(Debug, Clone, Copy)]
pub struct WeightedZone<'a> {
    /// Relative importance; 0 leaves the zone out.
    pub weight: u32,
    pub targets: &'a [u32],
}

/// What a weighted step does to one zone.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ZoneCut {
    pub principals_cut: u64,
    pub exposed_after: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WeightedStep {
    pub node: u32,
    pub edges: Vec<EdgeKey>,
    /// Weighted cut: sum over zones of weight × principals cut off that zone.
    pub score: u64,
    /// Weighted exposure left: sum over zones of weight × exposed principals.
    pub score_after: u64,
    pub cumulative_reduction_percent: f64,
    pub needs_window: bool,
    /// Per zone, in input order (zeros for weight-0 zones).
    pub zones: Vec<ZoneCut>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WeightedPlan {
    /// Weighted exposure before any step.
    pub baseline: u64,
    /// Exposed principals per zone before any step, in input order.
    pub zone_baselines: Vec<u64>,
    pub steps: Vec<WeightedStep>,
    pub truncated: bool,
}

/// Remediation plan across several zones at once: each step severs the choke
/// object with the largest weighted cut (sum over zones of weight × principals
/// it alone cuts off from that zone, exact via one dominator tree per zone),
/// then recomputes every zone. A principal exposed to two zones counts in
/// both. Candidate rules and ties are as in [`plan`]; with one zone of weight
/// 1 the plan is the same as [`plan`]'s.
pub fn plan_weighted(g: &Graph, zones: &[WeightedZone<'_>], opts: &PlanOptions, cancel: &Cancel) -> WeightedPlan {
    let f = EdgeFilter::traversable(g);
    let mut steps = Vec::new();
    let mut truncated = false;
    let mut planners: Vec<Option<Planner>> = Vec::with_capacity(zones.len());
    if opts.steps > 0 {
        for z in zones {
            if z.weight == 0 {
                planners.push(None);
                continue;
            }
            let zone = if opts.protect_target_membership { expand_membership(g, z.targets) } else { z.targets.to_vec() };
            match Planner::new(g, &zone, &f, cancel) {
                Some(p) => planners.push(Some(p)),
                None => {
                    return WeightedPlan { baseline: 0, zone_baselines: vec![0; zones.len()], steps, truncated: true };
                }
            }
        }
    }
    let mut zone_baselines: Option<Vec<u64>> = None;
    let mut baseline = 0u64;
    let mut score = vec![0u64; if opts.steps > 0 { g.node_count() } else { 0 }];
    let mut touched: Vec<u32> = Vec::new();
    while steps.len() < opts.steps {
        let mut exposed = vec![0u64; zones.len()];
        for (i, p) in planners.iter_mut().enumerate() {
            let Some(p) = p else { continue };
            let Some(dom) = p.dominate(cancel) else {
                truncated = true;
                break;
            };
            exposed[i] = dom.exposed;
        }
        if truncated {
            break;
        }
        if zone_baselines.is_none() {
            baseline = zones.iter().zip(&exposed).map(|(z, &e)| z.weight as u64 * e).sum();
            zone_baselines = Some(exposed.clone());
        }
        // Exact weighted cut of every candidate, over all zones.
        for (z, p) in zones.iter().zip(&planners) {
            let Some(p) = p else { continue };
            let w = z.weight as u64;
            p.for_each_cut(|v, c| {
                let s = &mut score[v as usize];
                if *s == 0 {
                    touched.push(v);
                }
                *s += w * c;
            });
        }
        let mut ranked: Vec<(u32, u64)> = touched.iter().map(|&v| (v, score[v as usize])).collect();
        for &v in &touched {
            score[v as usize] = 0;
        }
        touched.clear();
        let order = |a: &(u32, u64), b: &(u32, u64)| b.1.cmp(&a.1).then(a.0.cmp(&b.0));
        if ranked.len() > PICK_WINDOW {
            ranked.select_nth_unstable_by(PICK_WINDOW - 1, order);
            ranked.truncate(PICK_WINDOW);
        }
        ranked.sort_unstable_by(order);
        // Severing `d` deletes it from every zone it is not a member of, so its
        // fix is every onward edge into a node reachable in such a zone.
        let live: Vec<&Planner> = planners.iter().flatten().collect();
        let pick = pick_candidate(opts, ranked.into_iter(), |d| {
            let own: Vec<&&Planner> = live.iter().filter(|p| p.reachable(d) && !p.is_target(d)).collect();
            let (ds, ks) = g.out_edges(d);
            ds.iter()
                .zip(ks)
                .filter(|(&v, &k)| f.allows(k) && own.iter().any(|p| p.reachable(v)))
                .map(|(&v, &k)| (d, v, k))
                .collect()
        });
        let Some((node, s, onward, needs_window)) = pick else { break };
        let cuts: Vec<ZoneCut> = planners
            .iter()
            .zip(&exposed)
            .map(|(p, &e)| {
                let c = p.as_ref().map_or(0, |p| p.cut_of(node));
                ZoneCut { principals_cut: c, exposed_after: e - c }
            })
            .collect();
        for p in planners.iter_mut().flatten() {
            if !p.is_target(node) {
                p.kill(node);
            }
        }
        let score_after: u64 = zones.iter().zip(&cuts).map(|(z, c)| z.weight as u64 * c.exposed_after).sum();
        steps.push(WeightedStep {
            node,
            edges: onward,
            score: s,
            score_after,
            cumulative_reduction_percent: if baseline == 0 { 0.0 } else { 100.0 * (baseline - score_after) as f64 / baseline as f64 },
            needs_window,
            zones: cuts,
        });
    }
    WeightedPlan { baseline, zone_baselines: zone_baselines.unwrap_or_else(|| vec![0; zones.len()]), steps, truncated }
}

/// Remediation plan: each step severs the single choke object that cuts the
/// most principals off from the zone entirely (exact, via dominators), then
/// recomputes. A choke object qualifies only if all its onward attack edges are
/// removable (not of a `fixed_kinds` kind, no end with fix cost `Fixed`); ties
/// go to the lower node id. With `live_first`, qualifying objects that need no
/// maintenance window win over those that do.
pub fn plan(g: &Graph, targets: &[u32], opts: &PlanOptions, cancel: &Cancel) -> Plan {
    let f = EdgeFilter::traversable(g);
    let zone = if opts.protect_target_membership { expand_membership(g, targets) } else { targets.to_vec() };
    let mut steps = Vec::new();
    let mut baseline = None;
    let mut planner = if opts.steps > 0 { Planner::new(g, &zone, &f, cancel) } else { None };
    let mut truncated = opts.steps > 0 && planner.is_none();
    while let Some(planner) = planner.as_mut().filter(|_| steps.len() < opts.steps) {
        let Some(dom) = planner.dominate(cancel) else {
            truncated = true;
            break;
        };
        let base = *baseline.get_or_insert(dom.exposed);
        let pl = &*planner;
        let pick = pick_candidate(opts, dom.ranked.iter().copied(), |d| {
            let (ds, ks) = g.out_edges(d);
            ds.iter().zip(ks).filter(|(&v, &k)| f.allows(k) && pl.reachable(v)).map(|(&v, &k)| (d, v, k)).collect()
        });
        let Some((node, cut, onward, needs_window)) = pick else { break };
        planner.kill(node);
        let exposed_after = dom.exposed - cut;
        steps.push(PlanStep {
            node,
            edges: onward,
            principals_cut: cut,
            exposed_after,
            cumulative_reduction_percent: if base == 0 { 0.0 } else { 100.0 * (base - exposed_after) as f64 / base as f64 },
            needs_window,
        });
    }
    Plan { baseline: baseline.unwrap_or(0), steps, truncated }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ch_model::flags;
    use ch_store::{Edge, GraphParts};

    // ---- Reference: the original planner (Cooper-Harvey-Kennedy iterative
    // dominators over the whole graph, recomputed from scratch every step). ----

    struct RefDom {
        exposed: u64,
        /// `(node, principals it alone cuts off)`, best first.
        ranked: Vec<(u32, u64)>,
        reachable: Vec<bool>,
    }

    /// Build the dominator tree of the reverse attack graph (virtual root → targets
    /// → their attackers, …) with the Cooper–Harvey–Kennedy algorithm, and count,
    /// for every node, the exposed principals it dominates: removing that node's
    /// onward edges cuts exactly those principals off from every target.
    fn ref_dominate(g: &Graph, targets: &[u32], allow: &impl Fn(u32, u32, u16) -> bool, cancel: &Cancel) -> Option<RefDom> {
        let n = g.node_count();
        let root = n as u32;
        let mut is_target = vec![false; n];
        for &t in targets {
            is_target[t as usize] = true;
        }
        // Iterative DFS from the root over reverse edges → postorder numbers.
        let mut po = vec![UNDEF; n + 1];
        let mut visited = vec![false; n];
        let mut post: Vec<u32> = Vec::new();
        // Stack frames: (node, next in-edge index); root iterates over targets.
        let mut stack: Vec<(u32, usize)> = vec![(root, 0)];
        while let Some(&mut (v, ref mut i)) = stack.last_mut() {
            let next = if v == root {
                let mut found = None;
                while *i < targets.len() {
                    let t = targets[*i];
                    *i += 1;
                    if !visited[t as usize] {
                        found = Some(t);
                        break;
                    }
                }
                found
            } else {
                let (ss, ks) = g.in_edges(v);
                let mut found = None;
                while *i < ss.len() {
                    let (u, k) = (ss[*i], ks[*i]);
                    *i += 1;
                    if !visited[u as usize] && !is_target[u as usize] && allow(u, v, k) {
                        found = Some(u);
                        break;
                    }
                }
                found
            };
            match next {
                Some(u) => {
                    visited[u as usize] = true;
                    stack.push((u, 0));
                }
                None => {
                    po[v as usize] = post.len() as u32;
                    post.push(v);
                    stack.pop();
                }
            }
            if post.len().is_multiple_of(65_536) && cancel.hit() {
                return None;
            }
        }
        // Reverse postorder, root first.
        let rpo: Vec<u32> = post.iter().rev().copied().collect();
        let mut idom = vec![UNDEF; n + 1];
        idom[root as usize] = root;
        let intersect = |idom: &[u32], mut a: u32, mut b: u32| -> u32 {
            while a != b {
                while po[a as usize] < po[b as usize] {
                    a = idom[a as usize];
                }
                while po[b as usize] < po[a as usize] {
                    b = idom[b as usize];
                }
            }
            a
        };
        let mut changed = true;
        while changed {
            if cancel.hit() {
                return None;
            }
            changed = false;
            for &b in &rpo[1..] {
                let new = if is_target[b as usize] {
                    root
                } else {
                    // Predecessors in the reverse graph = onward attack edges b → v.
                    let (ds, ks) = g.out_edges(b);
                    let mut new = UNDEF;
                    for (&v, &k) in ds.iter().zip(ks) {
                        if po[v as usize] == UNDEF || idom[v as usize] == UNDEF || !allow(b, v, k) {
                            continue;
                        }
                        new = if new == UNDEF { v } else { intersect(&idom, v, new) };
                    }
                    new
                };
                if new != UNDEF && idom[b as usize] != new {
                    idom[b as usize] = new;
                    changed = true;
                }
            }
        }
        // Subtree sums of exposed principals, children before parents.
        let mut cnt = vec![0u64; n + 1];
        let mut exposed = 0u64;
        for &b in &post {
            if b == root {
                continue;
            }
            if !is_target[b as usize] && crate::is_principal(g.kind(b)) {
                cnt[b as usize] += 1;
                exposed += 1;
            }
            let p = idom[b as usize];
            if p != UNDEF {
                cnt[p as usize] += cnt[b as usize];
            }
        }
        let mut ranked: Vec<(u32, u64)> = post
            .iter()
            .copied()
            .filter(|&b| b != root && !is_target[b as usize] && cnt[b as usize] > 0)
            .map(|b| (b, cnt[b as usize]))
            .collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let reachable = (0..n).map(|i| po[i] != UNDEF).collect();
        Some(RefDom { exposed, ranked, reachable })
    }

    /// Remediation plan: each step severs the single choke object that cuts the
    /// most principals off from the zone entirely (exact, via dominators), then
    /// recomputes. A choke object qualifies only if all its onward attack edges are
    /// removable (not of a `fixed_kinds` kind).
    fn reference_plan(g: &Graph, targets: &[u32], opts: &PlanOptions, cancel: &Cancel) -> Plan {
        let f = EdgeFilter::traversable(g);
        let zone = if opts.protect_target_membership { expand_membership(g, targets) } else { targets.to_vec() };
        let mut removal = Removal::default();
        let mut steps = Vec::new();
        let mut baseline = None;
        let mut truncated = false;
        while steps.len() < opts.steps {
            let allow = |s: u32, d: u32, k: u16| f.allows(k) && !removal.blocks(s, d, k);
            let Some(dom) = ref_dominate(g, &zone, &allow, cancel) else {
                truncated = true;
                break;
            };
            let base = *baseline.get_or_insert(dom.exposed);
            // Best choke object whose onward edges are all removable; with
            // `live_first`, live candidates before window ones.
            let cost = |n: u32| opts.node_cost.as_ref().map_or(0, |c| c[n as usize]);
            let candidates: Vec<(u32, u64, Vec<EdgeKey>, u8)> = dom
                .ranked
                .iter()
                .take(256)
                .filter_map(|&(d, cut)| {
                    let (ds, ks) = g.out_edges(d);
                    let onward: Vec<EdgeKey> = ds
                        .iter()
                        .zip(ks)
                        .filter(|(&v, &k)| dom.reachable[v as usize] && allow(d, v, k))
                        .map(|(&v, &k)| (d, v, k))
                        .collect();
                    let worst = onward.iter().map(|e| cost(e.0).max(cost(e.1))).max().unwrap_or(0);
                    (!onward.is_empty() && onward.iter().all(|e| !opts.fixed_kinds.contains(&e.2)) && worst < 2)
                        .then_some((d, cut, onward, worst))
                })
                .collect();
            let pick = if opts.live_first {
                candidates.iter().find(|c| c.3 == 0).or(candidates.first()).cloned()
            } else {
                candidates.first().cloned()
            };
            let Some((node, cut, onward, worst)) = pick else { break };
            removal.edges.extend(onward.iter().copied());
            let exposed_after = dom.exposed - cut;
            steps.push(PlanStep {
                node,
                edges: onward,
                principals_cut: cut,
                exposed_after,
                cumulative_reduction_percent: if base == 0 { 0.0 } else { 100.0 * (base - exposed_after) as f64 / base as f64 },
                needs_window: worst == 1,
            });
        }
        Plan { baseline: baseline.unwrap_or(0), steps, truncated }
    }

    // ---- Equivalence tests. ----

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Random AD-like graph: users, groups and computers, traversable and
    /// non-traversable edges, self-loops and parallel edges of different kinds.
    fn random_graph(n: u32, m: usize, tier0: u32, seed: u64) -> Graph {
        let mut r = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
        let kinds: Vec<u8> = (0..n).map(|_| [1u8, 1, 2, 3][r.below(4) as usize]).collect();
        let mut fl = vec![0u32; n as usize];
        for _ in 0..tier0 {
            fl[r.below(n as u64) as usize] = flags::TIER0;
        }
        let ks = [ek::MEMBER_OF, ek::MEMBER_OF, ek::ADMIN_TO, ek::HAS_SESSION, ek::GENERIC_ALL, ek::GET_CHANGES];
        let edges: Vec<Edge> = (0..m)
            .map(|_| {
                let k = ks[r.below(ks.len() as u64) as usize];
                // Bias edges "upwards" (towards lower ids) so there are long chains
                // and choke points, plus some random back edges for cycles.
                let a = r.below(n as u64) as u32;
                let b = if r.below(4) == 0 { r.below(n as u64) as u32 } else { r.below(a as u64 + 1) as u32 };
                Edge::new(a, b, k)
            })
            .collect();
        Graph::build(GraphParts {
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
        .0
    }

    /// Asserts the new planner reproduces the reference exactly; returns
    /// `(steps, steps cutting more than one principal)` as a coverage signal.
    fn assert_same(g: &Graph, targets: &[u32], opts: &PlanOptions, ctx: &str) -> (usize, usize) {
        let a = plan(g, targets, opts, &Cancel::never());
        let b = reference_plan(g, targets, opts, &Cancel::never());
        assert_eq!(a.baseline, b.baseline, "{ctx}: baseline");
        assert_eq!(a.truncated, b.truncated, "{ctx}: truncated");
        assert_eq!(a.steps.len(), b.steps.len(), "{ctx}: step count");
        for (i, (x, y)) in a.steps.iter().zip(&b.steps).enumerate() {
            assert_eq!(
                (x.node, &x.edges, x.principals_cut, x.exposed_after),
                (y.node, &y.edges, y.principals_cut, y.exposed_after),
                "{ctx}: step {i}"
            );
            assert_eq!(x.cumulative_reduction_percent, y.cumulative_reduction_percent, "{ctx}: step {i} percent");
            assert_eq!(x.needs_window, y.needs_window, "{ctx}: step {i} window");
        }
        (a.steps.len(), a.steps.iter().filter(|s| s.principals_cut > 1).count())
    }

    #[test]
    fn matches_reference_on_random_graphs() {
        let (mut steps, mut big) = (0, 0);
        for seed in 0..400u64 {
            let n = 20 + (seed * 37 % 300) as u32;
            let m = n as usize * (1 + (seed % 5) as usize);
            let g = random_graph(n, m, 1 + (seed % 4) as u32, seed);
            let targets = g.nodes_with_flag(flags::TIER0);
            for (protect, fixed) in [(true, vec![]), (false, vec![]), (true, vec![ek::MEMBER_OF]), (false, vec![ek::ADMIN_TO, ek::HAS_SESSION])] {
                let opts = PlanOptions { steps: 15, fixed_kinds: fixed, protect_target_membership: protect, ..Default::default() };
                let (s, b) = assert_same(&g, &targets, &opts, &format!("seed {seed} n {n} m {m} protect {protect}"));
                steps += s;
                big += b;
            }
        }
        // The graphs must exercise the planner, not just agree on empty plans.
        eprintln!("compared {steps} steps, {big} cutting more than one principal");
        assert!(steps > 5_000 && big > 1_000, "{steps} steps, {big} non-trivial");
    }

    /// Fix costs: random `window` / `fixed` nodes, with and without `live_first`.
    #[test]
    fn fix_costs_match_reference() {
        let mut window = 0;
        for seed in 0..200u64 {
            let n = 30 + (seed * 37 % 250) as u32;
            let g = random_graph(n, n as usize * (2 + (seed % 3) as usize), 1 + (seed % 3) as u32, 5000 + seed);
            let targets = g.nodes_with_flag(flags::TIER0);
            let mut rng = Rng(seed * 7919 + 1);
            let cost: Vec<u8> = (0..n).map(|_| match rng.below(10) { 0 => 2, 1 | 2 => 1, _ => 0 }).collect();
            for live_first in [false, true] {
                let opts = PlanOptions { steps: 12, protect_target_membership: seed % 2 == 0, node_cost: Some(cost.clone()), live_first, ..Default::default() };
                assert_same(&g, &targets, &opts, &format!("cost seed {seed} live_first {live_first}"));
                let p = plan(&g, &targets, &opts, &Cancel::never());
                for s in &p.steps {
                    // No proposed edge touches a fixed object.
                    assert!(s.edges.iter().all(|e| cost[e.0 as usize] < 2 && cost[e.1 as usize] < 2), "seed {seed}");
                    assert_eq!(s.needs_window, s.edges.iter().any(|e| cost[e.0 as usize] == 1 || cost[e.1 as usize] == 1));
                    window += s.needs_window as usize;
                }
            }
            // Without costs the plan is unchanged by live_first.
            let a = plan(&g, &targets, &PlanOptions { steps: 8, ..Default::default() }, &Cancel::never());
            let b = plan(&g, &targets, &PlanOptions { steps: 8, live_first: true, ..Default::default() }, &Cancel::never());
            assert_eq!(a.steps.iter().map(|s| s.node).collect::<Vec<_>>(), b.steps.iter().map(|s| s.node).collect::<Vec<_>>());
        }
        assert!(window > 100, "window steps exercised: {window}");
    }

    /// Big enough for the parallel BFS / CSR paths and multi-chunk builds.
    #[test]
    fn matches_reference_on_larger_graphs() {
        for seed in 0..3u64 {
            let g = random_graph(60_000, 150_000 + 50_000 * seed as usize, 5, 1000 + seed);
            let targets = g.nodes_with_flag(flags::TIER0);
            let opts = PlanOptions { steps: 10, fixed_kinds: vec![], protect_target_membership: true, ..Default::default() };
            assert_same(&g, &targets, &opts, &format!("large seed {seed}"));
        }
    }

    /// Reference weighted plan: per-zone dominators recomputed from scratch with
    /// the edges of earlier steps removed; scores summed over every node.
    fn reference_weighted(g: &Graph, zones: &[(u32, Vec<u32>)], opts: &PlanOptions) -> WeightedPlan {
        let f = EdgeFilter::traversable(g);
        let cancel = Cancel::never();
        let zs: Vec<Vec<u32>> =
            zones.iter().map(|(_, t)| if opts.protect_target_membership { expand_membership(g, t) } else { t.clone() }).collect();
        let mut removal = Removal::default();
        let mut steps = Vec::new();
        let mut zone_baselines = None;
        let mut baseline = 0;
        let cost = |n: u32| opts.node_cost.as_ref().map_or(0, |c| c[n as usize]);
        while steps.len() < opts.steps {
            let allow = |s: u32, d: u32, k: u16| f.allows(k) && !removal.blocks(s, d, k);
            let doms: Vec<Option<RefDom>> =
                zones.iter().zip(&zs).map(|((w, _), t)| (*w > 0).then(|| ref_dominate(g, t, &allow, &cancel).unwrap())).collect();
            let exposed: Vec<u64> = doms.iter().map(|d| d.as_ref().map_or(0, |d| d.exposed)).collect();
            if zone_baselines.is_none() {
                baseline = zones.iter().zip(&exposed).map(|((w, _), e)| *w as u64 * e).sum();
                zone_baselines = Some(exposed.clone());
            }
            let cut = |z: usize, v: u32| doms[z].as_ref().and_then(|d| d.ranked.iter().find(|r| r.0 == v)).map_or(0, |r| r.1);
            let mut score = std::collections::BTreeMap::<u32, u64>::new();
            for (z, d) in doms.iter().enumerate() {
                for &(v, c) in d.iter().flat_map(|d| &d.ranked) {
                    *score.entry(v).or_default() += zones[z].0 as u64 * c;
                }
            }
            let mut ranked: Vec<(u32, u64)> = score.into_iter().collect();
            ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            let is_t = |z: usize, v: u32| zs[z].contains(&v);
            let candidates: Vec<(u32, u64, Vec<EdgeKey>, u8)> = ranked
                .iter()
                .take(256)
                .filter_map(|&(d, s)| {
                    let own: Vec<usize> =
                        (0..zones.len()).filter(|&z| doms[z].as_ref().is_some_and(|x| x.reachable[d as usize]) && !is_t(z, d)).collect();
                    let (ds, ks) = g.out_edges(d);
                    let onward: Vec<EdgeKey> = ds
                        .iter()
                        .zip(ks)
                        .filter(|(&v, &k)| allow(d, v, k) && own.iter().any(|&z| doms[z].as_ref().unwrap().reachable[v as usize]))
                        .map(|(&v, &k)| (d, v, k))
                        .collect();
                    let worst = onward.iter().map(|e| cost(e.0).max(cost(e.1))).max().unwrap_or(0);
                    (!onward.is_empty() && onward.iter().all(|e| !opts.fixed_kinds.contains(&e.2)) && worst < 2)
                        .then_some((d, s, onward, worst))
                })
                .collect();
            let pick = if opts.live_first { candidates.iter().find(|c| c.3 == 0).or(candidates.first()) } else { candidates.first() };
            let Some((node, s, onward, worst)) = pick.cloned() else { break };
            let cuts: Vec<ZoneCut> =
                (0..zones.len()).map(|z| ZoneCut { principals_cut: cut(z, node), exposed_after: exposed[z] - cut(z, node) }).collect();
            removal.edges.extend(onward.iter().copied());
            let score_after: u64 = zones.iter().zip(&cuts).map(|((w, _), c)| *w as u64 * c.exposed_after).sum();
            steps.push(WeightedStep {
                node,
                edges: onward,
                score: s,
                score_after,
                cumulative_reduction_percent: if baseline == 0 { 0.0 } else { 100.0 * (baseline - score_after) as f64 / baseline as f64 },
                needs_window: worst == 1,
                zones: cuts,
            });
        }
        WeightedPlan { baseline, zone_baselines: zone_baselines.unwrap_or_else(|| vec![0; zones.len()]), steps, truncated: false }
    }

    fn assert_weighted_same(g: &Graph, zones: &[(u32, Vec<u32>)], opts: &PlanOptions, ctx: &str) -> usize {
        let wz: Vec<WeightedZone> = zones.iter().map(|(w, t)| WeightedZone { weight: *w, targets: t }).collect();
        let a = plan_weighted(g, &wz, opts, &Cancel::never());
        let b = reference_weighted(g, zones, opts);
        assert_eq!((a.baseline, &a.zone_baselines, a.truncated), (b.baseline, &b.zone_baselines, false), "{ctx}: baseline");
        assert_eq!(a.steps.len(), b.steps.len(), "{ctx}: step count");
        for (i, (x, y)) in a.steps.iter().zip(&b.steps).enumerate() {
            assert_eq!(
                (x.node, &x.edges, x.score, x.score_after, &x.zones, x.needs_window),
                (y.node, &y.edges, y.score, y.score_after, &y.zones, y.needs_window),
                "{ctx}: step {i}"
            );
            assert_eq!(x.cumulative_reduction_percent, y.cumulative_reduction_percent, "{ctx}: step {i} percent");
        }
        a.steps.iter().filter(|s| s.zones.iter().filter(|z| z.principals_cut > 0).count() > 1).count()
    }

    #[test]
    fn weighted_matches_reference() {
        let mut multi = 0;
        for seed in 0..250u64 {
            let n = 20 + (seed * 37 % 250) as u32;
            let g = random_graph(n, n as usize * (1 + (seed % 4) as usize), 1 + (seed % 3) as u32, 9000 + seed);
            let mut r = Rng(seed * 104_729 + 3);
            let mut pick = |k: u64| -> Vec<u32> {
                let mut v: Vec<u32> = (0..k).map(|_| r.below(n as u64 / 2 + 1) as u32).collect();
                v.sort_unstable();
                v.dedup();
                v
            };
            let zones = vec![
                (1 + (seed % 5) as u32, g.nodes_with_flag(flags::TIER0)),
                ((seed % 3) as u32 * 2, pick(2)),
                (1 + (seed % 7) as u32, pick(1 + seed % 4)),
            ];
            let cost: Vec<u8> = (0..n).map(|i| [0, 0, 0, 0, 0, 0, 0, 1, 1, 2][((i as u64 * 31 + seed) % 10) as usize]).collect();
            for (protect, fixed, node_cost, live_first) in [
                (true, vec![], None, false),
                (false, vec![], None, false),
                (true, vec![ek::MEMBER_OF], None, false),
                (seed % 2 == 0, vec![], Some(cost.clone()), true),
            ] {
                let opts = PlanOptions { steps: 12, fixed_kinds: fixed, protect_target_membership: protect, node_cost, live_first };
                multi += assert_weighted_same(&g, &zones, &opts, &format!("seed {seed} protect {protect}"));
            }
        }
        assert!(multi > 300, "steps cutting principals off several zones: {multi}");
    }

    /// One zone of weight 1 gives the single-zone plan.
    #[test]
    fn weighted_single_zone_is_plan() {
        for seed in 0..100u64 {
            let n = 30 + (seed * 53 % 400) as u32;
            let g = random_graph(n, n as usize * 3, 2, 300 + seed);
            let t = g.nodes_with_flag(flags::TIER0);
            let opts = PlanOptions { steps: 15, protect_target_membership: seed % 2 == 0, ..Default::default() };
            let a = plan(&g, &t, &opts, &Cancel::never());
            let b = plan_weighted(&g, &[WeightedZone { weight: 1, targets: &t }], &opts, &Cancel::never());
            assert_eq!(a.baseline, b.baseline);
            let sa: Vec<_> = a.steps.iter().map(|s| (s.node, s.edges.clone(), s.principals_cut, s.exposed_after)).collect();
            let sb: Vec<_> = b.steps.iter().map(|s| (s.node, s.edges.clone(), s.score, s.score_after)).collect();
            assert_eq!(sa, sb, "seed {seed}");
        }
        // Larger graph (parallel paths) with two zones: deterministic and in range.
        let g = random_graph(60_000, 180_000, 5, 77);
        let t = g.nodes_with_flag(flags::TIER0);
        let other: Vec<u32> = (0..40).map(|i| i * 13).collect();
        let zs = [WeightedZone { weight: 5, targets: &t }, WeightedZone { weight: 2, targets: &other }];
        let opts = PlanOptions { steps: 8, protect_target_membership: true, ..Default::default() };
        let a = plan_weighted(&g, &zs, &opts, &Cancel::never());
        let b = plan_weighted(&g, &zs, &opts, &Cancel::never());
        assert_eq!(a.steps.iter().map(|s| (s.node, s.score)).collect::<Vec<_>>(), b.steps.iter().map(|s| (s.node, s.score)).collect::<Vec<_>>());
        assert!(a.steps.windows(2).all(|w| w[0].score_after > w[1].score_after));
        let mut left = a.baseline;
        for s in &a.steps {
            assert_eq!(s.score, 5 * s.zones[0].principals_cut + 2 * s.zones[1].principals_cut);
            left -= s.score;
            assert_eq!(left, s.score_after);
        }
        let c = Cancel::never();
        c.cancel();
        assert!(plan_weighted(&g, &zs, &opts, &c).truncated);
    }

    #[test]
    fn edge_cases() {
        let g = random_graph(200, 600, 2, 7);
        let targets = g.nodes_with_flag(flags::TIER0);
        // No steps, no targets, duplicated targets.
        let opts = PlanOptions { steps: 0, fixed_kinds: vec![], protect_target_membership: true, ..Default::default() };
        assert_same(&g, &targets, &opts, "zero steps");
        let opts = PlanOptions { steps: 5, fixed_kinds: vec![], protect_target_membership: true, ..Default::default() };
        assert_same(&g, &[], &opts, "no targets");
        let dup: Vec<u32> = targets.iter().chain(&targets).copied().collect();
        assert_same(&g, &dup, &opts, "duplicate targets");
        // Run until nothing is left to cut.
        let opts = PlanOptions { steps: 1000, fixed_kinds: vec![], protect_target_membership: false, ..Default::default() };
        assert_same(&g, &targets, &opts, "exhaustive");
        // Cancelled up front: truncated, like the reference.
        let c = Cancel::never();
        c.cancel();
        let p = plan(&g, &targets, &opts, &c);
        assert!(p.truncated && p.steps.is_empty());
    }
}
