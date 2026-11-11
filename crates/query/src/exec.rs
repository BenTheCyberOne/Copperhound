//! CHQL planner and executor.
//!
//! A query is a pipeline of stages (`MATCH`, `OPTIONAL MATCH`, `UNWIND`,
//! `WITH`, `RETURN`) that pass batches of rows downstream. Rows are vectors of
//! values indexed by slot; every clause's variables get fixed slots at plan
//! time, so evaluation never looks names up.
//!
//! Planning of each MATCH clause: single-variable WHERE conjuncts are pushed
//! into node filters; `name` / `objectid` equality (and `IN` lists) use the
//! hash index, `name STARTS WITH` the sorted name index; the parts of a node
//! filter the property-column store evaluates exactly (`pushdown.rs`) are
//! answered by `Graph::filter` once columns are ready; each pattern starts
//! from a node bound by an earlier pattern/clause if any, else from an indexed
//! node, else from whichever end has fewer candidates. Patterns of one clause
//! are joined by nested loops on shared variables. The first pattern of a
//! query fans out over its start candidates on all cores; later clauses fan
//! out over input rows.
//!
//! Streaming and bounds: rows flow downstream in waves, so `LIMIT` stops the
//! producers early (the downstream stage reports how many rows it still
//! wants), aggregation keeps only per-group state, `ORDER BY … LIMIT` keeps a
//! bounded top-k buffer. Every loop polls the [`Cancel`] token.
//!
//! Semantics worth knowing:
//! * Variable-length hops use reachability semantics: each reachable end node
//!   is produced once (with one shortest witness path), not every path.
//! * A fixed hop without edge kinds follows any edge kind; variable-length
//!   hops and path functions without kinds follow traversable kinds only.
//! * Fixed-length relationships are unique within one MATCH clause (Cypher
//!   relationship isomorphism).
//! * String comparisons are case-insensitive; WHERE uses two-valued logic
//!   (null is false).

use crate::ast::*;
use crate::expr::{label_ok, AggSpec, CExpr, Compiler, Env};
use crate::value::*;
use crate::{Cancel, ExecOptions, QueryError, QueryResult};
use ahash::{AHashMap, AHashSet};
use ch_engine::{shortest_path, EdgeFilter};
use crate::pushdown;
use ch_store::{Filter, Graph, RoaringBitmap};
use rayon::prelude::*;
use serde_json::Value;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

type Row = Vec<Val>;

/// Rows produced by MATCH stages before the query stops (and reports
/// `truncated`), so aggregations over huge expansions stay bounded.
const MAX_PRODUCED_ROWS: usize = 50_000_000;
/// Groups kept by one aggregation.
const MAX_GROUPS: usize = 2_000_000;
/// Rows buffered by one ORDER BY without LIMIT / DISTINCT set size.
const MAX_BUFFER_ROWS: usize = 5_000_000;
/// Start candidates processed per wave before rows are pushed downstream.
const WAVE: usize = 64 * 1024;
/// Start candidates from which non-start node predicates are answered by a
/// precomputed bitmap (one store filter, a few ms) instead of per node.
const END_BITMAP_MIN: usize = 4096;
/// Input rows processed per block by a MATCH / UNWIND stage.
const BLOCK: usize = 4096;
/// Elements produced by one UNWIND row.
const MAX_UNWIND: usize = 1_000_000;

/// Shared execution context.
pub(crate) struct Ctx<'g> {
    pub g: &'g Graph,
    pub cancel: Cancel,
    pub truncated: AtomicBool,
    produced: AtomicUsize,
    /// Edge cap for `allShortestPaths` subgraphs (the result limit).
    pub subgraph_cap: usize,
    /// Push node predicates down to the property columns when ready.
    pub pushdown: bool,
    /// Also evaluate every pushed predicate the CHQL way; panic on mismatch.
    pub verify: bool,
}

impl Ctx<'_> {
    #[inline]
    fn hit(&self) -> bool {
        self.cancel.hit()
    }
}

// ---------------------------------------------------------------- plan

pub(crate) struct NodeFilter {
    /// Allowed node kinds as a bitmask (labels folded in).
    kind_mask: u64,
    /// Label groups that need per-node flags (`Tag_Tier_Zero`, ...).
    flag_labels: Labels,
    /// Constant property equalities (lower-case keys).
    eqs: Vec<(Box<str>, Val)>,
    /// Single-variable predicates compiled against a one-slot row.
    exprs: Vec<CExpr>,
    /// Exact `name` / `objectid` values answerable from the hash index.
    index_keys: Option<Vec<String>>,
    /// `name STARTS WITH '…'`, answered from the sorted name index.
    prefix: Option<String>,
    /// `eqs[i]` / `exprs[i]` are part of `pushed`.
    eq_pushed: Vec<bool>,
    expr_pushed: Vec<bool>,
    /// Store filter equivalent to the labels plus every pushed eq / expr.
    pushed: Option<Filter>,
    /// Some property predicate (not only labels) is pushed.
    pushes_props: bool,
    /// The labels are part of `pushed` (or there are none).
    labels_pushed: bool,
    /// Nodes satisfying `pushed`; set only from the coordinating thread
    /// (`prepare`), read by workers.
    bitmap: OnceLock<RoaringBitmap>,
}

impl NodeFilter {
    fn new(kind_mask: u64, flag_labels: Labels, labels: &Labels) -> NodeFilter {
        NodeFilter {
            kind_mask,
            flag_labels,
            eqs: Vec::new(),
            exprs: Vec::new(),
            index_keys: None,
            prefix: None,
            eq_pushed: Vec::new(),
            expr_pushed: Vec::new(),
            pushed: pushdown::labels(labels),
            pushes_props: false,
            labels_pushed: labels.is_empty() || pushdown::labels(labels).is_some(),
            bitmap: OnceLock::new(),
        }
    }

    fn add_eq(&mut self, key: Box<str>, v: Val) {
        let f = pushdown::leaf_cmp(&key, CmpOp::Eq, &v);
        self.eq_pushed.push(f.is_some());
        self.push_filter(f);
        self.eqs.push((key, v));
    }

    fn add_expr(&mut self, e: CExpr, f: Option<Filter>) {
        self.expr_pushed.push(f.is_some());
        self.push_filter(f);
        self.exprs.push(e);
    }

    fn push_filter(&mut self, f: Option<Filter>) {
        let Some(f) = f else { return };
        self.pushes_props = true;
        self.pushed = Some(match self.pushed.take() {
            None => f,
            Some(Filter::And(mut v)) => {
                v.push(f);
                Filter::And(v)
            }
            Some(g) => Filter::And(vec![g, f]),
        });
    }

    fn trivial(&self) -> bool {
        self.kind_mask == u64::MAX && self.flag_labels.is_empty() && self.eqs.is_empty() && self.exprs.is_empty()
    }

    /// Full CHQL evaluation; with `skip_pushed`, predicates covered by the
    /// bitmap are skipped (labels are always checked: they are cheap).
    #[inline]
    fn check(&self, cx: &Ctx, id: u32, skip_pushed: bool) -> bool {
        let g = cx.g;
        if self.kind_mask != u64::MAX && (self.kind_mask >> (g.kind(id) as u8)) & 1 == 0 {
            return false;
        }
        if !self.flag_labels.is_empty() && !label_ok(g, id, &self.flag_labels) {
            return false;
        }
        if !self.eqs.iter().zip(&self.eq_pushed).all(|((k, v), p)| (skip_pushed && *p) || val_eq(&node_prop(g, id, k), v)) {
            return false;
        }
        if self.exprs.is_empty() || (skip_pushed && self.expr_pushed.iter().all(|p| *p)) {
            return true;
        }
        let row = [Val::Node(id)];
        let mut env = Env::new(cx, &row);
        self.exprs.iter().zip(&self.expr_pushed).all(|(e, p)| (skip_pushed && *p) || e.test(&mut env))
    }

    /// Evaluation of the pushed parts only, by CHQL (verification).
    fn check_pushed(&self, cx: &Ctx, id: u32) -> bool {
        let g = cx.g;
        // Labels count only when they are part of the store filter.
        if self.labels_pushed {
            if self.kind_mask != u64::MAX && (self.kind_mask >> (g.kind(id) as u8)) & 1 == 0 {
                return false;
            }
            if !self.flag_labels.is_empty() && !label_ok(g, id, &self.flag_labels) {
                return false;
            }
        }
        if !self.eqs.iter().zip(&self.eq_pushed).all(|((k, v), p)| !*p || val_eq(&node_prop(g, id, k), v)) {
            return false;
        }
        let row = [Val::Node(id)];
        let mut env = Env::new(cx, &row);
        self.exprs.iter().zip(&self.expr_pushed).all(|(e, p)| !*p || e.test(&mut env))
    }

    #[inline]
    fn matches(&self, cx: &Ctx, id: u32) -> bool {
        // Label-only filters: the kind byte / flag word beats a bitmap probe.
        if let Some(bm) = self.bitmap.get().filter(|_| self.pushes_props) {
            let r = bm.contains(id) && self.check(cx, id, true);
            if cx.verify {
                let want = self.check(cx, id, false);
                assert_eq!(r, want, "CHQL pushdown mismatch on node {id} for {:?}", self.pushed);
            }
            return r;
        }
        self.check(cx, id, false)
    }

    /// Whether `ensure_bitmap` would evaluate a filter.
    fn can_push(&self, cx: &Ctx) -> bool {
        cx.pushdown && self.pushed.is_some() && cx.g.columns_ready().is_some()
    }

    /// Evaluate `pushed` over the property columns once. Only call from the
    /// coordinating thread (see [`MatchPlan::prepare`]): the store builds
    /// lazy indexes with rayon inside `OnceLock`s.
    fn ensure_bitmap(&self, cx: &Ctx) {
        if self.bitmap.get().is_some() || !self.can_push(cx) {
            return;
        }
        let Some(f) = &self.pushed else { return };
        let bm = cx.g.filter(f);
        if cx.verify {
            let n = cx.g.node_count() as u32;
            let want: Vec<u32> = (0..n).into_par_iter().filter(|&id| self.check_pushed(cx, id)).collect();
            let got: Vec<u32> = bm.iter().collect();
            assert!(got == want, "CHQL pushdown mismatch for {f:?}: store {} nodes, CHQL {} nodes (first diff: {:?})", got.len(), want.len(), first_diff(&got, &want));
        }
        let _ = self.bitmap.set(bm);
    }

    fn candidates(&self, cx: &Ctx) -> Vec<u32> {
        let g = cx.g;
        if let Some(keys) = &self.index_keys {
            let mut ids: Vec<u32> = keys.iter().filter_map(|k| g.lookup(k)).collect();
            ids.sort_unstable();
            ids.dedup();
            ids.retain(|&id| self.matches(cx, id));
            return ids;
        }
        if !self.trivial() {
            self.ensure_bitmap(cx);
        }
        if let Some(prefix) = &self.prefix {
            let mut ids = g.search_prefix(prefix, None, usize::MAX);
            ids.retain(|&id| self.matches(cx, id));
            return ids;
        }
        if self.trivial() {
            return (0..g.node_count() as u32).collect();
        }
        let scan = || -> Vec<u32> { (0..g.node_count() as u32).into_par_iter().filter(|&id| !cx.hit() && self.check(cx, id, false)).collect() };
        let Some(bm) = self.bitmap.get() else { return scan() };
        let ids: Vec<u32> = bm.iter().collect();
        let all_pushed = self.labels_pushed && self.eq_pushed.iter().all(|p| *p) && self.expr_pushed.iter().all(|p| *p);
        let out: Vec<u32> = if all_pushed {
            ids
        } else {
            ids.into_par_iter().filter(|&id| !cx.hit() && self.check(cx, id, true)).collect()
        };
        if cx.verify && !cx.hit() {
            let want = scan();
            assert!(out == want, "CHQL pushdown candidate mismatch for {:?}: {:?}", self.pushed, first_diff(&out, &want));
        }
        out
    }
}

fn first_diff(a: &[u32], b: &[u32]) -> Option<(usize, Option<u32>, Option<u32>)> {
    (0..a.len().max(b.len())).find(|&i| a.get(i) != b.get(i)).map(|i| (i, a.get(i).copied(), b.get(i).copied()))
}

pub(crate) struct RelPlan {
    slot: Option<usize>,
    allow: EdgeFilter,
    dir: Dir,
    var_len: Option<(u32, Option<u32>)>,
}

#[derive(Clone, Copy, Debug)]
struct Step {
    from: usize,
    to: usize,
    rel: usize,
    /// Traversal direction (pattern direction, flipped when walking left).
    dir: Dir,
    /// Walking right-to-left: var-length edge lists are reversed on binding.
    reversed: bool,
    /// The target node's slot already holds a value at this step.
    to_bound: bool,
}

struct StartPlan {
    pos: usize,
    bound: bool,
    cands: Vec<u32>,
    steps: Vec<Step>,
}

pub(crate) struct PatPlan {
    node_slots: Vec<usize>,
    filters: Vec<NodeFilter>,
    rels: Vec<RelPlan>,
    path_slot: Option<usize>,
    func: PathFn,
    /// Node positions bound before this pattern starts.
    bound_before: Vec<bool>,
    start: OnceLock<StartPlan>,
    end_cands: [OnceLock<Vec<u32>>; 2],
}

impl PatPlan {
    fn steps_from(&self, s: usize) -> Vec<Step> {
        let k = self.rels.len();
        let mut bound: Vec<usize> = self.bound_before.iter().enumerate().filter(|(_, b)| **b).map(|(i, _)| self.node_slots[i]).collect();
        bound.push(self.node_slots[s]);
        let mut steps = Vec::new();
        let mut push = |from: usize, to: usize, rel: usize, reversed: bool, bound: &mut Vec<usize>| {
            let slot = self.node_slots[to];
            let dir = if reversed { self.rels[rel].dir.flip() } else { self.rels[rel].dir };
            steps.push(Step { from, to, rel, dir, reversed, to_bound: bound.contains(&slot) });
            bound.push(slot);
        };
        for to in s + 1..=k {
            push(to - 1, to, to - 1, false, &mut bound);
        }
        for to in (0..s).rev() {
            push(to + 1, to, to, true, &mut bound);
        }
        steps
    }

    fn start(&self, cx: &Ctx) -> &StartPlan {
        self.start.get_or_init(|| {
            let k = self.rels.len();
            if let Some(pos) = self.bound_before.iter().position(|b| *b) {
                return StartPlan { pos, bound: true, cands: Vec::new(), steps: self.steps_from(pos) };
            }
            let pos = if let Some(i) = self.filters.iter().position(|f| f.index_keys.is_some()) {
                Some(i)
            } else if k == 0 || self.filters[0].prefix.is_some() {
                Some(0)
            } else if self.filters[k].prefix.is_some() {
                Some(k)
            } else {
                None
            };
            let (pos, cands) = match pos {
                Some(p) => (p, self.filters[p].candidates(cx)),
                None => {
                    // Store filters must run on this thread (no rayon::join).
                    let (a, b) = if self.filters[0].can_push(cx) || self.filters[k].can_push(cx) {
                        (self.filters[0].candidates(cx), self.filters[k].candidates(cx))
                    } else {
                        rayon::join(|| self.filters[0].candidates(cx), || self.filters[k].candidates(cx))
                    };
                    if b.len() < a.len() {
                        (k, b)
                    } else {
                        (0, a)
                    }
                }
            };
            // Many walks ahead: answer the other positions' property
            // predicates by bitmap membership instead of per-node JSON.
            if cands.len() >= END_BITMAP_MIN {
                for (i, f) in self.filters.iter().enumerate() {
                    if i != pos && f.pushes_props {
                        f.ensure_bitmap(cx);
                    }
                }
            }
            StartPlan { pos, bound: false, cands, steps: self.steps_from(pos) }
        })
    }

    fn end_candidates(&self, cx: &Ctx, i: usize) -> &[u32] {
        self.end_cands[i].get_or_init(|| self.filters[if i == 0 { 0 } else { self.rels.len() }].candidates(cx))
    }
}

impl MatchPlan {
    /// Build start plans and candidate lists up front, innermost pattern
    /// predicates first, from the coordinating thread. Lazy initialisation
    /// inside rayon workers could deadlock: a thread blocked in a `OnceLock`
    /// initialiser may steal a task that waits on the same lock.
    pub fn prepare(&self, cx: &Ctx) {
        for p in &self.pats {
            for f in &p.filters {
                for e in &f.exprs {
                    e.visit_pats(&mut |pp| pp.prepare(cx));
                }
            }
        }
        for e in &self.residual {
            e.visit_pats(&mut |pp| pp.prepare(cx));
        }
        for p in &self.pats {
            if p.func == PathFn::None {
                p.start(cx);
            } else {
                if !p.bound_before[0] {
                    p.end_candidates(cx, 0);
                }
                if !p.bound_before[p.rels.len()] {
                    p.end_candidates(cx, 1);
                }
            }
        }
    }
}

pub(crate) struct MatchPlan {
    optional: bool,
    pats: Vec<PatPlan>,
    residual: Vec<CExpr>,
    /// Row width after this clause.
    width: usize,
}

/// A pattern predicate (`(a)-[:X]->(b)` in WHERE / `exists(...)`).
#[derive(Debug)]
pub(crate) struct PatPred {
    m: MatchPlan,
    /// Scope width (row + locals) at the predicate.
    base: usize,
}

impl std::fmt::Debug for MatchPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MatchPlan({} patterns)", self.pats.len())
    }
}

/// Matches counted by `size((a)-->(b))`.
const MAX_PATTERN_COUNT: usize = 1_000_000;

impl PatPred {
    pub fn prepare(&self, cx: &Ctx) {
        self.m.prepare(cx);
    }

    fn row(&self, env: &Env) -> Row {
        let mut row: Row = Vec::with_capacity(self.m.width);
        row.extend(env.row.iter().chain(env.locals.iter()).take(self.base).cloned());
        row.resize(self.m.width, Val::Null);
        row
    }

    pub fn exists(&self, env: &Env) -> bool {
        let mut row = self.row(env);
        let count = AtomicUsize::new(0);
        let stop = AtomicBool::new(false);
        let mut w = Walker::new(env.cx, &self.m, &count, &stop, 1);
        w.exists = true;
        w.run_pattern(0, &mut row);
        w.found
    }

    /// Number of matches (legacy `size((pattern))`), capped.
    pub fn count(&self, env: &Env) -> usize {
        let mut row = self.row(env);
        let count = AtomicUsize::new(0);
        let stop = AtomicBool::new(false);
        let mut w = Walker::new(env.cx, &self.m, &count, &stop, MAX_PATTERN_COUNT);
        w.count_only = true;
        w.run_pattern(0, &mut row);
        w.emitted.min(MAX_PATTERN_COUNT)
    }
}

fn edge_filter(g: &Graph, kinds: &[String], default_all: bool, pos: usize) -> Result<EdgeFilter, QueryError> {
    if kinds.is_empty() {
        return Ok(if default_all { EdgeFilter::all(g) } else { EdgeFilter::traversable(g) });
    }
    // Like Cypher, a relationship type absent from the data matches nothing;
    // only a list made entirely of unknown types is reported (likely a typo).
    let mut f = EdgeFilter::none(g);
    let mut known = 0;
    for k in kinds {
        if f.set(g, k, true).is_ok() {
            known += 1;
        }
    }
    if known == 0 {
        let msg = if kinds.len() == 1 { format!("unknown relationship type '{}'", kinds[0]) } else { format!("unknown relationship types {}", kinds.join("|")) };
        return Err(QueryError::sem_at(msg, pos));
    }
    Ok(f)
}

/// Split label groups into a kind bitmask and the groups that test flags.
fn fold_labels(labels: &Labels) -> (u64, Labels) {
    let mut mask = u64::MAX;
    let mut rest = Vec::new();
    for any in labels {
        if any.iter().any(|l| matches!(l, LabelPred::Flag(_) | LabelPred::Raw(_))) {
            rest.push(any.clone());
            continue;
        }
        let mut m = 0u64;
        for l in any {
            m |= match *l {
                LabelPred::Kind(k) => 1u64 << (k as u8),
                LabelPred::Any(None) => u64::MAX,
                LabelPred::Any(Some(az)) => ch_model::NodeKind::ALL.iter().filter(|k| k.is_azure() == az).fold(0, |a, k| a | 1u64 << (*k as u8)),
                LabelPred::Flag(_) | LabelPred::Raw(_) => 0,
            };
        }
        mask &= m;
    }
    (mask, rest)
}

fn hidden(prefix: &str, scope: &[String]) -> String {
    format!(" {prefix}{}", scope.len())
}

fn slot_for(name: String, scope: &mut Vec<String>) -> usize {
    match scope.iter().position(|s| *s == name) {
        Some(i) => i,
        None => {
            scope.push(name);
            scope.len() - 1
        }
    }
}

/// Value of a variable-free expression that folds at compile time.
fn const_val(g: &Graph, e: &Expr) -> Option<Val> {
    let mut v = Vec::new();
    e.vars(&mut v);
    if !v.is_empty() || e.has_aggregate() {
        return None;
    }
    match Compiler::new(g).compile(e, &mut Vec::new()) {
        Ok(CExpr::Const(v)) => Some(v),
        _ => None,
    }
}

/// Plan one MATCH clause. Extends `scope` with the clause's variables.
pub(crate) fn plan_match(g: &Graph, patterns: &[Pattern], filter: Option<&Expr>, optional: bool, scope: &mut Vec<String>) -> Result<MatchPlan, QueryError> {
    // Path functions run after the patterns that bind their endpoints.
    let mut order: Vec<&Pattern> = patterns.iter().filter(|p| p.func == PathFn::None).collect();
    order.extend(patterns.iter().filter(|p| p.func != PathFn::None));

    let mut extra_conj: Vec<Expr> = Vec::new();
    struct Pending {
        node_slots: Vec<usize>,
        node_vars: Vec<String>,
        rel_slots: Vec<Option<usize>>,
        path_slot: Option<usize>,
        bound_before: Vec<bool>,
    }
    let mut pend = Vec::new();
    let mut rel_names: AHashSet<String> = AHashSet::new();
    for p in &order {
        let mut node_slots = Vec::new();
        let mut node_vars = Vec::new();
        let mut bound_before = Vec::new();
        for n in &p.nodes {
            let name = n.var.clone().unwrap_or_else(|| hidden("n", scope));
            if rel_names.contains(&name) {
                return Err(QueryError::sem_at(format!("variable '{name}' is already bound to a relationship"), n.pos));
            }
            bound_before.push(scope.contains(&name));
            node_slots.push(slot_for(name.clone(), scope));
            node_vars.push(name);
        }
        let need_rel_slots = p.path_var.is_some();
        let mut rel_slots = Vec::new();
        for r in &p.rels {
            rel_slots.push(match &r.var {
                Some(v) => {
                    if scope.contains(v) {
                        return Err(QueryError::sem_at(format!("relationship variable '{v}' is already bound; re-using relationship variables is not supported"), r.pos));
                    }
                    rel_names.insert(v.clone());
                    Some(slot_for(v.clone(), scope))
                }
                None if need_rel_slots => Some(slot_for(hidden("r", scope), scope)),
                None => None,
            });
        }
        let path_slot = match &p.path_var {
            Some(v) => {
                if scope.contains(v) {
                    return Err(QueryError::sem_at(format!("path variable '{v}' is already bound"), p.pos));
                }
                Some(slot_for(v.clone(), scope))
            }
            None => None,
        };
        // Non-constant inline properties become WHERE conjuncts.
        for (n, var) in p.nodes.iter().zip(&node_vars) {
            for (k, e) in &n.props {
                if const_val(g, e).is_none() {
                    extra_conj.push(Expr::Cmp(
                        Box::new(Expr::Prop(Box::new(Expr::Var(var.clone(), n.pos)), k.clone())),
                        CmpOp::Eq,
                        Box::new(e.clone()),
                    ));
                }
            }
        }
        pend.push(Pending { node_slots, node_vars, rel_slots, path_slot, bound_before });
    }

    // Node filters.
    let mut filters: Vec<Vec<NodeFilter>> = Vec::new();
    for p in &order {
        let mut fs = Vec::new();
        for n in &p.nodes {
            let (kind_mask, flag_labels) = fold_labels(&n.labels);
            let mut f = NodeFilter::new(kind_mask, flag_labels, &n.labels);
            for (k, e) in &n.props {
                if let Some(v) = const_val(g, e) {
                    f.add_eq(k.to_ascii_lowercase().into_boxed_str(), v);
                }
            }
            f.index_keys = f.eqs.iter().find_map(|(k, v)| match v {
                Val::Str(s) if &**k == "name" || &**k == "objectid" => Some(vec![s.clone()]),
                _ => None,
            });
            fs.push(f);
        }
        filters.push(fs);
    }

    // WHERE: push single-node-variable conjuncts into node filters.
    let mut residual = Vec::new();
    let mut conj = Vec::new();
    if let Some(f) = filter {
        f.clone().conjuncts(&mut conj);
    }
    conj.extend(extra_conj);
    for c in conj {
        let mut vars = Vec::new();
        c.vars(&mut vars);
        vars.sort();
        vars.dedup();
        if c.has_aggregate() {
            return Err(QueryError::new("aggregate functions are not allowed in WHERE"));
        }
        let node_var = match vars.as_slice() {
            [v] if pend.iter().any(|pd| pd.node_vars.contains(v)) => Some(v.clone()),
            _ => None,
        };
        let Some(v) = node_var else {
            residual.push(Compiler::new(g).compile(&c, scope)?);
            continue;
        };
        for (fs, pd) in filters.iter_mut().zip(&pend) {
            for (f, nv) in fs.iter_mut().zip(&pd.node_vars) {
                if *nv != v {
                    continue;
                }
                let mut mini = vec![v.clone()];
                // Promote `x.name = '…'` / `x.objectid IN [...]` to index lookups.
                if let Expr::Cmp(a, op, b) = &c {
                    if let (Expr::Prop(base, key), Expr::Lit(Lit::Str(s))) = (&**a, &**b) {
                        let key = key.to_ascii_lowercase();
                        if matches!(&**base, Expr::Var(..)) {
                            match op {
                                CmpOp::Eq => {
                                    if (key == "name" || key == "objectid") && f.index_keys.is_none() {
                                        f.index_keys = Some(vec![s.clone()]);
                                    }
                                    f.add_eq(key.into_boxed_str(), Val::Str(s.clone()));
                                    continue;
                                }
                                CmpOp::StartsWith if key == "name" => {
                                    f.prefix.get_or_insert_with(|| s.clone());
                                }
                                _ => {}
                            }
                        }
                    }
                    if let (Expr::Prop(base, key), CmpOp::In, Expr::List(items)) = (&**a, op, &**b) {
                        let key = key.to_ascii_lowercase();
                        if matches!(&**base, Expr::Var(..)) && (key == "name" || key == "objectid") && f.index_keys.is_none() {
                            let strs: Vec<String> = items.iter().filter_map(|x| if let Expr::Lit(Lit::Str(s)) = x { Some(s.clone()) } else { None }).collect();
                            if strs.len() == items.len() {
                                f.index_keys = Some(strs);
                            }
                        }
                    }
                }
                let pushed = pushdown::expr(&c, &v, &|e| const_val(g, e));
                f.add_expr(Compiler::new(g).compile(&c, &mut mini)?, pushed);
            }
        }
    }

    let mut pats = Vec::new();
    for ((p, pd), fs) in order.iter().zip(pend).zip(filters) {
        let is_path = p.func != PathFn::None;
        let mut rels = Vec::new();
        for (r, slot) in p.rels.iter().zip(&pd.rel_slots) {
            rels.push(RelPlan {
                slot: *slot,
                allow: edge_filter(g, &r.kinds, r.var_len.is_none() && !is_path, r.pos)?,
                dir: r.dir,
                var_len: if is_path { Some(r.var_len.unwrap_or((1, None))) } else { r.var_len },
            });
        }
        pats.push(PatPlan {
            node_slots: pd.node_slots,
            filters: fs,
            rels,
            path_slot: pd.path_slot,
            func: p.func,
            bound_before: pd.bound_before,
            start: OnceLock::new(),
            end_cands: [OnceLock::new(), OnceLock::new()],
        });
    }
    Ok(MatchPlan { optional, pats, residual, width: scope.len() })
}

pub(crate) fn plan_pattern_pred(g: &Graph, p: &Pattern, scope: &mut Vec<String>) -> Result<PatPred, QueryError> {
    if p.func != PathFn::None {
        return Err(QueryError::sem_at("path functions are not allowed in pattern predicates", p.pos));
    }
    let base = scope.len();
    let m = plan_match(g, std::slice::from_ref(p), None, false, scope);
    scope.truncate(base);
    Ok(PatPred { m: m?, base })
}

// ------------------------------------------------------------ expansion

#[inline]
fn neighbors(g: &Graph, x: u32, dir: Dir, allow: &EdgeFilter, f: &mut impl FnMut(u32, E) -> bool) -> bool {
    if dir != Dir::In {
        let (ns, ks) = g.out_edges(x);
        for (&y, &k) in ns.iter().zip(ks) {
            if allow.allows(k) && !f(y, (x, y, k)) {
                return false;
            }
        }
    }
    if dir != Dir::Out {
        let (ns, ks) = g.in_edges(x);
        for (&y, &k) in ns.iter().zip(ks) {
            if allow.allows(k) && !f(y, (y, x, k)) {
                return false;
            }
        }
    }
    true
}

/// Variable-length expansion (BFS, reachability semantics). `f(v, edges)`
/// returns false to stop the expansion.
#[allow(clippy::too_many_arguments)]
fn expand_var(cx: &Ctx, u: u32, r: &RelPlan, dir: Dir, need_edges: bool, f: &mut dyn FnMut(u32, Vec<E>) -> bool) {
    let (min, max) = r.var_len.unwrap_or((1, None));
    let max = max.unwrap_or(u32::MAX);
    let g = cx.g;
    let mut parent: AHashMap<u32, E> = AHashMap::new();
    let mut seen: AHashSet<u32> = AHashSet::new();
    seen.insert(u);
    if min == 0 && !f(u, Vec::new()) {
        return;
    }
    let mut frontier = vec![u];
    let mut depth = 0u32;
    while !frontier.is_empty() && depth < max {
        if cx.hit() {
            return;
        }
        depth += 1;
        let mut next = Vec::new();
        for &x in &frontier {
            neighbors(g, x, dir, &r.allow, &mut |y, e| {
                if seen.insert(y) {
                    if need_edges {
                        parent.insert(y, e);
                    }
                    next.push(y);
                }
                true
            });
        }
        if depth >= min {
            for &y in &next {
                let edges = if need_edges {
                    let mut es = Vec::new();
                    let mut c = y;
                    while c != u {
                        let e = parent[&c];
                        es.push(e);
                        c = if e.1 == c { e.0 } else { e.1 };
                    }
                    es.reverse();
                    es
                } else {
                    Vec::new()
                };
                if !f(y, edges) {
                    return;
                }
            }
        }
        frontier = next;
    }
}

// --------------------------------------------------------------- walker

/// Depth-first matcher for the patterns of one MATCH clause.
struct Walker<'a, 'g> {
    cx: &'a Ctx<'g>,
    m: &'a MatchPlan,
    /// Fixed-length edges bound so far (relationship uniqueness).
    used: Vec<E>,
    out: Vec<Row>,
    count: &'a AtomicUsize,
    stop: &'a AtomicBool,
    cap: usize,
    exists: bool,
    found: bool,
    /// Aggregate rows in place instead of collecting them.
    agg: Option<(&'a ProjPlan, AggTable)>,
    err: Option<QueryError>,
    /// Rows produced but not yet added to `cx.produced`.
    pending: usize,
    emitted: usize,
    scratch: Row,
    count_only: bool,
}

impl Drop for Walker<'_, '_> {
    fn drop(&mut self) {
        self.cx.produced.fetch_add(self.pending, Ordering::Relaxed);
    }
}

impl<'a, 'g> Walker<'a, 'g> {
    fn new(cx: &'a Ctx<'g>, m: &'a MatchPlan, count: &'a AtomicUsize, stop: &'a AtomicBool, cap: usize) -> Self {
        Walker { cx, m, used: Vec::new(), out: Vec::new(), count, stop, cap, exists: false, found: false, agg: None, err: None, pending: 0, emitted: 0, scratch: Vec::new(), count_only: false }
    }

    #[inline]
    fn halted(&self) -> bool {
        self.stop.load(Ordering::Relaxed) || self.cx.hit()
    }

    fn emit(&mut self, row: &[Val]) -> bool {
        if !self.m.residual.is_empty() {
            let mut env = Env::new(self.cx, row);
            if !self.m.residual.iter().all(|e| e.test(&mut env)) {
                return true;
            }
        }
        if self.exists {
            self.found = true;
            return false;
        }
        self.deliver(row)
    }

    /// Hand a finished row downstream (no residual check).
    fn deliver(&mut self, row: &[Val]) -> bool {
        self.emitted += 1;
        if self.count_only {
            return self.emitted < self.cap && !self.cx.hit();
        }
        if self.cap != usize::MAX && self.count.fetch_add(1, Ordering::Relaxed) >= self.cap {
            self.stop.store(true, Ordering::Relaxed);
            return false;
        }
        self.pending += 1;
        if self.pending >= 1024 {
            let before = self.cx.produced.fetch_add(self.pending, Ordering::Relaxed);
            self.pending = 0;
            if before >= MAX_PRODUCED_ROWS {
                self.cx.truncated.store(true, Ordering::Relaxed);
                self.stop.store(true, Ordering::Relaxed);
                return false;
            }
        }
        if let Some((pp, t)) = &mut self.agg {
            if let Err(e) = t.add(self.cx, pp, row) {
                self.err = Some(e);
                self.stop.store(true, Ordering::Relaxed);
                return false;
            }
            return true;
        }
        self.out.push(row.to_vec());
        true
    }

    fn run_pattern(&mut self, pi: usize, row: &mut Row) -> bool {
        if pi == self.m.pats.len() {
            return self.emit(row);
        }
        let p = &self.m.pats[pi];
        if p.func != PathFn::None {
            return self.path_fn(pi, row);
        }
        let sp = p.start(self.cx);
        let slot = p.node_slots[sp.pos];
        if sp.bound {
            return match row[slot] {
                Val::Node(v) if p.filters[sp.pos].matches(self.cx, v) => self.walk(pi, 0, row),
                _ => true,
            };
        }
        for &c in &sp.cands {
            if self.halted() {
                return false;
            }
            row[slot] = Val::Node(c);
            let go = self.walk(pi, 0, row);
            row[slot] = Val::Null;
            if !go {
                return false;
            }
        }
        true
    }

    fn walk(&mut self, pi: usize, si: usize, row: &mut Row) -> bool {
        let m = self.m;
        let p = &m.pats[pi];
        let sp = p.start(self.cx);
        if si == sp.steps.len() {
            return self.pattern_done(pi, row);
        }
        let st = sp.steps[si];
        let Val::Node(u) = row[p.node_slots[st.from]] else { return true };
        let to_slot = p.node_slots[st.to];
        let filt = &p.filters[st.to];
        let r = &p.rels[st.rel];
        let target = if st.to_bound {
            match row[to_slot] {
                Val::Node(t) => Some(t),
                _ => return true,
            }
        } else {
            None
        };
        let cx = self.cx;
        if r.var_len.is_none() {
            let mut hits: Vec<(u32, E)> = Vec::new();
            neighbors(cx.g, u, st.dir, &r.allow, &mut |v, e| {
                if target.is_none_or(|t| t == v) && filt.matches(cx, v) {
                    hits.push((v, e));
                }
                true
            });
            for (v, e) in hits {
                if self.used.contains(&e) {
                    continue;
                }
                if self.halted() {
                    return false;
                }
                if !st.to_bound {
                    row[to_slot] = Val::Node(v);
                }
                if let Some(s) = r.slot {
                    row[s] = Val::Edge(e);
                }
                self.used.push(e);
                let go = self.walk(pi, si + 1, row);
                self.used.pop();
                if let Some(s) = r.slot {
                    row[s] = Val::Null;
                }
                if !st.to_bound {
                    row[to_slot] = Val::Null;
                }
                if !go {
                    return false;
                }
            }
            true
        } else {
            let need = r.slot.is_some();
            let mut hits: Vec<(u32, Vec<E>)> = Vec::new();
            expand_var(cx, u, r, st.dir, need, &mut |v, es| match target {
                Some(t) => {
                    if v == t {
                        if filt.matches(cx, v) {
                            hits.push((v, es));
                        }
                        return false;
                    }
                    true
                }
                None => {
                    if filt.matches(cx, v) {
                        hits.push((v, es));
                    }
                    !cx.hit()
                }
            });
            for (v, mut es) in hits {
                if self.halted() {
                    return false;
                }
                if !st.to_bound {
                    row[to_slot] = Val::Node(v);
                }
                if let Some(s) = r.slot {
                    if st.reversed {
                        es.reverse();
                    }
                    row[s] = Val::Edges(es.into());
                }
                let go = self.walk(pi, si + 1, row);
                if let Some(s) = r.slot {
                    row[s] = Val::Null;
                }
                if !st.to_bound {
                    row[to_slot] = Val::Null;
                }
                if !go {
                    return false;
                }
            }
            true
        }
    }

    fn pattern_done(&mut self, pi: usize, row: &mut Row) -> bool {
        let p = &self.m.pats[pi];
        let Some(ps) = p.path_slot else { return self.run_pattern(pi + 1, row) };
        row[ps] = build_path(p, row);
        let go = self.run_pattern(pi + 1, row);
        row[ps] = Val::Null;
        go
    }

    fn endpoint(&self, p: &PatPlan, i: usize, row: &Row) -> Option<Vec<u32>> {
        let pos = if i == 0 { 0 } else { p.rels.len() };
        if p.bound_before[pos] {
            match row[p.node_slots[pos]] {
                Val::Node(v) if p.filters[pos].matches(self.cx, v) => Some(vec![v]),
                _ => None,
            }
        } else {
            Some(p.end_candidates(self.cx, i).to_vec())
        }
    }

    fn path_fn(&mut self, pi: usize, row: &mut Row) -> bool {
        let p = &self.m.pats[pi];
        let (Some(a), Some(b)) = (self.endpoint(p, 0, row), self.endpoint(p, 1, row)) else { return true };
        if a.is_empty() || b.is_empty() {
            return true;
        }
        let r = &p.rels[0];
        let (s0, s1) = (p.node_slots[0], p.node_slots[1]);
        let (b0, b1) = (p.bound_before[0], p.bound_before[1]);
        if p.func == PathFn::AllShortest {
            let Some(sub) = all_shortest(self.cx, r, &a, &b) else { return true };
            if let Some(ps) = p.path_slot {
                row[ps] = Val::Subgraph(Arc::new(sub));
            }
            let go = self.run_pattern(pi + 1, row);
            if let Some(ps) = p.path_slot {
                row[ps] = Val::Null;
            }
            return go;
        }
        let mut go = true;
        shortest_paths(self.cx, r, &a, &b, &mut |nodes, edges| {
            if !b0 {
                row[s0] = Val::Node(nodes[0]);
            }
            if !b1 {
                row[s1] = Val::Node(*nodes.last().expect("non-empty"));
            }
            if let Some(s) = r.slot {
                row[s] = Val::Edges(edges.clone().into());
            }
            if let Some(ps) = p.path_slot {
                row[ps] = Val::Path(Arc::new(PathVal { nodes, edges }));
            }
            go = self.run_pattern(pi + 1, row);
            go
        });
        for (s, b) in [(s0, b0), (s1, b1)] {
            if !b {
                row[s] = Val::Null;
            }
        }
        if let Some(s) = r.slot {
            row[s] = Val::Null;
        }
        if let Some(ps) = p.path_slot {
            row[ps] = Val::Null;
        }
        go
    }
}

/// Ordered node / edge sequence through a matched pattern.
fn build_path(p: &PatPlan, row: &[Val]) -> Val {
    let Val::Node(mut cur) = row[p.node_slots[0]] else { return Val::Null };
    let mut nodes = vec![cur];
    let mut edges = Vec::new();
    for (i, r) in p.rels.iter().enumerate() {
        let es: Vec<E> = match r.slot.map(|s| &row[s]) {
            Some(Val::Edge(e)) => vec![*e],
            Some(Val::Edges(es)) => es.to_vec(),
            _ => Vec::new(),
        };
        let Val::Node(target) = row[p.node_slots[i + 1]] else { return Val::Null };
        for e in &es {
            cur = if e.0 == cur { e.1 } else { e.0 };
            nodes.push(cur);
        }
        if cur != target {
            cur = target;
            nodes.push(cur);
        }
        edges.extend(es);
    }
    Val::Path(Arc::new(PathVal { nodes, edges }))
}

// ------------------------------------------------------- path functions

/// Bidirectional BFS from `srcs` to `tgts` along `dir`, at most `max` hops.
fn bidi(cx: &Ctx, srcs: &[u32], tgts: &[u32], allow: &EdgeFilter, dir: Dir, max: Option<u32>) -> Option<(Vec<u32>, Vec<E>)> {
    const ROOT: E = (u32::MAX, u32::MAX, 0);
    let g = cx.g;
    let mut fw: AHashMap<u32, (E, u32)> = AHashMap::new();
    let mut bw: AHashMap<u32, (E, u32)> = AHashMap::new();
    let mut ff: Vec<u32> = Vec::new();
    let mut fb: Vec<u32> = Vec::new();
    for &s in srcs {
        if fw.insert(s, (ROOT, 0)).is_none() {
            ff.push(s);
        }
    }
    for &t in tgts {
        if bw.insert(t, (ROOT, 0)).is_none() {
            fb.push(t);
        }
    }
    let (mut df, mut db) = (0u32, 0u32);
    let meet = loop {
        if ff.is_empty() || fb.is_empty() || cx.hit() || max.is_some_and(|m| df + db >= m) {
            return None;
        }
        let forward = ff.len() <= fb.len();
        let (front, mine, other, d, sdir) = if forward { (&mut ff, &mut fw, &bw, &mut df, dir) } else { (&mut fb, &mut bw, &fw, &mut db, dir.flip()) };
        *d += 1;
        let depth = *d;
        let mut next = Vec::new();
        let mut best: Option<(u32, u32)> = None;
        for &x in front.iter() {
            neighbors(g, x, sdir, allow, &mut |y, e| {
                if let std::collections::hash_map::Entry::Vacant(v) = mine.entry(y) {
                    v.insert((e, depth));
                    next.push(y);
                    if let Some(&(_, od)) = other.get(&y) {
                        if best.is_none_or(|(_, c)| depth + od < c) {
                            best = Some((y, depth + od));
                        }
                    }
                }
                true
            });
        }
        *front = next;
        if let Some((m, cost)) = best {
            if max.is_none_or(|mx| cost <= mx) {
                break m;
            }
            return None;
        }
    };
    let walk = |map: &AHashMap<u32, (E, u32)>, start: u32| -> (Vec<u32>, Vec<E>) {
        let mut nodes = vec![start];
        let mut edges = Vec::new();
        let mut c = start;
        loop {
            let (e, _) = map[&c];
            if e == ROOT {
                break;
            }
            edges.push(e);
            c = if e.0 == c { e.1 } else { e.0 };
            nodes.push(c);
        }
        (nodes, edges)
    };
    let (mut n1, mut e1) = walk(&fw, meet);
    n1.reverse();
    e1.reverse();
    let (n2, e2) = walk(&bw, meet);
    n1.extend_from_slice(&n2[1..]);
    e1.extend(e2);
    Some((n1, e1))
}

/// Multi-source reverse BFS from `targets` against the pattern direction:
/// per node, the next hop toward the nearest target, the edge and distance.
/// Stops after the level where every node in `stop_when` has been reached.
/// Edge kinds carry bit 15 when the hop runs against graph orientation.
fn reverse_bfs(cx: &Ctx, targets: &[u32], allow: &EdgeFilter, dir: Dir, max: Option<u32>, stop_when: Option<&[u32]>, paths: bool) -> (Vec<u32>, Vec<u16>, Vec<u32>) {
    let g = cx.g;
    let n = g.node_count();
    let mut next = if paths { vec![u32::MAX; n] } else { Vec::new() };
    let mut kind = if paths { vec![0u16; n] } else { Vec::new() };
    let mut dist = vec![u32::MAX; n];
    let mut level: Vec<u32> = Vec::with_capacity(targets.len());
    for &t in targets {
        if dist[t as usize] == u32::MAX {
            if paths {
                next[t as usize] = t;
            }
            dist[t as usize] = 0;
            level.push(t);
        }
    }
    let mut remaining = stop_when.map(|s| s.iter().filter(|&&a| dist[a as usize] == u32::MAX).count());
    let mut d = 0u32;
    while !level.is_empty() && !cx.hit() && max.is_none_or(|m| d < m) {
        if remaining == Some(0) {
            break;
        }
        d += 1;
        let mut nl = Vec::new();
        for &v in &level {
            neighbors(g, v, dir.flip(), allow, &mut |u, e| {
                if dist[u as usize] == u32::MAX {
                    if paths {
                        next[u as usize] = v;
                        kind[u as usize] = if e.0 == u { e.2 } else { e.2 | 0x8000 };
                    }
                    dist[u as usize] = d;
                    nl.push(u);
                }
                true
            });
        }
        if let (Some(r), Some(s)) = (remaining.as_mut(), stop_when) {
            *r = s.iter().filter(|&&a| dist[a as usize] == u32::MAX).count();
        }
        level = nl;
    }
    (next, kind, dist)
}

/// One shortest path per start node in `a` to the nearest node of `b`.
fn shortest_paths(cx: &Ctx, r: &RelPlan, a: &[u32], b: &[u32], f: &mut dyn FnMut(Vec<u32>, Vec<E>) -> bool) {
    let (min, max) = r.var_len.unwrap_or((1, None));
    let g = cx.g;
    if a.len() <= 64 {
        let bset: AHashSet<u32> = b.iter().copied().collect();
        for &s in a {
            if cx.hit() {
                return;
            }
            let targets: Vec<u32> = if bset.contains(&s) { b.iter().copied().filter(|&t| t != s).collect() } else { b.to_vec() };
            if targets.is_empty() {
                continue;
            }
            let res = match (r.dir, max) {
                (Dir::Out, None) => shortest_path(g, &[s], &targets, &r.allow).map(|res| {
                    let edges: Vec<E> = res.nodes.windows(2).zip(&res.kinds).map(|(w, &k)| (w[0], w[1], k)).collect();
                    (res.nodes, edges)
                }),
                (Dir::In, None) => shortest_path(g, &targets, &[s], &r.allow).map(|res| {
                    let mut edges: Vec<E> = res.nodes.windows(2).zip(&res.kinds).map(|(w, &k)| (w[0], w[1], k)).collect();
                    let mut nodes = res.nodes;
                    nodes.reverse();
                    edges.reverse();
                    (nodes, edges)
                }),
                _ => bidi(cx, &[s], &targets, &r.allow, r.dir, max),
            };
            if let Some((nodes, edges)) = res {
                if (edges.len() as u32) < min {
                    continue;
                }
                if !f(nodes, edges) {
                    return;
                }
            }
        }
        return;
    }
    let (next, kind, dist) = reverse_bfs(cx, b, &r.allow, r.dir, max, None, true);
    for &s in a {
        if cx.hit() {
            return;
        }
        let d = dist[s as usize];
        if d == u32::MAX || d == 0 || d < min {
            continue;
        }
        let mut nodes = vec![s];
        let mut edges = Vec::new();
        let mut c = s;
        while next[c as usize] != c {
            let k = kind[c as usize];
            let nx = next[c as usize];
            edges.push(if k & 0x8000 == 0 { (c, nx, k) } else { (nx, c, k & 0x7fff) });
            c = nx;
            nodes.push(c);
        }
        if !f(nodes, edges) {
            return;
        }
    }
}

/// Union of all shortest paths from each node of `a` to its nearest node of `b`.
fn all_shortest(cx: &Ctx, r: &RelPlan, a: &[u32], b: &[u32]) -> Option<PathVal> {
    let (_, max) = r.var_len.unwrap_or((1, None));
    let (_, _, dist) = reverse_bfs(cx, b, &r.allow, r.dir, max, Some(a), false);
    let mut seen: AHashSet<u32> = AHashSet::new();
    let mut frontier: Vec<u32> = a.iter().copied().filter(|&s| dist[s as usize] != u32::MAX && dist[s as usize] > 0).collect();
    frontier.sort_unstable();
    frontier.dedup();
    if frontier.is_empty() {
        return None;
    }
    seen.extend(frontier.iter().copied());
    let mut nodes: Vec<u32> = frontier.clone();
    let mut edges: Vec<E> = Vec::new();
    let cap = cx.subgraph_cap.max(1);
    'outer: while !frontier.is_empty() && !cx.hit() {
        let mut next = Vec::new();
        for &u in &frontier {
            let du = dist[u as usize];
            if du == 0 {
                continue;
            }
            let mut full = false;
            neighbors(cx.g, u, r.dir, &r.allow, &mut |v, e| {
                if dist[v as usize] != u32::MAX && dist[v as usize] + 1 == du {
                    if edges.len() >= cap {
                        full = true;
                        return false;
                    }
                    edges.push(e);
                    if seen.insert(v) {
                        nodes.push(v);
                        next.push(v);
                    }
                }
                true
            });
            if full {
                cx.truncated.store(true, Ordering::Relaxed);
                break 'outer;
            }
        }
        frontier = next;
    }
    Some(PathVal { nodes, edges })
}

// --------------------------------------------------------------- stages

trait Stage {
    /// Push rows; returns false when no more rows are wanted.
    fn push(&mut self, cx: &Ctx, rows: Vec<Row>) -> Result<bool, QueryError>;
    fn finish(&mut self, cx: &Ctx) -> Result<(), QueryError>;
    /// Upper bound on the rows still useful from upstream, if known.
    fn demand(&self) -> Option<usize>;
    /// Final rows (collector only).
    fn take_rows(&mut self) -> Vec<Row> {
        Vec::new()
    }
    /// Merge a partial aggregation built by the upstream MATCH stage.
    fn merge_agg(&mut self, _cx: &Ctx, _t: AggTable) -> Result<(), QueryError> {
        Err(QueryError::new("internal: stage does not aggregate"))
    }
}

struct Collector {
    rows: Vec<Row>,
}

impl Stage for Collector {
    fn push(&mut self, _: &Ctx, rows: Vec<Row>) -> Result<bool, QueryError> {
        self.rows.extend(rows);
        Ok(true)
    }
    fn finish(&mut self, _: &Ctx) -> Result<(), QueryError> {
        Ok(())
    }
    fn demand(&self) -> Option<usize> {
        None
    }
    fn take_rows(&mut self) -> Vec<Row> {
        std::mem::take(&mut self.rows)
    }
}

struct MatchStage<'p> {
    plan: &'p MatchPlan,
    /// Next stage aggregates: aggregate inside the parallel producers.
    agg: Option<&'p ProjPlan>,
    buf: Vec<Row>,
    next: Box<dyn Stage + 'p>,
    done: bool,
}

type Work<'w, T> = dyn Fn(&mut Walker, &T) -> bool + Sync + 'w;

impl MatchStage<'_> {
    /// Run `work` over `items` on all cores; deliver rows (or partial
    /// aggregates) downstream. Returns (rows emitted, more wanted).
    fn fan_out<T: Sync>(&mut self, cx: &Ctx, items: &[T], chunk: usize, init: &Row, work: &Work<T>) -> Result<(usize, bool), QueryError> {
        let m = self.plan;
        let cap = self.next.demand().unwrap_or(usize::MAX);
        let count = AtomicUsize::new(0);
        let stop = AtomicBool::new(false);
        let run = |w: &mut Walker, ch: &[T]| {
            for it in ch {
                if w.halted() || !work(w, it) {
                    break;
                }
            }
        };
        if let Some(pp) = self.agg {
            type Part = (AggTable, usize, Option<QueryError>);
            let (table, n, err): Part = items
                .par_chunks(chunk)
                .fold(
                    || (AggTable::default(), 0usize, None),
                    |(t, n, e): Part, ch| {
                        let mut w = Walker::new(cx, m, &count, &stop, cap);
                        w.scratch = init.clone();
                        w.agg = Some((pp, t));
                        run(&mut w, ch);
                        let (_, t) = w.agg.take().expect("set above");
                        let e = e.or(w.err.take());
                        (t, n + w.emitted, e)
                    },
                )
                .reduce(
                    || (AggTable::default(), 0, None),
                    |(mut a, n1, e1): Part, (b, n2, e2): Part| {
                        let e3 = a.merge(cx, pp, b).err();
                        (a, n1 + n2, e1.or(e2).or(e3))
                    },
                );
            if let Some(e) = err {
                return Err(e);
            }
            self.next.merge_agg(cx, table)?;
            return Ok((n, true));
        }
        let rows: Vec<Row> = items
            .par_chunks(chunk)
            .flat_map_iter(|ch| {
                let mut w = Walker::new(cx, m, &count, &stop, cap);
                w.scratch = init.clone();
                run(&mut w, ch);
                std::mem::take(&mut w.out)
            })
            .collect();
        let n = rows.len();
        let more = self.next.push(cx, rows)?;
        Ok((n, more))
    }

    fn process(&mut self, cx: &Ctx) -> Result<bool, QueryError> {
        let block = std::mem::take(&mut self.buf);
        if block.is_empty() || self.done {
            return Ok(!self.done);
        }
        let m = self.plan;
        let width = m.width;
        let block: Vec<Row> = block
            .into_iter()
            .map(|mut r| {
                r.resize(width, Val::Null);
                r
            })
            .collect();
        // Fan out over the first pattern's start candidates.
        if block.len() == 1 && m.pats.first().is_some_and(|p| p.func == PathFn::None) {
            let p0 = &m.pats[0];
            let sp = p0.start(cx);
            if !sp.bound {
                let slot = p0.node_slots[sp.pos];
                let mut emitted = 0usize;
                let work = move |w: &mut Walker, c: &u32| {
                    let mut row = std::mem::take(&mut w.scratch);
                    row[slot] = Val::Node(*c);
                    let go = w.walk(0, 0, &mut row);
                    row[slot] = Val::Null;
                    w.scratch = row;
                    go
                };
                for wave in sp.cands.chunks(WAVE) {
                    if cx.hit() {
                        break;
                    }
                    let (n, more) = self.fan_out(cx, wave, 256, &block[0], &work)?;
                    emitted += n;
                    if !more || cx.produced.load(Ordering::Relaxed) >= MAX_PRODUCED_ROWS {
                        self.done = true;
                        return Ok(false);
                    }
                }
                if m.optional && emitted == 0 && !cx.hit() {
                    let more = self.next.push(cx, block)?;
                    self.done = !more;
                    return Ok(more);
                }
                return Ok(true);
            }
        }
        // Fan out over input rows.
        let optional = m.optional;
        let work = move |w: &mut Walker, input: &Row| {
            let before = w.emitted;
            let mut row = input.clone();
            let go = w.run_pattern(0, &mut row);
            if optional && w.emitted == before && !w.halted() {
                return w.deliver(input);
            }
            go || !w.halted()
        };
        let (_, more) = self.fan_out(cx, &block, 8, &Vec::new(), &work)?;
        if !more || cx.produced.load(Ordering::Relaxed) >= MAX_PRODUCED_ROWS {
            self.done = true;
            return Ok(false);
        }
        Ok(true)
    }
}

impl Stage for MatchStage<'_> {
    fn take_rows(&mut self) -> Vec<Row> {
        self.next.take_rows()
    }
    fn push(&mut self, cx: &Ctx, rows: Vec<Row>) -> Result<bool, QueryError> {
        if self.done {
            return Ok(false);
        }
        for r in rows {
            self.buf.push(r);
            if self.buf.len() >= BLOCK && !self.process(cx)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn finish(&mut self, cx: &Ctx) -> Result<(), QueryError> {
        self.process(cx)?;
        self.next.finish(cx)
    }
    fn demand(&self) -> Option<usize> {
        None
    }
}

struct UnwindStage<'p> {
    expr: &'p CExpr,
    width: usize,
    next: Box<dyn Stage + 'p>,
    done: bool,
}

impl Stage for UnwindStage<'_> {
    fn take_rows(&mut self) -> Vec<Row> {
        self.next.take_rows()
    }
    fn push(&mut self, cx: &Ctx, rows: Vec<Row>) -> Result<bool, QueryError> {
        if self.done {
            return Ok(false);
        }
        let mut out = Vec::new();
        for r in rows {
            if cx.hit() {
                return Ok(false);
            }
            let v = self.expr.eval(&mut Env::new(cx, &r));
            let items = match v {
                Val::Null => Vec::new(),
                Val::List(xs) => xs,
                Val::Edges(es) => es.iter().map(|e| Val::Edge(*e)).collect(),
                other => vec![other],
            };
            for x in items.into_iter().take(MAX_UNWIND) {
                let mut nr = r.clone();
                nr.resize(self.width, Val::Null);
                nr[self.width - 1] = x;
                out.push(nr);
            }
            if out.len() >= BLOCK && !self.next.push(cx, std::mem::take(&mut out))? {
                self.done = true;
                return Ok(false);
            }
        }
        let more = self.next.push(cx, out)?;
        self.done = !more;
        Ok(more)
    }
    fn finish(&mut self, cx: &Ctx) -> Result<(), QueryError> {
        self.next.finish(cx)
    }
    fn demand(&self) -> Option<usize> {
        None
    }
}

/// Compiled WITH / RETURN.
pub(crate) struct ProjPlan {
    pub names: Vec<String>,
    /// Plain-variable items (graph output candidates).
    pub plain_var: Vec<bool>,
    /// Item expressions: input scope; aggregate items reference `aggs`.
    items: Vec<CExpr>,
    is_key: Vec<bool>,
    aggs: Vec<AggSpec>,
    aggregate: bool,
    distinct: bool,
    /// Sort keys over `output ++ input` (or `output ++ representative row`).
    order: Vec<(CExpr, bool)>,
    /// Final RETURN of an aggregation without ORDER BY: sort by the first
    /// aggregate descending (CHQL convenience).
    implicit_order: Option<usize>,
    skip: usize,
    limit: Option<usize>,
    filter: Option<CExpr>,
    is_return: bool,
}

fn norm_text(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_lowercase()
}

pub(crate) fn plan_projection(g: &Graph, p: &Projection, scope: &mut Vec<String>, is_return: bool, limit_override: Option<usize>) -> Result<ProjPlan, QueryError> {
    let mut items_ast: Vec<(Expr, String, bool)> = Vec::new();
    if p.star {
        for s in scope.iter() {
            if !s.starts_with(' ') {
                items_ast.push((Expr::Var(s.clone(), 0), s.clone(), true));
            }
        }
        if items_ast.is_empty() && p.items.is_empty() {
            return Err(QueryError::new("RETURN * / WITH * with no variables in scope"));
        }
    }
    for it in &p.items {
        let name = match (&it.alias, &it.expr) {
            (Some(a), _) => a.clone(),
            (None, Expr::Var(v, _)) => v.clone(),
            (None, _) => it.text.clone(),
        };
        items_ast.push((it.expr.clone(), name, matches!(it.expr, Expr::Var(..))));
    }
    {
        let mut seen = AHashSet::new();
        for (_, n, _) in &items_ast {
            if !seen.insert(n.clone()) {
                return Err(QueryError::new(format!("duplicate column name '{n}' (use AS to rename)")));
            }
        }
    }
    let aggregate = items_ast.iter().any(|(e, _, _)| e.has_aggregate());
    let mut aggs: Vec<AggSpec> = Vec::new();
    let mut items = Vec::new();
    let mut is_key = Vec::new();
    for (e, _, _) in &items_ast {
        let has = e.has_aggregate();
        let mut c = Compiler::new(g);
        if has {
            c.aggs = Some(&mut aggs);
        }
        items.push(c.compile(e, scope)?);
        is_key.push(!has);
    }
    let names: Vec<String> = items_ast.iter().map(|(_, n, _)| n.clone()).collect();
    // ORDER BY: output columns first (by alias or identical text), then input variables.
    let mut order = Vec::new();
    let mut full: Vec<String> = names.clone();
    full.extend(scope.iter().cloned());
    for s in &p.order {
        let t = norm_text(&s.text);
        let hit = p.items.iter().enumerate().find_map(|(i, it)| {
            let idx = i + items_ast.len() - p.items.len();
            (norm_text(&it.text) == t || it.alias.as_deref().is_some_and(|a| norm_text(a) == t)).then_some(idx)
        });
        let c = match hit {
            Some(i) => CExpr::Slot(i),
            None => {
                let mut c = Compiler::new(g);
                if aggregate {
                    c.aggs = Some(&mut aggs);
                }
                c.compile(&s.expr, &mut full)?
            }
        };
        order.push((c, s.desc));
    }
    let filter = match &p.filter {
        Some(f) => {
            if f.has_aggregate() {
                return Err(QueryError::new("aggregate functions are not allowed in WHERE; aggregate in WITH first"));
            }
            let mut out_scope = names.clone();
            Some(Compiler::new(g).compile(f, &mut out_scope)?)
        }
        None => None,
    };
    let implicit_order = if is_return && aggregate && p.order.is_empty() { is_key.iter().position(|k| !k) } else { None };
    let plain_var = items_ast.iter().map(|(_, _, v)| *v).collect();
    *scope = names.clone();
    Ok(ProjPlan {
        names,
        plain_var,
        items,
        is_key,
        aggs,
        aggregate,
        distinct: p.distinct,
        order,
        implicit_order,
        skip: p.skip.unwrap_or(0),
        limit: if is_return { limit_override.or(p.limit) } else { p.limit },
        filter,
        is_return,
    })
}

struct Group {
    key_vals: Vec<Val>,
    rep: Row,
    accs: Vec<crate::expr::Acc>,
}

/// Per-group aggregation state; built per thread and merged.
#[derive(Default)]
pub(crate) struct AggTable {
    groups: AHashMap<Key, usize>,
    gstate: Vec<Group>,
}

impl AggTable {
    fn group(&mut self, p: &ProjPlan, key_vals: Vec<Val>, rep: &[Val]) -> Result<usize, QueryError> {
        if key_vals.is_empty() {
            if self.gstate.is_empty() {
                self.gstate.push(Group { key_vals, rep: rep.to_vec(), accs: p.aggs.iter().map(|a| a.init()).collect() });
            }
            return Ok(0);
        }
        let key = Key(key_vals);
        if let Some(&i) = self.groups.get(&key) {
            return Ok(i);
        }
        if self.gstate.len() >= MAX_GROUPS {
            return Err(QueryError::new(format!("aggregation produced more than {MAX_GROUPS} groups")));
        }
        self.gstate.push(Group { key_vals: key.0.clone(), rep: rep.to_vec(), accs: p.aggs.iter().map(|a| a.init()).collect() });
        self.groups.insert(key, self.gstate.len() - 1);
        Ok(self.gstate.len() - 1)
    }

    fn add(&mut self, cx: &Ctx, p: &ProjPlan, row: &[Val]) -> Result<(), QueryError> {
        let mut env = Env::new(cx, row);
        let key_vals: Vec<Val> = p.items.iter().zip(&p.is_key).filter(|(_, k)| **k).map(|(e, _)| e.eval(&mut env)).collect();
        let gi = self.group(p, key_vals, row)?;
        let grp = &mut self.gstate[gi];
        for (spec, acc) in p.aggs.iter().zip(grp.accs.iter_mut()) {
            if !spec.update(acc, &mut env) {
                cx.truncated.store(true, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    fn merge(&mut self, cx: &Ctx, p: &ProjPlan, other: AggTable) -> Result<(), QueryError> {
        if self.gstate.is_empty() {
            *self = other;
            return Ok(());
        }
        for g in other.gstate {
            let gi = self.group(p, g.key_vals, &g.rep)?;
            let mine = &mut self.gstate[gi];
            for ((spec, acc), theirs) in p.aggs.iter().zip(mine.accs.iter_mut()).zip(g.accs) {
                if !spec.merge(acc, theirs) {
                    cx.truncated.store(true, Ordering::Relaxed);
                }
            }
        }
        Ok(())
    }
}

struct ProjStage<'p> {
    p: &'p ProjPlan,
    next: Box<dyn Stage + 'p>,
    /// Rows passed the filter (before skip).
    seen: usize,
    sent: usize,
    distinct: AHashSet<Key>,
    /// (sort keys, output row) for ORDER BY.
    buf: Vec<(Vec<Val>, Row)>,
    table: AggTable,
    done: bool,
}

impl<'p> ProjStage<'p> {
    fn new(p: &'p ProjPlan, next: Box<dyn Stage + 'p>) -> Self {
        ProjStage { p, next, seen: 0, sent: 0, distinct: AHashSet::new(), buf: Vec::new(), table: AggTable::default(), done: false }
    }

    fn sorting(&self) -> bool {
        !self.p.order.is_empty() || self.p.implicit_order.is_some()
    }

    /// Bounded top-k size for ORDER BY … LIMIT (+1 to detect truncation).
    fn keep(&self) -> Option<usize> {
        self.p.limit.map(|l| self.p.skip + l + 1)
    }

    fn sort_keys(&self, cx: &Ctx, out: &[Val], input: &[Val], aggs: &[Val]) -> Vec<Val> {
        if let Some(i) = self.p.implicit_order {
            return vec![out[i].clone()];
        }
        let mut full = Vec::with_capacity(out.len() + input.len());
        full.extend_from_slice(out);
        full.extend_from_slice(input);
        let mut env = Env::new(cx, &full);
        env.aggs = aggs;
        self.p.order.iter().map(|(e, _)| e.eval(&mut env)).collect()
    }

    fn cmp_keys(&self, a: &[Val], b: &[Val]) -> std::cmp::Ordering {
        if self.p.implicit_order.is_some() {
            return sort_cmp(&b[0], &a[0]);
        }
        for ((x, y), (_, desc)) in a.iter().zip(b).zip(&self.p.order) {
            let o = sort_cmp(x, y);
            let o = if *desc { o.reverse() } else { o };
            if o != std::cmp::Ordering::Equal {
                return o;
            }
        }
        std::cmp::Ordering::Equal
    }

    fn compact(&mut self) {
        let mut buf = std::mem::take(&mut self.buf);
        buf.sort_by(|a, b| self.cmp_keys(&a.0, &b.0));
        if let Some(k) = self.keep() {
            buf.truncate(k);
        }
        self.buf = buf;
    }

    /// An output row that passed the filter.
    fn accept(&mut self, cx: &Ctx, out: Row, input: &[Val], aggs: &[Val]) -> Result<bool, QueryError> {
        if self.p.distinct {
            if self.distinct.len() >= MAX_BUFFER_ROWS {
                return Err(QueryError::new(format!("DISTINCT over more than {MAX_BUFFER_ROWS} rows; add filters or LIMIT")));
            }
            if !self.distinct.insert(Key(out.clone())) {
                return Ok(true);
            }
        }
        if self.sorting() {
            let keys = self.sort_keys(cx, &out, input, aggs);
            self.buf.push((keys, out));
            let lim = match self.keep() {
                Some(k) => (2 * k).max(4096),
                None => MAX_BUFFER_ROWS,
            };
            if self.buf.len() >= lim {
                if self.keep().is_none() {
                    return Err(QueryError::new(format!("ORDER BY over more than {MAX_BUFFER_ROWS} rows; add LIMIT")));
                }
                self.compact();
            }
            return Ok(true);
        }
        self.emit(cx, vec![out])
    }

    /// Apply SKIP / LIMIT and forward.
    fn emit(&mut self, cx: &Ctx, rows: Vec<Row>) -> Result<bool, QueryError> {
        let mut fwd = Vec::with_capacity(rows.len());
        for r in rows {
            self.seen += 1;
            if self.seen <= self.p.skip {
                continue;
            }
            if self.p.limit.is_some_and(|l| self.sent >= l) {
                if self.p.is_return {
                    cx.truncated.store(true, Ordering::Relaxed);
                }
                self.done = true;
                break;
            }
            self.sent += 1;
            fwd.push(r);
        }
        let more = self.next.push(cx, fwd)?;
        if !more {
            self.done = true;
        }
        Ok(!self.done)
    }

    fn eval_items(&self, cx: &Ctx, row: &[Val]) -> Row {
        let mut env = Env::new(cx, row);
        self.p.items.iter().map(|e| e.eval(&mut env)).collect()
    }

    fn passes(&self, cx: &Ctx, out: &[Val]) -> bool {
        match &self.p.filter {
            Some(f) => f.test(&mut Env::new(cx, out)),
            None => true,
        }
    }
}

impl Stage for ProjStage<'_> {
    fn take_rows(&mut self) -> Vec<Row> {
        self.next.take_rows()
    }
    fn merge_agg(&mut self, cx: &Ctx, t: AggTable) -> Result<(), QueryError> {
        self.table.merge(cx, self.p, t)
    }
    fn push(&mut self, cx: &Ctx, rows: Vec<Row>) -> Result<bool, QueryError> {
        if self.done {
            return Ok(false);
        }
        if self.p.aggregate {
            for r in rows {
                if cx.hit() {
                    return Ok(false);
                }
                self.table.add(cx, self.p, &r)?;
            }
            return Ok(true);
        }
        let streaming = !self.sorting();
        for r in rows {
            if cx.hit() {
                return Ok(false);
            }
            let out = self.eval_items(cx, &r);
            if !self.passes(cx, &out) {
                continue;
            }
            if !self.accept(cx, out, &r, &[])? {
                return Ok(false);
            }
            if streaming && self.done {
                return Ok(false);
            }
        }
        Ok(!self.done)
    }

    fn finish(&mut self, cx: &Ctx) -> Result<(), QueryError> {
        if self.p.aggregate && !self.done {
            let groups = std::mem::take(&mut self.table).gstate;
            // Global aggregation over zero rows still yields one row.
            let groups = if groups.is_empty() && self.p.is_key.iter().all(|k| !k) {
                vec![Group { key_vals: Vec::new(), rep: Vec::new(), accs: self.p.aggs.iter().map(|a| a.init()).collect() }]
            } else {
                groups
            };
            for grp in groups {
                if cx.hit() {
                    break;
                }
                let aggv: Vec<Val> = self.p.aggs.iter().zip(grp.accs).map(|(s, a)| s.finish(a)).collect();
                let mut keys = grp.key_vals.into_iter();
                let rep = if grp.rep.is_empty() { vec![Val::Null; 0] } else { grp.rep };
                let out: Row = {
                    let mut env = Env::new(cx, &rep);
                    env.aggs = &aggv;
                    self.p
                        .items
                        .iter()
                        .zip(&self.p.is_key)
                        .map(|(e, k)| if *k { keys.next().unwrap_or_default() } else { e.eval(&mut env) })
                        .collect()
                };
                if !self.passes(cx, &out) {
                    continue;
                }
                if !self.accept(cx, out, &rep, &aggv)? {
                    break;
                }
                if self.done {
                    break;
                }
            }
        }
        if self.sorting() && !self.done {
            self.compact();
            let buf = std::mem::take(&mut self.buf);
            let rows: Vec<Row> = buf.into_iter().map(|(_, r)| r).collect();
            self.emit(cx, rows)?;
        }
        self.next.finish(cx)
    }

    fn demand(&self) -> Option<usize> {
        if self.p.aggregate || self.sorting() || self.p.distinct || self.p.filter.is_some() {
            return None;
        }
        self.p.limit.map(|l| (self.p.skip + l + 1).saturating_sub(self.seen))
    }
}

// -------------------------------------------------------------- compile

enum StagePlan {
    Match(MatchPlan),
    Unwind(CExpr, usize),
    Project(ProjPlan),
}

fn plan_query(g: &Graph, q: &SingleQuery, default_limit: usize, cap: usize) -> Result<Vec<StagePlan>, QueryError> {
    let mut scope: Vec<String> = Vec::new();
    let mut out = Vec::new();
    let n = q.clauses.len();
    for (i, c) in q.clauses.iter().enumerate() {
        match c {
            Clause::Match { optional, patterns, filter } => {
                out.push(StagePlan::Match(plan_match(g, patterns, filter.as_ref(), *optional, &mut scope)?));
            }
            Clause::Unwind { expr, var } => {
                let e = Compiler::new(g).compile(expr, &mut scope)?;
                if scope.contains(var) {
                    return Err(QueryError::new(format!("variable '{var}' is already bound")));
                }
                scope.push(var.clone());
                out.push(StagePlan::Unwind(e, scope.len()));
            }
            Clause::With(p) => out.push(StagePlan::Project(plan_projection(g, p, &mut scope, false, None)?)),
            Clause::Return(p) => {
                debug_assert_eq!(i, n - 1);
                let lim = p.limit.unwrap_or(default_limit).min(cap);
                out.push(StagePlan::Project(plan_projection(g, p, &mut scope, true, Some(lim))?));
            }
        }
    }
    Ok(out)
}

fn run_single(cx: &Ctx, plans: &[StagePlan]) -> Result<Vec<Row>, QueryError> {
    let mut stage: Box<dyn Stage + '_> = Box::new(Collector { rows: Vec::new() });
    for (i, p) in plans.iter().enumerate().rev() {
        let agg_next = match plans.get(i + 1) {
            Some(StagePlan::Project(pp)) if pp.aggregate => Some(pp),
            _ => None,
        };
        stage = match p {
            StagePlan::Match(m) => Box::new(MatchStage { plan: m, agg: agg_next, buf: Vec::new(), next: stage, done: false }),
            StagePlan::Unwind(e, w) => Box::new(UnwindStage { expr: e, width: *w, next: stage, done: false }),
            StagePlan::Project(pp) => Box::new(ProjStage::new(pp, stage)),
        };
    }
    for p in plans {
        let mut visit = |e: &CExpr| e.visit_pats(&mut |pp| pp.prepare(cx));
        match p {
            StagePlan::Match(m) => m.prepare(cx),
            StagePlan::Unwind(e, _) => visit(e),
            StagePlan::Project(pp) => {
                pp.items.iter().for_each(&mut visit);
                pp.order.iter().for_each(|(e, _)| visit(e));
                pp.filter.iter().for_each(&mut visit);
                pp.aggs.iter().filter_map(|a| a.arg.as_ref()).for_each(&mut visit);
            }
        }
    }
    stage.push(cx, vec![Vec::new()])?;
    stage.finish(cx)?;
    Ok(stage.take_rows())
}


// ---------------------------------------------------------- execute

pub(crate) fn execute(g: &Graph, q: &Query, default_limit: usize, cap: usize, cancel: &Cancel, opts: &ExecOptions) -> Result<QueryResult, QueryError> {
    let limit = q.limit().unwrap_or(default_limit).min(cap);
    let cx = Ctx {
        g,
        cancel: cancel.clone(),
        truncated: AtomicBool::new(false),
        produced: AtomicUsize::new(0),
        subgraph_cap: limit,
        pushdown: opts.pushdown,
        verify: opts.verify,
    };
    let mut all_rows: Vec<Row> = Vec::new();
    let mut proj: Option<(Vec<String>, Vec<bool>)> = None;
    for part in &q.parts {
        let plans = plan_query(g, part, default_limit, cap)?;
        let Some(StagePlan::Project(last)) = plans.last() else { unreachable!("RETURN is last") };
        let cols = (last.names.clone(), last.plain_var.clone());
        if let Some((names, _)) = &proj {
            if *names != cols.0 {
                return Err(QueryError::new("all UNION parts must return the same columns"));
            }
        } else {
            proj = Some(cols);
        }
        let rows = run_single(&cx, &plans)?;
        all_rows.extend(rows);
        if cx.hit() {
            break;
        }
    }
    if q.parts.len() > 1 {
        if !q.union_all {
            let mut seen = AHashSet::new();
            all_rows.retain(|r| seen.insert(Key(r.clone())));
        }
        if all_rows.len() > cap {
            all_rows.truncate(cap);
            cx.truncated.store(true, Ordering::Relaxed);
        }
    }
    let (names, plain) = proj.unwrap_or_default();
    Ok(build_result(g, &names, &plain, all_rows, cx.truncated.load(Ordering::Relaxed)))
}

// ---------------------------------------------------------- results

fn build_result(g: &Graph, names: &[String], plain: &[bool], rows: Vec<Row>, truncated: bool) -> QueryResult {
    let mut res = QueryResult { truncated, ..Default::default() };
    let mut node_seen: AHashSet<u32> = AHashSet::new();
    let mut edge_seen: AHashSet<E> = AHashSet::new();
    fn add(v: &Val, res: &mut QueryResult, ns: &mut AHashSet<u32>, es: &mut AHashSet<E>) {
        let mut node = |id: u32, res: &mut QueryResult| {
            if ns.insert(id) {
                res.nodes.push(id);
            }
        };
        match v {
            Val::Node(id) => node(*id, res),
            Val::Edge(e) => {
                node(e.0, res);
                node(e.1, res);
                if es.insert(*e) {
                    res.edges.push(*e);
                }
            }
            Val::Edges(list) => {
                for e in list.iter() {
                    node(e.0, res);
                    node(e.1, res);
                    if es.insert(*e) {
                        res.edges.push(*e);
                    }
                }
            }
            Val::Path(p) | Val::Subgraph(p) => {
                for &n in &p.nodes {
                    node(n, res);
                }
                for e in &p.edges {
                    if es.insert(*e) {
                        res.edges.push(*e);
                    }
                }
                if matches!(v, Val::Path(_)) {
                    res.paths.push(p.nodes.clone());
                }
            }
            Val::List(xs) => {
                for x in xs {
                    add(x, res, ns, es);
                }
            }
            _ => {}
        }
    }
    for row in &rows {
        for v in row {
            add(v, &mut res, &mut node_seen, &mut edge_seen);
        }
    }
    let tabular = plain.iter().any(|p| !p) || rows.iter().any(|r| r.iter().any(|v| !v.is_graph()));
    if tabular {
        res.columns = names.to_vec();
        res.rows = rows.iter().map(|r| r.iter().map(|v| v.to_json(g)).collect::<Vec<Value>>()).collect();
    }
    res
}
