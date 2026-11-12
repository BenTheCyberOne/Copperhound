//! CHQL — CopperHound Query Language.
//!
//! A read-only Cypher dialect (multi-clause MATCH / OPTIONAL MATCH / WITH /
//! UNWIND / RETURN / UNION, aggregation, path functions) compiled to native
//! operations on the CSR graph: index lookups, parallel filtered scans,
//! per-hop expansion, bidirectional / multi-source BFS for path functions.
//! See `docs/CHQL.md` for the language reference.

mod ast;
mod exec;
mod expr;
mod library;
mod parse;
mod pushdown;
mod value;

use ch_store::Graph;
use serde::Serialize;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use ast::Query;
pub use library::{Prebuilt, PREBUILT};

#[derive(Debug, Clone, Serialize)]
pub struct QueryError {
    pub message: String,
    /// Byte offset into the query text, for syntax errors.
    pub position: Option<usize>,
    /// `syntax`, `semantic`, `timeout` or `cancelled`.
    pub code: &'static str,
}

impl QueryError {
    pub(crate) fn at(msg: impl Into<String>, pos: usize) -> Self {
        Self { message: msg.into(), position: Some(pos), code: "syntax" }
    }
    pub(crate) fn new(msg: impl Into<String>) -> Self {
        Self { message: msg.into(), position: None, code: "semantic" }
    }
    pub(crate) fn sem_at(msg: impl Into<String>, pos: usize) -> Self {
        Self { message: msg.into(), position: Some(pos), code: "semantic" }
    }
}

/// Cooperative cancellation: an explicit flag plus an optional deadline,
/// polled by every executor loop.
#[derive(Clone, Debug)]
pub struct Cancel {
    flag: Arc<AtomicBool>,
    timed_out: Arc<AtomicBool>,
    deadline: Option<Instant>,
    /// Remaining memory budget for values a query builds itself (lists,
    /// strings); see [`Cancel::charge`].
    budget: Arc<std::sync::atomic::AtomicI64>,
    over_budget: Arc<AtomicBool>,
}

/// Values (list elements, or 32 bytes of string) one query may build with
/// `range`, list comprehensions, concatenation, `split` and `replace`:
/// about 1 GiB. Graph data a query returns is not counted.
pub const QUERY_VALUE_BUDGET: i64 = 32 << 20;

impl Cancel {
    pub fn new(timeout: Option<Duration>) -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            timed_out: Arc::new(AtomicBool::new(false)),
            deadline: timeout.map(|t| Instant::now() + t),
            budget: Arc::new(std::sync::atomic::AtomicI64::new(QUERY_VALUE_BUDGET)),
            over_budget: Arc::new(AtomicBool::new(false)),
        }
    }
    /// Account for `units` built values; false (and the query is stopped)
    /// once the budget is spent.
    #[inline]
    pub(crate) fn charge(&self, units: usize) -> bool {
        let left = self.budget.fetch_sub(units.min(i64::MAX as usize) as i64, Ordering::Relaxed);
        if left < units as i64 {
            self.over_budget.store(true, Ordering::Relaxed);
            self.flag.store(true, Ordering::Relaxed);
            return false;
        }
        true
    }
    pub fn never() -> Self {
        Self::new(None)
    }
    /// Request cancellation (e.g. from another thread / an API call).
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }
    /// True once cancelled or past the deadline. Cheap enough for hot loops:
    /// the clock is read only every 1024 calls per thread.
    #[inline]
    pub fn hit(&self) -> bool {
        if self.flag.load(Ordering::Relaxed) {
            return true;
        }
        thread_local! { static N: std::cell::Cell<u32> = const { std::cell::Cell::new(0) }; }
        let n = N.with(|c| {
            let v = c.get().wrapping_add(1);
            c.set(v);
            v
        });
        if n.is_multiple_of(1024) {
            if let Some(d) = self.deadline {
                if Instant::now() >= d {
                    self.timed_out.store(true, Ordering::Relaxed);
                    self.flag.store(true, Ordering::Relaxed);
                    return true;
                }
            }
        }
        false
    }
    fn error(&self) -> Option<QueryError> {
        if !self.flag.load(Ordering::Relaxed) && !self.deadline.is_some_and(|d| Instant::now() >= d) {
            return None;
        }
        if self.over_budget.load(Ordering::Relaxed) {
            return Some(QueryError {
                message: "query builds too much data (lists or strings over the memory budget)".into(),
                position: None,
                code: "too_large",
            });
        }
        Some(if self.timed_out.load(Ordering::Relaxed) || self.deadline.is_some_and(|d| Instant::now() >= d) {
            QueryError { message: "query timed out".into(), position: None, code: "timeout" }
        } else {
            QueryError { message: "query cancelled".into(), position: None, code: "cancelled" }
        })
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.position {
            Some(p) => write!(f, "{} (at offset {p})", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for QueryError {}

#[derive(Debug, Clone, Default, Serialize)]
pub struct QueryResult {
    pub nodes: Vec<u32>,
    /// `(src, dst, kind)`
    pub edges: Vec<(u32, u32, u16)>,
    pub paths: Vec<Vec<u32>>,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub truncated: bool,
}

/// Hard ceiling on result rows regardless of the requested limit.
pub const MAX_LIMIT: usize = 100_000;

/// Executor switches. [`ExecOptions::default`] reads the environment:
/// `COPPERHOUND_CHQL_PUSHDOWN=0` disables predicate pushdown (kill switch);
/// `COPPERHOUND_VERIFY_PUSHDOWN=1` evaluates every pushed-down predicate both
/// ways and panics on any difference (debugging / test runs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecOptions {
    /// Answer single-variable node predicates from the property columns
    /// (`ch_store::Graph::filter`) once they are built.
    pub pushdown: bool,
    /// Cross-check every pushed predicate against CHQL's own evaluation.
    pub verify: bool,
}

impl Default for ExecOptions {
    fn default() -> Self {
        static ENV: std::sync::OnceLock<ExecOptions> = std::sync::OnceLock::new();
        *ENV.get_or_init(|| {
            let flag = |k: &str| std::env::var(k).ok().map(|v| !matches!(v.trim(), "" | "0" | "false" | "off" | "no"));
            ExecOptions { pushdown: flag("COPPERHOUND_CHQL_PUSHDOWN").unwrap_or(true), verify: flag("COPPERHOUND_VERIFY_PUSHDOWN").unwrap_or(false) }
        })
    }
}

/// Parse a query without running it.
pub fn parse(src: &str) -> Result<Query, QueryError> {
    parse::parse(src)
}

/// Syntax check for stored queries: like [`parse`] but labels that are not
/// built-in kinds are accepted (they may be custom kinds of a later graph).
pub fn parse_syntax(src: &str) -> Result<Query, QueryError> {
    parse::parse_syntax(src)
}

/// Parse and run a query. `default_limit` applies when the query has no
/// LIMIT; both are capped at [`MAX_LIMIT`].
pub fn run(g: &Graph, src: &str, default_limit: usize) -> Result<QueryResult, QueryError> {
    run_with(g, src, default_limit, &Cancel::never())
}

/// [`run`] with cooperative cancellation / timeout.
pub fn run_with(g: &Graph, src: &str, default_limit: usize, cancel: &Cancel) -> Result<QueryResult, QueryError> {
    run_capped(g, src, default_limit, MAX_LIMIT, cancel)
}

/// For internal analysis (findings, zones): like [`run_with`] but the caller
/// chooses the hard row ceiling instead of [`MAX_LIMIT`].
pub fn run_capped(g: &Graph, src: &str, default_limit: usize, cap: usize, cancel: &Cancel) -> Result<QueryResult, QueryError> {
    run_opts(g, src, default_limit, cap, cancel, &ExecOptions::default())
}

/// [`run_capped`] with explicit executor options.
pub fn run_opts(g: &Graph, src: &str, default_limit: usize, cap: usize, cancel: &Cancel, opts: &ExecOptions) -> Result<QueryResult, QueryError> {
    let q = parse::parse_with_kinds(src, g.custom_node_kinds())?;
    let res = exec::execute(g, &q, default_limit, cap, cancel, opts);
    match cancel.error() {
        Some(e) => Err(e),
        None => res,
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use ch_model::{ek, flags};
    use ch_store::{Edge, GraphParts};

    /// 0 alice(User) -MemberOf-> 1 helpdesk(Group) -AdminTo-> 2 ws1(Computer)
    /// -HasSession-> 3 bob(User, admincount) -MemberOf-> 4 DOMAIN ADMINS(Group, T0)
    /// 5 carol(User) -MemberOf-> 1 ;  0 -GetChanges-> 4 (non-traversable)
    fn graph() -> Graph {
        let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
        let names = ["ALICE@CORP", "HELPDESK@CORP", "WS1.CORP", "BOB@CORP", "DOMAIN ADMINS@CORP", "CAROL@CORP"];
        let (g, _) = Graph::build(GraphParts {
            kinds: vec![1, 2, 3, 1, 2, 1],
            flags: vec![flags::ENABLED, 0, flags::ENABLED, flags::ADMINCOUNT, flags::TIER0, 0],
            names: names.iter().map(|n| Some(n.to_string())).collect(),
            oids: (0..6).map(|i| format!("S-1-5-21-1-{}", if i == 4 { 512 } else { 1000 + i })).collect(),
            props: vec![
                Some(r#"{"name":"ALICE@CORP","title":"Engineer","pwdlastset":100}"#.into()),
                None,
                Some(r#"{"name":"WS1.CORP","operatingsystem":"Windows 11"}"#.into()),
                Some(r#"{"name":"BOB@CORP","title":"Admin","pwdlastset":50}"#.into()),
                None,
                Some(r#"{"name":"CAROL@CORP","title":"engineer"}"#.into()),
            ],
            edge_chunks: vec![vec![
                Edge::new(0, 1, ek::MEMBER_OF),
                Edge::new(1, 2, ek::ADMIN_TO),
                Edge::new(2, 3, ek::HAS_SESSION),
                Edge::new(3, 4, ek::MEMBER_OF),
                Edge::new(5, 1, ek::MEMBER_OF),
                Edge::new(0, 4, ek::GET_CHANGES),
            ]],
            edge_kinds,
            traversable,
            node_kinds: Vec::new(),
        })
        .unwrap();
        g
    }

    fn names(g: &Graph, ids: &[u32]) -> Vec<String> {
        let mut v: Vec<String> = ids.iter().map(|&i| g.name(i).to_string()).collect();
        v.sort();
        v
    }

    #[test]
    fn label_and_property_filters() {
        let g = graph();
        let r = run(&g, "MATCH (u:User) WHERE u.title = 'ENGINEER' RETURN u", 100).unwrap();
        assert_eq!(names(&g, &r.nodes), ["ALICE@CORP", "CAROL@CORP"]);
        let r = run(&g, "MATCH (u:User {admincount:true}) RETURN u.name, u.pwdlastset", 100).unwrap();
        assert_eq!(r.columns, ["u.name", "u.pwdlastset"]);
        assert_eq!(r.rows, vec![vec![serde_json::json!("BOB@CORP"), serde_json::json!(50)]]);
        let r = run(&g, "MATCH (u:User) WHERE u.pwdlastset < 75 OR u.name STARTS WITH 'car' RETURN u", 100).unwrap();
        assert_eq!(names(&g, &r.nodes), ["BOB@CORP", "CAROL@CORP"]);
        let r = run(&g, "MATCH (c:Computer) WHERE c.operatingsystem CONTAINS '11' RETURN c", 100).unwrap();
        assert_eq!(names(&g, &r.nodes), ["WS1.CORP"]);
    }

    #[test]
    fn hops_and_reverse_planning() {
        let g = graph();
        // Last node is indexed → planner starts from it and walks backwards.
        let r = run(&g, "MATCH (u:User)-[:MemberOf]->(g:Group {name:'HELPDESK@CORP'}) RETURN u", 100).unwrap();
        assert_eq!(names(&g, &r.nodes), ["ALICE@CORP", "CAROL@CORP"]);
        let r = run(&g, "MATCH (g:Group)-[r:AdminTo]->(c) RETURN g, r, c", 100).unwrap();
        assert_eq!(r.edges, vec![(1, 2, ek::ADMIN_TO)]);
        let r = run(&g, "MATCH (c:Computer)<-[:AdminTo]-(g) RETURN g", 100).unwrap();
        assert_eq!(names(&g, &r.nodes), ["HELPDESK@CORP"]);
        let r = run(&g, "MATCH (u:User)-[:MemberOf]->(g)-[:AdminTo]->(c) RETURN u.name, c.name", 100).unwrap();
        assert_eq!(r.rows.len(), 2);
    }

    #[test]
    fn variable_length_and_count() {
        let g = graph();
        let r = run(&g, "MATCH (u:User)-[*1..]->(t {tier0:true}) RETURN u", 100).unwrap();
        assert_eq!(names(&g, &r.nodes), ["ALICE@CORP", "BOB@CORP", "CAROL@CORP"]);
        let r = run(&g, "MATCH (u:User)-[*1..2]->(t {tier0:true}) RETURN u", 100).unwrap();
        assert_eq!(names(&g, &r.nodes), ["BOB@CORP"]);
        let r = run(&g, "MATCH (g:Group)-[:AdminTo]->(c:Computer) RETURN g.name, count(c)", 100).unwrap();
        assert_eq!(r.rows, vec![vec![serde_json::json!("HELPDESK@CORP"), serde_json::json!(1)]]);
        let r = run(&g, "MATCH (n:Domain) RETURN count(n)", 100).unwrap();
        assert_eq!(r.rows, vec![vec![serde_json::json!(0)]]);
    }

    #[test]
    fn path_functions() {
        let g = graph();
        let r = run(&g, "MATCH p = shortestPath((u:User {name:'ALICE@CORP'})-[*1..]->(t {tier0:true})) RETURN p", 100).unwrap();
        assert_eq!(r.paths, vec![vec![0, 1, 2, 3, 4]]);
        assert_eq!(r.edges.len(), 4);
        // Explicit non-traversable kind is allowed when named.
        let r = run(&g, "MATCH p = shortestPath((u {name:'ALICE@CORP'})-[:GetChanges*1..]->(t {tier0:true})) RETURN p", 100).unwrap();
        assert_eq!(r.paths, vec![vec![0, 4]]);
        let r = run(&g, "MATCH p = allShortestPaths((u:User)-[*1..]->(t {tier0:true})) RETURN p", 100).unwrap();
        assert_eq!(r.nodes.len(), 6);
        assert_eq!(r.edges.len(), 5);
        // Path through a fixed-length chain.
        let r = run(&g, "MATCH p = (u {name:'CAROL@CORP'})-[:MemberOf]->(g)-[:AdminTo]->(c) RETURN p", 100).unwrap();
        assert_eq!(r.paths, vec![vec![5, 1, 2]]);
    }

    #[test]
    fn errors() {
        let g = graph();
        assert!(run(&g, "MATCH (n) RETURN m", 10).unwrap_err().message.contains("unknown variable"));
        assert!(run(&g, "MATCH (a)-[:NotAKind]->(b) RETURN a", 10).unwrap_err().message.contains("unknown relationship"));
        assert!(run(&g, "MATCH p = shortestPath((a)-[*]->(b)-[*]->(c)) RETURN p", 10).is_err());
    }

    #[test]
    fn limit_truncates() {
        let g = graph();
        let r = run(&g, "MATCH (n) RETURN n LIMIT 2", 100).unwrap();
        assert_eq!(r.nodes.len(), 2);
        assert!(r.truncated);
    }

    #[test]
    fn prebuilt_queries_parse() {
        for p in PREBUILT {
            parse(p.query).unwrap_or_else(|e| panic!("{}: {e}", p.name));
        }
    }

    use serde_json::{json, Value};

    fn rows(g: &Graph, q: &str) -> Vec<Vec<Value>> {
        run(g, q, 100).unwrap_or_else(|e| panic!("{q}: {e}")).rows
    }

    fn col(g: &Graph, q: &str) -> Vec<Value> {
        rows(g, q).into_iter().map(|mut r| r.remove(0)).collect()
    }

    #[test]
    fn joins_and_multiple_matches() {
        let g = graph();
        let r = rows(&g, "MATCH (u:User)-[:MemberOf]->(g), (g)-[:AdminTo]->(c) RETURN u.name, c.name ORDER BY u.name");
        assert_eq!(r, vec![vec![json!("ALICE@CORP"), json!("WS1.CORP")], vec![json!("CAROL@CORP"), json!("WS1.CORP")]]);
        let r = rows(&g, "MATCH (u:User) MATCH (u)-[:MemberOf]->(g:Group) RETURN u.name, g.name ORDER BY u.name");
        assert_eq!(r.len(), 3);
        assert_eq!(r[1], vec![json!("BOB@CORP"), json!("DOMAIN ADMINS@CORP")]);
        // Cartesian product of disconnected patterns.
        assert_eq!(rows(&g, "MATCH (u:User), (c:Computer) RETURN count(*)"), vec![vec![json!(3)]]);
        // Cycle / repeated variable inside one pattern.
        assert_eq!(rows(&g, "MATCH (a)-[:MemberOf]->(g)<-[:MemberOf]-(a) RETURN count(*)"), vec![vec![json!(0)]]);
        // Relationship uniqueness: a and b are never the same membership edge.
        let r = rows(&g, "MATCH (a)-[:MemberOf]->(g)<-[:MemberOf]-(b) RETURN a.name, b.name ORDER BY a.name");
        assert_eq!(r, vec![vec![json!("ALICE@CORP"), json!("CAROL@CORP")], vec![json!("CAROL@CORP"), json!("ALICE@CORP")]]);
    }

    #[test]
    fn optional_match() {
        let g = graph();
        let r = rows(&g, "MATCH (u:User) OPTIONAL MATCH (u)-[:AdminTo]->(c) RETURN u.name, c.name ORDER BY u.name");
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|x| x[1].is_null()));
        let r = rows(&g, "MATCH (u:User) OPTIONAL MATCH (u)-[:MemberOf]->(g {name:'HELPDESK@CORP'}) RETURN u.name, count(g) AS n ORDER BY n DESC, u.name");
        assert_eq!(r[2], vec![json!("BOB@CORP"), json!(0)]);
        // OPTIONAL MATCH as the first clause yields one null row when nothing matches.
        assert_eq!(rows(&g, "OPTIONAL MATCH (d:Domain) RETURN d.name"), vec![vec![Value::Null]]);
    }

    #[test]
    fn with_order_skip_limit_distinct() {
        let g = graph();
        assert_eq!(rows(&g, "MATCH (u:User)-[:MemberOf]->(g:Group) WITH g, count(u) AS n WHERE n > 1 RETURN g.name, n"), vec![vec![json!("HELPDESK@CORP"), json!(2)]]);
        assert_eq!(col(&g, "MATCH (u:User) RETURN u.name AS name ORDER BY name DESC SKIP 1 LIMIT 1"), vec![json!("BOB@CORP")]);
        let r = run(&g, "MATCH (u:User) RETURN u.name ORDER BY u.name LIMIT 2", 100).unwrap();
        assert!(r.truncated);
        assert_eq!(col(&g, "MATCH (u:User)-[:MemberOf]->(g) RETURN DISTINCT g.name ORDER BY g.name"), vec![json!("DOMAIN ADMINS@CORP"), json!("HELPDESK@CORP")]);
        assert_eq!(col(&g, "MATCH (u:User) WITH u WHERE u.pwdlastset > 60 WITH u.name AS n RETURN n"), vec![json!("ALICE@CORP")]);
        // ORDER BY an aggregate that is not aliased, and by an input variable.
        let r = rows(&g, "MATCH (u:User)-[:MemberOf]->(g) RETURN g.name, count(u) ORDER BY count(u) ASC");
        assert_eq!(r[0], vec![json!("DOMAIN ADMINS@CORP"), json!(1)]);
        // Nulls sort last ascending, first descending (as in Cypher).
        assert_eq!(col(&g, "MATCH (u:User) RETURN u.name ORDER BY u.pwdlastset DESC, u.name LIMIT 2"), vec![json!("CAROL@CORP"), json!("ALICE@CORP")]);
        // Implicit order for aggregates: first aggregate descending.
        assert_eq!(rows(&g, "MATCH (u:User)-[:MemberOf]->(g) RETURN g.name, count(u)")[0], vec![json!("HELPDESK@CORP"), json!(2)]);
        // Graph output survives WITH.
        let r = run(&g, "MATCH (u:User) WITH u ORDER BY u.name LIMIT 1 RETURN u", 100).unwrap();
        assert_eq!(names(&g, &r.nodes), ["ALICE@CORP"]);
        assert!(r.rows.is_empty());
    }

    #[test]
    fn aggregates() {
        let g = graph();
        let r = rows(&g, "MATCH (u:User) RETURN count(*), count(DISTINCT u.title), min(u.pwdlastset), max(u.pwdlastset), sum(u.pwdlastset), avg(u.pwdlastset), size(collect(u.name))");
        assert_eq!(r, vec![vec![json!(3), json!(3), json!(50), json!(100), json!(150), json!(75), json!(3)]]);
        let r = rows(&g, "MATCH (u:User)-[:MemberOf]->(g) RETURN g.name AS grp, collect(u.name) AS members ORDER BY grp");
        assert_eq!(r[1][1].as_array().unwrap().len(), 2);
        // collect(node) feeds the graph output.
        let r = run(&g, "MATCH (u:User)-[:MemberOf]->(g {name:'HELPDESK@CORP'}) RETURN g.name, collect(u) AS us", 100).unwrap();
        assert_eq!(names(&g, &r.nodes), ["ALICE@CORP", "CAROL@CORP"]);
        assert_eq!(rows(&g, "MATCH (u:User) RETURN count(u) * 100 / 4 AS pct"), vec![vec![json!(75)]]);
        assert!(run(&g, "MATCH (u) WHERE count(u) > 1 RETURN u", 10).is_err());
        assert!(run(&g, "MATCH (u) RETURN count(count(u))", 10).unwrap_err().message.contains("nested"));
    }

    #[test]
    fn undirected_and_variable_length() {
        let g = graph();
        assert_eq!(col(&g, "MATCH (a {name:'HELPDESK@CORP'})-[:MemberOf|AdminTo]-(b) RETURN b.name ORDER BY b.name"), vec![json!("ALICE@CORP"), json!("CAROL@CORP"), json!("WS1.CORP")]);
        assert_eq!(col(&g, "MATCH (t {name:'DOMAIN ADMINS@CORP'})<-[*1..2]-(x) RETURN x.name ORDER BY x.name"), vec![json!("BOB@CORP"), json!("WS1.CORP")]);
        assert_eq!(col(&g, "MATCH (a {name:'ALICE@CORP'})-[*1..2]-(x) RETURN count(x)"), vec![json!(3)]);
        let r = rows(&g, "MATCH (u {name:'ALICE@CORP'})-[r:MemberOf|AdminTo*1..3]->(c:Computer) RETURN size(r), [x IN r | type(x)]");
        assert_eq!(r, vec![vec![json!(2), json!(["MemberOf", "AdminTo"])]]);
        // Bound end node: expansion stops at the target.
        let r = rows(&g, "MATCH (u:User), (t:Group {name:'DOMAIN ADMINS@CORP'}) WHERE (u)-[:MemberOf*1..]->(t) RETURN u.name");
        assert_eq!(r, vec![vec![json!("BOB@CORP")]]);
    }

    #[test]
    fn shortest_paths_with_bound_endpoints() {
        let g = graph();
        assert_eq!(col(&g, "MATCH (u:User {name:'CAROL@CORP'}), (t:Group {name:'DOMAIN ADMINS@CORP'}) MATCH p = shortestPath((u)-[*1..]->(t)) RETURN length(p)"), vec![json!(4)]);
        assert_eq!(col(&g, "MATCH (u:User), (t {tier0:true}) MATCH p = shortestPath((u)-[*1..]->(t)) RETURN u.name ORDER BY u.name"), vec![json!("ALICE@CORP"), json!("BOB@CORP"), json!("CAROL@CORP")]);
        assert_eq!(col(&g, "MATCH p=shortestPath((a {name:'ALICE@CORP'})-[*1..]-(b {name:'CAROL@CORP'})) RETURN length(p)"), vec![json!(2)]);
        assert!(rows(&g, "MATCH p=shortestPath((a {name:'ALICE@CORP'})-[*1..2]->(t {tier0:true})) RETURN p").is_empty());
        assert_eq!(col(&g, "MATCH p=shortestPath((t {tier0:true})<-[*1..]-(a {name:'ALICE@CORP'})) RETURN [n IN nodes(p) | n.name]"), vec![json!(["DOMAIN ADMINS@CORP", "BOB@CORP", "WS1.CORP", "HELPDESK@CORP", "ALICE@CORP"])]);
        let r = run(&g, "MATCH p=shortestPath((a {name:'ALICE@CORP'})-[*1..]->(t {tier0:true})) WHERE none(n IN nodes(p) WHERE n:Computer) RETURN p", 100).unwrap();
        assert!(r.paths.is_empty());
        let r = run(&g, "MATCH (u {name:'CAROL@CORP'}) MATCH p=allShortestPaths((u)-[*1..]->(t {tier0:true})) RETURN p", 100).unwrap();
        assert_eq!(r.edges.len(), 4);
    }

    #[test]
    fn where_extras() {
        let g = graph();
        assert_eq!(col(&g, "MATCH (u:User) WHERE u.name IN ['ALICE@CORP', 'BOB@CORP'] RETURN count(u)"), vec![json!(2)]);
        assert_eq!(col(&g, "MATCH (u) WHERE u.objectid IN ['S-1-5-21-1-512'] RETURN u.name"), vec![json!("DOMAIN ADMINS@CORP")]);
        assert_eq!(col(&g, "MATCH (u:User) WHERE u.name =~ 'al.*' RETURN u.name"), vec![json!("ALICE@CORP")]);
        assert_eq!(col(&g, "MATCH (u:User) WHERE u.name =~ '(?i).*@corp' RETURN count(u)"), vec![json!(3)]);
        assert!(run(&g, &format!("MATCH (u) WHERE u.name =~ '{}' RETURN u", "a".repeat(2000)), 10).is_err());
        assert!(run(&g, "MATCH (u) WHERE u.name =~ '(' RETURN u", 10).unwrap_err().message.contains("regular expression"));
        assert_eq!(col(&g, "MATCH (u:User) WHERE u.pwdlastset IS NULL RETURN u.name"), vec![json!("CAROL@CORP")]);
        assert_eq!(col(&g, "MATCH (u:User) WHERE u.pwdlastset IS NOT NULL RETURN count(u)"), vec![json!(2)]);
        assert_eq!(col(&g, "MATCH (u:User) WHERE NOT (u)-[:MemberOf]->(:Group {name:'HELPDESK@CORP'}) RETURN u.name"), vec![json!("BOB@CORP")]);
        assert_eq!(col(&g, "MATCH (u:User) WHERE exists((u)-[:GetChanges]->()) RETURN u.name"), vec![json!("ALICE@CORP")]);
        assert_eq!(col(&g, "MATCH (n) WHERE n:User OR n:Computer RETURN count(n)"), vec![json!(4)]);
        assert_eq!(col(&g, "MATCH (u:User) WHERE toLower(u.title) = 'admin' AND toUpper(u.name) STARTS WITH 'B' RETURN u.name"), vec![json!("BOB@CORP")]);
        assert_eq!(col(&g, "MATCH (u:User) RETURN coalesce(u.pwdlastset, -1) AS p ORDER BY p"), vec![json!(-1), json!(50), json!(100)]);
        assert_eq!(col(&g, "MATCH (u:User) WHERE u.admincount = true RETURN u.name"), vec![json!("BOB@CORP")]);
        assert_eq!(col(&g, "MATCH (u:User) WHERE exists(u.pwdlastset) AND u.enabled RETURN u.name"), vec![json!("ALICE@CORP")]);
        assert_eq!(col(&g, "MATCH (u:User) RETURN CASE WHEN u.admincount THEN 'adm' ELSE 'std' END AS t ORDER BY t"), vec![json!("adm"), json!("std"), json!("std")]);
        // BloodHound CE labels and tags.
        assert_eq!(col(&g, "MATCH (n:Base) RETURN count(n)"), vec![json!(6)]);
        assert_eq!(col(&g, "MATCH (n:Tag_Tier_Zero) RETURN n.name"), vec![json!("DOMAIN ADMINS@CORP")]);
        assert_eq!(col(&g, "MATCH (n:Group:Base) WHERE coalesce(n.system_tags, '') CONTAINS 'admin_tier_0' RETURN n.name"), vec![json!("DOMAIN ADMINS@CORP")]);
        assert_eq!(col(&g, "MATCH (n:User) WHERE 'User' IN labels(n) AND n.name ENDS WITH 'CORP' RETURN count(n)"), vec![json!(3)]);
    }

    #[test]
    fn union_and_unwind() {
        let g = graph();
        assert_eq!(rows(&g, "MATCH (u:User) RETURN u.name AS n UNION MATCH (g:Group) RETURN g.name AS n").len(), 5);
        assert_eq!(rows(&g, "MATCH (u:User) RETURN 1 AS x UNION MATCH (g:Group) RETURN 1 AS x").len(), 1);
        assert_eq!(rows(&g, "MATCH (u:User) RETURN 1 AS x UNION ALL MATCH (g:Group) RETURN 1 AS x").len(), 5);
        let r = run(&g, "MATCH (u:User {name:'ALICE@CORP'}) RETURN u UNION MATCH (c:Computer) RETURN c AS u", 100).unwrap();
        assert_eq!(names(&g, &r.nodes), ["ALICE@CORP", "WS1.CORP"]);
        assert_eq!(col(&g, "UNWIND ['ALICE@CORP', 'BOB@CORP'] AS n MATCH (u {name: n}) RETURN u.name ORDER BY u.name"), vec![json!("ALICE@CORP"), json!("BOB@CORP")]);
        assert_eq!(col(&g, "UNWIND range(1, 3) AS i RETURN sum(i)"), vec![json!(6)]);
    }

    #[test]
    fn semantic_errors_have_positions() {
        let g = graph();
        let e = run(&g, "MATCH (n) RETURN m", 10).unwrap_err();
        assert_eq!((e.position, e.code), (Some(17), "semantic"));
        let e = run(&g, "MATCH (n) WHERE frobnicate(n) RETURN n", 10).unwrap_err();
        assert_eq!(e.position, Some(16));
        let e = run(&g, "MATCH (a)-[:Nope]->(b) RETURN a", 10).unwrap_err();
        assert_eq!(e.position, Some(9));
    }

    #[test]
    fn cancellation_in_new_operators() {
        let g = graph();
        let c = Cancel::never();
        c.cancel();
        for q in [
            "MATCH (u:User), (c) RETURN count(*)",
            "MATCH (u:User) WITH u ORDER BY u.name RETURN u",
            "MATCH (u:User) RETURN u.name AS n UNION MATCH (g:Group) RETURN g.name AS n",
            "MATCH (u:User) OPTIONAL MATCH (u)-[*1..]-(x) RETURN u, count(x)",
        ] {
            assert_eq!(run_with(&g, q, 10, &c).unwrap_err().code, "cancelled", "{q}");
        }
    }
}
