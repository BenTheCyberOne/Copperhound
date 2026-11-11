//! Randomized differential tests for predicate pushdown: random property
//! graphs (nulls, mixed types, list values, numeric strings, case variants,
//! duplicate / missing keys, nameless nodes, duplicate object ids) and random
//! WHERE predicates; every query must return exactly the same result with
//! pushdown on (verified node by node) as with it off.

mod common;

use ch_model::{ek, flags, NodeKind};
use ch_store::{Edge, Graph, GraphParts};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn chance(&mut self, p: f64) -> bool {
        (self.next() % 1_000_000) as f64 / 1e6 < p
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
}

const STRS: &[&str] = &["CORP.LOCAL", "corp.local", "Corp.Local", "PARTNER", "partner", "", "10", " 10 ", "5", "5.0", "1e3", "abc", "ABC", "a", "A", "z", "Z", "NaN", "inf", "-3", "S-1-5-21", "User", "b\\u00e9ta", "Bêta"];

fn json_scalar(r: &mut Rng) -> String {
    match r.below(7) {
        0 => "null".into(),
        1 => r.pick(&["true", "false"]).to_string(),
        2 => r.pick(&["0", "1", "-1", "10", "10.0", "5", "2.5", "1000", "-0.0", "1e3", "9007199254740993"]).to_string(),
        _ => serde_json::to_string(r.pick(STRS)).unwrap(),
    }
}

fn json_value(r: &mut Rng, depth: u32) -> String {
    match r.below(10) {
        0 if depth < 2 => {
            let n = r.below(4);
            format!("[{}]", (0..n).map(|_| json_value(r, depth + 1)).collect::<Vec<_>>().join(","))
        }
        1 if depth < 1 => format!("{{\"a\":{}}}", json_scalar(r)),
        _ => json_scalar(r),
    }
}

/// Property object for node `i`.
fn props(r: &mut Rng, i: usize) -> Option<String> {
    if r.chance(0.05) {
        return None;
    }
    let mut kv: Vec<String> = Vec::new();
    let mut add = |k: &str, v: String| kv.push(format!("{}:{v}", serde_json::to_string(k).unwrap()));
    if r.chance(0.8) {
        let k = *r.pick(&["domain", "domain", "domain", "DOMAIN", "Domain"]);
        add(k, if r.chance(0.9) { serde_json::to_string(r.pick(&STRS[..8])).unwrap() } else { json_scalar(r) });
    }
    if r.chance(0.05) {
        add("domain", "\"second\"".into());
    }
    if r.chance(0.7) {
        // Mostly integers: becomes a numeric column; sometimes a stray type.
        add("num", if r.chance(0.97) { format!("{}", r.below(41) as i64 - 20) } else { json_scalar(r) });
    }
    if r.chance(0.6) {
        add("flt", format!("{}", (r.below(2001) as f64 - 1000.0) / 8.0));
    }
    if r.chance(0.6) {
        add("numstr", serde_json::to_string(r.pick(&["5", " 5", "5.0", "1e3", "abc", "NaN", "-3", "10", "", "0x10", "+7"])).unwrap());
    }
    if r.chance(0.6) {
        add("mixed", json_value(r, 0));
    }
    if r.chance(0.5) {
        let n = r.below(4);
        let items: Vec<String> = (0..n).map(|_| if r.chance(0.8) { serde_json::to_string(r.pick(STRS)).unwrap() } else { json_scalar(r) }).collect();
        add("lst", format!("[{}]", items.join(",")));
    }
    if r.chance(0.6) {
        add(if r.chance(0.9) { "enabled" } else { "Enabled" }, r.pick(&["true", "false", "null", "\"true\"", "1", "0"]).to_string());
    }
    if r.chance(0.3) {
        add("hasspn", r.pick(&["true", "false", "null", "\"x\""]).to_string());
    }
    if r.chance(0.2) {
        add("system_tags", serde_json::to_string(r.pick(&["admin_tier_0", "owned", "", "custom"])).unwrap());
    }
    if r.chance(0.5) {
        add("allnull", "null".into());
    }
    if r.chance(0.3) {
        add("obj", format!("{{\"k\":{}}}", json_scalar(r)));
    }
    if r.chance(0.7) {
        add("lastlogon", format!("{}", 1_600_000_000 + r.below(100_000_000)));
    }
    if r.chance(0.5) {
        // High cardinality: string column without an equality index.
        add("desc", format!("\"{} item {i} {}\"", r.pick(&["Alpha", "alpha", "BETA", "beta", "Gamma"]), r.pick(&["x", "Y", "10"])));
    }
    if r.chance(0.3) {
        add("bool", r.pick(&["true", "false"]).to_string());
    }
    if r.chance(0.1) {
        add("name", "\"PROPNAME\"".into());
    }
    if r.chance(0.02) {
        return Some("not json".into());
    }
    Some(format!("{{{}}}", kv.join(",")))
}

fn random_graph(seed: u64, n: usize, upper_oids: bool) -> Graph {
    let mut r = Rng(seed);
    let kinds_pool = [NodeKind::User, NodeKind::User, NodeKind::Computer, NodeKind::Group, NodeKind::Domain, NodeKind::AzUser, NodeKind::AzGroup];
    let flag_pool = [flags::ENABLED, flags::TIER0, flags::OWNED, flags::HAS_SPN, flags::ADMINCOUNT, flags::DONT_REQ_PREAUTH, flags::UNCONSTRAINED_DELEGATION, flags::HIGHVALUE];
    let mut kinds = Vec::new();
    let mut fl = Vec::new();
    let mut names = Vec::new();
    let mut oids = Vec::new();
    let mut ps = Vec::new();
    for i in 0..n {
        kinds.push(*r.pick(&kinds_pool) as u8);
        fl.push(flag_pool.iter().filter(|_| r.chance(0.3)).fold(0, |a, f| a | f));
        names.push(match r.below(12) {
            0 => None,
            1 => Some(format!("dup{}@corp", r.below(5))),
            2 => Some(format!("Mixed{i}@Corp.Local")),
            3 => Some(r.pick(STRS).to_string()),
            _ => Some(format!("{}{i}@CORP.LOCAL", r.pick(&["USER", "HOST", "GROUP", "ALPHA", "BETA"]))),
        });
        let oid = match r.below(20) {
            0 => format!("S-1-5-21-DUP-{}", r.below(3)),
            1 if !upper_oids => format!("s-1-5-21-low-{i}"),
            2 => String::new(),
            _ => format!("S-1-5-21-1-{}", 1000 + i),
        };
        oids.push(oid);
        ps.push(props(&mut r, i));
    }
    let mut edges = Vec::new();
    for _ in 0..n * 3 {
        let (a, b) = (r.below(n) as u32, r.below(n) as u32);
        edges.push(Edge::new(a, b, *r.pick(&[ek::MEMBER_OF, ek::MEMBER_OF, ek::ADMIN_TO, ek::HAS_SESSION])));
    }
    let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
    let (g, _) = Graph::build(GraphParts { kinds, flags: fl, names, oids, props: ps, edge_chunks: vec![edges], edge_kinds, traversable, node_kinds: Vec::new() }).unwrap();
    g
}

const KEYS: &[&str] = &[
    "domain", "DOMAIN", "num", "flt", "numstr", "mixed", "lst", "enabled", "Enabled", "hasspn", "tier0", "istierzero", "owned", "admincount", "system_tags", "allnull",
    "obj", "lastlogon", "name", "objectid", "kind", "label", "id", "desc", "bool", "missing", "highvalue", "dontreqpreauth",
];
const LITS: &[&str] = &[
    "'corp.local'", "'CORP.LOCAL'", "'Corp'", "'10'", "' 10 '", "10", "10.0", "-1", "0", "1", "true", "false", "null", "'5'", "'5.0'", "'abc'", "'ABC'", "''",
    "'S-1-5-21'", "'s-1-5-21-1-1005'", "'S-1-5-21-DUP-1'", "'User'", "'user'", "[1, 'a', null]", "['corp.local', 'PARTNER']", "[]", "[null]", "[10, '5']", "1e3",
    "'1e3'", "'nan'", "'a'", "'A'", "'z'", "'Z'", "toUpper('corp.local')", "1600000000 + 50000000", "'alpha'", "'ITEM 1'", "'dup1@corp'", "'USER1'", "-2.5",
    "'Mixed3@corp.local'", "[[1]]", "'beta'", "2.5", "'x'",
];
const OPS: &[&str] = &["=", "<>", "<", ">", "<=", ">=", "STARTS WITH", "ENDS WITH", "CONTAINS", "IN"];
const LABELS: &[&str] = &["User", "Computer", "Group", "Base", "AZBase", "Tag_Tier_Zero", "Tag_Owned", "User|Computer", "Domain"];

fn leaf(r: &mut Rng, v: &str) -> String {
    let key = *r.pick(KEYS);
    match r.below(16) {
        0..=6 => format!("{v}.{key} {} {}", r.pick(OPS), r.pick(LITS)),
        7 => format!("{} {} {v}.{key}", r.pick(LITS), r.pick(OPS)),
        8 => format!("{v}.{key} IS {}NULL", if r.chance(0.5) { "NOT " } else { "" }),
        9 => format!("{v}.{key}"),
        10 => format!("{v}:{}", r.pick(LABELS)),
        11 => format!("toLower({v}.{key}) = {}", r.pick(LITS)),
        12 => format!("coalesce({v}.{key}, 'zz') {} {}", r.pick(OPS), r.pick(LITS)),
        13 => format!("{v}.{key} =~ '(?i)corp.*'"),
        14 => format!("{v}.{key} IN [{}, {}]", r.pick(LITS), r.pick(LITS)),
        _ => format!("{} {} {}", r.pick(LITS), r.pick(OPS), r.pick(LITS)),
    }
}

fn pred(r: &mut Rng, v: &str, depth: u32) -> String {
    if depth >= 3 || r.chance(0.45) {
        return leaf(r, v);
    }
    match r.below(5) {
        0 => format!("NOT ({})", pred(r, v, depth + 1)),
        1 => format!("({}) OR ({})", pred(r, v, depth + 1), pred(r, v, depth + 1)),
        2 => format!("({}) XOR ({})", pred(r, v, depth + 1), pred(r, v, depth + 1)),
        _ => format!("({}) AND ({})", pred(r, v, depth + 1), pred(r, v, depth + 1)),
    }
}

fn queries(r: &mut Rng, count: usize, paths: bool) -> Vec<String> {
    let inline = ["{domain: 'corp.local'}", "{enabled: true}", "{num: 10}", "{tier0: true}", "{name: 'dup1@corp'}", "{lst: 'abc'}", "{enabled: false}", "{desc: 'x'}", "{objectid: 'S-1-5-21-DUP-0'}"];
    let mut out = Vec::new();
    for i in 0..count {
        let p = pred(r, "n", 0);
        let q = pred(r, "m", 0);
        let lab = r.pick(&["", ":User", ":Computer", ":Group", ":Base"]);
        out.push(match i % 9 {
            0 => format!("MATCH (n) WHERE {p} RETURN n"),
            1 => format!("MATCH (n{lab}) WHERE {p} RETURN n.name, n.num, n.domain"),
            2 => format!("MATCH (n{lab} {}) WHERE {p} RETURN n", r.pick(&inline)),
            3 => format!("MATCH (n)-[:MemberOf]->(m{lab}) WHERE {p} AND {q} RETURN n, m"),
            4 => format!("MATCH (n)-[:MemberOf|AdminTo*1..2]->(m) WHERE {q} RETURN n, m"),
            5 => format!("MATCH (n{lab}) WHERE {p} OPTIONAL MATCH (n)-[:AdminTo]->(m) WHERE {q} RETURN n, m"),
            6 => format!("MATCH (n) WHERE {p} RETURN count(n), collect(n.name)"),
            7 => format!("MATCH (a)-[:HasSession]->(n {})-[:MemberOf]->(m) WHERE {p} AND {q} RETURN a, n, m", r.pick(&inline)),
            _ if paths => format!("MATCH p = shortestPath((n)-[*1..3]->(m)) WHERE ({p}) AND ({q}) AND n <> m RETURN p"),
            _ => format!("MATCH (n) WHERE {p} AND exists((n)-[:MemberOf]->(:Group)) RETURN n"),
        });
    }
    out
}

fn run_all(g: &Graph, qs: &[String]) {
    let mut nonempty = 0;
    for q in qs {
        if common::check(g, q) > 0 {
            nonempty += 1;
        }
    }
    // Keep the generator honest: most queries should return something.
    assert!(nonempty * 4 > qs.len(), "only {nonempty} of {} queries returned rows", qs.len());
}

/// Extra randomized rounds: `COPPERHOUND_PUSHDOWN_ROUNDS=50 cargo test …`.
fn rounds() -> u64 {
    std::env::var("COPPERHOUND_PUSHDOWN_ROUNDS").ok().and_then(|v| v.parse().ok()).unwrap_or(1)
}

fn random_rounds(seed: u64, nodes: usize, upper_oids: bool, count: usize, paths: bool) {
    for round in 0..rounds() {
        let s = seed ^ round.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let g = random_graph(s | 1, nodes, upper_oids);
        g.columns();
        let mut r = Rng(s.rotate_left(17) | 1);
        // Debug builds are ~20x slower; release runs the full count.
        let count = if cfg!(debug_assertions) { count / 4 } else { count };
        run_all(&g, &queries(&mut r, count, paths));
    }
}

#[test]
fn random_predicates_small_graph_lowercase_oids() {
    random_rounds(0x9E37_79B9_7F4A_7C15, 1_500, false, 900, true);
}

#[test]
fn random_predicates_upper_oids_with_duplicates() {
    random_rounds(0xD1B5_4A32_D192_ED03, 1_500, true, 900, true);
}

/// Large enough that start sets exceed the end-bitmap threshold.
#[test]
fn random_predicates_end_bitmaps() {
    random_rounds(0x2545_F491_4F6C_DD1D, 14_000, true, 360, false);
}

/// Before the columns exist, pushdown falls back to the CHQL evaluator.
#[test]
fn falls_back_without_columns() {
    let g = random_graph(99, 800, false);
    assert!(g.columns_ready().is_none());
    let mut r = Rng(5);
    for q in queries(&mut r, 120, true) {
        let q = common::strip_limit(&q);
        let off = common::exec(&g, &q, &common::OFF).map(|x| common::canon(&x));
        let on = common::exec(&g, &q, &common::ON).map(|x| common::canon(&x));
        assert_eq!(off, on, "{q}");
    }
    assert!(g.columns_ready().is_none(), "queries must not build columns");
}

/// Exact behaviour of the semantic edge cases that made the store differ.
#[test]
fn semantic_edge_cases() {
    let g = random_graph(3, 2_000, true);
    g.columns();
    for q in [
        // enabled: JSON null with the flag unset is null for CHQL.
        "MATCH (n) WHERE n.enabled IS NULL RETURN n",
        "MATCH (n) WHERE n.enabled = false RETURN n",
        "MATCH (n) WHERE n.enabled <> true RETURN n",
        "MATCH (n) WHERE NOT n.enabled RETURN n",
        "MATCH (n {enabled: false}) RETURN n",
        // null IN [null] is false.
        "MATCH (n) WHERE n.allnull IN [null] RETURN n",
        "MATCH (n) WHERE n.missing IN [null, 1] RETURN n",
        "MATCH (n) WHERE NOT n.domain IN ['corp.local', null] RETURN n",
        // case variants order by exact bytes after folding.
        "MATCH (n) WHERE n.domain > 'CORP.LOCAL' RETURN n",
        "MATCH (n) WHERE n.domain <= 'corp.local' RETURN n",
        "MATCH (n) WHERE n.desc < 'alpha item 5' RETURN n",
        "MATCH (n) WHERE 'a' < n.domain RETURN n",
        // duplicate / empty object ids.
        "MATCH (n) WHERE n.objectid = 'S-1-5-21-DUP-1' RETURN n",
        "MATCH (n) WHERE n.objectid IN ['S-1-5-21-DUP-0', 's-1-5-21-dup-2'] RETURN n",
        "MATCH (n) WHERE n.objectid = '' RETURN n",
        // list membership is one-sided.
        "MATCH (n) WHERE n.lst = 'abc' RETURN n",
        "MATCH (n) WHERE 'abc' = n.lst RETURN n",
        "MATCH (n) WHERE n.system_tags CONTAINS 'admin' RETURN n",
    ] {
        common::check(&g, q);
    }
}
